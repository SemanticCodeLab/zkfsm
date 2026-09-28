//! RemoteDrive: a drive on another node, driven over RPC. It implements the drive
//! handle (`backend.drive.Ext`) so protection stores treat it like a local drive.
const std = @import("std");
const backend = @import("../backend/root.zig");
const rpc_mod = @import("rpc.zig");
const wire = @import("wire.zig");

const Error = backend.Error;
const PhysicalKey = backend.PhysicalKey;
const drive = backend.drive;

/// Bytes fetched per remote read beyond what the caller asked for.
const read_window = 1024 * 1024;
const open_window = 64 * 1024;
const write_buf = 256 * 1024;
const max_record = 16 * 1024 * 1024 + 64;

pub const RemoteDrive = struct {
    gpa: std.mem.Allocator,
    rpc: *rpc_mod.Rpc,
    node: u16,
    /// "pool.endpoint" address of the drive on its node.
    addr: [24]u8 = undefined,
    addr_len: u8 = 0,

    pub fn init(gpa: std.mem.Allocator, rpc: *rpc_mod.Rpc, node: u16, pool: u32, endpoint: u32) RemoteDrive {
        var d: RemoteDrive = .{ .gpa = gpa, .rpc = rpc, .node = node };
        d.addr_len = @intCast((std.fmt.bufPrint(&d.addr, "{d}.{d}", .{ pool, endpoint }) catch unreachable).len);
        return d;
    }

    fn address(d: *const RemoteDrive) []const u8 {
        return d.addr[0..d.addr_len];
    }

    pub fn ext(d: *RemoteDrive) drive.Ext {
        return .{ .ctx = d, .vtable = &ext_vtable };
    }

    const ext_vtable: drive.Ext.VTable = .{
        .store = storeFn,
        .begin = begin,
        .openRead = openRead,
        .readFormat = readFormat,
        .scan = scan,
        .online = online,
        .deleteRecordIf = deleteRecordIf,
    };

    fn cast(ctx: *anyopaque) *RemoteDrive {
        return @ptrCast(@alignCast(ctx));
    }

    fn online(ctx: *anyopaque) bool {
        const d = cast(ctx);
        return d.rpc.isOnline(d.node);
    }

    /// Query string `d=<addr>[&k=<key>]` plus extra parameters.
    fn query(d: *const RemoteDrive, buf: []u8, key: ?PhysicalKey, extra: []const u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.print("d={s}", .{d.address()}) catch unreachable;
        if (key) |k| w.print("&k={c}{s}", .{ wire.spaceChar(k.space), &k.hex }) catch unreachable;
        if (extra.len > 0) w.print("&{s}", .{extra}) catch unreachable;
        return w.buffered();
    }

    /// One small exchange; returns the finished call (caller deinits) or a mapped error.
    fn exchange(d: *RemoteDrive, op: []const u8, key: ?PhysicalKey, extra: []const u8, body: []const u8) Error!rpc_mod.Call {
        var qb: [256]u8 = undefined;
        var c = d.rpc.call(d.node, op, d.query(&qb, key, extra), .{ .bytes = body }, .{}) catch |e| return mapCall(e);
        if (!c.ok()) {
            const st = c.status;
            c.deinit();
            return mapStatus(st);
        }
        return c;
    }

    fn storeFn(ctx: *anyopaque) backend.StorageBackend {
        return .{ .ctx = ctx, .capabilities = .{ .atomic_rename = true, .durable_sync = true, .range_read = true }, .vtable = &store_vtable };
    }

    const store_vtable: backend.StorageBackend.VTable = .{
        .put = put,
        .get = get,
        .stat = stat,
        .delete = delete,
        .list = list,
        .putRecord = putRecord,
        .getRecord = getRecord,
        .deleteRecord = delete,
        .sync = sync,
    };

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: backend.PutOptions) Error!backend.ObjectMeta {
        _ = opts;
        var p = drive.Pending{ .ext = try begin(ctx) };
        errdefer p.abort();
        var buf: [64 * 1024]u8 = undefined;
        var total: u64 = 0;
        while (true) {
            const n = source.readSliceShort(&buf) catch return error.ReadFailed;
            if (n == 0) break;
            try p.writeAll(buf[0..n]);
            total += n;
            if (n < buf.len) break;
        }
        try p.commit(key);
        return .{ .size = total, .mtime_ns = std.time.nanoTimestamp() };
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?backend.Range, sink: *std.Io.Writer) Error!backend.ObjectMeta {
        const d = cast(ctx);
        var eb: [64]u8 = undefined;
        const extra = if (range) |r| std.fmt.bufPrint(&eb, "off={d}&len={d}", .{ r.offset, r.length }) catch unreachable else "all=1";
        var c = try d.exchange("read", key, extra, "");
        defer c.deinit();
        c.streamTo(sink) catch |e| return if (e == error.WriteFailed) error.WriteFailed else error.IoFailed;
        return .{ .size = c.meta.size orelse 0, .mtime_ns = c.meta.mtime_ns orelse 0 };
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!backend.ObjectMeta {
        var c = try cast(ctx).exchange("stat", key, "", "");
        defer c.deinit();
        return .{ .size = c.meta.size orelse return error.IoFailed, .mtime_ns = c.meta.mtime_ns orelse 0 };
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        var c = try cast(ctx).exchange("del", key, "", "");
        c.deinit();
    }

    fn deleteRecordIf(ctx: *anyopaque, key: PhysicalKey, stamp: u64) Error!void {
        var eb: [32]u8 = undefined;
        var c = try cast(ctx).exchange("rdelif", key, std.fmt.bufPrint(&eb, "stamp={d}", .{stamp}) catch unreachable, "");
        c.deinit();
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        var c = try cast(ctx).exchange("rput", key, "", bytes);
        c.deinit();
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        var c = try cast(ctx).exchange("rget", key, "", "");
        defer c.deinit();
        return c.readAll(gpa, max_record) catch |e| return mapCall(e);
    }

    fn sync(ctx: *anyopaque) Error!void {
        var c = try cast(ctx).exchange("sync", null, "", "");
        c.deinit();
    }

    fn list(ctx: *anyopaque, space: backend.KeySpace, cb: backend.ListCallback) Error!void {
        const d = cast(ctx);
        var after: ?[32]u8 = null;
        while (true) {
            var page: drive.ScanPage = .{};
            defer page.deinit(d.gpa);
            try scan(ctx, d.gpa, space, after, &page);
            for (page.keys.items) |k| try cb.func(cb.ctx, k);
            if (!page.more or page.keys.items.len == 0) return;
            after = page.keys.items[page.keys.items.len - 1].hex;
        }
    }

    fn scan(ctx: *anyopaque, gpa: std.mem.Allocator, space: backend.KeySpace, after: ?[32]u8, out: *drive.ScanPage) Error!void {
        const d = cast(ctx);
        var eb: [64]u8 = undefined;
        const extra = if (after) |a|
            std.fmt.bufPrint(&eb, "space={c}&after={s}", .{ wire.spaceChar(space), &a }) catch unreachable
        else
            std.fmt.bufPrint(&eb, "space={c}", .{wire.spaceChar(space)}) catch unreachable;
        var c = try d.exchange("scan", null, extra, "");
        defer c.deinit();
        const body = c.readAll(gpa, drive.scan_page_max * 33 + 16) catch |e| return mapCall(e);
        defer gpa.free(body);
        var it = std.mem.tokenizeScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (line.len != 32 or !wire.isHex(line)) return error.IoFailed;
            try out.keys.append(gpa, .{ .space = space, .hex = line[0..32].* });
        }
        out.more = c.meta.more;
    }

    fn readFormat(ctx: *anyopaque, buf: []u8) Error![]u8 {
        var c = try cast(ctx).exchange("format", null, "", "");
        defer c.deinit();
        if (c.body_left > buf.len) return error.TooLarge;
        const out = buf[0..@intCast(c.body_left)];
        c.readInto(out) catch |e| return mapCall(e);
        return out;
    }

    // ---- streamed writes ----

    fn begin(ctx: *anyopaque) Error!drive.ExtPending {
        const d = cast(ctx);
        const w = try d.gpa.create(RemoteWrite);
        errdefer d.gpa.destroy(w);
        const buf = try d.gpa.alloc(u8, write_buf);
        errdefer d.gpa.free(buf);
        var qb: [64]u8 = undefined;
        const c = d.rpc.call(d.node, "write", d.query(&qb, null, ""), .stream, .{}) catch |e| return mapCall(e);
        w.* = .{ .drive = d, .call = c, .buf = buf };
        return .{ .ctx = w, .vtable = &write_vtable };
    }

    const write_vtable: drive.ExtPending.VTable = .{
        .writeAll = RemoteWrite.writeAll,
        .pwrite = RemoteWrite.pwrite,
        .commit = RemoteWrite.commit,
        .abort = RemoteWrite.abort,
    };

    // ---- positional reads ----

    fn openRead(ctx: *anyopaque, key: PhysicalKey) Error!drive.ExtFile {
        const d = cast(ctx);
        const f = try d.gpa.create(RemoteFile);
        errdefer d.gpa.destroy(f);
        f.* = .{ .drive = d, .key = key };
        errdefer f.free();
        try f.fetch(0, open_window);
        return .{ .ctx = f, .vtable = &file_vtable };
    }

    const file_vtable: drive.ExtFile.VTable = .{
        .pread = RemoteFile.pread,
        .stat = RemoteFile.statFn,
        .close = RemoteFile.close,
    };
};

/// Frames go out as chunks of one streamed request; see `wire.Frame`.
const RemoteWrite = struct {
    drive: *RemoteDrive,
    call: rpc_mod.Call,
    buf: []u8,
    /// Data bytes buffered after the frame header slot.
    len: usize = 0,

    fn cast(ctx: *anyopaque) *RemoteWrite {
        return @ptrCast(@alignCast(ctx));
    }

    fn flushData(w: *RemoteWrite) Error!void {
        if (w.len == 0) return;
        wire.dataHeader(w.buf[0..wire.data_header_len], @intCast(w.len));
        w.call.writeChunk(w.buf[0 .. wire.data_header_len + w.len]) catch return error.IoFailed;
        w.len = 0;
    }

    fn writeAll(ctx: *anyopaque, bytes: []const u8) Error!void {
        const w = cast(ctx);
        var rest = bytes;
        const cap = w.buf.len - wire.data_header_len;
        while (rest.len > 0) {
            const n = @min(rest.len, cap - w.len);
            @memcpy(w.buf[wire.data_header_len + w.len ..][0..n], rest[0..n]);
            w.len += n;
            rest = rest[n..];
            if (w.len == cap) try w.flushData();
        }
    }

    fn pwrite(ctx: *anyopaque, bytes: []const u8, off: u64) Error!void {
        const w = cast(ctx);
        if (bytes.len > wire.max_patch) return error.InvalidKey;
        try w.flushData();
        var fb: [wire.patch_header_len + wire.max_patch]u8 = undefined;
        const frame = wire.patchFrame(&fb, bytes, off);
        w.call.writeChunk(frame) catch return error.IoFailed;
    }

    fn commit(ctx: *anyopaque, key: PhysicalKey) Error!void {
        const w = cast(ctx);
        defer w.destroy();
        try w.flushData();
        var fb: [wire.commit_frame_len]u8 = undefined;
        w.call.writeChunk(wire.commitFrame(&fb, key)) catch return error.IoFailed;
        w.call.finish() catch return error.IoFailed;
        if (!w.call.ok()) return mapStatus(w.call.status);
    }

    fn abort(ctx: *anyopaque) void {
        const w = cast(ctx);
        // Dropping the connection makes the owner discard the temp file.
        w.call.keep = false;
        w.destroy();
    }

    fn destroy(w: *RemoteWrite) void {
        const gpa = w.drive.gpa;
        w.call.deinit();
        gpa.free(w.buf);
        gpa.destroy(w);
    }
};

const RemoteFile = struct {
    drive: *RemoteDrive,
    key: PhysicalKey,
    size: u64 = 0,
    mtime_ns: i128 = 0,
    win: []u8 = &.{},
    win_off: u64 = 0,
    win_len: usize = 0,

    fn cast(ctx: *anyopaque) *RemoteFile {
        return @ptrCast(@alignCast(ctx));
    }

    /// Loads [off, off+want) (clipped to the blob) into the window.
    fn fetch(f: *RemoteFile, off: u64, want: usize) Error!void {
        const d = f.drive;
        var eb: [64]u8 = undefined;
        var c = try d.exchange("read", f.key, std.fmt.bufPrint(&eb, "off={d}&len={d}&clip=1", .{ off, want }) catch unreachable, "");
        defer c.deinit();
        f.size = c.meta.size orelse return error.IoFailed;
        f.mtime_ns = c.meta.mtime_ns orelse 0;
        const n: usize = @intCast(c.body_left);
        if (n > want) return error.IoFailed;
        if (f.win.len < n) {
            const nw = try d.gpa.alloc(u8, @max(n, open_window));
            d.gpa.free(f.win);
            f.win = nw;
        }
        c.readInto(f.win[0..n]) catch return error.IoFailed;
        f.win_off = off;
        f.win_len = n;
    }

    fn pread(ctx: *anyopaque, buf: []u8, off: u64) Error!usize {
        const f = cast(ctx);
        if (off >= f.size) return 0;
        const want: usize = @intCast(@min(buf.len, f.size - off));
        const inside = off >= f.win_off and off + want <= f.win_off + f.win_len;
        if (!inside) try f.fetch(off, @max(want, read_window));
        const lo: usize = @intCast(off - f.win_off);
        const n = @min(want, f.win_len - lo);
        @memcpy(buf[0..n], f.win[lo..][0..n]);
        return n;
    }

    fn statFn(ctx: *anyopaque) Error!drive.Stat {
        const f = cast(ctx);
        return .{ .size = f.size, .mtime_ns = f.mtime_ns };
    }

    fn free(f: *RemoteFile) void {
        f.drive.gpa.free(f.win);
    }

    fn close(ctx: *anyopaque) void {
        const f = cast(ctx);
        const gpa = f.drive.gpa;
        f.free();
        gpa.destroy(f);
    }
};

pub fn mapCall(e: rpc_mod.Error) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.IoFailed,
    };
}

pub fn mapStatus(status: u16) Error {
    return switch (status) {
        404 => error.NotFound,
        400 => error.InvalidKey,
        413 => error.TooLarge,
        507 => error.NoSpace,
        else => error.IoFailed,
    };
}
