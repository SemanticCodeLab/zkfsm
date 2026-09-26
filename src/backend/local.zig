//! Local filesystem backend: <root>/<space>/ab/cd/<hex>[.meta], temp + fsync + rename.
const std = @import("std");
const iface = @import("root.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const KeySpace = iface.KeySpace;
const ObjectMeta = iface.ObjectMeta;

const io_buf_len = 64 * 1024;
const max_record_len = 16 * 1024 * 1024;

pub const LocalBackend = struct {
    root: std.fs.Dir,

    pub const capabilities: iface.Capabilities = .{
        .atomic_rename = true,
        .durable_sync = true,
        .range_read = true,
        .sparse_files = true,
    };

    pub const OpenError = error{ OpenFailed, AccessDenied };

    pub fn open(path: []const u8) OpenError!LocalBackend {
        const root = std.fs.cwd().makeOpenPath(path, .{ .iterate = true }) catch |e| switch (e) {
            error.AccessDenied => return error.AccessDenied,
            else => return error.OpenFailed,
        };
        for ([_][]const u8{ "data", "record", "system", "tmp" }) |sub| {
            root.makePath(sub) catch return error.OpenFailed;
        }
        return .{ .root = root };
    }

    pub fn close(self: *LocalBackend) void {
        self.root.close();
    }

    pub fn backend(self: *LocalBackend) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = capabilities, .vtable = &vtable };
    }

    const vtable: iface.StorageBackend.VTable = .{
        .put = put,
        .get = get,
        .stat = stat,
        .delete = delete,
        .list = list,
        .putRecord = putRecord,
        .getRecord = getRecord,
        .deleteRecord = deleteRecord,
        .sync = sync,
    };

    fn self_(ctx: *anyopaque) *LocalBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!ObjectMeta {
        _ = opts;
        const self = self_(ctx);
        var path_buf: [path_max]u8 = undefined;
        const final = try keyPath(key, &path_buf);
        var tmp_buf: [48]u8 = undefined;
        const tmp = tempPath(&tmp_buf);

        var file = self.root.createFile(tmp, .{ .exclusive = true }) catch |e| return mapFs(e);
        var committed = false;
        defer if (!committed) self.root.deleteFile(tmp) catch {};
        {
            defer file.close();
            var wbuf: [io_buf_len]u8 = undefined;
            var fw = file.writer(&wbuf);
            _ = source.streamRemaining(&fw.interface) catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
                error.WriteFailed => return mapFs(fw.err orelse error.Unexpected),
            };
            fw.interface.flush() catch return mapFs(fw.err orelse error.Unexpected);
            file.sync() catch |e| return mapFs(e);
        }
        try self.commit(tmp, final);
        committed = true;
        return self.statPath(final);
    }

    /// Renames tmp into place and fsyncs the parent directory.
    fn commit(self: *LocalBackend, tmp: []const u8, final: []const u8) Error!void {
        const dir = std.fs.path.dirname(final) orelse ".";
        self.root.makePath(dir) catch |e| return mapFs(e);
        self.root.rename(tmp, final) catch |e| return mapFs(e);
        // A plain openDir yields an O_PATH fd, which fsync rejects.
        var d = self.root.openDir(dir, .{ .iterate = true }) catch |e| return mapFs(e);
        defer d.close();
        std.posix.fsync(d.fd) catch |e| return mapFs(e);
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?iface.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const self = self_(ctx);
        var path_buf: [path_max]u8 = undefined;
        const path = try keyPath(key, &path_buf);
        var file = self.root.openFile(path, .{}) catch |e| return mapFs(e);
        defer file.close();
        const st = file.stat() catch |e| return mapFs(e);
        const r = range orelse iface.Range{ .offset = 0, .length = st.size };
        if (r.length > 0 and (r.offset >= st.size or r.length > st.size - r.offset)) return error.IoFailed;
        var rbuf: [io_buf_len]u8 = undefined;
        var fr = file.reader(&rbuf);
        fr.seekTo(r.offset) catch return error.IoFailed;
        fr.interface.streamExact64(sink, r.length) catch |e| switch (e) {
            error.WriteFailed => return error.WriteFailed,
            error.ReadFailed, error.EndOfStream => return error.IoFailed,
        };
        return .{ .size = st.size, .mtime_ns = st.mtime };
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta {
        var path_buf: [path_max]u8 = undefined;
        return self_(ctx).statPath(try keyPath(key, &path_buf));
    }

    fn statPath(self: *LocalBackend, path: []const u8) Error!ObjectMeta {
        const st = self.root.statFile(path) catch |e| return mapFs(e);
        return .{ .size = st.size, .mtime_ns = st.mtime };
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        var path_buf: [path_max]u8 = undefined;
        self_(ctx).root.deleteFile(try keyPath(key, &path_buf)) catch |e| return mapFs(e);
    }

    /// Fixed two-level walk of the fanout; no recursion.
    fn list(ctx: *anyopaque, space: KeySpace, cb: iface.ListCallback) Error!void {
        const self = self_(ctx);
        var top = self.root.openDir(@tagName(space), .{ .iterate = true }) catch |e| return mapFs(e);
        defer top.close();
        if (space == .system) return iterLeaf(top, space, cb);
        var it1 = top.iterate();
        while (it1.next() catch |e| return mapFs(e)) |e1| {
            if (e1.kind != .directory or e1.name.len != 2) continue;
            var d1 = top.openDir(e1.name, .{ .iterate = true }) catch |e| return mapFs(e);
            defer d1.close();
            var it2 = d1.iterate();
            while (it2.next() catch |e| return mapFs(e)) |e2| {
                if (e2.kind != .directory or e2.name.len != 2) continue;
                var d2 = d1.openDir(e2.name, .{ .iterate = true }) catch |e| return mapFs(e);
                defer d2.close();
                try iterLeaf(d2, space, cb);
            }
        }
    }

    fn iterLeaf(dir: std.fs.Dir, space: KeySpace, cb: iface.ListCallback) Error!void {
        var it = dir.iterate();
        while (it.next() catch |e| return mapFs(e)) |ent| {
            if (ent.kind != .file) continue;
            const name = if (space == .data) ent.name else blk: {
                if (!std.mem.endsWith(u8, ent.name, ".meta")) continue;
                break :blk ent.name[0 .. ent.name.len - 5];
            };
            if (name.len != 32 or !isHex(name)) continue;
            try cb.func(cb.ctx, .{ .space = space, .hex = name[0..32].* });
        }
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        const self = self_(ctx);
        if (key.space == .data) return error.InvalidKey;
        var path_buf: [path_max]u8 = undefined;
        const final = try keyPath(key, &path_buf);
        var tmp_buf: [48]u8 = undefined;
        const tmp = tempPath(&tmp_buf);
        var file = self.root.createFile(tmp, .{ .exclusive = true }) catch |e| return mapFs(e);
        var committed = false;
        defer if (!committed) self.root.deleteFile(tmp) catch {};
        {
            defer file.close();
            file.writeAll(bytes) catch |e| return mapFs(e);
            file.sync() catch |e| return mapFs(e);
        }
        try self.commit(tmp, final);
        committed = true;
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        if (key.space == .data) return error.InvalidKey;
        var path_buf: [path_max]u8 = undefined;
        const path = try keyPath(key, &path_buf);
        return self_(ctx).root.readFileAlloc(gpa, path, max_record_len) catch |e| switch (e) {
            error.FileTooBig => error.TooLarge,
            error.OutOfMemory => error.OutOfMemory,
            else => mapFs(e),
        };
    }

    fn deleteRecord(ctx: *anyopaque, key: PhysicalKey) Error!void {
        if (key.space == .data) return error.InvalidKey;
        var path_buf: [path_max]u8 = undefined;
        self_(ctx).root.deleteFile(try keyPath(key, &path_buf)) catch |e| return mapFs(e);
    }

    fn sync(ctx: *anyopaque) Error!void {
        std.posix.fsync(self_(ctx).root.fd) catch |e| return mapFs(e);
    }
};

const path_max = 64;

fn isHex(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

/// data/ab/cd/<hex>, record/ab/cd/<hex>.meta, system/<hex>.meta
pub fn keyPath(key: PhysicalKey, buf: *[path_max]u8) Error![]const u8 {
    if (!isHex(&key.hex)) return error.InvalidKey;
    const h = &key.hex;
    return switch (key.space) {
        .data => std.fmt.bufPrint(buf, "data/{s}/{s}/{s}", .{ h[0..2], h[2..4], h }),
        .record => std.fmt.bufPrint(buf, "record/{s}/{s}/{s}.meta", .{ h[0..2], h[2..4], h }),
        .system => std.fmt.bufPrint(buf, "system/{s}.meta", .{h}),
    } catch error.InvalidKey;
}

fn tempPath(buf: *[48]u8) []const u8 {
    var r: [16]u8 = undefined;
    std.crypto.random.bytes(&r);
    return std.fmt.bufPrint(buf, "tmp/{s}.tmp", .{std.fmt.bytesToHex(r, .lower)}) catch unreachable; // fixed width
}

fn mapFs(e: anyerror) Error {
    return switch (e) {
        error.FileNotFound, error.NotDir => error.NotFound,
        error.NoSpaceLeft, error.DiskQuota => error.NoSpace,
        error.OutOfMemory => error.OutOfMemory,
        else => error.IoFailed,
    };
}

test "key fanout paths" {
    var buf: [path_max]u8 = undefined;
    const hex = "abcdef0123456789abcdef0123456789".*;
    try std.testing.expectEqualStrings(
        "data/ab/cd/abcdef0123456789abcdef0123456789",
        try keyPath(.{ .space = .data, .hex = hex }, &buf),
    );
    try std.testing.expectEqualStrings(
        "record/ab/cd/abcdef0123456789abcdef0123456789.meta",
        try keyPath(.{ .space = .record, .hex = hex }, &buf),
    );
    var bad = hex;
    bad[0] = '/';
    try std.testing.expectError(error.InvalidKey, keyPath(.{ .space = .data, .hex = bad }, &buf));
}

test "local backend put, ranged get, list, delete" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &pbuf);
    var lb = try LocalBackend.open(root);
    defer lb.close();
    const b = lb.backend();

    const key: PhysicalKey = .{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* };
    var src: std.Io.Reader = .fixed("0123456789");
    const m = try b.put(key, &src, .{});
    try std.testing.expectEqual(@as(u64, 10), m.size);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try b.get(key, .{ .offset = 3, .length = 4 }, &out.writer);
    try std.testing.expectEqualStrings("3456", out.written());

    const Counter = struct {
        n: usize = 0,
        fn f(ctx: *anyopaque, _: PhysicalKey) Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.n += 1;
        }
    };
    var c: Counter = .{};
    try b.list(.data, .{ .ctx = &c, .func = Counter.f });
    try std.testing.expectEqual(@as(usize, 1), c.n);

    try b.delete(key);
    try std.testing.expectError(error.NotFound, b.stat(key));

    const rk: PhysicalKey = .{ .space = .record, .hex = key.hex };
    try b.putRecord(rk, "rec");
    const got = try b.getRecord(rk, std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("rec", got);
}
