//! RPC server: authenticates peer requests under the reserved path and serves this
//! node's drives (streamed writes, ranged reads, records, scans), lock leases, change
//! notifications, and bootstrap queries.
const std = @import("std");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");
const s3 = @import("../s3/root.zig");
const auth = @import("auth.zig");
const rpc = @import("rpc.zig");
const wire = @import("wire.zig");
const locks = @import("locks.zig");
const node_mod = @import("node.zig");

const Node = node_mod.Node;
const Request = std.http.Server.Request;
const RawError = s3.server.RawError;
const LocalBackend = backend.local.LocalBackend;
const PhysicalKey = backend.PhysicalKey;

const max_small_body = 17 * 1024 * 1024;
const max_read = 8 * 1024 * 1024;

pub fn route(n: *Node) s3.server.RawRoute {
    return .{ .prefix = rpc.prefix, .ctx = n, .serve = serve };
}

const Query = struct {
    raw: []const u8,

    fn get(q: Query, name: []const u8) ?[]const u8 {
        var it = std.mem.splitScalar(u8, q.raw, '&');
        while (it.next()) |kv| {
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
            if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
        }
        return null;
    }

    fn int(q: Query, comptime T: type, name: []const u8) ?T {
        return std.fmt.parseInt(T, q.get(name) orelse return null, 10) catch null;
    }
};

fn fail(req: *Request, status: std.http.Status, why: []const u8) RawError!void {
    try req.respond("", .{ .status = status, .keep_alive = false, .extra_headers = &.{.{ .name = "x-zkfsm-error", .value = why }} });
}

fn statusOf(e: backend.Error) std.http.Status {
    return switch (e) {
        error.NotFound => .not_found,
        error.InvalidKey => .bad_request,
        error.TooLarge => .payload_too_large,
        error.NoSpace => .insufficient_storage,
        else => .internal_server_error,
    };
}

fn serve(ctx: *anyopaque, req: *Request, arena: std.mem.Allocator) RawError!void {
    const n: *Node = @ptrCast(@alignCast(ctx));
    if (req.head.method != .POST) return fail(req, .method_not_allowed, "method");
    var h: auth.Fields = .{ .method = "POST", .target = req.head.target, .node = "", .time = "", .nonce = "", .body = "" };
    var sig: []const u8 = "";
    var it = req.iterateHeaders();
    while (it.next()) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_node)) h.node = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_time)) h.time = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_nonce)) h.nonce = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_body)) h.body = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_sig)) sig = hd.value;
    }
    n.guard.verify(n.secret, h, sig, std.time.milliTimestamp()) catch |e| {
        if (e != error.Replayed) std.log.warn("rpc: rejected request from {s}: {t}", .{ h.node, e });
        return fail(req, if (e == error.Busy) .service_unavailable else .unauthorized, @errorName(e));
    };
    const path = req.head.target[rpc.prefix.len..];
    const qpos = std.mem.indexOfScalar(u8, path, '?');
    const op = path[0 .. qpos orelse path.len];
    const q: Query = .{ .raw = if (qpos) |p| path[p + 1 ..] else "" };

    if (std.mem.eql(u8, op, "write")) {
        if (!std.mem.eql(u8, h.body, auth.body_stream)) return fail(req, .bad_request, "body");
        return write(n, req, q);
    }
    // Every other call carries a small body whose digest was signed.
    const len = req.head.content_length orelse return fail(req, .length_required, "length");
    if (len > max_small_body) return fail(req, .payload_too_large, "body");
    var rb: [4096]u8 = undefined;
    const r = req.readerExpectContinue(&rb) catch return error.ReadFailed;
    const body = r.readAlloc(arena, @intCast(len)) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ReadFailed,
    };
    if (!std.mem.eql(u8, &auth.bodyDigest(body), h.body)) return fail(req, .bad_request, "digest");

    if (std.mem.eql(u8, op, "hello")) return hello(n, req, arena);
    if (std.mem.eql(u8, op, "format")) return formatGet(n, req, q);
    if (std.mem.eql(u8, op, "format_put")) return formatPut(n, req, q, body);
    if (std.mem.eql(u8, op, "lock") or std.mem.eql(u8, op, "refresh") or std.mem.eql(u8, op, "unlock")) return lockOp(n, req, op, body);
    if (std.mem.eql(u8, op, "notify")) return notify(n, req, body);
    if (std.mem.eql(u8, op, "diskinfo")) return diskInfo(n, req, q, arena);
    if (std.mem.eql(u8, op, "pread")) return pread(n, req, q);
    if (std.mem.eql(u8, op, "close")) {
        n.leases.close(q.int(u64, "h") orelse return fail(req, .bad_request, "h"));
        return req.respond("", .{});
    }
    if (!n.drives_open.load(.acquire)) return fail(req, .service_unavailable, "starting");
    const d = n.localDrive(q.get("d") orelse "") orelse return fail(req, .not_found, "drive");
    const lb = d.set.acquire(d.slot) orelse return fail(req, .service_unavailable, "offline");
    defer d.set.release(d.slot);
    const l = lb.local;
    if (std.mem.eql(u8, op, "sync")) {
        l.backend().sync() catch |e| return fail(req, statusOf(e), @errorName(e));
        return req.respond("", .{});
    }
    if (std.mem.eql(u8, op, "scan")) return scan(n, req, q, l, arena);
    const key = wire.parseKey(q.get("k") orelse "") orelse return fail(req, .bad_request, "key");
    if (std.mem.eql(u8, op, "read")) return read(req, q, l, key);
    if (std.mem.eql(u8, op, "open")) return openLease(n, req, q, l, key);
    if (std.mem.eql(u8, op, "stat")) {
        const m = l.backend().stat(key) catch |e| return fail(req, statusOf(e), @errorName(e));
        return respondMeta(req, "", m.size, m.mtime_ns);
    }
    if (std.mem.eql(u8, op, "del")) {
        const res = if (key.space == .data) l.backend().delete(key) else l.backend().deleteRecord(key);
        res catch |e| return fail(req, statusOf(e), @errorName(e));
        return req.respond("", .{});
    }
    if (key.space == .data) return fail(req, .bad_request, "space");
    if (std.mem.eql(u8, op, "rget")) {
        const bytes = l.backend().getRecord(key, arena) catch |e| return fail(req, statusOf(e), @errorName(e));
        return req.respond(bytes, .{});
    }
    if (std.mem.eql(u8, op, "rput")) {
        // Stamped cluster records keep the newest version on every drive.
        const res = if (protection.shard.unframeAny(body)) |u|
            (if (u.stamp != 0) protection.shard.putRecordNewer(l, n.gpa, key, body) else l.backend().putRecord(key, body))
        else
            l.backend().putRecord(key, body);
        res catch |e| return fail(req, statusOf(e), @errorName(e));
        return req.respond("", .{});
    }
    if (std.mem.eql(u8, op, "rdelif")) {
        const stamp = q.int(u64, "stamp") orelse return fail(req, .bad_request, "stamp");
        protection.shard.deleteRecordIf(l, n.gpa, key, stamp) catch |e| return fail(req, statusOf(e), @errorName(e));
        return req.respond("", .{});
    }
    return fail(req, .not_found, "op");
}

fn respondMeta(req: *Request, body: []const u8, size: u64, mtime: i128) RawError!void {
    var sb: [24]u8 = undefined;
    var mb: [48]u8 = undefined;
    try req.respond(body, .{ .extra_headers = &.{
        .{ .name = "x-zkfsm-size", .value = std.fmt.bufPrint(&sb, "{d}", .{size}) catch unreachable },
        .{ .name = "x-zkfsm-mtime", .value = std.fmt.bufPrint(&mb, "{d}", .{mtime}) catch unreachable },
    } });
}

fn hello(n: *Node, req: *Request, arena: std.mem.Allocator) RawError!void {
    const topo = std.fmt.bytesToHex(n.topo_fp, .lower);
    const root = std.fmt.bytesToHex(n.root_fp, .lower);
    const body = try std.fmt.allocPrint(arena, "node {d}\ntopology {s}\nroot {s}\nready {d}\ndrives {d}\n", .{
        n.topo.local, &topo, &root, @intFromBool(n.open.load(.acquire)), @intFromBool(n.drives_open.load(.acquire)),
    });
    try req.respond(body, .{});
}

fn formatGet(n: *Node, req: *Request, q: Query) RawError!void {
    const d = n.endpoint(q.get("d") orelse "") orelse return fail(req, .not_found, "drive");
    var dir = std.fs.cwd().openDir(d.path, .{}) catch return fail(req, .not_found, "unformatted");
    defer dir.close();
    var buf: [placement.layout.format_max]u8 = undefined;
    const bytes = dir.readFile(LocalBackend.format_file, &buf) catch |e| return switch (e) {
        error.FileNotFound => fail(req, .not_found, "unformatted"),
        else => fail(req, .internal_server_error, "io"),
    };
    try req.respond(bytes, .{});
}

/// Bootstrap: the formatting node writes identities onto every empty drive.
fn formatPut(n: *Node, req: *Request, q: Query, body: []const u8) RawError!void {
    const d = n.endpoint(q.get("d") orelse "") orelse return fail(req, .not_found, "drive");
    _ = placement.layout.FormatV2.parse(body) catch return fail(req, .bad_request, "format");
    var lb = LocalBackend.open(d.path) catch return fail(req, .internal_server_error, "open");
    defer lb.close();
    var buf: [placement.layout.format_max]u8 = undefined;
    if (lb.readFormat(&buf)) |cur| {
        if (std.mem.eql(u8, cur, body)) return req.respond("", .{});
        return fail(req, .conflict, "formatted");
    } else |e| if (e != error.NotFound) return fail(req, .internal_server_error, "io");
    lb.writeFormat(body) catch return fail(req, .internal_server_error, "io");
    try req.respond("", .{});
}

fn lockOp(n: *Node, req: *Request, op: []const u8, body: []const u8) RawError!void {
    const b = locks.decodeBody(body) orelse return fail(req, .bad_request, "lock");
    const now = std.time.milliTimestamp();
    const ok = if (std.mem.eql(u8, op, "lock"))
        try n.table.lock(b.resource, b.uid, now)
    else if (std.mem.eql(u8, op, "refresh"))
        n.table.refresh(b.resource, b.uid, now)
    else blk: {
        n.table.unlock(b.resource, b.uid);
        break :blk true;
    };
    if (!ok) return fail(req, .conflict, "held");
    try req.respond("", .{});
}

fn notify(n: *Node, req: *Request, body: []const u8) RawError!void {
    if (body.len > wire.max_notify) return fail(req, .payload_too_large, "notify");
    var it: wire.NoteIter = .{ .bytes = body };
    // Validate everything before applying anything.
    while (it.next() catch return fail(req, .bad_request, "notify")) |_| {}
    it = .{ .bytes = body };
    while (it.next() catch unreachable) |note| n.applyNote(note);
    try req.respond("", .{});
}

fn diskInfo(n: *Node, req: *Request, q: Query, arena: std.mem.Allocator) RawError!void {
    const d = n.endpoint(q.get("d") orelse "") orelse return fail(req, .not_found, "drive");
    const body = try std.fmt.allocPrint(arena, "total {d}\nused {d}\n", .{ d.total.load(.monotonic), d.used.load(.monotonic) });
    try req.respond(body, .{});
}

fn read(req: *Request, q: Query, l: *LocalBackend, key: PhysicalKey) RawError!void {
    var file = l.openRead(key) catch |e| return fail(req, statusOf(e), @errorName(e));
    defer file.close();
    const st = file.stat() catch return fail(req, .internal_server_error, "io");
    const size = st.size;
    var off: u64 = 0;
    var len: u64 = size;
    if (q.get("all") == null) {
        off = q.int(u64, "off") orelse return fail(req, .bad_request, "off");
        len = q.int(u64, "len") orelse return fail(req, .bad_request, "len");
        if (q.get("clip") != null) {
            len = if (off >= size) 0 else @min(len, size - off);
        } else if (off > size or len > size - off) return fail(req, .range_not_satisfiable, "range");
    }
    if (len > max_read and q.get("all") == null) return fail(req, .payload_too_large, "len");
    return sendRange(req, file, size, st.mtime, off, len, null);
}

/// Opens a blob for a peer's positional reads and sends its first window. A blob
/// larger than the window stays open under a lease the peer reads by id.
fn openLease(n: *Node, req: *Request, q: Query, l: *LocalBackend, key: PhysicalKey) RawError!void {
    const want = q.int(u64, "len") orelse return fail(req, .bad_request, "len");
    if (want > max_read) return fail(req, .payload_too_large, "len");
    var file = l.openRead(key) catch |e| return fail(req, statusOf(e), @errorName(e));
    const st = file.stat() catch {
        file.close();
        return fail(req, .internal_server_error, "io");
    };
    if (st.size <= want) {
        defer file.close();
        return sendRange(req, file, st.size, st.mtime, 0, st.size, null);
    }
    const now = std.time.milliTimestamp();
    const id = n.leases.open(file, now) catch |e| return fail(req, .service_unavailable, @errorName(e));
    const f = n.leases.acquire(id, now) orelse return fail(req, .internal_server_error, "lease");
    defer n.leases.release(id, std.time.milliTimestamp());
    return sendRange(req, f, st.size, st.mtime, 0, want, id);
}

/// Reads through a lease; 410 once it expired or was closed.
fn pread(n: *Node, req: *Request, q: Query) RawError!void {
    const id = q.int(u64, "h") orelse return fail(req, .bad_request, "h");
    const off = q.int(u64, "off") orelse return fail(req, .bad_request, "off");
    const want = q.int(u64, "len") orelse return fail(req, .bad_request, "len");
    if (want > max_read) return fail(req, .payload_too_large, "len");
    const f = n.leases.acquire(id, std.time.milliTimestamp()) orelse return fail(req, .gone, "lease");
    defer n.leases.release(id, std.time.milliTimestamp());
    const st = f.stat() catch return fail(req, .internal_server_error, "io");
    const len = if (off >= st.size) 0 else @min(want, st.size - off);
    return sendRange(req, f, st.size, st.mtime, off, len, null);
}

fn sendRange(req: *Request, file: std.fs.File, size: u64, mtime: i128, off: u64, len: u64, lease: ?u64) RawError!void {
    var sb: [24]u8 = undefined;
    var mb: [48]u8 = undefined;
    var hb: [24]u8 = undefined;
    const meta = [_]std.http.Header{
        .{ .name = "x-zkfsm-size", .value = std.fmt.bufPrint(&sb, "{d}", .{size}) catch unreachable },
        .{ .name = "x-zkfsm-mtime", .value = std.fmt.bufPrint(&mb, "{d}", .{mtime}) catch unreachable },
        .{ .name = "x-zkfsm-handle", .value = std.fmt.bufPrint(&hb, "{d}", .{lease orelse 0}) catch unreachable },
    };
    var wbuf: [64 * 1024]u8 = undefined;
    var bw = try req.respondStreaming(&wbuf, .{ .content_length = len, .respond_options = .{
        .extra_headers = if (lease != null) &meta else meta[0..2],
    } });
    var buf: [64 * 1024]u8 = undefined;
    var done: u64 = 0;
    while (done < len) {
        const want: usize = @intCast(@min(buf.len, len - done));
        const got = file.preadAll(buf[0..want], off + done) catch return error.WriteFailed;
        // The file shrank under us; the peer sees a short body and drops the connection.
        if (got == 0) return error.WriteFailed;
        bw.writer.writeAll(buf[0..got]) catch return error.WriteFailed;
        done += got;
    }
    bw.end() catch return error.WriteFailed;
}

fn scan(n: *Node, req: *Request, q: Query, l: *LocalBackend, arena: std.mem.Allocator) RawError!void {
    const sp = q.get("space") orelse return fail(req, .bad_request, "space");
    if (sp.len != 1) return fail(req, .bad_request, "space");
    const space = wire.parseSpace(sp[0]) orelse return fail(req, .bad_request, "space");
    var after: ?[32]u8 = null;
    if (q.get("after")) |a| {
        if (a.len != 32 or !wire.isHex(a)) return fail(req, .bad_request, "after");
        after = a[0..32].*;
    }
    var page: backend.drive.ScanPage = .{};
    defer page.deinit(n.gpa);
    scanLocal(n.gpa, arena, l.root, space, after, &page) catch return fail(req, .internal_server_error, "scan");
    var out: std.Io.Writer.Allocating = .init(arena);
    for (page.keys.items) |k| {
        out.writer.writeAll(&k.hex) catch return error.OutOfMemory;
        out.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    try req.respond(out.written(), .{ .extra_headers = &.{.{ .name = "x-zkfsm-more", .value = if (page.more) "1" else "0" }} });
}

fn lessName(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Sorted names of the entries in `dir` accepted by `keep`.
fn sortedNames(arena: std.mem.Allocator, dir: std.fs.Dir, comptime keep: fn (std.fs.Dir.Entry) ?[]const u8) error{ OutOfMemory, IoFailed }![][]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next() catch return error.IoFailed) |e| {
        const name = keep(e) orelse continue;
        try names.append(arena, try arena.dupe(u8, name));
    }
    std.mem.sort([]const u8, names.items, {}, lessName);
    return names.items;
}

fn fanDir(e: std.fs.Dir.Entry) ?[]const u8 {
    return if (e.kind == .directory and e.name.len == 2 and wire.isHex(e.name)) e.name else null;
}

fn dataName(e: std.fs.Dir.Entry) ?[]const u8 {
    return if (e.kind == .file and e.name.len == 32 and wire.isHex(e.name)) e.name else null;
}

fn metaName(e: std.fs.Dir.Entry) ?[]const u8 {
    if (e.kind != .file or e.name.len != 37 or !std.mem.endsWith(u8, e.name, ".meta")) return null;
    return if (wire.isHex(e.name[0..32])) e.name[0..32] else null;
}

/// Keys of `space` in ascending order strictly after `after`, one page at most.
pub fn scanLocal(gpa: std.mem.Allocator, arena: std.mem.Allocator, root: std.fs.Dir, space: backend.KeySpace, after: ?[32]u8, out: *backend.drive.ScanPage) error{ OutOfMemory, IoFailed }!void {
    const limit = backend.drive.scan_page_max;
    var top = root.openDir(@tagName(space), .{ .iterate = true }) catch |e| return if (e == error.FileNotFound) {} else error.IoFailed;
    defer top.close();
    const lo: []const u8 = if (after) |a| &a else "";
    if (space == .system) {
        for (try sortedNames(arena, top, metaName)) |name| {
            if (std.mem.order(u8, name, lo) != .gt) continue;
            if (out.keys.items.len == limit) {
                out.more = true;
                return;
            }
            try out.keys.append(gpa, .{ .space = space, .hex = name[0..32].* });
        }
        return;
    }
    for (try sortedNames(arena, top, fanDir)) |l1| {
        if (lo.len > 0 and std.mem.order(u8, l1, lo[0..2]) == .lt) continue;
        var d1 = top.openDir(l1, .{ .iterate = true }) catch return error.IoFailed;
        defer d1.close();
        for (try sortedNames(arena, d1, fanDir)) |l2| {
            if (lo.len > 0 and std.mem.eql(u8, l1, lo[0..2]) and std.mem.order(u8, l2, lo[2..4]) == .lt) continue;
            var d2 = d1.openDir(l2, .{ .iterate = true }) catch return error.IoFailed;
            defer d2.close();
            const leaf = if (space == .data) try sortedNames(arena, d2, dataName) else try sortedNames(arena, d2, metaName);
            for (leaf) |name| {
                if (std.mem.order(u8, name, lo) != .gt) continue;
                if (out.keys.items.len == limit) {
                    out.more = true;
                    return;
                }
                try out.keys.append(gpa, .{ .space = space, .hex = name[0..32].* });
            }
        }
    }
}

/// Streamed write: frames build a temp file; the commit frame renames it into place.
fn write(n: *Node, req: *Request, q: Query) RawError!void {
    if (!n.drives_open.load(.acquire)) return fail(req, .service_unavailable, "starting");
    const d = n.localDrive(q.get("d") orelse "") orelse return fail(req, .not_found, "drive");
    const h = d.set.acquire(d.slot) orelse return fail(req, .service_unavailable, "offline");
    defer d.set.release(d.slot);
    var rb: [64 * 1024]u8 = undefined;
    const r = req.readerExpectContinue(&rb) catch return error.ReadFailed;
    var p = h.local.begin() catch |e| return fail(req, statusOf(e), @errorName(e));
    var live = true;
    defer if (live) p.abort();
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const f = wire.readFrame(r) catch |e| switch (e) {
            // The writer went away without committing: drop the temp file.
            error.EndOfStream, error.ReadFailed => return error.ReadFailed,
            error.BadFrame => return fail(req, .bad_request, "frame"),
        };
        switch (f) {
            .data => |len| {
                var left: usize = len;
                while (left > 0) {
                    const chunk = @min(left, buf.len);
                    r.readSliceAll(buf[0..chunk]) catch return error.ReadFailed;
                    p.writeAll(buf[0..chunk]) catch |e| return fail(req, statusOf(e), @errorName(e));
                    left -= chunk;
                }
            },
            .patch => |pt| {
                r.readSliceAll(buf[0..pt.len]) catch return error.ReadFailed;
                p.file.pwriteAll(buf[0..pt.len], pt.off) catch return fail(req, .internal_server_error, "io");
            },
            .abort => {
                _ = r.discardRemaining() catch return error.ReadFailed;
                return req.respond("", .{});
            },
            .commit => |key| {
                if (key.space != .data) return fail(req, .bad_request, "space");
                _ = r.discardRemaining() catch return error.ReadFailed;
                live = false;
                p.commit(key) catch |e| return fail(req, statusOf(e), @errorName(e));
                return req.respond("", .{});
            },
        }
    }
}

test "local scan pages in key order" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var keys: [5]PhysicalKey = undefined;
    for (&keys, 0..) |*k, i| {
        k.* = .{ .space = .record, .hex = undefined };
        _ = std.fmt.bufPrint(&k.hex, "{x:0>32}", .{@as(u128, 5 - i) * 0x1111_0000_0000_0000_0000_0000_0000}) catch unreachable;
        try lb.backend().putRecord(k.*, "x");
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var page: backend.drive.ScanPage = .{};
    defer page.deinit(gpa);
    try scanLocal(gpa, arena.allocator(), lb.root, .record, null, &page);
    try std.testing.expectEqual(@as(usize, 5), page.keys.items.len);
    for (1..5) |i| try std.testing.expect(std.mem.order(u8, &page.keys.items[i - 1].hex, &page.keys.items[i].hex) == .lt);
    var rest: backend.drive.ScanPage = .{};
    defer rest.deinit(gpa);
    try scanLocal(gpa, arena.allocator(), lb.root, .record, page.keys.items[2].hex, &rest);
    try std.testing.expectEqual(@as(usize, 2), rest.keys.items.len);
    try std.testing.expectEqualSlices(u8, &page.keys.items[3].hex, &rest.keys.items[0].hex);
}
