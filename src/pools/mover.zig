//! Moves one physical key out of a pool into the active pools. The key guard
//! serializes it with record writers and other movers; the destination copy is
//! complete and verified before the source copy is removed.
const std = @import("std");
const backend = @import("../backend/root.zig");
const cluster = @import("../cluster/root.zig");

const Router = cluster.router.Router;
const PhysicalKey = backend.PhysicalKey;
const Error = backend.Error;

pub const Outcome = enum {
    moved,
    /// Deleted concurrently; nothing to move.
    gone,
    /// An active pool already held the key; the stale source copy was dropped.
    dup,
};

pub const Result = struct { outcome: Outcome, bytes: u64 = 0 };

pub const chunk = 4 * 1024 * 1024;

/// `buf` (at least `chunk` bytes) stages data blobs in ranged reads.
pub fn moveKey(r: *Router, gpa: std.mem.Allocator, key: PhysicalKey, src_pool: usize, buf: []u8) Error!Result {
    const tok = try r.lockKey(key);
    defer r.unlockToken(tok);
    const src = Router.at(&r.pools[src_pool], key);
    return switch (key.space) {
        .data => moveData(r, key, src_pool, src, buf),
        .record, .system => moveRecord(r, gpa, key, src_pool, src),
    };
}

fn activeHolder(r: *Router, key: PhysicalKey, src_pool: usize, gpa: std.mem.Allocator) Error!bool {
    for (r.pools, 0..) |*p, i| {
        if (i == src_pool or p.mode.load(.acquire) != .active) continue;
        const b = Router.at(p, key);
        if (key.space == .data) {
            _ = b.stat(key) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
        } else {
            const cur = b.getRecord(key, gpa) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            gpa.free(cur);
        }
        return true;
    }
    return false;
}

fn destination(r: *Router, key: PhysicalKey, src_pool: usize) Error!backend.StorageBackend {
    const d = if (key.space == .system) r.systemPool() else r.pickPool();
    if (d == src_pool or r.pools[d].mode.load(.acquire) != .active) return error.NoSpace;
    return Router.at(&r.pools[d], key);
}

fn moveRecord(r: *Router, gpa: std.mem.Allocator, key: PhysicalKey, src_pool: usize, src: backend.StorageBackend) Error!Result {
    const bytes = src.getRecord(key, gpa) catch |e| {
        if (e != error.NotFound) return e;
        // Listed but unreadable: shards a missed delete left behind.
        src.deleteRecord(key) catch {};
        return .{ .outcome = .gone };
    };
    defer gpa.free(bytes);
    if (try activeHolder(r, key, src_pool, gpa)) {
        src.deleteRecord(key) catch |e| if (e != error.NotFound) return e;
        return .{ .outcome = .dup };
    }
    const dst = try destination(r, key, src_pool);
    try dst.putRecord(key, bytes);
    src.deleteRecord(key) catch |e| if (e != error.NotFound) return e;
    return .{ .outcome = .moved, .bytes = bytes.len };
}

fn moveData(r: *Router, key: PhysicalKey, src_pool: usize, src: backend.StorageBackend, buf: []u8) Error!Result {
    const meta = src.stat(key) catch |e| {
        if (e != error.NotFound) return e;
        src.delete(key) catch {};
        return .{ .outcome = .gone };
    };
    if (try activeHolder(r, key, src_pool, r.gpa)) {
        src.delete(key) catch |e| if (e != error.NotFound) return e;
        return .{ .outcome = .dup };
    }
    const dst = try destination(r, key, src_pool);
    var rr: RangeReader = .init(src, key, meta.size, buf);
    _ = dst.put(key, &rr.interface, .{ .size_hint = meta.size }) catch |e| {
        dst.delete(key) catch {};
        return if (rr.err) |re| re else e;
    };
    const got = dst.stat(key) catch |e| {
        dst.delete(key) catch {};
        return e;
    };
    if (rr.err != null or got.size != meta.size) {
        dst.delete(key) catch {};
        return rr.err orelse error.IoFailed;
    }
    src.delete(key) catch |e| {
        // Deleted while copying: the copy must not outlive the object.
        if (e == error.NotFound) {
            dst.delete(key) catch {};
            return .{ .outcome = .gone };
        }
        return e;
    };
    return .{ .outcome = .moved, .bytes = meta.size };
}

/// Streams a blob through ranged reads; a failed read fails the stream instead of
/// ending it early, so a truncated copy is never committed.
pub const RangeReader = struct {
    src: backend.StorageBackend,
    key: PhysicalKey,
    size: u64,
    pos: u64 = 0,
    err: ?Error = null,
    interface: std.Io.Reader,

    pub fn init(src: backend.StorageBackend, key: PhysicalKey, size: u64, buf: []u8) RangeReader {
        return .{ .src = src, .key = key, .size = size, .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const self: *RangeReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (self.pos >= self.size) return error.EndOfStream;
        if (io_r.seek > 0) {
            const live = io_r.end - io_r.seek;
            std.mem.copyForwards(u8, io_r.buffer[0..live], io_r.buffer[io_r.seek..io_r.end]);
            io_r.seek = 0;
            io_r.end = live;
        }
        const room = io_r.buffer.len - io_r.end;
        if (room == 0) return 0;
        const n: usize = @intCast(@min(room, self.size - self.pos));
        var fw: std.Io.Writer = .fixed(io_r.buffer[io_r.end..][0..n]);
        _ = self.src.get(self.key, .{ .offset = self.pos, .length = n }, &fw) catch |e| {
            self.err = e;
            return error.ReadFailed;
        };
        if (fw.end != n) {
            self.err = error.IoFailed;
            return error.ReadFailed;
        }
        io_r.end += n;
        self.pos += n;
        return 0;
    }
};

test "range reader streams a blob in chunks and fails on a short read" {
    const Fake = struct {
        data: []const u8,
        fn cast(ctx: *anyopaque) *@This() {
            return @ptrCast(@alignCast(ctx));
        }
        fn get(ctx: *anyopaque, _: PhysicalKey, range: ?backend.Range, sink: *std.Io.Writer) Error!backend.ObjectMeta {
            const s = cast(ctx);
            const rg = range.?;
            if (rg.offset >= s.data.len) return error.IoFailed;
            sink.writeAll(s.data[@intCast(rg.offset)..@intCast(@min(s.data.len, rg.offset + rg.length))]) catch return error.WriteFailed;
            return .{ .size = s.data.len, .mtime_ns = 0 };
        }
    };
    var data: [1000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7);
    var fake: Fake = .{ .data = &data };
    const vt: backend.StorageBackend.VTable = .{ .put = undefined, .get = Fake.get, .stat = undefined, .delete = undefined, .list = undefined, .putRecord = undefined, .getRecord = undefined, .deleteRecord = undefined, .sync = undefined };
    const b: backend.StorageBackend = .{ .ctx = &fake, .capabilities = .{}, .vtable = &vt };
    const key: PhysicalKey = .{ .space = .data, .hex = @splat('a') };
    var buf: [64]u8 = undefined;
    var rr: RangeReader = .init(b, key, data.len, &buf);
    const out = try rr.interface.allocRemaining(std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, &data, out);
    // The source is shorter than its recorded size: the stream fails.
    var short: RangeReader = .init(b, key, data.len + 10, &buf);
    try std.testing.expectError(error.ReadFailed, short.interface.allocRemaining(std.testing.allocator, .unlimited));
    try std.testing.expect(short.err != null);
}
