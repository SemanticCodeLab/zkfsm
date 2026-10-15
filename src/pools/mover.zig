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
    /// Fewer than k shards of a deleted blob (a delete that missed a drive) were removed.
    purged,
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

/// True when an active pool holds the key. A blob counts only when it reads back
/// whole: a crash mid-move can leave a few committed shards that stat alone accepts.
fn activeHolder(r: *Router, key: PhysicalKey, src_pool: usize, gpa: std.mem.Allocator, buf: []u8) Error!bool {
    for (r.pools, 0..) |*p, i| {
        if (i == src_pool or p.mode.load(.acquire) != .active) continue;
        const b = Router.at(p, key);
        if (key.space == .data) {
            const st = b.stat(key) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            var d: std.Io.Writer.Discarding = .init(buf);
            const got = b.get(key, null, &d.writer) catch |e| switch (e) {
                // Unreadable remnant: the move rewrites it.
                error.NotFound, error.IoFailed => continue,
                else => return e,
            };
            if (got.size != st.size or d.fullCount() != st.size) continue;
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
    if (try activeHolder(r, key, src_pool, gpa, &.{})) {
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
        if (e != error.NotFound) {
            // Remnants of a move whose source delete missed a drive that was down.
            if (!try activeHolder(r, key, src_pool, r.gpa, buf)) return e;
            return dropSource(src, key);
        }
        src.delete(key) catch {};
        return .{ .outcome = .gone };
    };
    if (try activeHolder(r, key, src_pool, r.gpa, buf)) return dropSource(src, key);
    const dst = try destination(r, key, src_pool);
    // An unreadable earlier copy is rewritten, but never deleted if the rewrite fails.
    const prior = if (dst.stat(key)) |_| true else |_| false;
    var rr: RangeReader = .init(src, key, meta.size, buf);
    _ = dst.put(key, &rr.interface, .{ .size_hint = meta.size }) catch |e| {
        if (!prior) dst.delete(key) catch {};
        return if (rr.err) |re| re else e;
    };
    const got = dst.stat(key) catch |e| {
        if (!prior) dst.delete(key) catch {};
        return e;
    };
    if (rr.err != null or got.size != meta.size) {
        if (!prior) dst.delete(key) catch {};
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

/// An active pool holds a whole copy: drop the source. Nothing deleted is no progress
/// (the shards sit on drives out of reach), so the drain retries it.
fn dropSource(src: backend.StorageBackend, key: PhysicalKey) Error!Result {
    src.delete(key) catch |e| return if (e == error.NotFound) .{ .outcome = .gone } else e;
    return .{ .outcome = .dup };
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

/// A local drive whose stat or get can be made to fail, standing in for an erasure
/// set holding a few shards of a blob.
const Flaky = struct {
    lb: backend.local.LocalBackend,
    stat_err: ?Error = null,
    get_err: ?Error = null,

    fn inner(ctx: *anyopaque) backend.StorageBackend {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        return f.lb.backend();
    }
    fn put(ctx: *anyopaque, k: PhysicalKey, s: *std.Io.Reader, o: backend.PutOptions) Error!backend.ObjectMeta {
        return inner(ctx).put(k, s, o);
    }
    fn get(ctx: *anyopaque, k: PhysicalKey, r: ?backend.Range, w: *std.Io.Writer) Error!backend.ObjectMeta {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (f.get_err) |e| return e;
        return inner(ctx).get(k, r, w);
    }
    fn stat(ctx: *anyopaque, k: PhysicalKey) Error!backend.ObjectMeta {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (f.stat_err) |e| return e;
        return inner(ctx).stat(k);
    }
    fn delete(ctx: *anyopaque, k: PhysicalKey) Error!void {
        return inner(ctx).delete(k);
    }
    fn list(ctx: *anyopaque, s: backend.KeySpace, cb: backend.ListCallback) Error!void {
        return inner(ctx).list(s, cb);
    }
    fn putRecord(ctx: *anyopaque, k: PhysicalKey, b: []const u8) Error!void {
        return inner(ctx).putRecord(k, b);
    }
    fn getRecord(ctx: *anyopaque, k: PhysicalKey, a: std.mem.Allocator) Error![]u8 {
        return inner(ctx).getRecord(k, a);
    }
    fn deleteRecord(ctx: *anyopaque, k: PhysicalKey) Error!void {
        return inner(ctx).deleteRecord(k);
    }
    fn sync(ctx: *anyopaque) Error!void {
        return inner(ctx).sync();
    }
    const vt: backend.StorageBackend.VTable = .{ .put = put, .get = get, .stat = stat, .delete = delete, .list = list, .putRecord = putRecord, .getRecord = getRecord, .deleteRecord = deleteRecord, .sync = sync };
    fn sb(f: *Flaky) backend.StorageBackend {
        return .{ .ctx = f, .capabilities = .{ .range_read = true }, .vtable = &vt };
    }
};

test "a resumed move drops remnants only when an active pool holds a whole copy" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &pb);
    var p0b: [std.fs.max_path_bytes]u8 = undefined;
    var p1b: [std.fs.max_path_bytes]u8 = undefined;
    var src: Flaky = .{ .lb = try backend.local.LocalBackend.open(try std.fmt.bufPrint(&p0b, "{s}/a", .{root})) };
    defer src.lb.close();
    var dst: Flaky = .{ .lb = try backend.local.LocalBackend.open(try std.fmt.bufPrint(&p1b, "{s}/b", .{root})) };
    defer dst.lb.close();
    const s0 = [_]backend.StorageBackend{src.sb()};
    const s1 = [_]backend.StorageBackend{dst.sb()};
    var pools = [_]cluster.router.Pool{ .{ .sets = &s0, .seed = 1 }, .{ .sets = &s1, .seed = 2 } };
    pools[1].free.store(1 << 30, .monotonic);
    var r: Router = .{ .gpa = a, .pools = &pools };
    r.setMode(0, .draining);
    const buf = try a.alloc(u8, chunk);
    defer a.free(buf);
    const key: PhysicalKey = .{ .space = .data, .hex = "0123456789abcdef0123456789abcdef".* };
    const body = "blob moved before the mover was killed";
    var rd: std.Io.Reader = .fixed(body);
    _ = try src.sb().put(key, &rd, .{});

    // Source unreadable (shards on a drive that missed the delete), no copy elsewhere:
    // the key stays and the error is reported, never dropped.
    src.stat_err = error.ReadQuorum;
    try std.testing.expectError(error.ReadQuorum, moveKey(&r, a, key, 0, buf));
    _ = try src.lb.backend().stat(key);

    // A copy that stats but does not read back (a crash mid-commit) is no holder:
    // the move rewrites it from the source.
    src.stat_err = null;
    rd = .fixed("short");
    _ = try dst.sb().put(key, &rd, .{});
    dst.get_err = error.IoFailed;
    // With the source unreadable as well, the rewrite fails and the old copy stays.
    src.get_err = error.IoFailed;
    try std.testing.expectError(error.IoFailed, moveKey(&r, a, key, 0, buf));
    _ = try dst.lb.backend().stat(key);
    _ = try src.lb.backend().stat(key);
    src.get_err = null;
    const res = moveKey(&r, a, key, 0, buf);
    dst.get_err = null;
    try std.testing.expectEqual(Outcome.moved, (try res).outcome);
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    _ = try dst.sb().get(key, null, &out.writer);
    try std.testing.expectEqualStrings(body, out.written());
    try std.testing.expectError(error.NotFound, src.lb.backend().stat(key));

    // Remnant left behind after a whole copy landed: dropped as a duplicate.
    rd = .fixed(body[0..4]);
    _ = try src.sb().put(key, &rd, .{});
    src.stat_err = error.IoFailed;
    try std.testing.expectEqual(Outcome.dup, (try moveKey(&r, a, key, 0, buf)).outcome);
    try std.testing.expectError(error.NotFound, src.lb.backend().stat(key));
}
