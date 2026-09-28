//! Router: one StorageBackend over every pool and erasure set. A key maps to a set by
//! hashing it within its pool; new data goes to the pool with the most room, reads and
//! deletes find a key in whichever pool holds it. System keys always live in pool 0.
const std = @import("std");
const iface = @import("../backend/root.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;

pub const Pool = struct {
    sets: []const iface.StorageBackend,
    seed: u64,
    /// Estimated free bytes; refreshed in the background.
    free: std.atomic.Value(u64) = .init(0),
};

pub const Router = struct {
    gpa: std.mem.Allocator,
    pools: []Pool,

    pub fn backend(self: *Router) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = .{ .atomic_rename = true, .durable_sync = true, .range_read = true, .checksums = true }, .vtable = &vtable };
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

    fn cast(ctx: *anyopaque) *Router {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn setIndex(pool: *const Pool, key: PhysicalKey) usize {
        return @intCast(std.hash.Wyhash.hash(pool.seed, &key.hex) % pool.sets.len);
    }

    fn at(pool: *const Pool, key: PhysicalKey) iface.StorageBackend {
        return pool.sets[setIndex(pool, key)];
    }

    /// Pool for a new key: the one with the most free space (first on ties).
    pub fn pickPool(self: *const Router) usize {
        var best: usize = 0;
        var most: u64 = 0;
        for (self.pools, 0..) |*p, i| {
            const f = p.free.load(.monotonic);
            if (i == 0 or f > most) {
                best = i;
                most = f;
            }
        }
        return best;
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!iface.ObjectMeta {
        const self = cast(ctx);
        return at(&self.pools[self.pickPool()], key).put(key, source, opts);
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?iface.Range, sink: *std.Io.Writer) Error!iface.ObjectMeta {
        const self = cast(ctx);
        var first: Error = error.NotFound;
        for (self.pools) |*p| {
            return at(p, key).get(key, range, sink) catch |e| {
                if (e != error.NotFound) {
                    if (first == error.NotFound) first = e;
                }
                continue;
            };
        }
        return first;
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!iface.ObjectMeta {
        const self = cast(ctx);
        var first: Error = error.NotFound;
        for (self.pools) |*p| {
            return at(p, key).stat(key) catch |e| {
                if (e != error.NotFound and first == error.NotFound) first = e;
                continue;
            };
        }
        return first;
    }

    fn deleteIn(self: *Router, key: PhysicalKey, comptime record: bool) Error!void {
        var removed = false;
        var first: Error = error.NotFound;
        for (self.pools) |*p| {
            const b = at(p, key);
            const r = if (record) b.deleteRecord(key) else b.delete(key);
            r catch |e| {
                if (e != error.NotFound and first == error.NotFound) first = e;
                continue;
            };
            removed = true;
        }
        if (!removed) return first;
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        return cast(ctx).deleteIn(key, false);
    }

    fn deleteRecord(ctx: *anyopaque, key: PhysicalKey) Error!void {
        return cast(ctx).deleteIn(key, true);
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        const self = cast(ctx);
        if (key.space == .system or self.pools.len == 1) return at(&self.pools[0], key).putRecord(key, bytes);
        // Overwrites stay in the pool that already holds the name.
        for (self.pools) |*p| {
            const cur = at(p, key).getRecord(key, self.gpa) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            self.gpa.free(cur);
            return at(p, key).putRecord(key, bytes);
        }
        return at(&self.pools[self.pickPool()], key).putRecord(key, bytes);
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        const self = cast(ctx);
        if (key.space == .system) return at(&self.pools[0], key).getRecord(key, gpa);
        var first: Error = error.NotFound;
        for (self.pools) |*p| {
            return at(p, key).getRecord(key, gpa) catch |e| {
                if (e != error.NotFound and first == error.NotFound) first = e;
                continue;
            };
        }
        return first;
    }

    fn list(ctx: *anyopaque, space: iface.KeySpace, cb: iface.ListCallback) Error!void {
        const self = cast(ctx);
        var ok = false;
        var first: Error = error.IoFailed;
        for (self.pools) |*p| for (p.sets) |s| {
            s.list(space, cb) catch |e| {
                if (e == error.OutOfMemory) return e;
                first = e;
                continue;
            };
            ok = true;
        };
        if (!ok) return first;
    }

    fn sync(ctx: *anyopaque) Error!void {
        const self = cast(ctx);
        for (self.pools) |*p| for (p.sets) |s| s.sync() catch {};
    }
};

test "set hashing is stable and spreads keys; the emptiest pool wins" {
    var sets: [4]iface.StorageBackend = undefined;
    var pools = [_]Pool{ .{ .sets = &sets, .seed = 1 }, .{ .sets = sets[0..2], .seed = 2 } };
    var hits: [4]usize = @splat(0);
    for (0..400) |i| {
        var k: PhysicalKey = .{ .space = .data, .hex = undefined };
        _ = std.fmt.bufPrint(&k.hex, "{x:0>32}", .{i * 7919}) catch unreachable;
        const s = Router.setIndex(&pools[0], k);
        try std.testing.expectEqual(s, Router.setIndex(&pools[0], k));
        hits[s] += 1;
    }
    for (hits) |h| try std.testing.expect(h > 50);
    var r: Router = .{ .gpa = std.testing.allocator, .pools = &pools };
    pools[0].free.store(10, .monotonic);
    pools[1].free.store(20, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), r.pickPool());
    pools[0].free.store(30, .monotonic);
    try std.testing.expectEqual(@as(usize, 0), r.pickPool());
}
