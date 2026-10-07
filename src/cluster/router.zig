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
    /// Raw capacity of the pool's drives; refreshed with `free`.
    total: std.atomic.Value(u64) = .init(0),
    mode: std.atomic.Value(Mode) = .init(.active),
};

/// `draining`: no new keys, looked up last, keys move out. `retired`: decommissioned.
pub const Mode = enum(u8) { active, draining, retired };

pub const max_pools = 64;

/// Serializes record writes with pool moves of the same key while any pool drains.
pub const KeyGuard = struct {
    ctx: *anyopaque,
    lock: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!u64,
    unlock: *const fn (ctx: *anyopaque, token: u64) void,
};

pub const Router = struct {
    gpa: std.mem.Allocator,
    pools: []Pool,
    guard: ?KeyGuard = null,
    /// Some pool is draining: writes take the key guard and lookups span all pools.
    moving: std.atomic.Value(bool) = .init(false),

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

    pub fn at(pool: *const Pool, key: PhysicalKey) iface.StorageBackend {
        return pool.sets[setIndex(pool, key)];
    }

    pub fn mode(self: *const Router, p: usize) Mode {
        return self.pools[p].mode.load(.acquire);
    }

    pub fn setMode(self: *Router, p: usize, m: Mode) void {
        self.pools[p].mode.store(m, .release);
        var any = false;
        for (self.pools) |*q| any = any or q.mode.load(.acquire) == .draining;
        self.moving.store(any, .release);
    }

    /// Pool indexes to search: active pools first, then draining, then retired.
    pub fn order(self: *const Router, buf: *[max_pools]usize) []usize {
        var n: usize = 0;
        inline for (.{ Mode.active, Mode.draining, Mode.retired }) |want| {
            for (self.pools, 0..) |*p, i| if (p.mode.load(.acquire) == want and n < max_pools) {
                buf[n] = i;
                n += 1;
            };
        }
        return buf[0..n];
    }

    /// Pool for a new key: the active one with the most free space (first on ties).
    pub fn pickPool(self: *const Router) usize {
        var best: ?usize = null;
        var most: u64 = 0;
        for (self.pools, 0..) |*p, i| {
            if (p.mode.load(.acquire) != .active) continue;
            const f = p.free.load(.monotonic);
            if (best == null or f > most) {
                best = i;
                most = f;
            }
        }
        return best orelse self.systemPool();
    }

    /// System keys live in the first active pool.
    pub fn systemPool(self: *const Router) usize {
        for (self.pools, 0..) |*p, i| if (p.mode.load(.acquire) == .active) return i;
        for (self.pools, 0..) |*p, i| if (p.mode.load(.acquire) != .retired) return i;
        return 0;
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!iface.ObjectMeta {
        const self = cast(ctx);
        return at(&self.pools[self.pickPool()], key).put(key, source, opts);
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?iface.Range, sink: *std.Io.Writer) Error!iface.ObjectMeta {
        const self = cast(ctx);
        var first: Error = error.NotFound;
        var ob: [max_pools]usize = undefined;
        for (self.order(&ob)) |i| {
            return at(&self.pools[i], key).get(key, range, sink) catch |e| {
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
        var ob: [max_pools]usize = undefined;
        for (self.order(&ob)) |i| {
            return at(&self.pools[i], key).stat(key) catch |e| {
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
        const self = cast(ctx);
        const tok = try self.lockIfMoving(key);
        defer self.unlockToken(tok);
        return self.deleteIn(key, true);
    }

    pub fn lockKey(self: *Router, key: PhysicalKey) Error!?u64 {
        const g = self.guard orelse return null;
        return try g.lock(g.ctx, key);
    }

    fn lockIfMoving(self: *Router, key: PhysicalKey) Error!?u64 {
        if (!self.moving.load(.acquire)) return null;
        return self.lockKey(key);
    }

    pub fn unlockToken(self: *Router, tok: ?u64) void {
        if (tok) |t| self.guard.?.unlock(self.guard.?.ctx, t);
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        const self = cast(ctx);
        if (self.moving.load(.acquire)) return self.putRecordMoving(key, bytes);
        if (key.space == .system or self.pools.len == 1) return at(&self.pools[self.systemPoolFor(key)], key).putRecord(key, bytes);
        // Overwrites stay in the pool that already holds the name.
        for (self.pools) |*p| {
            if (p.mode.load(.acquire) == .retired) continue;
            const cur = at(p, key).getRecord(key, self.gpa) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            self.gpa.free(cur);
            return at(p, key).putRecord(key, bytes);
        }
        return at(&self.pools[self.pickPool()], key).putRecord(key, bytes);
    }

    fn systemPoolFor(self: *const Router, key: PhysicalKey) usize {
        return if (key.space == .system) self.systemPool() else 0;
    }

    /// Writes land in an active pool; a copy left in a draining pool is dropped.
    fn putRecordMoving(self: *Router, key: PhysicalKey, bytes: []const u8) Error!void {
        const tok = try self.lockKey(key);
        defer self.unlockToken(tok);
        var target: ?usize = null;
        if (key.space != .system) for (self.pools, 0..) |*p, i| {
            if (p.mode.load(.acquire) != .active) continue;
            const cur = at(p, key).getRecord(key, self.gpa) catch |e| switch (e) {
                error.NotFound => continue,
                else => return e,
            };
            self.gpa.free(cur);
            target = i;
            break;
        };
        const t = target orelse if (key.space == .system) self.systemPool() else self.pickPool();
        try at(&self.pools[t], key).putRecord(key, bytes);
        for (self.pools, 0..) |*p, i| {
            if (i == t or p.mode.load(.acquire) == .active) continue;
            at(p, key).deleteRecord(key) catch {};
        }
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        const self = cast(ctx);
        if (key.space == .system and !self.moving.load(.acquire)) return at(&self.pools[self.systemPool()], key).getRecord(key, gpa);
        var first: Error = error.NotFound;
        var ob: [max_pools]usize = undefined;
        for (self.order(&ob)) |i| {
            return at(&self.pools[i], key).getRecord(key, gpa) catch |e| {
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
    // A draining pool takes no new keys and is searched last.
    r.setMode(0, .draining);
    try std.testing.expect(r.moving.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), r.pickPool());
    try std.testing.expectEqual(@as(usize, 1), r.systemPool());
    var ob: [max_pools]usize = undefined;
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, r.order(&ob));
    r.setMode(0, .retired);
    try std.testing.expect(!r.moving.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), r.systemPool());
}
