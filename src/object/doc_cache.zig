//! In-memory copies of bucket documents (config, subresources, default encryption):
//! read on every request, rarely written. Absent documents are cached too.
const std = @import("std");
const backend = @import("../backend/root.zig");

pub const DocCache = struct {
    mutex: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged([32]u8, ?[]u8) = .empty,
    /// Bumped by every write and clear, so a slow read cannot store a stale copy.
    gen: u64 = 0,
    /// A local write peers have not been told about yet.
    dirty: std.atomic.Value(bool) = .init(false),

    pub fn deinit(c: *DocCache, gpa: std.mem.Allocator) void {
        c.clear(gpa);
        c.map.deinit(gpa);
    }

    pub fn clear(c: *DocCache, gpa: std.mem.Allocator) void {
        c.mutex.lock();
        defer c.mutex.unlock();
        c.gen += 1;
        var it = c.map.valueIterator();
        while (it.next()) |v| if (v.*) |b| gpa.free(b);
        c.map.clearRetainingCapacity();
    }

    pub const Hit = union(enum) { miss: u64, absent, found: []u8 };

    /// A copy in `arena`, or the generation to pass to `fill` after reading the store.
    pub fn get(c: *DocCache, arena: std.mem.Allocator, key: backend.PhysicalKey) error{OutOfMemory}!Hit {
        c.mutex.lock();
        defer c.mutex.unlock();
        const v = c.map.get(key.hex) orelse return .{ .miss = c.gen };
        return if (v) |b| .{ .found = try arena.dupe(u8, b) } else .absent;
    }

    /// Stores what a read found, unless anything changed since `gen` was taken.
    pub fn fill(c: *DocCache, gpa: std.mem.Allocator, key: backend.PhysicalKey, gen: u64, bytes: ?[]const u8) void {
        const copy: ?[]u8 = if (bytes) |b| (gpa.dupe(u8, b) catch return) else null;
        c.mutex.lock();
        defer c.mutex.unlock();
        if (c.gen != gen or c.map.contains(key.hex)) {
            if (copy) |b| gpa.free(b);
            return;
        }
        c.map.put(gpa, key.hex, copy) catch if (copy) |b| gpa.free(b);
    }

    /// Forgets `key` after a local write and marks peers as owed a notice.
    pub fn wrote(c: *DocCache, gpa: std.mem.Allocator, key: backend.PhysicalKey) void {
        c.mutex.lock();
        defer c.mutex.unlock();
        c.gen += 1;
        if (c.map.fetchRemove(key.hex)) |kv| if (kv.value) |b| gpa.free(b);
        c.dirty.store(true, .release);
    }
};

test "doc cache keeps hits and misses until a write or clear" {
    const gpa = std.testing.allocator;
    var c: DocCache = .{};
    defer c.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const k1: backend.PhysicalKey = .{ .space = .system, .hex = [_]u8{'1'} ** 32 };
    const k2: backend.PhysicalKey = .{ .space = .system, .hex = [_]u8{'2'} ** 32 };
    const g = (try c.get(arena.allocator(), k1)).miss;
    c.fill(gpa, k1, g, "doc");
    c.fill(gpa, k2, g, null);
    try std.testing.expectEqualStrings("doc", (try c.get(arena.allocator(), k1)).found);
    try std.testing.expect((try c.get(arena.allocator(), k2)) == .absent);
    c.wrote(gpa, k1);
    try std.testing.expect(c.dirty.load(.acquire));
    try std.testing.expect((try c.get(arena.allocator(), k1)) == .miss);
    // A read that started before the write must not be stored.
    c.fill(gpa, k1, g, "old");
    try std.testing.expect((try c.get(arena.allocator(), k1)) == .miss);
    c.clear(gpa);
    try std.testing.expect((try c.get(arena.allocator(), k2)) == .miss);
}
