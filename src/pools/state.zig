//! Cluster-wide pool state: per deployment pool its decommission progress, and the
//! running rebalance. Stored as one JSON system record; the highest epoch wins.
const std = @import("std");

pub const DecomStatus = enum { none, draining, complete, canceled, failed };
pub const RebalStatus = enum { none, started, completed, stopped, failed };

pub const Decom = struct {
    status: DecomStatus = .none,
    start_ns: i64 = 0,
    end_ns: i64 = 0,
    /// Pool capacity and free bytes when draining started.
    total_size: u64 = 0,
    start_free: u64 = 0,
    objects: u64 = 0,
    bytes: u64 = 0,
    objects_failed: u64 = 0,
    bytes_failed: u64 = 0,
};

pub const Pool = struct {
    /// Deployment pool index (stable when other pools leave the endpoint list).
    index: u32,
    cmdline: []const u8 = "",
    decom: Decom = .{},
};

pub const RebalPool = struct {
    index: u32,
    /// Moving keys out of this pool.
    source: bool = false,
    done: bool = false,
    objects: u64 = 0,
    bytes: u64 = 0,
};

pub const Rebalance = struct {
    id: []const u8 = "",
    status: RebalStatus = .none,
    /// Relative tolerance around the cluster-wide used ratio.
    threshold: f64 = 0.1,
    goal: f64 = 0,
    start_ns: i64 = 0,
    stop_ns: i64 = 0,
    pools: []RebalPool = &.{},
};

pub const Meta = struct {
    epoch: u64 = 0,
    pools: []Pool = &.{},
    rebalance: Rebalance = .{},

    pub fn pool(m: *Meta, index: u32) ?*Pool {
        for (m.pools) |*p| if (p.index == index) return p;
        return null;
    }

    pub fn rebalPool(m: *Meta, index: u32) ?*RebalPool {
        for (m.rebalance.pools) |*p| if (p.index == index) return p;
        return null;
    }

    /// Adds entries for pools not yet known.
    pub fn ensure(m: *Meta, a: std.mem.Allocator, index: u32, line: []const u8) error{OutOfMemory}!*Pool {
        if (m.pool(index)) |p| {
            if (line.len > 0) p.cmdline = line;
            return p;
        }
        const grown = try a.alloc(Pool, m.pools.len + 1);
        @memcpy(grown[0..m.pools.len], m.pools);
        grown[m.pools.len] = .{ .index = index, .cmdline = line };
        m.pools = grown;
        return &grown[m.pools.len - 1];
    }

    pub fn draining(m: *const Meta) ?u32 {
        for (m.pools) |p| if (p.decom.status == .draining) return p.index;
        return null;
    }

    pub fn encode(m: Meta, a: std.mem.Allocator) error{OutOfMemory}![]u8 {
        return std.json.Stringify.valueAlloc(a, m, .{});
    }

    pub fn decode(a: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, Corrupt }!Meta {
        return std.json.parseFromSliceLeaky(Meta, a, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Corrupt,
        };
    }

    pub fn clone(m: Meta, a: std.mem.Allocator) error{OutOfMemory}!Meta {
        const bytes = try m.encode(a);
        return decode(a, bytes) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Corrupt => unreachable,
        };
    }
};

/// The pool's `--data` arguments joined by spaces: how `mc admin decommission` names it.
pub fn cmdline(a: std.mem.Allocator, args: []const []const u8) error{OutOfMemory}![]const u8 {
    return std.mem.join(a, " ", args);
}

/// True when `name` (from an admin request) refers to the pool with these arguments.
pub fn matches(name: []const u8, args: []const []const u8) bool {
    const n = std.mem.trim(u8, name, " ");
    if (n.len == 0) return false;
    var it = std.mem.tokenizeAny(u8, n, " ,");
    var i: usize = 0;
    while (it.next()) |tok| : (i += 1) {
        if (i >= args.len or !std.mem.eql(u8, tok, args[i])) return false;
    }
    return i == args.len;
}

test "meta round trip and lookups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var m: Meta = .{ .epoch = 3 };
    const p = try m.ensure(a, 2, "http://h{1...4}/d{1...4}");
    p.decom = .{ .status = .draining, .objects = 7, .bytes = 1 << 40 };
    _ = try m.ensure(a, 0, "http://g/d");
    m.rebalance = .{ .id = "abc", .status = .started, .pools = try a.dupe(RebalPool, &.{.{ .index = 0, .source = true }}) };
    const g = try Meta.decode(a, try m.encode(a));
    try std.testing.expectEqual(@as(u64, 3), g.epoch);
    try std.testing.expectEqual(@as(?u32, 2), g.draining());
    var gm = g;
    try std.testing.expectEqual(@as(u64, 1 << 40), gm.pool(2).?.decom.bytes);
    try std.testing.expect(gm.rebalPool(0).?.source);
    try std.testing.expect(gm.pool(5) == null);
    try std.testing.expectError(error.Corrupt, Meta.decode(a, "{"));
    // Unknown fields from a newer writer are ignored.
    _ = try Meta.decode(a, "{\"epoch\":1,\"future\":true}");
}

test "pool names match the command line" {
    const args = [_][]const u8{ "http://a:9000/d{1...4}", "http://b:9000/d{1...4}" };
    try std.testing.expect(matches("http://a:9000/d{1...4} http://b:9000/d{1...4}", &args));
    try std.testing.expect(matches("http://a:9000/d{1...4},http://b:9000/d{1...4}", &args));
    try std.testing.expect(!matches("http://a:9000/d{1...4}", &args));
    try std.testing.expect(!matches("", &args));
    try std.testing.expect(matches(" http://x/y ", &.{"http://x/y"}));
}
