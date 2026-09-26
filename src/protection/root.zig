//! protection: ProtectionStrategy over a DriveSet: none/replica(N) and erasure(k,m).
const std = @import("std");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");

pub const shard = @import("shard.zig");
pub const replica = @import("replica.zig");
pub const erasure = @import("erasure.zig");
pub const ec_store = @import("ec_store.zig");

pub const ReplicaStore = replica.ReplicaStore;
pub const ErasureStore = ec_store.ErasureStore;
pub const KeyReport = replica.KeyReport;

pub const Error = error{UnsupportedProfile};

/// Caller-owned storage for whichever store the profile selects.
pub const Stores = struct {
    replica: ReplicaStore = undefined,
    erasure: ErasureStore = undefined,
};

pub const Strategy = union(enum) {
    /// `single` is replica with one copy: no redundancy, still checksummed.
    replica: *ReplicaStore,
    erasure: *ErasureStore,

    pub fn init(gpa: std.mem.Allocator, drives: *placement.DriveSet, stores: *Stores) Error!Strategy {
        switch (drives.profile) {
            .single, .replica => {
                stores.replica = .init(gpa, drives);
                return .{ .replica = &stores.replica };
            },
            .erasure => |g| {
                const p = erasure.Profile.fromGeometry(g.data, g.parity) catch return error.UnsupportedProfile;
                stores.erasure = .init(gpa, drives, p);
                return .{ .erasure = &stores.erasure };
            },
        }
    }

    pub fn backend(self: Strategy) iface.StorageBackend {
        return switch (self) {
            inline else => |s| s.backend(),
        };
    }

    /// Verifies all shards or replicas of `key` and rebuilds bad ones.
    pub fn healKey(self: Strategy, key: iface.PhysicalKey) KeyReport {
        return switch (self) {
            inline else => |s| s.healKey(key),
        };
    }
};

test "every closed-set profile maps to a strategy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [16][std.fs.max_path_bytes]u8 = undefined;
    var paths: [16][]const u8 = undefined;
    var nb: [4]u8 = undefined;
    for ([_][]const u8{ "single", "replica:2", "replica:3", "EC:4+2", "EC:8+4", "EC:12+4" }) |name| {
        const p = try placement.Profile.parse(name);
        const w = p.width();
        for (0..w) |i| {
            const d = try std.fmt.bufPrint(&nb, "{d}", .{i});
            try tmp.dir.deleteTree(d);
            try tmp.dir.makePath(d);
            paths[i] = try tmp.dir.realpath(d, &bufs[i]);
        }
        var set = try placement.DriveSet.open(std.testing.allocator, paths[0..w], p);
        defer set.deinit();
        var stores: Stores = .{};
        const s = try Strategy.init(std.testing.allocator, &set, &stores);
        try std.testing.expectEqual(p == .erasure, s == .erasure);
    }
}

test {
    _ = shard;
    _ = replica;
    _ = ec_store;
}
