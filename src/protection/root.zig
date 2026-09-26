//! protection: ProtectionStrategy over a DriveSet. none/replica(N) now; erasure(k,m) plugs in here.
const std = @import("std");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");

pub const shard = @import("shard.zig");
pub const replica = @import("replica.zig");

pub const ReplicaStore = replica.ReplicaStore;
pub const KeyReport = replica.KeyReport;

pub const Error = error{NotImplemented};

/// Placeholder for erasure coding; every operation reports NotImplemented.
pub const Erasure = struct {
    geometry: placement.profile.Erasure,
};

pub const Strategy = union(enum) {
    /// `single` is replica with one copy: no redundancy, still checksummed.
    replica: *ReplicaStore,
    erasure: Erasure,

    /// `store` is caller-owned storage for the replica variant.
    pub fn init(gpa: std.mem.Allocator, drives: *placement.DriveSet, store: *ReplicaStore) Error!Strategy {
        return switch (drives.profile) {
            .single, .replica => blk: {
                store.* = ReplicaStore.init(gpa, drives);
                break :blk .{ .replica = store };
            },
            .erasure => error.NotImplemented,
        };
    }

    pub fn backend(self: Strategy) Error!iface.StorageBackend {
        return switch (self) {
            .replica => |r| r.backend(),
            .erasure => error.NotImplemented,
        };
    }

    /// Verifies all shards of `key` and rebuilds bad ones.
    pub fn healKey(self: Strategy, key: iface.PhysicalKey) Error!KeyReport {
        return switch (self) {
            .replica => |r| r.healKey(key),
            .erasure => error.NotImplemented,
        };
    }
};

test "erasure profiles are typed but not implemented" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [6][std.fs.max_path_bytes]u8 = undefined;
    var paths: [6][]const u8 = undefined;
    var nb: [4]u8 = undefined;
    for (0..6) |i| {
        const name = try std.fmt.bufPrint(&nb, "d{d}", .{i});
        try tmp.dir.makePath(name);
        paths[i] = try tmp.dir.realpath(name, &bufs[i]);
    }
    var set = try placement.DriveSet.open(std.testing.allocator, &paths, try placement.Profile.parse("EC:4+2"));
    defer set.deinit();
    var store: ReplicaStore = undefined;
    try std.testing.expectError(error.NotImplemented, Strategy.init(std.testing.allocator, &set, &store));
    const ec: Strategy = .{ .erasure = .{ .geometry = .{ .data = 4, .parity = 2 } } };
    try std.testing.expectError(error.NotImplemented, ec.backend());
}

test {
    _ = shard;
    _ = replica;
}
