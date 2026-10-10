//! Protection profiles: a closed set; arbitrary geometries are rejected.
const std = @import("std");

pub const ParseError = error{UnknownProfile};

pub const Erasure = struct { data: u8, parity: u8 };

pub const Profile = union(enum) {
    single,
    replica: u8,
    erasure: Erasure,

    const Named = struct { name: []const u8, p: Profile };
    const all = [_]Named{
        .{ .name = "single", .p = .single },
        .{ .name = "replica:2", .p = .{ .replica = 2 } },
        .{ .name = "replica:3", .p = .{ .replica = 3 } },
        .{ .name = "EC:2+2", .p = .{ .erasure = .{ .data = 2, .parity = 2 } } },
        .{ .name = "EC:4+2", .p = .{ .erasure = .{ .data = 4, .parity = 2 } } },
        .{ .name = "EC:8+4", .p = .{ .erasure = .{ .data = 8, .parity = 4 } } },
        .{ .name = "EC:12+4", .p = .{ .erasure = .{ .data = 12, .parity = 4 } } },
    };

    pub fn parse(s: []const u8) ParseError!Profile {
        for (all) |n| if (std.mem.eql(u8, n.name, s)) return n.p;
        return error.UnknownProfile;
    }

    pub fn name(self: Profile) []const u8 {
        for (all) |n| if (n.p.eql(self)) return n.name;
        return "invalid";
    }

    pub fn eql(a: Profile, b: Profile) bool {
        return switch (a) {
            .single => b == .single,
            .replica => |n| b == .replica and b.replica == n,
            .erasure => |e| b == .erasure and b.erasure.data == e.data and b.erasure.parity == e.parity,
        };
    }

    /// Number of drives one object spans.
    pub fn width(self: Profile) u8 {
        return switch (self) {
            .single => 1,
            .replica => |n| n,
            .erasure => |e| e.data + e.parity,
        };
    }
};

/// Storage classes map to profiles by config; 0.2 has one class.
pub const StorageClassConfig = struct {
    standard: Profile,

    /// Default for `n` drives: replica:2 when there is room for it.
    pub fn defaultFor(n: usize) StorageClassConfig {
        return .{ .standard = if (n >= 2) .{ .replica = 2 } else .single };
    }
};

test "closed profile set" {
    try std.testing.expect((try Profile.parse("replica:3")).eql(.{ .replica = 3 }));
    try std.testing.expectEqual(@as(u8, 6), (try Profile.parse("EC:4+2")).width());
    try std.testing.expectError(error.UnknownProfile, Profile.parse("replica:4"));
    try std.testing.expectError(error.UnknownProfile, Profile.parse("EC:5+1"));
    try std.testing.expectEqualStrings("EC:12+4", (Profile{ .erasure = .{ .data = 12, .parity = 4 } }).name());
    try std.testing.expectEqualStrings("single", StorageClassConfig.defaultFor(1).standard.name());
}
