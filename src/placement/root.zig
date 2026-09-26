//! placement: maps object identity to physical keys and keys to drives.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");

pub const profile = @import("profile.zig");
pub const rendezvous = @import("rendezvous.zig");
pub const drives = @import("drives.zig");
pub const ellipsis = @import("ellipsis.zig");

pub const Profile = profile.Profile;
pub const StorageClassConfig = profile.StorageClassConfig;
pub const DriveSet = drives.DriveSet;
pub const max_drives = drives.max_drives;

pub const PhysicalKey = backend.PhysicalKey;

pub const StorageClass = enum(u8) { standard = 0 };

/// Data blob key for an object id.
pub fn dataKey(id: core.ObjectId) PhysicalKey {
    return .{ .space = .data, .hex = id.toHex() };
}

/// Record key for a (bucket, key) name.
pub fn recordKey(id: core.NameId) PhysicalKey {
    return .{ .space = .record, .hex = id.toHex() };
}

/// Record key for a noncurrent version of a name.
pub fn versionRecordKey(id: core.NameId) PhysicalKey {
    return .{ .space = .record, .hex = id.toHex() };
}

/// Per-bucket configuration record (versioning, lock, tags).
pub fn bucketConfigKey(id: core.BucketId) PhysicalKey {
    return .{ .space = .system, .hex = id.toHex() };
}

/// Fixed key holding the bucket catalog.
pub const catalog_key: PhysicalKey = .{ .space = .system, .hex = [_]u8{'0'} ** 32 };

test "data and record keys use distinct spaces" {
    const id = core.ObjectId{ .bytes = [_]u8{0xab} ** 16 };
    const k = dataKey(id);
    try std.testing.expectEqual(backend.KeySpace.data, k.space);
    try std.testing.expectEqualStrings("abab", k.hex[0..4]);
}

test {
    _ = profile;
    _ = rendezvous;
    _ = drives;
    _ = ellipsis;
}
