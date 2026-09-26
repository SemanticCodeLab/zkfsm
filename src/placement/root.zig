//! placement: maps object identity to backend physical keys. 0.1 is local-only.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");

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

/// Record key for an in-progress multipart upload. Upload ids are random, so they
/// cannot collide with the hashed name ids in the same space.
pub fn uploadKey(id: core.ObjectId) PhysicalKey {
    return .{ .space = .record, .hex = id.toHex() };
}

/// Fixed key holding the bucket catalog.
pub const catalog_key: PhysicalKey = .{ .space = .system, .hex = [_]u8{'0'} ** 32 };

test "data and record keys use distinct spaces" {
    const id = core.ObjectId{ .bytes = [_]u8{0xab} ** 16 };
    const k = dataKey(id);
    try std.testing.expectEqual(backend.KeySpace.data, k.space);
    try std.testing.expectEqualStrings("abab", k.hex[0..4]);
}
