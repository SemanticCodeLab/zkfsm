//! Persistent event state in the system key space (shared by cluster nodes):
//! the target configuration and each bucket's notification configuration.
const std = @import("std");
const backend = @import("../backend/root.zig");

const Allocator = std.mem.Allocator;
pub const PhysicalKey = backend.PhysicalKey;

pub const Kind = enum(u8) { targets = 0x54, bucket = 0x42 };

const magic_hex = "5a4e";

/// `5a4e<kind><26 hex of sha256(name)>`.
pub fn key(kind: Kind, name: []const u8) PhysicalKey {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &d, .{});
    const hex = std.fmt.bytesToHex(d, .lower);
    var k: PhysicalKey = .{ .space = .system, .hex = undefined };
    @memcpy(k.hex[0..4], magic_hex);
    _ = std.fmt.bufPrint(k.hex[4..6], "{x:0>2}", .{@intFromEnum(kind)}) catch unreachable; // 2 hex chars fit
    @memcpy(k.hex[6..], hex[0..26]);
    return k;
}

pub const Error = error{ StorageFailed, OutOfMemory };

pub fn get(store: backend.StorageBackend, a: Allocator, k: PhysicalKey) Error!?[]u8 {
    return store.getRecord(k, a) catch |e| switch (e) {
        error.NotFound => null,
        error.OutOfMemory => error.OutOfMemory,
        else => error.StorageFailed,
    };
}

pub fn put(store: backend.StorageBackend, k: PhysicalKey, bytes: []const u8) Error!void {
    store.putRecord(k, bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.StorageFailed;
}

pub fn remove(store: backend.StorageBackend, k: PhysicalKey) Error!void {
    store.deleteRecord(k) catch |e| switch (e) {
        error.NotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.StorageFailed,
    };
}

test "keys differ by kind and name" {
    const a = key(.bucket, "b");
    try std.testing.expectEqualStrings("5a4e42", a.hex[0..6]);
    try std.testing.expect(!std.mem.eql(u8, &a.hex, &key(.targets, "b").hex));
}
