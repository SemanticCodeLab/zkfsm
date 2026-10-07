//! Persistent replication state in the system key space: bucket replication
//! configs, remote targets, resync status, queue entries, and site state. Keys
//! carry a fixed hex prefix per kind so listings can skip unrelated records.
const std = @import("std");
const backend = @import("../backend/root.zig");

const Allocator = std.mem.Allocator;
pub const PhysicalKey = backend.PhysicalKey;

pub const Kind = enum(u8) {
    config = 0x43,
    deployment = 0x44,
    queue = 0x51,
    resync = 0x52,
    site = 0x53,
    targets = 0x54,
};

const magic_hex = "5a52";

/// `5a52<kind><26 hex of sha256(name)>`.
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

pub fn isKind(k: PhysicalKey, kind: Kind) bool {
    var p: [6]u8 = undefined;
    @memcpy(p[0..4], magic_hex);
    _ = std.fmt.bufPrint(p[4..6], "{x:0>2}", .{@intFromEnum(kind)}) catch unreachable; // fits
    return k.space == .system and std.mem.eql(u8, k.hex[0..6], &p);
}

pub const Error = error{ StorageFailed, OutOfMemory };

/// Record bytes, or null when absent.
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

/// Keys of one kind.
pub fn list(store: backend.StorageBackend, a: Allocator, kind: Kind) Error![]PhysicalKey {
    const C = struct {
        a: Allocator,
        kind: Kind,
        out: std.ArrayList(PhysicalKey) = .empty,
        fn f(ctx: *anyopaque, k: PhysicalKey) backend.Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (!isKind(k, c.kind)) return;
            for (c.out.items) |o| if (std.mem.eql(u8, &o.hex, &k.hex)) return;
            try c.out.append(c.a, k);
        }
    };
    var c: C = .{ .a = a, .kind = kind };
    store.list(.system, .{ .ctx = &c, .func = C.f }) catch |e| switch (e) {
        error.NotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.StorageFailed,
    };
    return c.out.items;
}

/// JSON value of `T` from a record; null when absent or unreadable.
pub fn getJson(comptime T: type, store: backend.StorageBackend, a: Allocator, k: PhysicalKey) Error!?T {
    const bytes = try get(store, a, k) orelse return null;
    return std.json.parseFromSliceLeaky(T, a, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

pub fn putJson(store: backend.StorageBackend, gpa: Allocator, k: PhysicalKey, v: anytype) Error!void {
    const bytes = try std.json.Stringify.valueAlloc(gpa, v, .{});
    defer gpa.free(bytes);
    try put(store, k, bytes);
}

/// Per-bucket record name: `<what>/<bucket id hex>`.
pub fn bucketName(buf: *[64]u8, what: []const u8, bid_hex: [32]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ what, &bid_hex }) catch unreachable; // short
}

test "keys carry their kind" {
    const k = key(.queue, "a");
    try std.testing.expect(isKind(k, .queue));
    try std.testing.expect(!isKind(k, .config));
    try std.testing.expect(!std.mem.eql(u8, &k.hex, &key(.queue, "b").hex));
    try std.testing.expectEqualStrings("5a5251", k.hex[0..6]);
}
