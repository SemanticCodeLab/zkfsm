//! On-disk shard layout: `header | (crc32c | chunk)*`, plus a CRC trailer for records.
const std = @import("std");
const core = @import("../core/root.zig");
const iface = @import("../backend/root.zig");

const Crc32c = core.checksum.Crc32c;

pub const magic = "ZKS1";
pub const chunk_size: u32 = 64 * 1024;
pub const header_len: u64 = 8;
const crc_len: u64 = 4;
const stride: u64 = chunk_size + crc_len;

pub fn header() [header_len]u8 {
    var h: [header_len]u8 = undefined;
    h[0..4].* = magic.*;
    std.mem.writeInt(u32, h[4..8], chunk_size, .little);
    return h;
}

pub fn headerValid(h: []const u8) bool {
    return h.len == header_len and std.mem.eql(u8, h[0..4], magic) and
        std.mem.readInt(u32, h[4..8], .little) == chunk_size;
}

/// Logical object size for a physical shard size; null if no layout fits.
pub fn logicalSize(physical: u64) ?u64 {
    if (physical < header_len) return null;
    const body = physical - header_len;
    const rem = body % stride;
    if (rem != 0 and rem <= crc_len) return null;
    return (body / stride) * chunk_size + (if (rem == 0) 0 else rem - crc_len);
}

pub fn chunkOffset(index: u64) u64 {
    return header_len + index * stride;
}

pub fn chunkCrc(data: []const u8) [4]u8 {
    var c: [4]u8 = undefined;
    std.mem.writeInt(u32, &c, Crc32c.hash(data), .little);
    return c;
}

/// `crc_and_data` is one stored chunk; returns the payload if the CRC matches.
pub fn verifyChunk(crc_and_data: []const u8) ?[]const u8 {
    if (crc_and_data.len < crc_len) return null;
    const want = std.mem.readInt(u32, crc_and_data[0..4], .little);
    const data = crc_and_data[crc_len..];
    return if (Crc32c.hash(data) == want) data else null;
}

const record_magic = "ZKR1";
pub const record_overhead = 8;

/// Appends `crc32c | magic` to a record payload.
pub fn frameRecord(gpa: std.mem.Allocator, payload: []const u8) error{OutOfMemory}![]u8 {
    const out = try gpa.alloc(u8, payload.len + record_overhead);
    @memcpy(out[0..payload.len], payload);
    std.mem.writeInt(u32, out[payload.len..][0..4], Crc32c.hash(payload), .little);
    out[payload.len + 4 ..][0..4].* = record_magic.*;
    return out;
}

const record2_magic = "ZKR2";
/// stamp u64 | flags u8 | crc32c | magic
pub const record2_overhead = 8 + 1 + 4 + 4;

/// Cluster record frame: a hybrid-clock stamp orders replicas; a tombstone marks a delete.
pub fn frameRecord2(gpa: std.mem.Allocator, payload: []const u8, stamp: u64, tombstone: bool) error{OutOfMemory}![]u8 {
    const out = try gpa.alloc(u8, payload.len + record2_overhead);
    @memcpy(out[0..payload.len], payload);
    std.mem.writeInt(u64, out[payload.len..][0..8], stamp, .little);
    out[payload.len + 8] = @intFromBool(tombstone);
    const crc = Crc32c.hash(out[0 .. payload.len + 9]);
    std.mem.writeInt(u32, out[payload.len + 9 ..][0..4], crc, .little);
    out[payload.len + 13 ..][0..4].* = record2_magic.*;
    return out;
}

pub const Unframed = struct { payload: []const u8, stamp: u64 = 0, tombstone: bool = false };

/// Accepts both frames; v1 records carry stamp 0.
pub fn unframeAny(framed: []const u8) ?Unframed {
    if (framed.len >= record2_overhead and std.mem.eql(u8, framed[framed.len - 4 ..], record2_magic)) {
        const n = framed.len - record2_overhead;
        const crc = std.mem.readInt(u32, framed[n + 9 ..][0..4], .little);
        if (crc != Crc32c.hash(framed[0 .. n + 9]) or framed[n + 8] > 1) return null;
        return .{ .payload = framed[0..n], .stamp = std.mem.readInt(u64, framed[n..][0..8], .little), .tombstone = framed[n + 8] == 1 };
    }
    return .{ .payload = unframeRecord(framed) orelse return null };
}

var clock: std.atomic.Value(u64) = .init(0);

/// Hybrid logical clock: wall time, but always past every stamp seen or issued here.
pub fn nextStamp() u64 {
    const now: u64 = @intCast(@max(0, std.time.nanoTimestamp()));
    var cur = clock.load(.monotonic);
    while (true) {
        const next = @max(now, cur + 1);
        cur = clock.cmpxchgWeak(cur, next, .monotonic, .monotonic) orelse return next;
    }
}

pub fn observeStamp(stamp: u64) void {
    _ = clock.fetchMax(stamp, .monotonic);
}

var record_locks: [64]std.Thread.Mutex = @splat(.{});

fn recordLock(key: iface.PhysicalKey) *std.Thread.Mutex {
    return &record_locks[std.hash.Wyhash.hash(7, &key.hex) % record_locks.len];
}

/// Stores a v2 record on a local drive unless the drive already holds a newer stamp.
/// Every writer of cluster records on this process goes through here.
pub fn putRecordNewer(lb: *iface.local.LocalBackend, gpa: std.mem.Allocator, key: iface.PhysicalKey, framed: []const u8) iface.Error!void {
    const new = unframeAny(framed) orelse return error.InvalidKey;
    const m = recordLock(key);
    m.lock();
    defer m.unlock();
    if (lb.backend().getRecord(key, gpa)) |cur| {
        defer gpa.free(cur);
        if (unframeAny(cur)) |u| if (u.stamp > new.stamp) return;
    } else |e| if (e != error.NotFound) return e;
    return lb.backend().putRecord(key, framed);
}

/// Removes a local record only while it still carries `stamp`.
pub fn deleteRecordIf(lb: *iface.local.LocalBackend, gpa: std.mem.Allocator, key: iface.PhysicalKey, stamp: u64) iface.Error!void {
    const m = recordLock(key);
    m.lock();
    defer m.unlock();
    const cur = try lb.backend().getRecord(key, gpa);
    defer gpa.free(cur);
    const u = unframeAny(cur) orelse return error.IoFailed;
    if (u.stamp != stamp) return;
    return lb.backend().deleteRecord(key);
}

pub fn unframeRecord(framed: []const u8) ?[]const u8 {
    if (framed.len < record_overhead) return null;
    const n = framed.len - record_overhead;
    if (!std.mem.eql(u8, framed[n + 4 ..], record_magic)) return null;
    if (std.mem.readInt(u32, framed[n..][0..4], .little) != Crc32c.hash(framed[0..n])) return null;
    return framed[0..n];
}

test "logical size inverts the layout" {
    for ([_]u64{ 0, 1, chunk_size - 1, chunk_size, chunk_size + 1, 3 * chunk_size, 3 * chunk_size + 7 }) |n| {
        const full = n / chunk_size;
        const tail = n % chunk_size;
        const phys = header_len + full * stride + (if (tail == 0) 0 else tail + crc_len);
        try std.testing.expectEqual(@as(?u64, n), logicalSize(phys));
    }
    try std.testing.expectEqual(@as(?u64, null), logicalSize(3));
    try std.testing.expectEqual(@as(?u64, null), logicalSize(header_len + 2));
}

test "chunk and record checks catch flips" {
    var buf: [9]u8 = undefined;
    buf[0..4].* = chunkCrc("hello");
    @memcpy(buf[4..], "hello");
    try std.testing.expectEqualStrings("hello", verifyChunk(&buf).?);
    buf[6] ^= 1;
    try std.testing.expect(verifyChunk(&buf) == null);

    const f = try frameRecord(std.testing.allocator, "rec");
    defer std.testing.allocator.free(f);
    try std.testing.expectEqualStrings("rec", unframeRecord(f).?);
    f[0] ^= 0x40;
    try std.testing.expect(unframeRecord(f) == null);
    try std.testing.expect(headerValid(&header()));

    const g = try frameRecord2(std.testing.allocator, "new", 42, false);
    defer std.testing.allocator.free(g);
    const u = unframeAny(g).?;
    try std.testing.expectEqualStrings("new", u.payload);
    try std.testing.expectEqual(@as(u64, 42), u.stamp);
    g[1] ^= 1;
    try std.testing.expect(unframeAny(g) == null);
    const ahead = nextStamp() + 1000;
    observeStamp(ahead);
    try std.testing.expect(nextStamp() > ahead);
}
