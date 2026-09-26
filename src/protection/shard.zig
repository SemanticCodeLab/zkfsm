//! On-disk shard layout: `header | (crc32c | chunk)*`, plus a CRC trailer for records.
const std = @import("std");
const core = @import("../core/root.zig");

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
}
