//! Raw (unframed) Snappy block decompression, as used by Parquet pages.
const std = @import("std");

pub const Error = error{ OutOfMemory, InvalidSnappy, SnappyTooLarge };

fn varint(s: []const u8, i: *usize) Error!u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (i.* >= s.len or shift > 28) return error.InvalidSnappy;
        const b = s[i.*];
        i.* += 1;
        v |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        shift += 7;
    }
}

pub fn decodedLen(src: []const u8) Error!usize {
    var i: usize = 0;
    return @intCast(try varint(src, &i));
}

/// Decompresses `src`; output length must not exceed `max_len`.
pub fn decompress(gpa: std.mem.Allocator, src: []const u8, max_len: usize) Error![]u8 {
    var i: usize = 0;
    const n: usize = @intCast(try varint(src, &i));
    if (n > max_len) return error.SnappyTooLarge;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    var o: usize = 0;
    while (i < src.len) {
        const tag = src[i];
        i += 1;
        switch (@as(u2, @truncate(tag))) {
            0 => {
                var len: usize = tag >> 2;
                if (len >= 60) {
                    const extra = len - 59;
                    if (i + extra > src.len) return error.InvalidSnappy;
                    len = 0;
                    for (0..extra) |k| len |= @as(usize, src[i + k]) << @intCast(8 * k);
                    i += extra;
                }
                len += 1;
                if (len > src.len - i or len > n - o) return error.InvalidSnappy;
                @memcpy(out[o .. o + len], src[i .. i + len]);
                i += len;
                o += len;
                continue;
            },
            1 => {
                if (i >= src.len) return error.InvalidSnappy;
                const len: usize = 4 + ((tag >> 2) & 7);
                const off: usize = (@as(usize, tag >> 5) << 8) | src[i];
                i += 1;
                try copy(out, &o, off, len);
            },
            2 => {
                if (i + 2 > src.len) return error.InvalidSnappy;
                const len: usize = (tag >> 2) + 1;
                const off: usize = std.mem.readInt(u16, src[i..][0..2], .little);
                i += 2;
                try copy(out, &o, off, len);
            },
            3 => {
                if (i + 4 > src.len) return error.InvalidSnappy;
                const len: usize = (tag >> 2) + 1;
                const off: usize = std.mem.readInt(u32, src[i..][0..4], .little);
                i += 4;
                try copy(out, &o, off, len);
            },
        }
    }
    if (o != n) return error.InvalidSnappy;
    return out;
}

fn copy(out: []u8, o: *usize, off: usize, len: usize) Error!void {
    if (off == 0 or off > o.* or len > out.len - o.*) return error.InvalidSnappy;
    // Byte-wise: source and destination may overlap (run-length copies).
    for (0..len) |k| out[o.* + k] = out[o.* - off + k];
    o.* += len;
}

test "literal and overlapping copy" {
    // len=10: literal "ab" then copy len 8 offset 2 (1-byte offset form).
    const src = [_]u8{ 10, 0x04, 'a', 'b', 0x11, 0x02 };
    const out = try decompress(std.testing.allocator, &src, 100);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("ababababab", out);
}

test "hostile snappy" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidSnappy, decompress(a, &[_]u8{ 4, 0x0d, 0x05 }, 100));
    try std.testing.expectError(error.InvalidSnappy, decompress(a, &[_]u8{ 3, 0x08, 'a' }, 100));
    try std.testing.expectError(error.SnappyTooLarge, decompress(a, &[_]u8{ 0xff, 0xff, 0x7f }, 100));
    try std.testing.expectError(error.InvalidSnappy, decompress(a, &[_]u8{ 2, 0x00, 'a' }, 100));
}
