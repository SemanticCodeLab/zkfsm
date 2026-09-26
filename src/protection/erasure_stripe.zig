//! Splits an object into fixed-size blocks; each block is striped across k
//! data shards (last block zero-padded) and the original size is recorded.
const std = @import("std");

pub const default_block_size: u32 = 1 << 20;

pub const LayoutError = error{InvalidBlockSize};

pub const Layout = struct {
    object_size: u64,
    block_size: u32,
    k: u8,

    pub fn init(object_size: u64, block_size: u32, k: u8) LayoutError!Layout {
        if (block_size == 0 or k == 0) return error.InvalidBlockSize;
        return .{ .object_size = object_size, .block_size = block_size, .k = k };
    }

    pub fn blockCount(l: Layout) u64 {
        return std.math.divCeil(u64, l.object_size, l.block_size) catch unreachable;
    }

    /// Bytes per shard per block; identical for every block, including the last.
    pub fn shardLen(l: Layout) u32 {
        return std.math.divCeil(u32, l.block_size, l.k) catch unreachable;
    }

    /// Real (unpadded) bytes in block `b`.
    pub fn blockLen(l: Layout, b: u64) u32 {
        std.debug.assert(b < l.blockCount());
        const start = b * l.block_size;
        return @intCast(@min(l.block_size, l.object_size - start));
    }
};

/// Copy `block` into k equal shard buffers, zero-padding the tail.
pub fn split(block: []const u8, shards: []const []u8) void {
    const sl = shards[0].len;
    std.debug.assert(block.len <= sl * shards.len);
    for (shards, 0..) |s, i| {
        const start = @min(block.len, i * sl);
        const end = @min(block.len, start + sl);
        @memcpy(s[0 .. end - start], block[start..end]);
        @memset(s[end - start ..], 0);
    }
}

/// Inverse of `split`: write the first `out.len` bytes held by the shards.
pub fn join(shards: []const []const u8, out: []u8) void {
    const sl = shards[0].len;
    std.debug.assert(out.len <= sl * shards.len);
    var pos: usize = 0;
    for (shards) |s| {
        const n = @min(sl, out.len - pos);
        @memcpy(out[pos..][0..n], s[0..n]);
        pos += n;
        if (pos == out.len) break;
    }
}

test "layout math" {
    const l = try Layout.init(2 * default_block_size + 5, default_block_size, 12);
    try std.testing.expectEqual(@as(u64, 3), l.blockCount());
    try std.testing.expectEqual(@as(u32, 5), l.blockLen(2));
    try std.testing.expectEqual(@as(u32, default_block_size), l.blockLen(0));
    try std.testing.expectEqual(@as(u32, 87382), l.shardLen());
    const empty = try Layout.init(0, default_block_size, 4);
    try std.testing.expectEqual(@as(u64, 0), empty.blockCount());
    try std.testing.expectError(error.InvalidBlockSize, Layout.init(1, 0, 4));
}

test "split then join round-trips with padding" {
    var prng = std.Random.DefaultPrng.init(3);
    var src: [103]u8 = undefined;
    prng.random().bytes(&src);
    for ([_]usize{ 0, 1, 26, 100, 103 }) |len| {
        var bufs: [4][26]u8 = undefined;
        const shards = [_][]u8{ &bufs[0], &bufs[1], &bufs[2], &bufs[3] };
        split(src[0..len], &shards);
        var out: [103]u8 = undefined;
        const ro = [_][]const u8{ &bufs[0], &bufs[1], &bufs[2], &bufs[3] };
        join(&ro, out[0..len]);
        try std.testing.expectEqualSlices(u8, src[0..len], out[0..len]);
        if (len < 104) try std.testing.expectEqual(@as(u8, 0), bufs[3][25]);
    }
}
