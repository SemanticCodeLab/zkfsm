//! HighwayHash (64/256-bit outputs), written from the published algorithm.
//! The migrator uses the 256-bit form to verify per-block bitrot checksums.
const std = @import("std");

/// Key the source format uses for streaming bitrot checksums.
pub const bitrot_key: [32]u8 = .{
    0x4b, 0xe7, 0x34, 0xfa, 0x8e, 0x23, 0x8a, 0xcd, 0x26, 0x3e, 0x83, 0xe6, 0xbb, 0x96, 0x85, 0x52,
    0x04, 0x0f, 0x93, 0x5d, 0xa3, 0x9f, 0x44, 0x14, 0x97, 0xe0, 0x9d, 0x13, 0x22, 0xde, 0x36, 0xa0,
};

const init0 = [4]u64{ 0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0, 0x13198a2e03707344, 0x243f6a8885a308d3 };
const init1 = [4]u64{ 0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c, 0xbe5466cf34e90c6c, 0x452821e638d01377 };

pub const Hasher = struct {
    v0: [4]u64,
    v1: [4]u64,
    mul0: [4]u64,
    mul1: [4]u64,
    buf: [32]u8 = undefined,
    buf_len: usize = 0,

    pub fn init(key: *const [32]u8) Hasher {
        var h: Hasher = .{ .v0 = undefined, .v1 = undefined, .mul0 = init0, .mul1 = init1 };
        for (0..4) |i| {
            const k = std.mem.readInt(u64, key[i * 8 ..][0..8], .little);
            h.v0[i] = init0[i] ^ k;
            h.v1[i] = init1[i] ^ std.math.rotl(u64, k, 32);
        }
        return h;
    }

    fn zipperAdd(v1: u64, v0: u64, add1: *u64, add0: *u64) void {
        add0.* +%= (((v0 & 0xff000000) | (v1 & 0xff00000000)) >> 24) |
            (((v0 & 0xff0000000000) | (v1 & 0xff000000000000)) >> 16) |
            (v0 & 0xff0000) | ((v0 & 0xff00) << 32) |
            ((v1 & 0xff00000000000000) >> 8) | (v0 << 56);
        add1.* +%= (((v1 & 0xff000000) | (v0 & 0xff00000000)) >> 24) |
            (v1 & 0xff0000) | ((v1 & 0xff0000000000) >> 16) |
            ((v1 & 0xff00) << 24) | ((v0 & 0xff000000000000) >> 8) |
            ((v1 & 0xff) << 48) | (v0 & 0xff00000000000000);
    }

    fn updateLanes(h: *Hasher, lanes: [4]u64) void {
        for (0..4) |i| {
            h.v1[i] +%= h.mul0[i] +% lanes[i];
            h.mul0[i] ^= (h.v1[i] & 0xffffffff) *% (h.v0[i] >> 32);
            h.v0[i] +%= h.mul1[i];
            h.mul1[i] ^= (h.v0[i] & 0xffffffff) *% (h.v1[i] >> 32);
        }
        zipperAdd(h.v1[1], h.v1[0], &h.v0[1], &h.v0[0]);
        zipperAdd(h.v1[3], h.v1[2], &h.v0[3], &h.v0[2]);
        zipperAdd(h.v0[1], h.v0[0], &h.v1[1], &h.v1[0]);
        zipperAdd(h.v0[3], h.v0[2], &h.v1[3], &h.v1[2]);
    }

    fn updatePacket(h: *Hasher, p: *const [32]u8) void {
        var lanes: [4]u64 = undefined;
        for (0..4) |i| lanes[i] = std.mem.readInt(u64, p[i * 8 ..][0..8], .little);
        h.updateLanes(lanes);
    }

    pub fn update(h: *Hasher, data: []const u8) void {
        var d = data;
        if (h.buf_len > 0) {
            const n = @min(32 - h.buf_len, d.len);
            @memcpy(h.buf[h.buf_len..][0..n], d[0..n]);
            h.buf_len += n;
            d = d[n..];
            if (h.buf_len < 32) return;
            h.updatePacket(&h.buf);
            h.buf_len = 0;
        }
        while (d.len >= 32) : (d = d[32..]) h.updatePacket(d[0..32]);
        @memcpy(h.buf[0..d.len], d);
        h.buf_len = d.len;
    }

    fn rot32By(count: u6, lanes: *[4]u64) void {
        const c: u5 = @intCast(count & 31);
        for (lanes) |*l| {
            const lo: u32 = @truncate(l.*);
            const hi: u32 = @truncate(l.* >> 32);
            l.* = @as(u64, std.math.rotl(u32, lo, c)) | (@as(u64, std.math.rotl(u32, hi, c)) << 32);
        }
    }

    fn remainder(h: *Hasher) void {
        const size: usize = h.buf_len;
        const size_mod4 = size & 3;
        const rem = size & ~@as(usize, 3);
        var packet: [32]u8 = @splat(0);
        for (&h.v0) |*v| v.* +%= (@as(u64, size) << 32) +% size;
        rot32By(@intCast(size), &h.v1);
        @memcpy(packet[0..rem], h.buf[0..rem]);
        if (size & 16 != 0) {
            for (0..4) |i| packet[28 + i] = h.buf[rem + i + size_mod4 - 4];
        } else if (size_mod4 != 0) {
            packet[16] = h.buf[rem];
            packet[17] = h.buf[rem + (size_mod4 >> 1)];
            packet[18] = h.buf[rem + size_mod4 - 1];
        }
        h.updatePacket(&packet);
    }

    fn permuteAndUpdate(h: *Hasher) void {
        const r = std.math.rotl;
        h.updateLanes(.{ r(u64, h.v0[2], 32), r(u64, h.v0[3], 32), r(u64, h.v0[0], 32), r(u64, h.v0[1], 32) });
    }

    pub fn final64(h: *Hasher) u64 {
        if (h.buf_len > 0) h.remainder();
        for (0..4) |_| h.permuteAndUpdate();
        return h.v0[0] +% h.v1[0] +% h.mul0[0] +% h.mul1[0];
    }

    fn reduce(a3u: u64, a2: u64, a1: u64, a0: u64, m1: *u64, m0: *u64) void {
        const a3 = a3u & 0x3fffffffffffffff;
        m1.* = a1 ^ ((a3 << 1) | (a2 >> 63)) ^ ((a3 << 2) | (a2 >> 62));
        m0.* = a0 ^ (a2 << 1) ^ (a2 << 2);
    }

    pub fn final256(h: *Hasher, out: *[32]u8) void {
        if (h.buf_len > 0) h.remainder();
        for (0..10) |_| h.permuteAndUpdate();
        var r: [4]u64 = undefined;
        reduce(h.v1[1] +% h.mul1[1], h.v1[0] +% h.mul1[0], h.v0[1] +% h.mul0[1], h.v0[0] +% h.mul0[0], &r[1], &r[0]);
        reduce(h.v1[3] +% h.mul1[3], h.v1[2] +% h.mul1[2], h.v0[3] +% h.mul0[3], h.v0[2] +% h.mul0[2], &r[3], &r[2]);
        for (0..4) |i| std.mem.writeInt(u64, out[i * 8 ..][0..8], r[i], .little);
    }
};

pub fn hash256(key: *const [32]u8, data: []const u8) [32]u8 {
    var h = Hasher.init(key);
    h.update(data);
    var out: [32]u8 = undefined;
    h.final256(&out);
    return out;
}

test "published 64-bit vectors" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*k, i| k.* = @intCast(i);
    var data: [33]u8 = undefined;
    for (&data, 0..) |*d, i| d.* = @intCast(i);
    const want = [_]u64{ 0x907A56DE22C26E53, 0x7EAB43AAC7CDDD78, 0xB8D0569AB0B53D62, 0x5C6BEFAB8A463D80 };
    for (want, 0..) |w, n| {
        var h = Hasher.init(&key);
        h.update(data[0..n]);
        try std.testing.expectEqual(w, h.final64());
    }
}

test "streaming equals one-shot" {
    var data: [200]u8 = undefined;
    for (&data, 0..) |*d, i| d.* = @truncate(i * 7);
    const one = hash256(&bitrot_key, &data);
    var h = Hasher.init(&bitrot_key);
    h.update(data[0..5]);
    h.update(data[5..77]);
    h.update(data[77..]);
    var two: [32]u8 = undefined;
    h.final256(&two);
    try std.testing.expectEqualSlices(u8, &one, &two);
}
