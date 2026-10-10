//! SHA-256 and CRC-32C on the CPU's own instructions (SHA-NI, SSE4.2) when it has
//! them, checked once at run time, so a portable build hashes at hardware speed.
//! Other CPUs and architectures use the standard library.
const std = @import("std");
const builtin = @import("builtin");

// Only the LLVM backend assembles these instructions.
const is_x86_64 = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm;

const Features = packed struct(u8) { known: bool = false, sha: bool = false, crc: bool = false, _: u5 = 0 };
var features: std.atomic.Value(u8) = .init(0);

fn cpu() Features {
    const f: Features = @bitCast(features.load(.monotonic));
    if (f.known) return f;
    var d: Features = .{ .known = true };
    if (is_x86_64) {
        const l1 = cpuid(1, 0);
        const l7 = if (cpuid(0, 0).a >= 7) cpuid(7, 0) else Regs{};
        const sse41 = l1.c & (1 << 19) != 0;
        d.crc = l1.c & (1 << 20) != 0;
        d.sha = sse41 and l1.c & (1 << 9) != 0 and l7.b & (1 << 29) != 0;
    }
    features.store(@bitCast(d), .monotonic);
    return d;
}

const Regs = struct { a: u32 = 0, b: u32 = 0, c: u32 = 0, d: u32 = 0 };

fn cpuid(leaf: u32, sub: u32) Regs {
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (sub),
    );
    return .{ .a = a, .b = b, .c = c, .d = d };
}

/// Drop-in for `std.crypto.hash.sha2.Sha256` (init/update/final/finalResult/hash).
pub const Sha256 = struct {
    pub const digest_length = 32;
    pub const block_length = 64;
    pub const Options = struct {};
    const Std = std.crypto.hash.sha2.Sha256;

    /// Chosen at the first update, so `init` also works at comptime.
    mode: enum { undecided, fast, soft } = .undecided,
    soft: Std,
    s: [8]u32 = iv,
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total: u64 = 0,

    const iv = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

    pub fn init(_: Options) Sha256 {
        return .{ .soft = Std.init(.{}) };
    }

    fn fast(d: *Sha256) bool {
        if (d.mode == .undecided) d.mode = if (is_x86_64 and cpu().sha) .fast else .soft;
        return d.mode == .fast;
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, opts: Options) void {
        var d = Sha256.init(opts);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Sha256, b: []const u8) void {
        if (!d.fast()) return d.soft.update(b);
        var in = b;
        d.total += in.len;
        if (d.buf_len > 0) {
            const n = @min(64 - d.buf_len, in.len);
            @memcpy(d.buf[d.buf_len..][0..n], in[0..n]);
            d.buf_len += @intCast(n);
            in = in[n..];
            if (d.buf_len < 64) return;
            compressNi(&d.s, &d.buf);
            d.buf_len = 0;
        }
        while (in.len >= 64) : (in = in[64..]) compressNi(&d.s, in[0..64]);
        @memcpy(d.buf[0..in.len], in);
        d.buf_len = @intCast(in.len);
    }

    pub fn final(d: *Sha256, out: *[digest_length]u8) void {
        if (!d.fast()) return d.soft.final(out);
        const bits = d.total * 8;
        var pad: [72]u8 = @splat(0);
        pad[0] = 0x80;
        const fill = if (d.buf_len < 56) 56 - d.buf_len else 120 - @as(usize, d.buf_len);
        std.mem.writeInt(u64, pad[fill..][0..8], bits, .big);
        d.update(pad[0 .. fill + 8]);
        for (d.s, 0..) |w, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], w, .big);
    }

    pub fn finalResult(d: *Sha256) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        d.final(&out);
        return out;
    }
};

const K = [64]u32{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

const V4 = @Vector(4, u32);

/// One 64-byte block with SHA-NI. State lanes: x = {F,E,B,A}, y = {H,G,D,C}.
fn compressNi(s: *[8]u32, block: *const [64]u8) void {
    if (!is_x86_64) unreachable;
    var w: [16]V4 = undefined;
    for (0..16) |i| {
        const q = i / 4;
        w[q][i % 4] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
    }
    var x: V4 = .{ s[5], s[4], s[1], s[0] };
    var y: V4 = .{ s[7], s[6], s[3], s[2] };
    inline for (0..16) |k| {
        if (k >= 4) {
            // W[k..k+4] = msg2(msg1(W[k-4], W[k-3]) + {W[k-2][1..], W[k-1][0]}, W[k-1]).
            const m1 = asm ("sha256msg1 %[b], %[a]"
                : [a] "=x" (-> V4),
                : [_] "0" (w[k - 4]),
                  [b] "x" (w[k - 3]),
            );
            const mid = m1 +% @shuffle(u32, w[k - 2], w[k - 1], [4]i32{ 1, 2, 3, -1 });
            w[k] = asm ("sha256msg2 %[b], %[a]"
                : [a] "=x" (-> V4),
                : [_] "0" (mid),
                  [b] "x" (w[k - 1]),
            );
        }
        const wk: V4 = w[k] +% @as(V4, K[4 * k ..][0..4].*);
        y = asm ("sha256rnds2 %[x], %[y]"
            : [y] "=x" (-> V4),
            : [_] "0" (y),
              [x] "x" (x),
              [_] "{xmm0}" (wk),
        );
        x = asm ("sha256rnds2 %[y], %[x]"
            : [x] "=x" (-> V4),
            : [_] "0" (x),
              [y] "x" (y),
              [_] "{xmm0}" (@shuffle(u32, wk, undefined, [4]i32{ 2, 3, 2, 3 })),
        );
    }
    s[0] +%= x[3];
    s[1] +%= x[2];
    s[4] +%= x[1];
    s[5] +%= x[0];
    s[2] +%= y[3];
    s[3] +%= y[2];
    s[6] +%= y[1];
    s[7] +%= y[0];
}

/// CRC-32C (Castagnoli) of `data`; same values as `std.hash.crc.Crc32Iscsi.hash`.
pub fn crc32c(data: []const u8) u32 {
    if (!is_x86_64 or !cpu().crc) return std.hash.crc.Crc32Iscsi.hash(data);
    var c: u64 = 0xFFFFFFFF;
    var p = data;
    while (p.len >= 8) : (p = p[8..]) {
        c = asm ("crc32q %[v], %[c]"
            : [c] "=r" (-> u64),
            : [_] "0" (c),
              [v] "r" (std.mem.readInt(u64, p[0..8], .little)),
        );
    }
    var c32: u32 = @truncate(c);
    for (p) |byte| {
        c32 = asm ("crc32b %[v], %[c]"
            : [c] "=r" (-> u32),
            : [_] "0" (c32),
              [v] "r" (byte),
        );
    }
    return ~c32;
}

test "sha256 matches the standard library across lengths and splits" {
    var prng = std.Random.DefaultPrng.init(5);
    var data: [700]u8 = undefined;
    prng.random().bytes(&data);
    for ([_]usize{ 0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 700 }) |len| {
        var want: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data[0..len], &want, .{});
        var got: [32]u8 = undefined;
        Sha256.hash(data[0..len], &got, .{});
        try std.testing.expectEqualSlices(u8, &want, &got);
        var d = Sha256.init(.{});
        var i: usize = 0;
        while (i < len) : (i += 13) d.update(data[i..@min(len, i + 13)]);
        try std.testing.expectEqualSlices(u8, &want, &d.finalResult());
    }
    var abc: [32]u8 = undefined;
    Sha256.hash("abc", &abc, .{});
    try std.testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &std.fmt.bytesToHex(abc, .lower));
}

test "crc32c matches the standard library" {
    var prng = std.Random.DefaultPrng.init(9);
    var data: [300]u8 = undefined;
    prng.random().bytes(&data);
    for ([_]usize{ 0, 1, 7, 8, 9, 64, 299, 300 }) |len| {
        try std.testing.expectEqual(std.hash.crc.Crc32Iscsi.hash(data[0..len]), crc32c(data[0..len]));
    }
    try std.testing.expectEqual(@as(u32, 0xE3069283), crc32c("123456789"));
}
