//! GF(2^8) arithmetic (polynomial 0x11D) and the SIMD multiply-accumulate
//! kernel used by the Reed-Solomon codec.
const std = @import("std");
const builtin = @import("builtin");

const poly: u16 = 0x11D;

const Tables = struct { exp: [512]u8, log: [256]u8 };

const tables: Tables = blk: {
    @setEvalBranchQuota(10_000);
    var t: Tables = .{ .exp = undefined, .log = [_]u8{0} ** 256 };
    var x: u16 = 1;
    for (0..255) |i| {
        t.exp[i] = @intCast(x);
        t.log[x] = @intCast(i);
        x <<= 1;
        if (x & 0x100 != 0) x ^= poly;
    }
    for (255..512) |i| t.exp[i] = t.exp[i - 255];
    break :blk t;
};

pub fn mul(a: u8, b: u8) u8 {
    if (a == 0 or b == 0) return 0;
    return tables.exp[@as(usize, tables.log[a]) + tables.log[b]];
}

/// Multiplicative inverse; `a` must be non-zero.
pub fn inv(a: u8) u8 {
    std.debug.assert(a != 0);
    return tables.exp[255 - @as(usize, tables.log[a])];
}

/// Full 256x256 product table for the scalar tail.
const mul_table: [256][256]u8 = blk: {
    @setEvalBranchQuota(200_000);
    var t: [256][256]u8 = undefined;
    for (0..256) |a| {
        for (0..256) |b| t[a][b] = mul(a, b);
    }
    break :blk t;
};

/// Nibble tables for one coefficient: c*x == lo[x & 15] ^ hi[x >> 4].
pub const Nibbles = struct {
    lo: [16]u8,
    hi: [16]u8,

    pub fn init(c: u8) Nibbles {
        var n: Nibbles = undefined;
        for (0..16) |i| {
            n.lo[i] = mul(c, @intCast(i));
            n.hi[i] = mul(c, @intCast(i << 4));
        }
        return n;
    }
};

// LLVM intrinsics are unavailable in the self-hosted (Debug) backend.
const x86_llvm = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm;
const has_avx512 = x86_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512bw);
const has_avx2 = x86_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
const has_ssse3 = x86_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3);

pub const lanes: usize = if (has_avx512) 64 else if (has_avx2) 32 else 16;
const V = @Vector(lanes, u8);

extern fn @"llvm.x86.avx512.pshuf.b.512"(V, V) V;
extern fn @"llvm.x86.avx2.pshuf.b"(V, V) V;
extern fn @"llvm.x86.ssse3.pshuf.b.128"(V, V) V;

/// Per-128-bit-lane table lookup (pshufb semantics for indices < 16).
inline fn lookup(t: V, idx: V) V {
    if (has_avx512) return @"llvm.x86.avx512.pshuf.b.512"(t, idx);
    if (has_avx2) return @"llvm.x86.avx2.pshuf.b"(t, idx);
    if (has_ssse3) return @"llvm.x86.ssse3.pshuf.b.128"(t, idx);
    var r: V = undefined;
    inline for (0..lanes) |i| r[i] = t[idx[i]];
    return r;
}

fn broadcast(t: [16]u8) V {
    var v: [lanes]u8 = undefined;
    for (0..lanes) |i| v[i] = t[i % 16];
    return v;
}

pub const max_inputs = 16;
pub const max_outputs = 4;

/// outputs[o] = sum_i coeffs[o][i] * inputs[i], over the byte range [from, to).
/// `coeffs` is row-major, outputs.len rows by inputs.len columns.
pub fn mulMatrix(coeffs: []const u8, inputs: []const []const u8, outputs: []const []u8, from: usize, to: usize) void {
    std.debug.assert(inputs.len <= max_inputs and outputs.len <= max_outputs);
    std.debug.assert(coeffs.len == inputs.len * outputs.len);
    switch (outputs.len) {
        0 => {},
        inline 1...max_outputs => |n| kernel(n, coeffs, inputs, outputs, from, to),
        else => unreachable,
    }
}

fn kernel(comptime n_out: usize, coeffs: []const u8, inputs: []const []const u8, outputs: []const []u8, from: usize, to: usize) void {
    const n_in = inputs.len;
    var lo: [max_outputs][max_inputs]V = undefined;
    var hi: [max_outputs][max_inputs]V = undefined;
    for (0..n_out) |o| {
        for (0..n_in) |i| {
            const nb = Nibbles.init(coeffs[o * n_in + i]);
            lo[o][i] = broadcast(nb.lo);
            hi[o][i] = broadcast(nb.hi);
        }
    }
    const mask: V = @splat(0x0f);
    const four: @Vector(lanes, u3) = @splat(4);
    var pos = from;
    while (pos + lanes <= to) : (pos += lanes) {
        var acc: [n_out]V = [_]V{@splat(0)} ** n_out;
        for (0..n_in) |i| {
            const x: V = inputs[i][pos..][0..lanes].*;
            const xl = x & mask;
            const xh = x >> four;
            inline for (0..n_out) |o| {
                acc[o] ^= lookup(lo[o][i], xl) ^ lookup(hi[o][i], xh);
            }
        }
        inline for (0..n_out) |o| outputs[o][pos..][0..lanes].* = acc[o];
    }
    while (pos < to) : (pos += 1) {
        for (0..n_out) |o| {
            var a: u8 = 0;
            for (0..n_in) |i| a ^= mul_table[coeffs[o * n_in + i]][inputs[i][pos]];
            outputs[o][pos] = a;
        }
    }
}

pub const InvertError = error{Singular};

/// In-place Gauss-Jordan inversion of an n x n row-major matrix.
pub fn invert(m: []u8, n: usize) InvertError!void {
    std.debug.assert(m.len == n * n and n <= max_inputs);
    var aug: [max_inputs][2 * max_inputs]u8 = undefined;
    for (0..n) |r| {
        for (0..n) |c| {
            aug[r][c] = m[r * n + c];
            aug[r][n + c] = if (r == c) 1 else 0;
        }
    }
    for (0..n) |col| {
        var piv = col;
        while (piv < n and aug[piv][col] == 0) piv += 1;
        if (piv == n) return error.Singular;
        std.mem.swap([2 * max_inputs]u8, &aug[piv], &aug[col]);
        const s = inv(aug[col][col]);
        for (0..2 * n) |c| aug[col][c] = mul(aug[col][c], s);
        for (0..n) |r| {
            if (r == col or aug[r][col] == 0) continue;
            const f = aug[r][col];
            for (0..2 * n) |c| aug[r][c] ^= mul(f, aug[col][c]);
        }
    }
    for (0..n) |r| {
        for (0..n) |c| m[r * n + c] = aug[r][n + c];
    }
}

test "field axioms" {
    for (1..256) |a| {
        try std.testing.expectEqual(@as(u8, 1), mul(@intCast(a), inv(@intCast(a))));
        try std.testing.expectEqual(@as(u8, @intCast(a)), mul(@intCast(a), 1));
    }
    try std.testing.expectEqual(@as(u8, 0), mul(0, 77));
    // 2 * 0x80 wraps through the polynomial.
    try std.testing.expectEqual(@as(u8, 0x1D), mul(2, 0x80));
    for (0..256) |c| {
        const nb = Nibbles.init(@intCast(c));
        for (0..256) |x| {
            try std.testing.expectEqual(mul(@intCast(c), @intCast(x)), nb.lo[x & 15] ^ nb.hi[x >> 4]);
        }
    }
}

test "simd kernel matches scalar" {
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    const len = 1000;
    var in_bufs: [5][len]u8 = undefined;
    for (&in_bufs) |*b| r.bytes(b);
    var out_bufs: [3][len]u8 = undefined;
    var coeffs: [15]u8 = undefined;
    r.bytes(&coeffs);
    const ins = [_][]const u8{ &in_bufs[0], &in_bufs[1], &in_bufs[2], &in_bufs[3], &in_bufs[4] };
    const outs = [_][]u8{ &out_bufs[0], &out_bufs[1], &out_bufs[2] };
    mulMatrix(&coeffs, &ins, &outs, 0, len);
    for (0..3) |o| {
        for (0..len) |p| {
            var a: u8 = 0;
            for (0..5) |i| a ^= mul(coeffs[o * 5 + i], in_bufs[i][p]);
            try std.testing.expectEqual(a, out_bufs[o][p]);
        }
    }
}

test "invert" {
    var m = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 10 };
    const orig = m;
    try invert(&m, 3);
    for (0..3) |r| {
        for (0..3) |c| {
            var s: u8 = 0;
            for (0..3) |k| s ^= mul(orig[r * 3 + k], m[k * 3 + c]);
            try std.testing.expectEqual(@as(u8, if (r == c) 1 else 0), s);
        }
    }
    var sing = [_]u8{ 1, 1, 1, 1 };
    try std.testing.expectError(error.Singular, invert(&sing, 2));
}
