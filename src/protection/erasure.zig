//! Systematic Reed-Solomon codec over GF(2^8) for the closed EC profile set.
//! Parity rows are a Cauchy matrix, so any k of the k+m shards reconstruct.
const std = @import("std");
const gf = @import("erasure_gf.zig");

pub const stripe = @import("erasure_stripe.zig");

pub const Profile = enum {
    ec4_2,
    ec8_4,
    ec12_4,

    pub fn dataShards(p: Profile) u8 {
        return switch (p) {
            .ec4_2 => 4,
            .ec8_4 => 8,
            .ec12_4 => 12,
        };
    }

    pub fn parityShards(p: Profile) u8 {
        return switch (p) {
            .ec4_2 => 2,
            .ec8_4, .ec12_4 => 4,
        };
    }

    pub fn totalShards(p: Profile) u8 {
        return p.dataShards() + p.parityShards();
    }

    pub fn name(p: Profile) []const u8 {
        return switch (p) {
            .ec4_2 => "EC:4+2",
            .ec8_4 => "EC:8+4",
            .ec12_4 => "EC:12+4",
        };
    }

    pub fn fromGeometry(k: usize, m: usize) ProfileError!Profile {
        inline for (std.meta.tags(Profile)) |p| {
            if (p.dataShards() == k and p.parityShards() == m) return p;
        }
        return error.UnsupportedProfile;
    }

    pub fn parse(s: []const u8) ProfileError!Profile {
        inline for (std.meta.tags(Profile)) |p| {
            if (std.mem.eql(u8, s, p.name())) return p;
        }
        return error.UnsupportedProfile;
    }
};

pub const ProfileError = error{UnsupportedProfile};
pub const ShardError = error{ ShardCountMismatch, ShardSizeMismatch };
pub const ReconstructError = ShardError || error{TooManyMissing};

const max_k = 12;
const max_m = 4;
const max_n = max_k + max_m;

comptime {
    std.debug.assert(max_k <= gf.max_inputs and max_m <= gf.max_outputs);
}

pub const Codec = struct {
    profile: Profile,
    k: u8,
    m: u8,
    /// m x k parity coefficients, row-major.
    parity: [max_m * max_k]u8,

    pub fn init(profile: Profile) Codec {
        const k = profile.dataShards();
        const m = profile.parityShards();
        var c: Codec = .{ .profile = profile, .k = k, .m = m, .parity = undefined };
        // Cauchy: 1 / (x_i + y_j), x_i = k + i, y_j = j; all distinct.
        for (0..m) |i| {
            for (0..k) |j| c.parity[i * k + j] = gf.inv(@intCast((k + i) ^ j));
        }
        return c;
    }

    /// Row `r` of the (k+m) x k encoding matrix.
    fn row(c: *const Codec, r: usize, out: []u8) void {
        if (r < c.k) {
            @memset(out, 0);
            out[r] = 1;
        } else @memcpy(out, c.parity[(r - c.k) * c.k ..][0..c.k]);
    }

    fn coeffs(c: *const Codec) []const u8 {
        return c.parity[0 .. @as(usize, c.m) * c.k];
    }

    /// Fill `parity` from `data`; all shards must share one length.
    pub fn encode(c: *const Codec, data: []const []const u8, parity: []const []u8) ShardError!void {
        if (data.len != c.k or parity.len != c.m) return error.ShardCountMismatch;
        const len = data[0].len;
        for (data) |d| if (d.len != len) return error.ShardSizeMismatch;
        for (parity) |p| if (p.len != len) return error.ShardSizeMismatch;
        run(c.coeffs(), data, parity, len);
    }

    /// True when parity matches data. Uses a fixed stack scratch, no allocation.
    pub fn verify(c: *const Codec, shards: []const []const u8) ShardError!bool {
        if (shards.len != @as(usize, c.k) + c.m) return error.ShardCountMismatch;
        const len = shards[0].len;
        for (shards) |s| if (s.len != len) return error.ShardSizeMismatch;
        const chunk = 4096;
        var scratch: [max_m][chunk]u8 = undefined;
        var outs: [max_m][]u8 = undefined;
        var ins: [max_k][]const u8 = undefined;
        var pos: usize = 0;
        while (pos < len) : (pos += chunk) {
            const n = @min(chunk, len - pos);
            for (0..c.k) |i| ins[i] = shards[i][pos..][0..n];
            for (0..c.m) |i| outs[i] = scratch[i][0..n];
            gf.mulMatrix(c.coeffs(), ins[0..c.k], outs[0..c.m], 0, n);
            for (0..c.m) |i| {
                if (!std.mem.eql(u8, outs[i], shards[c.k + i][pos..][0..n])) return false;
            }
        }
        return true;
    }

    /// Rebuild every shard whose `present[i]` is false, writing into `shards[i]`.
    /// All k+m buffers must be allocated with equal length.
    pub fn reconstruct(c: *const Codec, shards: []const []u8, present: []const bool) ReconstructError!void {
        const n = @as(usize, c.k) + c.m;
        if (shards.len != n or present.len != n) return error.ShardCountMismatch;
        const len = shards[0].len;
        for (shards) |s| if (s.len != len) return error.ShardSizeMismatch;

        var missing_data: [max_k]usize = undefined;
        var nmd: usize = 0;
        var missing_par: [max_m]usize = undefined;
        var nmp: usize = 0;
        var have: [max_k]usize = undefined;
        var nh: usize = 0;
        for (0..n) |i| {
            if (present[i]) {
                if (nh < c.k) {
                    have[nh] = i;
                    nh += 1;
                }
            } else if (i < c.k) {
                missing_data[nmd] = i;
                nmd += 1;
            } else {
                if (nmp == max_m) return error.TooManyMissing;
                missing_par[nmp] = i;
                nmp += 1;
            }
        }
        if (nh < c.k) return error.TooManyMissing;

        if (nmd > 0) {
            // Rows of the inverse of the surviving submatrix give lost data.
            var sub: [max_k * max_k]u8 = undefined;
            for (0..c.k) |r| c.row(have[r], sub[r * c.k ..][0..c.k]);
            gf.invert(sub[0 .. @as(usize, c.k) * c.k], c.k) catch unreachable;
            var dec: [max_m * max_k]u8 = undefined;
            var ins: [max_k][]const u8 = undefined;
            var outs: [max_m][]u8 = undefined;
            for (0..nmd) |j| {
                @memcpy(dec[j * c.k ..][0..c.k], sub[missing_data[j] * c.k ..][0..c.k]);
                outs[j] = shards[missing_data[j]];
            }
            for (0..c.k) |i| ins[i] = shards[have[i]];
            run(dec[0 .. nmd * c.k], ins[0..c.k], outs[0..nmd], len);
        }
        if (nmp > 0) {
            var cf: [max_m * max_k]u8 = undefined;
            var ins: [max_k][]const u8 = undefined;
            var outs: [max_m][]u8 = undefined;
            for (0..nmp) |j| {
                c.row(missing_par[j], cf[j * c.k ..][0..c.k]);
                outs[j] = shards[missing_par[j]];
            }
            for (0..c.k) |i| ins[i] = shards[i];
            run(cf[0 .. nmp * c.k], ins[0..c.k], outs[0..nmp], len);
        }
    }
};

/// Runs the kernel in cache-sized column chunks so inputs stay hot in L1/L2.
fn run(coeffs: []const u8, inputs: []const []const u8, outputs: []const []u8, len: usize) void {
    const chunk = 16 * 1024;
    var pos: usize = 0;
    while (pos < len) : (pos += chunk) {
        gf.mulMatrix(coeffs, inputs, outputs, pos, @min(len, pos + chunk));
    }
}

test {
    _ = gf;
    _ = stripe;
}

test "profile set is closed" {
    try std.testing.expectEqual(Profile.ec8_4, try Profile.parse("EC:8+4"));
    try std.testing.expectEqual(Profile.ec12_4, try Profile.fromGeometry(12, 4));
    try std.testing.expectError(error.UnsupportedProfile, Profile.parse("EC:6+3"));
    try std.testing.expectError(error.UnsupportedProfile, Profile.fromGeometry(10, 2));
    try std.testing.expectError(error.UnsupportedProfile, Profile.parse(""));
}

const Fixture = struct {
    bufs: [max_n][]u8,
    orig: [max_n][]u8,

    fn init(a: std.mem.Allocator, c: *const Codec, len: usize, r: std.Random) !Fixture {
        var f: Fixture = undefined;
        const n = @as(usize, c.k) + c.m;
        for (0..n) |i| {
            f.bufs[i] = try a.alloc(u8, len);
            f.orig[i] = try a.alloc(u8, len);
        }
        for (0..c.k) |i| r.bytes(f.bufs[i]);
        var data: [max_k][]const u8 = undefined;
        for (0..c.k) |i| data[i] = f.bufs[i];
        try c.encode(data[0..c.k], f.bufs[c.k..n]);
        for (0..n) |i| @memcpy(f.orig[i], f.bufs[i]);
        return f;
    }

    fn deinit(f: *Fixture, a: std.mem.Allocator, n: usize) void {
        for (0..n) |i| {
            a.free(f.bufs[i]);
            a.free(f.orig[i]);
        }
    }
};

fn checkAllErasures(profile: Profile, len: usize) !void {
    const a = std.testing.allocator;
    const c = Codec.init(profile);
    const n = @as(usize, c.k) + c.m;
    var prng = std.Random.DefaultPrng.init(len *% 31 + n);
    var f = try Fixture.init(a, &c, len, prng.random());
    defer f.deinit(a, n);
    try std.testing.expect(try c.verify(f.bufs[0..n]));

    // Every subset of shards of size <= m.
    var mask: u32 = 0;
    while (mask < (@as(u32, 1) << @intCast(n))) : (mask += 1) {
        if (@popCount(mask) > c.m) continue;
        var present: [max_n]bool = undefined;
        for (0..n) |i| {
            present[i] = mask & (@as(u32, 1) << @intCast(i)) == 0;
            if (!present[i]) @memset(f.bufs[i], 0xA5);
        }
        try c.reconstruct(f.bufs[0..n], present[0..n]);
        for (0..n) |i| try std.testing.expectEqualSlices(u8, f.orig[i], f.bufs[i]);
    }
}

test "every erasure pattern up to m, all profiles" {
    for (std.meta.tags(Profile)) |p| try checkAllErasures(p, 200);
}

test "odd sizes and zero length" {
    for (std.meta.tags(Profile)) |p| {
        for ([_]usize{ 0, 1, 15, 63, 64, 65, 4097 }) |len| try checkAllErasures(p, len);
    }
}

test "too many missing is rejected" {
    const a = std.testing.allocator;
    const c = Codec.init(.ec4_2);
    var prng = std.Random.DefaultPrng.init(1);
    var f = try Fixture.init(a, &c, 32, prng.random());
    defer f.deinit(a, 6);
    const present = [_]bool{ false, false, false, true, true, true };
    try std.testing.expectError(error.TooManyMissing, c.reconstruct(f.bufs[0..6], &present));
    try std.testing.expectError(error.ShardCountMismatch, c.reconstruct(f.bufs[0..5], present[0..5]));
}

test "verify detects corruption in any shard" {
    const a = std.testing.allocator;
    for (std.meta.tags(Profile)) |p| {
        const c = Codec.init(p);
        const n = @as(usize, c.k) + c.m;
        var prng = std.Random.DefaultPrng.init(9);
        const r = prng.random();
        var f = try Fixture.init(a, &c, 5000, r);
        defer f.deinit(a, n);
        for (0..n) |i| {
            const at = r.uintLessThan(usize, 5000);
            f.bufs[i][at] ^= 1 + r.uintLessThan(u8, 255);
            try std.testing.expect(!try c.verify(f.bufs[0..n]));
            f.bufs[i][at] = f.orig[i][at];
            try std.testing.expect(try c.verify(f.bufs[0..n]));
        }
    }
}

test "mismatched shard sizes are rejected" {
    const c = Codec.init(.ec4_2);
    var b: [6][8]u8 = undefined;
    var short: [7]u8 = undefined;
    const data = [_][]const u8{ &b[0], &b[1], &b[2], &short };
    const par = [_][]u8{ &b[4], &b[5] };
    try std.testing.expectError(error.ShardSizeMismatch, c.encode(&data, &par));
    try std.testing.expectError(error.ShardCountMismatch, c.encode(data[0..3], &par));
}

// Generated by tests/erasure_ref.py (independent pure-Python codec).
const ref_vectors = @import("erasure_ref_vectors.zig");

test "matches independent reference implementation" {
    for (ref_vectors.cases) |case| {
        const p = try Profile.parse(case.profile);
        const c = Codec.init(p);
        const len = case.shard_len;
        var data: [max_k][]const u8 = undefined;
        for (0..c.k) |i| data[i] = case.data[i * len ..][0..len];
        var out: [max_m * 64]u8 = undefined;
        var par: [max_m][]u8 = undefined;
        for (0..c.m) |i| par[i] = out[i * len ..][0..len];
        try c.encode(data[0..c.k], par[0..c.m]);
        try std.testing.expectEqualSlices(u8, case.parity, out[0 .. @as(usize, c.m) * len]);
    }
}
