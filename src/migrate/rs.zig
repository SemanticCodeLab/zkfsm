//! Reed-Solomon decoding for the source layout: GF(2^8) with polynomial 0x11d and a
//! systematic matrix derived from a Vandermonde matrix (rows r^c, times the inverse
//! of its top square). Only data shards are rebuilt; parity is never needed.
const std = @import("std");
const gf = @import("../protection/erasure_gf.zig");

pub const max_shards = 16;

pub const Error = error{ TooManyMissing, BadGeometry };

fn pow(a: u8, n: usize) u8 {
    if (n == 0) return 1;
    var r: u8 = 1;
    for (0..n) |_| r = gf.mul(r, a);
    return r;
}

pub const Codec = struct {
    k: usize,
    m: usize,
    /// (k+m) x k, row-major.
    matrix: [max_shards * max_shards]u8 = undefined,

    pub fn init(k: usize, m: usize) Error!Codec {
        if (k == 0 or k + m > max_shards) return error.BadGeometry;
        var c: Codec = .{ .k = k, .m = m };
        const n = k + m;
        var vm: [max_shards * max_shards]u8 = undefined;
        for (0..n) |r| for (0..k) |col| {
            vm[r * k + col] = pow(@intCast(r), col);
        };
        var top: [max_shards * max_shards]u8 = undefined;
        @memcpy(top[0 .. k * k], vm[0 .. k * k]);
        gf.invert(top[0 .. k * k], k) catch return error.BadGeometry;
        for (0..n) |r| for (0..k) |col| {
            var acc: u8 = 0;
            for (0..k) |i| acc ^= gf.mul(vm[r * k + i], top[i * k + col]);
            c.matrix[r * k + col] = acc;
        };
        return c;
    }

    /// Fills the missing data shards in place. `shards[i]` is null when shard i is
    /// unavailable; all present shards and every data-shard buffer share one length.
    pub fn reconstructData(c: *const Codec, shards: []?[]u8, bufs: [][]u8) Error!void {
        const k = c.k;
        if (shards.len != k + c.m or bufs.len < k) return error.BadGeometry;
        var missing = false;
        for (shards[0..k]) |s| if (s == null) {
            missing = true;
        };
        if (!missing) return;
        var rows: [max_shards]usize = undefined;
        var got: usize = 0;
        for (shards, 0..) |s, i| {
            if (got == k) break;
            if (s != null) {
                rows[got] = i;
                got += 1;
            }
        }
        if (got < k) return error.TooManyMissing;
        var sub: [max_shards * max_shards]u8 = undefined;
        for (0..k) |r| @memcpy(sub[r * k ..][0..k], c.matrix[rows[r] * k ..][0..k]);
        gf.invert(sub[0 .. k * k], k) catch return error.TooManyMissing;
        const len = shards[rows[0]].?.len;
        for (0..k) |i| {
            if (shards[i] != null) continue;
            const out = bufs[i][0..len];
            @memset(out, 0);
            for (0..k) |j| {
                const coef = sub[i * k + j];
                if (coef == 0) continue;
                var table: [256]u8 = undefined;
                for (&table, 0..) |*t, x| t.* = gf.mul(coef, @intCast(x));
                for (out, shards[rows[j]].?[0..len]) |*o, v| o.* ^= table[v];
            }
        }
        for (0..k) |i| if (shards[i] == null) {
            shards[i] = bufs[i][0..len];
        };
    }

    /// Parity rows of the systematic matrix applied to `data` (tests and self-checks).
    pub fn encodeParity(c: *const Codec, data: []const []const u8, parity: [][]u8) void {
        for (parity, 0..) |p, pi| {
            @memset(p, 0);
            for (data, 0..) |d, j| {
                const coef = c.matrix[(c.k + pi) * c.k + j];
                for (p, d) |*o, v| o.* ^= gf.mul(coef, v);
            }
        }
    }
};

test "systematic top rows" {
    const c = try Codec.init(4, 2);
    for (0..4) |r| for (0..4) |col| {
        try std.testing.expectEqual(@as(u8, if (r == col) 1 else 0), c.matrix[r * 4 + col]);
    };
}

test "any k shards rebuild the data" {
    const k = 3;
    const m = 2;
    const c = try Codec.init(k, m);
    var data: [k][8]u8 = undefined;
    for (&data, 0..) |*d, i| for (d, 0..) |*b, j| {
        b.* = @truncate(i * 31 + j * 7 + 1);
    };
    var par: [m][8]u8 = undefined;
    const dptr = [_][]const u8{ &data[0], &data[1], &data[2] };
    var pptr = [_][]u8{ &par[0], &par[1] };
    c.encodeParity(&dptr, &pptr);
    var bufs: [k][8]u8 = undefined;
    var bptr = [_][]u8{ &bufs[0], &bufs[1], &bufs[2] };
    // Drop every pair of shards in turn.
    for (0..k + m) |a| for (a + 1..k + m) |b| {
        var copy: [k + m][8]u8 = undefined;
        for (0..k) |i| copy[i] = data[i];
        for (0..m) |i| copy[k + i] = par[i];
        var shards: [k + m]?[]u8 = undefined;
        for (&shards, 0..) |*s, i| s.* = if (i == a or i == b) null else &copy[i];
        try c.reconstructData(&shards, &bptr);
        for (0..k) |i| try std.testing.expectEqualSlices(u8, &data[i], shards[i].?);
    };
    var none: [k + m]?[]u8 = .{ null, null, null, &par[0], &par[1] };
    try std.testing.expectError(error.TooManyMissing, c.reconstructData(&none, &bptr));
}
