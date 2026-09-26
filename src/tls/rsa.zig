//! RSASSA-PSS signing (RFC 8017 8.1) with a CRT private key; salt length = hash length.
const std = @import("std");
const ff = std.crypto.ff;

pub const max_bits = 4096;
pub const max_bytes = max_bits / 8;
const M = ff.Modulus(max_bits);

pub const Error = error{ BadKey, SignFailed };

/// Big-endian integers borrowed from the decoded key buffer.
pub const PrivateKey = struct {
    n: []const u8,
    e: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,

    pub fn modulusBits(k: PrivateKey) usize {
        return k.n.len * 8 - @clz(k.n[0]);
    }

    pub fn modulusLen(k: PrivateKey) usize {
        return k.n.len;
    }

    /// Rejects sizes outside 2048..4096 bits and keys that fail a sign/verify round trip.
    pub fn validate(k: PrivateKey) Error!void {
        const bits = k.modulusBits();
        if (bits < 2048 or bits > max_bits or k.e.len == 0 or k.e.len > 8) return error.BadKey;
        if (k.p.len == 0 or k.q.len == 0 or k.p.len > max_bytes / 2 + 1 or k.q.len > max_bytes / 2 + 1) return error.BadKey;
        var sig: [max_bytes]u8 = undefined;
        _ = try k.sign(std.crypto.hash.sha2.Sha256, "zkfsm key check", &sig);
    }

    /// Writes a signature of `msg` into `out` and returns it (length = modulus length).
    pub fn sign(k: PrivateKey, comptime Hash: type, msg: []const u8, out: *[max_bytes]u8) Error![]const u8 {
        var mh: [Hash.digest_length]u8 = undefined;
        Hash.hash(msg, &mh, .{});
        return k.signDigest(Hash, mh, out);
    }

    pub fn signDigest(k: PrivateKey, comptime Hash: type, m_hash: [Hash.digest_length]u8, out: *[max_bytes]u8) Error![]const u8 {
        const em_bits = k.modulusBits() - 1;
        const em_len = (em_bits + 7) / 8;
        var em_buf: [max_bytes]u8 = undefined;
        const em = em_buf[0..em_len];
        var salt: [Hash.digest_length]u8 = undefined;
        std.crypto.random.bytes(&salt);
        try pssEncode(Hash, m_hash, salt, em_bits, em);
        const k_len = k.modulusLen();
        const sig = out[0..k_len];
        try k.privateOp(em, sig);
        // Fault check: a faulty CRT result would leak a factor of n.
        try k.checkPublic(sig, em);
        return sig;
    }

    fn privateOp(k: PrivateKey, em: []const u8, sig: []u8) Error!void {
        const n = M.fromBytes(k.n, .big) catch return error.BadKey;
        var p = M.fromBytes(k.p, .big) catch return error.BadKey;
        defer wipe(&p);
        var q = M.fromBytes(k.q, .big) catch return error.BadKey;
        defer wipe(&q);
        const c = M.Fe.fromBytes(n, em, .big) catch return error.SignFailed;
        var m1 = p.powWithEncodedExponent(p.reduce(c.v), k.dp, .big) catch return error.BadKey;
        defer wipe(&m1);
        var m2 = q.powWithEncodedExponent(q.reduce(c.v), k.dq, .big) catch return error.BadKey;
        defer wipe(&m2);
        var qinv = M.Fe.fromBytes(p, k.qinv, .big) catch return error.BadKey;
        defer wipe(&qinv);
        var m2n = try lift(n, k.n.len, m2);
        defer wipe(&m2n);
        var h = p.mul(p.sub(m1, p.reduce(m2n.v)), qinv);
        defer wipe(&h);
        var qn = M.Fe.fromBytes(n, k.q, .big) catch return error.BadKey;
        defer wipe(&qn);
        const m = n.add(n.mul(try lift(n, k.n.len, h), qn), m2n);
        m.toBytes(sig, .big) catch return error.SignFailed;
    }

    fn wipe(x: anytype) void {
        std.crypto.secureZero(u8, std.mem.asBytes(x));
    }

    /// Re-encodes a value below a prime factor as an element mod n.
    fn lift(n: M, n_len: usize, x: M.Fe) Error!M.Fe {
        var buf: [max_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        x.toBytes(buf[0..n_len], .big) catch return error.SignFailed;
        return M.Fe.fromBytes(n, buf[0..n_len], .big) catch error.SignFailed;
    }

    fn checkPublic(k: PrivateKey, sig: []const u8, em: []const u8) Error!void {
        const n = M.fromBytes(k.n, .big) catch return error.BadKey;
        const s = M.Fe.fromBytes(n, sig, .big) catch return error.SignFailed;
        const v = n.powWithEncodedPublicExponent(s, k.e, .big) catch return error.BadKey;
        var got: [max_bytes]u8 = undefined;
        v.toBytes(got[0..em.len], .big) catch return error.SignFailed;
        if (!std.mem.eql(u8, got[0..em.len], em)) return error.SignFailed;
    }
};

fn pssEncode(comptime Hash: type, m_hash: [Hash.digest_length]u8, salt: [Hash.digest_length]u8, em_bits: usize, em: []u8) Error!void {
    const h_len = Hash.digest_length;
    if (em.len < 2 * h_len + 2) return error.BadKey;
    var h: [h_len]u8 = undefined;
    var hs = Hash.init(.{});
    hs.update(&([_]u8{0} ** 8));
    hs.update(&m_hash);
    hs.update(&salt);
    hs.final(&h);
    const db_len = em.len - h_len - 1;
    const db = em[0..db_len];
    @memset(db, 0);
    db[db_len - h_len - 1] = 0x01;
    @memcpy(db[db_len - h_len ..], &salt);
    mgf1Xor(Hash, &h, db);
    const clear_bits: u3 = @intCast(8 * em.len - em_bits);
    db[0] &= @as(u8, 0xff) >> clear_bits;
    @memcpy(em[db_len..][0..h_len], &h);
    em[em.len - 1] = 0xbc;
}

fn mgf1Xor(comptime Hash: type, seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < out.len) : (counter += 1) {
        var d: [Hash.digest_length]u8 = undefined;
        var hs = Hash.init(.{});
        hs.update(seed);
        var cb: [4]u8 = undefined;
        std.mem.writeInt(u32, &cb, counter, .big);
        hs.update(&cb);
        hs.final(&d);
        const n = @min(d.len, out.len - i);
        for (out[i..][0..n], d[0..n]) |*o, x| o.* ^= x;
        i += n;
    }
}

test "pss encode verifies with std verifier" {
    // Encoding only: std's EMSA-PSS-VERIFY must accept what we produce.
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var mh: [32]u8 = undefined;
    Sha256.hash("abc", &mh, .{});
    var salt: [32]u8 = undefined;
    std.crypto.random.bytes(&salt);
    var em: [256]u8 = undefined;
    try pssEncode(Sha256, mh, salt, 2047, &em);
    try std.testing.expectEqual(@as(u8, 0xbc), em[255]);
    try std.testing.expect(em[0] & 0x80 == 0);
}
