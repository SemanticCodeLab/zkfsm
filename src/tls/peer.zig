//! Client certificates for mutual TLS: a bounded X.509 shape check that makes
//! std.crypto.Certificate.parse safe on hostile bytes, chain validation against
//! configured CAs, and CertificateVerify signature checks.
const std = @import("std");
const der = @import("der.zig");
const Certificate = std.crypto.Certificate;
const Scheme = std.crypto.tls.SignatureScheme;

pub const max_chain = 8;
pub const max_chain_bytes = 1 << 16;
pub const max_common_name = 64;

pub const ChainError = error{ BadCertificate, CertificateExpired, UnknownCa };
pub const SignatureError = error{ DecryptError, IllegalParameter, BadCertificate };

/// Schemes offered in CertificateRequest, all verifiable below.
pub const schemes = [_]Scheme{
    .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,    .rsa_pss_rsae_sha512,    .ed25519,
};

const oid_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_ec = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 };
const tag_bool: u8 = 0x01;
const tag_set: u8 = 0x31;
const tag_utc: u8 = 0x17;
const tag_gen: u8 = 0x18;

pub const Shape = struct { is_ca: bool };

/// Checks every element std's parser walks is present, typed and in bounds.
pub fn checkShape(bytes: []const u8) error{BadCertificate}!Shape {
    if (bytes.len > max_chain_bytes) return error.BadCertificate;
    return shape(bytes) catch error.BadCertificate;
}

fn shape(bytes: []const u8) der.Error!Shape {
    var top: der.Reader = .{ .bytes = bytes };
    var cert = try top.sub(der.Tag.sequence);
    try done(top);
    var tbs = try cert.sub(der.Tag.sequence);
    var outer_alg = try cert.sub(der.Tag.sequence);
    _ = try outer_alg.expect(der.Tag.oid);
    _ = try bitString(&cert);
    try done(cert);

    if (tbs.peekTag() == der.Tag.ctx0) {
        if ((try tbs.expect(der.Tag.ctx0)).len != 3) return error.BadDer;
    }
    _ = try tbs.expect(der.Tag.integer);
    var sig_alg = try tbs.sub(der.Tag.sequence);
    _ = try sig_alg.expect(der.Tag.oid);
    _ = try tbs.expect(der.Tag.sequence);
    var validity = try tbs.sub(der.Tag.sequence);
    try time(&validity);
    try time(&validity);
    try done(validity);
    var subject = try tbs.sub(der.Tag.sequence);
    while (!subject.done()) {
        var rdn = try subject.sub(tag_set);
        if (rdn.done()) return error.BadDer;
        while (!rdn.done()) {
            var atav = try rdn.sub(der.Tag.sequence);
            _ = try atav.expect(der.Tag.oid);
            try atav.skip();
            try done(atav);
        }
    }
    var spki = try tbs.sub(der.Tag.sequence);
    var algo = try spki.sub(der.Tag.sequence);
    const algo_oid = try algo.expect(der.Tag.oid);
    if (std.mem.eql(u8, algo_oid, &oid_ec)) {
        _ = try algo.expect(der.Tag.oid);
    } else if (!algo.done()) try algo.skip();
    try done(algo);
    const key = try bitString(&spki);
    try done(spki);
    if (std.mem.eql(u8, algo_oid, &oid_rsa)) {
        var k: der.Reader = .{ .bytes = key[1..] };
        var s = try k.sub(der.Tag.sequence);
        _ = try s.expect(der.Tag.integer);
        _ = try s.expect(der.Tag.integer);
        try done(s);
        try done(k);
    }

    var is_ca = false;
    for ([_][2]u8{ .{ 0x81, 0xa1 }, .{ 0x82, 0xa2 } }) |ids| {
        const t = tbs.peekTag() orelse break;
        if (t == ids[0] or t == ids[1]) _ = try tbs.expect(t);
    }
    if (tbs.peekTag() == 0xa3) {
        var wrap = try tbs.sub(0xa3);
        var exts = try wrap.sub(der.Tag.sequence);
        try done(wrap);
        while (!exts.done()) {
            var e = try exts.sub(der.Tag.sequence);
            const id = try e.expect(der.Tag.oid);
            if (e.peekTag() == tag_bool) _ = try e.expect(tag_bool);
            const val = try e.expect(der.Tag.octet_string);
            try done(e);
            if (std.mem.eql(u8, id, &oid_basic_constraints)) is_ca = try basicCa(val);
        }
    }
    try done(tbs);
    return .{ .is_ca = is_ca };
}

fn done(r: der.Reader) der.Error!void {
    if (!r.done()) return error.BadDer;
}

fn bitString(r: *der.Reader) der.Error![]const u8 {
    const b = try r.expect(der.Tag.bit_string);
    if (b.len == 0) return error.BadDer;
    return b;
}

fn time(r: *der.Reader) der.Error!void {
    const t = r.peekTag() orelse return error.BadDer;
    if (t != tag_utc and t != tag_gen) return error.BadDer;
    _ = try r.expect(t);
}

fn basicCa(val: []const u8) der.Error!bool {
    var r: der.Reader = .{ .bytes = val };
    var s = try r.sub(der.Tag.sequence);
    if (s.peekTag() != tag_bool) return false;
    const b = try s.expect(tag_bool);
    return b.len == 1 and b[0] != 0;
}

/// Shape-checks then parses with std; trusted CA bytes go through the same path.
pub fn parse(bytes: []const u8) error{BadCertificate}!struct { Certificate.Parsed, Shape } {
    const sh = try checkShape(bytes);
    const p = (Certificate{ .buffer = bytes, .index = 0 }).parse() catch return error.BadCertificate;
    return .{ p, sh };
}

/// Leaf first; each link must be signed by the next or by a configured CA.
pub fn verifyChain(chain: []const []const u8, cas: []const []const u8, now_s: i64) ChainError!Certificate.Parsed {
    if (chain.len == 0 or chain.len > max_chain) return error.BadCertificate;
    var parsed: [max_chain]Certificate.Parsed = undefined;
    var total: usize = 0;
    for (chain, 0..) |c, i| {
        total += c.len;
        if (total > max_chain_bytes) return error.BadCertificate;
        const p, const sh = try parse(c);
        if (i > 0 and !sh.is_ca) return error.BadCertificate;
        parsed[i] = p;
    }
    for (parsed[0..chain.len], 0..) |p, i| {
        var found: ?ChainError = null;
        for (cas) |ca_bytes| {
            const ca, _ = parse(ca_bytes) catch continue;
            if (!std.mem.eql(u8, ca.subject(), p.issuer())) continue;
            if (now_s < ca.validity.not_before or now_s > ca.validity.not_after) {
                found = error.CertificateExpired;
                continue;
            }
            if (p.verify(ca, now_s)) |_| return parsed[0] else |e| found = mapVerify(e);
        }
        if (found) |e| return e;
        if (i + 1 == chain.len) return error.UnknownCa;
        p.verify(parsed[i + 1], now_s) catch |e| return mapVerify(e);
    }
    return error.UnknownCa;
}

fn mapVerify(e: Certificate.Parsed.VerifyError) ChainError {
    return switch (e) {
        error.CertificateExpired, error.CertificateNotYetValid => error.CertificateExpired,
        else => error.BadCertificate,
    };
}

/// Verifies a CertificateVerify signature by the leaf key over `content`.
pub fn verifySignature(leaf: Certificate.Parsed, scheme: u16, sig: []const u8, content: []const u8) SignatureError!void {
    const key = leaf.pubKey();
    const algo = leaf.pub_key_algo;
    switch (scheme) {
        inline @intFromEnum(Scheme.ecdsa_secp256r1_sha256), @intFromEnum(Scheme.ecdsa_secp384r1_sha384) => |v| {
            const p256 = v == @intFromEnum(Scheme.ecdsa_secp256r1_sha256);
            const E = if (p256) std.crypto.sign.ecdsa.EcdsaP256Sha256 else std.crypto.sign.ecdsa.EcdsaP384Sha384;
            const want: Certificate.NamedCurve = if (p256) .X9_62_prime256v1 else .secp384r1;
            if (algo != .X9_62_id_ecPublicKey or algo.X9_62_id_ecPublicKey != want) return error.IllegalParameter;
            const pk = E.PublicKey.fromSec1(key) catch return error.BadCertificate;
            const s = E.Signature.fromDer(sig) catch return error.DecryptError;
            s.verify(content, pk) catch return error.DecryptError;
        },
        inline @intFromEnum(Scheme.rsa_pss_rsae_sha256), @intFromEnum(Scheme.rsa_pss_rsae_sha384), @intFromEnum(Scheme.rsa_pss_rsae_sha512) => |v| {
            const H = switch (v) {
                @intFromEnum(Scheme.rsa_pss_rsae_sha256) => std.crypto.hash.sha2.Sha256,
                @intFromEnum(Scheme.rsa_pss_rsae_sha384) => std.crypto.hash.sha2.Sha384,
                else => std.crypto.hash.sha2.Sha512,
            };
            if (algo != .rsaEncryption) return error.IllegalParameter;
            const rsa = Certificate.rsa;
            const parts = rsa.PublicKey.parseDer(key) catch return error.BadCertificate;
            switch (parts.modulus.len) {
                inline 256, 384, 512 => |n| {
                    const pk = rsa.PublicKey.fromBytes(parts.exponent, parts.modulus) catch return error.BadCertificate;
                    if (sig.len != n) return error.DecryptError;
                    rsa.PSSSignature.verify(n, sig[0..n].*, content, pk, H) catch return error.DecryptError;
                },
                else => return error.BadCertificate,
            }
        },
        @intFromEnum(Scheme.ed25519) => {
            const Ed = std.crypto.sign.Ed25519;
            if (algo != .curveEd25519) return error.IllegalParameter;
            if (key.len != Ed.PublicKey.encoded_length) return error.BadCertificate;
            if (sig.len != Ed.Signature.encoded_length) return error.DecryptError;
            const pk = Ed.PublicKey.fromBytes(key[0..Ed.PublicKey.encoded_length].*) catch return error.BadCertificate;
            const s = Ed.Signature.fromBytes(sig[0..Ed.Signature.encoded_length].*);
            s.verify(content, pk) catch return error.DecryptError;
        },
        else => return error.IllegalParameter,
    }
}

/// Subject CN if it is 1..64 printable bytes.
pub fn commonName(p: Certificate.Parsed) ?[]const u8 {
    const cn = p.commonName();
    if (cn.len == 0 or cn.len > max_common_name) return null;
    for (cn) |c| if (c < 0x20 or c == 0x7f) return null;
    return cn;
}

// Test fixtures: an EC P-256 CA and a leaf (CN=readwrite) it signed.
const test_ca_pem = @embedFile("testdata/ca.pem");
const test_leaf_pem = @embedFile("testdata/leaf.pem");

fn testDer(buf: []u8, text: []const u8) ![]const u8 {
    const pem = @import("pem.zig");
    var it: pem.Iterator = .{ .text = text };
    const blk = (try it.next()).?;
    const d = try pem.decode(std.testing.allocator, blk.body);
    defer std.testing.allocator.free(d);
    @memcpy(buf[0..d.len], d);
    return buf[0..d.len];
}

test "chain verifies, CN extracted, untrusted and expired rejected" {
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    const ca = try testDer(&a, test_ca_pem);
    const leaf = try testDer(&b, test_leaf_pem);
    try std.testing.expect((try checkShape(ca)).is_ca);
    try std.testing.expect(!(try checkShape(leaf)).is_ca);
    const now: i64 = 1_900_000_000;
    const p = try verifyChain(&.{leaf}, &.{ca}, now);
    try std.testing.expectEqualStrings("readwrite", commonName(p).?);
    try std.testing.expectError(error.UnknownCa, verifyChain(&.{leaf}, &.{}, now));
    try std.testing.expectError(error.CertificateExpired, verifyChain(&.{leaf}, &.{ca}, 4_200_000_000));
    // A non-CA cert may not act as an intermediate.
    try std.testing.expectError(error.BadCertificate, verifyChain(&.{ leaf, leaf }, &.{ca}, now));
    var nine: [9][]const u8 = @splat(leaf);
    try std.testing.expectError(error.BadCertificate, verifyChain(&nine, &.{ca}, now));
}

test "hostile certificate bytes never panic" {
    var a: [4096]u8 = undefined;
    const ca = try testDer(&a, test_ca_pem);
    var m: [4096]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    for (0..20000) |_| {
        @memcpy(m[0..ca.len], ca);
        const n = r.intRangeAtMost(usize, 1, 4);
        for (0..n) |_| m[r.uintLessThan(usize, ca.len)] = r.int(u8);
        const len = if (r.boolean()) ca.len else r.uintLessThan(usize, ca.len + 1);
        _ = verifyChain(&.{m[0..len]}, &.{ca}, 1_900_000_000) catch {};
    }
    try std.testing.expectError(error.BadCertificate, checkShape(&.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }));
    try std.testing.expectError(error.BadCertificate, checkShape(&.{ 0x30, 0x02, 0x04, 0x00 }));
}
