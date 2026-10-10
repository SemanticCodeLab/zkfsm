//! Client certificate and key for mutual TLS: PEM loading and CertificateVerify
//! signing with ECDSA P-256/P-384, RSA (PSS, or PKCS#1 v1.5 in TLS 1.2) and Ed25519.
const std = @import("std");
const der = @import("der.zig");
const pem = @import("pem.zig");
const keys = @import("keys.zig");
const rsa = @import("rsa.zig");

const Certificate = std.crypto.Certificate;
pub const Scheme = std.crypto.tls.SignatureScheme;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const sha2 = std.crypto.hash.sha2;

pub const LoadError = error{ CannotRead, NoCertificate, BadCertificate, KeyMismatch, BadKey, UnsupportedKey, EncryptedKey, NoKey, OutOfMemory };
pub const SignError = error{SignFailed};

pub const max_signature_len = keys.max_signature_len;
/// Total DER bytes of the client chain; keeps the Certificate message small.
pub const max_chain_bytes = 1 << 15;
pub const max_chain = 8;
const max_file = 1 << 20;

const oid_ec = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_p384 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };

pub const Key = union(enum) {
    /// P-256 or RSA, parsed by the server key loader.
    std_key: keys.PrivateKey,
    p384: P384.KeyPair,
    ed25519: Ed25519.KeyPair,
};

pub const ClientAuth = struct {
    gpa: std.mem.Allocator,
    chain: [][]u8,
    key: Key,

    pub fn fromFiles(gpa: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) LoadError!ClientAuth {
        const cert = std.fs.cwd().readFileAlloc(gpa, cert_path, max_file) catch |e| return mapRead(e);
        defer gpa.free(cert);
        const key = std.fs.cwd().readFileAlloc(gpa, key_path, max_file) catch |e| return mapRead(e);
        defer {
            std.crypto.secureZero(u8, key);
            gpa.free(key);
        }
        return fromPem(gpa, cert, key);
    }

    pub fn fromPem(gpa: std.mem.Allocator, cert_pem: []const u8, key_pem: []const u8) LoadError!ClientAuth {
        const chain = try parseChain(gpa, cert_pem);
        errdefer freeChain(gpa, chain);
        var key = try parseKey(gpa, key_pem);
        errdefer wipeKey(gpa, &key);
        const leaf = (Certificate{ .buffer = chain[0], .index = 0 }).parse() catch return error.BadCertificate;
        if (!matches(key, leaf)) return error.KeyMismatch;
        return .{ .gpa = gpa, .chain = chain, .key = key };
    }

    pub fn deinit(a: *ClientAuth) void {
        freeChain(a.gpa, a.chain);
        wipeKey(a.gpa, &a.key);
        a.* = undefined;
    }

    /// Our scheme from the peer's offer (u16 big-endian list); PKCS#1 only before 1.3.
    pub fn chooseScheme(a: *const ClientAuth, offered: []const u8, tls13: bool) ?Scheme {
        const prefs: []const Scheme = switch (a.key) {
            .p384 => &.{.ecdsa_secp384r1_sha384},
            .ed25519 => &.{.ed25519},
            .std_key => |k| switch (k.kind) {
                .ecdsa_p256 => &.{.ecdsa_secp256r1_sha256},
                .rsa => if (tls13)
                    &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 }
                else
                    &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 },
            },
        };
        for (prefs) |want| {
            var i: usize = 0;
            while (i + 1 < offered.len) : (i += 2) {
                if (std.mem.readInt(u16, offered[i..][0..2], .big) == @intFromEnum(want)) return want;
            }
        }
        return null;
    }

    pub fn sign(a: *const ClientAuth, scheme: Scheme, msg: []const u8, out: *[max_signature_len]u8) SignError![]const u8 {
        switch (a.key) {
            .p384 => |kp| {
                const sig = kp.sign(msg, null) catch return error.SignFailed;
                return ecdsaDer(48, sig.r, sig.s, out);
            },
            .ed25519 => |kp| {
                const sig = kp.sign(msg, null) catch return error.SignFailed;
                out[0..64].* = sig.toBytes();
                return out[0..64];
            },
            .std_key => |k| switch (scheme) {
                .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => {
                    if (k.kind != .rsa) return error.SignFailed;
                    const o: *[rsa.max_bytes]u8 = out[0..rsa.max_bytes];
                    return switch (scheme) {
                        .rsa_pkcs1_sha256 => k.kind.rsa.signPkcs1(sha2.Sha256, msg, o),
                        .rsa_pkcs1_sha384 => k.kind.rsa.signPkcs1(sha2.Sha384, msg, o),
                        else => k.kind.rsa.signPkcs1(sha2.Sha512, msg, o),
                    } catch error.SignFailed;
                },
                else => return k.sign(scheme, msg, out) catch error.SignFailed,
            },
        }
    }
};

fn mapRead(e: anytype) LoadError {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.CannotRead;
}

fn freeChain(gpa: std.mem.Allocator, chain: [][]u8) void {
    for (chain) |c| gpa.free(c);
    gpa.free(chain);
}

fn parseChain(gpa: std.mem.Allocator, text: []const u8) LoadError![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |c| gpa.free(c);
        list.deinit(gpa);
    }
    var total: usize = 0;
    var it: pem.Iterator = .{ .text = text };
    while (it.next() catch return error.BadCertificate) |blk| {
        if (!std.mem.eql(u8, blk.label, "CERTIFICATE")) continue;
        if (list.items.len == max_chain) return error.BadCertificate;
        const d = pem.decode(gpa, blk.body) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadPem => error.BadCertificate,
        };
        list.append(gpa, d) catch {
            gpa.free(d);
            return error.OutOfMemory;
        };
        total += d.len;
        if (total > max_chain_bytes) return error.BadCertificate;
    }
    if (list.items.len == 0) return error.NoCertificate;
    return list.toOwnedSlice(gpa);
}

fn wipeKey(gpa: std.mem.Allocator, k: *Key) void {
    switch (k.*) {
        .std_key => |*s| s.deinit(gpa),
        .p384 => |*kp| std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key)),
        .ed25519 => |*kp| std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key)),
    }
}

fn parseKey(gpa: std.mem.Allocator, text: []const u8) LoadError!Key {
    if (keys.parsePem(gpa, text)) |k| return .{ .std_key = k } else |e| switch (e) {
        error.UnsupportedKey => {},
        else => |x| return x,
    }
    var it: pem.Iterator = .{ .text = text };
    while (it.next() catch return error.BadKey) |blk| {
        const pkcs8 = std.mem.eql(u8, blk.label, "PRIVATE KEY");
        if (!pkcs8 and !std.mem.eql(u8, blk.label, "EC PRIVATE KEY")) continue;
        const buf = pem.decode(gpa, blk.body) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadPem => error.BadKey,
        };
        defer {
            std.crypto.secureZero(u8, buf);
            gpa.free(buf);
        }
        const k: (LoadError || der.Error)!Key = if (pkcs8) parsePkcs8(buf) else if (parseSec1P384(buf, true)) |kp| .{ .p384 = kp } else |e| e;
        return k catch |e| switch (e) {
            error.BadDer => error.BadKey,
            else => |x| x,
        };
    }
    return error.NoKey;
}

fn parsePkcs8(buf: []const u8) (LoadError || der.Error)!Key {
    var top: der.Reader = .{ .bytes = buf };
    var seq = try top.sub(der.Tag.sequence);
    _ = try seq.uint();
    var alg = try seq.sub(der.Tag.sequence);
    const oid = try alg.expect(der.Tag.oid);
    const inner = try seq.expect(der.Tag.octet_string);
    if (std.mem.eql(u8, oid, &oid_ed25519)) {
        var r: der.Reader = .{ .bytes = inner };
        const seed = try r.expect(der.Tag.octet_string);
        if (seed.len != 32) return error.BadKey;
        const kp = Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return error.BadKey;
        return .{ .ed25519 = kp };
    }
    if (!std.mem.eql(u8, oid, &oid_ec)) return error.UnsupportedKey;
    const curve = try alg.expect(der.Tag.oid);
    if (!std.mem.eql(u8, curve, &oid_p384)) return error.UnsupportedKey;
    return .{ .p384 = try parseSec1P384(inner, false) };
}

fn parseSec1P384(buf: []const u8, need_curve: bool) (LoadError || der.Error)!P384.KeyPair {
    var top: der.Reader = .{ .bytes = buf };
    var seq = try top.sub(der.Tag.sequence);
    _ = try seq.uint();
    const secret = try seq.expect(der.Tag.octet_string);
    if (seq.peekTag() == der.Tag.ctx0) {
        var params = try seq.sub(der.Tag.ctx0);
        if (!std.mem.eql(u8, try params.expect(der.Tag.oid), &oid_p384)) return error.UnsupportedKey;
    } else if (need_curve) return error.UnsupportedKey;
    if (secret.len != 48) return error.UnsupportedKey;
    const sk = P384.SecretKey.fromBytes(secret[0..48].*) catch return error.BadKey;
    return P384.KeyPair.fromSecretKey(sk) catch error.BadKey;
}

fn matches(key: Key, leaf: Certificate.Parsed) bool {
    return switch (key) {
        .std_key => |k| k.matchesPublic(leaf.pub_key_algo, leaf.pubKey()),
        .p384 => |kp| leaf.pub_key_algo == .X9_62_id_ecPublicKey and
            leaf.pub_key_algo.X9_62_id_ecPublicKey == .secp384r1 and
            std.mem.eql(u8, &kp.public_key.toUncompressedSec1(), leaf.pubKey()),
        .ed25519 => |kp| leaf.pub_key_algo == .curveEd25519 and
            std.mem.eql(u8, &kp.public_key.toBytes(), leaf.pubKey()),
    };
}

/// SEQUENCE { INTEGER r, INTEGER s } with minimal integers.
fn ecdsaDer(comptime n: usize, r: [n]u8, s: [n]u8, out: *[max_signature_len]u8) []const u8 {
    var w: usize = 2;
    inline for (.{ r, s }) |v| {
        var i: usize = 0;
        while (i < n - 1 and v[i] == 0) i += 1;
        const pad: usize = @intFromBool(v[i] & 0x80 != 0);
        const len = n - i + pad;
        out[w] = 0x02;
        out[w + 1] = @intCast(len);
        out[w + 2] = 0;
        @memcpy(out[w + 2 + pad ..][0 .. n - i], v[i..]);
        w += 2 + len;
    }
    out[0] = 0x30;
    out[1] = @intCast(w - 2);
    return out[0..w];
}

const td = "testdata/";

fn verifyWithCert(a: *const ClientAuth, scheme: Scheme, sig: []const u8, msg: []const u8) !void {
    const leaf = try (Certificate{ .buffer = a.chain[0], .index = 0 }).parse();
    const pk = leaf.pubKey();
    switch (scheme) {
        .ecdsa_secp384r1_sha384 => try (try P384.Signature.fromDer(sig)).verify(msg, try P384.PublicKey.fromSec1(pk)),
        .ecdsa_secp256r1_sha256 => {
            const E = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            try (try E.Signature.fromDer(sig)).verify(msg, try E.PublicKey.fromSec1(pk));
        },
        .ed25519 => try Ed25519.Signature.fromBytes(sig[0..64].*).verify(msg, try Ed25519.PublicKey.fromBytes(pk[0..32].*)),
        .rsa_pkcs1_sha256 => {
            const R = Certificate.rsa;
            const c = try R.PublicKey.parseDer(pk);
            try R.PKCS1v1_5Signature.verify(256, sig[0..256].*, msg, try R.PublicKey.fromBytes(c.exponent, c.modulus), sha2.Sha256);
        },
        .rsa_pss_rsae_sha256 => {
            const R = Certificate.rsa;
            const c = try R.PublicKey.parseDer(pk);
            try R.PSSSignature.verify(256, sig[0..256].*, msg, try R.PublicKey.fromBytes(c.exponent, c.modulus), sha2.Sha256);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client keys load, pick schemes and sign verifiably" {
    const gpa = std.testing.allocator;
    const cases = .{
        .{ "p256", Scheme.ecdsa_secp256r1_sha256, false },
        .{ "p384", Scheme.ecdsa_secp384r1_sha384, false },
        .{ "ed25519", Scheme.ed25519, false },
        .{ "rsa", Scheme.rsa_pss_rsae_sha256, false },
        .{ "rsa", Scheme.rsa_pkcs1_sha256, true },
    };
    inline for (cases) |c| {
        var a = try ClientAuth.fromPem(gpa, @embedFile(td ++ "mtls_client_" ++ c[0] ++ ".pem"), @embedFile(td ++ "mtls_client_" ++ c[0] ++ ".key"));
        defer a.deinit();
        const offer = if (c[2]) [_]u8{ 0x04, 0x01 } else [_]u8{ 0x04, 0x01, 0x08, 0x07, 0x05, 0x03, 0x04, 0x03, 0x08, 0x04 };
        try std.testing.expectEqual(c[1], a.chooseScheme(&offer, false).?);
        var out: [max_signature_len]u8 = undefined;
        const sig = try a.sign(c[1], "transcript", &out);
        try verifyWithCert(&a, c[1], sig, "transcript");
    }
}

test "client auth rejects mismatched and garbage input" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.KeyMismatch, ClientAuth.fromPem(gpa, @embedFile(td ++ "mtls_client_p256.pem"), @embedFile(td ++ "mtls_client_p384.key")));
    try std.testing.expectError(error.NoCertificate, ClientAuth.fromPem(gpa, "x", @embedFile(td ++ "mtls_client_p384.key")));
    try std.testing.expectError(error.NoKey, ClientAuth.fromPem(gpa, @embedFile(td ++ "mtls_client_p256.pem"), "nothing"));
    var a = try ClientAuth.fromPem(gpa, @embedFile(td ++ "mtls_client_rsa.pem"), @embedFile(td ++ "mtls_client_rsa.key"));
    defer a.deinit();
    try std.testing.expect(a.chooseScheme(&.{ 0x04, 0x01 }, true) == null);
    try std.testing.expect(a.chooseScheme(&.{0x04}, false) == null);
}
