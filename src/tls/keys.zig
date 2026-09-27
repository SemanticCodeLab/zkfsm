//! Server private keys from PEM: PKCS#8, SEC1 EC and PKCS#1 RSA.
const std = @import("std");
const der = @import("der.zig");
const pem = @import("pem.zig");
const rsa = @import("rsa.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const SignatureScheme = std.crypto.tls.SignatureScheme;

pub const Error = error{ BadKey, UnsupportedKey, EncryptedKey, NoKey, OutOfMemory };
pub const SignError = error{SignFailed};

pub const max_signature_len = @max(rsa.max_bytes, Ecdsa.Signature.der_encoded_length_max);

const oid_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_rsa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };
const oid_ec = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

pub const PrivateKey = struct {
    /// Decoded DER; RSA fields point into it. Zeroed on deinit.
    der_buf: []u8,
    kind: union(enum) {
        ecdsa_p256: Ecdsa.KeyPair,
        rsa: rsa.PrivateKey,
    },

    pub fn deinit(k: *PrivateKey, gpa: std.mem.Allocator) void {
        std.crypto.secureZero(u8, k.der_buf);
        gpa.free(k.der_buf);
        if (k.kind == .ecdsa_p256) std.crypto.secureZero(u8, std.mem.asBytes(&k.kind.ecdsa_p256.secret_key));
        k.* = undefined;
    }

    /// Picks our signature scheme from the client's offer, in our preference order.
    pub fn chooseScheme(k: PrivateKey, offered: []const u8) ?SignatureScheme {
        const prefs: []const SignatureScheme = switch (k.kind) {
            .ecdsa_p256 => &.{.ecdsa_secp256r1_sha256},
            .rsa => &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        };
        for (prefs) |want| {
            var i: usize = 0;
            while (i + 1 < offered.len) : (i += 2) {
                if (std.mem.readInt(u16, offered[i..][0..2], .big) == @intFromEnum(want)) return want;
            }
        }
        return null;
    }

    pub fn sign(k: PrivateKey, scheme: SignatureScheme, msg: []const u8, out: *[max_signature_len]u8) SignError![]const u8 {
        switch (k.kind) {
            .ecdsa_p256 => |kp| {
                const sig = kp.sign(msg, null) catch return error.SignFailed;
                var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                const d = sig.toDer(&buf);
                @memcpy(out[0..d.len], d);
                return out[0..d.len];
            },
            .rsa => |r| {
                const o: *[rsa.max_bytes]u8 = out[0..rsa.max_bytes];
                return switch (scheme) {
                    .rsa_pss_rsae_sha256 => r.sign(std.crypto.hash.sha2.Sha256, msg, o),
                    .rsa_pss_rsae_sha384 => r.sign(std.crypto.hash.sha2.Sha384, msg, o),
                    .rsa_pss_rsae_sha512 => r.sign(std.crypto.hash.sha2.Sha512, msg, o),
                    else => error.SignFailed,
                } catch error.SignFailed;
            },
        }
    }

    /// True when `spki_key` (the certificate's subjectPublicKey bits) belongs to this key.
    pub fn matchesPublic(k: PrivateKey, algo: std.crypto.Certificate.Parsed.PubKeyAlgo, spki_key: []const u8) bool {
        switch (k.kind) {
            .ecdsa_p256 => |kp| {
                if (algo != .X9_62_id_ecPublicKey or algo.X9_62_id_ecPublicKey != .X9_62_prime256v1) return false;
                return std.mem.eql(u8, &kp.public_key.toUncompressedSec1(), spki_key);
            },
            .rsa => |r| {
                if (algo != .rsaEncryption and algo != .rsassa_pss) return false;
                var rd: der.Reader = .{ .bytes = spki_key };
                var seq = rd.sub(der.Tag.sequence) catch return false;
                const n = seq.uint() catch return false;
                const e = seq.uint() catch return false;
                return std.mem.eql(u8, n, r.n) and std.mem.eql(u8, e, r.e);
            },
        }
    }
};

/// Parses the first private key block in `text`.
pub fn parsePem(gpa: std.mem.Allocator, text: []const u8) Error!PrivateKey {
    var it: pem.Iterator = .{ .text = text };
    while (it.next() catch return error.BadKey) |blk| {
        const Fmt = enum { pkcs8, sec1, pkcs1 };
        const fmt: Fmt = if (std.mem.eql(u8, blk.label, "PRIVATE KEY"))
            .pkcs8
        else if (std.mem.eql(u8, blk.label, "EC PRIVATE KEY"))
            .sec1
        else if (std.mem.eql(u8, blk.label, "RSA PRIVATE KEY"))
            .pkcs1
        else if (std.mem.eql(u8, blk.label, "ENCRYPTED PRIVATE KEY"))
            return error.EncryptedKey
        else
            continue;
        if (std.mem.indexOf(u8, blk.body, "ENCRYPTED") != null) return error.EncryptedKey;
        const buf = pem.decode(gpa, blk.body) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadPem => error.BadKey,
        };
        errdefer {
            std.crypto.secureZero(u8, buf);
            gpa.free(buf);
        }
        var key: PrivateKey = .{ .der_buf = buf, .kind = undefined };
        key.kind = switch (fmt) {
            .pkcs8 => try parsePkcs8(buf),
            .sec1 => .{ .ecdsa_p256 = try parseSec1(buf) },
            .pkcs1 => .{ .rsa = try parsePkcs1(buf) },
        };
        if (key.kind == .rsa) key.kind.rsa.validate() catch return error.BadKey;
        return key;
    }
    return error.NoKey;
}

fn parsePkcs8(buf: []const u8) Error!@FieldType(PrivateKey, "kind") {
    var top: der.Reader = .{ .bytes = buf };
    var seq = top.sub(der.Tag.sequence) catch return error.BadKey;
    _ = seq.uint() catch return error.BadKey;
    var alg = seq.sub(der.Tag.sequence) catch return error.BadKey;
    const oid = alg.expect(der.Tag.oid) catch return error.BadKey;
    const inner = seq.expect(der.Tag.octet_string) catch return error.BadKey;
    if (std.mem.eql(u8, oid, &oid_rsa) or std.mem.eql(u8, oid, &oid_rsa_pss)) return .{ .rsa = try parsePkcs1(inner) };
    if (!std.mem.eql(u8, oid, &oid_ec)) return error.UnsupportedKey;
    const curve = alg.expect(der.Tag.oid) catch return error.UnsupportedKey;
    if (!std.mem.eql(u8, curve, &oid_p256)) return error.UnsupportedKey;
    return .{ .ecdsa_p256 = try parseSec1(inner) };
}

fn parseSec1(buf: []const u8) Error!Ecdsa.KeyPair {
    var top: der.Reader = .{ .bytes = buf };
    var seq = top.sub(der.Tag.sequence) catch return error.BadKey;
    _ = seq.uint() catch return error.BadKey;
    const secret = seq.expect(der.Tag.octet_string) catch return error.BadKey;
    if (seq.peekTag() == der.Tag.ctx0) {
        var params = seq.sub(der.Tag.ctx0) catch return error.BadKey;
        const curve = params.expect(der.Tag.oid) catch return error.UnsupportedKey;
        if (!std.mem.eql(u8, curve, &oid_p256)) return error.UnsupportedKey;
    }
    if (secret.len != 32) return error.UnsupportedKey;
    const sk = Ecdsa.SecretKey.fromBytes(secret[0..32].*) catch return error.BadKey;
    return Ecdsa.KeyPair.fromSecretKey(sk) catch error.BadKey;
}

fn parsePkcs1(buf: []const u8) Error!rsa.PrivateKey {
    var top: der.Reader = .{ .bytes = buf };
    var seq = top.sub(der.Tag.sequence) catch return error.BadKey;
    _ = seq.uint() catch return error.BadKey;
    var k: rsa.PrivateKey = undefined;
    k.n = seq.uint() catch return error.BadKey;
    k.e = seq.uint() catch return error.BadKey;
    _ = seq.uint() catch return error.BadKey; // d: CRT parameters are used instead
    k.p = seq.uint() catch return error.BadKey;
    k.q = seq.uint() catch return error.BadKey;
    k.dp = seq.uint() catch return error.BadKey;
    k.dq = seq.uint() catch return error.BadKey;
    k.qinv = seq.uint() catch return error.BadKey;
    if (k.n.len > rsa.max_bytes or k.n[0] == 0) return error.UnsupportedKey;
    return k;
}

test "garbage keys are rejected" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.NoKey, parsePem(a, "nothing here"));
    try std.testing.expectError(error.BadKey, parsePem(a, "-----BEGIN PRIVATE KEY-----\nMAMCAQA=\n-----END PRIVATE KEY-----\n"));
    try std.testing.expectError(error.EncryptedKey, parsePem(a, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"));
}
