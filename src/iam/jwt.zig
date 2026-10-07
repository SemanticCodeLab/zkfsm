//! OpenID Connect ID/access token (JWS compact) validation against a JWKS document,
//! for AssumeRoleWithWebIdentity / AssumeRoleWithClientGrants. Inputs are untrusted:
//! every size is bounded and failures map to a closed error set.
const std = @import("std");

const rsa = std.crypto.Certificate.rsa;
const EcP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const sha2 = std.crypto.hash.sha2;
const b64 = std.base64.url_safe_no_pad;

pub const limits = struct {
    pub const max_token_bytes = 16 * 1024;
    pub const max_jwks_bytes = 256 * 1024;
    pub const max_keys = 32;
    pub const max_header_bytes = 2048;
    pub const max_claims_bytes = 12 * 1024;
    pub const min_rsa_bits = 2048;
    pub const max_rsa_bytes = 512;
};

pub const Alg = enum {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,

    pub fn fromString(s: []const u8) ?Alg {
        return std.meta.stringToEnum(Alg, s);
    }
};

pub const Key = struct {
    kid: []const u8,
    alg: ?Alg,
    key: union(enum) {
        rsa: struct { modulus: []const u8, exponent: []const u8 },
        p256: [65]u8,
        p384: [97]u8,
    },

    fn supports(self: *const Key, alg: Alg) bool {
        if (self.alg) |a| if (a != alg) return false;
        return switch (alg) {
            .RS256, .RS384, .RS512 => self.key == .rsa,
            .ES256 => self.key == .p256,
            .ES384 => self.key == .p384,
        };
    }
};

pub const JwksError = error{ OutOfMemory, TooLarge, Malformed, NoUsableKeys };

pub const KeySet = struct {
    arena: std.heap.ArenaAllocator,
    keys: []const Key,

    /// Parses a JWKS JSON document ({"keys":[...]}). Unsupported or encryption keys are
    /// skipped; fails only on malformed JSON, oversize input, or zero usable keys.
    pub fn parse(gpa: std.mem.Allocator, json: []const u8) JwksError!KeySet {
        if (json.len > limits.max_jwks_bytes) return error.TooLarge;
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const root = try parseJson(a, json);
        if (root != .object) return error.Malformed;
        const arr = root.object.get("keys") orelse return error.Malformed;
        if (arr != .array) return error.Malformed;
        if (arr.array.items.len > limits.max_keys) return error.TooLarge;
        var keys: std.ArrayListUnmanaged(Key) = .empty;
        for (arr.array.items) |jwk| {
            if (jwk != .object) return error.Malformed;
            if (try parseJwk(a, jwk.object)) |k| try keys.append(a, k);
        }
        if (keys.items.len == 0) return error.NoUsableKeys;
        return .{ .arena = arena, .keys = keys.items };
    }

    pub fn deinit(self: *KeySet) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn parseJson(a: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, Malformed }!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
    }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Malformed,
    };
}

fn optString(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

/// Decodes base64url (no padding) into a fresh arena slice of at most `max` bytes.
fn decodeAlloc(a: std.mem.Allocator, s: []const u8, max: usize) error{ OutOfMemory, Malformed }![]u8 {
    const n = b64.Decoder.calcSizeForSlice(s) catch return error.Malformed;
    if (n > max) return error.Malformed;
    const out = try a.alloc(u8, n);
    b64.Decoder.decode(out, s) catch return error.Malformed;
    return out;
}

fn decodeFixed(comptime n: usize, s: []const u8) ?[n]u8 {
    const len = b64.Decoder.calcSizeForSlice(s) catch return null;
    if (len != n) return null;
    var out: [n]u8 = undefined;
    b64.Decoder.decode(&out, s) catch return null;
    return out;
}

/// Returns null for keys we cannot or must not use for signature checks.
fn parseJwk(a: std.mem.Allocator, obj: std.json.ObjectMap) error{OutOfMemory}!?Key {
    if (obj.get("use")) |u| if (u != .string or !std.mem.eql(u8, u.string, "sig")) return null;
    const kid = if (obj.get("kid")) |k| (if (k == .string) k.string else return null) else "";
    var alg: ?Alg = null;
    if (obj.get("alg")) |v| {
        if (v != .string) return null;
        alg = Alg.fromString(v.string) orelse return null;
    }
    const kty = optString(obj, "kty") orelse return null;
    if (std.mem.eql(u8, kty, "RSA")) {
        const n_s = optString(obj, "n") orelse return null;
        const e_s = optString(obj, "e") orelse return null;
        var n = decodeAlloc(a, n_s, limits.max_rsa_bytes + 1) catch |e| return mapSkip(e);
        n = n[(std.mem.indexOfNone(u8, n, &.{0}) orelse n.len)..];
        if (n.len != 256 and n.len != 384 and n.len != 512) return null;
        if (n.len * 8 < limits.min_rsa_bits) return null;
        var e = decodeAlloc(a, e_s, 8) catch |err| return mapSkip(err);
        e = e[(std.mem.indexOfNone(u8, e, &.{0}) orelse e.len)..];
        if (e.len == 0 or e.len > 4 or e[e.len - 1] & 1 == 0) return null;
        if (e.len == 1 and e[0] < 3) return null;
        _ = rsa.PublicKey.fromBytes(e, n) catch return null;
        return .{ .kid = kid, .alg = alg, .key = .{ .rsa = .{ .modulus = n, .exponent = e } } };
    }
    if (std.mem.eql(u8, kty, "EC")) {
        const crv = optString(obj, "crv") orelse return null;
        const x_s = optString(obj, "x") orelse return null;
        const y_s = optString(obj, "y") orelse return null;
        if (std.mem.eql(u8, crv, "P-256")) {
            const sec1 = ecPoint(32, x_s, y_s) orelse return null;
            _ = EcP256.PublicKey.fromSec1(&sec1) catch return null;
            return .{ .kid = kid, .alg = alg, .key = .{ .p256 = sec1 } };
        }
        if (std.mem.eql(u8, crv, "P-384")) {
            const sec1 = ecPoint(48, x_s, y_s) orelse return null;
            _ = EcP384.PublicKey.fromSec1(&sec1) catch return null;
            return .{ .kid = kid, .alg = alg, .key = .{ .p384 = sec1 } };
        }
    }
    return null;
}

fn mapSkip(e: error{ OutOfMemory, Malformed }) error{OutOfMemory}!?Key {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => null,
    };
}

fn ecPoint(comptime n: usize, x_s: []const u8, y_s: []const u8) ?[1 + 2 * n]u8 {
    const x = decodeFixed(n, x_s) orelse return null;
    const y = decodeFixed(n, y_s) orelse return null;
    return [_]u8{4} ++ x ++ y;
}

pub const Header = struct {
    alg: []const u8,
    kid: ?[]const u8,
};

/// Scratch space for `peekHeader`; returned slices point into it.
pub const HeaderBuffer = [8 * limits.max_header_bytes]u8;

/// Reads "alg" and "kid" without verifying (to pick keys or refetch JWKS on unknown kid).
pub fn peekHeader(buf: *HeaderBuffer, token: []const u8) error{Malformed}!Header {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    const segs = try split(token);
    const obj = decodeObject(fba.allocator(), segs[0], limits.max_header_bytes) catch return error.Malformed;
    return headerFields(obj);
}

fn headerFields(obj: std.json.ObjectMap) error{Malformed}!Header {
    const alg = obj.get("alg") orelse return error.Malformed;
    if (alg != .string) return error.Malformed;
    var kid: ?[]const u8 = null;
    if (obj.get("kid")) |k| {
        if (k != .string) return error.Malformed;
        kid = k.string;
    }
    return .{ .alg = alg.string, .kid = kid };
}

fn split(token: []const u8) error{Malformed}![3][]const u8 {
    if (token.len > limits.max_token_bytes) return error.Malformed;
    var it = std.mem.splitScalar(u8, token, '.');
    const h = it.next() orelse return error.Malformed;
    const p = it.next() orelse return error.Malformed;
    const s = it.next() orelse return error.Malformed;
    if (it.next() != null or h.len == 0 or p.len == 0) return error.Malformed;
    return .{ h, p, s };
}

fn decodeObject(a: std.mem.Allocator, seg: []const u8, max: usize) error{ OutOfMemory, Malformed }!std.json.ObjectMap {
    const bytes = try decodeAlloc(a, seg, max);
    const v = try parseJson(a, bytes);
    if (v != .object) return error.Malformed;
    return v.object;
}

pub const Options = struct {
    /// When set, "iss" must equal it exactly.
    issuer: ?[]const u8 = null,
    /// When non-empty, "aud" (string or array) or "azp" must contain one of them.
    audiences: []const []const u8 = &.{},
    leeway_s: i64 = 60,
    require_exp: bool = true,
};

pub const VerifyError = error{ OutOfMemory, Malformed, UnsupportedAlgorithm, UnknownKey, BadSignature, Expired, NotYetValid, IssuerMismatch, AudienceMismatch };

pub const Claims = struct {
    object: std.json.ObjectMap,

    pub fn string(self: Claims, name: []const u8) ?[]const u8 {
        return optString(self.object, name);
    }

    /// A JSON array of strings or a comma-separated string, trimmed with empty items
    /// dropped; null if absent or of another type.
    pub fn stringList(self: Claims, arena: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]const []const u8 {
        const v = self.object.get(name) orelse return null;
        var out: std.ArrayListUnmanaged([]const u8) = .empty;
        switch (v) {
            .string => |s| {
                var it = std.mem.splitScalar(u8, s, ',');
                while (it.next()) |item| try appendTrimmed(arena, &out, item);
            },
            .array => |arr| for (arr.items) |item| {
                if (item != .string) return null;
                try appendTrimmed(arena, &out, item.string);
            },
            else => return null,
        }
        return out.items;
    }

    pub fn int(self: Claims, name: []const u8) ?i64 {
        const v = self.object.get(name) orelse return null;
        return switch (v) {
            .integer => |i| i,
            .float => |f| if (f >= -9.0e18 and f <= 9.0e18) @intFromFloat(@trunc(f)) else null,
            else => null,
        };
    }
};

fn appendTrimmed(a: std.mem.Allocator, out: *std.ArrayListUnmanaged([]const u8), item: []const u8) error{OutOfMemory}!void {
    const t = std.mem.trim(u8, item, " \t\r\n");
    if (t.len != 0) try out.append(a, t);
}

/// Verifies the signature (key by header kid, else every key compatible with alg), then
/// exp/nbf/iat/iss/aud. Claims are parsed into `arena`.
pub fn verify(arena: std.mem.Allocator, token: []const u8, keys: *const KeySet, now_s: i64, opts: Options) VerifyError!Claims {
    const segs = try split(token);
    const hobj = try decodeObject(arena, segs[0], limits.max_header_bytes);
    const header = try headerFields(hobj);
    if (hobj.get("crit") != null) return error.UnsupportedAlgorithm;
    const alg = Alg.fromString(header.alg) orelse return error.UnsupportedAlgorithm;

    var sig_buf: [limits.max_rsa_bytes]u8 = undefined;
    const sig_len = b64.Decoder.calcSizeForSlice(segs[2]) catch return error.Malformed;
    if (sig_len > sig_buf.len) return error.BadSignature;
    b64.Decoder.decode(sig_buf[0..sig_len], segs[2]) catch return error.Malformed;
    const sig = sig_buf[0..sig_len];
    const signed = token[0 .. segs[0].len + 1 + segs[1].len];

    var tried = false;
    var ok = false;
    for (keys.keys) |*k| {
        if (header.kid) |kid| if (!std.mem.eql(u8, k.kid, kid)) continue;
        if (!k.supports(alg)) continue;
        tried = true;
        if (checkSig(alg, k, signed, sig)) {
            ok = true;
            break;
        }
    }
    if (!tried) return error.UnknownKey;
    if (!ok) return error.BadSignature;

    const claims: Claims = .{ .object = try decodeObject(arena, segs[1], limits.max_claims_bytes) };
    try checkClaims(claims, now_s, opts);
    return claims;
}

fn checkSig(alg: Alg, k: *const Key, msg: []const u8, sig: []const u8) bool {
    return switch (k.key) {
        .rsa => |r| switch (r.modulus.len) {
            inline 256, 384, 512 => |n| rsaVerify(n, alg, r.modulus, r.exponent, msg, sig),
            else => false,
        },
        .p256 => |p| ecVerify(EcP256, &p, msg, sig),
        .p384 => |p| ecVerify(EcP384, &p, msg, sig),
    };
}

fn rsaVerify(comptime n: usize, alg: Alg, modulus: []const u8, exponent: []const u8, msg: []const u8, sig: []const u8) bool {
    if (sig.len != n) return false;
    const pk = rsa.PublicKey.fromBytes(exponent, modulus) catch return false;
    const s: [n]u8 = sig[0..n].*;
    const res = switch (alg) {
        .RS256 => rsa.PKCS1v1_5Signature.verify(n, s, msg, pk, sha2.Sha256),
        .RS384 => rsa.PKCS1v1_5Signature.verify(n, s, msg, pk, sha2.Sha384),
        .RS512 => rsa.PKCS1v1_5Signature.verify(n, s, msg, pk, sha2.Sha512),
        .ES256, .ES384 => return false,
    };
    res catch return false;
    return true;
}

fn ecVerify(comptime Scheme: type, sec1: []const u8, msg: []const u8, sig: []const u8) bool {
    if (sig.len != Scheme.Signature.encoded_length) return false;
    const pk = Scheme.PublicKey.fromSec1(sec1) catch return false;
    const s = Scheme.Signature.fromBytes(sig[0..Scheme.Signature.encoded_length].*);
    s.verify(msg, pk) catch return false;
    return true;
}

fn timeClaim(c: Claims, name: []const u8) error{Malformed}!?i64 {
    if (c.object.get(name) == null) return null;
    return c.int(name) orelse error.Malformed;
}

fn checkClaims(c: Claims, now_s: i64, opts: Options) VerifyError!void {
    if (try timeClaim(c, "exp")) |exp| {
        if (now_s -| opts.leeway_s >= exp) return error.Expired;
    } else if (opts.require_exp) return error.Malformed;
    if (try timeClaim(c, "nbf")) |nbf| if (now_s +| opts.leeway_s < nbf) return error.NotYetValid;
    if (try timeClaim(c, "iat")) |iat| if (now_s +| opts.leeway_s < iat) return error.NotYetValid;
    if (opts.issuer) |want| {
        const iss = c.string("iss") orelse return error.IssuerMismatch;
        if (!std.mem.eql(u8, iss, want)) return error.IssuerMismatch;
    }
    if (opts.audiences.len == 0) return;
    if (c.object.get("aud")) |aud| switch (aud) {
        .string => |s| if (audAllowed(opts, s)) return,
        .array => |arr| for (arr.items) |item| {
            if (item == .string and audAllowed(opts, item.string)) return;
        },
        else => return error.Malformed,
    };
    if (c.string("azp")) |azp| if (audAllowed(opts, azp)) return;
    return error.AudienceMismatch;
}

fn audAllowed(opts: Options, aud: []const u8) bool {
    for (opts.audiences) |want| if (std.mem.eql(u8, want, aud)) return true;
    return false;
}

// Fixtures generated offline with openssl (RSA-2048 "rsa1", P-256 "ec1").
const fx_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa1\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"mM_OkJUW8s-g9Uf-fh3tCIms8IGzg-49MWgp6hDpE5qQYUBd0jbzmrS9wKrFXPPJBuPkPSe8JDdoELZSKcT848SmWXHbtNiXn8kwdechVyFCx4z27DGDRN9w2CfZ4nikhn_qYr9iibe3qZ32PoEXBLFwq18xIH1lZ2-x49ccc1nL-BDNGcWogTLgTwoitF_VTIu4Od5QIlkvXe61utJ8r0II7HyHSC7-khhTB3Pwkgo7-B0BxwK9V1PaZPsfNFzNYXu9KpvG4T_Hg1JYkyzWT6dA7mdTIp4LLKSG7FfqLb7hoKNy2_Ik62wg9io0brYKksGlO1RsY6xmjy9lsQ757Q\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"ec1\",\"crv\":\"P-256\",\"x\":\"i0TRShQJaHKezCqw5-NnSjAv9CbndMLnNdEWa_GYJiM\",\"y\":\"mtefnh9RoI39Wn3zb1TkQ6nz2yi_dTXW_Le9z3tMeGQ\"},{\"kty\":\"RSA\",\"kid\":\"enc1\",\"use\":\"enc\",\"n\":\"mM_OkJUW8s-g9Uf-fh3tCIms8IGzg-49MWgp6hDpE5qQYUBd0jbzmrS9wKrFXPPJBuPkPSe8JDdoELZSKcT848SmWXHbtNiXn8kwdechVyFCx4z27DGDRN9w2CfZ4nikhn_qYr9iibe3qZ32PoEXBLFwq18xIH1lZ2-x49ccc1nL-BDNGcWogTLgTwoitF_VTIu4Od5QIlkvXe61utJ8r0II7HyHSC7-khhTB3Pwkgo7-B0BxwK9V1PaZPsfNFzNYXu9KpvG4T_Hg1JYkyzWT6dA7mdTIp4LLKSG7FfqLb7hoKNy2_Ik62wg9io0brYKksGlO1RsY6xmjy9lsQ757Q\",\"e\":\"AQAB\"},{\"kty\":\"OKP\",\"kid\":\"ed1\",\"crv\":\"Ed25519\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}";
const fx_rs = "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJhdWQiOiJzdHMiLCJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6MTcwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJncm91cHMiOlsiZGV2Iiwib3BzIl0sInJvbGVzIjoiIGFkbWluLCAscmVhZGVyICJ9.auJenYSIXMCG9q1QlIFAQkBmEJ9TmATB-XrIDpLjxg2ZE7gVS4-UIhaU8C38U0TYm5LDLmp1c_FWQ784Z3SbqTMmYwKCbAC_XmLNLRPynBE0MpkaJ6SwC6hK87IMeiFoxS06LfADFunsbaKqComQ_9pm_pJL6M0wBvPgMMgXzh4C3DvSs4smh5hxUCYlFjmb52Y0fx8AvRKC4sW1vfN_i0G0HvbOe70pFthrsteNdTglkMlMlfqweszUB_DQmaMjN6t8JePjoxdn0UvQRVWJnKYQjSS5LdPsOpLF6_4q3MWhJu__YAwcEXYuqs40qLN-59HpJLzY6TDwYc9HnUg6Hw";
const fx_rs_nokid = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJhdWQiOiJzdHMiLCJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6MTcwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJncm91cHMiOlsiZGV2Iiwib3BzIl0sInJvbGVzIjoiIGFkbWluLCAscmVhZGVyICJ9.dC5yOF8R6u3X8WSS6Qyk1jtdUpsfaItOv24frR4AsVhlvGUR_kQS1JOGU1bxmbaa6F_DYPefzx3HC0q6lfkmppiAsRfiT9uK1BLcAiDy5-zm-vQ2F0WR55Hsu-BMw6yLdMIemrsFSVooMrOmKKQYA70jMUT9YRNVnSlfaASoKAf5abCZVpauHCOrDlH8RH0z2RgZ4xzgkDfbX1VsBLApmLZt0YNJueg8OEf-aewZWNuH4qnCWiwhOjR1smR0Qhayw4bc4LFB4pWXOi0seJcRSkDv5rRHVVGYxQU8rGdc31TGNBX6tKdGzLmwYhQaLEi-9k5x83_oQ6T6LpGIcHMayQ";
const fx_es = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjMSJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYm9iIiwiYXVkIjpbIm90aGVyIiwic3RzIl0sImV4cCI6NDEwMjQ0NDgwMCwibmJmIjoxNzAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsImdyb3VwcyI6WyJkZXYiLCJvcHMiXSwicm9sZXMiOiIgYWRtaW4sICxyZWFkZXIgIn0.sw6yBG-7QLw_Dx2YcSRsCltMhsLRWXFJvHxSg9CyJPskOHae7G5xKzyvNRuzlyv_RqrKG8XZnQOmFAKUxJb6fQ";
const fx_badkid = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im5vcGUifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJhdWQiOiJzdHMiLCJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6MTcwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJncm91cHMiOlsiZGV2Iiwib3BzIl0sInJvbGVzIjoiIGFkbWluLCAscmVhZGVyICJ9.SeTf890Zi7UFsanVmF_rmp_cpPJyO7-vAOMC1A_c3slf5Pnr9XYZ52xN5D5fo4P_3oV6gTsdtCrY0rggyzKehGZTC4odjHgYqiXiaxsyZcNllq2dxWZUISIivFoLES62X79bJlPT4lvbrLMQEDTTI0w80gWmt188vD99zQvKbsRhCusIBnl6dTnn-MzTRovJyH8ng3Eq13LlODIh0I6lQib9A3rV6q95H4DDa4GJoHOYRwQPCqBvee5lp0WQJNnbILPRkxTodgR1PcttdhUxsx4OoSrAWa59UrQxOHuuYqYPLClcmTMDK62h_k-09Sv7_OpHWdL3bdzngaukgRvk2Q";
const fx_none = "eyJhbGciOiJub25lIn0.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZSIsICJzdWIiOiAiYWxpY2UiLCAiYXVkIjogInN0cyIsICJleHAiOiA0MTAyNDQ0ODAwLCAibmJmIjogMTcwMDAwMDAwMCwgImlhdCI6IDE3MDAwMDAwMDAsICJncm91cHMiOiBbImRldiIsICJvcHMiXSwgInJvbGVzIjogIiBhZG1pbiwgLHJlYWRlciAifQ.";

const t_now: i64 = 1_800_000_000;
const t_opts: Options = .{ .issuer = "https://issuer.example", .audiences = &.{"sts"} };

fn testKeys() !KeySet {
    return KeySet.parse(std.testing.allocator, fx_jwks);
}

fn testVerify(token: []const u8, now_s: i64, opts: Options) VerifyError!void {
    var ks = testKeys() catch return error.Malformed;
    defer ks.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = try verify(arena.allocator(), token, &ks, now_s, opts);
}

test "jwks skips enc and unsupported keys" {
    var ks = try testKeys();
    defer ks.deinit();
    try std.testing.expectEqual(@as(usize, 2), ks.keys.len);
    try std.testing.expectEqualStrings("rsa1", ks.keys[0].kid);
    try std.testing.expectEqual(@as(?Alg, .RS256), ks.keys[0].alg);
    try std.testing.expect(ks.keys[1].key == .p256);
}

test "jwks garbage and limits" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.Malformed, KeySet.parse(gpa, "{not json"));
    try std.testing.expectError(error.Malformed, KeySet.parse(gpa, "[]"));
    try std.testing.expectError(error.Malformed, KeySet.parse(gpa, "{\"keys\":3}"));
    try std.testing.expectError(error.NoUsableKeys, KeySet.parse(gpa, "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AA\"}]}"));
    try std.testing.expectError(error.NoUsableKeys, KeySet.parse(gpa, "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}"));
    const big = try gpa.alloc(u8, limits.max_jwks_bytes + 1);
    defer gpa.free(big);
    @memset(big, ' ');
    try std.testing.expectError(error.TooLarge, KeySet.parse(gpa, big));
}

test "RS256 valid and claim accessors" {
    var ks = try testKeys();
    defer ks.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try verify(a, fx_rs, &ks, t_now, t_opts);
    try std.testing.expectEqualStrings("alice", c.string("sub").?);
    try std.testing.expectEqual(@as(?i64, 4102444800), c.int("exp"));
    const groups = (try c.stringList(a, "groups")).?;
    try std.testing.expectEqual(@as(usize, 2), groups.len);
    try std.testing.expectEqualStrings("ops", groups[1]);
    const roles = (try c.stringList(a, "roles")).?;
    try std.testing.expectEqual(@as(usize, 2), roles.len);
    try std.testing.expectEqualStrings("admin", roles[0]);
    try std.testing.expectEqualStrings("reader", roles[1]);
    try std.testing.expect((try c.stringList(a, "exp")) == null);
    try std.testing.expect((try c.stringList(a, "missing")) == null);
}

test "RS256 without kid tries compatible keys" {
    try testVerify(fx_rs_nokid, t_now, t_opts);
}

test "ES256 valid with aud array" {
    try testVerify(fx_es, t_now, t_opts);
    try testVerify(fx_es, t_now, .{ .audiences = &.{ "x", "other" } });
}

test "tampered payload" {
    var buf: [fx_rs.len]u8 = fx_rs.*;
    const dot = std.mem.indexOfScalar(u8, &buf, '.').?;
    buf[dot + 5] = if (buf[dot + 5] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, testVerify(&buf, t_now, t_opts));
    var es: [fx_es.len]u8 = fx_es.*;
    es[es.len - 3] = if (es[es.len - 3] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, testVerify(&es, t_now, t_opts));
}

test "unknown kid and alg none" {
    try std.testing.expectError(error.UnknownKey, testVerify(fx_badkid, t_now, t_opts));
    try std.testing.expectError(error.UnsupportedAlgorithm, testVerify(fx_none, t_now, t_opts));
    var hb: HeaderBuffer = undefined;
    const h = try peekHeader(&hb, fx_badkid);
    try std.testing.expectEqualStrings("RS256", h.alg);
    try std.testing.expectEqualStrings("nope", h.kid.?);
    try std.testing.expectEqualStrings("none", (try peekHeader(&hb, fx_none)).alg);
}

test "time and identity claims" {
    try std.testing.expectError(error.Expired, testVerify(fx_rs, 4102444800 + 61, t_opts));
    try testVerify(fx_rs, 4102444800 + 59, t_opts);
    try std.testing.expectError(error.NotYetValid, testVerify(fx_rs, 1700000000 - 61, t_opts));
    try std.testing.expectError(error.IssuerMismatch, testVerify(fx_rs, t_now, .{ .issuer = "https://issuer.example/" }));
    try std.testing.expectError(error.AudienceMismatch, testVerify(fx_rs, t_now, .{ .audiences = &.{"other"} }));
    try std.testing.expectError(error.AudienceMismatch, testVerify(fx_es, t_now, .{ .audiences = &.{"nope"} }));
}

test "malformed tokens" {
    const gpa = std.testing.allocator;
    const big = try gpa.alloc(u8, limits.max_token_bytes + 1);
    defer gpa.free(big);
    @memset(big, 'A');
    try std.testing.expectError(error.Malformed, testVerify(big, t_now, t_opts));
    try std.testing.expectError(error.Malformed, testVerify("a.b", t_now, t_opts));
    try std.testing.expectError(error.Malformed, testVerify(fx_rs ++ ".x", t_now, t_opts));
    try std.testing.expectError(error.Malformed, testVerify(fx_rs ++ "=", t_now, t_opts));
    try std.testing.expectError(error.Malformed, testVerify("W10.e30.AA", t_now, t_opts));
    try std.testing.expectError(error.UnsupportedAlgorithm, testVerify("eyJhbGciOiJIUzI1NiJ9.e30.AA", t_now, t_opts));
    var hb: HeaderBuffer = undefined;
    try std.testing.expectError(error.Malformed, peekHeader(&hb, "!!.e30.AA"));
}
