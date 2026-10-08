//! TLS 1.2 (RFC 5246) pieces: PRF, extended master secret (RFC 7627), and AEAD
//! record protection: AES-GCM with an explicit nonce (RFC 5288), ChaCha20-Poly1305
//! with an XOR nonce (RFC 7905). No CBC, no static RSA.
const std = @import("std");
const tls = std.crypto.tls;
const aead = std.crypto.aead;
const sha2 = std.crypto.hash.sha2;
const sched = @import("schedule.zig");

pub const master_len = 48;
pub const verify_len = 12;
pub const random_len = 32;
pub const OpenError = sched.OpenError;

/// P_hash(secret, label || seed) truncated to `out.len` (RFC 5246 section 5).
pub fn prf(comptime H: type, secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void {
    const Hmac = std.crypto.auth.hmac.Hmac(H);
    var a: [Hmac.mac_length]u8 = undefined;
    var block: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &a);
    defer std.crypto.secureZero(u8, &block);
    var h = Hmac.init(secret);
    h.update(label);
    h.update(seed);
    h.final(&a);
    var i: usize = 0;
    while (i < out.len) {
        h = Hmac.init(secret);
        h.update(&a);
        h.update(label);
        h.update(seed);
        h.final(&block);
        const n = @min(block.len, out.len - i);
        @memcpy(out[i..][0..n], block[0..n]);
        i += n;
        h = Hmac.init(secret);
        h.update(&a);
        h.final(&a);
    }
}

pub fn Suite(comptime Aead: type, comptime H: type, comptime ecdsa: u16, comptime rsa: u16, comptime explicit: bool) type {
    return struct {
        pub const ecdsa_id = ecdsa;
        pub const rsa_id = rsa;
        pub const Hash = H;
        pub const hash_len = H.digest_length;
        pub const tag_len = Aead.tag_length;
        /// Bytes of IV from the key block: the GCM salt, or the whole ChaCha nonce.
        pub const fixed_iv_len = if (explicit) 4 else Aead.nonce_length;
        pub const explicit_len = if (explicit) 8 else 0;
        const key_block_len = 2 * (Aead.key_length + fixed_iv_len);

        /// master_secret with the extended master secret construction (RFC 7627 section 4).
        pub fn masterSecret(pre_master: []const u8, session_hash: *const [hash_len]u8) [master_len]u8 {
            var out: [master_len]u8 = undefined;
            prf(H, pre_master, "extended master secret", session_hash, &out);
            return out;
        }

        pub fn verifyData(master: *const [master_len]u8, comptime label: []const u8, transcript: *const [hash_len]u8) [verify_len]u8 {
            var out: [verify_len]u8 = undefined;
            prf(H, master, label, transcript, &out);
            return out;
        }

        pub const Directions = struct { client: Traffic, server: Traffic };

        /// Key block split into client and server write keys (RFC 5246 section 6.3).
        pub fn trafficKeys(master: *const [master_len]u8, client_random: [random_len]u8, server_random: [random_len]u8) Directions {
            var seed: [2 * random_len]u8 = undefined;
            seed[0..random_len].* = server_random;
            seed[random_len..].* = client_random;
            var kb: [key_block_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &kb);
            prf(H, master, "key expansion", &seed, &kb);
            const kl = Aead.key_length;
            return .{
                .client = .{ .key = kb[0..kl].*, .iv = kb[2 * kl ..][0..fixed_iv_len].* },
                .server = .{ .key = kb[kl..][0..kl].*, .iv = kb[2 * kl + fixed_iv_len ..][0..fixed_iv_len].* },
            };
        }

        /// One direction of TLS 1.2 record protection.
        pub const Traffic = struct {
            key: [Aead.key_length]u8,
            iv: [fixed_iv_len]u8,
            seq: u64 = 0,

            /// Record body bytes beyond the plaintext.
            pub const overhead = explicit_len + tag_len;

            pub fn wipe(t: *Traffic) void {
                std.crypto.secureZero(u8, std.mem.asBytes(t));
            }

            /// GCM: salt || explicit; ChaCha: iv XOR padded sequence number.
            pub fn nonce(t: Traffic, explicit_part: [8]u8) [Aead.nonce_length]u8 {
                var n: [Aead.nonce_length]u8 = undefined;
                if (explicit) {
                    n[0..4].* = t.iv;
                    n[4..].* = explicit_part;
                } else {
                    n = t.iv;
                    var seq: [8]u8 = undefined;
                    std.mem.writeInt(u64, &seq, t.seq, .big);
                    for (n[n.len - 8 ..], seq) |*a, b| a.* ^= b;
                }
                return n;
            }

            fn aad(t: Traffic, ct: u8, len: usize) [13]u8 {
                var a: [13]u8 = undefined;
                std.mem.writeInt(u64, a[0..8], t.seq, .big);
                a[8..13].* = .{ ct, 3, 3, @intCast(len >> 8), @truncate(len) };
                return a;
            }

            /// Encrypts `data` as one record of type `ct` into `out`; returns its length.
            pub fn seal(t: *Traffic, ct: tls.ContentType, data: []const u8, scratch: []u8, out: []u8) usize {
                _ = scratch;
                std.debug.assert(data.len <= sched.max_plaintext);
                const body_len = explicit_len + data.len + tag_len;
                out[0..sched.header_len].* = .{ @intFromEnum(ct), 3, 3, @intCast(body_len >> 8), @truncate(body_len) };
                var ex: [8]u8 = undefined;
                std.mem.writeInt(u64, &ex, t.seq, .big);
                const body = out[sched.header_len..][0..body_len];
                if (explicit) body[0..8].* = ex;
                const ad = t.aad(@intFromEnum(ct), data.len);
                Aead.encrypt(body[explicit_len..][0..data.len], body[explicit_len + data.len ..][0..tag_len], data, &ad, t.nonce(ex), t.key);
                t.seq += 1;
                return sched.header_len + body_len;
            }

            /// Decrypts one record body into `out`; the content type is the header's.
            pub fn open(t: *Traffic, hdr: *const [sched.header_len]u8, body: []const u8, out: []u8) OpenError!struct { tls.ContentType, []u8 } {
                if (body.len > sched.max_ciphertext) return error.RecordOverflow;
                if (body.len < explicit_len + tag_len) return error.BadRecordMac;
                const clen = body.len - explicit_len - tag_len;
                if (clen > sched.max_plaintext) return error.RecordOverflow;
                const ex: [8]u8 = if (explicit) body[0..8].* else undefined;
                const ad = t.aad(hdr[0], clen);
                const c = body[explicit_len..][0..clen];
                Aead.decrypt(out[0..clen], c, body[explicit_len + clen ..][0..tag_len].*, &ad, t.nonce(ex), t.key) catch return error.BadRecordMac;
                t.seq += 1;
                return .{ @enumFromInt(hdr[0]), out[0..clen] };
            }
        };
    };
}

pub const Gcm128 = Suite(aead.aes_gcm.Aes128Gcm, sha2.Sha256, 0xc02b, 0xc02f, true);
pub const Gcm256 = Suite(aead.aes_gcm.Aes256Gcm, sha2.Sha384, 0xc02c, 0xc030, true);
pub const Chacha = Suite(aead.chacha_poly.ChaCha20Poly1305, sha2.Sha256, 0xcca9, 0xcca8, false);

/// Last 8 bytes of ServerHello.random when a 1.3-capable server picks 1.2 (RFC 8446 4.1.3).
pub const downgrade_sentinel = "DOWNGRD\x01".*;
pub const scsv_renegotiation: u16 = 0x00ff;
pub const scsv_fallback: u16 = 0x5600;

fn unhex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "prf sha256 and sha384 vectors" {
    // Expected outputs from `openssl kdf TLS1-PRF` with the same inputs.
    const secret = unhex("9bbe436ba940f017b17652849a71db35");
    const seed = unhex("a0ba9f936cda311827a6f796ffd5198c");
    var out: [100]u8 = undefined;
    prf(sha2.Sha256, &secret, "test label", &seed, &out);
    try std.testing.expectEqualSlices(u8, &unhex(prf256_expected), &out);
    var out384: [148]u8 = undefined;
    const secret384 = unhex("b80b733d6ceefcdc71566ea48e5567df");
    const seed384 = unhex("cd665cf6a8447dd6ff8b27555edb7465");
    prf(sha2.Sha384, &secret384, "test label", &seed384, &out384);
    try std.testing.expectEqualSlices(u8, &unhex(prf384_expected), &out384);
}

const prf256_expected = "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af" ++
    "0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66";
const prf384_expected = "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0" ++
    "e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d" ++
    "90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f";

test "extended master secret binds the session hash" {
    const pms = [_]u8{0x11} ** 32;
    var h1 = [_]u8{0} ** 32;
    const m1 = Gcm128.masterSecret(&pms, &h1);
    var want: [master_len]u8 = undefined;
    prf(sha2.Sha256, &pms, "extended master secret", &h1, &want);
    try std.testing.expectEqualSlices(u8, &want, &m1);
    try std.testing.expectEqualSlices(u8, &unhex(ems_expected), &m1);
    h1[0] = 1;
    try std.testing.expect(!std.mem.eql(u8, &m1, &Gcm128.masterSecret(&pms, &h1)));
}

const ems_expected = "a33c40b7d274631824bf98e2220afd37a91ab5396f76020e46b556e00a7db7b5c431a92999d3bc32f3bfc2458982bb15";

test "record nonce: explicit for gcm, xor for chacha" {
    var g: Gcm128.Traffic = .{ .key = [_]u8{1} ** 16, .iv = .{ 0xa, 0xb, 0xc, 0xd } };
    try std.testing.expectEqualSlices(u8, &.{ 0xa, 0xb, 0xc, 0xd, 0, 0, 0, 0, 0, 0, 0, 7 }, &g.nonce(.{ 0, 0, 0, 0, 0, 0, 0, 7 }));
    var c: Chacha.Traffic = .{ .key = [_]u8{2} ** 32, .iv = [_]u8{0xff} ** 12, .seq = 0x0102 };
    try std.testing.expectEqualSlices(u8, &(.{0xff} ** 10 ++ .{ 0xfe, 0xfd }), &c.nonce(undefined));

    // Round trip both suites; a flipped bit or a skipped sequence fails.
    inline for (.{ &g, &c }) |t| {
        var w = t.*;
        var r = t.*;
        var scratch: [1]u8 = undefined;
        var out: [sched.header_len + sched.max_ciphertext]u8 = undefined;
        var plain: [sched.max_ciphertext]u8 = undefined;
        var n = w.seal(.application_data, "hello", &scratch, &out);
        try std.testing.expectEqual(sched.header_len + @TypeOf(w).overhead + 5, n);
        const got = try r.open(out[0..5], out[5..n], &plain);
        try std.testing.expectEqualSlices(u8, "hello", got[1]);
        try std.testing.expectEqual(tls.ContentType.application_data, got[0]);
        n = w.seal(.alert, "xx", &scratch, &out);
        out[n - 1] ^= 1;
        try std.testing.expectError(error.BadRecordMac, r.open(out[0..5], out[5..n], &plain));
        try std.testing.expectError(error.BadRecordMac, r.open(out[0..5], out[5..8], &plain));
    }
}

test "key block split" {
    const m = [_]u8{3} ** master_len;
    const d = Gcm256.trafficKeys(&m, [_]u8{1} ** 32, [_]u8{2} ** 32);
    var kb: [2 * (32 + 4)]u8 = undefined;
    var seed = [_]u8{2} ** 32 ++ [_]u8{1} ** 32;
    prf(sha2.Sha384, &m, "key expansion", &seed, &kb);
    try std.testing.expectEqualSlices(u8, kb[0..32], &d.client.key);
    try std.testing.expectEqualSlices(u8, kb[32..64], &d.server.key);
    try std.testing.expectEqualSlices(u8, kb[64..68], &d.client.iv);
    try std.testing.expectEqualSlices(u8, kb[68..72], &d.server.iv);
}
