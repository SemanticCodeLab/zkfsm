//! Admin payload encryption compatible with madmin's EncryptData/DecryptData:
//! salt(32) | AEAD id(1) | nonce(8) | sio stream (16 KiB fragments, AEAD per fragment).
//! The key is derived from the caller's secret key with Argon2id or PBKDF2-SHA256.
const std = @import("std");

const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const argon2 = std.crypto.pwhash.argon2;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Algorithm = enum(u8) { argon2id_aes_gcm = 0, argon2id_chacha20_poly1305 = 1, pbkdf2_aes_gcm = 2 };

pub const Error = error{ OutOfMemory, Malformed, NotAuthentic, UnsupportedAlgorithm, KdfFailed };

pub const salt_len = 32;
pub const nonce_len = 8;
pub const header_len = salt_len + 1 + nonce_len;
const buf_size = 1 << 14;
const tag_len = 16;
const frag_len = buf_size + tag_len;

comptime {
    std.debug.assert(Aes.tag_length == tag_len and ChaCha.tag_length == tag_len);
    std.debug.assert(Aes.nonce_length == 12 and ChaCha.nonce_length == 12);
}

/// Argon2id with 64 MiB is heavy; serialize derivations like madmin does.
var kdf_mutex: std.Thread.Mutex = .{};

fn deriveKey(alg: Algorithm, password: []const u8, salt: *const [salt_len]u8) Error![32]u8 {
    var key: [32]u8 = undefined;
    switch (alg) {
        .argon2id_aes_gcm, .argon2id_chacha20_poly1305 => {
            kdf_mutex.lock();
            defer kdf_mutex.unlock();
            argon2.kdf(std.heap.page_allocator, &key, password, salt, .{ .t = 1, .m = 64 * 1024, .p = 4 }, .argon2id) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.KdfFailed,
            };
        },
        .pbkdf2_aes_gcm => std.crypto.pwhash.pbkdf2(&key, password, salt, 8192, HmacSha256) catch return error.KdfFailed,
    }
    return key;
}

fn fragmentNonce(base: *const [nonce_len]u8, seq: u32) [12]u8 {
    var n: [12]u8 = undefined;
    @memcpy(n[0..nonce_len], base);
    std.mem.writeInt(u32, n[nonce_len..12], seq, .little);
    return n;
}

fn Stream(comptime A: type) type {
    return struct {
        /// Fragment AD: a final-flag byte followed by the tag of an empty seal at sequence 0.
        fn initialAd(key: [32]u8, base: *const [nonce_len]u8) [1 + tag_len]u8 {
            var ad: [1 + tag_len]u8 = undefined;
            ad[0] = 0;
            A.encrypt(&.{}, ad[1..], "", "", fragmentNonce(base, 0), key);
            return ad;
        }

        fn seal(out: []u8, plain: []const u8, key: [32]u8, base: *const [nonce_len]u8) void {
            var ad = initialAd(key, base);
            var seq: u32 = 1;
            var p = plain;
            var o = out;
            while (p.len > buf_size) : (seq += 1) {
                A.encrypt(o[0..buf_size], o[buf_size..frag_len], p[0..buf_size], &ad, fragmentNonce(base, seq), key);
                p = p[buf_size..];
                o = o[frag_len..];
            }
            ad[0] = 0x80;
            A.encrypt(o[0..p.len], o[p.len..][0..tag_len], p, &ad, fragmentNonce(base, seq), key);
        }

        fn open(out: []u8, cipher: []const u8, key: [32]u8, base: *const [nonce_len]u8) Error!void {
            var ad = initialAd(key, base);
            var seq: u32 = 1;
            var c = cipher;
            var o = out;
            while (c.len > frag_len) : (seq += 1) {
                A.decrypt(o[0..buf_size], c[0..buf_size], c[buf_size..frag_len].*, &ad, fragmentNonce(base, seq), key) catch return error.NotAuthentic;
                c = c[frag_len..];
                o = o[buf_size..];
            }
            ad[0] = 0x80;
            const n = c.len - tag_len;
            A.decrypt(o[0..n], c[0..n], c[n..][0..tag_len].*, &ad, fragmentNonce(base, seq), key) catch return error.NotAuthentic;
        }
    };
}

fn fragments(plain_len: usize) usize {
    return if (plain_len == 0) 1 else (plain_len + buf_size - 1) / buf_size;
}

pub fn ciphertextLen(plain_len: usize) usize {
    return header_len + plain_len + fragments(plain_len) * tag_len;
}

/// Deterministic core of `encrypt`; salt and nonce must be fresh random values.
pub fn encryptWith(gpa: std.mem.Allocator, alg: Algorithm, password: []const u8, plain: []const u8, salt: [salt_len]u8, nonce: [nonce_len]u8) Error![]u8 {
    const key = try deriveKey(alg, password, &salt);
    const out = try gpa.alloc(u8, ciphertextLen(plain.len));
    @memcpy(out[0..salt_len], &salt);
    out[salt_len] = @intFromEnum(alg);
    @memcpy(out[salt_len + 1 .. header_len], &nonce);
    switch (alg) {
        .argon2id_aes_gcm, .pbkdf2_aes_gcm => Stream(Aes).seal(out[header_len..], plain, key, &nonce),
        .argon2id_chacha20_poly1305 => Stream(ChaCha).seal(out[header_len..], plain, key, &nonce),
    }
    return out;
}

/// Encrypts with Argon2id + AES-256-GCM, madmin's default on hardware with AES.
pub fn encrypt(gpa: std.mem.Allocator, password: []const u8, plain: []const u8) Error![]u8 {
    var salt: [salt_len]u8 = undefined;
    var nonce: [nonce_len]u8 = undefined;
    std.crypto.random.bytes(&salt);
    std.crypto.random.bytes(&nonce);
    return encryptWith(gpa, .argon2id_aes_gcm, password, plain, salt, nonce);
}

/// Decrypts any of the three madmin formats. Input is untrusted.
pub fn decrypt(gpa: std.mem.Allocator, password: []const u8, data: []const u8) Error![]u8 {
    if (data.len < header_len + tag_len) return error.Malformed;
    const alg = std.meta.intToEnum(Algorithm, data[salt_len]) catch return error.UnsupportedAlgorithm;
    const body = data[header_len..];
    const full = body.len / frag_len;
    var rest = body.len % frag_len;
    var n_frag = full;
    if (rest == 0) rest = frag_len else n_frag += 1;
    if (rest < tag_len) return error.Malformed;
    const plain_len = body.len - n_frag * tag_len;
    const salt = data[0..salt_len];
    const nonce = data[salt_len + 1 .. header_len];
    const key = try deriveKey(alg, password, salt);
    const out = try gpa.alloc(u8, plain_len);
    errdefer gpa.free(out);
    switch (alg) {
        .argon2id_aes_gcm, .pbkdf2_aes_gcm => try Stream(Aes).open(out, body, key, nonce),
        .argon2id_chacha20_poly1305 => try Stream(ChaCha).open(out, body, key, nonce),
    }
    return out;
}

pub fn isEncrypted(data: []const u8) bool {
    return data.len > salt_len and data[salt_len] <= 2;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const vector_password = "zkfsm-secret";
const vector_plain =
    \\{"secretKey":"alicesecret","status":"enabled"}
;

/// Produced by the reference Go implementation (madmin-go / sio-go) with
/// salt = 0x11 * 32 and nonce = 0x22 * 8, one per algorithm id.
const vectors = [_][]const u8{
    "11111111111111111111111111111111111111111111111111111111111111110022222222222222226c6045d026bd672d780cef222a6d3ef47ac41aac78dd2b768dff33c5efe85ef106eacebc7fdd34a4df9cdd15c94ffd358fa577e61fa1bb743b691edc19af",
    "1111111111111111111111111111111111111111111111111111111111111111012222222222222222b3679d8a6817815d26ca4037a065d3a47e901472b37f75bdbef38a9476dd032c5128af07a493d4994016cd8bda83c8346d369be23621612d127b7a79e53a",
    "1111111111111111111111111111111111111111111111111111111111111111022222222222222222b5f38a4a617fcdeb2b9ed9f137c5770dad3b8c3cff2176bf7aafa1049c6356aba55cb9290855774defbcfe3234af77ed4a645cc7eabd8ecaffe0fc8096fc",
    // madmin.EncryptData output (random salt and nonce).
    "6ff35129456b9bed7125da4784c636ad72cabafaa8b998052f9762ee6bf01aaf00e07c6fdf11cdcdf04b2afd9cbeaea65ec75199d6da9d41c9eb1639b08d4e17c4a4b464bedc7683146db3bca671a4d1d6cd7e4f4c9fb7ecd4246e9f4472e0d56f1882adc1087c",
};

test "known vectors from the reference implementation" {
    const a = testing.allocator;
    for (vectors, 0..) |hex, i| {
        var raw: [256]u8 = undefined;
        const ct = try std.fmt.hexToBytes(&raw, hex);
        const pt = try decrypt(a, vector_password, ct);
        defer a.free(pt);
        try testing.expectEqualStrings(vector_plain, pt);
        if (i < 3) {
            const again = try encryptWith(a, @enumFromInt(i), vector_password, vector_plain, @splat(0x11), @splat(0x22));
            defer a.free(again);
            try testing.expectEqualSlices(u8, ct, again);
        }
    }
}

test "round trip across fragment boundaries and tamper detection" {
    const a = testing.allocator;
    for ([_]usize{ 0, 1, buf_size, buf_size + 1, 3 * buf_size, 3 * buf_size + 7 }) |len| {
        const plain = try a.alloc(u8, len);
        defer a.free(plain);
        for (plain, 0..) |*b, i| b.* = @truncate(i *% 31);
        const ct = try encryptWith(a, .pbkdf2_aes_gcm, "pw", plain, @splat(1), @splat(2));
        defer a.free(ct);
        try testing.expectEqual(ciphertextLen(len), ct.len);
        const back = try decrypt(a, "pw", ct);
        defer a.free(back);
        try testing.expectEqualSlices(u8, plain, back);
        try testing.expectError(error.NotAuthentic, decrypt(a, "other", ct));
        ct[ct.len - 1] ^= 1;
        try testing.expectError(error.NotAuthentic, decrypt(a, "pw", ct));
        // Dropping the final fragment must not verify as a shorter message.
        if (len > buf_size) try testing.expectError(error.NotAuthentic, decrypt(a, "pw", ct[0 .. header_len + frag_len]));
    }
    try testing.expectError(error.Malformed, decrypt(a, "pw", "short"));
    var bad: [header_len + tag_len]u8 = @splat(0);
    bad[salt_len] = 9;
    try testing.expectError(error.UnsupportedAlgorithm, decrypt(a, "pw", &bad));
}
