//! SSH binary packet protection (RFC 4253 section 6): the cleartext framing used
//! during the first key exchange, chacha20-poly1305@openssh.com and
//! aes{128,256}-gcm@openssh.com (RFC 5647 with OpenSSH's length-as-AAD rule).
const std = @import("std");
const ChaCha = std.crypto.stream.chacha.ChaCha20With64BitNonce;
const Poly1305 = std.crypto.onetimeauth.Poly1305;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// Largest packet_length accepted or produced (payload plus padding).
pub const max_packet = 256 * 1024 + 64;
/// Largest payload we produce or accept.
pub const max_payload = 256 * 1024;
pub const tag_len = 16;
/// Wire bytes beyond `packet_length`: the length field and the tag.
pub const overhead = 4 + tag_len;

pub const Error = error{ BadPacket, BadMac };

pub const Algo = enum {
    chacha20_poly1305,
    aes256_gcm,
    aes128_gcm,

    pub fn name(a: Algo) []const u8 {
        return switch (a) {
            .chacha20_poly1305 => "chacha20-poly1305@openssh.com",
            .aes256_gcm => "aes256-gcm@openssh.com",
            .aes128_gcm => "aes128-gcm@openssh.com",
        };
    }

    pub fn keyLen(a: Algo) usize {
        return switch (a) {
            .chacha20_poly1305 => 64,
            .aes256_gcm => 32,
            .aes128_gcm => 16,
        };
    }

    pub fn ivLen(a: Algo) usize {
        return switch (a) {
            .chacha20_poly1305 => 0,
            .aes256_gcm, .aes128_gcm => 12,
        };
    }
};

/// Server preference order.
pub const supported = [_]Algo{ .chacha20_poly1305, .aes256_gcm, .aes128_gcm };

pub const Cipher = union(enum) {
    none,
    chacha: struct { main: [32]u8, hdr: [32]u8 },
    aes256: Gcm(Aes256Gcm),
    aes128: Gcm(Aes128Gcm),

    pub fn init(algo: Algo, key: []const u8, iv: []const u8) Cipher {
        return switch (algo) {
            .chacha20_poly1305 => .{ .chacha = .{ .main = key[0..32].*, .hdr = key[32..64].* } },
            .aes256_gcm => .{ .aes256 = .{ .key = key[0..32].*, .iv = iv[0..12].* } },
            .aes128_gcm => .{ .aes128 = .{ .key = key[0..16].*, .iv = iv[0..12].* } },
        };
    }

    pub fn wipe(c: *Cipher) void {
        std.crypto.secureZero(u8, std.mem.asBytes(c));
        c.* = .none;
    }

    fn blockSize(c: *const Cipher) usize {
        return switch (c.*) {
            .none, .chacha => 8,
            .aes256, .aes128 => 16,
        };
    }

    fn tagLen(c: *const Cipher) usize {
        return if (c.* == .none) 0 else tag_len;
    }

    /// Frames `payload` into `out` (needs payload.len + 4 + 1 + 19 + 16 bytes); returns the wire bytes.
    pub fn seal(c: *Cipher, seq: u32, payload: []const u8, out: []u8) Error![]u8 {
        if (payload.len > max_payload) return error.BadPacket;
        const bs = c.blockSize();
        // AEAD modes pad the part after the length; the cleartext mode pads it all.
        const covered = if (c.* == .none) 4 + 1 + payload.len else 1 + payload.len;
        var pad = bs - covered % bs;
        if (pad < 4) pad += bs;
        const plen = 1 + payload.len + pad;
        const total = 4 + plen + c.tagLen();
        if (out.len < total) return error.BadPacket;
        std.mem.writeInt(u32, out[0..4], @intCast(plen), .big);
        out[4] = @intCast(pad);
        @memcpy(out[5..][0..payload.len], payload);
        std.crypto.random.bytes(out[5 + payload.len ..][0..pad]);
        const body = out[4..][0..plen];
        switch (c.*) {
            .none => {},
            .chacha => |k| {
                var nonce: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce, seq, .big);
                ChaCha.xor(out[0..4], out[0..4], 0, k.hdr, nonce);
                var poly_key: [32]u8 = undefined;
                ChaCha.stream(&poly_key, 0, k.main, nonce);
                ChaCha.xor(body, body, 1, k.main, nonce);
                Poly1305.create(out[4 + plen ..][0..16], out[0 .. 4 + plen], &poly_key);
            },
            inline .aes256, .aes128 => |*g| g.seal(out[0..4], body, out[4 + plen ..][0..16]),
        }
        return out[0..total];
    }

    /// Bytes to read before the packet length is known.
    pub const first_len = 4;

    /// Recovers packet_length from the first four wire bytes and validates it.
    pub fn openLength(c: *const Cipher, seq: u32, first: [4]u8) Error!u32 {
        var hdr = first;
        if (c.* == .chacha) {
            var nonce: [8]u8 = undefined;
            std.mem.writeInt(u64, &nonce, seq, .big);
            ChaCha.xor(&hdr, &hdr, 0, c.chacha.hdr, nonce);
        }
        const len = std.mem.readInt(u32, &hdr, .big);
        if (len < 8 or len > max_packet) return error.BadPacket;
        const covered = if (c.* == .none) len + 4 else len;
        if (covered % c.blockSize() != 0) return error.BadPacket;
        return len;
    }

    /// Bytes that follow the length field: the body plus the tag.
    pub fn restLen(c: *const Cipher, len: u32) usize {
        return len + c.tagLen();
    }

    /// Authenticates and decrypts in place; `wire` is length field, body and tag.
    /// Returns the payload slice inside `wire`.
    pub fn open(c: *Cipher, seq: u32, wire: []u8) Error![]u8 {
        const tl = c.tagLen();
        if (wire.len < 4 + 8 + tl) return error.BadPacket;
        const plen = wire.len - 4 - tl;
        const body = wire[4..][0..plen];
        switch (c.*) {
            .none => {},
            .chacha => |k| {
                var nonce: [8]u8 = undefined;
                std.mem.writeInt(u64, &nonce, seq, .big);
                var poly_key: [32]u8 = undefined;
                ChaCha.stream(&poly_key, 0, k.main, nonce);
                var want: [16]u8 = undefined;
                Poly1305.create(&want, wire[0 .. 4 + plen], &poly_key);
                if (!std.crypto.timing_safe.eql([16]u8, want, wire[4 + plen ..][0..16].*)) return error.BadMac;
                ChaCha.xor(body, body, 1, k.main, nonce);
            },
            inline .aes256, .aes128 => |*g| try g.open(wire[0..4], body, wire[4 + plen ..][0..16].*),
        }
        const pad = body[0];
        if (pad < 4 or @as(usize, pad) + 1 > plen) return error.BadPacket;
        return body[1 .. plen - pad];
    }
};

fn Gcm(comptime A: type) type {
    return struct {
        key: [A.key_length]u8,
        iv: [12]u8,

        const Self = @This();

        fn bump(g: *Self) void {
            const ctr = std.mem.readInt(u64, g.iv[4..12], .big);
            std.mem.writeInt(u64, g.iv[4..12], ctr +% 1, .big);
        }

        fn seal(g: *Self, aad: []const u8, body: []u8, tag: *[16]u8) void {
            A.encrypt(body, tag, body, aad, g.iv, g.key);
            g.bump();
        }

        fn open(g: *Self, aad: []const u8, body: []u8, tag: [16]u8) Error!void {
            A.decrypt(body, body, tag, aad, g.iv, g.key) catch return error.BadMac;
            g.bump();
        }
    };
}

fn roundTrip(algo: ?Algo) !void {
    var key: [64]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const iv = [_]u8{9} ** 12;
    var tx: Cipher = if (algo) |a| .init(a, &key, &iv) else .none;
    var rx: Cipher = tx;
    var buf: [256]u8 = undefined;
    for (0..3) |seq| {
        const msg = "hello, ssh packet";
        const wire = try tx.seal(@intCast(seq), msg, &buf);
        const len = try rx.openLength(@intCast(seq), wire[0..4].*);
        try std.testing.expectEqual(wire.len, 4 + rx.restLen(len));
        try std.testing.expectEqualStrings(msg, try rx.open(@intCast(seq), wire));
    }
    if (algo != null) {
        const wire = try tx.seal(3, "tamper", &buf);
        wire[wire.len - 20] ^= 1;
        try std.testing.expectError(error.BadMac, rx.open(3, wire));
    }
}

test "packet round trips and tamper detection" {
    try roundTrip(null);
    for (supported) |a| try roundTrip(a);
}

test "length validation" {
    const c: Cipher = .none;
    try std.testing.expectError(error.BadPacket, c.openLength(0, .{ 0, 0, 0, 3 }));
    try std.testing.expectError(error.BadPacket, c.openLength(0, .{ 0x7f, 0, 0, 0 }));
    try std.testing.expectError(error.BadPacket, c.openLength(0, .{ 0, 0, 0, 13 }));
    try std.testing.expectEqual(@as(u32, 12), try c.openLength(0, .{ 0, 0, 0, 12 }));
}

test "chacha20-poly1305@openssh.com known answer" {
    // Wire bytes produced by an independent ChaCha20/Poly1305 implementation (seq 7).
    var key: [64]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    var c = Cipher.init(.chacha20_poly1305, &key, &.{});
    var wire = chacha_kat;
    try std.testing.expectEqual(@as(u32, 8), try c.openLength(7, wire[0..4].*));
    try std.testing.expectEqualStrings("abc", try c.open(7, &wire));
}

const chacha_kat = [_]u8{
    0xa3, 0x9a, 0xfc, 0xa2, 0x2c, 0x27, 0x77, 0x20, 0x4f, 0x81, 0x29, 0x5a, 0x67, 0x2a,
    0x51, 0x14, 0x63, 0xb7, 0xbd, 0x53, 0xe4, 0x20, 0xc9, 0x66, 0x57, 0xf5, 0xe8, 0x4d,
};

test "aes256-gcm@openssh.com known answer with invocation counter" {
    // Two packets from an independent AES-GCM implementation; the IV counter advances.
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    var c = Cipher.init(.aes256_gcm, &key, &([_]u8{9} ** 12));
    for (gcm_kat) |kat| {
        var wire = kat;
        try std.testing.expectEqual(@as(u32, 16), try c.openLength(0, wire[0..4].*));
        try std.testing.expectEqualStrings("abc", try c.open(0, &wire));
    }
}

const gcm_kat = [2][36]u8{
    .{ 0x00, 0x00, 0x00, 0x10, 0xbf, 0x79, 0x6a, 0x58, 0x87, 0x9f, 0x43, 0xa4, 0xd1, 0x09, 0x30, 0xf9, 0xab, 0x96, 0xbb, 0xcf, 0xfe, 0xef, 0xb9, 0x97, 0xfc, 0xe1, 0x48, 0xfc, 0xea, 0xb9, 0x73, 0x88, 0xda, 0x48, 0xd4, 0x02 },
    .{ 0x00, 0x00, 0x00, 0x10, 0x0d, 0x62, 0x9e, 0xb4, 0x43, 0xa8, 0x37, 0x1d, 0x78, 0x30, 0x0f, 0xbe, 0x3b, 0xe6, 0x9a, 0x62, 0x12, 0xcd, 0xe2, 0x8c, 0xcf, 0x09, 0xf1, 0x35, 0x37, 0xe3, 0x9c, 0x22, 0x9f, 0x2a, 0x6e, 0xf0 },
};
