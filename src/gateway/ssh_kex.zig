//! SSH key exchange (RFC 4253 section 7): KEXINIT encoding and negotiation,
//! curve25519-sha256 (RFC 8731), mlkem768x25519-sha256 hybrid, key derivation.
const std = @import("std");
const wire = @import("ssh_wire.zig");
const cipher = @import("ssh_cipher.zig");
const keys = @import("ssh_keys.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const X25519 = std.crypto.dh.X25519;
const MlKem = std.crypto.kem.ml_kem.MLKem768;

pub const msg_kexinit: u8 = 20;
pub const msg_newkeys: u8 = 21;
pub const msg_kex_ecdh_init: u8 = 30;
pub const msg_kex_ecdh_reply: u8 = 31;

pub const strict_c = "kex-strict-c-v00@openssh.com";
pub const strict_s = "kex-strict-s-v00@openssh.com";
pub const ext_info_c = "ext-info-c";

pub const NegotiateError = error{ NoCommonAlgorithm, BadMessage };
pub const KexError = error{ BadMessage, BadKey };

pub const KexAlgo = enum {
    mlkem768x25519_sha256,
    curve25519_sha256,
    curve25519_sha256_libssh,

    pub fn name(k: KexAlgo) []const u8 {
        return switch (k) {
            .mlkem768x25519_sha256 => "mlkem768x25519-sha256",
            .curve25519_sha256 => "curve25519-sha256",
            .curve25519_sha256_libssh => "curve25519-sha256@libssh.org",
        };
    }
};

const kex_order = [_]KexAlgo{ .mlkem768x25519_sha256, .curve25519_sha256, .curve25519_sha256_libssh };
/// MACs are advertised for compatibility; every offered cipher is an AEAD.
const mac_list = "hmac-sha2-256,hmac-sha2-512";

/// The algorithms a connection settled on.
pub const Negotiated = struct {
    kex: KexAlgo,
    host: keys.SigAlg,
    enc_cs: cipher.Algo,
    enc_sc: cipher.Algo,
    /// The client sent a guessed kex packet that must be discarded.
    skip_guess: bool,
    strict: bool,
    ext_info: bool,
};

/// Our KEXINIT payload for the given host key algorithms.
pub fn writeKexInit(w: *wire.Writer, has_ed25519: bool, has_rsa: bool, first: bool) wire.EncodeError!void {
    try w.byte(msg_kexinit);
    var cookie: [16]u8 = undefined;
    std.crypto.random.bytes(&cookie);
    try w.bytes(&cookie);
    const k = try w.beginString();
    for (kex_order, 0..) |a, i| {
        if (i > 0) try w.byte(',');
        try w.bytes(a.name());
    }
    // The strict-kex marker only counts in the first KEXINIT.
    if (first) try w.bytes("," ++ strict_s);
    w.endString(k);
    const h = try w.beginString();
    var n: usize = 0;
    if (has_ed25519) {
        try w.bytes("ssh-ed25519");
        n += 1;
    }
    if (has_rsa) {
        if (n > 0) try w.byte(',');
        try w.bytes("rsa-sha2-512,rsa-sha2-256");
    }
    w.endString(h);
    for (0..2) |_| {
        const c = try w.beginString();
        for (cipher.supported, 0..) |a, i| {
            if (i > 0) try w.byte(',');
            try w.bytes(a.name());
        }
        w.endString(c);
    }
    try w.string(mac_list);
    try w.string(mac_list);
    try w.string("none");
    try w.string("none");
    try w.string("");
    try w.string("");
    try w.boolean(false);
    try w.u32be(0);
}

const Lists = struct {
    kex: []const u8,
    host: []const u8,
    enc_cs: []const u8,
    enc_sc: []const u8,
    mac_cs: []const u8,
    mac_sc: []const u8,
    comp_cs: []const u8,
    comp_sc: []const u8,
    first_follows: bool,
};

fn parseLists(payload: []const u8) wire.DecodeError!Lists {
    var r = wire.Reader.init(payload);
    if (try r.byte() != msg_kexinit) return error.BadMessage;
    _ = try r.bytes(16);
    var l: Lists = undefined;
    l.kex = try r.stringMax(4096);
    l.host = try r.stringMax(4096);
    l.enc_cs = try r.stringMax(4096);
    l.enc_sc = try r.stringMax(4096);
    l.mac_cs = try r.stringMax(4096);
    l.mac_sc = try r.stringMax(4096);
    l.comp_cs = try r.stringMax(4096);
    l.comp_sc = try r.stringMax(4096);
    _ = try r.stringMax(4096);
    _ = try r.stringMax(4096);
    l.first_follows = try r.boolean();
    _ = try r.u32be();
    return l;
}

fn firstMatch(comptime T: type, client: []const u8, ours: []const T, ok: anytype) ?T {
    var it = wire.names(client);
    while (it.next()) |n| for (ours) |a| {
        if (std.mem.eql(u8, n, a.name()) and ok.allow(a)) return a;
    };
    return null;
}

const AllowAll = struct {
    fn allow(_: AllowAll, _: anytype) bool {
        return true;
    }
};

const HostAllow = struct {
    ed: bool,
    rsa: bool,
    fn allow(h: HostAllow, a: keys.SigAlg) bool {
        return if (a == .ssh_ed25519) h.ed else h.rsa;
    }
};

/// Picks algorithms from the client's KEXINIT (client preference wins, RFC 4253 7.1).
pub fn negotiate(client_kexinit: []const u8, has_ed25519: bool, has_rsa: bool, first: bool) NegotiateError!Negotiated {
    const l = try parseLists(client_kexinit);
    const host_order = [_]keys.SigAlg{ .ssh_ed25519, .rsa_sha2_512, .rsa_sha2_256 };
    const kex = firstMatch(KexAlgo, l.kex, &kex_order, AllowAll{}) orelse return error.NoCommonAlgorithm;
    const host = firstMatch(keys.SigAlg, l.host, &host_order, HostAllow{ .ed = has_ed25519, .rsa = has_rsa }) orelse return error.NoCommonAlgorithm;
    const enc_cs = firstMatch(cipher.Algo, l.enc_cs, &cipher.supported, AllowAll{}) orelse return error.NoCommonAlgorithm;
    const enc_sc = firstMatch(cipher.Algo, l.enc_sc, &cipher.supported, AllowAll{}) orelse return error.NoCommonAlgorithm;
    if (!wire.hasName(l.comp_cs, "none") or !wire.hasName(l.comp_sc, "none")) return error.NoCommonAlgorithm;
    var skip = false;
    if (l.first_follows) {
        // The guess is right only if both first entries are what we chose.
        var ki = wire.names(l.kex);
        var hi = wire.names(l.host);
        const k0 = ki.next() orelse "";
        const h0 = hi.next() orelse "";
        skip = !std.mem.eql(u8, k0, kex.name()) or !std.mem.eql(u8, h0, host.name());
    }
    return .{
        .kex = kex,
        .host = host,
        .enc_cs = enc_cs,
        .enc_sc = enc_sc,
        .skip_guess = skip,
        .strict = first and wire.hasName(l.kex, strict_c),
        .ext_info = first and wire.hasName(l.kex, ext_info_c),
    };
}

/// Shared secret K as it enters the exchange hash and the KDF (already wire-encoded).
pub const Secret = struct {
    buf: [40]u8 = undefined,
    len: usize = 0,

    pub fn bytes(s: *const Secret) []const u8 {
        return s.buf[0..s.len];
    }

    pub fn wipe(s: *Secret) void {
        std.crypto.secureZero(u8, &s.buf);
    }
};

/// Largest server ephemeral (Q_S): ML-KEM ciphertext plus an X25519 key.
pub const max_reply = MlKem.ciphertext_length + 32;

/// Server side of the exchange: consumes Q_C, writes Q_S into `reply`, returns K.
pub fn serverExchange(algo: KexAlgo, q_c: []const u8, reply: *[max_reply]u8, q_s_len: *usize) KexError!Secret {
    var s: Secret = .{};
    const eph = X25519.KeyPair.generate();
    switch (algo) {
        .curve25519_sha256, .curve25519_sha256_libssh => {
            if (q_c.len != 32) return error.BadMessage;
            var shared = X25519.scalarmult(eph.secret_key, q_c[0..32].*) catch return error.BadKey;
            defer std.crypto.secureZero(u8, &shared);
            // RFC 8731: the 32 bytes are an unsigned big-endian integer encoded as mpint.
            var w = wire.Writer.init(&s.buf);
            w.mpint(&shared) catch return error.BadKey;
            s.len = w.len;
            @memcpy(reply[0..32], &eph.public_key);
            q_s_len.* = 32;
        },
        .mlkem768x25519_sha256 => {
            const pk_len = MlKem.PublicKey.bytes_length;
            if (q_c.len != pk_len + 32) return error.BadMessage;
            const pk = MlKem.PublicKey.fromBytes(q_c[0..pk_len]) catch return error.BadKey;
            const enc = pk.encaps(null);
            var shared = X25519.scalarmult(eph.secret_key, q_c[pk_len..][0..32].*) catch return error.BadKey;
            defer std.crypto.secureZero(u8, &shared);
            var h = Sha256.init(.{});
            h.update(&enc.shared_secret);
            h.update(&shared);
            var k: [32]u8 = undefined;
            h.final(&k);
            defer std.crypto.secureZero(u8, &k);
            // The hybrid secret is a string, not an mpint.
            var w = wire.Writer.init(&s.buf);
            w.string(&k) catch return error.BadKey;
            s.len = w.len;
            @memcpy(reply[0..MlKem.ciphertext_length], &enc.ciphertext);
            @memcpy(reply[MlKem.ciphertext_length..][0..32], &eph.public_key);
            q_s_len.* = max_reply;
        },
    }
    return s;
}

/// H = SHA256(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K).
pub fn exchangeHash(v_c: []const u8, v_s: []const u8, i_c: []const u8, i_s: []const u8, k_s: []const u8, q_c: []const u8, q_s: []const u8, k: *const Secret) [32]u8 {
    var h = Sha256.init(.{});
    for ([_][]const u8{ v_c, v_s, i_c, i_s, k_s, q_c, q_s }) |part| {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(part.len), .big);
        h.update(&len);
        h.update(part);
    }
    h.update(k.bytes());
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// RFC 4253 7.2: HASH(K || H || letter || session_id), extended with HASH(K || H || K1 ...).
pub fn derive(k: *const Secret, h: [32]u8, letter: u8, session_id: [32]u8, out: []u8) void {
    var block: [32]u8 = undefined;
    var st = Sha256.init(.{});
    st.update(k.bytes());
    st.update(&h);
    st.update(&.{letter});
    st.update(&session_id);
    st.final(&block);
    var acc = Sha256.init(.{});
    acc.update(k.bytes());
    acc.update(&h);
    var off: usize = 0;
    while (true) {
        const n = @min(32, out.len - off);
        @memcpy(out[off..][0..n], block[0..n]);
        off += n;
        if (off >= out.len) break;
        acc.update(&block);
        var next = acc;
        next.final(&block);
    }
    std.crypto.secureZero(u8, &block);
}

/// Cipher states for both directions derived from one exchange.
pub fn makeCiphers(n: Negotiated, k: *const Secret, h: [32]u8, session_id: [32]u8) struct { cs: cipher.Cipher, sc: cipher.Cipher } {
    var iv_cs: [12]u8 = undefined;
    var iv_sc: [12]u8 = undefined;
    var key_cs: [64]u8 = undefined;
    var key_sc: [64]u8 = undefined;
    defer {
        std.crypto.secureZero(u8, &key_cs);
        std.crypto.secureZero(u8, &key_sc);
    }
    derive(k, h, 'A', session_id, iv_cs[0..n.enc_cs.ivLen()]);
    derive(k, h, 'B', session_id, iv_sc[0..n.enc_sc.ivLen()]);
    derive(k, h, 'C', session_id, key_cs[0..n.enc_cs.keyLen()]);
    derive(k, h, 'D', session_id, key_sc[0..n.enc_sc.keyLen()]);
    return .{
        .cs = .init(n.enc_cs, &key_cs, &iv_cs),
        .sc = .init(n.enc_sc, &key_sc, &iv_sc),
    };
}

fn testClientKexInit(buf: []u8, kex: []const u8, host: []const u8, enc: []const u8, follows: bool) ![]const u8 {
    var w = wire.Writer.init(buf);
    try w.byte(msg_kexinit);
    try w.bytes(&([_]u8{0} ** 16));
    try w.string(kex);
    try w.string(host);
    try w.string(enc);
    try w.string(enc);
    try w.string("hmac-sha2-256");
    try w.string("hmac-sha2-256");
    try w.string("none,zlib@openssh.com");
    try w.string("none");
    try w.string("");
    try w.string("");
    try w.boolean(follows);
    try w.u32be(0);
    return w.written();
}

test "negotiation follows client preference within our set" {
    var buf: [512]u8 = undefined;
    const ki = try testClientKexInit(&buf, "sntrup761x25519-sha512,curve25519-sha256,ext-info-c," ++ strict_c, "ecdsa-sha2-nistp256,rsa-sha2-256,ssh-ed25519", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", false);
    const n = try negotiate(ki, true, true, true);
    try std.testing.expectEqual(KexAlgo.curve25519_sha256, n.kex);
    try std.testing.expectEqual(keys.SigAlg.rsa_sha2_256, n.host);
    try std.testing.expectEqual(cipher.Algo.aes256_gcm, n.enc_cs);
    try std.testing.expect(n.strict and n.ext_info and !n.skip_guess);
    const no_rsa = try negotiate(ki, true, false, false);
    try std.testing.expectEqual(keys.SigAlg.ssh_ed25519, no_rsa.host);
    try std.testing.expect(!no_rsa.strict);
}

test "negotiation failures and wrong guesses" {
    var buf: [512]u8 = undefined;
    try std.testing.expectError(error.NoCommonAlgorithm, negotiate(try testClientKexInit(&buf, "diffie-hellman-group14-sha1", "ssh-ed25519", "aes128-ctr,aes256-gcm@openssh.com", false), true, false, true));
    try std.testing.expectError(error.NoCommonAlgorithm, negotiate(try testClientKexInit(&buf, "curve25519-sha256", "ssh-ed25519", "aes128-ctr", false), true, false, true));
    try std.testing.expectError(error.NoCommonAlgorithm, negotiate(try testClientKexInit(&buf, "curve25519-sha256", "rsa-sha2-256", "aes128-gcm@openssh.com", false), true, false, true));
    const g = try negotiate(try testClientKexInit(&buf, "ecdh-sha2-nistp256,mlkem768x25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com", true), true, false, true);
    try std.testing.expect(g.skip_guess);
    try std.testing.expectError(error.BadMessage, negotiate(buf[0..10], true, false, true));
}

test "our kexinit parses and offers strict kex only first" {
    var buf: [1024]u8 = undefined;
    var w = wire.Writer.init(&buf);
    try writeKexInit(&w, true, false, true);
    const l = try parseLists(w.written());
    try std.testing.expect(wire.hasName(l.kex, strict_s));
    try std.testing.expect(wire.hasName(l.kex, "mlkem768x25519-sha256"));
    try std.testing.expectEqualStrings("ssh-ed25519", l.host);
    w = wire.Writer.init(&buf);
    try writeKexInit(&w, true, true, false);
    const l2 = try parseLists(w.written());
    try std.testing.expect(!wire.hasName(l2.kex, strict_s));
    try std.testing.expectEqualStrings("ssh-ed25519,rsa-sha2-512,rsa-sha2-256", l2.host);
}

test "key derivation extends past one hash block" {
    var k: Secret = .{};
    k.buf[0..5].* = .{ 0, 0, 0, 1, 7 };
    k.len = 5;
    const h = [_]u8{1} ** 32;
    var short: [32]u8 = undefined;
    var long: [64]u8 = undefined;
    derive(&k, h, 'C', h, &short);
    derive(&k, h, 'C', h, &long);
    try std.testing.expectEqualSlices(u8, &short, long[0..32]);
    var k2: [32]u8 = undefined;
    var st = Sha256.init(.{});
    st.update(k.bytes());
    st.update(&h);
    st.update(&short);
    st.final(&k2);
    try std.testing.expectEqualSlices(u8, &k2, long[32..64]);
}

test "curve25519 and hybrid exchanges agree with a client" {
    var reply: [max_reply]u8 = undefined;
    var len: usize = 0;
    const c = X25519.KeyPair.generate();
    var s = try serverExchange(.curve25519_sha256, &c.public_key, &reply, &len);
    try std.testing.expectEqual(@as(usize, 32), len);
    const shared = try X25519.scalarmult(c.secret_key, reply[0..32].*);
    var want_buf: [40]u8 = undefined;
    var ww = wire.Writer.init(&want_buf);
    try ww.mpint(&shared);
    try std.testing.expectEqualSlices(u8, ww.written(), s.bytes());

    const kem = MlKem.KeyPair.generate();
    var q_c: [MlKem.PublicKey.bytes_length + 32]u8 = undefined;
    @memcpy(q_c[0..MlKem.PublicKey.bytes_length], &kem.public_key.toBytes());
    @memcpy(q_c[MlKem.PublicKey.bytes_length..], &c.public_key);
    s = try serverExchange(.mlkem768x25519_sha256, &q_c, &reply, &len);
    const kpq = try kem.secret_key.decaps(reply[0..MlKem.ciphertext_length]);
    const kcl = try X25519.scalarmult(c.secret_key, reply[MlKem.ciphertext_length..][0..32].*);
    var hk: [32]u8 = undefined;
    var st = Sha256.init(.{});
    st.update(&kpq);
    st.update(&kcl);
    st.final(&hk);
    try std.testing.expectEqualSlices(u8, &hk, s.bytes()[4..]);
    try std.testing.expectError(error.BadMessage, serverExchange(.mlkem768x25519_sha256, q_c[0..40], &reply, &len));
    try std.testing.expectError(error.BadKey, serverExchange(.curve25519_sha256, &([_]u8{0} ** 32), &reply, &len));
}
