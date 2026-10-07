//! SSH keys: server host keys (ed25519 in openssh-key-v1, RSA from PEM via the
//! TLS key parser), public key blobs, signatures, and client signature checks.
const std = @import("std");
const wire = @import("ssh_wire.zig");
const tls_keys = @import("../tls/keys.zig");
const tls_rsa = @import("../tls/rsa.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const M = std.crypto.ff.Modulus(tls_rsa.max_bits);

pub const LoadError = error{ BadKey, UnsupportedKey, EncryptedKey, NoKey, OutOfMemory };
pub const SignError = error{ SignFailed, NoSpace };

/// Largest signature blob we emit (RSA-4096 plus names).
pub const max_sig_blob = tls_rsa.max_bytes + 64;
/// Largest public key blob we emit.
pub const max_pub_blob = tls_rsa.max_bytes + 64;

pub const SigAlg = enum {
    ssh_ed25519,
    rsa_sha2_512,
    rsa_sha2_256,

    pub fn name(a: SigAlg) []const u8 {
        return switch (a) {
            .ssh_ed25519 => "ssh-ed25519",
            .rsa_sha2_512 => "rsa-sha2-512",
            .rsa_sha2_256 => "rsa-sha2-256",
        };
    }

    pub fn parse(s: []const u8) ?SigAlg {
        inline for (std.meta.fields(SigAlg)) |f| {
            const a: SigAlg = @enumFromInt(f.value);
            if (std.mem.eql(u8, s, a.name())) return a;
        }
        return null;
    }
};

/// Signature algorithms accepted for user authentication (ext-info server-sig-algs).
pub const user_sig_algs = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256";

pub const HostKey = union(enum) {
    ed25519: Ed25519.KeyPair,
    rsa: tls_keys.PrivateKey,

    pub fn deinit(k: *HostKey, gpa: std.mem.Allocator) void {
        switch (k.*) {
            .ed25519 => |*kp| std.crypto.secureZero(u8, std.mem.asBytes(kp)),
            .rsa => |*r| r.deinit(gpa),
        }
    }

    pub fn supports(k: *const HostKey, alg: SigAlg) bool {
        return switch (k.*) {
            .ed25519 => alg == .ssh_ed25519,
            .rsa => alg != .ssh_ed25519,
        };
    }

    fn rsaKey(k: *const HostKey) tls_rsa.PrivateKey {
        return k.rsa.kind.rsa;
    }

    /// The public key blob (RFC 4253 section 6.6, RFC 8709).
    pub fn writeBlob(k: *const HostKey, w: *wire.Writer) wire.EncodeError!void {
        switch (k.*) {
            .ed25519 => |kp| {
                try w.string("ssh-ed25519");
                try w.string(&kp.public_key.toBytes());
            },
            .rsa => {
                const r = k.rsaKey();
                try w.string("ssh-rsa");
                try w.mpint(r.e);
                try w.mpint(r.n);
            },
        }
    }

    /// Writes the signature blob (string alg, string signature) for `msg`.
    pub fn sign(k: *const HostKey, alg: SigAlg, msg: []const u8, w: *wire.Writer) SignError!void {
        switch (k.*) {
            .ed25519 => |kp| {
                const sig = kp.sign(msg, null) catch return error.SignFailed;
                try w.string("ssh-ed25519");
                try w.string(&sig.toBytes());
            },
            .rsa => {
                var out: [tls_rsa.max_bytes]u8 = undefined;
                const s = switch (alg) {
                    .rsa_sha2_256 => try rsaSign(k.rsaKey(), Sha256, msg, &out),
                    .rsa_sha2_512 => try rsaSign(k.rsaKey(), Sha512, msg, &out),
                    .ssh_ed25519 => return error.SignFailed,
                };
                try w.string(alg.name());
                try w.string(s);
            },
        }
    }

    /// OpenSSH-style SHA256 fingerprint text.
    pub fn fingerprint(k: *const HostKey, out: *[64]u8) []const u8 {
        var buf: [max_pub_blob]u8 = undefined;
        var w = wire.Writer.init(&buf);
        k.writeBlob(&w) catch return "";
        var d: [32]u8 = undefined;
        Sha256.hash(w.written(), &d, .{});
        const enc = std.base64.standard_no_pad.Encoder;
        @memcpy(out[0..7], "SHA256:");
        return out[0 .. 7 + enc.encode(out[7..], &d).len];
    }
};

/// Loads a host key file: openssh-key-v1 (unencrypted ed25519) or PEM RSA.
pub fn loadHostKey(gpa: std.mem.Allocator, text: []const u8) LoadError!HostKey {
    if (std.mem.indexOf(u8, text, "-----BEGIN OPENSSH PRIVATE KEY-----") != null) {
        return .{ .ed25519 = try parseOpenSsh(gpa, text) };
    }
    var k = tls_keys.parsePem(gpa, text) catch |e| return switch (e) {
        error.BadKey => error.BadKey,
        error.UnsupportedKey => error.UnsupportedKey,
        error.EncryptedKey => error.EncryptedKey,
        error.NoKey => error.NoKey,
        error.OutOfMemory => error.OutOfMemory,
    };
    if (k.kind != .rsa) {
        k.deinit(gpa);
        return error.UnsupportedKey;
    }
    return .{ .rsa = k };
}

const openssh_magic = "openssh-key-v1\x00";
const openssh_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
const openssh_end = "-----END OPENSSH PRIVATE KEY-----";

fn parseOpenSsh(gpa: std.mem.Allocator, text: []const u8) LoadError!Ed25519.KeyPair {
    const start = (std.mem.indexOf(u8, text, openssh_begin) orelse return error.NoKey) + openssh_begin.len;
    const end = std.mem.indexOfPos(u8, text, start, openssh_end) orelse return error.BadKey;
    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const body = text[start..end];
    if (body.len > 64 * 1024) return error.BadKey;
    const raw = try gpa.alloc(u8, body.len);
    defer {
        std.crypto.secureZero(u8, raw);
        gpa.free(raw);
    }
    const n = dec.decode(raw, body) catch return error.BadKey;
    return parseOpenSshBytes(raw[0..n]) catch |e| switch (e) {
        error.BadMessage => error.BadKey,
        else => |x| x,
    };
}

fn parseOpenSshBytes(raw: []const u8) (LoadError || wire.DecodeError)!Ed25519.KeyPair {
    if (!std.mem.startsWith(u8, raw, openssh_magic)) return error.BadKey;
    var r = wire.Reader.init(raw[openssh_magic.len..]);
    const cipher = try r.string();
    const kdf = try r.string();
    _ = try r.string();
    if (!std.mem.eql(u8, cipher, "none") or !std.mem.eql(u8, kdf, "none")) return error.EncryptedKey;
    if (try r.u32be() != 1) return error.UnsupportedKey;
    _ = try r.string();
    var p = wire.Reader.init(try r.string());
    if (try p.u32be() != try p.u32be()) return error.BadKey;
    const kt = try p.string();
    if (!std.mem.eql(u8, kt, "ssh-ed25519")) return error.UnsupportedKey;
    const pub_bytes = try p.string();
    const priv = try p.string();
    if (pub_bytes.len != 32 or priv.len != 64) return error.BadKey;
    const sk = Ed25519.SecretKey.fromBytes(priv[0..64].*) catch return error.BadKey;
    const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return error.BadKey;
    if (!std.mem.eql(u8, &kp.public_key.toBytes(), pub_bytes)) return error.BadKey;
    return kp;
}

/// Encodes an ed25519 key as an unencrypted openssh-key-v1 file.
pub fn encodeOpenSsh(kp: Ed25519.KeyPair, out: *[1024]u8) wire.EncodeError![]const u8 {
    var raw_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw_buf);
    var w = wire.Writer.init(&raw_buf);
    try w.bytes(openssh_magic);
    try w.string("none");
    try w.string("none");
    try w.string("");
    try w.u32be(1);
    const pk = kp.public_key.toBytes();
    const pb = try w.beginString();
    try w.string("ssh-ed25519");
    try w.string(&pk);
    w.endString(pb);
    const priv = try w.beginString();
    const check = std.crypto.random.int(u32);
    try w.u32be(check);
    try w.u32be(check);
    try w.string("ssh-ed25519");
    try w.string(&pk);
    try w.string(&kp.secret_key.toBytes());
    try w.string("zkfsm sftp host key");
    var i: u8 = 1;
    while ((w.len - priv) % 8 != 0) : (i += 1) try w.byte(i);
    w.endString(priv);
    var o = wire.Writer.init(out);
    try o.bytes(openssh_begin ++ "\n");
    const enc = std.base64.standard.Encoder;
    var b64: [700]u8 = undefined;
    const text = enc.encode(&b64, w.written());
    var off: usize = 0;
    while (off < text.len) : (off += 70) {
        try o.bytes(text[off..@min(text.len, off + 70)]);
        try o.byte('\n');
    }
    try o.bytes(openssh_end ++ "\n");
    return o.written();
}

/// PKCS#1 v1.5 signature (RFC 8017 8.2) with a CRT key; verified before release.
fn rsaSign(k: tls_rsa.PrivateKey, comptime Hash: type, msg: []const u8, out: *[tls_rsa.max_bytes]u8) SignError![]const u8 {
    const k_len = k.n.len;
    var em_buf: [tls_rsa.max_bytes]u8 = undefined;
    const em = em_buf[0..k_len];
    pkcs1Encode(Hash, msg, em) catch return error.SignFailed;
    const sig = out[0..k_len];
    rsaPrivate(k, em, sig) catch return error.SignFailed;
    const n = M.fromBytes(k.n, .big) catch return error.SignFailed;
    const s = M.Fe.fromBytes(n, sig, .big) catch return error.SignFailed;
    const v = n.powWithEncodedPublicExponent(s, k.e, .big) catch return error.SignFailed;
    var got: [tls_rsa.max_bytes]u8 = undefined;
    v.toBytes(got[0..k_len], .big) catch return error.SignFailed;
    if (!std.mem.eql(u8, got[0..k_len], em)) return error.SignFailed;
    return sig;
}

fn digestInfo(comptime Hash: type) []const u8 {
    return switch (Hash) {
        Sha256 => &.{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
        Sha512 => &.{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
        else => @compileError("unsupported hash"),
    };
}

fn pkcs1Encode(comptime Hash: type, msg: []const u8, em: []u8) error{TooShort}!void {
    const di = digestInfo(Hash);
    const t_len = di.len + Hash.digest_length;
    if (em.len < t_len + 11) return error.TooShort;
    em[0] = 0;
    em[1] = 1;
    @memset(em[2 .. em.len - t_len - 1], 0xff);
    em[em.len - t_len - 1] = 0;
    @memcpy(em[em.len - t_len ..][0..di.len], di);
    Hash.hash(msg, em[em.len - Hash.digest_length ..][0..Hash.digest_length], .{});
}

fn rsaPrivate(k: tls_rsa.PrivateKey, em: []const u8, sig: []u8) error{ BadKey, Overflow }!void {
    const n = M.fromBytes(k.n, .big) catch return error.BadKey;
    const p = M.fromBytes(k.p, .big) catch return error.BadKey;
    const q = M.fromBytes(k.q, .big) catch return error.BadKey;
    const c = M.Fe.fromBytes(n, em, .big) catch return error.Overflow;
    const m1 = p.powWithEncodedExponent(p.reduce(c.v), k.dp, .big) catch return error.BadKey;
    const m2 = q.powWithEncodedExponent(q.reduce(c.v), k.dq, .big) catch return error.BadKey;
    const qinv = M.Fe.fromBytes(p, k.qinv, .big) catch return error.BadKey;
    var buf: [tls_rsa.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    m2.toBytes(buf[0..k.n.len], .big) catch return error.Overflow;
    const m2n = M.Fe.fromBytes(n, buf[0..k.n.len], .big) catch return error.Overflow;
    const h = p.mul(p.sub(m1, p.reduce(m2n.v)), qinv);
    h.toBytes(buf[0..k.n.len], .big) catch return error.Overflow;
    const hn = M.Fe.fromBytes(n, buf[0..k.n.len], .big) catch return error.Overflow;
    const qn = M.Fe.fromBytes(n, k.q, .big) catch return error.BadKey;
    const m = n.add(n.mul(hn, qn), m2n);
    m.toBytes(sig, .big) catch return error.Overflow;
}

/// The key type named inside a public key blob.
pub fn blobType(blob: []const u8) ?[]const u8 {
    var r = wire.Reader.init(blob);
    return r.stringMax(64) catch null;
}

/// Checks a user signature blob over `msg` made with the key in `blob` using `alg`.
pub fn verify(alg_name: []const u8, blob: []const u8, sig_blob: []const u8, msg: []const u8) bool {
    const alg = SigAlg.parse(alg_name) orelse return false;
    var kr = wire.Reader.init(blob);
    var sr = wire.Reader.init(sig_blob);
    const kt = kr.string() catch return false;
    const st = sr.string() catch return false;
    const sig = sr.string() catch return false;
    if (!sr.done() or !std.mem.eql(u8, st, alg_name)) return false;
    switch (alg) {
        .ssh_ed25519 => {
            if (!std.mem.eql(u8, kt, "ssh-ed25519")) return false;
            const pk = kr.string() catch return false;
            if (!kr.done() or pk.len != 32 or sig.len != 64) return false;
            const key = Ed25519.PublicKey.fromBytes(pk[0..32].*) catch return false;
            Ed25519.Signature.fromBytes(sig[0..64].*).verify(msg, key) catch return false;
            return true;
        },
        .rsa_sha2_256, .rsa_sha2_512 => {
            if (!std.mem.eql(u8, kt, "ssh-rsa")) return false;
            const e = kr.mpintUnsigned() catch return false;
            const n = kr.mpintUnsigned() catch return false;
            if (!kr.done()) return false;
            return if (alg == .rsa_sha2_256) rsaVerify(Sha256, e, n, sig, msg) else rsaVerify(Sha512, e, n, sig, msg);
        },
    }
}

fn rsaVerify(comptime Hash: type, e: []const u8, n_bytes: []const u8, sig: []const u8, msg: []const u8) bool {
    if (n_bytes.len < 256 or n_bytes.len > tls_rsa.max_bytes or e.len == 0 or e.len > 8) return false;
    if (sig.len > n_bytes.len or sig.len == 0) return false;
    const n = M.fromBytes(n_bytes, .big) catch return false;
    var padded: [tls_rsa.max_bytes]u8 = @splat(0);
    @memcpy(padded[n_bytes.len - sig.len .. n_bytes.len], sig);
    const s = M.Fe.fromBytes(n, padded[0..n_bytes.len], .big) catch return false;
    const v = n.powWithEncodedPublicExponent(s, e, .big) catch return false;
    var got: [tls_rsa.max_bytes]u8 = undefined;
    v.toBytes(got[0..n_bytes.len], .big) catch return false;
    var want: [tls_rsa.max_bytes]u8 = undefined;
    pkcs1Encode(Hash, msg, want[0..n_bytes.len]) catch return false;
    return std.mem.eql(u8, got[0..n_bytes.len], want[0..n_bytes.len]);
}

/// Largest authorized-keys file read.
pub const max_authorized_file = 1024 * 1024;

/// True when `path` lists `blob` for `user` (lines: access-key keytype base64 [comment]).
pub fn authorized(text: []const u8, user: []const u8, blob: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var buf: [8192]u8 = undefined;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const who = f.next() orelse continue;
        const kt = f.next() orelse continue;
        const b64 = f.next() orelse continue;
        if (!std.mem.eql(u8, who, user)) continue;
        const dec = std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(b64) catch continue;
        if (n > buf.len) continue;
        dec.decode(buf[0..n], b64) catch continue;
        const t = blobType(buf[0..n]) orelse continue;
        if (!std.mem.eql(u8, t, kt)) continue;
        if (std.mem.eql(u8, buf[0..n], blob)) return true;
    }
    return false;
}

test "openssh-key-v1 ed25519 round trip and signatures" {
    const a = std.testing.allocator;
    const kp = Ed25519.KeyPair.generate();
    var out: [1024]u8 = undefined;
    const text = try encodeOpenSsh(kp, &out);
    var hk = try loadHostKey(a, text);
    defer hk.deinit(a);
    try std.testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &hk.ed25519.public_key.toBytes());
    var bb: [max_pub_blob]u8 = undefined;
    var bw = wire.Writer.init(&bb);
    try hk.writeBlob(&bw);
    var sb: [max_sig_blob]u8 = undefined;
    var sw = wire.Writer.init(&sb);
    try hk.sign(.ssh_ed25519, "exchange hash", &sw);
    try std.testing.expect(verify("ssh-ed25519", bw.written(), sw.written(), "exchange hash"));
    try std.testing.expect(!verify("ssh-ed25519", bw.written(), sw.written(), "other"));
    try std.testing.expect(!verify("rsa-sha2-256", bw.written(), sw.written(), "exchange hash"));
    var fp: [64]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, hk.fingerprint(&fp), "SHA256:"));
}

test "openssh key rejects encrypted and garbage" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.BadKey, loadHostKey(a, openssh_begin ++ "\nAAAA\n" ++ openssh_end));
    try std.testing.expectError(error.NoKey, loadHostKey(a, "nothing"));
}

test "authorized key lines" {
    var blob_buf: [64]u8 = undefined;
    var w = wire.Writer.init(&blob_buf);
    try w.string("ssh-ed25519");
    try w.string(&([_]u8{7} ** 32));
    var b64: [128]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&b64, w.written());
    var text_buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&text_buf, "# comment\nother ssh-ed25519 {s}\nalice ssh-ed25519 {s} laptop\n", .{ enc, enc });
    try std.testing.expect(authorized(text, "alice", w.written()));
    try std.testing.expect(!authorized(text, "bob", w.written()));
    try std.testing.expect(!authorized("alice ssh-rsa " ++ "AAAA", "alice", w.written()));
}

test "pkcs1 v1.5 encoding layout" {
    var em: [256]u8 = undefined;
    try pkcs1Encode(Sha256, "abc", &em);
    try std.testing.expectEqual(@as(u8, 1), em[1]);
    try std.testing.expectEqual(@as(u8, 0), em[256 - 52]);
    try std.testing.expectEqual(@as(u8, 0x30), em[256 - 51]);
}

test "rsa host key signs PKCS#1 v1.5 for both hashes" {
    const a = std.testing.allocator;
    var hk = try loadHostKey(a, test_rsa_pem);
    defer hk.deinit(a);
    var bb: [max_pub_blob]u8 = undefined;
    var bw = wire.Writer.init(&bb);
    try hk.writeBlob(&bw);
    try std.testing.expectEqualStrings("ssh-rsa", blobType(bw.written()).?);
    for ([_]SigAlg{ .rsa_sha2_256, .rsa_sha2_512 }) |alg| {
        var sb: [max_sig_blob]u8 = undefined;
        var sw = wire.Writer.init(&sb);
        try hk.sign(alg, "H", &sw);
        try std.testing.expect(verify(alg.name(), bw.written(), sw.written(), "H"));
        try std.testing.expect(!verify(alg.name(), bw.written(), sw.written(), "h"));
    }
    try std.testing.expect(!hk.supports(.ssh_ed25519));
}

// Test-only key.
const test_rsa_pem =
    \\-----BEGIN RSA PRIVATE KEY-----
    \\MIIEowIBAAKCAQEAuqFrGtHAPfW+fgbOHEZbCH87WlW9EXlWiMR6plM4hQLAexfJ
    \\NVxmB905h4VBcpNlzIDlI2iw9HZpmq5P35JaHBVvkDmo1yVgPvz4yaRRDNcAtdql
    \\TP1Hw5zL6mligGC/VGL1muBFcgQ5qX4YlSBwS91eJEaq2dFv75DEdzzgV0WjMa3c
    \\kN53V6A0NUaojoog9ny8gdh9TKdBdtfrztK6Mc3UpQgUssW/vaPLV2flUbYxRtoX
    \\UCHqBWMhaG64fc3zttN/dSqITIeIAQdHPUcCNYI/FTh61q0Fv8gfjB3hiJC9TgEP
    \\YF2+eUKBQJEEeaN6P/T5vUhKILuYVrFnrn+leQIDAQABAoIBAAGA62v75KCbKj25
    \\sE9qAbG/1KqVpkBNyfSwIIzWfs4Th5l2R5i2ddv6XExLNovFxDwxjacLYOGXUqJ8
    \\ZQhYFYHEanGvBT02f+ACCb8WI9EGqmrMqChGoh1hVgM9dh2yqdf0NCZbSDPy9MP4
    \\0BnjeQQjdG62Ywn+NfioIe0UAHqzgVx1jms0+JiUBYPaY1H6yQVUOrkhN9ROB1N2
    \\EcenUjHpEiVUICKrvBp+Xei9hQYfui7p9ms/jk1CCVtIIAfF1tvpGrJ+yccFyYmC
    \\wQmKcHWUY6g4v+2jTYQaciHQU1/Dy9f2+SJiwKJDg72JyhC7OmfNc6jaOGyRJja8
    \\t/HIMAECgYEA/3S/o5j17eqQP0qeQeHsgy5Z2+JYR1SSrgEZcNzQ0uI6IATT1j8/
    \\LE/nX4GRpUF1W5rXr6Sm1VhN6+O6LkwO8V95tAS+CteUn7AJZnr4aAjzDCmMnehG
    \\ELBmJzHUkgF8vcNx+vPLWb1JZn3hEQETDd2kSEeAyX0AKRSXmu80eyECgYEAuwcn
    \\AkuZHgIYo4XbOePWV+h/8WsqaZgmNaWNZMbOlUJbb5Vn5dKecWDm5IK4Tc/jmEUm
    \\m3JH56zrNtGQBl1yGMP5f/83/oSs0WJOGNvF3/upwDM7TjKnXhNHrJcnw9jvVu4K
    \\qwm3t6KwYBF19iCqDdLeh52YVo+TTGd3h6f091kCgYEApmqiJauSGuoCCplLu9O4
    \\RkU92Nb9d4qK+7xPnIzdpWQnRZCfiCUvvGhZbIh2H1gjYgffltcGsFmUeaWjNmHq
    \\Iih2mmW0gE+szNLbbN2TUgLyguvWZVBZxKmGAuadenhpkR3v9PI5eT6swI4kvvUa
    \\OqA3U7bxGVHLdvepRA+s+sECgYAsAhHWw20jF4EusSeVppvgEZBRgVL4h9mt0+fC
    \\Z9liW7viNLi+5mFr8k5CRNQTUzCNuu/LsgdjZ1ftjUAjj0dytmJ2ENrfI976YfRY
    \\exZDjxcxZ5yz2M1zIHxEC0lLFzeyL88I0f+N0VVJNbKZGLSLDixYoueerqgNWWdR
    \\316P+QKBgGxmosRIfS5BJbaQugVl4ev9D4XosiZC2H8Ryvewou32JoQl0p4uC/K2
    \\y5Kdu1kw7NfL3uZ8bxYhzXV16ihQh1IS3e3lU3wlILEGq2I9pW7UUN64R9RonIjo
    \\k9BZV/VxapU6E7tFue15WCA+RGnKoDA+KpNxID1lS9LfE/WFEzCR
    \\-----END RSA PRIVATE KEY-----
;
