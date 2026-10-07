//! Swift credentials: stateless tempauth tokens and temp URL signatures.
const std = @import("std");
const ctEql = @import("access.zig").ctEql;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const token_prefix = "AUTH_tk";
pub const max_name = 128;
pub const max_token = token_prefix.len + 2 * (8 + 2 + 2 * max_name) + 2 * HmacSha256.mac_length;

/// What a valid tempauth token proves; slices point into the caller's buffer.
pub const Claims = struct { account: []const u8, access_key: []const u8, expires_s: i64 };

pub const MintError = error{NameTooLong};

/// AUTH_tk<hex(expiry, account, key)><hex(hmac)>; `out` must hold `max_token` bytes.
pub fn mintToken(out: []u8, secret: *const [32]u8, account: []const u8, access_key: []const u8, expires_s: i64) MintError![]const u8 {
    if (account.len > max_name or access_key.len > max_name or out.len < max_token) return error.NameTooLong;
    var payload: [8 + 2 + 2 * max_name]u8 = undefined;
    const p = encodePayload(&payload, account, access_key, expires_s);
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, p, secret);
    var w: std.Io.Writer = .fixed(out);
    w.print("{s}{x}{x}", .{ token_prefix, p, &mac }) catch return error.NameTooLong;
    return w.buffered();
}

fn encodePayload(buf: []u8, account: []const u8, access_key: []const u8, expires_s: i64) []const u8 {
    std.mem.writeInt(i64, buf[0..8], expires_s, .big);
    buf[8] = @intCast(account.len);
    @memcpy(buf[9..][0..account.len], account);
    const k = 9 + account.len;
    buf[k] = @intCast(access_key.len);
    @memcpy(buf[k + 1 ..][0..access_key.len], access_key);
    return buf[0 .. k + 1 + access_key.len];
}

/// Checks the MAC (constant time) and expiry; `buf` receives the decoded payload.
pub fn verifyToken(buf: *[8 + 2 + 2 * max_name]u8, secret: *const [32]u8, token: []const u8, now_s: i64) ?Claims {
    if (!std.mem.startsWith(u8, token, token_prefix) or token.len > max_token) return null;
    const hex = token[token_prefix.len..];
    if (hex.len < 2 * HmacSha256.mac_length + 2 * 10 or hex.len % 2 != 0) return null;
    const ph = hex[0 .. hex.len - 2 * HmacSha256.mac_length];
    const p = std.fmt.hexToBytes(buf, ph) catch return null;
    var got: [HmacSha256.mac_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&got, hex[ph.len..]) catch return null;
    var want: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&want, p, secret);
    if (!ctEql(&got, &want)) return null;
    const exp = std.mem.readInt(i64, p[0..8], .big);
    if (exp <= now_s) return null;
    const al = p[8];
    if (9 + @as(usize, al) + 1 > p.len) return null;
    const kl = p[9 + al];
    if (9 + @as(usize, al) + 1 + kl != p.len) return null;
    return .{ .account = p[9..][0..al], .access_key = p[10 + al ..][0..kl], .expires_s = exp };
}

// ---- temp URLs ----

pub const Digest = enum { sha1, sha256, sha512 };
const max_mac = 64;

/// A signature from temp_url_sig: hex (length picks the digest) or "<digest>:<base64>".
pub const Sig = struct { digest: Digest, mac: [max_mac]u8, len: usize };

pub fn parseSig(s: []const u8) ?Sig {
    var sig: Sig = .{ .digest = .sha1, .mac = undefined, .len = 0 };
    if (std.mem.indexOfScalar(u8, s, ':')) |c| {
        sig.digest = std.meta.stringToEnum(Digest, s[0..c]) orelse return null;
        var b64 = s[c + 1 ..];
        b64 = std.mem.trimRight(u8, b64, "=");
        if (b64.len > 100) return null;
        var norm: [100]u8 = undefined;
        for (b64, 0..) |ch, i| norm[i] = switch (ch) {
            '-' => '+',
            '_' => '/',
            else => ch,
        };
        const dec = std.base64.standard_no_pad.Decoder;
        const n = dec.calcSizeForSlice(norm[0..b64.len]) catch return null;
        if (n != macLen(sig.digest)) return null;
        dec.decode(sig.mac[0..n], norm[0..b64.len]) catch return null;
        sig.len = n;
        return sig;
    }
    sig.digest = switch (s.len) {
        40 => .sha1,
        64 => .sha256,
        128 => .sha512,
        else => return null,
    };
    sig.len = s.len / 2;
    _ = std.fmt.hexToBytes(sig.mac[0..sig.len], s) catch return null;
    return sig;
}

fn macLen(d: Digest) usize {
    return switch (d) {
        .sha1 => 20,
        .sha256 => 32,
        .sha512 => 64,
    };
}

/// HMAC of "METHOD\nexpires\npath" (path is "prefix:<p>" for prefix URLs).
pub fn sign(out: *[max_mac]u8, d: Digest, key: []const u8, method: []const u8, expires: i64, path: []const u8, prefix: bool) []const u8 {
    var body_buf: [4096]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{s}\n{d}\n{s}{s}", .{ method, expires, if (prefix) "prefix:" else "", path }) catch return out[0..0];
    switch (d) {
        inline else => |t| {
            const H = switch (t) {
                .sha1 => std.crypto.auth.hmac.HmacSha1,
                .sha256 => std.crypto.auth.hmac.sha2.HmacSha256,
                .sha512 => std.crypto.auth.hmac.sha2.HmacSha512,
            };
            H.create(out[0..H.mac_length], body, key);
            return out[0..H.mac_length];
        },
    }
}

/// Parses temp_url_expires: unix seconds or ISO 8601 UTC.
pub fn parseExpires(s: []const u8) ?i64 {
    if (std.fmt.parseInt(i64, s, 10)) |v| return if (v >= 0) v else null else |_| {}
    return @import("swift_util.zig").parseIso8601(s);
}

/// True when `sig` matches any key for any method in `methods`.
pub fn verifySig(sig: Sig, keys: []const []const u8, methods: []const []const u8, expires: i64, path: []const u8, prefix: bool) bool {
    var ok = false;
    for (keys) |k| for (methods) |m| {
        var mac: [max_mac]u8 = undefined;
        const want = sign(&mac, sig.digest, k, m, expires, path, prefix);
        if (want.len > 0 and ctEql(want, sig.mac[0..sig.len])) ok = true;
    };
    return ok;
}

test "tempauth token round trip and tamper" {
    const secret = [_]u8{7} ** 32;
    var out: [max_token]u8 = undefined;
    const t = try mintToken(&out, &secret, "test", "AKIDEXAMPLE", 2000);
    var buf: [8 + 2 + 2 * max_name]u8 = undefined;
    const c = verifyToken(&buf, &secret, t, 1000).?;
    try std.testing.expectEqualStrings("test", c.account);
    try std.testing.expectEqualStrings("AKIDEXAMPLE", c.access_key);
    try std.testing.expect(verifyToken(&buf, &secret, t, 2000) == null);
    var bad: [max_token]u8 = undefined;
    @memcpy(bad[0..t.len], t);
    bad[t.len - 1] = if (bad[t.len - 1] == '0') '1' else '0';
    try std.testing.expect(verifyToken(&buf, &secret, bad[0..t.len], 1000) == null);
    const other = [_]u8{8} ** 32;
    try std.testing.expect(verifyToken(&buf, &other, t, 1000) == null);
    try std.testing.expect(verifyToken(&buf, &secret, "AUTH_tkzz", 1000) == null);
    try std.testing.expect(verifyToken(&buf, &secret, "nope", 1000) == null);
}

// Vectors from Python: hmac.new(b"mykey", b"GET\n1700000000\n/v1/AUTH_test/c/o", sha*).
test "temp url signature vectors" {
    const path = "/v1/AUTH_test/c/o";
    const cases = [_]struct { sig: []const u8 }{
        .{ .sig = "3994d403a1e371c61672cc49d49e3504805f4887" },
        .{ .sig = "7d8e44a645aab88cf197df39a844fc98555dad169375805007f6e9b55a5c9370" },
        .{ .sig = "1cc2a33fe5b1a4189352241e357eb4137852acf7b9dbd7ab04803fad3acabd2c8c47ff30f46792ed8ff0dda0f3990cc8bffcf41791c180a9f13e72cf2d42eb34" },
        .{ .sig = "sha512:HMKjP+WxpBiTUiQeNX60E3hSrPe529erBIA/rTrKvSyMR/8w9GeS7Y/w3aDzmQzIv/z0F5HBgKnxPnLPLULrNA==" },
        .{ .sig = "sha256:fY5EpkWquIzxl985qET8mFVdrRaTdYBQB_bptVpck3A" },
    };
    for (cases) |c| {
        const s = parseSig(c.sig) orelse return error.TestBadSig;
        try std.testing.expect(verifySig(s, &.{ "other", "mykey" }, &.{"GET"}, 1700000000, path, false));
        try std.testing.expect(!verifySig(s, &.{"mykey"}, &.{"PUT"}, 1700000000, path, false));
        try std.testing.expect(!verifySig(s, &.{"mykey"}, &.{"GET"}, 1700000001, path, false));
    }
    const ps = parseSig("57d9c8964671336c3c750615ddaebd26958c22f1").?;
    try std.testing.expect(verifySig(ps, &.{"mykey"}, &.{"GET"}, 1700000000, "/v1/AUTH_test/c/pre", true));
    try std.testing.expect(parseSig("abc") == null);
    try std.testing.expect(parseSig("md5:AAAA") == null);
    try std.testing.expectEqual(@as(?i64, 1700000000), parseExpires("2023-11-14T22:13:20Z"));
}
