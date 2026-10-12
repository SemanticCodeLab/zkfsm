//! Self-signed CA and server certificates (ECDSA P-256, X.509 v3) for clusters
//! that ask for `tls.mode: selfSigned`. PEM output: certificates and SEC1 keys.
const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const A = std.mem.Allocator;

const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ec_pub = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_cn = [_]u8{ 0x55, 0x04, 0x03 };
const oid_org = [_]u8{ 0x55, 0x04, 0x0A };
const oid_basic = [_]u8{ 0x55, 0x1D, 0x13 };
const oid_ku = [_]u8{ 0x55, 0x1D, 0x0F };
const oid_eku = [_]u8{ 0x55, 0x1D, 0x25 };
const oid_san = [_]u8{ 0x55, 0x1D, 0x11 };
const oid_ski = [_]u8{ 0x55, 0x1D, 0x0E };
const oid_aki = [_]u8{ 0x55, 0x1D, 0x23 };
const oid_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
const oid_client_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };

fn tlv(a: A, tag: u8, parts: []const []const u8) ![]u8 {
    var n: usize = 0;
    for (parts) |p| n += p.len;
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, tag);
    if (n < 0x80) {
        try out.append(a, @intCast(n));
    } else if (n < 0x100) {
        try out.appendSlice(a, &.{ 0x81, @intCast(n) });
    } else if (n < 0x10000) {
        try out.appendSlice(a, &.{ 0x82, @intCast(n >> 8), @intCast(n & 0xff) });
    } else return error.TooLong;
    for (parts) |p| try out.appendSlice(a, p);
    return out.items;
}

fn prim(a: A, tag: u8, b: []const u8) ![]u8 {
    return tlv(a, tag, &.{b});
}

fn seq(a: A, parts: []const []const u8) ![]u8 {
    return tlv(a, 0x30, parts);
}

/// Unsigned big-endian integer with minimal DER encoding.
fn uint(a: A, be: []const u8) ![]u8 {
    var i: usize = 0;
    while (i + 1 < be.len and be[i] == 0) i += 1;
    if (be[i] & 0x80 != 0) return tlv(a, 0x02, &.{ &.{0}, be[i..] });
    return tlv(a, 0x02, &.{be[i..]});
}

fn name(a: A, cn: []const u8) ![]u8 {
    const org = try tlv(a, 0x31, &.{try seq(a, &.{ try prim(a, 0x06, &oid_org), try prim(a, 0x0C, "zkfsm") })});
    const c = try tlv(a, 0x31, &.{try seq(a, &.{ try prim(a, 0x06, &oid_cn), try prim(a, 0x0C, cn) })});
    return seq(a, &.{ org, c });
}

fn utcTime(a: A, t: i64) ![]u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(t) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    const s = try std.fmt.allocPrint(a, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        @as(u32, yd.year % 100), md.month.numeric(),      @as(u32, md.day_index) + 1,
        ds.getHoursIntoDay(),    ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
    return tlv(a, 0x17, &.{s});
}

fn ext(a: A, oid: []const u8, critical: bool, value: []const u8) ![]u8 {
    if (critical) return seq(a, &.{ try prim(a, 0x06, oid), try prim(a, 0x01, &.{0xFF}), try tlv(a, 0x04, &.{value}) });
    return seq(a, &.{ try prim(a, 0x06, oid), try tlv(a, 0x04, &.{value}) });
}

fn sigDer(a: A, sig: Ecdsa.Signature) ![]u8 {
    return seq(a, &.{ try uint(a, &sig.r), try uint(a, &sig.s) });
}

fn keyId(pub_point: []const u8) [20]u8 {
    var h: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(pub_point, &h, .{});
    return h;
}

pub const Issued = struct {
    cert_pem: []u8,
    key_pem: []u8,
};

pub const Issuer = struct {
    kp: Ecdsa.KeyPair,
    cn: []const u8,
};

pub const Options = struct {
    cn: []const u8,
    dns: []const []const u8 = &.{},
    ips: []const [4]u8 = &.{},
    is_ca: bool = false,
    now: i64,
    days: u32 = 3650,
};

/// Issues a certificate for a fresh key; `issuer` null means self-signed.
pub fn issue(a: A, o: Options, issuer: ?Issuer) !Issued {
    const kp = Ecdsa.KeyPair.generate();
    return issueFor(a, o, kp, issuer);
}

fn issueFor(a: A, o: Options, kp: Ecdsa.KeyPair, issuer: ?Issuer) !Issued {
    const point = kp.public_key.toUncompressedSec1();
    var serial: [16]u8 = undefined;
    std.crypto.random.bytes(&serial);
    serial[0] = (serial[0] & 0x7f) | 0x01;
    const alg = try seq(a, &.{try prim(a, 0x06, &oid_ecdsa_sha256)});
    const spki = try seq(a, &.{ try seq(a, &.{ try prim(a, 0x06, &oid_ec_pub), try prim(a, 0x06, &oid_p256) }), try tlv(a, 0x03, &.{ &.{0}, &point }) });
    const signer = issuer orelse Issuer{ .kp = kp, .cn = o.cn };
    const ski = keyId(&point);
    const aki = keyId(&signer.kp.public_key.toUncompressedSec1());

    var exts: std.ArrayList([]const u8) = .empty;
    if (o.is_ca) {
        try exts.append(a, try ext(a, &oid_basic, true, try seq(a, &.{try prim(a, 0x01, &.{0xFF})})));
        try exts.append(a, try ext(a, &oid_ku, true, try tlv(a, 0x03, &.{ &.{1}, &.{0x86} })));
    } else {
        try exts.append(a, try ext(a, &oid_basic, true, try seq(a, &.{})));
        try exts.append(a, try ext(a, &oid_ku, true, try tlv(a, 0x03, &.{ &.{5}, &.{0xA0} })));
        try exts.append(a, try ext(a, &oid_eku, false, try seq(a, &.{ try prim(a, 0x06, &oid_server_auth), try prim(a, 0x06, &oid_client_auth) })));
        var sans: std.ArrayList([]const u8) = .empty;
        for (o.dns) |d| try sans.append(a, try tlv(a, 0x82, &.{d}));
        for (o.ips) |ip| try sans.append(a, try tlv(a, 0x87, &.{&ip}));
        try exts.append(a, try ext(a, &oid_san, false, try seq(a, sans.items)));
    }
    try exts.append(a, try ext(a, &oid_ski, false, try tlv(a, 0x04, &.{&ski})));
    try exts.append(a, try ext(a, &oid_aki, false, try seq(a, &.{try tlv(a, 0x80, &.{&aki})})));

    const tbs = try seq(a, &.{
        try tlv(a, 0xA0, &.{try uint(a, &.{2})}),
        try uint(a, &serial),
        alg,
        try name(a, signer.cn),
        try seq(a, &.{ try utcTime(a, o.now - 3600), try utcTime(a, o.now + @as(i64, o.days) * 86400) }),
        try name(a, o.cn),
        spki,
        try tlv(a, 0xA3, &.{try seq(a, exts.items)}),
    });
    const sig = try signer.kp.sign(tbs, null);
    const cert = try seq(a, &.{ tbs, alg, try tlv(a, 0x03, &.{ &.{0}, try sigDer(a, sig) }) });

    const sk = kp.secret_key.toBytes();
    const key = try seq(a, &.{
        try uint(a, &.{1}),
        try tlv(a, 0x04, &.{&sk}),
        try tlv(a, 0xA0, &.{try prim(a, 0x06, &oid_p256)}),
        try tlv(a, 0xA1, &.{try tlv(a, 0x03, &.{ &.{0}, &point })}),
    });
    return .{ .cert_pem = try pemEncode(a, "CERTIFICATE", cert), .key_pem = try pemEncode(a, "EC PRIVATE KEY", key) };
}

pub fn pemEncode(a: A, label: []const u8, der: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = try a.alloc(u8, enc.calcSize(der.len));
    _ = enc.encode(b64, der);
    var out: std.ArrayList(u8) = .empty;
    try out.print(a, "-----BEGIN {s}-----\n", .{label});
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try out.appendSlice(a, b64[i..@min(i + 64, b64.len)]);
        try out.append(a, '\n');
    }
    try out.print(a, "-----END {s}-----\n", .{label});
    return out.items;
}

/// Recovers the CA key pair from its SEC1 PEM (as written by `issue`).
pub fn loadIssuer(a: A, cn: []const u8, key_pem: []const u8) !Issuer {
    const begin = "-----BEGIN EC PRIVATE KEY-----";
    const s = std.mem.indexOf(u8, key_pem, begin) orelse return error.BadKey;
    const e = std.mem.indexOfPos(u8, key_pem, s, "-----END") orelse return error.BadKey;
    var b64: std.ArrayList(u8) = .empty;
    for (key_pem[s + begin.len .. e]) |c| if (!std.ascii.isWhitespace(c)) try b64.append(a, c);
    const dec = std.base64.standard.Decoder;
    const der = try a.alloc(u8, try dec.calcSizeForSlice(b64.items));
    try dec.decode(der, b64.items);
    // SEQ { INTEGER 1, OCTET STRING(32) d, ... }: fixed offsets for our own encoding.
    if (der.len < 7 + 32 or der[0] != 0x30 or der[5] != 0x04 or der[6] != 32) return error.BadKey;
    const sk = try Ecdsa.SecretKey.fromBytes(der[7..39].*);
    return .{ .kp = try Ecdsa.KeyPair.fromSecretKey(sk), .cn = cn };
}

test "issue CA and leaf; std parses and verifies the chain" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const now = std.time.timestamp();
    const ca = try issue(a, .{ .cn = "zkfsm-ca", .is_ca = true, .now = now }, null);
    const iss = try loadIssuer(a, "zkfsm-ca", ca.key_pem);
    const leaf = try issue(a, .{ .cn = "zkfsm", .dns = &.{ "*.c-hl.ns.svc.cluster.local", "localhost" }, .ips = &.{.{ 127, 0, 0, 1 }}, .now = now }, iss);

    const ca_der = try pemDecode(a, ca.cert_pem);
    const leaf_der = try pemDecode(a, leaf.cert_pem);
    const C = std.crypto.Certificate;
    const pca = try (C{ .buffer = ca_der, .index = 0 }).parse();
    const pleaf = try (C{ .buffer = leaf_der, .index = 0 }).parse();
    try pleaf.verify(pca, now);
    try pleaf.verifyHostName("p-0.c-hl.ns.svc.cluster.local");
    try std.testing.expectError(error.CertificateHostMismatch, pleaf.verifyHostName("other.example"));
    try std.testing.expect(std.mem.startsWith(u8, leaf.key_pem, "-----BEGIN EC PRIVATE KEY-----"));
}

fn pemDecode(a: A, pem: []const u8) ![]u8 {
    var b64: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, pem, '\n');
    while (it.next()) |l| if (l.len > 0 and l[0] != '-') try b64.appendSlice(a, l);
    const dec = std.base64.standard.Decoder;
    const out = try a.alloc(u8, try dec.calcSizeForSlice(b64.items));
    try dec.decode(out, b64.items);
    return out;
}
