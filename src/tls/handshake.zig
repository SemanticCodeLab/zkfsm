//! TLS 1.3 and 1.2 handshake message parsing and construction (RFC 8446 4, RFC 5246 7.4).
//! Every length read from the peer is checked against the enclosing slice.
const std = @import("std");
const tls = std.crypto.tls;

pub const ParseError = error{ DecodeError, IllegalParameter, ProtocolVersion };

pub const ext = struct {
    pub const server_name: u16 = 0;
    pub const ec_point_formats: u16 = 11;
    pub const extended_master_secret: u16 = 23;
    pub const renegotiation_info: u16 = 0xff01;
    pub const supported_groups: u16 = 10;
    pub const signature_algorithms: u16 = 13;
    pub const alpn: u16 = 16;
    pub const pre_shared_key: u16 = 41;
    pub const early_data: u16 = 42;
    pub const supported_versions: u16 = 43;
    pub const cookie: u16 = 44;
    pub const psk_key_exchange_modes: u16 = 45;
    pub const key_share: u16 = 51;
};

pub const group_x25519: u16 = 0x001d;
pub const group_secp256r1: u16 = 0x0017;

/// Bounded big-endian cursor over peer bytes.
pub const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    pub fn left(c: Cursor) usize {
        return c.b.len - c.i;
    }
    pub fn int(c: *Cursor, comptime T: type) ParseError!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        if (c.left() < n) return error.DecodeError;
        defer c.i += n;
        return std.mem.readInt(T, c.b[c.i..][0..n], .big);
    }
    pub fn bytes(c: *Cursor, n: usize) ParseError![]const u8 {
        if (c.left() < n) return error.DecodeError;
        defer c.i += n;
        return c.b[c.i..][0..n];
    }
    /// Length-prefixed vector with a `Len`-sized prefix.
    pub fn vec(c: *Cursor, comptime Len: type) ParseError![]const u8 {
        return c.bytes(try c.int(Len));
    }
};

pub const ClientHello = struct {
    random: [32]u8,
    session_id: []const u8,
    suites: []const u8,
    tls13: bool = false,
    tls12: bool = false,
    /// RFC 7627 extended_master_secret offered.
    ems: bool = false,
    /// renegotiated_connection from renegotiation_info (RFC 5746), if sent.
    reneg: ?[]const u8 = null,
    groups: ?[]const u8 = null,
    key_shares: ?[]const u8 = null,
    sig_algs: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    sni: ?[]const u8 = null,
    early_data: bool = false,
    psk: bool = false,
    cookie: bool = false,

    /// Parses a ClientHello body (after the 4-byte handshake header).
    pub fn parse(body: []const u8) ParseError!ClientHello {
        var c: Cursor = .{ .b = body };
        const legacy_version = try c.int(u16);
        var h: ClientHello = .{ .random = (try c.bytes(32))[0..32].*, .session_id = undefined, .suites = undefined };
        h.session_id = try c.vec(u8);
        if (h.session_id.len > 32) return error.IllegalParameter;
        h.suites = try c.vec(u16);
        if (h.suites.len < 2 or h.suites.len % 2 != 0) return error.DecodeError;
        const comp = try c.vec(u8);
        if (c.left() == 0) {
            // No extensions at all: at most a 1.2 hello.
            if (legacy_version < 0x0303) return error.ProtocolVersion;
            if (comp.len == 0 or std.mem.indexOfScalar(u8, comp, 0) == null) return error.IllegalParameter;
            h.tls12 = true;
            return h;
        }
        const exts = try c.vec(u16);
        if (c.left() != 0) return error.DecodeError;
        var seen = std.StaticBitSet(64).initEmpty();
        var e: Cursor = .{ .b = exts };
        while (e.left() > 0) {
            const typ = try e.int(u16);
            const data = try e.vec(u16);
            if (typ < 64) {
                if (seen.isSet(typ)) return error.IllegalParameter;
                seen.set(typ);
            }
            switch (typ) {
                ext.supported_versions => {
                    var v: Cursor = .{ .b = data };
                    const list = try v.vec(u8);
                    if (v.left() != 0 or list.len == 0 or list.len % 2 != 0) return error.DecodeError;
                    var i: usize = 0;
                    while (i < list.len) : (i += 2) {
                        switch (std.mem.readInt(u16, list[i..][0..2], .big)) {
                            0x0304 => h.tls13 = true,
                            0x0303 => h.tls12 = true,
                            else => {},
                        }
                    }
                },
                ext.extended_master_secret => {
                    if (data.len != 0) return error.DecodeError;
                    h.ems = true;
                },
                ext.renegotiation_info => {
                    if (h.reneg != null) return error.IllegalParameter;
                    var v: Cursor = .{ .b = data };
                    h.reneg = try v.vec(u8);
                    if (v.left() != 0) return error.DecodeError;
                },
                ext.supported_groups => h.groups = try evenList(data),
                ext.signature_algorithms => h.sig_algs = try evenList(data),
                ext.key_share => {
                    var v: Cursor = .{ .b = data };
                    const list = try v.vec(u16);
                    if (v.left() != 0) return error.DecodeError;
                    var s: Cursor = .{ .b = list };
                    while (s.left() > 0) {
                        _ = try s.int(u16);
                        if ((try s.vec(u16)).len == 0) return error.DecodeError;
                    }
                    h.key_shares = list;
                },
                ext.alpn => {
                    var v: Cursor = .{ .b = data };
                    const list = try v.vec(u16);
                    if (v.left() != 0 or list.len == 0) return error.DecodeError;
                    var s: Cursor = .{ .b = list };
                    while (s.left() > 0) if ((try s.vec(u8)).len == 0) return error.DecodeError;
                    h.alpn = list;
                },
                ext.server_name => h.sni = try parseSni(data),
                ext.early_data => h.early_data = true,
                ext.cookie => h.cookie = true,
                ext.pre_shared_key => {
                    // Must be last (RFC 8446 4.2.11); we never select it.
                    if (e.left() != 0) return error.IllegalParameter;
                    h.psk = true;
                },
                else => {},
            }
        }
        // Without supported_versions the legacy field is the offer (RFC 8446 4.2.1).
        if (!seen.isSet(ext.supported_versions) and legacy_version >= 0x0303) h.tls12 = true;
        if ((!h.tls13 and !h.tls12) or legacy_version < 0x0301) return error.ProtocolVersion;
        if (h.tls13) {
            if (comp.len != 1 or comp[0] != 0) return error.IllegalParameter;
        } else if (std.mem.indexOfScalar(u8, comp, 0) == null) return error.IllegalParameter;
        return h;
    }

    pub fn offersSuite(h: ClientHello, suite: u16) bool {
        return containsU16(h.suites, suite);
    }

    pub fn offersAlpn(h: ClientHello, proto: []const u8) bool {
        var s: Cursor = .{ .b = h.alpn orelse return false };
        while (s.left() > 0) if (std.mem.eql(u8, s.vec(u8) catch return false, proto)) return true;
        return false;
    }

    /// Returns the client's share for `group`, if any.
    pub fn keyShare(h: ClientHello, group: u16) ?[]const u8 {
        var s: Cursor = .{ .b = h.key_shares orelse return null };
        while (s.left() > 0) {
            const g = s.int(u16) catch return null;
            const k = s.vec(u16) catch return null;
            if (g == group) return k;
        }
        return null;
    }

    pub fn keyShareCount(h: ClientHello) usize {
        var s: Cursor = .{ .b = h.key_shares orelse return 0 };
        var n: usize = 0;
        while (s.left() > 0) : (n += 1) {
            _ = s.int(u16) catch break;
            _ = s.vec(u16) catch break;
        }
        return n;
    }
};

fn evenList(data: []const u8) ParseError![]const u8 {
    var v: Cursor = .{ .b = data };
    const list = try v.vec(u16);
    if (v.left() != 0 or list.len == 0 or list.len % 2 != 0) return error.DecodeError;
    return list;
}

fn parseSni(data: []const u8) ParseError!?[]const u8 {
    var v: Cursor = .{ .b = data };
    const list = try v.vec(u16);
    if (v.left() != 0) return error.DecodeError;
    var s: Cursor = .{ .b = list };
    var host: ?[]const u8 = null;
    while (s.left() > 0) {
        const typ = try s.int(u8);
        const name = try s.vec(u16);
        if (typ == 0) {
            if (host != null or name.len == 0 or name.len > 255) return error.IllegalParameter;
            host = name;
        }
    }
    return host;
}

pub fn containsU16(list: []const u8, want: u16) bool {
    var i: usize = 0;
    while (i + 1 < list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == want) return true;
    }
    return false;
}

/// Append-only builder over a caller buffer; overflow is a programming error guarded by `error.Overflow`.
pub const Builder = struct {
    buf: []u8,
    len: usize = 0,

    pub const Error = error{Overflow};

    pub fn bytes(b: *Builder, data: []const u8) Error!void {
        if (b.buf.len - b.len < data.len) return error.Overflow;
        @memcpy(b.buf[b.len..][0..data.len], data);
        b.len += data.len;
    }
    pub fn int(b: *Builder, comptime T: type, v: T) Error!void {
        var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .big);
        try b.bytes(&tmp);
    }
    /// Reserves a `Len`-sized length prefix; call `end` with the returned mark.
    pub fn begin(b: *Builder, comptime Len: type) Error!usize {
        const mark = b.len;
        try b.int(Len, 0);
        return mark;
    }
    pub fn end(b: *Builder, comptime Len: type, mark: usize) Error!void {
        const n = @divExact(@typeInfo(Len).int.bits, 8);
        const body = b.len - mark - n;
        if (body > std.math.maxInt(Len)) return error.Overflow;
        std.mem.writeInt(Len, b.buf[mark..][0..n], @intCast(body), .big);
    }
    pub fn written(b: Builder) []u8 {
        return b.buf[0..b.len];
    }
};

pub fn serverHello(b: *Builder, random: [32]u8, session_id: []const u8, suite: u16, group: u16, key: []const u8) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.server_hello));
    const m = try b.begin(u24);
    try b.int(u16, 0x0303);
    try b.bytes(&random);
    const s = try b.begin(u8);
    try b.bytes(session_id);
    try b.end(u8, s);
    try b.int(u16, suite);
    try b.int(u8, 0);
    const e = try b.begin(u16);
    try b.int(u16, ext.key_share);
    const ks = try b.begin(u16);
    try b.int(u16, group);
    if (key.len > 0) {
        const k = try b.begin(u16);
        try b.bytes(key);
        try b.end(u16, k);
    }
    try b.end(u16, ks);
    try b.int(u16, ext.supported_versions);
    try b.int(u16, 2);
    try b.int(u16, 0x0304);
    try b.end(u16, e);
    try b.end(u24, m);
}

pub fn helloRetryRequest(b: *Builder, session_id: []const u8, suite: u16, group: u16) Builder.Error!void {
    return serverHello(b, tls.hello_retry_request_sequence, session_id, suite, group, &.{});
}

pub fn encryptedExtensions(b: *Builder, alpn: ?[]const u8, ack_sni: bool) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.encrypted_extensions));
    const m = try b.begin(u24);
    const e = try b.begin(u16);
    if (alpn) |p| {
        try b.int(u16, ext.alpn);
        const x = try b.begin(u16);
        const l = try b.begin(u16);
        try b.int(u8, @intCast(p.len));
        try b.bytes(p);
        try b.end(u16, l);
        try b.end(u16, x);
    }
    if (ack_sni) {
        try b.int(u16, ext.server_name);
        try b.int(u16, 0);
    }
    try b.end(u16, e);
    try b.end(u24, m);
}

pub fn certificate(b: *Builder, chain: []const []const u8) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.certificate));
    const m = try b.begin(u24);
    try b.int(u8, 0);
    const l = try b.begin(u24);
    for (chain) |c| {
        const x = try b.begin(u24);
        try b.bytes(c);
        try b.end(u24, x);
        try b.int(u16, 0);
    }
    try b.end(u24, l);
    try b.end(u24, m);
}

pub fn certificateVerify(b: *Builder, scheme: u16, sig: []const u8) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.certificate_verify));
    const m = try b.begin(u24);
    try b.int(u16, scheme);
    const s = try b.begin(u16);
    try b.bytes(sig);
    try b.end(u16, s);
    try b.end(u24, m);
}

pub fn finished(b: *Builder, verify_data: []const u8) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.finished));
    const m = try b.begin(u24);
    try b.bytes(verify_data);
    try b.end(u24, m);
}

/// CertificateRequest with an empty context and our verifiable schemes (RFC 8446 4.3.2).
pub fn certificateRequest(b: *Builder, schemes: []const tls.SignatureScheme) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.certificate_request));
    const m = try b.begin(u24);
    try b.int(u8, 0);
    const e = try b.begin(u16);
    try b.int(u16, ext.signature_algorithms);
    const x = try b.begin(u16);
    const l = try b.begin(u16);
    for (schemes) |sc| try b.int(u16, @intFromEnum(sc));
    try b.end(u16, l);
    try b.end(u16, x);
    try b.end(u16, e);
    try b.end(u24, m);
}

// ---- TLS 1.2 messages ----

pub const Hello12 = struct {
    random: [32]u8,
    suite: u16,
    alpn: ?[]const u8,
    ack_sni: bool,
    secure_reneg: bool,
};

/// ServerHello with an empty session id (no resumption) and the EMS extension.
pub fn serverHello12(b: *Builder, h: Hello12) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.server_hello));
    const m = try b.begin(u24);
    try b.int(u16, 0x0303);
    try b.bytes(&h.random);
    try b.int(u8, 0);
    try b.int(u16, h.suite);
    try b.int(u8, 0);
    const e = try b.begin(u16);
    if (h.secure_reneg) try b.bytes(&.{ 0xff, 0x01, 0, 1, 0 });
    try b.bytes(&.{ 0, ext.extended_master_secret, 0, 0 });
    try b.bytes(&.{ 0, ext.ec_point_formats, 0, 2, 1, 0 });
    if (h.alpn) |p| {
        try b.int(u16, ext.alpn);
        const x = try b.begin(u16);
        const l = try b.begin(u16);
        try b.int(u8, @intCast(p.len));
        try b.bytes(p);
        try b.end(u16, l);
        try b.end(u16, x);
    }
    if (h.ack_sni) try b.bytes(&.{ 0, 0, 0, 0 });
    try b.end(u16, e);
    try b.end(u24, m);
}

/// Certificate without request context or per-entry extensions (RFC 5246 7.4.2).
pub fn certificate12(b: *Builder, chain: []const []const u8) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.certificate));
    const m = try b.begin(u24);
    const l = try b.begin(u24);
    for (chain) |c| {
        const x = try b.begin(u24);
        try b.bytes(c);
        try b.end(u24, x);
    }
    try b.end(u24, l);
    try b.end(u24, m);
}

/// ECParameters + public point: the signed part of ServerKeyExchange (RFC 8422 5.4).
pub fn ecdheParams(b: *Builder, group: u16, point: []const u8) Builder.Error!void {
    try b.int(u8, 3); // named_curve
    try b.int(u16, group);
    const p = try b.begin(u8);
    try b.bytes(point);
    try b.end(u8, p);
}

pub fn certificateRequest12(b: *Builder, schemes: []const tls.SignatureScheme) Builder.Error!void {
    try b.int(u8, @intFromEnum(tls.HandshakeType.certificate_request));
    const m = try b.begin(u24);
    try b.bytes(&.{ 2, 1, 64 }); // rsa_sign, ecdsa_sign
    const l = try b.begin(u16);
    for (schemes) |sc| try b.int(u16, @intFromEnum(sc));
    try b.end(u16, l);
    try b.int(u16, 0);
    try b.end(u24, m);
}

pub fn serverHelloDone(b: *Builder) Builder.Error!void {
    try b.bytes(&.{ @intFromEnum(tls.HandshakeType.server_hello_done), 0, 0, 0 });
}

/// Splits a 1.2 client Certificate body into DER entries; empty means no certificate.
pub fn parseCertificate12(body: []const u8, out: *[max_peer_chain][]const u8) CertificateError![]const []const u8 {
    var c: Cursor = .{ .b = body };
    const list = try c.vec(u24);
    if (c.left() != 0) return error.DecodeError;
    var l: Cursor = .{ .b = list };
    var n: usize = 0;
    while (l.left() > 0) : (n += 1) {
        const cert = try l.vec(u24);
        if (cert.len == 0) return error.DecodeError;
        if (n == max_peer_chain) return error.BadCertificate;
        out[n] = cert;
    }
    return out[0..n];
}

/// ClientKeyExchange body: one ECPoint (RFC 8422 5.7).
pub fn parseClientKeyExchange(body: []const u8) ParseError![]const u8 {
    var c: Cursor = .{ .b = body };
    const point = try c.vec(u8);
    if (c.left() != 0 or point.len == 0) return error.DecodeError;
    return point;
}

pub const max_peer_chain = 8;
pub const CertificateError = ParseError || error{BadCertificate};

/// Splits a client Certificate body into DER entries; empty means no certificate.
pub fn parseCertificate(body: []const u8, out: *[max_peer_chain][]const u8) CertificateError![]const []const u8 {
    var c: Cursor = .{ .b = body };
    if ((try c.vec(u8)).len != 0) return error.IllegalParameter;
    const list = try c.vec(u24);
    if (c.left() != 0) return error.DecodeError;
    var l: Cursor = .{ .b = list };
    var n: usize = 0;
    while (l.left() > 0) : (n += 1) {
        const cert = try l.vec(u24);
        _ = try l.vec(u16);
        if (cert.len == 0) return error.DecodeError;
        if (n == max_peer_chain) return error.BadCertificate;
        out[n] = cert;
    }
    return out[0..n];
}

/// Content covered by the server CertificateVerify signature (RFC 8446 4.4.3).
pub fn verifyContent(out: []u8, transcript_hash: []const u8) []const u8 {
    return verifyContentFor(out, "TLS 1.3, server CertificateVerify", transcript_hash);
}

pub const client_verify_context = "TLS 1.3, client CertificateVerify";

pub fn verifyContentFor(out: []u8, comptime ctx: []const u8, transcript_hash: []const u8) []const u8 {
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..ctx.len], ctx);
    out[64 + ctx.len] = 0;
    @memcpy(out[65 + ctx.len ..][0..transcript_hash.len], transcript_hash);
    return out[0 .. 65 + ctx.len + transcript_hash.len];
}

test "client hello rejects duplicates, bad lengths, and pre-1.3" {
    // Minimal valid-looking hello with supported_versions {0304}.
    const good = [_]u8{ 0x03, 0x03 } ++ [_]u8{0} ** 32 ++ [_]u8{ 0, 0, 2, 0x13, 0x01, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4 };
    const h = try ClientHello.parse(&good);
    try std.testing.expect(h.tls13 and h.offersSuite(0x1301));
    const dup = [_]u8{ 0x03, 0x03 } ++ [_]u8{0} ** 32 ++ [_]u8{ 0, 0, 2, 0x13, 0x01, 1, 0, 0, 14, 0, 43, 0, 3, 2, 3, 4, 0, 43, 0, 3, 2, 3, 4 };
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(&dup));
    const old = [_]u8{ 0x03, 0x01 } ++ [_]u8{0} ** 32 ++ [_]u8{ 0, 0, 2, 0x00, 0x2f, 1, 0 };
    try std.testing.expectError(error.ProtocolVersion, ClientHello.parse(&old));
    const long = [_]u8{ 0x03, 0x03 } ++ [_]u8{0} ** 32 ++ [_]u8{ 0, 0, 2, 0x13, 0x01, 1, 0, 0, 7, 0, 43, 0, 9, 2, 3, 4 };
    try std.testing.expectError(error.DecodeError, ClientHello.parse(&long));
}

test "client hello version offers" {
    const pre = [_]u8{ 0x03, 0x03 } ++ [_]u8{0} ** 32 ++ [_]u8{ 0, 0, 2, 0xc0, 0x2b, 1, 0 };
    // No extensions, legacy 1.2: a 1.2 offer without EMS.
    const a = try ClientHello.parse(&pre);
    try std.testing.expect(a.tls12 and !a.tls13 and !a.ems);
    // supported_versions {0303} plus EMS and empty renegotiation_info.
    const b = pre ++ [_]u8{ 0, 16, 0, 43, 0, 3, 2, 3, 3, 0, 23, 0, 0, 0xff, 1, 0, 1, 0 };
    const hb = try ClientHello.parse(&b);
    try std.testing.expect(hb.tls12 and !hb.tls13 and hb.ems and hb.reneg.?.len == 0);
    // supported_versions without 1.2/1.3 overrides legacy_version.
    const c = pre ++ [_]u8{ 0, 7, 0, 43, 0, 3, 2, 3, 2 };
    try std.testing.expectError(error.ProtocolVersion, ClientHello.parse(&c));
    const bad_ems = pre ++ [_]u8{ 0, 5, 0, 23, 0, 1, 0 };
    try std.testing.expectError(error.DecodeError, ClientHello.parse(&bad_ems));
}

test "tls 1.2 message bounds" {
    var out: [max_peer_chain][]const u8 = undefined;
    try std.testing.expectEqual(0, (try parseCertificate12(&.{ 0, 0, 0 }, &out)).len);
    try std.testing.expectEqualSlices(u8, &.{0xaa}, (try parseCertificate12(&.{ 0, 0, 4, 0, 0, 1, 0xaa }, &out))[0]);
    try std.testing.expectError(error.DecodeError, parseCertificate12(&.{ 0, 0, 4, 0, 0, 2, 0xaa }, &out));
    try std.testing.expectError(error.DecodeError, parseClientKeyExchange(&.{ 2, 1 }));
    try std.testing.expectError(error.DecodeError, parseClientKeyExchange(&.{0}));
    try std.testing.expectEqualSlices(u8, &.{ 9, 9 }, try parseClientKeyExchange(&.{ 2, 9, 9 }));
}

test "certificate request encoding" {
    var buf: [64]u8 = undefined;
    var b: Builder = .{ .buf = &buf };
    try certificateRequest(&b, &.{ .ecdsa_secp256r1_sha256, .ed25519 });
    try std.testing.expectEqualSlices(u8, &.{ 13, 0, 0, 13, 0, 0, 10, 0, 13, 0, 6, 0, 4, 4, 3, 8, 7 }, b.written());
}

test "client certificate message bounds" {
    var out: [max_peer_chain][]const u8 = undefined;
    try std.testing.expectEqual(0, (try parseCertificate(&.{ 0, 0, 0, 0 }, &out)).len);
    const one = [_]u8{ 0, 0, 0, 7, 0, 0, 2, 0xaa, 0xbb, 0, 0 };
    const got = try parseCertificate(&one, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, got[0]);
    // Non-empty request context, overlong entry, trailing bytes, empty entry.
    try std.testing.expectError(error.IllegalParameter, parseCertificate(&.{ 1, 9, 0, 0, 0 }, &out));
    try std.testing.expectError(error.DecodeError, parseCertificate(&.{ 0, 0, 0, 7, 0, 0, 9, 0xaa, 0xbb, 0, 0 }, &out));
    try std.testing.expectError(error.DecodeError, parseCertificate(&.{ 0, 0, 0, 0, 1 }, &out));
    try std.testing.expectError(error.DecodeError, parseCertificate(&.{ 0, 0, 0, 5, 0, 0, 0, 0, 0 }, &out));
    try std.testing.expectError(error.DecodeError, parseCertificate(&.{ 0, 0xff, 0xff, 0xff }, &out));
    var nine: [4 + 9 * 6]u8 = undefined;
    nine[0..4].* = .{ 0, 0, 0, 9 * 6 };
    for (0..9) |i| nine[4 + i * 6 ..][0..6].* = .{ 0, 0, 1, 0x30, 0, 0 };
    try std.testing.expectError(error.BadCertificate, parseCertificate(&nine, &out));
}
