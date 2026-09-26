//! TLS 1.3 handshake message parsing and construction (RFC 8446 section 4).
//! Every length read from the peer is checked against the enclosing slice.
const std = @import("std");
const tls = std.crypto.tls;

pub const ParseError = error{ DecodeError, IllegalParameter, ProtocolVersion };

pub const ext = struct {
    pub const server_name: u16 = 0;
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
            // No extensions at all: a pre-1.3 hello.
            return error.ProtocolVersion;
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
                        if (std.mem.readInt(u16, list[i..][0..2], .big) == 0x0304) h.tls13 = true;
                    }
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
        if (!h.tls13 or legacy_version < 0x0301) return error.ProtocolVersion;
        if (comp.len != 1 or comp[0] != 0) return error.IllegalParameter;
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

/// Content covered by the server CertificateVerify signature (RFC 8446 4.4.3).
pub fn verifyContent(out: []u8, transcript_hash: []const u8) []const u8 {
    const ctx = "TLS 1.3, server CertificateVerify";
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
