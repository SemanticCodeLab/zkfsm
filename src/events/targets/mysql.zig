//! MySQL/MariaDB notification target (MinIO notify_mysql layout). Speaks the
//! client/server protocol directly: handshake v10, optional TLS, native and
//! caching_sha2 auth (RSA-OAEP full auth without TLS), and COM_QUERY.
//! Values are sent as hex literals, so no escaping depends on sql_mode.
const std = @import("std");
const target = @import("../target.zig");
const net = @import("../net.zig");

const log = std.log.scoped(.events_mysql);
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const keys = [_][]const u8{
    "dsn_string", "table", "format",   "max_open_connections", "queue_dir", "queue_limit", "comment",
    "host",       "port",  "username", "password",             "database",
};

/// Largest server packet accepted; one wire packet carries at most 16 MiB - 1.
const max_read = 4 << 20;
const max_packet = 0xff_ffff;

const cap = struct {
    const long_password: u32 = 1;
    const long_flag: u32 = 4;
    const connect_with_db: u32 = 8;
    const protocol_41: u32 = 0x200;
    const ssl: u32 = 0x800;
    const transactions: u32 = 0x2000;
    const secure_connection: u32 = 0x8000;
    const multi_results: u32 = 0x20000;
    const plugin_auth: u32 = 0x80000;
    const plugin_auth_lenenc: u32 = 0x200000;
};

pub const TlsMode = enum { off, preferred, skip_verify, verify };

pub const Config = struct {
    user: []const u8 = "",
    password: []const u8 = "",
    host: []const u8 = "127.0.0.1",
    port: u16 = 3306,
    dbname: []const u8 = "",
    tls: TlsMode = .off,
    timeout_ms: u32 = 5000,
};

pub const ParseError = error{ InvalidConfig, OutOfMemory };

/// Parses a Go-driver DSN `user:pass@tcp(host:port)/db?tls=..` onto `cfg`.
/// tls accepts true, false, skip-verify, preferred; unix sockets are rejected.
pub fn parseDsn(a: std.mem.Allocator, cfg: *Config, dsn: []const u8) ParseError!void {
    if (dsn.len == 0) return;
    const slash = std.mem.lastIndexOfScalar(u8, dsn, '/') orelse return error.InvalidConfig;
    var head = dsn[0..slash];
    var tail = dsn[slash + 1 ..];
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, tail, '?')) |q| {
        query = tail[q + 1 ..];
        tail = tail[0..q];
    }
    cfg.dbname = try pctDecode(a, tail);
    if (std.mem.lastIndexOfScalar(u8, head, '@')) |at| {
        const ui = head[0..at];
        head = head[at + 1 ..];
        if (std.mem.indexOfScalar(u8, ui, ':')) |c| {
            cfg.user = ui[0..c];
            cfg.password = ui[c + 1 ..];
        } else cfg.user = ui;
    }
    if (head.len > 0) {
        var addr = head;
        if (std.mem.indexOfScalar(u8, head, '(')) |p| {
            if (!std.mem.eql(u8, head[0..p], "tcp") or head[head.len - 1] != ')') return error.InvalidConfig;
            addr = head[p + 1 .. head.len - 1];
        }
        if (addr.len > 0) {
            const hp = net.splitHostPort(addr, 3306) catch return error.InvalidConfig;
            cfg.host = hp[0];
            cfg.port = hp[1];
        }
    }
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.InvalidConfig;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "tls")) {
            cfg.tls = if (std.mem.eql(u8, v, "true")) .verify else if (std.mem.eql(u8, v, "false")) .off else if (std.mem.eql(u8, v, "skip-verify")) .skip_verify else if (std.mem.eql(u8, v, "preferred")) .preferred else return error.InvalidConfig;
        } else if (std.mem.eql(u8, k, "timeout")) {
            const ts: target.Settings = .{ .kvs = &.{.{ .key = "t", .value = v }} };
            const ms = ts.durationMs("t", 5000) catch return error.InvalidConfig;
            cfg.timeout_ms = std.math.cast(u32, ms) orelse return error.InvalidConfig;
        }
    }
}

fn pctDecode(a: std.mem.Allocator, s: []const u8) ParseError![]const u8 {
    var out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (n += 1) {
        if (s[i] == '%') {
            if (i + 3 > s.len) return error.InvalidConfig;
            out[n] = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.InvalidConfig;
            i += 3;
        } else {
            out[n] = s[i];
            i += 1;
        }
    }
    return out[0..n];
}

/// `name` or `db.name`, each part [A-Za-z_][A-Za-z0-9_$]{0,63}.
pub fn validIdent(s: []const u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var parts: usize = 0;
    while (it.next()) |p| {
        parts += 1;
        if (parts > 2 or p.len == 0 or p.len > 64) return false;
        if (!(std.ascii.isAlphabetic(p[0]) or p[0] == '_')) return false;
        for (p) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '$')) return false;
    }
    return parts > 0;
}

/// mysql_native_password: SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw))).
pub fn nativeScramble(password: []const u8, scramble: *const [20]u8) [20]u8 {
    var h1: [20]u8 = undefined;
    Sha1.hash(password, &h1, .{});
    var h2: [20]u8 = undefined;
    Sha1.hash(&h1, &h2, .{});
    var s = Sha1.init(.{});
    s.update(scramble);
    s.update(&h2);
    var h3: [20]u8 = undefined;
    s.final(&h3);
    for (&h1, h3) |*a, b| a.* ^= b;
    return h1;
}

/// caching_sha2_password fast path: SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + scramble).
pub fn sha2Scramble(password: []const u8, scramble: *const [20]u8) [32]u8 {
    var h1: [32]u8 = undefined;
    Sha256.hash(password, &h1, .{});
    var h2: [32]u8 = undefined;
    Sha256.hash(&h1, &h2, .{});
    var s = Sha256.init(.{});
    s.update(&h2);
    s.update(scramble);
    var h3: [32]u8 = undefined;
    s.final(&h3);
    for (&h1, h3) |*a, b| a.* ^= b;
    return h1;
}

pub const RsaError = error{ BadKey, MessageTooLong, OutOfMemory };

const RsaMod = std.crypto.ff.Modulus(4096);

/// Bounded DER element: tag, contents, and the index after it.
fn derNext(b: []const u8, i: usize) RsaError!struct { tag: u8, body: []const u8, end: usize } {
    if (i + 2 > b.len) return error.BadKey;
    const tag = b[i];
    var len: usize = b[i + 1];
    var j = i + 2;
    if (len & 0x80 != 0) {
        const nb = len & 0x7f;
        if (nb == 0 or nb > 3 or j + nb > b.len) return error.BadKey;
        len = 0;
        for (b[j .. j + nb]) |x| len = (len << 8) | x;
        j += nb;
    }
    if (len > b.len - j) return error.BadKey;
    return .{ .tag = tag, .body = b[j .. j + len], .end = j + len };
}

const RsaPub = struct { n: []const u8, e: []const u8 };

/// Extracts modulus and exponent from an SPKI or PKCS#1 PEM public key.
/// `der` must hold the decoded bytes (≥ PEM length).
pub fn parsePublicPem(pem: []const u8, der: []u8) RsaError!RsaPub {
    const begin = std.mem.indexOf(u8, pem, "-----BEGIN ") orelse return error.BadKey;
    const hdr_end = std.mem.indexOfPos(u8, pem, begin + 11, "-----") orelse return error.BadKey;
    const body_start = hdr_end + 5;
    const end = std.mem.indexOfPos(u8, pem, body_start, "-----END ") orelse return error.BadKey;
    var n: usize = 0;
    var b64: [4096]u8 = undefined;
    for (pem[body_start..end]) |c| if (!std.ascii.isWhitespace(c)) {
        if (n >= b64.len) return error.BadKey;
        b64[n] = c;
        n += 1;
    };
    const dec = std.base64.standard.Decoder;
    const dl = dec.calcSizeForSlice(b64[0..n]) catch return error.BadKey;
    if (dl > der.len) return error.BadKey;
    dec.decode(der[0..dl], b64[0..n]) catch return error.BadKey;
    var key: []const u8 = der[0..dl];
    const top = try derNext(key, 0);
    if (top.tag != 0x30) return error.BadKey;
    const first = try derNext(top.body, 0);
    if (first.tag == 0x30) {
        // SubjectPublicKeyInfo: AlgorithmIdentifier, then BIT STRING with RSAPublicKey.
        const bits = try derNext(top.body, first.end);
        if (bits.tag != 0x03 or bits.body.len < 1 or bits.body[0] != 0) return error.BadKey;
        key = bits.body[1..];
    }
    const seq = try derNext(key, 0);
    if (seq.tag != 0x30) return error.BadKey;
    const ni = try derNext(seq.body, 0);
    const ei = try derNext(seq.body, ni.end);
    if (ni.tag != 0x02 or ei.tag != 0x02) return error.BadKey;
    const nz = std.mem.indexOfNone(u8, ni.body, "\x00") orelse return error.BadKey;
    const ez = std.mem.indexOfNone(u8, ei.body, "\x00") orelse return error.BadKey;
    const mod = ni.body[nz..];
    if (mod.len < 64 or mod.len > 512 or ei.body.len - ez > 8) return error.BadKey;
    return .{ .n = mod, .e = ei.body[ez..] };
}

fn mgf1Xor(out: []u8, seed: []const u8) void {
    var counter: u32 = 0;
    var i: usize = 0;
    while (i < out.len) : (counter += 1) {
        var h = Sha1.init(.{});
        h.update(seed);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        h.update(&c);
        var d: [20]u8 = undefined;
        h.final(&d);
        for (d) |x| {
            if (i >= out.len) break;
            out[i] ^= x;
            i += 1;
        }
    }
}

/// RSAES-OAEP (SHA-1, MGF1-SHA-1, empty label) as MySQL's RSA_PKCS1_OAEP_PADDING.
/// Writes `k = len(n)` bytes into `out` and returns them.
pub fn rsaOaepEncrypt(key: RsaPub, msg: []const u8, seed: *const [20]u8, out: []u8) RsaError![]u8 {
    const k = key.n.len;
    if (out.len < k) return error.BadKey;
    if (msg.len + 2 * 20 + 2 > k) return error.MessageTooLong;
    var em: [512]u8 = undefined;
    const e = em[0..k];
    @memset(e, 0);
    const db = e[21..];
    Sha1.hash("", db[0..20], .{});
    db[db.len - msg.len - 1] = 1;
    @memcpy(db[db.len - msg.len ..], msg);
    @memcpy(e[1..21], seed);
    mgf1Xor(db, seed);
    mgf1Xor(e[1..21], db);
    const m = RsaMod.fromBytes(key.n, .big) catch return error.BadKey;
    const x = RsaMod.Fe.fromBytes(m, e, .big) catch return error.BadKey;
    const y = m.powWithEncodedExponent(x, key.e, .big) catch return error.BadKey;
    y.toBytes(out[0..k], .big) catch return error.BadKey;
    return out[0..k];
}

/// RFC 3339 UTC time to a DATETIME literal body "YYYY-MM-DD HH:MM:SS".
/// Returns the offset ("+HH:MM", empty for Z) or null when malformed.
pub fn datetime(t: []const u8, out: *[19]u8) ?[]const u8 {
    if (t.len < 20) return null;
    const pat = "dddd-dd-ddTdd:dd:dd";
    for (pat, 0..) |p, i| switch (p) {
        'd' => if (!std.ascii.isDigit(t[i])) return null,
        'T' => if (t[i] != 'T' and t[i] != 't' and t[i] != ' ') return null,
        else => if (t[i] != p) return null,
    };
    @memcpy(out, t[0..19]);
    out[10] = ' ';
    var i: usize = 19;
    if (t[i] == '.') {
        i += 1;
        while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    }
    const z = t[i..];
    if (z.len == 1 and (z[0] == 'Z' or z[0] == 'z')) return "";
    if (z.len == 6 and (z[0] == '+' or z[0] == '-') and std.ascii.isDigit(z[1]) and std.ascii.isDigit(z[2]) and z[3] == ':' and std.ascii.isDigit(z[4]) and std.ascii.isDigit(z[5])) return z;
    return null;
}

/// Net/Protocol drop the connection (Unreachable); Server keeps it (Rejected).
const E = error{ Net, Protocol, Server, TooLarge, OutOfMemory };

const Cur = struct {
    b: []const u8,
    i: usize = 0,

    fn take(c: *Cur, n: usize) E![]const u8 {
        if (n > c.b.len - c.i) return error.Protocol;
        defer c.i += n;
        return c.b[c.i..][0..n];
    }
    fn byte(c: *Cur) E!u8 {
        return (try c.take(1))[0];
    }
    fn int(c: *Cur, comptime T: type) E!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return std.mem.readInt(T, (try c.take(n))[0..n], .little);
    }
    fn cstr(c: *Cur) E![]const u8 {
        const end = std.mem.indexOfScalarPos(u8, c.b, c.i, 0) orelse return error.Protocol;
        defer c.i = end + 1;
        return c.b[c.i..end];
    }
    fn rest(c: *Cur) []const u8 {
        defer c.i = c.b.len;
        return c.b[c.i..];
    }
    fn lenenc(c: *Cur) E!?u64 {
        const f = try c.byte();
        return switch (f) {
            0xfb => null,
            0xfc => try c.int(u16),
            0xfd => try c.int(u24),
            0xfe => try c.int(u64),
            0xff => error.Protocol,
            else => f,
        };
    }
};

const My = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    cfg: Config,
    format: target.Format,
    table: []const u8,
    conn: ?*net.Conn = null,
    tls_on: bool = false,
    seq: u8 = 0,
    in: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,

    fn drop(p: *My) void {
        if (p.conn) |c| c.close();
        p.conn = null;
        p.tls_on = false;
    }

    fn deinit(p: *My) void {
        if (p.conn != null) {
            p.seq = 0;
            p.writePacket(&.{0x01}) catch {};
        }
        p.drop();
        p.in.deinit(p.gpa);
        p.out.deinit(p.gpa);
        const gpa = p.gpa;
        p.arena.deinit();
        gpa.destroy(p);
    }

    fn writePacket(p: *My, payload: []const u8) E!void {
        if (payload.len >= max_packet) return error.TooLarge;
        const c = p.conn orelse return error.Net;
        var h: [4]u8 = undefined;
        std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .little);
        h[3] = p.seq;
        p.seq +%= 1;
        c.writer().writeAll(&h) catch return error.Net;
        c.writer().writeAll(payload) catch return error.Net;
        c.flush() catch return error.Net;
    }

    fn readPacket(p: *My) E![]const u8 {
        const r = (p.conn orelse return error.Net).reader();
        var h: [4]u8 = undefined;
        r.readSliceAll(&h) catch return error.Net;
        const n = std.mem.readInt(u24, h[0..3], .little);
        if (n > max_read) return error.Protocol;
        p.seq = h[3] +% 1;
        try p.in.resize(p.gpa, n);
        r.readSliceAll(p.in.items) catch return error.Net;
        return p.in.items;
    }

    fn logErr(p: *My, pkt: []const u8) void {
        var c: Cur = .{ .b = pkt, .i = 1 };
        const code = c.int(u16) catch 0;
        var msg = c.rest();
        if (msg.len >= 6 and msg[0] == '#') msg = msg[6..];
        log.warn("mysql {s}: {d} {s}", .{ p.cfg.host, code, msg });
    }

    fn connect(p: *My) E!void {
        const cfg = &p.cfg;
        p.conn = net.dial(p.gpa, cfg.host, cfg.port, .{ .connect_timeout_ms = cfg.timeout_ms }) catch |e|
            return if (e == error.OutOfMemory) error.OutOfMemory else error.Net;
        errdefer p.drop();
        const hs = try p.readPacket();
        if (hs.len > 0 and hs[0] == 0xff) {
            p.logErr(hs);
            return error.Server;
        }
        var c: Cur = .{ .b = hs };
        if (try c.byte() != 10) return error.Protocol;
        _ = try c.cstr();
        _ = try c.int(u32);
        var scramble: [20]u8 = undefined;
        @memcpy(scramble[0..8], try c.take(8));
        _ = try c.byte();
        var caps: u32 = try c.int(u16);
        var plugin: []const u8 = "mysql_native_password";
        var plugin_buf: [64]u8 = undefined;
        if (c.i < c.b.len) {
            _ = try c.take(3);
            caps |= @as(u32, try c.int(u16)) << 16;
            const alen = try c.byte();
            _ = try c.take(10);
            const l2 = @max(13, @as(usize, alen) -| 8);
            const part2 = try c.take(@min(l2, c.b.len - c.i));
            if (part2.len < 12) return error.Protocol;
            @memcpy(scramble[8..20], part2[0..12]);
            if (caps & cap.plugin_auth != 0 and c.i < c.b.len) {
                const r = c.rest();
                const name = r[0 .. std.mem.indexOfScalar(u8, r, 0) orelse r.len];
                if (name.len > plugin_buf.len) return error.Protocol;
                @memcpy(plugin_buf[0..name.len], name);
                plugin = plugin_buf[0..name.len];
            }
        } else return error.Protocol;
        if (caps & cap.protocol_41 == 0 or caps & cap.secure_connection == 0) return error.Protocol;

        var mine: u32 = cap.long_password | cap.long_flag | cap.protocol_41 | cap.transactions |
            cap.secure_connection | cap.multi_results | cap.plugin_auth | cap.plugin_auth_lenenc;
        if (cfg.dbname.len > 0) mine |= cap.connect_with_db;
        mine &= caps | cap.protocol_41 | cap.secure_connection;
        if (cfg.tls != .off) {
            if (caps & cap.ssl != 0) {
                mine |= cap.ssl;
                var req: [32]u8 = @splat(0);
                std.mem.writeInt(u32, req[0..4], mine, .little);
                std.mem.writeInt(u32, req[4..8], 1 << 24, .little);
                req[8] = 45;
                try p.writePacket(&req);
                p.conn.?.startTls(cfg.host, .{ .skip_verify = cfg.tls != .verify }) catch |e|
                    return if (e == error.OutOfMemory) error.OutOfMemory else error.Net;
                p.tls_on = true;
            } else if (cfg.tls != .preferred) {
                log.warn("mysql {s}: server does not offer TLS", .{cfg.host});
                return error.Server;
            }
        }

        p.out.clearRetainingCapacity();
        const g = p.gpa;
        try p.out.appendSlice(g, std.mem.asBytes(&std.mem.nativeToLittle(u32, mine)));
        try p.out.appendSlice(g, std.mem.asBytes(&std.mem.nativeToLittle(u32, 1 << 24)));
        try p.out.append(g, 45);
        try p.out.appendNTimes(g, 0, 23);
        try p.out.appendSlice(g, cfg.user);
        try p.out.append(g, 0);
        var ab: [32]u8 = undefined;
        const auth = authData(plugin, cfg.password, &scramble, &ab);
        try p.out.append(g, @intCast(auth.len));
        try p.out.appendSlice(g, auth);
        if (mine & cap.connect_with_db != 0) {
            try p.out.appendSlice(g, cfg.dbname);
            try p.out.append(g, 0);
        }
        try p.out.appendSlice(g, if (isKnown(plugin)) plugin else "mysql_native_password");
        try p.out.append(g, 0);
        try p.writePacket(p.out.items);
        try p.authLoop(plugin, &scramble);
        try p.exec(try p.createSql());
    }

    fn isKnown(plugin: []const u8) bool {
        return std.mem.eql(u8, plugin, "mysql_native_password") or std.mem.eql(u8, plugin, "caching_sha2_password");
    }

    fn authData(plugin: []const u8, password: []const u8, scramble: *const [20]u8, buf: *[32]u8) []const u8 {
        if (password.len == 0) return "";
        if (std.mem.eql(u8, plugin, "caching_sha2_password")) {
            buf.* = sha2Scramble(password, scramble);
            return buf[0..32];
        }
        buf[0..20].* = nativeScramble(password, scramble);
        return buf[0..20];
    }

    fn authLoop(p: *My, first_plugin: []const u8, first_scramble: *const [20]u8) E!void {
        var plugin_buf: [64]u8 = undefined;
        var plugin = if (isKnown(first_plugin)) first_plugin else "mysql_native_password";
        var scramble = first_scramble.*;
        var awaiting_key = false;
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            const pkt = try p.readPacket();
            if (pkt.len == 0) return error.Protocol;
            switch (pkt[0]) {
                0x00 => return,
                0xff => {
                    p.logErr(pkt);
                    return error.Server;
                },
                0xfe => {
                    var c: Cur = .{ .b = pkt, .i = 1 };
                    const name = try c.cstr();
                    const data = c.rest();
                    if (!isKnown(name) or name.len > plugin_buf.len) {
                        log.warn("mysql {s}: unsupported auth plugin {s}", .{ p.cfg.host, name });
                        return error.Server;
                    }
                    if (data.len < 20) return error.Protocol;
                    @memcpy(plugin_buf[0..name.len], name);
                    plugin = plugin_buf[0..name.len];
                    scramble = data[0..20].*;
                    var ab: [32]u8 = undefined;
                    try p.writePacket(authData(plugin, p.cfg.password, &scramble, &ab));
                },
                0x01 => {
                    const data = pkt[1..];
                    if (!std.mem.eql(u8, plugin, "caching_sha2_password")) return error.Protocol;
                    if (awaiting_key) {
                        try p.sendRsaPassword(data, &scramble);
                        awaiting_key = false;
                    } else if (data.len == 1 and data[0] == 3) {
                        continue;
                    } else if (data.len == 1 and data[0] == 4) {
                        if (p.tls_on) {
                            const pw = try p.gpa.alloc(u8, p.cfg.password.len + 1);
                            defer p.gpa.free(pw);
                            @memcpy(pw[0..p.cfg.password.len], p.cfg.password);
                            pw[pw.len - 1] = 0;
                            try p.writePacket(pw);
                        } else {
                            try p.writePacket(&.{0x02});
                            awaiting_key = true;
                        }
                    } else return error.Protocol;
                },
                else => return error.Protocol,
            }
        }
        return error.Protocol;
    }

    fn sendRsaPassword(p: *My, pem: []const u8, scramble: *const [20]u8) E!void {
        if (pem.len > 4096) return error.Protocol;
        var der: [4096]u8 = undefined;
        const key = parsePublicPem(pem, &der) catch return error.Protocol;
        var msg: [512]u8 = undefined;
        const n = p.cfg.password.len + 1;
        if (n > msg.len) return error.TooLarge;
        @memcpy(msg[0 .. n - 1], p.cfg.password);
        msg[n - 1] = 0;
        for (msg[0..n], 0..) |*b, i| b.* ^= scramble[i % 20];
        var seed: [20]u8 = undefined;
        std.crypto.random.bytes(&seed);
        var out: [512]u8 = undefined;
        const ct = rsaOaepEncrypt(key, msg[0..n], &seed, &out) catch |e| return switch (e) {
            error.MessageTooLong => error.TooLarge,
            else => error.Protocol,
        };
        try p.writePacket(ct);
    }

    fn createSql(p: *My) E![]const u8 {
        p.out.clearRetainingCapacity();
        const sql = switch (p.format) {
            .namespace => "CREATE TABLE IF NOT EXISTS {s} (key_name VARCHAR(3072) NOT NULL, key_hash CHAR(64) GENERATED ALWAYS AS (SHA2(key_name, 256)) STORED NOT NULL PRIMARY KEY, value JSON) CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC",
            .access => "CREATE TABLE IF NOT EXISTS {s} (event_time DATETIME NOT NULL, event_data JSON)",
        };
        var it = std.mem.splitSequence(u8, sql, "{s}");
        try p.out.appendSlice(p.gpa, it.first());
        try p.out.appendSlice(p.gpa, p.table);
        try p.out.appendSlice(p.gpa, it.rest());
        return p.out.items;
    }

    fn appendHexText(p: *My, v: []const u8) E!void {
        try p.out.appendSlice(p.gpa, "CONVERT(X'");
        const hex = "0123456789ABCDEF";
        try p.out.ensureUnusedCapacity(p.gpa, v.len * 2 + 32);
        for (v) |b| p.out.appendSliceAssumeCapacity(&.{ hex[b >> 4], hex[b & 15] });
        try p.out.appendSlice(p.gpa, "' USING utf8mb4)");
    }

    fn put(p: *My, s: []const u8) E!void {
        try p.out.appendSlice(p.gpa, s);
    }

    /// Runs COM_QUERY; `first` receives the first column of the first row.
    fn query(p: *My, sql: []const u8, first: ?*?[]u8) E!void {
        p.seq = 0;
        var cmd = try p.gpa.alloc(u8, sql.len + 1);
        defer p.gpa.free(cmd);
        cmd[0] = 0x03;
        @memcpy(cmd[1..], sql);
        try p.writePacket(cmd);
        var pkt = try p.readPacket();
        if (pkt.len == 0) return error.Protocol;
        if (pkt[0] == 0x00) return;
        if (pkt[0] == 0xff) {
            p.logErr(pkt);
            return error.Server;
        }
        // Result set: column definitions, EOF, rows, EOF.
        var c: Cur = .{ .b = pkt };
        const ncols = (try c.lenenc()) orelse return error.Protocol;
        if (ncols == 0 or ncols > 4096) return error.Protocol;
        var eofs: u8 = 0;
        while (eofs < 2) {
            pkt = try p.readPacket();
            if (pkt.len == 0) return error.Protocol;
            if (pkt[0] == 0xfe and pkt.len < 9) {
                eofs += 1;
                continue;
            }
            if (pkt[0] == 0xff) {
                p.logErr(pkt);
                return error.Server;
            }
            if (eofs == 1) if (first) |f| if (f.* == null) {
                var rc: Cur = .{ .b = pkt };
                if (try rc.lenenc()) |n| {
                    if (n > rc.b.len - rc.i) return error.Protocol;
                    f.* = try p.gpa.dupe(u8, try rc.take(@intCast(n)));
                }
            };
        }
    }

    fn exec(p: *My, sql: []const u8) E!void {
        return p.query(sql, null);
    }

    fn deliver(p: *My, msg: *const target.Message) E!void {
        if (p.conn == null) try p.connect();
        p.out.clearRetainingCapacity();
        switch (p.format) {
            .namespace => if (msg.removed) {
                try p.put("DELETE FROM ");
                try p.put(p.table);
                try p.put(" WHERE key_name = ");
                try p.appendHexText(msg.key);
            } else {
                try p.put("INSERT INTO ");
                try p.put(p.table);
                try p.put(" (key_name, value) VALUES (");
                try p.appendHexText(msg.key);
                try p.put(", ");
                try p.appendHexText(msg.body);
                try p.put(") ON DUPLICATE KEY UPDATE value=VALUES(value)");
            },
            .access => {
                try p.put("INSERT INTO ");
                try p.put(p.table);
                try p.put(" (event_time, event_data) VALUES (");
                var dt: [19]u8 = undefined;
                if (msg.event_time.len == 0) {
                    try p.put("UTC_TIMESTAMP()");
                } else if (datetime(msg.event_time, &dt)) |off| {
                    // Only digits and fixed separators reach the literal.
                    if (off.len == 0) {
                        try p.put("'");
                        try p.put(&dt);
                        try p.put("'");
                    } else {
                        try p.put("CONVERT_TZ('");
                        try p.put(&dt);
                        try p.put("', '");
                        try p.put(off);
                        try p.put("', '+00:00')");
                    }
                } else return error.TooLarge;
                try p.put(", ");
                try p.appendHexText(msg.body);
                try p.put(")");
            },
        }
        if (p.out.items.len + 1 >= max_packet) return error.TooLarge;
        const sql = try p.gpa.dupe(u8, p.out.items);
        defer p.gpa.free(sql);
        try p.exec(sql);
    }
};

fn sendFn(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
    const p: *My = @ptrCast(@alignCast(ctx));
    p.deliver(msg) catch |e| switch (e) {
        error.Server, error.TooLarge => return error.Rejected,
        error.OutOfMemory => {
            p.drop();
            return error.OutOfMemory;
        },
        error.Net, error.Protocol => {
            p.drop();
            return error.Unreachable;
        },
    };
}

fn deinitFn(ctx: *anyopaque) void {
    const p: *My = @ptrCast(@alignCast(ctx));
    p.deinit();
}

const vtable: target.Client.VTable = .{ .send = sendFn, .deinit = deinitFn };

/// Validates settings and builds a client; no I/O until the first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const p = try gpa.create(My);
    p.* = .{ .gpa = gpa, .arena = .init(gpa), .cfg = .{}, .format = .namespace, .table = "" };
    errdefer {
        p.arena.deinit();
        gpa.destroy(p);
    }
    const a = p.arena.allocator();
    const cfg = &p.cfg;
    if (s.get("host").len > 0) cfg.host = s.get("host");
    if (s.get("port").len > 0) cfg.port = std.fmt.parseInt(u16, s.get("port"), 10) catch return error.InvalidConfig;
    cfg.user = s.get("username");
    cfg.password = s.get("password");
    cfg.dbname = s.get("database");
    try parseDsn(a, cfg, s.get("dsn_string"));
    cfg.host = try a.dupe(u8, cfg.host);
    cfg.user = try a.dupe(u8, cfg.user);
    cfg.password = try a.dupe(u8, cfg.password);
    cfg.dbname = try a.dupe(u8, cfg.dbname);
    for ([_][]const u8{ cfg.user, cfg.dbname }) |v|
        if (std.mem.indexOfScalar(u8, v, 0) != null) return error.InvalidConfig;
    if (cfg.host.len == 0 or cfg.user.len == 0 or cfg.password.len > 255) return error.InvalidConfig;
    p.format = try target.Format.parse(s.get("format"));
    _ = try s.int(u32, "max_open_connections", 2);
    _ = try s.int(u64, "queue_limit", 0);
    if (!validIdent(s.get("table"))) return error.InvalidConfig;
    p.table = try a.dupe(u8, s.get("table"));
    return .{ .ctx = p, .vtable = &vtable };
}

// ---- tests ----

const testing = std.testing;

test "dsn parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var c: Config = .{};
    try parseDsn(arena.allocator(), &c, "root:p@ss:w@tcp(db.local:3307)/events?tls=skip-verify&timeout=3s");
    try testing.expectEqualStrings("root", c.user);
    try testing.expectEqualStrings("p@ss:w", c.password);
    try testing.expectEqualStrings("db.local", c.host);
    try testing.expectEqual(@as(u16, 3307), c.port);
    try testing.expectEqualStrings("events", c.dbname);
    try testing.expectEqual(TlsMode.skip_verify, c.tls);
    try testing.expectEqual(@as(u32, 3000), c.timeout_ms);
    var d: Config = .{};
    try parseDsn(arena.allocator(), &d, "u@/db");
    try testing.expectEqualStrings("127.0.0.1", d.host);
    try testing.expectEqual(@as(u16, 3306), d.port);
    try testing.expectError(error.InvalidConfig, parseDsn(arena.allocator(), &d, "u@unix(/s)/db"));
    try testing.expectError(error.InvalidConfig, parseDsn(arena.allocator(), &d, "u@tcp(h)/db?tls=custom"));
    try testing.expectError(error.InvalidConfig, parseDsn(arena.allocator(), &d, "nodb"));
}

test "identifier validation and create" {
    try testing.expect(validIdent("events"));
    try testing.expect(validIdent("db.ev$1"));
    try testing.expect(!validIdent("ev`; drop"));
    try testing.expect(!validIdent(""));
    const bad = [_]target.Kv{ .{ .key = "dsn_string", .value = "u:p@tcp(h:1)/d" }, .{ .key = "table", .value = "a b" } };
    try testing.expectError(error.InvalidConfig, create(testing.allocator, .{ .kvs = &bad }));
    const ok = [_]target.Kv{ .{ .key = "host", .value = "h" }, .{ .key = "username", .value = "u" }, .{ .key = "table", .value = "t" } };
    const c = try create(testing.allocator, .{ .kvs = &ok });
    c.deinit();
}

test "native_password and caching_sha2 scrambles" {
    var s: [20]u8 = undefined;
    for (&s, 1..) |*b, i| b.* = @intCast(i);
    // Reference values from an independent implementation (Python hashlib).
    try testing.expectEqualStrings("b32bb3a583e1340c0a1108d58b1be49781ad8c2f", &std.fmt.bytesToHex(nativeScramble("secret", &s), .lower));
    try testing.expectEqualStrings("746ebe205d56a0707acb3e796e834e0dd7b1d61743b26bd5202c7a623230c7c9", &std.fmt.bytesToHex(sha2Scramble("secret", &s), .lower));
}

test "datetime conversion" {
    var dt: [19]u8 = undefined;
    try testing.expectEqualStrings("", datetime("2024-01-02T03:04:05.123Z", &dt).?);
    try testing.expectEqualStrings("2024-01-02 03:04:05", &dt);
    try testing.expectEqualStrings("+05:30", datetime("2024-01-02T03:04:05+05:30", &dt).?);
    try testing.expect(datetime("2024-01-02T03:04:05'); drop", &dt) == null);
    try testing.expect(datetime("short", &dt) == null);
}

const test_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDayYcZYkrry3crMEVOAL2PyIn7
    \\AXngqet/K4xL3McO5ZYKMTR3RXCG7OaOnpt7+oAB19pf+MuvBZCm5n9BWcLjdRLs
    \\Uh60LuSB2SWx5ylosOuZlqC8XW25doU0PL6NIvi0d7gAeI7Ig+uEJ+LUrs8HGRrI
    \\S5MLwZkqiA/3/Lgb6QIDAQAB
    \\-----END PUBLIC KEY-----
    \\
;
const test_d_hex = "b968fddfaa27d9e9a4c4e9f461a548fff7afcf12b2298d767060045629f45b907ef5863b73345aa74d4e19e119dd182db0e22f4313c1f141e3133dd4ec19d8887e0cb3e9cc471464828436fe73440500849dcb414c12b1aa6f8cdee68b072b891b191a40067f429698d545cf27417ae67672945c534b03b16ac015759c739a81";

/// Test-only RSA-OAEP decryption with the throwaway key above.
fn testOaepDecrypt(ct: []const u8, out: []u8) ![]u8 {
    var der: [1024]u8 = undefined;
    const key = try parsePublicPem(test_pem, &der);
    var d: [128]u8 = undefined;
    _ = try std.fmt.hexToBytes(&d, test_d_hex);
    const m = try RsaMod.fromBytes(key.n, .big);
    const x = try RsaMod.Fe.fromBytes(m, ct, .big);
    const y = try m.powWithEncodedExponent(x, &d, .big);
    var em: [128]u8 = undefined;
    try y.toBytes(&em, .big);
    if (em[0] != 0) return error.BadPadding;
    mgf1Xor(em[1..21], em[21..]);
    mgf1Xor(em[21..], em[1..21]);
    var lh: [20]u8 = undefined;
    Sha1.hash("", &lh, .{});
    if (!std.mem.eql(u8, em[21..41], &lh)) return error.BadPadding;
    const one = std.mem.indexOfNonePos(u8, &em, 41, "\x00") orelse return error.BadPadding;
    if (em[one] != 1) return error.BadPadding;
    const msg = em[one + 1 ..];
    @memcpy(out[0..msg.len], msg);
    return out[0..msg.len];
}

test "rsa oaep encrypt round trip and pem parsing" {
    var der: [1024]u8 = undefined;
    const key = try parsePublicPem(test_pem, &der);
    try testing.expectEqual(@as(usize, 128), key.n.len);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 1 }, key.e);
    var seed: [20]u8 = @splat(7);
    var ct: [512]u8 = undefined;
    const c = try rsaOaepEncrypt(key, "hello\x00", &seed, &ct);
    var pt: [128]u8 = undefined;
    try testing.expectEqualStrings("hello\x00", try testOaepDecrypt(c, &pt));
    var big: [100]u8 = @splat(1);
    try testing.expectError(error.MessageTooLong, rsaOaepEncrypt(key, &big, &seed, &ct));
    try testing.expectError(error.BadKey, parsePublicPem("-----BEGIN PUBLIC KEY-----\nMAMCAQ==\n-----END PUBLIC KEY-----", &der));
    try testing.expectError(error.BadKey, parsePublicPem("junk", &der));
}

/// A listener speaking just enough server protocol; records COM_QUERY text.
const FakeMy = struct {
    srv: std.net.Server,
    sha2_full: bool = false,
    fail_on: []const u8 = "",
    queries: std.ArrayList(u8) = .empty,
    auth_ok: bool = false,

    fn pkt(w: *std.Io.Writer, seq: u8, body: []const u8) !void {
        var h: [4]u8 = undefined;
        std.mem.writeInt(u24, h[0..3], @intCast(body.len), .little);
        h[3] = seq;
        try w.writeAll(&h);
        try w.writeAll(body);
        try w.flush();
    }

    fn read(r: *std.Io.Reader) !struct { u8, []u8 } {
        var h: [4]u8 = undefined;
        try r.readSliceAll(&h);
        return .{ h[3], try r.take(std.mem.readInt(u24, h[0..3], .little)) };
    }

    fn run(f: *FakeMy) void {
        f.serve() catch {};
    }

    fn serve(f: *FakeMy) !void {
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [8192]u8 = undefined;
        var wb: [8192]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const r = sr.interface();
        const w = &sw.interface;
        var scramble: [20]u8 = undefined;
        for (&scramble, 1..) |*b, i| b.* = @intCast(i);
        const plugin = if (f.sha2_full) "caching_sha2_password" else "mysql_native_password";
        var hs: [256]u8 = undefined;
        var n: usize = 0;
        const parts = [_][]const u8{ "\x0a8.0.36\x00", "\x01\x00\x00\x00", scramble[0..8], "\x00", "\xff\xff", "\x2d", "\x02\x00", "\xff\x00", "\x15", "\x00" ** 10, scramble[8..20], "\x00", plugin, "\x00" };
        for (parts) |s| {
            @memcpy(hs[n..][0..s.len], s);
            n += s.len;
        }
        try pkt(w, 0, hs[0..n]);
        _, const resp = try read(r);
        const user_end = std.mem.indexOfScalarPos(u8, resp, 32, 0).?;
        const alen = resp[user_end + 1];
        const auth = resp[user_end + 2 ..][0..alen];
        if (f.sha2_full) {
            try pkt(w, 2, "\x01\x04");
            _, const req = try read(r);
            if (!std.mem.eql(u8, req, "\x02")) return;
            var key: [300]u8 = undefined;
            key[0] = 1;
            @memcpy(key[1..][0..test_pem.len], test_pem);
            try pkt(w, 4, key[0 .. test_pem.len + 1]);
            _, const ct = try read(r);
            var pt: [128]u8 = undefined;
            const plain = try testOaepDecrypt(ct, &pt);
            for (plain, 0..) |*b, i| b.* ^= scramble[i % 20];
            f.auth_ok = std.mem.eql(u8, plain, "pw\x00");
        } else {
            f.auth_ok = std.mem.eql(u8, auth, &nativeScramble("pw", &scramble));
        }
        if (!f.auth_ok) {
            try pkt(w, 2, "\xff\x15\x04#28000Access denied");
            return;
        }
        try pkt(w, 2, "\x00\x00\x00\x02\x00\x00\x00");
        while (true) {
            _, const q = read(r) catch return;
            if (q.len == 0 or q[0] == 0x01) return;
            try f.queries.appendSlice(testing.allocator, q[1..]);
            try f.queries.append(testing.allocator, '\n');
            if (f.fail_on.len > 0 and std.mem.indexOf(u8, q, f.fail_on) != null) {
                try pkt(w, 1, "\xff\x0e\x0f#22032Invalid JSON text");
            } else try pkt(w, 1, "\x00\x01\x00\x02\x00\x00\x00");
        }
    }
};

fn fakeClient(f: *FakeMy, extra: []const target.Kv) !target.Client {
    var buf: [96]u8 = undefined;
    const dsn = try std.fmt.bufPrint(&buf, "u:pw@tcp(127.0.0.1:{d})/db", .{f.srv.listen_address.getPort()});
    var kvs: [8]target.Kv = undefined;
    kvs[0] = .{ .key = "dsn_string", .value = dsn };
    for (extra, 1..) |kv, i| kvs[i] = kv;
    return create(testing.allocator, .{ .kvs = kvs[0 .. extra.len + 1] });
}

test "fake server namespace upsert and delete (native_password)" {
    var f: FakeMy = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}) };
    defer f.srv.deinit();
    defer f.queries.deinit(testing.allocator);
    const th = try std.Thread.spawn(.{}, FakeMy.run, .{&f});
    const c = try fakeClient(&f, &.{.{ .key = "table", .value = "ev" }});
    const r1 = c.send(&.{ .key = "b/o'", .body = "{}" });
    const r2 = c.send(&.{ .key = "b/o'", .body = "", .removed = true });
    c.deinit();
    th.join();
    try r1;
    try r2;
    try testing.expect(f.auth_ok);
    try testing.expectEqualStrings(
        "CREATE TABLE IF NOT EXISTS ev (key_name VARCHAR(3072) NOT NULL, key_hash CHAR(64) GENERATED ALWAYS AS (SHA2(key_name, 256)) STORED NOT NULL PRIMARY KEY, value JSON) CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = DYNAMIC\n" ++
            "INSERT INTO ev (key_name, value) VALUES (CONVERT(X'622F6F27' USING utf8mb4), CONVERT(X'7B7D' USING utf8mb4)) ON DUPLICATE KEY UPDATE value=VALUES(value)\n" ++
            "DELETE FROM ev WHERE key_name = CONVERT(X'622F6F27' USING utf8mb4)\n",
        f.queries.items,
    );
}

test "fake server access insert (caching_sha2 full auth over RSA) and rejected error" {
    var f: FakeMy = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .sha2_full = true, .fail_on = "X'78'" };
    defer f.srv.deinit();
    defer f.queries.deinit(testing.allocator);
    const th = try std.Thread.spawn(.{}, FakeMy.run, .{&f});
    const c = try fakeClient(&f, &.{ .{ .key = "table", .value = "audit" }, .{ .key = "format", .value = "access" } });
    const r1 = c.send(&.{ .body = "{}", .event_time = "2024-01-02T03:04:05Z" });
    const r2 = c.send(&.{ .body = "x", .event_time = "2024-01-02T03:04:05Z" });
    const r3 = c.send(&.{ .body = "{}", .event_time = "bad'time" });
    c.deinit();
    th.join();
    try r1;
    try testing.expectError(error.Rejected, r2);
    try testing.expectError(error.Rejected, r3);
    try testing.expect(f.auth_ok);
    try testing.expectEqualStrings(
        "CREATE TABLE IF NOT EXISTS audit (event_time DATETIME NOT NULL, event_data JSON)\n" ++
            "INSERT INTO audit (event_time, event_data) VALUES ('2024-01-02 03:04:05', CONVERT(X'7B7D' USING utf8mb4))\n" ++
            "INSERT INTO audit (event_time, event_data) VALUES ('2024-01-02 03:04:05', CONVERT(X'78' USING utf8mb4))\n",
        f.queries.items,
    );
}

test "unreachable server maps to Unreachable" {
    const kvs = [_]target.Kv{ .{ .key = "dsn_string", .value = "u:p@tcp(127.0.0.1:1)/d" }, .{ .key = "table", .value = "t" } };
    const c = try create(testing.allocator, .{ .kvs = &kvs });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .key = "a", .body = "{}" }));
}

test "events live mysql" {
    const gpa = testing.allocator;
    const dsn = std.process.getEnvVarOwned(gpa, "ZKFSM_TEST_MYSQL") catch return error.SkipZigTest;
    defer gpa.free(dsn);
    var rnd: [4]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);
    var names: [2][40]u8 = undefined;
    const ns_t = try std.fmt.bufPrint(&names[0], "zkfsm_live_ns_{s}", .{hex});
    const ac_t = try std.fmt.bufPrint(&names[1], "zkfsm_live_ac_{s}", .{hex});
    var sql: [256]u8 = undefined;

    const ns = try create(gpa, .{ .kvs = &.{ .{ .key = "dsn_string", .value = dsn }, .{ .key = "table", .value = ns_t } } });
    defer ns.deinit();
    const np: *My = @ptrCast(@alignCast(ns.ctx));
    try ns.send(&.{ .key = "bkt/obj", .body = "{\"Records\":[{\"n\":1}]}" });
    try ns.send(&.{ .key = "bkt/obj", .body = "{\"Records\":[{\"n\":2}]}" });
    var v: ?[]u8 = null;
    try np.query(try std.fmt.bufPrint(&sql, "SELECT JSON_EXTRACT(value, '$.Records[0].n') FROM {s} WHERE key_name = 'bkt/obj'", .{ns_t}), &v);
    try testing.expectEqualStrings("2", v.?);
    gpa.free(v.?);
    try ns.send(&.{ .key = "bkt/obj", .body = "", .removed = true });
    v = null;
    try np.query(try std.fmt.bufPrint(&sql, "SELECT COUNT(*) FROM {s}", .{ns_t}), &v);
    try testing.expectEqualStrings("0", v.?);
    gpa.free(v.?);
    try np.exec(try std.fmt.bufPrint(&sql, "DROP TABLE {s}", .{ns_t}));

    const ac = try create(gpa, .{ .kvs = &.{ .{ .key = "dsn_string", .value = dsn }, .{ .key = "table", .value = ac_t }, .{ .key = "format", .value = "access" } } });
    defer ac.deinit();
    const ap: *My = @ptrCast(@alignCast(ac.ctx));
    try ac.send(&.{ .body = "{\"Records\":[{\"k\":\"x\"}]}", .event_time = "2024-01-02T03:04:05Z" });
    v = null;
    try ap.query(try std.fmt.bufPrint(&sql, "SELECT CONCAT(YEAR(event_time), ':', JSON_UNQUOTE(JSON_EXTRACT(event_data, '$.Records[0].k'))) FROM {s}", .{ac_t}), &v);
    try testing.expectEqualStrings("2024:x", v.?);
    gpa.free(v.?);
    try ap.exec(try std.fmt.bufPrint(&sql, "DROP TABLE {s}", .{ac_t}));
}
