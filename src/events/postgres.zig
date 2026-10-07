//! PostgreSQL notification target (MinIO notify_postgres layout). Speaks the
//! v3 wire protocol directly: TLS via SSLRequest, cleartext/MD5/SCRAM-SHA-256
//! auth, and the extended query protocol so values travel as parameters.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

const log = std.log.scoped(.events_postgres);
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Md5 = std.crypto.hash.Md5;

pub const keys = [_][]const u8{
    "connection_string", "table", "format",   "max_open_connections", "queue_dir", "queue_limit", "comment",
    "host",              "port",  "username", "password",             "database",
};

/// Largest backend message accepted; bigger frames are a protocol error.
const max_msg = 1 << 20;
/// Largest single parameter value sent.
const max_param = 64 << 20;
const max_scram_iterations = 1_000_000;

pub const SslMode = enum { disable, allow, prefer, require, verify_ca, verify_full };

pub const Config = struct {
    host: []const u8 = "localhost",
    port: u16 = 5432,
    user: []const u8 = "",
    password: []const u8 = "",
    dbname: []const u8 = "",
    sslmode: SslMode = .prefer,
    sslrootcert: []const u8 = "",
    connect_timeout_ms: u32 = 5000,
};

pub const ParseError = error{ InvalidConfig, OutOfMemory };

/// Applies a libpq conninfo (`key=value ...` or `postgres://` URI) onto `cfg`.
/// Strings are allocated in `a`; unknown keys are ignored like libpq does.
pub fn parseConninfo(a: std.mem.Allocator, cfg: *Config, s: []const u8) ParseError!void {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (std.mem.startsWith(u8, t, "postgres://") or std.mem.startsWith(u8, t, "postgresql://")) return parseUri(a, cfg, t);
    var i: usize = 0;
    while (true) {
        while (i < t.len and std.ascii.isWhitespace(t[i])) i += 1;
        if (i >= t.len) return;
        const ks = i;
        while (i < t.len and t[i] != '=' and !std.ascii.isWhitespace(t[i])) i += 1;
        const key = t[ks..i];
        while (i < t.len and std.ascii.isWhitespace(t[i])) i += 1;
        if (i >= t.len or t[i] != '=' or key.len == 0) return error.InvalidConfig;
        i += 1;
        while (i < t.len and std.ascii.isWhitespace(t[i])) i += 1;
        var val: std.ArrayList(u8) = .empty;
        if (i < t.len and t[i] == '\'') {
            i += 1;
            while (true) {
                if (i >= t.len) return error.InvalidConfig;
                const c = t[i];
                i += 1;
                if (c == '\'') break;
                if (c == '\\') {
                    if (i >= t.len) return error.InvalidConfig;
                    try val.append(a, t[i]);
                    i += 1;
                } else try val.append(a, c);
            }
        } else {
            while (i < t.len and !std.ascii.isWhitespace(t[i])) : (i += 1) {
                if (t[i] == '\\' and i + 1 < t.len) i += 1;
                try val.append(a, t[i]);
            }
        }
        try setKey(cfg, key, val.items);
    }
}

fn setKey(cfg: *Config, key: []const u8, v: []const u8) ParseError!void {
    if (std.mem.eql(u8, key, "host") or std.mem.eql(u8, key, "hostaddr")) {
        if (v.len > 0) cfg.host = v;
    } else if (std.mem.eql(u8, key, "port")) {
        if (v.len > 0) cfg.port = std.fmt.parseInt(u16, v, 10) catch return error.InvalidConfig;
    } else if (std.mem.eql(u8, key, "user")) {
        cfg.user = v;
    } else if (std.mem.eql(u8, key, "password")) {
        cfg.password = v;
    } else if (std.mem.eql(u8, key, "dbname")) {
        cfg.dbname = v;
    } else if (std.mem.eql(u8, key, "sslrootcert")) {
        cfg.sslrootcert = v;
    } else if (std.mem.eql(u8, key, "connect_timeout")) {
        const n = std.fmt.parseInt(u32, v, 10) catch return error.InvalidConfig;
        if (n > 0) cfg.connect_timeout_ms = std.math.mul(u32, n, 1000) catch return error.InvalidConfig;
    } else if (std.mem.eql(u8, key, "sslmode")) {
        const modes = [_]struct { []const u8, SslMode }{
            .{ "disable", .disable }, .{ "allow", .allow },         .{ "prefer", .prefer },
            .{ "require", .require }, .{ "verify-ca", .verify_ca }, .{ "verify-full", .verify_full },
        };
        for (modes) |m| if (std.mem.eql(u8, v, m[0])) {
            cfg.sslmode = m[1];
            return;
        };
        return error.InvalidConfig;
    }
}

fn parseUri(a: std.mem.Allocator, cfg: *Config, s: []const u8) ParseError!void {
    var rest = s[std.mem.indexOf(u8, s, "://").? + 3 ..];
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| {
        query = rest[q + 1 ..];
        rest = rest[0..q];
    }
    if (std.mem.indexOfScalar(u8, rest, '/')) |sl| {
        cfg.dbname = try pctDecode(a, rest[sl + 1 ..]);
        rest = rest[0..sl];
    }
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
        const ui = rest[0..at];
        rest = rest[at + 1 ..];
        if (std.mem.indexOfScalar(u8, ui, ':')) |c| {
            cfg.user = try pctDecode(a, ui[0..c]);
            cfg.password = try pctDecode(a, ui[c + 1 ..]);
        } else cfg.user = try pctDecode(a, ui);
    }
    if (rest.len > 0) {
        const hp = net.splitHostPort(rest, cfg.port) catch return error.InvalidConfig;
        cfg.host = try pctDecode(a, hp[0]);
        cfg.port = hp[1];
    }
    var it = std.mem.tokenizeScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.InvalidConfig;
        try setKey(cfg, kv[0..eq], try pctDecode(a, kv[eq + 1 ..]));
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

/// `name` or `schema.name`, each part [A-Za-z_][A-Za-z0-9_]{0,62}.
pub fn validIdent(s: []const u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var parts: usize = 0;
    while (it.next()) |p| {
        parts += 1;
        if (parts > 2 or p.len == 0 or p.len > 63) return false;
        if (!(std.ascii.isAlphabetic(p[0]) or p[0] == '_')) return false;
        for (p) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    return parts > 0;
}

/// "md5" + hex(md5(hex(md5(password + user)) + salt)).
pub fn md5Password(user: []const u8, password: []const u8, salt: [4]u8) [35]u8 {
    var d: [16]u8 = undefined;
    var h = Md5.init(.{});
    h.update(password);
    h.update(user);
    h.final(&d);
    const inner = std.fmt.bytesToHex(d, .lower);
    h = Md5.init(.{});
    h.update(&inner);
    h.update(&salt);
    h.final(&d);
    var out: [35]u8 = undefined;
    @memcpy(out[0..3], "md5");
    out[3..].* = std.fmt.bytesToHex(d, .lower);
    return out;
}

pub const ScramError = error{ScramFailed};

pub const ScramFinal = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,
    server_sig: [32]u8 = undefined,

    pub fn msg(f: *const ScramFinal) []const u8 {
        return f.buf[0..f.len];
    }
};

/// RFC 5802/7677 client-final-message for SCRAM-SHA-256 without channel binding.
/// `client_first_bare` is "n=<user>,r=<nonce>"; the expected server signature is kept.
pub fn scramClientFinal(password: []const u8, client_first_bare: []const u8, server_first: []const u8, client_nonce: []const u8) ScramError!ScramFinal {
    if (server_first.len > 1024 or client_first_bare.len > 512) return error.ScramFailed;
    var nonce: []const u8 = "";
    var salt_b64: []const u8 = "";
    var iters: u32 = 0;
    var it = std.mem.splitScalar(u8, server_first, ',');
    while (it.next()) |attr| {
        if (attr.len < 2 or attr[1] != '=') return error.ScramFailed;
        const v = attr[2..];
        switch (attr[0]) {
            'r' => nonce = v,
            's' => salt_b64 = v,
            'i' => iters = std.fmt.parseInt(u32, v, 10) catch return error.ScramFailed,
            'm' => return error.ScramFailed,
            else => {},
        }
    }
    if (nonce.len <= client_nonce.len or nonce.len > 256 or !std.mem.startsWith(u8, nonce, client_nonce)) return error.ScramFailed;
    if (iters == 0 or iters > max_scram_iterations) return error.ScramFailed;
    const dec = std.base64.standard.Decoder;
    const salt_len = dec.calcSizeForSlice(salt_b64) catch return error.ScramFailed;
    if (salt_len == 0 or salt_len > 128) return error.ScramFailed;
    var salt: [128]u8 = undefined;
    dec.decode(salt[0..salt_len], salt_b64) catch return error.ScramFailed;

    var salted: [32]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&salted, password, salt[0..salt_len], iters, HmacSha256) catch return error.ScramFailed;
    var client_key: [32]u8 = undefined;
    HmacSha256.create(&client_key, "Client Key", &salted);
    var stored: [32]u8 = undefined;
    Sha256.hash(&client_key, &stored, .{});
    var server_key: [32]u8 = undefined;
    HmacSha256.create(&server_key, "Server Key", &salted);

    var f: ScramFinal = .{};
    const without_proof = std.fmt.bufPrint(&f.buf, "c=biws,r={s}", .{nonce}) catch return error.ScramFailed;
    var auth_buf: [2048]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buf, "{s},{s},{s}", .{ client_first_bare, server_first, without_proof }) catch return error.ScramFailed;
    var sig: [32]u8 = undefined;
    HmacSha256.create(&sig, auth, &stored);
    var proof: [32]u8 = undefined;
    for (&proof, client_key, sig) |*p, k, s| p.* = k ^ s;
    HmacSha256.create(&f.server_sig, auth, &server_key);

    var proof_b64: [44]u8 = undefined;
    const enc = std.base64.standard.Encoder.encode(&proof_b64, &proof);
    const all = std.fmt.bufPrint(&f.buf, "c=biws,r={s},p={s}", .{ nonce, enc }) catch return error.ScramFailed;
    f.len = all.len;
    return f;
}

/// Checks a server-final-message ("v=<base64>") against the expected signature.
pub fn scramVerify(f: *const ScramFinal, server_final: []const u8) ScramError!void {
    if (!std.mem.startsWith(u8, server_final, "v=")) return error.ScramFailed;
    const v = std.mem.trimRight(u8, server_final[2..], "\x00");
    if (v.len != 44) return error.ScramFailed;
    var got: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&got, v) catch return error.ScramFailed;
    if (!std.crypto.timing_safe.eql([32]u8, got, f.server_sig)) return error.ScramFailed;
}

/// Net/Protocol drop the connection (Unreachable); Server keeps it (Rejected).
const E = error{ Net, Protocol, Server, TooLarge, OutOfMemory };

const Pg = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    cfg: Config,
    format: target.Format,
    sql_create: []const u8,
    sql_upsert: []const u8,
    sql_delete: []const u8,
    sql_insert: []const u8,
    conn: ?*net.Conn = null,
    in: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,

    fn drop(p: *Pg) void {
        if (p.conn) |c| c.close();
        p.conn = null;
    }

    fn deinit(p: *Pg) void {
        if (p.conn != null) {
            p.out.clearRetainingCapacity();
            if (p.begin('X')) |at| {
                p.finish(at) catch {};
                p.flushOut() catch {};
            } else |_| {}
        }
        p.drop();
        p.in.deinit(p.gpa);
        p.out.deinit(p.gpa);
        const gpa = p.gpa;
        p.arena.deinit();
        gpa.destroy(p);
    }

    fn begin(p: *Pg, t: u8) E!usize {
        if (t != 0) try p.out.append(p.gpa, t);
        const at = p.out.items.len;
        try p.out.appendNTimes(p.gpa, 0, 4);
        return at;
    }

    fn finish(p: *Pg, at: usize) E!void {
        const n = p.out.items.len - at;
        if (n > std.math.maxInt(i32)) return error.TooLarge;
        std.mem.writeInt(u32, p.out.items[at..][0..4], @intCast(n), .big);
    }

    fn put(p: *Pg, b: []const u8) E!void {
        try p.out.appendSlice(p.gpa, b);
    }

    fn cstr(p: *Pg, s: []const u8) E!void {
        try p.put(s);
        try p.out.append(p.gpa, 0);
    }

    fn int(p: *Pg, comptime T: type, v: T) E!void {
        const b = try p.out.addManyAsArray(p.gpa, @sizeOf(T));
        std.mem.writeInt(T, b, v, .big);
    }

    fn flushOut(p: *Pg) E!void {
        defer p.out.clearRetainingCapacity();
        const c = p.conn orelse return error.Net;
        c.writer().writeAll(p.out.items) catch return error.Net;
        c.flush() catch return error.Net;
    }

    fn readMsg(p: *Pg) E!struct { u8, []const u8 } {
        const r = (p.conn orelse return error.Net).reader();
        const t = r.takeByte() catch return error.Net;
        const len = r.takeInt(u32, .big) catch return error.Net;
        if (len < 4 or len - 4 > max_msg) return error.Protocol;
        try p.in.resize(p.gpa, len - 4);
        r.readSliceAll(p.in.items) catch return error.Net;
        return .{ t, p.in.items };
    }

    fn connect(p: *Pg) E!void {
        const cfg = &p.cfg;
        p.conn = net.dial(p.gpa, cfg.host, cfg.port, .{ .connect_timeout_ms = cfg.connect_timeout_ms }) catch |e|
            return if (e == error.OutOfMemory) error.OutOfMemory else error.Net;
        errdefer p.drop();
        p.out.clearRetainingCapacity();
        if (cfg.sslmode != .disable and cfg.sslmode != .allow) {
            try p.int(u32, 8);
            try p.int(u32, 80877103);
            try p.flushOut();
            const b = p.conn.?.reader().takeByte() catch return error.Net;
            if (b == 'S') {
                const verify = cfg.sslmode == .verify_ca or cfg.sslmode == .verify_full;
                p.conn.?.startTls(cfg.host, .{ .skip_verify = !verify, .ca_file = cfg.sslrootcert }) catch |e|
                    return if (e == error.OutOfMemory) error.OutOfMemory else error.Net;
            } else if (b == 'N') {
                if (cfg.sslmode != .prefer) {
                    log.warn("postgres {s}: server refused TLS (sslmode requires it)", .{cfg.host});
                    return error.Server;
                }
            } else return error.Protocol;
        }
        const at = try p.begin(0);
        try p.int(u32, 196608);
        try p.cstr("user");
        try p.cstr(cfg.user);
        if (cfg.dbname.len > 0) {
            try p.cstr("database");
            try p.cstr(cfg.dbname);
        }
        try p.cstr("client_encoding");
        try p.cstr("UTF8");
        try p.out.append(p.gpa, 0);
        try p.finish(at);
        try p.flushOut();
        try p.authenticate();
        try p.waitReady();
        try p.query(p.sql_create, &.{}, null);
    }

    fn authenticate(p: *Pg) E!void {
        var nonce_b64: [24]u8 = undefined;
        var first_bare: [32]u8 = undefined;
        var first_bare_len: usize = 0;
        var final: ?ScramFinal = null;
        while (true) {
            const t, const body = try p.readMsg();
            switch (t) {
                'E' => {
                    p.logError(body);
                    return error.Server;
                },
                'N' => continue,
                'R' => {},
                else => return error.Protocol,
            }
            if (body.len < 4) return error.Protocol;
            const code = std.mem.readInt(u32, body[0..4], .big);
            const data = body[4..];
            switch (code) {
                0 => return,
                3 => {
                    const at = try p.begin('p');
                    try p.cstr(p.cfg.password);
                    try p.finish(at);
                    try p.flushOut();
                },
                5 => {
                    if (data.len < 4) return error.Protocol;
                    const h = md5Password(p.cfg.user, p.cfg.password, data[0..4].*);
                    const at = try p.begin('p');
                    try p.cstr(&h);
                    try p.finish(at);
                    try p.flushOut();
                },
                10 => {
                    var ok = false;
                    var it = std.mem.splitScalar(u8, data, 0);
                    while (it.next()) |m| if (std.mem.eql(u8, m, "SCRAM-SHA-256")) {
                        ok = true;
                    };
                    if (!ok) {
                        log.warn("postgres {s}: no supported SASL mechanism", .{p.cfg.host});
                        return error.Server;
                    }
                    var raw: [18]u8 = undefined;
                    std.crypto.random.bytes(&raw);
                    _ = std.base64.standard.Encoder.encode(&nonce_b64, &raw);
                    const bare = std.fmt.bufPrint(&first_bare, "n=,r={s}", .{nonce_b64}) catch unreachable;
                    first_bare_len = bare.len;
                    const at = try p.begin('p');
                    try p.cstr("SCRAM-SHA-256");
                    try p.int(u32, @intCast(bare.len + 3));
                    try p.put("n,,");
                    try p.put(bare);
                    try p.finish(at);
                    try p.flushOut();
                },
                11 => {
                    if (first_bare_len == 0) return error.Protocol;
                    const f = scramClientFinal(p.cfg.password, first_bare[0..first_bare_len], data, &nonce_b64) catch return error.Protocol;
                    final = f;
                    const at = try p.begin('p');
                    try p.put(final.?.msg());
                    try p.finish(at);
                    try p.flushOut();
                },
                12 => {
                    const f = final orelse return error.Protocol;
                    scramVerify(&f, data) catch {
                        log.warn("postgres {s}: bad SCRAM server signature", .{p.cfg.host});
                        return error.Protocol;
                    };
                },
                else => {
                    log.warn("postgres {s}: unsupported auth method {d}", .{ p.cfg.host, code });
                    return error.Server;
                },
            }
        }
    }

    fn waitReady(p: *Pg) E!void {
        while (true) {
            const t, const body = try p.readMsg();
            switch (t) {
                'Z' => return,
                'E' => {
                    p.logError(body);
                    return error.Server;
                },
                'S', 'K', 'N' => {},
                else => return error.Protocol,
            }
        }
    }

    fn logError(p: *Pg, body: []const u8) void {
        var msg: []const u8 = "";
        var code: []const u8 = "";
        var i: usize = 0;
        while (i < body.len and body[i] != 0) {
            const f = body[i];
            const end = std.mem.indexOfScalarPos(u8, body, i + 1, 0) orelse break;
            if (f == 'M') msg = body[i + 1 .. end];
            if (f == 'C') code = body[i + 1 .. end];
            i = end + 1;
        }
        log.warn("postgres {s}: {s} ({s})", .{ p.cfg.host, msg, code });
    }

    /// Parse/Bind/Execute/Sync with text parameters; copies the first column of
    /// the first row into `first` (caller frees) when given.
    fn query(p: *Pg, sql: []const u8, params: []const []const u8, first: ?*?[]u8) E!void {
        p.out.clearRetainingCapacity();
        var at = try p.begin('P');
        try p.cstr("");
        try p.cstr(sql);
        try p.int(u16, 0);
        try p.finish(at);
        at = try p.begin('B');
        try p.cstr("");
        try p.cstr("");
        try p.int(u16, 0);
        try p.int(u16, @intCast(params.len));
        for (params) |v| {
            if (v.len > max_param) return error.TooLarge;
            try p.int(u32, @intCast(v.len));
            try p.put(v);
        }
        try p.int(u16, 0);
        try p.finish(at);
        at = try p.begin('E');
        try p.cstr("");
        try p.int(u32, 0);
        try p.finish(at);
        at = try p.begin('S');
        try p.finish(at);
        try p.flushOut();

        var failed = false;
        while (true) {
            const t, const body = try p.readMsg();
            switch (t) {
                'Z' => break,
                'E' => {
                    p.logError(body);
                    failed = true;
                },
                'D' => if (first) |f| if (f.* == null and body.len >= 6 and std.mem.readInt(u16, body[0..2], .big) >= 1) {
                    const n = std.mem.readInt(i32, body[2..6], .big);
                    if (n >= 0) {
                        if (@as(usize, @intCast(n)) > body.len - 6) return error.Protocol;
                        f.* = try p.gpa.dupe(u8, body[6..][0..@intCast(n)]);
                    }
                },
                '1', '2', '3', 'C', 'n', 'T', 's', 'I', 'N', 'S', 'A' => {},
                else => return error.Protocol,
            }
        }
        if (failed) return error.Server;
    }

    fn deliver(p: *Pg, msg: *const target.Message) E!void {
        if (p.conn == null) try p.connect();
        switch (p.format) {
            .namespace => if (msg.removed)
                try p.query(p.sql_delete, &.{msg.key}, null)
            else
                try p.query(p.sql_upsert, &.{ msg.key, msg.body }, null),
            .access => try p.query(p.sql_insert, &.{ msg.event_time, msg.body }, null),
        }
    }
};

fn sendFn(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
    const p: *Pg = @ptrCast(@alignCast(ctx));
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
    const p: *Pg = @ptrCast(@alignCast(ctx));
    p.deinit();
}

const vtable: target.Client.VTable = .{ .send = sendFn, .deinit = deinitFn };

/// Validates settings and builds a client; no I/O until the first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const p = try gpa.create(Pg);
    p.* = .{
        .gpa = gpa,
        .arena = .init(gpa),
        .cfg = .{},
        .format = .namespace,
        .sql_create = "",
        .sql_upsert = "",
        .sql_delete = "",
        .sql_insert = "",
    };
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
    try parseConninfo(a, cfg, s.get("connection_string"));
    cfg.host = try a.dupe(u8, cfg.host);
    cfg.user = try a.dupe(u8, cfg.user);
    cfg.password = try a.dupe(u8, cfg.password);
    cfg.dbname = try a.dupe(u8, cfg.dbname);
    cfg.sslrootcert = try a.dupe(u8, cfg.sslrootcert);
    for ([_][]const u8{ cfg.host, cfg.user, cfg.password, cfg.dbname }) |v|
        if (std.mem.indexOfScalar(u8, v, 0) != null) return error.InvalidConfig;
    if (cfg.host.len == 0 or cfg.user.len == 0) return error.InvalidConfig;
    p.format = try target.Format.parse(s.get("format"));
    _ = try s.int(u32, "max_open_connections", 2);
    _ = try s.int(u64, "queue_limit", 0);
    const table = s.get("table");
    if (!validIdent(table)) return error.InvalidConfig;
    switch (p.format) {
        .namespace => {
            p.sql_create = try std.fmt.allocPrint(a, "CREATE TABLE IF NOT EXISTS {s} (key VARCHAR PRIMARY KEY, value JSONB)", .{table});
            p.sql_upsert = try std.fmt.allocPrint(a, "INSERT INTO {s} (key, value) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", .{table});
            p.sql_delete = try std.fmt.allocPrint(a, "DELETE FROM {s} WHERE key = $1", .{table});
        },
        .access => {
            p.sql_create = try std.fmt.allocPrint(a, "CREATE TABLE IF NOT EXISTS {s} (event_time TIMESTAMP WITH TIME ZONE NOT NULL, event_data JSONB)", .{table});
            p.sql_insert = try std.fmt.allocPrint(a, "INSERT INTO {s} (event_time, event_data) VALUES (COALESCE(NULLIF($1::text, '')::timestamptz, now()), $2::jsonb)", .{table});
        },
    }
    return .{ .ctx = p, .vtable = &vtable };
}

// ---- tests ----

const testing = std.testing;

test "conninfo parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var c: Config = .{};
    try parseConninfo(arena.allocator(), &c, "host=db.local port=6543 user=postgres password='p w\\'x' dbname=ev sslmode=verify-full connect_timeout=3");
    try testing.expectEqualStrings("db.local", c.host);
    try testing.expectEqual(@as(u16, 6543), c.port);
    try testing.expectEqualStrings("p w'x", c.password);
    try testing.expectEqualStrings("ev", c.dbname);
    try testing.expectEqual(SslMode.verify_full, c.sslmode);
    try testing.expectEqual(@as(u32, 3000), c.connect_timeout_ms);

    var u: Config = .{};
    try parseConninfo(arena.allocator(), &u, "postgres://me:p%40ss@h:5433/d?sslmode=disable");
    try testing.expectEqualStrings("me", u.user);
    try testing.expectEqualStrings("p@ss", u.password);
    try testing.expectEqualStrings("h", u.host);
    try testing.expectEqual(@as(u16, 5433), u.port);
    try testing.expectEqual(SslMode.disable, u.sslmode);

    try testing.expectError(error.InvalidConfig, parseConninfo(arena.allocator(), &c, "sslmode=bogus"));
    try testing.expectError(error.InvalidConfig, parseConninfo(arena.allocator(), &c, "password='open"));
    try testing.expectError(error.InvalidConfig, parseConninfo(arena.allocator(), &c, "port=x"));
}

test "identifier validation and create" {
    try testing.expect(validIdent("events"));
    try testing.expect(validIdent("public.ev_1"));
    try testing.expect(!validIdent(""));
    try testing.expect(!validIdent("a;drop table x"));
    try testing.expect(!validIdent("1abc"));
    try testing.expect(!validIdent("a.b.c"));
    const bad = [_]target.Kv{ .{ .key = "connection_string", .value = "user=u" }, .{ .key = "table", .value = "t\"x" } };
    try testing.expectError(error.InvalidConfig, create(testing.allocator, .{ .kvs = &bad }));
    const nouser = [_]target.Kv{.{ .key = "table", .value = "t" }};
    try testing.expectError(error.InvalidConfig, create(testing.allocator, .{ .kvs = &nouser }));
    const ok = [_]target.Kv{ .{ .key = "host", .value = "h" }, .{ .key = "username", .value = "u" }, .{ .key = "table", .value = "t" }, .{ .key = "format", .value = "access" } };
    const c = try create(testing.allocator, .{ .kvs = &ok });
    c.deinit();
}

test "md5 password hash" {
    // Matches libpq / pg_md5_encrypt for user "postgres", password "secret".
    var d: [16]u8 = undefined;
    Md5.hash("secretpostgres", &d, .{});
    const inner = std.fmt.bytesToHex(d, .lower);
    var h = Md5.init(.{});
    h.update(&inner);
    h.update(&[_]u8{ 1, 2, 3, 4 });
    h.final(&d);
    const want = "md5" ++ std.fmt.bytesToHex(d, .lower);
    try testing.expectEqualStrings(want, &md5Password("postgres", "secret", .{ 1, 2, 3, 4 }));
    try testing.expectEqualStrings("md5", md5Password("u", "p", .{ 0, 0, 0, 0 })[0..3]);
    // Stored form md5(password+user) known value: "md5" + md5("foobar").
    Md5.hash("foobar", &d, .{});
    try testing.expectEqualStrings("3858f62230ac3c915f300c664312c63f", &std.fmt.bytesToHex(d, .lower));
}

test "scram-sha-256 RFC 7677 vector" {
    const f = try scramClientFinal(
        "pencil",
        "n=user,r=rOprNGfwEbeRWgbNEkqO",
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        "rOprNGfwEbeRWgbNEkqO",
    );
    try testing.expectEqualStrings("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", f.msg());
    try scramVerify(&f, "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    try testing.expectError(error.ScramFailed, scramVerify(&f, "v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
    try testing.expectError(error.ScramFailed, scramClientFinal("p", "n=,r=abc", "r=xyz1,s=AAAA,i=1", "abc"));
    try testing.expectError(error.ScramFailed, scramClientFinal("p", "n=,r=abc", "r=abcd,s=AAAA,i=99999999", "abc"));
    try testing.expectError(error.ScramFailed, scramClientFinal("p", "n=,r=abc", "garbage", "abc"));
}

test "message encoding" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var p: Pg = .{ .gpa = testing.allocator, .arena = undefined, .cfg = .{}, .format = .namespace, .sql_create = "", .sql_upsert = "", .sql_delete = "", .sql_insert = "" };
    defer p.out.deinit(testing.allocator);
    const at = try p.begin('B');
    try p.cstr("");
    try p.cstr("");
    try p.int(u16, 0);
    try p.int(u16, 1);
    try p.int(u32, 2);
    try p.put("hi");
    try p.int(u16, 0);
    try p.finish(at);
    try testing.expectEqualSlices(u8, "B\x00\x00\x00\x12\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02hi\x00\x00", p.out.items);
}

/// Speaks just enough backend protocol for the client; records Parse SQL and Bind params.
const FakePg = struct {
    srv: std.net.Server,
    log_buf: std.ArrayList(u8) = .empty,
    md5: bool = false,
    fail_on: []const u8 = "",

    fn msg(w: *std.Io.Writer, t: u8, body: []const u8) !void {
        try w.writeByte(t);
        try w.writeInt(u32, @intCast(body.len + 4), .big);
        try w.writeAll(body);
    }

    fn run(f: *FakePg) void {
        f.serve() catch {};
    }

    fn serve(f: *FakePg) !void {
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [8192]u8 = undefined;
        var wb: [8192]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const r = sr.interface();
        const w = &sw.interface;
        const n = try r.takeInt(u32, .big);
        _ = try r.take(n - 4);
        if (f.md5) {
            try msg(w, 'R', "\x00\x00\x00\x05salt");
            try w.flush();
            _ = try r.takeByte();
            const l = try r.takeInt(u32, .big);
            const got = try r.take(l - 4);
            const want = md5Password("u", "pw", "salt".*);
            if (!std.mem.eql(u8, got[0..35], &want)) {
                try msg(w, 'E', "SFATAL\x00C28P01\x00Mauth failed\x00\x00");
                try w.flush();
                return;
            }
        }
        try msg(w, 'R', "\x00\x00\x00\x00");
        try msg(w, 'S', "server_version\x0016\x00");
        try msg(w, 'K', "\x00\x00\x00\x01\x00\x00\x00\x02");
        try msg(w, 'Z', "I");
        try w.flush();
        var failing = false;
        while (true) {
            const t = r.takeByte() catch return;
            const l = try r.takeInt(u32, .big);
            const body = try r.take(l - 4);
            switch (t) {
                'X' => return,
                'P' => {
                    const q = std.mem.sliceTo(body[1..], 0);
                    failing = f.fail_on.len > 0 and std.mem.indexOf(u8, q, f.fail_on) != null;
                    try f.log_buf.appendSlice(testing.allocator, q);
                    try f.log_buf.append(testing.allocator, '\n');
                },
                'B' => {
                    var i: usize = 2 + 2;
                    const np = std.mem.readInt(u16, body[i..][0..2], .big);
                    i += 2;
                    for (0..np) |_| {
                        const pl = std.mem.readInt(u32, body[i..][0..4], .big);
                        i += 4;
                        try f.log_buf.appendSlice(testing.allocator, "  $");
                        try f.log_buf.appendSlice(testing.allocator, body[i..][0..pl]);
                        try f.log_buf.append(testing.allocator, '\n');
                        i += pl;
                    }
                },
                'S' => {
                    if (failing) {
                        try msg(w, 'E', "SERROR\x00C22P02\x00Minvalid json\x00\x00");
                    } else {
                        try msg(w, '1', "");
                        try msg(w, '2', "");
                        try msg(w, 'N', "SNOTICE\x00Mhi\x00\x00");
                        try msg(w, 'C', "INSERT 0 1\x00");
                    }
                    try msg(w, 'Z', "I");
                    try w.flush();
                },
                else => {},
            }
        }
    }
};

fn fakeClient(f: *FakePg, extra: []const target.Kv) !target.Client {
    var cs_buf: [128]u8 = undefined;
    const cs = try std.fmt.bufPrint(&cs_buf, "host=127.0.0.1 port={d} user=u password=pw dbname=d sslmode=disable", .{f.srv.listen_address.getPort()});
    var kvs: [8]target.Kv = undefined;
    kvs[0] = .{ .key = "connection_string", .value = cs };
    for (extra, 1..) |kv, i| kvs[i] = kv;
    return create(testing.allocator, .{ .kvs = kvs[0 .. extra.len + 1] });
}

test "fake server namespace upsert and delete (md5 auth)" {
    var f: FakePg = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .md5 = true };
    defer f.srv.deinit();
    defer f.log_buf.deinit(testing.allocator);
    const th = try std.Thread.spawn(.{}, FakePg.run, .{&f});
    const c = try fakeClient(&f, &.{.{ .key = "table", .value = "ev" }});
    c.send(&.{ .key = "b/o'; drop", .body = "{\"Records\":[1]}" }) catch |e| {
        c.deinit();
        th.join();
        return e;
    };
    try c.send(&.{ .key = "b/o'; drop", .body = "", .removed = true });
    c.deinit();
    th.join();
    try testing.expectEqualStrings(
        "CREATE TABLE IF NOT EXISTS ev (key VARCHAR PRIMARY KEY, value JSONB)\n" ++
            "INSERT INTO ev (key, value) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value\n" ++
            "  $b/o'; drop\n  ${\"Records\":[1]}\n" ++
            "DELETE FROM ev WHERE key = $1\n  $b/o'; drop\n",
        f.log_buf.items,
    );
}

test "fake server access insert and rejected error" {
    var f: FakePg = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .fail_on = "INSERT" };
    defer f.srv.deinit();
    defer f.log_buf.deinit(testing.allocator);
    const th = try std.Thread.spawn(.{}, FakePg.run, .{&f});
    const c = try fakeClient(&f, &.{ .{ .key = "table", .value = "audit" }, .{ .key = "format", .value = "access" } });
    const r = c.send(&.{ .body = "{\"Records\":[]}", .event_time = "2024-01-02T03:04:05Z" });
    c.deinit();
    th.join();
    try testing.expectError(error.Rejected, r);
    try testing.expect(std.mem.indexOf(u8, f.log_buf.items, "INSERT INTO audit (event_time, event_data) VALUES (COALESCE(NULLIF($1::text, '')::timestamptz, now()), $2::jsonb)\n  $2024-01-02T03:04:05Z\n  ${\"Records\":[]}\n") != null);
}

test "unreachable server maps to Unreachable" {
    const kvs = [_]target.Kv{ .{ .key = "connection_string", .value = "host=127.0.0.1 port=1 user=u sslmode=disable" }, .{ .key = "table", .value = "t" } };
    const c = try create(testing.allocator, .{ .kvs = &kvs });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .key = "a", .body = "{}" }));
}

test "events live postgres" {
    const gpa = testing.allocator;
    const cs = std.process.getEnvVarOwned(gpa, "ZKFSM_TEST_POSTGRES") catch return error.SkipZigTest;
    defer gpa.free(cs);
    var name_buf: [2][40]u8 = undefined;
    var rnd: [4]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    const hex = std.fmt.bytesToHex(rnd, .lower);
    const ns_t = try std.fmt.bufPrint(&name_buf[0], "zkfsm_live_ns_{s}", .{hex});
    const ac_t = try std.fmt.bufPrint(&name_buf[1], "zkfsm_live_ac_{s}", .{hex});

    const ns = try create(gpa, .{ .kvs = &.{ .{ .key = "connection_string", .value = cs }, .{ .key = "table", .value = ns_t } } });
    defer ns.deinit();
    const np: *Pg = @ptrCast(@alignCast(ns.ctx));
    try ns.send(&.{ .key = "bkt/obj", .body = "{\"Records\":[{\"n\":1}]}" });
    try ns.send(&.{ .key = "bkt/obj", .body = "{\"Records\":[{\"n\":2}]}" });
    var v: ?[]u8 = null;
    var sql_buf: [256]u8 = undefined;
    try np.query(try std.fmt.bufPrint(&sql_buf, "SELECT value->'Records'->0->>'n' FROM {s} WHERE key = $1", .{ns_t}), &.{"bkt/obj"}, &v);
    try testing.expect(v != null);
    try testing.expectEqualStrings("2", v.?);
    gpa.free(v.?);
    try ns.send(&.{ .key = "bkt/obj", .body = "", .removed = true });
    v = null;
    try np.query(try std.fmt.bufPrint(&sql_buf, "SELECT count(*)::text FROM {s}", .{ns_t}), &.{}, &v);
    try testing.expectEqualStrings("0", v.?);
    gpa.free(v.?);
    try np.query(try std.fmt.bufPrint(&sql_buf, "DROP TABLE {s}", .{ns_t}), &.{}, null);

    const ac = try create(gpa, .{ .kvs = &.{ .{ .key = "connection_string", .value = cs }, .{ .key = "table", .value = ac_t }, .{ .key = "format", .value = "access" } } });
    defer ac.deinit();
    const ap: *Pg = @ptrCast(@alignCast(ac.ctx));
    try ac.send(&.{ .body = "{\"Records\":[{\"k\":\"x\"}]}", .event_time = "2024-01-02T03:04:05Z" });
    v = null;
    try ap.query(try std.fmt.bufPrint(&sql_buf, "SELECT extract(year from event_time)::int::text || ':' || (event_data->'Records'->0->>'k') FROM {s}", .{ac_t}), &.{}, &v);
    try testing.expectEqualStrings("2024:x", v.?);
    gpa.free(v.?);
    try testing.expectError(error.Rejected, ac.send(&.{ .body = "not json", .event_time = "2024-01-02T03:04:05Z" }));
    try ac.send(&.{ .body = "{}", .event_time = "" });
    try ap.query(try std.fmt.bufPrint(&sql_buf, "DROP TABLE {s}", .{ac_t}), &.{}, null);
}
