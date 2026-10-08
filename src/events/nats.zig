//! NATS notification target: core publish confirmed by PING/PONG, or a
//! JetStream publish confirmed by the stream's ack on a private inbox.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{
    "address",     "subject",              "username",        "password",
    "token",       "tls",                  "tls_skip_verify", "cert_authority",
    "client_cert", "client_key",           "ping_interval",   "jetstream",
    "streaming",   "streaming_cluster_id", "streaming_async", "streaming_max_pub_acks_in_flight",
    "queue_dir",   "queue_limit",          "comment",         "tls_server_name",
    "tls_min_version",
};

/// Largest inbound message payload accepted from the server.
pub const max_payload: usize = 8 << 20;
const default_port: u16 = 4222;

const Nats = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    host: []const u8 = "",
    port: u16 = default_port,
    subject: []const u8 = "",
    user: []const u8 = "",
    pass: []const u8 = "",
    token: []const u8 = "",
    tls: bool = false,
    tls_opts: net.TlsOptions = .{},
    jetstream: bool = false,
    timeout_ms: u32 = 10_000,
    inbox: ["_INBOX.zkfsm.".len + 16]u8 = undefined,
    seq: u64 = 0,
    conn: ?*net.Conn = null,

    fn configure(n: *Nats, s: target.Settings) target.InitError!void {
        const a = n.arena.allocator();
        var addr = s.get("address");
        for ([_][]const u8{ "nats://", "tls://" }) |p| {
            if (std.ascii.startsWithIgnoreCase(addr, p)) {
                if (p[0] == 't') n.tls = true;
                addr = addr[p.len..];
            }
        }
        const hp = net.splitHostPort(addr, default_port) catch return error.InvalidConfig;
        if (hp[0].len == 0) return error.InvalidConfig;
        n.host = try a.dupe(u8, hp[0]);
        n.port = hp[1];
        const subj = s.get("subject");
        if (!validSubject(subj)) return error.InvalidConfig;
        n.subject = try a.dupe(u8, subj);
        n.user = try a.dupe(u8, s.get("username"));
        n.pass = try a.dupe(u8, s.get("password"));
        n.token = try a.dupe(u8, s.get("token"));
        if (s.flag("tls")) n.tls = true;
        n.tls_opts = try net.tlsOptions(a, s, .{ .ca = "cert_authority" });
        // NATS Streaming (STAN) is retired.
        if (s.flag("streaming")) return error.InvalidConfig;
        _ = try s.durationMs("ping_interval", 0);
        _ = try s.int(u64, "queue_limit", 0);
        n.jetstream = s.flag("jetstream");
        var rnd: [8]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        _ = std.fmt.bufPrint(&n.inbox, "_INBOX.zkfsm.{s}", .{std.fmt.bytesToHex(rnd, .lower)}) catch unreachable;
    }

    fn drop(n: *Nats) void {
        if (n.conn) |c| c.close();
        n.conn = null;
    }

    fn connect(n: *Nats) target.SendError!void {
        const c = net.dial(n.gpa, n.host, n.port, .{ .io_timeout_ms = n.timeout_ms }) catch |e| return mapNet(e);
        errdefer c.close();
        const line = try readLine(c);
        if (!std.mem.startsWith(u8, line, "INFO ")) return error.Unreachable;
        const tls_required = try parseInfo(n.gpa, line[5..]);
        if (n.tls or tls_required) c.startTls(n.host, n.tls_opts) catch |e| return mapNet(e);
        const w = c.writer();
        writeConnect(w, n.user, n.pass, n.token) catch return error.Unreachable;
        if (n.jetstream) w.print("SUB {s}.* 1\r\n", .{n.inbox}) catch return error.Unreachable;
        w.writeAll("PING\r\n") catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        while (true) switch (try next(n.gpa, c)) {
            .pong => break,
            .err => return error.Rejected,
            .msg => |m| n.gpa.free(m.buf),
        };
        n.conn = c;
    }

    fn publish(n: *Nats, body: []const u8) target.SendError!void {
        const c = n.conn.?;
        const w = c.writer();
        var rbuf: [64]u8 = undefined;
        var reply: []const u8 = "";
        if (n.jetstream) {
            n.seq +%= 1;
            reply = std.fmt.bufPrint(&rbuf, "{s}.{d}", .{ &n.inbox, n.seq }) catch unreachable;
            w.print("PUB {s} {s} {d}\r\n", .{ n.subject, reply, body.len }) catch return error.Unreachable;
        } else w.print("PUB {s} {d}\r\n", .{ n.subject, body.len }) catch return error.Unreachable;
        w.writeAll(body) catch return error.Unreachable;
        w.writeAll(if (n.jetstream) "\r\n" else "\r\nPING\r\n") catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        var guard: u32 = 0;
        while (guard < 1024) : (guard += 1) {
            // A JetStream ack that never comes counts as a refusal.
            const op = next(n.gpa, c) catch |e| return if (n.jetstream and e == error.Unreachable) error.Rejected else e;
            switch (op) {
                .pong => if (!n.jetstream) return,
                .err => return error.Rejected,
                .msg => |m| {
                    defer n.gpa.free(m.buf);
                    if (!n.jetstream or !std.mem.eql(u8, m.subject, reply)) continue;
                    if (!try ackOk(n.gpa, m.hdr, m.payload)) return error.Rejected;
                    return;
                },
            }
        }
        return error.Unreachable;
    }
};

fn sendFn(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
    const n: *Nats = @ptrCast(@alignCast(ctx));
    if (n.conn == null) try n.connect();
    n.publish(msg.body) catch |e| {
        n.drop();
        return e;
    };
}

fn deinitFn(ctx: *anyopaque) void {
    const n: *Nats = @ptrCast(@alignCast(ctx));
    n.drop();
    n.arena.deinit();
    n.gpa.destroy(n);
}

const vtable: target.Client.VTable = .{ .send = sendFn, .deinit = deinitFn };

/// Validates settings and builds the client; connects on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const n = try gpa.create(Nats);
    errdefer gpa.destroy(n);
    n.* = .{ .gpa = gpa, .arena = .init(gpa) };
    errdefer n.arena.deinit();
    try n.configure(s);
    return .{ .ctx = n, .vtable = &vtable };
}

fn validSubject(s: []const u8) bool {
    if (s.len == 0 or s.len > 1024) return false;
    for (s) |ch| if (ch <= ' ' or ch == 0x7f or ch == '*' or ch == '>') return false;
    return s[0] != '.' and s[s.len - 1] != '.' and std.mem.indexOf(u8, s, "..") == null;
}

fn mapNet(e: net.Error) target.SendError {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
}

/// Writes the CONNECT line; credentials are JSON-escaped and omitted when empty.
pub fn writeConnect(w: *std.Io.Writer, user: []const u8, pass: []const u8, token: []const u8) error{WriteFailed}!void {
    const opt = struct {
        verbose: bool = false,
        pedantic: bool = false,
        user: ?[]const u8,
        pass: ?[]const u8,
        auth_token: ?[]const u8,
        headers: bool = true,
        no_responders: bool = true,
        protocol: u8 = 1,
        lang: []const u8 = "zig",
        name: []const u8 = "zkfsm",
    }{
        .user = if (user.len > 0) user else null,
        .pass = if (pass.len > 0) pass else null,
        .auth_token = if (token.len > 0) token else null,
    };
    try w.writeAll("CONNECT ");
    try std.json.Stringify.value(opt, .{ .emit_null_optional_fields = false }, w);
    try w.writeAll("\r\n");
}

fn parseInfo(gpa: std.mem.Allocator, json: []const u8) target.SendError!bool {
    const Info = struct { tls_required: bool = false };
    const p = std.json.parseFromSlice(Info, gpa, json, .{ .ignore_unknown_fields = true }) catch |e|
        return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
    defer p.deinit();
    return p.value.tls_required;
}

/// True for a JetStream PubAck; false for an error reply or a status-only header (503).
pub fn ackOk(gpa: std.mem.Allocator, hdr: []const u8, payload: []const u8) error{OutOfMemory}!bool {
    if (hdr.len > 0) {
        const first = hdr[0 .. std.mem.indexOfScalar(u8, hdr, '\r') orelse hdr.len];
        var it = std.mem.tokenizeScalar(u8, first, ' ');
        _ = it.next();
        if (it.next()) |code| if (code.len > 0 and code[0] >= '3') return false;
    }
    const Ack = struct { stream: ?[]const u8 = null, seq: ?u64 = null, @"error": ?std.json.Value = null };
    const p = std.json.parseFromSlice(Ack, gpa, payload, .{ .ignore_unknown_fields = true }) catch |e|
        return if (e == error.OutOfMemory) error.OutOfMemory else false;
    defer p.deinit();
    return p.value.@"error" == null and p.value.stream != null and p.value.seq != null;
}

fn readLine(c: *net.Conn) target.SendError![]const u8 {
    const raw = c.reader().takeDelimiterInclusive('\n') catch return error.Unreachable;
    return std.mem.trimRight(u8, raw, "\r\n");
}

const Msg = struct { buf: []u8, subject: []const u8, hdr: []const u8, payload: []const u8 };
const Op = union(enum) { pong, err, msg: Msg };

/// Next meaningful server op; answers PING, skips +OK and INFO. MSG buffers are caller-owned.
fn next(gpa: std.mem.Allocator, c: *net.Conn) target.SendError!Op {
    var guard: u32 = 0;
    while (guard < 1024) : (guard += 1) {
        const line = try readLine(c);
        if (std.ascii.startsWithIgnoreCase(line, "PING")) {
            c.writer().writeAll("PONG\r\n") catch return error.Unreachable;
            c.flush() catch return error.Unreachable;
            continue;
        }
        if (std.ascii.startsWithIgnoreCase(line, "PONG")) return .pong;
        if (std.ascii.startsWithIgnoreCase(line, "+OK") or std.ascii.startsWithIgnoreCase(line, "INFO")) continue;
        if (std.ascii.startsWithIgnoreCase(line, "-ERR")) return .err;
        if (std.ascii.startsWithIgnoreCase(line, "MSG ") or std.ascii.startsWithIgnoreCase(line, "HMSG ")) return .{ .msg = try readMsg(gpa, c, line) };
        return error.Unreachable;
    }
    return error.Unreachable;
}

fn readMsg(gpa: std.mem.Allocator, c: *net.Conn, line: []const u8) target.SendError!Msg {
    var tok: [7][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |t| {
        if (n == tok.len) return error.Unreachable;
        tok[n] = t;
        n += 1;
    }
    const with_hdr = line[0] == 'H' or line[0] == 'h';
    const min: usize = if (with_hdr) 5 else 4;
    if (n != min and n != min + 1) return error.Unreachable;
    const total = std.fmt.parseInt(usize, tok[n - 1], 10) catch return error.Unreachable;
    const hdr_len = if (with_hdr) std.fmt.parseInt(usize, tok[n - 2], 10) catch return error.Unreachable else 0;
    if (total > max_payload or hdr_len > total) return error.Unreachable;
    const subj = tok[1];
    const buf = try gpa.alloc(u8, subj.len + total + 2);
    errdefer gpa.free(buf);
    @memcpy(buf[0..subj.len], subj);
    c.reader().readSliceAll(buf[subj.len..]) catch return error.Unreachable;
    if (!std.mem.endsWith(u8, buf, "\r\n")) return error.Unreachable;
    const data = buf[subj.len .. subj.len + total];
    return .{ .buf = buf, .subject = buf[0..subj.len], .hdr = data[0..hdr_len], .payload = data[hdr_len..] };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "connect json" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeConnect(&w, "u\"x", "p", "");
    try testing.expectEqualStrings(
        "CONNECT {\"verbose\":false,\"pedantic\":false,\"user\":\"u\\\"x\",\"pass\":\"p\",\"headers\":true,\"no_responders\":true,\"protocol\":1,\"lang\":\"zig\",\"name\":\"zkfsm\"}\r\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try writeConnect(&w, "", "", "tok");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"auth_token\":\"tok\"") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"user\"") == null);
}

test "settings validation" {
    const gpa = testing.allocator;
    const bad = [_][]const target.Kv{
        &.{.{ .key = "subject", .value = "a" }},
        &.{.{ .key = "address", .value = "h:1" }},
        &.{ .{ .key = "address", .value = "h:x" }, .{ .key = "subject", .value = "a" } },
        &.{ .{ .key = "address", .value = "h" }, .{ .key = "subject", .value = "a b" } },
        &.{ .{ .key = "address", .value = "h" }, .{ .key = "subject", .value = "a.>" } },
        &.{ .{ .key = "address", .value = "h" }, .{ .key = "subject", .value = "a" }, .{ .key = "streaming", .value = "on" } },
        &.{ .{ .key = "address", .value = "h" }, .{ .key = "subject", .value = "a" }, .{ .key = "client_cert", .value = "c.pem" } },
        &.{ .{ .key = "address", .value = "h" }, .{ .key = "subject", .value = "a" }, .{ .key = "ping_interval", .value = "x" } },
    };
    for (bad) |kvs| try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = kvs }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "nats://h:5" }, .{ .key = "subject", .value = "a.b" }, .{ .key = "jetstream", .value = "on" } } });
    defer c.deinit();
    const n: *Nats = @ptrCast(@alignCast(c.ctx));
    try testing.expectEqualStrings("h", n.host);
    try testing.expectEqual(@as(u16, 5), n.port);
    try testing.expect(n.jetstream);
}

test "ack parsing" {
    const gpa = testing.allocator;
    try testing.expect(try ackOk(gpa, "", "{\"stream\":\"S\",\"seq\":3}"));
    try testing.expect(!try ackOk(gpa, "", "{\"error\":{\"code\":503,\"description\":\"x\"}}"));
    try testing.expect(!try ackOk(gpa, "NATS/1.0 503\r\n\r\n", ""));
    try testing.expect(!try ackOk(gpa, "", "garbage"));
}

const Fake = struct {
    srv: std.net.Server,
    js: bool = false,
    err_on_pub: bool = false,
    got: [256]u8 = undefined,
    got_len: usize = 0,

    fn run(f: *Fake) void {
        f.serve() catch {};
    }

    fn serve(f: *Fake) !void {
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const r = sr.interface();
        const w = &sw.interface;
        try w.writeAll("INFO {\"server_id\":\"x\",\"headers\":true}\r\n");
        try w.flush();
        while (true) {
            const l = try r.takeDelimiterInclusive('\n');
            if (std.mem.startsWith(u8, l, "PING")) break;
        }
        try w.writeAll("PING\r\nPONG\r\n");
        try w.flush();
        var line = try r.takeDelimiterInclusive('\n');
        if (std.mem.startsWith(u8, line, "PONG")) line = try r.takeDelimiterInclusive('\n');
        var it = std.mem.tokenizeAny(u8, line, " \r\n");
        _ = it.next();
        _ = it.next();
        var reply: [64]u8 = undefined;
        var reply_len: usize = 0;
        var len_tok = it.next().?;
        if (it.next()) |t| {
            reply_len = len_tok.len;
            @memcpy(reply[0..reply_len], len_tok);
            len_tok = t;
        }
        const len = try std.fmt.parseInt(usize, len_tok, 10);
        try r.readSliceAll(f.got[0 .. len + 2]);
        f.got_len = len;
        if (f.err_on_pub) {
            try w.writeAll("-ERR 'Permissions Violation'\r\n");
        } else if (f.js) {
            const ack = "{\"stream\":\"S\",\"seq\":1}";
            try w.print("MSG {s} 1 {d}\r\n{s}\r\n", .{ reply[0..reply_len], ack.len, ack });
        } else {
            _ = try r.takeDelimiterInclusive('\n');
            try w.writeAll("PONG\r\n");
        }
        try w.flush();
        _ = r.takeByte() catch {};
    }
};

fn fakeRun(js: bool, err_on_pub: bool) !void {
    const gpa = testing.allocator;
    var f: Fake = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .js = js, .err_on_pub = err_on_pub };
    defer f.srv.deinit();
    var abuf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&abuf, "127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "subject", .value = "ev.x" }, .{ .key = "jetstream", .value = if (js) "on" else "off" } } });
    defer c.deinit();
    const t = try std.Thread.spawn(.{}, Fake.run, .{&f});
    const res = c.send(&.{ .body = "{\"k\":1}" });
    @as(*Nats, @ptrCast(@alignCast(c.ctx))).drop();
    t.join();
    if (err_on_pub) return testing.expectError(error.Rejected, res);
    try res;
    try testing.expectEqualStrings("{\"k\":1}", f.got[0..f.got_len]);
}

test "fake broker publish" {
    try fakeRun(false, false);
}

test "fake broker jetstream ack" {
    try fakeRun(true, false);
}

test "fake broker -ERR is rejected" {
    try fakeRun(false, true);
}

test "unreachable broker" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "address", .value = "127.0.0.1:1" }, .{ .key = "subject", .value = "a" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .body = "x" }));
}

// Live tests: ZKFSM_TEST_NATS=host:port (server started with -js).

fn liveAddr() ![]const u8 {
    return std.posix.getenv("ZKFSM_TEST_NATS") orelse error.SkipZigTest;
}

/// Plain subscriber connection used to observe deliveries.
fn liveSub(gpa: std.mem.Allocator, addr: []const u8, subj: []const u8) !*net.Conn {
    const hp = try net.splitHostPort(addr, default_port);
    const c = try net.dial(gpa, hp[0], hp[1], .{});
    errdefer c.close();
    _ = try readLine(c);
    try c.writer().print("CONNECT {{\"verbose\":false,\"headers\":true,\"no_responders\":true,\"protocol\":1}}\r\nSUB {s} 1\r\nPING\r\n", .{subj});
    try c.flush();
    while (try next(gpa, c) != .pong) {}
    return c;
}

fn awaitMsg(gpa: std.mem.Allocator, c: *net.Conn) !Msg {
    while (true) switch (try next(gpa, c)) {
        .msg => |m| return m,
        .err => return error.TestUnexpectedResult,
        .pong => {},
    };
}

test "events live nats" {
    const addr = try liveAddr();
    const gpa = testing.allocator;
    const sub = try liveSub(gpa, addr, "zkev.core.>");
    defer sub.close();
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "subject", .value = "zkev.core.a" } } });
    defer c.deinit();
    for (0..3) |i| {
        var b: [32]u8 = undefined;
        const body = try std.fmt.bufPrint(&b, "{{\"n\":{d}}}", .{i});
        try c.send(&.{ .body = body });
        const m = try awaitMsg(gpa, sub);
        defer gpa.free(m.buf);
        try testing.expectEqualStrings("zkev.core.a", m.subject);
        try testing.expectEqualStrings(body, m.payload);
    }
}

test "events live nats jetstream" {
    const addr = try liveAddr();
    const gpa = testing.allocator;
    // Create (or find) the stream through the JS API on a fresh server.
    const api = try liveSub(gpa, addr, "_INBOX.zkevtest.>");
    defer api.close();
    const cfg = "{\"name\":\"ZKEVJS\",\"subjects\":[\"zkev.js.>\"],\"storage\":\"memory\"}";
    try api.writer().print("PUB $JS.API.STREAM.CREATE.ZKEVJS _INBOX.zkevtest.1 {d}\r\n{s}\r\n", .{ cfg.len, cfg });
    try api.flush();
    const created = try awaitMsg(gpa, api);
    gpa.free(created.buf);

    const sub = try liveSub(gpa, addr, "zkev.js.>");
    defer sub.close();
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "subject", .value = "zkev.js.a" }, .{ .key = "jetstream", .value = "on" } } });
    defer c.deinit();
    try c.send(&.{ .body = "{\"js\":1}" });
    try c.send(&.{ .body = "{\"js\":2}" });
    for ([_][]const u8{ "{\"js\":1}", "{\"js\":2}" }) |want| {
        const m = try awaitMsg(gpa, sub);
        defer gpa.free(m.buf);
        try testing.expectEqualStrings(want, m.payload);
    }
    // No stream covers this subject: the server answers 503 no responders.
    const none = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "subject", .value = "zkev.nostream.a" }, .{ .key = "jetstream", .value = "on" } } });
    defer none.deinit();
    try testing.expectError(error.Rejected, none.send(&.{ .body = "x" }));
}
