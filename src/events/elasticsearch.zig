//! Elasticsearch notification target: a small HTTP/1.1 client that indexes
//! events as documents (namespace: one doc per object key, access: append-only).
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "url", "format", "index", "username", "password", "queue_dir", "queue_limit", "comment" };

/// Response bounds; anything larger is treated as a transport failure.
pub const max_body = 1024 * 1024;
pub const max_headers = 100;
pub const max_index = 255;

pub const Method = enum { PUT, POST, DELETE };

pub const Url = struct {
    tls: bool,
    host: []const u8,
    port: u16,
    user: []const u8,
    password: []const u8,
};

/// Parses `http(s)://[user:pass@]host[:port][/]`; userinfo stays percent-encoded.
pub fn parseUrl(s: []const u8) error{InvalidConfig}!Url {
    var rest: []const u8 = undefined;
    var tls = false;
    if (std.ascii.startsWithIgnoreCase(s, "http://")) {
        rest = s[7..];
    } else if (std.ascii.startsWithIgnoreCase(s, "https://")) {
        rest = s[8..];
        tls = true;
    } else return error.InvalidConfig;
    if (std.mem.endsWith(u8, rest, "/")) rest = rest[0 .. rest.len - 1];
    if (std.mem.indexOfAny(u8, rest, "/?#") != null) return error.InvalidConfig;
    var user: []const u8 = "";
    var password: []const u8 = "";
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| {
        const info = rest[0..at];
        rest = rest[at + 1 ..];
        const colon = std.mem.indexOfScalar(u8, info, ':') orelse info.len;
        user = info[0..colon];
        if (colon < info.len) password = info[colon + 1 ..];
        if (user.len == 0) return error.InvalidConfig;
    }
    const hp = net.splitHostPort(rest, 9200) catch return error.InvalidConfig;
    if (hp[0].len == 0 or hp[1] == 0) return error.InvalidConfig;
    return .{ .tls = tls, .host = hp[0], .port = hp[1], .user = user, .password = password };
}

/// Index names per ES rules: lowercase, no path/wildcard characters, bounded.
pub fn validIndex(s: []const u8) bool {
    if (s.len == 0 or s.len > max_index) return false;
    if (std.mem.eql(u8, s, ".") or std.mem.eql(u8, s, "..")) return false;
    if (s[0] == '-' or s[0] == '_' or s[0] == '+') return false;
    for (s) |c| {
        if (std.ascii.isUpper(c) or c <= ' ' or c >= 0x7f) return false;
        if (std.mem.indexOfScalar(u8, "\\/*?\"<>|,#:", c) != null) return false;
    }
    return true;
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
pub fn writeEscaped(w: *std.Io.Writer, s: []const u8) error{WriteFailed}!void {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            try w.writeByte(c);
        } else try w.print("%{X:0>2}", .{c});
    }
}

/// Writes one request; `auth` is the base64 basic credential or empty.
pub fn writeRequest(w: *std.Io.Writer, method: Method, host: []const u8, port: u16, path_index: []const u8, doc_id: ?[]const u8, auth: []const u8, body: []const u8) error{WriteFailed}!void {
    try w.print("{s} /{s}/_doc", .{ @tagName(method), path_index });
    if (doc_id) |id| {
        try w.writeByte('/');
        try writeEscaped(w, id);
    }
    const bracket = std.mem.indexOfScalar(u8, host, ':') != null;
    if (bracket) try w.print(" HTTP/1.1\r\nHost: [{s}]:{d}\r\n", .{ host, port }) else try w.print(" HTTP/1.1\r\nHost: {s}:{d}\r\n", .{ host, port });
    if (auth.len > 0) try w.print("Authorization: Basic {s}\r\n", .{auth});
    if (method != .DELETE) try w.writeAll("Content-Type: application/json\r\n");
    try w.print("Content-Length: {d}\r\n\r\n", .{body.len});
    try w.writeAll(body);
}

pub const Response = struct {
    status: u16,
    /// The server asked to close, or the body ran to EOF.
    close: bool,
};

pub const ResponseError = error{ Protocol, ReadFailed, EndOfStream };

fn line(r: *std.Io.Reader) ResponseError![]const u8 {
    const l = r.takeDelimiterInclusive('\n') catch |e| return switch (e) {
        error.StreamTooLong => error.Protocol,
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream => error.EndOfStream,
    };
    if (l.len < 2 or l[l.len - 2] != '\r') return error.Protocol;
    return l[0 .. l.len - 2];
}

fn discard(r: *std.Io.Reader, n: u64) ResponseError!void {
    r.discardAll64(n) catch |e| return switch (e) {
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream => error.EndOfStream,
    };
}

/// Reads status line, headers and body (discarded, at most `max_body` bytes).
pub fn readResponse(r: *std.Io.Reader, method_head: bool) ResponseError!Response {
    const status_line = try line(r);
    if (status_line.len < 12 or !std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.Protocol;
    if (status_line[12 - 4] != ' ') return error.Protocol;
    const status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.Protocol;
    if (status < 100 or status > 599) return error.Protocol;
    var close = status_line[7] == '0';
    var length: ?u64 = null;
    var chunked = false;
    var n: usize = 0;
    while (true) : (n += 1) {
        if (n > max_headers) return error.Protocol;
        const h = try line(r);
        if (h.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.Protocol;
        const name = h[0..colon];
        const value = std.mem.trim(u8, h[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const v = std.fmt.parseInt(u64, value, 10) catch return error.Protocol;
            if (length != null and length.? != v) return error.Protocol;
            length = v;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.Protocol;
            chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.eqlIgnoreCase(value, "close")) close = true;
        }
    }
    if (method_head or status == 204 or status == 304 or status < 200) return .{ .status = status, .close = close };
    if (chunked) {
        var total: u64 = 0;
        while (true) {
            const l = try line(r);
            const semi = std.mem.indexOfScalar(u8, l, ';') orelse l.len;
            const size = std.fmt.parseInt(u64, std.mem.trim(u8, l[0..semi], " \t"), 16) catch return error.Protocol;
            total += size;
            if (total > max_body) return error.Protocol;
            if (size == 0) break;
            try discard(r, size);
            if ((try line(r)).len != 0) return error.Protocol;
        }
        var t: usize = 0;
        while ((try line(r)).len != 0) : (t += 1) if (t > max_headers) return error.Protocol;
        return .{ .status = status, .close = close };
    }
    if (length) |len| {
        if (len > max_body) return error.Protocol;
        try discard(r, len);
        return .{ .status = status, .close = close };
    }
    // No framing: the body runs to EOF.
    var left: usize = max_body;
    while (left > 0) {
        const got = r.discard(.limited(left)) catch |e| switch (e) {
            error.EndOfStream => return .{ .status = status, .close = true },
            error.ReadFailed => return error.ReadFailed,
        };
        left -= got;
    }
    return error.Protocol;
}

const Elastic = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    url: Url,
    index: []const u8,
    auth: []const u8,
    format: target.Format,
    conn: ?*net.Conn = null,

    const Fail = target.SendError;

    fn drop(self: *Elastic) void {
        if (self.conn) |c| c.close();
        self.conn = null;
    }

    fn sendOnce(self: *Elastic, msg: *const target.Message) Fail!void {
        if (self.conn == null) {
            self.conn = net.dial(self.gpa, self.url.host, self.url.port, .{ .tls = if (self.url.tls) .{} else null }) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.Unreachable,
            };
        }
        const c = self.conn.?;
        const w = c.writer();
        var delete = false;
        switch (self.format) {
            .namespace => if (msg.removed) {
                delete = true;
                writeRequest(w, .DELETE, self.url.host, self.url.port, self.index, msg.key, self.auth, "") catch return error.Unreachable;
            } else {
                const doc = std.fmt.allocPrint(self.gpa, "{{\"Records\":[{s}]}}", .{msg.record}) catch return error.OutOfMemory;
                defer self.gpa.free(doc);
                writeRequest(w, .PUT, self.url.host, self.url.port, self.index, msg.key, self.auth, doc) catch return error.Unreachable;
            },
            .access => {
                const body = accessBody(self.gpa, msg) catch return error.OutOfMemory;
                defer self.gpa.free(body);
                writeRequest(w, .POST, self.url.host, self.url.port, self.index, null, self.auth, body) catch return error.Unreachable;
            },
        }
        c.flush() catch return error.Unreachable;
        const rep = readResponse(c.reader(), false) catch return error.Unreachable;
        if (rep.close) self.drop();
        if (rep.status >= 200 and rep.status < 300) return;
        if (delete and rep.status == 404) return;
        return error.Rejected;
    }

    fn send(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const self: *Elastic = @ptrCast(@alignCast(ctx));
        self.sendOnce(msg) catch |e| {
            if (e != error.Rejected) self.drop();
            return e;
        };
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *Elastic = @ptrCast(@alignCast(ctx));
        self.drop();
        self.arena.deinit();
        self.gpa.destroy(self);
    }

    const vtable: target.Client.VTable = .{ .send = send, .deinit = deinit };
};

/// Access document: `{"Records":[<record>],"EventTime":"<time>"}`.
pub fn accessBody(gpa: std.mem.Allocator, msg: *const target.Message) error{OutOfMemory}![]u8 {
    const record = if (msg.record.len > 0) msg.record else "null";
    return std.fmt.allocPrint(gpa, "{{\"Records\":[{s}],\"EventTime\":{f}}}", .{ record, std.json.fmt(msg.event_time, .{}) });
}

/// Validates settings and builds a client; the connection opens on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const url = try parseUrl(s.get("url"));
    const format = try target.Format.parse(s.get("format"));
    const index = s.get("index");
    if (!validIndex(index)) return error.InvalidConfig;
    _ = try s.int(u64, "queue_limit", 0);
    const self = try gpa.create(Elastic);
    errdefer gpa.destroy(self);
    self.* = .{ .gpa = gpa, .arena = .init(gpa), .url = url, .index = "", .auth = "", .format = format };
    errdefer self.arena.deinit();
    const a = self.arena.allocator();
    self.url.host = try a.dupe(u8, url.host);
    self.index = try a.dupe(u8, index);
    var user: []const u8 = s.get("username");
    var pass: []const u8 = s.get("password");
    if (user.len == 0 and url.user.len > 0) {
        user = std.Uri.percentDecodeInPlace(try a.dupe(u8, url.user));
        pass = std.Uri.percentDecodeInPlace(try a.dupe(u8, url.password));
    }
    if (user.len == 0 and pass.len > 0) return error.InvalidConfig;
    if (std.mem.indexOfScalar(u8, user, ':') != null) return error.InvalidConfig;
    if (user.len > 0) {
        const raw = try std.fmt.allocPrint(a, "{s}:{s}", .{ user, pass });
        const enc = std.base64.standard.Encoder;
        const out = try a.alloc(u8, enc.calcSize(raw.len));
        self.auth = enc.encode(out, raw);
    }
    return .{ .ctx = self, .vtable = &Elastic.vtable };
}

// ---- tests ----

const testing = std.testing;

test "url and index validation" {
    const u = try parseUrl("https://el%40stic:p:w@es.local:9243/");
    try testing.expect(u.tls);
    try testing.expectEqualStrings("es.local", u.host);
    try testing.expectEqual(@as(u16, 9243), u.port);
    try testing.expectEqualStrings("el%40stic", u.user);
    try testing.expectEqualStrings("p:w", u.password);
    try testing.expectEqual(@as(u16, 9200), (try parseUrl("http://es")).port);
    try testing.expectEqualStrings("::1", (try parseUrl("http://[::1]:9201")).host);
    for ([_][]const u8{ "", "es:9200", "ftp://es", "http://es/x", "http://:9200", "http://es:0", "http://es:x", "http://@es" }) |b|
        try testing.expectError(error.InvalidConfig, parseUrl(b));
    try testing.expect(validIndex("minio-events.v1"));
    for ([_][]const u8{ "", "Upper", "a/b", "_x", "-x", "a b", "a*", ".." }) |b| try testing.expect(!validIndex(b));
}

test "request encoding" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeRequest(&w, .PUT, "es", 9200, "ev", "b/a b+c", "dTpw", "{}");
    try testing.expectEqualStrings("PUT /ev/_doc/b%2Fa%20b%2Bc HTTP/1.1\r\nHost: es:9200\r\nAuthorization: Basic dTpw\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", w.buffered());
    w = .fixed(&buf);
    try writeRequest(&w, .DELETE, "::1", 1, "ev", "k", "", "");
    try testing.expectEqualStrings("DELETE /ev/_doc/k HTTP/1.1\r\nHost: [::1]:1\r\nContent-Length: 0\r\n\r\n", w.buffered());
    const body = try accessBody(testing.allocator, &.{ .body = "", .record = "{\"a\":1}", .event_time = "2026-01-01T00:00:00Z" });
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("{\"Records\":[{\"a\":1}],\"EventTime\":\"2026-01-01T00:00:00Z\"}", body);
}

test "response parsing" {
    var r: std.Io.Reader = .fixed("HTTP/1.1 201 Created\r\ncontent-length: 3\r\n\r\nabcHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x\r\nabc\r\n0\r\n\r\nHTTP/1.0 404 NF\r\n\r\nrest");
    const a = try readResponse(&r, false);
    try testing.expectEqual(@as(u16, 201), a.status);
    try testing.expect(!a.close);
    try testing.expectEqual(@as(u16, 200), (try readResponse(&r, false)).status);
    const c = try readResponse(&r, false);
    try testing.expectEqual(@as(u16, 404), c.status);
    try testing.expect(c.close);
    const bad = [_][]const u8{ "HTTP/1.1 2x0 OK\r\n\r\n", "SMTP 220\r\n\r\n", "HTTP/1.1 200 OK\nx", "HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFF\r\n", "HTTP/1.1 200 OK\r\nnocolon\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n" };
    for (bad) |b| {
        var br: std.Io.Reader = .fixed(b);
        try testing.expectError(error.Protocol, readResponse(&br, false));
    }
    var short: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab");
    try testing.expectError(error.EndOfStream, readResponse(&short, false));
}

test "settings validation" {
    const gpa = testing.allocator;
    const bad = [_][]const target.Kv{
        &.{.{ .key = "index", .value = "ev" }},
        &.{.{ .key = "url", .value = "http://es" }},
        &.{ .{ .key = "url", .value = "http://es" }, .{ .key = "index", .value = "EV" } },
        &.{ .{ .key = "url", .value = "http://es" }, .{ .key = "index", .value = "ev" }, .{ .key = "format", .value = "x" } },
        &.{ .{ .key = "url", .value = "http://es" }, .{ .key = "index", .value = "ev" }, .{ .key = "password", .value = "p" } },
        &.{ .{ .key = "url", .value = "http://es" }, .{ .key = "index", .value = "ev" }, .{ .key = "queue_limit", .value = "-1" } },
    };
    for (bad) |kvs| try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = kvs }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = "https://u:p%21@es" }, .{ .key = "index", .value = "ev" }, .{ .key = "format", .value = "access" } } });
    const self: *Elastic = @ptrCast(@alignCast(c.ctx));
    try testing.expectEqualStrings("dTpwIQ==", self.auth);
    c.deinit();
}

// Scripted peer: for each step, read exactly `expect[i]` then write `reply[i]`.
const FakeServer = struct {
    srv: std.net.Server,
    expect: []const []const u8,
    reply: []const []const u8,
    got: [2048]u8 = undefined,
    got_len: usize = 0,

    fn run(f: *FakeServer) void {
        const conn = f.srv.accept() catch return;
        defer conn.stream.close();
        for (f.expect, f.reply) |e, rep| {
            const end = f.got_len + e.len;
            while (f.got_len < end) {
                const n = conn.stream.read(f.got[f.got_len..end]) catch return;
                if (n == 0) return;
                f.got_len += n;
            }
            conn.stream.writeAll(rep) catch return;
        }
    }
};

const ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";

test "fake server: namespace put + delete, access, 404 delete, 4xx and garbage" {
    // Each scenario binds its own listener; host header carries that port.
    try scenario("namespace", &.{
        .{ .key = "b/o", .body = "{}", .record = "{\"r\":1}" },
        .{ .key = "b/o", .body = "{}", .removed = true },
    }, &.{ .{ "PUT", "/ev/_doc/b%2Fo", "{\"Records\":[{\"r\":1}]}" }, .{ "DELETE", "/ev/_doc/b%2Fo", "" } }, &.{ "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" }, null);
    try scenario("access", &.{.{ .key = "b/o", .body = "{}", .record = "{}", .event_time = "T" }}, &.{.{ "POST", "/ev/_doc", "{\"Records\":[{}],\"EventTime\":\"T\"}" }}, &.{ok}, null);
    try scenario("namespace", &.{.{ .key = "k", .body = "{}", .record = "{}" }}, &.{.{ "PUT", "/ev/_doc/k", "{\"Records\":[{}]}" }}, &.{"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\n{}"}, error.Rejected);
    try scenario("namespace", &.{.{ .key = "k", .body = "{}", .record = "{}" }}, &.{.{ "PUT", "/ev/_doc/k", "{\"Records\":[{}]}" }}, &.{"HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"}, error.Rejected);
    try scenario("namespace", &.{.{ .key = "k", .body = "{}", .record = "{}" }}, &.{.{ "PUT", "/ev/_doc/k", "{\"Records\":[{}]}" }}, &.{"garbage\r\n\r\n"}, error.Unreachable);
}

fn scenario(format: []const u8, msgs: []const target.Message, reqs: []const struct { []const u8, []const u8, []const u8 }, replies: []const []const u8, want: ?target.SendError) !void {
    var f: FakeServer = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .expect = &.{}, .reply = replies };
    defer f.srv.deinit();
    const port = f.srv.listen_address.getPort();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const expect = try a.alloc([]const u8, reqs.len);
    for (reqs, expect) |r, *e| {
        const ct = if (std.mem.eql(u8, r[0], "DELETE")) "" else "Content-Type: application/json\r\n";
        e.* = try std.fmt.allocPrint(a, "{s} {s} HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Basic dTpw\r\n{s}Content-Length: {d}\r\n\r\n{s}", .{ r[0], r[1], port, ct, r[2].len, r[2] });
    }
    f.expect = expect;
    const url = try std.fmt.allocPrint(a, "http://u:p@127.0.0.1:{d}", .{port});
    const t = try std.Thread.spawn(.{}, FakeServer.run, .{&f});
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "url", .value = url }, .{ .key = "index", .value = "ev" }, .{ .key = "format", .value = format } } });
    var res: target.SendError!void = {};
    for (msgs) |*m| {
        res = c.send(m);
        res catch break;
    }
    c.deinit();
    t.join();
    try testing.expectEqualStrings(try std.mem.concat(a, u8, expect), f.got[0..f.got_len]);
    if (want) |w| try testing.expectError(w, res) else try res;
}

test "unreachable server" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "url", .value = "http://127.0.0.1:1" }, .{ .key = "index", .value = "ev" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .key = "a", .body = "{}", .record = "{}" }));
}

test "events live elasticsearch" {
    const url = std.posix.getenv("ZKFSM_TEST_ELASTICSEARCH") orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    {
        const c = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = url }, .{ .key = "index", .value = "zkev-ns" } } });
        defer c.deinit();
        try c.send(&.{ .key = "b/o", .body = "{}", .record = "{\"n\":1}" });
        try c.send(&.{ .key = "b/o", .body = "{}", .removed = true });
        try c.send(&.{ .key = "b/o", .body = "{}", .removed = true });
    }
    {
        const c = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = url }, .{ .key = "index", .value = "zkev-log" }, .{ .key = "format", .value = "access" } } });
        defer c.deinit();
        try c.send(&.{ .key = "b/o", .body = "{}", .record = "{\"n\":2}", .event_time = "2026-01-01T00:00:00Z" });
        try testing.expectError(error.Rejected, c.send(&.{ .key = "b/o", .body = "{}", .record = "not json", .event_time = "x" }));
    }
}
