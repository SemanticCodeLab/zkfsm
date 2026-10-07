//! Redis notification target: a small RESP2 client that writes events as
//! hash fields (namespace), list entries (access) or channel messages (pubsub).
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "address", "key", "format", "password", "user", "tls", "tls_skip_verify", "queue_dir", "queue_limit", "comment" };

pub const Mode = enum { namespace, access, pubsub };

/// Wire bounds for replies; anything larger is treated as a protocol failure.
pub const max_line = 64 * 1024;
pub const max_bulk = 16 * 1024 * 1024;
pub const max_array = 1024 * 1024;
pub const max_depth = 8;

pub const Reply = union(enum) {
    simple: []const u8,
    err: []const u8,
    int: i64,
    bulk: ?[]const u8,
    array: ?[]const Reply,
};

pub const ReplyError = error{ Protocol, ReadFailed, EndOfStream, OutOfMemory };

/// Writes one command as a RESP array of bulk strings.
pub fn writeCommand(w: *std.Io.Writer, args: []const []const u8) error{WriteFailed}!void {
    try w.print("*{d}\r\n", .{args.len});
    for (args) |a| {
        try w.print("${d}\r\n", .{a.len});
        try w.writeAll(a);
        try w.writeAll("\r\n");
    }
}

fn readLine(r: *std.Io.Reader) ReplyError![]const u8 {
    const line = r.takeDelimiterInclusive('\n') catch |e| return switch (e) {
        error.StreamTooLong => error.Protocol,
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream => error.EndOfStream,
    };
    if (line.len < 2 or line[line.len - 2] != '\r' or line.len > max_line) return error.Protocol;
    return line[0 .. line.len - 2];
}

/// Reads one reply; strings are allocated from `a` (use an arena).
pub fn readReply(r: *std.Io.Reader, a: std.mem.Allocator) ReplyError!Reply {
    return readDepth(r, a, 0);
}

fn readDepth(r: *std.Io.Reader, a: std.mem.Allocator, depth: usize) ReplyError!Reply {
    if (depth > max_depth) return error.Protocol;
    const line = try readLine(r);
    if (line.len == 0) return error.Protocol;
    const rest = line[1..];
    switch (line[0]) {
        '+' => return .{ .simple = try a.dupe(u8, rest) },
        '-' => return .{ .err = try a.dupe(u8, rest) },
        ':' => return .{ .int = std.fmt.parseInt(i64, rest, 10) catch return error.Protocol },
        '$' => {
            const n = std.fmt.parseInt(i64, rest, 10) catch return error.Protocol;
            if (n == -1) return .{ .bulk = null };
            if (n < 0 or n > max_bulk) return error.Protocol;
            const body = r.readAlloc(a, @intCast(n)) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.ReadFailed => error.ReadFailed,
                error.EndOfStream => error.EndOfStream,
            };
            const crlf = r.take(2) catch |e| return switch (e) {
                error.ReadFailed => error.ReadFailed,
                error.EndOfStream => error.EndOfStream,
            };
            if (!std.mem.eql(u8, crlf, "\r\n")) return error.Protocol;
            return .{ .bulk = body };
        },
        '*' => {
            const n = std.fmt.parseInt(i64, rest, 10) catch return error.Protocol;
            if (n == -1) return .{ .array = null };
            if (n < 0 or n > max_array) return error.Protocol;
            const items = try a.alloc(Reply, @intCast(n));
            for (items) |*it| it.* = try readDepth(r, a, depth + 1);
            return .{ .array = items };
        },
        else => return error.Protocol,
    }
}

const Redis = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    host: []const u8,
    port: u16,
    key: []const u8,
    user: []const u8,
    password: []const u8,
    mode: Mode,
    tls: ?net.TlsOptions,
    conn: ?*net.Conn = null,

    const Fail = error{ Unreachable, Rejected, OutOfMemory };

    fn drop(self: *Redis) void {
        if (self.conn) |c| c.close();
        self.conn = null;
    }

    // One round trip; an error reply becomes Rejected, the stream stays in sync.
    fn call(self: *Redis, args: []const []const u8) Fail!void {
        const c = self.conn orelse return error.Unreachable;
        writeCommand(c.writer(), args) catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const rep = readReply(c.reader(), arena.allocator()) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unreachable,
        };
        if (rep == .err) return error.Rejected;
    }

    fn connect(self: *Redis) Fail!void {
        if (self.conn != null) return;
        self.conn = net.dial(self.gpa, self.host, self.port, .{ .tls = self.tls }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unreachable,
        };
        if (self.password.len == 0) return;
        const r = if (self.user.len > 0)
            self.call(&.{ "AUTH", self.user, self.password })
        else
            self.call(&.{ "AUTH", self.password });
        r catch |e| {
            self.drop();
            return e;
        };
    }

    fn sendOnce(self: *Redis, msg: *const target.Message) Fail!void {
        try self.connect();
        switch (self.mode) {
            .namespace => if (msg.removed)
                try self.call(&.{ "HDEL", self.key, msg.key })
            else {
                // Namespace values are `{"Records":[record]}`, as consumers of this format expect.
                const v = std.fmt.allocPrint(self.gpa, "{{\"Records\":[{s}]}}", .{msg.record}) catch return error.OutOfMemory;
                defer self.gpa.free(v);
                try self.call(&.{ "HSET", self.key, msg.key, v });
            },
            .access => {
                const v = std.fmt.allocPrint(self.gpa, "[{{\"Event\":[{s}],\"EventTime\":\"{s}\"}}]", .{ msg.record, msg.event_time }) catch return error.OutOfMemory;
                defer self.gpa.free(v);
                try self.call(&.{ "RPUSH", self.key, v });
            },
            .pubsub => try self.call(&.{ "PUBLISH", self.key, msg.body }),
        }
    }

    fn send(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const self: *Redis = @ptrCast(@alignCast(ctx));
        self.sendOnce(msg) catch |e| {
            if (e != error.Rejected) self.drop();
            return e;
        };
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *Redis = @ptrCast(@alignCast(ctx));
        self.drop();
        self.arena.deinit();
        self.gpa.destroy(self);
    }

    const vtable: target.Client.VTable = .{ .send = send, .deinit = deinit };
};

fn parseMode(s: []const u8) error{InvalidConfig}!Mode {
    if (std.ascii.eqlIgnoreCase(s, "pubsub")) return .pubsub;
    return switch (try target.Format.parse(s)) {
        .namespace => .namespace,
        .access => .access,
    };
}

/// Validates settings and builds a client; the connection opens on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const hp = net.splitHostPort(s.get("address"), 6379) catch return error.InvalidConfig;
    if (hp[0].len == 0 or hp[1] == 0) return error.InvalidConfig;
    const key = s.get("key");
    if (key.len == 0) return error.InvalidConfig;
    const mode = try parseMode(s.get("format"));
    if (s.get("user").len > 0 and s.get("password").len == 0) return error.InvalidConfig;
    _ = try s.int(u64, "queue_limit", 0);

    const self = try gpa.create(Redis);
    errdefer gpa.destroy(self);
    self.* = .{ .gpa = gpa, .arena = .init(gpa), .host = "", .port = hp[1], .key = "", .user = "", .password = "", .mode = mode, .tls = null };
    errdefer self.arena.deinit();
    const a = self.arena.allocator();
    self.host = try a.dupe(u8, hp[0]);
    self.key = try a.dupe(u8, key);
    self.user = try a.dupe(u8, s.get("user"));
    self.password = try a.dupe(u8, s.get("password"));
    if (s.flag("tls")) self.tls = .{ .skip_verify = s.flag("tls_skip_verify") };
    return .{ .ctx = self, .vtable = &Redis.vtable };
}

// ---- tests ----

const testing = std.testing;

test "resp command encoding" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeCommand(&w, &.{ "HSET", "k", "" });
    try testing.expectEqualStrings("*3\r\n$4\r\nHSET\r\n$1\r\nk\r\n$0\r\n\r\n", w.buffered());
}

test "resp reply parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var r: std.Io.Reader = .fixed("+OK\r\n-ERR bad\r\n:42\r\n$3\r\na\r\n\r\n$-1\r\n*2\r\n:1\r\n*1\r\n+x\r\n*-1\r\n");
    try testing.expectEqualStrings("OK", (try readReply(&r, a)).simple);
    try testing.expectEqualStrings("ERR bad", (try readReply(&r, a)).err);
    try testing.expectEqual(@as(i64, 42), (try readReply(&r, a)).int);
    try testing.expectEqualStrings("a\r\n", (try readReply(&r, a)).bulk.?);
    try testing.expect((try readReply(&r, a)).bulk == null);
    const arr = (try readReply(&r, a)).array.?;
    try testing.expectEqual(@as(i64, 1), arr[0].int);
    try testing.expectEqualStrings("x", arr[1].array.?[0].simple);
    try testing.expect((try readReply(&r, a)).array == null);
    try testing.expectError(error.EndOfStream, readReply(&r, a));
}

test "resp rejects malformed and oversized replies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const bad = [_][]const u8{ "?x\r\n", "+no-cr\n", ":abc\r\n", "$99999999999\r\n", "$-5\r\n", "*2000000\r\n", "$3\r\nabcXY", "\r\n" };
    for (bad) |b| {
        var r: std.Io.Reader = .fixed(b);
        try testing.expectError(error.Protocol, readReply(&r, arena.allocator()));
    }
    var deep: [64]u8 = undefined;
    for (deep[0..60], 0..) |*c, i| c.* = if (i % 4 == 0) '*' else if (i % 4 == 1) '1' else if (i % 4 == 2) '\r' else '\n';
    var r: std.Io.Reader = .fixed(deep[0..60]);
    try testing.expectError(error.Protocol, readReply(&r, arena.allocator()));
    var r2: std.Io.Reader = .fixed("$5\r\nab");
    try testing.expectError(error.EndOfStream, readReply(&r2, arena.allocator()));
}

test "settings validation" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{.{ .key = "key", .value = "k" }} }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{.{ .key = "address", .value = "h:1" }} }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "h:x" }, .{ .key = "key", .value = "k" } } }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "h" }, .{ .key = "key", .value = "k" }, .{ .key = "format", .value = "bogus" } } }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "h" }, .{ .key = "key", .value = "k" }, .{ .key = "user", .value = "u" } } }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "h" }, .{ .key = "key", .value = "k" }, .{ .key = "queue_limit", .value = "-1" } } }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = "h" }, .{ .key = "key", .value = "k" }, .{ .key = "format", .value = "PUBSUB" }, .{ .key = "tls", .value = "on" } } });
    c.deinit();
}

// Scripted peer: for each step, read exactly `expect[i]` then write `reply[i]`.
const FakeServer = struct {
    srv: std.net.Server,
    expect: []const []const u8,
    reply: []const []const u8,
    got: [1024]u8 = undefined,
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

fn fakeSend(mode: []const u8, msg: target.Message, expect: []const []const u8, reply: []const []const u8, password: []const u8) !void {
    var f: FakeServer = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .expect = expect, .reply = reply };
    defer f.srv.deinit();
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    const t = try std.Thread.spawn(.{}, FakeServer.run, .{&f});
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "key", .value = "ev" }, .{ .key = "format", .value = mode }, .{ .key = "password", .value = password } } });
    const res = c.send(&msg);
    c.deinit();
    t.join();
    const all = try std.mem.concat(testing.allocator, u8, expect);
    defer testing.allocator.free(all);
    try testing.expectEqualStrings(all, f.got[0..f.got_len]);
    return res;
}

test "fake server: namespace put, delete, access, pubsub, auth, error reply" {
    try fakeSend("namespace", .{ .key = "b/o", .body = "{}", .record = "{\"r\":1}" }, &.{"*4\r\n$4\r\nHSET\r\n$2\r\nev\r\n$3\r\nb/o\r\n$21\r\n{\"Records\":[{\"r\":1}]}\r\n"}, &.{":1\r\n"}, "");
    try fakeSend("namespace", .{ .key = "b/o", .body = "{}", .removed = true }, &.{"*3\r\n$4\r\nHDEL\r\n$2\r\nev\r\n$3\r\nb/o\r\n"}, &.{":1\r\n"}, "");
    try fakeSend("access", .{ .key = "b/o", .body = "{}", .record = "{}", .event_time = "T" }, &.{"*3\r\n$5\r\nRPUSH\r\n$2\r\nev\r\n$32\r\n[{\"Event\":[{}],\"EventTime\":\"T\"}]\r\n"}, &.{":1\r\n"}, "");
    const publish_x = "*3\r\n$7\r\nPUBLISH\r\n$2\r\nev\r\n$1\r\nx\r\n";
    try fakeSend("pubsub", .{ .body = "x" }, &.{publish_x}, &.{":0\r\n"}, "");
    try fakeSend("pubsub", .{ .body = "x" }, &.{ "*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n", publish_x }, &.{ "+OK\r\n", ":0\r\n" }, "pw");
    try testing.expectError(error.Rejected, fakeSend("pubsub", .{ .body = "x" }, &.{"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n"}, &.{"-WRONGPASS\r\n"}, "pw"));
    try testing.expectError(error.Rejected, fakeSend("pubsub", .{ .body = "x" }, &.{publish_x}, &.{"-ERR no\r\n"}, ""));
    try testing.expectError(error.Unreachable, fakeSend("pubsub", .{ .body = "x" }, &.{publish_x}, &.{""}, ""));
    try testing.expectError(error.Unreachable, fakeSend("pubsub", .{ .body = "x" }, &.{publish_x}, &.{"$999999999\r\n"}, ""));
}

test "unreachable server" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "address", .value = "127.0.0.1:1" }, .{ .key = "key", .value = "k" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .key = "a", .body = "{}" }));
}

fn liveCall(c: *net.Conn, a: std.mem.Allocator, args: []const []const u8) !Reply {
    try writeCommand(c.writer(), args);
    try c.flush();
    return readReply(c.reader(), a);
}

test "events live redis" {
    const addr = std.posix.getenv("ZKFSM_TEST_REDIS") orelse return error.SkipZigTest;
    const pw = std.posix.getenv("ZKFSM_TEST_REDIS_PASSWORD") orelse "";
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const hp = try net.splitHostPort(addr, 6379);
    const probe = try net.dial(gpa, hp[0], hp[1], .{});
    defer probe.close();
    if (pw.len > 0) _ = try liveCall(probe, a, &.{ "AUTH", pw });
    _ = try liveCall(probe, a, &.{ "DEL", "zkev:ns", "zkev:log" });

    const base = [_]target.Kv{ .{ .key = "address", .value = addr }, .{ .key = "password", .value = pw } };
    {
        const c = try create(gpa, .{ .kvs = &(base ++ [_]target.Kv{ .{ .key = "key", .value = "zkev:ns" }, .{ .key = "format", .value = "namespace" } }) });
        defer c.deinit();
        try c.send(&.{ .key = "b/o", .body = "{}", .record = "{\"n\":1}" });
        try testing.expectEqualStrings("{\"n\":1}", (try liveCall(probe, a, &.{ "HGET", "zkev:ns", "b/o" })).bulk.?);
        try c.send(&.{ .key = "b/o", .body = "{}", .removed = true });
        try testing.expectEqual(@as(i64, 0), (try liveCall(probe, a, &.{ "HEXISTS", "zkev:ns", "b/o" })).int);
    }
    {
        const c = try create(gpa, .{ .kvs = &(base ++ [_]target.Kv{ .{ .key = "key", .value = "zkev:log" }, .{ .key = "format", .value = "access" } }) });
        defer c.deinit();
        try c.send(&.{ .key = "b/o", .body = "{}", .record = "{\"n\":2}", .event_time = "2026-01-01T00:00:00Z" });
        const items = (try liveCall(probe, a, &.{ "LRANGE", "zkev:log", "0", "-1" })).array.?;
        try testing.expectEqual(@as(usize, 1), items.len);
        try testing.expectEqualStrings("[{\"Event\":[{\"n\":2}],\"EventTime\":\"2026-01-01T00:00:00Z\"}]", items[0].bulk.?);
    }
    {
        const sub = try net.dial(gpa, hp[0], hp[1], .{});
        defer sub.close();
        if (pw.len > 0) _ = try liveCall(sub, a, &.{ "AUTH", pw });
        _ = try liveCall(sub, a, &.{ "SUBSCRIBE", "zkev:ch" });
        const c = try create(gpa, .{ .kvs = &(base ++ [_]target.Kv{ .{ .key = "key", .value = "zkev:ch" }, .{ .key = "format", .value = "pubsub" } }) });
        defer c.deinit();
        try c.send(&.{ .body = "{\"hello\":1}" });
        const m = (try readReply(sub.reader(), a)).array.?;
        try testing.expectEqualStrings("message", m[0].bulk.?);
        try testing.expectEqualStrings("zkev:ch", m[1].bulk.?);
        try testing.expectEqualStrings("{\"hello\":1}", m[2].bulk.?);
    }
    if (pw.len > 0) {
        const c = try create(gpa, .{ .kvs = &.{ .{ .key = "address", .value = addr }, .{ .key = "key", .value = "k" }, .{ .key = "password", .value = "wrong" } } });
        defer c.deinit();
        try testing.expectError(error.Rejected, c.send(&.{ .body = "{}" }));
    }
}
