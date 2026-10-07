//! MQTT notification target (3.1.1 and 5): one clean-session connection kept
//! open between sends, PUBLISH at QoS 0/1/2 with the matching ack flow.
const std = @import("std");
const target = @import("../target.zig");
const net = @import("../net.zig");

pub const keys = [_][]const u8{
    "broker",    "topic",       "username", "password",         "qos", "keep_alive_interval", "reconnect_interval",
    "queue_dir", "queue_limit", "comment",  "protocol_version",
};

/// Largest inbound packet body accepted from the broker.
pub const max_packet: usize = 8 << 20;
/// MQTT's remaining-length ceiling (four varint bytes).
pub const max_remaining: u32 = 268_435_455;

const Mqtt = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    host: []const u8 = "",
    port: u16 = 1883,
    tls: bool = false,
    topic: []const u8 = "",
    user: []const u8 = "",
    pass: []const u8 = "",
    qos: u2 = 0,
    keepalive_s: u16 = 10,
    v5: bool = false,
    timeout_ms: u32 = 10_000,
    client_id: ["zkfsm-".len + 16]u8 = undefined,
    pid: u16 = 0,
    last_ms: i64 = 0,
    conn: ?*net.Conn = null,

    fn configure(m: *Mqtt, s: target.Settings) target.InitError!void {
        const a = m.arena.allocator();
        const b = try parseBroker(s.get("broker"));
        m.host = try a.dupe(u8, b.host);
        m.port = b.port;
        m.tls = b.tls;
        const topic = s.get("topic");
        if (topic.len == 0 or topic.len > 65535 or std.mem.indexOfAny(u8, topic, "+#\x00") != null) return error.InvalidConfig;
        m.topic = try a.dupe(u8, topic);
        m.user = try a.dupe(u8, s.get("username"));
        m.pass = try a.dupe(u8, s.get("password"));
        if (m.user.len > 65535 or m.pass.len > 65535) return error.InvalidConfig;
        const qos = try s.int(u8, "qos", 0);
        if (qos > 2) return error.InvalidConfig;
        m.qos = @intCast(qos);
        const ka = try s.durationMs("keep_alive_interval", 10_000);
        if (ka > 65535 * 1000) return error.InvalidConfig;
        m.keepalive_s = @intCast(if (ka > 0 and ka < 1000) 1 else ka / 1000);
        _ = try s.durationMs("reconnect_interval", 0);
        _ = try s.int(u64, "queue_limit", 0);
        const pv = s.get("protocol_version");
        if (pv.len == 0 or std.mem.eql(u8, pv, "4") or std.mem.eql(u8, pv, "3.1.1")) {
            m.v5 = false;
        } else if (std.mem.eql(u8, pv, "5") or std.mem.eql(u8, pv, "5.0")) {
            m.v5 = true;
        } else return error.InvalidConfig;
        // 3.1.1 forbids a password without a user name.
        if (!m.v5 and m.pass.len > 0 and m.user.len == 0) return error.InvalidConfig;
        var rnd: [8]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        _ = std.fmt.bufPrint(&m.client_id, "zkfsm-{s}", .{std.fmt.bytesToHex(rnd, .lower)}) catch unreachable;
    }

    fn drop(m: *Mqtt) void {
        if (m.conn) |c| c.close();
        m.conn = null;
    }

    fn connect(m: *Mqtt) target.SendError!void {
        const c = net.dial(m.gpa, m.host, m.port, .{ .io_timeout_ms = m.timeout_ms, .tls = if (m.tls) .{} else null }) catch |e|
            return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        errdefer c.close();
        writeConnect(c.writer(), m.v5, &m.client_id, m.user, m.pass, m.keepalive_s) catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        const p = try readPacket(m.gpa, c.reader(), 4096);
        defer m.gpa.free(p.body);
        if (p.kind != 0x20 or p.body.len < 2) return error.Unreachable;
        if (if (m.v5) p.body[1] >= 0x80 else p.body[1] != 0) return error.Rejected;
        m.conn = c;
        m.last_ms = std.time.milliTimestamp();
    }

    fn nextPid(m: *Mqtt) u16 {
        m.pid +%= 1;
        if (m.pid == 0) m.pid = 1;
        return m.pid;
    }

    fn ping(m: *Mqtt) target.SendError!void {
        const c = m.conn.?;
        c.writer().writeAll(&.{ 0xC0, 0 }) catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        try m.expectAck(c, 0xD0, null);
    }

    fn publish(m: *Mqtt, body: []const u8) target.SendError!void {
        const c = m.conn.?;
        const pid: u16 = if (m.qos > 0) m.nextPid() else 0;
        writePublish(c.writer(), m.v5, m.topic, m.qos, pid, body) catch |e| return switch (e) {
            error.TooLarge => error.Rejected,
            error.WriteFailed => error.Unreachable,
        };
        switch (m.qos) {
            // QoS 0 has no ack; a ping round trip proves the broker took it.
            0 => {
                c.flush() catch return error.Unreachable;
                return m.ping();
            },
            1 => {
                c.flush() catch return error.Unreachable;
                try m.expectAck(c, 0x40, pid);
            },
            else => {
                c.flush() catch return error.Unreachable;
                try m.expectAck(c, 0x50, pid);
                c.writer().writeAll(&.{ 0x62, 2, @intCast(pid >> 8), @truncate(pid) }) catch return error.Unreachable;
                c.flush() catch return error.Unreachable;
                try m.expectAck(c, 0x70, pid);
            },
        }
    }

    /// Waits for packet type `kind` (matching `pid`); reason codes >= 0x80 are refusals.
    fn expectAck(m: *Mqtt, c: *net.Conn, kind: u8, pid: ?u16) target.SendError!void {
        var guard: u32 = 0;
        while (guard < 64) : (guard += 1) {
            const p = try readPacket(m.gpa, c.reader(), max_packet);
            defer m.gpa.free(p.body);
            if (p.kind == 0xE0) return if (p.body.len > 0 and p.body[0] >= 0x80) error.Rejected else error.Unreachable;
            if (p.kind & 0xF0 != kind) continue;
            if (pid) |want| {
                if (p.body.len < 2) return error.Unreachable;
                if (std.mem.readInt(u16, p.body[0..2], .big) != want) continue;
                if (p.body.len > 2 and p.body[2] >= 0x80) return error.Rejected;
            }
            m.last_ms = std.time.milliTimestamp();
            return;
        }
        return error.Unreachable;
    }
};

fn sendFn(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
    const m: *Mqtt = @ptrCast(@alignCast(ctx));
    if (m.conn != null and m.keepalive_s > 0 and std.time.milliTimestamp() - m.last_ms > @as(i64, m.keepalive_s) * 1000) {
        m.ping() catch m.drop();
    }
    if (m.conn == null) try m.connect();
    m.publish(msg.body) catch |e| {
        m.drop();
        return e;
    };
}

fn deinitFn(ctx: *anyopaque) void {
    const m: *Mqtt = @ptrCast(@alignCast(ctx));
    if (m.conn) |c| {
        c.writer().writeAll(&.{ 0xE0, 0 }) catch {};
        c.flush() catch {};
    }
    m.drop();
    m.arena.deinit();
    m.gpa.destroy(m);
}

const vtable: target.Client.VTable = .{ .send = sendFn, .deinit = deinitFn };

/// Validates settings and builds the client; connects on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const m = try gpa.create(Mqtt);
    errdefer gpa.destroy(m);
    m.* = .{ .gpa = gpa, .arena = .init(gpa) };
    errdefer m.arena.deinit();
    try m.configure(s);
    return .{ .ctx = m, .vtable = &vtable };
}

pub const Broker = struct { host: []const u8, port: u16, tls: bool };

/// Parses tcp://, mqtt://, ssl://, tls://, mqtts:// URLs or a bare host:port.
pub fn parseBroker(url: []const u8) error{InvalidConfig}!Broker {
    var rest = url;
    var tls = false;
    if (std.mem.indexOf(u8, url, "://")) |i| {
        const scheme = url[0..i];
        rest = url[i + 3 ..];
        if (std.ascii.eqlIgnoreCase(scheme, "ssl") or std.ascii.eqlIgnoreCase(scheme, "tls") or std.ascii.eqlIgnoreCase(scheme, "mqtts")) {
            tls = true;
        } else if (!std.ascii.eqlIgnoreCase(scheme, "tcp") and !std.ascii.eqlIgnoreCase(scheme, "mqtt")) return error.InvalidConfig;
    }
    if (std.mem.indexOfScalar(u8, rest, '/')) |i| {
        if (i + 1 != rest.len) return error.InvalidConfig;
        rest = rest[0..i];
    }
    const hp = net.splitHostPort(rest, if (tls) 8883 else 1883) catch return error.InvalidConfig;
    if (hp[0].len == 0) return error.InvalidConfig;
    return .{ .host = hp[0], .port = hp[1], .tls = tls };
}

/// Encodes a remaining length; TooLarge past 268,435,455.
pub fn encodeVarint(buf: *[4]u8, value: usize) error{TooLarge}![]const u8 {
    if (value > max_remaining) return error.TooLarge;
    var v = value;
    var i: usize = 0;
    while (true) {
        var b: u8 = @intCast(v % 128);
        v /= 128;
        if (v > 0) b |= 0x80;
        buf[i] = b;
        i += 1;
        if (v == 0) return buf[0..i];
    }
}

/// Decodes a varint prefix of `bytes`; null when truncated or longer than 4 bytes.
pub fn decodeVarint(bytes: []const u8) ?struct { value: u32, len: usize } {
    var v: u32 = 0;
    for (bytes, 0..) |b, i| {
        if (i == 4) return null;
        v |= @as(u32, b & 0x7f) << @intCast(7 * i);
        if (b & 0x80 == 0) return .{ .value = v, .len = i + 1 };
    }
    return null;
}

fn writeHeader(w: *std.Io.Writer, first: u8, len: usize) error{ WriteFailed, TooLarge }!void {
    var vb: [4]u8 = undefined;
    const v = try encodeVarint(&vb, len);
    try w.writeByte(first);
    try w.writeAll(v);
}

fn writeStr(w: *std.Io.Writer, s: []const u8) error{WriteFailed}!void {
    try w.writeInt(u16, @intCast(s.len), .big);
    try w.writeAll(s);
}

/// CONNECT with clean session; strings must be <= 65535 bytes.
pub fn writeConnect(w: *std.Io.Writer, v5: bool, client_id: []const u8, user: []const u8, pass: []const u8, keepalive_s: u16) error{WriteFailed}!void {
    var flags: u8 = 0x02;
    // v5 adds one byte: an empty CONNECT properties block.
    var len: usize = 10 + 2 + client_id.len + @as(usize, if (v5) 1 else 0);
    if (user.len > 0) {
        flags |= 0x80;
        len += 2 + user.len;
    }
    if (pass.len > 0) {
        flags |= 0x40;
        len += 2 + pass.len;
    }
    writeHeader(w, 0x10, len) catch return error.WriteFailed;
    try writeStr(w, "MQTT");
    try w.writeByte(if (v5) 5 else 4);
    try w.writeByte(flags);
    try w.writeInt(u16, keepalive_s, .big);
    if (v5) try w.writeByte(0);
    try writeStr(w, client_id);
    if (user.len > 0) try writeStr(w, user);
    if (pass.len > 0) try writeStr(w, pass);
}

/// PUBLISH; `pid` is used only for QoS > 0.
pub fn writePublish(w: *std.Io.Writer, v5: bool, topic: []const u8, qos: u2, pid: u16, payload: []const u8) error{ WriteFailed, TooLarge }!void {
    const len = 2 + topic.len + @as(usize, if (qos > 0) 2 else 0) + @as(usize, if (v5) 1 else 0) + payload.len;
    try writeHeader(w, 0x30 | @as(u8, qos) << 1, len);
    try writeStr(w, topic);
    if (qos > 0) try w.writeInt(u16, pid, .big);
    if (v5) try w.writeByte(0);
    try w.writeAll(payload);
}

pub const Packet = struct { kind: u8, body: []u8 };

/// Reads one packet; the body is caller-owned. Bodies over `max` drop the connection.
pub fn readPacket(gpa: std.mem.Allocator, r: *std.Io.Reader, max: usize) target.SendError!Packet {
    const kind = r.takeByte() catch return error.Unreachable;
    var vb: [4]u8 = undefined;
    var n: usize = 0;
    const len = while (n < 4) {
        vb[n] = r.takeByte() catch return error.Unreachable;
        n += 1;
        if (vb[n - 1] & 0x80 == 0) break (decodeVarint(vb[0..n]) orelse return error.Unreachable).value;
    } else return error.Unreachable;
    if (len > max) return error.Unreachable;
    const body = try gpa.alloc(u8, len);
    errdefer gpa.free(body);
    r.readSliceAll(body) catch return error.Unreachable;
    return .{ .kind = kind, .body = body };
}

pub const Publish = struct { topic: []const u8, qos: u2, pid: u16, payload: []const u8 };

/// Splits a received PUBLISH body; null when malformed.
pub fn parsePublish(v5: bool, kind: u8, body: []const u8) ?Publish {
    if (kind & 0xF0 != 0x30 or body.len < 2) return null;
    const qos: u2 = @intCast((kind >> 1) & 3);
    if (qos == 3) return null;
    const tl = std.mem.readInt(u16, body[0..2], .big);
    var i: usize = 2 + tl;
    if (i > body.len) return null;
    const topic = body[2..i];
    var pid: u16 = 0;
    if (qos > 0) {
        if (i + 2 > body.len) return null;
        pid = std.mem.readInt(u16, body[i..][0..2], .big);
        i += 2;
    }
    if (v5) {
        const pl = decodeVarint(body[i..]) orelse return null;
        i += pl.len;
        if (pl.value > body.len - i) return null;
        i += pl.value;
    }
    return .{ .topic = topic, .qos = qos, .pid = pid, .payload = body[i..] };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "remaining length varint" {
    var b: [4]u8 = undefined;
    const cases = [_]struct { usize, []const u8 }{
        .{ 0, &.{0} },                                  .{ 127, &.{0x7f} },              .{ 128, &.{ 0x80, 1 } },
        .{ 16383, &.{ 0xff, 0x7f } },                   .{ 16384, &.{ 0x80, 0x80, 1 } }, .{ 2097152, &.{ 0x80, 0x80, 0x80, 1 } },
        .{ 268_435_455, &.{ 0xff, 0xff, 0xff, 0x7f } },
    };
    for (cases) |c| {
        try testing.expectEqualSlices(u8, c[1], try encodeVarint(&b, c[0]));
        try testing.expectEqual(@as(u32, @intCast(c[0])), decodeVarint(c[1]).?.value);
    }
    try testing.expectError(error.TooLarge, encodeVarint(&b, 268_435_456));
    try testing.expect(decodeVarint(&.{ 0x80, 0x80, 0x80, 0x80, 1 }) == null);
    try testing.expect(decodeVarint(&.{0x80}) == null);
}

test "connect bytes 3.1.1 and 5" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeConnect(&w, false, "id", "u", "p", 10);
    try testing.expectEqualSlices(u8, &.{ 0x10, 20, 0, 4, 'M', 'Q', 'T', 'T', 4, 0xC2, 0, 10, 0, 2, 'i', 'd', 0, 1, 'u', 0, 1, 'p' }, w.buffered());
    w = .fixed(&buf);
    try writeConnect(&w, true, "id", "", "", 30);
    try testing.expectEqualSlices(u8, &.{ 0x10, 15, 0, 4, 'M', 'Q', 'T', 'T', 5, 0x02, 0, 30, 0, 0, 2, 'i', 'd' }, w.buffered());
    w = .fixed(&buf);
    try writePublish(&w, true, "t", 1, 7, "x");
    try testing.expectEqualSlices(u8, &.{ 0x32, 7, 0, 1, 't', 0, 7, 0, 'x' }, w.buffered());
    const p = parsePublish(true, 0x32, w.buffered()[2..]).?;
    try testing.expectEqualStrings("x", p.payload);
    try testing.expectEqual(@as(u16, 7), p.pid);
}

test "settings validation" {
    const gpa = testing.allocator;
    const bad = [_][]const target.Kv{
        &.{.{ .key = "topic", .value = "t" }},
        &.{.{ .key = "broker", .value = "tcp://h:1883" }},
        &.{ .{ .key = "broker", .value = "ws://h:80" }, .{ .key = "topic", .value = "t" } },
        &.{ .{ .key = "broker", .value = "tcp://h" }, .{ .key = "topic", .value = "a/#" } },
        &.{ .{ .key = "broker", .value = "tcp://h" }, .{ .key = "topic", .value = "t" }, .{ .key = "qos", .value = "3" } },
        &.{ .{ .key = "broker", .value = "tcp://h" }, .{ .key = "topic", .value = "t" }, .{ .key = "protocol_version", .value = "3" } },
        &.{ .{ .key = "broker", .value = "tcp://h" }, .{ .key = "topic", .value = "t" }, .{ .key = "password", .value = "p" } },
        &.{ .{ .key = "broker", .value = "tcp://h" }, .{ .key = "topic", .value = "t" }, .{ .key = "keep_alive_interval", .value = "x" } },
    };
    for (bad) |kvs| try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = kvs }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "broker", .value = "ssl://h" }, .{ .key = "topic", .value = "a/b" }, .{ .key = "qos", .value = "2" }, .{ .key = "protocol_version", .value = "5" }, .{ .key = "keep_alive_interval", .value = "1m" } } });
    defer c.deinit();
    const m: *Mqtt = @ptrCast(@alignCast(c.ctx));
    try testing.expectEqual(@as(u16, 8883), m.port);
    try testing.expect(m.tls and m.v5);
    try testing.expectEqual(@as(u2, 2), m.qos);
    try testing.expectEqual(@as(u16, 60), m.keepalive_s);
}

const Fake = struct {
    srv: std.net.Server,
    v5: bool,
    qos: u2,
    reject: bool = false,
    got: [256]u8 = undefined,
    got_len: usize = 0,
    ok: bool = false,

    fn run(f: *Fake) void {
        f.serve() catch {};
    }

    fn serve(f: *Fake) !void {
        const gpa = std.heap.page_allocator;
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const r = sr.interface();
        const w = &sw.interface;
        const cp = try readPacket(gpa, r, 4096);
        gpa.free(cp.body);
        if (cp.kind != 0x10) return;
        try w.writeAll(if (f.v5) &[_]u8{ 0x20, 3, 0, 0, 0 } else &[_]u8{ 0x20, 2, 0, 0 });
        try w.flush();
        const pp = try readPacket(gpa, r, 4096);
        defer gpa.free(pp.body);
        const p = parsePublish(f.v5, pp.kind, pp.body) orelse return;
        if (p.qos != f.qos) return;
        @memcpy(f.got[0..p.payload.len], p.payload);
        f.got_len = p.payload.len;
        const hi: u8 = @intCast(p.pid >> 8);
        const lo: u8 = @truncate(p.pid);
        switch (p.qos) {
            0 => {
                const pr = try readPacket(gpa, r, 16);
                gpa.free(pr.body);
                try w.writeAll(&.{ 0xD0, 0 });
            },
            1 => try w.writeAll(if (f.reject) &[_]u8{ 0x40, 4, hi, lo, 0x87, 0 } else &[_]u8{ 0x40, 2, hi, lo }),
            else => {
                try w.writeAll(&.{ 0x50, 2, hi, lo });
                try w.flush();
                const rel = try readPacket(gpa, r, 16);
                defer gpa.free(rel.body);
                if (rel.kind != 0x62 or rel.body.len != 2 or rel.body[1] != lo) return;
                try w.writeAll(&.{ 0x70, 2, hi, lo });
            },
        }
        try w.flush();
        f.ok = true;
        _ = r.takeByte() catch {};
    }
};

fn fakeRun(v5: bool, qos: u2, reject: bool) !void {
    const gpa = testing.allocator;
    var f: Fake = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .v5 = v5, .qos = qos, .reject = reject };
    defer f.srv.deinit();
    var abuf: [40]u8 = undefined;
    const url = try std.fmt.bufPrint(&abuf, "tcp://127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    var qb: [1]u8 = .{'0' + @as(u8, qos)};
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "broker", .value = url }, .{ .key = "topic", .value = "ev/x" }, .{ .key = "qos", .value = &qb }, .{ .key = "protocol_version", .value = if (v5) "5" else "4" } } });
    defer c.deinit();
    const t = try std.Thread.spawn(.{}, Fake.run, .{&f});
    const res = c.send(&.{ .body = "{\"k\":1}" });
    @as(*Mqtt, @ptrCast(@alignCast(c.ctx))).drop();
    t.join();
    if (reject) return testing.expectError(error.Rejected, res);
    try res;
    try testing.expect(f.ok);
    try testing.expectEqualStrings("{\"k\":1}", f.got[0..f.got_len]);
}

test "fake broker qos0 qos1 qos2, 3.1.1 and 5" {
    for ([_]bool{ false, true }) |v5| for ([_]u2{ 0, 1, 2 }) |q| try fakeRun(v5, q, false);
}

test "fake broker v5 negative puback is rejected" {
    try fakeRun(true, 1, true);
}

test "unreachable broker" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "broker", .value = "tcp://127.0.0.1:1" }, .{ .key = "topic", .value = "t" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .body = "x" }));
}

// Live test: ZKFSM_TEST_MQTT=host:port (anonymous broker).

fn liveSub(gpa: std.mem.Allocator, addr: []const u8, v5: bool, topic: []const u8) !*net.Conn {
    const b = try parseBroker(addr);
    const c = try net.dial(gpa, b.host, b.port, .{});
    errdefer c.close();
    const w = c.writer();
    try writeConnect(w, v5, if (v5) "zkfsm-test-sub5" else "zkfsm-test-sub4", "", "", 30);
    const len = 2 + @as(usize, if (v5) 1 else 0) + 2 + topic.len + 1;
    try writeHeader(w, 0x82, len);
    try w.writeInt(u16, 1, .big);
    if (v5) try w.writeByte(0);
    try writeStr(w, topic);
    try w.writeByte(2);
    try c.flush();
    const ca = try readPacket(gpa, c.reader(), 64);
    defer gpa.free(ca.body);
    if (ca.kind != 0x20 or ca.body[1] != 0) return error.TestUnexpectedResult;
    const sa = try readPacket(gpa, c.reader(), 64);
    defer gpa.free(sa.body);
    if (sa.kind != 0x90 or sa.body[sa.body.len - 1] >= 0x80) return error.TestUnexpectedResult;
    return c;
}

test "events live mqtt" {
    const addr = std.posix.getenv("ZKFSM_TEST_MQTT") orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    for ([_]bool{ false, true }) |v5| {
        const topic = if (v5) "zkev/live/5" else "zkev/live/4";
        const sub = try liveSub(gpa, addr, v5, topic);
        defer sub.close();
        for ([_]u8{ '0', '1', '2' }) |q| {
            const qs = [1]u8{q};
            const c = try create(gpa, .{ .kvs = &.{ .{ .key = "broker", .value = addr }, .{ .key = "topic", .value = topic }, .{ .key = "qos", .value = &qs }, .{ .key = "protocol_version", .value = if (v5) "5" else "3.1.1" } } });
            defer c.deinit();
            var bb: [32]u8 = undefined;
            const body = try std.fmt.bufPrint(&bb, "{{\"v5\":{},\"q\":{c}}}", .{ v5, q });
            try c.send(&.{ .body = body });
            try c.send(&.{ .body = body });
            var seen: usize = 0;
            while (seen < 2) {
                const p = try readPacket(gpa, sub.reader(), max_packet);
                defer gpa.free(p.body);
                if (p.kind == 0x62 and p.body.len >= 2) {
                    try sub.writer().writeAll(&.{ 0x70, 2, p.body[0], p.body[1] });
                    try sub.flush();
                    continue;
                }
                const pub_ = parsePublish(v5, p.kind, p.body) orelse return error.TestUnexpectedResult;
                seen += 1;
                try testing.expectEqualStrings(topic, pub_.topic);
                try testing.expectEqualStrings(body, pub_.payload);
                try testing.expectEqual(@as(u2, @intCast(q - '0')), pub_.qos);
                const hi: u8 = @intCast(pub_.pid >> 8);
                const lo: u8 = @truncate(pub_.pid);
                if (pub_.qos == 1) try sub.writer().writeAll(&.{ 0x40, 2, hi, lo });
                if (pub_.qos == 2) try sub.writer().writeAll(&.{ 0x50, 2, hi, lo });
                try sub.flush();
            }
        }
    }
}
