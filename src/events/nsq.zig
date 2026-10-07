//! NSQ notification target: the nsqd TCP protocol (V2), publishing each
//! event body to one topic with PUB and waiting for the OK frame.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "nsqd_address", "topic", "tls", "tls_skip_verify", "queue_dir", "queue_limit", "comment" };

pub const magic = "  V2";
/// Largest response frame accepted; nsqd replies are tiny.
pub const max_frame = 1024 * 1024;
/// Heartbeats answered per PUB before giving up on the reply.
pub const max_heartbeats = 16;

pub const FrameType = enum(u32) { response = 0, err = 1, message = 2, _ };

pub const Frame = struct { kind: FrameType, data: []const u8 };

/// Topic names: [.a-zA-Z0-9_-]{1,64}, optionally ending in "#ephemeral".
pub fn validTopic(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    const base = if (std.mem.endsWith(u8, s, "#ephemeral")) s[0 .. s.len - "#ephemeral".len] else s;
    if (base.len == 0) return false;
    for (base) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) return false;
    return true;
}

pub fn writePub(w: *std.Io.Writer, topic: []const u8, body: []const u8) error{ WriteFailed, TooLarge }!void {
    const n = std.math.cast(u32, body.len) orelse return error.TooLarge;
    try w.print("PUB {s}\n", .{topic});
    try w.writeInt(u32, n, .big);
    try w.writeAll(body);
}

pub const FrameError = error{ Protocol, ReadFailed, EndOfStream };

/// Reads one frame; `data` points into the reader buffer until the next read.
pub fn readFrame(r: *std.Io.Reader) FrameError!Frame {
    const size = r.takeInt(u32, .big) catch |e| return mapRead(e);
    if (size < 4 or size > max_frame or size > r.buffer.len) return error.Protocol;
    const kind = r.takeInt(u32, .big) catch |e| return mapRead(e);
    const data = r.take(size - 4) catch |e| return mapRead(e);
    return .{ .kind = @enumFromInt(kind), .data = data };
}

fn mapRead(e: std.Io.Reader.Error) FrameError {
    return switch (e) {
        error.ReadFailed => error.ReadFailed,
        error.EndOfStream => error.EndOfStream,
    };
}

const Nsq = struct {
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    topic: []const u8,
    conn: ?*net.Conn = null,

    fn drop(self: *Nsq) void {
        if (self.conn) |c| c.close();
        self.conn = null;
    }

    fn sendOnce(self: *Nsq, msg: *const target.Message) target.SendError!void {
        if (self.conn == null) {
            const c = net.dial(self.gpa, self.host, self.port, .{}) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.Unreachable,
            };
            self.conn = c;
            c.writer().writeAll(magic) catch return error.Unreachable;
        }
        const c = self.conn.?;
        writePub(c.writer(), self.topic, msg.body) catch |e| return switch (e) {
            error.TooLarge => error.Rejected,
            error.WriteFailed => error.Unreachable,
        };
        c.flush() catch return error.Unreachable;
        var beats: usize = 0;
        while (true) {
            const f = readFrame(c.reader()) catch return error.Unreachable;
            switch (f.kind) {
                .response => {
                    if (std.mem.eql(u8, f.data, "OK")) return;
                    if (!std.mem.eql(u8, f.data, "_heartbeat_")) return error.Unreachable;
                    beats += 1;
                    if (beats > max_heartbeats) return error.Unreachable;
                    c.writer().writeAll("NOP\n") catch return error.Unreachable;
                    c.flush() catch return error.Unreachable;
                },
                // Many nsqd errors are fatal and close the socket; reconnect next time.
                .err => {
                    self.drop();
                    return error.Rejected;
                },
                .message => {},
                _ => return error.Unreachable,
            }
        }
    }

    fn send(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const self: *Nsq = @ptrCast(@alignCast(ctx));
        self.sendOnce(msg) catch |e| {
            if (e != error.Rejected) self.drop();
            return e;
        };
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *Nsq = @ptrCast(@alignCast(ctx));
        self.drop();
        self.gpa.free(self.host);
        self.gpa.free(self.topic);
        self.gpa.destroy(self);
    }

    const vtable: target.Client.VTable = .{ .send = send, .deinit = deinit };
};

/// Validates settings and builds a client; the connection opens on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const hp = net.splitHostPort(s.get("nsqd_address"), 4150) catch return error.InvalidConfig;
    if (hp[0].len == 0 or hp[1] == 0) return error.InvalidConfig;
    const topic = s.get("topic");
    if (!validTopic(topic)) return error.InvalidConfig;
    // TLS needs the IDENTIFY tls_v1 upgrade, which is not implemented yet.
    if (s.flag("tls")) return error.InvalidConfig;
    _ = try s.int(u64, "queue_limit", 0);
    const self = try gpa.create(Nsq);
    errdefer gpa.destroy(self);
    const host = try gpa.dupe(u8, hp[0]);
    errdefer gpa.free(host);
    self.* = .{ .gpa = gpa, .host = host, .port = hp[1], .topic = try gpa.dupe(u8, topic) };
    return .{ .ctx = self, .vtable = &Nsq.vtable };
}

// ---- tests ----

const testing = std.testing;

inline fn frame(comptime kind: u32, comptime data: []const u8) []const u8 {
    return std.mem.toBytes(std.mem.nativeToBig(u32, 4 + data.len)) ++ std.mem.toBytes(std.mem.nativeToBig(u32, kind)) ++ data;
}

test "topic validation and PUB encoding" {
    try testing.expect(validTopic("minio.events_1-a"));
    try testing.expect(validTopic("t#ephemeral"));
    for ([_][]const u8{ "", "#ephemeral", "a b", "a/b", "x" ** 65, "t#other" }) |b| try testing.expect(!validTopic(b));
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePub(&w, "t", "hey");
    try testing.expectEqualStrings("PUB t\n\x00\x00\x00\x03hey", w.buffered());
}

test "frame parsing" {
    var r: std.Io.Reader = .fixed(comptime frame(0, "OK") ++ frame(1, "E_BAD_TOPIC x") ++ frame(2, ""));
    const a = try readFrame(&r);
    try testing.expectEqual(FrameType.response, a.kind);
    try testing.expectEqualStrings("OK", a.data);
    try testing.expectEqualStrings("E_BAD_TOPIC x", (try readFrame(&r)).data);
    try testing.expectEqual(FrameType.message, (try readFrame(&r)).kind);
    try testing.expectError(error.EndOfStream, readFrame(&r));
    for ([_][]const u8{ "\x00\x00\x00\x02xx", "\x7f\xff\xff\xff\x00\x00\x00\x00" }) |b| {
        var br: std.Io.Reader = .fixed(b);
        try testing.expectError(error.Protocol, readFrame(&br));
    }
    var short: std.Io.Reader = .fixed("\x00\x00\x00\x08\x00\x00\x00\x00O");
    try testing.expectError(error.EndOfStream, readFrame(&short));
}

test "settings validation" {
    const gpa = testing.allocator;
    const bad = [_][]const target.Kv{
        &.{.{ .key = "topic", .value = "t" }},
        &.{.{ .key = "nsqd_address", .value = "h:4150" }},
        &.{ .{ .key = "nsqd_address", .value = "h:x" }, .{ .key = "topic", .value = "t" } },
        &.{ .{ .key = "nsqd_address", .value = "h" }, .{ .key = "topic", .value = "bad topic" } },
        &.{ .{ .key = "nsqd_address", .value = "h" }, .{ .key = "topic", .value = "t" }, .{ .key = "tls", .value = "on" } },
        &.{ .{ .key = "nsqd_address", .value = "h" }, .{ .key = "topic", .value = "t" }, .{ .key = "queue_limit", .value = "x" } },
    };
    for (bad) |kvs| try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = kvs }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "nsqd_address", .value = "h" }, .{ .key = "topic", .value = "t" } } });
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

fn fakeSend(body: []const u8, expect: []const []const u8, reply: []const []const u8) !void {
    var f: FakeServer = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}), .expect = expect, .reply = reply };
    defer f.srv.deinit();
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    const t = try std.Thread.spawn(.{}, FakeServer.run, .{&f});
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "nsqd_address", .value = addr }, .{ .key = "topic", .value = "ev" } } });
    const res = c.send(&.{ .body = body });
    c.deinit();
    t.join();
    const all = try std.mem.concat(testing.allocator, u8, expect);
    defer testing.allocator.free(all);
    try testing.expectEqualStrings(all, f.got[0..f.got_len]);
    return res;
}

test "fake server: publish, heartbeat, error frame, garbage" {
    const pub_x = magic ++ "PUB ev\n\x00\x00\x00\x01x";
    try fakeSend("x", &.{pub_x}, &.{frame(0, "OK")});
    try fakeSend("x", &.{ pub_x, "NOP\n" }, &.{ frame(0, "_heartbeat_"), comptime frame(2, "msg") ++ frame(0, "OK") });
    try testing.expectError(error.Rejected, fakeSend("x", &.{pub_x}, &.{frame(1, "E_PUB_FAILED")}));
    try testing.expectError(error.Unreachable, fakeSend("x", &.{pub_x}, &.{frame(0, "WAT")}));
    try testing.expectError(error.Unreachable, fakeSend("x", &.{pub_x}, &.{"\xff\xff\xff\xff"}));
    try testing.expectError(error.Unreachable, fakeSend("x", &.{pub_x}, &.{""}));
}

test "unreachable server" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "nsqd_address", .value = "127.0.0.1:1" }, .{ .key = "topic", .value = "t" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .body = "{}" }));
}

test "events live nsq" {
    const addr = std.posix.getenv("ZKFSM_TEST_NSQ") orelse return error.SkipZigTest;
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "nsqd_address", .value = addr }, .{ .key = "topic", .value = "zkev" } } });
    defer c.deinit();
    try c.send(&.{ .body = "{\"n\":1}" });
    try c.send(&.{ .body = "{\"n\":2}" });
}
