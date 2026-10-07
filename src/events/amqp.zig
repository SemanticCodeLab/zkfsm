//! AMQP 0-9-1 notification target (RabbitMQ and compatible brokers): one
//! connection, one channel, optional exchange declare and publisher confirms.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "url", "exchange", "exchange_type", "routing_key", "mandatory", "durable", "no_wait", "internal", "auto_deleted", "delivery_mode", "publisher_confirms", "queue_dir", "queue_limit", "comment" };

pub const frame_method: u8 = 1;
pub const frame_header: u8 = 2;
pub const frame_body: u8 = 3;
pub const frame_heartbeat: u8 = 8;
pub const frame_end: u8 = 0xCE;

/// Largest frame we accept or ask for; the broker may lower it in Tune.
pub const max_frame: u32 = 128 * 1024;
const min_frame: u32 = 4096;
const channel: u16 = 1;

pub const Frame = struct { kind: u8, channel: u16, payload: []const u8 };
pub const Method = struct { class: u16, id: u16, args: Parser };

pub const ProtoError = error{ Protocol, ReadFailed, EndOfStream };

/// Bounds-checked reader over a frame payload.
pub const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(p: *Parser, n: usize) error{Protocol}![]const u8 {
        if (p.buf.len - p.pos < n) return error.Protocol;
        defer p.pos += n;
        return p.buf[p.pos..][0..n];
    }
    pub fn int(p: *Parser, comptime T: type) error{Protocol}!T {
        return std.mem.readInt(T, (try p.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    pub fn shortstr(p: *Parser) error{Protocol}![]const u8 {
        return p.take(try p.int(u8));
    }
    pub fn longstr(p: *Parser) error{Protocol}![]const u8 {
        return p.take(try p.int(u32));
    }
};

/// Builds method/header payloads; field tables are always sent empty.
pub const Enc = struct {
    list: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn deinit(e: *Enc) void {
        e.list.deinit(e.gpa);
    }
    pub fn int(e: *Enc, comptime T: type, v: T) error{OutOfMemory}!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        try e.list.appendSlice(e.gpa, &b);
    }
    pub fn shortstr(e: *Enc, s: []const u8) error{OutOfMemory}!void {
        std.debug.assert(s.len <= 255);
        try e.int(u8, @intCast(s.len));
        try e.list.appendSlice(e.gpa, s);
    }
    pub fn longstr(e: *Enc, s: []const u8) error{OutOfMemory}!void {
        try e.int(u32, @intCast(s.len));
        try e.list.appendSlice(e.gpa, s);
    }
    pub fn method(e: *Enc, class: u16, id: u16) error{OutOfMemory}!void {
        e.list.clearRetainingCapacity();
        try e.int(u16, class);
        try e.int(u16, id);
    }
};

pub fn writeFrame(w: *std.Io.Writer, kind: u8, ch: u16, payload: []const u8) error{WriteFailed}!void {
    var h: [7]u8 = undefined;
    h[0] = kind;
    std.mem.writeInt(u16, h[1..3], ch, .big);
    std.mem.writeInt(u32, h[3..7], @intCast(payload.len), .big);
    try w.writeAll(&h);
    try w.writeAll(payload);
    try w.writeByte(frame_end);
}

/// Reads one frame into `buf`; frames larger than `buf` are a protocol error.
pub fn readFrame(r: *std.Io.Reader, buf: []u8) ProtoError!Frame {
    var h: [7]u8 = undefined;
    r.readSliceAll(&h) catch |e| return e;
    const n = std.mem.readInt(u32, h[3..7], .big);
    if (n > buf.len) return error.Protocol;
    r.readSliceAll(buf[0..n]) catch |e| return e;
    const end = r.takeByte() catch |e| return e;
    if (end != frame_end) return error.Protocol;
    return .{ .kind = h[0], .channel = std.mem.readInt(u16, h[1..3], .big), .payload = buf[0..n] };
}

pub fn parseMethod(f: Frame) error{Protocol}!Method {
    if (f.kind != frame_method) return error.Protocol;
    var p: Parser = .{ .buf = f.payload };
    const class = try p.int(u16);
    const id = try p.int(u16);
    return .{ .class = class, .id = id, .args = p };
}

pub const Url = struct {
    host: []const u8,
    port: u16,
    user: []const u8,
    password: []const u8,
    vhost: []const u8,
    tls: bool,
};

/// Parses amqp[s]://user:pass@host:port/vhost; strings are allocated from `a`.
pub fn parseUrl(a: std.mem.Allocator, text: []const u8) error{ InvalidConfig, OutOfMemory }!Url {
    const u = std.Uri.parse(text) catch return error.InvalidConfig;
    const tls = if (std.ascii.eqlIgnoreCase(u.scheme, "amqps")) true else if (std.ascii.eqlIgnoreCase(u.scheme, "amqp")) false else return error.InvalidConfig;
    const host = u.getHostAlloc(a) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidConfig;
    if (host.len == 0) return error.InvalidConfig;
    var vhost = try u.path.toRawMaybeAlloc(a);
    if (vhost.len > 0 and vhost[0] == '/') vhost = vhost[1..];
    if (vhost.len == 0) vhost = "/";
    const out: Url = .{
        .host = host,
        .port = u.port orelse if (tls) 5671 else 5672,
        .user = if (u.user) |c| try c.toRawMaybeAlloc(a) else "guest",
        .password = if (u.password) |c| try c.toRawMaybeAlloc(a) else "guest",
        .vhost = vhost,
        .tls = tls,
    };
    if (out.vhost.len > 255 or out.port == 0) return error.InvalidConfig;
    return out;
}

const Fail = error{ Unreachable, Rejected, OutOfMemory };

const Amqp = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    url: Url,
    exchange: []const u8,
    exchange_type: []const u8,
    routing_key: []const u8,
    mandatory: bool,
    durable: bool,
    no_wait: bool,
    internal: bool,
    auto_deleted: bool,
    persistent: bool,
    confirms: bool,
    conn: ?*net.Conn = null,
    frame_max: u32 = max_frame,
    tag: u64 = 0,
    rbuf: []u8,
    enc: Enc,

    fn drop(self: *Amqp) void {
        if (self.conn) |c| c.close();
        self.conn = null;
    }

    fn sendMethod(self: *Amqp, ch: u16) Fail!void {
        const c = self.conn orelse return error.Unreachable;
        writeFrame(c.writer(), frame_method, ch, self.enc.list.items) catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
    }

    // Next method frame; answers heartbeats and server-initiated closes.
    fn nextMethod(self: *Amqp) Fail!Method {
        const c = self.conn orelse return error.Unreachable;
        while (true) {
            const f = readFrame(c.reader(), self.rbuf) catch return error.Unreachable;
            if (f.kind == frame_heartbeat) {
                writeFrame(c.writer(), frame_heartbeat, 0, "") catch return error.Unreachable;
                c.flush() catch return error.Unreachable;
                continue;
            }
            if (f.kind != frame_method) continue; // e.g. content of a returned message
            const m = parseMethod(f) catch return error.Unreachable;
            if ((m.class == 10 and m.id == 50) or (m.class == 20 and m.id == 40)) {
                try self.enc.method(m.class, m.id + 1);
                self.sendMethod(f.channel) catch {};
                self.drop();
                return error.Rejected;
            }
            return m;
        }
    }

    fn expect(self: *Amqp, class: u16, id: u16) Fail!Method {
        const m = try self.nextMethod();
        if (m.class != class or m.id != id) return error.Unreachable;
        return m;
    }

    fn connect(self: *Amqp) Fail!void {
        if (self.conn != null) return;
        const u = self.url;
        const tls: ?net.TlsOptions = if (u.tls) .{} else null;
        self.conn = net.dial(self.gpa, u.host, u.port, .{ .tls = tls }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        errdefer self.drop();
        const c = self.conn.?;
        c.writer().writeAll("AMQP\x00\x00\x09\x01") catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        self.frame_max = max_frame;

        var start = try self.expect(10, 10);
        _ = start.args.take(2) catch return error.Unreachable;
        _ = start.args.longstr() catch return error.Unreachable; // server properties
        const mechs = start.args.longstr() catch return error.Unreachable;
        if (std.mem.indexOf(u8, mechs, "PLAIN") == null) return error.Rejected;

        const e = &self.enc;
        try e.method(10, 11);
        try e.int(u32, 0);
        try e.shortstr("PLAIN");
        try e.int(u32, @intCast(u.user.len + u.password.len + 2));
        try e.int(u8, 0);
        try e.list.appendSlice(self.gpa, u.user);
        try e.int(u8, 0);
        try e.list.appendSlice(self.gpa, u.password);
        try e.shortstr("en_US");
        try self.sendMethod(0);

        // A bad login closes the connection; nextMethod maps that to Rejected.
        const tm = self.nextMethod() catch |err| return if (err == error.Unreachable) error.Rejected else err;
        if (tm.class != 10 or tm.id != 30) return error.Unreachable;
        var tune = tm.args;
        const ch_max = tune.int(u16) catch return error.Unreachable;
        const fmax = tune.int(u32) catch return error.Unreachable;
        if (fmax != 0) self.frame_max = @max(min_frame, @min(fmax, max_frame));
        try e.method(10, 31);
        try e.int(u16, ch_max);
        try e.int(u32, self.frame_max);
        try e.int(u16, 0);
        try self.sendMethod(0);

        try e.method(10, 40);
        try e.shortstr(u.vhost);
        try e.shortstr("");
        try e.int(u8, 0);
        try self.sendMethod(0);
        _ = try self.expect(10, 41);

        try e.method(20, 10);
        try e.shortstr("");
        try self.sendMethod(channel);
        _ = try self.expect(20, 11);

        if (self.exchange.len > 0) {
            try e.method(40, 10);
            try e.int(u16, 0);
            try e.shortstr(self.exchange);
            try e.shortstr(self.exchange_type);
            var bits: u8 = 0;
            // Brokers refuse to (re)declare reserved amq.* exchanges; only check they exist.
            if (std.mem.startsWith(u8, self.exchange, "amq.")) bits |= 1;
            if (self.durable) bits |= 2;
            if (self.auto_deleted) bits |= 4;
            if (self.internal) bits |= 8;
            if (self.no_wait) bits |= 16;
            try e.int(u8, bits);
            try e.int(u32, 0);
            try self.sendMethod(channel);
            if (!self.no_wait) _ = try self.expect(40, 11);
        }
        self.tag = 0;
        if (self.confirms) {
            try e.method(85, 10);
            try e.int(u8, 0);
            try self.sendMethod(channel);
            _ = try self.expect(85, 11);
        }
    }

    fn publish(self: *Amqp, body: []const u8) Fail!void {
        const c = self.conn orelse return error.Unreachable;
        const w = c.writer();
        const e = &self.enc;
        try e.method(60, 40);
        try e.int(u16, 0);
        try e.shortstr(self.exchange);
        try e.shortstr(self.routing_key);
        try e.int(u8, if (self.mandatory) 1 else 0);
        writeFrame(w, frame_method, channel, e.list.items) catch return error.Unreachable;

        e.list.clearRetainingCapacity();
        try e.int(u16, 60);
        try e.int(u16, 0);
        try e.int(u64, body.len);
        try e.int(u16, if (self.persistent) 0x9000 else 0x8000);
        try e.shortstr("application/json");
        if (self.persistent) try e.int(u8, 2);
        writeFrame(w, frame_header, channel, e.list.items) catch return error.Unreachable;

        const chunk = self.frame_max - 8;
        var rest = body;
        while (rest.len > 0) {
            const n = @min(rest.len, chunk);
            writeFrame(w, frame_body, channel, rest[0..n]) catch return error.Unreachable;
            rest = rest[n..];
        }
        c.flush() catch return error.Unreachable;
        if (!self.confirms) return;
        self.tag += 1;

        // Basic.Return (unroutable mandatory) precedes the ack and fails the send.
        var returned = false;
        while (true) {
            var m = try self.nextMethod();
            if (m.class != 60) continue;
            if (m.id == 50) {
                returned = true;
                continue;
            }
            if (m.id != 80 and m.id != 120) continue;
            const t = m.args.int(u64) catch return error.Unreachable;
            const multiple = ((m.args.int(u8) catch 0) & 1) != 0;
            if (t != self.tag and !(multiple and t > self.tag)) {
                if (t > self.tag) return error.Unreachable;
                continue;
            }
            if (m.id == 120 or returned) return error.Rejected;
            return;
        }
    }

    fn send(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const self: *Amqp = @ptrCast(@alignCast(ctx));
        self.connect() catch |e| return e;
        self.publish(msg.body) catch |e| {
            if (e != error.Rejected) self.drop();
            return e;
        };
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *Amqp = @ptrCast(@alignCast(ctx));
        self.drop();
        self.enc.deinit();
        self.gpa.free(self.rbuf);
        self.arena.deinit();
        self.gpa.destroy(self);
    }

    const vtable: target.Client.VTable = .{ .send = send, .deinit = deinit };
};

/// Validates settings and builds a client; the connection opens on first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const url = try parseUrl(a, s.get("url"));
    if (url.user.len + url.password.len > 4096) return error.InvalidConfig;
    const exchange = try a.dupe(u8, s.get("exchange"));
    const etype_raw = s.get("exchange_type");
    const etype = try a.dupe(u8, if (etype_raw.len == 0) "direct" else etype_raw);
    const rk = try a.dupe(u8, s.get("routing_key"));
    if (exchange.len > 255 or etype.len > 255 or rk.len > 255) return error.InvalidConfig;
    const dm = try s.int(u8, "delivery_mode", 0);
    if (dm > 2) return error.InvalidConfig;
    _ = try s.int(u64, "queue_limit", 0);

    const rbuf = try gpa.alloc(u8, max_frame);
    errdefer gpa.free(rbuf);
    const self = try gpa.create(Amqp);
    self.* = .{
        .gpa = gpa,
        .arena = arena,
        .url = url,
        .exchange = exchange,
        .exchange_type = etype,
        .routing_key = rk,
        .mandatory = s.flag("mandatory"),
        .durable = s.flag("durable"),
        .no_wait = s.flag("no_wait"),
        .internal = s.flag("internal"),
        .auto_deleted = s.flag("auto_deleted"),
        .persistent = dm == 2 or s.flag("durable"),
        .confirms = s.flag("publisher_confirms"),
        .rbuf = rbuf,
        .enc = .{ .gpa = gpa },
    };
    return .{ .ctx = self, .vtable = &Amqp.vtable };
}

// ---- tests ----

const testing = std.testing;

test "frame encoding and decoding" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeFrame(&w, frame_method, 1, "\x00\x14\x00\x0a");
    try testing.expectEqualSlices(u8, "\x01\x00\x01\x00\x00\x00\x04\x00\x14\x00\x0a\xce", w.buffered());
    var r: std.Io.Reader = .fixed(w.buffered());
    var fb: [16]u8 = undefined;
    const f = try readFrame(&r, &fb);
    const m = try parseMethod(f);
    try testing.expectEqual(@as(u16, 1), f.channel);
    try testing.expectEqual(@as(u16, 20), m.class);
    try testing.expectEqual(@as(u16, 10), m.id);

    var r2: std.Io.Reader = .fixed("\x01\x00\x00\x00\x00\x00\x02ab\x00");
    try testing.expectError(error.Protocol, readFrame(&r2, &fb));
    var r3: std.Io.Reader = .fixed("\x01\x00\x00\xff\xff\xff\xff");
    try testing.expectError(error.Protocol, readFrame(&r3, &fb));
    var r4: std.Io.Reader = .fixed("\x01\x00\x00\x00\x00\x00\x05ab");
    try testing.expectError(error.EndOfStream, readFrame(&r4, &fb));
}

test "method encoding and parser bounds" {
    var e: Enc = .{ .gpa = testing.allocator };
    defer e.deinit();
    try e.method(60, 40);
    try e.int(u16, 0);
    try e.shortstr("ex");
    try e.shortstr("rk");
    try e.int(u8, 1);
    try testing.expectEqualSlices(u8, "\x00\x3c\x00\x28\x00\x00\x02ex\x02rk\x01", e.list.items);
    var p: Parser = .{ .buf = e.list.items[4..] };
    _ = try p.int(u16);
    try testing.expectEqualStrings("ex", try p.shortstr());
    try testing.expectEqualStrings("rk", try p.shortstr());
    try testing.expectError(error.Protocol, p.int(u16));
    var q: Parser = .{ .buf = "\x00\x00\x00\x09abc" };
    try testing.expectError(error.Protocol, q.longstr());
}

test "url parsing and settings validation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const u = try parseUrl(arena.allocator(), "amqps://u%40x:p@broker/v%2Fh");
    try testing.expectEqualStrings("broker", u.host);
    try testing.expectEqual(@as(u16, 5671), u.port);
    try testing.expectEqualStrings("u@x", u.user);
    try testing.expectEqualStrings("v/h", u.vhost);
    try testing.expect(u.tls);
    const d = try parseUrl(arena.allocator(), "amqp://h:1234/");
    try testing.expectEqualStrings("guest", d.user);
    try testing.expectEqualStrings("/", d.vhost);
    try testing.expectEqual(@as(u16, 1234), d.port);
    try testing.expectError(error.InvalidConfig, parseUrl(arena.allocator(), "http://h/"));
    try testing.expectError(error.InvalidConfig, parseUrl(arena.allocator(), ""));

    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, create(gpa, .{}));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = "amqp://h/" }, .{ .key = "delivery_mode", .value = "3" } } }));
    try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = "amqp://h/" }, .{ .key = "exchange", .value = "x" ** 256 } } }));
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = "amqp://h/" }, .{ .key = "durable", .value = "on" } } });
    c.deinit();
}

// Scripted broker for one connection; records the published body.
const FakeBroker = struct {
    srv: std.net.Server,
    confirms: bool,
    ack_id: u16 = 80,
    close_on_declare: bool = false,
    body: [16384]u8 = undefined,
    body_len: usize = 0,
    delivery_mode: u8 = 0,
    got_close_ok: bool = false,
    ok: bool = false,

    fn method(w: *std.Io.Writer, ch: u16, class: u16, id: u16, args: []const u8) !void {
        var b: [256]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], class, .big);
        std.mem.writeInt(u16, b[2..4], id, .big);
        @memcpy(b[4..][0..args.len], args);
        try writeFrame(w, frame_method, ch, b[0 .. 4 + args.len]);
        try w.flush();
    }

    fn want(r: *std.Io.Reader, buf: []u8, class: u16, id: u16) !Method {
        const m = try parseMethod(try readFrame(r, buf));
        if (m.class != class or m.id != id) return error.Unexpected;
        return m;
    }

    fn run(f: *FakeBroker) void {
        f.serve() catch return;
        f.ok = true;
    }

    fn serve(f: *FakeBroker) !void {
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [8192]u8 = undefined;
        var wb: [8192]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const r = sr.interface();
        const w = &sw.interface;
        var fb: [8192]u8 = undefined;
        var hdr: [8]u8 = undefined;
        try r.readSliceAll(&hdr);
        if (!std.mem.eql(u8, &hdr, "AMQP\x00\x00\x09\x01")) return error.Unexpected;
        try method(w, 0, 10, 10, "\x00\x09\x00\x00\x00\x00\x00\x00\x00\x05PLAIN\x00\x00\x00\x05en_US");
        var so = try want(r, &fb, 10, 11);
        _ = try so.args.longstr();
        if (!std.mem.eql(u8, try so.args.shortstr(), "PLAIN")) return error.Unexpected;
        if (!std.mem.eql(u8, try so.args.longstr(), "\x00guest\x00guest")) return error.Unexpected;
        try method(w, 0, 10, 30, "\x00\x00\x00\x00\x10\x00\x00\x3c"); // frame_max 4096
        var to = try want(r, &fb, 10, 31);
        _ = try to.args.int(u16);
        if (try to.args.int(u32) != 4096) return error.Unexpected;
        var op = try want(r, &fb, 10, 40);
        if (!std.mem.eql(u8, try op.args.shortstr(), "/")) return error.Unexpected;
        try method(w, 0, 10, 41, "\x00");
        _ = try want(r, &fb, 20, 10);
        try method(w, 1, 20, 11, "\x00\x00\x00\x00");
        var ed = try want(r, &fb, 40, 10);
        _ = try ed.args.int(u16);
        if (!std.mem.eql(u8, try ed.args.shortstr(), "ex")) return error.Unexpected;
        if (!std.mem.eql(u8, try ed.args.shortstr(), "fanout")) return error.Unexpected;
        if (f.close_on_declare) {
            try method(w, 0, 10, 50, "\x01\x18\x03bad\x00\x28\x00\x0a");
            _ = try want(r, &fb, 10, 51);
            f.got_close_ok = true;
            return;
        }
        try method(w, 1, 40, 11, "");
        if (f.confirms) {
            _ = try want(r, &fb, 85, 10);
            try writeFrame(w, frame_heartbeat, 0, "");
            try method(w, 1, 85, 11, "");
            const hb = try readFrame(r, &fb);
            if (hb.kind != frame_heartbeat) return error.Unexpected;
        }
        var pb = try want(r, &fb, 60, 40);
        _ = try pb.args.int(u16);
        if (!std.mem.eql(u8, try pb.args.shortstr(), "ex")) return error.Unexpected;
        if (!std.mem.eql(u8, try pb.args.shortstr(), "rk")) return error.Unexpected;
        const h = try readFrame(r, &fb);
        if (h.kind != frame_header) return error.Unexpected;
        var hp: Parser = .{ .buf = h.payload };
        _ = try hp.int(u32);
        const size = try hp.int(u64);
        const flags = try hp.int(u16);
        if (!std.mem.eql(u8, try hp.shortstr(), "application/json")) return error.Unexpected;
        if (flags & 0x1000 != 0) f.delivery_mode = try hp.int(u8);
        while (f.body_len < size) {
            const b = try readFrame(r, &fb);
            if (b.kind != frame_body or b.payload.len > 4096 - 8) return error.Unexpected;
            @memcpy(f.body[f.body_len..][0..b.payload.len], b.payload);
            f.body_len += b.payload.len;
        }
        if (f.confirms) try method(w, 1, 60, f.ack_id, "\x00\x00\x00\x00\x00\x00\x00\x01\x00");
    }
};

fn fakePublish(f: *FakeBroker, extra: []const target.Kv, body: []const u8) !void {
    f.srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{});
    defer f.srv.deinit();
    var ub: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&ub, "amqp://127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    var kvs: std.ArrayList(target.Kv) = .empty;
    defer kvs.deinit(testing.allocator);
    try kvs.appendSlice(testing.allocator, &.{ .{ .key = "url", .value = url }, .{ .key = "exchange", .value = "ex" }, .{ .key = "exchange_type", .value = "fanout" }, .{ .key = "routing_key", .value = "rk" } });
    try kvs.appendSlice(testing.allocator, extra);
    const t = try std.Thread.spawn(.{}, FakeBroker.run, .{f});
    const c = try create(testing.allocator, .{ .kvs = kvs.items });
    const res = c.send(&.{ .body = body });
    c.deinit();
    t.join();
    try testing.expect(f.ok);
    return res;
}

test "fake broker: publish with confirms, large body, nack, no confirms, server close" {
    const big = "x" ** 10000;
    var f: FakeBroker = .{ .srv = undefined, .confirms = true };
    try fakePublish(&f, &.{ .{ .key = "publisher_confirms", .value = "on" }, .{ .key = "delivery_mode", .value = "2" } }, big);
    try testing.expectEqualStrings(big, f.body[0..f.body_len]);
    try testing.expectEqual(@as(u8, 2), f.delivery_mode);

    f = .{ .srv = undefined, .confirms = true, .ack_id = 120 };
    try testing.expectError(error.Rejected, fakePublish(&f, &.{.{ .key = "publisher_confirms", .value = "on" }}, "{}"));

    f = .{ .srv = undefined, .confirms = false };
    try fakePublish(&f, &.{}, "{\"a\":1}");
    try testing.expectEqualStrings("{\"a\":1}", f.body[0..f.body_len]);
    try testing.expectEqual(@as(u8, 0), f.delivery_mode);

    f = .{ .srv = undefined, .confirms = false, .close_on_declare = true };
    try testing.expectError(error.Rejected, fakePublish(&f, &.{}, "{}"));
    try testing.expect(f.got_close_ok);
}

test "unreachable broker" {
    const c = try create(testing.allocator, .{ .kvs = &.{.{ .key = "url", .value = "amqp://127.0.0.1:1/" }} });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .body = "{}" }));
}

test "events live amqp" {
    const url = std.posix.getenv("ZKFSM_TEST_AMQP") orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const pc = try create(gpa, .{ .kvs = &.{
        .{ .key = "url", .value = url },
        .{ .key = "exchange", .value = "zkev.ex" },
        .{ .key = "exchange_type", .value = "direct" },
        .{ .key = "routing_key", .value = "zkev.rk" },
        .{ .key = "publisher_confirms", .value = "on" },
        .{ .key = "mandatory", .value = "on" },
    } });
    defer pc.deinit();
    const p: *Amqp = @ptrCast(@alignCast(pc.ctx));
    try p.connect();

    // Reader connection: exclusive queue bound to the exchange.
    const rc = try create(gpa, .{ .kvs = &.{.{ .key = "url", .value = url }} });
    defer rc.deinit();
    const q: *Amqp = @ptrCast(@alignCast(rc.ctx));
    try q.connect();
    const e = &q.enc;
    try e.method(50, 10);
    try e.int(u16, 0);
    try e.shortstr("zkev.q");
    try e.int(u8, 4); // exclusive
    try e.int(u32, 0);
    try q.sendMethod(channel);
    _ = try q.expect(50, 11);
    try e.method(50, 20);
    try e.int(u16, 0);
    try e.shortstr("zkev.q");
    try e.shortstr("zkev.ex");
    try e.shortstr("zkev.rk");
    try e.int(u8, 0);
    try e.int(u32, 0);
    try q.sendMethod(channel);
    _ = try q.expect(50, 21);

    const body = "{\"live\":" ++ "1" ** 200000 ++ "}";
    try pc.send(&.{ .body = body });

    try e.method(60, 70);
    try e.int(u16, 0);
    try e.shortstr("zkev.q");
    try e.int(u8, 1); // no-ack
    try q.sendMethod(channel);
    _ = try q.expect(60, 71);
    const c = q.conn.?;
    const h = try readFrame(c.reader(), q.rbuf);
    try testing.expectEqual(frame_header, h.kind);
    var hp: Parser = .{ .buf = h.payload };
    _ = try hp.int(u32);
    const size = try hp.int(u64);
    try testing.expectEqual(@as(u64, body.len), size);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    while (got.items.len < size) {
        const b = try readFrame(c.reader(), q.rbuf);
        try testing.expectEqual(frame_body, b.kind);
        try got.appendSlice(gpa, b.payload);
    }
    try testing.expectEqualStrings(body, got.items);

    // Unroutable mandatory publish is returned and fails the send.
    const uc = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = url }, .{ .key = "exchange", .value = "zkev.ex" }, .{ .key = "routing_key", .value = "nowhere" }, .{ .key = "publisher_confirms", .value = "on" }, .{ .key = "mandatory", .value = "on" } } });
    defer uc.deinit();
    try testing.expectError(error.Rejected, uc.send(&.{ .body = "{}" }));
    // Bad credentials are a rejection, not an outage.
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    const at = std.mem.indexOfScalar(u8, url, '@') orelse return;
    try bad.print(gpa, "amqp://nobody:wrong{s}", .{url[at..]});
    const bc = try create(gpa, .{ .kvs = &.{.{ .key = "url", .value = bad.items }} });
    defer bc.deinit();
    try testing.expectError(error.Rejected, bc.send(&.{ .body = "{}" }));
}
