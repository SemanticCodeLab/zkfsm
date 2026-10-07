//! Apache Pulsar target: a minimal binary-protocol producer (CONNECT, LOOKUP,
//! PRODUCER, SEND) with hand-written protobuf and CRC32C payload frames.
const std = @import("std");
const target = @import("../target.zig");
const net = @import("../net.zig");

pub const keys = [_][]const u8{ "url", "topic", "token", "tls_skip_verify", "queue_dir", "queue_limit", "comment" };

const protocol_version = 15;
const client_version = "zkfsm-pulsar/1";
const max_frame = 64 * 1024; // inbound frames are commands only
const max_url = 256;
const max_topic = 200;
const max_partitions = 4096;
const max_hops = 8;
const default_max_message = 5 * 1024 * 1024;
const hard_max_message = 128 * 1024 * 1024;
const magic: u16 = 0x0e01;

const Type = enum(u32) {
    connect = 2,
    connected = 3,
    producer = 5,
    send = 6,
    send_receipt = 7,
    send_error = 8,
    err = 14,
    close_producer = 15,
    producer_success = 17,
    ping = 18,
    pong = 19,
    partitioned_metadata = 21,
    partitioned_metadata_response = 22,
    lookup = 23,
    lookup_response = 24,
    _,
};

// ---- protobuf ----

const Enc = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    fn deinit(e: *Enc) void {
        e.buf.deinit(e.gpa);
    }

    fn varint(e: *Enc, v: u64) error{OutOfMemory}!void {
        var x = v;
        while (x >= 0x80) : (x >>= 7) try e.buf.append(e.gpa, @as(u8, @truncate(x)) | 0x80);
        try e.buf.append(e.gpa, @truncate(x));
    }

    fn uint(e: *Enc, num: u32, v: u64) error{OutOfMemory}!void {
        try e.varint(@as(u64, num) << 3);
        try e.varint(v);
    }

    fn bytes(e: *Enc, num: u32, b: []const u8) error{OutOfMemory}!void {
        try e.varint(@as(u64, num) << 3 | 2);
        try e.varint(b.len);
        try e.buf.appendSlice(e.gpa, b);
    }
};

const Malformed = error{Malformed};

const Field = struct { num: u64, wire: u3, int: u64 = 0, data: []const u8 = "" };

const Fields = struct {
    buf: []const u8,
    pos: usize = 0,

    fn varint(it: *Fields) Malformed!u64 {
        var v: u64 = 0;
        for (0..10) |n| {
            if (it.pos >= it.buf.len) return error.Malformed;
            const b = it.buf[it.pos];
            it.pos += 1;
            if (n == 9 and b > 1) return error.Malformed;
            v |= @as(u64, b & 0x7f) << @intCast(n * 7);
            if (b < 0x80) return v;
        }
        return error.Malformed;
    }

    fn take(it: *Fields, n: u64) Malformed![]const u8 {
        if (n > it.buf.len - it.pos) return error.Malformed;
        const s = it.buf[it.pos..][0..@intCast(n)];
        it.pos += s.len;
        return s;
    }

    fn next(it: *Fields) Malformed!?Field {
        if (it.pos >= it.buf.len) return null;
        const tag = try it.varint();
        var f: Field = .{ .num = tag >> 3, .wire = @truncate(tag & 7) };
        switch (f.wire) {
            0 => f.int = try it.varint(),
            1 => f.data = try it.take(8),
            2 => f.data = try it.take(try it.varint()),
            5 => f.data = try it.take(4),
            else => return error.Malformed,
        }
        return f;
    }
};

fn getInt(msg: []const u8, num: u64) Malformed!?u64 {
    var it: Fields = .{ .buf = msg };
    var out: ?u64 = null;
    while (try it.next()) |f| {
        if (f.num == num and f.wire == 0) out = f.int;
    }
    return out;
}

fn getBytes(msg: []const u8, num: u64) Malformed!?[]const u8 {
    var it: Fields = .{ .buf = msg };
    var out: ?[]const u8 = null;
    while (try it.next()) |f| {
        if (f.num == num and f.wire == 2) out = f.data;
    }
    return out;
}

// ---- frames ----

/// BaseCommand { type = t; <field t> = inner }.
fn command(gpa: std.mem.Allocator, t: Type, inner: []const u8) error{OutOfMemory}![]u8 {
    var e: Enc = .{ .gpa = gpa };
    errdefer e.deinit();
    try e.uint(1, @intFromEnum(t));
    try e.bytes(@intFromEnum(t), inner);
    return e.buf.toOwnedSlice(gpa);
}

/// `totalSize | commandSize | command`.
fn simpleFrame(gpa: std.mem.Allocator, cmd: []const u8) error{OutOfMemory}![]u8 {
    const out = try gpa.alloc(u8, 8 + cmd.len);
    std.mem.writeInt(u32, out[0..4], @intCast(4 + cmd.len), .big);
    std.mem.writeInt(u32, out[4..8], @intCast(cmd.len), .big);
    @memcpy(out[8..], cmd);
    return out;
}

/// Simple frame plus `magic | crc32c | metadataSize | metadata | payload`;
/// the CRC covers everything after itself.
fn payloadFrame(gpa: std.mem.Allocator, cmd: []const u8, meta: []const u8, payload: []const u8) error{OutOfMemory}![]u8 {
    const total = 4 + cmd.len + 2 + 4 + 4 + meta.len + payload.len;
    if (total > std.math.maxInt(u32)) return error.OutOfMemory;
    const out = try gpa.alloc(u8, 4 + total);
    std.mem.writeInt(u32, out[0..4], @intCast(total), .big);
    std.mem.writeInt(u32, out[4..8], @intCast(cmd.len), .big);
    var p: usize = 8;
    @memcpy(out[p..][0..cmd.len], cmd);
    p += cmd.len;
    std.mem.writeInt(u16, out[p..][0..2], magic, .big);
    const crc_at = p + 2;
    p += 6;
    const covered = p;
    std.mem.writeInt(u32, out[p..][0..4], @intCast(meta.len), .big);
    p += 4;
    @memcpy(out[p..][0..meta.len], meta);
    p += meta.len;
    @memcpy(out[p..][0..payload.len], payload);
    std.mem.writeInt(u32, out[crc_at..][0..4], std.hash.crc.Crc32Iscsi.hash(out[covered..]), .big);
    return out;
}

/// Reads one frame (without the leading total size) into `buf`.
fn readFrame(r: *std.Io.Reader, buf: []u8) error{Unreachable}![]u8 {
    var hdr: [4]u8 = undefined;
    r.readSliceAll(&hdr) catch return error.Unreachable;
    const total = std.mem.readInt(u32, &hdr, .big);
    if (total < 4 or total > buf.len) return error.Unreachable;
    r.readSliceAll(buf[0..total]) catch return error.Unreachable;
    return buf[0..total];
}

const Cmd = struct { type: Type, body: []const u8, rest: []const u8 };

fn parseCommand(frame: []const u8) Malformed!Cmd {
    if (frame.len < 4) return error.Malformed;
    const n = std.mem.readInt(u32, frame[0..4], .big);
    if (n > frame.len - 4) return error.Malformed;
    const cmd = frame[4..][0..n];
    const t = (try getInt(cmd, 1)) orelse return error.Malformed;
    if (t == 0 or t > 1000) return error.Malformed;
    return .{ .type = @enumFromInt(@as(u32, @intCast(t))), .body = (try getBytes(cmd, t)) orelse "", .rest = frame[4 + n ..] };
}

const Payload = struct { meta: []const u8, payload: []const u8 };

fn parsePayload(rest: []const u8) Malformed!Payload {
    if (rest.len < 10 or std.mem.readInt(u16, rest[0..2], .big) != magic) return error.Malformed;
    if (std.mem.readInt(u32, rest[2..6], .big) != std.hash.crc.Crc32Iscsi.hash(rest[6..])) return error.Malformed;
    const m = std.mem.readInt(u32, rest[6..10], .big);
    if (m > rest.len - 10) return error.Malformed;
    return .{ .meta = rest[10..][0..m], .payload = rest[10 + m ..] };
}

// ---- settings ----

const Endpoint = struct {
    host_buf: [max_url]u8 = undefined,
    host_len: usize = 0,
    port: u16 = 0,
    tls: bool = false,

    fn host(e: *const Endpoint) []const u8 {
        return e.host_buf[0..e.host_len];
    }

    fn eql(a: *const Endpoint, b: *const Endpoint) bool {
        return a.port == b.port and a.tls == b.tls and std.ascii.eqlIgnoreCase(a.host(), b.host());
    }
};

fn parseUrl(s: []const u8) error{InvalidConfig}!Endpoint {
    var ep: Endpoint = .{};
    var rest: []const u8 = undefined;
    var default_port: u16 = 6650;
    if (std.ascii.startsWithIgnoreCase(s, "pulsar+ssl://")) {
        ep.tls = true;
        default_port = 6651;
        rest = s["pulsar+ssl://".len..];
    } else if (std.ascii.startsWithIgnoreCase(s, "pulsar://")) {
        rest = s["pulsar://".len..];
    } else return error.InvalidConfig;
    rest = std.mem.trimRight(u8, rest, "/");
    if (rest.len == 0 or std.mem.indexOfAny(u8, rest, "/,@ \t\r\n") != null) return error.InvalidConfig;
    const hp = net.splitHostPort(rest, default_port) catch return error.InvalidConfig;
    if (hp[0].len == 0 or hp[0].len > max_url or hp[1] == 0) return error.InvalidConfig;
    @memcpy(ep.host_buf[0..hp[0].len], hp[0]);
    ep.host_len = hp[0].len;
    ep.port = hp[1];
    return ep;
}

/// Full `persistent://tenant/ns/name`; short names go to public/default.
fn normalizeTopic(t: []const u8, buf: []u8) error{InvalidConfig}![]const u8 {
    if (t.len == 0 or t.len > max_topic) return error.InvalidConfig;
    for (t) |c| if (c <= ' ' or c == 0x7f) return error.InvalidConfig;
    var path = t;
    var scheme: []const u8 = "persistent";
    if (std.mem.indexOf(u8, t, "://")) |i| {
        scheme = t[0..i];
        if (!std.mem.eql(u8, scheme, "persistent") and !std.mem.eql(u8, scheme, "non-persistent")) return error.InvalidConfig;
        path = t[i + 3 ..];
    } else if (std.mem.indexOfScalar(u8, t, '/') == null) {
        return std.fmt.bufPrint(buf, "persistent://public/default/{s}", .{t}) catch error.InvalidConfig;
    }
    var parts: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |p| : (parts += 1) if (p.len == 0) return error.InvalidConfig;
    if (parts != 3) return error.InvalidConfig;
    return std.fmt.bufPrint(buf, "{s}://{s}", .{ scheme, path }) catch error.InvalidConfig;
}

// ---- client ----

const SendError = target.SendError;

const Session = struct { conn: *net.Conn, ep: Endpoint, max_size: usize };

const Producer = struct { conn: *net.Conn, id: u64, name: []u8, seq: u64, max_size: usize };

const Pulsar = struct {
    gpa: std.mem.Allocator,
    service: Endpoint,
    topic: []u8,
    token: []u8,
    skip_verify: bool,
    rx: []u8,
    partitions: ?u32 = null,
    slots: []?Producer = &.{},
    next_id: u64 = 1,

    fn nextId(p: *Pulsar) u64 {
        defer p.next_id +%= 1;
        return p.next_id;
    }

    fn put(conn: *net.Conn, b: []const u8) error{Unreachable}!void {
        conn.writer().writeAll(b) catch return error.Unreachable;
        conn.flush() catch return error.Unreachable;
    }

    fn putCommand(p: *Pulsar, conn: *net.Conn, t: Type, inner: []const u8) SendError!void {
        const cmd = try command(p.gpa, t, inner);
        defer p.gpa.free(cmd);
        const f = try simpleFrame(p.gpa, cmd);
        defer p.gpa.free(f);
        try put(conn, f);
    }

    /// Next command of type `want`, answering pings; slices live until the next read.
    fn waitFor(p: *Pulsar, conn: *net.Conn, want: Type) SendError!Cmd {
        for (0..64) |_| {
            const cmd = parseCommand(try readFrame(conn.reader(), p.rx)) catch return error.Unreachable;
            if (cmd.type == want) return cmd;
            switch (cmd.type) {
                .ping => try p.putCommand(conn, .pong, ""),
                .err, .send_error => return error.Rejected,
                .close_producer => return error.Unreachable,
                else => {},
            }
        }
        return error.Unreachable;
    }

    fn handshake(p: *Pulsar, ep: Endpoint) SendError!Session {
        const opts: net.Options = .{ .tls = if (ep.tls) .{ .skip_verify = p.skip_verify } else null };
        const conn = net.dial(p.gpa, ep.host(), ep.port, opts) catch |e|
            return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        errdefer conn.close();
        var e: Enc = .{ .gpa = p.gpa };
        defer e.deinit();
        try e.bytes(1, client_version);
        try e.uint(4, protocol_version);
        if (p.token.len > 0) {
            try e.bytes(5, "token");
            try e.bytes(3, p.token);
        }
        try p.putCommand(conn, .connect, e.buf.items);
        const c = try p.waitFor(conn, .connected);
        var max: usize = default_max_message;
        if (getInt(c.body, 3) catch return error.Unreachable) |m| {
            if (m > 0) max = @intCast(@min(m, hard_max_message));
        }
        return .{ .conn = conn, .ep = ep, .max_size = max };
    }

    fn partitionCount(p: *Pulsar, s: *Session) SendError!u32 {
        var e: Enc = .{ .gpa = p.gpa };
        defer e.deinit();
        try e.bytes(1, p.topic);
        try e.uint(2, p.nextId());
        try p.putCommand(s.conn, .partitioned_metadata, e.buf.items);
        const c = try p.waitFor(s.conn, .partitioned_metadata_response);
        if (((getInt(c.body, 3) catch return error.Unreachable) orelse 0) != 0) return error.Rejected;
        const n = (getInt(c.body, 1) catch return error.Unreachable) orelse 0;
        if (n > max_partitions) return error.Rejected;
        return @intCast(n);
    }

    /// Follows LOOKUP redirects, reconnecting `s` directly to the owning broker.
    fn locate(p: *Pulsar, s: *Session, topic: []const u8) SendError!void {
        var authoritative = false;
        for (0..max_hops) |_| {
            var e: Enc = .{ .gpa = p.gpa };
            defer e.deinit();
            try e.bytes(1, topic);
            try e.uint(2, p.nextId());
            try e.uint(3, @intFromBool(authoritative));
            try p.putCommand(s.conn, .lookup, e.buf.items);
            const c = try p.waitFor(s.conn, .lookup_response);
            const kind = (getInt(c.body, 3) catch return error.Unreachable) orelse 0;
            if (kind > 1) return error.Rejected;
            authoritative = ((getInt(c.body, 5) catch return error.Unreachable) orelse 0) != 0;
            const url = (getBytes(c.body, if (s.ep.tls) 2 else 1) catch return error.Unreachable) orelse "";
            const next = if (url.len == 0) s.ep else parseUrl(url) catch return error.Rejected;
            if (!next.eql(&s.ep)) {
                const ns = try p.handshake(next);
                s.conn.close();
                s.* = ns;
            }
            if (kind == 1) return;
        }
        return error.Rejected;
    }

    fn openProducer(p: *Pulsar, s: *Session, topic: []const u8) SendError!Producer {
        const id = p.nextId();
        var e: Enc = .{ .gpa = p.gpa };
        defer e.deinit();
        try e.bytes(1, topic);
        try e.uint(2, id);
        try e.uint(3, p.nextId());
        try p.putCommand(s.conn, .producer, e.buf.items);
        var c = try p.waitFor(s.conn, .producer_success);
        // producer_ready=false means queued behind an exclusive producer.
        for (0..8) |_| {
            if (((getInt(c.body, 6) catch return error.Unreachable) orelse 1) != 0) break;
            c = try p.waitFor(s.conn, .producer_success);
        } else return error.Rejected;
        const name = (getBytes(c.body, 2) catch return error.Unreachable) orelse "";
        if (name.len == 0 or name.len > max_url) return error.Rejected;
        const last: i64 = @bitCast((getInt(c.body, 3) catch return error.Unreachable) orelse std.math.maxInt(u64));
        return .{
            .conn = s.conn,
            .id = id,
            .name = try p.gpa.dupe(u8, name),
            .seq = if (last >= 0) @as(u64, @intCast(last)) +% 1 else 0,
            .max_size = s.max_size,
        };
    }

    fn publish(p: *Pulsar, prod: *Producer, msg: *const target.Message) SendError!void {
        if (msg.body.len > prod.max_size) return error.Rejected;
        var meta: Enc = .{ .gpa = p.gpa };
        defer meta.deinit();
        try meta.bytes(1, prod.name);
        try meta.uint(2, prod.seq);
        try meta.uint(3, @intCast(@max(0, std.time.milliTimestamp())));
        if (msg.key.len > 0) try meta.bytes(6, msg.key);
        var e: Enc = .{ .gpa = p.gpa };
        defer e.deinit();
        try e.uint(1, prod.id);
        try e.uint(2, prod.seq);
        try e.uint(3, 1);
        const cmd = try command(p.gpa, .send, e.buf.items);
        defer p.gpa.free(cmd);
        const f = try payloadFrame(p.gpa, cmd, meta.buf.items, msg.body);
        defer p.gpa.free(f);
        try put(prod.conn, f);
        const c = try p.waitFor(prod.conn, .send_receipt);
        if ((getInt(c.body, 2) catch return error.Unreachable) != prod.seq) return error.Unreachable;
        prod.seq +%= 1;
    }

    fn drop(p: *Pulsar, idx: usize, polite: bool) void {
        const prod = p.slots[idx] orelse return;
        if (polite) {
            var e: Enc = .{ .gpa = p.gpa };
            defer e.deinit();
            e.uint(1, prod.id) catch {};
            e.uint(2, p.nextId()) catch {};
            p.putCommand(prod.conn, .close_producer, e.buf.items) catch {};
        }
        prod.conn.close();
        p.gpa.free(prod.name);
        p.slots[idx] = null;
    }

    fn send(ctx: *anyopaque, msg: *const target.Message) SendError!void {
        const p: *Pulsar = @ptrCast(@alignCast(ctx));
        var spare: ?Session = null;
        defer if (spare) |s| s.conn.close();
        if (p.partitions == null) {
            spare = try p.handshake(p.service);
            const n = try p.partitionCount(&spare.?);
            const slots = try p.gpa.alloc(?Producer, @max(n, 1));
            @memset(slots, null);
            p.slots = slots;
            p.partitions = n;
        }
        const n = p.partitions.?;
        const idx: usize = if (n == 0) 0 else std.hash.Murmur3_32.hash(msg.key) % n;
        if (p.slots[idx] == null) {
            var s = if (spare) |sp| sp else try p.handshake(p.service);
            spare = null;
            errdefer s.conn.close();
            var tb: [max_topic + 64]u8 = undefined;
            const topic = if (n == 0) p.topic else std.fmt.bufPrint(&tb, "{s}-partition-{d}", .{ p.topic, idx }) catch return error.Rejected;
            try p.locate(&s, topic);
            p.slots[idx] = try p.openProducer(&s, topic);
        }
        p.publish(&p.slots[idx].?, msg) catch |e| {
            if (e != error.OutOfMemory) p.drop(idx, false);
            return e;
        };
    }

    fn deinit(ctx: *anyopaque) void {
        const p: *Pulsar = @ptrCast(@alignCast(ctx));
        for (0..p.slots.len) |i| p.drop(i, true);
        if (p.slots.len > 0) p.gpa.free(p.slots);
        p.gpa.free(p.rx);
        p.gpa.free(p.topic);
        p.gpa.free(p.token);
        p.gpa.destroy(p);
    }

    const vtable: target.Client.VTable = .{ .send = send, .deinit = deinit };
};

/// Validates settings (no I/O); the broker is dialed on the first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const service = try parseUrl(s.get("url"));
    var tb: [max_topic + 64]u8 = undefined;
    const topic = try normalizeTopic(s.get("topic"), &tb);
    _ = try s.int(u64, "queue_limit", 0);
    const p = try gpa.create(Pulsar);
    errdefer gpa.destroy(p);
    const t = try gpa.dupe(u8, topic);
    errdefer gpa.free(t);
    const tok = try gpa.dupe(u8, s.get("token"));
    errdefer gpa.free(tok);
    const rx = try gpa.alloc(u8, max_frame);
    p.* = .{ .gpa = gpa, .service = service, .topic = t, .token = tok, .skip_verify = s.flag("tls_skip_verify"), .rx = rx };
    return .{ .ctx = p, .vtable = &Pulsar.vtable };
}

// ---- tests ----

const testing = std.testing;

test "protobuf varint and fields" {
    var e: Enc = .{ .gpa = testing.allocator };
    defer e.deinit();
    try e.varint(300);
    try testing.expectEqualSlices(u8, &.{ 0xac, 0x02 }, e.buf.items);
    e.buf.clearRetainingCapacity();
    try e.uint(1, 150);
    try e.bytes(2, "hi");
    try e.uint(3, std.math.maxInt(u64));
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x96, 0x01, 0x12, 0x02, 'h', 'i' }, e.buf.items[0..7]);
    try testing.expectEqual(@as(?u64, 150), try getInt(e.buf.items, 1));
    try testing.expectEqualStrings("hi", (try getBytes(e.buf.items, 2)).?);
    try testing.expectEqual(@as(?u64, std.math.maxInt(u64)), try getInt(e.buf.items, 3));
    try testing.expectEqual(@as(?u64, null), try getInt(e.buf.items, 9));
    // Truncated length, overlong varint, bad wire type.
    try testing.expectError(error.Malformed, getInt(&.{ 0x12, 0x05, 'a' }, 1));
    try testing.expectError(error.Malformed, getInt(&(.{0x08} ++ .{0xff} ** 10 ++ .{0x01}), 1));
    try testing.expectError(error.Malformed, getInt(&.{0x0b}, 1));
}

test "simple and payload frame layout" {
    const gpa = testing.allocator;
    const cmd = try command(gpa, .ping, "");
    defer gpa.free(cmd);
    try testing.expectEqualSlices(u8, &.{ 0x08, 18, 0x92, 0x01, 0x00 }, cmd);
    const f = try simpleFrame(gpa, cmd);
    defer gpa.free(f);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 9, 0, 0, 0, 5 }, f[0..8]);
    const parsed = try parseCommand(f[4..]);
    try testing.expectEqual(Type.ping, parsed.type);

    const pf = try payloadFrame(gpa, cmd, "MD", "body");
    defer gpa.free(pf);
    try testing.expectEqual(@as(u32, @intCast(pf.len - 4)), std.mem.readInt(u32, pf[0..4], .big));
    try testing.expectEqual(magic, std.mem.readInt(u16, pf[13..15], .big));
    const want_crc = std.hash.crc.Crc32Iscsi.hash(&[_]u8{ 0, 0, 0, 2, 'M', 'D', 'b', 'o', 'd', 'y' });
    try testing.expectEqual(want_crc, std.mem.readInt(u32, pf[15..19], .big));
    const c = try parseCommand(pf[4..]);
    const pl = try parsePayload(c.rest);
    try testing.expectEqualStrings("MD", pl.meta);
    try testing.expectEqualStrings("body", pl.payload);
    pf[pf.len - 1] ^= 1;
    try testing.expectError(error.Malformed, parsePayload((try parseCommand(pf[4..])).rest));
    // Oversized declared lengths are refused.
    try testing.expectError(error.Malformed, parseCommand(&.{ 0, 0, 0, 9, 0 }));
}

test "settings validation" {
    const gpa = testing.allocator;
    const ok = [_][2][]const u8{
        .{ "pulsar://h:6650", "zkfsm" },
        .{ "pulsar+ssl://h", "persistent://t/n/x" },
        .{ "pulsar://[::1]:1/", "non-persistent://t/n/x" },
        .{ "pulsar://h", "t/n/x" },
    };
    for (ok) |c| {
        const cl = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = c[0] }, .{ .key = "topic", .value = c[1] } } });
        cl.deinit();
    }
    const bad = [_][2][]const u8{
        .{ "http://h", "x" },
        .{ "pulsar://", "x" },
        .{ "pulsar://h:x", "x" },
        .{ "pulsar://a:1,b:2", "x" },
        .{ "pulsar://h", "" },
        .{ "pulsar://h", "a/b" },
        .{ "pulsar://h", "foo://a/b/c" },
        .{ "pulsar://h", "persistent://a//c" },
        .{ "pulsar://h", "has space" },
    };
    for (bad) |c| try testing.expectError(error.InvalidConfig, create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = c[0] }, .{ .key = "topic", .value = c[1] } } }));
    var b: [300]u8 = undefined;
    try testing.expectEqualStrings("persistent://public/default/zkfsm", try normalizeTopic("zkfsm", &b));
    const ep = try parseUrl("pulsar+ssl://broker");
    try testing.expect(ep.tls and ep.port == 6651);
}

/// Scripted single-connection broker used by the round-trip tests.
const Fake = struct {
    srv: std.net.Server,
    redirect_port: ?u16 = null,
    fail_send: bool = false,
    token: [16]u8 = undefined,
    token_len: usize = 0,
    topic: [64]u8 = undefined,
    topic_len: usize = 0,
    bodies: [4][16]u8 = undefined,
    body_lens: [4]usize = .{0} ** 4,
    seqs: [4]u64 = .{0} ** 4,
    key: [16]u8 = undefined,
    key_len: usize = 0,
    count: usize = 0,
    pongs: usize = 0,

    fn serve(f: *Fake) void {
        f.run() catch {};
    }

    fn copy(dst: []u8, len: *usize, src: []const u8) void {
        const n = @min(dst.len, src.len);
        @memcpy(dst[0..n], src[0..n]);
        len.* = n;
    }

    fn run(f: *Fake) !void {
        const gpa = std.heap.page_allocator;
        const conn = try f.srv.accept();
        defer conn.stream.close();
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var sr = conn.stream.reader(&rb);
        var sw = conn.stream.writer(&wb);
        const w = &sw.interface;
        const buf = try gpa.alloc(u8, 1 << 20);
        defer gpa.free(buf);
        const port = f.srv.listen_address.getPort();
        while (true) {
            const cmd = try parseCommand(readFrame(sr.interface(), buf) catch return);
            var e: Enc = .{ .gpa = gpa };
            defer e.deinit();
            const reply: Type = switch (cmd.type) {
                .connect => blk: {
                    copy(&f.token, &f.token_len, (try getBytes(cmd.body, 3)) orelse "");
                    try e.bytes(1, "fake");
                    try e.uint(2, 15);
                    break :blk .connected;
                },
                .partitioned_metadata => blk: {
                    try e.uint(1, 0);
                    try e.uint(2, (try getInt(cmd.body, 2)).?);
                    break :blk .partitioned_metadata_response;
                },
                .lookup => blk: {
                    var ub: [64]u8 = undefined;
                    try e.bytes(1, try std.fmt.bufPrint(&ub, "pulsar://127.0.0.1:{d}", .{f.redirect_port orelse port}));
                    try e.uint(3, 1);
                    try e.uint(4, (try getInt(cmd.body, 2)).?);
                    break :blk .lookup_response;
                },
                .producer => blk: {
                    copy(&f.topic, &f.topic_len, (try getBytes(cmd.body, 1)).?);
                    try e.uint(1, (try getInt(cmd.body, 3)).?);
                    try e.bytes(2, "fake-producer");
                    try e.uint(3, @bitCast(@as(i64, -1)));
                    break :blk .producer_success;
                },
                .send => blk: {
                    const pl = try parsePayload(cmd.rest);
                    const i = f.count;
                    if (i < 4) {
                        copy(&f.bodies[i], &f.body_lens[i], pl.payload);
                        f.seqs[i] = (try getInt(pl.meta, 2)).?;
                    }
                    copy(&f.key, &f.key_len, (try getBytes(pl.meta, 6)) orelse "");
                    f.count += 1;
                    const ping = try simpleFrame(gpa, &.{ 0x08, 18, 0x92, 0x01, 0x00 });
                    defer gpa.free(ping);
                    try w.writeAll(ping);
                    try e.uint(1, (try getInt(cmd.body, 1)).?);
                    try e.uint(2, (try getInt(cmd.body, 2)).?);
                    break :blk if (f.fail_send) .send_error else .send_receipt;
                },
                .pong => {
                    f.pongs += 1;
                    continue;
                },
                .close_producer => continue,
                else => return,
            };
            const c = try command(gpa, reply, e.buf.items);
            defer gpa.free(c);
            const fr = try simpleFrame(gpa, c);
            defer gpa.free(fr);
            try w.writeAll(fr);
            try w.flush();
        }
    }
};

fn fakeListen() !std.net.Server {
    return (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{});
}

fn testClient(port: u16) !target.Client {
    var ub: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&ub, "pulsar://127.0.0.1:{d}", .{port});
    return create(testing.allocator, .{ .kvs = &.{
        .{ .key = "url", .value = url },
        .{ .key = "topic", .value = "zkfsm" },
        .{ .key = "token", .value = "tok" },
    } });
}

test "fake broker send round trip" {
    var f: Fake = .{ .srv = try fakeListen() };
    defer f.srv.deinit();
    const t = try std.Thread.spawn(.{}, Fake.serve, .{&f});
    const c = try testClient(f.srv.listen_address.getPort());
    c.send(&.{ .key = "b/o1", .body = "one" }) catch |e| {
        c.deinit();
        t.join();
        return e;
    };
    try c.send(&.{ .key = "b/o2", .body = "two" });
    c.deinit();
    t.join();
    try testing.expectEqual(@as(usize, 2), f.count);
    try testing.expectEqualStrings("one", f.bodies[0][0..f.body_lens[0]]);
    try testing.expectEqualStrings("two", f.bodies[1][0..f.body_lens[1]]);
    try testing.expectEqual(@as(u64, 0), f.seqs[0]);
    try testing.expectEqual(@as(u64, 1), f.seqs[1]);
    try testing.expectEqualStrings("b/o2", f.key[0..f.key_len]);
    try testing.expectEqualStrings("tok", f.token[0..f.token_len]);
    try testing.expectEqualStrings("persistent://public/default/zkfsm", f.topic[0..f.topic_len]);
    try testing.expectEqual(@as(usize, 2), f.pongs);
}

test "fake broker lookup redirect and send error" {
    var owner: Fake = .{ .srv = try fakeListen(), .fail_send = true };
    defer owner.srv.deinit();
    var front: Fake = .{ .srv = try fakeListen(), .redirect_port = owner.srv.listen_address.getPort() };
    defer front.srv.deinit();
    const t1 = try std.Thread.spawn(.{}, Fake.serve, .{&front});
    const t2 = try std.Thread.spawn(.{}, Fake.serve, .{&owner});
    const c = try testClient(front.srv.listen_address.getPort());
    const r = c.send(&.{ .body = "x" });
    c.deinit();
    t1.join();
    t2.join();
    try testing.expectError(error.Rejected, r);
    try testing.expectEqual(@as(usize, 0), front.count);
    try testing.expectEqual(@as(usize, 1), owner.count);
}

test "send to a closed port is Unreachable" {
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "url", .value = "pulsar://127.0.0.1:1" }, .{ .key = "topic", .value = "x" } } });
    defer c.deinit();
    try testing.expectError(error.Unreachable, c.send(&.{ .body = "x" }));
}

test "events live pulsar" {
    const gpa = testing.allocator;
    const url = std.process.getEnvVarOwned(gpa, "ZKFSM_TEST_PULSAR") catch return error.SkipZigTest;
    defer gpa.free(url);
    const c = try create(gpa, .{ .kvs = &.{ .{ .key = "url", .value = url }, .{ .key = "topic", .value = "zkfsm-live-test" } } });
    defer c.deinit();
    try c.send(&.{ .key = "bucket/live", .body = "{\"EventName\":\"s3:ObjectCreated:Put\"}" });
    try c.send(&.{ .key = "bucket/live", .body = "{\"EventName\":\"s3:ObjectRemoved:Delete\"}" });
}
