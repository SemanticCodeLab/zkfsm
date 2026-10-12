//! Kafka producer target over the native wire protocol: ApiVersions, SASL
//! (PLAIN, SCRAM-SHA-256/512), Metadata leader lookup, Produce v3 with
//! record batch v2 and acks=all.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "brokers", "topic", "sasl", "sasl_username", "sasl_password", "sasl_mechanism", "tls", "tls_skip_verify", "tls_client_auth", "client_tls_cert", "client_tls_key", "tls_ca_file", "tls_server_name", "tls_min_version", "version", "batch_size", "queue_dir", "queue_limit", "comment" };

const default_port: u16 = 9092;
const max_frame: usize = 64 << 20;
const max_scram_iterations: u32 = 1_000_000;
const client_id = "zkfsm";

const api_produce: i16 = 0;
const api_fetch: i16 = 1;
const api_metadata: i16 = 3;
const api_sasl_handshake: i16 = 17;
const api_versions: i16 = 18;
const api_sasl_authenticate: i16 = 36;

pub const Mechanism = enum { plain, sha256, sha512 };

const Broker = struct { host: []const u8, port: u16 };
const Node = struct { id: i32, host: []const u8, port: u16 };
const Partition = struct { id: i32, leader: i32 };

/// Wire-level failures; mapped onto SendError at the `send` boundary.
const WireError = error{ Unreachable, Rejected, OutOfMemory };

pub const Kafka = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    brokers: []Broker,
    topic: []const u8,
    sasl: ?struct { mech: Mechanism, user: []const u8, pass: []const u8 },
    opts: net.Options,
    conn: ?*net.Conn = null,
    /// Node id of `conn`; -1 for a bootstrap broker.
    conn_node: i32 = -1,
    corr: i32 = 0,
    meta: ?std.heap.ArenaAllocator = null,
    nodes: []Node = &.{},
    parts: []Partition = &.{},

    fn drop(k: *Kafka) void {
        if (k.conn) |c| c.close();
        k.conn = null;
        k.conn_node = -1;
    }

    fn clearMeta(k: *Kafka) void {
        if (k.meta) |*m| m.deinit();
        k.meta = null;
        k.nodes = &.{};
        k.parts = &.{};
    }

    pub fn deinit(k: *Kafka) void {
        k.drop();
        k.clearMeta();
        k.arena.deinit();
        k.gpa.destroy(k);
    }

    /// Opens an authenticated connection to host:port.
    fn open(k: *Kafka, host: []const u8, port: u16, node: i32) WireError!void {
        k.drop();
        k.conn = net.dial(k.gpa, host, port, k.opts) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        k.conn_node = node;
        errdefer k.drop();
        try k.apiVersions();
        if (k.sasl != null) try k.authenticate();
    }

    fn openBootstrap(k: *Kafka) WireError!void {
        var last: WireError = error.Unreachable;
        for (k.brokers) |b| {
            k.open(b.host, b.port, -1) catch |e| {
                if (e == error.OutOfMemory) return e;
                last = e;
                continue;
            };
            return;
        }
        return last;
    }

    /// Sends one request and returns the response body after the correlation id.
    /// Caller frees the returned buffer (the full frame; body starts at offset 4).
    fn roundTrip(k: *Kafka, api: i16, ver: i16, body: []const u8) WireError![]u8 {
        const c = k.conn orelse return error.Unreachable;
        k.corr +%= 1;
        var hdr: Buf = .{ .gpa = k.gpa };
        defer hdr.deinit();
        try hdr.int(i32, @intCast(10 + client_id.len + body.len));
        try hdr.int(i16, api);
        try hdr.int(i16, ver);
        try hdr.int(i32, k.corr);
        try hdr.str(client_id);
        const w = c.writer();
        w.writeAll(hdr.list.items) catch return k.fail();
        w.writeAll(body) catch return k.fail();
        c.flush() catch return k.fail();
        const r = c.reader();
        var szb: [4]u8 = undefined;
        r.readSliceAll(&szb) catch return k.fail();
        const sz = std.mem.readInt(i32, &szb, .big);
        if (sz < 4 or @as(usize, @intCast(sz)) > max_frame) {
            k.drop();
            return error.Rejected;
        }
        const frame = try k.gpa.alloc(u8, @intCast(sz));
        errdefer k.gpa.free(frame);
        r.readSliceAll(frame) catch return k.fail();
        if (std.mem.readInt(i32, frame[0..4], .big) != k.corr) {
            k.drop();
            return error.Rejected;
        }
        return frame;
    }

    fn fail(k: *Kafka) WireError {
        k.drop();
        return error.Unreachable;
    }

    fn apiVersions(k: *Kafka) WireError!void {
        const frame = try k.roundTrip(api_versions, 0, "");
        defer k.gpa.free(frame);
        var p: Parser = .{ .b = frame[4..] };
        if ((p.int(i16) catch return error.Rejected) != 0) return error.Rejected;
        const n = p.arrayLen(6) catch return error.Rejected;
        var produce_ok = false;
        for (0..n) |_| {
            const key = p.int(i16) catch return error.Rejected;
            const min = p.int(i16) catch return error.Rejected;
            const max = p.int(i16) catch return error.Rejected;
            if (key == api_produce and min <= 3 and max >= 3) produce_ok = true;
        }
        if (!produce_ok) return error.Rejected;
    }

    fn authenticate(k: *Kafka) WireError!void {
        const s = k.sasl.?;
        const name = switch (s.mech) {
            .plain => "PLAIN",
            .sha256 => "SCRAM-SHA-256",
            .sha512 => "SCRAM-SHA-512",
        };
        var b: Buf = .{ .gpa = k.gpa };
        defer b.deinit();
        try b.str(name);
        const hs = try k.roundTrip(api_sasl_handshake, 1, b.list.items);
        defer k.gpa.free(hs);
        var p: Parser = .{ .b = hs[4..] };
        if ((p.int(i16) catch return error.Rejected) != 0) return error.Rejected;
        switch (s.mech) {
            .plain => {
                const msg = try std.mem.concat(k.gpa, u8, &.{ "\x00", s.user, "\x00", s.pass });
                defer k.gpa.free(msg);
                const out = try k.saslStep(msg);
                k.gpa.free(out);
            },
            .sha256 => try k.scram(Scram(std.crypto.hash.sha2.Sha256)),
            .sha512 => try k.scram(Scram(std.crypto.hash.sha2.Sha512)),
        }
    }

    fn scram(k: *Kafka, comptime S: type) WireError!void {
        const s = k.sasl.?;
        var nonce_raw: [18]u8 = undefined;
        std.crypto.random.bytes(&nonce_raw);
        var nonce: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&nonce, &nonce_raw);
        var st = try S.init(k.gpa, s.user, s.pass, &nonce);
        defer st.deinit();
        const first = try k.saslStep(st.client_first);
        defer k.gpa.free(first);
        const final = st.clientFinal(first) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Rejected;
        const last = try k.saslStep(final);
        defer k.gpa.free(last);
        st.verifyServer(last) catch return error.Rejected;
    }

    /// One SaslAuthenticate v0 exchange; returns the server bytes (owned).
    fn saslStep(k: *Kafka, data: []const u8) WireError![]u8 {
        var b: Buf = .{ .gpa = k.gpa };
        defer b.deinit();
        try b.bytes(data);
        const frame = try k.roundTrip(api_sasl_authenticate, 0, b.list.items);
        defer k.gpa.free(frame);
        var p: Parser = .{ .b = frame[4..] };
        const code = p.int(i16) catch return error.Rejected;
        _ = p.nullableStr() catch return error.Rejected;
        const out = p.bytes() catch return error.Rejected;
        if (code != 0) return error.Rejected;
        return k.gpa.dupe(u8, out orelse "");
    }

    fn refreshMeta(k: *Kafka) WireError!void {
        k.clearMeta();
        if (k.conn == null) try k.openBootstrap();
        var b: Buf = .{ .gpa = k.gpa };
        defer b.deinit();
        try b.int(i32, 1);
        try b.str(k.topic);
        const frame = try k.roundTrip(api_metadata, 1, b.list.items);
        defer k.gpa.free(frame);
        var arena = std.heap.ArenaAllocator.init(k.gpa);
        errdefer arena.deinit();
        parseMetadata(arena.allocator(), frame[4..], k.topic, &k.nodes, &k.parts) catch |e| {
            k.nodes = &.{};
            k.parts = &.{};
            return if (e == error.OutOfMemory) error.OutOfMemory else error.Rejected;
        };
        k.meta = arena;
    }

    fn partitionFor(k: *Kafka, key: []const u8) Partition {
        const h = murmur2(key) & 0x7fffffff;
        return k.parts[h % k.parts.len];
    }

    fn connectLeader(k: *Kafka, leader: i32) WireError!void {
        if (k.conn != null and k.conn_node == leader) return;
        for (k.nodes) |n| if (n.id == leader) {
            // A bootstrap connection to the same address is reused.
            if (k.conn != null and k.conn_node == -1 and k.sameBootstrap(n)) {
                k.conn_node = leader;
                return;
            }
            return k.open(n.host, n.port, leader);
        };
        k.clearMeta();
        return error.Rejected;
    }

    fn sameBootstrap(k: *Kafka, n: Node) bool {
        return k.brokers.len == 1 and k.brokers[0].port == n.port and std.mem.eql(u8, k.brokers[0].host, n.host);
    }

    fn produce(k: *Kafka, part: i32, key: []const u8, value: []const u8) WireError!void {
        var batch: Buf = .{ .gpa = k.gpa };
        defer batch.deinit();
        try encodeBatch(&batch, key, value, std.time.milliTimestamp());
        var b: Buf = .{ .gpa = k.gpa };
        defer b.deinit();
        try b.int(i16, -1); // null transactional id
        try b.int(i16, -1); // acks=all
        try b.int(i32, 30_000);
        try b.int(i32, 1);
        try b.str(k.topic);
        try b.int(i32, 1);
        try b.int(i32, part);
        try b.bytes(batch.list.items);
        const frame = try k.roundTrip(api_produce, 3, b.list.items);
        defer k.gpa.free(frame);
        const code = parseProduce(frame[4..], k.topic, part) catch return error.Rejected;
        if (code != 0) {
            k.clearMeta();
            return error.Rejected;
        }
    }

    fn sendImpl(k: *Kafka, msg: *const target.Message) WireError!void {
        if (k.parts.len == 0) try k.refreshMeta();
        const p = k.partitionFor(msg.key);
        if (p.leader < 0) {
            k.clearMeta();
            return error.Rejected;
        }
        try k.connectLeader(p.leader);
        try k.produce(p.id, msg.key, msg.body);
    }

    fn sendFn(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const k: *Kafka = @ptrCast(@alignCast(ctx));
        return k.sendImpl(msg);
    }

    fn deinitFn(ctx: *anyopaque) void {
        const k: *Kafka = @ptrCast(@alignCast(ctx));
        k.deinit();
    }

    const vtable: target.Client.VTable = .{ .send = sendFn, .deinit = deinitFn };
};

pub fn parseMechanism(s: []const u8) error{InvalidConfig}!Mechanism {
    const eq = std.ascii.eqlIgnoreCase;
    if (s.len == 0 or eq(s, "plain")) return .plain;
    if (eq(s, "sha256") or eq(s, "scram-sha-256")) return .sha256;
    if (eq(s, "sha512") or eq(s, "scram-sha-512")) return .sha512;
    return error.InvalidConfig;
}

/// Validates settings; no I/O until the first send.
pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const k = try createKafka(gpa, s);
    return .{ .ctx = k, .vtable = &Kafka.vtable };
}

fn createKafka(gpa: std.mem.Allocator, s: target.Settings) target.InitError!*Kafka {
    const topic = s.get("topic");
    if (topic.len == 0 or topic.len > 249) return error.InvalidConfig;
    const mech = try parseMechanism(s.get("sasl_mechanism"));
    if (s.flag("sasl") and s.get("sasl_username").len == 0) return error.InvalidConfig;

    const k = try gpa.create(Kafka);
    errdefer gpa.destroy(k);
    k.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa), .brokers = &.{}, .topic = "", .sasl = null, .opts = .{} };
    errdefer k.arena.deinit();
    const a = k.arena.allocator();
    var list: std.ArrayList(Broker) = .empty;
    var it = std.mem.splitScalar(u8, s.get("brokers"), ',');
    while (it.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t");
        if (item.len == 0) continue;
        const hp = net.splitHostPort(item, default_port) catch return error.InvalidConfig;
        if (hp[0].len == 0 or hp[1] == 0) return error.InvalidConfig;
        try list.append(a, .{ .host = try a.dupe(u8, hp[0]), .port = hp[1] });
    }
    if (list.items.len == 0) return error.InvalidConfig;
    k.brokers = list.items;
    k.topic = try a.dupe(u8, topic);
    if (s.flag("sasl")) k.sasl = .{ .mech = mech, .user = try a.dupe(u8, s.get("sasl_username")), .pass = try a.dupe(u8, s.get("sasl_password")) };
    // tls_client_auth is the broker's policy in MinIO; the certificate decides here.
    if (s.flag("tls")) k.opts.tls = try net.tlsOptions(a, s, .{ .cert = "client_tls_cert", .key = "client_tls_key" });
    return k;
}

// ---- encoding ----

const Buf = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(u8) = .empty,

    fn deinit(b: *Buf) void {
        b.list.deinit(b.gpa);
    }
    fn int(b: *Buf, comptime T: type, v: T) error{OutOfMemory}!void {
        var tmp: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .big);
        try b.list.appendSlice(b.gpa, &tmp);
    }
    fn str(b: *Buf, s: []const u8) error{OutOfMemory}!void {
        try b.int(i16, @intCast(s.len));
        try b.list.appendSlice(b.gpa, s);
    }
    fn bytes(b: *Buf, s: []const u8) error{OutOfMemory}!void {
        try b.int(i32, @intCast(s.len));
        try b.list.appendSlice(b.gpa, s);
    }
    /// Zigzag varint as used inside v2 records.
    fn varint(b: *Buf, v: i64) error{OutOfMemory}!void {
        var z: u64 = @bitCast((v << 1) ^ (v >> 63));
        while (z >= 0x80) : (z >>= 7) try b.list.append(b.gpa, @as(u8, @truncate(z)) | 0x80);
        try b.list.append(b.gpa, @truncate(z));
    }
};

pub fn crc32c(data: []const u8) u32 {
    return std.hash.crc.Crc32Iscsi.hash(data);
}

/// One record batch (magic 2) holding a single record.
fn encodeBatch(b: *Buf, key: []const u8, value: []const u8, ts: i64) error{OutOfMemory}!void {
    var rec: Buf = .{ .gpa = b.gpa };
    defer rec.deinit();
    try rec.list.append(rec.gpa, 0); // attributes
    try rec.varint(0); // timestamp delta
    try rec.varint(0); // offset delta
    if (key.len == 0) try rec.varint(-1) else {
        try rec.varint(@intCast(key.len));
        try rec.list.appendSlice(rec.gpa, key);
    }
    try rec.varint(@intCast(value.len));
    try rec.list.appendSlice(rec.gpa, value);
    try rec.varint(0); // headers

    const start = b.list.items.len;
    try b.int(i64, 0); // base offset
    try b.int(i32, 0); // batch length, patched below
    try b.int(i32, -1); // partition leader epoch
    try b.list.append(b.gpa, 2); // magic
    try b.int(u32, 0); // crc, patched below
    const crc_from = b.list.items.len;
    try b.int(i16, 0); // attributes
    try b.int(i32, 0); // last offset delta
    try b.int(i64, ts);
    try b.int(i64, ts);
    try b.int(i64, -1); // producer id
    try b.int(i16, -1); // producer epoch
    try b.int(i32, -1); // base sequence
    try b.int(i32, 1); // record count
    try b.varint(@intCast(rec.list.items.len));
    try b.list.appendSlice(b.gpa, rec.list.items);
    const items = b.list.items;
    std.mem.writeInt(i32, items[start + 8 ..][0..4], @intCast(items.len - start - 12), .big);
    std.mem.writeInt(u32, items[crc_from - 4 ..][0..4], crc32c(items[crc_from..]), .big);
}

/// Kafka's default partitioner hash (murmur2, seed 0x9747b28c).
pub fn murmur2(data: []const u8) u32 {
    const m: u32 = 0x5bd1e995;
    var h: u32 = 0x9747b28c ^ @as(u32, @truncate(data.len));
    var i: usize = 0;
    while (i + 4 <= data.len) : (i += 4) {
        var x = std.mem.readInt(u32, data[i..][0..4], .little);
        x *%= m;
        x ^= x >> 24;
        x *%= m;
        h *%= m;
        h ^= x;
    }
    const rest = data[i..];
    if (rest.len >= 3) h ^= @as(u32, rest[2]) << 16;
    if (rest.len >= 2) h ^= @as(u32, rest[1]) << 8;
    if (rest.len >= 1) {
        h ^= rest[0];
        h *%= m;
    }
    h ^= h >> 13;
    h *%= m;
    h ^= h >> 15;
    return h;
}

// ---- decoding ----

const Parser = struct {
    b: []const u8,
    i: usize = 0,

    const Error = error{Malformed};

    fn take(p: *Parser, n: usize) Error![]const u8 {
        if (n > p.b.len - p.i) return error.Malformed;
        defer p.i += n;
        return p.b[p.i..][0..n];
    }
    fn int(p: *Parser, comptime T: type) Error!T {
        return std.mem.readInt(T, (try p.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn nullableStr(p: *Parser) Error!?[]const u8 {
        const n = try p.int(i16);
        if (n < 0) return null;
        return try p.take(@intCast(n));
    }
    fn str(p: *Parser) Error![]const u8 {
        return (try p.nullableStr()) orelse error.Malformed;
    }
    fn bytes(p: *Parser) Error!?[]const u8 {
        const n = try p.int(i32);
        if (n < 0) return null;
        return try p.take(@intCast(n));
    }
    /// Array count bounded by remaining bytes and a minimum element size.
    fn arrayLen(p: *Parser, min_elem: usize) Error!usize {
        const n = try p.int(i32);
        if (n < 0) return 0;
        const u: usize = @intCast(n);
        if (u > (p.b.len - p.i) / @max(min_elem, 1)) return error.Malformed;
        return u;
    }
};

/// Metadata v1 response: brokers and the partitions of `topic`.
fn parseMetadata(a: std.mem.Allocator, body: []const u8, topic: []const u8, nodes: *[]Node, parts: *[]Partition) (Parser.Error || error{ OutOfMemory, TopicError })!void {
    var p: Parser = .{ .b = body };
    const nb = try p.arrayLen(10);
    const ns = try a.alloc(Node, nb);
    for (ns) |*n| {
        const id = try p.int(i32);
        const host = try a.dupe(u8, try p.str());
        const port = try p.int(i32);
        _ = try p.nullableStr(); // rack
        if (port <= 0 or port > 65535) return error.Malformed;
        n.* = .{ .id = id, .host = host, .port = @intCast(port) };
    }
    _ = try p.int(i32); // controller
    const nt = try p.arrayLen(9);
    for (0..nt) |_| {
        const terr = try p.int(i16);
        const name = try p.str();
        _ = try p.int(u8); // internal
        const np = try p.arrayLen(18);
        const mine = std.mem.eql(u8, name, topic);
        if (mine and (terr != 0 or np == 0)) return error.TopicError;
        const ps: []Partition = if (mine) try a.alloc(Partition, np) else &.{};
        for (0..np) |j| {
            _ = try p.int(i16); // partition error
            const id = try p.int(i32);
            const leader = try p.int(i32);
            for (0..2) |_| { // replicas, isr
                const nr = try p.arrayLen(4);
                _ = try p.take(nr * 4);
            }
            if (mine) ps[j] = .{ .id = id, .leader = leader };
        }
        if (mine) {
            nodes.* = ns;
            parts.* = ps;
            return;
        }
    }
    return error.TopicError;
}

/// Produce v3 response: the error code for (topic, part).
fn parseProduce(body: []const u8, topic: []const u8, part: i32) Parser.Error!i16 {
    var p: Parser = .{ .b = body };
    const nt = try p.arrayLen(6);
    for (0..nt) |_| {
        const name = try p.str();
        const np = try p.arrayLen(22);
        for (0..np) |_| {
            const id = try p.int(i32);
            const code = try p.int(i16);
            _ = try p.int(i64);
            _ = try p.int(i64);
            if (id == part and std.mem.eql(u8, name, topic)) return code;
        }
    }
    return error.Malformed;
}

// ---- SCRAM (RFC 5802) ----

fn Scram(comptime H: type) type {
    return struct {
        const Self = @This();
        const Hmac = std.crypto.auth.hmac.Hmac(H);
        const n = H.digest_length;

        gpa: std.mem.Allocator,
        pass: []const u8,
        nonce: []const u8,
        client_first: []u8,
        auth_msg: []u8 = &.{},
        salted: [n]u8 = undefined,
        final: []u8 = &.{},

        const StepError = error{ OutOfMemory, BadServer };

        fn init(gpa: std.mem.Allocator, user: []const u8, pass: []const u8, nonce: []const u8) error{OutOfMemory}!Self {
            var u: std.ArrayList(u8) = .empty;
            defer u.deinit(gpa);
            for (user) |c| switch (c) {
                '=' => try u.appendSlice(gpa, "=3D"),
                ',' => try u.appendSlice(gpa, "=2C"),
                else => try u.append(gpa, c),
            };
            const cf = try std.fmt.allocPrint(gpa, "n,,n={s},r={s}", .{ u.items, nonce });
            return .{ .gpa = gpa, .pass = pass, .nonce = nonce, .client_first = cf };
        }

        fn deinit(s: *Self) void {
            s.gpa.free(s.client_first);
            s.gpa.free(s.auth_msg);
            s.gpa.free(s.final);
        }

        /// Builds client-final from server-first; result is owned by `s`.
        fn clientFinal(s: *Self, server_first: []const u8) StepError![]const u8 {
            var r: []const u8 = "";
            var salt_b64: []const u8 = "";
            var iters: u32 = 0;
            var it = std.mem.splitScalar(u8, server_first, ',');
            while (it.next()) |attr| {
                if (attr.len < 2 or attr[1] != '=') continue;
                switch (attr[0]) {
                    'r' => r = attr[2..],
                    's' => salt_b64 = attr[2..],
                    'i' => iters = std.fmt.parseInt(u32, attr[2..], 10) catch return error.BadServer,
                    else => {},
                }
            }
            if (!std.mem.startsWith(u8, r, s.nonce) or r.len == s.nonce.len) return error.BadServer;
            if (iters == 0 or iters > max_scram_iterations) return error.BadServer;
            const dec = std.base64.standard.Decoder;
            const slen = dec.calcSizeForSlice(salt_b64) catch return error.BadServer;
            if (slen == 0 or slen > 256) return error.BadServer;
            var salt: [256]u8 = undefined;
            dec.decode(salt[0..slen], salt_b64) catch return error.BadServer;
            std.crypto.pwhash.pbkdf2(&s.salted, s.pass, salt[0..slen], iters, Hmac) catch return error.BadServer;

            const without_proof = try std.fmt.allocPrint(s.gpa, "c=biws,r={s}", .{r});
            defer s.gpa.free(without_proof);
            s.auth_msg = try std.mem.concat(s.gpa, u8, &.{ s.client_first[3..], ",", server_first, ",", without_proof });
            var ck: [n]u8 = undefined;
            Hmac.create(&ck, "Client Key", &s.salted);
            var stored: [n]u8 = undefined;
            H.hash(&ck, &stored, .{});
            var sig: [n]u8 = undefined;
            Hmac.create(&sig, s.auth_msg, &stored);
            for (&ck, sig) |*a, b| a.* ^= b;
            var proof: [std.base64.standard.Encoder.calcSize(n)]u8 = undefined;
            _ = std.base64.standard.Encoder.encode(&proof, &ck);
            s.final = try std.fmt.allocPrint(s.gpa, "{s},p={s}", .{ without_proof, proof });
            return s.final;
        }

        fn verifyServer(s: *Self, server_final: []const u8) error{BadServer}!void {
            if (!std.mem.startsWith(u8, server_final, "v=")) return error.BadServer;
            var sk: [n]u8 = undefined;
            Hmac.create(&sk, "Server Key", &s.salted);
            var sig: [n]u8 = undefined;
            Hmac.create(&sig, s.auth_msg, &sk);
            var want: [std.base64.standard.Encoder.calcSize(n)]u8 = undefined;
            _ = std.base64.standard.Encoder.encode(&want, &sig);
            const got = std.mem.trimRight(u8, server_final[2..], "\x00");
            if (!std.mem.eql(u8, got, &want)) return error.BadServer;
        }
    };
}

// ---- tests ----

const testing = std.testing;

/// Test-side decoder for one v2 record batch holding one record.
fn decodeBatch(batch: []const u8) !struct { key: []const u8, value: []const u8 } {
    var p: Parser = .{ .b = batch };
    _ = try p.int(i64);
    const len = try p.int(i32);
    try testing.expectEqual(batch.len - 12, @as(usize, @intCast(len)));
    _ = try p.int(i32);
    try testing.expectEqual(@as(u8, 2), try p.int(u8));
    const crc = try p.int(u32);
    try testing.expectEqual(crc32c(batch[p.i..]), crc);
    _ = try p.take(2 + 4 + 8 + 8 + 8 + 2 + 4);
    try testing.expectEqual(@as(i32, 1), try p.int(i32));
    _ = try readVarint(&p); // record length
    _ = try p.take(1);
    _ = try readVarint(&p);
    _ = try readVarint(&p);
    const kl = try readVarint(&p);
    const key = if (kl < 0) "" else try p.take(@intCast(kl));
    const vl = try readVarint(&p);
    const value = try p.take(@intCast(vl));
    return .{ .key = key, .value = value };
}

fn readVarint(p: *Parser) !i64 {
    var z: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const c = (try p.take(1))[0];
        z |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) break;
        if (shift >= 63) return error.Malformed;
        shift += 7;
    }
    return @as(i64, @bitCast(z >> 1)) ^ -@as(i64, @bitCast(z & 1));
}

test "crc32c and varint vectors" {
    try testing.expectEqual(@as(u32, 0xE3069283), crc32c("123456789"));
    var b: Buf = .{ .gpa = testing.allocator };
    defer b.deinit();
    try b.varint(0);
    try b.varint(-1);
    try b.varint(1);
    try b.varint(150);
    try b.varint(-65);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0xac, 0x02, 0x81, 0x01 }, b.list.items);
    var p: Parser = .{ .b = b.list.items };
    for ([_]i64{ 0, -1, 1, 150, -65 }) |want| try testing.expectEqual(want, try readVarint(&p));
}

test "record batch encoding" {
    var b: Buf = .{ .gpa = testing.allocator };
    defer b.deinit();
    try encodeBatch(&b, "bucket/obj", "{\"x\":1}", 1_700_000_000_000);
    const got = try decodeBatch(b.list.items);
    try testing.expectEqualStrings("bucket/obj", got.key);
    try testing.expectEqualStrings("{\"x\":1}", got.value);
    // 61-byte fixed header + 1 length byte + record.
    try testing.expectEqual(@as(usize, 61 + 1 + 1 + 1 + 1 + 1 + 10 + 1 + 7 + 1), b.list.items.len);
}

test "scram sha256 rfc 7677 vector" {
    const S = Scram(std.crypto.hash.sha2.Sha256);
    var s = try S.init(testing.allocator, "user", "pencil", "rOprNGfwEbeRWgbNEkqO");
    defer s.deinit();
    try testing.expectEqualStrings("n,,n=user,r=rOprNGfwEbeRWgbNEkqO", s.client_first);
    const final = try s.clientFinal("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
    try testing.expectEqualStrings("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", final);
    try s.verifyServer("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    try testing.expectError(error.BadServer, s.verifyServer("v=AAAA"));
}

test "scram rejects hostile server-first" {
    const S = Scram(std.crypto.hash.sha2.Sha512);
    var s = try S.init(testing.allocator, "a=b,c", "p", "abc");
    defer s.deinit();
    try testing.expectEqualStrings("n,,n=a=3Db=2Cc,r=abc", s.client_first);
    try testing.expectError(error.BadServer, s.clientFinal("r=xyz1,s=AAAA,i=1"));
    try testing.expectError(error.BadServer, s.clientFinal("r=abc1,s=AAAA,i=999999999"));
    try testing.expectError(error.BadServer, s.clientFinal("r=abc1,s=!!,i=10"));
}

test "settings validation" {
    const T = struct {
        fn mk(kvs: []const target.Kv) target.InitError!target.Client {
            return create(testing.allocator, .{ .kvs = kvs });
        }
    };
    try testing.expectError(error.InvalidConfig, T.mk(&.{.{ .key = "brokers", .value = "h:9092" }}));
    try testing.expectError(error.InvalidConfig, T.mk(&.{.{ .key = "topic", .value = "t" }}));
    try testing.expectError(error.InvalidConfig, T.mk(&.{ .{ .key = "topic", .value = "t" }, .{ .key = "brokers", .value = "h:x" } }));
    try testing.expectError(error.InvalidConfig, T.mk(&.{ .{ .key = "topic", .value = "t" }, .{ .key = "brokers", .value = "h" }, .{ .key = "sasl_mechanism", .value = "gssapi" } }));
    try testing.expectError(error.InvalidConfig, T.mk(&.{ .{ .key = "topic", .value = "t" }, .{ .key = "brokers", .value = "h" }, .{ .key = "tls", .value = "on" }, .{ .key = "client_tls_cert", .value = "/nonexistent" } }));
    try testing.expectError(error.InvalidConfig, T.mk(&.{ .{ .key = "topic", .value = "t" }, .{ .key = "brokers", .value = "h" }, .{ .key = "sasl", .value = "on" } }));
    const c = try T.mk(&.{ .{ .key = "topic", .value = "t" }, .{ .key = "brokers", .value = "a:1, b ,[::1]:3" }, .{ .key = "sasl", .value = "on" }, .{ .key = "sasl_username", .value = "u" }, .{ .key = "sasl_mechanism", .value = "SCRAM-SHA-512" }, .{ .key = "tls", .value = "on" } });
    defer c.deinit();
    const k: *Kafka = @ptrCast(@alignCast(c.ctx));
    try testing.expectEqual(@as(usize, 3), k.brokers.len);
    try testing.expectEqual(@as(u16, 9092), k.brokers[1].port);
    try testing.expectEqualStrings("::1", k.brokers[2].host);
    try testing.expectEqual(Mechanism.sha512, k.sasl.?.mech);
    try testing.expect(k.opts.tls != null);
    try testing.expectEqual(Mechanism.sha256, try parseMechanism("sha256"));
}

const FakeBroker = struct {
    srv: std.net.Server,
    produce_req: [4096]u8 = undefined,
    produce_len: usize = 0,

    fn reply(s: std.net.Stream, corr: []const u8, body: []const u8) !void {
        var sz: [4]u8 = undefined;
        std.mem.writeInt(i32, &sz, @intCast(4 + body.len), .big);
        try s.writeAll(&sz);
        try s.writeAll(corr);
        try s.writeAll(body);
    }

    fn run(f: *FakeBroker) void {
        f.serve() catch {};
    }

    fn serve(f: *FakeBroker) !void {
        const conn = try f.srv.accept();
        defer conn.stream.close();
        const port: i32 = f.srv.listen_address.getPort();
        var buf: [4096]u8 = undefined;
        while (true) {
            var szb: [4]u8 = undefined;
            if (try conn.stream.readAtLeast(&szb, 4) < 4) return;
            const sz: usize = @intCast(std.mem.readInt(i32, &szb, .big));
            if (sz > buf.len) return error.TooBig;
            if (try conn.stream.readAtLeast(buf[0..sz], sz) < sz) return;
            const req = buf[0..sz];
            const api = std.mem.readInt(i16, req[0..2], .big);
            const corr = req[4..8];
            var b: Buf = .{ .gpa = std.heap.page_allocator };
            defer b.deinit();
            switch (api) {
                api_versions => {
                    try b.int(i16, 0);
                    try b.int(i32, 2);
                    for ([_]i16{ api_produce, 0, 9, api_metadata, 0, 12 }) |v| try b.int(i16, v);
                },
                api_metadata => {
                    try b.int(i32, 1);
                    try b.int(i32, 7);
                    try b.str("127.0.0.1");
                    try b.int(i32, port);
                    try b.int(i16, -1);
                    try b.int(i32, 7);
                    try b.int(i32, 1);
                    try b.int(i16, 0);
                    try b.str("events");
                    try b.list.append(b.gpa, 0);
                    try b.int(i32, 1);
                    try b.int(i16, 0);
                    try b.int(i32, 0);
                    try b.int(i32, 7);
                    try b.int(i32, 1);
                    try b.int(i32, 7);
                    try b.int(i32, 1);
                    try b.int(i32, 7);
                },
                api_produce => {
                    @memcpy(f.produce_req[0..sz], req);
                    f.produce_len = sz;
                    try b.int(i32, 1);
                    try b.str("events");
                    try b.int(i32, 1);
                    try b.int(i32, 0);
                    try b.int(i16, 0);
                    try b.int(i64, 42);
                    try b.int(i64, -1);
                    try b.int(i32, 0);
                },
                else => return error.Unexpected,
            }
            try reply(conn.stream, corr, b.list.items);
            if (api == api_produce) return;
        }
    }
};

test "fake broker receives one framed produce" {
    var f: FakeBroker = .{ .srv = try (try std.net.Address.parseIp("127.0.0.1", 0)).listen(.{}) };
    defer f.srv.deinit();
    const t = try std.Thread.spawn(.{}, FakeBroker.run, .{&f});
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{f.srv.listen_address.getPort()});
    const c = try create(testing.allocator, .{ .kvs = &.{ .{ .key = "topic", .value = "events" }, .{ .key = "brokers", .value = addr } } });
    defer c.deinit();
    try c.send(&.{ .key = "b/o", .body = "hello" });
    t.join();

    var p: Parser = .{ .b = f.produce_req[0..f.produce_len] };
    try testing.expectEqual(api_produce, try p.int(i16));
    try testing.expectEqual(@as(i16, 3), try p.int(i16));
    _ = try p.int(i32);
    try testing.expectEqualStrings(client_id, try p.str());
    try testing.expectEqual(@as(?[]const u8, null), try p.nullableStr());
    try testing.expectEqual(@as(i16, -1), try p.int(i16));
    _ = try p.int(i32);
    try testing.expectEqual(@as(i32, 1), try p.int(i32));
    try testing.expectEqualStrings("events", try p.str());
    try testing.expectEqual(@as(i32, 1), try p.int(i32));
    try testing.expectEqual(@as(i32, 0), try p.int(i32));
    const batch = (try p.bytes()).?;
    try testing.expectEqual(p.b.len, p.i);
    const got = try decodeBatch(batch);
    try testing.expectEqualStrings("b/o", got.key);
    try testing.expectEqualStrings("hello", got.value);

    // Broker gone: next send reports Unreachable.
    try testing.expectError(error.Unreachable, c.send(&.{ .key = "b/o", .body = "x" }));
}

/// Minimal Fetch v4 for the live test: true when `want` is in the partition log.
fn fetchContains(k: *Kafka, part: i32, want: []const u8) !bool {
    var b: Buf = .{ .gpa = k.gpa };
    defer b.deinit();
    try b.int(i32, -1);
    try b.int(i32, 500);
    try b.int(i32, 1);
    try b.int(i32, 1 << 20);
    try b.list.append(b.gpa, 0);
    try b.int(i32, 1);
    try b.str(k.topic);
    try b.int(i32, 1);
    try b.int(i32, part);
    try b.int(i64, 0);
    try b.int(i32, 1 << 20);
    const frame = try k.roundTrip(api_fetch, 4, b.list.items);
    defer k.gpa.free(frame);
    var p: Parser = .{ .b = frame[4..] };
    _ = try p.int(i32);
    const nt = try p.arrayLen(6);
    for (0..nt) |_| {
        _ = try p.str();
        const np = try p.arrayLen(4);
        for (0..np) |_| {
            _ = try p.int(i32);
            try testing.expectEqual(@as(i16, 0), try p.int(i16));
            _ = try p.take(16);
            const na = try p.arrayLen(16);
            _ = try p.take(na * 16);
            const recs = (try p.bytes()) orelse "";
            if (std.mem.indexOf(u8, recs, want) != null) return true;
        }
    }
    return false;
}

test "events live kafka" {
    const addr = std.posix.getenv("ZKFSM_TEST_KAFKA") orelse return error.SkipZigTest;
    const user = std.posix.getenv("ZKFSM_TEST_KAFKA_USER") orelse "";
    const pass = std.posix.getenv("ZKFSM_TEST_KAFKA_PASS") orelse "";
    const mech = std.posix.getenv("ZKFSM_TEST_KAFKA_MECH") orelse "SCRAM-SHA-256";
    var topic_buf: [64]u8 = undefined;
    const topic = try std.fmt.bufPrint(&topic_buf, "zkfsm-live-{d}", .{std.time.milliTimestamp()});
    const c = try create(testing.allocator, .{ .kvs = &.{
        .{ .key = "topic", .value = topic },
        .{ .key = "brokers", .value = addr },
        .{ .key = "sasl", .value = if (user.len > 0) "on" else "off" },
        .{ .key = "sasl_username", .value = user },
        .{ .key = "sasl_password", .value = pass },
        .{ .key = "sasl_mechanism", .value = mech },
    } });
    defer c.deinit();
    var val_buf: [64]u8 = undefined;
    const value = try std.fmt.bufPrint(&val_buf, "{{\"live\":{d}}}", .{std.time.nanoTimestamp()});
    const msg: target.Message = .{ .key = "bucket/live", .body = value };
    // The first sends may race topic auto-creation.
    var tries: usize = 0;
    while (true) : (tries += 1) {
        c.send(&msg) catch |e| {
            if (tries >= 20) return e;
            std.Thread.sleep(500 * std.time.ns_per_ms);
            continue;
        };
        break;
    }
    const k: *Kafka = @ptrCast(@alignCast(c.ctx));
    const part = k.partitionFor(msg.key);
    try testing.expect(try fetchContains(k, part.id, value));
}
