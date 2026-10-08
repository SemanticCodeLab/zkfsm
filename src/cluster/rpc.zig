//! Internal RPC client: HTTP/1.1 to peers on the S3 port under a reserved path, signed
//! per request, with pooled keep-alive connections, per-call timeouts, and a circuit
//! breaker that fails calls fast while a node is down (a heartbeat brings it back).
const std = @import("std");
const posix = std.posix;
const auth = @import("auth.zig");
const core = @import("../core/root.zig");
const topology = @import("topology.zig");

pub const prefix = "/zkfsm/rpc/v1/";

pub const Error = error{
    /// The breaker has the node marked down; the call was not attempted.
    NodeOffline,
    /// Connect, send, receive, or timeout failure.
    Transport,
    /// The peer answered with something that is not a valid response.
    BadResponse,
    OutOfMemory,
};

pub const Opts = struct {
    timeout_ms: u32 = 15_000,
    /// Attempt even while the node is marked offline (heartbeats, bootstrap).
    probe: bool = false,
};

const max_idle_per_peer = 16;
/// Pooled connections idle longer than this are dropped (servers close them at 30 s).
const max_idle_ns: i128 = 15 * std.time.ns_per_s;
const io_buf = 64 * 1024;
const max_head = 16 * 1024;
const connect_timeout_ms = 3000;

const Conn = struct {
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    sw: std.net.Stream.Writer,
    tls: ?std.crypto.tls.Client = null,
    idle_since: i128 = 0,
    rbuf: []u8,
    wbuf: []u8,
    tls_rbuf: []u8 = &.{},
    tls_wbuf: []u8 = &.{},

    fn reader(c: *Conn) *std.Io.Reader {
        return if (c.tls) |*t| &t.reader else c.sr.interface();
    }

    fn writer(c: *Conn) *std.Io.Writer {
        return if (c.tls) |*t| &t.writer else &c.sw.interface;
    }

    /// Pushes buffered bytes through TLS (if any) to the socket.
    fn flush(c: *Conn) error{WriteFailed}!void {
        try c.writer().flush();
        if (c.tls != null) try c.sw.interface.flush();
    }

    fn destroy(c: *Conn, gpa: std.mem.Allocator) void {
        c.stream.close();
        gpa.free(c.rbuf);
        gpa.free(c.wbuf);
        gpa.free(c.tls_rbuf);
        gpa.free(c.tls_wbuf);
        gpa.destroy(c);
    }

    fn setTimeout(c: *Conn, ms: u32) void {
        const tv: posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
        posix.setsockopt(c.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        posix.setsockopt(c.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
    }
};

pub const Peer = struct {
    node: u16,
    host: []const u8,
    port: u16,
    name: []const u8,
    online: std.atomic.Value(bool) = .init(true),
    mutex: std.Thread.Mutex = .{},
    idle: std.ArrayList(*Conn) = .empty,
};

/// Called on every online/offline transition of a peer.
pub const OnChange = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, node: u16, online: bool) void,
};

pub const Rpc = struct {
    gpa: std.mem.Allocator,
    secret: auth.Secret,
    self_node: u16,
    tls: bool,
    /// Trust anchors for peer certificates (TLS clusters).
    ca: ?std.crypto.Certificate.Bundle = null,
    peers: []Peer,
    on_change: ?OnChange = null,

    pub fn init(gpa: std.mem.Allocator, topo: *const topology.Topology, secret: auth.Secret) Error!Rpc {
        const peers = try gpa.alloc(Peer, topo.nodes.len);
        for (topo.nodes, peers, 0..) |n, *p, i| p.* = .{ .node = @intCast(i), .host = n.host, .port = n.port, .name = n.name };
        return .{ .gpa = gpa, .secret = secret, .self_node = topo.local, .tls = topo.tls, .peers = peers };
    }

    pub fn deinit(self: *Rpc) void {
        for (self.peers) |*p| {
            for (p.idle.items) |c| c.destroy(self.gpa);
            p.idle.deinit(self.gpa);
        }
        self.gpa.free(self.peers);
        if (self.ca) |*b| b.deinit(self.gpa);
    }

    pub fn isOnline(self: *Rpc, node: u16) bool {
        return node == self.self_node or self.peers[node].online.load(.acquire);
    }

    pub fn setOnline(self: *Rpc, node: u16, up: bool) void {
        const p = &self.peers[node];
        if (p.online.swap(up, .acq_rel) == up) return;
        if (up) std.log.info("node {s} is online", .{p.name}) else std.log.warn("node {s} is offline", .{p.name});
        if (!up) self.dropIdle(p);
        if (self.on_change) |cb| cb.func(cb.ctx, node, up);
    }

    fn dropIdle(self: *Rpc, p: *Peer) void {
        p.mutex.lock();
        defer p.mutex.unlock();
        for (p.idle.items) |c| c.destroy(self.gpa);
        p.idle.clearRetainingCapacity();
    }

    fn takeIdle(self: *Rpc, p: *Peer) ?*Conn {
        p.mutex.lock();
        defer p.mutex.unlock();
        const now = std.time.nanoTimestamp();
        while (p.idle.pop()) |c| {
            if (now - c.idle_since < max_idle_ns and quiet(c)) return c;
            c.destroy(self.gpa);
        }
        return null;
    }

    fn putIdle(self: *Rpc, p: *Peer, c: *Conn) void {
        p.mutex.lock();
        defer p.mutex.unlock();
        if (p.idle.items.len >= max_idle_per_peer) return c.destroy(self.gpa);
        c.idle_since = std.time.nanoTimestamp();
        p.idle.append(self.gpa, c) catch c.destroy(self.gpa);
    }

    fn connect(self: *Rpc, p: *Peer) Error!*Conn {
        const list = std.net.getAddressList(self.gpa, p.host, p.port) catch return error.Transport;
        defer list.deinit();
        var stream: ?std.net.Stream = null;
        for (list.addrs) |addr| {
            stream = connectTimeout(addr, connect_timeout_ms) catch continue;
            break;
        }
        const s = stream orelse return error.Transport;
        errdefer s.close();
        const c = try self.gpa.create(Conn);
        errdefer self.gpa.destroy(c);
        const tls_len = std.crypto.tls.Client.min_buffer_len;
        c.* = .{ .stream = s, .sr = undefined, .sw = undefined, .rbuf = &.{}, .wbuf = &.{} };
        errdefer {
            self.gpa.free(c.rbuf);
            self.gpa.free(c.wbuf);
            self.gpa.free(c.tls_rbuf);
            self.gpa.free(c.tls_wbuf);
        }
        c.rbuf = try self.gpa.alloc(u8, if (self.tls) tls_len else io_buf);
        c.wbuf = try self.gpa.alloc(u8, if (self.tls) tls_len else io_buf);
        c.sr = s.reader(c.rbuf);
        c.sw = s.writer(c.wbuf);
        if (self.tls) {
            c.tls_rbuf = try self.gpa.alloc(u8, tls_len + io_buf);
            c.tls_wbuf = try self.gpa.alloc(u8, tls_len);
            c.setTimeout(connect_timeout_ms);
            c.tls = std.crypto.tls.Client.init(c.sr.interface(), &c.sw.interface, .{
                .host = .{ .explicit = p.host },
                .ca = if (self.ca) |b| .{ .bundle = b } else .self_signed,
                .read_buffer = c.tls_rbuf,
                .write_buffer = c.tls_wbuf,
                .allow_truncation_attacks = true,
            }) catch |e| {
                std.log.warn("tls handshake with {s} failed: {t}", .{ p.name, e });
                return error.Transport;
            };
        }
        return c;
    }

    pub const Body = union(enum) {
        bytes: []const u8,
        /// Chunked; write with `Call.writeChunk`, then `Call.finish`.
        stream,
    };

    /// Starts a call. With a byte body the response head is already read on return.
    /// A reused connection that fails is retried once on a fresh one.
    pub fn call(self: *Rpc, node: u16, op: []const u8, query: []const u8, body: Body, opts: Opts) Error!Call {
        const p = &self.peers[node];
        if (!opts.probe and !p.online.load(.acquire)) return error.NodeOffline;
        var sp = core.trace.leaf("internode", .client, .internal);
        sp.str("rpc.op", op);
        sp.int("rpc.node", node);
        var handed = false;
        defer if (!handed) {
            sp.fail("rpc failed");
            sp.end();
        };
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            var reused = true;
            const conn = self.takeIdle(p) orelse blk: {
                reused = false;
                break :blk self.connect(p) catch |e| {
                    if (e == error.Transport) self.setOnline(node, false);
                    return e;
                };
            };
            var c: Call = .{ .rpc = self, .peer = p, .conn = conn, .span = sp };
            conn.setTimeout(opts.timeout_ms);
            c.sendHead(op, query, body) catch |e| {
                c.abandon();
                if (e == error.Transport and reused and attempt == 0) continue;
                if (e == error.Transport) self.setOnline(node, false);
                return e;
            };
            if (body == .stream) {
                handed = true;
                return c;
            }
            c.receiveHead() catch |e| {
                c.abandon();
                if (e == error.Transport and reused and attempt == 0) continue;
                if (e == error.Transport) self.setOnline(node, false);
                return e;
            };
            handed = true;
            return c;
        }
    }
};

/// An idle keep-alive connection has nothing to read; EOF or data means it is stale.
fn quiet(c: *Conn) bool {
    if (c.reader().bufferedLen() > 0) return false;
    var fds = [_]posix.pollfd{.{ .fd = c.stream.handle, .events = posix.POLL.IN, .revents = 0 }};
    const n = posix.poll(&fds, 0) catch return false;
    return n == 0;
}

fn connectTimeout(addr: std.net.Address, timeout_ms: i32) !std.net.Stream {
    const fd = try posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.TCP);
    errdefer posix.close(fd);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |e| switch (e) {
        error.WouldBlock => {
            var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
            if (try posix.poll(&fds, timeout_ms) == 0) return error.ConnectionTimedOut;
            try posix.getsockoptError(fd);
        },
        else => return e,
    };
    const fl = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, fl & ~@as(usize, @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))));
    const one: c_int = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
    return .{ .handle = fd };
}

/// Response headers the protocol uses (x-zkfsm-*), copied out of the head.
pub const Meta = struct {
    size: ?u64 = null,
    mtime_ns: ?i128 = null,
    more: bool = false,
    err_buf: [64]u8 = undefined,
    err_len: u8 = 0,

    pub fn err(m: *const Meta) []const u8 {
        return m.err_buf[0..m.err_len];
    }
};

pub const Call = struct {
    rpc: *Rpc,
    peer: *Peer,
    conn: *Conn,
    status: u16 = 0,
    body_left: u64 = 0,
    meta: Meta = .{},
    keep: bool = true,
    /// Client span, ended by `deinit`; its context travels as `traceparent`.
    span: core.trace.Span = .{},

    fn sendHead(c: *Call, op: []const u8, query: []const u8, body: Rpc.Body) Error!void {
        var tbuf: [1024]u8 = undefined;
        const target = std.fmt.bufPrint(&tbuf, "{s}{s}{s}{s}", .{ prefix, op, if (query.len > 0) "?" else "", query }) catch return error.OutOfMemory;
        var nb: [8]u8 = undefined;
        const node = std.fmt.bufPrint(&nb, "{d}", .{c.rpc.self_node}) catch unreachable;
        var timeb: [24]u8 = undefined;
        const time = std.fmt.bufPrint(&timeb, "{d}", .{std.time.milliTimestamp()}) catch unreachable;
        const nonce = auth.newNonce();
        const digest = if (body == .bytes) auth.bodyDigest(body.bytes) else undefined;
        const btag: []const u8 = if (body == .bytes) &digest else auth.body_stream;
        const sig = auth.sign(c.rpc.secret, .{ .method = "POST", .target = target, .node = node, .time = time, .nonce = &nonce, .body = btag });
        const w = c.conn.writer();
        w.print("POST {s} HTTP/1.1\r\nhost: {s}\r\n{s}: {s}\r\n{s}: {s}\r\n{s}: {s}\r\n{s}: {s}\r\n{s}: {s}\r\n", .{
            target,            c.peer.name,
            auth.header_node,  node,
            auth.header_time,  time,
            auth.header_nonce, &nonce,
            auth.header_body,  btag,
            auth.header_sig,   &sig,
        }) catch return error.Transport;
        var tpb: [core.trace.header_len]u8 = undefined;
        const tp: ?[]const u8 = if (c.span.recording) core.trace.format(c.span.ctx, &tpb) else core.trace.outgoing(&tpb);
        if (tp) |v| w.print("traceparent: {s}\r\n", .{v}) catch return error.Transport;
        switch (body) {
            .bytes => |b| {
                w.print("content-length: {d}\r\n\r\n", .{b.len}) catch return error.Transport;
                w.writeAll(b) catch return error.Transport;
            },
            .stream => w.writeAll("transfer-encoding: chunked\r\n\r\n") catch return error.Transport,
        }
        c.conn.flush() catch return error.Transport;
    }

    /// Sends one chunk of a streamed body.
    pub fn writeChunk(c: *Call, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        const w = c.conn.writer();
        w.print("{x}\r\n", .{bytes.len}) catch return c.fail();
        w.writeAll(bytes) catch return c.fail();
        w.writeAll("\r\n") catch return c.fail();
        c.conn.flush() catch return c.fail();
    }

    /// Ends a streamed body and reads the response head.
    pub fn finish(c: *Call) Error!void {
        const w = c.conn.writer();
        w.writeAll("0\r\n\r\n") catch return c.fail();
        c.conn.flush() catch return c.fail();
        c.receiveHead() catch |e| {
            if (e == error.Transport) c.rpc.setOnline(c.peer.node, false);
            return e;
        };
    }

    fn fail(c: *Call) Error {
        c.keep = false;
        c.rpc.setOnline(c.peer.node, false);
        return error.Transport;
    }

    fn receiveHead(c: *Call) Error!void {
        const r = c.conn.reader();
        const status_line = r.takeDelimiterInclusive('\n') catch return error.Transport;
        if (status_line.len < 12 or !std.mem.startsWith(u8, status_line, "HTTP/1.1 ")) return error.BadResponse;
        c.status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.BadResponse;
        var have_len = false;
        var total: usize = status_line.len;
        while (true) {
            const line = r.takeDelimiterInclusive('\n') catch return error.Transport;
            total += line.len;
            if (total > max_head) return error.BadResponse;
            const l = std.mem.trimRight(u8, line, "\r\n");
            if (l.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, l, ':') orelse return error.BadResponse;
            const name = l[0..colon];
            const value = std.mem.trim(u8, l[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                c.body_left = std.fmt.parseInt(u64, value, 10) catch return error.BadResponse;
                have_len = true;
            } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                if (std.ascii.eqlIgnoreCase(value, "close")) c.keep = false;
            } else if (std.ascii.eqlIgnoreCase(name, "x-zkfsm-size")) {
                c.meta.size = std.fmt.parseInt(u64, value, 10) catch return error.BadResponse;
            } else if (std.ascii.eqlIgnoreCase(name, "x-zkfsm-mtime")) {
                c.meta.mtime_ns = std.fmt.parseInt(i128, value, 10) catch return error.BadResponse;
            } else if (std.ascii.eqlIgnoreCase(name, "x-zkfsm-more")) {
                c.meta.more = std.mem.eql(u8, value, "1");
            } else if (std.ascii.eqlIgnoreCase(name, "x-zkfsm-error")) {
                const n = @min(value.len, c.meta.err_buf.len);
                @memcpy(c.meta.err_buf[0..n], value[0..n]);
                c.meta.err_len = @intCast(n);
            }
        }
        if (!have_len) return error.BadResponse;
    }

    /// Reads the whole body (at most `limit` bytes) into memory.
    pub fn readAll(c: *Call, gpa: std.mem.Allocator, limit: usize) Error![]u8 {
        if (c.body_left > limit) return error.BadResponse;
        const out = try gpa.alloc(u8, @intCast(c.body_left));
        errdefer gpa.free(out);
        try c.readInto(out);
        return out;
    }

    /// Fills `buf` from the body; `buf.len` must not exceed what is left.
    pub fn readInto(c: *Call, buf: []u8) Error!void {
        if (buf.len > c.body_left) return error.BadResponse;
        c.conn.reader().readSliceAll(buf) catch {
            c.keep = false;
            return error.Transport;
        };
        c.body_left -= buf.len;
    }

    /// Streams the rest of the body into `sink`.
    pub fn streamTo(c: *Call, sink: *std.Io.Writer) error{ Transport, WriteFailed }!void {
        c.conn.reader().streamExact64(sink, c.body_left) catch |e| {
            c.keep = false;
            return switch (e) {
                error.WriteFailed => error.WriteFailed,
                else => error.Transport,
            };
        };
        c.body_left = 0;
    }

    /// Returns the connection to the pool when the exchange ended cleanly.
    pub fn deinit(c: *Call) void {
        c.span.int("http.response.status_code", c.status);
        if (!c.ok()) c.span.fail("rpc failed");
        c.span.end();
        if (c.keep and c.body_left > 0 and c.body_left <= 64 * 1024) {
            c.conn.reader().discardAll64(c.body_left) catch {
                c.keep = false;
            };
            c.body_left = 0;
        }
        if (c.keep and c.body_left == 0 and c.status != 0) c.rpc.putIdle(c.peer, c.conn) else c.conn.destroy(c.rpc.gpa);
    }

    fn abandon(c: *Call) void {
        c.conn.destroy(c.rpc.gpa);
    }

    pub fn ok(c: *const Call) bool {
        return c.status >= 200 and c.status < 300;
    }
};

test "connect timeout to a closed port fails fast" {
    const addr = try std.net.Address.parseIp("127.0.0.1", 1);
    try std.testing.expectError(error.ConnectionRefused, connectTimeout(addr, 1000));
}
