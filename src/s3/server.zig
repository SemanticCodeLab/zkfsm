//! HTTP listener: a fixed worker pool serves accepted connections (keep-alive request
//! loop). A watchdog enforces the idle and header deadlines and the shutdown drain.
//! With a preamble route, a classifier sorts new connections by their first bytes so
//! internal RPC has its own bounded pool that S3 load cannot occupy.
const std = @import("std");
const posix = std.posix;
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const sigv4 = @import("sigv4.zig");
const authz = @import("authz.zig");
const metrics = @import("../metrics/root.zig");
const tls = @import("../tls/root.zig");

pub const RunError = error{ ListenFailed, OutOfMemory, ThreadFailed };

pub const Limits = struct {
    /// Open connections (served plus queued); more are refused with 503.
    max_conns: u32 = 1024,
    /// Connections served at once; each worker owns one connection at a time.
    workers: u32 = 256,
    /// Wait for the next request, and for any single socket read or write.
    idle_timeout_s: u32 = 30,
    /// Total time for a request head once its first byte arrived (slowloris guard).
    header_timeout_s: u32 = 10,
    /// How long shutdown waits for in-flight requests.
    shutdown_timeout_s: u32 = 30,
    /// Workers for preamble (internal RPC) connections; 0 serves them in the S3 pool.
    rpc_workers: u32 = 0,
};

const Phase = enum(u8) { free, idle, head, busy };

pub const RawError = error{ WriteFailed, ReadFailed, OutOfMemory, HttpExpectationFailed };

/// A reserved path served before S3 parsing and authentication (the route
/// authenticates itself). It must consume the request body it accepts.
pub const RawRoute = struct {
    prefix: []const u8,
    ctx: *anyopaque,
    serve: *const fn (ctx: *anyopaque, req: *std.http.Server.Request, arena: std.mem.Allocator) RawError!void,
    /// Connections that open with these bytes (before TLS) belong to this route and
    /// are served by the RPC pool; the bytes are consumed.
    preamble: ?[]const u8 = null,
};

/// Readiness override (cluster quorum); default is a storage sync probe.
pub const Ready = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque) bool,
};

/// One worker's connection, visible to the watchdog.
const Slot = struct {
    mutex: std.Thread.Mutex = .{},
    fd: ?posix.socket_t = null,
    phase: Phase = .free,
    /// Monotonic ns after which the connection is cut; 0 for none.
    deadline: u64 = 0,

    fn set(s: *Slot, phase: Phase, deadline: u64) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        s.phase = phase;
        s.deadline = deadline;
    }
};

/// Bounded FIFO of accepted connections.
const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    items: []std.net.Server.Connection,
    head: usize = 0,
    len: usize = 0,
    closed: bool = false,

    fn push(q: *Queue, c: std.net.Server.Connection) bool {
        q.mutex.lock();
        defer q.mutex.unlock();
        if (q.len == q.items.len) return false;
        q.items[(q.head + q.len) % q.items.len] = c;
        q.len += 1;
        q.cond.signal();
        return true;
    }

    /// Blocks for the next connection; null once closed and empty.
    fn pop(q: *Queue) ?std.net.Server.Connection {
        q.mutex.lock();
        defer q.mutex.unlock();
        while (q.len == 0) {
            if (q.closed) return null;
            q.cond.wait(&q.mutex);
        }
        const c = q.items[q.head];
        q.head = (q.head + 1) % q.items.len;
        q.len -= 1;
        return c;
    }

    fn close(q: *Queue) void {
        q.mutex.lock();
        defer q.mutex.unlock();
        q.closed = true;
        q.cond.broadcast();
    }
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    svc: *object.ObjectService,
    auth: sigv4.Config,
    extensions: []const @import("extension.zig").Extension = &.{},
    observers: []const @import("extension.zig").Observer = &.{},
    routing: @import("router.zig").Routing = .{},
    ops: metrics.Paths = .{},
    /// When set, every connection is TLS-terminated before HTTP.
    tls: ?*tls.Context = null,
    limits: Limits = .{},
    raw_routes: []const RawRoute = &.{},
    ready: ?Ready = null,
    /// While false, S3 requests get 503 (raw routes and health still work).
    open_gate: ?*const std.atomic.Value(bool) = null,

    stopping: std.atomic.Value(bool) = .init(false),
    listen_fd: std.atomic.Value(posix.socket_t) = .init(-1),
    open_conns: std.atomic.Value(u32) = .init(0),
    drain_deadline: std.atomic.Value(u64) = .init(0),

    /// Stops accepting and starts the drain; `run` returns once drained.
    /// Async-signal-safe: atomics and one shutdown(2).
    /// Returns false when a stop was already requested.
    pub fn requestStop(self: *Server) bool {
        if (self.stopping.swap(true, .seq_cst)) return false;
        const fd = self.listen_fd.load(.seq_cst);
        if (fd >= 0) _ = std.os.linux.shutdown(fd, posix.SHUT.RD);
        return true;
    }

    pub fn run(self: *Server, addr: std.net.Address) RunError!void {
        var listener = addr.listen(.{ .reuse_address = true, .kernel_backlog = 1024 }) catch return error.ListenFailed;
        defer listener.deinit();
        self.listen_fd.store(listener.stream.handle, .seq_cst);
        defer self.listen_fd.store(-1, .seq_cst);
        std.log.info("zkfsm listening on {f}", .{addr});

        const preamble = self.rpcPreamble();
        const n_rpc: usize = if (preamble != null) self.limits.rpc_workers else 0;
        const items = try self.gpa.alloc(std.net.Server.Connection, @max(1, self.limits.max_conns));
        defer self.gpa.free(items);
        var queue: Queue = .{ .items = items };
        const rpc_items = try self.gpa.alloc(std.net.Server.Connection, @max(1, 2 * n_rpc));
        defer self.gpa.free(rpc_items);
        var rpc_queue: Queue = .{ .items = rpc_items };
        const n_s3: usize = @max(1, self.limits.workers);
        const slots = try self.gpa.alloc(Slot, n_s3 + n_rpc);
        defer self.gpa.free(slots);
        for (slots) |*s| s.* = .{};
        const threads = try self.gpa.alloc(std.Thread, slots.len);
        defer self.gpa.free(threads);

        // Deferred in reverse: workers are joined (drained) before the watchdog stops.
        var watch_done: std.atomic.Value(bool) = .init(false);
        const watch = std.Thread.spawn(.{}, watchdog, .{ self, slots, &watch_done }) catch return error.ThreadFailed;
        defer {
            watch_done.store(true, .seq_cst);
            watch.join();
        }
        var started: usize = 0;
        defer {
            queue.close();
            rpc_queue.close();
            for (threads[0..started]) |t| t.join();
        }
        for (slots, threads, 0..) |*s, *t, i| {
            const rpc = i >= n_s3;
            t.* = std.Thread.spawn(.{ .stack_size = 4 * 1024 * 1024 }, worker, .{ self, if (rpc) &rpc_queue else &queue, s, rpc }) catch return error.ThreadFailed;
            started += 1;
        }
        var cls: ?Classifier = null;
        if (n_rpc > 0) {
            cls = Classifier.init(self, preamble.?, &queue, &rpc_queue) catch return error.ThreadFailed;
        }
        defer if (cls) |*c| c.deinit();
        var cls_thread: ?std.Thread = null;
        if (cls) |*c| cls_thread = std.Thread.spawn(.{}, Classifier.loop, .{c}) catch return error.ThreadFailed;
        defer if (cls_thread) |t| {
            cls.?.stop.store(true, .seq_cst);
            t.join();
        };

        while (!self.stopping.load(.seq_cst)) {
            const conn = listener.accept() catch |e| {
                if (self.stopping.load(.seq_cst)) break;
                std.log.warn("accept failed: {t}", .{e});
                // Out of descriptors or memory: back off instead of spinning.
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            if (cls) |*c| c.add(conn) else self.admit(&queue, conn);
        }
        const grace = @as(u64, self.limits.shutdown_timeout_s) * std.time.ns_per_s;
        self.drain_deadline.store(now() + grace, .seq_cst);
        std.log.info("shutting down: draining in-flight requests (up to {d}s)", .{self.limits.shutdown_timeout_s});
    }

    fn rpcPreamble(self: *const Server) ?[]const u8 {
        for (self.raw_routes) |r| if (r.preamble) |p| return p;
        return null;
    }

    fn setTimeouts(self: *Server, fd: posix.socket_t) void {
        const timeout = posix.timeval{ .sec = @intCast(self.limits.idle_timeout_s), .usec = 0 };
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
    }

    fn refuse(self: *Server, conn: std.net.Server.Connection) void {
        _ = self;
        _ = metrics.global.counters.conn_errors.fetchAdd(1, .monotonic);
        _ = posix.write(conn.stream.handle, "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
        conn.stream.close();
    }

    fn admit(self: *Server, queue: *Queue, conn: std.net.Server.Connection) void {
        self.setTimeouts(conn.stream.handle);
        if (self.open_conns.fetchAdd(1, .seq_cst) >= self.limits.max_conns or !queue.push(conn)) {
            _ = self.open_conns.fetchSub(1, .seq_cst);
            self.refuse(conn);
        }
    }

    fn worker(self: *Server, queue: *Queue, slot: *Slot, rpc: bool) void {
        while (queue.pop()) |conn| {
            {
                slot.mutex.lock();
                defer slot.mutex.unlock();
                slot.fd = conn.stream.handle;
            }
            self.serveConn(conn, slot, rpc);
            {
                // Cleared before close so the watchdog never shuts a reused descriptor.
                slot.mutex.lock();
                defer slot.mutex.unlock();
                slot.fd = null;
                slot.phase = .free;
                slot.deadline = 0;
            }
            conn.stream.close();
            if (!rpc) _ = self.open_conns.fetchSub(1, .seq_cst);
        }
    }

    /// Cuts connections past their deadline, idle ones once stopping, and all of
    /// them once the drain deadline passes.
    fn watchdog(self: *Server, slots: []Slot, done: *std.atomic.Value(bool)) void {
        while (!done.load(.seq_cst)) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
            const t = now();
            const stopping = self.stopping.load(.seq_cst);
            const drain = self.drain_deadline.load(.seq_cst);
            for (slots) |*s| {
                s.mutex.lock();
                defer s.mutex.unlock();
                const fd = s.fd orelse continue;
                const cut = (s.deadline != 0 and t > s.deadline) or
                    (stopping and s.phase == .idle) or
                    (drain != 0 and t > drain);
                if (cut) {
                    _ = std.os.linux.shutdown(fd, posix.SHUT.RDWR);
                    s.deadline = 0;
                }
            }
        }
    }

    fn isReady(self: *Server) bool {
        if (self.open_gate) |g| if (!g.load(.acquire)) return false;
        if (self.ready) |r| return r.func(r.ctx);
        return metrics.isReady(self.svc);
    }

    fn rawRoute(self: *Server, target: []const u8) ?RawRoute {
        for (self.raw_routes) |r| if (std.mem.startsWith(u8, target, r.prefix)) return r;
        return null;
    }

    fn serveOps(self: *Server, req: *std.http.Server.Request, ep: metrics.Endpoint) !void {
        switch (ep) {
            .live => try req.respond("OK\n", .{}),
            .ready => if (self.isReady() and !self.stopping.load(.monotonic))
                try req.respond("OK\n", .{})
            else
                try req.respond("NOT READY\n", .{ .status = .service_unavailable }),
            .metrics => {
                var buf: [64 * 1024]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                try metrics.global.counters.render(&w);
                try metrics.tier.render(self.svc, &w);
                try req.respond(w.buffered(), .{ .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/plain; version=0.0.4" },
                } });
            },
        }
    }

    /// Serves one connection's requests; `rpc` connections reach raw routes and ops only.
    fn serveConn(self: *Server, conn: std.net.Server.Connection, slot: *Slot, rpc: bool) void {
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [16 * 1024]u8 = undefined;
        var sr = conn.stream.reader(&rbuf);
        var sw = conn.stream.writer(&wbuf);
        const head_ns = @as(u64, self.limits.header_timeout_s) * std.time.ns_per_s;
        // The handshake gets the header deadline so silent TLS clients are cut too.
        if (self.tls != null) slot.set(.head, now() + head_ns);
        var in: *std.Io.Reader = sr.interface();
        var out: *std.Io.Writer = &sw.interface;
        const secure: ?*tls.Session = if (self.tls) |ctx| tls.Session.accept(self.gpa, ctx, in, out) catch |e| {
            std.log.debug("tls handshake failed: {t}", .{e});
            return;
        } else null;
        defer if (secure) |t| t.close();
        if (secure) |t| {
            in = &t.reader;
            out = &t.writer;
        }
        var http = std.http.Server.init(in, out);
        var client_cert: ?authz.ClientCert = null;
        if (secure) |t| if (t.peerIdentity()) |p| {
            client_cert = .{ .common_name = p.common_name, .not_after_s = p.not_after_s };
        };
        const idle_ns = @as(u64, self.limits.idle_timeout_s) * std.time.ns_per_s;
        var served: usize = 0;
        while (true) {
            if (served > 0 and self.stopping.load(.seq_cst)) return;
            slot.set(.idle, now() + idle_ns);
            _ = http.reader.in.peek(1) catch return;
            slot.set(.head, now() + head_ns);
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            const head_buffer = http.reader.receiveHead() catch return;
            slot.set(.busy, 0);
            served += 1;
            var req: std.http.Server.Request = .{
                .server = &http,
                .head_buffer = head_buffer,
                .head = sigv4.parseHead(arena.allocator(), head_buffer) catch {
                    // Unparseable head (e.g. a negative Content-Length): answer, then close.
                    _ = out.writeAll(bad_request) catch {};
                    _ = out.flush() catch {};
                    return;
                },
            };
            const keep_alive = req.head.keep_alive;
            if (self.rawRoute(req.head.target)) |r| {
                r.serve(r.ctx, &req, arena.allocator()) catch return;
            } else if (metrics.matchPaths(self.ops, req.head.target)) |ep| {
                serveOps(self, &req, ep) catch return;
            } else if (rpc) {
                req.respond("", .{ .status = .not_found, .keep_alive = false }) catch {};
                return;
            } else if (self.open_gate != null and !self.open_gate.?.load(.acquire)) {
                req.respond("server is starting\n", .{ .status = .service_unavailable, .keep_alive = false }) catch {};
                return;
            } else {
                const t0 = metrics.global.counters.begin();
                metrics.global.last_status = 200;
                const res = handler.handle(self.svc, .{ .auth = self.auth, .peer = conn.address, .extensions = self.extensions, .observers = self.observers, .routing = self.routing, .client_cert = client_cert }, &req, arena.allocator());
                metrics.global.counters.end(t0, metrics.global.last_status);
                res catch |e| {
                    _ = metrics.global.counters.conn_errors.fetchAdd(1, .monotonic);
                    std.log.debug("connection closed: {t}", .{e});
                    return;
                };
            }
            if (!keep_alive or !bodyDone(&http.reader)) return;
        }
    }
};

const bad_request = "HTTP/1.1 400 Bad Request\r\ncontent-type: application/xml\r\ncontent-length: 118\r\nconnection: close\r\n\r\n" ++
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BadRequest</Code><Message>Malformed request head</Message></Error>";
/// Sorts new connections by their first bytes: the preamble sends one to the RPC
/// queue, anything else to the S3 queue. Connections that stay silent past the header
/// timeout are dropped. Runs on one thread over epoll.
const Classifier = struct {
    server: *Server,
    magic: []const u8,
    s3: *Queue,
    rpc: *Queue,
    epfd: i32,
    mutex: std.Thread.Mutex = .{},
    pending: std.AutoHashMapUnmanaged(posix.socket_t, Pending) = .empty,
    stop: std.atomic.Value(bool) = .init(false),

    const Pending = struct { conn: std.net.Server.Connection, deadline: u64 };
    const linux = std.os.linux;

    fn init(server: *Server, magic: []const u8, s3: *Queue, rpc: *Queue) error{EpollFailed}!Classifier {
        const fd = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (linux.E.init(fd) != .SUCCESS) return error.EpollFailed;
        return .{ .server = server, .magic = magic, .s3 = s3, .rpc = rpc, .epfd = @intCast(fd) };
    }

    fn deinit(c: *Classifier) void {
        var it = c.pending.valueIterator();
        while (it.next()) |p| p.conn.stream.close();
        c.pending.deinit(c.server.gpa);
        posix.close(c.epfd);
    }

    fn add(c: *Classifier, conn: std.net.Server.Connection) void {
        const fd = conn.stream.handle;
        c.server.setTimeouts(fd);
        {
            c.mutex.lock();
            defer c.mutex.unlock();
            if (c.pending.count() >= c.server.limits.max_conns) return c.server.refuse(conn);
            const head_ns = @as(u64, c.server.limits.header_timeout_s) * std.time.ns_per_s;
            c.pending.put(c.server.gpa, fd, .{ .conn = conn, .deadline = now() + head_ns }) catch return c.server.refuse(conn);
        }
        var ev: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.ONESHOT, .data = .{ .fd = fd } };
        if (linux.E.init(linux.epoll_ctl(c.epfd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) {
            if (c.take(fd)) |p| c.server.refuse(p.conn);
        }
    }

    fn take(c: *Classifier, fd: posix.socket_t) ?Pending {
        c.mutex.lock();
        defer c.mutex.unlock();
        const kv = c.pending.fetchRemove(fd) orelse return null;
        return kv.value;
    }

    fn loop(c: *Classifier) void {
        var events: [64]linux.epoll_event = undefined;
        while (!c.stop.load(.seq_cst)) {
            const rc = linux.epoll_wait(c.epfd, &events, events.len, 100);
            const n: usize = if (linux.E.init(rc) == .SUCCESS) rc else 0;
            for (events[0..n]) |ev| c.ready(ev.data.fd);
            c.expire();
        }
    }

    fn ready(c: *Classifier, fd: posix.socket_t) void {
        var buf: [16]u8 = undefined;
        const want = @min(buf.len, c.magic.len);
        const rc = linux.recvfrom(fd, &buf, want, linux.MSG.PEEK | linux.MSG.DONTWAIT, null, null);
        const err = linux.E.init(rc);
        if (err == .AGAIN or err == .INTR) return c.rearm(fd);
        const got: usize = if (err == .SUCCESS) rc else 0;
        const p = c.take(fd) orelse return;
        // EOF or an error before any byte.
        if (got == 0) return p.conn.stream.close();
        const seen = buf[0..got];
        if (std.mem.eql(u8, seen, c.magic[0..want])) {
            // Consume the preamble; it is already buffered, so this does not block.
            var sink: [16]u8 = undefined;
            const r = linux.recvfrom(fd, &sink, want, linux.MSG.DONTWAIT, null, null);
            if (linux.E.init(r) != .SUCCESS or r != want) return p.conn.stream.close();
            if (!c.rpc.push(p.conn)) c.server.refuse(p.conn);
            return;
        }
        if (std.mem.startsWith(u8, c.magic, seen)) {
            // A proper prefix so far: wait for the rest.
            c.mutex.lock();
            c.pending.put(c.server.gpa, fd, p) catch {
                c.mutex.unlock();
                return c.server.refuse(p.conn);
            };
            c.mutex.unlock();
            return c.rearm(fd);
        }
        c.server.admit(c.s3, p.conn);
    }

    fn rearm(c: *Classifier, fd: posix.socket_t) void {
        var ev: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.ONESHOT, .data = .{ .fd = fd } };
        if (linux.E.init(linux.epoll_ctl(c.epfd, linux.EPOLL.CTL_MOD, fd, &ev)) != .SUCCESS) {
            if (c.take(fd)) |p| p.conn.stream.close();
        }
    }

    /// Drops connections that sent nothing classifiable before their deadline.
    fn expire(c: *Classifier) void {
        const t = now();
        var dead: [64]Pending = undefined;
        var n: usize = 0;
        {
            c.mutex.lock();
            defer c.mutex.unlock();
            var it = c.pending.iterator();
            while (it.next()) |kv| if (kv.value_ptr.deadline < t) {
                dead[n] = kv.value_ptr.*;
                n += 1;
                if (n == dead.len) break;
            };
            for (dead[0..n]) |p| _ = c.pending.remove(p.conn.stream.handle);
        }
        for (dead[0..n]) |p| {
            _ = metrics.global.counters.conn_errors.fetchAdd(1, .monotonic);
            p.conn.stream.close();
        }
    }
};

/// True when the request body was consumed exactly, so the next request can follow.
/// A reader that stopped at the declared length never saw EndOfStream; mark it ready.
fn bodyDone(r: *std.http.Reader) bool {
    switch (r.state) {
        .ready => return true,
        .body_remaining_content_length => |n| if (n == 0) {
            r.state = .ready;
            return true;
        },
        else => {},
    }
    return false;
}

fn now() u64 {
    return @intCast(@max(0, std.time.nanoTimestamp()));
}

test "queue is bounded and drains after close" {
    var items: [2]std.net.Server.Connection = undefined;
    var q: Queue = .{ .items = &items };
    const c: std.net.Server.Connection = .{ .stream = .{ .handle = -1 }, .address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0) };
    try std.testing.expect(q.push(c));
    try std.testing.expect(q.push(c));
    try std.testing.expect(!q.push(c));
    q.close();
    try std.testing.expect(q.pop() != null);
    try std.testing.expect(q.pop() != null);
    try std.testing.expect(q.pop() == null);
}
