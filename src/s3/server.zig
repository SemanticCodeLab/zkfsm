//! HTTP listener: a fixed worker pool serves accepted connections (keep-alive request
//! loop). A watchdog enforces the idle and header deadlines and the shutdown drain.
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
};

const Phase = enum(u8) { free, idle, head, busy };

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
    /// When set, every connection is TLS-terminated before HTTP.
    tls: ?*tls.Context = null,
    limits: Limits = .{},

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

        const items = try self.gpa.alloc(std.net.Server.Connection, @max(1, self.limits.max_conns));
        defer self.gpa.free(items);
        var queue: Queue = .{ .items = items };
        const slots = try self.gpa.alloc(Slot, @max(1, self.limits.workers));
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
            for (threads[0..started]) |t| t.join();
        }
        for (slots, threads) |*s, *t| {
            t.* = std.Thread.spawn(.{ .stack_size = 4 * 1024 * 1024 }, worker, .{ self, &queue, s }) catch return error.ThreadFailed;
            started += 1;
        }

        while (!self.stopping.load(.seq_cst)) {
            const conn = listener.accept() catch |e| {
                if (self.stopping.load(.seq_cst)) break;
                std.log.warn("accept failed: {t}", .{e});
                // Out of descriptors or memory: back off instead of spinning.
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            self.admit(&queue, conn);
        }
        const grace = @as(u64, self.limits.shutdown_timeout_s) * std.time.ns_per_s;
        self.drain_deadline.store(now() + grace, .seq_cst);
        std.log.info("shutting down: draining in-flight requests (up to {d}s)", .{self.limits.shutdown_timeout_s});
    }

    fn admit(self: *Server, queue: *Queue, conn: std.net.Server.Connection) void {
        const timeout = posix.timeval{ .sec = @intCast(self.limits.idle_timeout_s), .usec = 0 };
        posix.setsockopt(conn.stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        posix.setsockopt(conn.stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        if (self.open_conns.fetchAdd(1, .seq_cst) >= self.limits.max_conns or !queue.push(conn)) {
            _ = self.open_conns.fetchSub(1, .seq_cst);
            _ = metrics.global.counters.conn_errors.fetchAdd(1, .monotonic);
            _ = posix.write(conn.stream.handle, "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
            conn.stream.close();
        }
    }

    fn worker(self: *Server, queue: *Queue, slot: *Slot) void {
        while (queue.pop()) |conn| {
            {
                slot.mutex.lock();
                defer slot.mutex.unlock();
                slot.fd = conn.stream.handle;
            }
            self.serveConn(conn, slot);
            {
                // Cleared before close so the watchdog never shuts a reused descriptor.
                slot.mutex.lock();
                defer slot.mutex.unlock();
                slot.fd = null;
                slot.phase = .free;
                slot.deadline = 0;
            }
            conn.stream.close();
            _ = self.open_conns.fetchSub(1, .seq_cst);
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

    fn serveOps(self: *Server, req: *std.http.Server.Request, ep: metrics.Endpoint) !void {
        switch (ep) {
            .live => try req.respond("OK\n", .{}),
            .ready => if (metrics.isReady(self.svc) and !self.stopping.load(.monotonic))
                try req.respond("OK\n", .{})
            else
                try req.respond("NOT READY\n", .{ .status = .service_unavailable }),
            .metrics => {
                var buf: [8192]u8 = undefined;
                var w: std.Io.Writer = .fixed(&buf);
                try metrics.global.counters.render(&w);
                try req.respond(w.buffered(), .{ .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/plain; version=0.0.4" },
                } });
            },
        }
    }

    fn serveConn(self: *Server, conn: std.net.Server.Connection, slot: *Slot) void {
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
                .head = sigv4.parseHead(arena.allocator(), head_buffer) catch return,
            };
            const keep_alive = req.head.keep_alive;
            if (metrics.match(req.head.target)) |ep| {
                serveOps(self, &req, ep) catch return;
            } else {
                const t0 = metrics.global.counters.begin();
                metrics.global.last_status = 200;
                const res = handler.handle(self.svc, .{ .auth = self.auth, .peer = conn.address, .extensions = self.extensions }, &req, arena.allocator());
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
