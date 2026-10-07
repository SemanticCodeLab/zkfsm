//! TCP listener for the gateways: one thread per connection, bounded count,
//! socket timeouts as the idle guard, and a stop that drains briefly.
const std = @import("std");
const posix = std.posix;

pub const StartError = error{ ListenFailed, ThreadFailed };

pub const Handler = struct {
    ctx: *anyopaque,
    /// Owns `conn` and must close its stream.
    serve: *const fn (ctx: *anyopaque, conn: std.net.Server.Connection) void,
};

pub const Listener = struct {
    name: []const u8,
    handler: Handler,
    max_conns: u32 = 256,
    /// Per socket read/write stall limit.
    idle_timeout_s: u32 = 300,

    listen_fd: std.atomic.Value(posix.socket_t) = .init(-1),
    stopping: std.atomic.Value(bool) = .init(false),
    active: std.atomic.Value(u32) = .init(0),
    thread: ?std.Thread = null,
    /// Bound address (port filled in when listening on port 0).
    bound: std.net.Address = undefined,

    /// Binds now (so errors surface at startup), accepts on a background thread.
    pub fn start(self: *Listener, addr: std.net.Address) StartError!void {
        var server = addr.listen(.{ .reuse_address = true, .kernel_backlog = 128 }) catch return error.ListenFailed;
        self.bound = server.listen_address;
        self.listen_fd.store(server.stream.handle, .seq_cst);
        self.thread = std.Thread.spawn(.{}, acceptLoop, .{ self, server }) catch {
            server.deinit();
            return error.ThreadFailed;
        };
        std.log.info("{s} listening on {f}", .{ self.name, self.bound });
    }

    /// Stops accepting and waits up to `drain_s` for open sessions.
    pub fn stop(self: *Listener, drain_s: u32) void {
        if (self.stopping.swap(true, .seq_cst)) return;
        const fd = self.listen_fd.load(.seq_cst);
        if (fd >= 0) _ = std.os.linux.shutdown(fd, posix.SHUT.RDWR);
        if (self.thread) |t| t.join();
        self.thread = null;
        var waited: u32 = 0;
        while (self.active.load(.seq_cst) > 0 and waited < drain_s * 10) : (waited += 1) std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    pub fn isStopping(self: *const Listener) bool {
        return self.stopping.load(.seq_cst);
    }

    fn acceptLoop(self: *Listener, server_in: std.net.Server) void {
        var server = server_in;
        defer {
            self.listen_fd.store(-1, .seq_cst);
            server.deinit();
        }
        while (!self.stopping.load(.seq_cst)) {
            const conn = server.accept() catch |e| {
                if (self.stopping.load(.seq_cst)) return;
                std.log.debug("{s}: accept failed: {t}", .{ self.name, e });
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };
            if (self.active.fetchAdd(1, .seq_cst) >= self.max_conns) {
                _ = self.active.fetchSub(1, .seq_cst);
                conn.stream.close();
                continue;
            }
            setTimeouts(conn.stream.handle, self.idle_timeout_s);
            const t = std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, runConn, .{ self, conn }) catch {
                _ = self.active.fetchSub(1, .seq_cst);
                conn.stream.close();
                continue;
            };
            t.detach();
        }
    }

    fn runConn(self: *Listener, conn: std.net.Server.Connection) void {
        defer _ = self.active.fetchSub(1, .seq_cst);
        self.handler.serve(self.handler.ctx, conn);
    }
};

/// Applies the idle limit to blocking reads and writes on `fd`.
pub fn setTimeouts(fd: posix.socket_t, seconds: u32) void {
    const tv: posix.timeval = .{ .sec = @intCast(seconds), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// Parses HOST:PORT (IPv6 hosts in brackets or bare).
pub fn parseAddr(s: []const u8) error{BadAddress}!std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadAddress;
    const host = std.mem.trim(u8, s[0..colon], "[]");
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.BadAddress;
    return std.net.Address.parseIp(if (host.len == 0) "0.0.0.0" else host, port) catch error.BadAddress;
}

test "parseAddr" {
    const a = try parseAddr("127.0.0.1:2121");
    try std.testing.expectEqual(@as(u16, 2121), a.getPort());
    _ = try parseAddr(":21");
    _ = try parseAddr("[::1]:22");
    try std.testing.expectError(error.BadAddress, parseAddr("nope"));
}
