//! HTTP listener: one detached thread per connection, keep-alive request loop.
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const sigv4 = @import("sigv4.zig");

pub const RunError = error{ListenFailed};

pub const Server = struct {
    gpa: std.mem.Allocator,
    svc: *object.ObjectService,
    auth: sigv4.Config,

    pub fn run(self: *Server, addr: std.net.Address) RunError!void {
        var listener = addr.listen(.{ .reuse_address = true }) catch return error.ListenFailed;
        defer listener.deinit();
        std.log.info("zkfsm listening on {f}", .{addr});
        while (true) {
            const conn = listener.accept() catch |e| {
                std.log.warn("accept failed: {t}", .{e});
                continue;
            };
            const t = std.Thread.spawn(.{ .stack_size = 4 * 1024 * 1024 }, serveConn, .{ self, conn }) catch {
                conn.stream.close();
                continue;
            };
            t.detach();
        }
    }

    fn serveConn(self: *Server, conn: std.net.Server.Connection) void {
        defer conn.stream.close();
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [16 * 1024]u8 = undefined;
        var sr = conn.stream.reader(&rbuf);
        var sw = conn.stream.writer(&wbuf);
        var http = std.http.Server.init(sr.interface(), &sw.interface);
        while (true) {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            const head_buffer = http.reader.receiveHead() catch return;
            var req: std.http.Server.Request = .{
                .server = &http,
                .head_buffer = head_buffer,
                .head = sigv4.parseHead(arena.allocator(), head_buffer) catch return,
            };
            const keep_alive = req.head.keep_alive;
            handler.handle(self.svc, self.auth, &req, arena.allocator()) catch |e| {
                std.log.debug("connection closed: {t}", .{e});
                return;
            };
            if (!keep_alive or http.reader.state != .ready) return;
        }
    }
};
