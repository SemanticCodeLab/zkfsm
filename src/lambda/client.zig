//! POSTs a lambda event to a webhook and exposes the response head and a body
//! reader (content-length, chunked, or close-delimited).
const std = @import("std");
const net = @import("../events/net.zig");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;
const Header = std.http.Header;

pub const max_head_len = 16 * 1024;
const max_headers = 128;

pub const Error = error{ Unreachable, BadResponse, OutOfMemory };

pub const Options = struct {
    connect_timeout_ms: u32 = 5000,
    /// Per read/write deadline, including waiting for the response head.
    io_timeout_ms: u32 = 30000,
    skip_verify: bool = false,
};

/// Heap-pinned (the body reader points into it); `close` frees it.
pub const Response = struct {
    gpa: Allocator,
    conn: *net.Conn,
    hr: std.http.Reader,
    status: u16,
    /// Copies owned by the caller's arena.
    headers: []const Header,
    content_length: ?u64,
    body: *std.Io.Reader = undefined,
    transfer_buf: [8192]u8 = undefined,

    pub fn close(r: *Response) void {
        r.conn.close();
        r.gpa.destroy(r);
    }
};

pub fn post(gpa: Allocator, arena: Allocator, ep: config.Endpoint, auth: ?[]const u8, body: []const u8, o: Options) Error!*Response {
    const c = net.dial(gpa, ep.host, ep.port, .{
        .connect_timeout_ms = o.connect_timeout_ms,
        .io_timeout_ms = o.io_timeout_ms,
        .tls = if (ep.secure) .{ .skip_verify = o.skip_verify } else null,
    }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Unreachable,
    };
    var owned = true;
    defer if (owned) c.close();
    const w = c.writer();
    w.print("POST {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: zkfsm\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n", .{ ep.path, ep.host_header, body.len }) catch return error.Unreachable;
    if (auth) |v| w.print("Authorization: {s}\r\n", .{v}) catch return error.Unreachable;
    w.writeAll("\r\n") catch return error.Unreachable;
    w.writeAll(body) catch return error.Unreachable;
    c.flush() catch return error.Unreachable;

    const r = try gpa.create(Response);
    errdefer gpa.destroy(r);
    r.* = .{ .gpa = gpa, .conn = c, .hr = .{ .in = c.reader(), .interface = undefined, .state = .ready, .max_head_len = max_head_len }, .status = 0, .headers = &.{}, .content_length = null };
    const head_bytes = r.hr.receiveHead() catch |e| return switch (e) {
        error.HttpHeadersOversize => error.BadResponse,
        else => error.Unreachable,
    };
    try parseHead(arena, r, head_bytes);
    owned = false;
    return r;
}

fn parseHead(arena: Allocator, r: *Response, head_bytes: []const u8) Error!void {
    // std's status parser trusts its three digits; check them first.
    if (head_bytes.len < 12) return error.BadResponse;
    for (head_bytes[9..12]) |d| if (!std.ascii.isDigit(d)) return error.BadResponse;
    const head = std.http.Client.Response.Head.parse(head_bytes) catch return error.BadResponse;
    const status: u16 = @intFromEnum(head.status);
    if (status < 100 or status > 599 or head.content_encoding != .identity) return error.BadResponse;
    var hs: std.ArrayList(Header) = .empty;
    var it = head.iterateHeaders();
    while (it.next()) |h| {
        if (hs.items.len == max_headers) return error.BadResponse;
        try hs.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
    }
    r.status = status;
    r.headers = hs.items;
    r.content_length = if (head.transfer_encoding == .chunked) null else head.content_length;
    r.body = r.hr.bodyReader(&r.transfer_buf, head.transfer_encoding, r.content_length);
}

test "post and read a chunked reply" {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{});
    defer srv.deinit();
    const th = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.net.Server) void {
            const conn = s.accept() catch return;
            defer conn.stream.close();
            var buf: [2048]u8 = undefined;
            var n: usize = 0;
            while (n < buf.len) {
                const k = conn.stream.read(buf[n..]) catch return;
                if (k == 0) break;
                n += k;
                if (std.mem.indexOf(u8, buf[0..n], "{}") != null) break;
            }
            _ = conn.stream.write("HTTP/1.1 200 OK\r\nX-Amz-Fwd-Header-Content-Type: text/x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n") catch {};
        }
    }.run, .{&srv});
    defer th.join();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ep: config.Endpoint = .{ .host = "127.0.0.1", .port = srv.listen_address.getPort(), .path = "/", .host_header = "h", .secure = false };
    const r = try post(std.testing.allocator, arena.allocator(), ep, "Bearer t", "{}", .{});
    defer r.close();
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqual(@as(usize, 2), r.headers.len);
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const n = try r.body.streamRemaining(&w);
    try std.testing.expectEqualStrings("HELLO", out[0..n]);
}

test "unreachable and malformed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ep: config.Endpoint = .{ .host = "127.0.0.1", .port = 1, .path = "/", .host_header = "h", .secure = false };
    try std.testing.expectError(error.Unreachable, post(std.testing.allocator, arena.allocator(), ep, null, "{}", .{ .connect_timeout_ms = 300 }));
    var r: Response = .{ .gpa = std.testing.allocator, .conn = undefined, .hr = undefined, .status = 0, .headers = &.{}, .content_length = null };
    try std.testing.expectError(error.BadResponse, parseHead(arena.allocator(), &r, "HTTP/1.1 zzz OK\r\n\r\n"));
}
