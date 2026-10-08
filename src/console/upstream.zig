//! Minimal HTTP/1.1 client for the loopback S3 listener: any method may carry a
//! body, and response bodies are read for every status (PUT errors included).
const std = @import("std");

const Allocator = std.mem.Allocator;
pub const Header = std.http.Header;
pub const Head = std.http.Client.Response.Head;

pub const Error = error{ OutOfMemory, Unreachable, BadResponse };

pub const Endpoint = struct {
    host: []const u8,
    port: u16,

    /// Value for the Host header.
    pub fn authority(e: Endpoint, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ e.host, e.port }) catch e.host;
    }

    /// Parses `http://host:port` (or bare `host:port`).
    pub fn parse(url: []const u8) error{InvalidUrl}!Endpoint {
        var rest = url;
        if (std.mem.startsWith(u8, rest, "http://")) rest = rest["http://".len..];
        if (std.mem.indexOf(u8, rest, "://") != null) return error.InvalidUrl;
        if (std.mem.indexOfScalar(u8, rest, '/')) |i| rest = rest[0..i];
        const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return .{ .host = rest, .port = 80 };
        if (colon == 0) return error.InvalidUrl;
        const port = std.fmt.parseInt(u16, rest[colon + 1 ..], 10) catch return error.InvalidUrl;
        return .{ .host = rest[0..colon], .port = port };
    }
};

pub const Response = struct {
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    http: std.http.Reader,
    head: Head,
    /// Copy of the head bytes; `head` points into it.
    head_bytes: []const u8,
    body_buf: [16 * 1024]u8 = undefined,
    method: std.http.Method,

    pub fn status(r: *const Response) u16 {
        return @intFromEnum(r.head.status);
    }

    pub fn header(r: *const Response, name: []const u8) ?[]const u8 {
        var it = r.head.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    pub fn hasBody(r: *const Response) bool {
        const s = r.status();
        return r.method != .HEAD and s != 204 and s != 304 and !(s >= 100 and s < 200);
    }

    pub fn bodyReader(r: *Response) *std.Io.Reader {
        if (!r.hasBody()) return std.Io.Reader.ending;
        return r.http.bodyReader(&r.body_buf, r.head.transfer_encoding, r.head.content_length);
    }

    /// Reads the whole body (at most `max` bytes).
    pub fn readAll(r: *Response, a: Allocator, max: usize) Error![]u8 {
        const rd = r.bodyReader();
        return rd.allocRemaining(a, .limited(max)) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadResponse,
        };
    }

    pub fn close(r: *Response) void {
        r.stream.close();
    }
};

/// Sends one request (connection: close) and parses the response head.
/// `target` is the encoded path and query. Free with `close`.
pub fn send(a: Allocator, ep: Endpoint, method: std.http.Method, target: []const u8, headers: []const Header, body: []const u8) Error!*Response {
    const stream = std.net.tcpConnectToHost(a, ep.host, ep.port) catch return error.Unreachable;
    errdefer stream.close();
    const r = try a.create(Response);
    r.* = .{ .stream = stream, .sr = undefined, .http = undefined, .head = undefined, .head_bytes = &.{}, .method = method };
    const rbuf = try a.alloc(u8, 64 * 1024);
    const wbuf = try a.alloc(u8, 16 * 1024);
    var sw = stream.writer(wbuf);
    const w = &sw.interface;
    var hb: [300]u8 = undefined;
    writeHead(w, method, target, ep.authority(&hb), headers, body.len) catch return error.Unreachable;
    w.writeAll(body) catch return error.Unreachable;
    w.flush() catch return error.Unreachable;
    r.sr = stream.reader(rbuf);
    r.http = .{ .in = r.sr.interface(), .interface = undefined, .state = .ready, .max_head_len = rbuf.len };
    const raw = r.http.receiveHead() catch return error.BadResponse;
    r.head_bytes = try a.dupe(u8, raw);
    r.head = Head.parse(r.head_bytes) catch return error.BadResponse;
    return r;
}

fn writeHead(w: *std.Io.Writer, method: std.http.Method, target: []const u8, host: []const u8, headers: []const Header, body_len: usize) std.Io.Writer.Error!void {
    try w.print("{s} {s} HTTP/1.1\r\nhost: {s}\r\nconnection: close\r\n", .{ @tagName(method), target, host });
    for (headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    if (body_len > 0 or method.requestHasBody()) try w.print("content-length: {d}\r\n", .{body_len});
    try w.writeAll("\r\n");
}

test "endpoint parsing" {
    const e = try Endpoint.parse("http://127.0.0.1:9000");
    try std.testing.expectEqualStrings("127.0.0.1", e.host);
    try std.testing.expectEqual(@as(u16, 9000), e.port);
    try std.testing.expectEqual(@as(u16, 80), (try Endpoint.parse("localhost")).port);
    try std.testing.expectError(error.InvalidUrl, Endpoint.parse("https://x:1"));
}
