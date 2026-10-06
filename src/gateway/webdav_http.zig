//! Generic HTTP/1.1 connection loop for gateways: std.http.Server framing over a
//! raw or TLS stream, extension methods (PROPFIND, MKCOL, ...) and bounded bodies.
const std = @import("std");
const tls = @import("../tls/root.zig");

pub const max_method = 16;
/// Request heads larger than this are refused (431 semantics: connection closed).
pub const head_buffer_len = 16 * 1024;

pub const Error = error{ WriteFailed, ReadFailed, HttpExpectationFailed, OutOfMemory, BodyTooLarge };

/// One request. `method` is the token as sent; std sees extension methods as POST.
pub const Exchange = struct {
    req: *std.http.Server.Request,
    method: []const u8,
    /// Encoded request target, copied before the body is read.
    target: []const u8,
    arena: std.mem.Allocator,
    peer: std.net.Address,
    secure: bool,

    pub fn header(x: *const Exchange, name: []const u8) ?[]const u8 {
        // head_buffer is an arena copy, valid even after the body was read.
        var it = std.http.HeaderIterator.init(x.req.head_buffer);
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    /// True when the client sent a body we have not read yet.
    pub fn hasBody(x: *const Exchange) bool {
        const h = x.req.head;
        return h.transfer_encoding == .chunked or (h.content_length orelse 0) > 0;
    }

    /// Reads a body of at most `max` bytes into the arena.
    pub fn readSmallBody(x: *Exchange, max: usize) Error![]const u8 {
        if (!x.hasBody()) return "";
        if ((x.req.head.content_length orelse 0) > max) return error.BodyTooLarge;
        const buf = try x.arena.alloc(u8, 4096);
        const r = try x.req.readerExpectContinue(buf);
        return r.allocRemaining(x.arena, .limited(max)) catch |e| switch (e) {
            error.StreamTooLong => error.BodyTooLarge,
            error.OutOfMemory => error.OutOfMemory,
            error.ReadFailed => error.ReadFailed,
        };
    }

    /// Body stream for uploads; call once.
    pub fn bodyReader(x: *Exchange, buf: []u8) Error!*std.Io.Reader {
        return x.req.readerExpectContinue(buf);
    }
};

pub const Handler = struct {
    ctx: *anyopaque,
    /// An error closes the connection.
    handle: *const fn (ctx: *anyopaque, x: *Exchange) Error!void,
};

pub const Options = struct {
    gpa: std.mem.Allocator,
    tls: ?*tls.Context,
    handler: Handler,
    stopping: *const std.atomic.Value(bool),
};

/// Serves requests on `conn` until close, error or shutdown; closes the stream.
pub fn serve(o: Options, conn: std.net.Server.Connection) void {
    defer conn.stream.close();
    var rbuf: [head_buffer_len]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var sr = conn.stream.reader(&rbuf);
    var sw = conn.stream.writer(&wbuf);
    var in: *std.Io.Reader = sr.interface();
    var out: *std.Io.Writer = &sw.interface;
    const secure: ?*tls.Session = if (o.tls) |ctx| tls.Session.accept(o.gpa, ctx, in, out) catch |e| {
        std.log.debug("webdav tls handshake failed: {t}", .{e});
        return;
    } else null;
    defer if (secure) |t| t.close();
    if (secure) |t| {
        in = &t.reader;
        out = &t.writer;
    }
    var http = std.http.Server.init(in, out);
    var served: usize = 0;
    while (true) {
        if (served > 0 and o.stopping.load(.seq_cst)) return;
        _ = http.reader.in.peek(1) catch return;
        var arena_state = std.heap.ArenaAllocator.init(o.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const raw = http.reader.receiveHead() catch |e| {
            if (e == error.HttpHeadersOversize) rawStatus(out, "431 Request Header Fields Too Large");
            return;
        };
        served += 1;
        const parsed = parseHead(arena, raw) catch {
            rawStatus(out, "400 Bad Request");
            return;
        };
        var req: std.http.Server.Request = .{ .server = &http, .head_buffer = parsed.buf, .head = parsed.head };
        var x: Exchange = .{
            .req = &req,
            .method = parsed.method,
            .target = parsed.head.target,
            .arena = arena,
            .peer = conn.address,
            .secure = secure != null,
        };
        const keep_alive = req.head.keep_alive;
        o.handler.handle(o.handler.ctx, &x) catch |e| {
            std.log.debug("webdav connection closed: {t}", .{e});
            return;
        };
        if (!keep_alive or !bodyDone(&http.reader)) return;
    }
}

const Parsed = struct { head: std.http.Server.Request.Head, buf: []const u8, method: []const u8 };

/// Copies the head into the arena (so it outlives body reads) and maps unknown
/// methods to POST for std's parser. Bodies without framing get length 0.
fn parseHead(arena: std.mem.Allocator, raw: []const u8) error{ Bad, OutOfMemory }!Parsed {
    const sp = std.mem.indexOfScalar(u8, raw, ' ') orelse return error.Bad;
    const m = raw[0..sp];
    if (m.len == 0 or m.len > max_method) return error.Bad;
    for (m) |c| if (!std.ascii.isUpper(c) and c != '-' and c != '_') return error.Bad;
    const method = try arena.dupe(u8, m);
    const known = std.meta.stringToEnum(std.http.Method, m) != null;
    const buf = if (known) try arena.dupe(u8, raw) else try std.mem.concat(arena, u8, &.{ "POST", raw[sp..] });
    var head = std.http.Server.Request.Head.parse(buf) catch return error.Bad;
    if (head.transfer_encoding == .none and head.content_length == null) head.content_length = 0;
    // Bodies on methods std treats as bodiless would desync the stream.
    if (!head.method.requestHasBody() and (head.transfer_encoding == .chunked or head.content_length.? > 0))
        head.keep_alive = false;
    return .{ .head = head, .buf = buf, .method = method };
}

fn rawStatus(out: *std.Io.Writer, status: []const u8) void {
    out.print("HTTP/1.1 {s}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n", .{status}) catch return;
    out.flush() catch {};
}

/// True when the request body was consumed, so another request may follow.
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

test "parseHead maps extension methods" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try parseHead(a, "PROPFIND /b/x HTTP/1.1\r\nHost: h\r\nDepth: 1\r\n\r\n");
    try std.testing.expectEqualStrings("PROPFIND", p.method);
    try std.testing.expectEqual(std.http.Method.POST, p.head.method);
    try std.testing.expectEqualStrings("/b/x", p.head.target);
    try std.testing.expectEqual(@as(?u64, 0), p.head.content_length);
    const g = try parseHead(a, "GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n");
    try std.testing.expect(!g.head.keep_alive);
    try std.testing.expectError(error.Bad, parseHead(a, "prop<x> / HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(error.Bad, parseHead(a, "VERYLONGMETHODNAMEXX / HTTP/1.1\r\n\r\n"));
}
