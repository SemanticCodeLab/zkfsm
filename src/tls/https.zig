//! Minimal HTTP/1.1 client over `dial.zig` so HTTPS callers get CA files and client
//! certificates: one request per connection, bounded head and body.
const std = @import("std");
const dial = @import("dial.zig");

pub const Error = error{ OutOfMemory, InvalidArgument, ConnectFailed, TlsFailed, InvalidResponse, ResponseTooLarge };

const max_line = 8 << 10;
const max_headers = 100;

pub const Request = struct {
    method: std.http.Method = .GET,
    url: []const u8,
    headers: []const std.http.Header = &.{},
    body: ?[]const u8 = null,
    /// Used for https:// URLs.
    tls: dial.TlsOptions = .{},
    connect_timeout_ms: u32 = 5000,
    io_timeout_ms: u32 = 10_000,
    max_body: usize = 4 << 20,
    user_agent: []const u8 = "zkfsm",
};

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(r: *Response, gpa: std.mem.Allocator) void {
        gpa.free(r.body);
    }
};

pub fn send(gpa: std.mem.Allocator, r: Request) Error!Response {
    const uri = std.Uri.parse(r.url) catch return error.InvalidArgument;
    const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) true else if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) false else return error.InvalidArgument;
    var hb: [std.Uri.host_name_max]u8 = undefined;
    const host = uri.getHost(&hb) catch return error.InvalidArgument;
    const port = uri.port orelse @as(u16, if (secure) 443 else 80);
    for (r.headers) |h| {
        if (std.mem.indexOfAny(u8, h.value, "\r\n") != null or std.mem.indexOfAny(u8, h.name, "\r\n: ") != null) return error.InvalidArgument;
    }
    var target: std.Io.Writer.Allocating = .init(gpa);
    defer target.deinit();
    uri.path.formatPath(&target.writer) catch return error.OutOfMemory;
    if (target.written().len == 0) target.writer.writeByte('/') catch return error.OutOfMemory;
    if (uri.query) |q| {
        target.writer.writeByte('?') catch return error.OutOfMemory;
        q.formatQuery(&target.writer) catch return error.OutOfMemory;
    }
    if (std.mem.indexOfAny(u8, target.written(), "\r\n ") != null) return error.InvalidArgument;

    const c = try dial.dial(gpa, host, port, .{
        .connect_timeout_ms = r.connect_timeout_ms,
        .io_timeout_ms = r.io_timeout_ms,
        .tls = if (secure) r.tls else null,
    });
    defer c.close();
    const w = c.writer();
    const v6 = std.mem.indexOfScalar(u8, host, ':') != null;
    writeHead(w, r, target.written(), host, uri.port, v6) catch return error.ConnectFailed;
    if (r.body) |b| w.writeAll(b) catch return error.ConnectFailed;
    c.flush() catch return error.ConnectFailed;
    return readResponse(gpa, c.reader(), r.max_body, r.method == .HEAD);
}

fn writeHead(w: *std.Io.Writer, r: Request, target: []const u8, host: []const u8, port: ?u16, v6: bool) std.Io.Writer.Error!void {
    try w.print("{s} {s} HTTP/1.1\r\nHost: ", .{ @tagName(r.method), target });
    if (v6) try w.print("[{s}]", .{host}) else try w.writeAll(host);
    if (port) |p| try w.print(":{d}", .{p});
    try w.print("\r\nUser-Agent: {s}\r\nAccept-Encoding: identity\r\nConnection: close\r\n", .{r.user_agent});
    if (r.body) |b| try w.print("Content-Length: {d}\r\n", .{b.len});
    for (r.headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    try w.writeAll("\r\n");
}

fn line(rd: *std.Io.Reader) Error![]const u8 {
    const l = rd.takeDelimiterInclusive('\n') catch |e| return switch (e) {
        error.StreamTooLong => error.ResponseTooLarge,
        error.ReadFailed, error.EndOfStream => error.ConnectFailed,
    };
    if (l.len > max_line) return error.ResponseTooLarge;
    return std.mem.trimRight(u8, l, "\r\n");
}

/// Parses one response; exposed for tests over fixed readers.
pub fn readResponse(gpa: std.mem.Allocator, rd: *std.Io.Reader, max_body: usize, head_only: bool) Error!Response {
    var status: u16 = 0;
    var length: ?usize = null;
    var chunked = false;
    while (true) {
        const sl = try line(rd);
        if (sl.len < 12 or !std.mem.startsWith(u8, sl, "HTTP/1.") or sl[8] != ' ') return error.InvalidResponse;
        status = std.fmt.parseInt(u16, sl[9..12], 10) catch return error.InvalidResponse;
        if (status < 100 or status > 999) return error.InvalidResponse;
        var n: usize = 0;
        while (true) : (n += 1) {
            if (n > max_headers) return error.ResponseTooLarge;
            const h = try line(rd);
            if (h.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.InvalidResponse;
            const name = h[0..colon];
            const value = std.mem.trim(u8, h[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                const v = std.fmt.parseInt(usize, value, 10) catch return error.InvalidResponse;
                if (length != null and length.? != v) return error.InvalidResponse;
                length = v;
            } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.InvalidResponse;
                chunked = true;
            }
        }
        if (status >= 200) break;
        length = null;
        chunked = false;
    }
    if (head_only or status == 204 or status == 304) return .{ .status = status, .body = try gpa.alloc(u8, 0) };
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(gpa);
    if (chunked) {
        while (true) {
            const sz_line = try line(rd);
            const hex = if (std.mem.indexOfScalar(u8, sz_line, ';')) |i| sz_line[0..i] else sz_line;
            if (hex.len == 0 or hex.len > 8) return error.InvalidResponse;
            const sz = std.fmt.parseInt(usize, std.mem.trim(u8, hex, " \t"), 16) catch return error.InvalidResponse;
            if (sz == 0) break;
            if (sz > max_body - body.items.len) return error.ResponseTooLarge;
            try readInto(gpa, rd, &body, sz);
            if ((try line(rd)).len != 0) return error.InvalidResponse;
        }
        var t: usize = 0;
        while ((try line(rd)).len != 0) : (t += 1) if (t > max_headers) return error.ResponseTooLarge;
    } else if (length) |len| {
        if (len > max_body) return error.ResponseTooLarge;
        try readInto(gpa, rd, &body, len);
    } else {
        rd.appendRemaining(gpa, &body, .limited(max_body)) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.ResponseTooLarge,
            error.ReadFailed => error.ConnectFailed,
        };
    }
    return .{ .status = status, .body = try body.toOwnedSlice(gpa) };
}

fn readInto(gpa: std.mem.Allocator, rd: *std.Io.Reader, body: *std.ArrayList(u8), n: usize) Error!void {
    const dst = try body.addManyAsSlice(gpa, n);
    rd.readSliceAll(dst) catch return error.ConnectFailed;
}

test "response parsing: length, chunked, interim, bounds" {
    const gpa = std.testing.allocator;
    {
        var rd: std.Io.Reader = .fixed("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        var r = try readResponse(gpa, &rd, 64, false);
        defer r.deinit(gpa);
        try std.testing.expectEqual(@as(u16, 200), r.status);
        try std.testing.expectEqualStrings("ok", r.body);
    }
    {
        var rd: std.Io.Reader = .fixed("HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nT: v\r\n\r\n");
        var r = try readResponse(gpa, &rd, 64, false);
        defer r.deinit(gpa);
        try std.testing.expectEqualStrings("abcde", r.body);
    }
    {
        var rd: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nx");
        try std.testing.expectError(error.ResponseTooLarge, readResponse(gpa, &rd, 64, false));
    }
    {
        var rd: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffff\r\n");
        try std.testing.expectError(error.InvalidResponse, readResponse(gpa, &rd, 64, false));
    }
    {
        var rd: std.Io.Reader = .fixed("garbage\r\n\r\n");
        try std.testing.expectError(error.InvalidResponse, readResponse(gpa, &rd, 64, false));
    }
    {
        var rd: std.Io.Reader = .fixed("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab");
        try std.testing.expectError(error.InvalidResponse, readResponse(gpa, &rd, 64, false));
    }
}
