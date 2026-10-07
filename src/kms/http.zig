//! Small HTTP(S) helper for KMS backends: per-socket I/O timeouts plus
//! retries with exponential backoff on transport errors, 429 and 5xx.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidArgument, BackendUnavailable, InvalidResponse };

pub const Options = struct {
    /// Applied as SO_RCVTIMEO/SO_SNDTIMEO; connect uses the OS default.
    timeout_ms: u32 = 10_000,
    max_attempts: u8 = 4,
    backoff_ms: u32 = 100,
    max_body: usize = 4 << 20,
};

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(r: *Response, gpa: Allocator) void {
        gpa.free(r.body);
    }
};

pub const Client = struct {
    http: std.http.Client,
    opts: Options,

    pub fn init(gpa: Allocator, opts: Options) Client {
        return .{ .http = .{ .allocator = gpa }, .opts = opts };
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// Sends a request; retries idempotent failures. Caller owns the body.
    /// Header values must not contain CR/LF.
    pub fn send(c: *Client, gpa: Allocator, method: std.http.Method, url: []const u8, headers: []const std.http.Header, payload: ?[]const u8) Error!Response {
        const uri = std.Uri.parse(url) catch return error.InvalidArgument;
        for (headers) |h| {
            if (std.mem.indexOfAny(u8, h.value, "\r\n") != null) return error.InvalidArgument;
        }
        var attempt: u8 = 1;
        var delay: u64 = c.opts.backoff_ms;
        while (true) : (attempt += 1) {
            const last = attempt >= c.opts.max_attempts;
            if (c.once(gpa, method, uri, headers, payload)) |resp| {
                const retry = resp.status == 429 or (resp.status >= 500 and resp.status != 501);
                if (!retry or last) return resp;
                var r = resp;
                r.deinit(gpa);
            } else |e| switch (e) {
                error.OutOfMemory, error.InvalidArgument, error.InvalidResponse => return e,
                error.BackendUnavailable => if (last) return e,
            }
            const jitter = std.crypto.random.uintLessThan(u64, delay / 2 + 1);
            std.Thread.sleep((delay + jitter) * std.time.ns_per_ms);
            delay = @min(delay * 2, 5_000);
        }
    }

    fn once(c: *Client, gpa: Allocator, method: std.http.Method, uri: std.Uri, headers: []const std.http.Header, payload: ?[]const u8) Error!Response {
        const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.InvalidArgument;
        var host_buf: [std.Uri.host_name_max]u8 = undefined;
        const host = uri.getHost(&host_buf) catch return error.InvalidArgument;
        const port: u16 = uri.port orelse switch (protocol) {
            .plain => 80,
            .tls => 443,
        };
        const conn = c.http.connect(host, port, protocol) catch |e| return mapErr(e);
        setTimeouts(conn.stream_reader.getStream().handle, c.opts.timeout_ms);

        var req = c.http.request(method, uri, .{
            .connection = conn,
            .redirect_behavior = .not_allowed,
            .keep_alive = false,
            .extra_headers = headers,
            .headers = .{ .accept_encoding = .{ .override = "identity" }, .user_agent = .{ .override = "zkfsm-kms" } },
        }) catch |e| {
            c.http.connection_pool.release(conn);
            return mapErr(e);
        };
        defer req.deinit();
        if (payload) |p| {
            req.transfer_encoding = .{ .content_length = p.len };
            var body = req.sendBodyUnflushed(&.{}) catch |e| return mapErr(e);
            body.writer.writeAll(p) catch return error.BackendUnavailable;
            body.end() catch return error.BackendUnavailable;
            req.connection.?.flush() catch return error.BackendUnavailable;
        } else {
            req.sendBodiless() catch |e| return mapErr(e);
        }
        var resp = req.receiveHead(&.{}) catch |e| return mapErr(e);
        var tbuf: [64]u8 = undefined;
        const rd = resp.reader(&tbuf);
        const body = rd.allocRemaining(gpa, .limited(c.opts.max_body)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.InvalidResponse,
            error.ReadFailed => return error.BackendUnavailable,
        };
        return .{ .status = @intFromEnum(resp.head.status), .body = body };
    }

    fn mapErr(e: anyerror) Error {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnsupportedUriScheme, error.UriMissingHost, error.UriHostTooLong => error.InvalidArgument,
            error.HttpHeadersInvalid, error.HttpHeadersOversize, error.HttpChunkInvalid, error.HttpContentEncodingUnsupported, error.TooManyHttpRedirects, error.HttpRedirectLocationMissing, error.HttpRedirectLocationOversize, error.HttpRedirectLocationInvalid => error.InvalidResponse,
            else => error.BackendUnavailable,
        };
    }
};

fn setTimeouts(fd: std.posix.socket_t, ms: u32) void {
    const tv: std.posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
}

/// Percent-encodes a path segment (RFC 3986 unreserved kept).
pub fn escapeSegment(gpa: Allocator, s: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (s) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => try out.append(gpa, ch),
        else => try out.print(gpa, "%{X:0>2}", .{ch}),
    };
    return out.toOwnedSlice(gpa);
}

test "escape segment" {
    const gpa = std.testing.allocator;
    const e = try escapeSegment(gpa, "a b/c~");
    defer gpa.free(e);
    try std.testing.expectEqualStrings("a%20b%2Fc~", e);
}

fn flakyServer(srv: *std.net.Server) void {
    const replies = [_][]const u8{
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    };
    for (replies) |r| {
        const conn = srv.accept() catch return;
        defer conn.stream.close();
        var buf: [4096]u8 = undefined;
        _ = conn.stream.read(&buf) catch {};
        conn.stream.writeAll(r) catch {};
    }
}

test "retries 5xx then succeeds" {
    const gpa = std.testing.allocator;
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{ .reuse_address = true });
    defer srv.deinit();
    const t = try std.Thread.spawn(.{}, flakyServer, .{&srv});
    defer t.join();
    var c = Client.init(gpa, .{ .max_attempts = 3, .backoff_ms = 1 });
    defer c.deinit();
    var ub: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&ub, "http://127.0.0.1:{d}/x", .{srv.listen_address.getPort()});
    var r = try c.send(gpa, .GET, url, &.{}, null);
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("ok", r.body);
}

test "retries then reports unavailable on refused connection" {
    const gpa = std.testing.allocator;
    // Bind then close to get a port with nothing listening.
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{});
    const port = srv.listen_address.getPort();
    srv.deinit();
    var c = Client.init(gpa, .{ .max_attempts = 2, .backoff_ms = 1, .timeout_ms = 500 });
    defer c.deinit();
    var ub: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&ub, "http://127.0.0.1:{d}/", .{port});
    try std.testing.expectError(error.BackendUnavailable, c.send(gpa, .GET, url, &.{}, null));
}
