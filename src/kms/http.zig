//! Small HTTP(S) helper for KMS backends: per-socket I/O timeouts plus
//! retries with exponential backoff on transport errors, 429 and 5xx.
const std = @import("std");
const tls = @import("../tls/root.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidArgument, BackendUnavailable, InvalidResponse };

pub const Options = struct {
    /// Connect deadline and SO_RCVTIMEO/SO_SNDTIMEO.
    timeout_ms: u32 = 10_000,
    max_attempts: u8 = 4,
    backoff_ms: u32 = 100,
    max_body: usize = 4 << 20,
    /// CA file, client certificate and key for https:// URLs.
    tls: tls.TlsOptions = .{},
};

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(r: *Response, gpa: Allocator) void {
        gpa.free(r.body);
    }
};

pub const Client = struct {
    opts: Options,

    pub fn init(gpa: Allocator, opts: Options) Client {
        _ = gpa;
        return .{ .opts = opts };
    }

    pub fn deinit(c: *Client) void {
        c.* = undefined;
    }

    /// Sends a request; retries idempotent failures. Caller owns the body.
    /// Header values must not contain CR/LF.
    pub fn send(c: *Client, gpa: Allocator, method: std.http.Method, url: []const u8, headers: []const std.http.Header, payload: ?[]const u8) Error!Response {
        var attempt: u8 = 1;
        var delay: u64 = c.opts.backoff_ms;
        while (true) : (attempt += 1) {
            const last = attempt >= c.opts.max_attempts;
            if (c.once(gpa, method, url, headers, payload)) |resp| {
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

    fn once(c: *Client, gpa: Allocator, method: std.http.Method, url: []const u8, headers: []const std.http.Header, payload: ?[]const u8) Error!Response {
        const r = tls.https.send(gpa, .{
            .method = method,
            .url = url,
            .headers = headers,
            .body = payload,
            .tls = c.opts.tls,
            .connect_timeout_ms = c.opts.timeout_ms,
            .io_timeout_ms = c.opts.timeout_ms,
            .max_body = c.opts.max_body,
            .user_agent = "zkfsm-kms",
        }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidArgument => error.InvalidArgument,
            error.InvalidResponse, error.ResponseTooLarge => error.InvalidResponse,
            error.ConnectFailed, error.TlsFailed => error.BackendUnavailable,
        };
        return .{ .status = r.status, .body = r.body };
    }
};

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
