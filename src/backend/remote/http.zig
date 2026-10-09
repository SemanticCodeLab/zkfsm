//! HTTP plumbing shared by remote object providers: endpoints, single exchanges, retry policy.
const std = @import("std");
const http = std.http;

pub const Endpoint = struct {
    tls: bool,
    host: []const u8,
    port: ?u16,
    /// Percent-encoded path prefix without trailing slash ("" or "/account").
    base_path: []const u8,

    pub const ParseError = error{InvalidEndpoint};

    pub fn parse(url: []const u8) ParseError!Endpoint {
        const u = std.Uri.parse(url) catch return error.InvalidEndpoint;
        const tls = if (std.ascii.eqlIgnoreCase(u.scheme, "https"))
            true
        else if (std.ascii.eqlIgnoreCase(u.scheme, "http"))
            false
        else
            return error.InvalidEndpoint;
        const host = componentStr(u.host orelse return error.InvalidEndpoint);
        if (host.len == 0 or u.query != null or u.user != null) return error.InvalidEndpoint;
        return .{
            .tls = tls,
            .host = host,
            .port = u.port,
            .base_path = std.mem.trimRight(u8, componentStr(u.path), "/"),
        };
    }

    /// Host header value: `<sub><host>[:port]`; `sub` is e.g. "bucket." for virtual-host style.
    pub fn authority(e: Endpoint, sub: []const u8, buf: []u8) error{NoSpaceLeft}![]const u8 {
        if (e.port) |p| return std.fmt.bufPrint(buf, "{s}{s}:{d}", .{ sub, e.host, p });
        return std.fmt.bufPrint(buf, "{s}{s}", .{ sub, e.host });
    }

    /// `host` without port; `path` and `query` already percent-encoded.
    pub fn uri(e: Endpoint, host: []const u8, path: []const u8, query: []const u8) std.Uri {
        return .{
            .scheme = if (e.tls) "https" else "http",
            .host = .{ .raw = host },
            .port = e.port,
            .path = .{ .percent_encoded = path },
            .query = if (query.len == 0) null else .{ .percent_encoded = query },
        };
    }
};

fn componentStr(c: std.Uri.Component) []const u8 {
    return switch (c) {
        .raw, .percent_encoded => |s| s,
    };
}

/// Trusts `ca_file` (else $SSL_CERT_FILE) instead of the system roots when one is set.
pub fn useCaFile(client: *http.Client, gpa: std.mem.Allocator, ca_file: []const u8) error{ InvalidConfig, OutOfMemory }!void {
    const path = if (ca_file.len > 0) ca_file else std.posix.getenv("SSL_CERT_FILE") orelse return;
    if (path.len == 0) return;
    client.ca_bundle.addCertsFromFilePath(gpa, std.fs.cwd(), path) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidConfig;
    if (client.ca_bundle.map.count() == 0) return error.InvalidConfig;
    @atomicStore(bool, &client.next_https_rescan_certs, false, .release);
}

/// Exponential backoff with full jitter.
pub const RetryPolicy = struct {
    max_attempts: u32 = 5,
    base_ms: u32 = 100,
    cap_ms: u32 = 10_000,

    /// Sleeps before the next attempt; false once the attempt budget is spent.
    pub fn backoff(p: RetryPolicy, attempt: *u32) bool {
        attempt.* += 1;
        if (attempt.* >= p.max_attempts) return false;
        std.Thread.sleep(p.delayMs(attempt.*) * std.time.ns_per_ms);
        return true;
    }

    pub fn delayMs(p: RetryPolicy, attempt: u32) u64 {
        const shift: u6 = @intCast(@min(attempt -| 1, 30));
        const ceil = @min(@as(u64, p.cap_ms), @as(u64, p.base_ms) << shift);
        return std.crypto.random.uintAtMost(u64, ceil);
    }
};

pub fn retryableStatus(s: http.Status) bool {
    const c = @intFromEnum(s);
    return c >= 500 or c == 429 or c == 408;
}

pub const Info = struct {
    status: http.Status = .ok,
    content_length: ?u64 = null,
    /// From Content-Range: first byte and total object size.
    range_first: ?u64 = null,
    range_total: ?u64 = null,
    mtime_ns: ?i128 = null,
    etag_buf: [128]u8 = undefined,
    etag_len: u8 = 0,

    pub fn etag(i: *const Info) []const u8 {
        return i.etag_buf[0..i.etag_len];
    }

    /// Size of the whole object: Content-Range total, else Content-Length.
    pub fn objectSize(i: *const Info) ?u64 {
        return i.range_total orelse i.content_length;
    }
};

pub const SendError = error{ Transient, OutOfMemory };

/// One request/response. Must stay at a stable address between `start` and `deinit`.
pub const Exchange = struct {
    req: http.Client.Request,
    info: Info,
    te: http.TransferEncoding,

    pub const Options = struct {
        method: http.Method,
        uri: std.Uri,
        host: []const u8,
        authorization: ?[]const u8,
        headers: []const http.Header,
        body: ?[]const u8 = null,
    };

    /// Sends the request and reads the response head. On success call `deinit`.
    pub fn start(x: *Exchange, client: *http.Client, o: Options) SendError!void {
        x.req = client.request(o.method, o.uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{
                .host = .{ .override = o.host },
                .authorization = if (o.authorization) |a| .{ .override = a } else .omit,
                .user_agent = .{ .override = "zkfsm" },
                .accept_encoding = .omit,
            },
            .extra_headers = o.headers,
        }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Transient,
        };
        // A failed exchange must not return its (possibly dead) connection to the pool.
        errdefer {
            if (x.req.connection) |c| c.closing = true;
            x.req.deinit();
        }
        const payload: ?[]const u8 = o.body orelse if (o.method.requestHasBody()) @as([]const u8, "") else null;
        if (payload) |b| {
            x.req.transfer_encoding = .{ .content_length = b.len };
            var bw = x.req.sendBodyUnflushed(&.{}) catch return error.Transient;
            bw.writer.writeAll(b) catch return error.Transient;
            bw.end() catch return error.Transient;
        } else {
            x.req.sendBodiless() catch return error.Transient;
        }
        const resp = x.req.receiveHead(&.{}) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Transient,
        };
        x.info = .{ .status = resp.head.status, .content_length = resp.head.content_length };
        x.te = resp.head.transfer_encoding;
        if (!x.hasBody()) x.info.content_length = x.info.content_length orelse 0;
        var it = resp.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "etag")) {
                const n = @min(h.value.len, x.info.etag_buf.len);
                @memcpy(x.info.etag_buf[0..n], h.value[0..n]);
                x.info.etag_len = @intCast(n);
            } else if (std.ascii.eqlIgnoreCase(h.name, "last-modified")) {
                x.info.mtime_ns = parseHttpDate(h.value);
            } else if (std.ascii.eqlIgnoreCase(h.name, "content-range")) {
                parseContentRange(h.value, &x.info);
            }
        }
    }

    fn hasBody(x: *const Exchange) bool {
        const c = @intFromEnum(x.info.status);
        return x.req.method != .HEAD and c >= 200 and c != 204 and c != 304;
    }

    /// Body stream; call at most once. Bypasses std's PUT-has-no-response-body rule.
    pub fn body(x: *Exchange, transfer_buf: []u8) *std.Io.Reader {
        if (!x.hasBody()) return std.Io.Reader.ending;
        return x.req.reader.bodyReader(transfer_buf, x.te, x.info.content_length);
    }

    /// Reads a small body (XML, error document) into memory.
    pub fn readAll(x: *Exchange, gpa: std.mem.Allocator, limit: usize) error{ Transient, OutOfMemory, TooLarge }![]u8 {
        var buf: [4096]u8 = undefined;
        const r = x.body(&buf);
        return r.allocRemaining(gpa, .limited(limit)) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.TooLarge,
            error.ReadFailed => error.Transient,
        };
    }

    pub fn deinit(x: *Exchange) void {
        // Drain unread bodies so keep-alive connections return to the pool; std would
        // otherwise read a bodiless 204 until EOF.
        const rd = &x.req.reader;
        if (rd.state == .received_head) {
            if (!x.hasBody()) {
                _ = rd.bodyReader(&.{}, .none, 0).discardRemaining() catch {};
            } else if (x.info.content_length != null or x.te == .chunked) {
                _ = rd.bodyReader(&.{}, x.te, x.info.content_length).discardRemaining() catch {};
            }
        } else if (rd.state == .body_remaining_content_length and rd.state.body_remaining_content_length == 0) {
            rd.state = .ready;
        }
        x.req.deinit();
    }
};

/// "bytes a-b/total"
fn parseContentRange(v: []const u8, info: *Info) void {
    const rest = std.mem.trim(u8, v, " ");
    if (!std.mem.startsWith(u8, rest, "bytes ")) return;
    const spec = rest[6..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return;
    const slash = std.mem.indexOfScalar(u8, spec, '/') orelse return;
    if (slash < dash) return;
    info.range_first = std.fmt.parseInt(u64, spec[0..dash], 10) catch null;
    info.range_total = std.fmt.parseInt(u64, spec[slash + 1 ..], 10) catch null;
}

/// IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT") to ns since epoch.
pub fn parseHttpDate(v: []const u8) ?i128 {
    var it = std.mem.tokenizeAny(u8, v, " ,:");
    _ = it.next() orelse return null; // weekday
    const day = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    const mon_s = it.next() orelse return null;
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    var mon: ?u8 = null;
    for (months, 1..) |m, i| {
        if (std.mem.eql(u8, m, mon_s)) mon = @intCast(i);
    }
    const year = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const hh = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const mm = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const ss = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const days = daysFromCivil(year, mon orelse return null, day);
    const secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    return @as(i128, secs) * std.time.ns_per_s;
}

/// Howard Hinnant's days_from_civil.
fn daysFromCivil(y0: i64, m: u8, d: u8) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

test "endpoint parse and authority" {
    const e = try Endpoint.parse("http://127.0.0.1:9000/");
    try std.testing.expect(!e.tls);
    try std.testing.expectEqual(@as(?u16, 9000), e.port);
    try std.testing.expectEqualStrings("", e.base_path);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("b.127.0.0.1:9000", try e.authority("b.", &buf));
    const a = try Endpoint.parse("https://acct.blob.core.windows.net");
    try std.testing.expect(a.tls);
    try std.testing.expectEqualStrings("acct.blob.core.windows.net", try a.authority("", &buf));
    const z = try Endpoint.parse("http://localhost:10000/devstoreaccount1");
    try std.testing.expectEqualStrings("/devstoreaccount1", z.base_path);
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("ftp://x"));
}

test "http date and content-range parse" {
    try std.testing.expectEqual(@as(?i128, 784111777 * std.time.ns_per_s), parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT"));
    try std.testing.expectEqual(@as(?i128, null), parseHttpDate("garbage"));
    var info: Info = .{};
    parseContentRange("bytes 10-19/1000", &info);
    try std.testing.expectEqual(@as(?u64, 10), info.range_first);
    try std.testing.expectEqual(@as(?u64, 1000), info.objectSize());
}

test "retry backoff bounded by cap" {
    const p: RetryPolicy = .{ .base_ms = 100, .cap_ms = 250 };
    for (1..20) |i| try std.testing.expect(p.delayMs(@intCast(i)) <= 250);
    var attempt: u32 = 0;
    const once: RetryPolicy = .{ .max_attempts = 1 };
    try std.testing.expect(!once.backoff(&attempt));
    try std.testing.expect(retryableStatus(.service_unavailable));
    try std.testing.expect(retryableStatus(.too_many_requests));
    try std.testing.expect(!retryableStatus(.not_found));
}
