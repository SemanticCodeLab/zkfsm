//! Minimal SigV4 S3/admin client for replication targets and site peers: one request
//! per call, small bodies in memory or streamed uploads, optional bandwidth cap.
const std = @import("std");
const sign = @import("../backend/s3/sign.zig");

const Allocator = std.mem.Allocator;
const http = std.http;

pub const Remote = struct {
    /// `host[:port]`.
    endpoint: []const u8,
    secure: bool = false,
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8 = "us-east-1",
    /// Upload cap in bytes per second; 0 is unlimited.
    bandwidth: u64 = 0,
};

pub const Param = sign.Param;
pub const Header = http.Header;

/// Writes exactly `len` bytes of an upload body.
pub const Stream = struct {
    len: u64,
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void,
};

pub const Body = union(enum) { none, bytes: []const u8, stream: Stream };

pub const Request = struct {
    method: http.Method,
    /// Unencoded absolute path, e.g. `/bucket/key`.
    path: []const u8,
    query: []const Param = &.{},
    headers: []const Header = &.{},
    body: Body = .none,
    content_type: ?[]const u8 = null,
};

pub const Response = struct {
    status: u16,
    body: []const u8 = "",
    etag: []const u8 = "",
    version_id: []const u8 = "",
    delete_marker: bool = false,
    replication_status: []const u8 = "",

    pub fn ok(r: Response) bool {
        return r.status >= 200 and r.status < 300;
    }

    /// S3 error code from an XML error body, or "".
    pub fn code(r: Response) []const u8 {
        const i = std.mem.indexOf(u8, r.body, "<Code>") orelse return jsonCode(r.body);
        const j = std.mem.indexOfPos(u8, r.body, i, "</Code>") orelse return "";
        return r.body[i + 6 .. j];
    }

    fn jsonCode(body: []const u8) []const u8 {
        const k = "\"Code\":\"";
        const i = std.mem.indexOf(u8, body, k) orelse return "";
        const j = std.mem.indexOfScalarPos(u8, body, i + k.len, '"') orelse return "";
        return body[i + k.len .. j];
    }
};

/// Connection failures and source read failures; HTTP errors come back as a Response.
pub const Error = error{ Unreachable, SourceFailed, InvalidEndpoint, OutOfMemory };

pub const max_response = 4 * 1024 * 1024;

/// Sends one request; response strings are allocated in `a`.
pub fn send(client: *http.Client, a: Allocator, r: Remote, req: Request) Error!Response {
    const hp = splitHostPort(r.endpoint) orelse return error.InvalidEndpoint;
    var path_w: std.Io.Writer.Allocating = .init(a);
    sign.uriEncode(&path_w.writer, req.path, false) catch return error.OutOfMemory;
    var query_w: std.Io.Writer.Allocating = .init(a);
    sign.canonicalQuery(&query_w.writer, req.query) catch return error.OutOfMemory;
    const payload: []const u8 = switch (req.body) {
        .none => sign.empty_sha256,
        .bytes => |b| try a.dupe(u8, &sign.hashHex(b)),
        .stream => sign.unsigned_payload,
    };
    const date = sign.amzDate(std.time.nanoTimestamp());
    const signed = [_]sign.Header{
        .{ .name = "host", .value = r.endpoint },
        .{ .name = "x-amz-content-sha256", .value = payload },
        .{ .name = "x-amz-date", .value = &date },
    };
    var auth_buf: [512]u8 = undefined;
    const auth = sign.authorization(.{ .access_key = r.access_key, .secret_key = r.secret_key }, r.region, "s3", .{
        .method = @tagName(req.method),
        .canonical_uri = path_w.written(),
        .canonical_query = query_w.written(),
        .headers = &signed,
        .payload_hash = payload,
        .amz_date = &date,
    }, &auth_buf) catch return error.OutOfMemory;
    var extra: std.ArrayList(Header) = .empty;
    try extra.appendSlice(a, &.{
        .{ .name = "x-amz-content-sha256", .value = payload },
        .{ .name = "x-amz-date", .value = &date },
    });
    try extra.appendSlice(a, req.headers);
    const uri: std.Uri = .{
        .scheme = if (r.secure) "https" else "http",
        .host = .{ .raw = hp.host },
        .port = hp.port,
        .path = .{ .percent_encoded = path_w.written() },
        .query = if (query_w.written().len == 0) null else .{ .percent_encoded = query_w.written() },
    };
    var hreq = client.request(req.method, uri, .{
        .redirect_behavior = .unhandled,
        .keep_alive = true,
        .headers = .{
            .host = .{ .override = r.endpoint },
            .authorization = .{ .override = auth },
            .user_agent = .{ .override = "zkfsm-replication" },
            .accept_encoding = .omit,
            .content_type = if (req.content_type) |ct| .{ .override = ct } else .default,
        },
        .extra_headers = extra.items,
    }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else lost(e, @src().line);
    defer hreq.deinit();
    var send_buf: [64 * 1024]u8 = undefined;
    switch (req.body) {
        .none => if (req.method.requestHasBody()) {
            hreq.transfer_encoding = .{ .content_length = 0 };
            var bw = hreq.sendBodyUnflushed(&.{}) catch |e| return lost(e, @src().line);
            bw.end() catch |e| return lost(e, @src().line);
        } else hreq.sendBodiless() catch |e| return lost(e, @src().line),
        .bytes => |b| {
            hreq.transfer_encoding = .{ .content_length = b.len };
            var bw = hreq.sendBodyUnflushed(&send_buf) catch |e| return lost(e, @src().line);
            bw.writer.writeAll(b) catch |e| return lost(e, @src().line);
            bw.end() catch |e| return lost(e, @src().line);
        },
        .stream => |s| {
            hreq.transfer_encoding = .{ .content_length = s.len };
            var bw = hreq.sendBodyUnflushed(&send_buf) catch |e| return lost(e, @src().line);
            var th: Throttle = .{ .inner = &bw.writer, .rate = r.bandwidth };
            s.write(s.ctx, &th.writer) catch |e| return if (e == error.SourceFailed) error.SourceFailed else lost(e, @src().line);
            th.writer.flush() catch |e| return lost(e, @src().line);
            bw.end() catch |e| return lost(e, @src().line);
        },
    }
    var redirect_buf: [0]u8 = .{};
    var resp = hreq.receiveHead(&redirect_buf) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else lost(e, @src().line);
    var out: Response = .{ .status = @intFromEnum(resp.head.status) };
    var it = resp.head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "etag")) out.etag = try a.dupe(u8, std.mem.trim(u8, h.value, "\""));
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-version-id")) out.version_id = try a.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-delete-marker")) out.delete_marker = std.mem.eql(u8, h.value, "true");
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-replication-status")) out.replication_status = try a.dupe(u8, h.value);
    }
    const has_body = req.method != .HEAD and out.status >= 200 and out.status != 204 and out.status != 304;
    if (has_body) {
        var tbuf: [4096]u8 = undefined;
        const rd = hreq.reader.bodyReader(&tbuf, resp.head.transfer_encoding, resp.head.content_length);
        out.body = rd.allocRemaining(a, .limited(max_response)) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else lost(e, @src().line);
    } else {
        _ = hreq.reader.bodyReader(&.{}, .none, 0).discardRemaining() catch {};
    }
    return out;
}

/// Connection-level failure; the cause is logged at debug level.
fn lost(e: anyerror, line: u32) Error {
    std.log.debug("replication client: {t} at line {d}", .{ e, line });
    return error.Unreachable;
}

const HostPort = struct { host: []const u8, port: ?u16 };

fn splitHostPort(ep: []const u8) ?HostPort {
    if (ep.len == 0) return null;
    if (ep[0] == '[') {
        const close = std.mem.indexOfScalar(u8, ep, ']') orelse return null;
        const rest = ep[close + 1 ..];
        if (rest.len == 0) return .{ .host = ep[1..close], .port = null };
        if (rest[0] != ':') return null;
        return .{ .host = ep[1..close], .port = std.fmt.parseInt(u16, rest[1..], 10) catch return null };
    }
    const colon = std.mem.lastIndexOfScalar(u8, ep, ':') orelse return .{ .host = ep, .port = null };
    return .{ .host = ep[0..colon], .port = std.fmt.parseInt(u16, ep[colon + 1 ..], 10) catch return null };
}

/// Splits `http(s)://host[:port][/...]` into an endpoint and the TLS flag.
pub fn parseUrl(url: []const u8) ?struct { endpoint: []const u8, secure: bool } {
    const secure = std.ascii.startsWithIgnoreCase(url, "https://");
    if (!secure and !std.ascii.startsWithIgnoreCase(url, "http://")) return null;
    const rest = url[if (secure) 8 else 7..];
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    if (end == 0) return null;
    return .{ .endpoint = rest[0..end], .secure = secure };
}

/// Token-bucket pacing over an inner writer; `rate` 0 passes through.
const Throttle = struct {
    inner: *std.Io.Writer,
    rate: u64,
    start_ns: i128 = 0,
    sent: u64 = 0,
    writer: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } },

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Throttle = @alignCast(@fieldParentPtr("writer", w));
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.put(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.put(last);
        return n + last.len * splat;
    }

    fn put(self: *Throttle, d: []const u8) std.Io.Writer.Error!void {
        if (self.rate == 0) return self.inner.writeAll(d);
        if (self.start_ns == 0) self.start_ns = std.time.nanoTimestamp();
        var rest = d;
        while (rest.len > 0) {
            const chunk = rest[0..@min(rest.len, 16 * 1024)];
            try self.inner.writeAll(chunk);
            self.sent += chunk.len;
            rest = rest[chunk.len..];
            const due_ns: i128 = @divTrunc(@as(i128, self.sent) * std.time.ns_per_s, self.rate);
            const elapsed = std.time.nanoTimestamp() - self.start_ns;
            if (due_ns > elapsed) {
                try self.inner.flush();
                std.Thread.sleep(@intCast(due_ns - elapsed));
            }
        }
    }
};

test "url and host parsing" {
    const u = parseUrl("https://h.example:9000/bucket").?;
    try std.testing.expect(u.secure);
    try std.testing.expectEqualStrings("h.example:9000", u.endpoint);
    try std.testing.expect(parseUrl("ftp://x") == null);
    const hp = splitHostPort("127.0.0.1:9000").?;
    try std.testing.expectEqual(@as(?u16, 9000), hp.port);
    try std.testing.expectEqualStrings("::1", splitHostPort("[::1]:80").?.host);
    const r: Response = .{ .status = 404, .body = "<Error><Code>NoSuchKey</Code></Error>" };
    try std.testing.expectEqualStrings("NoSuchKey", r.code());
    const j: Response = .{ .status = 400, .body = "{\"Code\":\"XMinioX\",\"Message\":\"m\"}" };
    try std.testing.expectEqualStrings("XMinioX", j.code());
}

test "throttle paces output" {
    var out: [64 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var th: Throttle = .{ .inner = &w, .rate = 200 * 1024 };
    const t0 = std.time.nanoTimestamp();
    const data = [_]u8{7} ** (40 * 1024);
    try th.writer.writeAll(&data);
    try std.testing.expect(std.time.nanoTimestamp() - t0 >= 150 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, data.len), w.buffered().len);
}
