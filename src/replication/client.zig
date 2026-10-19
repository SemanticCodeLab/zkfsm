//! Minimal SigV4 S3/admin client for replication targets and site peers over the pooled
//! outbound client (client certificates, CA files, IP SANs): small bodies in memory or
//! streamed uploads, optional bandwidth cap.
const std = @import("std");
const sign = @import("../backend/s3/sign.zig");
const core = @import("../core/root.zig");
const httpc = @import("../tls/httpc.zig");
const dial = @import("../tls/dial.zig");

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
    /// Per-remote TLS settings; empty fields fall back to the node defaults.
    tls: TlsFields = .{},
};

/// TLS settings as stored on targets and peers (paths are node-local).
pub const TlsFields = struct {
    client_cert: []const u8 = "",
    client_key: []const u8 = "",
    ca_file: []const u8 = "",
    server_name: []const u8 = "",
    min_version: []const u8 = "",

    pub const names = .{ "client_cert", "client_key", "ca_file", "server_name", "min_version" };
    /// JSON keys in admin requests and listings.
    pub const json = .{ "clientCert", "clientKey", "caFile", "serverName", "minVersion" };

    pub fn isEmpty(f: TlsFields) bool {
        inline for (names) |n| if (@field(f, n).len > 0) return false;
        return true;
    }

    /// Effective options: these fields over the node defaults.
    pub fn options(f: TlsFields) ?dial.TlsOptions {
        var m = f;
        inline for (names) |n| if (@field(m, n).len == 0) {
            @field(m, n) = @field(node_tls, n);
        };
        return .{
            .ca_file = m.ca_file,
            .server_name = m.server_name,
            .client_cert_file = m.client_cert,
            .client_key_file = m.client_key,
            .min_version = dial.parseMinVersion(m.min_version) orelse return null,
        };
    }

    /// Rejects unreadable files and unknown versions at configuration time.
    pub fn check(f: TlsFields, gpa: Allocator) bool {
        const o = f.options() orelse return false;
        o.check(gpa) catch return false;
        return true;
    }

    /// Reads the fields from a JSON object (`json` key names).
    pub fn fromJson(o: std.json.ObjectMap) TlsFields {
        var f: TlsFields = .{};
        inline for (names, json) |n, k| if (o.get(k)) |v| if (v == .string) {
            @field(f, n) = v.string;
        };
        return f;
    }

    pub fn writeJson(f: TlsFields, w: *std.json.Stringify) std.Io.Writer.Error!void {
        inline for (names, json) |n, k| if (@field(f, n).len > 0) {
            try w.objectField(k);
            try w.write(@field(f, n));
        };
    }
};

pub const Param = sign.Param;
pub const hdr_no_proxy = "x-minio-source-proxy-request";
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
    /// Receives a 2xx response head and streams its body instead of buffering it.
    sink: ?Sink = null,
};

/// `begin` gets the status, passthrough headers and length; it returns where the body goes.
pub const Sink = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque, status: u16, headers: []const Header, len: ?u64) ?*std.Io.Writer,
};

/// Node-wide TLS defaults for targets and peers (`ZKFSM_REPLICATION_*` variables).
pub var node_tls: TlsFields = .{};

pub const Http = httpc.Pool;
pub const Exchange = httpc.Exchange;

pub fn newHttp(gpa: Allocator) Http {
    return .init(gpa, .{});
}

/// Reads `ZKFSM_REPLICATION_{CA_FILE,CLIENT_CERT,CLIENT_KEY,SERVER_NAME,MIN_VERSION}` once at startup.
pub fn loadCaFromEnv() void {
    const env = std.posix.getenv;
    node_tls = .{
        .ca_file = env("ZKFSM_REPLICATION_CA_FILE") orelse "",
        .client_cert = env("ZKFSM_REPLICATION_CLIENT_CERT") orelse "",
        .client_key = env("ZKFSM_REPLICATION_CLIENT_KEY") orelse "",
        .server_name = env("ZKFSM_REPLICATION_SERVER_NAME") orelse "",
        .min_version = env("ZKFSM_REPLICATION_MIN_VERSION") orelse "",
    };
}

fn passthrough(name: []const u8) bool {
    const keep = [_][]const u8{ "content-type", "content-length", "content-range", "etag", "last-modified", "accept-ranges", "cache-control", "content-encoding", "content-disposition", "content-language", "expires" };
    for (keep) |k| if (std.ascii.eqlIgnoreCase(k, name)) return true;
    return std.ascii.startsWithIgnoreCase(name, "x-amz-") and !std.ascii.eqlIgnoreCase(name, "x-amz-request-id") and !std.ascii.eqlIgnoreCase(name, "x-amz-id-2");
}

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
pub const Error = error{ Unreachable, SourceFailed, SinkFailed, InvalidEndpoint, OutOfMemory };

pub const max_response = 4 * 1024 * 1024;

/// Sends one request; response strings are allocated in `a`.
pub fn send(client: *Http, a: Allocator, r: Remote, req: Request) Error!Response {
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
    var tpb: [core.trace.header_len]u8 = undefined;
    if (core.trace.outgoing(&tpb)) |tp| try extra.append(a, .{ .name = "traceparent", .value = try a.dupe(u8, tp) });
    // Replication's own reads must see the peer's local state, never a proxied one.
    if (req.method == .GET or req.method == .HEAD) try extra.append(a, .{ .name = hdr_no_proxy, .value = "true" });
    if (req.content_type) |ct| try extra.append(a, .{ .name = "Content-Type", .value = ct });
    try extra.append(a, .{ .name = "Authorization", .value = auth });
    var target: std.Io.Writer.Allocating = .init(a);
    target.writer.writeAll(if (path_w.written().len == 0) "/" else path_w.written()) catch return error.OutOfMemory;
    if (query_w.written().len > 0) target.writer.print("?{s}", .{query_w.written()}) catch return error.OutOfMemory;
    const tls: ?dial.TlsOptions = if (r.secure) r.tls.options() orelse return error.InvalidEndpoint else null;
    var st: StreamCtx = undefined;
    const body: httpc.Body = switch (req.body) {
        .none => .none,
        .bytes => |b| .{ .bytes = b },
        .stream => |s| blk: {
            st = .{ .s = s, .rate = r.bandwidth };
            break :blk .{ .stream = .{ .len = s.len, .ctx = &st, .write = StreamCtx.write } };
        },
    };
    var x: httpc.Exchange = undefined;
    x.start(client, .{ .host = hp.host, .port = hp.port orelse @as(u16, if (r.secure) 443 else 80), .tls = tls }, .{
        .method = req.method,
        .target = target.written(),
        .host = r.endpoint,
        .headers = extra.items,
        .body = body,
        .user_agent = "zkfsm-replication",
    }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.SourceFailed => error.SourceFailed,
        error.InvalidArgument => error.InvalidEndpoint,
        else => lost(@errorName(e), @src().line),
    };
    defer x.deinit();
    var out: Response = .{ .status = x.status };
    var keep: std.ArrayList(Header) = .empty;
    for (x.headers()) |h| {
        if (req.sink != null and passthrough(h.name) and !std.ascii.eqlIgnoreCase(h.name, "content-length"))
            try keep.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) });
        if (std.ascii.eqlIgnoreCase(h.name, "etag")) out.etag = try a.dupe(u8, std.mem.trim(u8, h.value, "\""));
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-version-id")) out.version_id = try a.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-delete-marker")) out.delete_marker = std.mem.eql(u8, h.value, "true");
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-replication-status")) out.replication_status = try a.dupe(u8, h.value);
    }
    if (req.sink) |sk| if (out.ok()) {
        const w = sk.begin(sk.ctx, out.status, keep.items, x.content_length) orelse return out;
        var tbuf: [64 * 1024]u8 = undefined;
        _ = x.body(&tbuf).streamRemaining(w) catch |e| return if (e == error.WriteFailed) error.SinkFailed else lost(@errorName(e), @src().line);
        return out;
    };
    out.body = x.readAll(a, max_response) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooLarge, error.Transient => lost(@errorName(e), @src().line),
    };
    return out;
}

/// Feeds a request stream through the bandwidth throttle.
const StreamCtx = struct {
    s: Stream,
    rate: u64,

    fn write(ctx: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void {
        const self: *StreamCtx = @ptrCast(@alignCast(ctx));
        var th: Throttle = .{ .inner = w, .rate = self.rate };
        try self.s.write(self.s.ctx, &th.writer);
        try th.writer.flush();
    }
};

/// Connection-level failure; the cause is logged at debug level.
fn lost(cause: []const u8, line: u32) Error {
    std.log.debug("replication client: {s} at line {d}", .{ cause, line });
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
