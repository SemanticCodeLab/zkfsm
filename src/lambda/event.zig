//! Object Lambda wire pieces: ARN parsing, the presigned inputS3Url, the event
//! JSON posted to the webhook, and the webhook response mapping (x-amz-fwd-*).
const std = @import("std");
const core = @import("../core/root.zig");

const Allocator = std.mem.Allocator;
const Header = std.http.Header;
const sv = core.sigv4;

pub const protocol_version = "1.00";
pub const presign_expires_s = 3600;

pub const ArnError = error{InvalidArn};

/// `arn:minio:s3-object-lambda:<region>:<id>:webhook` -> id.
pub fn parseArn(arn: []const u8) ArnError![]const u8 {
    if (arn.len > 512) return error.InvalidArn;
    var parts: [6][]const u8 = undefined;
    var it = std.mem.splitScalar(u8, arn, ':');
    var n: usize = 0;
    while (it.next()) |p| : (n += 1) {
        if (n == parts.len) return error.InvalidArn;
        parts[n] = p;
    }
    if (n != parts.len) return error.InvalidArn;
    if (!std.mem.eql(u8, parts[0], "arn") or !std.mem.eql(u8, parts[1], "minio") or
        !std.mem.eql(u8, parts[2], "s3-object-lambda") or !std.mem.eql(u8, parts[5], "webhook") or parts[4].len == 0)
        return error.InvalidArn;
    return parts[4];
}

pub const Presign = struct {
    scheme: []const u8,
    host: []const u8,
    /// Decoded request path (`/bucket/key`, or `/key` for virtual hosts).
    path: []const u8,
    /// Decoded query params to keep (lambdaArn and auth params already dropped).
    params: []const sv.Param,
    /// Null credentials give an unsigned URL (anonymous server).
    access_key: ?[]const u8 = null,
    secret_key: []const u8 = "",
    session_token: ?[]const u8 = null,
    region: []const u8,
    now_s: i64,
    expires_s: u32 = presign_expires_s,
};

/// Presigned GET URL in the canonical form the SigV4 verifier recomputes.
pub fn presignUrl(a: Allocator, p: Presign) error{OutOfMemory}![]const u8 {
    return presignInner(a, p) catch error.OutOfMemory;
}

fn presignInner(a: Allocator, p: Presign) (std.Io.Writer.Error || error{OutOfMemory})![]const u8 {
    var params: std.ArrayList(sv.Param) = .empty;
    try params.appendSlice(a, p.params);
    var date_buf: [16]u8 = undefined;
    const amz_date = amzDate(p.now_s, &date_buf);
    const scope: sv.Scope = .{ .date = amz_date[0..8], .region = p.region, .service = "s3" };
    if (p.access_key) |ak| {
        const cred = try std.fmt.allocPrint(a, "{s}/{f}", .{ ak, scope });
        try params.appendSlice(a, &.{
            .{ .name = "X-Amz-Algorithm", .value = sv.algorithm },
            .{ .name = "X-Amz-Credential", .value = cred },
            .{ .name = "X-Amz-Date", .value = amz_date },
            .{ .name = "X-Amz-Expires", .value = try std.fmt.allocPrint(a, "{d}", .{p.expires_s}) },
            .{ .name = "X-Amz-SignedHeaders", .value = "host" },
        });
        if (p.session_token) |tok| try params.append(a, .{ .name = "X-Amz-Security-Token", .value = tok });
    }
    var path: std.Io.Writer.Allocating = .init(a);
    try sv.uriEncode(&path.writer, p.path, true);
    var query: std.Io.Writer.Allocating = .init(a);
    try sv.writeCanonicalQuery(a, &query.writer, params.items);
    var url: std.Io.Writer.Allocating = .init(a);
    const w = &url.writer;
    try w.print("{s}://{s}{s}", .{ p.scheme, p.host, path.written() });
    if (query.written().len > 0) try w.print("?{s}", .{query.written()});
    if (p.access_key != null) {
        var creq: std.Io.Writer.Allocating = .init(a);
        try creq.writer.print("GET\n{s}\n{s}\nhost:", .{ path.written(), query.written() });
        try sv.writeHeaderValue(&creq.writer, p.host);
        try creq.writer.writeAll("\n\nhost\n" ++ sv.unsigned_payload);
        var sts: std.Io.Writer.Allocating = .init(a);
        try sv.writeStringToSign(&sts.writer, amz_date, scope, creq.written());
        const key = sv.signingKey(p.secret_key, scope.date, scope.region, scope.service);
        const sig = sv.sign(key, sts.written());
        try w.print("{s}X-Amz-Signature={s}", .{ if (query.written().len > 0) "&" else "?", &sig });
    }
    return url.written();
}

fn amzDate(now_s: i64, buf: *[16]u8) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(now_s, 0)) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable; // 16 chars for years < 10000
}

/// Opaque per-request token: base64url(HMAC(key, route|access key|expiry)).
pub fn outputToken(a: Allocator, key: [32]u8, route: []const u8, access_key: []const u8, expires_at: i64) error{OutOfMemory}![]const u8 {
    var h = std.crypto.auth.hmac.sha2.HmacSha256.init(&key);
    h.update(route);
    h.update("\x00");
    h.update(access_key);
    var eb: [24]u8 = undefined;
    h.update(std.fmt.bufPrint(&eb, "\x00{d}", .{expires_at}) catch unreachable); // i64 fits
    var mac: [32]u8 = undefined;
    h.final(&mac);
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try a.alloc(u8, enc.calcSize(mac.len));
    _ = enc.encode(out, &mac);
    return out;
}

/// Random route id (22 base62-ish chars, like a short UUID).
pub fn outputRoute(buf: *[22]u8) []const u8 {
    const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var r: [22]u8 = undefined;
    std.crypto.random.bytes(&r);
    for (buf, r) |*o, b| o.* = alphabet[b % alphabet.len];
    return buf;
}

pub const Event = struct {
    input_url: []const u8,
    route: []const u8,
    token: []const u8,
    arn: []const u8,
    url: []const u8,
    headers: []const Header,
    principal: []const u8,
    access_key: []const u8,
};

/// Canonical MIME form of a header name (`x-amz-date` -> `X-Amz-Date`).
fn canonicalName(a: Allocator, name: []const u8) error{OutOfMemory}![]const u8 {
    const out = try a.dupe(u8, name);
    var up = true;
    for (out) |*c| {
        c.* = if (up) std.ascii.toUpper(c.*) else std.ascii.toLower(c.*);
        up = c.* == '-';
    }
    return out;
}

/// Request headers never handed to the webhook (caller credentials).
fn private(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or std.ascii.eqlIgnoreCase(name, "x-amz-security-token");
}

/// The event JSON in the MinIO layout; headers map to arrays of values.
pub fn eventJson(a: Allocator, e: Event) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    writeEvent(a, &out.writer, e) catch return error.OutOfMemory;
    return out.written();
}

fn writeEvent(a: Allocator, w: *std.Io.Writer, e: Event) (std.Io.Writer.Error || error{OutOfMemory})!void {
    var js: std.json.Stringify = .{ .writer = w };
    try js.beginObject();
    try js.objectField("protocolVersion");
    try js.write(protocol_version);
    try js.objectField("getObjectContext");
    try js.write(.{ .inputS3Url = e.input_url, .outputRoute = e.route, .outputToken = e.token });
    try js.objectField("configuration");
    try js.write(.{ .accessPointArn = e.arn, .supportingAccessPointArn = e.arn, .payload = "" });
    try js.objectField("userRequest");
    try js.beginObject();
    try js.objectField("url");
    try js.write(e.url);
    try js.objectField("headers");
    try js.beginObject();
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    for (e.headers) |h| {
        if (private(h.name)) continue;
        const name = try canonicalName(a, h.name);
        if ((try seen.getOrPut(a, name)).found_existing) continue;
        try js.objectField(name);
        try js.beginArray();
        for (e.headers) |o| if (std.ascii.eqlIgnoreCase(o.name, h.name)) try js.write(o.value);
        try js.endArray();
    }
    try js.endObject();
    try js.endObject();
    try js.objectField("userIdentity");
    try js.write(.{ .type = "IAMUser", .principalId = e.principal, .accessKeyId = e.access_key });
    try js.endObject();
}

pub const fwd_header_prefix = "x-amz-fwd-header-";

/// Response headers the server sets itself; never taken from the webhook.
fn reserved(name: []const u8) bool {
    for ([_][]const u8{ "content-length", "transfer-encoding", "connection", "keep-alive", "x-amz-request-id", "upgrade", "trailer" }) |r|
        if (std.ascii.eqlIgnoreCase(name, r)) return true;
    return false;
}

pub const max_fwd_headers = 64;

fn tokenName(name: []const u8) bool {
    for (name) |ch| if (!(std.ascii.isAlphanumeric(ch) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", ch) != null)) return false;
    return true;
}

/// `x-amz-fwd-header-<Name>: v` becomes `<Name>: v`; others are dropped.
pub fn forwardHeaders(a: Allocator, webhook: []const Header) error{OutOfMemory}![]Header {
    var out: std.ArrayList(Header) = .empty;
    for (webhook) |h| {
        if (h.name.len <= fwd_header_prefix.len or !std.ascii.startsWithIgnoreCase(h.name, fwd_header_prefix)) continue;
        const name = h.name[fwd_header_prefix.len..];
        if (reserved(name) or !tokenName(name) or out.items.len == max_fwd_headers) continue;
        try out.append(a, .{ .name = name, .value = h.value });
    }
    return out.items;
}

pub const Outcome = union(enum) {
    /// Stream the webhook body with this status.
    ok: u16,
    fail: struct { status: u16, code: []const u8, message: []const u8 },
};

fn get(hs: []const Header, name: []const u8) ?[]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return std.mem.trim(u8, h.value, " \t");
    return null;
}

/// x-amz-fwd-status (else the webhook's own status) decides; non-2xx becomes an S3 error
/// with x-amz-fwd-error-code / x-amz-fwd-error-message.
pub fn outcome(http_status: u16, hs: []const Header) Outcome {
    var status = http_status;
    if (get(hs, "x-amz-fwd-status")) |s| {
        const v = std.fmt.parseInt(u16, s, 10) catch 0;
        status = if (v >= 200 and v <= 599) v else 502;
    }
    if (status == 200 or status == 206) return .{ .ok = status };
    if (status >= 200 and status < 300) return .{ .ok = status };
    return .{ .fail = .{
        .status = status,
        .code = get(hs, "x-amz-fwd-error-code") orelse defaultCode(status),
        .message = get(hs, "x-amz-fwd-error-message") orelse "The lambda function returned an error.",
    } };
}

fn defaultCode(status: u16) []const u8 {
    return switch (status) {
        400 => "InvalidRequest",
        403 => "AccessDenied",
        404 => "NoSuchKey",
        412 => "PreconditionFailed",
        416 => "InvalidRange",
        503 => "SlowDown",
        else => "LambdaFunctionError",
    };
}

const t = std.testing;

test "arn" {
    try t.expectEqualStrings("fn1", try parseArn("arn:minio:s3-object-lambda::fn1:webhook"));
    try t.expectEqualStrings("fn1", try parseArn("arn:minio:s3-object-lambda:us-east-1:fn1:webhook"));
    try t.expectError(error.InvalidArn, parseArn("arn:minio:sqs::fn1:webhook"));
    try t.expectError(error.InvalidArn, parseArn("arn:minio:s3-object-lambda::fn1:webhook:x"));
    try t.expectError(error.InvalidArn, parseArn("arn:minio:s3-object-lambda:::webhook"));
    try t.expectError(error.InvalidArn, parseArn(""));
}

test "event json" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const j = try eventJson(a, .{
        .input_url = "http://h/b/k?X=1",
        .route = "r1",
        .token = "tok",
        .arn = "arn:minio:s3-object-lambda::fn:webhook",
        .url = "/b/k?lambdaArn=x",
        .headers = &.{ .{ .name = "x-amz-date", .value = "d" }, .{ .name = "Authorization", .value = "secret" }, .{ .name = "accept", .value = "a" }, .{ .name = "Accept", .value = "b" } },
        .principal = "u",
        .access_key = "AK",
    });
    try t.expect(std.mem.indexOf(u8, j, "secret") == null);
    const P = struct {
        protocolVersion: []const u8,
        getObjectContext: struct { inputS3Url: []const u8, outputRoute: []const u8, outputToken: []const u8 },
        configuration: struct { accessPointArn: []const u8 },
        userRequest: struct { url: []const u8, headers: std.json.Value },
        userIdentity: struct { type: []const u8, principalId: []const u8, accessKeyId: []const u8 },
    };
    const p = try std.json.parseFromSliceLeaky(P, a, j, .{ .ignore_unknown_fields = true });
    try t.expectEqualStrings("http://h/b/k?X=1", p.getObjectContext.inputS3Url);
    try t.expectEqualStrings("tok", p.getObjectContext.outputToken);
    try t.expectEqualStrings("/b/k?lambdaArn=x", p.userRequest.url);
    try t.expectEqualStrings("d", p.userRequest.headers.object.get("X-Amz-Date").?.array.items[0].string);
    try t.expectEqual(@as(usize, 2), p.userRequest.headers.object.get("Accept").?.array.items.len);
    try t.expectEqualStrings("AK", p.userIdentity.accessKeyId);
}

test "forward headers and status" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const hs = [_]Header{
        .{ .name = "X-Amz-Fwd-Header-Content-Type", .value = "text/plain" },
        .{ .name = "x-amz-fwd-header-Content-Length", .value = "9" },
        .{ .name = "x-amz-fwd-status", .value = "403" },
        .{ .name = "x-amz-fwd-error-code", .value = "AccessDenied" },
        .{ .name = "x-amz-fwd-error-message", .value = "nope" },
        .{ .name = "Server", .value = "py" },
    };
    const f = try forwardHeaders(arena.allocator(), &hs);
    try t.expectEqual(@as(usize, 1), f.len);
    try t.expectEqualStrings("Content-Type", f[0].name);
    const o = outcome(200, &hs);
    try t.expectEqual(@as(u16, 403), o.fail.status);
    try t.expectEqualStrings("AccessDenied", o.fail.code);
    try t.expectEqualStrings("nope", o.fail.message);
    try t.expectEqual(@as(u16, 206), outcome(200, &.{.{ .name = "x-amz-fwd-status", .value = "206" }}).ok);
    try t.expectEqual(@as(u16, 200), outcome(200, &.{}).ok);
    try t.expectEqualStrings("LambdaFunctionError", outcome(500, &.{}).fail.code);
    try t.expectEqual(@as(u16, 502), outcome(200, &.{.{ .name = "x-amz-fwd-status", .value = "abc" }}).fail.status);
}

test "presigned url verifies like the server canonicalizes" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const u = try presignUrl(a, .{
        .scheme = "http",
        .host = "127.0.0.1:9000",
        .path = "/b/a key+x",
        .params = &.{.{ .name = "versionId", .value = "v1" }},
        .access_key = "AK",
        .secret_key = "SK",
        .region = "us-east-1",
        .now_s = 1700000000,
    });
    try t.expect(std.mem.startsWith(u8, u, "http://127.0.0.1:9000/b/a%20key%2Bx?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK%2F20231114%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231114T221320Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&versionId=v1&X-Amz-Signature="));
    const plain = try presignUrl(a, .{ .scheme = "http", .host = "h", .path = "/b/k", .params = &.{}, .region = "r", .now_s = 0 });
    try t.expectEqualStrings("http://h/b/k", plain);
    var buf: [22]u8 = undefined;
    try t.expectEqual(@as(usize, 22), outputRoute(&buf).len);
    try t.expectEqual(@as(usize, 43), (try outputToken(a, @splat(1), "r", "ak", 5)).len);
}
