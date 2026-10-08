//! GET object with `?lambdaArn=...`: presigns the plain GetObject, posts the event
//! to the lambda webhook and streams its reply back (x-amz-fwd-* mapping).
const std = @import("std");
const backend = @import("../backend/root.zig");
const object = @import("../object/root.zig");
const metrics = @import("../metrics/root.zig");
const iam = @import("../iam/root.zig");
const s3 = @import("../s3/root.zig");
const config = @import("config.zig");
const event = @import("event.zig");
const client = @import("client.zig");

const Allocator = std.mem.Allocator;
const Header = std.http.Header;
const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;

pub const default_max_response_bytes: u64 = 5 * 1024 * 1024 * 1024;
const max_stored_config = 256 * 1024;

pub const Registry = struct {
    gpa: Allocator,
    svc: *object.ObjectService,
    /// Targets from the environment (enabled only); stored targets win on id clashes.
    env_targets: []const config.Target = &.{},
    /// Scheme of inputS3Url ("https" when the server terminates TLS).
    scheme: []const u8 = "http",
    region: []const u8 = "",
    token_key: [32]u8,
    client: client.Options = .{},
    max_response_bytes: u64 = default_max_response_bytes,

    pub fn init(gpa: Allocator, svc: *object.ObjectService, env_targets: []const config.Target) Registry {
        var k: [32]u8 = undefined;
        std.crypto.random.bytes(&k);
        return .{ .gpa = gpa, .svc = svc, .env_targets = env_targets, .token_key = k };
    }

    pub fn extension(self: *Registry) s3.Extension {
        return .{ .name = "lambda", .ctx = self, .route = route };
    }

    pub const StoreError = error{ StorageFailed, OutOfMemory };

    /// Targets set through the admin config API (shared by cluster nodes).
    pub fn stored(self: *Registry, a: Allocator) StoreError![]config.Target {
        const bytes = self.svc.store.getRecord(storeKey(), a) catch |e| return switch (e) {
            error.NotFound => &.{},
            error.OutOfMemory => error.OutOfMemory,
            else => error.StorageFailed,
        };
        if (bytes.len > max_stored_config) return error.StorageFailed;
        return config.parse(a, bytes) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => &.{},
        };
    }

    pub fn save(self: *Registry, text: []const u8) StoreError!void {
        self.svc.store.putRecord(storeKey(), text) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.StorageFailed;
    }

    pub fn lookup(self: *Registry, a: Allocator, id: []const u8) StoreError!?config.Target {
        for (try self.stored(a)) |t| if (std.mem.eql(u8, t.id, id)) return if (t.enabled()) t else null;
        for (self.env_targets) |t| if (std.mem.eql(u8, t.id, id)) return t;
        return null;
    }
};

/// `5a4c4c` + 26 hex of sha256("lambda_webhook").
fn storeKey() backend.PhysicalKey {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(config.subsys, &d, .{});
    const hex = std.fmt.bytesToHex(d, .lower);
    var k: backend.PhysicalKey = .{ .space = .system, .hex = undefined };
    @memcpy(k.hex[0..6], "5a4c4c");
    @memcpy(k.hex[6..], hex[0..26]);
    return k;
}

fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
    const self: *Registry = @ptrCast(@alignCast(ptr));
    if (c.method != .GET or c.route.bucket.len == 0 or c.route.key.len == 0) return false;
    const arn = try s3.handler.param(c, "lambdaArn") orelse return false;
    try serve(self, c, arn);
    return true;
}

fn serve(self: *Registry, c: *Ctx, arn: []const u8) ConnError!void {
    const a = c.arena;
    const id = event.parseArn(arn) catch return failCode(c, 400, "LambdaARNInvalid", "The specified lambda ARN is invalid.", &.{});
    const target = self.lookup(a, id) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StorageFailed => return failCode(c, 503, "XMinioServerNotInitialized", "Lambda configuration storage is unavailable.", &.{}),
    } orelse return failCode(c, 404, "LambdaARNNotFound", "The specified lambda ARN does not exist.", &.{});
    const ep = config.endpoint(a, target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidConfig => return failCode(c, 500, "InternalError", "The lambda target is misconfigured.", &.{}),
    };
    const auth = config.authHeader(a, target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidConfig => return failCode(c, 500, "InternalError", "The lambda target is misconfigured.", &.{}),
    };
    const host = c.host orelse return s3.handler.fail(c, .InvalidRequest);
    const now_s = std.time.timestamp();
    const input_url = (try inputUrl(self, c, host, now_s)) orelse return;
    var rb: [22]u8 = undefined;
    const out_route = event.outputRoute(&rb);
    const token = try event.outputToken(a, self.token_key, out_route, c.auth.access_key, now_s + event.presign_expires_s);
    const body = try event.eventJson(a, .{
        .input_url = input_url,
        .route = out_route,
        .token = token,
        .arn = arn,
        .url = c.target,
        .headers = c.headers,
        .principal = c.auth.principal,
        .access_key = c.auth.access_key,
    });
    const r = client.post(self.gpa, a, ep, auth, body, self.client) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unreachable => return failCode(c, 500, "InternalError", "The lambda target could not be reached.", &.{}),
        error.BadResponse => return failCode(c, 500, "InternalError", "The lambda target sent a malformed response.", &.{}),
    };
    defer r.close();
    const fwd = try event.forwardHeaders(a, r.headers);
    switch (event.outcome(r.status, r.headers)) {
        .fail => |f| return failCode(c, f.status, f.code, f.message, fwd),
        .ok => |status| try stream(self, c, r, status, fwd),
    }
}

/// Presigned plain GetObject for the caller; null after an error response.
fn inputUrl(self: *Registry, c: *Ctx, host: []const u8, now_s: i64) ConnError!?[]const u8 {
    const a = c.arena;
    const q = std.mem.indexOfScalar(u8, c.target, '?');
    const path = s3.router.percentDecode(a, c.target[0 .. q orelse c.target.len], false) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUri => {
            try s3.handler.fail(c, .InvalidURI);
            return null;
        },
    };
    var params: std.ArrayList(@import("../core/root.zig").sigv4.Param) = .empty;
    var token: ?[]const u8 = null;
    if (q) |i| {
        var it = std.mem.splitScalar(u8, c.target[i + 1 ..], '&');
        while (it.next()) |pair| {
            if (pair.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, pair, '=');
            const name = s3.router.percentDecode(a, pair[0 .. eq orelse pair.len], false) catch continue;
            const value = if (eq) |e| s3.router.percentDecode(a, pair[e + 1 ..], false) catch continue else "";
            if (std.ascii.eqlIgnoreCase(name, "X-Amz-Security-Token")) token = value;
            if (std.mem.eql(u8, name, "lambdaArn") or std.ascii.startsWithIgnoreCase(name, "X-Amz-")) continue;
            if (params.items.len == 64) break;
            try params.append(a, .{ .name = name, .value = value });
        }
    }
    for (c.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-amz-security-token")) {
        token = h.value;
    };
    var p: event.Presign = .{
        .scheme = self.scheme,
        .host = host,
        .path = path,
        .params = params.items,
        .region = if (c.auth.scope.region.len > 0) c.auth.scope.region else if (self.region.len > 0) self.region else "us-east-1",
        .now_s = now_s,
    };
    const env = c.env.auth;
    if (env.iam) |store| if (!c.auth.anonymous and c.auth.access_key.len > 0) {
        const ak = c.auth.access_key;
        var sbuf: iam.Store.SecretBuf = undefined;
        var sts_secret: [iam.sts.secret_key_len]u8 = undefined;
        const secret: []const u8 = if (!std.mem.eql(u8, ak, c.auth.principal)) blk: {
            const issuer = env.sts orelse return deny(c);
            sts_secret = issuer.secretFor(ak);
            p.session_token = token orelse return deny(c);
            break :blk &sts_secret;
        } else store.secretFor(ak, now_s, &sbuf) orelse return deny(c);
        p.access_key = ak;
        p.secret_key = try a.dupe(u8, secret);
    };
    return try event.presignUrl(a, p);
}

fn deny(c: *Ctx) ConnError!?[]const u8 {
    try s3.handler.fail(c, .AccessDenied);
    return null;
}

fn stream(self: *Registry, c: *Ctx, r: *client.Response, status: u16, fwd: []const Header) ConnError!void {
    if (r.content_length) |n| if (n > self.max_response_bytes)
        return failCode(c, 500, "InternalError", "The lambda response is too large.", fwd);
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, fwd);
    try hdrs.appendSlice(c.arena, c.extra);
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    c.resp_headers = hdrs.items;
    metrics.global.last_status = @intCast(status);
    var out_buf: [s3.handler.io_buf_len]u8 = undefined;
    var bw = try c.req.respondStreaming(&out_buf, .{
        .content_length = r.content_length,
        .respond_options = .{ .status = @enumFromInt(status), .extra_headers = hdrs.items, .keep_alive = false },
    });
    var left = self.max_response_bytes;
    while (true) {
        const n = r.body.stream(&bw.writer, .limited(@min(left, 64 * 1024))) catch |e| switch (e) {
            error.EndOfStream => break,
            error.ReadFailed => return error.StreamAborted,
            error.WriteFailed => return error.WriteFailed,
        };
        left -= n;
        if (left == 0) {
            // One more byte means the body is over the limit.
            var probe: [1]u8 = undefined;
            const extra = r.body.readSliceShort(&probe) catch return error.StreamAborted;
            if (extra > 0) return error.StreamAborted;
            break;
        }
    }
    try bw.end();
}

fn failCode(c: *Ctx, status: u16, code: []const u8, message: []const u8, extra: []const Header) ConnError!void {
    const st: u16 = if (status >= 300 and status <= 599) status else 500;
    metrics.global.last_status = @intCast(st);
    var out: std.Io.Writer.Allocating = .init(c.arena);
    const w = &out.writer;
    writeError(w, c, code, message) catch return error.OutOfMemory;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, c.extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    c.resp_headers = hdrs.items;
    try c.req.respond(out.written(), .{ .status = @enumFromInt(st), .extra_headers = hdrs.items, .keep_alive = false });
}

fn writeError(w: *std.Io.Writer, c: *Ctx, code: []const u8, message: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(s3.xml.declaration ++ "<Error>");
    try s3.xml.elem(w, "Code", code);
    try s3.xml.elem(w, "Message", message);
    try s3.xml.elem(w, "BucketName", c.route.bucket);
    try s3.xml.elem(w, "Key", c.route.key);
    try s3.xml.elem(w, "Resource", std.mem.sliceTo(c.target, '?'));
    try s3.xml.elem(w, "RequestId", &c.request_id);
    try w.writeAll("</Error>");
}

test "store key" {
    const k = storeKey();
    try std.testing.expectEqualStrings("5a4c4c", k.hex[0..6]);
}
