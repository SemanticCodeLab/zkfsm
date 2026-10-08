//! console: the embedded web console. Serves the prebuilt UI bundle and a small
//! JSON API; S3 and admin calls are proxied to the S3 listener and signed there
//! with the session's temporary credentials, so the browser never holds a secret.
const std = @import("std");
const iam = @import("../iam/root.zig");
pub const sign = @import("sign.zig");
pub const session = @import("session.zig");
pub const upstream = @import("upstream.zig");
pub const oidc = @import("oidc.zig");
const assets = @import("console_assets");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Request = std.http.Server.Request;
const Header = std.http.Header;

pub const ServeError = error{ WriteFailed, ReadFailed, OutOfMemory, HttpExpectationFailed };

pub const cookie_name = "zkfsm_console";
pub const default_port: u16 = 9001;

pub const limits = struct {
    /// Largest proxied request body; the UI uploads bigger files in parts.
    pub const max_body = 64 * 1024 * 1024;
    /// Admin responses are buffered to decrypt them.
    pub const max_admin_response = 16 * 1024 * 1024;
    pub const max_login_body = 16 * 1024;
    pub const min_session_s = 900;
    pub const max_session_s = 43200;
    pub const max_share_s = 7 * 24 * 3600;
};

pub const SealError = error{ OutOfMemory, Failed };

/// What main provides: admin payload sealing (the admin API's encrypted body
/// format) and the dashboard probe, both owned by layers above this one.
pub const Hooks = struct {
    ctx: *anyopaque,
    seal: *const fn (a: Allocator, secret: []const u8, plain: []const u8) SealError![]u8,
    open: *const fn (a: Allocator, secret: []const u8, data: []const u8) SealError![]u8,
    is_sealed: *const fn (data: []const u8) bool,
    /// Writes the dashboard JSON (see console/src/lib/api.ts ClusterInfo).
    cluster: *const fn (ctx: *anyopaque, a: Allocator, w: *Writer) Writer.Error!void,
    /// Requests a background heal pass; false when unavailable.
    heal: ?*const fn (ctx: *anyopaque) bool = null,
};

pub const Config = struct {
    /// The S3 listener as seen from this process (plain HTTP, usually loopback).
    upstream: upstream.Endpoint,
    region: []const u8 = "us-east-1",
    admin_prefix: []const u8 = "/minio/admin",
    metrics_path: []const u8 = "/minio/v2/metrics/cluster",
    session_ttl_s: u32 = limits.max_session_s,
    /// Public S3 base URL for share links; default: request host with `s3_port`.
    s3_url: ?[]const u8 = null,
    s3_port: u16 = 9000,
    s3_tls: bool = false,
    /// Console served over TLS: cookies get `Secure`.
    secure: bool = false,
    /// Identity providers for the login page.
    iam: ?*iam.Store = null,
    idp_env: iam.idp.EnvConfig = .{},
};

pub const Console = struct {
    gpa: Allocator,
    cfg: Config,
    hooks: Hooks,
    sessions: session.Store,

    pub fn init(gpa: Allocator, cfg: Config, hooks: Hooks) Console {
        return .{ .gpa = gpa, .cfg = cfg, .hooks = hooks, .sessions = .{ .gpa = gpa } };
    }

    pub fn deinit(c: *Console) void {
        c.sessions.deinit();
    }

    /// Entry point for the listener (matches the S3 server's raw-route signature).
    pub fn serve(ptr: *anyopaque, req: *Request, arena: Allocator) ServeError!void {
        const c: *Console = @ptrCast(@alignCast(ptr));
        // No length and not chunked means no body; std's discard logic needs it explicit.
        if (req.head.transfer_encoding == .none and req.head.content_length == null) req.head.content_length = 0;
        const target = req.head.target;
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        if (std.mem.startsWith(u8, path, "/api/")) return c.api(req, arena, path);
        return serveStatic(req, path);
    }

    fn api(c: *Console, req: *Request, a: Allocator, path: []const u8) ServeError!void {
        const m = req.head.method;
        if (m != .GET and m != .HEAD and !csrfOk(req)) {
            try drain(req);
            return jsonError(req, .forbidden, "CsrfRejected", "Missing or cross-origin request header.");
        }
        const now = std.time.timestamp();
        if (std.mem.eql(u8, path, "/api/v1/login/methods")) return c.loginMethods(req, a);
        if (std.mem.eql(u8, path, "/api/v1/login") and m == .POST) return c.login(req, a, now);
        if (std.mem.eql(u8, path, "/api/v1/oidc/start")) return oidc.start(c, req, a, now);
        if (std.mem.eql(u8, path, "/api/v1/oidc/callback")) return oidc.callback(c, req, a, now);
        if (std.mem.eql(u8, path, "/api/v1/logout") and m == .POST) {
            if (cookie(req)) |id| c.sessions.remove(id);
            try drain(req);
            return respond(req, .ok, "application/json", "{}", &.{.{ .name = "set-cookie", .value = try c.clearCookie(a) }});
        }
        const sess = (if (cookie(req)) |id| try c.sessions.get(a, id, now) else null) orelse {
            try drain(req);
            return jsonError(req, .unauthorized, "Unauthorized", "Log in to continue.");
        };
        if (std.mem.eql(u8, path, "/api/v1/session")) return respond(req, .ok, "application/json", try sessionJson(a, sess), &.{});
        if (std.mem.startsWith(u8, path, "/api/v1/s3/") or std.mem.eql(u8, path, "/api/v1/s3")) return c.proxy(req, a, sess, now);
        if (std.mem.eql(u8, path, "/api/v1/cluster")) return c.cluster(req, a, sess, now);
        if (std.mem.eql(u8, path, "/api/v1/metrics")) return c.metrics(req, a, sess, now);
        if (std.mem.eql(u8, path, "/api/v1/presign")) return c.presign(req, a, sess, now);
        if (std.mem.eql(u8, path, "/api/v1/heal") and m == .POST) return c.heal(req, a, sess, now);
        try drain(req);
        return jsonError(req, .not_found, "NotFound", "Unknown console API.");
    }

    // ------------------------------------------------------------ login

    fn loginMethods(c: *Console, req: *Request, a: Allocator) ServeError!void {
        var out: Writer.Allocating = .init(a);
        var js: std.json.Stringify = .{ .writer = &out.writer };
        const Provider = struct { name: []const u8, label: []const u8 };
        var list: std.ArrayList(Provider) = .empty;
        var ldap = false;
        if (c.cfg.iam) |st| {
            for (try iam.idp.effective(a, st, c.cfg.idp_env, .openid)) |e| {
                const p = iam.idp.OpenId.from(e.name, e.settings);
                if (!p.enabled or p.client_id.len == 0) continue;
                const label = iam.idp.get(e.settings, "display_name") orelse if (std.mem.eql(u8, e.name, iam.idp.default_name)) "OpenID" else e.name;
                try list.append(a, .{ .name = e.name, .label = label });
            }
            for (try iam.idp.effective(a, st, c.cfg.idp_env, .ldap)) |e| {
                if (iam.idp.Ldap.from(e.settings).enabled) ldap = true;
            }
        }
        js.write(.{ .password = true, .ldap = ldap, .openid = list.items }) catch return error.OutOfMemory;
        return respond(req, .ok, "application/json", out.written(), &.{});
    }

    fn login(c: *Console, req: *Request, a: Allocator, now: i64) ServeError!void {
        const body = try readBody(req, a, limits.max_login_body) orelse return jsonError(req, .payload_too_large, "EntityTooLarge", "Request body is too large.");
        const In = struct { accessKey: []const u8 = "", secretKey: []const u8 = "", ldap: bool = false };
        const in = std.json.parseFromSliceLeaky(In, a, body, .{ .ignore_unknown_fields = true }) catch
            return jsonError(req, .bad_request, "InvalidRequest", "Expected JSON with accessKey and secretKey.");
        if (in.accessKey.len == 0 or in.secretKey.len == 0) return jsonError(req, .bad_request, "InvalidRequest", "Access key and secret key are required.");
        var form: Writer.Allocating = .init(a);
        const fw = &form.writer;
        fw.print("Version=2011-06-15&DurationSeconds={d}", .{c.ttl()}) catch return error.OutOfMemory;
        var creds: ?sign.Credentials = null;
        if (in.ldap) {
            fw.writeAll("&Action=AssumeRoleWithLDAPIdentity&LDAPUsername=") catch return error.OutOfMemory;
            formEncode(fw, in.accessKey) catch return error.OutOfMemory;
            fw.writeAll("&LDAPPassword=") catch return error.OutOfMemory;
            formEncode(fw, in.secretKey) catch return error.OutOfMemory;
        } else {
            fw.writeAll("&Action=AssumeRole") catch return error.OutOfMemory;
            creds = .{ .access_key = in.accessKey, .secret_key = in.secretKey };
        }
        const got = c.assume(a, creds, form.written(), now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Unreachable, error.BadResponse => return jsonError(req, .bad_gateway, "Unavailable", "The storage server did not answer."),
            error.Rejected => {
                std.Thread.sleep(300 * std.time.ns_per_ms);
                return jsonError(req, .unauthorized, "InvalidLogin", "Invalid login credentials.");
            },
        };
        return c.startSession(req, a, .{
            .user = in.accessKey,
            .access_key = got.access_key,
            .secret_key = got.secret_key,
            .session_token = got.session_token,
            .provider = if (in.ldap) "ldap" else "password",
            .expires_s = got.expires_s,
        }, now, null);
    }

    pub fn ttl(c: *const Console) u32 {
        return std.math.clamp(c.cfg.session_ttl_s, limits.min_session_s, limits.max_session_s);
    }

    pub const AssumeError = error{ OutOfMemory, Unreachable, BadResponse, Rejected };
    pub const Assumed = struct { access_key: []const u8, secret_key: []const u8, session_token: []const u8, expires_s: i64, subject: []const u8 };

    /// Calls STS on the S3 listener; `creds` signs the call (AssumeRole) or null (federated).
    pub fn assume(c: *Console, a: Allocator, creds: ?sign.Credentials, form: []const u8, now: i64) AssumeError!Assumed {
        var hb: [300]u8 = undefined;
        const host = c.cfg.upstream.authority(&hb);
        const ct: Header = .{ .name = "content-type", .value = "application/x-www-form-urlencoded" };
        var headers: []const Header = &.{ct};
        if (creds) |cr| {
            const hash = core_sha256Hex(form);
            const s = try sign.sign(a, cr, .{ .method = "POST", .host = host, .path = "/", .headers = &.{ct}, .payload_sha256_hex = try a.dupe(u8, &hash), .region = c.cfg.region, .service = "sts" }, now);
            headers = s.headers;
        }
        const res = upstream.send(a, c.cfg.upstream, .POST, "/", headers, form) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Unreachable => error.Unreachable,
            error.BadResponse => error.BadResponse,
        };
        defer res.close();
        const body = res.readAll(a, 64 * 1024) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadResponse,
        };
        if (res.status() != 200) return error.Rejected;
        const ak = xmlText(body, "AccessKeyId") orelse return error.BadResponse;
        const sk = xmlText(body, "SecretAccessKey") orelse return error.BadResponse;
        const tok = xmlText(body, "SessionToken") orelse "";
        const exp = xmlText(body, "Expiration") orelse "";
        return .{
            .access_key = ak,
            .secret_key = sk,
            .session_token = tok,
            .expires_s = parseIsoTime(exp) orelse now + c.ttl(),
            .subject = xmlText(body, "SubjectFromWebIdentityToken") orelse "",
        };
    }

    /// Stores the session and answers with its cookie; `redirect` answers 303 instead of JSON.
    pub fn startSession(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64, redirect: ?[]const u8) ServeError!void {
        const id = c.sessions.create(s, now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooManySessions => return jsonError(req, .service_unavailable, "TooManySessions", "Too many console sessions."),
        };
        const max_age = @max(0, s.expires_s - now);
        const set = try std.fmt.allocPrint(a, cookie_name ++ "={s}; Path=/; HttpOnly; SameSite=Strict; Max-Age={d}{s}", .{ &id, max_age, if (c.cfg.secure) "; Secure" else "" });
        if (redirect) |loc| return respond(req, .see_other, "text/plain", "", &.{ .{ .name = "set-cookie", .value = set }, .{ .name = "location", .value = loc } });
        return respond(req, .ok, "application/json", try sessionJson(a, s), &.{.{ .name = "set-cookie", .value = set }});
    }

    fn clearCookie(c: *Console, a: Allocator) error{OutOfMemory}![]const u8 {
        return std.fmt.allocPrint(a, cookie_name ++ "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}", .{if (c.cfg.secure) "; Secure" else ""});
    }

    // ------------------------------------------------------------ proxy

    fn credsOf(s: session.Session) sign.Credentials {
        return .{ .access_key = s.access_key, .secret_key = s.secret_key, .session_token = s.session_token };
    }

    fn isAdminPath(c: *const Console, path: []const u8) bool {
        return under(path, c.cfg.admin_prefix) or under(path, "/zkfsm/admin") or under(path, "/minio/admin");
    }

    fn proxy(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64) ServeError!void {
        const target = req.head.target;
        const q = std.mem.indexOfScalar(u8, target, '?');
        const raw_path = target["/api/v1/s3".len .. q orelse target.len];
        const path = try sign.decode(a, if (raw_path.len == 0) "/" else raw_path, false);
        if (std.mem.indexOf(u8, path, "/../") != null or std.mem.endsWith(u8, path, "/..")) {
            try drain(req);
            return jsonError(req, .bad_request, "InvalidPath", "Invalid path.");
        }
        var download = false;
        var params: std.ArrayList(sign.Param) = .empty;
        for (try sign.parseQuery(a, if (q) |i| target[i + 1 ..] else "")) |p| {
            if (std.mem.eql(u8, p.name, "x-console-download")) download = true else try params.append(a, p);
        }
        var fwd: std.ArrayList(Header) = .empty;
        var encrypt = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "x-console-encrypt")) encrypt = true;
            if (forwardRequestHeader(h.name)) try fwd.append(a, .{ .name = try std.ascii.allocLowerString(a, h.name), .value = h.value });
        }
        var body = try readBody(req, a, limits.max_body) orelse return jsonError(req, .payload_too_large, "EntityTooLarge", "Request body is too large; upload in parts.");
        const admin = c.isAdminPath(path);
        if (encrypt and admin and body.len > 0) body = c.hooks.seal(a, s.secret_key, body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Failed => return jsonError(req, .internal_server_error, "SealFailed", "Cannot encrypt the request."),
        };
        const res = c.call(a, s, req.head.method, path, params.items, fwd.items, body, now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return jsonError(req, .bad_gateway, "Unavailable", "The storage server did not answer."),
        };
        defer res.close();
        return c.relay(req, a, res, s, admin, if (download) std.fs.path.basenamePosix(path) else null);
    }

    pub fn call(c: *Console, a: Allocator, s: session.Session, method: std.http.Method, path: []const u8, params: []const sign.Param, headers: []const Header, body: []const u8, now: i64) upstream.Error!*upstream.Response {
        var hb: [300]u8 = undefined;
        const hash = core_sha256Hex(body);
        const signed = try sign.sign(a, credsOf(s), .{
            .method = @tagName(method),
            .host = c.cfg.upstream.authority(&hb),
            .path = path,
            .params = params,
            .headers = headers,
            .payload_sha256_hex = try a.dupe(u8, &hash),
            .region = c.cfg.region,
        }, now);
        return upstream.send(a, c.cfg.upstream, method, signed.target, signed.headers, body);
    }

    /// Streams the upstream response back; admin responses are decrypted first.
    fn relay(c: *Console, req: *Request, a: Allocator, res: *upstream.Response, s: session.Session, admin: bool, attachment: ?[]const u8) ServeError!void {
        var hs: std.ArrayList(Header) = .empty;
        try hs.appendSlice(a, &proxy_security_headers);
        var hit = res.head.iterateHeaders();
        while (hit.next()) |h| if (forwardResponseHeader(h.name)) try hs.append(a, h);
        if (attachment) |name| {
            var v: Writer.Allocating = .init(a);
            v.writer.writeAll("attachment; filename*=UTF-8''") catch return error.OutOfMemory;
            sign.encodePathTo(&v.writer, name) catch return error.OutOfMemory;
            try hs.append(a, .{ .name = "content-disposition", .value = v.written() });
        }
        const status: std.http.Status = @enumFromInt(res.status());
        if (admin and res.hasBody()) {
            var body = res.readAll(a, limits.max_admin_response) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return jsonError(req, .bad_gateway, "Unavailable", "Truncated response from the storage server."),
            };
            if (c.hooks.is_sealed(body)) body = c.hooks.open(a, s.secret_key, body) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Failed => return jsonError(req, .bad_gateway, "UnsealFailed", "Cannot decrypt the response."),
            };
            return req.respond(body, .{ .status = status, .extra_headers = hs.items, .keep_alive = req.head.keep_alive });
        }
        const len: ?u64 = if (res.head.transfer_encoding == .chunked) null else res.head.content_length orelse if (res.hasBody()) null else 0;
        var buf: [16 * 1024]u8 = undefined;
        var bw = try req.respondStreaming(&buf, .{ .content_length = len, .respond_options = .{ .status = status, .extra_headers = hs.items, .keep_alive = req.head.keep_alive and len != null } });
        if (res.hasBody() and req.head.method != .HEAD) {
            const rd = res.bodyReader();
            _ = rd.streamRemaining(&bw.writer) catch |e| switch (e) {
                error.WriteFailed => return error.WriteFailed,
                error.ReadFailed => return error.WriteFailed, // upstream cut: the client sees a short body
            };
        }
        try bw.end();
    }

    // ------------------------------------------------------------ dashboard, metrics, share links

    /// The dashboard reveals drive paths: require the server-info admin permission.
    fn mayAdmin(c: *Console, a: Allocator, s: session.Session, now: i64) error{OutOfMemory}!?u16 {
        const p = try std.fmt.allocPrint(a, "{s}/v3/info", .{c.cfg.admin_prefix});
        const res = c.call(a, s, .GET, p, &.{}, &.{}, "", now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return 502,
        };
        defer res.close();
        _ = res.readAll(a, 1 << 20) catch {};
        return if (res.status() == 200) null else res.status();
    }

    fn cluster(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64) ServeError!void {
        try drain(req);
        if (try c.mayAdmin(a, s, now)) |st| return jsonError(req, @enumFromInt(st), "AccessDenied", "Server information requires the admin:ServerInfo permission.");
        var out: Writer.Allocating = .init(a);
        c.hooks.cluster(c.hooks.ctx, a, &out.writer) catch return error.OutOfMemory;
        return respond(req, .ok, "application/json", out.written(), &.{});
    }

    fn heal(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64) ServeError!void {
        try drain(req);
        if (try c.mayAdmin(a, s, now)) |st| return jsonError(req, @enumFromInt(st), "AccessDenied", "Healing requires admin permissions.");
        const f = c.hooks.heal orelse return jsonError(req, .not_implemented, "NotImplemented", "Healing is not available on this server.");
        if (!f(c.hooks.ctx)) return jsonError(req, .service_unavailable, "HealUnavailable", "The background healer is not running.");
        return respond(req, .accepted, "application/json", "{\"started\":true}", &.{});
    }

    fn metrics(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64) ServeError!void {
        try drain(req);
        const res = c.call(a, s, .GET, c.cfg.metrics_path, &.{}, &.{}, "", now) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return jsonError(req, .bad_gateway, "Unavailable", "The storage server did not answer."),
        };
        defer res.close();
        return c.relay(req, a, res, s, false, null);
    }

    fn presign(c: *Console, req: *Request, a: Allocator, s: session.Session, now: i64) ServeError!void {
        try drain(req);
        const target = req.head.target;
        const params = try sign.parseQuery(a, if (std.mem.indexOfScalar(u8, target, '?')) |i| target[i + 1 ..] else "");
        const bucket = paramOf(params, "bucket") orelse "";
        const key = paramOf(params, "key") orelse "";
        if (bucket.len == 0 or key.len == 0) return jsonError(req, .bad_request, "InvalidRequest", "bucket and key are required.");
        const want = std.fmt.parseInt(i64, paramOf(params, "expires") orelse "3600", 10) catch 3600;
        // Links are signed with the session credentials, so they die with the session.
        const expires: u32 = @intCast(std.math.clamp(@min(want, s.expires_s - now), 1, limits.max_share_s));
        var extra: std.ArrayList(sign.Param) = .empty;
        if (paramOf(params, "versionId")) |v| if (v.len > 0) try extra.append(a, .{ .name = "versionId", .value = v });
        const base = try c.publicBase(req, a);
        const host = base[std.mem.indexOf(u8, base, "://").? + 3 ..];
        const path = try std.fmt.allocPrint(a, "/{s}/{s}", .{ bucket, key });
        const url = try sign.presign(a, credsOf(s), base, host, path, extra.items, expires, c.cfg.region, now);
        var tb: [32]u8 = undefined;
        var out: Writer.Allocating = .init(a);
        var js: std.json.Stringify = .{ .writer = &out.writer };
        js.write(.{ .url = url, .expires = isoTime(now + expires, &tb), .expiresSeconds = expires }) catch return error.OutOfMemory;
        return respond(req, .ok, "application/json", out.written(), &.{});
    }

    fn publicBase(c: *Console, req: *Request, a: Allocator) error{OutOfMemory}![]const u8 {
        if (c.cfg.s3_url) |u| return std.mem.trimRight(u8, u, "/");
        var host: []const u8 = "localhost";
        var it = req.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            host = h.value;
        };
        // Strip the console port; bracketed IPv6 keeps its colons.
        const end = if (std.mem.lastIndexOfScalar(u8, host, ':')) |i| (if (std.mem.indexOfScalar(u8, host[i..], ']') == null) i else host.len) else host.len;
        return std.fmt.allocPrint(a, "{s}://{s}:{d}", .{ if (c.cfg.s3_tls) "https" else "http", host[0..end], c.cfg.s3_port });
    }

    pub fn redirectUri(c: *Console, req: *Request, a: Allocator) error{OutOfMemory}![]const u8 {
        var host: []const u8 = "localhost";
        var it = req.iterateHeaders();
        while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "host")) {
            host = h.value;
        };
        return std.fmt.allocPrint(a, "{s}://{s}/api/v1/oidc/callback", .{ if (c.cfg.secure) "https" else "http", host });
    }
};

// ---------------------------------------------------------------- helpers

fn under(path: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, path, prefix) and (path.len == prefix.len or path[prefix.len] == '/');
}

pub fn paramOf(params: []const sign.Param, name: []const u8) ?[]const u8 {
    for (params) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
    return null;
}

fn core_sha256Hex(data: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

fn forwardRequestHeader(name: []const u8) bool {
    const allowed = [_][]const u8{ "content-type", "content-md5", "cache-control", "content-disposition", "content-encoding", "content-language", "expires", "range", "if-match", "if-none-match", "if-modified-since", "if-unmodified-since" };
    for (allowed) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    if (name.len > 6 and std.ascii.eqlIgnoreCase(name[0..6], "x-amz-")) {
        const own = [_][]const u8{ "x-amz-date", "x-amz-content-sha256", "x-amz-security-token" };
        for (own) |n| if (std.ascii.eqlIgnoreCase(name, n)) return false;
        return true;
    }
    return false;
}

fn forwardResponseHeader(name: []const u8) bool {
    const allowed = [_][]const u8{ "content-type", "etag", "last-modified", "content-range", "accept-ranges", "content-disposition", "content-encoding", "content-language", "expires" };
    for (allowed) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return (name.len > 6 and std.ascii.eqlIgnoreCase(name[0..6], "x-amz-")) or (name.len > 8 and std.ascii.eqlIgnoreCase(name[0..8], "x-minio-"));
}

/// Proxied bytes are user content: never let them run as console pages.
const proxy_security_headers = [_]Header{
    .{ .name = "content-security-policy", .value = "default-src 'none'; sandbox" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "cache-control", .value = "no-store" },
};

const api_headers = [_]Header{
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
};

pub const page_csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " ++
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const page_headers = [_]Header{
    .{ .name = "content-security-policy", .value = page_csp },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-frame-options", .value = "DENY" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
    .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
};

/// State-changing calls need the custom header (forces a CORS preflight) and,
/// when the browser sends Origin, the console's own origin.
fn csrfOk(req: *Request) bool {
    var marked = false;
    var origin: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-console-csrf")) marked = true;
        if (std.ascii.eqlIgnoreCase(h.name, "origin")) origin = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "host")) host = h.value;
    }
    if (!marked) return false;
    const o = origin orelse return true;
    const h = host orelse return false;
    const rest = if (std.mem.indexOf(u8, o, "://")) |i| o[i + 3 ..] else return false;
    return std.mem.eql(u8, rest, h);
}

pub fn cookie(req: *Request) ?[]const u8 {
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "cookie")) continue;
        var parts = std.mem.tokenizeScalar(u8, h.value, ';');
        while (parts.next()) |p| {
            const t = std.mem.trim(u8, p, " ");
            if (std.mem.startsWith(u8, t, cookie_name ++ "=")) return t[cookie_name.len + 1 ..];
        }
    }
    return null;
}

/// Reads the request body; null (after answering nothing) when it exceeds `max`.
pub fn readBody(req: *Request, a: Allocator, max: usize) ServeError!?[]u8 {
    const has = req.head.transfer_encoding != .none or (req.head.content_length orelse 0) > 0;
    if (!has) return try a.alloc(u8, 0);
    if ((req.head.content_length orelse 0) > max) return null;
    var buf: [16 * 1024]u8 = undefined;
    const r = try req.readerExpectContinue(&buf);
    return r.allocRemaining(a, .limited(max)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => null,
        error.ReadFailed => error.ReadFailed,
    };
}

/// Consumes an unused body so the connection can serve the next request.
pub fn drain(req: *Request) ServeError!void {
    const has = req.head.transfer_encoding != .none or (req.head.content_length orelse 0) > 0;
    if (!has) return;
    var buf: [4096]u8 = undefined;
    const r = try req.readerExpectContinue(&buf);
    _ = r.discardRemaining() catch |e| switch (e) {
        error.ReadFailed => return error.ReadFailed,
    };
}

pub fn respond(req: *Request, status: std.http.Status, content_type: []const u8, body: []const u8, extra: []const Header) ServeError!void {
    var hs: [16]Header = undefined;
    var n: usize = 0;
    hs[n] = .{ .name = "content-type", .value = content_type };
    n += 1;
    for (api_headers) |h| {
        hs[n] = h;
        n += 1;
    }
    for (extra[0..@min(extra.len, hs.len - n)]) |h| {
        hs[n] = h;
        n += 1;
    }
    return req.respond(body, .{ .status = status, .extra_headers = hs[0..n], .keep_alive = req.head.keep_alive });
}

pub fn jsonError(req: *Request, status: std.http.Status, code: []const u8, msg: []const u8) ServeError!void {
    var buf: [1024]u8 = undefined;
    var w: Writer = .fixed(&buf);
    var js: std.json.Stringify = .{ .writer = &w };
    js.write(.{ .code = code, .message = msg }) catch return respond(req, status, "application/json", "{}", &.{});
    return respond(req, status, "application/json", w.buffered(), &.{});
}

fn sessionJson(a: Allocator, s: session.Session) error{OutOfMemory}![]const u8 {
    var tb: [32]u8 = undefined;
    var out: Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer };
    js.write(.{ .user = s.user, .accessKey = s.access_key, .expires = isoTime(s.expires_s, &tb), .provider = s.provider }) catch return error.OutOfMemory;
    return out.written();
}

pub fn isoTime(t: i64, buf: *[32]u8) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(t, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` to Unix seconds.
pub fn parseIsoTime(s: []const u8) ?i64 {
    if (s.len < 19 or s[4] != '-' or s[7] != '-' or s[10] != 'T') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const h = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const se = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return null;
    // Days from civil (proleptic Gregorian).
    const yy = if (mo <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = @mod(@as(i64, mo) + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + h * 3600 + mi * 60 + se;
}

/// First `<tag>text</tag>` in an XML document (no nesting, entities decoded for the basics).
pub fn xmlText(doc: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [80]u8 = undefined;
    var close_buf: [80]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const i = std.mem.indexOf(u8, doc, open) orelse return null;
    const j = std.mem.indexOfPos(u8, doc, i + open.len, close) orelse return null;
    return doc[i + open.len .. j];
}

fn formEncode(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') try w.writeByte(ch) else try w.print("%{X:0>2}", .{ch});
    }
}
pub const formEncodeTo = formEncode;

fn serveStatic(req: *Request, path: []const u8) ServeError!void {
    try drain(req);
    if (req.head.method != .GET and req.head.method != .HEAD) return respond(req, .method_not_allowed, "text/plain", "method not allowed\n", &.{});
    const f = assets.find(path) orelse assets.find("/index.html").?;
    var hs: [8]Header = undefined;
    hs[0] = .{ .name = "content-type", .value = f.mime };
    hs[1] = .{ .name = "cache-control", .value = if (std.mem.endsWith(u8, f.path, ".html")) "no-cache" else "public, max-age=300" };
    for (page_headers, 0..) |h, i| hs[2 + i] = h;
    return req.respond(f.data, .{ .extra_headers = hs[0 .. 2 + page_headers.len], .keep_alive = req.head.keep_alive });
}

test {
    _ = sign;
    _ = session;
    _ = upstream;
    _ = oidc;
}

test "iso time round trip and xml text" {
    var b: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2013-05-24T00:00:00Z", isoTime(1369353600, &b));
    try std.testing.expectEqual(@as(?i64, 1369353600), parseIsoTime("2013-05-24T00:00:00.000Z"));
    try std.testing.expectEqual(@as(?i64, 951782400), parseIsoTime("2000-02-29T00:00:00Z"));
    try std.testing.expectEqualStrings("AK", xmlText("<R><AccessKeyId>AK</AccessKeyId></R>", "AccessKeyId").?);
    try std.testing.expect(xmlText("<R/>", "X") == null);
}

test "header forwarding rules" {
    try std.testing.expect(forwardRequestHeader("Content-Type"));
    try std.testing.expect(forwardRequestHeader("x-amz-meta-a"));
    try std.testing.expect(!forwardRequestHeader("x-amz-date"));
    try std.testing.expect(!forwardRequestHeader("cookie"));
    try std.testing.expect(!forwardRequestHeader("authorization"));
    try std.testing.expect(forwardResponseHeader("ETag"));
    try std.testing.expect(!forwardResponseHeader("set-cookie"));
    try std.testing.expect(under("/minio/admin/v3/info", "/minio/admin"));
    try std.testing.expect(!under("/minio/administrator", "/minio/admin"));
}
