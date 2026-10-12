//! Console login over OpenID Connect (authorization code + PKCE), unauthenticated:
//!   GET <prefix>/v3/oidc/providers             enabled OpenID configurations
//!   GET <prefix>/v3/oidc/authorize/<name>      302 to the IdP (sets the binding cookie)
//!   GET <prefix>/v3/oidc/callback/<name>       code exchange -> STS credentials
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const api = @import("api.zig");

const Allocator = std.mem.Allocator;
const login = iam.oidc_login;
const Error = api.Error;

pub const cookie_name = "zkfsm_oidc";

pub const Response = struct {
    status: std.http.Status = .ok,
    body: []const u8 = "",
    content_type: []const u8 = "application/json",
    location: ?[]const u8 = null,
    set_cookie: ?[]const u8 = null,
};

pub const Env = struct {
    fed: ?*iam.federation.Federation,
    issuer: ?*const iam.sts.Issuer,
    store: *iam.Store,
    /// Admin prefix the request came in on (for callback URL and cookie path).
    prefix: []const u8,
    /// `scheme://host` the client used.
    origin: []const u8,
};

pub const Request = struct {
    op: []const u8,
    query: []const u8,
    cookie: []const u8 = "",
    now_s: i64,
};

/// Handles `/oidc/...` operations; null for anything else.
pub fn handle(a: Allocator, env: Env, req: Request) Error!?Response {
    const base = "/oidc/";
    if (!std.mem.startsWith(u8, req.op, base)) return null;
    const rest = req.op[base.len..];
    const fed = env.fed orelse return try fail(a, .bad_request, "InvalidParameterValue", "No identity provider is configured.");
    if (std.mem.eql(u8, rest, "providers")) return try providers(a, fed);
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return try fail(a, .not_found, "NotFound", "Unknown login operation.");
    const name = try api.formDecode(a, rest[slash + 1 ..]) orelse return try fail(a, .bad_request, "InvalidRequest", "Invalid provider name.");
    const action = rest[0..slash];
    if (std.mem.eql(u8, action, "authorize")) return try authorize(a, env, fed, name, req);
    if (std.mem.eql(u8, action, "callback")) return try callback(a, env, fed, name, req);
    return try fail(a, .not_found, "NotFound", "Unknown login operation.");
}

fn fail(a: Allocator, status: std.http.Status, code: []const u8, message: []const u8) Error!Response {
    const r = try api.fail(a, status, code, message);
    return .{ .status = r.status, .body = r.body };
}

fn loginFail(a: Allocator, e: login.Error) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoProvider => fail(a, .not_found, "InvalidParameterValue", "No such OpenID provider."),
        error.ProviderUnavailable, error.ExchangeFailed => fail(a, .bad_gateway, "IDPCommunicationError", "The identity provider could not complete the login."),
        error.InvalidState => fail(a, .forbidden, "AccessDenied", "The login state is invalid, expired, or from another browser."),
        error.InvalidRedirect => fail(a, .bad_request, "InvalidRequest", "redirect_after must be a path on this server."),
        error.InvalidToken, error.ExpiredToken => fail(a, .forbidden, "InvalidIdentityToken", "The identity token is not valid."),
        error.NoPolicy => fail(a, .forbidden, "AccessDenied", "The token grants no known policy."),
        error.InvalidTenant => fail(a, .forbidden, "AccessDenied", "The token names no active tenant."),
    };
}

fn providers(a: Allocator, fed: *iam.federation.Federation) Error!?Response {
    const entries = try iam.idp.effective(a, fed.store, fed.env, .openid);
    var names: std.ArrayList([]const u8) = .empty;
    for (entries) |e| if (iam.idp.OpenId.from(e.name, e.settings).enabled) try names.append(a, e.name);
    return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .providers = names.items }, .{}) };
}

fn authorize(a: Allocator, env: Env, fed: *iam.federation.Federation, name: []const u8, req: Request) Error!Response {
    const issuer = env.issuer orelse return fail(a, .not_implemented, "NotImplemented", "STS requires authenticated mode.");
    const after = try api.queryParam(a, req.query, "redirect_after") orelse "";
    const cb = try std.fmt.allocPrint(a, "{s}{s}/v3/oidc/callback/{s}", .{ env.origin, env.prefix, name });
    const b = login.begin(fed, a, issuer.key, name, cb, after, req.now_s, std.crypto.random) catch |e| return loginFail(a, e);
    const cookie = try std.fmt.allocPrint(a, "{s}={s}; Path={s}/v3/oidc; Max-Age={d}; HttpOnly; SameSite=Lax", .{ cookie_name, b.binding, env.prefix, login.max_state_age_s });
    return .{ .status = .found, .location = b.url, .set_cookie = cookie };
}

fn callback(a: Allocator, env: Env, fed: *iam.federation.Federation, name: []const u8, req: Request) Error!Response {
    const issuer = env.issuer orelse return fail(a, .not_implemented, "NotImplemented", "STS requires authenticated mode.");
    if (try api.queryParam(a, req.query, "error")) |_| return fail(a, .forbidden, "AccessDenied", "The identity provider refused the login.");
    const code = try api.queryParam(a, req.query, "code") orelse return fail(a, .bad_request, "MissingParameter", "code is required.");
    const state = try api.queryParam(a, req.query, "state") orelse return fail(a, .bad_request, "MissingParameter", "state is required.");
    const binding = cookieValue(req.cookie, cookie_name) orelse return loginFail(a, error.InvalidState);
    const f = login.finish(fed, a, issuer.key, name, code, state, binding, req.now_s) catch |e| return loginFail(a, e);
    const id = f.id;
    var duration: i64 = 3600;
    if (id.expires_s) |exp| duration = std.math.clamp(exp - req.now_s, iam.sts.limits.min_duration_s, iam.sts.limits.max_duration_s);
    const issued_ms = std.time.milliTimestamp();
    const creds = issuer.issue(a, .{
        .parent = id.subject,
        .duration_s = duration,
        .federated_policies = id.policies,
        .tenant = id.tenant,
        .provider = .openid,
        .issued_ms = issued_ms,
    }, req.now_s, std.crypto.random) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => fail(a, .bad_request, "InvalidParameterValue", "The identity is not usable for a session."),
    };
    iam.sessions.record(env.store, .{
        .access_key = &creds.access_key,
        .parent = id.subject,
        .provider = "openid",
        .idp_config = id.provider,
        .issued_ms = issued_ms,
        .expires_s = creds.expires_s,
    }, req.now_s) catch {};
    const tb = try a.create([24]u8);
    const exp = core.time.iso8601(@as(i128, creds.expires_s) * std.time.ns_per_s, tb);
    const clear = try std.fmt.allocPrint(a, "{s}=; Path={s}/v3/oidc; Max-Age=0; HttpOnly; SameSite=Lax", .{ cookie_name, env.prefix });
    if (f.redirect_after.len > 0) {
        var w: std.Io.Writer.Allocating = .init(a);
        const fields = [_]struct { []const u8, []const u8 }{
            .{ "#accessKey=", &creds.access_key },
            .{ "&secretKey=", &creds.secret_key },
            .{ "&sessionToken=", creds.session_token },
            .{ "&expiration=", exp },
        };
        w.writer.writeAll(f.redirect_after) catch return error.OutOfMemory;
        for (fields) |kv| {
            w.writer.writeAll(kv[0]) catch return error.OutOfMemory;
            login.formEscape(&w.writer, kv[1]) catch return error.OutOfMemory;
        }
        return .{ .status = .found, .location = w.written(), .set_cookie = clear };
    }
    const body = try std.json.Stringify.valueAlloc(a, .{
        .accessKey = &creds.access_key,
        .secretKey = &creds.secret_key,
        .sessionToken = creds.session_token,
        .expiration = exp,
        .subject = id.subject,
        .provider = id.provider,
    }, .{});
    return .{ .body = body, .set_cookie = clear };
}

/// Value of cookie `name` in a Cookie header.
pub fn cookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, header, ';');
    while (it.next()) |raw| {
        const kv = std.mem.trim(u8, raw, " ");
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
    }
    return null;
}

test "cookie parsing" {
    try std.testing.expectEqualStrings("abc", cookieValue("a=1; zkfsm_oidc=abc; b=2", cookie_name).?);
    try std.testing.expect(cookieValue("a=1", cookie_name) == null);
}
