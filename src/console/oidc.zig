//! OpenID Connect authorization-code login: redirect to the provider, exchange the
//! code for an ID token, then trade it for temporary credentials via STS.
const std = @import("std");
const iam = @import("../iam/root.zig");
const root = @import("root.zig");
const session = @import("session.zig");
const sign = @import("sign.zig");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Request = std.http.Server.Request;
const Console = root.Console;

const max_doc = 256 * 1024;

pub const Discovery = struct {
    authorization_endpoint: []const u8 = "",
    token_endpoint: []const u8 = "",
};

fn provider(c: *Console, a: Allocator, name: []const u8) error{OutOfMemory}!?iam.idp.OpenId {
    const st = c.cfg.iam orelse return null;
    for (try iam.idp.effective(a, st, c.cfg.idp_env, .openid)) |e| {
        if (!std.mem.eql(u8, e.name, name)) continue;
        const p = iam.idp.OpenId.from(e.name, e.settings);
        return if (p.enabled and p.client_id.len > 0 and p.config_url.len > 0) p else null;
    }
    return null;
}

const FetchError = error{ OutOfMemory, FetchFailed };

fn fetch(a: Allocator, url: []const u8, method: std.http.Method, form: ?[]const u8) FetchError![]const u8 {
    var client: std.http.Client = .{ .allocator = a };
    defer client.deinit();
    var out: Writer.Allocating = .init(a);
    const res = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = form,
        .headers = .{ .content_type = if (form != null) .{ .override = "application/x-www-form-urlencoded" } else .default },
        .extra_headers = &.{.{ .name = "accept", .value = "application/json" }},
        .response_writer = &out.writer,
        .keep_alive = false,
    }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.FetchFailed,
    };
    if (res.status != .ok or out.written().len > max_doc) return error.FetchFailed;
    return out.written();
}

fn discover(a: Allocator, config_url: []const u8) FetchError!Discovery {
    const doc = try fetch(a, config_url, .GET, null);
    return std.json.parseFromSliceLeaky(Discovery, a, doc, .{ .ignore_unknown_fields = true }) catch error.FetchFailed;
}

fn fail(req: *Request, a: Allocator, msg: []const u8) root.ServeError!void {
    var loc: Writer.Allocating = .init(a);
    loc.writer.writeAll("/?error=") catch return error.OutOfMemory;
    sign.encodePathTo(&loc.writer, msg) catch return error.OutOfMemory;
    return root.respond(req, .see_other, "text/plain", "", &.{.{ .name = "location", .value = loc.written() }});
}

fn queryParams(a: Allocator, req: *Request) error{OutOfMemory}![]sign.Param {
    const t = req.head.target;
    return sign.parseQuery(a, if (std.mem.indexOfScalar(u8, t, '?')) |i| t[i + 1 ..] else "");
}

/// GET /api/v1/oidc/start?provider=NAME: 303 to the provider's authorization endpoint.
pub fn start(c: *Console, req: *Request, a: Allocator, now: i64) root.ServeError!void {
    try root.drain(req);
    const params = try queryParams(a, req);
    const name = root.paramOf(params, "provider") orelse iam.idp.default_name;
    const p = try provider(c, a, name) orelse return fail(req, a, "Unknown identity provider.");
    const d = discover(a, p.config_url) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FetchFailed => return fail(req, a, "The identity provider is unreachable."),
    };
    if (d.authorization_endpoint.len == 0) return fail(req, a, "The identity provider has no authorization endpoint.");
    const redirect = if (p.redirect_uri.len > 0) p.redirect_uri else try c.redirectUri(req, a);
    const state = session.Store.newId();
    c.sessions.putPending(&state, .{ .provider = p.name, .redirect_uri = redirect, .created_s = now }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManySessions => return fail(req, a, "Too many logins in progress."),
    };
    var loc: Writer.Allocating = .init(a);
    const w = &loc.writer;
    const sep: u8 = if (std.mem.indexOfScalar(u8, d.authorization_endpoint, '?') != null) '&' else '?';
    w.print("{s}{c}response_type=code&client_id=", .{ d.authorization_endpoint, sep }) catch return error.OutOfMemory;
    root.formEncodeTo(w, p.client_id) catch return error.OutOfMemory;
    w.writeAll("&redirect_uri=") catch return error.OutOfMemory;
    root.formEncodeTo(w, redirect) catch return error.OutOfMemory;
    w.writeAll("&scope=") catch return error.OutOfMemory;
    root.formEncodeTo(w, try scopes(a, p.scopes)) catch return error.OutOfMemory;
    w.print("&state={s}", .{&state}) catch return error.OutOfMemory;
    return root.respond(req, .see_other, "text/plain", "", &.{.{ .name = "location", .value = loc.written() }});
}

/// Space-separated scopes, always including `openid`.
fn scopes(a: Allocator, configured: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "openid");
    var it = std.mem.tokenizeAny(u8, configured, ", ");
    while (it.next()) |s| if (!std.mem.eql(u8, s, "openid")) {
        try out.append(a, ' ');
        try out.appendSlice(a, s);
    };
    return out.items;
}

/// GET /api/v1/oidc/callback?code=..&state=..: exchanges the code and starts a session.
pub fn callback(c: *Console, req: *Request, a: Allocator, now: i64) root.ServeError!void {
    try root.drain(req);
    const params = try queryParams(a, req);
    if (root.paramOf(params, "error")) |e| return fail(req, a, root.paramOf(params, "error_description") orelse e);
    const state = root.paramOf(params, "state") orelse return fail(req, a, "Missing login state.");
    const code = root.paramOf(params, "code") orelse return fail(req, a, "Missing authorization code.");
    const pending = try c.sessions.takePending(a, state, now) orelse return fail(req, a, "The login expired; try again.");
    const p = try provider(c, a, pending.provider) orelse return fail(req, a, "Unknown identity provider.");
    const d = discover(a, p.config_url) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FetchFailed => return fail(req, a, "The identity provider is unreachable."),
    };
    var form: Writer.Allocating = .init(a);
    const fw = &form.writer;
    fw.writeAll("grant_type=authorization_code&code=") catch return error.OutOfMemory;
    root.formEncodeTo(fw, code) catch return error.OutOfMemory;
    fw.writeAll("&redirect_uri=") catch return error.OutOfMemory;
    root.formEncodeTo(fw, pending.redirect_uri) catch return error.OutOfMemory;
    fw.writeAll("&client_id=") catch return error.OutOfMemory;
    root.formEncodeTo(fw, p.client_id) catch return error.OutOfMemory;
    if (p.client_secret.len > 0) {
        fw.writeAll("&client_secret=") catch return error.OutOfMemory;
        root.formEncodeTo(fw, p.client_secret) catch return error.OutOfMemory;
    }
    const tok_doc = fetch(a, d.token_endpoint, .POST, form.written()) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FetchFailed => return fail(req, a, "The identity provider rejected the login."),
    };
    const Tok = struct { id_token: []const u8 = "" };
    const tok = std.json.parseFromSliceLeaky(Tok, a, tok_doc, .{ .ignore_unknown_fields = true }) catch return fail(req, a, "Malformed token response.");
    if (tok.id_token.len == 0) return fail(req, a, "The identity provider returned no ID token.");

    var sts: Writer.Allocating = .init(a);
    const sw = &sts.writer;
    sw.writeAll("Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=") catch return error.OutOfMemory;
    root.formEncodeTo(sw, tok.id_token) catch return error.OutOfMemory;
    var rb: [160]u8 = undefined;
    const arn = p.roleArn(&rb);
    if (arn.len > 0) {
        sw.writeAll("&RoleArn=") catch return error.OutOfMemory;
        root.formEncodeTo(sw, arn) catch return error.OutOfMemory;
    }
    const got = c.assume(a, null, sts.written(), now) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Rejected => return fail(req, a, "The storage server rejected the identity token."),
        else => return fail(req, a, "The storage server did not answer."),
    };
    const user = if (got.subject.len > 0) got.subject else p.name;
    const prov = try std.fmt.allocPrint(a, "openid:{s}", .{p.name});
    return c.startSession(req, a, .{
        .user = user,
        .access_key = got.access_key,
        .secret_key = got.secret_key,
        .session_token = got.session_token,
        .provider = prov,
        .expires_s = @min(got.expires_s, now + c.ttl()),
    }, now, "/");
}

test "scopes always include openid" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("openid email groups", try scopes(arena.allocator(), "email,groups,openid"));
    try std.testing.expectEqualStrings("openid", try scopes(arena.allocator(), ""));
}
