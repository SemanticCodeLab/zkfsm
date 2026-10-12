//! OpenID login served by the storage server itself (`<admin>/v3/oidc/...`), when
//! it has those routes: provider detection, and pass-through of authorize and
//! callback under the same paths so the provider redirects back to the console.
const std = @import("std");
const root = @import("root.zig");
const sign = @import("sign.zig");
const upstream = @import("upstream.zig");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Request = std.http.Server.Request;
const Header = std.http.Header;
const Console = root.Console;

const max_doc = 64 * 1024;
const route_suffix = "/v3/oidc/";

/// The part after `<admin>/v3/oidc/` for a login route, else null.
pub fn match(c: *const Console, path: []const u8) ?[]const u8 {
    const p = c.cfg.admin_prefix;
    if (!std.mem.startsWith(u8, path, p)) return null;
    const rest = path[p.len..];
    if (!std.mem.startsWith(u8, rest, route_suffix)) return null;
    const op = rest[route_suffix.len..];
    return if (std.mem.startsWith(u8, op, "authorize/") or std.mem.startsWith(u8, op, "callback/")) op else null;
}

pub fn has(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

pub fn authorizeHref(c: *const Console, a: Allocator, name: []const u8) error{OutOfMemory}![]const u8 {
    var out: Writer.Allocating = .init(a);
    out.writer.print("{s}{s}authorize/", .{ c.cfg.admin_prefix, route_suffix }) catch return error.OutOfMemory;
    sign.encodePathTo(&out.writer, name) catch return error.OutOfMemory;
    return out.written();
}

/// Providers the server offers a login flow for; empty when it has no such routes.
pub fn providers(c: *Console, a: Allocator) error{OutOfMemory}![]const []const u8 {
    const target = try std.fmt.allocPrint(a, "{s}{s}providers", .{ c.cfg.admin_prefix, route_suffix });
    const res = upstream.send(a, c.cfg.upstream, .GET, target, &.{}, "") catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => &.{},
    };
    defer res.close();
    if (res.status() != 200) return &.{};
    const body = res.readAll(a, max_doc) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => &.{},
    };
    return parseProviders(a, body);
}

fn parseProviders(a: Allocator, body: []const u8) []const []const u8 {
    const Doc = struct { providers: []const []const u8 = &.{} };
    const doc = std.json.parseFromSliceLeaky(Doc, a, body, .{ .ignore_unknown_fields = true }) catch return &.{};
    return doc.providers;
}

fn headerOf(req: *Request, name: []const u8) ?[]const u8 {
    var it = req.iterateHeaders();
    while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

fn fail(req: *Request, a: Allocator, msg: []const u8) root.ServeError!void {
    var loc: Writer.Allocating = .init(a);
    loc.writer.writeAll("/?error=") catch return error.OutOfMemory;
    sign.encodePathTo(&loc.writer, msg) catch return error.OutOfMemory;
    return root.respond(req, .see_other, "text/plain", "", &.{.{ .name = "location", .value = loc.written() }});
}

/// Error text of a server reply (`{"Message":..}`), or a generic one.
fn messageOf(a: Allocator, body: []const u8) []const u8 {
    const Doc = struct { Message: []const u8 = "" };
    const doc = std.json.parseFromSliceLeaky(Doc, a, body, .{ .ignore_unknown_fields = true }) catch return "Login failed.";
    return if (doc.Message.len > 0) doc.Message else "Login failed.";
}

/// GET `<admin>/v3/oidc/authorize/<name>` and `.../callback/<name>?code=..&state=..`.
pub fn serve(c: *Console, req: *Request, a: Allocator, op: []const u8, now: i64) root.ServeError!void {
    try root.drain(req);
    if (req.head.method != .GET) return root.respond(req, .method_not_allowed, "text/plain", "method not allowed\n", &.{});
    const is_callback = std.mem.startsWith(u8, op, "callback/");
    const t = req.head.target;
    var target: []const u8 = t;
    // The callback must answer with credentials, not a redirect carrying them.
    if (!is_callback) target = t[0 .. std.mem.indexOfScalar(u8, t, '?') orelse t.len];
    var hs: std.ArrayList(Header) = .empty;
    if (headerOf(req, "cookie")) |v| try hs.append(a, .{ .name = "cookie", .value = try a.dupe(u8, v) });
    const host = if (headerOf(req, "host")) |h| try a.dupe(u8, h) else null;
    const res = upstream.sendAs(a, c.cfg.upstream, host, .GET, target, hs.items, "") catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(req, a, "The storage server did not answer."),
    };
    defer res.close();
    const body = res.readAll(a, max_doc) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(req, a, "The storage server did not answer."),
    };
    const status = res.status();
    if (!is_callback) {
        const loc = res.header("location") orelse return fail(req, a, messageOf(a, body));
        if (status != 302 and status != 303) return fail(req, a, messageOf(a, body));
        var out: std.ArrayList(Header) = .empty;
        try out.append(a, .{ .name = "location", .value = loc });
        if (res.header("set-cookie")) |sc| try out.append(a, .{ .name = "set-cookie", .value = sc });
        return root.respond(req, .see_other, "text/plain", "", out.items);
    }
    if (status != 200) return fail(req, a, messageOf(a, body));
    const Creds = struct {
        accessKey: []const u8 = "",
        secretKey: []const u8 = "",
        sessionToken: []const u8 = "",
        expiration: []const u8 = "",
        subject: []const u8 = "",
        provider: []const u8 = "",
    };
    const cr = std.json.parseFromSliceLeaky(Creds, a, body, .{ .ignore_unknown_fields = true }) catch return fail(req, a, "Malformed login response.");
    if (cr.accessKey.len == 0 or cr.secretKey.len == 0) return fail(req, a, "Malformed login response.");
    const expires = root.parseIsoTime(cr.expiration) orelse now + c.ttl();
    return c.startSession(req, a, .{
        .user = if (cr.subject.len > 0) cr.subject else cr.accessKey,
        .access_key = cr.accessKey,
        .secret_key = cr.secretKey,
        .session_token = cr.sessionToken,
        .provider = try std.fmt.allocPrint(a, "openid:{s}", .{if (cr.provider.len > 0) cr.provider else op["callback/".len..]}),
        .expires_s = @min(expires, now + c.ttl()),
    }, now, "/");
}

test "route matching and provider list" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var c: Console = .init(std.testing.allocator, .{ .upstream = .{ .host = "127.0.0.1", .port = 1 } }, undefined);
    defer c.deinit();
    try std.testing.expectEqualStrings("authorize/corp", match(&c, "/minio/admin/v3/oidc/authorize/corp").?);
    try std.testing.expectEqualStrings("callback/corp", match(&c, "/minio/admin/v3/oidc/callback/corp").?);
    try std.testing.expect(match(&c, "/minio/admin/v3/oidc/providers") == null);
    try std.testing.expect(match(&c, "/minio/admin/v3/info") == null);
    try std.testing.expectEqualStrings("/minio/admin/v3/oidc/authorize/a%20b", try authorizeHref(&c, a, "a b"));
    const names = parseProviders(a, "{\"providers\":[\"corp\",\"dev\"]}");
    try std.testing.expect(has(names, "dev") and !has(names, "x"));
    try std.testing.expectEqual(@as(usize, 0), parseProviders(a, "<Error/>").len);
}
