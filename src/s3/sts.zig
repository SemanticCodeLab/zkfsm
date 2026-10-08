//! STS on `POST /` (form body or query): AssumeRole for signed callers, and the
//! federated actions (web identity, client grants, LDAP, client certificate)
//! that turn an external identity into temporary credentials with mapped policies.
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const handler = @import("handler.zig");
const sigv4 = @import("sigv4.zig");
const authz = @import("authz.zig");
const router = @import("router.zig");
const xml = @import("xml.zig");
const metrics = @import("../metrics/root.zig");

const Ctx = handler.Ctx;
const ConnError = handler.ConnError;
const Header = std.http.Header;

pub const max_body = 16 * 1024;
const ns = "https://sts.amazonaws.com/doc/2011-06-15/";

fn isForm(c: *const Ctx) bool {
    return c.method == .POST and std.mem.eql(u8, std.mem.sliceTo(c.target, '?'), "/") and
        std.ascii.startsWithIgnoreCase(c.content_type, "application/x-www-form-urlencoded");
}

/// Reads a form body to `/` before authentication: STS clients sign the body hash
/// without sending it in a header, so the verifier gets it as a synthetic header.
pub fn prepare(c: *Ctx, in: *sigv4.Input) ConnError!void {
    if (!isForm(c)) return;
    const len = c.req.head.content_length orelse return;
    if (len > max_body) return;
    var buf: [4096]u8 = undefined;
    const r = try c.req.readerExpectContinue(&buf);
    const body = r.readAlloc(c.arena, @intCast(len)) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ReadFailed,
    };
    var digest: [32]u8 = undefined;
    core.sigv4.Sha256.hash(body, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (in.header("x-amz-content-sha256")) |declared| {
        // A mismatched declared hash leaves the body unset; the request then fails normally.
        if (!std.mem.eql(u8, declared, &hex)) return;
    } else {
        const hs = try c.arena.alloc(Header, in.headers.len + 1);
        @memcpy(hs[0..in.headers.len], in.headers);
        hs[in.headers.len] = .{ .name = "x-amz-content-sha256", .value = try c.arena.dupe(u8, &hex) };
        in.headers = hs;
    }
    c.body = body;
}

/// Handles the request when it is an STS call; false leaves it to S3 dispatch.
pub fn route(c: *Ctx, env: authz.Env, now_s: i64) ConnError!bool {
    const body = c.body orelse queryForm(c) orelse return false;
    const action = try formParam(c.arena, body, "Action") orelse return false;
    const issuer = env.auth.sts orelse {
        try fail(c, .not_implemented, "NotImplemented", "STS requires authenticated mode.");
        return true;
    };
    const kind = std.meta.stringToEnum(Action, action) orelse {
        try fail(c, .bad_request, "InvalidAction", "Unsupported STS action.");
        return true;
    };
    var duration: ?i64 = null;
    if (try formParam(c.arena, body, "DurationSeconds")) |d| {
        duration = std.fmt.parseInt(i64, d, 10) catch {
            try fail(c, .bad_request, "InvalidParameterValue", "DurationSeconds must be an integer.");
            return true;
        };
    }
    const pol = try formParam(c.arena, body, "Policy");
    const session_policy = if (pol) |p| (if (p.len == 0) null else p) else null;
    const issued_ms = std.time.milliTimestamp();
    var req: iam.sts.Request = .{ .parent = "", .duration_s = duration orelse 3600, .session_policy = session_policy, .issued_ms = issued_ms };
    req.token_type = try formParam(c.arena, body, "TokenRevokeType") orelse "";
    var extra: [3]Field = undefined;
    var idp_config: []const u8 = "";
    var n_extra: usize = 0;
    switch (kind) {
        .AssumeRole => {
            if (c.auth.anonymous or c.auth.principal.len == 0) {
                try fail(c, .forbidden, "AccessDenied", "AssumeRole requires a signed request.");
                return true;
            }
            // Temporary credentials cannot assume further roles.
            if (!std.mem.eql(u8, c.auth.access_key, c.auth.principal)) {
                try fail(c, .forbidden, "AccessDenied", "Temporary credentials cannot call AssumeRole.");
                return true;
            }
            req.parent = c.auth.principal;
        },
        .AssumeRoleWithWebIdentity, .AssumeRoleWithClientGrants => {
            const fed = env.auth.federation orelse return notConfigured(c);
            const param = if (kind == .AssumeRoleWithWebIdentity) "WebIdentityToken" else "Token";
            const token = try formParam(c.arena, body, param) orelse {
                try fail(c, .bad_request, "MissingParameter", "The identity token is required.");
                return true;
            };
            const role_arn = try formParam(c.arena, body, "RoleArn");
            const id = fed.webIdentity(c.arena, token, if (role_arn) |r| (if (r.len == 0) null else r) else null, now_s) catch |e| {
                try webIdentityFail(c, e);
                return true;
            };
            req.parent = id.subject;
            req.provider = .openid;
            idp_config = id.provider;
            req.federated_policies = id.policies;
            req.tenant = id.tenant;
            if (duration == null) if (id.expires_s) |exp| {
                req.duration_s = std.math.clamp(exp - now_s, iam.sts.limits.min_duration_s, iam.sts.limits.max_duration_s);
            };
            extra[0] = .{ "SubjectFromWebIdentityToken", id.subject };
            extra[1] = .{ "Audience", id.audience };
            extra[2] = .{ "Provider", id.issuer };
            n_extra = 3;
        },
        .AssumeRoleWithLDAPIdentity => {
            const fed = env.auth.federation orelse return notConfigured(c);
            const user = try formParam(c.arena, body, "LDAPUsername") orelse "";
            const pass = try formParam(c.arena, body, "LDAPPassword") orelse "";
            const id = fed.ldapIdentity(c.arena, user, pass) catch |e| {
                try ldapFail(c, e);
                return true;
            };
            req.parent = id.user_dn;
            req.provider = .ldap;
            req.federated_policies = id.policies;
            req.tenant = id.tenant;
        },
        .AssumeRoleWithCertificate => {
            const id = env.client_cert orelse {
                try fail(c, .forbidden, "AccessDenied", "A verified TLS client certificate is required.");
                return true;
            };
            const st = env.auth.iam orelse return notConfigured(c);
            if (!st.policyExists(id.common_name)) {
                try fail(c, .forbidden, "AccessDenied", "No policy matches the certificate subject.");
                return true;
            }
            req.parent = id.common_name;
            req.provider = .tls;
            req.federated_policies = id.common_name;
            if (duration == null) req.duration_s = std.math.clamp(id.not_after_s - now_s, iam.sts.limits.min_duration_s, 3600);
        },
    }
    var creds = issuer.issue(c.arena, req, now_s, std.crypto.random) catch |e| {
        switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidDuration => try fail(c, .bad_request, "InvalidParameterValue", "DurationSeconds must be between 900 and 43200."),
            error.SessionPolicyTooLarge => try fail(c, .bad_request, "PackedPolicyTooLarge", "Session policy is too large."),
            error.InvalidSessionPolicy => try fail(c, .bad_request, "MalformedPolicyDocument", "Session policy is invalid."),
            error.InvalidTokenType => try fail(c, .bad_request, "InvalidParameterValue", "TokenRevokeType is too long."),
            error.InvalidParent, error.InvalidRoles, error.InvalidTenant => try fail(c, .bad_request, "InvalidParameterValue", "Caller identity is not usable for a session."),
        }
        return true;
    };
    // Listing only; revocation works from the token's own claims if this fails.
    if (env.auth.iam) |st| iam.sessions.record(st, .{
        .access_key = &creds.access_key,
        .parent = req.parent,
        .provider = @tagName(req.provider),
        .idp_config = idp_config,
        .token_type = req.token_type,
        .issued_ms = issued_ms,
        .expires_s = creds.expires_s,
    }, now_s) catch {};
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var tb: [24]u8 = undefined;
    const exp = core.time.iso8601(@as(i128, creds.expires_s) * std.time.ns_per_s, &tb);
    writeResponse(w, @tagName(kind), &creds, exp, &c.request_id, extra[0..n_extra]) catch return error.OutOfMemory;
    try respond(c, .ok, a.written());
    return true;
}

const Action = enum {
    AssumeRole,
    AssumeRoleWithWebIdentity,
    AssumeRoleWithClientGrants,
    AssumeRoleWithLDAPIdentity,
    AssumeRoleWithCertificate,
};

const Field = struct { []const u8, []const u8 };

/// `POST /?Action=...` with the parameters in the query (no form body).
fn queryForm(c: *const Ctx) ?[]const u8 {
    if (c.method != .POST) return null;
    const q = std.mem.indexOfScalar(u8, c.target, '?') orelse return null;
    if (!std.mem.eql(u8, c.target[0..q], "/")) return null;
    const query = c.target[q + 1 ..];
    return if (std.mem.indexOf(u8, query, "Action=") != null) query else null;
}

fn notConfigured(c: *Ctx) ConnError!bool {
    try fail(c, .bad_request, "InvalidParameterValue", "No identity provider is configured for this action.");
    return true;
}

fn webIdentityFail(c: *Ctx, e: iam.federation.Error) ConnError!void {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoProvider => fail(c, .bad_request, "InvalidParameterValue", "No matching OpenID provider is configured."),
        error.ProviderUnavailable => fail(c, .bad_request, "IDPCommunicationError", "The identity provider could not be reached."),
        error.InvalidToken => fail(c, .bad_request, "InvalidIdentityToken", "The web identity token is not valid."),
        error.ExpiredToken => fail(c, .bad_request, "ExpiredTokenException", "The web identity token has expired."),
        error.NoPolicy => fail(c, .forbidden, "AccessDenied", "The token grants no known policy."),
        error.InvalidTenant => fail(c, .forbidden, "AccessDenied", "The token names no active tenant."),
    };
}

fn ldapFail(c: *Ctx, e: iam.federation.LdapError) ConnError!void {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NotConfigured => fail(c, .bad_request, "InvalidParameterValue", "LDAP is not configured."),
        error.InvalidCredentials => fail(c, .forbidden, "AccessDenied", "Invalid LDAP credentials."),
        error.DirectoryUnavailable => fail(c, .service_unavailable, "ServiceUnavailable", "The LDAP directory could not be reached."),
        error.NoPolicy => fail(c, .forbidden, "AccessDenied", "No policy is mapped to this LDAP identity."),
        error.InvalidTenant => fail(c, .forbidden, "AccessDenied", "The configured tenant is not active."),
    };
}

fn writeResponse(w: *std.Io.Writer, action: []const u8, creds: *const iam.sts.Credentials, exp: []const u8, request_id: []const u8, extra: []const Field) std.Io.Writer.Error!void {
    try w.print(xml.declaration ++ "<{s}Response xmlns=\"" ++ ns ++ "\"><{s}Result>", .{ action, action });
    try w.writeAll("<AssumedRoleUser><Arn></Arn><AssumeRoleId></AssumeRoleId></AssumedRoleUser><Credentials>");
    try xml.elem(w, "AccessKeyId", &creds.access_key);
    try xml.elem(w, "SecretAccessKey", &creds.secret_key);
    try xml.elem(w, "SessionToken", creds.session_token);
    try xml.elem(w, "Expiration", exp);
    try w.writeAll("</Credentials>");
    for (extra) |f| try xml.elem(w, f[0], f[1]);
    try w.print("</{s}Result><ResponseMetadata>", .{action});
    try xml.elem(w, "RequestId", request_id);
    try w.print("</ResponseMetadata></{s}Response>", .{action});
}

fn formParam(a: std.mem.Allocator, body: []const u8, name: []const u8) error{OutOfMemory}!?[]const u8 {
    return router.queryParam(a, body, name) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUri => null,
    };
}

fn respond(c: *Ctx, status: std.http.Status, body: []const u8) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    try c.req.respond(body, .{ .status = status, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    } });
}

fn fail(c: *Ctx, status: std.http.Status, code: []const u8, message: []const u8) ConnError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    writeError(w, code, message, &c.request_id) catch return error.OutOfMemory;
    try respond(c, status, a.written());
}

fn writeError(w: *std.Io.Writer, code: []const u8, message: []const u8, request_id: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(xml.declaration ++ "<ErrorResponse xmlns=\"" ++ ns ++ "\"><Error><Type>Sender</Type>");
    try xml.elem(w, "Code", code);
    try xml.elem(w, "Message", message);
    try w.writeAll("</Error>");
    try xml.elem(w, "RequestId", request_id);
    try w.writeAll("</ErrorResponse>");
}

test "AssumeRole response and form parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body = "Action=AssumeRole&Version=2011-06-15&DurationSeconds=900&Policy=%7B%22Version%22%3A%222012-10-17%22%7D&RoleSessionName=s";
    try std.testing.expectEqualStrings("AssumeRole", (try formParam(a, body, "Action")).?);
    try std.testing.expectEqualStrings("{\"Version\":\"2012-10-17\"}", (try formParam(a, body, "Policy")).?);
    try std.testing.expect(try formParam(a, body, "RoleArn") == null);

    const issuer: iam.sts.Issuer = .{ .key = @splat(4) };
    var prng = std.Random.DefaultPrng.init(1);
    var creds = try issuer.issue(a, .{ .parent = "alice", .duration_s = 900 }, 0, prng.random());
    var out: std.Io.Writer.Allocating = .init(a);
    try writeResponse(&out.writer, "AssumeRole", &creds, "1970-01-01T00:15:00.000Z", "RID", &.{});
    const x = out.written();
    try std.testing.expect(std.mem.indexOf(u8, x, "<AccessKeyId>ASIA") != null);
    try std.testing.expect(std.mem.indexOf(u8, x, "<Expiration>1970-01-01T00:15:00.000Z</Expiration>") != null);
    const tok = try std.fmt.allocPrint(a, "<SessionToken>{s}</SessionToken>", .{creds.session_token});
    try std.testing.expect(std.mem.indexOf(u8, x, tok) != null);
    try std.testing.expect(std.mem.startsWith(u8, x[std.mem.indexOf(u8, x, "<AssumeRoleResponse").?..], "<AssumeRoleResponse xmlns="));

    var fed: std.Io.Writer.Allocating = .init(a);
    try writeResponse(&fed.writer, "AssumeRoleWithWebIdentity", &creds, "x", "RID", &.{.{ "SubjectFromWebIdentityToken", "sub<1>" }});
    const f = fed.written();
    try std.testing.expect(std.mem.indexOf(u8, f, "<AssumeRoleWithWebIdentityResult>") != null);
    try std.testing.expect(std.mem.indexOf(u8, f, "<SubjectFromWebIdentityToken>sub&lt;1&gt;</SubjectFromWebIdentityToken></AssumeRoleWithWebIdentityResult>") != null);
    try std.testing.expect(std.mem.endsWith(u8, f, "</AssumeRoleWithWebIdentityResponse>"));
}
