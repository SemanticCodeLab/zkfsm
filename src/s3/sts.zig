//! STS AssumeRole on `POST /` (form body): issues temporary credentials for the
//! signing user, optionally narrowed by a session policy.
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
    const body = c.body orelse return false;
    const action = try formParam(c.arena, body, "Action") orelse return false;
    if (!std.mem.eql(u8, action, "AssumeRole")) {
        try fail(c, .bad_request, "InvalidAction", "Only AssumeRole is supported.");
        return true;
    }
    const issuer = env.auth.sts orelse {
        try fail(c, .not_implemented, "NotImplemented", "STS requires authenticated mode.");
        return true;
    };
    if (c.auth.anonymous or c.auth.principal.len == 0) {
        try fail(c, .forbidden, "AccessDenied", "AssumeRole requires a signed request.");
        return true;
    }
    // Temporary credentials cannot assume further roles.
    if (!std.mem.eql(u8, c.auth.access_key, c.auth.principal) or c.auth.principal.len == 0) {
        try fail(c, .forbidden, "AccessDenied", "Temporary credentials cannot call AssumeRole.");
        return true;
    }
    var duration: i64 = 3600;
    if (try formParam(c.arena, body, "DurationSeconds")) |d| {
        duration = std.fmt.parseInt(i64, d, 10) catch {
            try fail(c, .bad_request, "InvalidParameterValue", "DurationSeconds must be an integer.");
            return true;
        };
    }
    const pol = try formParam(c.arena, body, "Policy");
    var creds = issuer.issue(c.arena, .{
        .parent = c.auth.principal,
        .duration_s = duration,
        .session_policy = if (pol) |p| (if (p.len == 0) null else p) else null,
    }, now_s, std.crypto.random) catch |e| {
        switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidDuration => try fail(c, .bad_request, "InvalidParameterValue", "DurationSeconds must be between 900 and 43200."),
            error.SessionPolicyTooLarge => try fail(c, .bad_request, "PackedPolicyTooLarge", "Session policy is too large."),
            error.InvalidSessionPolicy => try fail(c, .bad_request, "MalformedPolicyDocument", "Session policy is invalid."),
            error.InvalidParent => try fail(c, .bad_request, "InvalidParameterValue", "Caller identity is not usable for a session."),
        }
        return true;
    };
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var tb: [24]u8 = undefined;
    const exp = core.time.iso8601(@as(i128, creds.expires_s) * std.time.ns_per_s, &tb);
    writeResponse(w, &creds, exp, &c.request_id) catch return error.OutOfMemory;
    try respond(c, .ok, a.written());
    return true;
}

fn writeResponse(w: *std.Io.Writer, creds: *const iam.sts.Credentials, exp: []const u8, request_id: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(xml.declaration ++ "<AssumeRoleResponse xmlns=\"" ++ ns ++ "\"><AssumeRoleResult>");
    try w.writeAll("<AssumedRoleUser><Arn></Arn><AssumeRoleId></AssumeRoleId></AssumedRoleUser><Credentials>");
    try xml.elem(w, "AccessKeyId", &creds.access_key);
    try xml.elem(w, "SecretAccessKey", &creds.secret_key);
    try xml.elem(w, "SessionToken", creds.session_token);
    try xml.elem(w, "Expiration", exp);
    try w.writeAll("</Credentials></AssumeRoleResult><ResponseMetadata>");
    try xml.elem(w, "RequestId", request_id);
    try w.writeAll("</ResponseMetadata></AssumeRoleResponse>");
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
    try writeResponse(&out.writer, &creds, "1970-01-01T00:15:00.000Z", "RID");
    const x = out.written();
    try std.testing.expect(std.mem.indexOf(u8, x, "<AccessKeyId>ASIA") != null);
    try std.testing.expect(std.mem.indexOf(u8, x, "<Expiration>1970-01-01T00:15:00.000Z</Expiration>") != null);
    const tok = try std.fmt.allocPrint(a, "<SessionToken>{s}</SessionToken>", .{creds.session_token});
    try std.testing.expect(std.mem.indexOf(u8, x, tok) != null);
}
