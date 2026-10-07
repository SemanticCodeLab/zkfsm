//! Get/Put/DeleteBucketPolicy and GetBucketPolicyStatus. Documents are validated
//! with the IAM policy parser; authz.zig evaluates them per request.
const std = @import("std");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;

/// Handles `?policy` and `?policyStatus` on a bucket; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len != 0) return false;
    if ((try handler.param(c, "policyStatus")) != null) {
        if (c.method != .GET) return failed(c, .MethodNotAllowed);
        const doc = try object.policy.get(c.svc, c.arena, c.route.bucket);
        // Public through the policy or through a public bucket ACL.
        const public = (if (doc) |d| try isPublic(c.arena, d) else false) or (try @import("acl.zig").bucketAcl(c.svc, c.arena, c.route.bucket)).isPublic();
        var a: std.Io.Writer.Allocating = .init(c.arena);
        try xml.openRoot(&a.writer, "PolicyStatus");
        try xml.elemBool(&a.writer, "IsPublic", public);
        try xml.close(&a.writer, "PolicyStatus");
        try handler.respondXml(c, .ok, a.written());
        return true;
    }
    if ((try handler.param(c, "policy")) == null) return false;
    switch (c.method) {
        .GET => {
            const doc = try object.policy.get(c.svc, c.arena, c.route.bucket) orelse return failed(c, .NoSuchBucketPolicy);
            try c.req.respond(doc, .{ .extra_headers = &.{
                .{ .name = "content-type", .value = "application/json" },
                .{ .name = "x-amz-request-id", .value = &c.request_id },
            } });
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, object.policy.max_policy_bytes + 1) orelse return true;
            validate(c.arena, body, c.route.bucket) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.MalformedPolicy => failed(c, .MalformedPolicy),
            };
            try c.svc.headBucket(c.route.bucket);
            if (try isPublic(c.arena, body) and (try @import("bucket_extras.zig").publicAccess(c)).block_public_policy) return failed(c, .AccessDenied);
            try object.policy.set(c.svc, c.route.bucket, body);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        .DELETE => {
            try object.policy.set(c.svc, c.route.bucket, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => return failed(c, .MethodNotAllowed),
    }
    return true;
}

fn failed(c: *Ctx, code: @import("errors.zig").Code) DispatchError!bool {
    try handler.fail(c, code);
    return true;
}

/// A bucket policy must parse, name a Principal in every statement, and only
/// cover this bucket and its objects.
pub fn validate(arena: std.mem.Allocator, doc: []const u8, bucket: []const u8) error{ OutOfMemory, MalformedPolicy }!void {
    if (doc.len > object.policy.max_policy_bytes) return error.MalformedPolicy;
    const p = iam.policy.parse(arena, doc) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedPolicy,
    };
    for (p.statements) |s| {
        if (s.principal == null) return error.MalformedPolicy;
        // NotPrincipal only makes sense with Deny.
        if (s.not_principal and s.effect == .allow) return error.MalformedPolicy;
        const rs = s.resources orelse return error.MalformedPolicy;
        for (rs) |r| if (!coversOnly(r, bucket)) return error.MalformedPolicy;
    }
}

/// The resource names this bucket or its objects, possibly through wildcards.
fn coversOnly(resource: []const u8, bucket: []const u8) bool {
    const base = "arn:aws:s3:::";
    if (!std.mem.startsWith(u8, resource, base)) return false;
    const rest = resource[base.len..];
    const wild = std.mem.indexOfAny(u8, rest, "*?") orelse {
        if (!std.mem.startsWith(u8, rest, bucket)) return false;
        return rest.len == bucket.len or rest[bucket.len] == '/';
    };
    // Up to the first wildcard the pattern must agree with `bucket/`.
    const fixed = rest[0..wild];
    if (fixed.len <= bucket.len) return std.mem.startsWith(u8, bucket, fixed);
    return std.mem.startsWith(u8, fixed, bucket) and fixed[bucket.len] == '/';
}

/// Public when an unconditional Allow names every principal.
pub fn isPublic(arena: std.mem.Allocator, doc: []const u8) error{OutOfMemory}!bool {
    const p = iam.policy.parse(arena, doc) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => false,
    };
    for (p.statements) |s| {
        if (s.effect != .allow or s.not_principal or s.conditions.len > 0) continue;
        const pr = s.principal orelse continue;
        if (pr.any) return true;
        for (pr.values) |v| if (v.kind == .account and std.mem.eql(u8, v.value, "*")) return true;
    }
    return false;
}

test "bucket policy validation and public status" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const public =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}
    ;
    try validate(a, public, "pub");
    try std.testing.expect(try isPublic(a, public));
    try std.testing.expectError(error.MalformedPolicy, validate(a, public, "other"));
    try std.testing.expectError(error.MalformedPolicy, validate(a, public, "pu"));
    try std.testing.expect(coversOnly("arn:aws:s3:::*", "pub") and coversOnly("arn:aws:s3:::p*/x", "pub"));
    try std.testing.expect(!coversOnly("arn:aws:s3:::other*", "pub") and !coversOnly("arn:aws:s3:::pubx*", "pub"));
    try std.testing.expectError(error.MalformedPolicy, validate(a, "not json", "pub"));
    const no_principal =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}
    ;
    try std.testing.expectError(error.MalformedPolicy, validate(a, no_principal, "pub"));
    const conditional =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pub",
        \\"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}
    ;
    try validate(a, conditional, "pub");
    try std.testing.expect(!try isPublic(a, conditional));
}
