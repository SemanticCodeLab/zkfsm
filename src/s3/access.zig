//! Second-chance authorization after IAM and bucket policies deny: ACL grants, the
//! bucket owner's rights, public access block settings, and the 404-versus-403
//! answer for missing buckets and keys.
const std = @import("std");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const handler = @import("handler.zig");
const authz = @import("authz.zig");
const acl = @import("acl.zig");
const extras = @import("bucket_extras.zig");
const policy = @import("policy.zig");
const sigv4 = @import("sigv4.zig");
const router = @import("router.zig");
const errors = @import("errors.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const Op = iam.actions.Op;
const Code = errors.Code;
const DispatchError = handler.DispatchError;

pub const Verdict = union(enum) { allow, deny: Code };

fn permFor(op: Op) ?acl.Perm {
    return switch (op) {
        .list_objects, .list_objects_v2, .list_object_versions, .list_multipart_uploads, .head_bucket, .list_parts => .READ,
        .get_object, .head_object, .get_object_version => .READ,
        .put_object, .delete_object, .delete_object_version, .create_multipart_upload, .upload_part, .complete_multipart_upload, .abort_multipart_upload, .copy_object, .upload_part_copy, .delete_objects => .WRITE,
        .get_bucket_acl, .get_object_acl => .READ_ACP,
        .put_bucket_acl, .put_object_acl => .WRITE_ACP,
        else => null,
    };
}

fn objectScoped(op: Op) bool {
    return switch (op) {
        .get_object, .head_object, .get_object_version, .get_object_acl, .put_object_acl => true,
        else => false,
    };
}

/// Ignores group grants when the bucket's public access block says so.
fn grants(a: acl.Acl, who: acl.Caller, want: acl.Perm, ignore_public: bool) bool {
    if (!ignore_public) return acl.allows(a, who, want);
    var filtered: [64]acl.Grant = undefined;
    var n: usize = 0;
    for (a.grants) |g| {
        if (g.kind == .group or n == filtered.len) continue;
        filtered[n] = g;
        n += 1;
    }
    return acl.allows(.{ .owner = a.owner, .grants = filtered[0..n] }, who, want);
}

/// Decides a request IAM denied. `ar` is the request as authorized.
pub fn fallback(c: *Ctx, ar: authz.Request, now_s: i64) DispatchError!Verdict {
    const denied: Verdict = .{ .deny = .AccessDenied };
    const op = authz.classify(ar.method, ar.bucket, ar.key, ar.query, ar.copy_source) orelse return denied;
    if (ar.bucket.len == 0 or op == .create_bucket) return denied;
    c.svc.headBucket(ar.bucket) catch |e| return switch (e) {
        error.NoSuchBucket => .{ .deny = .NoSuchBucket },
        else => e,
    };
    const who = acl.callerOf(c.env.auth, c.auth);
    const pab = try extras.publicAccessOf(c.svc, c.arena, ar.bucket);
    const bacl = try acl.bucketAcl(c.svc, c.arena, ar.bucket);
    // The bucket's owner controls the bucket (identities without IAM grants own buckets via ACLs).
    if (!who.anonymous and std.mem.eql(u8, who.id, bacl.owner) and !objectScoped(op)) return .allow;
    const perm = permFor(op) orelse return denied;
    if (!objectScoped(op)) return if (grants(bacl, who, perm, pab.ignore_public_acls)) .allow else denied;
    const version = s3v.versionParam(c) catch null;
    const info = object.versioning.headVersion(c.svc, c.arena, ar.bucket, ar.key, version) catch |e| switch (e) {
        error.NoSuchKey, error.NoSuchVersion => {
            if (!try mayList(c, ar, who, bacl, pab, now_s)) return denied;
            return .{ .deny = if (e == error.NoSuchKey) .NoSuchKey else .NoSuchVersion };
        },
        error.InvalidVersionId => return .{ .deny = .InvalidArgument },
        else => return e,
    };
    if (info.delete_marker) {
        if (!try mayList(c, ar, who, bacl, pab, now_s)) return denied;
        return .{ .deny = .NoSuchKey };
    }
    const oacl = try acl.objectAcl(c.arena, info);
    if (!who.anonymous and std.mem.eql(u8, who.id, oacl.owner)) return .allow;
    return if (grants(oacl, who, perm, pab.ignore_public_acls)) .allow else denied;
}

/// ListBucket on the key's prefix (policy, with `s3:prefix` = key) or bucket READ.
fn mayList(c: *Ctx, ar: authz.Request, who: acl.Caller, bacl: acl.Acl, pab: extras.PublicAccess, now_s: i64) DispatchError!bool {
    if (grants(bacl, who, .READ, pab.ignore_public_acls)) return true;
    var q: std.Io.Writer.Allocating = .init(c.arena);
    q.writer.writeAll("list-type=2&prefix=") catch return error.OutOfMemory;
    @import("../core/root.zig").sigv4.uriEncode(&q.writer, ar.key, true) catch return error.OutOfMemory;
    const list: authz.Request = .{ .method = .GET, .bucket = ar.bucket, .key = "", .query = q.written(), .bucket_policy = ar.bucket_policy };
    return authz.allowed(c.arena, c.env, c.auth, list, now_s);
}

fn one(arena: std.mem.Allocator, v: []const u8) error{OutOfMemory}![]const []const u8 {
    const out = try arena.alloc([]const u8, 1);
    out[0] = v;
    return out;
}

/// Request-specific policy condition keys: selected headers, request and existing object tags.
pub fn conditionKeys(c: *Ctx, ar: authz.Request) DispatchError![]const iam.context.Entry {
    var list: std.ArrayList(iam.context.Entry) = .empty;
    const names = [_]struct { []const u8, []const u8 }{
        .{ "referer", "aws:Referer" },
        .{ "user-agent", "aws:UserAgent" },
        .{ "x-amz-acl", "s3:x-amz-acl" },
        .{ "x-amz-grant-read", "s3:x-amz-grant-read" },
        .{ "x-amz-grant-write", "s3:x-amz-grant-write" },
        .{ "x-amz-grant-read-acp", "s3:x-amz-grant-read-acp" },
        .{ "x-amz-grant-write-acp", "s3:x-amz-grant-write-acp" },
        .{ "x-amz-grant-full-control", "s3:x-amz-grant-full-control" },
        .{ "x-amz-copy-source", "s3:x-amz-copy-source" },
        .{ "x-amz-metadata-directive", "s3:x-amz-metadata-directive" },
        .{ "x-amz-server-side-encryption", "s3:x-amz-server-side-encryption" },
        .{ "x-amz-storage-class", "s3:x-amz-storage-class" },
    };
    for (c.headers) |h| {
        for (names) |n| if (std.ascii.eqlIgnoreCase(h.name, n[0])) {
            try list.append(c.arena, .{ .key = n[1], .values = try one(c.arena, std.mem.trim(u8, h.value, " ")) });
        };
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-tagging")) {
            const tags = s3v.parseTagQuery(c.arena, h.value) catch continue;
            const keys = try c.arena.alloc([]const u8, tags.len);
            for (tags, keys) |t, *k| {
                k.* = t.key;
                try list.append(c.arena, .{ .key = try std.fmt.allocPrint(c.arena, "s3:RequestObjectTag/{s}", .{t.key}), .values = try one(c.arena, t.value) });
            }
            try list.append(c.arena, .{ .key = "s3:RequestObjectTagKeys", .values = keys });
        }
    }
    if (try handler.param(c, "versionId")) |v| try list.append(c.arena, .{ .key = "s3:VersionId", .values = try one(c.arena, v) });
    // Existing tags cost a metadata read: only when the bucket policy refers to them.
    if (ar.key.len > 0) if (ar.bucket_policy) |doc| if (std.mem.indexOf(u8, doc, "ExistingObjectTag") != null) {
        const version = s3v.versionParam(c) catch null;
        if (object.versioning.headVersion(c.svc, c.arena, ar.bucket, ar.key, version)) |info| {
            for (try object.decodeTags(c.arena, info.tags)) |t|
                try list.append(c.arena, .{ .key = try std.fmt.allocPrint(c.arena, "s3:ExistingObjectTag/{s}", .{t.key}), .values = try one(c.arena, t.value) });
        } else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        }
    };
    return list.items;
}

/// RestrictPublicBuckets: a public bucket policy grants nothing to anonymous callers.
pub fn restrictPolicy(c: *Ctx, ar: *authz.Request) DispatchError!void {
    const doc = ar.bucket_policy orelse return;
    if (!c.auth.anonymous) return;
    const pab = try extras.publicAccessOf(c.svc, c.arena, ar.bucket);
    if (pab.restrict_public_buckets and try policy.isPublic(c.arena, doc)) ar.bucket_policy = null;
}

/// Whether an anonymous GET of `key` in the request's bucket would be allowed.
pub fn anonymousMayRead(c: *Ctx, key: []const u8) DispatchError!bool {
    if (c.env.auth.iam == null) return true;
    const saved = c.auth;
    defer c.auth = saved;
    c.auth = .{ .anonymous = true };
    var ar: authz.Request = .{ .method = .GET, .bucket = c.route.bucket, .key = key, .query = "" };
    if (object.tenancy.access(c.svc, c.arena, c.route.bucket)) |acc| ar.bucket_policy = acc.policy else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
    try restrictPolicy(c, &ar);
    const now_s = std.time.timestamp();
    if (try authz.allowed(c.arena, c.env, c.auth, ar, now_s)) return true;
    const saved_route = c.route;
    defer c.route = saved_route;
    c.route.key = key;
    c.route.query = "";
    return (try fallback(c, ar, now_s)) == .allow;
}

/// Read access to a copy source: IAM and policies, else the source object's ACL.
pub fn copySourceAllowed(c: *Ctx, src: object.copy.Source) DispatchError!bool {
    const now_s = std.time.timestamp();
    if (try @import("tenancy.zig").copySourceAllowed(c.svc, c.arena, c.env, c.auth, src, now_s)) return true;
    if (c.env.auth.iam == null) return true;
    const who = acl.callerOf(c.env.auth, c.auth);
    const info = object.versioning.headVersion(c.svc, c.arena, src.bucket, src.key, src.version) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => false,
    };
    if (info.delete_marker) return false;
    const pab = try extras.publicAccessOf(c.svc, c.arena, src.bucket);
    const oacl = try acl.objectAcl(c.arena, info);
    if (!who.anonymous and std.mem.eql(u8, who.id, oacl.owner)) return true;
    return grants(oacl, who, .READ, pab.ignore_public_acls);
}
