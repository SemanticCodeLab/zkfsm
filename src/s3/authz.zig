//! Per-request IAM authorization: maps an S3 request to an action and resource
//! ARN, builds the condition context, and asks the IAM store for a decision.
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const router = @import("router.zig");
const sigv4 = @import("sigv4.zig");

const Op = iam.actions.Op;
const Method = std.http.Method;

/// What the listener knows about a connection, passed to every request.
pub const Env = struct {
    auth: sigv4.Config = .{},
    peer: ?std.net.Address = null,
    extensions: []const @import("extension.zig").Extension = &.{},
    routing: router.Routing = .{},
    /// Verified TLS client certificate of the connection (mutual TLS only).
    client_cert: ?ClientCert = null,
};

pub const ClientCert = struct { common_name: []const u8, not_after_s: i64 };

/// Action for requests no S3 operation covers; only root (or `*` grants) pass.
const unmapped_action = "s3:ZkfsmUnmappedRequest";

fn has(query: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const k = pair[0 .. std.mem.indexOfScalar(u8, pair, '=') orelse pair.len];
        if (std.mem.eql(u8, k, name)) return true;
    }
    return false;
}

fn pick(m: Method, get: ?Op, put: ?Op, del: ?Op) ?Op {
    return switch (m) {
        .GET, .HEAD => get,
        .PUT => put,
        .DELETE => del,
        else => null,
    };
}

/// The S3 operation a request performs, or null when none applies.
pub fn classify(m: Method, bucket: []const u8, key: []const u8, query: []const u8, copy_source: bool) ?Op {
    const q = query;
    if (bucket.len == 0) return if (m == .GET) .list_buckets else null;
    if (key.len == 0) {
        if (has(q, "delete")) return if (m == .POST) .delete_objects else null;
        if (has(q, "uploads")) return if (m == .GET) .list_multipart_uploads else null;
        if (has(q, "versioning")) return pick(m, .get_bucket_versioning, .put_bucket_versioning, null);
        if (has(q, "object-lock")) return pick(m, .get_object_lock_configuration, .put_object_lock_configuration, null);
        if (has(q, "versions")) return pick(m, .list_object_versions, null, null);
        if (has(q, "location")) return pick(m, .get_bucket_location, null, null);
        if (has(q, "policyStatus")) return pick(m, .get_bucket_policy_status, null, null);
        if (has(q, "policy")) return pick(m, .get_bucket_policy, .put_bucket_policy, .delete_bucket_policy);
        if (has(q, "tagging")) return pick(m, .get_bucket_tagging, .put_bucket_tagging, .delete_bucket_tagging);
        if (has(q, "acl")) return pick(m, .get_bucket_acl, .put_bucket_acl, null);
        if (has(q, "cors")) return pick(m, .get_bucket_cors, .put_bucket_cors, .delete_bucket_cors);
        if (has(q, "lifecycle")) return pick(m, .get_bucket_lifecycle, .put_bucket_lifecycle, .delete_bucket_lifecycle);
        if (has(q, "encryption")) return pick(m, .get_bucket_encryption, .put_bucket_encryption, .delete_bucket_encryption);
        if (has(q, "notification")) return pick(m, .get_bucket_notification, .put_bucket_notification, null);
        if (has(q, "replication")) return pick(m, .get_bucket_replication, .put_bucket_replication, .delete_bucket_replication);
        return switch (m) {
            .GET => if (has(q, "list-type")) .list_objects_v2 else .list_objects,
            .HEAD => .head_bucket,
            .PUT => .create_bucket,
            .DELETE => .delete_bucket,
            else => null,
        };
    }
    const versioned = has(q, "versionId");
    if (has(q, "uploadId")) return switch (m) {
        .PUT => if (copy_source) .upload_part_copy else .upload_part,
        .POST => .complete_multipart_upload,
        .DELETE => .abort_multipart_upload,
        .GET => .list_parts,
        else => null,
    };
    if (has(q, "uploads")) return if (m == .POST) .create_multipart_upload else null;
    if (has(q, "tagging"))
        return pick(m, if (versioned) .get_object_version_tagging else .get_object_tagging, .put_object_tagging, .delete_object_tagging);
    if (has(q, "retention")) return pick(m, .get_object_retention, .put_object_retention, null);
    if (has(q, "legal-hold")) return pick(m, .get_object_legal_hold, .put_object_legal_hold, null);
    if (has(q, "acl")) return pick(m, .get_object_acl, .put_object_acl, null);
    if (has(q, "attributes")) return pick(m, .get_object_attributes, null, null);
    if (has(q, "restore")) return if (m == .POST) .restore_object else null;
    if (has(q, "select")) return if (m == .POST) .select_object_content else null;
    return switch (m) {
        .GET => if (versioned) .get_object_version else .get_object,
        .HEAD => if (versioned) .get_object_version else .head_object,
        .PUT => if (copy_source) .copy_object else .put_object,
        .DELETE => if (versioned) .delete_object_version else .delete_object,
        else => null,
    };
}

pub const Request = struct {
    method: Method,
    bucket: []const u8,
    key: []const u8,
    query: []const u8,
    copy_source: bool = false,
    /// Policy JSON of the target bucket: explicit denies win, then any allow (identity or bucket).
    bucket_policy: ?[]const u8 = null,
};

/// True when the verified caller may perform the request. Anonymous mode allows all.
/// Unsigned requests on an authenticated server are allowed only by a bucket policy.
pub fn allowed(arena: std.mem.Allocator, env: Env, auth: sigv4.Auth, r: Request, now_s: i64) error{OutOfMemory}!bool {
    const store = env.auth.iam orelse return true;
    var session: ?iam.Policy = null;
    if (auth.session_policy) |doc| session = iam.policy.parse(arena, doc) catch return false;
    const who: iam.Identity = .{ .access_key = auth.principal, .session_policy = if (session) |*p| p else null, .federated_policies = auth.federated_policies };
    // Stored policies were validated on PUT; one that no longer parses grants nothing.
    var bucket_policy: ?iam.Policy = null;
    if (r.bucket_policy) |doc| bucket_policy = iam.policy.parse(arena, doc) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => null,
    };

    var arn_buf: [2048]u8 = undefined;
    const op = classify(r.method, r.bucket, r.key, r.query, r.copy_source);
    const action = if (op) |o| iam.actions.mapping(o).action else unmapped_action;
    const arn = if (op) |o|
        iam.actions.resourceArn(&arn_buf, o, r.bucket, r.key) catch return false
    else
        "arn:aws:s3:::*";
    const ctx: iam.Context = .{
        .entries = try entries(arena, env, r, now_s),
        .now_s = now_s,
        .resource_policy = if (bucket_policy) |*p| p else null,
    };
    if (auth.anonymous) {
        const nobody: iam.Principal = .{};
        return iam.authorize(&nobody, action, arn, &ctx).allowed();
    }
    return store.authorize(who, action, arn, &ctx).allowed();
}

fn one(arena: std.mem.Allocator, v: []const u8) error{OutOfMemory}![]const []const u8 {
    const out = try arena.alloc([]const u8, 1);
    out[0] = v;
    return out;
}

fn entries(arena: std.mem.Allocator, env: Env, r: Request, now_s: i64) error{OutOfMemory}![]const iam.context.Entry {
    var list: std.ArrayList(iam.context.Entry) = .empty;
    if (env.peer) |addr| {
        const s = try std.fmt.allocPrint(arena, "{f}", .{addr});
        // Strip the port (and IPv6 brackets) that Address formatting appends.
        const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse s.len;
        const host = std.mem.trim(u8, s[0..colon], "[]");
        try list.append(arena, .{ .key = "aws:SourceIp", .values = try one(arena, host) });
    }
    var tb: [24]u8 = undefined;
    const iso = core.time.iso8601(@as(i128, now_s) * std.time.ns_per_s, &tb);
    const cur = try std.fmt.allocPrint(arena, "{s}Z", .{iso[0..19]});
    try list.append(arena, .{ .key = "aws:CurrentTime", .values = try one(arena, cur) });
    try list.append(arena, .{ .key = "aws:EpochTime", .values = try one(arena, try std.fmt.allocPrint(arena, "{d}", .{now_s})) });
    try list.append(arena, .{ .key = "aws:SecureTransport", .values = try one(arena, "false") });
    for ([_][]const u8{ "prefix", "delimiter", "max-keys" }) |name| {
        const v = router.queryParam(arena, r.query, name) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUri => null,
        } orelse continue;
        try list.append(arena, .{ .key = try std.fmt.allocPrint(arena, "s3:{s}", .{name}), .values = try one(arena, v) });
    }
    return list.items;
}

test "classify S3 requests" {
    try std.testing.expectEqual(Op.list_buckets, classify(.GET, "", "", "", false).?);
    try std.testing.expect(classify(.POST, "", "", "", false) == null);
    try std.testing.expectEqual(Op.list_objects_v2, classify(.GET, "b", "", "list-type=2&prefix=a", false).?);
    try std.testing.expectEqual(Op.create_bucket, classify(.PUT, "b", "", "", false).?);
    try std.testing.expectEqual(Op.put_bucket_versioning, classify(.PUT, "b", "", "versioning", false).?);
    try std.testing.expectEqual(Op.delete_objects, classify(.POST, "b", "", "delete", false).?);
    try std.testing.expectEqual(Op.get_object, classify(.GET, "b", "k", "", false).?);
    try std.testing.expectEqual(Op.head_object, classify(.HEAD, "b", "k", "", false).?);
    try std.testing.expectEqual(Op.get_object_version, classify(.GET, "b", "k", "versionId=x", false).?);
    try std.testing.expectEqual(Op.put_object_tagging, classify(.PUT, "b", "k", "tagging", false).?);
    try std.testing.expectEqual(Op.upload_part, classify(.PUT, "b", "k", "partNumber=1&uploadId=u", false).?);
    try std.testing.expectEqual(Op.create_multipart_upload, classify(.POST, "b", "k", "uploads", false).?);
    try std.testing.expectEqual(Op.copy_object, classify(.PUT, "b", "k", "", true).?);
    try std.testing.expectEqual(Op.delete_object_version, classify(.DELETE, "b", "k", "versionId=v", false).?);
}

test "readonly service account can read but not write" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var mem: iam.store.MemoryPersistence = .{ .gpa = gpa };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(gpa, mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
    defer st.deinit();
    try st.createUser("reader", "readersecret");
    try st.attachPolicy(.user, "reader", "readonly");
    try st.createServiceAccount(.{ .access_key = "svcreader", .secret = "svcsecret1", .parent = "reader" });

    const env: Env = .{ .auth = .{ .iam = &st }, .peer = try std.net.Address.parseIp("10.1.2.3", 5555) };
    const sa: sigv4.Auth = .{ .principal = "svcreader" };
    const get: Request = .{ .method = .GET, .bucket = "b", .key = "k", .query = "" };
    const put: Request = .{ .method = .PUT, .bucket = "b", .key = "k", .query = "" };
    try std.testing.expect(try allowed(a, env, sa, get, 1000));
    try std.testing.expect(!try allowed(a, env, sa, put, 1000));
    try std.testing.expect(try allowed(a, env, .{ .principal = "rootkey" }, put, 1000));
    try std.testing.expect(!try allowed(a, env, .{ .principal = "nobody" }, get, 1000));
    try std.testing.expect(try allowed(a, .{}, .{}, put, 1000));

    // Conditions see the request context.
    try st.putPolicy("fromlan",
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b",
        \\"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"StringEquals":{"s3:prefix":"pub/"}}}]}
    );
    try st.attachPolicy(.user, "reader", "fromlan");
    const list_pub: Request = .{ .method = .GET, .bucket = "b", .key = "", .query = "list-type=2&prefix=pub%2F" };
    const list_all: Request = .{ .method = .GET, .bucket = "b", .key = "", .query = "list-type=2" };
    try std.testing.expect(try allowed(a, env, sa, list_pub, 1000));
    try std.testing.expect(!try allowed(a, env, sa, list_all, 1000));
    const wan: Env = .{ .auth = env.auth, .peer = try std.net.Address.parseIp("192.0.2.1", 1) };
    try std.testing.expect(!try allowed(a, wan, sa, list_pub, 1000));
}

test "bucket policy: public read, anonymous access, and explicit deny" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var mem: iam.store.MemoryPersistence = .{ .gpa = gpa };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(gpa, mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
    defer st.deinit();
    try st.createUser("writer", "writersecret");
    try st.attachPolicy(.user, "writer", "readwrite");
    const env: Env = .{ .auth = .{ .iam = &st } };
    const anon: sigv4.Auth = .{ .anonymous = true };
    const writer: sigv4.Auth = .{ .principal = "writer" };
    const policy =
        \\{"Version":"2012-10-17","Statement":[
        \\{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"},
        \\{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::pub/keep/*"}]}
    ;
    const get: Request = .{ .method = .GET, .bucket = "pub", .key = "k", .query = "", .bucket_policy = policy };
    try std.testing.expect(try allowed(a, env, anon, get, 1000));
    var no_policy = get;
    no_policy.bucket_policy = null;
    try std.testing.expect(!try allowed(a, env, anon, no_policy, 1000));
    const put: Request = .{ .method = .PUT, .bucket = "pub", .key = "k", .query = "", .bucket_policy = policy };
    try std.testing.expect(!try allowed(a, env, anon, put, 1000));
    try std.testing.expect(!try allowed(a, env, anon, .{ .method = .GET, .bucket = "pub", .key = "", .query = "", .bucket_policy = policy }, 1000));
    // Identity allow is overridden by an explicit bucket-policy deny.
    const del_keep: Request = .{ .method = .DELETE, .bucket = "pub", .key = "keep/x", .query = "", .bucket_policy = policy };
    const del_other: Request = .{ .method = .DELETE, .bucket = "pub", .key = "tmp/x", .query = "", .bucket_policy = policy };
    try std.testing.expect(!try allowed(a, env, writer, del_keep, 1000));
    try std.testing.expect(try allowed(a, env, writer, del_other, 1000));
    try std.testing.expect(try allowed(a, env, .{ .principal = "rootkey" }, del_keep, 1000));
    // A bucket policy can grant an identity without identity policies.
    try st.createUser("plain", "plainsecret");
    const grant =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/plain"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::pub/*"}]}
    ;
    var put_plain = put;
    put_plain.bucket_policy = grant;
    try std.testing.expect(try allowed(a, env, .{ .principal = "plain" }, put_plain, 1000));
    try std.testing.expect(!try allowed(a, env, .{ .principal = "plain" }, put, 1000));
}
