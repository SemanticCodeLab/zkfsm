//! Tenant isolation on the S3 path. A tenant's identities see and reach only the
//! tenant's buckets; global identities only global buckets; root reaches all.
//! Anonymous access is still decided by bucket policies alone.
const std = @import("std");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const sigv4 = @import("sigv4.zig");
const authz = @import("authz.zig");

pub const NameBuf = [iam.store.limits.max_name]u8;

/// Tenant of the authenticated caller, or null for global identities and anonymous calls.
pub fn callerTenant(cfg: sigv4.Config, auth: sigv4.Auth, buf: *NameBuf) ?[]const u8 {
    if (auth.anonymous) return null;
    if (auth.federated_policies != null) return if (auth.tenant.len > 0) auth.tenant else null;
    const st = cfg.iam orelse return null;
    return st.tenantOf(auth.principal, buf);
}

pub fn isRoot(cfg: sigv4.Config, auth: sigv4.Auth) bool {
    const st = cfg.iam orelse return false;
    if (auth.anonymous or auth.federated_policies != null) return false;
    const v = st.view();
    defer v.release();
    if (v.isRoot(auth.principal)) return true;
    // Service accounts of root act with root's reach.
    const sa = v.serviceAccount(auth.principal) orelse return false;
    return v.isRoot(sa.parent);
}

/// False when the caller's tenant was removed or disabled.
pub fn tenantActive(cfg: sigv4.Config, tenant: []const u8) bool {
    const st = cfg.iam orelse return true;
    return iam.federation.tenantUsable(st, tenant);
}

/// Whether a signed caller in `caller` (null = global) may touch a bucket owned by `owner`.
pub fn mayReach(cfg: sigv4.Config, auth: sigv4.Auth, caller: ?[]const u8, owner: []const u8) bool {
    if (auth.anonymous or cfg.iam == null or isRoot(cfg, auth)) return true;
    return std.mem.eql(u8, caller orelse "", owner);
}

/// The tenant new buckets of this caller belong to ("" = global).
pub fn ownerFor(cfg: sigv4.Config, auth: sigv4.Auth, buf: *NameBuf) []const u8 {
    return callerTenant(cfg, auth, buf) orelse "";
}

/// Buckets the caller may list: all for root, else those of its tenant (or global ones).
pub fn visibleBuckets(svc: *object.ObjectService, arena: std.mem.Allocator, cfg: sigv4.Config, auth: sigv4.Auth) object.Error![]object.BucketInfo {
    if (cfg.iam == null or isRoot(cfg, auth)) return svc.listBuckets(arena);
    var buf: NameBuf = undefined;
    const t = callerTenant(cfg, auth, &buf) orelse "";
    return object.tenancy.listOwned(svc, arena, t);
}

/// Read access to a copy source: the tenant boundary plus s3:GetObject on it.
pub fn copySourceAllowed(svc: *object.ObjectService, arena: std.mem.Allocator, env: authz.Env, auth: sigv4.Auth, src: object.copy.Source, now_s: i64) error{OutOfMemory}!bool {
    if (env.auth.iam == null) return true;
    const acc = object.tenancy.access(svc, arena, src.bucket) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        // A missing source fails later with the precise error.
        else => return true,
    };
    var buf: NameBuf = undefined;
    if (!mayReach(env.auth, auth, callerTenant(env.auth, auth, &buf), acc.tenant)) return false;
    const query = if (src.version != null) "versionId=x" else "";
    return authz.allowed(arena, env, auth, .{ .method = .GET, .bucket = src.bucket, .key = src.key, .query = query, .bucket_policy = acc.policy }, now_s);
}

test "tenant boundary rules" {
    const gpa = std.testing.allocator;
    var mem: iam.store.MemoryPersistence = .{ .gpa = gpa };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(gpa, mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
    defer st.deinit();
    try st.createUser("alice", "alicesecret");
    const cfg: sigv4.Config = .{ .iam = &st };
    const root: sigv4.Auth = .{ .principal = "rootkey", .access_key = "rootkey" };
    const alice: sigv4.Auth = .{ .principal = "alice", .access_key = "alice" };
    const fed: sigv4.Auth = .{ .principal = "sub-1", .access_key = "ASIAX", .federated_policies = "readwrite", .tenant = "acme" };
    var buf: NameBuf = undefined;
    try std.testing.expect(isRoot(cfg, root));
    try std.testing.expect(!isRoot(cfg, alice));
    try std.testing.expect(callerTenant(cfg, alice, &buf) == null);
    try std.testing.expectEqualStrings("acme", callerTenant(cfg, fed, &buf).?);
    try std.testing.expect(mayReach(cfg, root, null, "acme"));
    try std.testing.expect(mayReach(cfg, alice, null, ""));
    try std.testing.expect(!mayReach(cfg, alice, null, "acme"));
    try std.testing.expect(mayReach(cfg, fed, "acme", "acme"));
    try std.testing.expect(!mayReach(cfg, fed, "acme", ""));
    try std.testing.expect(!tenantActive(cfg, "acme"));
}
