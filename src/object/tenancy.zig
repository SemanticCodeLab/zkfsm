//! Bucket ownership by tenant. The owner is part of the bucket config, so every node
//! sees the same boundary; the protocol layer decides who may cross it.
const std = @import("std");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const versioning = @import("versioning.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const BucketConfig = versioning.BucketConfig;

pub const max_tenant_len = metadata.bucket_config.max_tenant_len;

/// What request authorization needs from the bucket config, read once.
pub const Access = struct {
    policy: ?[]const u8,
    tenant: []const u8,
};

/// Strings live in `arena`.
pub fn access(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error!Access {
    const cfg = try versioning.getConfig(svc, arena, bucket);
    return .{ .policy = if (cfg.policy.len > 0) cfg.policy else null, .tenant = cfg.tenant };
}

pub fn tenantOf(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error![]const u8 {
    return (try versioning.getConfig(svc, arena, bucket)).tenant;
}

/// Assigns the bucket to `tenant` ("" makes it global).
pub fn setTenant(svc: *Svc, bucket: []const u8, tenant: []const u8) Error!void {
    if (tenant.len > max_tenant_len) return error.InvalidRequest;
    try versioning.updateConfig(svc, bucket, tenant, struct {
        fn f(t: []const u8, c: *BucketConfig) Error!void {
            c.tenant = t;
        }
    }.f);
}

/// Creates a bucket owned by `tenant`; the bucket is removed again if the owner
/// cannot be recorded, so no unowned bucket is left behind.
pub fn createOwned(svc: *Svc, name: []const u8, tenant: []const u8) Error!void {
    if (tenant.len > max_tenant_len) return error.InvalidRequest;
    try svc.createBucket(name);
    if (tenant.len == 0) return;
    setTenant(svc, name, tenant) catch |e| {
        svc.deleteBucket(name) catch {};
        return e;
    };
}

/// Buckets owned by `tenant` ("" = global buckets); null lists all. Names in `arena`.
pub fn listOwned(svc: *Svc, arena: std.mem.Allocator, tenant: ?[]const u8) Error![]service.BucketInfo {
    const all = try svc.listBuckets(arena);
    const t = tenant orelse return all;
    var out: std.ArrayList(service.BucketInfo) = .empty;
    for (all) |b| {
        const owner = tenantOf(svc, arena, b.name) catch |e| switch (e) {
            error.NoSuchBucket => continue,
            else => return e,
        };
        if (std.mem.eql(u8, owner, t)) try out.append(arena, b);
    }
    return out.items;
}

test "bucket ownership" {
    const backend = @import("../backend/root.zig");
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try Svc.init(gpa, lb.backend());
    defer svc.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    try createOwned(&svc, "acme-data", "acme");
    try createOwned(&svc, "shared", "");
    try std.testing.expectError(error.BucketAlreadyExists, createOwned(&svc, "acme-data", "globex"));
    try std.testing.expectEqualStrings("acme", (try access(&svc, a, "acme-data")).tenant);
    try std.testing.expectEqual(@as(usize, 1), (try listOwned(&svc, a, "acme")).len);
    try std.testing.expectEqualStrings("shared", (try listOwned(&svc, a, ""))[0].name);
    try std.testing.expectEqual(@as(usize, 2), (try listOwned(&svc, a, null)).len);
    try setTenant(&svc, "shared", "acme");
    try std.testing.expectEqual(@as(usize, 2), (try listOwned(&svc, a, "acme")).len);
    try std.testing.expectError(error.InvalidRequest, createOwned(&svc, "x", "t" ** 65));
}
