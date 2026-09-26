//! Bucket policy storage. The document is validated by the protocol layer
//! (which owns the IAM parser); here it is only stored and returned.
const std = @import("std");
const service = @import("service.zig");
const versioning = @import("versioning.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const BucketConfig = versioning.BucketConfig;

pub const max_policy_bytes = 20 * 1024;

/// The bucket's policy JSON in `arena`, or null when none is set.
pub fn get(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error!?[]const u8 {
    const cfg = try versioning.getConfig(svc, arena, bucket);
    return if (cfg.policy.len > 0) cfg.policy else null;
}

/// `doc` null deletes the policy.
pub fn set(svc: *Svc, bucket: []const u8, doc: ?[]const u8) Error!void {
    const d = doc orelse "";
    if (d.len > max_policy_bytes or (doc != null and d.len == 0)) return error.InvalidRequest;
    try versioning.updateConfig(svc, bucket, d, struct {
        fn f(x: []const u8, c: *BucketConfig) Error!void {
            c.policy = x;
        }
    }.f);
}

test "bucket policy set, get, delete" {
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
    try svc.createBucket("pol");
    try std.testing.expect((try get(&svc, a, "pol")) == null);
    try set(&svc, "pol", "{\"x\":1}");
    try versioning.setBucketTags(&svc, "pol", &.{.{ .key = "k", .value = "v" }});
    try std.testing.expectEqualStrings("{\"x\":1}", (try get(&svc, a, "pol")).?);
    try set(&svc, "pol", null);
    try std.testing.expect((try get(&svc, a, "pol")) == null);
    try std.testing.expectEqual(@as(usize, 1), (try versioning.getBucketTags(&svc, a, "pol")).len);
    try std.testing.expectError(error.NoSuchBucket, get(&svc, a, "nope"));
    try std.testing.expectError(error.InvalidRequest, set(&svc, "pol", "x" ** (max_policy_bytes + 1)));
}
