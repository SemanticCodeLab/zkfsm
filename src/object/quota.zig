//! Hard bucket quotas. The limit lives in the bucket config (shared by every node);
//! usage comes from the key index, which every node keeps in step with the records.
const std = @import("std");
const core = @import("../core/root.zig");
const service = @import("service.zig");
const versioning = @import("versioning.zig");
const index = @import("index.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const BucketConfig = versioning.BucketConfig;

pub const Usage = index.Usage;

pub const Info = struct { quota: u64, usage: Usage };

/// Sets the hard quota in bytes; 0 removes it.
pub fn set(svc: *Svc, bucket: []const u8, bytes: u64) Error!void {
    try versioning.updateConfig(svc, bucket, bytes, struct {
        fn f(b: u64, c: *BucketConfig) Error!void {
            c.quota = b;
        }
    }.f);
}

pub fn info(svc: *Svc, bucket: []const u8) Error!Info {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const cfg = try versioning.getConfig(svc, arena.allocator(), bucket);
    return .{ .quota = cfg.quota, .usage = try usage(svc, bucket) };
}

pub fn usage(svc: *Svc, bucket: []const u8) Error!Usage {
    const bid = try svc.bucketId(bucket);
    if (svc.index.stale) try svc.rebuildIndex();
    return svc.index.usage(bid);
}

/// Fails when storing `adding` more bytes (after `freeing` is released) would pass the quota.
pub fn check(svc: *Svc, bid: core.BucketId, cfg: BucketConfig, adding: u64, freeing: u64) Error!void {
    if (cfg.quota == 0) return;
    const used = svc.index.usage(bid).bytes -| freeing;
    if (used +| adding > cfg.quota) return error.QuotaExceeded;
}

/// Early rejection before a body of known size is streamed in; commit re-checks.
/// `key` names an object the write replaces (unversioned buckets free its bytes).
pub fn precheck(svc: *Svc, bucket: []const u8, key: ?[]const u8, size: u64) Error!void {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const cfg = try versioning.getConfig(svc, arena.allocator(), bucket);
    if (cfg.quota == 0) return;
    const used = (try usage(svc, bucket)).bytes;
    var freed: u64 = 0;
    if (key) |k| if (cfg.versioning == .unset) if (svc.index.current(try svc.bucketId(bucket), k)) |v| {
        if (!v.delete_marker) freed = v.size;
    };
    if ((used -| freed) +| size > cfg.quota) return error.QuotaExceeded;
}

test "quota enforced on put, overwrite, and multipart" {
    const backend = @import("../backend/root.zig");
    const multipart = @import("multipart.zig");
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try Svc.init(gpa, lb.backend());
    defer svc.deinit();
    try svc.createBucket("qb1");
    try set(&svc, "qb1", 10);
    try std.testing.expectEqual(@as(u64, 10), (try info(&svc, "qb1")).quota);

    var r1: std.Io.Reader = .fixed("123456");
    _ = try svc.put("qb1", "a", &r1, .{ .content_length = 6 });
    var r2: std.Io.Reader = .fixed("12345");
    try std.testing.expectError(error.QuotaExceeded, svc.put("qb1", "b", &r2, .{ .content_length = 5 }));
    // Without a declared length the commit-time check still applies.
    var r3: std.Io.Reader = .fixed("12345");
    try std.testing.expectError(error.QuotaExceeded, svc.put("qb1", "b", &r3, .{}));
    // Overwriting in an unversioned bucket frees the old bytes first.
    var r4: std.Io.Reader = .fixed("123456789");
    _ = try svc.put("qb1", "a", &r4, .{ .content_length = 9 });
    const u = try usage(&svc, "qb1");
    try std.testing.expectEqual(@as(u64, 9), u.bytes);
    try std.testing.expectEqual(@as(u64, 1), u.objects);

    const id = try multipart.create(&svc, "qb1", "mp", .{});
    var p: std.Io.Reader = .fixed("abc");
    const etag = try multipart.uploadPart(&svc, "qb1", "mp", id, 1, &p, null);
    try std.testing.expectError(error.QuotaExceeded, multipart.complete(&svc, "qb1", "mp", id, &.{.{ .number = 1, .md5 = etag.md5 }}));
    var p2: std.Io.Reader = .fixed("abc");
    try std.testing.expectError(error.QuotaExceeded, multipart.uploadPart(&svc, "qb1", "mp", id, 2, &p2, 3));

    try set(&svc, "qb1", 0);
    var r5: std.Io.Reader = .fixed("12345");
    _ = try svc.put("qb1", "b", &r5, .{});
    _ = try versioning.deleteObject(&svc, "qb1", "b", .{});
    try std.testing.expectEqual(@as(u64, 9), (try usage(&svc, "qb1")).bytes);
}
