//! Per-version internal headers set after the write (object ACLs, checksums).
const std = @import("std");
const core = @import("../core/root.zig");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const versioning = @import("versioning.zig");

const Svc = service.ObjectService;
const Error = service.Error;

/// Sets (or with `value` null removes) one internal header of a version; null `version` is current.
pub fn setInternalHeader(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, name: []const u8, value: ?[]const u8) Error!core.VersionId {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const X = struct { a: std.mem.Allocator, name: []const u8, value: ?[]const u8 };
    return versioning.mutate(svc, bucket, key, version, X{ .a = arena.allocator(), .name = name, .value = value }, struct {
        fn f(x: X, _: versioning.BucketConfig, rec: *metadata.ObjectRecord) Error!void {
            rec.internal_meta = try withHeader(x.a, rec.internal_meta, x.name, x.value);
        }
    }.f);
}

/// Re-encodes an internal header list with `name` replaced or removed.
pub fn withHeader(a: std.mem.Allocator, encoded: []const u8, name: []const u8, value: ?[]const u8) Error![]const u8 {
    const hs = metadata.headers.decode(a, encoded) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    var out: std.ArrayList(metadata.headers.Header) = .empty;
    for (hs) |h| if (!std.mem.eql(u8, h.name, name)) try out.append(a, h);
    if (value) |v| try out.append(a, .{ .name = name, .value = v });
    return metadata.headers.encode(a, out.items, .internal) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MetadataTooLarge => error.MetadataTooLarge,
        error.InvalidMetadata => error.InvalidMetadata,
    };
}

test "internal header replace and remove" {
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
    try svc.createBucket("ometa");
    var body: std.Io.Reader = .fixed("x");
    _ = try svc.put("ometa", "k", &body, .{ .internal = &.{.{ .name = "x-zkfsm-internal-keep", .value = "1" }} });
    _ = try setInternalHeader(&svc, "ometa", "k", null, "x-zkfsm-internal-obj-acl", "a|b");
    _ = try setInternalHeader(&svc, "ometa", "k", null, "x-zkfsm-internal-obj-acl", "c");
    const h = try svc.head(arena.allocator(), "ometa", "k");
    try std.testing.expectEqual(@as(usize, 2), h.internal.len);
    try std.testing.expectEqualStrings("c", h.internal[1].value);
    _ = try setInternalHeader(&svc, "ometa", "k", null, "x-zkfsm-internal-obj-acl", null);
    try std.testing.expectEqual(@as(usize, 1), (try svc.head(arena.allocator(), "ometa", "k")).internal.len);
}
