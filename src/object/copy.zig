//! Server-side copy: streams an existing object into a new object.
const std = @import("std");
const service = @import("service.zig");
const blob = @import("blob.zig");
const versioning = @import("versioning.zig");
const core = @import("../core/root.zig");
const conditional = @import("conditional.zig");

const ObjectService = service.ObjectService;
const Error = service.Error;

pub const Source = struct {
    bucket: []const u8,
    key: []const u8,
    /// Null copies the current version.
    version: ?core.VersionId = null,
};

pub const CopyInput = struct {
    /// Destination fields; lock settings and conditions always come from here.
    put: service.PutInput = .{},
    /// Metadata directive REPLACE: take content type, user metadata, and system headers
    /// from `put` instead of the source. Internal headers and overrides always follow the blob.
    replace_metadata: bool = false,
    /// Tagging directive REPLACE: take `put.tags` instead of the source's.
    replace_tags: bool = false,
    /// x-amz-copy-source-if-*: evaluated against the source; any failure is PreconditionFailed.
    source_conditions: conditional.Conditions = .{},
};

/// Resolves a copy source to a readable (non-delete-marker) version.
pub fn resolveSource(svc: *ObjectService, arena: std.mem.Allocator, src: Source) Error!service.ObjectInfo {
    const info = try versioning.headVersion(svc, arena, src.bucket, src.key, src.version);
    if (info.delete_marker) return if (src.version != null) error.InvalidRequest else error.NoSuchKey;
    return info;
}

/// Copies `src` to `dst_bucket/dst_key`. Copying an object onto itself is allowed.
pub fn copyObject(svc: *ObjectService, src: Source, dst_bucket: []const u8, dst_key: []const u8, in: CopyInput) Error!service.ObjectInfo {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const info = try resolveSource(svc, arena.allocator(), src);
    var eb: [core.ETag.quoted_max]u8 = undefined;
    if (conditional.evalRead(in.source_conditions, info.etag.quoted(&eb), info.created_ns) != .proceed) return error.PreconditionFailed;
    const segs = [_]blob.Segment{.{ .blob = info.object_id, .offset = 0, .length = info.blob_size }};
    var buf: [64 * 1024]u8 = undefined;
    var br = blob.BlobReader.init(svc.store, &segs, &buf);
    var put_in = in.put;
    put_in.content_length = info.blob_size;
    put_in.internal = info.internal;
    put_in.logical_size = info.logical_size;
    put_in.etag_override = info.etag_override;
    if (!in.replace_metadata) {
        put_in.content_type = info.content_type;
        put_in.metadata = info.metadata;
        put_in.system = info.system;
    }
    if (!in.replace_tags) put_in.tags = info.tags;
    return svc.put(dst_bucket, dst_key, &br.reader, put_in) catch |e| switch (e) {
        // The source vanished mid-copy (overwritten or deleted).
        error.ReadFailed => if (br.err) |be| switch (be) {
            error.NotFound => error.NoSuchKey,
            else => service.mapBackend(be),
        } else error.ReadFailed,
        else => e,
    };
}

test "copy object keeps or replaces content type" {
    const backend = @import("../backend/root.zig");
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try ObjectService.init(gpa, lb.backend());
    defer svc.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    try svc.createBucket("src");
    try svc.createBucket("dst");
    var body: std.Io.Reader = .fixed("copy me");
    const orig = try svc.put("src", "k", &body, .{
        .content_type = "text/plain",
        .metadata = &.{.{ .name = "color", .value = "red" }},
        .internal = &.{.{ .name = "x-zkfsm-internal-k", .value = "i" }},
        .system = .{ .cache_control = "max-age=1" },
        .logical_size = 3,
    });

    const c1 = try copyObject(&svc, .{ .bucket = "src", .key = "k" }, "dst", "k2", .{});
    try std.testing.expectEqual(@as(u32, 0), c1.etag.parts);
    try std.testing.expectEqualSlices(u8, &orig.etag.md5, &c1.etag.md5);
    const h1 = try svc.head(a, "dst", "k2");
    try std.testing.expectEqualStrings("text/plain", h1.content_type);
    try std.testing.expectEqualStrings("red", h1.metadata[0].value);
    try std.testing.expectEqualStrings("max-age=1", h1.system.cache_control);
    try std.testing.expectEqual(@as(u64, 3), h1.size);
    try std.testing.expectEqual(@as(u64, 7), h1.blob_size);

    _ = try copyObject(&svc, .{ .bucket = "src", .key = "k" }, "src", "k", .{
        .put = .{ .content_type = "app/x", .metadata = &.{.{ .name = "color", .value = "blue" }} },
        .replace_metadata = true,
    });
    const h = try svc.head(a, "src", "k");
    try std.testing.expectEqualStrings("app/x", h.content_type);
    try std.testing.expectEqualStrings("blue", h.metadata[0].value);
    try std.testing.expectEqualStrings("", h.system.cache_control);
    try std.testing.expectEqualStrings("i", h.internal[0].value);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try svc.read(h, null, &out.writer);
    try std.testing.expectEqualStrings("copy me", out.written());

    try std.testing.expectError(error.NoSuchKey, copyObject(&svc, .{ .bucket = "src", .key = "nope" }, "dst", "x", .{}));
    try std.testing.expectError(error.PreconditionFailed, copyObject(&svc, .{ .bucket = "src", .key = "k" }, "dst", "x", .{
        .source_conditions = .{ .if_match = "\"0123\"" },
    }));
}
