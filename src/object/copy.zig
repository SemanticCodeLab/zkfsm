//! Server-side copy: streams an existing object into a new object.
const std = @import("std");
const service = @import("service.zig");
const blob = @import("blob.zig");

const ObjectService = service.ObjectService;
const Error = service.Error;

pub const Source = struct {
    bucket: []const u8,
    key: []const u8,
};

pub const CopyInput = struct {
    /// Null keeps the source content type (metadata directive COPY).
    content_type: ?[]const u8 = null,
};

/// Copies `src` to `dst_bucket/dst_key`. Copying an object onto itself is allowed.
pub fn copyObject(svc: *ObjectService, src: Source, dst_bucket: []const u8, dst_key: []const u8, in: CopyInput) Error!service.ObjectInfo {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const info = try svc.head(arena.allocator(), src.bucket, src.key);
    const segs = [_]blob.Segment{.{ .blob = info.object_id, .offset = 0, .length = info.size }};
    var buf: [64 * 1024]u8 = undefined;
    var br = blob.BlobReader.init(svc.store, &segs, &buf);
    return svc.put(dst_bucket, dst_key, &br.reader, .{
        .content_type = in.content_type orelse info.content_type,
        .content_length = info.size,
    }) catch |e| switch (e) {
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
    const orig = try svc.put("src", "k", &body, .{ .content_type = "text/plain" });

    const c1 = try copyObject(&svc, .{ .bucket = "src", .key = "k" }, "dst", "k2", .{});
    try std.testing.expectEqualSlices(u8, &orig.etag.md5, &c1.etag.md5);
    try std.testing.expectEqualStrings("text/plain", (try svc.head(a, "dst", "k2")).content_type);

    _ = try copyObject(&svc, .{ .bucket = "src", .key = "k" }, "src", "k", .{ .content_type = "app/x" });
    const h = try svc.head(a, "src", "k");
    try std.testing.expectEqualStrings("app/x", h.content_type);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try svc.read(h, null, &out.writer);
    try std.testing.expectEqualStrings("copy me", out.written());

    try std.testing.expectError(error.NoSuchKey, copyObject(&svc, .{ .bucket = "src", .key = "nope" }, "dst", "x", .{}));
}
