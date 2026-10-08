//! Filter evaluation against stored versions: times, tags, metadata, names.
const std = @import("std");
const object = @import("../object/root.zig");
const spec = @import("spec.zig");

/// Time filters on a version's modification time.
pub fn times(f: spec.Filter, mtime_ns: i128) bool {
    if (f.newer_than_ns) |t| if (mtime_ns < t) return false;
    if (f.older_than_ns) |t| if (mtime_ns > t) return false;
    if (f.created_after_ns) |t| if (mtime_ns <= t) return false;
    if (f.created_before_ns) |t| if (mtime_ns >= t) return false;
    return true;
}

/// Every filter tag must be present with a value matching its wildcard.
pub fn tags(arena: std.mem.Allocator, want: []const spec.KeyValue, info: object.ObjectInfo) bool {
    if (want.len == 0) return true;
    const have = object.decodeTags(arena, info.tags) catch return false;
    outer: for (want) |w| {
        for (have) |h| if (std.mem.eql(u8, h.key, w.key) and spec.glob(w.value, h.value)) continue :outer;
        return false;
    }
    return true;
}

/// Metadata filters see user metadata (with or without `x-amz-meta-`), the
/// content type, and the standard system headers; names compare case-insensitively.
pub fn metadata(want: []const spec.KeyValue, info: object.ObjectInfo) bool {
    outer: for (want) |w| {
        const name = if (std.ascii.startsWithIgnoreCase(w.key, "x-amz-meta-")) w.key["x-amz-meta-".len..] else w.key;
        if (std.ascii.eqlIgnoreCase(w.key, "content-type")) {
            if (spec.glob(w.value, info.content_type)) continue;
            return false;
        }
        inline for (object.SystemHeaders.fields) |f| if (std.ascii.eqlIgnoreCase(w.key, f[1])) {
            if (spec.glob(w.value, @field(info.system, f[0]))) continue :outer;
            return false;
        };
        for (info.metadata) |m| if (std.ascii.eqlIgnoreCase(m.name, name) and spec.glob(w.value, m.value)) continue :outer;
        return false;
    }
    return true;
}

test "metadata and tags" {
    const info: object.ObjectInfo = .{
        .key = "k",
        .size = 1,
        .etag = .{ .md5 = @splat(0) },
        .created_ns = 0,
        .content_type = "image/png",
        .object_id = undefined,
        .version_id = undefined,
        .metadata = &.{.{ .name = "color", .value = "red" }},
    };
    try std.testing.expect(metadata(&.{.{ .key = "content-type", .value = "image/*" }}, info));
    try std.testing.expect(metadata(&.{.{ .key = "X-Amz-Meta-Color", .value = "r*" }}, info));
    try std.testing.expect(!metadata(&.{.{ .key = "color", .value = "blue" }}, info));
    try std.testing.expect(!metadata(&.{.{ .key = "shape", .value = "*" }}, info));
    try std.testing.expect(times(.{ .newer_than_ns = 5 }, 6));
    try std.testing.expect(!times(.{ .created_before_ns = 5 }, 6));
}
