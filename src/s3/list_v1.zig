//! ListObjects (v1): marker-based pagination, still used by older tools.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const acl = @import("acl.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const max_keys = 1000;

pub fn list(c: *Ctx) DispatchError!void {
    var p: object.ListParams = .{
        .prefix = (try handler.param(c, "prefix")) orelse "",
        .delimiter = (try handler.param(c, "delimiter")) orelse "",
        .start_after = (try handler.param(c, "marker")) orelse "",
        .max_keys = max_keys,
    };
    if (try handler.param(c, "max-keys")) |mk| {
        const n = std.fmt.parseInt(usize, mk, 10) catch return handler.fail(c, .InvalidArgument);
        p.max_keys = @min(n, max_keys);
    }
    const url = if (try handler.param(c, "encoding-type")) |e| blk: {
        if (!std.mem.eql(u8, e, "url")) return handler.fail(c, .InvalidArgument);
        break :blk true;
    } else false;
    const res = try c.svc.list(c.arena, c.route.bucket, p);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    const f: Fmt = .{ .url = url };
    try xml.openRoot(w, "ListBucketResult");
    try xml.elem(w, "Name", c.route.bucket);
    try f.elem(w, "Prefix", p.prefix);
    try f.elem(w, "Marker", p.start_after);
    try xml.elemInt(w, "MaxKeys", p.max_keys);
    if (p.delimiter.len > 0) try f.elem(w, "Delimiter", p.delimiter);
    if (url) try xml.elem(w, "EncodingType", "url");
    try xml.elemBool(w, "IsTruncated", res.is_truncated);
    if (res.is_truncated) if (res.next_marker) |m| try f.elem(w, "NextMarker", m);
    for (res.contents) |e| {
        var tb: [24]u8 = undefined;
        var eb: [core.ETag.quoted_max]u8 = undefined;
        try w.writeAll("<Contents>");
        try f.elem(w, "Key", e.key);
        try xml.elem(w, "LastModified", core.time.iso8601(e.mtime_ns, &tb));
        try xml.elem(w, "ETag", e.etag.quoted(&eb));
        try xml.elemInt(w, "Size", e.size);
        try w.writeAll("<Owner><ID>" ++ acl.owner_id ++ "</ID><DisplayName>" ++ acl.owner_id ++ "</DisplayName></Owner>");
        try xml.elem(w, "StorageClass", try handler.storageClass(c, e));
        try w.writeAll("</Contents>");
    }
    for (res.common_prefixes) |cp| {
        try w.writeAll("<CommonPrefixes>");
        try f.elem(w, "Prefix", cp);
        try w.writeAll("</CommonPrefixes>");
    }
    try xml.close(w, "ListBucketResult");
    try handler.respondXml(c, .ok, a.written());
}

/// Writes key-like values, URL-encoded when `encoding-type=url` was asked for.
const Fmt = struct {
    url: bool,

    fn elem(f: Fmt, w: *std.Io.Writer, name: []const u8, v: []const u8) std.Io.Writer.Error!void {
        if (!f.url) return xml.elem(w, name, v);
        try xml.open(w, name);
        try core.sigv4.uriEncode(w, v, true);
        try xml.close(w, name);
    }
};

test "url encoding of keys" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (Fmt{ .url = true }).elem(&w, "Key", "a b/c&d");
    try (Fmt{ .url = false }).elem(&w, "Key", "a&b");
    try std.testing.expectEqualStrings("<Key>a%20b/c%26d</Key><Key>a&amp;b</Key>", w.buffered());
}
