//! GetObjectAttributes (`GET /bucket/key?attributes`): ETag, checksum, parts,
//! storage class, and size of one version without reading its data.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const s3v = @import("versioning.zig");
const checksums = @import("checksums.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const Header = std.http.Header;

const Want = struct { etag: bool = false, checksum: bool = false, parts: bool = false, class: bool = false, size: bool = false };

/// Handles `?attributes` on an object; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len == 0 or (try handler.param(c, "attributes")) == null) return false;
    if (c.method != .GET) {
        try handler.fail(c, .MethodNotAllowed);
        return true;
    }
    var want: Want = .{};
    var max_parts: usize = 1000;
    var marker: usize = 0;
    var it = c.req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-object-attributes")) {
            var vs = std.mem.tokenizeAny(u8, h.value, ", ");
            while (vs.next()) |v| {
                if (std.mem.eql(u8, v, "ETag")) want.etag = true else if (std.mem.eql(u8, v, "Checksum")) want.checksum = true else if (std.mem.eql(u8, v, "ObjectParts")) want.parts = true else if (std.mem.eql(u8, v, "StorageClass")) want.class = true else if (std.mem.eql(u8, v, "ObjectSize")) want.size = true else {
                    try handler.fail(c, .InvalidArgument);
                    return true;
                }
            }
        } else if (std.ascii.eqlIgnoreCase(h.name, "x-amz-max-parts")) {
            max_parts = std.fmt.parseInt(usize, std.mem.trim(u8, h.value, " "), 10) catch {
                try handler.fail(c, .InvalidArgument);
                return true;
            };
        } else if (std.ascii.eqlIgnoreCase(h.name, "x-amz-part-number-marker")) {
            marker = std.fmt.parseInt(usize, std.mem.trim(u8, h.value, " "), 10) catch {
                try handler.fail(c, .InvalidArgument);
                return true;
            };
        }
    }
    const asked = try s3v.versionParam(c);
    const info = try object.versioning.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, asked);
    var hdrs: std.ArrayList(Header) = .empty;
    var tb: [29]u8 = undefined;
    try hdrs.append(c.arena, .{ .name = "last-modified", .value = try c.arena.dupe(u8, core.time.httpDate(info.created_ns, &tb)) });
    if (asked != null or !info.version_id.eql(object.versioning.null_version_id)) {
        const vb = try c.arena.create([32]u8);
        try hdrs.append(c.arena, .{ .name = "x-amz-version-id", .value = object.versioning.formatVersionId(info.version_id, vb) });
    }
    if (info.delete_marker) {
        try hdrs.append(c.arena, .{ .name = "x-amz-delete-marker", .value = "true" });
        try handler.failWith(c, if (asked != null) .MethodNotAllowed else .NoSuchKey, hdrs.items);
        return true;
    }
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "GetObjectAttributesResponse");
    if (want.etag) {
        var eb: [core.ETag.quoted_max]u8 = undefined;
        const q = info.etag.quoted(&eb);
        try xml.elem(w, "ETag", q[1 .. q.len - 1]);
    }
    const ck = checksums.stored(info);
    if (want.checksum) if (ck) |s| {
        try w.writeAll("<Checksum>");
        try xml.elem(w, checksumElem(s.alg), s.value);
        try xml.elem(w, "ChecksumType", s.ctype.wireName());
        try w.writeAll("</Checksum>");
    };
    const count = info.part_sizes.len / 8;
    if (want.parts and count > 0 and info.logical_size == null) {
        try w.writeAll("<ObjectParts>");
        try xml.elemInt(w, "PartsCount", count);
        try xml.elemInt(w, "PartNumberMarker", marker);
        try xml.elemInt(w, "MaxParts", max_parts);
        var shown: usize = 0;
        var last = marker;
        var parts: std.Io.Writer.Allocating = .init(c.arena);
        var n = marker + 1;
        while (n <= count and shown < max_parts) : (n += 1) {
            try parts.writer.writeAll("<Part>");
            try xml.elemInt(&parts.writer, "PartNumber", n);
            try xml.elemInt(&parts.writer, "Size", object.partSize(info.part_sizes, n - 1));
            if (ck) |s| if (s.ctype == .composite) if (checksums.partValue(info, n)) |pv| try xml.elem(&parts.writer, checksumElem(s.alg), pv);
            try parts.writer.writeAll("</Part>");
            shown += 1;
            last = n;
        }
        const truncated = n <= count;
        try xml.elemBool(w, "IsTruncated", truncated);
        if (truncated) try xml.elemInt(w, "NextPartNumberMarker", last);
        try w.writeAll(parts.written());
        try w.writeAll("</ObjectParts>");
    }
    if (want.class) try xml.elem(w, "StorageClass", if (info.tier.len > 0) info.tier else "STANDARD");
    if (want.size) try xml.elemInt(w, "ObjectSize", info.size);
    try xml.close(w, "GetObjectAttributesResponse");
    try handler.respondXmlWith(c, .ok, a.written(), hdrs.items);
    return true;
}

fn checksumElem(alg: checksums.Algorithm) []const u8 {
    return switch (alg) {
        .crc32 => "ChecksumCRC32",
        .crc32c => "ChecksumCRC32C",
        .crc64nvme => "ChecksumCRC64NVME",
        .sha1 => "ChecksumSHA1",
        .sha256 => "ChecksumSHA256",
    };
}
