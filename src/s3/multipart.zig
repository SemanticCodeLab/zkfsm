//! S3 multipart uploads, CopyObject, UploadPartCopy and DeleteObjects.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const router = @import("router.zig");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");
const errors = @import("errors.zig");

const Ctx = handler.Ctx;
const ConnError = handler.ConnError;
const Code = errors.Code;
const mp = object.multipart;

/// Upper bound for XML request bodies (10000 parts or 1000 delete keys fit).
const max_xml_body = 4 * 1024 * 1024;
const max_list = 1000;
const max_delete_keys = 1000;

const OpError = ConnError || mp.Error || error{ MalformedXML, EntityTooLarge, BadCopySource };

/// Handles the request if it is one of this file's operations; false means "not mine".
pub fn handle(c: *Ctx) ConnError!bool {
    const op = try classify(c) orelse return false;
    run(c, op) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => |oe| try handler.fail(c, code(oe)),
    };
    return true;
}

const Op = enum { create, upload_part, complete, abort, list_parts, list_uploads, copy_object, delete_objects, unsupported };

fn classify(c: *Ctx) error{OutOfMemory}!?Op {
    const r = c.route;
    const has = struct {
        fn f(cx: *Ctx, n: []const u8) error{OutOfMemory}!bool {
            return (try handler.param(cx, n)) != null;
        }
    }.f;
    if (r.bucket.len == 0) return null;
    if (r.key.len == 0) {
        if (c.method == .POST and try has(c, "delete")) return .delete_objects;
        if (c.method == .GET and try has(c, "uploads")) return .list_uploads;
        return null;
    }
    if (try has(c, "uploads")) return if (c.method == .POST) .create else .unsupported;
    if (try has(c, "uploadId")) return switch (c.method) {
        .PUT => .upload_part,
        .POST => .complete,
        .DELETE => .abort,
        .GET => .list_parts,
        else => .unsupported,
    };
    if (c.method == .PUT and c.copy_source) return .copy_object;
    return null;
}

fn run(c: *Ctx, op: Op) OpError!void {
    switch (op) {
        .create => try create(c),
        .upload_part => try uploadPart(c),
        .complete => try complete(c),
        .abort => {
            try mp.abort(c.svc, c.route.bucket, c.route.key, try uploadId(c));
            try handler.respondEmpty(c, .no_content, &.{});
        },
        .list_parts => try listParts(c),
        .list_uploads => try listUploads(c),
        .copy_object => try copyObject(c),
        .delete_objects => try deleteObjects(c),
        .unsupported => try handler.fail(c, .MethodNotAllowed),
    }
}

fn code(e: OpError) Code {
    return switch (e) {
        error.NoSuchUpload => .NoSuchUpload,
        error.InvalidPart => .InvalidPart,
        error.InvalidPartOrder => .InvalidPartOrder,
        error.EntityTooSmall => .EntityTooSmall,
        error.EntityTooLarge => .EntityTooLarge,
        error.MalformedXML => .MalformedXML,
        error.InvalidPartNumber, error.BadCopySource => .InvalidArgument,
        error.InvalidRange => .InvalidRange,
        error.HttpExpectationFailed, error.StreamAborted => .InternalError,
        else => |oe| errors.fromObject(oe),
    };
}

fn uploadId(c: *Ctx) OpError!mp.UploadId {
    const s = (try handler.param(c, "uploadId")) orelse return error.NoSuchUpload;
    return mp.UploadId.parseHex(s) catch error.NoSuchUpload;
}

fn create(c: *Ctx) OpError!void {
    const id = try mp.create(c.svc, c.route.bucket, c.route.key, c.content_type);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "InitiateMultipartUploadResult");
    try xml.elem(w, "Bucket", c.route.bucket);
    try xml.elem(w, "Key", c.route.key);
    try xml.elem(w, "UploadId", &id.toHex());
    try w.writeAll("</InitiateMultipartUploadResult>");
    try handler.respondXml(c, .ok, a.written());
}

fn partNumber(c: *Ctx) OpError!u16 {
    const s = (try handler.param(c, "partNumber")) orelse return error.InvalidPartNumber;
    return std.fmt.parseInt(u16, s, 10) catch error.InvalidPartNumber;
}

const CopyHeaders = struct {
    source: ?[]const u8 = null,
    range: ?[]const u8 = null,
    directive: ?[]const u8 = null,
};

/// Must run before the body is read; reading invalidates the header buffer.
fn copyHeaders(c: *Ctx) error{OutOfMemory}!CopyHeaders {
    var h: CopyHeaders = .{};
    var it = c.req.iterateHeaders();
    while (it.next()) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, "x-amz-copy-source")) h.source = try c.arena.dupe(u8, f.value);
        if (std.ascii.eqlIgnoreCase(f.name, "x-amz-copy-source-range")) h.range = try c.arena.dupe(u8, f.value);
        if (std.ascii.eqlIgnoreCase(f.name, "x-amz-metadata-directive")) h.directive = try c.arena.dupe(u8, f.value);
    }
    return h;
}

/// `x-amz-copy-source`: `[/]bucket/key[?versionId=...]`, percent-encoded.
fn parseCopySource(arena: std.mem.Allocator, raw: []const u8) OpError!object.copy.Source {
    var s = std.mem.sliceTo(raw, '?');
    if (s.len > 0 and s[0] == '/') s = s[1..];
    const decoded = router.percentDecode(arena, s, false) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUri => error.BadCopySource,
    };
    const slash = std.mem.indexOfScalar(u8, decoded, '/') orelse return error.BadCopySource;
    if (slash == 0 or slash + 1 == decoded.len) return error.BadCopySource;
    return .{ .bucket = decoded[0..slash], .key = decoded[slash + 1 ..] };
}

fn uploadPart(c: *Ctx) OpError!void {
    const id = try uploadId(c);
    const n = try partNumber(c);
    const ch = try copyHeaders(c);
    if (ch.source) |raw| {
        const src = try parseCopySource(c.arena, raw);
        var range: ?mp.CopyRange = null;
        if (ch.range) |rh| {
            const spec = core.RangeSpec.parse(rh) catch return error.BadCopySource;
            if (spec != .from_to) return error.BadCopySource;
            range = .{ .first = spec.from_to.first, .last = spec.from_to.last };
        }
        const etag = try mp.uploadPartCopy(c.svc, c.route.bucket, c.route.key, id, n, src, range);
        return copyResult(c, "CopyPartResult", etag, core.time.nowNs());
    }
    if (c.content_sha256) |s| if (std.mem.startsWith(u8, s, "STREAMING-")) return handler.fail(c, .NotImplemented);
    const len = c.req.head.content_length;
    var body_buf: [handler.io_buf_len]u8 = undefined;
    const body = try c.req.readerExpectContinue(&body_buf);
    const etag = try mp.uploadPart(c.svc, c.route.bucket, c.route.key, id, n, body, len);
    var eb: [core.ETag.quoted_max]u8 = undefined;
    try handler.respondEmpty(c, .ok, &.{.{ .name = "etag", .value = etag.quoted(&eb) }});
}

fn copyResult(c: *Ctx, root: []const u8, etag: core.ETag, mtime_ns: i128) OpError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var tb: [24]u8 = undefined;
    var eb: [core.ETag.quoted_max]u8 = undefined;
    try xml.openRoot(w, root);
    try xml.elem(w, "LastModified", core.time.iso8601(mtime_ns, &tb));
    try xml.elem(w, "ETag", etag.quoted(&eb));
    try xml.close(w, root);
    try handler.respondXml(c, .ok, a.written());
}

fn copyObject(c: *Ctx) OpError!void {
    const ch = try copyHeaders(c);
    const src = try parseCopySource(c.arena, ch.source orelse return error.BadCopySource);
    const replace = if (ch.directive) |d| blk: {
        if (std.ascii.eqlIgnoreCase(d, "REPLACE")) break :blk true;
        if (std.ascii.eqlIgnoreCase(d, "COPY")) break :blk false;
        return error.BadCopySource;
    } else false;
    // S3 rejects a same-key copy that changes nothing.
    if (!replace and std.mem.eql(u8, src.bucket, c.route.bucket) and std.mem.eql(u8, src.key, c.route.key))
        return handler.fail(c, .InvalidRequest);
    const info = try object.copy.copyObject(c.svc, src, c.route.bucket, c.route.key, .{
        .content_type = if (replace) c.content_type else null,
    });
    try copyResult(c, "CopyObjectResult", info.etag, info.created_ns);
}

fn readXmlBody(c: *Ctx) OpError![]const u8 {
    var body_buf: [handler.io_buf_len]u8 = undefined;
    const body = try c.req.readerExpectContinue(&body_buf);
    return body.allocRemaining(c.arena, .limited(max_xml_body)) catch |e| switch (e) {
        error.StreamTooLong => error.EntityTooLarge,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Parses `<Part><PartNumber>n</PartNumber><ETag>"hex"</ETag></Part>...`.
fn parseCompleteBody(arena: std.mem.Allocator, body: []const u8) (xml_read.Error || error{InvalidPart})![]mp.PartRef {
    var refs: std.ArrayList(mp.PartRef) = .empty;
    var sc: xml_read.Scanner = .{ .s = body };
    if (try sc.next("CompleteMultipartUpload") == null) return error.MalformedXML;
    sc.pos = 0;
    while (try sc.next("Part")) |part| {
        if (refs.items.len >= mp.max_part_number) return error.MalformedXML;
        var in: xml_read.Scanner = .{ .s = part };
        const num_s = (try in.next("PartNumber")) orelse return error.MalformedXML;
        in.pos = 0;
        const etag_s = try xml_read.unescape(arena, (try in.next("ETag")) orelse return error.MalformedXML);
        const num = std.fmt.parseInt(u16, std.mem.trim(u8, num_s, " \t\r\n"), 10) catch return error.MalformedXML;
        const hex = std.mem.trim(u8, etag_s, " \t\r\n\"");
        var md5: [16]u8 = undefined;
        if (hex.len != 32) return error.InvalidPart;
        _ = std.fmt.hexToBytes(&md5, hex) catch return error.InvalidPart;
        try refs.append(arena, .{ .number = num, .md5 = md5 });
    }
    return refs.items;
}

fn complete(c: *Ctx) OpError!void {
    const id = try uploadId(c);
    const body = try readXmlBody(c);
    const refs = try parseCompleteBody(c.arena, body);
    const info = try mp.complete(c.svc, c.route.bucket, c.route.key, id, refs);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var eb: [core.ETag.quoted_max]u8 = undefined;
    try xml.openRoot(w, "CompleteMultipartUploadResult");
    try xml.elem(w, "Location", std.mem.sliceTo(c.target, '?'));
    try xml.elem(w, "Bucket", c.route.bucket);
    try xml.elem(w, "Key", c.route.key);
    try xml.elem(w, "ETag", info.etag.quoted(&eb));
    try w.writeAll("</CompleteMultipartUploadResult>");
    try handler.respondXml(c, .ok, a.written());
}

fn maxParam(c: *Ctx, name: []const u8) OpError!usize {
    const s = (try handler.param(c, name)) orelse return max_list;
    const n = std.fmt.parseInt(usize, s, 10) catch return error.InvalidPartNumber;
    return @min(n, max_list);
}

const owner = "<ID>zkfsm</ID><DisplayName>zkfsm</DisplayName>";

fn listParts(c: *Ctx) OpError!void {
    const id = try uploadId(c);
    const max = try maxParam(c, "max-parts");
    const marker_s = (try handler.param(c, "part-number-marker")) orelse "0";
    const marker = std.fmt.parseInt(u16, marker_s, 10) catch return error.InvalidPartNumber;
    const rec = try mp.listParts(c.svc, c.arena, c.route.bucket, c.route.key, id);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListPartsResult");
    try xml.elem(w, "Bucket", c.route.bucket);
    try xml.elem(w, "Key", c.route.key);
    try xml.elem(w, "UploadId", &id.toHex());
    try w.print("<Initiator>{s}</Initiator><Owner>{s}</Owner><StorageClass>STANDARD</StorageClass>", .{ owner, owner });
    try xml.elemInt(w, "PartNumberMarker", marker);
    try xml.elemInt(w, "MaxParts", max);
    var shown: usize = 0;
    var last: u16 = marker;
    var truncated = false;
    var body: std.Io.Writer.Allocating = .init(c.arena);
    for (rec.parts) |p| {
        if (p.number <= marker) continue;
        if (shown == max) {
            truncated = true;
            break;
        }
        var tb: [24]u8 = undefined;
        var eb: [core.ETag.quoted_max]u8 = undefined;
        const bw = &body.writer;
        try bw.writeAll("<Part>");
        try xml.elemInt(bw, "PartNumber", p.number);
        try xml.elem(bw, "LastModified", core.time.iso8601(p.created_ns, &tb));
        try xml.elem(bw, "ETag", (core.ETag{ .md5 = p.md5 }).quoted(&eb));
        try xml.elemInt(bw, "Size", p.size);
        try bw.writeAll("</Part>");
        shown += 1;
        last = p.number;
    }
    try xml.elemInt(w, "NextPartNumberMarker", last);
    try xml.elemBool(w, "IsTruncated", truncated);
    try w.writeAll(body.written());
    try w.writeAll("</ListPartsResult>");
    try handler.respondXml(c, .ok, a.written());
}

fn listUploads(c: *Ctx) OpError!void {
    const prefix = (try handler.param(c, "prefix")) orelse "";
    const key_marker = (try handler.param(c, "key-marker")) orelse "";
    const id_marker = (try handler.param(c, "upload-id-marker")) orelse "";
    const max = try maxParam(c, "max-uploads");
    const all = try mp.listUploads(c.svc, c.arena, c.route.bucket, prefix);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListMultipartUploadsResult");
    try xml.elem(w, "Bucket", c.route.bucket);
    try xml.elem(w, "KeyMarker", key_marker);
    try xml.elem(w, "UploadIdMarker", id_marker);
    try xml.elem(w, "Prefix", prefix);
    try xml.elemInt(w, "MaxUploads", max);
    var body: std.Io.Writer.Allocating = .init(c.arena);
    var shown: usize = 0;
    var truncated = false;
    var next_key: []const u8 = "";
    var next_id: [32]u8 = @splat('0');
    // Without an upload-id marker, the key marker excludes that key entirely.
    var past_marker = key_marker.len == 0;
    for (all) |u| {
        const hex = u.upload_id.toHex();
        if (!past_marker) {
            const ord = std.mem.order(u8, u.key, key_marker);
            if (ord == .lt) continue;
            if (ord == .eq) {
                if (id_marker.len == 0) continue;
                if (std.mem.eql(u8, &hex, id_marker)) past_marker = true;
                continue;
            }
            past_marker = true;
        }
        if (shown == max) {
            truncated = true;
            break;
        }
        var tb: [24]u8 = undefined;
        const bw = &body.writer;
        try bw.writeAll("<Upload>");
        try xml.elem(bw, "Key", u.key);
        try xml.elem(bw, "UploadId", &hex);
        try bw.print("<Initiator>{s}</Initiator><Owner>{s}</Owner><StorageClass>STANDARD</StorageClass>", .{ owner, owner });
        try xml.elem(bw, "Initiated", core.time.iso8601(u.created_ns, &tb));
        try bw.writeAll("</Upload>");
        shown += 1;
        next_key = u.key;
        next_id = hex;
    }
    if (truncated) {
        try xml.elem(w, "NextKeyMarker", next_key);
        try xml.elem(w, "NextUploadIdMarker", &next_id);
    }
    try xml.elemBool(w, "IsTruncated", truncated);
    try w.writeAll(body.written());
    try w.writeAll("</ListMultipartUploadsResult>");
    try handler.respondXml(c, .ok, a.written());
}

fn deleteObjects(c: *Ctx) OpError!void {
    try c.svc.headBucket(c.route.bucket);
    const body = try readXmlBody(c);
    var sc: xml_read.Scanner = .{ .s = body };
    const root = (try sc.next("Delete")) orelse return error.MalformedXML;
    var qs: xml_read.Scanner = .{ .s = root };
    const quiet = if (try qs.next("Quiet")) |q| std.mem.eql(u8, std.mem.trim(u8, q, " \t\r\n"), "true") else false;

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "DeleteResult");
    var objs: xml_read.Scanner = .{ .s = root };
    var n: usize = 0;
    while (try objs.next("Object")) |o| {
        n += 1;
        if (n > max_delete_keys) return error.MalformedXML;
        var ks: xml_read.Scanner = .{ .s = o };
        const key = try xml_read.unescape(c.arena, (try ks.next("Key")) orelse return error.MalformedXML);
        if (c.svc.delete(c.route.bucket, key)) {
            if (quiet) continue;
            try w.writeAll("<Deleted>");
            try xml.elem(w, "Key", key);
            try w.writeAll("</Deleted>");
        } else |e| {
            const ec = errors.fromObject(e);
            try w.writeAll("<Error>");
            try xml.elem(w, "Key", key);
            try xml.elem(w, "Code", @tagName(ec));
            try xml.elem(w, "Message", ec.message());
            try w.writeAll("</Error>");
        }
    }
    try w.writeAll("</DeleteResult>");
    try handler.respondXml(c, .ok, a.written());
}

test "copy source parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try parseCopySource(a, "/bkt/dir/my%20file?versionId=null");
    try std.testing.expectEqualStrings("bkt", s.bucket);
    try std.testing.expectEqualStrings("dir/my file", s.key);
    try std.testing.expectEqualStrings("k", (try parseCopySource(a, "b/k")).key);
    try std.testing.expectError(error.BadCopySource, parseCopySource(a, "nokey"));
    try std.testing.expectError(error.BadCopySource, parseCopySource(a, "/b/"));
}

test "complete body parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const body =
        \\<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\ <Part><ETag>&quot;0123456789abcdef0123456789abcdef&quot;</ETag><PartNumber>1</PartNumber></Part>
        \\ <Part><PartNumber>2</PartNumber><ETag>"ffffffffffffffffffffffffffffffff"</ETag></Part>
        \\</CompleteMultipartUpload>
    ;
    const refs = try parseCompleteBody(a, body);
    try std.testing.expectEqual(@as(usize, 2), refs.len);
    try std.testing.expectEqual(@as(u16, 1), refs[0].number);
    try std.testing.expectEqual(@as(u8, 0x01), refs[0].md5[0]);
    try std.testing.expectEqual(@as(u16, 2), refs[1].number);
    try std.testing.expectError(error.MalformedXML, parseCompleteBody(a, "<Nope/>"));
    try std.testing.expectError(error.InvalidPart, parseCompleteBody(a, "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>zz</ETag></Part></CompleteMultipartUpload>"));
}

test "error code mapping" {
    try std.testing.expectEqual(Code.NoSuchUpload, code(error.NoSuchUpload));
    try std.testing.expectEqual(Code.NoSuchKey, code(error.NoSuchKey));
    try std.testing.expectEqual(std.http.Status.not_found, Code.NoSuchUpload.status());
}
