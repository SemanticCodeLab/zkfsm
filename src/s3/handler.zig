//! S3 operations: dispatches one parsed request to ObjectService and writes the response.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const router = @import("router.zig");
const xml = @import("xml.zig");
const errors = @import("errors.zig");
const sigv4 = @import("sigv4.zig");
const multipart = @import("multipart.zig");

const Request = std.http.Server.Request;
const Header = std.http.Header;
const Code = errors.Code;

/// Errors that end the connection; S3-level failures become XML responses instead.
pub const ConnError = error{ WriteFailed, ReadFailed, HttpExpectationFailed, OutOfMemory, StreamAborted };

const io_buf_len = 64 * 1024;
const max_list_keys = 1000;

/// Request fields copied out of the head before the body reader invalidates it.
const Ctx = struct {
    req: *Request,
    arena: std.mem.Allocator,
    svc: *object.ObjectService,
    method: std.http.Method,
    target: []const u8,
    route: router.Target,
    range: ?[]const u8,
    content_type: []const u8,
    content_sha256: ?[]const u8,
    copy_source: bool,
    request_id: [16]u8,
};

pub fn handle(svc: *object.ObjectService, req: *Request, arena: std.mem.Allocator) ConnError!void {
    // No length and no chunking means an empty body (RFC 9112 6.3); std asserts otherwise.
    if (req.head.transfer_encoding == .none and req.head.content_length == null) req.head.content_length = 0;
    var ctx: Ctx = .{
        .req = req,
        .arena = arena,
        .svc = svc,
        .method = req.head.method,
        .target = try arena.dupe(u8, req.head.target),
        .route = undefined,
        .range = null,
        .content_type = try arena.dupe(u8, req.head.content_type orelse ""),
        .content_sha256 = null,
        .copy_source = false,
        .request_id = std.fmt.bytesToHex(core.ObjectId.random().bytes[0..8].*, .upper),
    };
    var hit = req.iterateHeaders();
    while (hit.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "range")) ctx.range = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-content-sha256")) ctx.content_sha256 = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-copy-source")) ctx.copy_source = true;
    }
    ctx.route = router.parse(arena, ctx.target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUri => return fail(&ctx, .InvalidURI),
    };
    if (!sigv4.authorize(req)) return fail(&ctx, .InternalError);
    if (multipart.isMultipartRequest(ctx.route.query)) return fail(&ctx, .NotImplemented);
    dispatch(&ctx) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => |oe| return fail(&ctx, errors.fromObject(oe)),
    };
}

const DispatchError = ConnError || object.Error;

fn dispatch(c: *Ctx) DispatchError!void {
    const r = c.route;
    if (r.bucket.len == 0) return switch (c.method) {
        .GET => listBuckets(c),
        else => fail(c, .MethodNotAllowed),
    };
    if (r.key.len == 0) return switch (c.method) {
        .PUT => {
            try c.svc.createBucket(r.bucket);
            try respondEmpty(c, .ok, &.{.{ .name = "location", .value = c.target }});
        },
        .DELETE => {
            try c.svc.deleteBucket(r.bucket);
            try respondEmpty(c, .no_content, &.{});
        },
        .HEAD => {
            try c.svc.headBucket(r.bucket);
            try respondEmpty(c, .ok, &.{});
        },
        .GET => if ((try param(c, "location")) != null) getLocation(c) else listObjects(c),
        else => fail(c, .MethodNotAllowed),
    };
    return switch (c.method) {
        .PUT => putObject(c),
        .GET, .HEAD => getObject(c),
        .DELETE => {
            try c.svc.delete(r.bucket, r.key);
            try respondEmpty(c, .no_content, &.{});
        },
        else => fail(c, .MethodNotAllowed),
    };
}

fn param(c: *Ctx, name: []const u8) error{OutOfMemory}!?[]const u8 {
    return router.queryParam(c.arena, c.route.query, name) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUri => null,
    };
}

fn listBuckets(c: *Ctx) DispatchError!void {
    const buckets = try c.svc.listBuckets(c.arena);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListAllMyBucketsResult");
    try w.writeAll("<Owner><ID>zkfsm</ID><DisplayName>zkfsm</DisplayName></Owner><Buckets>");
    for (buckets) |b| {
        var tb: [24]u8 = undefined;
        try w.writeAll("<Bucket>");
        try xml.elem(w, "Name", b.name);
        try xml.elem(w, "CreationDate", core.time.iso8601(b.created_ns, &tb));
        try w.writeAll("</Bucket>");
    }
    try w.writeAll("</Buckets></ListAllMyBucketsResult>");
    try respondXml(c, .ok, a.written());
}

fn getLocation(c: *Ctx) DispatchError!void {
    try c.svc.headBucket(c.route.bucket);
    const body = xml.declaration ++ "<LocationConstraint xmlns=\"" ++ xml.s3_ns ++ "\"></LocationConstraint>";
    try respondXml(c, .ok, body);
}

fn listObjects(c: *Ctx) DispatchError!void {
    var p: object.ListParams = .{
        .prefix = (try param(c, "prefix")) orelse "",
        .delimiter = (try param(c, "delimiter")) orelse "",
        .start_after = (try param(c, "start-after")) orelse "",
        .max_keys = max_list_keys,
    };
    if (try param(c, "max-keys")) |mk| {
        const n = std.fmt.parseInt(usize, mk, 10) catch return fail(c, .InvalidArgument);
        p.max_keys = @min(n, max_list_keys);
    }
    const token = try param(c, "continuation-token");
    if (token) |t| {
        if (t.len % 2 != 0) return fail(c, .InvalidArgument);
        const raw = try c.arena.alloc(u8, t.len / 2);
        p.start_after = std.fmt.hexToBytes(raw, t) catch return fail(c, .InvalidArgument);
    }
    const res = try c.svc.list(c.arena, c.route.bucket, p);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListBucketResult");
    try xml.elem(w, "Name", c.route.bucket);
    try xml.elem(w, "Prefix", p.prefix);
    if (p.delimiter.len > 0) try xml.elem(w, "Delimiter", p.delimiter);
    if (token) |t| try xml.elem(w, "ContinuationToken", t);
    if (try param(c, "start-after")) |sa| try xml.elem(w, "StartAfter", sa);
    try xml.elemInt(w, "KeyCount", res.contents.len + res.common_prefixes.len);
    try xml.elemInt(w, "MaxKeys", p.max_keys);
    try xml.elemBool(w, "IsTruncated", res.is_truncated);
    if (res.is_truncated) if (res.next_marker) |m| {
        const hex = try c.arena.alloc(u8, m.len * 2);
        for (m, 0..) |byte, i| _ = std.fmt.bufPrint(hex[i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable; // 2 hex chars fit
        try xml.elem(w, "NextContinuationToken", hex);
    };
    for (res.contents) |e| {
        var tb: [24]u8 = undefined;
        try w.writeAll("<Contents>");
        try xml.elem(w, "Key", e.key);
        try xml.elem(w, "LastModified", core.time.iso8601(e.mtime_ns, &tb));
        try xml.elem(w, "ETag", &e.etag.quoted());
        try xml.elemInt(w, "Size", e.size);
        try w.writeAll("<StorageClass>STANDARD</StorageClass></Contents>");
    }
    for (res.common_prefixes) |cp| {
        try w.writeAll("<CommonPrefixes>");
        try xml.elem(w, "Prefix", cp);
        try w.writeAll("</CommonPrefixes>");
    }
    try w.writeAll("</ListBucketResult>");
    try respondXml(c, .ok, a.written());
}

fn putObject(c: *Ctx) DispatchError!void {
    if (c.copy_source) return fail(c, .NotImplemented);
    if (c.content_sha256) |s| if (std.mem.startsWith(u8, s, "STREAMING-")) return fail(c, .NotImplemented);
    const len = c.req.head.content_length;
    var body_buf: [io_buf_len]u8 = undefined;
    const body = try c.req.readerExpectContinue(&body_buf);
    const info = try c.svc.put(c.route.bucket, c.route.key, body, .{ .content_type = c.content_type, .content_length = len });
    const etag = info.etag.quoted();
    try respondEmpty(c, .ok, &.{.{ .name = "etag", .value = &etag }});
}

fn getObject(c: *Ctx) DispatchError!void {
    const info = try c.svc.head(c.arena, c.route.bucket, c.route.key);
    var range: ?core.Range = null;
    if (c.range) |h| if (core.RangeSpec.parse(h)) |spec| {
        range = spec.resolve(info.size) catch {
            const cr = try std.fmt.allocPrint(c.arena, "bytes */{d}", .{info.size});
            return failWith(c, .InvalidRange, &.{.{ .name = "content-range", .value = cr }});
        };
    } else |_| {}; // malformed Range is ignored, as S3 does

    const etag = info.etag.quoted();
    var db: [29]u8 = undefined;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "etag", .value = &etag },
        .{ .name = "last-modified", .value = core.time.httpDate(info.created_ns, &db) },
        .{ .name = "accept-ranges", .value = "bytes" },
        .{ .name = "content-type", .value = if (info.content_type.len > 0) info.content_type else "binary/octet-stream" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    if (range) |r| try hdrs.append(c.arena, .{
        .name = "content-range",
        .value = try std.fmt.allocPrint(c.arena, "bytes {d}-{d}/{d}", .{ r.offset, r.last(), info.size }),
    });
    const len = if (range) |r| r.length else info.size;
    var out_buf: [io_buf_len]u8 = undefined;
    var bw = try c.req.respondStreaming(&out_buf, .{
        .content_length = len,
        .respond_options = .{ .status = if (range != null) .partial_content else .ok, .extra_headers = hdrs.items },
    });
    if (bw.isEliding()) return bw.flush();
    // Headers are committed; a failure now can only abort the connection.
    c.svc.read(info, range, &bw.writer) catch return error.StreamAborted;
    try bw.end();
}

fn respondXml(c: *Ctx, status: std.http.Status, body: []const u8) ConnError!void {
    try c.req.respond(body, .{ .status = status, .extra_headers = &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    } });
}

fn respondEmpty(c: *Ctx, status: std.http.Status, extra: []const Header) ConnError!void {
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    try c.req.respond("", .{ .status = status, .extra_headers = hdrs.items });
}

fn fail(c: *Ctx, code: Code) ConnError!void {
    return failWith(c, code, &.{});
}

fn failWith(c: *Ctx, code: Code, extra: []const Header) ConnError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const resource = std.mem.sliceTo(c.target, '?');
    errors.writeBody(&a.writer, code, resource, &c.request_id) catch return error.OutOfMemory;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    // After a failed body read the connection state is unknown; close it.
    const keep = c.req.server.reader.state == .ready or c.req.server.reader.state == .received_head;
    try c.req.respond(a.written(), .{ .status = code.status(), .extra_headers = hdrs.items, .keep_alive = keep });
}
