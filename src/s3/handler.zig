//! S3 operations: dispatches one parsed request to ObjectService and writes the response.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const router = @import("router.zig");
const xml = @import("xml.zig");
const errors = @import("errors.zig");
const sigv4 = @import("sigv4.zig");
const authz = @import("authz.zig");
const multipart = @import("multipart.zig");
const metrics = @import("../metrics/root.zig");
const versioning = @import("versioning.zig");
const lifecycle = @import("lifecycle.zig");
const policy = @import("policy.zig");
const acl = @import("acl.zig");
const list_v1 = @import("list_v1.zig");
const sts = @import("sts.zig");

const Request = std.http.Server.Request;
const Header = std.http.Header;
const Code = errors.Code;

/// Errors that end the connection; S3-level failures become XML responses instead.
pub const ConnError = error{ WriteFailed, ReadFailed, HttpExpectationFailed, OutOfMemory, StreamAborted };

pub const io_buf_len = 64 * 1024;
const max_list_keys = 1000;

/// Request fields copied out of the head before the body reader invalidates it.
pub const Ctx = struct {
    req: *Request,
    arena: std.mem.Allocator,
    svc: *object.ObjectService,
    method: std.http.Method,
    target: []const u8,
    route: router.Target,
    range: ?[]const u8,
    content_type: []const u8,
    copy_source: bool,
    auth: sigv4.Auth,
    request_id: [16]u8,
    ext: versioning.Headers = .{},
    /// Body read before authentication (STS form posts only).
    body: ?[]const u8 = null,
};

pub fn handle(svc: *object.ObjectService, env: authz.Env, req: *Request, arena: std.mem.Allocator) ConnError!void {
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
        .copy_source = false,
        .auth = .{},
        .request_id = std.fmt.bytesToHex(core.ObjectId.random().bytes[0..8].*, .upper),
    };
    var host: ?[]const u8 = null;
    var hit = req.iterateHeaders();
    while (hit.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "host")) host = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "range")) ctx.range = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-copy-source")) ctx.copy_source = true;
        try ctx.ext.capture(arena, h);
    }
    ctx.route = router.resolve(arena, env.routing, host, ctx.target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUri => return fail(&ctx, .InvalidURI),
        // Outside the base path: answer like an unknown bucket, before authentication.
        error.OutsidePrefix => return fail(&ctx, .NoSuchBucket),
    };
    const now_s = std.time.timestamp();
    var in = try sigv4.Input.fromRequest(arena, req);
    try sts.prepare(&ctx, &in);
    switch (try sigv4.verify(arena, env.auth, in, now_s)) {
        .ok => |a| ctx.auth = a,
        .denied => |code| return fail(&ctx, code),
    }
    if (try sts.route(&ctx, env, now_s)) return;
    // STS-scoped signatures are only valid for STS calls.
    if (std.mem.eql(u8, ctx.auth.scope.service, "sts")) return fail(&ctx, .AccessDenied);
    for (env.extensions) |x| if (x.before_authz and try x.route(x.ctx, &ctx)) return;
    var ar: authz.Request = .{ .method = ctx.method, .bucket = ctx.route.bucket, .key = ctx.route.key, .query = ctx.route.query, .copy_source = ctx.copy_source };
    if (env.auth.iam != null and ctx.route.bucket.len > 0) {
        ar.bucket_policy = object.policy.get(svc, arena, ctx.route.bucket) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => null,
        };
    }
    if (!try authz.allowed(arena, env, ctx.auth, ar, now_s)) return fail(&ctx, .AccessDenied);
    for (env.extensions) |x| if (!x.before_authz and try x.route(x.ctx, &ctx)) return;
    if (try multipart.handle(&ctx)) return;
    dispatch(&ctx) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => |oe| return fail(&ctx, errors.fromObject(oe)),
    };
}

pub const DispatchError = ConnError || object.Error;

fn dispatch(c: *Ctx) DispatchError!void {
    const r = c.route;
    if (r.bucket.len == 0) return switch (c.method) {
        .GET => listBuckets(c),
        else => fail(c, .MethodNotAllowed),
    };
    if (try lifecycle.route(c) or try policy.route(c) or try acl.route(c)) return;
    if (try versioning.route(c)) return;
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
        .GET => if ((try param(c, "location")) != null)
            getLocation(c)
        else if ((try param(c, "list-type")) == null)
            list_v1.list(c)
        else
            listObjects(c),
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

pub fn param(c: *Ctx, name: []const u8) error{OutOfMemory}!?[]const u8 {
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
    try w.writeAll(owner_xml ++ "<Buckets>");
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
    // ListObjects V1 pages with marker/NextMarker, V2 with opaque continuation tokens.
    const v2 = if (try param(c, "list-type")) |lt| std.mem.eql(u8, lt, "2") else false;
    const url = if (try param(c, "encoding-type")) |et| blk: {
        if (!std.ascii.eqlIgnoreCase(et, "url")) return fail(c, .InvalidArgument);
        break :blk true;
    } else false;
    var p: object.ListParams = .{
        .prefix = (try param(c, "prefix")) orelse "",
        .delimiter = (try param(c, "delimiter")) orelse "",
        .start_after = (try param(c, if (v2) "start-after" else "marker")) orelse "",
        .max_keys = max_list_keys,
    };
    if (try param(c, "max-keys")) |mk| {
        const n = std.fmt.parseInt(usize, mk, 10) catch return fail(c, .InvalidArgument);
        p.max_keys = @min(n, max_list_keys);
    }
    const token = if (v2) try param(c, "continuation-token") else null;
    if (token) |t| {
        if (t.len % 2 != 0) return fail(c, .InvalidArgument);
        const raw = try c.arena.alloc(u8, t.len / 2);
        p.start_after = std.fmt.hexToBytes(raw, t) catch return fail(c, .InvalidArgument);
    }
    const fetch_owner = !v2 or if (try param(c, "fetch-owner")) |f| std.mem.eql(u8, f, "true") else false;
    const res = try c.svc.list(c.arena, c.route.bucket, p);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListBucketResult");
    try xml.elem(w, "Name", c.route.bucket);
    try keyElem(w, url, "Prefix", p.prefix);
    if (p.delimiter.len > 0) try keyElem(w, url, "Delimiter", p.delimiter);
    if (url) try xml.elem(w, "EncodingType", "url");
    if (v2) {
        if (token) |t| try xml.elem(w, "ContinuationToken", t);
        if (try param(c, "start-after")) |sa| try keyElem(w, url, "StartAfter", sa);
        try xml.elemInt(w, "KeyCount", res.contents.len + res.common_prefixes.len);
    } else {
        try keyElem(w, url, "Marker", p.start_after);
    }
    try xml.elemInt(w, "MaxKeys", p.max_keys);
    try xml.elemBool(w, "IsTruncated", res.is_truncated);
    if (res.is_truncated) if (res.next_marker) |m| {
        if (v2) {
            const hex = try c.arena.alloc(u8, m.len * 2);
            for (m, 0..) |byte, i| _ = std.fmt.bufPrint(hex[i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable; // 2 hex chars fit
            try xml.elem(w, "NextContinuationToken", hex);
        } else try keyElem(w, url, "NextMarker", m);
    };
    for (res.contents) |e| {
        var tb: [24]u8 = undefined;
        try w.writeAll("<Contents>");
        try keyElem(w, url, "Key", e.key);
        try xml.elem(w, "LastModified", core.time.iso8601(e.mtime_ns, &tb));
        var eb: [core.ETag.quoted_max]u8 = undefined;
        try xml.elem(w, "ETag", e.etag.quoted(&eb));
        try xml.elemInt(w, "Size", e.size);
        if (fetch_owner) try w.writeAll(owner_xml);
        try w.writeAll("<StorageClass>STANDARD</StorageClass></Contents>");
    }
    for (res.common_prefixes) |cp| {
        try w.writeAll("<CommonPrefixes>");
        try keyElem(w, url, "Prefix", cp);
        try w.writeAll("</CommonPrefixes>");
    }
    try w.writeAll("</ListBucketResult>");
    try respondXml(c, .ok, a.written());
}

pub const owner_xml = "<Owner><ID>zkfsm</ID><DisplayName>zkfsm</DisplayName></Owner>";

/// A key-like element, percent-encoded when the client asked for encoding-type=url.
pub fn keyElem(w: *std.Io.Writer, url: bool, name: []const u8, text: []const u8) std.Io.Writer.Error!void {
    if (!url) return xml.elem(w, name, text);
    try xml.open(w, name);
    for (text) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~', '/' => try w.writeByte(ch),
        else => try w.print("%{X:0>2}", .{ch}),
    };
    try xml.close(w, name);
}

test "keyElem url encoding" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try keyElem(&w, true, "Key", "a b+c/\xc3\xbc%");
    try std.testing.expectEqualStrings("<Key>a%20b%2Bc/%C3%BC%25</Key>", w.buffered());
}

fn putObject(c: *Ctx) DispatchError!void {
    if (c.copy_source) return fail(c, .NotImplemented);
    var body_buf: [io_buf_len]u8 = undefined;
    var check_buf: [io_buf_len]u8 = undefined;
    var br: sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&body_buf), &check_buf);
    br.limitTo(c.req.head.content_length);
    var in: object.PutInput = .{ .content_type = c.content_type, .content_length = br.contentLength(c.req.head.content_length) };
    if (!try versioning.putExtras(c, &in)) return;
    const info = c.svc.put(c.route.bucket, c.route.key, br.body(), in) catch |e| {
        if (br.failure) |code| return fail(c, code);
        return e;
    };
    var eb: [core.ETag.quoted_max]u8 = undefined;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.append(c.arena, .{ .name = "etag", .value = info.etag.quoted(&eb) });
    try versioning.putResponseHeaders(c, info, &hdrs);
    try respondEmpty(c, .ok, hdrs.items);
}

fn getObject(c: *Ctx) DispatchError!void {
    const info = try versioning.lookupForRead(c) orelse return;
    var range: ?core.Range = null;
    var parts_count: ?usize = null;
    if (try param(c, "partNumber")) |pn| {
        if (c.range != null) return fail(c, .InvalidRequest);
        const n = std.fmt.parseInt(u16, pn, 10) catch return fail(c, .InvalidArgument);
        const sel = partRange(info, n) catch return fail(c, if (n == 0) .InvalidArgument else .InvalidPartNumber);
        range = sel.range;
        parts_count = sel.count;
    } else if (c.range) |h| if (core.RangeSpec.parse(h)) |spec| {
        range = spec.resolve(info.size) catch {
            const cr = try std.fmt.allocPrint(c.arena, "bytes */{d}", .{info.size});
            return failWith(c, .InvalidRange, &.{.{ .name = "content-range", .value = cr }});
        };
    } else |_| {}; // malformed Range is ignored, as S3 does

    var eb: [core.ETag.quoted_max]u8 = undefined;
    const etag = info.etag.quoted(&eb);
    var db: [29]u8 = undefined;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "etag", .value = etag },
        .{ .name = "last-modified", .value = core.time.httpDate(info.created_ns, &db) },
        .{ .name = "accept-ranges", .value = "bytes" },
        .{ .name = "content-type", .value = if (info.content_type.len > 0) info.content_type else "binary/octet-stream" },
    });
    try versioning.objectHeaders(c, info, (try param(c, "versionId")) != null, &hdrs);
    if (c.method == .GET) try versioning.applyResponseOverrides(c, &hdrs);
    if (!try versioning.checkRead(c, info, etag, hdrs.items)) return;
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    if (parts_count) |n| try hdrs.append(c.arena, .{ .name = "x-amz-mp-parts-count", .value = try std.fmt.allocPrint(c.arena, "{d}", .{n}) });
    if (range) |r| try hdrs.append(c.arena, .{
        .name = "content-range",
        .value = try std.fmt.allocPrint(c.arena, "bytes {d}-{d}/{d}", .{ r.offset, r.last(), info.size }),
    });
    const len = if (range) |r| r.length else info.size;
    var out_buf: [io_buf_len]u8 = undefined;
    metrics.global.last_status = if (range != null) 206 else 200;
    var bw = try c.req.respondStreaming(&out_buf, .{
        .content_length = len,
        .respond_options = .{ .status = if (range != null) .partial_content else .ok, .extra_headers = hdrs.items },
    });
    if (bw.isEliding()) return bw.flush();
    // Headers are committed; a failure now can only abort the connection.
    c.svc.read(info, range, &bw.writer) catch return error.StreamAborted;
    try bw.end();
}

const PartSel = struct { range: ?core.Range, count: ?usize };

/// Byte range of part `n` (1-based). Single-part objects have only part 1: the whole object.
fn partRange(info: object.ObjectInfo, n: u16) error{InvalidPartNumber}!PartSel {
    const count = info.part_sizes.len / 8;
    // Parts describe the stored blob; transformed objects are served whole.
    if (count == 0 or info.logical_size != null) return if (n == 1) .{ .range = null, .count = null } else error.InvalidPartNumber;
    if (n == 0 or n > count) return error.InvalidPartNumber;
    var offset: u64 = 0;
    for (0..n - 1) |i| offset += object.partSize(info.part_sizes, i);
    const len = object.partSize(info.part_sizes, n - 1);
    if (len == 0) return .{ .range = null, .count = count };
    return .{ .range = .{ .offset = offset, .length = len }, .count = count };
}

pub fn respondXml(c: *Ctx, status: std.http.Status, body: []const u8) ConnError!void {
    return respondXmlWith(c, status, body, &.{});
}

pub fn respondXmlWith(c: *Ctx, status: std.http.Status, body: []const u8, extra: []const Header) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    try c.req.respond(body, .{ .status = status, .extra_headers = hdrs.items, .keep_alive = keepAlive(c) });
}

pub fn respondEmpty(c: *Ctx, status: std.http.Status, extra: []const Header) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    try c.req.respond("", .{ .status = status, .extra_headers = hdrs.items, .keep_alive = keepAlive(c) });
}

/// Close instead of draining an unread body: std asserts if the client hangs up mid-drain
/// (e.g. after `Expect: 100-continue` is refused), and a failed read leaves the state unknown.
fn keepAlive(c: *Ctx) bool {
    const r = &c.req.server.reader;
    if (r.state == .ready) return true;
    if (r.state != .received_head) return false;
    const h = c.req.head;
    return !h.method.requestHasBody() or (h.transfer_encoding == .none and (h.content_length orelse 0) == 0);
}

pub fn fail(c: *Ctx, code: Code) ConnError!void {
    return failWith(c, code, &.{});
}

pub fn failWith(c: *Ctx, code: Code, extra: []const Header) ConnError!void {
    metrics.global.last_status = @intFromEnum(code.status());
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const resource = std.mem.sliceTo(c.target, '?');
    errors.writeBody(&a.writer, code, resource, &c.request_id) catch return error.OutOfMemory;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    try c.req.respond(a.written(), .{ .status = code.status(), .extra_headers = hdrs.items, .keep_alive = keepAlive(c) });
}
