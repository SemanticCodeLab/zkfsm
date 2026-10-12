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
const restore = @import("restore.zig");
const tenancy = @import("tenancy.zig");
const cors = @import("cors.zig");
const website = @import("website.zig");
const access = @import("access.zig");
const extras = @import("bucket_extras.zig");
const postobject = @import("postobject.zig");
const attributes = @import("attributes.zig");
const checksums = @import("checksums.zig");

const Request = std.http.Server.Request;
const Header = std.http.Header;
const Code = errors.Code;

/// Errors that end the connection; S3-level failures become XML responses instead.
pub const ConnError = error{ WriteFailed, ReadFailed, HttpExpectationFailed, OutOfMemory, StreamAborted };

pub const io_buf_len = 64 * 1024;
const max_observed_headers = 64;
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
    env: authz.Env = .{},
    /// Tenant that buckets created by this caller belong to ("" = global).
    tenant: []const u8 = "",
    /// Connection peer and observer-visible state (events, audit).
    peer: ?std.net.Address = null,
    start_ns: i128 = 0,
    /// Request headers, copied before the body is read.
    req_headers: []const Header = &.{},
    /// Extra headers of the response written last.
    resp_headers: []const Header = &.{},
    host: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    acr_method: ?[]const u8 = null,
    acr_headers: ?[]const u8 = null,
    /// Added to every response (CORS headers).
    extra: []const Header = &.{},
    /// Status for a served object other than 200/206 (website error documents).
    status_override: ?std.http.Status = null,
    /// Request headers, copied (valid after the body is read).
    headers: []const Header = &.{},
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
        .peer = env.peer,
        .start_ns = std.time.nanoTimestamp(),
    };
    var hit = req.iterateHeaders();
    var copied: std.ArrayList(Header) = .empty;
    while (hit.next()) |h| {
        if (env.observers.len > 0 and copied.items.len < max_observed_headers)
            try copied.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
        if (std.ascii.eqlIgnoreCase(h.name, "host")) ctx.host = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "range")) ctx.range = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-copy-source")) ctx.copy_source = true;
        if (std.ascii.eqlIgnoreCase(h.name, "origin")) ctx.origin = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "access-control-request-method")) ctx.acr_method = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "access-control-request-headers")) ctx.acr_headers = try arena.dupe(u8, h.value);
        try ctx.ext.capture(arena, h);
    }
    ctx.req_headers = copied.items;
    for (env.observers) |o| o.begin(o.ctx, &ctx);
    defer for (env.observers) |o| o.end(o.ctx, &ctx, metrics.global.last_status);
    ctx.env = env;
    ctx.route = router.resolve(arena, env.routing, ctx.host, ctx.target) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidUri => return fail(&ctx, .InvalidURI),
        // Outside the base path: answer like an unknown bucket, before authentication.
        error.OutsidePrefix => return fail(&ctx, .NoSuchBucket),
    };
    if (ctx.route.website) return website.serve(&ctx);
    if (try cors.preflight(&ctx)) return;
    try cors.prepare(&ctx);
    var in = try sigv4.Input.fromRequest(arena, req);
    ctx.headers = in.headers;
    if (try postobject.handle(&ctx)) return;
    const now_s = std.time.timestamp();
    if (ctx.route.vhost) in.vhost_bucket = ctx.route.bucket;
    try sts.prepare(&ctx, &in);
    switch (try sigv4.verify(arena, env.auth, in, now_s)) {
        .ok => |a| ctx.auth = a,
        .denied => |code| return fail(&ctx, code),
    }
    if (try sts.route(&ctx, env, now_s)) return;
    // STS-scoped signatures are only valid for STS calls.
    if (std.mem.eql(u8, ctx.auth.scope.service, "sts") or std.mem.eql(u8, ctx.auth.scope.service, "s3tables")) return fail(&ctx, .AccessDenied);
    for (env.extensions) |x| if (x.before_authz and try x.route(x.ctx, &ctx)) return;
    const ar: authz.Request = .{ .method = ctx.method, .bucket = ctx.route.bucket, .key = ctx.route.key, .query = ctx.route.query, .copy_source = ctx.copy_source };
    if (!try authorize(&ctx, ar, now_s)) return;
    for (env.extensions) |x| if (!x.before_authz and try x.route(x.ctx, &ctx)) return;
    try runBuiltin(&ctx);
}

/// Tenant boundary, IAM and bucket policy, then ACLs; false after answering with an error.
pub fn authorize(c: *Ctx, request: authz.Request, now_s: i64) ConnError!bool {
    const env = c.env;
    var ar = request;
    var tbuf: tenancy.NameBuf = undefined;
    const caller_tenant = tenancy.callerTenant(env.auth, c.auth, &tbuf);
    if (caller_tenant) |t| {
        if (!tenancy.tenantActive(env.auth, t)) return denyWith(c, .AccessDenied);
        c.tenant = try c.arena.dupe(u8, t);
    }
    if (env.auth.iam != null and ar.bucket.len > 0) {
        if (object.tenancy.access(c.svc, c.arena, ar.bucket)) |acc| {
            if (!tenancy.mayReach(env.auth, c.auth, caller_tenant, acc.tenant)) return denyWith(c, .AccessDenied);
            ar.bucket_policy = acc.policy;
        } else |e| if (e == error.OutOfMemory) return error.OutOfMemory;
        access.restrictPolicy(c, &ar) catch |e| {
            try failDispatch(c, e);
            return false;
        };
    }
    ar.extra = access.conditionKeys(c, ar) catch |e| {
        try failDispatch(c, e);
        return false;
    };
    switch (try authz.decide(c.arena, env, c.auth, ar, now_s)) {
        .allow => return expectedOwnerOk(c),
        .explicit_deny => return denyWith(c, .AccessDenied),
        .implicit_deny => {},
    }
    const v = access.fallback(c, ar, now_s) catch |e| {
        try failDispatch(c, e);
        return false;
    };
    return switch (v) {
        .allow => expectedOwnerOk(c),
        .deny => |code| denyWith(c, code),
    };
}

/// `x-amz-expected-bucket-owner` must name the bucket's owner.
fn expectedOwnerOk(c: *Ctx) ConnError!bool {
    if (c.route.bucket.len == 0) return true;
    for (c.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-amz-expected-bucket-owner")) {
        const owner = (acl.bucketAcl(c.svc, c.arena, c.route.bucket) catch |e| {
            try failDispatch(c, e);
            return false;
        }).owner;
        if (!std.mem.eql(u8, std.mem.trim(u8, h.value, " "), owner)) return denyWith(c, .AccessDenied);
    };
    return true;
}

fn denyWith(c: *Ctx, code: Code) ConnError!bool {
    try fail(c, code);
    return false;
}

/// Answers a dispatch-level error (connection errors pass through).
pub fn failDispatch(c: *Ctx, e: DispatchError) ConnError!void {
    return switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| ce,
        else => |oe| fail(c, errors.fromObject(oe)),
    };
}

/// Whether an anonymous GET of `key` would be allowed (website endpoint).
pub fn anonymousMayRead(c: *Ctx, key: []const u8) DispatchError!bool {
    return access.anonymousMayRead(c, key);
}

/// Built-in S3 dispatch; lets an extension wrap the standard handling of a request.
pub fn runBuiltin(ctx: *Ctx) ConnError!void {
    if (try multipart.handle(ctx)) return;
    dispatch(ctx) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => |oe| return fail(ctx, errors.fromObject(oe)),
    };
}

pub const DispatchError = ConnError || object.Error;

fn dispatch(c: *Ctx) DispatchError!void {
    const r = c.route;
    if (r.bucket.len == 0) return switch (c.method) {
        .GET => listBuckets(c),
        else => fail(c, .MethodNotAllowed),
    };
    if (try lifecycle.route(c) or try policy.route(c) or try acl.route(c) or try restore.route(c)) return;
    if (try cors.route(c) or try website.route(c) or try extras.route(c) or try attributes.route(c)) return;
    if (r.key.len == 0 and c.method == .PUT and !try acl.checkCreateHeaders(c)) return;
    if (try versioning.route(c)) return;
    if (r.key.len == 0) return switch (c.method) {
        .PUT => createBucket(c),
        .DELETE => {
            const bid = try c.svc.bucketId(r.bucket);
            try c.svc.deleteBucket(r.bucket);
            object.bucket_meta.dropAll(c.svc, bid);
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
    if (c.method == .GET and (try param(c, "torrent")) != null) return fail(c, .NoSuchKey);
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
    const all = try tenancy.visibleBuckets(c.svc, c.arena, c.env.auth, c.auth);
    std.mem.sort(object.BucketInfo, all, {}, struct {
        fn lt(_: void, x: object.BucketInfo, y: object.BucketInfo) bool {
            return std.mem.order(u8, x.name, y.name) == .lt;
        }
    }.lt);
    const prefix = (try param(c, "prefix")) orelse "";
    const after = (try param(c, "continuation-token")) orelse "";
    var max: usize = std.math.maxInt(usize);
    if (try param(c, "max-buckets")) |m| {
        max = std.fmt.parseInt(usize, m, 10) catch return fail(c, .InvalidArgument);
        if (max == 0 or max > 10000) return fail(c, .InvalidArgument);
    }
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ListAllMyBucketsResult");
    try w.writeAll(owner_xml ++ "<Buckets>");
    var shown: usize = 0;
    var next: ?[]const u8 = null;
    for (all) |b| {
        if (!std.mem.startsWith(u8, b.name, prefix)) continue;
        if (after.len > 0 and std.mem.order(u8, b.name, after) != .gt) continue;
        if (shown == max) break;
        var tb: [24]u8 = undefined;
        try w.writeAll("<Bucket>");
        try xml.elem(w, "Name", b.name);
        try xml.elem(w, "CreationDate", core.time.iso8601(b.created_ns, &tb));
        try w.writeAll("</Bucket>");
        shown += 1;
        next = b.name;
    }
    try w.writeAll("</Buckets>");
    if (shown == max and next != null and hasMore(all, prefix, next.?)) try xml.elem(w, "ContinuationToken", next.?);
    if (prefix.len > 0) try xml.elem(w, "Prefix", prefix);
    try w.writeAll("</ListAllMyBucketsResult>");
    try respondXml(c, .ok, a.written());
}

fn hasMore(all: []const object.BucketInfo, prefix: []const u8, last: []const u8) bool {
    for (all) |b| if (std.mem.startsWith(u8, b.name, prefix) and std.mem.order(u8, b.name, last) == .gt) return true;
    return false;
}

/// CreateBucket. Re-creating a bucket the caller already owns succeeds (us-east-1 semantics).
fn createBucket(c: *Ctx) DispatchError!void {
    const who = acl.callerOf(c.env.auth, c.auth);
    var hdrs: [1]Header = .{.{ .name = "location", .value = std.mem.sliceTo(c.target, '?') }};
    const body = try versioning.readBodyMax(c, 64 * 1024) orelse return;
    const location: ?[]const u8 = if (versioning.elemText(body, "LocationConstraint")) |l| (if (l.len > 0) l else null) else null;
    object.tenancy.createOwned(c.svc, c.route.bucket, c.tenant) catch |e| switch (e) {
        error.BucketAlreadyExists => {
            const cur = try acl.bucketAcl(c.svc, c.arena, c.route.bucket);
            const tenant = object.tenancy.tenantOf(c.svc, c.arena, c.route.bucket) catch "";
            if (!std.mem.eql(u8, cur.owner, who.id) or !std.mem.eql(u8, tenant, c.tenant)) return fail(c, .BucketAlreadyExists);
            // Only a plain re-create is a no-op; one that would change the ACL conflicts.
            if (c.ext.acl.present() or cur.grants.len > 1 or cur.isPublic()) return fail(c, .BucketAlreadyExists);
            return respondEmpty(c, .ok, &hdrs);
        },
        else => return e,
    };
    try acl.onBucketCreated(c, who);
    try extras.applyCreateOwnership(c, c.ext.object_ownership);
    if (location) |l| try object.bucket_meta.set(c.svc, c.route.bucket, .location, l);
    try respondEmpty(c, .ok, &hdrs);
}

fn getLocation(c: *Ctx) DispatchError!void {
    const loc = try object.bucket_meta.get(c.svc, c.arena, c.route.bucket, .location) orelse "";
    var a: std.Io.Writer.Allocating = .init(c.arena);
    try a.writer.writeAll(xml.declaration ++ "<LocationConstraint xmlns=\"" ++ xml.s3_ns ++ "\">");
    try xml.escape(&a.writer, loc);
    try a.writer.writeAll("</LocationConstraint>");
    try respondXml(c, .ok, a.written());
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
    const truncated = res.is_truncated and p.max_keys > 0;
    try xml.elemBool(w, "IsTruncated", truncated);
    if (truncated) if (res.next_marker) |m| {
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
        try xml.elem(w, "StorageClass", try storageClass(c, e));
        try w.writeAll("</Contents>");
    }
    for (res.common_prefixes) |cp| {
        try w.writeAll("<CommonPrefixes>");
        try keyElem(w, url, "Prefix", cp);
        try w.writeAll("</CommonPrefixes>");
    }
    try w.writeAll("</ListBucketResult>");
    try respondXml(c, .ok, a.written());
}

/// Tier name for tiered entries (one record read each), else STANDARD.
pub fn storageClass(c: *Ctx, e: object.list.Entry) error{OutOfMemory}![]const u8 {
    if (!e.tiered) return "STANDARD";
    const info = object.versioning.headVersion(c.svc, c.arena, c.route.bucket, e.key, null) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => "STANDARD",
    };
    return if (info.tier.len > 0) info.tier else "STANDARD";
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
    if (!try checksums.checkHeaders(c)) return;
    var body_buf: [io_buf_len]u8 = undefined;
    var check_buf: [io_buf_len]u8 = undefined;
    var br: sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&body_buf), &check_buf);
    br.limitTo(c.req.head.content_length);
    var in: object.PutInput = .{ .content_type = c.content_type, .content_length = br.contentLength(c.req.head.content_length) };
    if (!try versioning.putExtras(c, &in)) return;
    var ck_buf: [io_buf_len]u8 = undefined;
    var ver = checksums.Verifier.init(c.ext.checksum, br.body(), &br, &ck_buf);
    var source = br.body();
    var stored_value: []u8 = "";
    if (ver) |*v| {
        v.expect_len = in.content_length;
        source = &v.reader;
        // Filled in once the body is read (put encodes internal headers after the body).
        const prefix = try std.fmt.allocPrint(c.arena, "{s}:FULL_OBJECT:", .{v.alg.wireName()});
        stored_value = try c.arena.alloc(u8, prefix.len + v.alg.base64Len());
        @memcpy(stored_value[0..prefix.len], prefix);
        @memset(stored_value[prefix.len..], 'A');
        var list: std.ArrayList(object.Header) = .empty;
        try list.appendSlice(c.arena, in.internal);
        try list.append(c.arena, .{ .name = checksums.stored_header, .value = stored_value });
        in.internal = list.items;
        v.slot = stored_value;
        if (v.finishEmpty()) |code| return fail(c, code);
    }
    const info = c.svc.put(c.route.bucket, c.route.key, source, in) catch |e| {
        if (br.failure) |code| return fail(c, code);
        if (ver) |v| if (v.failure) |code| return fail(c, code);
        return e;
    };
    var eb: [core.ETag.quoted_max]u8 = undefined;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.append(c.arena, .{ .name = "etag", .value = info.etag.quoted(&eb) });
    if (ver) |*v| {
        try hdrs.append(c.arena, .{ .name = v.alg.headerName(), .value = try c.arena.dupe(u8, v.text()) });
        try hdrs.append(c.arena, .{ .name = "x-amz-checksum-type", .value = "FULL_OBJECT" });
    }
    try versioning.putResponseHeaders(c, info, &hdrs);
    try respondEmpty(c, .ok, hdrs.items);
}

/// GET/HEAD of `c.route.key` (website endpoint documents included).
pub fn serveObject(c: *Ctx) DispatchError!void {
    return getObject(c);
}

fn getObject(c: *Ctx) DispatchError!void {
    const info = try versioning.lookupForRead(c) orelse return;
    var range: ?core.Range = null;
    var parts_count: ?usize = null;
    var part_n: ?u16 = null;
    if (try param(c, "partNumber")) |pn| {
        if (c.range != null) return fail(c, .InvalidRequest);
        const n = std.fmt.parseInt(u16, pn, 10) catch return fail(c, .InvalidArgument);
        part_n = n;
        const sel = partRange(info, n) catch return fail(c, if (n == 0) .InvalidArgument else .InvalidPart);
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
    if (c.ext.checksum.mode_enabled and (range == null or parts_count != null))
        try checksums.responseHeaders(c, info, if (parts_count != null) part_n else null, &hdrs);
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    try hdrs.appendSlice(c.arena, c.extra);
    if (parts_count) |n| try hdrs.append(c.arena, .{ .name = "x-amz-mp-parts-count", .value = try std.fmt.allocPrint(c.arena, "{d}", .{n}) });
    if (range) |r| try hdrs.append(c.arena, .{
        .name = "content-range",
        .value = try std.fmt.allocPrint(c.arena, "bytes {d}-{d}/{d}", .{ r.offset, r.last(), info.size }),
    });
    c.resp_headers = hdrs.items;
    const len = if (range) |r| r.length else info.size;
    var out_buf: [io_buf_len]u8 = undefined;
    const st: std.http.Status = c.status_override orelse if (range != null) .partial_content else .ok;
    metrics.global.last_status = @intFromEnum(st);
    const opts: std.http.Server.Request.RespondStreamingOptions = .{
        .content_length = len,
        .respond_options = .{ .status = st, .extra_headers = hdrs.items },
    };
    if (c.method != .GET) {
        var bw = try c.req.respondStreaming(&out_buf, opts);
        return bw.flush();
    }
    // Headers go out with the first body byte, so a read that fails before any data
    // (e.g. storage quorum lost) still gets a proper error response.
    var lazy: LazyBody = .{ .req = c.req, .buf = &out_buf, .opts = opts };
    c.svc.read(info, range, &lazy.writer) catch |e| {
        if (lazy.bw != null) return error.StreamAborted;
        return fail(c, errors.fromObject(e));
    };
    const bw = lazy.begin() catch return error.WriteFailed;
    try bw.end();
}

/// A body writer that commits the response head on its first write.
const LazyBody = struct {
    req: *Request,
    buf: []u8,
    opts: std.http.Server.Request.RespondStreamingOptions,
    bw: ?std.http.BodyWriter = null,
    writer: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } },

    fn begin(self: *LazyBody) std.Io.Writer.Error!*std.http.BodyWriter {
        if (self.bw == null) self.bw = self.req.respondStreaming(self.buf, self.opts) catch return error.WriteFailed;
        return &self.bw.?;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *LazyBody = @fieldParentPtr("writer", w);
        const bw = try self.begin();
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try bw.writer.writeAll(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try bw.writer.writeAll(last);
        return n + last.len * splat;
    }
};

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
    return respondBody(c, status, body, "application/xml", extra);
}

pub fn respondBody(c: *Ctx, status: std.http.Status, body: []const u8, content_type: []const u8, extra: []const Header) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, c.extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = content_type },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    c.resp_headers = hdrs.items;
    try c.req.respond(body, .{ .status = status, .extra_headers = hdrs.items, .keep_alive = keepAlive(c) });
}

pub fn respondEmpty(c: *Ctx, status: std.http.Status, extra: []const Header) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, c.extra);
    try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
    c.resp_headers = hdrs.items;
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
    // Refusing before reading the body: no `100 Continue` (the connection then closes).
    if (c.req.server.reader.state == .received_head) c.req.head.expect = null;
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const resource = std.mem.sliceTo(c.target, '?');
    errors.writeBody(&a.writer, code, resource, &c.request_id) catch return error.OutOfMemory;
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(c.arena, extra);
    try hdrs.appendSlice(c.arena, c.extra);
    try hdrs.appendSlice(c.arena, &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    });
    c.resp_headers = hdrs.items;
    // HEAD responses carry no body.
    const body = if (c.method == .HEAD) "" else a.written();
    try c.req.respond(body, .{ .status = code.status(), .extra_headers = hdrs.items, .keep_alive = keepAlive(c) });
}
