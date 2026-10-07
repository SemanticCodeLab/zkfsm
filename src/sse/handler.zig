//! Server-side encryption: SSE-S3, SSE-KMS and SSE-C on Put/Get/Head, multipart
//! uploads, CopyObject and UploadPartCopy, plus bucket default encryption.
//! SSE-S3/SSE-KMS need a KMS; storage layout: see README "Server-side encryption".
const std = @import("std");
const backend = @import("../backend/root.zig");
const core = @import("../core/root.zig");
const io = @import("../io/root.zig");
const metadata = @import("../metadata/root.zig");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const kms = @import("../kms/root.zig");
const common = @import("common.zig");

const sse = kms.sse;
const kstream = kms.stream;
const mp = object.multipart;
const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const DispatchError = s3.handler.DispatchError;
const Header = std.http.Header;
const ObjectInfo = object.ObjectInfo;
const Reader = std.Io.Reader;
const Md5 = std.crypto.hash.Md5;
const b64 = std.base64.standard;

/// Content-type prefix of the legacy envelope format (sealed key in the content
/// type). No longer written; such objects stay readable.
pub const marker = "application/x-zkfsm-sse-v1";
/// Multipart part table: comma-separated runs `<first part>:<ciphertext size>*<count>`.
pub const hdr_parts = object.internal_prefix ++ "sse-parts";
/// SSE-S3 PUT/copy bodies up to this size are buffered to compute the plaintext MD5 ETag.
pub const md5_buffer_limit = 8 * 1024 * 1024;

pub fn isEncrypted(info: ObjectInfo) bool {
    return isLegacy(info) or findHeader(info.internal, sse.hdr_scheme) != null;
}

fn isLegacy(info: ObjectInfo) bool {
    return std.mem.startsWith(u8, info.content_type, marker);
}

fn findHeader(hs: []const object.Header, name: []const u8) ?[]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

/// Legacy envelope: `marker;ct=<b64>;<Name>=<value>...` in the content type.
pub const Envelope = struct {
    content_type: []const u8,
    meta: []const sse.Header,

    pub const Error = error{ OutOfMemory, Invalid };

    pub fn encode(arena: std.mem.Allocator, content_type: []const u8, meta: []const sse.Header) Error![]const u8 {
        var a: std.Io.Writer.Allocating = .init(arena);
        const w = &a.writer;
        w.writeAll(marker ++ ";ct=") catch return error.OutOfMemory;
        b64.Encoder.encodeWriter(w, content_type) catch return error.OutOfMemory;
        for (meta) |h| {
            if (std.mem.indexOfAny(u8, h.value, ";\r\n") != null) return error.Invalid;
            w.print(";{s}={s}", .{ h.name, h.value }) catch return error.OutOfMemory;
        }
        return a.written();
    }

    pub fn decode(arena: std.mem.Allocator, s: []const u8) Error!Envelope {
        if (!std.mem.startsWith(u8, s, marker ++ ";")) return error.Invalid;
        var it = std.mem.splitScalar(u8, s[marker.len + 1 ..], ';');
        var list: std.ArrayList(sse.Header) = .empty;
        var ct: ?[]const u8 = null;
        while (it.next()) |part| {
            const eq = std.mem.indexOfScalar(u8, part, '=') orelse return error.Invalid;
            const name = part[0..eq];
            const value = part[eq + 1 ..];
            if (std.mem.eql(u8, name, "ct")) {
                const n = b64.Decoder.calcSizeForSlice(value) catch return error.Invalid;
                const out = try arena.alloc(u8, n);
                b64.Decoder.decode(out, value) catch return error.Invalid;
                ct = out;
            } else try list.append(arena, .{ .name = name, .value = value });
        }
        return .{ .content_type = ct orelse return error.Invalid, .meta = list.items };
    }
};

/// One independently encrypted DARE stream inside the stored blob. `part` 0 is a
/// single-part object (AAD = path); multipart segments bind their part number.
pub const Seg = struct { part: u16, plain: u64, ct_off: u64, ct_len: u64 };

/// How an encrypted object is stored: sealed-key headers, the caller's content
/// type, and the segment layout of its blob.
pub const Stored = struct {
    meta_headers: []const sse.Header,
    content_type: []const u8,
    segs: []const Seg,
    size: u64,
};

pub fn stored(arena: std.mem.Allocator, info: ObjectInfo) error{ OutOfMemory, Corrupt }!Stored {
    if (isLegacy(info)) {
        const env = Envelope.decode(arena, info.content_type) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Invalid => error.Corrupt,
        };
        const size = common.plainSize(info.blob_size) catch return error.Corrupt;
        const segs = try arena.dupe(Seg, &.{.{ .part = 0, .plain = size, .ct_off = 0, .ct_len = info.blob_size }});
        return .{ .meta_headers = env.meta, .content_type = env.content_type, .segs = segs, .size = size };
    }
    const segs = if (findHeader(info.internal, hdr_parts)) |t|
        try parseParts(arena, t)
    else
        try arena.dupe(Seg, &.{.{ .part = 0, .plain = common.plainSize(info.blob_size) catch return error.Corrupt, .ct_off = 0, .ct_len = info.blob_size }});
    var total: u64 = 0;
    for (segs) |s| total += s.plain;
    const last = segs[segs.len - 1];
    if (last.ct_off + last.ct_len != info.blob_size or total != info.size) return error.Corrupt;
    return .{ .meta_headers = try toSse(arena, info.internal), .content_type = info.content_type, .segs = segs, .size = total };
}

fn toSse(arena: std.mem.Allocator, hs: []const object.Header) error{OutOfMemory}![]sse.Header {
    const out = try arena.alloc(sse.Header, hs.len);
    for (hs, out) |h, *o| o.* = .{ .name = h.name, .value = h.value };
    return out;
}

fn toObject(arena: std.mem.Allocator, hs: []const sse.Header, extra: usize) error{OutOfMemory}![]object.Header {
    const out = try arena.alloc(object.Header, hs.len + extra);
    for (hs, out[0..hs.len]) |h, *o| o.* = .{ .name = h.name, .value = h.value };
    return out;
}

pub const PartSize = struct { number: u16, ct: u64 };

pub fn formatParts(arena: std.mem.Allocator, parts: []const PartSize) error{OutOfMemory}![]const u8 {
    var a: std.Io.Writer.Allocating = .init(arena);
    const w = &a.writer;
    var i: usize = 0;
    while (i < parts.len) {
        var n: usize = 1;
        while (i + n < parts.len and parts[i + n].ct == parts[i].ct and parts[i + n].number == parts[i].number + n) n += 1;
        w.print("{s}{d}:{d}*{d}", .{ if (i == 0) "" else ",", parts[i].number, parts[i].ct, n }) catch return error.OutOfMemory;
        i += n;
    }
    return a.written();
}

pub fn parseParts(arena: std.mem.Allocator, text: []const u8) error{ OutOfMemory, Corrupt }![]Seg {
    var list: std.ArrayList(Seg) = .empty;
    var off: u64 = 0;
    var prev: u32 = 0;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |run| {
        const colon = std.mem.indexOfScalar(u8, run, ':') orelse return error.Corrupt;
        const star = std.mem.indexOfScalarPos(u8, run, colon, '*') orelse return error.Corrupt;
        const first = std.fmt.parseInt(u32, run[0..colon], 10) catch return error.Corrupt;
        const ct = std.fmt.parseInt(u64, run[colon + 1 .. star], 10) catch return error.Corrupt;
        const plain = common.plainSize(ct) catch return error.Corrupt;
        const n = std.fmt.parseInt(u32, run[star + 1 ..], 10) catch return error.Corrupt;
        if (first <= prev or n == 0 or first + n - 1 > mp.max_part_number or ct > 1 << 40) return error.Corrupt;
        for (0..n) |i| {
            try list.append(arena, .{ .part = @intCast(first + i), .plain = plain, .ct_off = off, .ct_len = ct });
            off += ct;
        }
        prev = first + n - 1;
    }
    if (list.items.len == 0) return error.Corrupt;
    return list.items;
}

fn segAad(arena: std.mem.Allocator, path: []const u8, part: u16) error{OutOfMemory}![]const u8 {
    if (part == 0) return path;
    return std.fmt.allocPrint(arena, "{s}\x00part={d}", .{ path, part });
}

/// SSE-C headers of a request (target object or copy source).
pub const Customer = struct {
    algorithm: ?[]const u8 = null,
    key: ?[]const u8 = null,
    md5: ?[]const u8 = null,

    pub fn any(c: Customer) bool {
        return c.algorithm != null or c.key != null or c.md5 != null;
    }

    fn parse(c: Customer) sse.Error!sse.CustomerKey {
        return sse.parseCustomerKey(c.algorithm orelse "", c.key orelse "", c.md5 orelse "");
    }
};

/// SSE request headers, captured before the body is read.
pub const SseHeaders = struct {
    algorithm: ?[]const u8 = null,
    kms_key: ?[]const u8 = null,
    context: ?[]const u8 = null,
    customer: Customer = .{},
    copy_customer: Customer = .{},

    pub fn capture(c: *Ctx) error{OutOfMemory}!SseHeaders {
        var h: SseHeaders = .{};
        var it = c.req.iterateHeaders();
        const p = "x-amz-server-side-encryption";
        const cp = "x-amz-copy-source-server-side-encryption";
        while (it.next()) |x| {
            const fields = .{
                .{ p, &h.algorithm },                                         .{ p ++ "-aws-kms-key-id", &h.kms_key },
                .{ p ++ "-context", &h.context },                             .{ p ++ "-customer-algorithm", &h.customer.algorithm },
                .{ p ++ "-customer-key", &h.customer.key },                   .{ p ++ "-customer-key-md5", &h.customer.md5 },
                .{ cp ++ "-customer-algorithm", &h.copy_customer.algorithm }, .{ cp ++ "-customer-key", &h.copy_customer.key },
                .{ cp ++ "-customer-key-md5", &h.copy_customer.md5 },
            };
            inline for (fields) |f| if (std.ascii.eqlIgnoreCase(x.name, f[0])) {
                f[1].* = try c.arena.dupe(u8, x.value);
            };
        }
        return h;
    }

    pub fn any(h: SseHeaders) bool {
        return h.algorithm != null or h.kms_key != null or h.context != null or h.customer.any();
    }
};

pub const BucketConfig = struct { scheme: sse.Scheme, key_id: []const u8 = "" };

/// System-space record holding a bucket's default encryption; keyed by the
/// bucket id so a recreated bucket never inherits a stale config.
fn configKey(bid: core.BucketId) backend.PhysicalKey {
    var h: [32]u8 = undefined;
    var s = std.crypto.hash.sha2.Sha256.init(.{});
    s.update("zkfsm/sse-bucket-config/v1\x00");
    s.update(&bid.bytes);
    s.final(&h);
    return .{ .space = .system, .hex = std.fmt.bytesToHex(h[0..16].*, .lower) };
}

const subresources = [_][]const u8{ "tagging", "retention", "legal-hold", "acl", "attributes", "restore", "torrent", "select" };

const MpError = DispatchError || mp.Error || error{ MalformedXML, EntityTooLarge };

/// Plaintext MD5 handling for an encrypted write.
const Md5Mode = union(enum) { none, known: [16]u8, compute };

/// A resolved `x-amz-copy-source`.
const Source = struct { info: ObjectInfo, path: []const u8, version: ?core.VersionId };

pub const SseExt = struct {
    gpa: std.mem.Allocator,
    /// Null without a configured KMS; SSE-C still works.
    kms: ?kms.Kms,
    default_key: []const u8,
    mutex: std.Thread.Mutex = .{},

    pub fn extension(self: *SseExt) s3.Extension {
        return .{ .name = "sse", .ctx = self, .route = route };
    }

    fn route(ctx: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *SseExt = @ptrCast(@alignCast(ctx));
        return self.dispatch(c) catch |e| {
            try common.failObject(c, e);
            return true;
        };
    }

    fn dispatch(self: *SseExt, c: *Ctx) DispatchError!bool {
        const r = c.route;
        if (r.bucket.len == 0) return false;
        if (r.key.len == 0) {
            if (!try common.hasParam(c, "encryption")) return false;
            try self.bucketEncryption(c);
            return true;
        }
        if (try common.hasParam(c, "uploads") or try common.hasParam(c, "uploadId")) return self.multipart(c);
        for (subresources) |sr| if (try common.hasParam(c, sr)) return false;
        return switch (c.method) {
            .PUT => if (c.copy_source) self.copy(c) else self.put(c),
            .GET, .HEAD => self.get(c),
            else => false,
        };
    }

    fn noKms(c: *Ctx) ConnError!void {
        try common.failCustom(c, .not_implemented, "NotImplemented", "Server side encryption specified but KMS is not configured");
    }

    pub fn loadConfig(self: *SseExt, c: *Ctx, bucket: []const u8) DispatchError!?BucketConfig {
        _ = self;
        const bid = try c.svc.bucketId(bucket);
        const bytes = c.svc.store.getRecord(configKey(bid), c.arena) catch |e| switch (e) {
            error.NotFound => return null,
            else => return object.service.mapBackend(e),
        };
        const nl = std.mem.indexOfScalar(u8, bytes, '\n') orelse return error.Corrupt;
        const scheme = sse.Scheme.parse(bytes[0..nl]) orelse return error.Corrupt;
        if (scheme == .c) return error.Corrupt;
        return .{ .scheme = scheme, .key_id = bytes[nl + 1 ..] };
    }

    /// Explicit SSE headers, else the bucket default; false when neither applies.
    fn destination(self: *SseExt, c: *Ctx, h: *SseHeaders) DispatchError!bool {
        if (h.any()) return true;
        const cfg = try self.loadConfig(c, c.route.bucket) orelse return false;
        h.algorithm = cfg.scheme.wire();
        if (cfg.key_id.len > 0) h.kms_key = cfg.key_id;
        return true;
    }

    fn bucketEncryption(self: *SseExt, c: *Ctx) DispatchError!void {
        const bid = try c.svc.bucketId(c.route.bucket);
        const key = configKey(bid);
        switch (c.method) {
            .GET => {
                const cfg = try self.loadConfig(c, c.route.bucket) orelse
                    return common.failCustom(c, .not_found, "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found");
                var a: std.Io.Writer.Allocating = .init(c.arena);
                const w = &a.writer;
                try s3.xml.openRoot(w, "ServerSideEncryptionConfiguration");
                try w.writeAll("<Rule><ApplyServerSideEncryptionByDefault>");
                try s3.xml.elem(w, "SSEAlgorithm", cfg.scheme.wire());
                if (cfg.key_id.len > 0) try s3.xml.elem(w, "KMSMasterKeyID", cfg.key_id);
                try w.writeAll("</ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>");
                return s3.handler.respondXml(c, .ok, a.written());
            },
            .DELETE => {
                c.svc.store.deleteRecord(key) catch |e| switch (e) {
                    error.NotFound => {},
                    else => return object.service.mapBackend(e),
                };
                return s3.handler.respondEmpty(c, .no_content, &.{});
            },
            .PUT => {
                var rejected: ?s3.errors.Code = null;
                const body = common.readBody(c, 64 * 1024, &rejected) catch |e| switch (e) {
                    error.TooLarge => return s3.handler.fail(c, .MalformedXML),
                    error.Rejected => return s3.handler.fail(c, rejected.?),
                    else => |ce| return ce,
                };
                const algo = std.mem.trim(u8, s3.versioning.elemText(body, "SSEAlgorithm") orelse return s3.handler.fail(c, .MalformedXML), " \r\n\t");
                const scheme = sse.Scheme.parse(algo) orelse return s3.handler.fail(c, .MalformedXML);
                if (scheme == .c) return s3.handler.fail(c, .MalformedXML);
                const key_id = std.mem.trim(u8, s3.versioning.elemText(body, "KMSMasterKeyID") orelse "", " \r\n\t");
                if (key_id.len > 0 and (scheme != .kms or !kms.types.validKeyName(key_id))) return s3.handler.fail(c, .InvalidArgument);
                const rec = try std.fmt.allocPrint(c.arena, "{s}\n{s}", .{ scheme.wire(), key_id });
                c.svc.store.putRecord(key, rec) catch |e| return object.service.mapBackend(e);
                return s3.handler.respondEmpty(c, .ok, &.{});
            },
            else => return s3.handler.fail(c, .MethodNotAllowed),
        }
    }

    fn objectPath(c: *Ctx) error{OutOfMemory}![]const u8 {
        return std.fmt.allocPrint(c.arena, "{s}/{s}", .{ c.route.bucket, c.route.key });
    }

    fn rejectMarker(c: *Ctx) ConnError!bool {
        if (!std.mem.startsWith(u8, c.content_type, marker)) return false;
        try s3.handler.fail(c, .InvalidArgument);
        return true;
    }

    fn put(self: *SseExt, c: *Ctx) DispatchError!bool {
        if (try rejectMarker(c)) return true;
        var h = try SseHeaders.capture(c);
        const enc = self.destination(c, &h) catch |e| switch (e) {
            error.NoSuchBucket => return false,
            else => return e,
        };
        if (!enc) return false;
        const path = try objectPath(c);
        var nk = (try self.newKey(c, h, path)) orelse return true;
        defer nk.deinit(self.gpa);
        const meta = try decodeMeta(c, nk.headers);

        var body_buf: [s3.handler.io_buf_len]u8 = undefined;
        var check_buf: [s3.handler.io_buf_len]u8 = undefined;
        var br: s3.sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&body_buf), &check_buf);
        br.limitTo(c.req.head.content_length);
        const plain_len = br.contentLength(c.req.head.content_length) orelse {
            try common.failCustom(c, .length_required, "MissingContentLength", "You must provide the Content-Length HTTP header.");
            return true;
        };
        var in: object.PutInput = .{ .content_type = c.content_type, .internal = try toObject(c.arena, nk.headers, 0) };
        if (!try s3.versioning.putExtras(c, &in)) return true;
        const info = putEncrypted(c, c.route.bucket, c.route.key, br.body(), plain_len, &nk.dek, path, md5Mode(meta.scheme, null), in) catch |e| {
            if (br.failure) |code| {
                try s3.handler.fail(c, code);
                return true;
            }
            return e;
        };
        var eb: [core.ETag.quoted_max]u8 = undefined;
        var hdrs: std.ArrayList(Header) = .empty;
        try hdrs.append(c.arena, .{ .name = "etag", .value = info.etag.quoted(&eb) });
        try responseHeaders(c, meta, &hdrs);
        try s3.versioning.putResponseHeaders(c, info, &hdrs);
        try s3.handler.respondEmpty(c, .ok, hdrs.items);
        return true;
    }

    /// Fresh object key; null after writing an error response.
    fn newKey(self: *SseExt, c: *Ctx, h: SseHeaders, path: []const u8) DispatchError!?sse.NewObjectKey {
        if (h.customer.any()) {
            if (h.algorithm != null or h.kms_key != null or h.context != null) return badArg(c);
            var ck = h.customer.parse() catch return badArg(c);
            defer ck.deinit();
            return sse.newCustomerObjectKey(self.gpa, &ck, path) catch |e| switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => badArg(c),
            };
        }
        const scheme = sse.Scheme.parse(h.algorithm orelse return badArg(c)) orelse return badArg(c);
        if (scheme == .c) return badArg(c);
        if (scheme == .s3 and (h.kms_key != null or h.context != null)) return badArg(c);
        const k = self.kms orelse {
            try noKms(c);
            return null;
        };
        const key_id = h.kms_key orelse self.default_key;
        if (!kms.types.validKeyName(key_id)) return badArg(c);
        const pairs = parseContext(c.arena, h.context) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Invalid => return badArg(c),
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        return sse.newKmsObjectKey(self.gpa, k, scheme, key_id, path, pairs) catch |e| {
            try kmsFail(c, e);
            return null;
        };
    }

    fn get(self: *SseExt, c: *Ctx) DispatchError!bool {
        const version = s3.versioning.versionParam(c) catch return false;
        const info = object.versioning.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, version) catch return false;
        if (info.delete_marker or !isEncrypted(info)) return false;
        const h = try SseHeaders.capture(c);
        const path = try objectPath(c);
        var opened = (try self.openObject(c, info, h.customer, path)) orelse return true;
        defer std.crypto.secureZero(u8, &opened.dek);
        const size = opened.stored.size;

        var range: ?core.Range = null;
        if (c.range) |rh| if (core.RangeSpec.parse(rh)) |spec| {
            range = spec.resolve(size) catch {
                const cr = try std.fmt.allocPrint(c.arena, "bytes */{d}", .{size});
                try s3.handler.failWith(c, .InvalidRange, &.{.{ .name = "content-range", .value = cr }});
                return true;
            };
        } else |_| {};

        var eb: [core.ETag.quoted_max]u8 = undefined;
        const etag = info.etag.quoted(&eb);
        var db: [29]u8 = undefined;
        var hdrs: std.ArrayList(Header) = .empty;
        const ct = opened.stored.content_type;
        try hdrs.appendSlice(c.arena, &.{
            .{ .name = "etag", .value = etag },
            .{ .name = "last-modified", .value = core.time.httpDate(info.created_ns, &db) },
            .{ .name = "accept-ranges", .value = "bytes" },
            .{ .name = "content-type", .value = if (ct.len > 0) ct else "binary/octet-stream" },
        });
        try responseHeaders(c, opened.meta, &hdrs);
        try s3.versioning.objectHeaders(c, info, version != null, &hdrs);
        if (c.method == .GET) try s3.versioning.applyResponseOverrides(c, &hdrs);
        if (!try s3.versioning.checkRead(c, info, etag, hdrs.items)) return true;
        try hdrs.append(c.arena, .{ .name = "x-amz-request-id", .value = &c.request_id });
        if (range) |r| try hdrs.append(c.arena, .{
            .name = "content-range",
            .value = try std.fmt.allocPrint(c.arena, "bytes {d}-{d}/{d}", .{ r.offset, r.last(), size }),
        });
        const len = if (range) |r| r.length else size;
        var out_buf: [s3.handler.io_buf_len]u8 = undefined;
        var bw = try c.req.respondStreaming(&out_buf, .{
            .content_length = len,
            .respond_options = .{ .status = if (range != null) .partial_content else .ok, .extra_headers = hdrs.items },
        });
        if (bw.isEliding()) {
            try bw.flush();
            return true;
        }
        // Headers are committed; a failure now can only abort the connection.
        const plain = openPlain(c.arena, c.svc, info, &opened.dek, opened.stored.segs, path, if (range) |r| r.offset else 0, len) catch return error.StreamAborted;
        defer plain.deinit();
        plain.reader().streamExact64(&bw.writer, len) catch return error.StreamAborted;
        try bw.end();
        return true;
    }

    pub const Opened = struct {
        dek: [32]u8,
        meta: sse.SealedMeta,
        stored: Stored,
    };

    /// Recovers an encrypted object's key; null after writing an error response.
    pub fn openObject(self: *SseExt, c: *Ctx, info: ObjectInfo, cust: Customer, path: []const u8) DispatchError!?Opened {
        const st = stored(c.arena, info) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Corrupt => error.Corrupt,
        };
        const meta = try decodeMeta(c, st.meta_headers);
        const dek = (try self.unseal(c, meta, cust, path)) orelse return null;
        return .{ .dek = dek, .meta = meta, .stored = st };
    }

    /// DEK for sealed metadata bound to `path`; null after writing an error response.
    fn unseal(self: *SseExt, c: *Ctx, meta: sse.SealedMeta, cust: Customer, path: []const u8) DispatchError!?[32]u8 {
        if (meta.scheme == .c) {
            if (!cust.any()) {
                try common.failCustom(c, .bad_request, "InvalidRequest", "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.");
                return null;
            }
            var ck = cust.parse() catch {
                try s3.handler.fail(c, .InvalidArgument);
                return null;
            };
            defer ck.deinit();
            return sse.openCustomerObjectKey(meta, &ck, path) catch |e| switch (e) {
                error.WrongCustomerKey => {
                    try s3.handler.fail(c, .AccessDenied);
                    return null;
                },
                else => error.Corrupt,
            };
        }
        if (cust.any()) {
            try s3.handler.fail(c, .InvalidArgument);
            return null;
        }
        const k = self.kms orelse {
            try noKms(c);
            return null;
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        return sse.openKmsObjectKey(self.gpa, k, meta, path) catch |e| {
            try kmsFail(c, e);
            return null;
        };
    }

    // ---- CopyObject ----

    /// Resolves `x-amz-copy-source`; null lets the core report any problem.
    fn copySource(c: *Ctx) DispatchError!?Source {
        const raw = try common.header(c, "x-amz-copy-source") orelse return null;
        var version: ?core.VersionId = null;
        if (std.mem.indexOfScalar(u8, raw, '?')) |q| {
            const v = s3.router.queryParam(c.arena, raw[q + 1 ..], "versionId") catch return null;
            if (v) |vs| version = object.versioning.parseVersionId(vs) catch return null;
        }
        const path = std.Uri.percentDecodeInPlace(try c.arena.dupe(u8, std.mem.trimLeft(u8, std.mem.sliceTo(raw, '?'), "/")));
        const slash = std.mem.indexOfScalar(u8, path, '/') orelse return null;
        if (slash == 0 or slash + 1 == path.len) return null;
        const info = object.copy.resolveSource(c.svc, c.arena, .{ .bucket = path[0..slash], .key = path[slash + 1 ..], .version = version }) catch return null;
        return .{ .info = info, .path = path, .version = version };
    }

    fn copy(self: *SseExt, c: *Ctx) DispatchError!bool {
        return self.copyOp(c) catch |e| mpFail(c, e);
    }

    fn copyOp(self: *SseExt, c: *Ctx) MpError!bool {
        if (try rejectMarker(c)) return true;
        var h = try SseHeaders.capture(c);
        const explicit = h.any();
        const src = try copySource(c) orelse return false;
        const src_enc = isEncrypted(src.info);
        const enc = self.destination(c, &h) catch |e| switch (e) {
            error.NoSuchBucket => return false,
            else => return e,
        };
        if (!src_enc and !enc) {
            if (!h.copy_customer.any()) return false;
            try s3.handler.fail(c, .InvalidArgument);
            return true;
        }
        const directive = try common.header(c, "x-amz-metadata-directive");
        const tag_directive = try common.header(c, "x-amz-tagging-directive");
        const replace = isReplace(directive) orelse return badRequest(c);
        const replace_tags = isReplace(tag_directive) orelse return badRequest(c);
        const dst_path = try objectPath(c);
        // S3 allows a same-key copy only when it changes metadata or encryption.
        if (!replace and !explicit and src.version == null and std.mem.eql(u8, src.path, dst_path)) return badRequest(c);

        var sr = (try self.sourceReader(c, src, h.copy_customer, null)) orelse return true;
        defer sr.deinit();
        var in: object.PutInput = .{ .content_type = c.content_type };
        if (!try s3.versioning.putExtras(c, &in)) return true;
        if (!replace) {
            in.content_type = sr.content_type;
            in.metadata = src.info.metadata;
            in.system = src.info.system;
        }
        if (!replace_tags) in.tags = src.info.tags;

        var hdrs: std.ArrayList(Header) = .empty;
        const info = if (enc) blk: {
            var nk = (try self.newKey(c, h, dst_path)) orelse return true;
            defer nk.deinit(self.gpa);
            const meta = try decodeMeta(c, nk.headers);
            try responseHeaders(c, meta, &hdrs);
            in.internal = try toObject(c.arena, nk.headers, 0);
            break :blk try putEncrypted(c, c.route.bucket, c.route.key, sr.reader, sr.len, &nk.dek, dst_path, md5Mode(meta.scheme, plainMd5(src.info)), in);
        } else blk: {
            in.content_length = sr.len;
            break :blk try c.svc.put(c.route.bucket, c.route.key, sr.reader, in);
        };
        if (src.version) |v| try hdrs.append(c.arena, try versionHeader(c, "x-amz-copy-source-version-id", v));
        if (!info.version_id.eql(object.versioning.null_version_id)) try hdrs.append(c.arena, try versionHeader(c, "x-amz-version-id", info.version_id));
        try copyResult(c, "CopyObjectResult", info.etag, info.created_ns, hdrs.items);
        return true;
    }

    const SourceReader = struct {
        reader: *Reader,
        len: u64,
        content_type: []const u8,
        plain: ?*Plain,

        fn deinit(s: *SourceReader) void {
            if (s.plain) |p| p.deinit();
        }
    };

    /// Plaintext reader over a copy source (or an inclusive range of it); null
    /// after writing an error response.
    fn sourceReader(self: *SseExt, c: *Ctx, src: Source, cust: Customer, range: ?mp.CopyRange) MpError!?SourceReader {
        if (!isEncrypted(src.info)) {
            if (cust.any()) {
                try s3.handler.fail(c, .InvalidArgument);
                return null;
            }
            const off, const len = try clampRange(range, src.info.size);
            const obj = try c.arena.create(common.ObjectReader);
            obj.init(c.svc, src.info, off, len, try c.arena.alloc(u8, 4 * kstream.package_size));
            return .{ .reader = &obj.interface, .len = len, .content_type = src.info.content_type, .plain = null };
        }
        var opened = (try self.openObject(c, src.info, cust, src.path)) orelse return null;
        defer std.crypto.secureZero(u8, &opened.dek);
        const off, const len = try clampRange(range, opened.stored.size);
        const p = openPlain(c.arena, c.svc, src.info, &opened.dek, opened.stored.segs, src.path, off, len) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Corrupt,
        };
        return .{ .reader = p.reader(), .len = len, .content_type = opened.stored.content_type, .plain = p };
    }

    // ---- multipart ----

    fn multipart(self: *SseExt, c: *Ctx) DispatchError!bool {
        return self.multipartOp(c) catch |e| mpFail(c, e);
    }

    fn multipartOp(self: *SseExt, c: *Ctx) MpError!bool {
        const h = try SseHeaders.capture(c);
        if (try common.hasParam(c, "uploads")) return if (c.method == .POST) self.createUpload(c, h) else false;
        const id_s = try s3.handler.param(c, "uploadId") orelse return false;
        const id = mp.UploadId.parseHex(id_s) catch return false;
        const rec = mp.listParts(c.svc, c.arena, c.route.bucket, c.route.key, id) catch |e| switch (e) {
            error.NoSuchUpload, error.NoSuchBucket => return false,
            else => return e,
        };
        const up_hs = metadata.headers.decode(c.arena, rec.internal_meta) catch return error.Corrupt;
        const enc = findHeader(up_hs, sse.hdr_scheme) != null;
        return switch (c.method) {
            .PUT => self.uploadPart(c, h, id, if (enc) up_hs else null),
            .POST => if (enc) self.complete(c, id, rec, up_hs) else false,
            else => false,
        };
    }

    fn createUpload(self: *SseExt, c: *Ctx, h0: SseHeaders) MpError!bool {
        if (try rejectMarker(c)) return true;
        var h = h0;
        const enc = self.destination(c, &h) catch |e| switch (e) {
            error.NoSuchBucket => return false,
            else => return e,
        };
        if (!enc) return false;
        const path = try objectPath(c);
        var nk = (try self.newKey(c, h, path)) orelse return true;
        defer nk.deinit(self.gpa);
        const meta = try decodeMeta(c, nk.headers);
        var in: object.PutInput = .{ .content_type = c.content_type, .internal = try toObject(c.arena, nk.headers, 0) };
        if (!try s3.versioning.putExtras(c, &in)) return true;
        const id = try mp.create(c.svc, c.route.bucket, c.route.key, in);
        var a: std.Io.Writer.Allocating = .init(c.arena);
        const w = &a.writer;
        try s3.xml.openRoot(w, "InitiateMultipartUploadResult");
        try s3.xml.elem(w, "Bucket", c.route.bucket);
        try s3.xml.elem(w, "Key", c.route.key);
        try s3.xml.elem(w, "UploadId", &id.toHex());
        try w.writeAll("</InitiateMultipartUploadResult>");
        var hdrs: std.ArrayList(Header) = .empty;
        try responseHeaders(c, meta, &hdrs);
        try s3.handler.respondXmlWith(c, .ok, a.written(), hdrs.items);
        return true;
    }

    /// UploadPart / UploadPartCopy into an encrypted upload (`up_hs` set), or a
    /// part copied out of an encrypted source.
    fn uploadPart(self: *SseExt, c: *Ctx, h: SseHeaders, id: mp.UploadId, up_hs: ?[]const object.Header) MpError!bool {
        const src: ?Source = if (c.copy_source) try copySource(c) else null;
        const src_enc = if (src) |s| isEncrypted(s.info) else false;
        if (up_hs == null and !src_enc) {
            if (!h.customer.any() and !h.copy_customer.any()) return false;
            try s3.handler.fail(c, .InvalidArgument);
            return true;
        }
        const n_s = try s3.handler.param(c, "partNumber") orelse return error.InvalidPartNumber;
        const n = std.fmt.parseInt(u16, n_s, 10) catch return error.InvalidPartNumber;
        if (n == 0 or n > mp.max_part_number) return error.InvalidPartNumber;
        const path = try objectPath(c);

        var dek: ?[32]u8 = null;
        defer if (dek) |*d| std.crypto.secureZero(u8, d);
        var meta: ?sse.SealedMeta = null;
        if (up_hs) |hs| {
            meta = try decodeMeta(c, try toSse(c.arena, hs));
            dek = (try self.unseal(c, meta.?, h.customer, path)) orelse return true;
        } else if (h.customer.any()) {
            try s3.handler.fail(c, .InvalidArgument);
            return true;
        }

        var hdrs: std.ArrayList(Header) = .empty;
        if (meta) |m| try responseHeaders(c, m, &hdrs);
        if (src) |s| {
            var range: ?mp.CopyRange = null;
            if (try common.header(c, "x-amz-copy-source-range")) |rh| {
                const spec = core.RangeSpec.parse(rh) catch return error.InvalidPartNumber;
                if (spec != .from_to) return error.InvalidPartNumber;
                range = .{ .first = spec.from_to.first, .last = spec.from_to.last };
            }
            var sr = (try self.sourceReader(c, s, h.copy_customer, range)) orelse return true;
            defer sr.deinit();
            const etag = try partPut(c, id, n, sr.reader, sr.len, if (dek) |*d| d else null, path);
            try copyResult(c, "CopyPartResult", etag, core.time.nowNs(), hdrs.items);
            return true;
        }
        var body_buf: [s3.handler.io_buf_len]u8 = undefined;
        var check_buf: [s3.handler.io_buf_len]u8 = undefined;
        var br: s3.sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&body_buf), &check_buf);
        br.limitTo(c.req.head.content_length);
        const len = br.contentLength(c.req.head.content_length);
        const etag = partPut(c, id, n, br.body(), len, &dek.?, path) catch |e| {
            if (br.failure) |fc| {
                try s3.handler.fail(c, fc);
                return true;
            }
            return e;
        };
        var eb: [core.ETag.quoted_max]u8 = undefined;
        try hdrs.append(c.arena, .{ .name = "etag", .value = etag.quoted(&eb) });
        try s3.handler.respondEmpty(c, .ok, hdrs.items);
        return true;
    }

    /// Encrypted multipart complete: concatenates the per-part streams into one
    /// object whose part table, plaintext size and multipart ETag live in its record.
    fn complete(_: *SseExt, c: *Ctx, id: mp.UploadId, rec: mp.UploadRecord, up_hs: []const object.Header) MpError!bool {
        var rejected: ?s3.errors.Code = null;
        const body = common.readBody(c, 4 * 1024 * 1024, &rejected) catch |e| switch (e) {
            error.TooLarge => return error.EntityTooLarge,
            error.Rejected => {
                try s3.handler.fail(c, rejected.?);
                return true;
            },
            else => |ce| return ce,
        };
        const refs = try parseComplete(c.arena, body);
        if (refs.len == 0) return error.InvalidPartNumber;
        const segs = try c.arena.alloc(object.blob.Segment, refs.len);
        const plains = try c.arena.alloc(PartSize, refs.len);
        var etag_hash = Md5.init(.{});
        var prev: u16 = 0;
        var total_ct: u64 = 0;
        var total_plain: u64 = 0;
        for (refs, segs, plains, 0..) |r, *s, *pp, i| {
            if (r.number <= prev) return error.InvalidPartOrder;
            prev = r.number;
            const p = rec.findPart(r.number) orelse return error.InvalidPart;
            if (!std.mem.eql(u8, &p.md5, &r.md5)) return error.InvalidPart;
            const plain = common.plainSize(p.size) catch return error.Corrupt;
            if (i + 1 < refs.len and plain < mp.min_part_size) return error.EntityTooSmall;
            s.* = .{ .blob = p.blob, .offset = 0, .length = p.size };
            pp.* = .{ .number = r.number, .ct = p.size };
            etag_hash.update(&r.md5);
            total_ct += p.size;
            total_plain += plain;
        }
        var etag: core.ETag = .{ .md5 = undefined, .parts = @intCast(refs.len) };
        etag_hash.final(&etag.md5);

        const internal = try c.arena.alloc(object.Header, up_hs.len + 1);
        @memcpy(internal[0..up_hs.len], up_hs);
        internal[up_hs.len] = .{ .name = hdr_parts, .value = try formatParts(c.arena, plains) };
        const in: object.PutInput = .{
            .content_type = rec.content_type,
            .content_length = total_ct,
            .tags = rec.tags,
            .retention = if (rec.retention_mode != .none) .{ .mode = rec.retention_mode, .until_ns = rec.retain_until_ns } else null,
            .legal_hold = rec.legal_hold,
            .metadata = metadata.headers.decode(c.arena, rec.user_meta) catch return error.Corrupt,
            .internal = internal,
            .system = rec.system,
            .logical_size = total_plain,
            .etag_override = etag,
        };
        const buf = try c.arena.alloc(u8, 4 * kstream.package_size);
        var br = object.blob.BlobReader.init(c.svc.store, segs, buf);
        const info = c.svc.put(c.route.bucket, c.route.key, &br.reader, in) catch |e| switch (e) {
            error.ReadFailed => return if (br.err != null) error.NoSuchUpload else e,
            else => return e,
        };
        mp.abort(c.svc, c.route.bucket, c.route.key, id) catch {};

        var a: std.Io.Writer.Allocating = .init(c.arena);
        const w = &a.writer;
        var eb: [core.ETag.quoted_max]u8 = undefined;
        try s3.xml.openRoot(w, "CompleteMultipartUploadResult");
        try s3.xml.elem(w, "Location", std.mem.sliceTo(c.target, '?'));
        try s3.xml.elem(w, "Bucket", c.route.bucket);
        try s3.xml.elem(w, "Key", c.route.key);
        try s3.xml.elem(w, "ETag", info.etag.quoted(&eb));
        try w.writeAll("</CompleteMultipartUploadResult>");
        var hdrs: std.ArrayList(Header) = .empty;
        try responseHeaders(c, try decodeMeta(c, try toSse(c.arena, up_hs)), &hdrs);
        if (!info.version_id.eql(object.versioning.null_version_id)) try hdrs.append(c.arena, try versionHeader(c, "x-amz-version-id", info.version_id));
        try s3.handler.respondXmlWith(c, .ok, a.written(), hdrs.items);
        return true;
    }
};

/// Streams one part (encrypted when `dek` is set) into the upload.
fn partPut(c: *Ctx, id: mp.UploadId, n: u16, src: *Reader, len: ?u64, dek: ?*const [32]u8, path: []const u8) MpError!core.ETag {
    const key = dek orelse return mp.uploadPart(c.svc, c.route.bucket, c.route.key, id, n, src, len);
    const er = try c.arena.create(common.EncryptReader);
    er.init(src, key, try segAad(c.arena, path, n), try c.arena.alloc(u8, common.EncryptReader.min_buffer));
    defer er.deinit();
    const ct_len = if (len) |l| kstream.encryptedSize(l) else null;
    return mp.uploadPart(c.svc, c.route.bucket, c.route.key, id, n, &er.interface, ct_len) catch |e| {
        if (er.err != null) return error.StorageFailed;
        return e;
    };
}

/// Encrypts `src` (exactly `len` plaintext bytes) into bucket/key as one stream
/// bound to `aad`; sets the plaintext size and, per `md5`, the plaintext ETag.
fn putEncrypted(c: *Ctx, bucket: []const u8, key: []const u8, src0: *Reader, len: u64, dek: *const [32]u8, aad: []const u8, md5: Md5Mode, base: object.PutInput) DispatchError!ObjectInfo {
    var in = base;
    var src = src0;
    in.content_length = kstream.encryptedSize(len);
    in.logical_size = len;
    switch (md5) {
        .none => {},
        .known => |m| in.etag_override = .{ .md5 = m },
        // Without a core hook for post-stream overrides, the MD5 needs the whole body first.
        .compute => if (len <= md5_buffer_limit) {
            // Read exactly `len`: std.http bodies panic when read past their end.
            const data = try c.arena.alloc(u8, @intCast(len));
            src.readSliceAll(data) catch |e| return switch (e) {
                error.EndOfStream => error.IncompleteBody,
                error.ReadFailed => error.ReadFailed,
            };
            var d: [16]u8 = undefined;
            Md5.hash(data, &d, .{});
            in.etag_override = .{ .md5 = d };
            const fixed = try c.arena.create(Reader);
            fixed.* = .fixed(data);
            src = fixed;
        },
    }
    const er = try c.arena.create(common.EncryptReader);
    er.init(src, dek, aad, try c.arena.alloc(u8, common.EncryptReader.min_buffer));
    defer er.deinit();
    return c.svc.put(bucket, key, &er.interface, in) catch |e| {
        if (er.err != null) return error.StorageFailed;
        return e;
    };
}

/// S3 semantics: SSE-S3 ETags are the plaintext MD5; SSE-KMS and SSE-C ETags are
/// not (here: the ciphertext MD5), which also avoids a plaintext fingerprint.
fn md5Mode(scheme: sse.Scheme, known: ?[16]u8) Md5Mode {
    if (scheme != .s3) return .none;
    return if (known) |m| .{ .known = m } else .compute;
}

/// The source's plaintext MD5 when its ETag already is one.
fn plainMd5(info: ObjectInfo) ?[16]u8 {
    if (info.etag.parts != 0) return null;
    if (!isEncrypted(info)) return info.etag.md5;
    if (info.etag_override) |o| if (o.parts == 0) return o.md5;
    return null;
}

fn clampRange(range: ?mp.CopyRange, size: u64) mp.Error!struct { u64, u64 } {
    const r = range orelse return .{ 0, size };
    if (r.last < r.first or r.last >= size) return error.InvalidRange;
    return .{ r.first, r.last - r.first + 1 };
}

fn isReplace(directive: ?[]const u8) ?bool {
    const d = directive orelse return false;
    if (std.ascii.eqlIgnoreCase(d, "REPLACE")) return true;
    if (std.ascii.eqlIgnoreCase(d, "COPY")) return false;
    return null;
}

fn parseComplete(arena: std.mem.Allocator, body: []const u8) MpError![]mp.PartRef {
    const xr = s3.xml_read;
    var refs: std.ArrayList(mp.PartRef) = .empty;
    var sc: xr.Scanner = .{ .s = body };
    if (try sc.next("CompleteMultipartUpload") == null) return error.MalformedXML;
    sc.pos = 0;
    while (try sc.next("Part")) |part| {
        if (refs.items.len >= mp.max_part_number) return error.MalformedXML;
        var in: xr.Scanner = .{ .s = part };
        const num_s = (try in.next("PartNumber")) orelse return error.MalformedXML;
        in.pos = 0;
        const etag_s = try xr.unescape(arena, (try in.next("ETag")) orelse return error.MalformedXML);
        const num = std.fmt.parseInt(u16, std.mem.trim(u8, num_s, " \t\r\n"), 10) catch return error.MalformedXML;
        const hex = std.mem.trim(u8, etag_s, " \t\r\n\"");
        var md5: [16]u8 = undefined;
        if (hex.len != 32) return error.InvalidPart;
        _ = std.fmt.hexToBytes(&md5, hex) catch return error.InvalidPart;
        try refs.append(arena, .{ .number = num, .md5 = md5 });
    }
    return refs.items;
}

fn copyResult(c: *Ctx, root: []const u8, etag: core.ETag, mtime_ns: i128, extra: []const Header) ConnError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var tb: [24]u8 = undefined;
    var eb: [core.ETag.quoted_max]u8 = undefined;
    try s3.xml.openRoot(w, root);
    try s3.xml.elem(w, "LastModified", core.time.iso8601(mtime_ns, &tb));
    try s3.xml.elem(w, "ETag", etag.quoted(&eb));
    try s3.xml.close(w, root);
    try s3.handler.respondXmlWith(c, .ok, a.written(), extra);
}

fn versionHeader(c: *Ctx, name: []const u8, v: core.VersionId) error{OutOfMemory}!Header {
    const buf = try c.arena.create([32]u8);
    return .{ .name = name, .value = object.versioning.formatVersionId(v, buf) };
}

fn decodeMeta(c: *Ctx, hs: []const sse.Header) error{ OutOfMemory, Corrupt }!sse.SealedMeta {
    const scratch = try c.arena.alloc(u8, 2048);
    return sse.SealedMeta.decode(hs, scratch) catch error.Corrupt;
}

fn mpFail(c: *Ctx, e: MpError) ConnError!bool {
    return switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| ce,
        error.NoSuchUpload => failCode(c, .NoSuchUpload),
        error.InvalidPart => failCode(c, .InvalidPart),
        error.InvalidPartOrder => failCode(c, .InvalidPartOrder),
        error.EntityTooSmall => failCode(c, .EntityTooSmall),
        error.EntityTooLarge => failCode(c, .EntityTooLarge),
        error.MalformedXML => failCode(c, .MalformedXML),
        error.InvalidPartNumber => failCode(c, .InvalidArgument),
        error.InvalidRange => failCode(c, .InvalidRange),
        else => |oe| failCode(c, s3.errors.fromObject(oe)),
    };
}

fn failCode(c: *Ctx, code: s3.errors.Code) ConnError!bool {
    try s3.handler.fail(c, code);
    return true;
}

fn badRequest(c: *Ctx) ConnError!bool {
    return failCode(c, .InvalidRequest);
}

fn badArg(c: *Ctx) ConnError!?sse.NewObjectKey {
    try s3.handler.fail(c, .InvalidArgument);
    return null;
}

fn kmsFail(c: *Ctx, e: sse.KmsError) ConnError!void {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.KeyNotFound => common.failCustom(c, .bad_request, "KMS.NotFoundException", "The KMS key does not exist"),
        error.KeyDisabled => common.failCustom(c, .bad_request, "KMS.DisabledException", "The KMS key is disabled"),
        error.AccessDenied => s3.handler.fail(c, .AccessDenied),
        error.InvalidArgument => s3.handler.fail(c, .InvalidArgument),
        error.BackendUnavailable => common.failCustom(c, .service_unavailable, "KMS.KMSInternalException", "The KMS backend is unavailable"),
        else => s3.handler.fail(c, .InternalError),
    };
}

fn responseHeaders(c: *Ctx, meta: sse.SealedMeta, out: *std.ArrayList(Header)) error{OutOfMemory}!void {
    const p = "x-amz-server-side-encryption";
    switch (meta.scheme) {
        .s3 => try out.append(c.arena, .{ .name = p, .value = "AES256" }),
        .kms => try out.appendSlice(c.arena, &.{
            .{ .name = p, .value = "aws:kms" },
            .{ .name = p ++ "-aws-kms-key-id", .value = try c.arena.dupe(u8, meta.key_id) },
        }),
        .c => {
            const md5 = meta.key_md5 orelse return;
            const v = try c.arena.alloc(u8, b64.Encoder.calcSize(16));
            _ = b64.Encoder.encode(v, &md5);
            try out.appendSlice(c.arena, &.{
                .{ .name = p ++ "-customer-algorithm", .value = "AES256" },
                .{ .name = p ++ "-customer-key-MD5", .value = v },
            });
        },
    }
}

/// x-amz-server-side-encryption-context: base64 of a flat JSON string map.
fn parseContext(arena: std.mem.Allocator, header: ?[]const u8) error{ OutOfMemory, Invalid }![]const kms.Context.Pair {
    const h = header orelse return &.{};
    const n = b64.Decoder.calcSizeForSlice(h) catch return error.Invalid;
    const raw = try arena.alloc(u8, n);
    b64.Decoder.decode(raw, h) catch return error.Invalid;
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Invalid,
    };
    if (v != .object) return error.Invalid;
    const pairs = try arena.alloc(kms.Context.Pair, v.object.count());
    for (v.object.keys(), v.object.values(), pairs) |k, val, *p| {
        if (val != .string) return error.Invalid;
        p.* = .{ .key = k, .value = val.string };
    }
    return pairs;
}

pub const PlainError = error{ OutOfMemory, ReadFailed, Corrupt };

/// Decrypting reader over `len` plaintext bytes from `offset`, walking the
/// object's segments; each segment is a separate DARE stream with its own AAD.
pub const Plain = struct {
    svc: *object.ObjectService,
    info: ObjectInfo,
    arena: std.mem.Allocator,
    dek: [32]u8,
    path: []const u8,
    segs: []const Seg,
    idx: usize,
    left: u64,
    open: bool = false,
    obuf: []u8,
    obj: common.ObjectReader = undefined,
    dec: kstream.Decryptor = undefined,
    interface: Reader,

    pub fn reader(p: *Plain) *Reader {
        return &p.interface;
    }

    pub fn deinit(p: *Plain) void {
        if (p.open) p.dec.deinit();
        p.open = false;
        std.crypto.secureZero(u8, &p.dek);
    }

    fn openSeg(p: *Plain, off: u64) PlainError!void {
        const s = p.segs[p.idx];
        const aad = try segAad(p.arena, p.path, s.part);
        const first = off / kstream.package_size;
        if (first == 0) {
            p.obj.init(p.svc, p.info, s.ct_off, s.ct_len, p.obuf);
            p.dec.init(&p.obj.interface, &p.dek, aad);
        } else {
            var head: [kstream.stream_header_len]u8 = undefined;
            var hw: std.Io.Writer = .fixed(&head);
            p.svc.read(p.info, .{ .offset = s.ct_off, .length = head.len }, &hw) catch return error.ReadFailed;
            if (hw.end != head.len) return error.Corrupt;
            const start = kstream.packageOffset(first);
            if (start >= s.ct_len or first > std.math.maxInt(u32)) return error.Corrupt;
            p.obj.init(p.svc, p.info, s.ct_off + start, s.ct_len - start, p.obuf);
            p.dec.initAt(&p.obj.interface, &p.dek, aad, head, @intCast(first));
        }
        p.open = true;
        p.dec.reader().discardAll64(off - first * kstream.package_size) catch return error.ReadFailed;
    }

    /// Moves to the next segment; a missing one while bytes remain is corruption.
    fn advance(p: *Plain) Reader.Error!void {
        p.dec.deinit();
        p.open = false;
        p.idx += 1;
        if (p.idx == p.segs.len) return error.ReadFailed;
        p.openSeg(0) catch return error.ReadFailed;
    }

    fn stream(r: *Reader, w: *std.Io.Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const p: *Plain = @alignCast(@fieldParentPtr("interface", r));
        if (p.left == 0) return error.EndOfStream;
        const n = p.dec.reader().stream(w, limit.min(.limited64(p.left))) catch |e| switch (e) {
            error.EndOfStream => {
                try p.advance();
                return 0;
            },
            else => |x| return x,
        };
        p.left -= n;
        return n;
    }

    fn discard(r: *Reader, limit: std.Io.Limit) Reader.Error!usize {
        const p: *Plain = @alignCast(@fieldParentPtr("interface", r));
        if (p.left == 0) return error.EndOfStream;
        const n = p.dec.reader().discard(limit.min(.limited64(p.left))) catch |e| switch (e) {
            error.EndOfStream => {
                try p.advance();
                return 0;
            },
            else => |x| return x,
        };
        p.left -= n;
        return n;
    }
};

pub fn openPlain(arena: std.mem.Allocator, svc: *object.ObjectService, info: ObjectInfo, dek: *const [32]u8, segs: []const Seg, path: []const u8, offset: u64, len: u64) PlainError!*Plain {
    const p = try arena.create(Plain);
    p.* = .{
        .svc = svc,
        .info = info,
        .arena = arena,
        .dek = dek.*,
        .path = path,
        .segs = segs,
        .idx = 0,
        .left = len,
        .obuf = try arena.alloc(u8, 4 * kstream.package_size),
        .interface = .{ .vtable = &.{ .stream = Plain.stream, .discard = Plain.discard }, .buffer = try arena.alloc(u8, kstream.package_size), .seek = 0, .end = 0 },
    };
    if (len == 0) return p;
    var off = offset;
    while (p.idx < segs.len and off >= segs[p.idx].plain) : (p.idx += 1) off -= segs[p.idx].plain;
    if (p.idx == segs.len) {
        p.deinit();
        return error.Corrupt;
    }
    p.openSeg(off) catch |e| {
        p.deinit();
        return e;
    };
    return p;
}

test "legacy envelope round trip" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const meta = [_]sse.Header{ .{ .name = sse.hdr_scheme, .value = "AES256" }, .{ .name = sse.hdr_sealed, .value = "YWJj+/==" } };
    const s = try Envelope.encode(arena, "text/csv; charset=utf-8", &meta);
    try std.testing.expect(std.mem.startsWith(u8, s, marker));
    const e = try Envelope.decode(arena, s);
    try std.testing.expectEqualStrings("text/csv; charset=utf-8", e.content_type);
    try std.testing.expectEqual(@as(usize, 2), e.meta.len);
    try std.testing.expectEqualStrings("YWJj+/==", e.meta[1].value);
    const bad = [_]sse.Header{.{ .name = sse.hdr_key_id, .value = "a;b" }};
    try std.testing.expectError(error.Invalid, Envelope.encode(arena, "", &bad));
    try std.testing.expectError(error.Invalid, Envelope.decode(arena, "text/plain"));
}

test "part table runs" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const parts = [_]PartSize{ .{ .number = 1, .ct = 50 }, .{ .number = 2, .ct = 50 }, .{ .number = 3, .ct = 50 }, .{ .number = 5, .ct = 50 }, .{ .number = 6, .ct = 43 } };
    const t = try formatParts(a, &parts);
    try std.testing.expectEqualStrings("1:50*3,5:50*1,6:43*1", t);
    const segs = try parseParts(a, t);
    try std.testing.expectEqual(@as(usize, 5), segs.len);
    try std.testing.expectEqual(@as(u16, 5), segs[3].part);
    try std.testing.expectEqual(@as(u64, 150), segs[3].ct_off);
    try std.testing.expectEqual(@as(u64, 10), segs[3].plain);
    for ([_][]const u8{ "", "1:50", "2:50*1,1:50*1", "0:50*1", "1:50*0", "9999:50*5", "x:50*1", "1:10*1" }) |bad|
        try std.testing.expectError(error.Corrupt, parseParts(a, bad));
}

test "context header parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const pairs = try parseContext(arena_state.allocator(), "eyJkZXB0IjoiZmluIn0="); // {"dept":"fin"}
    try std.testing.expectEqual(@as(usize, 1), pairs.len);
    try std.testing.expectEqualStrings("fin", pairs[0].value);
    try std.testing.expectError(error.Invalid, parseContext(arena_state.allocator(), "e30"));
}

const TestStore = struct {
    tmp: std.testing.TmpDir,
    lb: backend.local.LocalBackend,
    svc: object.ObjectService,
    kms_mem: kms.keyring.MemoryStore,
    kr: kms.keyring.KeyringKms,

    fn init(self: *TestStore) !void {
        const gpa = std.testing.allocator;
        self.tmp = std.testing.tmpDir(.{});
        var pbuf: [std.fs.max_path_bytes]u8 = undefined;
        self.lb = try backend.local.LocalBackend.open(try self.tmp.dir.realpath(".", &pbuf));
        self.svc = try object.ObjectService.init(gpa, self.lb.backend());
        try self.svc.createBucket("bkt");
        self.kms_mem = .{ .gpa = gpa };
        self.kr = .{ .store = self.kms_mem.keyStore(), .kind = .local };
        var ki = try self.kr.kms().createKey(gpa, "k1");
        ki.deinit(gpa);
    }

    fn deinit(self: *TestStore) void {
        self.kms_mem.deinit();
        self.svc.deinit();
        self.lb.close();
        self.tmp.cleanup();
    }

    /// Head, unseal and decrypt `len` bytes from `off`.
    fn readBack(self: *TestStore, a: std.mem.Allocator, key: []const u8, off: u64, len: u64) ![]u8 {
        const info = try self.svc.head(a, "bkt", key);
        try std.testing.expect(isEncrypted(info));
        const st = try stored(a, info);
        var scratch: [2048]u8 = undefined;
        const meta = try sse.SealedMeta.decode(st.meta_headers, &scratch);
        const path = try std.fmt.allocPrint(a, "bkt/{s}", .{key});
        var dek = try sse.openKmsObjectKey(std.testing.allocator, self.kr.kms(), meta, path);
        const p = try openPlain(a, &self.svc, info, &dek, st.segs, path, off, len);
        defer p.deinit();
        return p.reader().allocRemaining(a, .unlimited);
    }
};

test "legacy content-type objects still decrypt, including ranges" {
    var ts: TestStore = undefined;
    try ts.init();
    defer ts.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const gpa = std.testing.allocator;
    const plain = try a.alloc(u8, 3 * kstream.package_size + 77);
    for (plain, 0..) |*x, i| x.* = @truncate(i *% 13);

    // Old writer: mixed-case names in a content-type envelope, no size override.
    var nk = try sse.newKmsObjectKey(gpa, ts.kr.kms(), .s3, "k1", "bkt/old", &.{});
    defer nk.deinit(gpa);
    const old = try a.alloc(sse.Header, nk.headers.len);
    for (nk.headers, old) |h, *o| o.* = .{ .name = try std.ascii.allocUpperString(a, h.name), .value = h.value };
    const ct = try kstream.encryptAlloc(a, &nk.dek, "bkt/old", plain);
    var src: Reader = .fixed(ct);
    _ = try ts.svc.put("bkt", "old", &src, .{ .content_type = try Envelope.encode(a, "text/csv", old) });

    const info = try ts.svc.head(a, "bkt", "old");
    const st = try stored(a, info);
    try std.testing.expectEqualStrings("text/csv", st.content_type);
    try std.testing.expectEqual(@as(u64, plain.len), st.size);
    try std.testing.expectEqualSlices(u8, plain, try ts.readBack(a, "old", 0, plain.len));
    const off = kstream.package_size + 5;
    try std.testing.expectEqualSlices(u8, plain[off..][0..70000], try ts.readBack(a, "old", off, 70000));
}

test "multipart layout decrypts across part boundaries" {
    var ts: TestStore = undefined;
    try ts.init();
    defer ts.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const gpa = std.testing.allocator;
    const sizes = [_]u64{ 2 * kstream.package_size, 2 * kstream.package_size + 9, 100 };
    var total: u64 = 0;
    for (sizes) |s| total += s;
    const plain = try a.alloc(u8, total);
    for (plain, 0..) |*x, i| x.* = @truncate(i *% 7 +% (i >> 11));

    var nk = try sse.newKmsObjectKey(gpa, ts.kr.kms(), .kms, "k1", "bkt/mp", &.{});
    defer nk.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    var parts: [sizes.len]PartSize = undefined;
    var off: usize = 0;
    for (sizes, 0..) |s, i| {
        const n: u16 = @intCast(i + 1);
        try blob.appendSlice(a, try kstream.encryptAlloc(a, &nk.dek, try segAad(a, "bkt/mp", n), plain[off..][0..s]));
        parts[i] = .{ .number = n, .ct = kstream.encryptedSize(s) };
        off += s;
    }
    const internal = try toObject(a, nk.headers, 1);
    internal[internal.len - 1] = .{ .name = hdr_parts, .value = try formatParts(a, &parts) };
    var src: Reader = .fixed(blob.items);
    _ = try ts.svc.put("bkt", "mp", &src, .{ .content_type = "x/y", .internal = internal, .logical_size = total });

    try std.testing.expectEqualSlices(u8, plain, try ts.readBack(a, "mp", 0, total));
    for ([_][2]u64{ .{ sizes[0] - 3, 10 }, .{ sizes[0] + kstream.package_size + 1, total - sizes[0] - kstream.package_size - 2 }, .{ total - 1, 1 }, .{ 5, total - 5 } }) |r|
        try std.testing.expectEqualSlices(u8, plain[r[0]..][0..r[1]], try ts.readBack(a, "mp", r[0], r[1]));

    // A segment bound to the wrong part number fails authentication.
    const info = try ts.svc.head(a, "bkt", "mp");
    const st = try stored(a, info);
    const shifted = try a.dupe(Seg, st.segs);
    for (shifted) |*s| s.part += 1;
    var scratch: [2048]u8 = undefined;
    var dek = try sse.openKmsObjectKey(gpa, ts.kr.kms(), try sse.SealedMeta.decode(st.meta_headers, &scratch), "bkt/mp");
    const p = try openPlain(a, &ts.svc, info, &dek, shifted, "bkt/mp", 0, total);
    defer p.deinit();
    try std.testing.expectError(error.ReadFailed, p.reader().allocRemaining(a, .unlimited));
}
