//! Remote S3 provider (AWS S3, MinIO, GCS XML interop): SigV4 header auth,
//! multipart upload for large puts, ranged gets with resume, ListObjectsV2 paging,
//! retries with exponential backoff and jitter.
const std = @import("std");
const iface = @import("root.zig");
const remote = @import("remote.zig");
const sign = @import("s3/sign.zig");
const rhttp = @import("remote/http.zig");
const xml = @import("remote/xml.zig");

const Error = iface.Error;
const ObjectMeta = iface.ObjectMeta;
const PutError = remote.PutError;
const Writer = std.Io.Writer;
const log = std.log.scoped(.s3_backend);

pub const Credentials = sign.Credentials;
pub const RetryPolicy = rhttp.RetryPolicy;

pub const MiB = 1024 * 1024;
pub const min_part_size = 5 * MiB;
pub const max_part_size = 5 * 1024 * MiB;
pub const max_parts = 10_000;

pub const Addressing = enum { path, virtual_host };
pub const PayloadSigning = enum {
    /// SHA-256 of each buffered body goes into the signature.
    signed,
    /// `UNSIGNED-PAYLOAD`; cheaper, relies on TLS for integrity.
    unsigned,
};

pub const Config = struct {
    /// Scheme, host and port, e.g. "https://s3.eu-west-1.amazonaws.com".
    endpoint: []const u8,
    region: []const u8 = "us-east-1",
    bucket: []const u8,
    /// Object name prefix; empty or ending in '/'.
    prefix: []const u8 = "",
    credentials: Credentials,
    addressing: Addressing = .path,
    /// Puts larger than this use multipart upload; also the per-put buffer size.
    part_size: usize = 16 * MiB,
    payload: PayloadSigning = .signed,
    /// Server honours `If-None-Match: *` on PUT and CompleteMultipartUpload.
    conditional_write: bool = true,
    retry: RetryPolicy = .{},
    list_page_size: u16 = 1000,
    /// SigV4 service name in the credential scope.
    service: []const u8 = "s3",
};

pub const InitError = error{ InvalidConfig, OutOfMemory };

/// Bucket names are restricted to DNS-safe characters so they never need encoding.
fn validBucket(b: []const u8) bool {
    if (b.len < 3 or b.len > 63) return false;
    for (b) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '-' or c == '.' or c == '_')) return false;
    return true;
}

pub const S3Client = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    endpoint: rhttp.Endpoint,
    http: std.http.Client,

    pub fn init(gpa: std.mem.Allocator, cfg: Config) InitError!S3Client {
        const ep = rhttp.Endpoint.parse(cfg.endpoint) catch return error.InvalidConfig;
        if (!validBucket(cfg.bucket)) return error.InvalidConfig;
        if (cfg.prefix.len > 0 and cfg.prefix[cfg.prefix.len - 1] != '/') return error.InvalidConfig;
        if (cfg.part_size < min_part_size or cfg.part_size > max_part_size) return error.InvalidConfig;
        if (cfg.list_page_size == 0 or cfg.region.len == 0) return error.InvalidConfig;
        if (cfg.addressing == .virtual_host and std.mem.indexOfScalar(u8, cfg.bucket, '.') != null and ep.tls)
            return error.InvalidConfig; // dotted buckets break wildcard TLS certs
        return .{ .gpa = gpa, .cfg = cfg, .endpoint = ep, .http = .{ .allocator = gpa } };
    }

    pub fn deinit(self: *S3Client) void {
        self.http.deinit();
    }

    pub fn capabilities(self: *const S3Client) iface.Capabilities {
        return .{
            .durable_sync = true,
            .range_read = true,
            .multipart_native = true,
            .conditional_write = self.cfg.conditional_write,
        };
    }

    pub fn provider(self: *S3Client) remote.Provider {
        return .{ .ctx = self, .capabilities = self.capabilities(), .vtable = &provider_vtable };
    }

    const provider_vtable: remote.Provider.VTable = .{
        .put = putCb,
        .get = getCb,
        .head = headCb,
        .delete = deleteCb,
        .list = listCb,
    };

    fn from(ctx: *anyopaque) *S3Client {
        return @ptrCast(@alignCast(ctx));
    }
    fn putCb(ctx: *anyopaque, name: []const u8, src: *std.Io.Reader, o: remote.PutObjectOptions) PutError!ObjectMeta {
        return from(ctx).putObject(name, src, o);
    }
    fn getCb(ctx: *anyopaque, name: []const u8, r: ?iface.Range, sink: *Writer) Error!ObjectMeta {
        return from(ctx).getObject(name, r, sink);
    }
    fn headCb(ctx: *anyopaque, name: []const u8) Error!ObjectMeta {
        return from(ctx).headObject(name);
    }
    fn deleteCb(ctx: *anyopaque, name: []const u8) Error!void {
        return from(ctx).deleteObject(name);
    }
    fn listCb(ctx: *anyopaque, prefix: []const u8, cb: remote.NameCallback) Error!void {
        return from(ctx).listObjects(prefix, cb);
    }

    // ---- request construction ----

    pub const Op = struct {
        method: std.http.Method,
        /// Object name; null addresses the bucket.
        key: ?[]const u8 = null,
        params: []const sign.Param = &.{},
        /// Lowercase names; signed.
        headers: []const sign.Header = &.{},
        body: ?[]const u8 = null,
    };

    const max_headers = 12;

    /// Everything needed to put one signed request on the wire.
    pub const Built = struct {
        path_buf: [4096]u8 = undefined,
        path: []const u8 = "",
        query_buf: [2048]u8 = undefined,
        query: []const u8 = "",
        host_buf: [300]u8 = undefined,
        host: []const u8 = "",
        uri_host_buf: [300]u8 = undefined,
        uri_host: []const u8 = "",
        hash_buf: [64]u8 = undefined,
        date: [16]u8 = undefined,
        auth_buf: [512]u8 = undefined,
        auth: []const u8 = "",
        headers: [max_headers]std.http.Header = undefined,
        n_headers: usize = 0,
    };

    pub fn build(self: *const S3Client, op: Op, now_ns: i128, out: *Built) Error!void {
        const vhost = self.cfg.addressing == .virtual_host;
        {
            var w: Writer = .fixed(&out.path_buf);
            w.writeAll(self.endpoint.base_path) catch return error.InvalidKey;
            if (!vhost) w.print("/{s}", .{self.cfg.bucket}) catch return error.InvalidKey;
            w.writeByte('/') catch return error.InvalidKey;
            if (op.key) |k| sign.uriEncode(&w, k, false) catch return error.InvalidKey;
            out.path = w.buffered();
        }
        {
            var w: Writer = .fixed(&out.query_buf);
            sign.canonicalQuery(&w, op.params) catch return error.InvalidKey;
            out.query = w.buffered();
        }
        var sub_buf: [80]u8 = undefined;
        const sub = if (vhost) std.fmt.bufPrint(&sub_buf, "{s}.", .{self.cfg.bucket}) catch return error.InvalidKey else "";
        out.host = self.endpoint.authority(sub, &out.host_buf) catch return error.InvalidKey;
        out.uri_host = std.fmt.bufPrint(&out.uri_host_buf, "{s}{s}", .{ sub, self.endpoint.host }) catch return error.InvalidKey;

        const payload_hash: []const u8 = if (op.body) |b| switch (self.cfg.payload) {
            .signed => blk: {
                out.hash_buf = sign.hashHex(b);
                break :blk &out.hash_buf;
            },
            .unsigned => sign.unsigned_payload,
        } else sign.empty_sha256;
        out.date = sign.amzDate(now_ns);

        var hs: [max_headers]sign.Header = undefined;
        var n: usize = 0;
        hs[n] = .{ .name = "host", .value = out.host };
        n += 1;
        hs[n] = .{ .name = "x-amz-content-sha256", .value = payload_hash };
        n += 1;
        hs[n] = .{ .name = "x-amz-date", .value = &out.date };
        n += 1;
        if (self.cfg.credentials.session_token) |t| {
            hs[n] = .{ .name = "x-amz-security-token", .value = t };
            n += 1;
        }
        if (n + op.headers.len > hs.len) return error.InvalidKey;
        for (op.headers) |h| {
            hs[n] = h;
            n += 1;
        }
        std.mem.sort(sign.Header, hs[0..n], {}, struct {
            fn lt(_: void, a: sign.Header, b: sign.Header) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);
        out.auth = sign.authorization(self.cfg.credentials, self.cfg.region, self.cfg.service, .{
            .method = @tagName(op.method),
            .canonical_uri = out.path,
            .canonical_query = out.query,
            .headers = hs[0..n],
            .payload_hash = payload_hash,
            .amz_date = &out.date,
        }, &out.auth_buf) catch return error.InvalidKey;
        out.n_headers = 0;
        for (hs[0..n]) |h| {
            if (std.mem.eql(u8, h.name, "host")) continue;
            out.headers[out.n_headers] = .{ .name = h.name, .value = h.value };
            out.n_headers += 1;
        }
    }

    const SendError = error{ Transient, OutOfMemory, InvalidKey };

    fn sendOnce(self: *S3Client, x: *rhttp.Exchange, op: Op, b: *Built) SendError!void {
        self.build(op, std.time.nanoTimestamp(), b) catch return error.InvalidKey;
        return x.start(&self.http, .{
            .method = op.method,
            .uri = self.endpoint.uri(b.uri_host, b.path, b.query),
            .host = b.host,
            .authorization = b.auth,
            .headers = b.headers[0..b.n_headers],
            .body = op.body,
        });
    }

    /// Sends with retries; on return `x` holds a non-retryable response (caller deinits).
    fn call(self: *S3Client, x: *rhttp.Exchange, op: Op, b: *Built) Error!void {
        var attempt: u32 = 0;
        while (true) {
            self.sendOnce(x, op, b) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidKey => return error.InvalidKey,
                error.Transient => {
                    log.debug("{s} transport error, attempt {d}", .{ @tagName(op.method), attempt + 1 });
                    if (self.cfg.retry.backoff(&attempt)) continue;
                    return error.IoFailed;
                },
            };
            if (!rhttp.retryableStatus(x.info.status)) return;
            log.debug("{s} HTTP {d}, attempt {d}", .{ @tagName(op.method), @intFromEnum(x.info.status), attempt + 1 });
            x.deinit();
            if (!self.cfg.retry.backoff(&attempt)) return error.IoFailed;
        }
    }

    const Small = struct { status: std.http.Status, body: []u8 };

    /// call() plus reading a small response body, retrying body read failures too.
    fn callSmall(self: *S3Client, op: Op) Error!Small {
        var attempt: u32 = 0;
        while (true) {
            var b: Built = .{};
            var x: rhttp.Exchange = undefined;
            try self.call(&x, op, &b);
            defer x.deinit();
            const body = x.readAll(self.gpa, 64 * MiB) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.TooLarge => return error.IoFailed,
                error.Transient => {
                    if (self.cfg.retry.backoff(&attempt)) continue;
                    return error.IoFailed;
                },
            };
            return .{ .status = x.info.status, .body = body };
        }
    }

    fn failure(self: *S3Client, what: []const u8, status: std.http.Status, body: ?[]const u8) Error {
        const code = if (body) |bd| xml.find(bd, "Code") orelse "" else "";
        log.warn("{s} failed: HTTP {d} {s} (bucket {s})", .{ what, @intFromEnum(status), code, self.cfg.bucket });
        return switch (status) {
            .not_found => error.NotFound,
            else => if (std.mem.eql(u8, code, "EntityTooLarge")) error.TooLarge else error.IoFailed,
        };
    }

    fn failX(self: *S3Client, what: []const u8, x: *rhttp.Exchange) Error {
        const body = x.readAll(self.gpa, 64 * 1024) catch null;
        defer if (body) |bd| self.gpa.free(bd);
        return self.failure(what, x.info.status, body);
    }

    // ---- operations ----

    pub fn headObject(self: *S3Client, name: []const u8) Error!ObjectMeta {
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .HEAD, .key = name }, &b);
        defer x.deinit();
        if (x.info.status == .not_found) return error.NotFound;
        if (x.info.status != .ok) return self.failure("HEAD", x.info.status, null);
        return .{ .size = x.info.content_length orelse return error.IoFailed, .mtime_ns = x.info.mtime_ns orelse 0 };
    }

    pub fn deleteObject(self: *S3Client, name: []const u8) Error!void {
        // S3 DELETE is idempotent; HEAD first to report NotFound like the local backend.
        _ = try self.headObject(name);
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .DELETE, .key = name }, &b);
        defer x.deinit();
        switch (x.info.status) {
            .ok, .no_content, .accepted => {},
            else => return self.failX("DELETE", &x),
        }
    }

    pub fn getObject(self: *S3Client, name: []const u8, range: ?iface.Range, sink: *Writer) Error!ObjectMeta {
        if (range) |r| if (r.length == 0) return self.headObject(name);
        var done: u64 = 0;
        var want: ?u64 = if (range) |r| r.length else null;
        var size: u64 = 0;
        var etag_buf: [128]u8 = undefined;
        var etag: []const u8 = "";
        var mtime: i128 = 0;
        var attempt: u32 = 0;
        const start = if (range) |r| r.offset else 0;
        while (true) {
            var rb: [64]u8 = undefined;
            var hs: [2]sign.Header = undefined;
            var nh: usize = 0;
            if (range != null or done > 0) {
                const from_byte = start + done;
                hs[nh] = .{ .name = "range", .value = (if (range) |r|
                    std.fmt.bufPrint(&rb, "bytes={d}-{d}", .{ from_byte, r.offset + r.length - 1 })
                else
                    std.fmt.bufPrint(&rb, "bytes={d}-", .{from_byte})) catch unreachable }; // 64 bytes fit two u64
                nh += 1;
            }
            if (done > 0 and etag.len > 0) {
                hs[nh] = .{ .name = "if-match", .value = etag };
                nh += 1;
            }
            var b: Built = .{};
            var x: rhttp.Exchange = undefined;
            try self.call(&x, .{ .method = .GET, .key = name, .headers = hs[0..nh] }, &b);
            defer x.deinit();
            switch (x.info.status) {
                .ok, .partial_content => {},
                .not_found => return error.NotFound,
                .range_not_satisfiable, .precondition_failed => return error.IoFailed,
                else => return self.failX("GET", &x),
            }
            if (x.info.status == .partial_content and x.info.range_first != start + done) return error.IoFailed;
            if (x.info.status == .ok and (range != null or done > 0)) return error.IoFailed;
            if (done == 0) {
                size = x.info.objectSize() orelse return error.IoFailed;
                if (range) |r| if (r.offset >= size or r.length > size - r.offset) return error.IoFailed;
                want = want orelse size;
                const n = @min(x.info.etag().len, etag_buf.len);
                @memcpy(etag_buf[0..n], x.info.etag()[0..n]);
                etag = etag_buf[0..n];
                mtime = x.info.mtime_ns orelse 0;
            }
            const total = want.?;
            var tbuf: [64 * 1024]u8 = undefined;
            const body = x.body(&tbuf);
            while (done < total) {
                const n = body.stream(sink, .limited64(total - done)) catch |e| switch (e) {
                    error.WriteFailed => return error.WriteFailed,
                    error.ReadFailed, error.EndOfStream => break,
                };
                done += n;
            }
            if (done == total) return .{ .size = size, .mtime_ns = mtime };
            log.debug("GET interrupted at {d}/{d}, resuming", .{ done, total });
            if (!self.cfg.retry.backoff(&attempt)) return error.IoFailed;
        }
    }

    pub fn putObject(self: *S3Client, name: []const u8, source: *std.Io.Reader, opts: remote.PutObjectOptions) PutError!ObjectMeta {
        const ps = self.cfg.part_size;
        const first_cap: usize = if (opts.size_hint) |h| @intCast(@min(h + 1, ps)) else ps;
        var buf = try self.gpa.alloc(u8, @max(first_cap, 1));
        defer self.gpa.free(buf);
        var n = source.readSliceShort(buf) catch return error.ReadFailed;
        if (n == buf.len and buf.len < ps) {
            buf = try self.gpa.realloc(buf, ps);
            n += source.readSliceShort(buf[n..]) catch return error.ReadFailed;
        }
        if (n < ps) {
            try self.putSingle(name, buf[0..n], opts.if_absent);
            return .{ .size = n, .mtime_ns = std.time.nanoTimestamp() };
        }
        return self.putMultipart(name, buf, n, source, opts.if_absent);
    }

    const if_none_match_star = [_]sign.Header{.{ .name = "if-none-match", .value = "*" }};

    fn condHeaders(_: *const S3Client, if_absent: bool) []const sign.Header {
        return if (if_absent) &if_none_match_star else &.{};
    }

    fn putSingle(self: *S3Client, name: []const u8, body: []const u8, if_absent: bool) PutError!void {
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .PUT, .key = name, .body = body, .headers = self.condHeaders(if_absent) }, &b);
        defer x.deinit();
        if (x.info.status == .precondition_failed) return error.PreconditionFailed;
        if (x.info.status != .ok) return self.failX("PUT", &x);
    }

    fn putMultipart(self: *S3Client, name: []const u8, buf: []u8, first_len: usize, source: *std.Io.Reader, if_absent: bool) PutError!ObjectMeta {
        const upload_id = try self.createUpload(name);
        defer self.gpa.free(upload_id);
        var etags: std.ArrayList([]u8) = .empty;
        defer {
            for (etags.items) |e| self.gpa.free(e);
            etags.deinit(self.gpa);
        }
        errdefer self.abortUpload(name, upload_id);
        var total: u64 = 0;
        var len = first_len;
        while (true) {
            if (etags.items.len >= max_parts) return error.TooLarge;
            try etags.ensureUnusedCapacity(self.gpa, 1);
            etags.appendAssumeCapacity(try self.uploadPart(name, upload_id, etags.items.len + 1, buf[0..len]));
            total += len;
            if (len < buf.len) break;
            len = source.readSliceShort(buf) catch return error.ReadFailed;
            if (len == 0) break;
        }
        try self.completeUpload(name, upload_id, etags.items, if_absent);
        return .{ .size = total, .mtime_ns = std.time.nanoTimestamp() };
    }

    fn createUpload(self: *S3Client, name: []const u8) Error![]u8 {
        const r = try self.callSmall(.{ .method = .POST, .key = name, .params = &.{.{ .name = "uploads", .value = "" }} });
        defer self.gpa.free(r.body);
        if (r.status != .ok) return self.failure("CreateMultipartUpload", r.status, r.body);
        const raw = xml.find(r.body, "UploadId") orelse return error.IoFailed;
        var ub: [1024]u8 = undefined;
        const id = xml.unescape(raw, &ub) catch return error.IoFailed;
        return self.gpa.dupe(u8, id);
    }

    fn uploadPart(self: *S3Client, name: []const u8, upload_id: []const u8, part: usize, body: []const u8) Error![]u8 {
        var pn: [8]u8 = undefined;
        const part_s = std.fmt.bufPrint(&pn, "{d}", .{part}) catch unreachable; // <= 10000
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .PUT, .key = name, .body = body, .params = &.{
            .{ .name = "partNumber", .value = part_s },
            .{ .name = "uploadId", .value = upload_id },
        } }, &b);
        defer x.deinit();
        if (x.info.status != .ok) return self.failX("UploadPart", &x);
        if (x.info.etag().len == 0) return error.IoFailed;
        return self.gpa.dupe(u8, x.info.etag());
    }

    fn completeUpload(self: *S3Client, name: []const u8, upload_id: []const u8, etags: []const []u8, if_absent: bool) PutError!void {
        var doc: Writer.Allocating = .init(self.gpa);
        defer doc.deinit();
        const w = &doc.writer;
        w.writeAll("<CompleteMultipartUpload>") catch return error.OutOfMemory;
        for (etags, 1..) |e, i| {
            w.print("<Part><PartNumber>{d}</PartNumber><ETag>", .{i}) catch return error.OutOfMemory;
            xml.escape(w, e) catch return error.OutOfMemory;
            w.writeAll("</ETag></Part>") catch return error.OutOfMemory;
        }
        w.writeAll("</CompleteMultipartUpload>") catch return error.OutOfMemory;
        const r = try self.callSmall(.{
            .method = .POST,
            .key = name,
            .params = &.{.{ .name = "uploadId", .value = upload_id }},
            .headers = self.condHeaders(if_absent),
            .body = doc.written(),
        });
        defer self.gpa.free(r.body);
        // A 200 can still carry an <Error> document.
        const code = if (std.mem.indexOf(u8, r.body, "<Error>") != null) xml.find(r.body, "Code") orelse "" else "";
        if (r.status == .precondition_failed or std.mem.eql(u8, code, "PreconditionFailed")) return error.PreconditionFailed;
        if (r.status != .ok or code.len > 0) return self.failure("CompleteMultipartUpload", r.status, r.body);
    }

    fn abortUpload(self: *S3Client, name: []const u8, upload_id: []const u8) void {
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        self.call(&x, .{ .method = .DELETE, .key = name, .params = &.{.{ .name = "uploadId", .value = upload_id }} }, &b) catch return;
        x.deinit();
    }

    pub fn listObjects(self: *S3Client, prefix: []const u8, cb: remote.NameCallback) Error!void {
        var token: ?[]u8 = null;
        defer if (token) |t| self.gpa.free(t);
        var mk: [8]u8 = undefined;
        const max_keys = std.fmt.bufPrint(&mk, "{d}", .{self.cfg.list_page_size}) catch unreachable; // u16
        while (true) {
            var params: [4]sign.Param = .{
                .{ .name = "list-type", .value = "2" },
                .{ .name = "max-keys", .value = max_keys },
                .{ .name = "prefix", .value = prefix },
                undefined,
            };
            var np: usize = 3;
            if (token) |t| {
                params[3] = .{ .name = "continuation-token", .value = t };
                np = 4;
            }
            const r = try self.callSmall(.{ .method = .GET, .params = params[0..np] });
            defer self.gpa.free(r.body);
            if (r.status != .ok) return self.failure("ListObjectsV2", r.status, r.body);
            var sc: xml.Scanner = .{ .doc = r.body };
            var kb: [2048]u8 = undefined;
            while (sc.next("Key")) |raw| {
                const key = xml.unescape(raw, &kb) catch return error.IoFailed;
                try cb.func(cb.ctx, key);
            }
            const truncated = std.mem.eql(u8, xml.find(r.body, "IsTruncated") orelse "false", "true");
            if (!truncated) return;
            const raw_tok = xml.find(r.body, "NextContinuationToken") orelse return error.IoFailed;
            const tok = xml.unescape(raw_tok, &kb) catch return error.IoFailed;
            if (token) |t| self.gpa.free(t);
            token = null;
            token = try self.gpa.dupe(u8, tok);
        }
    }

    /// Creates the bucket; succeeds if it already exists and is ours.
    pub fn ensureBucket(self: *S3Client) Error!void {
        var body_buf: [256]u8 = undefined;
        const body: ?[]const u8 = if (std.mem.eql(u8, self.cfg.region, "us-east-1")) null else std.fmt.bufPrint(&body_buf,
            \\<CreateBucketConfiguration><LocationConstraint>{s}</LocationConstraint></CreateBucketConfiguration>
        , .{self.cfg.region}) catch return error.InvalidKey;
        const r = try self.callSmall(.{ .method = .PUT, .body = body orelse "" });
        defer self.gpa.free(r.body);
        if (r.status == .ok) return;
        const code = xml.find(r.body, "Code") orelse "";
        if (r.status == .conflict and std.mem.eql(u8, code, "BucketAlreadyOwnedByYou")) return;
        return self.failure("CreateBucket", r.status, r.body);
    }
};

/// S3Client plus the key mapping: a ready-to-use StorageBackend.
pub const S3Backend = struct {
    client: S3Client,
    remote: remote.RemoteObjectBackend,

    /// Initializes in place; `self` must not move afterwards.
    pub fn init(self: *S3Backend, gpa: std.mem.Allocator, cfg: Config) InitError!void {
        self.client = try S3Client.init(gpa, cfg);
        self.remote = .init(self.client.provider(), cfg.prefix);
    }

    pub fn deinit(self: *S3Backend) void {
        self.client.deinit();
    }

    pub fn backend(self: *S3Backend) iface.StorageBackend {
        return self.remote.backend();
    }
};

const test_cfg: Config = .{
    .endpoint = "http://127.0.0.1:9000",
    .bucket = "examplebucket",
    .credentials = .{ .access_key = "AKIAIOSFODNN7EXAMPLE", .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
};

test "config validation" {
    const gpa = std.testing.allocator;
    var bad = test_cfg;
    bad.bucket = "Bad_Bucket!";
    try std.testing.expectError(error.InvalidConfig, S3Client.init(gpa, bad));
    bad = test_cfg;
    bad.part_size = 1024;
    try std.testing.expectError(error.InvalidConfig, S3Client.init(gpa, bad));
    bad = test_cfg;
    bad.prefix = "noslash";
    try std.testing.expectError(error.InvalidConfig, S3Client.init(gpa, bad));
    bad = test_cfg;
    bad.endpoint = "ftp://x";
    try std.testing.expectError(error.InvalidConfig, S3Client.init(gpa, bad));
    var ok = try S3Client.init(gpa, test_cfg);
    defer ok.deinit();
    try std.testing.expect(ok.capabilities().multipart_native);
}

test "path and virtual-host request construction" {
    const gpa = std.testing.allocator;
    var c = try S3Client.init(gpa, test_cfg);
    defer c.deinit();
    var b: S3Client.Built = .{};
    const t: i128 = 1369353600 * std.time.ns_per_s; // 20130524T000000Z
    try c.build(.{ .method = .GET, .key = "dir/a b$", .params = &.{.{ .name = "partNumber", .value = "1" }} }, t, &b);
    try std.testing.expectEqualStrings("/examplebucket/dir/a%20b%24", b.path);
    try std.testing.expectEqualStrings("127.0.0.1:9000", b.host);
    try std.testing.expectEqualStrings("partNumber=1", b.query);
    try std.testing.expectEqualStrings("20130524T000000Z", &b.date);
    try std.testing.expect(std.mem.startsWith(u8, b.auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="));

    var vcfg = test_cfg;
    vcfg.endpoint = "https://s3.amazonaws.com";
    vcfg.addressing = .virtual_host;
    var v = try S3Client.init(gpa, vcfg);
    defer v.deinit();
    // Reproduces the AWS doc GET example through the full builder.
    try v.build(.{ .method = .GET, .key = "test.txt", .headers = &.{.{ .name = "range", .value = "bytes=0-9" }} }, t, &b);
    try std.testing.expectEqualStrings("/test.txt", b.path);
    try std.testing.expectEqualStrings("examplebucket.s3.amazonaws.com", b.host);
    try std.testing.expectEqualStrings("examplebucket.s3.amazonaws.com", b.uri_host);
    try std.testing.expect(std.mem.endsWith(u8, b.auth, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"));
}

test "unreachable endpoint exhausts retries with IoFailed" {
    const gpa = std.testing.allocator;
    // Bind then close a listener to get a port that refuses connections.
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{});
    const port = srv.listen_address.getPort();
    srv.deinit();
    var ep_buf: [64]u8 = undefined;
    var cfg = test_cfg;
    cfg.endpoint = try std.fmt.bufPrint(&ep_buf, "http://127.0.0.1:{d}", .{port});
    cfg.retry = .{ .max_attempts = 3, .base_ms = 1, .cap_ms = 2 };
    var c = try S3Client.init(gpa, cfg);
    defer c.deinit();
    try std.testing.expectError(error.IoFailed, c.headObject("x"));
}

/// Deterministic byte stream: byte at offset p is `patternByte(p)`.
pub const PatternReader = struct {
    pos: u64 = 0,
    len: u64,
    reader: std.Io.Reader,

    pub fn init(len: u64, buf: []u8) PatternReader {
        return .{ .len = len, .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    pub fn patternByte(p: u64) u8 {
        return @truncate((p *% 2654435761) >> 7);
    }

    fn stream(r: *std.Io.Reader, w: *Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *PatternReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.pos >= self.len) return error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n: usize = @intCast(@min(dest.len, self.len - self.pos));
        for (dest[0..n], 0..) |*d, i| d.* = patternByte(self.pos + i);
        self.pos += n;
        w.advance(n);
        return n;
    }
};

fn envOrNull(gpa: std.mem.Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(gpa, name) catch null;
}

// Live test; tests/remote_backend.sh provides a MinIO endpoint. Skipped without env.
test "remote live s3 backend" {
    const gpa = std.testing.allocator;
    const ep = envOrNull(gpa, "ZKFSM_S3_ENDPOINT") orelse return error.SkipZigTest;
    defer gpa.free(ep);
    const ak = envOrNull(gpa, "ZKFSM_S3_ACCESS_KEY") orelse return error.SkipZigTest;
    defer gpa.free(ak);
    const sk = envOrNull(gpa, "ZKFSM_S3_SECRET_KEY") orelse return error.SkipZigTest;
    defer gpa.free(sk);
    const bucket = envOrNull(gpa, "ZKFSM_S3_BUCKET") orelse try gpa.dupe(u8, "zkfsm-live");
    defer gpa.free(bucket);
    const big_mb: u64 = if (envOrNull(gpa, "ZKFSM_S3_BIG_MB")) |s| blk: {
        defer gpa.free(s);
        break :blk std.fmt.parseInt(u64, s, 10) catch 100;
    } else 100;

    var sb: S3Backend = undefined;
    try sb.init(gpa, .{
        .endpoint = ep,
        .bucket = bucket,
        .prefix = "live/",
        .credentials = .{ .access_key = ak, .secret_key = sk },
        .part_size = min_part_size,
        .list_page_size = 3,
        .retry = .{ .max_attempts = 4, .base_ms = 50 },
    });
    defer sb.deinit();
    try sb.client.ensureBucket();
    try runLiveSuite(gpa, &sb.remote, big_mb);

    // Unsigned payload path.
    sb.client.cfg.payload = .unsigned;
    const k: iface.PhysicalKey = .{ .space = .data, .hex = "ffffffffffffffffffffffffffffffff".* };
    var src: std.Io.Reader = .fixed("unsigned body");
    _ = try sb.backend().put(k, &src, .{});
    try sb.backend().delete(k);
}

/// Exercises every StorageBackend method; shared with other live remote tests.
pub fn runLiveSuite(gpa: std.mem.Allocator, rb: *remote.RemoteObjectBackend, big_mb: u64) !void {
    const t = std.testing;
    const b = rb.backend();
    const small: iface.PhysicalKey = .{ .space = .data, .hex = "0123456789abcdef0123456789abcdef".* };
    const big: iface.PhysicalKey = .{ .space = .data, .hex = "fedcba9876543210fedcba9876543210".* };
    const rec: iface.PhysicalKey = .{ .space = .record, .hex = small.hex };

    // Clean slate from an earlier run.
    b.delete(small) catch {};
    b.delete(big) catch {};
    b.deleteRecord(rec) catch {};

    var src: std.Io.Reader = .fixed("hello remote world");
    const m = try b.put(small, &src, .{});
    try t.expectEqual(@as(u64, 18), m.size);
    try t.expectEqual(@as(u64, 18), (try b.stat(small)).size);

    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    _ = try b.get(small, .{ .offset = 6, .length = 6 }, &out.writer);
    try t.expectEqualStrings("remote", out.written());
    out.clearRetainingCapacity();
    const gm = try b.get(small, null, &out.writer);
    try t.expectEqualStrings("hello remote world", out.written());
    try t.expectEqual(@as(u64, 18), gm.size);
    try t.expectError(error.IoFailed, b.get(small, .{ .offset = 10, .length = 100 }, &out.writer));

    if (b.capabilities.conditional_write) {
        var again: std.Io.Reader = .fixed("x");
        try t.expectError(error.PreconditionFailed, rb.putIfAbsent(small, &again, .{}));
    }

    // Records and listing (page size forces pagination).
    try b.putRecord(rec, "record-bytes");
    const got = try b.getRecord(rec, gpa);
    defer gpa.free(got);
    try t.expectEqualStrings("record-bytes", got);
    var extra: [6]iface.PhysicalKey = undefined;
    for (&extra, 0..) |*k, i| {
        k.* = .{ .space = .data, .hex = "a0000000000000000000000000000000".* };
        k.hex[31] = "0123456789"[i];
        var s: std.Io.Reader = .fixed("x");
        _ = try b.put(k.*, &s, .{});
    }
    const Counter = struct {
        n: usize = 0,
        fn f(ctx: *anyopaque, _: iface.PhysicalKey) Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.n += 1;
        }
    };
    var c: Counter = .{};
    try b.list(.data, .{ .ctx = &c, .func = Counter.f });
    try t.expectEqual(@as(usize, 7), c.n);
    var rc: Counter = .{};
    try b.list(.record, .{ .ctx = &rc, .func = Counter.f });
    try t.expectEqual(@as(usize, 1), rc.n);
    for (extra) |k| try b.delete(k);

    // Large streamed put (multipart) and ranged reads across part boundaries.
    const big_len = big_mb * MiB;
    var pbuf: [64 * 1024]u8 = undefined;
    var pr = PatternReader.init(big_len, &pbuf);
    var timer = try std.time.Timer.start();
    const bm = try b.put(big, &pr.reader, .{});
    const put_ns = timer.lap();
    try t.expectEqual(big_len, bm.size);
    try t.expectEqual(big_len, (try b.stat(big)).size);

    const off: u64 = 5 * MiB - 100; // straddles the first part boundary
    out.clearRetainingCapacity();
    _ = try b.get(big, .{ .offset = off, .length = 1000 }, &out.writer);
    for (out.written(), 0..) |byte, i| try t.expectEqual(PatternReader.patternByte(off + i), byte);

    var hbuf: [64 * 1024]u8 = undefined;
    var hw: Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&hbuf);
    _ = try b.get(big, null, &hw.writer);
    try hw.writer.flush();
    const get_ns = timer.lap();
    var want_h = std.crypto.hash.sha2.Sha256.init(.{});
    var pr2 = PatternReader.init(big_len, &pbuf);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = try pr2.reader.readSliceShort(&chunk);
        want_h.update(chunk[0..n]);
        if (n < chunk.len) break;
    }
    try t.expectEqual(want_h.finalResult(), hw.hasher.finalResult());
    std.debug.print("live: {d} MiB put {d} ms, get {d} ms\n", .{ big_mb, put_ns / std.time.ns_per_ms, get_ns / std.time.ns_per_ms });

    try b.sync();
    try b.delete(big);
    try b.delete(small);
    try b.deleteRecord(rec);
    try t.expectError(error.NotFound, b.stat(small));
    try t.expectError(error.NotFound, b.delete(small));
    try t.expectError(error.NotFound, b.getRecord(rec, gpa));
}
