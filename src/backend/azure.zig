//! Azure Blob provider: SharedKey auth, Put Blob / Put Block + Put Block List,
//! ranged Get Blob with resume, List Blobs paging, retries with backoff and jitter.
const std = @import("std");
const iface = @import("root.zig");
const remote = @import("remote.zig");
const rhttp = @import("remote/http.zig");
const xml = @import("remote/xml.zig");
const s3 = @import("s3.zig");

const Error = iface.Error;
const ObjectMeta = iface.ObjectMeta;
const PutError = remote.PutError;
const Writer = std.Io.Writer;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.standard;
const log = std.log.scoped(.azure_backend);

const MiB = s3.MiB;
pub const max_block_size = 4000 * MiB;
pub const max_blocks = 50_000;
pub const api_version = "2021-08-06";

pub const Config = struct {
    account: []const u8,
    /// Base64 account key.
    key: []const u8,
    container: []const u8,
    /// Defaults to https://<account>.blob.core.windows.net; may carry a path (Azurite).
    endpoint: ?[]const u8 = null,
    /// Blob name prefix; empty or ending in '/'.
    prefix: []const u8 = "",
    /// Puts larger than this use Put Block + Put Block List.
    block_size: usize = 16 * MiB,
    retry: rhttp.RetryPolicy = .{},
    list_page_size: u16 = 5000,
    /// PEM CA bundle for https endpoints; empty uses $SSL_CERT_FILE, then system roots.
    ca_file: []const u8 = "",
};

pub const InitError = error{ InvalidConfig, OutOfMemory };

pub const Param = struct { name: []const u8, value: []const u8 };
pub const Header = struct { name: []const u8, value: []const u8 };

/// Standard headers that take part in the SharedKey string-to-sign.
pub const SignedStd = struct {
    content_length: u64 = 0,
    content_type: []const u8 = "",
    if_none_match: []const u8 = "",
};

/// Writes the SharedKey string-to-sign (Blob service, version 2015-02-21+).
/// `ms_headers` must be lowercase x-ms-* and sorted; `params` sorted by name.
pub fn stringToSign(w: *Writer, method: []const u8, std_h: SignedStd, ms_headers: []const Header, account: []const u8, path: []const u8, params: []const Param) Writer.Error!void {
    try w.print("{s}\n\n\n", .{method}); // verb, content-encoding, content-language
    if (std_h.content_length > 0) try w.print("{d}", .{std_h.content_length});
    try w.print("\n\n{s}\n\n\n\n{s}\n\n\n", .{ std_h.content_type, std_h.if_none_match });
    // md5, type, date, if-modified-since, if-match, if-none-match, if-unmodified-since, range
    for (ms_headers) |h| try w.print("{s}:{s}\n", .{ h.name, h.value });
    try w.print("/{s}{s}", .{ account, path });
    for (params) |p| try w.print("\n{s}:{s}", .{ p.name, p.value });
}

pub fn sign(key: []const u8, string_to_sign: []const u8) [44]u8 {
    var mac: [32]u8 = undefined;
    Hmac.create(&mac, string_to_sign, key);
    var out: [44]u8 = undefined;
    _ = b64.Encoder.encode(&out, &mac);
    return out;
}

fn validContainer(c: []const u8) bool {
    if (c.len < 3 or c.len > 63) return false;
    for (c) |ch| if (!(std.ascii.isLower(ch) or std.ascii.isDigit(ch) or ch == '-')) return false;
    return true;
}

pub const AzureClient = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    endpoint: rhttp.Endpoint,
    endpoint_buf: [256]u8,
    key_buf: [128]u8,
    key_len: usize,
    http: std.http.Client,

    /// Initializes in place; `self` must not move afterwards (endpoint borrows endpoint_buf).
    pub fn init(self: *AzureClient, gpa: std.mem.Allocator, cfg: Config) InitError!void {
        self.* = .{ .gpa = gpa, .cfg = cfg, .endpoint = undefined, .endpoint_buf = undefined, .key_buf = undefined, .key_len = 0, .http = .{ .allocator = gpa } };
        const url = cfg.endpoint orelse std.fmt.bufPrint(&self.endpoint_buf, "https://{s}.blob.core.windows.net", .{cfg.account}) catch return error.InvalidConfig;
        self.endpoint = rhttp.Endpoint.parse(url) catch return error.InvalidConfig;
        if (!validContainer(cfg.container) or cfg.account.len == 0) return error.InvalidConfig;
        if (cfg.prefix.len > 0 and cfg.prefix[cfg.prefix.len - 1] != '/') return error.InvalidConfig;
        if (cfg.block_size == 0 or cfg.block_size > max_block_size or cfg.list_page_size == 0) return error.InvalidConfig;
        const n = b64.Decoder.calcSizeForSlice(cfg.key) catch return error.InvalidConfig;
        if (n > self.key_buf.len) return error.InvalidConfig;
        b64.Decoder.decode(self.key_buf[0..n], cfg.key) catch return error.InvalidConfig;
        self.key_len = n;
        if (self.endpoint.tls) rhttp.useCaFile(&self.http, gpa, cfg.ca_file) catch |e| {
            self.http.deinit();
            return e;
        };
    }

    pub fn deinit(self: *AzureClient) void {
        self.http.deinit();
    }

    pub const capabilities: iface.Capabilities = .{
        .durable_sync = true,
        .range_read = true,
        .multipart_native = true,
        .conditional_write = true,
    };

    pub fn provider(self: *AzureClient) remote.Provider {
        return .{ .ctx = self, .capabilities = capabilities, .vtable = &provider_vtable };
    }

    const provider_vtable: remote.Provider.VTable = .{
        .put = putCb,
        .get = getCb,
        .head = headCb,
        .delete = deleteCb,
        .list = listCb,
    };

    fn from(ctx: *anyopaque) *AzureClient {
        return @ptrCast(@alignCast(ctx));
    }
    fn putCb(ctx: *anyopaque, name: []const u8, src: *std.Io.Reader, o: remote.PutObjectOptions) PutError!ObjectMeta {
        return from(ctx).putBlob(name, src, o);
    }
    fn getCb(ctx: *anyopaque, name: []const u8, r: ?iface.Range, sink: *Writer) Error!ObjectMeta {
        return from(ctx).getBlob(name, r, sink);
    }
    fn headCb(ctx: *anyopaque, name: []const u8) Error!ObjectMeta {
        return from(ctx).headBlob(name);
    }
    fn deleteCb(ctx: *anyopaque, name: []const u8) Error!void {
        return from(ctx).deleteBlob(name);
    }
    fn listCb(ctx: *anyopaque, prefix: []const u8, cb: remote.NameCallback) Error!void {
        return from(ctx).listBlobs(prefix, cb);
    }

    pub const Op = struct {
        method: std.http.Method,
        /// Blob name; null addresses the container.
        blob: ?[]const u8 = null,
        params: []const Param = &.{},
        /// Lowercase x-ms-* headers besides x-ms-date and x-ms-version.
        ms_headers: []const Header = &.{},
        if_none_match: []const u8 = "",
        body: ?[]const u8 = null,
    };

    const max_ms = 8;

    pub const Built = struct {
        path_buf: [4096]u8 = undefined,
        path: []const u8 = "",
        query_buf: [2048]u8 = undefined,
        query: []const u8 = "",
        host_buf: [300]u8 = undefined,
        host: []const u8 = "",
        date_buf: [29]u8 = undefined,
        auth_buf: [256]u8 = undefined,
        auth: []const u8 = "",
        headers: [max_ms + 3]std.http.Header = undefined,
        n_headers: usize = 0,
    };

    pub fn build(self: *const AzureClient, op: Op, now_ns: i128, out: *Built) Error!void {
        {
            var w: Writer = .fixed(&out.path_buf);
            w.print("{s}/{s}", .{ self.endpoint.base_path, self.cfg.container }) catch return error.InvalidKey;
            if (op.blob) |b| {
                w.writeByte('/') catch return error.InvalidKey;
                encodePath(&w, b) catch return error.InvalidKey;
            }
            out.path = w.buffered();
        }
        var sorted: [8]Param = undefined;
        if (op.params.len > sorted.len) return error.InvalidKey;
        @memcpy(sorted[0..op.params.len], op.params);
        std.mem.sort(Param, sorted[0..op.params.len], {}, struct {
            fn lt(_: void, a: Param, b: Param) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);
        const params = sorted[0..op.params.len];
        {
            var w: Writer = .fixed(&out.query_buf);
            for (params, 0..) |p, i| {
                if (i != 0) w.writeByte('&') catch return error.InvalidKey;
                encodeQuery(&w, p.name) catch return error.InvalidKey;
                w.writeByte('=') catch return error.InvalidKey;
                encodeQuery(&w, p.value) catch return error.InvalidKey;
            }
            out.query = w.buffered();
        }
        out.host = self.endpoint.authority("", &out.host_buf) catch return error.InvalidKey;
        const date = httpDate(now_ns, &out.date_buf);

        var ms: [max_ms]Header = undefined;
        if (op.ms_headers.len + 2 > ms.len) return error.InvalidKey;
        @memcpy(ms[0..op.ms_headers.len], op.ms_headers);
        var n = op.ms_headers.len;
        ms[n] = .{ .name = "x-ms-date", .value = date };
        ms[n + 1] = .{ .name = "x-ms-version", .value = api_version };
        n += 2;
        std.mem.sort(Header, ms[0..n], {}, struct {
            fn lt(_: void, a: Header, b: Header) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);

        var sts_buf: [8192]u8 = undefined;
        var sw: Writer = .fixed(&sts_buf);
        stringToSign(&sw, @tagName(op.method), .{
            .content_length = if (op.body) |b| b.len else 0,
            .if_none_match = op.if_none_match,
        }, ms[0..n], self.cfg.account, out.path, params) catch return error.InvalidKey;
        const sig = sign(self.key_buf[0..self.key_len], sw.buffered());
        out.auth = std.fmt.bufPrint(&out.auth_buf, "SharedKey {s}:{s}", .{ self.cfg.account, &sig }) catch return error.InvalidKey;

        out.n_headers = 0;
        for (ms[0..n]) |h| {
            out.headers[out.n_headers] = .{ .name = h.name, .value = h.value };
            out.n_headers += 1;
        }
        if (op.if_none_match.len > 0) {
            out.headers[out.n_headers] = .{ .name = "if-none-match", .value = op.if_none_match };
            out.n_headers += 1;
        }
    }

    const SendError = error{ Transient, OutOfMemory, InvalidKey };

    fn sendOnce(self: *AzureClient, x: *rhttp.Exchange, op: Op, b: *Built) SendError!void {
        self.build(op, std.time.nanoTimestamp(), b) catch return error.InvalidKey;
        return x.start(&self.http, .{
            .method = op.method,
            .uri = self.endpoint.uri(self.endpoint.host, b.path, b.query),
            .host = b.host,
            .authorization = b.auth,
            .headers = b.headers[0..b.n_headers],
            .body = op.body,
        });
    }

    fn call(self: *AzureClient, x: *rhttp.Exchange, op: Op, b: *Built) Error!void {
        var attempt: u32 = 0;
        while (true) {
            self.sendOnce(x, op, b) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidKey => return error.InvalidKey,
                error.Transient => {
                    if (self.cfg.retry.backoff(&attempt)) continue;
                    return error.IoFailed;
                },
            };
            if (!rhttp.retryableStatus(x.info.status)) return;
            x.deinit();
            if (!self.cfg.retry.backoff(&attempt)) return error.IoFailed;
        }
    }

    const Small = struct { status: std.http.Status, body: []u8 };

    fn callSmall(self: *AzureClient, op: Op) Error!Small {
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

    fn failure(self: *AzureClient, what: []const u8, status: std.http.Status, body: ?[]const u8) Error {
        const code = if (body) |bd| xml.find(bd, "Code") orelse "" else "";
        log.warn("{s} failed: HTTP {d} {s} (container {s})", .{ what, @intFromEnum(status), code, self.cfg.container });
        return if (status == .not_found) error.NotFound else error.IoFailed;
    }

    fn failX(self: *AzureClient, what: []const u8, x: *rhttp.Exchange) Error {
        const body = x.readAll(self.gpa, 64 * 1024) catch null;
        defer if (body) |bd| self.gpa.free(bd);
        return self.failure(what, x.info.status, body);
    }

    pub fn headBlob(self: *AzureClient, name: []const u8) Error!ObjectMeta {
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .HEAD, .blob = name }, &b);
        defer x.deinit();
        if (x.info.status == .not_found) return error.NotFound;
        if (x.info.status != .ok) return self.failure("GetBlobProperties", x.info.status, null);
        return .{ .size = x.info.content_length orelse return error.IoFailed, .mtime_ns = x.info.mtime_ns orelse 0 };
    }

    pub fn deleteBlob(self: *AzureClient, name: []const u8) Error!void {
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .DELETE, .blob = name }, &b);
        defer x.deinit();
        switch (x.info.status) {
            .accepted, .ok => {},
            .not_found => return error.NotFound,
            else => return self.failX("DeleteBlob", &x),
        }
    }

    pub fn getBlob(self: *AzureClient, name: []const u8, range: ?iface.Range, sink: *Writer) Error!ObjectMeta {
        if (range) |r| if (r.length == 0) return self.headBlob(name);
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
            var hs: [2]Header = undefined;
            var nh: usize = 0;
            if (range != null or done > 0) {
                const from_byte = start + done;
                hs[nh] = .{ .name = "x-ms-range", .value = (if (range) |r|
                    std.fmt.bufPrint(&rb, "bytes={d}-{d}", .{ from_byte, r.offset + r.length - 1 })
                else
                    std.fmt.bufPrint(&rb, "bytes={d}-", .{from_byte})) catch unreachable }; // two u64 fit
                nh += 1;
            }
            // Resumed reads compare the response ETag instead of sending If-Match.
            var b: Built = .{};
            var x: rhttp.Exchange = undefined;
            try self.call(&x, .{ .method = .GET, .blob = name, .ms_headers = hs[0..nh] }, &b);
            defer x.deinit();
            switch (x.info.status) {
                .ok, .partial_content => {},
                .not_found => return error.NotFound,
                .range_not_satisfiable => return error.IoFailed,
                else => return self.failX("GetBlob", &x),
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
            } else if (!std.mem.eql(u8, etag, x.info.etag())) {
                return error.IoFailed; // blob replaced mid-read
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
            if (!self.cfg.retry.backoff(&attempt)) return error.IoFailed;
        }
    }

    pub fn putBlob(self: *AzureClient, name: []const u8, source: *std.Io.Reader, opts: remote.PutObjectOptions) PutError!ObjectMeta {
        const bs = self.cfg.block_size;
        const first_cap: usize = if (opts.size_hint) |h| @intCast(@min(h + 1, bs)) else bs;
        var buf = try self.gpa.alloc(u8, @max(first_cap, 1));
        defer self.gpa.free(buf);
        var n = source.readSliceShort(buf) catch return error.ReadFailed;
        if (n == buf.len and buf.len < bs) {
            buf = try self.gpa.realloc(buf, bs);
            n += source.readSliceShort(buf[n..]) catch return error.ReadFailed;
        }
        const cond: []const u8 = if (opts.if_absent) "*" else "";
        if (n < bs) {
            var b: Built = .{};
            var x: rhttp.Exchange = undefined;
            try self.call(&x, .{
                .method = .PUT,
                .blob = name,
                .body = buf[0..n],
                .if_none_match = cond,
                .ms_headers = &.{.{ .name = "x-ms-blob-type", .value = "BlockBlob" }},
            }, &b);
            defer x.deinit();
            if (x.info.status == .precondition_failed or x.info.status == .conflict) return error.PreconditionFailed;
            if (x.info.status != .created) return self.failX("PutBlob", &x);
            return .{ .size = n, .mtime_ns = x.info.mtime_ns orelse std.time.nanoTimestamp() };
        }
        var count: u32 = 0;
        var total: u64 = 0;
        var len = n;
        while (true) {
            if (count >= max_blocks) return error.TooLarge;
            try self.putBlock(name, count, buf[0..len]);
            count += 1;
            total += len;
            if (len < buf.len) break;
            len = source.readSliceShort(buf) catch return error.ReadFailed;
            if (len == 0) break;
        }
        try self.putBlockList(name, count, cond);
        return .{ .size = total, .mtime_ns = std.time.nanoTimestamp() };
    }

    /// Fixed-width ids: Azure requires equal-length block ids within a blob.
    fn blockId(i: u32, out: *[12]u8) []const u8 {
        var raw: [8]u8 = undefined;
        _ = std.fmt.bufPrint(&raw, "{d:0>8}", .{i}) catch unreachable; // < 10^8
        return b64.Encoder.encode(out, &raw);
    }

    fn putBlock(self: *AzureClient, name: []const u8, i: u32, body: []const u8) Error!void {
        var idb: [12]u8 = undefined;
        var b: Built = .{};
        var x: rhttp.Exchange = undefined;
        try self.call(&x, .{ .method = .PUT, .blob = name, .body = body, .params = &.{
            .{ .name = "comp", .value = "block" },
            .{ .name = "blockid", .value = blockId(i, &idb) },
        } }, &b);
        defer x.deinit();
        if (x.info.status != .created) return self.failX("PutBlock", &x);
    }

    fn putBlockList(self: *AzureClient, name: []const u8, count: u32, cond: []const u8) PutError!void {
        var doc: Writer.Allocating = .init(self.gpa);
        defer doc.deinit();
        const w = &doc.writer;
        w.writeAll("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>") catch return error.OutOfMemory;
        for (0..count) |i| {
            var idb: [12]u8 = undefined;
            w.print("<Latest>{s}</Latest>", .{blockId(@intCast(i), &idb)}) catch return error.OutOfMemory;
        }
        w.writeAll("</BlockList>") catch return error.OutOfMemory;
        const r = try self.callSmall(.{
            .method = .PUT,
            .blob = name,
            .params = &.{.{ .name = "comp", .value = "blocklist" }},
            .if_none_match = cond,
            .body = doc.written(),
        });
        defer self.gpa.free(r.body);
        if (r.status == .precondition_failed or r.status == .conflict) return error.PreconditionFailed;
        if (r.status != .created) return self.failure("PutBlockList", r.status, r.body);
    }

    pub fn listBlobs(self: *AzureClient, prefix: []const u8, cb: remote.NameCallback) Error!void {
        var marker: ?[]u8 = null;
        defer if (marker) |m| self.gpa.free(m);
        var mr: [8]u8 = undefined;
        const max_results = std.fmt.bufPrint(&mr, "{d}", .{self.cfg.list_page_size}) catch unreachable; // u16
        while (true) {
            var params: [5]Param = .{
                .{ .name = "restype", .value = "container" },
                .{ .name = "comp", .value = "list" },
                .{ .name = "prefix", .value = prefix },
                .{ .name = "maxresults", .value = max_results },
                undefined,
            };
            var np: usize = 4;
            if (marker) |m| {
                params[4] = .{ .name = "marker", .value = m };
                np = 5;
            }
            const r = try self.callSmall(.{ .method = .GET, .params = params[0..np] });
            defer self.gpa.free(r.body);
            if (r.status != .ok) return self.failure("ListBlobs", r.status, r.body);
            var sc: xml.Scanner = .{ .doc = r.body };
            var nb: [2048]u8 = undefined;
            while (sc.next("Name")) |raw| {
                const name = xml.unescape(raw, &nb) catch return error.IoFailed;
                try cb.func(cb.ctx, name);
            }
            const raw_next = xml.find(r.body, "NextMarker") orelse return;
            if (raw_next.len == 0) return;
            const next = xml.unescape(raw_next, &nb) catch return error.IoFailed;
            if (marker) |m| self.gpa.free(m);
            marker = null;
            marker = try self.gpa.dupe(u8, next);
        }
    }

    /// Creates the container; succeeds if it already exists.
    pub fn ensureContainer(self: *AzureClient) Error!void {
        const r = try self.callSmall(.{ .method = .PUT, .params = &.{.{ .name = "restype", .value = "container" }} });
        defer self.gpa.free(r.body);
        if (r.status == .created or r.status == .conflict) return;
        return self.failure("CreateContainer", r.status, r.body);
    }
};

/// AzureClient plus the key mapping.
pub const AzureBackend = struct {
    client: AzureClient,
    remote: remote.RemoteObjectBackend,

    pub fn init(self: *AzureBackend, gpa: std.mem.Allocator, cfg: Config) InitError!void {
        try self.client.init(gpa, cfg);
        self.remote = .init(self.client.provider(), cfg.prefix);
    }

    pub fn deinit(self: *AzureBackend) void {
        self.client.deinit();
    }

    pub fn backend(self: *AzureBackend) iface.StorageBackend {
        return self.remote.backend();
    }
};

fn encodePath(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| {
        const keep = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~' or c == '/';
        if (keep) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

fn encodeQuery(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| {
        const keep = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
        if (keep) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

fn httpDate(ns: i128, buf: *[29]u8) []const u8 {
    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const secs: u64 = std.math.cast(u64, @divFloor(ns, std.time.ns_per_s)) orelse 0;
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        days[(ed.day + 4) % 7], @as(u8, md.day_index) + 1, months[md.month.numeric() - 1], yd.year,
        ds.getHoursIntoDay(),   ds.getMinutesIntoHour(),   ds.getSecondsIntoMinute(),
    }) catch unreachable; // fixed width
}

// Azurite's published development-storage key (public, documented by Microsoft).
const dev_key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

test "shared key canonicalized resource matches the documented examples" {
    // From "Authorize with Shared Key": canonicalized resource section.
    var buf: [512]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try stringToSign(&w, "GET", .{}, &.{}, "myaccount", "/mycontainer", &.{
        .{ .name = "comp", .value = "metadata" },
        .{ .name = "restype", .value = "container" },
    });
    try std.testing.expect(std.mem.endsWith(u8, w.buffered(), "\n/myaccount/mycontainer\ncomp:metadata\nrestype:container"));
    // Twelve standard slots before the resource; zero Content-Length is an empty line.
    try std.testing.expectEqualStrings("GET\n\n\n\n\n\n\n\n\n\n\n\n/myaccount/mycontainer\ncomp:metadata\nrestype:container", w.buffered());
}

test "shared key put blob string-to-sign and signature" {
    var buf: [1024]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try stringToSign(&w, "PUT", .{ .content_length = 11, .if_none_match = "*" }, &.{
        .{ .name = "x-ms-blob-type", .value = "BlockBlob" },
        .{ .name = "x-ms-date", .value = "Sun, 06 Nov 1994 08:49:37 GMT" },
        .{ .name = "x-ms-version", .value = api_version },
    }, "devstoreaccount1", "/devstoreaccount1/c1/a%20b", &.{});
    const want =
        "PUT\n\n\n11\n\n\n\n\n\n*\n\n\n" ++
        "x-ms-blob-type:BlockBlob\nx-ms-date:Sun, 06 Nov 1994 08:49:37 GMT\nx-ms-version:2021-08-06\n" ++
        "/devstoreaccount1/devstoreaccount1/c1/a%20b";
    try std.testing.expectEqualStrings(want, w.buffered());
    var key: [64]u8 = undefined;
    try b64.Decoder.decode(&key, dev_key);
    // Cross-checked with Python: base64(hmac.new(b64decode(key), sts, sha256).digest()).
    try std.testing.expectEqualStrings("hUjzJqR1AHsfbg00JUX5+aMIhnK6LWDyQ7HWvt0eYh4=", &sign(&key, want));
}

test "azure request construction" {
    var c: AzureClient = undefined;
    try c.init(std.testing.allocator, .{ .account = "myaccount", .key = dev_key, .container = "mycontainer" });
    defer c.deinit();
    var b: AzureClient.Built = .{};
    try c.build(.{ .method = .GET, .params = &.{
        .{ .name = "restype", .value = "container" },
        .{ .name = "comp", .value = "list" },
        .{ .name = "prefix", .value = "p/x y" },
    } }, 784111777 * std.time.ns_per_s, &b);
    try std.testing.expectEqualStrings("/mycontainer", b.path);
    try std.testing.expectEqualStrings("comp=list&prefix=p%2Fx%20y&restype=container", b.query);
    try std.testing.expectEqualStrings("myaccount.blob.core.windows.net", b.host);
    try std.testing.expect(std.mem.startsWith(u8, b.auth, "SharedKey myaccount:"));
    var idb: [12]u8 = undefined;
    try std.testing.expectEqualStrings("MDAwMDAwMDc=", AzureClient.blockId(7, &idb));
    var bad: AzureClient = undefined;
    try std.testing.expectError(error.InvalidConfig, bad.init(std.testing.allocator, .{ .account = "a", .key = "!!", .container = "mycontainer" }));
}

// Live test against Azurite or Azure; tests/remote_backend.sh sets the env when Azurite is available.
test "remote live azure backend" {
    const gpa = std.testing.allocator;
    const ep = std.process.getEnvVarOwned(gpa, "ZKFSM_AZURE_ENDPOINT") catch return error.SkipZigTest;
    defer gpa.free(ep);
    const account = std.process.getEnvVarOwned(gpa, "ZKFSM_AZURE_ACCOUNT") catch return error.SkipZigTest;
    defer gpa.free(account);
    const key = std.process.getEnvVarOwned(gpa, "ZKFSM_AZURE_KEY") catch return error.SkipZigTest;
    defer gpa.free(key);
    var ab: AzureBackend = undefined;
    try ab.init(gpa, .{
        .account = account,
        .key = key,
        .container = "zkfsm-live",
        .endpoint = ep,
        .prefix = "live/",
        .block_size = 5 * MiB,
        .list_page_size = 3,
        .retry = .{ .max_attempts = 4, .base_ms = 50 },
    });
    defer ab.deinit();
    try ab.client.ensureContainer();
    try s3.runLiveSuite(gpa, &ab.remote, 20);
}
