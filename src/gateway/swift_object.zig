//! Swift objects: GET/HEAD/PUT/POST/COPY/DELETE, dynamic and static large objects,
//! and temp URLs. Manifests are ordinary objects marked by reserved internal headers;
//! their GET streams the referenced segment blobs in order.
const std = @import("std");
const object = @import("../object/root.zig");
const core = @import("../core/root.zig");
const h = @import("swift_handler.zig");
const util = @import("swift_util.zig");
const listing = @import("swift_listing.zig");
const auth = @import("swift_auth.zig");
const meta = @import("swift_meta.zig");
const slo = @import("swift_slo.zig");

const Ctx = h.Ctx;
const ConnError = h.ConnError;
const Header = std.http.Header;
const blob = object.blob;

pub const max_dlo_segments = 10_000;
pub const max_object_size: u64 = 5 * 1024 * 1024 * 1024 + 2;
const slo_hdr = object.internal_prefix ++ "swift-slo";
const dlo_hdr = object.internal_prefix ++ "swift-dlo";
const io_buf = 64 * 1024;

pub fn dispatch(c: *Ctx) ConnError!void {
    return switch (c.method) {
        .GET, .HEAD => get(c),
        .PUT => put(c),
        .POST => post(c),
        .DELETE => delete(c),
        .TRACE => if (c.is_copy) copyVerb(c) else c.fail(.method_not_allowed, "Method not allowed."),
        else => c.fail(.method_not_allowed, "Method not allowed."),
    };
}

fn internal(info: object.ObjectInfo, name: []const u8) ?[]const u8 {
    for (info.internal) |x| if (std.mem.eql(u8, x.name, name)) return x.value;
    return null;
}

/// ETag as Swift prints it: hex MD5, or "<hex>-<parts>" for multipart uploads.
pub fn etagHex(a: std.mem.Allocator, e: core.ETag) error{OutOfMemory}![]const u8 {
    var qb: [core.ETag.quoted_max]u8 = undefined;
    return a.dupe(u8, std.mem.trim(u8, e.quoted(&qb), "\""));
}

const Kind = enum { plain, slo, dlo };

const Resolved = struct {
    info: object.ObjectInfo,
    kind: Kind = .plain,
    size: u64,
    /// Header value: bare hex for plain objects, quoted for manifests (as Swift).
    etag: []const u8,
    /// Blob ranges in order; filled for manifests when segments were requested.
    segs: []blob.Segment = &.{},
};

fn kindOf(info: object.ObjectInfo) Kind {
    if (internal(info, slo_hdr) != null) return .slo;
    if (internal(info, dlo_hdr) != null) return .dlo;
    return .plain;
}

/// Size, ETag and (if `want_segs`) segment blobs of `info`; responds and returns null on failure.
fn resolve(c: *Ctx, info: object.ObjectInfo, want_segs: bool) ConnError!?Resolved {
    switch (kindOf(info)) {
        .plain => return .{ .info = info, .size = info.size, .etag = try etagHex(c.a, info.etag) },
        .slo => {
            const v = internal(info, slo_hdr).?;
            const sp = std.mem.indexOfScalar(u8, v, ' ') orelse return corrupt(c);
            const total = std.fmt.parseInt(u64, v[0..sp], 10) catch return corrupt(c);
            var r: Resolved = .{ .info = info, .kind = .slo, .size = total, .etag = try std.fmt.allocPrint(c.a, "\"{s}\"", .{v[sp + 1 ..]}) };
            if (!want_segs) return r;
            const stored = (try readManifest(c, info)) orelse return null;
            const segs = try c.a.alloc(blob.Segment, stored.len);
            var sum: u64 = 0;
            for (stored, segs) |s, *out| {
                if (!c.allowed(.get_object, s.container, s.object)) {
                    try c.denied();
                    return null;
                }
                const si = c.svc().head(c.a, s.container, s.object) catch |e| switch (e) {
                    error.NoSuchKey, error.NoSuchBucket => {
                        try c.fail(.conflict, "A segment of this large object is missing.");
                        return null;
                    },
                    else => {
                        try c.failObj(e);
                        return null;
                    },
                };
                if (!std.mem.eql(u8, try etagHex(c.a, si.etag), s.hash) or si.logical_size != null) {
                    try c.fail(.conflict, "A segment of this large object changed.");
                    return null;
                }
                const rg = slo.resolveRange(c.a, s.range, si.blob_size) catch return corrupt(c);
                out.* = .{ .blob = si.object_id, .offset = rg.offset, .length = rg.length };
                sum += rg.length;
            }
            if (sum != total) return corrupt(c);
            r.segs = segs;
            return r;
        },
        .dlo => return resolveDlo(c, info, want_segs),
    }
}

fn corrupt(c: *Ctx) ConnError!?Resolved {
    try c.fail(.internal_server_error, "Corrupt large object manifest.");
    return null;
}

fn readManifest(c: *Ctx, info: object.ObjectInfo) ConnError!?[]slo.Stored {
    if (info.blob_size > slo.max_manifest_bytes) {
        _ = try corrupt(c);
        return null;
    }
    var out: std.Io.Writer.Allocating = .init(c.a);
    c.svc().read(info, null, &out.writer) catch |e| {
        try c.failObj(e);
        return null;
    };
    return slo.parseStored(c.a, out.written()) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => {
            _ = try corrupt(c);
            return null;
        },
    };
}

fn splitManifest(v: []const u8) ?struct { []const u8, []const u8 } {
    const p = if (v.len > 0 and v[0] == '/') v[1..] else v;
    const i = std.mem.indexOfScalar(u8, p, '/') orelse return if (p.len > 0) .{ p, "" } else null;
    if (i == 0) return null;
    return .{ p[0..i], p[i + 1 ..] };
}

/// DLO: every object under container/prefix, in name order (at most `max_dlo_segments`).
fn resolveDlo(c: *Ctx, info: object.ObjectInfo, want_segs: bool) ConnError!?Resolved {
    const parts = splitManifest(internal(info, dlo_hdr).?) orelse return corrupt(c);
    const cont = parts[0];
    const prefix = parts[1];
    if (!c.allowed(.list_objects_v2, cont, "")) {
        try c.denied();
        return null;
    }
    var md5 = std.crypto.hash.Md5.init(.{});
    var segs: std.ArrayList(blob.Segment) = .empty;
    var total: u64 = 0;
    var cursor: []const u8 = "";
    var n: usize = 0;
    while (n < max_dlo_segments) {
        const r = c.svc().list(c.a, cont, .{ .prefix = prefix, .start_after = cursor, .max_keys = @min(1000, max_dlo_segments - n) }) catch |e| switch (e) {
            error.NoSuchBucket => break,
            else => {
                try c.failObj(e);
                return null;
            },
        };
        for (r.contents) |e| {
            md5.update(try etagHex(c.a, e.etag));
            total += e.size;
            if (want_segs) {
                if (!c.allowed(.get_object, cont, e.key)) {
                    try c.denied();
                    return null;
                }
                const si = c.svc().head(c.a, cont, e.key) catch |err| {
                    try c.failObj(err);
                    return null;
                };
                if (si.size != e.size or si.logical_size != null) {
                    try c.fail(.conflict, "A segment of this large object changed.");
                    return null;
                }
                try segs.append(c.a, .{ .blob = si.object_id, .offset = 0, .length = si.blob_size });
            }
        }
        n += r.contents.len;
        if (!r.is_truncated or r.contents.len == 0) break;
        cursor = r.contents[r.contents.len - 1].key;
    }
    var d: [16]u8 = undefined;
    md5.final(&d);
    return .{ .info = info, .kind = .dlo, .size = total, .etag = try std.fmt.allocPrint(c.a, "\"{x}\"", .{&d}), .segs = segs.items };
}

/// Trims `segs` to the byte range `r` of their concatenation.
fn sliceSegs(a: std.mem.Allocator, segs: []const blob.Segment, r: core.Range) error{OutOfMemory}![]blob.Segment {
    var out: std.ArrayList(blob.Segment) = .empty;
    var pos: u64 = 0;
    const end = r.offset + r.length;
    for (segs) |s| {
        const s_end = pos + s.length;
        defer pos = s_end;
        if (s_end <= r.offset or pos >= end) continue;
        const from = @max(pos, r.offset);
        const to = @min(s_end, end);
        try out.append(a, .{ .blob = s.blob, .offset = s.offset + (from - pos), .length = to - from });
    }
    return out.items;
}

pub fn listingRow(c: *Ctx, e: object.list.Entry) ConnError!listing.ObjectRow {
    var row: listing.ObjectRow = .{ .name = e.key, .hash = try etagHex(c.a, e.etag), .bytes = e.size, .content_type = "application/octet-stream", .mtime_ns = e.mtime_ns };
    const info = c.svc().head(c.a, c.container, e.key) catch return row;
    if (info.content_type.len > 0) row.content_type = info.content_type;
    if (internal(info, slo_hdr)) |v| if (std.mem.indexOfScalar(u8, v, ' ')) |sp| {
        row.bytes = std.fmt.parseInt(u64, v[0..sp], 10) catch row.bytes;
        row.hash = v[sp + 1 ..];
    };
    return row;
}

// ---- GET / HEAD ----

fn objectHeaders(c: *Ctx, r: Resolved, list: *std.ArrayList(Header)) ConnError!void {
    const info = r.info;
    const secs: i64 = @intCast(@divFloor(info.created_ns, std.time.ns_per_s));
    const lm = try c.a.create([29]u8);
    const ts = try c.a.create([32]u8);
    try list.append(c.a, .{ .name = "Etag", .value = r.etag });
    try list.append(c.a, .{ .name = "Last-Modified", .value = util.httpDate(lm, secs) });
    try list.append(c.a, .{ .name = "X-Timestamp", .value = util.timestamp(ts, info.created_ns) });
    try list.append(c.a, .{ .name = "Accept-Ranges", .value = "bytes" });
    for (info.metadata) |m| {
        var tb: [meta.max_name]u8 = undefined;
        if (!util.safeValue(m.value)) continue;
        try list.append(c.a, .{ .name = try std.fmt.allocPrint(c.a, "X-Object-Meta-{s}", .{util.titleCase(&tb, m.name)}), .value = m.value });
    }
    const sys = info.system;
    inline for (.{
        .{ sys.cache_control, "Cache-Control" },
        .{ sys.content_disposition, "Content-Disposition" },
        .{ sys.content_encoding, "Content-Encoding" },
        .{ sys.content_language, "Content-Language" },
        .{ sys.expires, "Expires" },
    }) |p| if (p[0].len > 0 and !(c.tempurl and std.mem.eql(u8, p[1], "Content-Disposition"))) try list.append(c.a, .{ .name = p[1], .value = p[0] });
    switch (r.kind) {
        .slo => try list.append(c.a, .{ .name = "X-Static-Large-Object", .value = "True" }),
        .dlo => try list.append(c.a, .{ .name = "X-Object-Manifest", .value = internal(info, dlo_hdr).? }),
        .plain => {},
    }
}

fn contentDisposition(c: *Ctx) ConnError!?[]const u8 {
    if (!c.tempurl or c.method != .GET) return null;
    const fname_q = c.q("filename");
    const base = blk: {
        const o = c.object;
        const i = std.mem.lastIndexOfScalar(u8, o, '/') orelse break :blk o;
        break :blk o[i + 1 ..];
    };
    const inline_ = util.queryRaw(c.query, "inline") != null;
    const name = fname_q orelse base;
    var quoted: std.Io.Writer.Allocating = .init(c.a);
    for (name) |ch| if (ch >= 0x20 and ch < 0x7f and ch != '"' and ch != '\\') quoted.writer.writeByte(ch) catch return error.OutOfMemory;
    var enc: std.Io.Writer.Allocating = .init(c.a);
    util.percentEncode(&enc.writer, name, false) catch return error.OutOfMemory;
    if (inline_ and fname_q == null) return "inline";
    return try std.fmt.allocPrint(c.a, "{s}; filename=\"{s}\"; filename*=UTF-8''{s}", .{ if (inline_) "inline" else "attachment", quoted.written(), enc.written() });
}

fn get(c: *Ctx) ConnError!void {
    if (!c.allowed(if (c.method == .HEAD) .head_object else .get_object, c.container, c.object)) return c.denied();
    const info = c.svc().head(c.a, c.container, c.object) catch |e| return c.failObj(e);
    const mm = c.q("multipart-manifest");
    if (mm != null and std.mem.eql(u8, mm.?, "get") and kindOf(info) == .slo) return getManifest(c, info);

    const r = (try resolve(c, info, false)) orelse return;
    var hs: std.ArrayList(Header) = .empty;
    try objectHeaders(c, r, &hs);
    const ims = if (c.header("if-modified-since")) |v| util.parseHttpDate(v) else null;
    const ius = if (c.header("if-unmodified-since")) |v| util.parseHttpDate(v) else null;
    const cond: object.conditional.Conditions = .{
        .if_match = c.header("if-match"),
        .if_none_match = c.header("if-none-match"),
        .if_modified_since_ns = if (ims) |s| @as(i128, s) * std.time.ns_per_s else null,
        .if_unmodified_since_ns = if (ius) |s| @as(i128, s) * std.time.ns_per_s else null,
    };
    switch (object.conditional.evalRead(cond, r.etag, info.created_ns)) {
        .proceed => {},
        .not_modified => return c.send(.not_modified, "", null, hs.items),
        .precondition_failed => return c.send(.precondition_failed, "", null, hs.items),
    }
    var range: ?core.Range = null;
    if (c.header("range")) |rh| if (core.RangeSpec.parse(rh)) |spec| {
        range = spec.resolve(r.size) catch {
            try hs.append(c.a, .{ .name = "Content-Range", .value = try std.fmt.allocPrint(c.a, "bytes */{d}", .{r.size}) });
            return c.send(.range_not_satisfiable, "", null, hs.items);
        };
    } else |_| {};
    if (range) |rg| try hs.append(c.a, .{ .name = "Content-Range", .value = try std.fmt.allocPrint(c.a, "bytes {d}-{d}/{d}", .{ rg.offset, rg.last(), r.size }) });
    if (try contentDisposition(c)) |cd| try hs.append(c.a, .{ .name = "Content-Disposition", .value = cd });

    const ctype = if (info.content_type.len > 0 and util.safeValue(info.content_type)) info.content_type else "application/octet-stream";
    const status: std.http.Status = if (range != null) .partial_content else .ok;
    const len = if (range) |rg| rg.length else r.size;
    const all = try c.baseHeaders(hs.items, ctype);
    const opts: std.http.Server.Request.RespondStreamingOptions = .{ .content_length = len, .respond_options = .{ .status = status, .extra_headers = all } };
    const buf = try c.a.alloc(u8, io_buf);
    if (c.method == .HEAD) {
        var bw = try c.req.respondStreaming(buf, opts);
        return bw.flush() catch error.WriteFailed;
    }
    var lazy: LazyBody = .{ .req = c.req, .buf = buf, .opts = opts };
    if (r.kind == .plain) {
        c.svc().read(info, range, &lazy.writer) catch |e| {
            if (lazy.bw != null) return error.StreamAborted;
            return c.failObj(e);
        };
    } else {
        const full = (try resolve(c, info, true)) orelse return;
        const segs = if (range) |rg| try sliceSegs(c.a, full.segs, rg) else full.segs;
        const rbuf = try c.a.alloc(u8, io_buf);
        var br = blob.BlobReader.init(c.svc().store, segs, rbuf);
        _ = br.reader.streamRemaining(&lazy.writer) catch {
            if (lazy.bw != null) return error.StreamAborted;
            return c.fail(.conflict, "A segment of this large object could not be read.");
        };
    }
    return lazy.finish();
}

/// Sends the response head with the first body byte, so early read errors still get a status.
const LazyBody = struct {
    req: *std.http.Server.Request,
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

    /// Ends the body; a short body aborts the connection instead of tripping the length check.
    fn finish(self: *LazyBody) ConnError!void {
        const bw = self.begin() catch return error.WriteFailed;
        bw.writer.flush() catch return error.WriteFailed;
        switch (bw.state) {
            .content_length => |left| if (left != 0) return error.StreamAborted,
            else => {},
        }
        bw.end() catch return error.WriteFailed;
    }
};

fn getManifest(c: *Ctx, info: object.ObjectInfo) ConnError!void {
    const stored = (try readManifest(c, info)) orelse return;
    var out: std.Io.Writer.Allocating = .init(c.a);
    const raw = if (c.q("format")) |f| std.mem.eql(u8, f, "raw") else false;
    (if (raw) slo.renderRaw(&out.writer, stored) else slo.renderStored(&out.writer, stored)) catch return error.OutOfMemory;
    const etag = try etagHex(c.a, info.etag);
    return c.send(.ok, if (c.method == .HEAD) "" else out.written(), "application/json; charset=utf-8", &.{
        .{ .name = "X-Static-Large-Object", .value = "True" },
        .{ .name = "Etag", .value = etag },
    });
}

// ---- PUT ----

const Common = struct {
    content_type: ?[]const u8,
    metadata: []object.Header,
    system: object.SystemHeaders,
    has_system: bool,
};

fn commonInput(c: *Ctx) ConnError!?Common {
    const changes = meta.fromHeaders(c.a, c.headers, "x-object-meta-", meta.max_name) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try c.fail(.bad_request, "Invalid object metadata.");
            return null;
        },
    };
    var md: std.ArrayList(object.Header) = .empty;
    var total: usize = 0;
    for (changes) |m| if (m.value.len > 0) {
        total += m.name.len + m.value.len;
        try md.append(c.a, .{ .name = m.name, .value = m.value });
    };
    if (total > object.user_meta_limit) {
        try c.fail(.bad_request, "Metadata too large.");
        return null;
    }
    var sys: object.SystemHeaders = .{};
    var has = false;
    inline for (.{
        .{ "cache_control", "cache-control" },
        .{ "content_disposition", "content-disposition" },
        .{ "content_encoding", "content-encoding" },
        .{ "content_language", "content-language" },
        .{ "expires", "expires" },
    }) |p| if (c.header(p[1])) |v| {
        @field(sys, p[0]) = v;
        has = true;
    };
    var ct = c.header("content-type");
    if (ct) |v| if (v.len == 0 or v.len > 256 or !util.safeValue(v)) {
        ct = null;
    };
    return .{ .content_type = ct, .metadata = md.items, .system = sys, .has_system = has };
}

fn put(c: *Ctx) ConnError!void {
    if (c.header("x-copy-from")) |src| {
        if (c.tempurl) return c.fail(.bad_request, "Copy is not allowed with a temp URL.");
        const parts = parseObjectRef(c, src) orelse return c.fail(.precondition_failed, "X-Copy-From header must be of the form <container name>/<object name>");
        return copyObj(c, parts[0], parts[1], c.container, c.object);
    }
    if (!c.allowed(.put_object, c.container, c.object)) return c.denied();
    if (c.length_missing) return c.fail(.length_required, "Missing Content-Length or chunked transfer encoding.");
    if (c.req.head.content_length) |n| if (n > max_object_size) return c.fail(.payload_too_large, "Object too large.");
    const mm = c.q("multipart-manifest");
    if (mm != null and std.mem.eql(u8, mm.?, "put")) {
        if (c.tempurl) return c.fail(.bad_request, "Manifests are not allowed with a temp URL.");
        return sloPut(c);
    }
    const ci = (try commonInput(c)) orelse return;
    var in: object.PutInput = .{
        .content_type = ci.content_type orelse "application/octet-stream",
        .content_length = c.req.head.content_length,
        .metadata = ci.metadata,
        .system = ci.system,
    };
    if (c.header("etag")) |e| in.content_md5 = util.parseMd5Hex(e) orelse return c.fail(.unprocessable_entity, "Invalid Etag.");
    if (c.header("if-none-match")) |v| in.conditions.if_none_match = v;
    var internal_buf: [1]object.Header = undefined;
    if (c.header("x-object-manifest")) |v| {
        if (c.tempurl) return c.fail(.bad_request, "Manifests are not allowed with a temp URL.");
        const dec = util.percentDecodeAlloc(c.a, v, false) catch return c.fail(.bad_request, "Invalid X-Object-Manifest.");
        if (splitManifest(dec) == null or dec.len > 1024 or !util.safeValue(dec)) return c.fail(.bad_request, "X-Object-Manifest must be <container>/<prefix>.");
        internal_buf[0] = .{ .name = dlo_hdr, .value = dec };
        in.internal = &internal_buf;
    }
    if (c.svc().headBucket(c.container)) |_| {} else |e| return c.failObj(e);
    var body_buf: [io_buf]u8 = undefined;
    const body = try c.req.readerExpectContinue(&body_buf);
    const info = c.svc().put(c.container, c.object, body, in) catch |e| return c.failObj(e);
    return created(c, info, try etagHex(c.a, info.etag), &.{});
}

fn created(c: *Ctx, info: object.ObjectInfo, etag: []const u8, extra: []const Header) ConnError!void {
    const lm = try c.a.create([29]u8);
    var hs: std.ArrayList(Header) = .empty;
    try hs.appendSlice(c.a, extra);
    try hs.append(c.a, .{ .name = "Etag", .value = etag });
    try hs.append(c.a, .{ .name = "Last-Modified", .value = util.httpDate(lm, @intCast(@divFloor(info.created_ns, std.time.ns_per_s))) });
    return c.send(.created, "", null, hs.items);
}

fn sloPut(c: *Ctx) ConnError!void {
    var body_buf: [io_buf]u8 = undefined;
    const rd = try c.req.readerExpectContinue(&body_buf);
    const body = rd.allocRemaining(c.a, .limited(slo.max_manifest_bytes + 1)) catch |e| return switch (e) {
        error.StreamTooLong => c.fail(.payload_too_large, "Manifest is too large."),
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed => error.ReadFailed,
    };
    const segs = slo.parsePut(c.a, body) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooManySegments => c.fail(.bad_request, "Too many segments (max 1000)."),
        error.ManifestTooLarge => c.fail(.payload_too_large, "Manifest is too large."),
        error.BadManifest => c.fail(.bad_request, "Manifest must be a list of {\"path\", \"etag\", \"size_bytes\", \"range\"} objects."),
    };
    const ci = (try commonInput(c)) orelse return;
    var errs: std.Io.Writer.Allocating = .init(c.a);
    const stored = try c.a.alloc(slo.Stored, segs.len);
    for (segs, stored, 0..) |s, *st, i| {
        st.* = .{ .container = s.container, .object = s.object, .hash = "", .bytes = 0, .range = s.range };
        const problem: ?[]const u8 = blk: {
            if (!c.allowed(.get_object, s.container, s.object)) break :blk "403 Forbidden";
            const si = c.svc().head(c.a, s.container, s.object) catch |e| switch (e) {
                error.NoSuchKey, error.NoSuchBucket, error.InvalidKey, error.KeyTooLong => break :blk "404 Not Found",
                else => return c.failObj(e),
            };
            if (kindOf(si) != .plain) break :blk "Nested large objects are not supported";
            st.hash = try etagHex(c.a, si.etag);
            if (s.etag) |want| if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, want, "\""), st.hash)) break :blk "Etag Mismatch";
            if (s.size) |want| if (want != si.size) break :blk "Size Mismatch";
            const rg = slo.resolveRange(c.a, s.range, si.size) catch break :blk "Invalid Range";
            st.bytes = rg.length;
            if (st.bytes == 0 and i + 1 < segs.len) break :blk "Too small; each segment must be at least 1 byte.";
            st.content_type = if (si.content_type.len > 0) si.content_type else "application/octet-stream";
            st.mtime_ns = si.created_ns;
            break :blk null;
        };
        if (problem) |p| errs.writer.print("/{s}/{s}, {s}\n", .{ s.container, s.object, p }) catch return error.OutOfMemory;
    }
    if (errs.written().len > 0) return c.send(.bad_request, try std.fmt.allocPrint(c.a, "Errors:\n{s}", .{errs.written()}), null, &.{});
    const tag = slo.etag(stored);
    const total = slo.totalBytes(stored);
    var out: std.Io.Writer.Allocating = .init(c.a);
    slo.renderStored(&out.writer, stored) catch return error.OutOfMemory;
    const marker = [_]object.Header{.{ .name = slo_hdr, .value = try std.fmt.allocPrint(c.a, "{d} {s}", .{ total, &tag }) }};
    var src: std.Io.Reader = .fixed(out.written());
    const info = c.svc().put(c.container, c.object, &src, .{
        .content_type = ci.content_type orelse "application/octet-stream",
        .metadata = ci.metadata,
        .system = ci.system,
        .internal = &marker,
    }) catch |e| return c.failObj(e);
    return created(c, info, try std.fmt.allocPrint(c.a, "\"{s}\"", .{&tag}), &.{});
}

// ---- POST / COPY ----

fn post(c: *Ctx) ConnError!void {
    if (!c.allowed(.put_object, c.container, c.object)) return c.denied();
    const info = c.svc().head(c.a, c.container, c.object) catch |e| return c.failObj(e);
    const ci = (try commonInput(c)) orelse return;
    _ = object.copy.copyObject(c.svc(), .{ .bucket = c.container, .key = c.object }, c.container, c.object, .{
        .put = .{
            .content_type = ci.content_type orelse info.content_type,
            .metadata = ci.metadata,
            .system = if (ci.has_system) ci.system else info.system,
        },
        .replace_metadata = true,
    }) catch |e| return c.failObj(e);
    return c.send(.accepted, "", null, &.{});
}

/// "container/object" (leading slash optional, URL-encoded) split in two.
fn parseObjectRef(c: *Ctx, v: []const u8) ?struct { []const u8, []const u8 } {
    const dec = util.percentDecodeAlloc(c.a, v, false) catch return null;
    const p = if (dec.len > 0 and dec[0] == '/') dec[1..] else dec;
    const i = std.mem.indexOfScalar(u8, p, '/') orelse return null;
    if (i == 0 or i + 1 >= p.len) return null;
    return .{ p[0..i], p[i + 1 ..] };
}

fn copyVerb(c: *Ctx) ConnError!void {
    const dst = c.header("destination") orelse return c.fail(.precondition_failed, "Destination header required");
    const parts = parseObjectRef(c, dst) orelse return c.fail(.precondition_failed, "Destination header must be of the form <container name>/<object name>");
    return copyObj(c, c.container, c.object, parts[0], parts[1]);
}

fn copyObj(c: *Ctx, sc: []const u8, so: []const u8, dc: []const u8, do: []const u8) ConnError!void {
    if (!c.allowed(.get_object, sc, so) or !c.allowed(.put_object, dc, do)) return c.denied();
    const info = c.svc().head(c.a, sc, so) catch |e| return c.failObj(e);
    const ci = (try commonInput(c)) orelse return;
    const fresh = if (c.header("x-fresh-metadata")) |v| std.ascii.eqlIgnoreCase(v, "true") else false;
    var md: std.ArrayList(object.Header) = .empty;
    if (!fresh) for (info.metadata) |m| {
        var over = false;
        for (ci.metadata) |n| if (std.mem.eql(u8, n.name, m.name)) {
            over = true;
        };
        if (!over) try md.append(c.a, m);
    };
    try md.appendSlice(c.a, ci.metadata);
    const put_in: object.PutInput = .{
        .content_type = ci.content_type orelse info.content_type,
        .metadata = md.items,
        .system = if (ci.has_system) ci.system else info.system,
    };
    const mm = c.q("multipart-manifest");
    const keep_manifest = mm != null and std.mem.eql(u8, mm.?, "get");
    var out: object.ObjectInfo = undefined;
    var etag: []const u8 = undefined;
    if (kindOf(info) != .plain and !keep_manifest) {
        const r = (try resolve(c, info, true)) orelse return;
        var in = put_in;
        in.content_length = r.size;
        const rbuf = try c.a.alloc(u8, io_buf);
        var br = blob.BlobReader.init(c.svc().store, r.segs, rbuf);
        out = c.svc().put(dc, do, &br.reader, in) catch |e| return c.failObj(e);
        etag = try etagHex(c.a, out.etag);
    } else {
        out = object.copy.copyObject(c.svc(), .{ .bucket = sc, .key = so }, dc, do, .{ .put = put_in, .replace_metadata = true }) catch |e| return c.failObj(e);
        etag = (try resolve(c, out, false) orelse return).etag;
    }
    var from: std.Io.Writer.Allocating = .init(c.a);
    util.percentEncode(&from.writer, sc, false) catch return error.OutOfMemory;
    from.writer.writeByte('/') catch return error.OutOfMemory;
    util.percentEncode(&from.writer, so, true) catch return error.OutOfMemory;
    const lm = try c.a.create([29]u8);
    return created(c, out, etag, &.{
        .{ .name = "X-Copied-From", .value = from.written() },
        .{ .name = "X-Copied-From-Last-Modified", .value = util.httpDate(lm, @intCast(@divFloor(info.created_ns, std.time.ns_per_s))) },
    });
}

// ---- DELETE ----

fn delete(c: *Ctx) ConnError!void {
    if (!c.allowed(.delete_object, c.container, c.object)) return c.denied();
    const info = c.svc().head(c.a, c.container, c.object) catch |e| return c.failObj(e);
    const mm = c.q("multipart-manifest");
    if (mm == null or !std.mem.eql(u8, mm.?, "delete") or kindOf(info) != .slo) {
        c.svc().delete(c.container, c.object) catch |e| return c.failObj(e);
        return c.send(.no_content, "", null, &.{});
    }
    const stored = (try readManifest(c, info)) orelse return;
    var deleted: usize = 0;
    var missing: usize = 0;
    var errs: std.ArrayList([]const u8) = .empty;
    for (stored) |s| {
        if (!c.allowed(.delete_object, s.container, s.object)) {
            try errs.append(c.a, try std.fmt.allocPrint(c.a, "/{s}/{s}", .{ s.container, s.object }));
            continue;
        }
        _ = c.svc().head(c.a, s.container, s.object) catch {
            missing += 1;
            continue;
        };
        c.svc().delete(s.container, s.object) catch {
            try errs.append(c.a, try std.fmt.allocPrint(c.a, "/{s}/{s}", .{ s.container, s.object }));
            continue;
        };
        deleted += 1;
    }
    if (errs.items.len == 0) {
        c.svc().delete(c.container, c.object) catch |e| return c.failObj(e);
        deleted += 1;
    }
    const status = if (errs.items.len == 0) "200 OK" else "400 Bad Request";
    var out: std.Io.Writer.Allocating = .init(c.a);
    const w = &out.writer;
    const json = if (c.header("accept")) |a| std.mem.indexOf(u8, a, "json") != null else false;
    if (json) {
        w.print("{{\"Number Deleted\": {d}, \"Number Not Found\": {d}, \"Response Body\": \"\", \"Response Status\": \"{s}\", \"Errors\": [", .{ deleted, missing, status }) catch return error.OutOfMemory;
        for (errs.items, 0..) |e, i| {
            if (i > 0) w.writeAll(", ") catch return error.OutOfMemory;
            w.writeByte('[') catch return error.OutOfMemory;
            util.jsonString(w, e) catch return error.OutOfMemory;
            w.writeAll(", \"403 Forbidden\"]") catch return error.OutOfMemory;
        }
        w.writeAll("]}") catch return error.OutOfMemory;
    } else {
        w.print("Number Deleted: {d}\nNumber Not Found: {d}\nResponse Body: \nResponse Status: {s}\nErrors: \n", .{ deleted, missing, status }) catch return error.OutOfMemory;
        for (errs.items) |e| w.print("{s}, 403 Forbidden\n", .{e}) catch return error.OutOfMemory;
    }
    return c.send(.ok, out.written(), if (json) "application/json; charset=utf-8" else "text/plain; charset=utf-8", &.{});
}

// ---- temp URLs ----

/// Authorizes a temp URL request against account and container keys, then runs it
/// as the identity that set the matching key.
pub fn tempUrl(c: *Ctx) ConnError!void {
    const unauthorized = "Temp URL invalid or expired.";
    if (c.container.len == 0 or c.object.len == 0) return c.fail(.unauthorized, unauthorized);
    const methods: []const []const u8 = switch (c.method) {
        .GET => &.{"GET"},
        .PUT => &.{"PUT"},
        .HEAD => &.{ "HEAD", "GET", "PUT" },
        else => return c.fail(.unauthorized, unauthorized),
    };
    const sig = auth.parseSig(c.q("temp_url_sig") orelse "") orelse return c.fail(.unauthorized, unauthorized);
    const exp = auth.parseExpires(c.q("temp_url_expires") orelse "") orelse return c.fail(.unauthorized, unauthorized);
    if (exp <= std.time.timestamp()) return c.fail(.unauthorized, unauthorized);
    var signed = c.path;
    const prefix = c.q("temp_url_prefix");
    if (prefix) |p| {
        if (!std.mem.startsWith(u8, c.object, p)) return c.fail(.unauthorized, unauthorized);
        signed = try std.fmt.allocPrint(c.a, "/v1/{s}/{s}/{s}", .{ c.account, c.container, p });
    }
    var owner: ?[]const u8 = null;
    const acct = c.st.accounts.get(c.a, c.account) catch return c.fail(.unauthorized, unauthorized);
    if (acct.owner) |o| if (keysMatch(acct.meta, sig, methods, exp, signed, prefix != null)) {
        owner = o;
    };
    if (owner == null) if (meta.getContainer(c.svc(), c.a, c.container)) |cm| {
        if (cm.owner) |o| if (keysMatch(cm.meta, sig, methods, exp, signed, prefix != null)) {
            owner = o;
        };
    } else |_| {};
    c.who = c.st.access.known(owner orelse return c.fail(.unauthorized, unauthorized)) orelse return c.fail(.unauthorized, unauthorized);
    c.tempurl = true;
    return switch (c.method) {
        .PUT => put(c),
        else => get(c),
    };
}

fn keysMatch(list: []const meta.Meta, sig: auth.Sig, methods: []const []const u8, exp: i64, path: []const u8, prefix: bool) bool {
    var keys: [2][]const u8 = undefined;
    var n: usize = 0;
    for ([_][]const u8{ "temp-url-key", "temp-url-key-2" }) |name| if (meta.find(list, name)) |k| if (k.len > 0) {
        keys[n] = k;
        n += 1;
    };
    return n > 0 and auth.verifySig(sig, keys[0..n], methods, exp, path, prefix);
}

test "segment slicing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const id = core.ObjectId.random();
    const segs = [_]blob.Segment{
        .{ .blob = id, .offset = 0, .length = 5 },
        .{ .blob = id, .offset = 10, .length = 5 },
        .{ .blob = id, .offset = 20, .length = 5 },
    };
    const s = try sliceSegs(arena.allocator(), &segs, .{ .offset = 3, .length = 8 });
    try std.testing.expectEqual(@as(usize, 3), s.len);
    try std.testing.expectEqual(@as(u64, 3), s[0].offset);
    try std.testing.expectEqual(@as(u64, 2), s[0].length);
    try std.testing.expectEqual(@as(u64, 10), s[1].offset);
    try std.testing.expectEqual(@as(u64, 5), s[1].length);
    try std.testing.expectEqual(@as(u64, 20), s[2].offset);
    try std.testing.expectEqual(@as(u64, 1), s[2].length);
    const t = try sliceSegs(arena.allocator(), &segs, .{ .offset = 9, .length = 2 });
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqual(@as(u64, 14), t[0].offset);
    try std.testing.expectEqual(@as(u64, 20), t[1].offset);
    try std.testing.expectEqual(@as(u64, 1), t[1].length);
}

test "manifest header split" {
    const p = splitManifest("/segs/pre/fix").?;
    try std.testing.expectEqualStrings("segs", p[0]);
    try std.testing.expectEqualStrings("pre/fix", p[1]);
    try std.testing.expectEqualStrings("", splitManifest("segs").?[1]);
    try std.testing.expect(splitManifest("/") == null);
}
