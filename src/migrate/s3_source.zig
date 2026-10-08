//! Online source: a live S3 endpoint read with SigV4 (bucket list, configuration
//! subresources, ListObjectVersions pages, per-version HEAD/tagging, streamed GETs).
const std = @import("std");
const sign = @import("../backend/s3/sign.zig");
const xml = @import("../backend/remote/xml.zig");
const core = @import("../core/root.zig");
const model = @import("model.zig");
const xlmeta = @import("xlmeta.zig");

const http = std.http;

pub const Error = error{ OutOfMemory, Unreachable, BadResponse, InvalidEndpoint };

const max_small = 8 * 1024 * 1024;

const State = struct {
    gpa: std.mem.Allocator,
    req: http.Client.Request,
    status: u16 = 0,
    headers: []model.Header = &.{},
    arena: std.heap.ArenaAllocator,
    tbuf: [16 * 1024]u8 = undefined,
    body: ?*std.Io.Reader = null,

    fn destroy(st: *State) void {
        st.req.deinit();
        st.arena.deinit();
        st.gpa.destroy(st);
    }
};

/// A streamed GET; the reader is valid until `deinit`.
pub const Get = struct {
    st: *State,

    pub fn reader(g: *Get) *std.Io.Reader {
        return g.st.body.?;
    }

    pub fn deinit(g: *Get) void {
        g.st.destroy();
    }
};

pub const Source = struct {
    gpa: std.mem.Allocator,
    client: http.Client,
    endpoint: []const u8,
    host: []const u8,
    port: ?u16,
    secure: bool,
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,

    pub fn init(gpa: std.mem.Allocator, url: []const u8, ak: []const u8, sk: []const u8, region: []const u8) Error!Source {
        const secure = std.ascii.startsWithIgnoreCase(url, "https://");
        if (!secure and !std.ascii.startsWithIgnoreCase(url, "http://")) return error.InvalidEndpoint;
        const rest = url[if (secure) 8 else 7..];
        const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
        if (end == 0) return error.InvalidEndpoint;
        const ep = rest[0..end];
        var host = ep;
        var port: ?u16 = null;
        if (std.mem.lastIndexOfScalar(u8, ep, ':')) |c| if (std.mem.indexOfScalar(u8, ep, ']') == null or c > std.mem.indexOfScalar(u8, ep, ']').?) {
            host = ep[0..c];
            port = std.fmt.parseInt(u16, ep[c + 1 ..], 10) catch return error.InvalidEndpoint;
        };
        host = std.mem.trim(u8, host, "[]");
        return .{ .gpa = gpa, .client = .{ .allocator = gpa }, .endpoint = ep, .host = host, .port = port, .secure = secure, .access_key = ak, .secret_key = sk, .region = region };
    }

    pub fn deinit(s: *Source) void {
        s.client.deinit();
    }

    /// Sends a bodiless signed request and reads the response head.
    fn begin(s: *Source, method: http.Method, path: []const u8, query: []const sign.Param) Error!*State {
        const st = try s.gpa.create(State);
        st.* = .{ .gpa = s.gpa, .req = undefined, .arena = .init(s.gpa) };
        errdefer {
            st.arena.deinit();
            s.gpa.destroy(st);
        }
        const a = st.arena.allocator();
        var path_w: std.Io.Writer.Allocating = .init(a);
        sign.uriEncode(&path_w.writer, path, false) catch return error.OutOfMemory;
        var query_w: std.Io.Writer.Allocating = .init(a);
        sign.canonicalQuery(&query_w.writer, query) catch return error.OutOfMemory;
        const date = sign.amzDate(std.time.nanoTimestamp());
        const signed = [_]sign.Header{
            .{ .name = "host", .value = s.endpoint },
            .{ .name = "x-amz-content-sha256", .value = sign.empty_sha256 },
            .{ .name = "x-amz-date", .value = &date },
        };
        var auth_buf: [512]u8 = undefined;
        const auth = sign.authorization(.{ .access_key = s.access_key, .secret_key = s.secret_key }, s.region, "s3", .{
            .method = @tagName(method),
            .canonical_uri = path_w.written(),
            .canonical_query = query_w.written(),
            .headers = &signed,
            .payload_hash = sign.empty_sha256,
            .amz_date = &date,
        }, &auth_buf) catch return error.OutOfMemory;
        const auth_owned = try a.dupe(u8, auth);
        const date_owned = try a.dupe(u8, &date);
        const uri: std.Uri = .{
            .scheme = if (s.secure) "https" else "http",
            .host = .{ .raw = s.host },
            .port = s.port,
            .path = .{ .percent_encoded = path_w.written() },
            .query = if (query_w.written().len == 0) null else .{ .percent_encoded = query_w.written() },
        };
        st.req = s.client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = true,
            .headers = .{
                .host = .{ .override = s.endpoint },
                .authorization = .{ .override = auth_owned },
                .user_agent = .{ .override = "zkfsm-migrate" },
                .accept_encoding = .omit,
            },
            .extra_headers = &.{
                .{ .name = "x-amz-content-sha256", .value = sign.empty_sha256 },
                .{ .name = "x-amz-date", .value = date_owned },
            },
        }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        errdefer st.req.deinit();
        st.req.sendBodiless() catch return error.Unreachable;
        var redirect_buf: [0]u8 = .{};
        var resp = st.req.receiveHead(&redirect_buf) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
        st.status = @intFromEnum(resp.head.status);
        var hs: std.ArrayList(model.Header) = .empty;
        var it = resp.head.iterateHeaders();
        while (it.next()) |h| try hs.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, std.mem.trim(u8, h.value, " ")) });
        st.headers = hs.items;
        if (method != .HEAD and st.status != 204 and st.status != 304) {
            st.body = st.req.reader.bodyReader(&st.tbuf, resp.head.transfer_encoding, resp.head.content_length);
        } else {
            _ = st.req.reader.bodyReader(&.{}, .none, 0).discardRemaining() catch {};
        }
        return st;
    }

    const Small = struct { status: u16, body: []const u8, headers: []model.Header };

    /// Whole response; strings live in `arena`.
    fn small(s: *Source, arena: std.mem.Allocator, method: http.Method, path: []const u8, query: []const sign.Param) Error!Small {
        const st = try s.begin(method, path, query);
        defer st.destroy();
        var out: Small = .{ .status = st.status, .body = "", .headers = try arena.alloc(model.Header, st.headers.len) };
        for (st.headers, out.headers) |h, *o| o.* = .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) };
        if (st.body) |b| out.body = b.allocRemaining(arena, .limited(max_small)) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unreachable,
        };
        return out;
    }

    pub fn listBuckets(s: *Source, arena: std.mem.Allocator) Error![][]const u8 {
        const r = try s.small(arena, .GET, "/", &.{});
        if (r.status != 200) return failed(r);
        var out: std.ArrayList([]const u8) = .empty;
        var sc: xml.Scanner = .{ .doc = r.body };
        while (sc.next("Bucket")) |b| try out.append(arena, try unescape(arena, xml.find(b, "Name") orelse continue));
        return out.items;
    }

    fn subresource(s: *Source, arena: std.mem.Allocator, bucket: []const u8, name: []const u8) Error!?[]const u8 {
        const path = try std.fmt.allocPrint(arena, "/{s}", .{bucket});
        const r = try s.small(arena, .GET, path, &.{.{ .name = name, .value = "" }});
        if (r.status == 200) return if (r.body.len == 0) null else r.body;
        if (r.status == 404 or r.status == 501 or r.status == 400) return null;
        return failed(r);
    }

    pub fn bucketConfigs(s: *Source, arena: std.mem.Allocator, bucket: []const u8) Error!model.BucketConfigs {
        var c: model.BucketConfigs = .{
            .versioning = try s.subresource(arena, bucket, "versioning"),
            .object_lock = try s.subresource(arena, bucket, "object-lock"),
            .policy = try s.subresource(arena, bucket, "policy"),
            .tagging = try s.subresource(arena, bucket, "tagging"),
            .lifecycle = try s.subresource(arena, bucket, "lifecycle"),
            .encryption = try s.subresource(arena, bucket, "encryption"),
            .notification = try s.subresource(arena, bucket, "notification"),
            .cors = try s.subresource(arena, bucket, "cors"),
        };
        if (c.object_lock) |d| c.lock_enabled = std.mem.indexOf(u8, d, "<ObjectLockEnabled>Enabled</ObjectLockEnabled>") != null;
        if (c.notification) |d| if (std.mem.indexOf(u8, d, "Configuration>") == null or
            (std.mem.indexOf(u8, d, "<QueueConfiguration>") == null and std.mem.indexOf(u8, d, "<TopicConfiguration>") == null and
                std.mem.indexOf(u8, d, "<CloudFunctionConfiguration>") == null))
        {
            c.notification = null;
        };
        return c;
    }

    /// Pages through ListObjectVersions and calls `cb` once per key with all its versions.
    pub fn eachKey(s: *Source, bucket: []const u8, comptime E: type, ctx: anytype, comptime cb: fn (@TypeOf(ctx), []const u8, []model.VersionInfo) E!void) (E || Error)!void {
        var key_marker: std.ArrayList(u8) = .empty;
        defer key_marker.deinit(s.gpa);
        var vid_marker: std.ArrayList(u8) = .empty;
        defer vid_marker.deinit(s.gpa);
        var carry_arena = std.heap.ArenaAllocator.init(s.gpa);
        defer carry_arena.deinit();
        var cur_key: []const u8 = "";
        var cur: std.ArrayList(model.VersionInfo) = .empty;
        while (true) {
            var page = std.heap.ArenaAllocator.init(s.gpa);
            defer page.deinit();
            const a = page.allocator();
            var q: std.ArrayList(sign.Param) = .empty;
            try q.append(a, .{ .name = "versions", .value = "" });
            try q.append(a, .{ .name = "max-keys", .value = "1000" });
            if (key_marker.items.len > 0) try q.append(a, .{ .name = "key-marker", .value = key_marker.items });
            if (vid_marker.items.len > 0) try q.append(a, .{ .name = "version-id-marker", .value = vid_marker.items });
            const path = try std.fmt.allocPrint(a, "/{s}", .{bucket});
            const r = try s.small(a, .GET, path, q.items);
            if (r.status != 200) return failed(r);
            var pos: usize = 0;
            while (nextEntry(r.body, &pos)) |ent| {
                const ca = carry_arena.allocator();
                const key = try unescape(ca, xml.find(ent.body, "Key") orelse return error.BadResponse);
                if (cur.items.len > 0 and !std.mem.eql(u8, key, cur_key)) {
                    try cb(ctx, cur_key, cur.items);
                    // Only the new key's entry must survive the reset.
                    const keep = try s.gpa.dupe(u8, key);
                    defer s.gpa.free(keep);
                    _ = carry_arena.reset(.retain_capacity);
                    cur = .empty;
                    cur_key = try carry_arena.allocator().dupe(u8, keep);
                } else if (cur.items.len == 0) cur_key = key;
                try cur.append(carry_arena.allocator(), try parseEntry(carry_arena.allocator(), ent));
            }
            const truncated = std.mem.eql(u8, std.mem.trim(u8, xml.find(r.body, "IsTruncated") orelse "false", " "), "true");
            if (!truncated) break;
            const nk = try unescape(a, xml.find(r.body, "NextKeyMarker") orelse return error.BadResponse);
            const nv = xml.find(r.body, "NextVersionIdMarker") orelse "";
            key_marker.clearRetainingCapacity();
            try key_marker.appendSlice(s.gpa, nk);
            vid_marker.clearRetainingCapacity();
            try vid_marker.appendSlice(s.gpa, nv);
        }
        if (cur.items.len > 0) try cb(ctx, cur_key, cur.items);
    }

    /// HEAD plus tagging for one version: metadata the listing does not carry.
    pub fn fillVersion(s: *Source, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, v: *model.VersionInfo) Error!void {
        const path = try std.fmt.allocPrint(arena, "/{s}/{s}", .{ bucket, key });
        const q = [_]sign.Param{.{ .name = "versionId", .value = v.src_id }};
        const r = try s.small(arena, .HEAD, path, &q);
        if (r.status != 200) return failed(r);
        const listed_etag = v.etag;
        try model.applyMeta(arena, v, r.headers);
        // The server decrypts and decompresses on GET, so those versions copy as plaintext.
        v.skip_reason = null;
        if (v.etag.len == 0) v.etag = listed_etag;
        v.mode = .none;
        v.until_ns = 0;
        for (r.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "x-amz-object-lock-mode")) v.mode = model.parseMode(h.value);
            if (std.ascii.eqlIgnoreCase(h.name, "x-amz-object-lock-retain-until-date")) v.until_ns = core.time.parseIso8601(h.value) catch 0;
        }
        var count: u32 = 0;
        for (r.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-amz-tagging-count")) {
            count = std.fmt.parseInt(u32, h.value, 10) catch 0;
        };
        v.tags = &.{};
        if (count == 0) return;
        const tq = [_]sign.Param{ .{ .name = "tagging", .value = "" }, .{ .name = "versionId", .value = v.src_id } };
        const t = try s.small(arena, .GET, path, &tq);
        if (t.status != 200) return failed(t);
        var tags: std.ArrayList(model.Tag) = .empty;
        var sc: xml.Scanner = .{ .doc = t.body };
        while (sc.next("Tag")) |tag| try tags.append(arena, .{
            .key = try unescape(arena, xml.find(tag, "Key") orelse continue),
            .value = try unescape(arena, xml.find(tag, "Value") orelse ""),
        });
        v.tags = tags.items;
    }

    pub fn openVersion(s: *Source, bucket: []const u8, key: []const u8, src_id: []const u8) Error!Get {
        var pa = std.heap.ArenaAllocator.init(s.gpa);
        defer pa.deinit();
        const path = try std.fmt.allocPrint(pa.allocator(), "/{s}/{s}", .{ bucket, key });
        const q = [_]sign.Param{.{ .name = "versionId", .value = src_id }};
        const st = try s.begin(.GET, path, &q);
        if (st.status != 200 or st.body == null) {
            std.log.err("GET {s}: HTTP {d}", .{ path, st.status });
            st.destroy();
            return error.BadResponse;
        }
        return .{ .st = st };
    }
};

fn failed(r: anytype) Error {
    std.log.err("source answered HTTP {d}: {s}", .{ r.status, r.body[0..@min(r.body.len, 300)] });
    return error.BadResponse;
}

const Entry = struct { body: []const u8, marker: bool };

/// Next `<Version>` or `<DeleteMarker>` element in document order.
fn nextEntry(doc: []const u8, pos: *usize) ?Entry {
    const v = std.mem.indexOfPos(u8, doc, pos.*, "<Version>");
    const d = std.mem.indexOfPos(u8, doc, pos.*, "<DeleteMarker>");
    const marker = if (v == null) d != null else if (d == null) false else d.? < v.?;
    const start = (if (marker) d else v) orelse return null;
    const open_len: usize = if (marker) "<DeleteMarker>".len else "<Version>".len;
    const close = if (marker) "</DeleteMarker>" else "</Version>";
    const end = std.mem.indexOfPos(u8, doc, start, close) orelse return null;
    pos.* = end + close.len;
    return .{ .body = doc[start + open_len .. end], .marker = marker };
}

fn parseEntry(arena: std.mem.Allocator, e: Entry) Error!model.VersionInfo {
    const vid = std.mem.trim(u8, xml.find(e.body, "VersionId") orelse "null", " ");
    var v: model.VersionInfo = .{ .delete_marker = e.marker, .src_id = try arena.dupe(u8, vid) };
    v.id = versionBytes(vid);
    const lm = xml.find(e.body, "LastModified") orelse return error.BadResponse;
    v.mtime_ns = core.time.parseIso8601(std.mem.trim(u8, lm, " ")) catch return error.BadResponse;
    if (!e.marker) {
        const etag = try unescape(arena, xml.find(e.body, "ETag") orelse "");
        v.etag = std.mem.trim(u8, etag, "\" ");
        v.size = std.fmt.parseInt(u64, std.mem.trim(u8, xml.find(e.body, "Size") orelse "0", " "), 10) catch return error.BadResponse;
    }
    return v;
}

/// UUID ids map to their bytes; other non-null ids to a stable digest.
pub fn versionBytes(vid: []const u8) [16]u8 {
    if (vid.len == 0 or std.mem.eql(u8, vid, "null")) return @splat(0);
    if (xlmeta.parseUuid(vid)) |u| if (!std.mem.allEqual(u8, &u, 0)) return u;
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(vid, &d, .{});
    return d[0..16].*;
}

fn unescape(arena: std.mem.Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
    const buf = try arena.alloc(u8, raw.len);
    return xml.unescape(raw, buf) catch raw;
}

test "version listing entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const doc =
        \\<ListVersionsResult><Version><Key>a&amp;b</Key><VersionId>6053e2b9-7941-4a38-b48f-d5262f2d75e8</VersionId>
        \\<LastModified>2026-10-08T03:48:59.123Z</LastModified><ETag>&quot;abc&quot;</ETag><Size>7</Size></Version>
        \\<DeleteMarker><Key>a&amp;b</Key><VersionId>null</VersionId><LastModified>2026-10-08T03:49:00Z</LastModified></DeleteMarker>
        \\</ListVersionsResult>
    ;
    var pos: usize = 0;
    const e1 = nextEntry(doc, &pos).?;
    const v1 = try parseEntry(arena.allocator(), e1);
    try std.testing.expect(!v1.delete_marker);
    try std.testing.expectEqualStrings("abc", v1.etag);
    try std.testing.expectEqual(@as(u64, 7), v1.size);
    try std.testing.expectEqual(@as(u8, 0x60), v1.id[0]);
    const v2 = try parseEntry(arena.allocator(), nextEntry(doc, &pos).?);
    try std.testing.expect(v2.delete_marker and v2.isNull());
    try std.testing.expect(nextEntry(doc, &pos) == null);
    try std.testing.expect(!std.mem.allEqual(u8, &versionBytes("opaque-id"), 0));
}
