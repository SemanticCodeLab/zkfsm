//! Remote S3 source access for batch replication: version listings and
//! streamed, SigV4-signed GETs whose body is handed to a consumer as a reader.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const sign = @import("../backend/s3/sign.zig");
const replication = @import("../replication/root.zig");

const Allocator = std.mem.Allocator;
const client = replication.client;
const http = std.http;

pub const Error = client.Error || error{BadListing};

pub const Entry = struct {
    key: []const u8,
    version_id: []const u8,
    delete_marker: bool,
    is_latest: bool,
    mtime_ns: i128,
    size: u64,
    etag: []const u8,
};

pub const Page = struct {
    entries: []Entry,
    truncated: bool,
    next_key: []const u8,
    next_version: []const u8,
};

pub const max_list_entries = 1000;

/// One ListObjectVersions page.
pub fn listVersions(hc: *http.Client, a: Allocator, r: client.Remote, bucket: []const u8, prefix: []const u8, key_marker: []const u8, version_marker: []const u8) Error!Page {
    var q: std.ArrayList(client.Param) = .empty;
    try q.append(a, .{ .name = "versions", .value = "" });
    try q.append(a, .{ .name = "max-keys", .value = "1000" });
    if (prefix.len > 0) try q.append(a, .{ .name = "prefix", .value = prefix });
    if (key_marker.len > 0) try q.append(a, .{ .name = "key-marker", .value = key_marker });
    if (version_marker.len > 0) try q.append(a, .{ .name = "version-id-marker", .value = version_marker });
    const res = try client.send(hc, a, r, .{ .method = .GET, .path = try std.fmt.allocPrint(a, "/{s}", .{bucket}), .query = q.items });
    if (!res.ok()) return error.BadListing;
    return parseListing(a, res.body);
}

pub fn parseListing(a: Allocator, body: []const u8) Error!Page {
    var out: std.ArrayList(Entry) = .empty;
    var pos: usize = 0;
    while (true) {
        const v = std.mem.indexOfPos(u8, body, pos, "<Version>");
        const d = std.mem.indexOfPos(u8, body, pos, "<DeleteMarker>");
        const marker = if (v != null and d != null) d.? < v.? else d != null;
        const start = (if (marker) d else v) orelse break;
        const close = if (marker) "</DeleteMarker>" else "</Version>";
        const end = std.mem.indexOfPos(u8, body, start, close) orelse return error.BadListing;
        const el = body[start..end];
        pos = end + close.len;
        if (out.items.len >= max_list_entries) return error.BadListing;
        const key = try field(a, el, "Key") orelse return error.BadListing;
        const lm = try field(a, el, "LastModified") orelse "";
        try out.append(a, .{
            .key = key,
            .version_id = try field(a, el, "VersionId") orelse "null",
            .delete_marker = marker,
            .is_latest = std.mem.eql(u8, try field(a, el, "IsLatest") orelse "", "true"),
            .mtime_ns = replication.targets.parseRfc3339(lm) orelse 0,
            .size = std.fmt.parseInt(u64, try field(a, el, "Size") orelse "0", 10) catch return error.BadListing,
            .etag = std.mem.trim(u8, try field(a, el, "ETag") orelse "", "\""),
        });
    }
    return .{
        .entries = out.items,
        .truncated = std.mem.eql(u8, try field(a, body, "IsTruncated") orelse "", "true"),
        .next_key = try field(a, body, "NextKeyMarker") orelse "",
        .next_version = try field(a, body, "NextVersionIdMarker") orelse "",
    };
}

fn field(a: Allocator, el: []const u8, name: []const u8) Error!?[]const u8 {
    var sc: s3.xml_read.Scanner = .{ .s = el };
    const raw = (sc.next(name) catch return error.BadListing) orelse return null;
    return s3.xml_read.unescape(a, raw) catch |e| if (e == error.OutOfMemory) error.OutOfMemory else error.BadListing;
}

/// Response head of a streamed GET.
pub const Head = struct {
    status: u16,
    content_length: ?u64 = null,
    content_type: []const u8 = "",
    etag: []const u8 = "",
    /// User metadata names without `x-amz-meta-`.
    metadata: []const http.Header = &.{},
    tagging: []const u8 = "",
};

pub const Consumer = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, head: Head, body: *std.Io.Reader) bool,
};

/// GETs `path`; on 2xx hands the body to `c` (its result is returned as `consumed`).
pub fn getInto(hc: *http.Client, a: Allocator, r: client.Remote, path: []const u8, query: []const client.Param, c: Consumer) client.Error!struct { head: Head, consumed: bool } {
    var path_w: std.Io.Writer.Allocating = .init(a);
    sign.uriEncode(&path_w.writer, path, false) catch return error.OutOfMemory;
    var query_w: std.Io.Writer.Allocating = .init(a);
    sign.canonicalQuery(&query_w.writer, query) catch return error.OutOfMemory;
    const date = sign.amzDate(std.time.nanoTimestamp());
    const signed = [_]sign.Header{
        .{ .name = "host", .value = r.endpoint },
        .{ .name = "x-amz-content-sha256", .value = sign.empty_sha256 },
        .{ .name = "x-amz-date", .value = &date },
    };
    var auth_buf: [512]u8 = undefined;
    const auth = sign.authorization(.{ .access_key = r.access_key, .secret_key = r.secret_key }, r.region, "s3", .{
        .method = "GET",
        .canonical_uri = path_w.written(),
        .canonical_query = query_w.written(),
        .headers = &signed,
        .payload_hash = sign.empty_sha256,
        .amz_date = &date,
    }, &auth_buf) catch return error.OutOfMemory;
    const hp = splitHostPort(r.endpoint) orelse return error.InvalidEndpoint;
    const uri: std.Uri = .{
        .scheme = if (r.secure) "https" else "http",
        .host = .{ .raw = hp.host },
        .port = hp.port,
        .path = .{ .percent_encoded = path_w.written() },
        .query = if (query_w.written().len == 0) null else .{ .percent_encoded = query_w.written() },
    };
    const extra = [_]http.Header{
        .{ .name = "x-amz-content-sha256", .value = sign.empty_sha256 },
        .{ .name = "x-amz-date", .value = &date },
    };
    var req = hc.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
        .keep_alive = true,
        .headers = .{
            .host = .{ .override = r.endpoint },
            .authorization = .{ .override = auth },
            .user_agent = .{ .override = "zkfsm-batch" },
            .accept_encoding = .omit,
        },
        .extra_headers = &extra,
    }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
    defer req.deinit();
    req.sendBodiless() catch return error.Unreachable;
    var redirect_buf: [0]u8 = .{};
    var resp = req.receiveHead(&redirect_buf) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unreachable;
    var head: Head = .{ .status = @intFromEnum(resp.head.status), .content_length = resp.head.content_length };
    var meta: std.ArrayList(http.Header) = .empty;
    var it = resp.head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-type")) head.content_type = try a.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "etag")) head.etag = try a.dupe(u8, std.mem.trim(u8, h.value, "\""));
        if (std.ascii.startsWithIgnoreCase(h.name, "x-amz-meta-") and h.name.len > 11 and meta.items.len < 64)
            try meta.append(a, .{ .name = try std.ascii.allocLowerString(a, h.name[11..]), .value = try a.dupe(u8, h.value) });
    }
    head.metadata = meta.items;
    var tbuf: [64 * 1024]u8 = undefined;
    const body = req.reader.bodyReader(&tbuf, resp.head.transfer_encoding, resp.head.content_length);
    if (head.status < 200 or head.status >= 300) {
        _ = body.discardRemaining() catch {};
        return .{ .head = head, .consumed = false };
    }
    return .{ .head = head, .consumed = c.func(c.ctx, head, body) };
}

const HostPort = struct { host: []const u8, port: ?u16 };

fn splitHostPort(ep: []const u8) ?HostPort {
    if (ep.len == 0) return null;
    if (ep[0] == '[') {
        const close = std.mem.indexOfScalar(u8, ep, ']') orelse return null;
        const rest = ep[close + 1 ..];
        if (rest.len == 0) return .{ .host = ep[1..close], .port = null };
        if (rest[0] != ':') return null;
        return .{ .host = ep[1..close], .port = std.fmt.parseInt(u16, rest[1..], 10) catch return null };
    }
    const colon = std.mem.lastIndexOfScalar(u8, ep, ':') orelse return .{ .host = ep, .port = null };
    return .{ .host = ep[0..colon], .port = std.fmt.parseInt(u16, ep[colon + 1 ..], 10) catch return null };
}

test "listing parse keeps order and kinds" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const body =
        \\<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>b</NextKeyMarker>
        \\<Version><Key>a&amp;b</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><LastModified>2024-01-01T00:00:00.000Z</LastModified><ETag>"e"</ETag><Size>3</Size></Version>
        \\<DeleteMarker><Key>a&amp;b</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><LastModified>2023-01-01T00:00:00Z</LastModified></DeleteMarker>
        \\</ListVersionsResult>
    ;
    const p = try parseListing(arena.allocator(), body);
    try std.testing.expectEqual(@as(usize, 2), p.entries.len);
    try std.testing.expectEqualStrings("a&b", p.entries[0].key);
    try std.testing.expect(!p.entries[0].delete_marker and p.entries[1].delete_marker);
    try std.testing.expectEqual(@as(u64, 3), p.entries[0].size);
    try std.testing.expect(p.truncated);
    try std.testing.expectEqualStrings("b", p.next_key);
    try std.testing.expectError(error.BadListing, parseListing(arena.allocator(), "<Version><Key>x</Key>"));
}
