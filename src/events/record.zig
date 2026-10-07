//! Event records in the MinIO-compatible JSON layout, and the per-target payload
//! `{"EventName":..,"Key":..,"Records":[..]}`.
const std = @import("std");
const core = @import("../core/root.zig");
const names = @import("names.zig");

const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;

pub const Event = struct {
    name: names.Name,
    bucket: []const u8,
    key: []const u8 = "",
    version_id: []const u8 = "",
    size: u64 = 0,
    etag: []const u8 = "",
    content_type: []const u8 = "",
    time_ns: i128,
    principal: []const u8 = "",
    source_host: []const u8 = "",
    source_port: []const u8 = "",
    user_agent: []const u8 = "",
    request_id: []const u8 = "",
    /// This node's endpoint (`http://host:port`).
    endpoint: []const u8 = "",
    region: []const u8 = "",
    deployment_id: []const u8 = "",
};

/// RFC 3339 UTC time with milliseconds.
pub fn timeText(ns: i128, buf: *[24]u8) []const u8 {
    const s = core.time.iso8601(ns, buf);
    const ms: u64 = @intCast(@mod(@divFloor(@max(ns, 0), std.time.ns_per_ms), 1000));
    _ = std.fmt.bufPrint(buf[20..23], "{d:0>3}", .{ms}) catch unreachable; // 3 digits fit
    return s;
}

/// Query-escapes an object key the way event consumers expect (space as '+').
fn writeEscapedKey(w: *std.Io.Writer, key: []const u8) std.Io.Writer.Error!void {
    for (key) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => try w.writeByte(c),
        ' ' => try w.writeByte('+'),
        else => try w.print("%{X:0>2}", .{c}),
    };
}

/// One record object for `rule_id`.
pub fn renderRecord(a: Allocator, ev: Event, rule_id: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    writeRecord(&out.writer, a, ev, rule_id) catch return error.OutOfMemory;
    return out.written();
}

fn writeRecord(w: *std.Io.Writer, a: Allocator, ev: Event, rule_id: []const u8) (std.Io.Writer.Error || error{OutOfMemory})!void {
    var tb: [24]u8 = undefined;
    var ek: std.Io.Writer.Allocating = .init(a);
    try writeEscapedKey(&ek.writer, ev.key);
    var seq_buf: [16]u8 = undefined;
    const seq = std.fmt.bufPrint(&seq_buf, "{X:0>16}", .{@as(u64, @truncate(@as(u128, @bitCast(ev.time_ns))))}) catch unreachable; // 16 hex fit
    var arn_buf: std.Io.Writer.Allocating = .init(a);
    try arn_buf.writer.print("arn:aws:s3:::{s}", .{ev.bucket});
    var s: Stringify = .{ .writer = w };
    try s.beginObject();
    try field(&s, "eventVersion", "2.0");
    try field(&s, "eventSource", "minio:s3");
    try field(&s, "awsRegion", ev.region);
    try field(&s, "eventTime", timeText(ev.time_ns, &tb));
    try field(&s, "eventName", ev.name.text());
    try s.objectField("userIdentity");
    try s.beginObject();
    try field(&s, "principalId", ev.principal);
    try s.endObject();
    try s.objectField("requestParameters");
    try s.beginObject();
    try field(&s, "principalId", ev.principal);
    try field(&s, "region", ev.region);
    try field(&s, "sourceIPAddress", ev.source_host);
    try s.endObject();
    try s.objectField("responseElements");
    try s.beginObject();
    if (ev.request_id.len > 0) {
        try field(&s, "x-amz-id-2", ev.deployment_id);
        try field(&s, "x-amz-request-id", ev.request_id);
    }
    try field(&s, "x-minio-deployment-id", ev.deployment_id);
    try field(&s, "x-minio-origin-endpoint", ev.endpoint);
    try s.endObject();
    try s.objectField("s3");
    try s.beginObject();
    try field(&s, "s3SchemaVersion", "1.0");
    try field(&s, "configurationId", rule_id);
    try s.objectField("bucket");
    try s.beginObject();
    try field(&s, "name", ev.bucket);
    try s.objectField("ownerIdentity");
    try s.beginObject();
    try field(&s, "principalId", ev.principal);
    try s.endObject();
    try field(&s, "arn", arn_buf.written());
    try s.endObject();
    try s.objectField("object");
    try s.beginObject();
    try field(&s, "key", ek.written());
    if (!isRemoval(ev.name)) {
        try s.objectField("size");
        try s.write(ev.size);
        if (ev.etag.len > 0) try field(&s, "eTag", ev.etag);
        if (ev.content_type.len > 0) {
            try field(&s, "contentType", ev.content_type);
            try s.objectField("userMetadata");
            try s.beginObject();
            try field(&s, "content-type", ev.content_type);
            try s.endObject();
        }
    }
    if (ev.version_id.len > 0) try field(&s, "versionId", ev.version_id);
    try field(&s, "sequencer", seq);
    try s.endObject();
    try s.endObject();
    try s.objectField("source");
    try s.beginObject();
    try field(&s, "host", ev.source_host);
    try field(&s, "port", ev.source_port);
    try field(&s, "userAgent", ev.user_agent);
    try s.endObject();
    try s.endObject();
}

fn field(s: *Stringify, name: []const u8, v: []const u8) std.Io.Writer.Error!void {
    try s.objectField(name);
    try s.write(v);
}

pub fn isRemoval(n: names.Name) bool {
    return std.mem.startsWith(u8, n.text(), "s3:ObjectRemoved:") or n == .bucket_removed or
        n == .lifecycle_expiration_delete or n == .lifecycle_expiration_delete_marker_created;
}

/// `bucket/key` as targets key their entries.
pub fn entryKey(a: Allocator, ev: Event) error{OutOfMemory}![]const u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ ev.bucket, ev.key });
}

/// The full payload for one record.
pub fn renderPayload(a: Allocator, ev: Event, record: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    var s: Stringify = .{ .writer = w };
    s.beginObject() catch return error.OutOfMemory;
    field(&s, "EventName", ev.name.text()) catch return error.OutOfMemory;
    field(&s, "Key", try entryKey(a, ev)) catch return error.OutOfMemory;
    s.objectField("Records") catch return error.OutOfMemory;
    // The record is already JSON; splice it in.
    w.writeAll("[") catch return error.OutOfMemory;
    w.writeAll(record) catch return error.OutOfMemory;
    w.writeAll("]}") catch return error.OutOfMemory;
    return out.written();
}

test "record and payload shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ev: Event = .{ .name = .object_created_put, .bucket = "b", .key = "dir/a b.txt", .size = 5, .etag = "abc", .content_type = "text/plain", .time_ns = 1_700_000_000_123_000_000, .principal = "root", .source_host = "127.0.0.1" };
    const rec = try renderRecord(a, ev, "r1");
    const p = try renderPayload(a, ev, rec);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, p, .{});
    try std.testing.expectEqualStrings("s3:ObjectCreated:Put", v.object.get("EventName").?.string);
    try std.testing.expectEqualStrings("b/dir/a b.txt", v.object.get("Key").?.string);
    const r = v.object.get("Records").?.array.items[0].object;
    try std.testing.expectEqualStrings("2023-11-14T22:13:20.123Z", r.get("eventTime").?.string);
    const o = r.get("s3").?.object.get("object").?.object;
    try std.testing.expectEqualStrings("dir%2Fa+b.txt", o.get("key").?.string);
    try std.testing.expectEqual(@as(i64, 5), o.get("size").?.integer);
    try std.testing.expectEqualStrings("r1", r.get("s3").?.object.get("configurationId").?.string);
}
