//! One authenticated catalog request and its JSON responses (Iceberg REST and
//! S3 Tables error shapes).
const std = @import("std");
const s3 = @import("../s3/root.zig");
const json = @import("json.zig");

pub const RawError = s3.server.RawError;
const Status = std.http.Status;

pub const Req = struct {
    raw: *std.http.Server.Request,
    arena: std.mem.Allocator,
    method: std.http.Method,
    /// Path without the query, still percent-encoded.
    path: []const u8,
    query: []const u8,
    body: []const u8,
    auth: s3.sigv4.Auth,
    request_id: [16]u8,

    /// Decoded query parameter.
    pub fn param(r: *Req, name: []const u8) RawError!?[]const u8 {
        return s3.router.queryParam(r.arena, r.query, name) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidUri => null,
        };
    }

    /// Principal recorded as creator/modifier.
    pub fn who(r: *const Req) []const u8 {
        return if (r.auth.principal.len > 0) r.auth.principal else "anonymous";
    }

    pub fn send(r: *Req, status: Status, body: []const u8, extra: []const std.http.Header) RawError!void {
        var hdrs: [4]std.http.Header = undefined;
        var n: usize = 0;
        hdrs[n] = .{ .name = "content-type", .value = "application/json" };
        n += 1;
        hdrs[n] = .{ .name = "x-amz-request-id", .value = &r.request_id };
        n += 1;
        for (extra[0..@min(extra.len, hdrs.len - n)]) |h| {
            hdrs[n] = h;
            n += 1;
        }
        r.raw.respond(body, .{ .status = status, .extra_headers = hdrs[0..n] }) catch return error.WriteFailed;
    }

    pub fn sendJson(r: *Req, status: Status, v: json.Value) RawError!void {
        return r.send(status, try json.stringify(r.arena, v), &.{});
    }

    pub fn sendObject(r: *Req, status: Status, o: json.ObjectMap) RawError!void {
        return r.sendJson(status, .{ .object = o });
    }

    pub fn noContent(r: *Req) RawError!void {
        r.raw.respond("", .{ .status = .no_content, .extra_headers = &.{.{ .name = "x-amz-request-id", .value = &r.request_id }} }) catch return error.WriteFailed;
    }

    /// Iceberg REST error model.
    pub fn iceberg(r: *Req, status: Status, kind: []const u8, msg: []const u8) RawError!void {
        var e = json.newObject(r.arena);
        try e.put("message", json.s(msg));
        try e.put("type", json.s(kind));
        try e.put("code", json.i(@intFromEnum(status)));
        var o = json.newObject(r.arena);
        try o.put("error", .{ .object = e });
        return r.sendObject(status, o);
    }

    /// S3 Tables (rest-json) error: type in x-amzn-errortype, message in the body.
    pub fn tables(r: *Req, status: Status, kind: []const u8, msg: []const u8) RawError!void {
        var o = json.newObject(r.arena);
        try o.put("message", json.s(msg));
        return r.send(status, try json.stringify(r.arena, .{ .object = o }), &.{.{ .name = "x-amzn-errortype", .value = kind }});
    }
};

/// Raw path segments after `prefix` (empty segments dropped).
pub fn segments(arena: std.mem.Allocator, path: []const u8) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (out.items.len >= 16) break;
        try out.append(arena, seg);
    }
    return out.items;
}

pub fn decode(arena: std.mem.Allocator, seg: []const u8) error{ OutOfMemory, InvalidUri }![]const u8 {
    return s3.router.percentDecode(arena, seg, false);
}

/// Unix ms to ISO 8601 with milliseconds.
pub fn isoMs(arena: std.mem.Allocator, ms: i64) error{OutOfMemory}![]const u8 {
    var buf: [24]u8 = undefined;
    const base = @import("../core/root.zig").time.iso8601(@as(i128, ms) * std.time.ns_per_ms, &buf);
    return std.fmt.allocPrint(arena, "{s}.{d:0>3}Z", .{ base[0..19], @as(u64, @intCast(@mod(ms, 1000))) });
}

test "segments drop empties and cap count" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const s = try segments(a.allocator(), "/a//b/");
    try std.testing.expectEqual(@as(usize, 2), s.len);
    const many = try segments(a.allocator(), "/a" ** 40);
    try std.testing.expectEqual(@as(usize, 16), many.len);
    try std.testing.expectEqualStrings("1970-01-01T00:00:01.250Z", try isoMs(a.allocator(), 1250));
}
