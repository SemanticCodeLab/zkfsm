//! Audit log entries in the MinIO audit JSON layout (version "1"), one per request.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const record = @import("record.zig");

const Ctx = s3.handler.Ctx;
const Header = std.http.Header;
const Stringify = std.json.Stringify;

/// Header values never written to audit logs.
fn redacted(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or std.ascii.eqlIgnoreCase(name, "x-amz-security-token") or
        std.ascii.eqlIgnoreCase(name, "cookie");
}

/// `put_object` -> `PutObject`.
fn apiName(a: std.mem.Allocator, c: *const Ctx) error{OutOfMemory}![]const u8 {
    const op = s3.authz.classify(c.method, c.route.bucket, c.route.key, c.route.query, c.copy_source) orelse
        return if (std.mem.indexOf(u8, c.target, "/admin/v") != null) "Admin" else "Unknown";
    const tag = @tagName(op);
    var out: std.ArrayList(u8) = .empty;
    var up = true;
    for (tag) |ch| {
        if (ch == '_') {
            up = true;
            continue;
        }
        try out.append(a, if (up) std.ascii.toUpper(ch) else ch);
        up = false;
    }
    return out.items;
}

pub fn entry(a: std.mem.Allocator, c: *Ctx, status: u16, deployment_id: []const u8, node: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    write(&out.writer, a, c, status, deployment_id, node) catch return error.OutOfMemory;
    return out.written();
}

fn write(w: *std.Io.Writer, a: std.mem.Allocator, c: *Ctx, status: u16, deployment_id: []const u8, node: []const u8) (std.Io.Writer.Error || error{OutOfMemory})!void {
    const now = std.time.nanoTimestamp();
    const elapsed: u64 = @intCast(@max(0, now - c.start_ns));
    var tb: [24]u8 = undefined;
    var s: Stringify = .{ .writer = w };
    try s.beginObject();
    try str(&s, "version", "1");
    try str(&s, "deploymentid", deployment_id);
    try str(&s, "time", record.timeText(now, &tb));
    try str(&s, "event", "");
    try str(&s, "trigger", "incoming");
    try s.objectField("api");
    try s.beginObject();
    try str(&s, "name", try apiName(a, c));
    if (c.route.bucket.len > 0) try str(&s, "bucket", c.route.bucket);
    if (c.route.key.len > 0) try str(&s, "object", c.route.key);
    const st: std.http.Status = @enumFromInt(status);
    try str(&s, "status", st.phrase() orelse "");
    try s.objectField("statusCode");
    try s.write(status);
    try s.objectField("rx");
    try s.write(c.req.head.content_length orelse 0);
    try s.objectField("tx");
    try s.write(responseLength(c));
    try str(&s, "timeToResponse", try std.fmt.allocPrint(a, "{d}ns", .{elapsed}));
    try str(&s, "timeToResponseInNS", try std.fmt.allocPrint(a, "{d}", .{elapsed}));
    try s.endObject();
    const hp = if (c.peer) |p| @import("s3ext.zig").peerParts(a, p) else [2][]const u8{ "", "" };
    try str(&s, "remotehost", hp[0]);
    try str(&s, "requestID", &c.request_id);
    try str(&s, "userAgent", headerValue(c.req_headers, "user-agent"));
    try str(&s, "requestPath", std.mem.sliceTo(c.target, '?'));
    try str(&s, "requestHost", headerValue(c.req_headers, "host"));
    try str(&s, "requestNode", node);
    try s.objectField("requestQuery");
    try s.beginObject();
    var it = std.mem.splitScalar(u8, c.route.query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const k = s3.router.percentDecode(a, pair[0 .. eq orelse pair.len], true) catch continue;
        const v = if (eq) |i| s3.router.percentDecode(a, pair[i + 1 ..], true) catch continue else "";
        try str(&s, k, v);
    }
    try s.endObject();
    try headers(&s, "requestHeader", c.req_headers);
    try headers(&s, "responseHeader", c.resp_headers);
    try s.objectField("tags");
    try s.beginObject();
    try s.endObject();
    try str(&s, "accessKey", c.auth.access_key);
    if (!std.mem.eql(u8, c.auth.principal, c.auth.access_key)) try str(&s, "parentUser", c.auth.principal);
    if (c.tenant.len > 0) try str(&s, "tenant", c.tenant);
    try s.endObject();
}

fn responseLength(c: *const Ctx) u64 {
    const v = headerValue(c.resp_headers, "content-length");
    return std.fmt.parseInt(u64, v, 10) catch 0;
}

fn headerValue(hs: []const Header, name: []const u8) []const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return "";
}

fn headers(s: *Stringify, field: []const u8, hs: []const Header) std.Io.Writer.Error!void {
    try s.objectField(field);
    try s.beginObject();
    for (hs, 0..) |h, i| {
        // Repeated names keep their first value; JSON objects need unique keys.
        const dup = for (hs[0..i]) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, h.name)) break true;
        } else false;
        if (dup) continue;
        try str(s, h.name, if (redacted(h.name)) "*REDACTED*" else h.value);
    }
    try s.endObject();
}

fn str(s: *Stringify, name: []const u8, v: []const u8) std.Io.Writer.Error!void {
    try s.objectField(name);
    try s.write(v);
}
