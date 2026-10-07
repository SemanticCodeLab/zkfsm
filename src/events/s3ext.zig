//! S3 side of events: Get/PutBucketNotificationConfiguration, ListenBucketNotification
//! streaming, the request observer (access events, audit), and the object change sink.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const metrics = @import("../metrics/root.zig");
const notifier = @import("notifier.zig");
const config = @import("config.zig");
const names = @import("names.zig");
const record = @import("record.zig");
const audit = @import("audit.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const handler = s3.handler;
const Name = names.Name;

/// The request being served on this thread; set between observer begin and end.
threadlocal var current: ?*Ctx = null;

pub const Ext = struct {
    n: *notifier.Notifier,

    pub fn extension(self: *Ext) s3.Extension {
        return .{ .name = "events", .ctx = self, .route = route };
    }

    pub fn observer(self: *Ext) s3.Observer {
        return .{ .ctx = self, .begin = begin, .end = end };
    }

    pub fn sink(self: *Ext) object.events.Sink {
        return .{ .ctx = self, .notify = onChange };
    }
};

fn has(query: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const k = pair[0 .. std.mem.indexOfScalar(u8, pair, '=') orelse pair.len];
        if (std.mem.eql(u8, k, name)) return true;
    }
    return false;
}

fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
    const self: *Ext = @ptrCast(@alignCast(ptr));
    const r = c.route;
    if (r.key.len > 0) return false;
    if (c.method == .GET and has(r.query, "events")) {
        try listen(self.n, c);
        return true;
    }
    if (r.bucket.len == 0 or !has(r.query, "notification")) return false;
    configOp(self.n, c) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        error.StorageFailed => try handler.fail(c, .InternalError),
        else => |oe| try handler.fail(c, s3.errors.fromObject(oe)),
    };
    return true;
}

const OpError = ConnError || object.Error || error{StorageFailed};

fn configOp(n: *notifier.Notifier, c: *Ctx) OpError!void {
    try c.svc.headBucket(c.route.bucket);
    switch (c.method) {
        .GET => {
            const doc = try n.getBucketXml(c.arena, c.route.bucket) orelse
                s3.xml.declaration ++ "<NotificationConfiguration xmlns=\"" ++ s3.xml.s3_ns ++ "\"></NotificationConfiguration>";
            try handler.respondXml(c, .ok, doc);
        },
        .PUT => {
            const body = try s3.versioning.readBodyMax(c, 1024 * 1024) orelse return;
            const cfg = config.parse(c.arena, body) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.MalformedXML => handler.fail(c, .MalformedXML),
                error.InvalidArgument => failCode(c, "InvalidArgument", "The notification configuration is not valid."),
            };
            for (cfg.rules) |rule| if (!n.knowsArn(rule.arn))
                return failCode(c, "InvalidArgument", "A specified destination ARN does not exist or is not well-formed. Verify the destination ARN.");
            try n.setBucketXml(c.route.bucket, if (cfg.rules.len == 0) null else try config.render(c.arena, cfg));
            try handler.respondEmpty(c, .ok, &.{});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
}

fn failCode(c: *Ctx, code: []const u8, message: []const u8) ConnError!void {
    metrics.global.last_status = 400;
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    w.writeAll(s3.xml.declaration ++ "<Error>") catch return error.OutOfMemory;
    s3.xml.elem(w, "Code", code) catch return error.OutOfMemory;
    s3.xml.elem(w, "Message", message) catch return error.OutOfMemory;
    s3.xml.elem(w, "BucketName", c.route.bucket) catch return error.OutOfMemory;
    s3.xml.elem(w, "Resource", std.mem.sliceTo(c.target, '?')) catch return error.OutOfMemory;
    s3.xml.elem(w, "RequestId", &c.request_id) catch return error.OutOfMemory;
    w.writeAll("</Error>") catch return error.OutOfMemory;
    try c.req.respond(a.written(), .{ .status = .bad_request, .extra_headers = &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    } });
}

// ---- ListenBucketNotification ----

const max_listen_events = 64;

fn listen(n: *notifier.Notifier, c: *Ctx) ConnError!void {
    var l: notifier.Listener = .{ .gpa = n.gpa, .bucket = c.route.bucket, .prefix = "", .suffix = "", .mask = names.Mask.initEmpty() };
    var ping_s: u64 = 10;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, c.route.query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = s3.router.percentDecode(c.arena, pair[eq + 1 ..], true) catch return handler.fail(c, .InvalidArgument);
        if (std.mem.eql(u8, k, "events")) {
            count += 1;
            if (count > max_listen_events) return handler.fail(c, .InvalidArgument);
            l.mask.setUnion(names.parse(v) orelse return failCode(c, "InvalidArgument", "A specified event is not supported for notifications."));
        } else if (std.mem.eql(u8, k, "prefix")) {
            l.prefix = v;
        } else if (std.mem.eql(u8, k, "suffix")) {
            l.suffix = v;
        } else if (std.mem.eql(u8, k, "ping")) {
            ping_s = std.fmt.parseInt(u64, v, 10) catch return handler.fail(c, .InvalidArgument);
            ping_s = std.math.clamp(ping_s, 1, 3600);
        }
    }
    if (count == 0) return handler.fail(c, .InvalidArgument);
    if (c.route.bucket.len > 0) c.svc.headBucket(c.route.bucket) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => handler.fail(c, s3.errors.fromObject(e)),
    };
    try n.subscribe(&l);
    defer {
        n.unsubscribe(&l);
        l.deinit();
    }
    metrics.global.last_status = 200;
    var out_buf: [16 * 1024]u8 = undefined;
    var bw = try c.req.respondStreaming(&out_buf, .{ .respond_options = .{
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "text/event-stream" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
        },
    } });
    // Pings keep proxies and clients from timing the stream out.
    try bw.writer.writeAll(" ");
    try bw.writer.flush();
    try bw.flush();
    while (true) {
        const recs = try l.take(ping_s * std.time.ns_per_s);
        defer {
            for (recs) |r| n.gpa.free(r);
            n.gpa.free(recs);
        }
        if (recs.len == 0) {
            bw.writer.writeAll(" ") catch return error.StreamAborted;
        } else for (recs) |r| {
            bw.writer.writeAll("{\"Records\":[") catch return error.StreamAborted;
            bw.writer.writeAll(r) catch return error.StreamAborted;
            bw.writer.writeAll("]}\n") catch return error.StreamAborted;
        }
        bw.writer.flush() catch return error.StreamAborted;
        bw.flush() catch return error.StreamAborted;
    }
}

// ---- observer ----

fn begin(_: *anyopaque, c: *Ctx) void {
    current = c;
}

fn end(ptr: *anyopaque, c: *Ctx, status: u16) void {
    const self: *Ext = @ptrCast(@alignCast(ptr));
    defer current = null;
    const n = self.n;
    const ok = status >= 200 and status < 300;
    if (ok and c.route.bucket.len > 0) requestEvent(n, c);
    if (n.auditing()) {
        var arena = std.heap.ArenaAllocator.init(n.gpa);
        defer arena.deinit();
        const entry = audit.entry(arena.allocator(), c, status, n.opts.deployment_id, n.opts.endpoint) catch return;
        n.audit(entry);
    }
}

/// Events for requests that change nothing in storage (reads, bucket lifecycle, restore).
fn requestEvent(n: *notifier.Notifier, c: *Ctx) void {
    const r = c.route;
    const q = r.query;
    if (r.key.len == 0) {
        if (q.len > 0 and !has(q, "x-id")) return;
        switch (c.method) {
            .PUT => if (n.active()) n.publish(baseEvent(c, .bucket_created, r.bucket, "")),
            .DELETE => {
                if (n.active()) n.publish(baseEvent(c, .bucket_removed, r.bucket, ""));
                n.setBucketXml(r.bucket, null) catch {};
            },
            else => {},
        }
        return;
    }
    if (!n.active()) return;
    const name: Name = switch (c.method) {
        .GET => if (has(q, "retention"))
            .object_accessed_get_retention
        else if (has(q, "legal-hold"))
            .object_accessed_get_legal_hold
        else if (has(q, "attributes"))
            .object_accessed_attributes
        else if (q.len == 0 or has(q, "versionId") or has(q, "partNumber") or has(q, "response-content-type"))
            .object_accessed_get
        else
            return,
        .HEAD => .object_accessed_head,
        .POST => if (has(q, "restore")) .object_restore_post else return,
        else => return,
    };
    var ev = baseEvent(c, name, r.bucket, r.key);
    for (c.resp_headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "etag")) ev.etag = std.mem.trim(u8, h.value, "\"");
        if (std.ascii.eqlIgnoreCase(h.name, "content-type")) ev.content_type = h.value;
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-version-id")) ev.version_id = h.value;
    }
    n.publish(ev);
}

fn baseEvent(c: ?*Ctx, name: Name, bucket: []const u8, key: []const u8) record.Event {
    var ev: record.Event = .{ .name = name, .bucket = bucket, .key = key, .time_ns = std.time.nanoTimestamp() };
    const ctx = c orelse return ev;
    ev.principal = ctx.auth.access_key;
    ev.request_id = &ctx.request_id;
    if (ctx.peer) |p| {
        const hp = peerParts(ctx.arena, p);
        ev.source_host = hp[0];
        ev.source_port = hp[1];
    }
    for (ctx.req_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) {
        ev.user_agent = h.value;
    };
    return ev;
}

/// Host and port text of a peer address.
pub fn peerParts(a: std.mem.Allocator, p: std.net.Address) [2][]const u8 {
    const s = std.fmt.allocPrint(a, "{f}", .{p}) catch return .{ "", "" };
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return .{ s, "" };
    const host = std.mem.trim(u8, s[0..colon], "[]");
    return .{ host, s[colon + 1 ..] };
}

// ---- object changes ----

fn onChange(ptr: *anyopaque, ch: object.events.Change) void {
    const self: *Ext = @ptrCast(@alignCast(ptr));
    if (!self.n.active()) return;
    const c = current;
    const lifecycle = object.events.cause == .lifecycle;
    const name: Name = switch (ch.kind) {
        .created => createdName(c),
        .deleted => if (lifecycle) .lifecycle_expiration_delete else .object_removed_delete,
        .delete_marker => if (lifecycle) .lifecycle_expiration_delete_marker_created else .object_removed_delete_marker_created,
        .tags_put => .object_created_put_tagging,
        .tags_deleted => .object_created_delete_tagging,
        .retention_put => .object_created_put_retention,
        .legal_hold_put => .object_created_put_legal_hold,
        .transitioned => .object_transition_complete,
        .transition_failed => .object_transition_failed,
        .restore_completed => .object_restore_completed,
        .replication_completed => .replication_complete,
        .replication_failed => .replication_failed,
    };
    var ev = baseEvent(if (lifecycle) null else c, name, ch.bucket, ch.key);
    ev.size = ch.size;
    ev.etag = ch.etag;
    ev.content_type = ch.content_type;
    var vb: [32]u8 = undefined;
    if (ch.version) |v| if (!v.eql(object.versioning.null_version_id)) {
        ev.version_id = object.versioning.formatVersionId(v, &vb);
    };
    self.n.publish(ev);
}

fn createdName(c: ?*Ctx) Name {
    const ctx = c orelse return .object_created_put;
    if (ctx.method == .POST and has(ctx.route.query, "uploadId")) return .object_created_complete_multipart_upload;
    if (ctx.copy_source) return .object_created_copy;
    if (ctx.method == .POST) return .object_created_post;
    return .object_created_put;
}

test {
    _ = core;
}
