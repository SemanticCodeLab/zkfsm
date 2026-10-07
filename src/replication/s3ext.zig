//! S3 side of replication: the bucket `?replication` configuration, replication
//! metrics, resync (`?replication-reset`), the receiver for replica writes from a
//! source, and change capture of bucket operations for site replication.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const metrics = @import("../metrics/root.zig");
const engine = @import("engine.zig");
const config = @import("config.zig");
const targets = @import("targets.zig");
const client = @import("client.zig");
const queue = @import("queue.zig");
const deliver = @import("deliver.zig");
const site = @import("site.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const handler = s3.handler;
const ov = object.versioning;
const Stringify = std.json.Stringify;

pub const Ext = struct {
    r: *engine.Replicator,

    pub fn extension(self: *Ext) s3.Extension {
        return .{ .name = "replication", .ctx = self, .route = route };
    }
};

fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
    const self: *Ext = @ptrCast(@alignCast(ptr));
    const r = self.r;
    if (c.route.bucket.len == 0) return false;
    if (header(c, deliver.hdr_request)) |v| if (std.ascii.eqlIgnoreCase(v, "true")) return receive(r, c);
    if (c.route.key.len > 0) return false;
    if (try handler.param(c, "replication") != null) {
        configOp(r, c) catch |e| return failObject(c, e);
        return true;
    }
    if (try handler.param(c, "replication-metrics")) |v| {
        metricsOp(r, c, std.mem.eql(u8, v, "2")) catch |e| return failObject(c, e);
        return true;
    }
    if (try handler.param(c, "replication-reset") != null) {
        resetOp(r, c) catch |e| return failObject(c, e);
        return true;
    }
    if (try handler.param(c, "replication-reset-status") != null) {
        resetStatusOp(r, c) catch |e| return failObject(c, e);
        return true;
    }
    if (try handler.param(c, "replication-check") != null) {
        checkOp(r, c) catch |e| return failObject(c, e);
        return true;
    }
    return siteBucketOp(r, c);
}

fn header(c: *Ctx, name: []const u8) ?[]const u8 {
    var it = c.req.iterateHeaders();
    while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return std.mem.trim(u8, h.value, " ");
    return null;
}

const OpError = ConnError || object.Error || engine.Error;

fn failObject(c: *Ctx, e: OpError) ConnError!bool {
    switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        error.StorageFailed => try handler.fail(c, .InternalError),
        else => |oe| try handler.fail(c, s3.errors.fromObject(oe)),
    }
    return true;
}

/// S3 error document for codes the shared error table does not carry.
fn failCode(c: *Ctx, status: std.http.Status, code: []const u8, message: []const u8) ConnError!void {
    metrics.global.last_status = @intFromEnum(status);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    w.writeAll(s3.xml.declaration ++ "<Error>") catch return error.OutOfMemory;
    s3.xml.elem(w, "Code", code) catch return error.OutOfMemory;
    s3.xml.elem(w, "Message", message) catch return error.OutOfMemory;
    s3.xml.elem(w, "BucketName", c.route.bucket) catch return error.OutOfMemory;
    s3.xml.elem(w, "Resource", std.mem.sliceTo(c.target, '?')) catch return error.OutOfMemory;
    s3.xml.elem(w, "RequestId", &c.request_id) catch return error.OutOfMemory;
    w.writeAll("</Error>") catch return error.OutOfMemory;
    try c.req.respond(a.written(), .{ .status = status, .extra_headers = &.{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    } });
}

// ---- receiver ----

/// Runs the standard handling of a replica write with its source identity attached,
/// so versions keep their ids and times and nothing is replicated back.
fn receive(r: *engine.Replicator, c: *Ctx) ConnError!bool {
    var origin: object.replica.Origin = .{};
    if (try handler.param(c, "versionId")) |v| if (ov.parseVersionId(v)) |id| {
        if (!id.eql(ov.null_version_id)) origin.version = id;
    } else |_| {};
    if (header(c, deliver.hdr_mtime)) |m| origin.created_ns = targets.parseRfc3339(m);
    if (header(c, deliver.hdr_marker)) |m| origin.delete_marker = std.ascii.eqlIgnoreCase(m, "true");
    const len = c.req.head.content_length orelse 0;
    const is_put = c.method == .PUT and c.route.key.len > 0 and (try handler.param(c, "tagging")) == null;
    object.replica.origin = origin;
    defer object.replica.origin = null;
    try handler.runBuiltin(c);
    const st = metrics.global.last_status;
    if (is_put and st >= 200 and st < 300) r.stats.received(len);
    return true;
}

// ---- configuration ----

fn configOp(r: *engine.Replicator, c: *Ctx) OpError!void {
    switch (c.method) {
        .GET => {
            const v = try r.view(c.arena, c.route.bucket);
            const x = v.cfg_xml orelse return failCode(c, .not_found, "ReplicationConfigurationNotFoundError", "The replication configuration was not found");
            try handler.respondXml(c, .ok, x);
        },
        .PUT => {
            const body = try s3.versioning.readBodyMax(c, 1024 * 1024) orelse return;
            const cfg = config.parse(c.arena, body) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.MalformedXML => handler.fail(c, .MalformedXML),
                error.InvalidRequest => failCode(c, .bad_request, "InvalidRequest", "The replication configuration is not valid."),
            };
            const bc = try ov.getConfig(c.svc, c.arena, c.route.bucket);
            if (bc.versioning != .enabled)
                return failCode(c, .bad_request, "InvalidRequest", "Versioning must be 'Enabled' on the bucket to apply a replication configuration");
            const v = try r.view(c.arena, c.route.bucket);
            for (cfg.rules) |rule| {
                const known = for (v.targets) |t| {
                    if (std.mem.eql(u8, t.arn, rule.dest)) break true;
                } else false;
                if (!known) return failCode(c, .bad_request, "InvalidArgument", "The destination ARN does not name a remote target of this bucket.");
            }
            var out: std.Io.Writer.Allocating = .init(c.arena);
            config.render(&out.writer, cfg) catch return error.OutOfMemory;
            try r.putConfigXml(c.route.bucket, out.written());
            // Existing objects go out once, right away, to every rule that asks for them.
            for (cfg.rules) |rule| if (rule.enabled and rule.existing) {
                const was = if (v.cfg) |old| for (old.rules) |o| {
                    if (std.mem.eql(u8, o.dest, rule.dest) and o.existing and o.enabled) break true;
                } else false else false;
                if (!was) r.startScan(c.route.bucket, rule.dest, "", core.time.nowNs()) catch {};
            };
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try r.putConfigXml(c.route.bucket, null);
            // Clients of the reference server expect 200 here.
            try handler.respondEmpty(c, .ok, &.{});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
}

fn checkOp(r: *engine.Replicator, c: *Ctx) OpError!void {
    const v = try r.view(c.arena, c.route.bucket);
    const cfg = v.cfg orelse return failCode(c, .not_found, "ReplicationConfigurationNotFoundError", "The replication configuration was not found");
    var hc: std.http.Client = .{ .allocator = r.gpa };
    defer hc.deinit();
    for (cfg.rules) |rule| {
        const t = for (v.targets) |t| {
            if (std.mem.eql(u8, t.arn, rule.dest)) break t;
        } else return failCode(c, .bad_request, "InvalidArgument", "A rule names a missing remote target.");
        const path = try std.fmt.allocPrint(c.arena, "/{s}", .{t.target_bucket});
        const res = client.send(&hc, c.arena, t.remote(), .{ .method = .HEAD, .path = path }) catch
            return failCode(c, .service_unavailable, "XMinioReplicationRemoteConnectionError", "Remote target is unreachable.");
        if (!res.ok()) return failCode(c, .bad_request, "XMinioReplicationRemoteConnectionError", "Remote target bucket is not usable.");
    }
    try handler.respondEmpty(c, .ok, &.{});
}

// ---- metrics ----

fn metricsOp(r: *engine.Replicator, c: *Ctx, v2: bool) OpError!void {
    const v = try r.view(c.arena, c.route.bucket);
    var out: std.Io.Writer.Allocating = .init(c.arena);
    var w: Stringify = .{ .writer = &out.writer };
    writeMetrics(r, &w, c.route.bucket, v, v2) catch return error.OutOfMemory;
    try respondJson(c, out.written());
}

fn writeMetrics(r: *engine.Replicator, w: *Stringify, bucket: []const u8, v: engine.Replicator.BucketView, v2: bool) std.Io.Writer.Error!void {
    _ = bucket;
    var sent_n: u64 = 0;
    var sent_b: u64 = 0;
    var failed_n: u64 = 0;
    var failed_b: u64 = 0;
    var pending: u64 = 0;
    if (v2) {
        try w.beginObject();
        try w.objectField("uptime");
        try w.write(@divTrunc(std.time.nanoTimestamp() - r.stats.started_ns, std.time.ns_per_s));
        try w.objectField("currStats");
    }
    try w.beginObject();
    try w.objectField("Stats");
    try w.beginObject();
    for (v.targets) |t| {
        const s = r.stats.snapshot(t.arn) orelse stat0(t);
        sent_n += s.sent_count;
        sent_b += s.sent_bytes;
        failed_n += s.failed_count;
        failed_b += s.failed_bytes;
        pending += s.pending_count;
        try w.objectField(t.arn);
        try w.write(.{
            .replicationCount = s.sent_count,
            .completedReplicationSize = s.sent_bytes,
            .limitInBits = t.bandwidth,
            .failed = .{ .totals = .{ .count = s.failed_count, .bytes = s.failed_bytes }, .lastMinute = .{ .count = 0, .bytes = 0 }, .lastHour = .{ .count = 0, .bytes = 0 } },
            .pendingReplicationCount = s.pending_count,
            .failedReplicationSize = s.failed_bytes,
            .failedReplicationCount = s.failed_count,
        });
    }
    try w.endObject();
    try w.objectField("completedReplicationSize");
    try w.write(sent_b);
    try w.objectField("replicationCount");
    try w.write(sent_n);
    r.stats.mutex.lock();
    const recv_n = r.stats.received_count;
    const recv_b = r.stats.received_bytes;
    r.stats.mutex.unlock();
    try w.objectField("replicaSize");
    try w.write(recv_b);
    try w.objectField("replicaCount");
    try w.write(recv_n);
    try w.objectField("failed");
    try w.write(.{ .totals = .{ .count = failed_n, .bytes = failed_b }, .lastMinute = .{ .count = 0, .bytes = 0 }, .lastHour = .{ .count = 0, .bytes = 0 } });
    try w.objectField("queued");
    try w.write(.{ .curr = .{ .count = pending, .bytes = 0 }, .avg = .{ .count = pending, .bytes = 0 }, .peak = .{ .count = pending, .bytes = 0 } });
    try w.objectField("pendingReplicationCount");
    try w.write(pending);
    try w.objectField("failedReplicationCount");
    try w.write(failed_n);
    try w.endObject();
    if (v2) {
        try w.objectField("queueStats");
        try w.beginObject();
        try w.objectField("nodes");
        try w.beginArray();
        try w.endArray();
        try w.endObject();
        try w.objectField("downtimeInfo");
        try w.beginObject();
        for (v.targets) |t| {
            const s = r.stats.snapshot(t.arn) orelse continue;
            try w.objectField(t.arn);
            const secs: i64 = @intCast(@divTrunc(s.downtime_ns, std.time.ns_per_s));
            try w.write(.{ .duration = .{ .total = secs, .avg = secs, .max = secs }, .count = .{ .total = s.offline_count, .avg = s.offline_count, .max = s.offline_count } });
        }
        try w.endObject();
        try w.endObject();
    }
}

fn stat0(t: targets.Target) @import("stats.zig").Target {
    return .{ .bucket = t.source_bucket, .arn = t.arn };
}

// ---- resync ----

/// Go duration text (`1h2m3.5s`, `500ms`) in ns; null when malformed.
pub fn parseGoDuration(s: []const u8) ?i128 {
    if (s.len == 0) return null;
    if (std.mem.eql(u8, s, "0")) return 0;
    var total: f128 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const start = i;
        while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '.')) i += 1;
        if (i == start) return null;
        const num = std.fmt.parseFloat(f64, s[start..i]) catch return null;
        const ustart = i;
        while (i < s.len and !std.ascii.isDigit(s[i]) and s[i] != '.') i += 1;
        const unit = s[ustart..i];
        const mult: f64 = if (std.mem.eql(u8, unit, "h")) 3600e9 else if (std.mem.eql(u8, unit, "m")) 60e9 else if (std.mem.eql(u8, unit, "s")) 1e9 else if (std.mem.eql(u8, unit, "ms")) 1e6 else if (std.mem.eql(u8, unit, "us") or std.mem.eql(u8, unit, "µs")) 1e3 else if (std.mem.eql(u8, unit, "ns")) 1 else return null;
        total += num * mult;
    }
    return @intFromFloat(total);
}

fn resetOp(r: *engine.Replicator, c: *Ctx) OpError!void {
    if (c.method != .PUT) return handler.fail(c, .MethodNotAllowed);
    const v = try r.view(c.arena, c.route.bucket);
    const cfg = v.cfg orelse return failCode(c, .not_found, "ReplicationConfigurationNotFoundError", "The replication configuration was not found");
    const want = try handler.param(c, "arn") orelse "";
    const older: i128 = if (try handler.param(c, "older-than")) |o| parseGoDuration(o) orelse return handler.fail(c, .InvalidArgument) else 0;
    var reset_id = try handler.param(c, "reset-id") orelse "";
    if (reset_id.len == 0) {
        var b: [16]u8 = undefined;
        std.crypto.random.bytes(&b);
        reset_id = try c.arena.dupe(u8, &std.fmt.bytesToHex(b, .lower));
    }
    var arns: std.ArrayList([]const u8) = .empty;
    for (cfg.rules) |rule| {
        if (!rule.enabled) continue;
        if (want.len > 0 and !std.mem.eql(u8, rule.dest, want)) continue;
        for (arns.items) |x| {
            if (std.mem.eql(u8, x, rule.dest)) break;
        } else try arns.append(c.arena, rule.dest);
    }
    if (arns.items.len == 0) return failCode(c, .bad_request, "InvalidArgument", "No replication rule targets this ARN.");
    const cutoff = core.time.nowNs() - older;
    var out: std.Io.Writer.Allocating = .init(c.arena);
    var w: Stringify = .{ .writer = &out.writer };
    w.beginObject() catch return error.OutOfMemory;
    w.objectField("target") catch return error.OutOfMemory;
    w.beginArray() catch return error.OutOfMemory;
    for (arns.items) |arn| {
        r.updateResync(c.route.bucket, arn, reset_id, .{ .start = true });
        r.startScan(c.route.bucket, arn, reset_id, cutoff) catch return handler.fail(c, .InternalError);
        w.write(.{ .arn = arn, .resetid = reset_id }) catch return error.OutOfMemory;
    }
    w.endArray() catch return error.OutOfMemory;
    w.endObject() catch return error.OutOfMemory;
    try respondJson(c, out.written());
}

fn resetStatusOp(r: *engine.Replicator, c: *Ctx) OpError!void {
    const want = try handler.param(c, "arn") orelse "";
    const list = try r.resyncs(c.arena, c.route.bucket);
    var out: std.Io.Writer.Allocating = .init(c.arena);
    var w: Stringify = .{ .writer = &out.writer };
    w.beginObject() catch return error.OutOfMemory;
    w.objectField("target") catch return error.OutOfMemory;
    w.beginArray() catch return error.OutOfMemory;
    for (list) |t| {
        if (want.len > 0 and !std.mem.eql(u8, t.arn, want)) continue;
        var sb: [32]u8 = undefined;
        var eb: [32]u8 = undefined;
        w.write(.{
            .arn = t.arn,
            .resetid = t.reset_id,
            .startTime = targets.rfc3339(t.start_ns, &sb),
            .endTime = targets.rfc3339(t.end_ns, &eb),
            .resyncStatus = t.status,
            .completedReplicationSize = t.replicated_bytes,
            .failedReplicationSize = t.failed_bytes,
            .failedReplicationCount = t.failed_count,
            .replicationCount = t.replicated_count,
            .bucket = c.route.bucket,
            .object = t.last_key,
        }) catch return error.OutOfMemory;
    }
    w.endArray() catch return error.OutOfMemory;
    w.endObject() catch return error.OutOfMemory;
    try respondJson(c, out.written());
}

fn respondJson(c: *Ctx, body: []const u8) ConnError!void {
    metrics.global.last_status = 200;
    try c.req.respond(body, .{ .status = .ok, .extra_headers = &.{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    } });
}

// ---- site replication: bucket change capture ----

const synced_subresources = [_][]const u8{ "versioning", "policy", "lifecycle", "tagging", "object-lock", "encryption", "cors" };

/// Queues a delayed push of the bucket to peers; the push reads the state after this
/// request has been applied. Pushes made by peers are not sent on again.
fn siteBucketOp(r: *engine.Replicator, c: *Ctx) ConnError!bool {
    if (c.method != .PUT and c.method != .DELETE) return false;
    const q = c.route.query;
    const relevant = q.len == 0 or for (synced_subresources) |s| {
        if ((try handler.param(c, s)) != null) break true;
    } else false;
    if (!relevant) return false;
    const st = try r.siteState(c.arena) orelse return false;
    if (std.mem.eql(u8, c.auth.access_key, st.svc_access_key)) return false;
    const due: i64 = @intCast(std.time.nanoTimestamp() + std.time.ns_per_s);
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
        r.enqueue(.{ .op = .bucket, .bucket = c.route.bucket, .arn = p.deployment_id, .next_ns = due }) catch |e|
            std.log.warn("site replication: cannot queue bucket {s}: {t}", .{ c.route.bucket, e });
    }
    if (c.method != .PUT or q.len != 0) return false;
    // New buckets are versioned before the first write can land unversioned.
    try handler.runBuiltin(c);
    const code = metrics.global.last_status;
    if (code >= 200 and code < 300) ov.setVersioning(c.svc, c.route.bucket, .enabled) catch |e|
        std.log.warn("site replication: cannot enable versioning on {s}: {t}", .{ c.route.bucket, e });
    return true;
}

test "go durations" {
    try std.testing.expectEqual(@as(i128, 3_723_500_000_000), parseGoDuration("1h2m3.5s").?);
    try std.testing.expectEqual(@as(i128, 500_000_000), parseGoDuration("500ms").?);
    try std.testing.expect(parseGoDuration("5x") == null);
    try std.testing.expect(parseGoDuration("") == null);
}

test {
    _ = queue;
    _ = site;
}
