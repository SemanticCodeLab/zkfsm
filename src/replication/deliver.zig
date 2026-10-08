//! Delivers one queued object operation to its target: new versions (single PUT or
//! multipart with the source's part layout), delete markers, version deletes, and
//! metadata updates. Requests carry the source version id and time, so replicas keep them.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const sign = @import("../backend/s3/sign.zig");
const client = @import("client.zig");
const queue = @import("queue.zig");
const engine = @import("engine.zig");
const targets = @import("targets.zig");

const Allocator = std.mem.Allocator;
const Entry = queue.Entry;
const Header = client.Header;
const ov = object.versioning;

pub const Outcome = enum { done, retry, drop };

pub const hdr_request = "x-minio-source-replication-request";
pub const hdr_mtime = "x-minio-source-mtime";
pub const hdr_marker = "x-minio-source-deletemarker";
pub const hdr_etag = "x-minio-source-etag";

/// Version deletes and markers give up after this many attempts (e.g. a locked replica).
const max_delete_attempts = 50;

pub fn process(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, e: Entry) Outcome {
    var sp = core.trace.root("replication", .producer, .replication, .{});
    defer sp.end();
    sp.str("path", e.key);
    sp.str("aws.s3.bucket", e.bucket);
    sp.str("replication.op", @tagName(e.op));
    const out = processInner(r, hc, a, e);
    sp.str("replication.outcome", @tagName(out));
    if (out == .retry) sp.fail("retry");
    return out;
}

fn processInner(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, e: Entry) Outcome {
    const bid = r.svc.bucketId(e.bucket) catch |err| return if (err == error.NoSuchBucket) .drop else .retry;
    const version = ov.parseVersionId(e.version) catch return .drop;
    const d = (r.destByArn(a, bid, e.bucket, e.arn) catch return .retry) orelse return .drop;
    const out: Outcome = switch (e.op) {
        .put, .existing, .metadata, .delete_marker => blk: {
            const info = ov.headVersion(r.svc, a, e.bucket, e.key, version) catch |err| break :blk switch (err) {
                error.NoSuchKey, error.NoSuchVersion, error.NoSuchBucket => .drop,
                else => .retry,
            };
            if (info.delete_marker) break :blk sendMarker(r, hc, a, d, e, info);
            if (e.op == .delete_marker) break :blk .drop;
            if (e.op == .metadata) break :blk sendMetadata(r, hc, a, d, e, info);
            break :blk sendObject(r, hc, a, d, e, info);
        },
        .delete_version => sendDeleteVersion(r, hc, a, d, e),
        .bucket, .iam => .drop,
    };
    if (out == .retry and (e.op == .delete_version or e.op == .delete_marker) and e.attempts + 1 >= max_delete_attempts) {
        std.log.warn("replication: giving up on delete of {s}/{s} ({s}) for {s}", .{ e.bucket, e.key, e.version, e.arn });
        return .drop;
    }
    return out;
}

fn objectPath(a: Allocator, d: engine.Dest, key: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(a, "/{s}/{s}", .{ d.target_bucket, key });
}

fn failed(r: *engine.Replicator, d: engine.Dest, e: Entry, bytes: u64, why: []const u8) Outcome {
    r.stats.failed(e.bucket, d.arn, bytes);
    if (e.resync_id.len > 0) r.updateResync(e.bucket, d.arn, e.resync_id, .{ .failed_bytes = bytes });
    if (e.attempts == 0 or e.attempts % 10 == 0)
        std.log.warn("replication: {s}/{s} to {s} failed ({s}); attempt {d}", .{ e.bucket, e.key, d.arn, why, e.attempts + 1 });
    return .retry;
}

fn unreachable_(r: *engine.Replicator, d: engine.Dest, e: Entry, bytes: u64) Outcome {
    r.stats.health(e.bucket, d.arn, false, 0);
    return failed(r, d, e, bytes, "target unreachable");
}

fn succeeded(r: *engine.Replicator, d: engine.Dest, e: Entry, bytes: u64) void {
    r.stats.sent(e.bucket, d.arn, bytes);
    r.stats.health(e.bucket, d.arn, true, 0);
    if (e.resync_id.len > 0) r.updateResync(e.bucket, d.arn, e.resync_id, .{ .sent_bytes = bytes, .last_key = e.key });
}

fn mtimeHeader(a: Allocator, ns: i128) Allocator.Error!Header {
    const buf = try a.create([32]u8);
    return .{ .name = hdr_mtime, .value = targets.rfc3339(ns, buf) };
}

fn versionParam(a: Allocator, v: core.VersionId) Allocator.Error![]const u8 {
    const buf = try a.create([32]u8);
    return ov.formatVersionId(v, buf);
}

/// `base` plus versionId; the null version is addressed without one (the target
/// keeps its own id for it).
fn withVersion(a: Allocator, vid: []const u8, base: []const client.Param) Allocator.Error![]const client.Param {
    if (std.mem.eql(u8, vid, "null")) return base;
    const out = try a.alloc(client.Param, base.len + 1);
    @memcpy(out[0..base.len], base);
    out[base.len] = .{ .name = "versionId", .value = vid };
    return out;
}

fn etagText(a: Allocator, et: core.ETag) Allocator.Error![]const u8 {
    const buf = try a.create([core.ETag.quoted_max]u8);
    return std.mem.trim(u8, et.quoted(buf), "\"");
}

/// Data source for streamed uploads: a byte range of the local version.
const Source = struct {
    svc: *object.ObjectService,
    info: object.ObjectInfo,
    range: ?core.Range,

    fn write(ctx: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void {
        const s: *Source = @ptrCast(@alignCast(ctx));
        s.svc.read(s.info, s.range, w) catch |e| return if (e == error.WriteFailed) error.WriteFailed else error.SourceFailed;
    }
};

fn objectHeaders(a: Allocator, d: engine.Dest, info: object.ObjectInfo) Allocator.Error![]Header {
    var hs: std.ArrayList(Header) = .empty;
    for (info.metadata) |m| try hs.append(a, .{ .name = try std.fmt.allocPrint(a, "x-amz-meta-{s}", .{m.name}), .value = m.value });
    inline for (object.SystemHeaders.fields) |f| {
        var v = @field(info.system, f[0]);
        if (comptime std.mem.eql(u8, f[1], "content-encoding")) v = try s3.versioning.withoutAwsChunked(a, v);
        if (v.len > 0) try hs.append(a, .{ .name = f[1], .value = v });
    }
    if (info.tags.len > 0) {
        const tags = engine.decodeTags(a, info.tags);
        var tw: std.Io.Writer.Allocating = .init(a);
        for (tags, 0..) |t, i| {
            if (i > 0) tw.writer.writeByte('&') catch return error.OutOfMemory;
            sign.uriEncode(&tw.writer, t.key, true) catch return error.OutOfMemory;
            tw.writer.writeByte('=') catch return error.OutOfMemory;
            sign.uriEncode(&tw.writer, t.value, true) catch return error.OutOfMemory;
        }
        try hs.append(a, .{ .name = "x-amz-tagging", .value = tw.written() });
    }
    if (info.retention_mode != .none) {
        const tb = try a.create([24]u8);
        try hs.append(a, .{ .name = "x-amz-object-lock-mode", .value = if (info.retention_mode == .compliance) "COMPLIANCE" else "GOVERNANCE" });
        try hs.append(a, .{ .name = "x-amz-object-lock-retain-until-date", .value = core.time.iso8601(info.retain_until_ns, tb) });
    }
    if (info.legal_hold) try hs.append(a, .{ .name = "x-amz-object-lock-legal-hold", .value = "ON" });
    if (d.storage_class.len > 0) try hs.append(a, .{ .name = "x-amz-storage-class", .value = d.storage_class });
    try replicaHeaders(a, &hs, info);
    return hs.items;
}

fn replicaHeaders(a: Allocator, hs: *std.ArrayList(Header), info: object.ObjectInfo) Allocator.Error!void {
    try hs.append(a, .{ .name = hdr_request, .value = "true" });
    try hs.append(a, try mtimeHeader(a, info.created_ns));
    try hs.append(a, .{ .name = "x-amz-replication-status", .value = "REPLICA" });
    try hs.append(a, .{ .name = hdr_etag, .value = try etagText(a, info.etag) });
}

fn sendObject(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry, info: object.ObjectInfo) Outcome {
    return sendObjectInner(r, hc, a, d, e, info) catch |err| switch (err) {
        error.OutOfMemory, error.SourceFailed, error.InvalidEndpoint => failed(r, d, e, info.size, @errorName(err)),
        error.Unreachable => unreachable_(r, d, e, info.size),
    };
}

fn sendObjectInner(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry, info: object.ObjectInfo) client.Error!Outcome {
    const path = try objectPath(a, d, e.key);
    const vid = try versionParam(a, info.version_id);
    const vq = try withVersion(a, vid, &.{});
    // An unparseable answer (e.g. an encoding the HTTP client rejects) just means "send it".
    const head = client.send(hc, a, d.remote, .{ .method = .HEAD, .path = path, .query = vq }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => client.Response{ .status = 0 },
    };
    if (head.status == 200 and std.mem.eql(u8, head.etag, try etagText(a, info.etag))) {
        markCompleted(r, a, e, info.version_id);
        succeeded(r, d, e, 0);
        return .done;
    }
    const parts = info.part_sizes.len / 8;
    const ok = if (parts > 1 and info.logical_size == null)
        try sendMultipart(r, hc, a, d, path, vid, info, parts)
    else
        try sendSingle(r, hc, a, d, path, vid, info);
    if (!ok.ok()) return failed(r, d, e, info.size, try std.fmt.allocPrint(a, "HTTP {d} {s}", .{ ok.status, ok.code() }));
    succeeded(r, d, e, info.size);
    markCompleted(r, a, e, info.version_id);
    return .done;
}

fn sendSingle(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, path: []const u8, vid: []const u8, info: object.ObjectInfo) client.Error!client.Response {
    var src: Source = .{ .svc = r.svc, .info = info, .range = null };
    return client.send(hc, a, d.remote, .{
        .method = .PUT,
        .path = path,
        .query = try withVersion(a, vid, &.{}),
        .headers = try objectHeaders(a, d, info),
        .content_type = if (info.content_type.len > 0) info.content_type else "binary/octet-stream",
        .body = .{ .stream = .{ .len = info.size, .ctx = &src, .write = Source.write } },
    });
}

/// Same part boundaries as the source, so the replica's multipart ETag matches.
fn sendMultipart(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, path: []const u8, vid: []const u8, info: object.ObjectInfo, parts: usize) client.Error!client.Response {
    const init_res = try client.send(hc, a, d.remote, .{
        .method = .POST,
        .path = path,
        .query = &.{.{ .name = "uploads", .value = "" }},
        .headers = try objectHeaders(a, d, info),
        .content_type = if (info.content_type.len > 0) info.content_type else "binary/octet-stream",
    });
    if (!init_res.ok()) return init_res;
    const upload_id = s3.versioning.elemText(init_res.body, "UploadId") orelse return .{ .status = 502 };
    var complete: std.Io.Writer.Allocating = .init(a);
    const cw = &complete.writer;
    cw.writeAll("<CompleteMultipartUpload>") catch return error.OutOfMemory;
    var offset: u64 = 0;
    var abort = true;
    defer if (abort) {
        _ = client.send(hc, a, d.remote, .{ .method = .DELETE, .path = path, .query = &.{.{ .name = "uploadId", .value = upload_id }} }) catch {};
    };
    for (0..parts) |i| {
        const len = object.partSize(info.part_sizes, i);
        var src: Source = .{ .svc = r.svc, .info = info, .range = .{ .offset = offset, .length = len } };
        if (len == 0) src.range = null;
        offset += len;
        const pn = try std.fmt.allocPrint(a, "{d}", .{i + 1});
        const res = try client.send(hc, a, d.remote, .{
            .method = .PUT,
            .path = path,
            .query = &.{ .{ .name = "partNumber", .value = pn }, .{ .name = "uploadId", .value = upload_id } },
            .body = .{ .stream = .{ .len = len, .ctx = &src, .write = Source.write } },
        });
        if (!res.ok()) return res;
        cw.print("<Part><PartNumber>{d}</PartNumber><ETag>\"{s}\"</ETag></Part>", .{ i + 1, res.etag }) catch return error.OutOfMemory;
    }
    cw.writeAll("</CompleteMultipartUpload>") catch return error.OutOfMemory;
    var hs: std.ArrayList(Header) = .empty;
    try replicaHeaders(a, &hs, info);
    const res = try client.send(hc, a, d.remote, .{
        .method = .POST,
        .path = path,
        .query = try withVersion(a, vid, &.{.{ .name = "uploadId", .value = upload_id }}),
        .headers = hs.items,
        .body = .{ .bytes = complete.written() },
        .content_type = "application/xml",
    });
    // A 200 can still carry an error document.
    if (res.ok() and std.mem.indexOf(u8, res.body, "<Error>") != null) return .{ .status = 500, .body = res.body };
    if (res.ok()) abort = false;
    return res;
}

fn sendMarker(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry, info: object.ObjectInfo) Outcome {
    if (!d.rule.delete_marker) return .drop;
    // A null-version marker becomes a fresh marker on the target.
    const nullv = info.version_id.eql(ov.null_version_id);
    const vid = versionParam(a, info.version_id) catch return .retry;
    const res = client.send(hc, a, d.remote, .{
        .method = .DELETE,
        .path = objectPath(a, d, e.key) catch return .retry,
        .query = withVersion(a, vid, &.{}) catch return .retry,
        .headers = &.{
            .{ .name = hdr_marker, .value = if (nullv) "false" else "true" },
            .{ .name = hdr_request, .value = "true" },
            mtimeHeader(a, info.created_ns) catch return .retry,
        },
    }) catch return unreachable_(r, d, e, 0);
    if (!res.ok()) return failed(r, d, e, 0, res.code());
    succeeded(r, d, e, 0);
    return .done;
}

fn sendDeleteVersion(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry) Outcome {
    if (!d.rule.delete) return .drop;
    const res = client.send(hc, a, d.remote, .{
        .method = .DELETE,
        .path = objectPath(a, d, e.key) catch return .retry,
        .query = &.{.{ .name = "versionId", .value = e.version }},
        .headers = &.{.{ .name = hdr_request, .value = "true" }},
    }) catch return unreachable_(r, d, e, 0);
    if (!res.ok() and res.status != 404) return failed(r, d, e, 0, res.code());
    succeeded(r, d, e, 0);
    return .done;
}

fn sendMetadata(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry, info: object.ObjectInfo) Outcome {
    return sendMetadataInner(r, hc, a, d, e, info) catch |err| switch (err) {
        error.Unreachable => unreachable_(r, d, e, 0),
        else => failed(r, d, e, 0, @errorName(err)),
    };
}

fn sendMetadataInner(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, d: engine.Dest, e: Entry, info: object.ObjectInfo) client.Error!Outcome {
    const path = try objectPath(a, d, e.key);
    const vid = try versionParam(a, info.version_id);
    const hs = [_]Header{.{ .name = hdr_request, .value = "true" }};
    const tag_res = if (info.tags.len == 0)
        try client.send(hc, a, d.remote, .{ .method = .DELETE, .path = path, .query = try withVersion(a, vid, &.{.{ .name = "tagging", .value = "" }}), .headers = &hs })
    else blk: {
        var tw: std.Io.Writer.Allocating = .init(a);
        const w = &tw.writer;
        w.writeAll("<Tagging><TagSet>") catch return error.OutOfMemory;
        for (engine.decodeTags(a, info.tags)) |t| {
            w.writeAll("<Tag>") catch return error.OutOfMemory;
            s3.xml.elem(w, "Key", t.key) catch return error.OutOfMemory;
            s3.xml.elem(w, "Value", t.value) catch return error.OutOfMemory;
            w.writeAll("</Tag>") catch return error.OutOfMemory;
        }
        w.writeAll("</TagSet></Tagging>") catch return error.OutOfMemory;
        break :blk try client.send(hc, a, d.remote, .{ .method = .PUT, .path = path, .query = try withVersion(a, vid, &.{.{ .name = "tagging", .value = "" }}), .headers = &hs, .body = .{ .bytes = tw.written() }, .content_type = "application/xml" });
    };
    // The version never arrived: send it whole.
    if (tag_res.status == 404) return sendObjectInner(r, hc, a, d, e, info);
    if (!tag_res.ok()) return failed(r, d, e, 0, tag_res.code());
    const lock_cfg = ov.getConfig(r.svc, a, e.bucket) catch return .retry;
    if (lock_cfg.lock_enabled) {
        const tb = try a.create([24]u8);
        const ret_body = if (info.retention_mode == .none)
            "<Retention></Retention>"
        else
            try std.fmt.allocPrint(a, "<Retention><Mode>{s}</Mode><RetainUntilDate>{s}</RetainUntilDate></Retention>", .{
                if (info.retention_mode == .compliance) "COMPLIANCE" else "GOVERNANCE", core.time.iso8601(info.retain_until_ns, tb),
            });
        const lock_hs = [_]Header{ .{ .name = hdr_request, .value = "true" }, .{ .name = "x-amz-bypass-governance-retention", .value = "true" } };
        const rr = try client.send(hc, a, d.remote, .{ .method = .PUT, .path = path, .query = try withVersion(a, vid, &.{.{ .name = "retention", .value = "" }}), .headers = &lock_hs, .body = .{ .bytes = ret_body }, .content_type = "application/xml" });
        if (!rr.ok()) return failed(r, d, e, 0, rr.code());
        const lh = try std.fmt.allocPrint(a, "<LegalHold><Status>{s}</Status></LegalHold>", .{if (info.legal_hold) "ON" else "OFF"});
        const lr = try client.send(hc, a, d.remote, .{ .method = .PUT, .path = path, .query = try withVersion(a, vid, &.{.{ .name = "legal-hold", .value = "" }}), .headers = &hs, .body = .{ .bytes = lh }, .content_type = "application/xml" });
        if (!lr.ok()) return failed(r, d, e, 0, lr.code());
    }
    succeeded(r, d, e, 0);
    return .done;
}

/// COMPLETED once no other target still has this version queued.
fn markCompleted(r: *engine.Replicator, a: Allocator, e: Entry, v: core.VersionId) void {
    const bid = r.svc.bucketId(e.bucket) catch return;
    const arns = r.allArns(a, bid, e.bucket) catch return;
    for (arns) |arn| {
        if (std.mem.eql(u8, arn, e.arn)) continue;
        for ([_]queue.Op{ .put, .existing }) |op| {
            const other: Entry = .{ .op = op, .bucket = e.bucket, .key = e.key, .version = e.version, .arn = arn };
            const k = other.recordKey(a) catch return;
            if (r.svc.store.getRecord(k, a)) |_| return else |_| {}
        }
    }
    ov.setReplicationStatus(r.svc, e.bucket, e.key, v, .completed) catch {};
    r.svc.emitEvent(.{ .bucket = e.bucket, .key = e.key, .version = v, .kind = .replication_completed });
}

/// Marks a version FAILED after its first failed delivery.
pub fn markFailed(r: *engine.Replicator, e: Entry) void {
    if (e.op != .put and e.op != .existing) return;
    const v = ov.parseVersionId(e.version) catch return;
    ov.setReplicationStatus(r.svc, e.bucket, e.key, v, .failed) catch {};
    r.svc.emitEvent(.{ .bucket = e.bucket, .key = e.key, .version = v, .kind = .replication_failed });
}
