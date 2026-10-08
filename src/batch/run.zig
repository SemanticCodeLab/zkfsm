//! One pass of a job over its objects: replicate (local or remote source and
//! target), keyrotate (in-place reseal), expire (rule-matched version deletes).
//! Failures are counted, not fatal; the manager decides about retries.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const sign = @import("../backend/s3/sign.zig");
const sse_mod = @import("../sse/root.zig");
const replication = @import("../replication/root.zig");
const spec = @import("spec.zig");
const job_mod = @import("job.zig");
const walk = @import("walk.zig");
const crypt = @import("crypt.zig");
const match = @import("match.zig");
const remote = @import("remote.zig");

const Allocator = std.mem.Allocator;
const ov = object.versioning;
const client = replication.client;
const hdr = replication.deliver;
const Job = job_mod.Job;
const Version = walk.Version;

pub const Env = struct {
    svc: *object.ObjectService,
    sse: ?*sse_mod.Sse = null,
};

/// Checkpoints are saved at most this often.
const save_interval_ns = 2 * std.time.ns_per_s;

pub const Run = struct {
    env: Env,
    job: *Job,
    spec: spec.Job,
    attempt: u32,
    now_ns: i128,
    failures: bool = false,
    last_save_ns: i128 = 0,
    hc: std.http.Client,

    pub fn init(env: Env, j: *Job, s: spec.Job, attempt: u32) Run {
        return .{ .env = env, .job = j, .spec = s, .attempt = attempt, .now_ns = std.time.nanoTimestamp(), .hc = .{ .allocator = j.gpa } };
    }

    pub fn deinit(r: *Run) void {
        r.hc.deinit();
    }

    fn mark(r: *Run, key: []const u8) void {
        r.job.setCheckpoint(key);
        const now = std.time.nanoTimestamp();
        if (now - r.last_save_ns < save_interval_ns) return;
        r.last_save_ns = now;
        job_mod.persist(r.job, r.env.svc.store);
    }

    fn failed(r: *Run, d: job_mod.Counters, what: []const u8, key: []const u8, why: []const u8) void {
        r.failures = true;
        r.job.add(d);
        std.log.warn("batch {s}: {s} {s} failed: {s}", .{ &r.job.id, what, key, why });
    }

    /// Runs one pass from the job's checkpoint.
    pub fn pass(r: *Run) void {
        const from = r.job.gpa.dupe(u8, r.job.checkpoint.items) catch return r.fatal("out of memory");
        defer r.job.gpa.free(from);
        switch (r.spec.body) {
            .replicate => |rep| if (rep.source.isLocal()) {
                walk.keys(r.env.svc, r.job.gpa, rep.source.bucket, rep.source.prefix, from, r, replicateKey) catch |e| r.fatal(@errorName(e));
            } else r.pullRemote(rep, from),
            .keyrotate => |k| walk.keys(r.env.svc, r.job.gpa, k.bucket, k.prefix, from, r, rotateKey) catch |e| r.fatal(@errorName(e)),
            .expire => |e| walk.keys(r.env.svc, r.job.gpa, e.bucket, e.prefix, from, r, expireKey) catch |err| r.fatal(@errorName(err)),
        }
        job_mod.persist(r.job, r.env.svc.store);
    }

    fn fatal(r: *Run, why: []const u8) void {
        r.failures = true;
        r.job.setState(r.job.getState(), why);
        std.log.warn("batch {s}: pass stopped: {s}", .{ &r.job.id, why });
    }

    // ---- replicate ----

    fn targetKey(a: Allocator, prefix: []const u8, key: []const u8) Allocator.Error![]const u8 {
        if (prefix.len == 0) return key;
        if (prefix[prefix.len - 1] == '/') return std.mem.concat(a, u8, &.{ prefix, key });
        return std.mem.concat(a, u8, &.{ prefix, "/", key });
    }

    fn replicateKey(r: *Run, key: []const u8, versions: []const Version) bool {
        if (r.job.canceled()) return false;
        const rep = r.spec.body.replicate;
        r.job.touch(rep.source.bucket, key);
        var arena = std.heap.ArenaAllocator.init(r.job.gpa);
        defer arena.deinit();
        var i = versions.len;
        while (i > 0) {
            i -= 1;
            _ = arena.reset(.retain_capacity);
            if (r.job.canceled()) return false;
            r.replicateVersion(arena.allocator(), rep, key, versions[i]);
        }
        r.mark(key);
        return true;
    }

    fn replicateVersion(r: *Run, a: Allocator, rep: spec.Replicate, key: []const u8, v: Version) void {
        if (!match.times(rep.filter, v.mtime_ns)) return;
        const tkey = targetKey(a, rep.target.prefix, key) catch return r.failed(.{ .objects_failed = 1 }, "replicate", key, "out of memory");
        if (v.delete_marker) {
            const ok = if (rep.target.isLocal()) r.localMarker(rep.target.bucket, tkey, v.version, v.mtime_ns) else r.remoteMarker(a, rep.target, tkey, v);
            if (ok) r.job.add(.{ .delete_markers = 1 }) else r.failed(.{ .delete_markers_failed = 1 }, "delete marker", key, "target refused");
            return;
        }
        const info = ov.headVersion(r.env.svc, a, rep.source.bucket, key, v.version) catch |e| switch (e) {
            error.NoSuchKey, error.NoSuchVersion => return,
            else => return r.failed(.{ .objects_failed = 1 }, "replicate", key, @errorName(e)),
        };
        if (!match.tags(a, rep.filter.tags, info) or !match.metadata(rep.filter.metadata, info)) return;
        const res = if (rep.target.isLocal())
            r.copyLocal(a, rep, key, tkey, info)
        else
            r.pushRemote(a, rep, key, tkey, info);
        switch (res) {
            .sent => r.job.add(.{ .objects = 1, .bytes = @intCast(info.size) }),
            .present => if (r.attempt == 0) r.job.add(.{ .objects = 1 }),
            .failed => |why| r.failed(.{ .objects_failed = 1, .bytes_failed = @intCast(info.size) }, "replicate", key, why),
        }
    }

    const Outcome = union(enum) { sent, present, failed: []const u8 };

    fn originFor(v: core.VersionId, created_ns: i128, marker: bool) object.replica.Origin {
        return .{ .version = if (v.eql(ov.null_version_id)) null else v, .created_ns = created_ns, .delete_marker = marker };
    }

    fn copyLocal(r: *Run, a: Allocator, rep: spec.Replicate, key: []const u8, tkey: []const u8, info: object.ObjectInfo) Outcome {
        const svc = r.env.svc;
        if (!info.version_id.eql(ov.null_version_id)) {
            if (ov.headVersion(svc, a, rep.target.bucket, tkey, info.version_id)) |t| {
                if (!t.delete_marker and std.meta.eql(t.etag, info.etag)) return .present;
            } else |_| {}
        }
        const seal = crypt.sealing(a, info) catch |e| return .{ .failed = @errorName(e) };
        object.replica.origin = originFor(info.version_id, info.created_ns, false);
        defer object.replica.origin = null;
        if (seal == null) {
            _ = object.copy.copyObject(svc, .{ .bucket = rep.source.bucket, .key = key, .version = info.version_id }, rep.target.bucket, tkey, .{}) catch |e| return .{ .failed = @errorName(e) };
            return .sent;
        }
        var plain = crypt.open(a, r.env.sse, svc, info, rep.source.bucket, key) catch |e| return .{ .failed = @errorName(e) };
        defer plain.deinit();
        const t = crypt.sameTarget(a, seal.?) catch |e| return .{ .failed = @errorName(e) };
        const base = sealedBase(a, info) catch |e| return .{ .failed = @errorName(e) };
        _ = crypt.putSealed(a, r.env.sse, svc, rep.target.bucket, tkey, plain.reader(), plain.size, t, base) catch |e| return .{ .failed = @errorName(e) };
        return .sent;
    }

    fn localMarker(r: *Run, bucket: []const u8, key: []const u8, v: core.VersionId, mtime_ns: i128) bool {
        var arena = std.heap.ArenaAllocator.init(r.job.gpa);
        defer arena.deinit();
        const cfg = ov.getConfig(r.env.svc, arena.allocator(), bucket) catch return false;
        if (cfg.versioning == .enabled and !v.eql(ov.null_version_id)) {
            object.replica.origin = originFor(v, mtime_ns, true);
            defer object.replica.origin = null;
            _ = ov.deleteObject(r.env.svc, bucket, key, .{ .version = v }) catch return false;
            return true;
        }
        _ = ov.deleteObject(r.env.svc, bucket, key, .{}) catch return false;
        return true;
    }

    fn remoteOf(l: spec.Location) client.Remote {
        return .{ .endpoint = l.endpoint, .secure = l.secure, .access_key = l.access_key, .secret_key = l.secret_key };
    }

    fn versionParam(a: Allocator, v: core.VersionId, base: []const client.Param) Allocator.Error![]const client.Param {
        if (v.eql(ov.null_version_id)) return base;
        const buf = try a.create([32]u8);
        const out = try a.alloc(client.Param, base.len + 1);
        @memcpy(out[0..base.len], base);
        out[base.len] = .{ .name = "versionId", .value = ov.formatVersionId(v, buf) };
        return out;
    }

    fn remoteMarker(r: *Run, a: Allocator, t: spec.Location, tkey: []const u8, v: Version) bool {
        const nullv = v.version.eql(ov.null_version_id);
        const mb = a.create([32]u8) catch return false;
        const res = client.send(&r.hc, a, remoteOf(t), .{
            .method = .DELETE,
            .path = std.fmt.allocPrint(a, "/{s}/{s}", .{ t.bucket, tkey }) catch return false,
            .query = versionParam(a, v.version, &.{}) catch return false,
            .headers = &.{
                .{ .name = hdr.hdr_marker, .value = if (nullv) "false" else "true" },
                .{ .name = hdr.hdr_request, .value = "true" },
                .{ .name = hdr.hdr_mtime, .value = replication.targets.rfc3339(v.mtime_ns, mb) },
            },
        }) catch return false;
        return res.ok();
    }

    const Pipe = struct {
        plain: *crypt.Plain,
        fn write(ctx: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void {
            const p: *Pipe = @ptrCast(@alignCast(ctx));
            p.plain.reader().streamExact64(w, p.plain.size) catch |e| return switch (e) {
                error.WriteFailed => error.WriteFailed,
                else => error.SourceFailed,
            };
        }
    };

    fn pushRemote(r: *Run, a: Allocator, rep: spec.Replicate, key: []const u8, tkey: []const u8, info: object.ObjectInfo) Outcome {
        const t = rep.target;
        const path = std.fmt.allocPrint(a, "/{s}/{s}", .{ t.bucket, tkey }) catch return .{ .failed = "out of memory" };
        var eb: [core.ETag.quoted_max]u8 = undefined;
        const etag = std.mem.trim(u8, info.etag.quoted(&eb), "\"");
        const q = versionParam(a, info.version_id, &.{}) catch return .{ .failed = "out of memory" };
        if (!info.version_id.eql(ov.null_version_id)) {
            if (client.send(&r.hc, a, remoteOf(t), .{ .method = .HEAD, .path = path, .query = q })) |h| {
                if (h.status == 200 and std.mem.eql(u8, h.etag, etag)) return .present;
            } else |_| {}
        }
        const seal = crypt.sealing(a, info) catch |e| return .{ .failed = @errorName(e) };
        var plain = crypt.open(a, r.env.sse, r.env.svc, info, rep.source.bucket, key) catch |e| return .{ .failed = @errorName(e) };
        defer plain.deinit();
        const hs = remoteHeaders(a, info, seal, etag) catch return .{ .failed = "out of memory" };
        var pipe: Pipe = .{ .plain = &plain };
        const res = client.send(&r.hc, a, remoteOf(t), .{
            .method = .PUT,
            .path = path,
            .query = q,
            .headers = hs,
            .content_type = if (info.content_type.len > 0) info.content_type else "binary/octet-stream",
            .body = .{ .stream = .{ .len = plain.size, .ctx = &pipe, .write = Pipe.write } },
        }) catch |e| return .{ .failed = @errorName(e) };
        if (!res.ok()) return .{ .failed = std.fmt.allocPrint(a, "HTTP {d} {s}", .{ res.status, res.code() }) catch "HTTP error" };
        return .sent;
    }

    fn remoteHeaders(a: Allocator, info: object.ObjectInfo, seal: ?crypt.Sealing, etag: []const u8) Allocator.Error![]const client.Header {
        var hs: std.ArrayList(client.Header) = .empty;
        for (info.metadata) |m| try hs.append(a, .{ .name = try std.fmt.allocPrint(a, "x-amz-meta-{s}", .{m.name}), .value = m.value });
        inline for (object.SystemHeaders.fields) |f| {
            var v = @field(info.system, f[0]);
            if (comptime std.mem.eql(u8, f[1], "content-encoding")) v = try s3.versioning.withoutAwsChunked(a, v);
            if (v.len > 0) try hs.append(a, .{ .name = f[1], .value = v });
        }
        if (info.tags.len > 0) {
            const tags = object.decodeTags(a, info.tags) catch &.{};
            var tw: std.Io.Writer.Allocating = .init(a);
            for (tags, 0..) |t, i| {
                if (i > 0) tw.writer.writeByte('&') catch return error.OutOfMemory;
                sign.uriEncode(&tw.writer, t.key, true) catch return error.OutOfMemory;
                tw.writer.writeByte('=') catch return error.OutOfMemory;
                sign.uriEncode(&tw.writer, t.value, true) catch return error.OutOfMemory;
            }
            try hs.append(a, .{ .name = "x-amz-tagging", .value = tw.written() });
        }
        if (seal) |s| switch (s.scheme) {
            .s3 => try hs.append(a, .{ .name = "x-amz-server-side-encryption", .value = "AES256" }),
            .kms => {
                try hs.append(a, .{ .name = "x-amz-server-side-encryption", .value = "aws:kms" });
                try hs.append(a, .{ .name = "x-amz-server-side-encryption-aws-kms-key-id", .value = s.key_id });
            },
            .c => {},
        };
        const mb = try a.create([32]u8);
        try hs.append(a, .{ .name = hdr.hdr_request, .value = "true" });
        try hs.append(a, .{ .name = hdr.hdr_mtime, .value = replication.targets.rfc3339(info.created_ns, mb) });
        try hs.append(a, .{ .name = hdr.hdr_etag, .value = etag });
        return hs.items;
    }

    /// Remote source into a local bucket, page by page from the checkpoint key.
    fn pullRemote(r: *Run, rep: spec.Replicate, from: []const u8) void {
        var key_marker: std.ArrayList(u8) = .empty;
        defer key_marker.deinit(r.job.gpa);
        var ver_marker: std.ArrayList(u8) = .empty;
        defer ver_marker.deinit(r.job.gpa);
        key_marker.appendSlice(r.job.gpa, from) catch return r.fatal("out of memory");
        const src = remoteOf(rep.source);
        while (!r.job.canceled()) {
            var arena = std.heap.ArenaAllocator.init(r.job.gpa);
            defer arena.deinit();
            const a = arena.allocator();
            const page = remote.listVersions(&r.hc, a, src, rep.source.bucket, rep.source.prefix, key_marker.items, ver_marker.items) catch |e| return r.fatal(@errorName(e));
            var i: usize = 0;
            while (i < page.entries.len) {
                var n: usize = 1;
                while (i + n < page.entries.len and std.mem.eql(u8, page.entries[i + n].key, page.entries[i].key)) n += 1;
                const group = page.entries[i .. i + n];
                r.job.touch(rep.source.bucket, group[0].key);
                var k = n;
                while (k > 0) {
                    k -= 1;
                    if (r.job.canceled()) return;
                    r.pullVersion(a, rep, group[k]);
                }
                // A key split across pages is checkpointed once its last part is done.
                if (i + n < page.entries.len or !page.truncated) r.mark(group[0].key);
                i += n;
            }
            if (!page.truncated) return;
            if (page.next_key.len == 0) return r.fatal("truncated listing without a marker");
            key_marker.clearRetainingCapacity();
            ver_marker.clearRetainingCapacity();
            key_marker.appendSlice(r.job.gpa, page.next_key) catch return r.fatal("out of memory");
            ver_marker.appendSlice(r.job.gpa, page.next_version) catch return r.fatal("out of memory");
        }
    }

    const Sink = struct {
        r: *Run,
        a: Allocator,
        rep: spec.Replicate,
        tkey: []const u8,
        e: remote.Entry,
        err: ?[]const u8 = null,
        skipped: bool = false,

        fn consume(ctx: *anyopaque, head: remote.Head, body: *std.Io.Reader) bool {
            const s: *Sink = @ptrCast(@alignCast(ctx));
            const meta = s.a.alloc(object.Header, head.metadata.len) catch {
                s.err = "out of memory";
                return false;
            };
            for (head.metadata, meta) |h, *m| m.* = .{ .name = h.name, .value = h.value };
            var probe: object.ObjectInfo = .{ .key = s.e.key, .size = 0, .etag = .{ .md5 = @splat(0) }, .created_ns = 0, .content_type = head.content_type, .object_id = undefined, .version_id = undefined, .metadata = meta };
            probe.system = .{};
            if (!match.metadata(s.rep.filter.metadata, probe)) {
                s.skipped = true;
                _ = body.discardRemaining() catch {};
                return false;
            }
            const len = head.content_length orelse {
                s.err = "no content length";
                return false;
            };
            const v = ov.parseVersionId(s.e.version_id) catch ov.null_version_id;
            object.replica.origin = originFor(v, s.e.mtime_ns, false);
            defer object.replica.origin = null;
            _ = s.r.env.svc.put(s.rep.target.bucket, s.tkey, body, .{ .content_type = head.content_type, .content_length = len, .metadata = meta }) catch |e| {
                s.err = @errorName(e);
                return false;
            };
            return true;
        }
    };

    fn pullVersion(r: *Run, a: Allocator, rep: spec.Replicate, e: remote.Entry) void {
        if (!match.times(rep.filter, e.mtime_ns)) return;
        const tkey = targetKey(a, rep.target.prefix, e.key) catch return r.failed(.{ .objects_failed = 1 }, "replicate", e.key, "out of memory");
        const v = ov.parseVersionId(e.version_id) catch ov.null_version_id;
        if (e.delete_marker) {
            if (r.localMarker(rep.target.bucket, tkey, v, e.mtime_ns)) r.job.add(.{ .delete_markers = 1 }) else r.failed(.{ .delete_markers_failed = 1 }, "delete marker", e.key, "local delete failed");
            return;
        }
        if (!v.eql(ov.null_version_id)) {
            if (ov.headVersion(r.env.svc, a, rep.target.bucket, tkey, v)) |t| {
                var eb: [core.ETag.quoted_max]u8 = undefined;
                if (!t.delete_marker and std.mem.eql(u8, std.mem.trim(u8, t.etag.quoted(&eb), "\""), e.etag)) {
                    if (r.attempt == 0) r.job.add(.{ .objects = 1 });
                    return;
                }
            } else |_| {}
        }
        var sink: Sink = .{ .r = r, .a = a, .rep = rep, .tkey = tkey, .e = e };
        const q = if (std.mem.eql(u8, e.version_id, "null")) &[_]client.Param{} else a.dupe(client.Param, &.{.{ .name = "versionId", .value = e.version_id }}) catch return r.failed(.{ .objects_failed = 1 }, "replicate", e.key, "out of memory");
        const path = std.fmt.allocPrint(a, "/{s}/{s}", .{ rep.source.bucket, e.key }) catch return r.failed(.{ .objects_failed = 1 }, "replicate", e.key, "out of memory");
        const res = remote.getInto(&r.hc, a, remoteOf(rep.source), path, q, .{ .ctx = &sink, .func = Sink.consume }) catch |err|
            return r.failed(.{ .objects_failed = 1, .bytes_failed = @intCast(e.size) }, "replicate", e.key, @errorName(err));
        if (sink.skipped) return;
        if (!res.consumed) {
            const why = sink.err orelse (std.fmt.allocPrint(a, "HTTP {d}", .{res.head.status}) catch "HTTP error");
            return r.failed(.{ .objects_failed = 1, .bytes_failed = @intCast(e.size) }, "replicate", e.key, why);
        }
        r.job.add(.{ .objects = 1, .bytes = @intCast(e.size) });
    }

    // ---- keyrotate ----

    fn rotateKey(r: *Run, key: []const u8, versions: []const Version) bool {
        if (r.job.canceled()) return false;
        const kr = r.spec.body.keyrotate;
        r.job.touch(kr.bucket, key);
        var arena = std.heap.ArenaAllocator.init(r.job.gpa);
        defer arena.deinit();
        for (versions) |v| {
            _ = arena.reset(.retain_capacity);
            if (r.job.canceled()) return false;
            if (v.delete_marker or !match.times(kr.filter, v.mtime_ns)) continue;
            switch (r.rotateVersion(arena.allocator(), kr, key, v.version)) {
                .skipped => {},
                .rotated => r.job.add(.{ .objects = 1 }),
                .failed => |why| r.failed(.{ .objects_failed = 1 }, "keyrotate", key, why),
            }
        }
        r.mark(key);
        return true;
    }

    const Rotation = union(enum) { skipped, rotated, failed: []const u8 };

    fn rotateVersion(r: *Run, a: Allocator, kr: spec.KeyRotate, key: []const u8, version: core.VersionId) Rotation {
        const svc = r.env.svc;
        const info = ov.headVersion(svc, a, kr.bucket, key, version) catch |e| return switch (e) {
            error.NoSuchKey, error.NoSuchVersion => .skipped,
            else => .{ .failed = @errorName(e) },
        };
        const seal = (crypt.sealing(a, info) catch |e| return switch (e) {
            error.Unsupported => .skipped,
            else => .{ .failed = @errorName(e) },
        }) orelse return .skipped;
        if (kr.filter.kms_key.len > 0 and !std.mem.eql(u8, kr.filter.kms_key, seal.key_id)) return .skipped;
        if (!match.tags(a, kr.filter.tags, info) or !match.metadata(kr.filter.metadata, info)) return .skipped;
        const ext = r.env.sse orelse return .{ .failed = "KMS not configured" };
        const target: crypt.Target = .{
            .scheme = if (kr.encryption == .sse_s3) .s3 else .kms,
            .key_id = if (kr.encryption == .sse_s3) ext.default_key else kr.key,
            .context = toPairs(a, kr.context) catch return .{ .failed = "out of memory" },
        };
        // A retry pass leaves versions it already moved alone.
        if (r.attempt > 0 and seal.scheme == target.scheme and std.mem.eql(u8, seal.key_id, target.key_id)) return .skipped;
        const cfg = ov.getConfig(svc, a, kr.bucket) catch |e| return .{ .failed = @errorName(e) };
        const is_null = version.eql(ov.null_version_id);
        // Rewrites keep the version id; these states cannot place it.
        if (cfg.versioning == .suspended and !is_null) return .{ .failed = "non-null version in a suspended bucket" };
        if (cfg.versioning == .enabled and is_null) return .{ .failed = "null version in a versioned bucket" };
        var plain = crypt.open(a, r.env.sse, svc, info, kr.bucket, key) catch |e| return .{ .failed = @errorName(e) };
        defer plain.deinit();
        var base = sealedBase(a, info) catch return .{ .failed = "out of memory" };
        if (info.retention_mode != .none) base.retention = .{ .mode = info.retention_mode, .until_ns = info.retain_until_ns };
        base.legal_hold = info.legal_hold;
        {
            object.replica.origin = originFor(version, info.created_ns, false);
            defer object.replica.origin = null;
            _ = crypt.putSealed(a, r.env.sse, svc, kr.bucket, key, plain.reader(), plain.size, target, base) catch |e| return .{ .failed = @errorName(e) };
        }
        // The rewrite is not a replica: restore the version's own replication status.
        const old = for (info.internal) |h| {
            if (std.mem.eql(u8, h.name, object.replica.status_header)) break h.value;
        } else null;
        _ = object.objmeta.setInternalHeader(svc, kr.bucket, key, if (is_null) null else version, object.replica.status_header, old) catch {};
        return .rotated;
    }

    fn toPairs(a: Allocator, kv: []const spec.KeyValue) Allocator.Error![]const @import("../kms/root.zig").Context.Pair {
        const out = try a.alloc(@import("../kms/root.zig").Context.Pair, kv.len);
        for (kv, out) |x, *o| o.* = .{ .key = x.key, .value = x.value };
        return out;
    }

    // ---- expire ----

    fn expireKey(r: *Run, key: []const u8, versions: []const Version) bool {
        if (r.job.canceled()) return false;
        const ex = r.spec.body.expire;
        r.job.touch(ex.bucket, key);
        var arena = std.heap.ArenaAllocator.init(r.job.gpa);
        defer arena.deinit();
        const rule = for (ex.rules) |rule| {
            if (r.ruleMatches(arena.allocator(), ex.bucket, rule, key, versions)) break rule;
        } else {
            r.mark(key);
            return true;
        };
        if (rule.retain_versions < versions.len) for (versions[rule.retain_versions..]) |v| {
            if (r.job.canceled()) return false;
            if (ov.deleteObject(r.env.svc, ex.bucket, key, .{ .version = v.version })) |_| {
                r.job.add(if (v.delete_marker) .{ .delete_markers = 1 } else .{ .objects = 1 });
            } else |e| switch (e) {
                error.NoSuchKey, error.NoSuchVersion => {},
                else => r.failed(if (v.delete_marker) .{ .delete_markers_failed = 1 } else .{ .objects_failed = 1 }, "expire", key, @errorName(e)),
            }
        };
        r.mark(key);
        return true;
    }

    fn ruleMatches(r: *Run, a: Allocator, bucket: []const u8, rule: spec.Rule, key: []const u8, versions: []const Version) bool {
        const latest = versions[0];
        if (latest.delete_marker != (rule.type == .deleted)) return false;
        if (rule.name.len > 0 and !spec.glob(rule.name, key)) return false;
        if (rule.older_than_ns) |d| if (r.now_ns - latest.mtime_ns < @as(i128, d)) return false;
        if (rule.created_before_ns) |t| if (latest.mtime_ns >= t) return false;
        if (rule.size_lt) |n| if (latest.size >= n) return false;
        if (rule.size_gt) |n| if (latest.size <= n) return false;
        if (rule.tags.len == 0 and rule.metadata.len == 0) return true;
        const info = ov.headVersion(r.env.svc, a, bucket, key, latest.version) catch return false;
        return match.tags(a, rule.tags, info) and match.metadata(rule.metadata, info);
    }
};

/// Put fields of a rewritten version: content type, metadata, tags, ETag;
/// encryption headers are dropped (the writer adds fresh ones).
fn sealedBase(a: Allocator, info: object.ObjectInfo) crypt.Error!object.PutInput {
    return .{
        .content_type = info.content_type,
        .metadata = info.metadata,
        .system = info.system,
        .tags = info.tags,
        .internal = try crypt.plainInternal(a, info),
        .etag_override = info.etag,
    };
}
