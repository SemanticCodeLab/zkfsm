//! Writes migrated buckets, versions, delete markers, configurations, and IAM
//! entities into zkfsm through its object and IAM layers, keeping version ids and
//! modification times. Also compares an imported version against its source.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const s3 = @import("../s3/root.zig");
const sse = @import("../sse/root.zig");
const events = @import("../events/root.zig");
const xml = @import("../backend/remote/xml.zig");
const model = @import("model.zig");

const ov = object.versioning;
const Svc = object.ObjectService;

pub const Error = object.Error;

pub const Stats = struct {
    buckets: u64 = 0,
    versions: u64 = 0,
    markers: u64 = 0,
    bytes: u64 = 0,
    skipped: u64 = 0,
    failed: u64 = 0,
    config_warnings: u64 = 0,
    iam_entities: u64 = 0,
    verified: u64 = 0,
    mismatches: u64 = 0,
};

pub const Sink = struct {
    svc: *Svc,
    iam_store: ?*iam.Store = null,
    stats: Stats = .{},

    fn warnCfg(s: *Sink, bucket: []const u8, what: []const u8, e: anytype) void {
        s.stats.config_warnings += 1;
        std.log.warn("bucket {s}: {s} not imported: {t}", .{ bucket, what, e });
    }

    /// Creates the bucket ready for import: lock-enabled if the source is, and with
    /// versioning on whenever the source ever versioned (suspended is set at the end).
    pub fn ensureBucket(s: *Sink, name: []const u8, c: model.BucketConfigs) Error!void {
        const exists = if (s.svc.headBucket(name)) true else |e| if (e == error.NoSuchBucket) false else return e;
        if (!exists) {
            if (c.lock_enabled) try ov.createLockedBucket(s.svc, name) else try s.svc.createBucket(name);
            s.stats.buckets += 1;
        }
        if (versioningState(c.versioning) != .unset) try ov.setVersioning(s.svc, name, .enabled);
    }

    /// Applies every configuration after the objects are in (default retention must
    /// not stamp imported versions, and suspension must follow the import).
    pub fn finishBucket(s: *Sink, arena: std.mem.Allocator, name: []const u8, c: model.BucketConfigs) Error!void {
        if (versioningState(c.versioning) == .suspended) ov.setVersioning(s.svc, name, .suspended) catch |e| s.warnCfg(name, "versioning", e);
        if (c.object_lock) |doc| s.applyLock(name, doc) catch |e| s.warnCfg(name, "object lock configuration", e);
        if (c.policy) |doc| object.policy.set(s.svc, name, doc) catch |e| s.warnCfg(name, "policy", e);
        if (c.tagging) |doc| s.applyTagging(arena, name, doc) catch |e| s.warnCfg(name, "tagging", e);
        if (c.lifecycle) |doc| s.applyLifecycle(arena, name, doc) catch |e| s.warnCfg(name, "lifecycle", e);
        if (c.encryption) |doc| s.applyEncryption(arena, name, doc) catch |e| s.warnCfg(name, "encryption", e);
        if (c.notification) |doc| s.applyNotification(arena, name, doc) catch |e| s.warnCfg(name, "notification", e);
        if (c.cors) |doc| s.applyCors(arena, name, doc) catch |e| s.warnCfg(name, "cors", e);
        if (c.quota) |doc| s.applyQuota(arena, name, doc) catch |e| s.warnCfg(name, "quota", e);
        if (c.replication != null) {
            s.stats.config_warnings += 1;
            std.log.warn("bucket {s}: replication rules are not migrated (remote targets hold source credentials)", .{name});
        }
    }

    fn applyLock(s: *Sink, name: []const u8, doc: []const u8) Error!void {
        const rule = xml.find(doc, "DefaultRetention") orelse return;
        const mode = model.parseMode(std.mem.trim(u8, xml.find(rule, "Mode") orelse "", " \r\n\t"));
        const days = std.fmt.parseInt(u32, std.mem.trim(u8, xml.find(rule, "Days") orelse "0", " \r\n\t"), 10) catch return error.InvalidRequest;
        const years = std.fmt.parseInt(u32, std.mem.trim(u8, xml.find(rule, "Years") orelse "0", " \r\n\t"), 10) catch return error.InvalidRequest;
        try ov.setLockConfig(s.svc, name, .{ .mode = mode, .days = days, .years = years });
    }

    fn applyTagging(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        var tags: std.ArrayList(model.Tag) = .empty;
        var sc: xml.Scanner = .{ .doc = doc };
        while (sc.next("Tag")) |t| {
            const k = try unescape(arena, xml.find(t, "Key") orelse return error.InvalidTag);
            const v = try unescape(arena, xml.find(t, "Value") orelse "");
            try tags.append(arena, .{ .key = k, .value = v });
        }
        try ov.setBucketTags(s.svc, name, if (tags.items.len == 0) null else tags.items);
    }

    fn applyLifecycle(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        const rules = s3.lifecycle.parse(arena, doc) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRequest,
        };
        try object.lifecycle.set(s.svc, name, rules);
        try object.bucket_meta.set(s.svc, name, .lifecycle_legacy, try s3.lifecycle.legacyMarks(arena, doc, rules.len));
    }

    fn applyEncryption(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        const algo = std.mem.trim(u8, xml.find(doc, "SSEAlgorithm") orelse return error.InvalidRequest, " \r\n\t");
        const key_id = std.mem.trim(u8, xml.find(doc, "KMSMasterKeyID") orelse "", " \r\n\t");
        const wire = if (std.mem.eql(u8, algo, "AES256")) "AES256" else if (std.mem.eql(u8, algo, "aws:kms")) "aws:kms" else return error.InvalidRequest;
        const bid = try s.svc.bucketId(name);
        const rec = try std.fmt.allocPrint(arena, "{s}\n{s}", .{ wire, key_id });
        s.svc.store.putRecord(sse.handler.configKey(bid), rec) catch |e| return object.service.mapBackend(e);
    }

    fn applyNotification(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        const cfg = events.config.parse(arena, doc) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRequest,
        };
        if (cfg.rules.len == 0) return;
        std.log.info("bucket {s}: notification rules imported; define their targets on zkfsm", .{name});
        const out = try events.config.render(arena, cfg);
        events.store.put(s.svc.store, events.store.key(.bucket, name), out) catch return error.StorageFailed;
    }

    fn applyCors(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        _ = s3.cors_config.parse(arena, doc) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidRequest,
        };
        try object.bucket_meta.set(s.svc, name, .cors, doc);
    }

    fn applyQuota(s: *Sink, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error!void {
        const Q = struct { quota: u64 = 0, size: u64 = 0 };
        const q = std.json.parseFromSliceLeaky(Q, arena, doc, .{ .ignore_unknown_fields = true }) catch return error.InvalidRequest;
        const bytes = if (q.size > 0) q.size else q.quota;
        if (bytes > 0) try object.quota.set(s.svc, name, bytes);
    }

    /// Stores one object version from `body` under its source id and time.
    pub fn putVersion(s: *Sink, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, v: model.VersionInfo, body: *std.Io.Reader) Error!void {
        var in: object.PutInput = .{
            .content_type = v.content_type,
            .content_length = v.size,
            .metadata = v.user,
            .system = v.system,
            .legal_hold = v.legal_hold,
        };
        if (v.tags.len > 0) in.tags = try ov.encodeObjectTags(arena, v.tags);
        if (v.mode != .none and v.until_ns > 0) in.retention = .{ .mode = v.mode, .until_ns = v.until_ns };
        if (multipartEtag(v.etag)) |e| in.etag_override = e;
        object.replica.origin = s.origin(v);
        defer object.replica.origin = null;
        _ = try s.svc.put(bucket, key, body, in);
        s.stats.versions += 1;
        s.stats.bytes += v.size;
    }

    pub fn putMarker(s: *Sink, bucket: []const u8, key: []const u8, v: model.VersionInfo) Error!void {
        var o = s.origin(v);
        o.delete_marker = true;
        object.replica.origin = o;
        defer object.replica.origin = null;
        _ = try ov.deleteObject(s.svc, bucket, key, .{ .version = .{ .bytes = v.id } });
        s.stats.markers += 1;
    }

    fn origin(s: *Sink, v: model.VersionInfo) object.replica.Origin {
        _ = s;
        return .{ .version = .{ .bytes = v.id }, .created_ns = v.mtime_ns, .migrated = true };
    }

    // ---- verification ----

    /// Compares the imported version with the source; returns a mismatch description.
    /// `body` streams the source bytes; null for delete markers.
    pub fn verifyVersion(s: *Sink, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, v: model.VersionInfo, body: ?*std.Io.Reader) Error!?[]const u8 {
        const info = ov.headVersion(s.svc, arena, bucket, key, .{ .bytes = v.id }) catch |e| switch (e) {
            error.NoSuchKey, error.NoSuchVersion, error.MethodNotAllowed => return "version missing",
            else => return e,
        };
        if (info.delete_marker != v.delete_marker) return "delete-marker flag differs";
        if (info.created_ns != v.mtime_ns) return "modification time differs";
        if (v.delete_marker) return null;
        if (info.size != v.size) return "size differs";
        var eb: [core.ETag.quoted_max]u8 = undefined;
        const etag = std.mem.trim(u8, info.etag.quoted(&eb), "\"");
        if (v.etag.len > 0 and !std.ascii.eqlIgnoreCase(etag, v.etag)) return "etag differs";
        if (!std.mem.eql(u8, info.content_type, v.content_type) and v.content_type.len > 0) return "content-type differs";
        if (info.metadata.len != v.user.len) return "user metadata differs";
        for (v.user) |h| {
            const got = for (info.metadata) |m| {
                if (std.mem.eql(u8, m.name, h.name)) break m.value;
            } else return "user metadata differs";
            if (!std.mem.eql(u8, got, h.value)) return "user metadata differs";
        }
        const tags = try object.decodeTags(arena, info.tags);
        if (tags.len != v.tags.len) return "tags differ";
        for (v.tags, tags) |a, b| if (!std.mem.eql(u8, a.key, b.key) or !std.mem.eql(u8, a.value, b.value)) return "tags differ";
        if (v.mode != .none and (info.retention_mode != v.mode or info.retain_until_ns != v.until_ns)) return "retention differs";
        if (info.legal_hold != v.legal_hold) return "legal hold differs";
        const src = body orelse return null;
        var want: [32]u8 = undefined;
        sha256Of(src, &want) catch return "source unreadable";
        var hw: HashWriter = undefined;
        hw.init();
        s.svc.read(info, null, &hw.writer) catch return "stored data unreadable";
        var got: [32]u8 = undefined;
        hw.final(&got);
        if (!std.mem.eql(u8, &want, &got)) return "content differs";
        return null;
    }
};

const HashWriter = struct {
    h: std.crypto.hash.sha2.Sha256 = .init(.{}),
    buf: [64 * 1024]u8 = undefined,
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },

    fn init(self: *HashWriter) void {
        self.* = .{};
        self.writer.buffer = &self.buf;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *HashWriter = @alignCast(@fieldParentPtr("writer", w));
        self.h.update(w.buffer[0..w.end]);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            self.h.update(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| self.h.update(last);
        return n + last.len * splat;
    }

    fn final(self: *HashWriter, out: *[32]u8) void {
        self.h.update(self.writer.buffer[0..self.writer.end]);
        self.writer.end = 0;
        self.h.final(out);
    }
};

fn sha256Of(r: *std.Io.Reader, out: *[32]u8) std.Io.Reader.StreamError!void {
    var hw: HashWriter = undefined;
    hw.init();
    _ = r.streamRemaining(&hw.writer) catch |e| switch (e) {
        error.ReadFailed => return error.ReadFailed,
        error.WriteFailed => return error.WriteFailed,
    };
    hw.final(out);
}

pub fn versioningState(doc: ?[]const u8) ov.Versioning {
    const d = doc orelse return .unset;
    const st = std.mem.trim(u8, xml.find(d, "Status") orelse return .unset, " \r\n\t");
    if (std.mem.eql(u8, st, "Enabled")) return .enabled;
    if (std.mem.eql(u8, st, "Suspended")) return .suspended;
    return .unset;
}

/// `<md5hex>-<parts>` as an ETag; null for single-part ETags.
pub fn multipartEtag(s: []const u8) ?core.ETag {
    const dash = std.mem.indexOfScalar(u8, s, '-') orelse return null;
    if (dash != 32) return null;
    var e: core.ETag = .{ .md5 = undefined };
    _ = std.fmt.hexToBytes(&e.md5, s[0..32]) catch return null;
    e.parts = std.fmt.parseInt(u32, s[33..], 10) catch return null;
    return e;
}

fn unescape(arena: std.mem.Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
    const buf = try arena.alloc(u8, raw.len);
    return xml.unescape(raw, buf) catch raw;
}

// ---- IAM ----

pub const IamError = iam.store.StoreError || error{OutOfMemory};

/// Imports one IAM record by its path under `config/iam/`. Unknown paths are ignored.
pub fn importIam(s: *Sink, arena: std.mem.Allocator, path: []const u8, body: []const u8) IamError!void {
    const st = s.iam_store orelse return;
    if (body.len == 0 or body[0] != '{') {
        std.log.warn("iam {s}: not plain JSON (encrypted?); skipped", .{path});
        return;
    }
    var parts: [8][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |p| {
        if (n == parts.len) return;
        parts[n] = p;
        n += 1;
    }
    const json = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch {
        std.log.warn("iam {s}: malformed JSON; skipped", .{path});
        return;
    };
    if (json != .object) return;
    const obj = json.object;
    if (n == 3 and std.mem.eql(u8, parts[0], "policies") and std.mem.eql(u8, parts[2], "policy.json")) {
        const doc = obj.get("Policy") orelse return;
        const text = std.json.Stringify.valueAlloc(arena, doc, .{}) catch return error.OutOfMemory;
        st.putPolicy(parts[1], text) catch |e| return logIam(path, e);
    } else if (n == 3 and std.mem.eql(u8, parts[0], "users") and std.mem.eql(u8, parts[2], "identity.json")) {
        const c = obj.get("credentials") orelse return;
        if (c != .object) return;
        const secret = strField(c.object, "secretKey") orelse return;
        const status = strField(c.object, "status") orelse "on";
        st.upsertUser(parts[1], secret, !std.mem.eql(u8, status, "off")) catch |e| return logIam(path, e);
    } else if (n == 3 and std.mem.eql(u8, parts[0], "groups") and std.mem.eql(u8, parts[2], "members.json")) {
        st.createGroup(parts[1]) catch |e| if (e != error.AlreadyExists) return logIam(path, e);
        if (obj.get("members")) |m| if (m == .array) for (m.array.items) |u| if (u == .string) {
            st.addGroupMember(parts[1], u.string) catch |e| logIam(path, e) catch {};
        };
        if (strField(obj, "status")) |stv| st.setGroupEnabled(parts[1], !std.mem.eql(u8, stv, "disabled")) catch {};
    } else if (n == 3 and std.mem.eql(u8, parts[0], "policydb") and (std.mem.eql(u8, parts[1], "users") or std.mem.eql(u8, parts[1], "groups"))) {
        if (!std.mem.endsWith(u8, parts[2], ".json")) return;
        const who = parts[2][0 .. parts[2].len - 5];
        const list = strField(obj, "policy") orelse return;
        var names: std.ArrayList([]const u8) = .empty;
        var pit = std.mem.splitScalar(u8, list, ',');
        while (pit.next()) |p| {
            const t = std.mem.trim(u8, p, " ");
            if (t.len > 0) try names.append(arena, t);
        }
        const target: iam.store.AttachTarget = if (std.mem.eql(u8, parts[1], "users")) .user else .group;
        st.setPolicies(target, who, names.items) catch |e| return logIam(path, e);
    } else if (n == 3 and std.mem.eql(u8, parts[0], "service-accounts") and std.mem.eql(u8, parts[2], "identity.json")) {
        const c = obj.get("credentials") orelse return;
        if (c != .object) return;
        st.createServiceAccount(.{
            .access_key = strField(c.object, "accessKey") orelse parts[1],
            .secret = strField(c.object, "secretKey") orelse return,
            .parent = strField(c.object, "parentUser") orelse return,
            .enabled = !std.mem.eql(u8, strField(c.object, "status") orelse "on", "off"),
            .name = strField(c.object, "name"),
            .description = strField(c.object, "description"),
        }) catch |e| return logIam(path, e);
    } else return;
    s.stats.iam_entities += 1;
}

fn strField(o: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = o.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

fn logIam(path: []const u8, e: iam.store.StoreError) IamError!void {
    if (e == error.OutOfMemory) return error.OutOfMemory;
    std.log.warn("iam {s}: not imported: {t}", .{ path, e });
}

test "multipart etag and versioning state" {
    const e = multipartEtag("d552c71fa8c768bfa0fe1c087a448c75-12").?;
    try std.testing.expectEqual(@as(u32, 12), e.parts);
    try std.testing.expect(multipartEtag("d552c71fa8c768bfa0fe1c087a448c75") == null);
    try std.testing.expect(multipartEtag("zz-1") == null);
    try std.testing.expectEqual(ov.Versioning.enabled, versioningState("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"));
    try std.testing.expectEqual(ov.Versioning.suspended, versioningState("<V><Status>Suspended</Status></V>"));
    try std.testing.expectEqual(ov.Versioning.unset, versioningState(null));
}
