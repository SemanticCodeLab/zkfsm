//! Versioning: version ids, null versions, delete markers, version lookup and listing,
//! plus per-version retention, legal hold, and tags. The current version of a name lives
//! in its name record; noncurrent versions live in per-version records.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const lock = @import("lock.zig");
const conditional = @import("conditional.zig");
const quota = @import("quota.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const Record = metadata.ObjectRecord;
pub const BucketConfig = metadata.BucketConfig;
pub const Versioning = metadata.bucket_config.Versioning;
pub const Tag = metadata.tags.Tag;
pub const null_version_id = metadata.record.null_version_id;

/// `null` for the null version, else 32 lowercase hex chars.
pub fn formatVersionId(v: core.VersionId, buf: *[32]u8) []const u8 {
    if (v.eql(null_version_id)) return "null";
    buf.* = v.toHex();
    return buf;
}

pub fn parseVersionId(s: []const u8) error{InvalidVersionId}!core.VersionId {
    if (std.mem.eql(u8, s, "null")) return null_version_id;
    const v = core.VersionId.parseHex(s) catch return error.InvalidVersionId;
    if (v.eql(null_version_id)) return error.InvalidVersionId;
    return v;
}

fn currentKey(bid: core.BucketId, key: []const u8) backend.PhysicalKey {
    return placement.recordKey(core.ids.nameId(bid, key));
}

fn slotKey(bid: core.BucketId, key: []const u8, v: core.VersionId) backend.PhysicalKey {
    return placement.versionRecordKey(core.ids.versionNameId(bid, key, v));
}

pub fn isCurrentSlot(pk: backend.PhysicalKey, bid: core.BucketId, key: []const u8) bool {
    return std.mem.eql(u8, &pk.hex, &currentKey(bid, key).hex);
}

/// Loads and checks a record; the returned strings live in `arena`.
fn loadAt(svc: *Svc, arena: std.mem.Allocator, pk: backend.PhysicalKey, bid: core.BucketId, key: []const u8) Error!?Record {
    const bytes = svc.store.getRecord(pk, arena) catch |e| return switch (e) {
        error.NotFound => null,
        else => service.mapBackend(e),
    };
    const rec = metadata.record.decode(bytes) catch return error.Corrupt;
    if (!rec.bucket_id.eql(bid) or !std.mem.eql(u8, rec.key, key)) return null;
    return rec;
}

/// Writes a record and mirrors it in the key index. Caller holds the mutex.
fn store(svc: *Svc, pk: backend.PhysicalKey, rec: Record) Error!void {
    const bytes = metadata.record.encode(rec, svc.gpa) catch |e| return switch (e) {
        error.KeyTooLong => error.KeyTooLong,
        error.MetadataTooLarge => error.MetadataTooLarge,
        else => error.OutOfMemory,
    };
    defer svc.gpa.free(bytes);
    try svc.beginIndexChange();
    const version = if (isCurrentSlot(pk, rec.bucket_id, rec.key)) null else rec.versionId();
    defer svc.emit(.{ .record = .{ .pk = pk, .bid = rec.bucket_id, .key = rec.key, .version = version } });
    svc.store.putRecord(pk, bytes) catch |e| {
        svc.indexResync(pk, rec.bucket_id, rec.key, version);
        return service.mapBackend(e);
    };
    svc.indexStored(pk, rec);
}

/// Deletes the current record (`version` null) or one noncurrent version record.
fn dropRecord(svc: *Svc, bid: core.BucketId, key: []const u8, version: ?core.VersionId) Error!void {
    const pk = if (version) |v| slotKey(bid, key, v) else currentKey(bid, key);
    try svc.beginIndexChange();
    defer svc.emit(.{ .record = .{ .pk = pk, .bid = bid, .key = key, .version = version } });
    svc.store.deleteRecord(pk) catch |e| switch (e) {
        error.NotFound => {},
        else => {
            svc.indexResync(pk, bid, key, version);
            return service.mapBackend(e);
        },
    };
    if (version) |v| svc.index.removeNoncurrent(bid, key, v) else svc.index.setCurrent(bid, key, null);
}

fn retentionOf(r: Record) lock.Retention {
    return .{ .mode = r.retention_mode, .until_ns = r.retain_until_ns };
}

fn checkRemovable(r: Record, bypass: bool) Error!void {
    lock.checkDelete(retentionOf(r), r.flags.legal_hold, bypass, core.time.nowNs()) catch return error.ObjectLocked;
}

/// Data blobs that became unreachable; deleted by the caller after the lock is released.
pub const Garbage = struct {
    ids: [2]?core.ObjectId = .{ null, null },

    fn add(g: *Garbage, r: Record) void {
        if (r.flags.delete_marker) return;
        for (&g.ids) |*s| if (s.* == null) {
            s.* = r.object_id;
            return;
        };
    }

    pub fn collect(g: Garbage, svc: *Svc) void {
        for (g.ids) |id| if (id) |o| svc.store.delete(placement.dataKey(o)) catch {};
    }
};

// ---- bucket configuration ----

/// Caller holds the mutex. Tag bytes borrow from `arena`.
fn loadConfigLocked(svc: *Svc, arena: std.mem.Allocator, bid: core.BucketId) Error!BucketConfig {
    const bytes = svc.store.getRecord(placement.bucketConfigKey(bid), arena) catch |e| return switch (e) {
        error.NotFound => .{},
        else => service.mapBackend(e),
    };
    return metadata.bucket_config.decode(bytes) catch error.Corrupt;
}

fn storeConfigLocked(svc: *Svc, bid: core.BucketId, cfg: BucketConfig) Error!void {
    const bytes = metadata.bucket_config.encode(cfg, svc.gpa) catch |e| return switch (e) {
        error.InvalidTag => error.InvalidTag,
        error.OutOfMemory => error.OutOfMemory,
    };
    defer svc.gpa.free(bytes);
    svc.store.putRecord(placement.bucketConfigKey(bid), bytes) catch |e| return service.mapBackend(e);
}

pub fn getConfig(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error!BucketConfig {
    const bid = try svc.bucketId(bucket);
    svc.mutex.lock();
    defer svc.mutex.unlock();
    return loadConfigLocked(svc, arena, bid);
}

pub fn updateConfig(svc: *Svc, bucket: []const u8, ctx: anytype, comptime f: fn (@TypeOf(ctx), *BucketConfig) Error!void) Error!void {
    const bid = try svc.bucketId(bucket);
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const held = try svc.clusterLock("config", bucket, "");
    defer svc.clusterUnlock(held);
    svc.mutex.lock();
    defer svc.mutex.unlock();
    var cfg = try loadConfigLocked(svc, arena.allocator(), bid);
    try f(ctx, &cfg);
    try storeConfigLocked(svc, bid, cfg);
}

/// Creates a bucket with Object Lock enabled (which also enables versioning).
pub fn createLockedBucket(svc: *Svc, name: []const u8) Error!void {
    try svc.createBucket(name);
    updateConfig(svc, name, {}, struct {
        fn f(_: void, c: *BucketConfig) Error!void {
            c.versioning = .enabled;
            c.lock_enabled = true;
        }
    }.f) catch |e| {
        svc.deleteBucket(name) catch {};
        return e;
    };
}

/// Buckets cannot return to unset; lock-enabled buckets cannot be suspended.
pub fn setVersioning(svc: *Svc, bucket: []const u8, state: Versioning) Error!void {
    if (state == .unset) return error.InvalidRequest;
    try updateConfig(svc, bucket, state, struct {
        fn f(s: Versioning, c: *BucketConfig) Error!void {
            if (c.lock_enabled and s != .enabled) return error.InvalidBucketState;
            c.versioning = s;
        }
    }.f);
}

pub const LockDefault = struct { mode: lock.Mode = .none, days: u32 = 0, years: u32 = 0 };

pub fn setLockConfig(svc: *Svc, bucket: []const u8, d: LockDefault) Error!void {
    if (d.mode != .none and ((d.days == 0) == (d.years == 0))) return error.InvalidRequest;
    try updateConfig(svc, bucket, d, struct {
        fn f(x: LockDefault, c: *BucketConfig) Error!void {
            if (!c.lock_enabled) return error.InvalidBucketState;
            c.default_mode = x.mode;
            c.default_days = x.days;
            c.default_years = x.years;
        }
    }.f);
}

/// `tags` null removes the bucket tag set.
pub fn setBucketTags(svc: *Svc, bucket: []const u8, tags: ?[]const Tag) Error!void {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    var enc: []const u8 = "";
    if (tags) |t| enc = metadata.tags.encode(arena.allocator(), t) catch |e| return switch (e) {
        error.InvalidTag => error.InvalidTag,
        error.OutOfMemory => error.OutOfMemory,
    };
    const Upd = struct { enc: []const u8, set: bool };
    try updateConfig(svc, bucket, Upd{ .enc = enc, .set = tags != null }, struct {
        fn f(u: Upd, c: *BucketConfig) Error!void {
            c.tags = u.enc;
            c.has_tags = u.set;
        }
    }.f);
}

pub fn getBucketTags(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error![]Tag {
    const cfg = try getConfig(svc, arena, bucket);
    if (!cfg.has_tags) return error.NoSuchTagSet;
    return metadata.tags.decode(arena, cfg.tags) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Corrupt => error.Corrupt,
    };
}

pub fn encodeObjectTags(arena: std.mem.Allocator, tags: []const Tag) Error![]const u8 {
    metadata.tags.validate(tags, 10) catch return error.InvalidTag;
    return metadata.tags.encode(arena, tags) catch |e| switch (e) {
        error.InvalidTag => error.InvalidTag,
        error.OutOfMemory => error.OutOfMemory,
    };
}

// ---- writes ----

/// Commits `rec` (data blob already written) as the new current version of its name.
/// Assigns the version id and lock fields; returns blobs that became unreachable.
pub fn commitPut(svc: *Svc, bucket: []const u8, rec: *Record, in: service.PutInput) Error!Garbage {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var g: Garbage = .{};
    const held = try svc.clusterLock("obj", bucket, rec.key);
    defer svc.clusterUnlock(held);
    svc.mutex.lock();
    defer svc.mutex.unlock();
    const b = svc.catalog.find(bucket) orelse return error.NoSuchBucket;
    const bid = b.id;
    const cfg = try loadConfigLocked(svc, a, bid);

    if (in.retention != null or in.legal_hold) {
        if (!cfg.lock_enabled) return error.InvalidRequest;
    }
    const ret = in.retention orelse lock.defaultRetention(cfg, rec.created_ns);
    rec.retention_mode = ret.mode;
    rec.retain_until_ns = ret.until_ns;
    rec.flags.legal_hold = in.legal_hold;

    const ck = currentKey(bid, rec.key);
    const cur = try loadAt(svc, a, ck, bid, rec.key);
    var etag_buf: [core.ETag.quoted_max]u8 = undefined;
    const live_etag: ?[]const u8 = if (cur) |c| (if (c.flags.delete_marker) null else c.reportedEtag().quoted(&etag_buf)) else null;
    conditional.evalWrite(in.conditions, live_etag) catch |e| return e;
    const freed: u64 = if (cfg.versioning == .unset) if (cur) |c| (if (c.flags.delete_marker) 0 else c.reportedSize()) else 0 else 0;
    try quota.check(svc, bid, cfg, rec.reportedSize(), freed);

    switch (cfg.versioning) {
        .unset => {
            rec.flags.null_version = true;
            if (cur) |c| {
                try checkRemovable(c, false);
                g.add(c);
            }
        },
        .enabled => {
            rec.version = core.ids.newVersionId(rec.created_ns);
            if (cur) |c| try store(svc, slotKey(bid, c.key, c.versionId()), c);
        },
        .suspended => {
            rec.flags.null_version = true;
            try replaceNull(svc, a, bid, rec.key, cur, &g);
        },
    }
    try store(svc, ck, rec.*);
    return g;
}

/// Suspended-mode write: the existing null version is replaced, a versioned current is demoted.
fn replaceNull(svc: *Svc, a: std.mem.Allocator, bid: core.BucketId, key: []const u8, cur: ?Record, g: *Garbage) Error!void {
    const nk = slotKey(bid, key, null_version_id);
    const old_null = try loadAt(svc, a, nk, bid, key);
    if (old_null) |n| try checkRemovable(n, false);
    if (cur) |c| {
        if (c.flags.null_version) {
            try checkRemovable(c, false);
            g.add(c);
        } else try store(svc, slotKey(bid, key, c.versionId()), c);
    }
    if (old_null) |n| {
        try dropRecord(svc, bid, key, null_version_id);
        g.add(n);
    }
}

pub const DeleteOptions = struct {
    version: ?core.VersionId = null,
    bypass_governance: bool = false,
    /// Only act if the current version was created at this time (lifecycle's
    /// guard against an object replaced since it was scanned).
    if_created_ns: ?i128 = null,
};

pub const DeleteResult = struct {
    version: ?core.VersionId = null,
    delete_marker: bool = false,
};

pub fn deleteObject(svc: *Svc, bucket: []const u8, key: []const u8, opts: DeleteOptions) Error!DeleteResult {
    try service.validKey(key);
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    var g: Garbage = .{};
    const held = try svc.clusterLock("obj", bucket, key);
    defer svc.clusterUnlock(held);
    const r = blk: {
        svc.mutex.lock();
        defer svc.mutex.unlock();
        break :blk try deleteLocked(svc, arena.allocator(), bucket, key, opts, &g);
    };
    g.collect(svc);
    return r;
}

fn deleteLocked(svc: *Svc, a: std.mem.Allocator, bucket: []const u8, key: []const u8, opts: DeleteOptions, g: *Garbage) Error!DeleteResult {
    const bid = (svc.catalog.find(bucket) orelse return error.NoSuchBucket).id;
    const ck = currentKey(bid, key);
    const cur = try loadAt(svc, a, ck, bid, key);
    if (opts.if_created_ns) |t| if (cur == null or cur.?.created_ns != t) return error.PreconditionFailed;
    if (opts.version) |v| return deleteVersion(svc, a, bid, key, cur, v, opts.bypass_governance, g);

    const cfg = try loadConfigLocked(svc, a, bid);
    const now = core.time.nowNs();
    var marker: Record = .{
        .object_id = core.ObjectId.random(),
        .bucket_id = bid,
        .version = core.ids.newVersionId(now),
        .size = 0,
        .etag = .{ .md5 = [_]u8{0} ** 16 },
        .checksum = .{},
        .created_ns = now,
        .key = key,
        .flags = .{ .delete_marker = true },
    };
    switch (cfg.versioning) {
        .unset => {
            const c = cur orelse return .{};
            try checkRemovable(c, opts.bypass_governance);
            try dropRecord(svc, bid, key, null);
            g.add(c);
            return .{};
        },
        .enabled => if (cur) |c| try store(svc, slotKey(bid, key, c.versionId()), c),
        .suspended => {
            marker.flags.null_version = true;
            try replaceNull(svc, a, bid, key, cur, g);
        },
    }
    try store(svc, ck, marker);
    return .{ .version = marker.versionId(), .delete_marker = true };
}

fn deleteVersion(svc: *Svc, a: std.mem.Allocator, bid: core.BucketId, key: []const u8, cur: ?Record, v: core.VersionId, bypass: bool, g: *Garbage) Error!DeleteResult {
    if (cur) |c| if (c.versionId().eql(v)) {
        try checkRemovable(c, bypass);
        const ck = currentKey(bid, key);
        if (try newestNoncurrent(svc, a, bid, key)) |n| {
            try store(svc, ck, n.rec);
            try dropRecord(svc, bid, key, n.rec.versionId());
        } else try dropRecord(svc, bid, key, null);
        g.add(c);
        return .{ .version = v, .delete_marker = c.flags.delete_marker };
    };
    const sk = slotKey(bid, key, v);
    const old = try loadAt(svc, a, sk, bid, key) orelse return .{ .version = v };
    try checkRemovable(old, bypass);
    try dropRecord(svc, bid, key, v);
    g.add(old);
    return .{ .version = v, .delete_marker = old.flags.delete_marker };
}

const Located = struct { rec: Record, pk: backend.PhysicalKey };

/// From the key index; entries whose record has vanished are dropped and skipped.
fn newestNoncurrent(svc: *Svc, a: std.mem.Allocator, bid: core.BucketId, key: []const u8) Error!?Located {
    if (svc.index.stale) try svc.beginIndexChange();
    while (svc.index.newestNoncurrent(bid, key)) |v| {
        const pk = slotKey(bid, key, v.id);
        if (try loadAt(svc, a, pk, bid, key)) |rec| return .{ .rec = rec, .pk = pk };
        svc.index.removeNoncurrent(bid, key, v.id);
    }
    return null;
}

// ---- reads and per-version updates ----

/// Finds a version (current if `version` is null); caller holds the mutex.
fn locate(svc: *Svc, a: std.mem.Allocator, bid: core.BucketId, key: []const u8, version: ?core.VersionId) Error!Located {
    const ck = currentKey(bid, key);
    const cur = try loadAt(svc, a, ck, bid, key);
    const v = version orelse {
        const c = cur orelse return error.NoSuchKey;
        return .{ .rec = c, .pk = ck };
    };
    if (cur) |c| if (c.versionId().eql(v)) return .{ .rec = c, .pk = ck };
    const sk = slotKey(bid, key, v);
    const r = try loadAt(svc, a, sk, bid, key) orelse return error.NoSuchVersion;
    return .{ .rec = r, .pk = sk };
}

/// Like head, but returns delete markers too (the caller decides how to answer).
pub fn headVersion(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, version: ?core.VersionId) Error!service.ObjectInfo {
    try service.validKey(key);
    const bid = try svc.bucketId(bucket);
    svc.mutex.lock();
    defer svc.mutex.unlock();
    const l = try locate(svc, arena, bid, key, version);
    var info = try service.decodeInfo(arena, l.rec);
    info.is_latest = isCurrentSlot(l.pk, bid, key);
    return info;
}

fn mutate(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, ctx: anytype, comptime f: fn (@TypeOf(ctx), BucketConfig, *Record) Error!void) Error!core.VersionId {
    try service.validKey(key);
    const bid = try svc.bucketId(bucket);
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const held = try svc.clusterLock("obj", bucket, key);
    defer svc.clusterUnlock(held);
    svc.mutex.lock();
    defer svc.mutex.unlock();
    const cfg = try loadConfigLocked(svc, arena.allocator(), bid);
    var l = try locate(svc, arena.allocator(), bid, key, version);
    if (l.rec.flags.delete_marker) return error.MethodNotAllowed;
    try f(ctx, cfg, &l.rec);
    try store(svc, l.pk, l.rec);
    return l.rec.versionId();
}

/// `tags` null deletes the tag set.
pub fn setObjectTags(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, tags: ?[]const Tag) Error!core.VersionId {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const enc = if (tags) |t| try encodeObjectTags(arena.allocator(), t) else "";
    return mutate(svc, bucket, key, version, enc, struct {
        fn f(e: []const u8, _: BucketConfig, r: *Record) Error!void {
            r.tags = e;
        }
    }.f);
}

pub const RetentionInput = struct { retention: lock.Retention, bypass_governance: bool = false };

pub fn setRetention(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, in: RetentionInput) Error!core.VersionId {
    return mutate(svc, bucket, key, version, in, struct {
        fn f(x: RetentionInput, cfg: BucketConfig, r: *Record) Error!void {
            if (!cfg.lock_enabled) return error.InvalidRequest;
            lock.checkChange(retentionOf(r.*), x.retention, x.bypass_governance, core.time.nowNs()) catch return error.ObjectLocked;
            r.retention_mode = x.retention.mode;
            r.retain_until_ns = if (x.retention.mode == .none) 0 else x.retention.until_ns;
        }
    }.f);
}

pub fn setLegalHold(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, on: bool) Error!core.VersionId {
    return mutate(svc, bucket, key, version, on, struct {
        fn f(x: bool, cfg: BucketConfig, r: *Record) Error!void {
            if (!cfg.lock_enabled) return error.InvalidRequest;
            r.flags.legal_hold = x;
        }
    }.f);
}

// ---- ListObjectVersions ----

pub const VersionEntry = struct {
    key: []const u8,
    version: core.VersionId,
    is_latest: bool,
    delete_marker: bool,
    size: u64,
    etag: core.ETag,
    mtime_ns: i128,
};

pub const VersionListParams = struct {
    prefix: []const u8 = "",
    delimiter: []const u8 = "",
    key_marker: []const u8 = "",
    version_id_marker: ?core.VersionId = null,
    max_keys: usize = 1000,
};

pub const VersionListResult = struct {
    entries: []VersionEntry,
    common_prefixes: [][]const u8,
    is_truncated: bool,
    next_key_marker: ?[]const u8,
    next_version_id_marker: ?core.VersionId,
};

pub fn listVersions(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8, p: VersionListParams) Error!VersionListResult {
    const bid = try svc.bucketId(bucket);
    if (svc.index.stale) try svc.rebuildIndex();
    const rows = try svc.index.collectVersions(arena, bid, .{ .prefix = p.prefix, .delimiter = p.delimiter, .key_marker = p.key_marker, .max_keys = p.max_keys });
    const entries = try arena.alloc(VersionEntry, rows.len);
    for (rows, entries) |r, *e| e.* = .{
        .key = r.key,
        .version = r.v.id,
        .is_latest = r.is_latest,
        .delete_marker = r.v.delete_marker,
        .size = r.v.size,
        .etag = r.v.etag,
        .mtime_ns = r.v.mtime_ns,
    };
    return applyVersions(arena, entries, p);
}

fn lessVersion(_: void, x: VersionEntry, y: VersionEntry) bool {
    switch (std.mem.order(u8, x.key, y.key)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (x.is_latest != y.is_latest) return x.is_latest;
    if (x.mtime_ns != y.mtime_ns) return x.mtime_ns > y.mtime_ns;
    return std.mem.order(u8, &x.version.bytes, &y.version.bytes) == .gt;
}

/// Orders by key, then newest first; applies markers, delimiter, and max-keys.
pub fn applyVersions(arena: std.mem.Allocator, entries: []VersionEntry, p: VersionListParams) error{OutOfMemory}!VersionListResult {
    std.mem.sort(VersionEntry, entries, {}, lessVersion);
    var out: std.ArrayList(VersionEntry) = .empty;
    var prefixes: std.ArrayList([]const u8) = .empty;
    var truncated = false;
    var last_key: ?[]const u8 = null;
    var last_ver: ?core.VersionId = null;
    var last_cp: ?[]const u8 = null;
    var seeking = p.version_id_marker != null;
    var prev: ?VersionEntry = null;

    for (entries) |e| {
        // A crash between demote and overwrite can leave a duplicate; keep the first.
        defer prev = e;
        if (prev) |q| if (std.mem.eql(u8, q.key, e.key) and q.version.eql(e.version)) continue;
        if (!std.mem.startsWith(u8, e.key, p.prefix)) continue;
        if (p.key_marker.len > 0) switch (std.mem.order(u8, e.key, p.key_marker)) {
            .lt => continue,
            .eq => if (p.version_id_marker) |vm| {
                if (seeking) {
                    if (e.version.eql(vm)) seeking = false;
                    continue;
                }
            } else continue,
            .gt => {},
        };
        var cp: ?[]const u8 = null;
        if (p.delimiter.len > 0) if (std.mem.indexOf(u8, e.key[p.prefix.len..], p.delimiter)) |i| {
            cp = e.key[0 .. p.prefix.len + i + p.delimiter.len];
        };
        if (cp) |c| {
            if (last_cp != null and std.mem.eql(u8, last_cp.?, c)) continue;
            if (p.key_marker.len > 0 and !std.mem.lessThan(u8, p.key_marker, c)) continue;
        }
        if (out.items.len + prefixes.items.len >= p.max_keys) {
            truncated = true;
            break;
        }
        if (cp) |c| {
            try prefixes.append(arena, c);
            last_cp = c;
            last_key = c;
            last_ver = null;
        } else {
            try out.append(arena, e);
            last_key = e.key;
            last_ver = e.version;
        }
    }
    return .{
        .entries = out.items,
        .common_prefixes = prefixes.items,
        .is_truncated = truncated,
        .next_key_marker = if (truncated) last_key else null,
        .next_version_id_marker = if (truncated) last_ver else null,
    };
}

// ---- tests ----

fn ve(key: []const u8, v: u8, latest: bool, t: i128) VersionEntry {
    return .{
        .key = key,
        .version = .{ .bytes = [_]u8{v} ** 16 },
        .is_latest = latest,
        .delete_marker = false,
        .size = 0,
        .etag = .{ .md5 = [_]u8{0} ** 16 },
        .mtime_ns = t,
    };
}

test "version id format and parse" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("null", formatVersionId(null_version_id, &buf));
    const v = core.ids.newVersionId(42);
    try std.testing.expect((try parseVersionId(formatVersionId(v, &buf))).eql(v));
    try std.testing.expect((try parseVersionId("null")).eql(null_version_id));
    try std.testing.expectError(error.InvalidVersionId, parseVersionId("xyz"));
    try std.testing.expectError(error.InvalidVersionId, parseVersionId(&([_]u8{'0'} ** 32)));
}

test "version listing order and pagination" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var es = [_]VersionEntry{ ve("b", 1, false, 1), ve("a", 2, true, 5), ve("a", 3, false, 3), ve("b", 4, true, 2), ve("a", 3, false, 3) };
    const r = try applyVersions(a, &es, .{ .max_keys = 2 });
    try std.testing.expectEqual(@as(usize, 2), r.entries.len);
    try std.testing.expect(r.entries[0].is_latest and r.entries[0].version.bytes[0] == 2);
    try std.testing.expectEqual(@as(u8, 3), r.entries[1].version.bytes[0]);
    try std.testing.expect(r.is_truncated);
    try std.testing.expectEqualStrings("a", r.next_key_marker.?);

    const r2 = try applyVersions(a, &es, .{ .key_marker = "a", .version_id_marker = r.next_version_id_marker });
    try std.testing.expectEqual(@as(usize, 2), r2.entries.len);
    try std.testing.expectEqualStrings("b", r2.entries[0].key);
    try std.testing.expect(r2.entries[0].is_latest);
    try std.testing.expect(!r2.is_truncated);

    const r3 = try applyVersions(a, &es, .{ .key_marker = "a" });
    try std.testing.expectEqual(@as(usize, 2), r3.entries.len);
    const r4 = try applyVersions(a, &es, .{ .key_marker = "a", .version_id_marker = .{ .bytes = [_]u8{2} ** 16 } });
    try std.testing.expectEqual(@as(usize, 3), r4.entries.len);
}

test "version listing delimiter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var es = [_]VersionEntry{ ve("d/x", 1, true, 1), ve("d/y", 2, true, 1), ve("e", 3, true, 1) };
    const r = try applyVersions(arena.allocator(), &es, .{ .delimiter = "/" });
    try std.testing.expectEqual(@as(usize, 1), r.common_prefixes.len);
    try std.testing.expectEqualStrings("d/", r.common_prefixes[0]);
    try std.testing.expectEqual(@as(usize, 1), r.entries.len);
}

const TestEnv = struct {
    tmp: std.testing.TmpDir,
    lb: backend.local.LocalBackend,
    svc: Svc,
    arena: std.heap.ArenaAllocator,

    fn init(self: *TestEnv) !void {
        self.tmp = std.testing.tmpDir(.{});
        var pbuf: [std.fs.max_path_bytes]u8 = undefined;
        self.lb = try backend.local.LocalBackend.open(try self.tmp.dir.realpath(".", &pbuf));
        self.svc = try Svc.init(std.testing.allocator, self.lb.backend());
        self.arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    }

    fn deinit(self: *TestEnv) void {
        self.arena.deinit();
        self.svc.deinit();
        self.lb.close();
        self.tmp.cleanup();
    }

    fn put(self: *TestEnv, key: []const u8, data: []const u8, in: service.PutInput) !service.ObjectInfo {
        var r: std.Io.Reader = .fixed(data);
        return self.svc.put("bkt", key, &r, in);
    }

    fn body(self: *TestEnv, info: service.ObjectInfo) ![]const u8 {
        var out: std.Io.Writer.Allocating = .init(self.arena.allocator());
        try self.svc.read(info, null, &out.writer);
        return out.written();
    }
};

test "versioned put, get by version, delete marker, and promotion" {
    var env: TestEnv = undefined;
    try env.init();
    defer env.deinit();
    const a = env.arena.allocator();
    const svc = &env.svc;
    try svc.createBucket("bkt");
    const v0 = try env.put("k", "zero", .{});
    try std.testing.expect(v0.version_id.eql(null_version_id));
    try setVersioning(svc, "bkt", .enabled);
    const v1 = try env.put("k", "one", .{});
    const v2 = try env.put("k", "two", .{});
    try std.testing.expect(!v1.version_id.eql(v2.version_id));
    try std.testing.expectEqualStrings("two", try env.body(try svc.head(a, "bkt", "k")));
    try std.testing.expectEqualStrings("one", try env.body(try headVersion(svc, a, "bkt", "k", v1.version_id)));
    try std.testing.expectEqualStrings("zero", try env.body(try headVersion(svc, a, "bkt", "k", null_version_id)));

    const d = try deleteObject(svc, "bkt", "k", .{});
    try std.testing.expect(d.delete_marker);
    try std.testing.expectError(error.NoSuchKey, svc.head(a, "bkt", "k"));
    try std.testing.expect((try headVersion(svc, a, "bkt", "k", null)).delete_marker);
    const l = try svc.list(a, "bkt", .{});
    try std.testing.expectEqual(@as(usize, 0), l.contents.len);
    const lv = try listVersions(svc, a, "bkt", .{});
    try std.testing.expectEqual(@as(usize, 4), lv.entries.len);
    try std.testing.expect(lv.entries[0].delete_marker and lv.entries[0].is_latest);
    try std.testing.expectError(error.BucketNotEmpty, svc.deleteBucket("bkt"));

    // Removing the marker promotes v2 back to current.
    _ = try deleteObject(svc, "bkt", "k", .{ .version = d.version });
    try std.testing.expectEqualStrings("two", try env.body(try svc.head(a, "bkt", "k")));
    _ = try deleteObject(svc, "bkt", "k", .{ .version = v2.version_id });
    try std.testing.expectEqualStrings("one", try env.body(try svc.head(a, "bkt", "k")));
    try std.testing.expectError(error.NoSuchVersion, headVersion(svc, a, "bkt", "k", v2.version_id));
    _ = try deleteObject(svc, "bkt", "k", .{ .version = v1.version_id });
    _ = try deleteObject(svc, "bkt", "k", .{ .version = null_version_id });
    try std.testing.expectError(error.NoSuchKey, svc.head(a, "bkt", "k"));
    try svc.deleteBucket("bkt");
}

test "suspended versioning replaces the null version" {
    var env: TestEnv = undefined;
    try env.init();
    defer env.deinit();
    const a = env.arena.allocator();
    const svc = &env.svc;
    try svc.createBucket("bkt");
    try setVersioning(svc, "bkt", .enabled);
    const v1 = try env.put("k", "one", .{});
    try setVersioning(svc, "bkt", .suspended);
    _ = try env.put("k", "n1", .{});
    _ = try env.put("k", "n2", .{});
    const lv = try listVersions(svc, a, "bkt", .{});
    try std.testing.expectEqual(@as(usize, 2), lv.entries.len);
    try std.testing.expectEqualStrings("n2", try env.body(try svc.head(a, "bkt", "k")));
    try std.testing.expectEqualStrings("one", try env.body(try headVersion(svc, a, "bkt", "k", v1.version_id)));
    const d = try deleteObject(svc, "bkt", "k", .{});
    try std.testing.expect(d.delete_marker and d.version.?.eql(null_version_id));
    try std.testing.expectEqual(@as(usize, 2), (try listVersions(svc, a, "bkt", .{})).entries.len);
}

test "object lock blocks deletes and retention changes" {
    var env: TestEnv = undefined;
    try env.init();
    defer env.deinit();
    const a = env.arena.allocator();
    const svc = &env.svc;
    try svc.createBucket("plain");
    var r0: std.Io.Reader = .fixed("x");
    try std.testing.expectError(error.InvalidRequest, svc.put("plain", "k", &r0, .{ .legal_hold = true }));
    try std.testing.expectError(error.InvalidBucketState, setLockConfig(svc, "plain", .{}));

    try createLockedBucket(svc, "bkt");
    try std.testing.expectError(error.InvalidBucketState, setVersioning(svc, "bkt", .suspended));
    const far = core.time.nowNs() + 3600 * std.time.ns_per_s;
    const g = try env.put("g", "gov", .{ .retention = .{ .mode = .governance, .until_ns = far } });
    try std.testing.expectError(error.ObjectLocked, deleteObject(svc, "bkt", "g", .{ .version = g.version_id }));
    // A plain delete only adds a marker, which is allowed.
    _ = try deleteObject(svc, "bkt", "g", .{});
    try std.testing.expectError(error.ObjectLocked, setRetention(svc, "bkt", "g", g.version_id, .{ .retention = .{} }));
    _ = try deleteObject(svc, "bkt", "g", .{ .version = g.version_id, .bypass_governance = true });

    const c = try env.put("c", "comp", .{ .retention = .{ .mode = .compliance, .until_ns = far } });
    try std.testing.expectError(error.ObjectLocked, deleteObject(svc, "bkt", "c", .{ .version = c.version_id, .bypass_governance = true }));
    _ = try setRetention(svc, "bkt", "c", c.version_id, .{ .retention = .{ .mode = .compliance, .until_ns = far + 1 } });
    try std.testing.expectEqual(far + 1, (try headVersion(svc, a, "bkt", "c", c.version_id)).retain_until_ns);

    const h = try env.put("h", "held", .{ .legal_hold = true });
    try std.testing.expectError(error.ObjectLocked, deleteObject(svc, "bkt", "h", .{ .version = h.version_id }));
    _ = try setLegalHold(svc, "bkt", "h", null, false);
    _ = try deleteObject(svc, "bkt", "h", .{ .version = h.version_id });

    try setLockConfig(svc, "bkt", .{ .mode = .governance, .days = 1 });
    const dflt = try env.put("d", "x", .{});
    try std.testing.expectEqual(lock.Mode.governance, dflt.retention_mode);
}

test "tags and conditional put" {
    var env: TestEnv = undefined;
    try env.init();
    defer env.deinit();
    const a = env.arena.allocator();
    const svc = &env.svc;
    try svc.createBucket("bkt");
    const enc = try encodeObjectTags(a, &.{.{ .key = "k", .value = "v" }});
    const p = try env.put("t", "x", .{ .tags = enc, .conditions = .{ .if_none_match = "*" } });
    try std.testing.expectError(error.PreconditionFailed, env.put("t", "y", .{ .conditions = .{ .if_none_match = "*" } }));
    try std.testing.expectError(error.NoSuchKey, env.put("u", "y", .{ .conditions = .{ .if_match = "\"x\"" } }));
    var qb: [core.ETag.quoted_max]u8 = undefined;
    _ = try env.put("t", "x2", .{ .tags = enc, .conditions = .{ .if_match = p.etag.quoted(&qb) } });
    try std.testing.expectEqualStrings(enc, (try svc.head(a, "bkt", "t")).tags);
    _ = try setObjectTags(svc, "bkt", "t", null, null);
    try std.testing.expectEqualStrings("", (try svc.head(a, "bkt", "t")).tags);
    try std.testing.expectError(error.NoSuchTagSet, getBucketTags(svc, a, "bkt"));
    try setBucketTags(svc, "bkt", &.{.{ .key = "team", .value = "x" }});
    try std.testing.expectEqualStrings("team", (try getBucketTags(svc, a, "bkt"))[0].key);
    try setBucketTags(svc, "bkt", null);
    try std.testing.expectError(error.NoSuchTagSet, getBucketTags(svc, a, "bkt"));
}
