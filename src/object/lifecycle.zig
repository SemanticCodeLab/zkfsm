//! Bucket lifecycle: rule storage and the expiration pass. The pass takes the
//! current time as an argument so tests can run it deterministically.
//! Due times follow S3: creation (or noncurrent) time plus N days, rounded up to midnight UTC.
const std = @import("std");
const core = @import("../core/root.zig");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const versioning = @import("versioning.zig");
const multipart = @import("multipart.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const Record = metadata.ObjectRecord;
pub const Rule = metadata.lifecycle.Rule;
pub const Filter = metadata.lifecycle.Filter;
pub const max_rules = metadata.lifecycle.max_rules;
const day_ns: i128 = std.time.ns_per_day;

/// Rules in `arena`, or null when the bucket has no lifecycle configuration.
pub fn get(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8) Error!?[]Rule {
    const cfg = try versioning.getConfig(svc, arena, bucket);
    if (cfg.lifecycle.len == 0) return null;
    return metadata.lifecycle.decode(arena, cfg.lifecycle) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Corrupt => error.Corrupt,
    };
}

/// Replaces the configuration; null deletes it. Invalid rule sets are InvalidRequest.
pub fn set(svc: *Svc, bucket: []const u8, rules: ?[]const Rule) Error!void {
    var enc: []u8 = &.{};
    defer svc.gpa.free(enc);
    if (rules) |rs| {
        try validate(rs);
        enc = metadata.lifecycle.encode(svc.gpa, rs) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidRule => error.InvalidRequest,
        };
    }
    try versioning.updateConfig(svc, bucket, @as([]const u8, enc), struct {
        fn f(x: []const u8, c: *versioning.BucketConfig) Error!void {
            c.lifecycle = x;
        }
    }.f);
}

/// Structural rules S3 enforces on PutBucketLifecycleConfiguration.
pub fn validate(rules: []const Rule) error{InvalidRequest}!void {
    if (rules.len == 0 or rules.len > max_rules) return error.InvalidRequest;
    for (rules, 0..) |r, i| {
        if (r.id.len > 0) for (rules[0..i]) |p| if (std.mem.eql(u8, p.id, r.id)) return error.InvalidRequest;
        const any_action = r.expiration_days != null or r.expiration_date_ns != null or r.expired_object_delete_marker or
            r.noncurrent_days != null or r.abort_upload_days != null;
        if (!any_action) return error.InvalidRequest;
        if (r.expiration_days != null and r.expiration_date_ns != null) return error.InvalidRequest;
        if (r.expired_object_delete_marker and (r.expiration_days != null or r.expiration_date_ns != null)) return error.InvalidRequest;
        if (r.expiration_date_ns) |d| if (@mod(d, day_ns) != 0) return error.InvalidRequest;
        inline for (.{ r.expiration_days, r.noncurrent_days, r.abort_upload_days }) |d| if (d) |n| if (n == 0) return error.InvalidRequest;
        if (r.newer_noncurrent_versions) |n| if (r.noncurrent_days == null or n == 0 or n > 100) return error.InvalidRequest;
        const f = r.filter;
        const narrowed = f.tags.len > 0 or f.size_gt != null or f.size_lt != null;
        if (narrowed and (r.abort_upload_days != null or r.expired_object_delete_marker)) return error.InvalidRequest;
        if (f.size_gt != null and f.size_lt != null and f.size_gt.? >= f.size_lt.?) return error.InvalidRequest;
    }
}

pub const Stats = struct {
    expired: usize = 0,
    noncurrent_expired: usize = 0,
    markers_removed: usize = 0,
    uploads_aborted: usize = 0,
    /// Actions skipped because retention or a legal hold protects the version.
    locked: usize = 0,
};

/// Applies every bucket's rules as of `now_ns`. Failures on one bucket do not stop the others.
pub fn runOnce(svc: *Svc, now_ns: i128) Error!Stats {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    var st: Stats = .{};
    for (try svc.listBuckets(arena.allocator())) |b| {
        var ba = std.heap.ArenaAllocator.init(svc.gpa);
        defer ba.deinit();
        runBucket(svc, ba.allocator(), b.name, now_ns, &st) catch |e| switch (e) {
            error.NoSuchBucket => {},
            else => std.log.warn("lifecycle: bucket {s}: {t}", .{ b.name, e }),
        };
    }
    return st;
}

const Item = struct { rec: Record, current: bool };

fn newerFirst(_: void, x: Item, y: Item) bool {
    switch (std.mem.order(u8, x.rec.key, y.rec.key)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (x.current != y.current) return x.current;
    if (x.rec.created_ns != y.rec.created_ns) return x.rec.created_ns > y.rec.created_ns;
    return std.mem.order(u8, &x.rec.version.bytes, &y.rec.version.bytes) == .gt;
}

fn runBucket(svc: *Svc, a: std.mem.Allocator, bucket: []const u8, now: i128, st: *Stats) Error!void {
    const rules = try get(svc, a, bucket) orelse return;
    const bid = try svc.bucketId(bucket);
    var items: std.ArrayList(Item) = .empty;
    var it = try svc.scanRecords(a);
    while (try it.next(svc, bid)) |rec| {
        for (rules) |r| {
            if (r.enabled and std.mem.startsWith(u8, rec.key, r.filter.prefix)) break;
        } else continue;
        try items.append(a, .{ .rec = rec, .current = versioning.isCurrentSlot(it.lastKey(), bid, rec.key) });
    }
    std.mem.sort(Item, items.items, {}, newerFirst);
    var i: usize = 0;
    while (i < items.items.len) {
        var j = i + 1;
        while (j < items.items.len and std.mem.eql(u8, items.items[j].rec.key, items.items[i].rec.key)) j += 1;
        try applyKey(svc, a, bucket, rules, items.items[i..j], now, st);
        i = j;
    }
    try abortUploads(svc, a, bucket, rules, now, st);
}

/// `versions` holds one key's versions, current first, then newest to oldest.
fn applyKey(svc: *Svc, a: std.mem.Allocator, bucket: []const u8, rules: []const Rule, versions: []const Item, now: i128, st: *Stats) Error!void {
    const key = versions[0].rec.key;
    const cur: ?Record = if (versions[0].current) versions[0].rec else null;
    const older = if (cur != null) versions[1..] else versions;
    if (cur) |c| if (!c.flags.delete_marker) {
        for (rules) |r| {
            if (!r.enabled or !try matches(a, r.filter, c)) continue;
            const due = if (r.expiration_days) |d| dueAt(c.created_ns, d) <= now else if (r.expiration_date_ns) |d| d <= now else false;
            if (!due) continue;
            if (try act(svc, bucket, key, null, st)) st.expired += 1;
            break;
        }
    } else if (older.len == 0) {
        for (rules) |r| {
            if (!r.enabled or !r.expired_object_delete_marker or !try matches(a, r.filter, c)) continue;
            if (try act(svc, bucket, key, c.versionId(), st)) st.markers_removed += 1;
            break;
        }
    };
    var successor_ns: i128 = if (cur) |c| c.created_ns else now;
    var prev: ?core.VersionId = null;
    var index: u32 = 0;
    for (older) |o| {
        // A crash between demote and overwrite can leave a duplicate; skip it.
        if (prev) |p| if (p.eql(o.rec.versionId())) continue;
        prev = o.rec.versionId();
        defer {
            successor_ns = o.rec.created_ns;
            index += 1;
        }
        for (rules) |r| {
            const days = r.noncurrent_days orelse continue;
            if (!r.enabled or index < (r.newer_noncurrent_versions orelse 0)) continue;
            if (dueAt(successor_ns, days) > now or !try matches(a, r.filter, o.rec)) continue;
            if (try act(svc, bucket, key, o.rec.versionId(), st)) st.noncurrent_expired += 1;
            break;
        }
    }
}

/// Deletes (or, when `version` is null, expires the current version of) `key`.
/// Returns false when object lock protects it.
fn act(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, st: *Stats) Error!bool {
    _ = versioning.deleteObject(svc, bucket, key, .{ .version = version }) catch |e| switch (e) {
        error.ObjectLocked => {
            st.locked += 1;
            return false;
        },
        error.NoSuchKey, error.NoSuchVersion => return false,
        else => return e,
    };
    return true;
}

fn abortUploads(svc: *Svc, a: std.mem.Allocator, bucket: []const u8, rules: []const Rule, now: i128, st: *Stats) Error!void {
    for (rules) |r| {
        const days = r.abort_upload_days orelse continue;
        if (!r.enabled) continue;
        const ups = multipart.listUploads(svc, a, bucket, r.filter.prefix) catch |e| return mapMp(e);
        for (ups) |u| {
            if (dueAt(u.created_ns, days) > now) continue;
            multipart.abort(svc, bucket, u.key, u.upload_id) catch |e| switch (e) {
                error.NoSuchUpload => continue,
                else => return mapMp(e),
            };
            st.uploads_aborted += 1;
        }
    }
}

fn mapMp(e: multipart.Error) Error {
    return switch (e) {
        error.NoSuchUpload, error.InvalidPart, error.InvalidPartOrder, error.EntityTooSmall, error.InvalidPartNumber, error.InvalidRange => error.StorageFailed,
        else => |x| x,
    };
}

/// `start + days`, rounded up to the next midnight UTC.
pub fn dueAt(start_ns: i128, days: u32) i128 {
    const t = start_ns + @as(i128, days) * day_ns;
    return @divFloor(t + day_ns - 1, day_ns) * day_ns;
}

fn matches(a: std.mem.Allocator, f: Filter, r: Record) Error!bool {
    if (!std.mem.startsWith(u8, r.key, f.prefix)) return false;
    if (r.flags.delete_marker) return f.tags.len == 0 and f.size_gt == null and f.size_lt == null;
    const size = r.reportedSize();
    if (f.size_gt) |n| if (size <= n) return false;
    if (f.size_lt) |n| if (size >= n) return false;
    if (f.tags.len == 0) return true;
    const have = metadata.tags.decode(a, r.tags) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else false;
    for (f.tags) |want| {
        for (have) |h| {
            if (std.mem.eql(u8, h.key, want.key) and std.mem.eql(u8, h.value, want.value)) break;
        } else return false;
    }
    return true;
}

// ---- tests ----

const backend = @import("../backend/root.zig");

const Env = struct {
    tmp: std.testing.TmpDir,
    lb: backend.local.LocalBackend,
    svc: Svc,
    arena: std.heap.ArenaAllocator,

    fn init(self: *Env) !void {
        self.tmp = std.testing.tmpDir(.{});
        var pbuf: [std.fs.max_path_bytes]u8 = undefined;
        self.lb = try backend.local.LocalBackend.open(try self.tmp.dir.realpath(".", &pbuf));
        self.svc = try Svc.init(std.testing.allocator, self.lb.backend());
        self.arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        try self.svc.createBucket("lcb");
    }

    fn deinit(self: *Env) void {
        self.arena.deinit();
        self.svc.deinit();
        self.lb.close();
        self.tmp.cleanup();
    }

    fn put(self: *Env, key: []const u8, data: []const u8, in: service.PutInput) !service.ObjectInfo {
        var r: std.Io.Reader = .fixed(data);
        return self.svc.put("lcb", key, &r, in);
    }

    fn versions(self: *Env) !usize {
        return (try versioning.listVersions(&self.svc, self.arena.allocator(), "lcb", .{})).entries.len;
    }
};

test "due time rounds up to midnight" {
    try std.testing.expectEqual(2 * day_ns, dueAt(1, 1));
    try std.testing.expectEqual(day_ns, dueAt(0, 1));
    try std.testing.expectEqual(3 * day_ns, dueAt(day_ns + 5, 1));
}

test "validate rejects malformed rule sets" {
    try validate(&.{.{ .expiration_days = 1 }});
    try std.testing.expectError(error.InvalidRequest, validate(&.{}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{}}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .expiration_days = 0 }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .expiration_days = 1, .expiration_date_ns = 0 }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .expiration_date_ns = 5 }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .expiration_days = 1, .expired_object_delete_marker = true }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .noncurrent_days = 1, .newer_noncurrent_versions = 101 }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .abort_upload_days = 1, .filter = .{ .size_gt = 1 } }}));
    try std.testing.expectError(error.InvalidRequest, validate(&.{ .{ .id = "a", .expiration_days = 1 }, .{ .id = "a", .expiration_days = 2 } }));
    try std.testing.expectError(error.InvalidRequest, validate(&.{.{ .expiration_days = 1, .filter = .{ .size_gt = 5, .size_lt = 5 } }}));
}

test "expiration on an unversioned bucket honors filters" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    const svc = &env.svc;
    const a = env.arena.allocator();
    const tags = try versioning.encodeObjectTags(a, &.{.{ .key = "t", .value = "1" }});
    const old = try env.put("logs/a", "aaaa", .{ .tags = tags });
    _ = try env.put("logs/b", "bb", .{});
    _ = try env.put("keep/c", "cccc", .{ .tags = tags });
    try set(svc, "lcb", &.{
        .{ .id = "logs", .filter = .{ .prefix = "logs/", .tags = &.{.{ .key = "t", .value = "1" }} }, .expiration_days = 2 },
        .{ .id = "big", .filter = .{ .size_gt = 3 }, .expiration_days = 30, .enabled = false },
    });
    try std.testing.expectEqual(@as(usize, 2), (try get(svc, a, "lcb")).?.len);

    const t0 = old.created_ns;
    try std.testing.expectEqual(@as(usize, 0), (try runOnce(svc, t0 + day_ns)).expired);
    const s = try runOnce(svc, dueAt(t0, 2));
    try std.testing.expectEqual(@as(usize, 1), s.expired);
    try std.testing.expectError(error.NoSuchKey, svc.head(a, "lcb", "logs/a"));
    _ = try svc.head(a, "lcb", "logs/b");
    _ = try svc.head(a, "lcb", "keep/c");
    try set(svc, "lcb", null);
    try std.testing.expect((try get(svc, a, "lcb")) == null);
}

test "versioned expiration adds a marker; noncurrent and marker cleanup" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    const svc = &env.svc;
    const a = env.arena.allocator();
    try versioning.setVersioning(svc, "lcb", .enabled);
    const v1 = try env.put("k", "1", .{});
    _ = try env.put("k", "2", .{});
    _ = try env.put("k", "3", .{});
    const t0 = v1.created_ns;
    try set(svc, "lcb", &.{.{ .expiration_days = 1, .noncurrent_days = 1, .newer_noncurrent_versions = 1 }});

    // Day 1: current expires to a marker; of the noncurrent versions the newest one is kept.
    const s = try runOnce(svc, dueAt(t0, 1));
    try std.testing.expectEqual(@as(usize, 1), s.expired);
    try std.testing.expectEqual(@as(usize, 1), s.noncurrent_expired);
    try std.testing.expect((try versioning.headVersion(svc, a, "lcb", "k", null)).delete_marker);
    try std.testing.expectEqual(@as(usize, 3), try env.versions()); // marker, "3", "2"

    // Much later, with NewerNoncurrentVersions=1 the newest noncurrent ("3") survives.
    const later = dueAt(t0, 30);
    _ = try runOnce(svc, later);
    try std.testing.expectEqual(@as(usize, 2), try env.versions());

    // A marker with no versions behind it goes away with ExpiredObjectDeleteMarker.
    try set(svc, "lcb", &.{ .{ .id = "nc", .noncurrent_days = 1 }, .{ .id = "dm", .expired_object_delete_marker = true } });
    const s2 = try runOnce(svc, later);
    try std.testing.expectEqual(@as(usize, 1), s2.noncurrent_expired);
    try std.testing.expectEqual(@as(usize, 0), s2.markers_removed); // still had a version behind it this pass
    const s3 = try runOnce(svc, later);
    try std.testing.expectEqual(@as(usize, 1), s3.markers_removed);
    try std.testing.expectEqual(@as(usize, 0), try env.versions());
}

test "object lock blocks lifecycle deletion of protected versions" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    const svc = &env.svc;
    try versioning.createLockedBucket(svc, "locked");
    var r: std.Io.Reader = .fixed("x");
    const far = core.time.nowNs() + 1000 * day_ns;
    const v = try svc.put("locked", "k", &r, .{ .retention = .{ .mode = .compliance, .until_ns = far } });
    try set(svc, "locked", &.{.{ .expiration_days = 1, .noncurrent_days = 1 }});
    const s = try runOnce(svc, dueAt(v.created_ns, 5));
    try std.testing.expectEqual(@as(usize, 1), s.expired); // marker on top is allowed
    const s2 = try runOnce(svc, dueAt(v.created_ns, 10));
    try std.testing.expectEqual(@as(usize, 0), s2.noncurrent_expired);
    try std.testing.expectEqual(@as(usize, 1), s2.locked);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    _ = try versioning.headVersion(svc, arena.allocator(), "locked", "k", v.version_id);
}

test "abort incomplete multipart uploads" {
    var env: Env = undefined;
    try env.init();
    defer env.deinit();
    const svc = &env.svc;
    const id = try multipart.create(svc, "lcb", "tmp/big", .{});
    _ = try multipart.create(svc, "lcb", "other", .{});
    try set(svc, "lcb", &.{.{ .filter = .{ .prefix = "tmp/" }, .abort_upload_days = 1 }});
    const now = core.time.nowNs();
    try std.testing.expectEqual(@as(usize, 0), (try runOnce(svc, now)).uploads_aborted);
    try std.testing.expectEqual(@as(usize, 1), (try runOnce(svc, now + 3 * day_ns)).uploads_aborted);
    try std.testing.expectError(error.NoSuchUpload, multipart.abort(svc, "lcb", "tmp/big", id));
    try std.testing.expectEqual(@as(usize, 1), (try multipart.listUploads(svc, env.arena.allocator(), "lcb", "")).len);
}
