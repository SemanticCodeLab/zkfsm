//! Lifecycle transition of object data to remote tiers, RestoreObject, expiry of
//! restored copies, tier usage stats, and the cleanup journal: remote data of removed
//! versions is deleted by the housekeeping pass, retried until the tier answers.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const versioning = @import("versioning.zig");
const blob = @import("blob.zig");
const tier = @import("tier.zig");
const codec = @import("../metadata/codec.zig");

const Svc = service.ObjectService;
const Error = service.Error;
const Record = metadata.ObjectRecord;
const log = std.log.scoped(.tier);

/// Length of a lifecycle/restore "day"; tests shorten it.
pub var day_len_ns: i128 = std.time.ns_per_day;

/// `start + days`, rounded up to the next day boundary (midnight UTC for real days).
pub fn dueAt(start_ns: i128, days: u32) i128 {
    const d = day_len_ns;
    const t = start_ns + @as(i128, days) * d;
    return @divFloor(t + d - 1, d) * d;
}

// ---- cleanup journal ----

/// Journal entries live in system space under keys starting with "zktj".
const journal_hex_prefix = "7a6b746a";
const journal_magic = "ZKTJ";

fn journalKey(id: [16]u8) backend.PhysicalKey {
    const h = std.fmt.bytesToHex(id, .lower);
    return .{ .space = .system, .hex = (journal_hex_prefix ++ h[0..24]).* };
}

/// Durably notes that blob `id` on `tier_name` is garbage. Never fails the caller:
/// an unwritable journal only leaks remote data.
pub fn enqueueCleanup(svc: *Svc, tier_name: []const u8, id: [16]u8) void {
    var buf: [4 + 1 + metadata.record.max_tier_name + 16 + 16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.writeAll(journal_magic) catch unreachable; // fits by construction
    w.writeByte(@intCast(tier_name.len)) catch unreachable;
    w.writeAll(tier_name) catch unreachable;
    w.writeAll(&id) catch unreachable;
    w.writeInt(i128, core.time.nowNs(), .little) catch unreachable;
    svc.store.putRecord(journalKey(id), w.buffered()) catch |e|
        log.warn("cleanup journal write failed ({t}); remote blob {x} on {s} is orphaned", .{ e, id, tier_name });
}

const JournalEntry = struct { tier: []const u8, id: [16]u8, created_ns: i128 };

fn decodeEntry(bytes: []const u8) ?JournalEntry {
    var c: codec.Cursor = .{ .bytes = bytes };
    const magic = c.take(4) catch return null;
    if (!std.mem.eql(u8, magic, journal_magic)) return null;
    const n = (c.take(1) catch return null)[0];
    const e: JournalEntry = .{
        .tier = c.take(n) catch return null,
        .id = c.fixed(16) catch return null,
        .created_ns = c.int(i128) catch return null,
    };
    return if (c.pos == bytes.len and n > 0) e else null;
}

// ---- transition ----

pub const Outcome = enum { done, skipped, failed };

/// Moves the data of version `rec` of `bucket` to `tier_name`; the record keeps its
/// metadata plus the remote pointer. Losing a race with a writer is `skipped`.
pub fn transition(svc: *Svc, bucket: []const u8, rec: Record, tier_name: []const u8) Error!Outcome {
    if (rec.tier.len > 0 or rec.flags.delete_marker) return .skipped;
    const reg = svc.tiers orelse return .skipped;
    const t = reg.acquire(tier_name) orelse {
        log.warn("transition of {s}/{s}: tier {s} is not configured", .{ bucket, rec.key, tier_name });
        tier.Counters.inc(&reg.counters.transition_failures, 1);
        return .failed;
    };
    defer t.release();
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    const segs = [_]blob.Segment{.{ .blob = rec.object_id, .offset = 0, .length = rec.size }};
    var buf: [64 * 1024]u8 = undefined;
    var br = blob.BlobReader.init(svc.store, &segs, &buf);
    t.put(id, &br.reader, rec.size) catch |e| {
        if (br.err) |be| if (be == error.NotFound) return .skipped; // replaced meanwhile
        log.warn("transition of {s}/{s} to {s} failed: {t}", .{ bucket, rec.key, tier_name, e });
        tier.Counters.inc(&reg.counters.transition_failures, 1);
        return .failed;
    };
    const Ctx = struct { oid: core.ObjectId, tier: []const u8, id: [16]u8 };
    _ = versioning.mutate(svc, bucket, rec.key, rec.versionId(), Ctx{ .oid = rec.object_id, .tier = t.cfg.name, .id = id }, struct {
        fn f(c: Ctx, _: versioning.BucketConfig, r: *Record) Error!void {
            if (!r.object_id.eql(c.oid) or r.tier.len > 0) return error.PreconditionFailed;
            r.tier = c.tier;
            r.tier_object = c.id;
            r.restore_expiry_ns = 0;
        }
    }.f) catch |e| {
        t.delete(id) catch enqueueCleanup(svc, t.cfg.name, id);
        return switch (e) {
            error.PreconditionFailed, error.NoSuchKey, error.NoSuchVersion, error.MethodNotAllowed, error.NoSuchBucket => .skipped,
            else => blk: {
                tier.Counters.inc(&reg.counters.transition_failures, 1);
                log.warn("transition of {s}/{s}: commit failed: {t}", .{ bucket, rec.key, e });
                break :blk .failed;
            },
        };
    };
    svc.store.delete(placement.dataKey(rec.object_id)) catch {};
    tier.Counters.inc(&reg.counters.transitions, 1);
    tier.Counters.inc(&reg.counters.transitioned_bytes, rec.size);
    return .done;
}

// ---- restore ----

pub const RestoreResult = enum {
    /// A local copy was made.
    accepted,
    /// A live copy existed; its expiry was moved.
    extended,
};

/// RestoreObject: copies tiered data back locally for `days`.
pub fn restore(svc: *Svc, bucket: []const u8, key: []const u8, version: ?core.VersionId, days: u32) Error!RestoreResult {
    if (days == 0) return error.InvalidRequest;
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const info = try versioning.headVersion(svc, arena.allocator(), bucket, key, version);
    if (info.delete_marker) return if (version != null) error.MethodNotAllowed else error.NoSuchKey;
    if (info.tier.len == 0) return error.InvalidObjectState;
    const reg = svc.tiers orelse return error.TierUnavailable;
    const now = core.time.nowNs();
    const expiry = dueAt(now, days);
    if (info.restore_expiry_ns > now) {
        try setExpiry(svc, bucket, info, expiry, null);
        return .extended;
    }
    reg.beginRestore(info.object_id.bytes) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.RestoreInProgress => error.RestoreInProgress,
    };
    defer reg.endRestore(info.object_id.bytes);
    const t = reg.acquire(info.tier) orelse return error.TierUnavailable;
    defer t.release();
    const chunk = try svc.gpa.alloc(u8, @intCast(@max(1, @min(tier.chunk_len, info.blob_size))));
    defer svc.gpa.free(chunk);
    var small: [4096]u8 = undefined;
    var rd = tier.Reader.init(t, info.tier_object, 0, info.blob_size, chunk, &small);
    const dk = placement.dataKey(info.object_id);
    const meta = svc.store.put(dk, &rd.interface, .{ .size_hint = info.blob_size }) catch |e| {
        tier.Counters.inc(&reg.counters.restore_failures, 1);
        if (rd.err) |re| return tier.mapRemote(re);
        return service.mapBackend(e);
    };
    var keep = false;
    defer if (!keep) svc.store.delete(dk) catch {};
    if (meta.size != info.blob_size) {
        tier.Counters.inc(&reg.counters.restore_failures, 1);
        return error.StorageFailed;
    }
    try setExpiry(svc, bucket, info, expiry, null);
    keep = true;
    tier.Counters.inc(&reg.counters.restores, 1);
    return .accepted;
}

/// Sets the restore expiry of `info`'s version if it still holds the same data
/// (and, with `only_if`, the same expiry as scanned).
fn setExpiry(svc: *Svc, bucket: []const u8, info: service.ObjectInfo, expiry: i128, only_if: ?i128) Error!void {
    const Ctx = struct { oid: core.ObjectId, expiry: i128, only_if: ?i128 };
    _ = try versioning.mutate(svc, bucket, info.key, info.version_id, Ctx{ .oid = info.object_id, .expiry = expiry, .only_if = only_if }, struct {
        fn f(c: Ctx, _: versioning.BucketConfig, r: *Record) Error!void {
            if (!r.object_id.eql(c.oid) or r.tier.len == 0) return error.PreconditionFailed;
            if (c.only_if) |want| if (r.restore_expiry_ns != want) return error.PreconditionFailed;
            r.restore_expiry_ns = c.expiry;
        }
    }.f);
}

/// The `x-amz-restore` value for `info`, or null when it has no restore state.
pub fn restoreHeader(svc: *Svc, arena: std.mem.Allocator, info: service.ObjectInfo) error{OutOfMemory}!?[]const u8 {
    if (info.tier.len == 0) return null;
    if (svc.tiers) |reg| if (reg.isRestoring(info.object_id.bytes)) return "ongoing-request=\"true\"";
    if (info.restore_expiry_ns == 0) return null;
    var db: [29]u8 = undefined;
    return try std.fmt.allocPrint(arena, "ongoing-request=\"false\", expiry-date=\"{s}\"", .{core.time.httpDate(info.restore_expiry_ns, &db)});
}

// ---- housekeeping ----

pub const HouseStats = struct {
    restores_expired: usize = 0,
    cleaned: usize = 0,
    cleanup_pending: usize = 0,
};

/// One pass: expires restored copies, retries the cleanup journal, refreshes usage stats.
pub fn housekeeping(svc: *Svc, now: i128) Error!HouseStats {
    const reg = svc.tiers orelse return .{};
    var st: HouseStats = .{};
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const Bucket = struct { id: core.BucketId, name: []const u8 };
    var buckets: std.ArrayList(Bucket) = .empty;
    for (try svc.listBuckets(a)) |b| try buckets.append(a, .{ .id = svc.bucketId(b.name) catch continue, .name = b.name });

    var usage: std.StringArrayHashMapUnmanaged(tier.Usage) = .empty;
    var hot: tier.Usage = .{};
    const it = try svc.scanRecords(a);
    var rec_arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer rec_arena.deinit();
    for (it.keys) |pk| {
        _ = rec_arena.reset(.retain_capacity);
        const ra = rec_arena.allocator();
        const bytes = svc.store.getRecord(pk, ra) catch continue;
        const rec = metadata.record.decode(bytes) catch continue;
        if (rec.flags.delete_marker) continue;
        const b = for (buckets.items) |b| {
            if (b.id.eql(rec.bucket_id)) break b;
        } else continue;
        const current = versioning.isCurrentSlot(pk, rec.bucket_id, rec.key);
        const u = if (rec.tier.len == 0) &hot else blk: {
            const gop = try usage.getOrPut(a, rec.tier);
            if (!gop.found_existing) {
                gop.key_ptr.* = try a.dupe(u8, rec.tier);
                gop.value_ptr.* = .{};
            }
            break :blk gop.value_ptr;
        };
        u.versions += 1;
        u.objects += @intFromBool(current);
        u.bytes += rec.size;
        if (rec.tier.len > 0 and rec.restore_expiry_ns != 0 and rec.restore_expiry_ns <= now) {
            if (expireRestore(svc, b.name, rec)) st.restores_expired += 1 else |e| log.warn("restore expiry of {s}/{s}: {t}", .{ b.name, rec.key, e });
        }
    }

    try processJournal(svc, reg, a, now, &st);

    var stats: std.ArrayList(tier.TierStat) = .empty;
    var uit = usage.iterator();
    while (uit.next()) |e| try stats.append(a, .{ .name = e.key_ptr.*, .kind = "", .usage = e.value_ptr.* });
    reg.setStats(hot, stats.items);
    tier.Counters.inc(&reg.counters.restores_expired, st.restores_expired);
    reg.counters.cleanup_pending.store(st.cleanup_pending, .monotonic);
    return st;
}

fn expireRestore(svc: *Svc, bucket: []const u8, rec: Record) Error!void {
    var info = service.infoFrom(rec);
    info.version_id = rec.versionId();
    setExpiry(svc, bucket, info, 0, rec.restore_expiry_ns) catch |e| switch (e) {
        error.PreconditionFailed, error.NoSuchKey, error.NoSuchVersion, error.MethodNotAllowed => return,
        else => return e,
    };
    svc.store.delete(placement.dataKey(rec.object_id)) catch {};
}

fn processJournal(svc: *Svc, reg: *tier.Registry, a: std.mem.Allocator, now: i128, st: *HouseStats) Error!void {
    const Collect = struct {
        a: std.mem.Allocator,
        keys: std.ArrayList(backend.PhysicalKey) = .empty,
        fn f(ctx: *anyopaque, k: backend.PhysicalKey) backend.Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (std.mem.startsWith(u8, &k.hex, journal_hex_prefix)) try c.keys.append(c.a, k);
        }
    };
    var c: Collect = .{ .a = a };
    svc.store.list(.system, .{ .ctx = &c, .func = Collect.f }) catch |e| switch (e) {
        error.NotFound => {},
        else => return service.mapBackend(e),
    };
    for (c.keys.items) |k| {
        const bytes = svc.store.getRecord(k, a) catch continue;
        const e = decodeEntry(bytes) orelse continue;
        const t = reg.acquire(e.tier) orelse {
            // The tier was force-removed; nothing left to retry against.
            if (now - e.created_ns > std.time.ns_per_day) svc.store.deleteRecord(k) catch {};
            st.cleanup_pending += 1;
            continue;
        };
        defer t.release();
        t.delete(e.id) catch |err| {
            tier.Counters.inc(&reg.counters.cleanup_failures, 1);
            log.debug("cleanup of {x} on {s} deferred: {t}", .{ e.id, e.tier, err });
            st.cleanup_pending += 1;
            continue;
        };
        svc.store.deleteRecord(k) catch {};
        st.cleaned += 1;
        tier.Counters.inc(&reg.counters.cleanup_deleted, 1);
    }
}

test "journal entry codec and key" {
    var id: [16]u8 = undefined;
    for (&id, 0..) |*b, i| b.* = @intCast(i);
    const k = journalKey(id);
    try std.testing.expect(std.mem.startsWith(u8, &k.hex, journal_hex_prefix));
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll(journal_magic);
    try w.writeByte(4);
    try w.writeAll("WARM");
    try w.writeAll(&id);
    try w.writeInt(i128, 42, .little);
    const e = decodeEntry(w.buffered()).?;
    try std.testing.expectEqualStrings("WARM", e.tier);
    try std.testing.expectEqual(@as(i128, 42), e.created_ns);
    for (0..w.end) |n| try std.testing.expect(decodeEntry(w.buffered()[0..n]) == null);
}

test "due times follow the configured day length" {
    try std.testing.expectEqual(2 * day_len_ns, dueAt(1, 1));
    try std.testing.expectEqual(day_len_ns, dueAt(0, 1));
}

// ---- end-to-end over an in-memory tier ----

const MemTier = struct {
    gpa: std.mem.Allocator,
    objects: std.StringHashMapUnmanaged([]u8) = .empty,
    down: bool = false,

    fn deinit(m: *MemTier) void {
        var it = m.objects.iterator();
        while (it.next()) |e| {
            m.gpa.free(e.key_ptr.*);
            m.gpa.free(e.value_ptr.*);
        }
        m.objects.deinit(m.gpa);
    }

    fn provider(m: *MemTier) backend.remote.Provider {
        return .{ .ctx = m, .capabilities = .{ .range_read = true }, .vtable = &.{ .put = put, .get = get, .head = head, .delete = delete, .list = list } };
    }

    fn from(ctx: *anyopaque) *MemTier {
        return @ptrCast(@alignCast(ctx));
    }

    fn put(ctx: *anyopaque, n: []const u8, src: *std.Io.Reader, _: backend.remote.PutObjectOptions) backend.remote.PutError!backend.ObjectMeta {
        const m = from(ctx);
        if (m.down) return error.IoFailed;
        const data = src.allocRemaining(m.gpa, .unlimited) catch return error.ReadFailed;
        const gop = m.objects.getOrPut(m.gpa, n) catch return error.OutOfMemory;
        if (gop.found_existing) m.gpa.free(gop.value_ptr.*) else gop.key_ptr.* = m.gpa.dupe(u8, n) catch return error.OutOfMemory;
        gop.value_ptr.* = data;
        return .{ .size = data.len, .mtime_ns = 0 };
    }

    fn get(ctx: *anyopaque, n: []const u8, range: ?core.Range, sink: *std.Io.Writer) backend.Error!backend.ObjectMeta {
        const m = from(ctx);
        if (m.down) return error.IoFailed;
        const d = m.objects.get(n) orelse return error.NotFound;
        const r = range orelse core.Range{ .offset = 0, .length = d.len };
        sink.writeAll(d[r.offset..][0..r.length]) catch return error.WriteFailed;
        return .{ .size = d.len, .mtime_ns = 0 };
    }

    fn head(ctx: *anyopaque, n: []const u8) backend.Error!backend.ObjectMeta {
        const m = from(ctx);
        if (m.down) return error.IoFailed;
        return .{ .size = (m.objects.get(n) orelse return error.NotFound).len, .mtime_ns = 0 };
    }

    fn delete(ctx: *anyopaque, n: []const u8) backend.Error!void {
        const m = from(ctx);
        if (m.down) return error.IoFailed;
        const kv = m.objects.fetchRemove(n) orelse return error.NotFound;
        m.gpa.free(kv.key);
        m.gpa.free(kv.value);
    }

    fn list(ctx: *anyopaque, prefix: []const u8, cb: backend.remote.NameCallback) backend.Error!void {
        var it = from(ctx).objects.keyIterator();
        while (it.next()) |k| if (std.mem.startsWith(u8, k.*, prefix)) try cb.func(cb.ctx, k.*);
    }
};

const lifecycle = @import("lifecycle.zig");

const TierEnv = struct {
    tmp: std.testing.TmpDir,
    lb: backend.local.LocalBackend,
    svc: Svc,
    reg: tier.Registry,
    mem: MemTier,
    arena: std.heap.ArenaAllocator,

    fn init(e: *TierEnv) !void {
        e.tmp = std.testing.tmpDir(.{});
        var pbuf: [std.fs.max_path_bytes]u8 = undefined;
        e.lb = try backend.local.LocalBackend.open(try e.tmp.dir.realpath(".", &pbuf));
        e.svc = try Svc.init(std.testing.allocator, e.lb.backend());
        e.reg = tier.Registry.init(std.testing.allocator, &e.svc, tier.sealKey("root", "rootsecret"));
        e.svc.tiers = &e.reg;
        e.mem = .{ .gpa = std.testing.allocator };
        try e.reg.pin("WARM", e.mem.provider());
        e.arena = .init(std.testing.allocator);
        try e.svc.createBucket("tbk");
    }

    fn deinit(e: *TierEnv) void {
        e.arena.deinit();
        e.reg.deinit();
        e.mem.deinit();
        e.svc.deinit();
        e.lb.close();
        e.tmp.cleanup();
    }

    fn put(e: *TierEnv, key: []const u8, data: []const u8) !service.ObjectInfo {
        var r: std.Io.Reader = .fixed(data);
        return e.svc.put("tbk", key, &r, .{});
    }

    fn body(e: *TierEnv, key: []const u8, version: ?core.VersionId, range: ?core.Range) ![]const u8 {
        const info = try versioning.headVersion(&e.svc, e.arena.allocator(), "tbk", key, version);
        var out: std.Io.Writer.Allocating = .init(e.arena.allocator());
        try e.svc.read(info, range, &out.writer);
        return out.written();
    }

    fn localBlob(e: *TierEnv, oid: core.ObjectId) bool {
        _ = e.svc.store.stat(placement.dataKey(oid)) catch return false;
        return true;
    }
};

test "transition, read-through, restore, outage, and cleanup" {
    var e: TierEnv = undefined;
    try e.init();
    defer e.deinit();
    const svc = &e.svc;
    const a = e.arena.allocator();
    const v = try e.put("k", "hello tiered world");
    try std.testing.expectError(error.InvalidStorageClass, lifecycle.set(svc, "tbk", &.{.{ .transition_days = 1, .transition_tier = "NOPE" }}));
    try lifecycle.set(svc, "tbk", &.{.{ .transition_days = 1, .transition_tier = "WARM" }});

    try std.testing.expectEqual(@as(usize, 0), (try lifecycle.runOnce(svc, v.created_ns)).transitioned);
    // Outage: the transition fails and the object stays local.
    e.mem.down = true;
    const due = dueAt(v.created_ns, 1);
    try std.testing.expectEqual(@as(usize, 1), (try lifecycle.runOnce(svc, due)).transition_failed);
    try std.testing.expect(e.localBlob(v.object_id));
    e.mem.down = false;
    try std.testing.expectEqual(@as(usize, 1), (try lifecycle.runOnce(svc, due)).transitioned);
    const h = try svc.head(a, "tbk", "k");
    try std.testing.expectEqualStrings("WARM", h.tier);
    try std.testing.expect(!e.localBlob(v.object_id));
    try std.testing.expectEqual(@as(u32, 1), e.mem.objects.count());
    try std.testing.expectEqualStrings("hello tiered world", try e.body("k", null, null));
    try std.testing.expectEqualStrings("tiered", try e.body("k", null, .{ .offset = 6, .length = 6 }));
    // Already transitioned: nothing more to do.
    try std.testing.expectEqual(@as(usize, 0), (try lifecycle.runOnce(svc, due)).transitioned);

    e.mem.down = true;
    try std.testing.expectError(error.TierUnavailable, e.body("k", null, null));
    try std.testing.expectError(error.TierUnavailable, restore(svc, "tbk", "k", null, 1));
    e.mem.down = false;

    try std.testing.expectEqual(RestoreResult.accepted, try restore(svc, "tbk", "k", null, 1));
    try std.testing.expect(e.localBlob(v.object_id));
    const r = try svc.head(a, "tbk", "k");
    try std.testing.expect(r.restore_expiry_ns > core.time.nowNs());
    try std.testing.expect((try restoreHeader(svc, a, r)) != null);
    e.mem.down = true; // served from the restored copy
    try std.testing.expectEqualStrings("hello tiered world", try e.body("k", null, null));
    e.mem.down = false;
    try std.testing.expectEqual(RestoreResult.extended, try restore(svc, "tbk", "k", null, 2));
    try std.testing.expectError(error.InvalidObjectState, blk: {
        _ = try e.put("local", "x");
        break :blk restore(svc, "tbk", "local", null, 1);
    });

    // The restored copy expires; data is read from the tier again.
    const hs = try housekeeping(svc, core.time.nowNs() + 10 * day_len_ns);
    try std.testing.expectEqual(@as(usize, 1), hs.restores_expired);
    try std.testing.expect(!e.localBlob(v.object_id));
    try std.testing.expectEqual(@as(i128, 0), (try svc.head(a, "tbk", "k")).restore_expiry_ns);
    try std.testing.expectEqualStrings("hello tiered world", try e.body("k", null, null));
    const view = try e.reg.statsCopy(a);
    try std.testing.expectEqual(@as(u64, 1), view.hot.objects);

    // Overwrite: the remote blob goes through the journal, retried across an outage.
    _ = try e.put("k", "new");
    e.mem.down = true;
    const p1 = try housekeeping(svc, core.time.nowNs());
    try std.testing.expectEqual(@as(usize, 1), p1.cleanup_pending);
    try std.testing.expectEqual(@as(u32, 1), e.mem.objects.count());
    e.mem.down = false;
    const p2 = try housekeeping(svc, core.time.nowNs());
    try std.testing.expectEqual(@as(usize, 1), p2.cleaned);
    try std.testing.expectEqual(@as(u32, 0), e.mem.objects.count());
    try std.testing.expectEqual(@as(usize, 0), (try housekeeping(svc, core.time.nowNs())).cleanup_pending);
}

test "noncurrent transition, copy of tiered data, and version delete cleanup" {
    var e: TierEnv = undefined;
    try e.init();
    defer e.deinit();
    const svc = &e.svc;
    try versioning.setVersioning(svc, "tbk", .enabled);
    const v1 = try e.put("k", "version one");
    const v2 = try e.put("k", "version two");
    try lifecycle.set(svc, "tbk", &.{.{ .noncurrent_transition_days = 1, .noncurrent_transition_tier = "WARM" }});
    const s = try lifecycle.runOnce(svc, dueAt(v2.created_ns, 1));
    try std.testing.expectEqual(@as(usize, 1), s.noncurrent_transitioned);
    try std.testing.expectEqualStrings("version one", try e.body("k", v1.version_id, null));
    try std.testing.expectEqualStrings("version two", try e.body("k", null, null));

    const copy = @import("copy.zig");
    _ = try copy.copyObject(svc, .{ .bucket = "tbk", .key = "k", .version = v1.version_id }, "tbk", "copied", .{});
    try std.testing.expectEqualStrings("version one", try e.body("copied", null, null));

    _ = try versioning.deleteObject(svc, "tbk", "k", .{ .version = v1.version_id });
    try std.testing.expectEqual(@as(usize, 1), (try housekeeping(svc, core.time.nowNs())).cleaned);
    try std.testing.expectEqual(@as(u32, 0), e.mem.objects.count());
}
