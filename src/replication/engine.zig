//! The replication engine: per-bucket configuration cache, the durable queue's
//! dispatcher and workers, object delivery to targets, status, resync, and health.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const config = @import("config.zig");
const targets_mod = @import("targets.zig");
const client = @import("client.zig");
const queue = @import("queue.zig");
const store = @import("store.zig");
const stats_mod = @import("stats.zig");
const site = @import("site.zig");
const deliver = @import("deliver.zig");

const Allocator = std.mem.Allocator;
const Entry = queue.Entry;
const ov = object.versioning;
const ns_per_s = std.time.ns_per_s;

pub const Leader = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque) bool,
};

pub const Options = struct {
    workers: usize = 4,
    /// Cluster mode: only the leader delivers; every node enqueues.
    leader: ?Leader = null,
    cache_ttl_ns: i128 = 3 * ns_per_s,
    /// Full queue listing period when no local change woke the dispatcher.
    scan_interval_ns: u64 = 5 * ns_per_s,
    health_interval_ns: i128 = 15 * ns_per_s,
};

pub const Error = error{ NoSuchBucket, StorageFailed, OutOfMemory };

const Cached = struct {
    arena: std.heap.ArenaAllocator,
    bucket: []const u8,
    loaded_ns: i128,
    cfg: ?config.Config = null,
    cfg_xml: ?[]const u8 = null,
    targets: []const targets_mod.Target = &.{},
};

const SiteCached = struct {
    arena: std.heap.ArenaAllocator,
    loaded_ns: i128,
    state: ?site.State,
};

/// Where one version goes.
pub const Dest = struct {
    arn: []const u8,
    rule: config.Rule,
    remote: client.Remote,
    target_bucket: []const u8,
    storage_class: []const u8 = "",
    /// Implicit site-replication peer (deployment id in `arn`).
    peer: ?[]const u8 = null,
};

pub const ResyncTarget = struct {
    arn: []const u8,
    reset_id: []const u8,
    start_ns: i64 = 0,
    end_ns: i64 = 0,
    status: []const u8 = "Pending",
    scheduled: u64 = 0,
    scan_done: bool = false,
    replicated_count: u64 = 0,
    replicated_bytes: u64 = 0,
    failed_count: u64 = 0,
    failed_bytes: u64 = 0,
    last_key: []const u8 = "",
};

pub const Replicator = struct {
    gpa: Allocator,
    svc: *object.ObjectService,
    opts: Options,
    mutex: std.Thread.Mutex = .{},
    cache: std.AutoHashMapUnmanaged([16]u8, *Cached) = .empty,
    site_cache: ?*SiteCached = null,
    wake: std.Thread.ResetEvent = .{},
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    stats: stats_mod.Stats,
    /// Resync progress by reset id, flushed to the bucket's resync record.
    resync_mutex: std.Thread.Mutex = .{},
    last_health_ns: i128 = 0,
    /// Earliest retry time of queued entries, as last seen.
    next_due_ns: std.atomic.Value(i64) = .init(std.math.maxInt(i64)),
    /// Site replication: how peers reach this deployment's admin and S3 API.
    site_ctx: site.Context = .{},

    pub fn init(gpa: Allocator, svc: *object.ObjectService, opts: Options) Replicator {
        return .{ .gpa = gpa, .svc = svc, .opts = opts, .stats = .{ .gpa = gpa, .started_ns = std.time.nanoTimestamp() } };
    }

    pub fn deinit(r: *Replicator) void {
        r.stop();
        var it = r.cache.valueIterator();
        while (it.next()) |c| freeCached(r.gpa, c.*);
        r.cache.deinit(r.gpa);
        if (r.site_cache) |s| {
            s.arena.deinit();
            r.gpa.destroy(s);
        }
        r.stats.deinit();
    }

    fn freeCached(gpa: Allocator, c: *Cached) void {
        c.arena.deinit();
        gpa.destroy(c);
    }

    pub fn sink(r: *Replicator) object.replica.Sink {
        return .{ .ctx = r, .vtable = &.{ .wants = wantsFn, .notify = notifyFn } };
    }

    pub fn start(r: *Replicator) std.Thread.SpawnError!void {
        r.thread = try std.Thread.spawn(.{}, dispatchLoop, .{r});
    }

    pub fn stop(r: *Replicator) void {
        r.stopping.store(true, .release);
        r.wake.set();
        if (r.thread) |t| t.join();
        r.thread = null;
    }

    // ---- configuration cache ----

    /// Caller holds `mutex`.
    fn cachedLocked(r: *Replicator, bid: core.BucketId, bucket: []const u8) Error!*Cached {
        const now = std.time.nanoTimestamp();
        if (r.cache.get(bid.bytes)) |c| {
            if (now - c.loaded_ns < r.opts.cache_ttl_ns) return c;
            _ = r.cache.remove(bid.bytes);
            freeCached(r.gpa, c);
        }
        const c = try r.gpa.create(Cached);
        c.* = .{ .arena = .init(r.gpa), .bucket = "", .loaded_ns = now };
        errdefer freeCached(r.gpa, c);
        const a = c.arena.allocator();
        c.bucket = try a.dupe(u8, bucket);
        var nb: [64]u8 = undefined;
        const hex = bid.toHex();
        if (try store.get(r.svc.store, a, store.key(.config, store.bucketName(&nb, "config", hex)))) |x| {
            c.cfg_xml = x;
            c.cfg = config.parse(a, x) catch null;
        }
        c.targets = try store.getJson([]targets_mod.Target, r.svc.store, a, store.key(.targets, store.bucketName(&nb, "targets", hex))) orelse &.{};
        try r.cache.put(r.gpa, bid.bytes, c);
        return c;
    }

    pub fn invalidate(r: *Replicator, bid: core.BucketId) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        if (r.cache.fetchRemove(bid.bytes)) |kv| freeCached(r.gpa, kv.value);
    }

    pub fn invalidateSite(r: *Replicator) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        if (r.site_cache) |s| {
            s.arena.deinit();
            r.gpa.destroy(s);
            r.site_cache = null;
        }
    }

    /// Caller holds `mutex`.
    fn siteLocked(r: *Replicator) ?*const site.State {
        const now = std.time.nanoTimestamp();
        if (r.site_cache) |s| {
            if (now - s.loaded_ns < r.opts.cache_ttl_ns) return if (s.state) |*st| st else null;
            s.arena.deinit();
            r.gpa.destroy(s);
            r.site_cache = null;
        }
        const s = r.gpa.create(SiteCached) catch return null;
        s.* = .{ .arena = .init(r.gpa), .loaded_ns = now, .state = null };
        s.state = site.load(r.svc.store, s.arena.allocator()) catch null;
        r.site_cache = s;
        return if (s.state) |*st| st else null;
    }

    /// Site state copied into `a`; null when site replication is off.
    pub fn siteState(r: *Replicator, a: Allocator) Allocator.Error!?site.State {
        r.mutex.lock();
        defer r.mutex.unlock();
        const st = r.siteLocked() orelse return null;
        if (!st.enabled) return null;
        return try clone(site.State, a, st.*);
    }

    pub const BucketView = struct {
        cfg: ?config.Config,
        cfg_xml: ?[]const u8,
        targets: []const targets_mod.Target,
    };

    pub fn view(r: *Replicator, a: Allocator, bucket: []const u8) (Error || object.Error)!BucketView {
        const bid = try r.svc.bucketId(bucket);
        r.mutex.lock();
        defer r.mutex.unlock();
        const c = try r.cachedLocked(bid, bucket);
        return .{
            .cfg = if (c.cfg) |cfg| try clone(config.Config, a, cfg) else null,
            .cfg_xml = if (c.cfg_xml) |x| try a.dupe(u8, x) else null,
            .targets = try clone([]const targets_mod.Target, a, c.targets),
        };
    }

    pub fn putConfigXml(r: *Replicator, bucket: []const u8, canonical: ?[]const u8) (Error || object.Error)!void {
        const bid = try r.svc.bucketId(bucket);
        var nb: [64]u8 = undefined;
        const k = store.key(.config, store.bucketName(&nb, "config", bid.toHex()));
        if (canonical) |x| try store.put(r.svc.store, k, x) else try store.remove(r.svc.store, k);
        r.invalidate(bid);
    }

    pub fn putTargets(r: *Replicator, bucket: []const u8, list: []const targets_mod.Target) (Error || object.Error)!void {
        const bid = try r.svc.bucketId(bucket);
        var nb: [64]u8 = undefined;
        try store.putJson(r.svc.store, r.gpa, store.key(.targets, store.bucketName(&nb, "targets", bid.toHex())), list);
        r.invalidate(bid);
    }

    // ---- destinations ----

    /// Caller holds `mutex`; results are copied into `a`.
    fn destsLocked(r: *Replicator, a: Allocator, c: *Cached, key: []const u8, tags: []const config.Tag, op: config.Op, is_replica: bool) Allocator.Error![]Dest {
        var out: std.ArrayList(Dest) = .empty;
        if (c.cfg) |cfg| {
            const rules = try config.match(a, cfg, key, tags, op, is_replica);
            for (rules) |rule| {
                const t = findTarget(c.targets, rule.dest) orelse continue;
                try out.append(a, try explicitDest(a, t, rule));
            }
        }
        if (r.siteLocked()) |st| if (st.enabled and !is_replica) {
            for (st.peers) |p| {
                if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
                try out.append(a, try peerDest(a, st.*, p, c.bucket));
            }
        };
        return out.items;
    }

    /// The destination for one ARN, if it is still configured.
    pub fn destByArn(r: *Replicator, a: Allocator, bid: core.BucketId, bucket: []const u8, arn: []const u8) Error!?Dest {
        r.mutex.lock();
        defer r.mutex.unlock();
        const c = try r.cachedLocked(bid, bucket);
        if (c.cfg) |cfg| for (cfg.rules) |rule| {
            if (!std.mem.eql(u8, rule.dest, arn)) continue;
            const t = findTarget(c.targets, arn) orelse break;
            return try explicitDest(a, t, rule);
        };
        if (r.siteLocked()) |st| if (st.enabled) for (st.peers) |p| {
            if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
            const d = try peerDest(a, st.*, p, bucket);
            if (std.mem.eql(u8, d.arn, arn)) return d;
        };
        return null;
    }

    /// Every ARN this bucket replicates to (rule filters ignored).
    pub fn allArns(r: *Replicator, a: Allocator, bid: core.BucketId, bucket: []const u8) Error![]const []const u8 {
        r.mutex.lock();
        defer r.mutex.unlock();
        const c = try r.cachedLocked(bid, bucket);
        var out: std.ArrayList([]const u8) = .empty;
        if (c.cfg) |cfg| for (cfg.rules) |rule| {
            if (!rule.enabled) continue;
            for (out.items) |x| {
                if (std.mem.eql(u8, x, rule.dest)) break;
            } else try out.append(a, try a.dupe(u8, rule.dest));
        };
        if (r.siteLocked()) |st| if (st.enabled) for (st.peers) |p| {
            if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
            try out.append(a, try site.peerArn(a, p.deployment_id, bucket));
        };
        return out.items;
    }

    // ---- sink ----

    fn wantsFn(ctx: *anyopaque, bid: core.BucketId, bucket: []const u8, key: []const u8, tags_enc: []const u8) bool {
        const r: *Replicator = @ptrCast(@alignCast(ctx));
        var buf: [16 * 1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const a = fba.allocator();
        const tags = decodeTags(a, tags_enc);
        r.mutex.lock();
        defer r.mutex.unlock();
        const c = r.cachedLocked(bid, bucket) catch return false;
        const ds = r.destsLocked(a, c, key, tags, .put, false) catch return true;
        return ds.len > 0;
    }

    fn notifyFn(ctx: *anyopaque, ev: object.replica.Event) void {
        const r: *Replicator = @ptrCast(@alignCast(ctx));
        r.notify(ev) catch |e| std.log.warn("replication: cannot queue {s}/{s}: {t}", .{ ev.bucket, ev.key, e });
    }

    fn notify(r: *Replicator, ev: object.replica.Event) (Error || object.Error)!void {
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const bid = try r.svc.bucketId(ev.bucket);
        var tags: []const config.Tag = &.{};
        var is_replica = false;
        if (ev.kind == .put or ev.kind == .metadata) {
            const info = try ov.headVersion(r.svc, a, ev.bucket, ev.key, ev.version);
            tags = decodeTags(a, info.tags);
            is_replica = object.replica.statusOf(info.internal) == .replica;
        }
        const op: config.Op = switch (ev.kind) {
            .put => .put,
            .delete_marker => .delete_marker,
            .delete_version => .delete_version,
            .metadata => .metadata,
        };
        const dests = blk: {
            r.mutex.lock();
            defer r.mutex.unlock();
            const c = try r.cachedLocked(bid, ev.bucket);
            break :blk try r.destsLocked(a, c, ev.key, tags, op, is_replica);
        };
        var vb: [32]u8 = undefined;
        const vid = ov.formatVersionId(ev.version, &vb);
        const qop: queue.Op = switch (ev.kind) {
            .put => .put,
            .delete_marker => .delete_marker,
            .delete_version => .delete_version,
            .metadata => .metadata,
        };
        for (dests) |d| try r.enqueue(.{ .op = qop, .bucket = ev.bucket, .key = ev.key, .version = vid, .arn = d.arn });
    }

    /// Persists one work item and wakes the dispatcher.
    pub fn enqueue(r: *Replicator, e0: Entry) Error!void {
        var e = e0;
        if (e.enq_ns == 0) e.enq_ns = @intCast(std.time.nanoTimestamp());
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        try store.putJson(r.svc.store, r.gpa, try e.recordKey(arena.allocator()), e);
        r.wake.set();
    }

    // ---- dispatcher ----

    fn isLeader(r: *Replicator) bool {
        const l = r.opts.leader orelse return true;
        return l.func(l.ctx);
    }

    fn dispatchLoop(r: *Replicator) void {
        while (!r.stopping.load(.acquire)) {
            var wait: u64 = r.opts.scan_interval_ns;
            const next_due = r.next_due_ns.load(.monotonic);
            if (next_due != std.math.maxInt(i64)) {
                const left = next_due - @as(i64, @intCast(std.time.nanoTimestamp()));
                wait = @min(wait, @as(u64, @intCast(@max(left, 50 * std.time.ns_per_ms))));
            }
            r.wake.timedWait(wait) catch {};
            r.wake.reset();
            if (r.stopping.load(.acquire)) break;
            if (!r.isLeader()) continue;
            var rounds: usize = 0;
            while (!r.stopping.load(.acquire) and rounds < 64) : (rounds += 1) {
                const more = r.round() catch |e| blk: {
                    std.log.warn("replication: queue pass failed: {t}", .{e});
                    break :blk false;
                };
                if (!more) break;
            }
            const now = std.time.nanoTimestamp();
            if (now - r.last_health_ns >= r.opts.health_interval_ns) {
                r.last_health_ns = now;
                r.probeTargets();
            }
        }
    }

    const Item = struct { key: store.PhysicalKey, e: Entry };

    /// One pass over the due entries; true when something was delivered and more may follow.
    fn round(r: *Replicator) Error!bool {
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const keys = try store.list(r.svc.store, a, .queue);
        var all: std.ArrayList(Item) = .empty;
        for (keys) |k| {
            const e = try store.getJson(Entry, r.svc.store, a, k) orelse continue;
            try all.append(a, .{ .key = k, .e = e });
        }
        r.updatePending(all.items);
        const now: i64 = @intCast(std.time.nanoTimestamp());
        var due: std.ArrayList(Item) = .empty;
        r.next_due_ns.store(std.math.maxInt(i64), .monotonic);
        for (all.items) |it| {
            if (it.e.next_ns <= now) try due.append(a, it) else _ = r.next_due_ns.fetchMin(it.e.next_ns, .monotonic);
        }
        r.finishResyncs(a, all.items);
        if (due.items.len == 0) return false;
        std.mem.sort(Item, due.items, {}, struct {
            fn lt(_: void, x: Item, y: Item) bool {
                return x.e.enq_ns < y.e.enq_ns;
            }
        }.lt);
        const lanes = @max(r.opts.workers, 1);
        const lists = try a.alloc(std.ArrayList(Item), lanes);
        for (lists) |*l| l.* = .empty;
        for (due.items) |it| {
            // Site work stays ordered on lane 0; objects keep per-key order on their lane.
            const lane = if (it.e.isSite()) 0 else std.hash.Wyhash.hash(0, it.e.key) % lanes;
            try lists[lane].append(a, it);
        }
        var progressed = std.atomic.Value(usize).init(0);
        var threads: std.ArrayList(std.Thread) = .empty;
        for (lists[1..]) |*l| {
            if (l.items.len == 0) continue;
            const t = std.Thread.spawn(.{}, runLane, .{ r, l.items, &progressed }) catch {
                runLane(r, l.items, &progressed);
                continue;
            };
            try threads.append(a, t);
        }
        runLane(r, lists[0].items, &progressed);
        for (threads.items) |t| t.join();
        return progressed.load(.monotonic) > 0;
    }

    fn runLane(r: *Replicator, items: []const Item, progressed: *std.atomic.Value(usize)) void {
        if (items.len == 0) return;
        var hc: std.http.Client = .{ .allocator = r.gpa };
        defer hc.deinit();
        for (items) |it| {
            if (r.stopping.load(.acquire)) return;
            var arena = std.heap.ArenaAllocator.init(r.gpa);
            defer arena.deinit();
            const a = arena.allocator();
            const outcome = if (it.e.isSite()) site.process(r, &hc, a, it.e) else deliver.process(r, &hc, a, it.e);
            switch (outcome) {
                .done, .drop => {
                    store.remove(r.svc.store, it.key) catch continue;
                    if (outcome == .done) _ = progressed.fetchAdd(1, .monotonic);
                },
                .retry => {
                    if (it.e.attempts == 0 and !it.e.isSite()) deliver.markFailed(r, it.e);
                    var e = it.e;
                    e.attempts += 1;
                    e.next_ns = @as(i64, @intCast(std.time.nanoTimestamp())) + queue.backoffNs(e.attempts - 1);
                    _ = r.next_due_ns.fetchMin(e.next_ns, .monotonic);
                    store.putJson(r.svc.store, r.gpa, it.key, e) catch {};
                },
            }
        }
    }

    fn updatePending(r: *Replicator, items: []const Item) void {
        r.stats.mutex.lock();
        defer r.stats.mutex.unlock();
        r.stats.queued = items.len;
        for (r.stats.targets.values()) |t| t.pending_count = 0;
        for (items) |it| {
            if (it.e.isSite()) continue;
            const t = r.stats.targetLocked(it.e.bucket, it.e.arn) orelse continue;
            t.pending_count += 1;
        }
    }

    /// Checks every configured target's reachability.
    fn probeTargets(r: *Replicator) void {
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const buckets = r.svc.listBuckets(a) catch return;
        var hc: std.http.Client = .{ .allocator = r.gpa };
        defer hc.deinit();
        for (buckets) |b| {
            const bid = r.svc.bucketId(b.name) catch continue;
            const arns = r.allArns(a, bid, b.name) catch continue;
            for (arns) |arn| {
                const d = (r.destByArn(a, bid, b.name, arn) catch continue) orelse continue;
                const t0 = std.time.nanoTimestamp();
                const res = client.send(&hc, a, d.remote, .{ .method = .HEAD, .path = try_path(a, d.target_bucket) }) catch null;
                const online = if (res) |x| x.status < 500 else false;
                r.stats.health(b.name, arn, online, @intCast(@max(std.time.nanoTimestamp() - t0, 0)));
            }
        }
    }

    fn try_path(a: Allocator, bucket: []const u8) []const u8 {
        return std.fmt.allocPrint(a, "/{s}", .{bucket}) catch "/";
    }

    // ---- existing objects and resync ----

    /// Enqueues every version of `bucket` (not newer than `cutoff_ns`) for `arn`.
    pub fn startScan(r: *Replicator, bucket: []const u8, arn: []const u8, reset_id: []const u8, cutoff_ns: i128) std.Thread.SpawnError!void {
        const owned = r.gpa.alloc(u8, bucket.len + arn.len + reset_id.len) catch return error.SystemResources;
        @memcpy(owned[0..bucket.len], bucket);
        @memcpy(owned[bucket.len..][0..arn.len], arn);
        @memcpy(owned[bucket.len + arn.len ..], reset_id);
        const t = std.Thread.spawn(.{}, scanThread, .{ r, owned, bucket.len, arn.len, cutoff_ns }) catch |e| {
            r.gpa.free(owned);
            return e;
        };
        t.detach();
    }

    fn scanThread(r: *Replicator, owned: []u8, blen: usize, alen: usize, cutoff_ns: i128) void {
        defer r.gpa.free(owned);
        const bucket = owned[0..blen];
        const arn = owned[blen..][0..alen];
        const reset_id = owned[blen + alen ..];
        const n = r.scan(bucket, arn, reset_id, cutoff_ns) catch |e| {
            std.log.warn("replication: scan of {s} for {s} failed: {t}", .{ bucket, arn, e });
            if (reset_id.len > 0) r.updateResync(bucket, arn, reset_id, .{ .status = "Failed", .scan_done = true });
            return;
        };
        if (reset_id.len > 0) r.updateResync(bucket, arn, reset_id, .{ .scheduled = n, .scan_done = true });
        std.log.info("replication: queued {d} existing versions of {s} for {s}", .{ n, bucket, arn });
    }

    fn scan(r: *Replicator, bucket: []const u8, arn: []const u8, reset_id: []const u8, cutoff_ns: i128) (Error || object.Error)!u64 {
        var n: u64 = 0;
        var marker_buf: std.ArrayList(u8) = .empty;
        defer marker_buf.deinit(r.gpa);
        var vmarker: ?core.VersionId = null;
        const bid = try r.svc.bucketId(bucket);
        while (!r.stopping.load(.acquire)) {
            var arena = std.heap.ArenaAllocator.init(r.gpa);
            defer arena.deinit();
            const a = arena.allocator();
            const d = try r.destByArn(a, bid, bucket, arn) orelse return n;
            const res = try ov.listVersions(r.svc, a, bucket, .{ .key_marker = marker_buf.items, .version_id_marker = vmarker, .max_keys = 1000 });
            for (res.entries) |ve| {
                if (ve.mtime_ns > cutoff_ns) continue;
                const info = ov.headVersion(r.svc, a, bucket, ve.key, ve.version) catch continue;
                if (object.replica.statusOf(info.internal) == .replica) continue;
                const tags = decodeTags(a, info.tags);
                const op: config.Op = if (info.delete_marker) .delete_marker else .existing;
                if (!config.ruleApplies(d.rule, ve.key, tags, op, false)) continue;
                if (d.peer == null and !config.ruleApplies(d.rule, ve.key, tags, if (info.delete_marker) .delete_marker else .put, false)) continue;
                var vb: [32]u8 = undefined;
                try r.enqueue(.{
                    .op = if (info.delete_marker) .delete_marker else .existing,
                    .bucket = bucket,
                    .key = ve.key,
                    .version = ov.formatVersionId(ve.version, &vb),
                    .arn = arn,
                    .resync_id = reset_id,
                });
                n += 1;
            }
            if (!res.is_truncated) break;
            marker_buf.clearRetainingCapacity();
            try marker_buf.appendSlice(r.gpa, res.next_key_marker orelse break);
            vmarker = res.next_version_id_marker;
        }
        return n;
    }

    fn resyncKey(bid: core.BucketId) store.PhysicalKey {
        var nb: [64]u8 = undefined;
        return store.key(.resync, store.bucketName(&nb, "resync", bid.toHex()));
    }

    /// Resync records for a bucket.
    pub fn resyncs(r: *Replicator, a: Allocator, bucket: []const u8) (Error || object.Error)![]ResyncTarget {
        const bid = try r.svc.bucketId(bucket);
        r.resync_mutex.lock();
        defer r.resync_mutex.unlock();
        return try store.getJson([]ResyncTarget, r.svc.store, a, resyncKey(bid)) orelse &.{};
    }

    pub const ResyncUpdate = struct {
        status: ?[]const u8 = null,
        scheduled: ?u64 = null,
        scan_done: ?bool = null,
        sent_bytes: ?u64 = null,
        failed_bytes: ?u64 = null,
        last_key: ?[]const u8 = null,
        start: bool = false,
    };

    /// Creates or updates one target's resync record.
    pub fn updateResync(r: *Replicator, bucket: []const u8, arn: []const u8, reset_id: []const u8, u: ResyncUpdate) void {
        const bid = r.svc.bucketId(bucket) catch return;
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        r.resync_mutex.lock();
        defer r.resync_mutex.unlock();
        const k = resyncKey(bid);
        const cur = (store.getJson([]ResyncTarget, r.svc.store, a, k) catch return) orelse &.{};
        var list: std.ArrayList(ResyncTarget) = .empty;
        var found = false;
        for (cur) |t| {
            if (!std.mem.eql(u8, t.arn, arn)) {
                list.append(a, t) catch return;
                continue;
            }
            if (u.start) continue;
            found = true;
            if (!std.mem.eql(u8, t.reset_id, reset_id)) {
                list.append(a, t) catch return;
                continue;
            }
            var n = t;
            applyResync(&n, u);
            list.append(a, n) catch return;
        }
        if (!found and u.start) {
            var n: ResyncTarget = .{ .arn = arn, .reset_id = reset_id, .start_ns = @intCast(std.time.nanoTimestamp()), .status = "Ongoing" };
            applyResync(&n, u);
            n.status = "Ongoing";
            list.append(a, n) catch return;
        }
        store.putJson(r.svc.store, r.gpa, k, list.items) catch {};
    }

    fn applyResync(t: *ResyncTarget, u: ResyncUpdate) void {
        if (u.status) |s| t.status = s;
        if (u.scheduled) |s| t.scheduled = s;
        if (u.scan_done) |s| t.scan_done = s;
        if (u.sent_bytes) |b| {
            t.replicated_count += 1;
            t.replicated_bytes += b;
        }
        if (u.failed_bytes) |b| {
            t.failed_count += 1;
            t.failed_bytes += b;
        }
        if (u.last_key) |k| t.last_key = k;
        if (u.status) |s| if (!std.mem.eql(u8, s, "Ongoing")) {
            t.end_ns = @intCast(std.time.nanoTimestamp());
        };
    }

    /// Marks scanned resyncs complete once none of their entries remain queued.
    fn finishResyncs(r: *Replicator, a: Allocator, items: []const Item) void {
        const buckets = r.svc.listBuckets(a) catch return;
        for (buckets) |b| {
            const list = r.resyncs(a, b.name) catch continue;
            for (list) |t| {
                if (!t.scan_done or !std.mem.eql(u8, t.status, "Ongoing")) continue;
                const left = for (items) |it| {
                    if (std.mem.eql(u8, it.e.resync_id, t.reset_id)) break true;
                } else false;
                if (!left) r.updateResync(b.name, t.arn, t.reset_id, .{ .status = if (t.failed_count > 0) "Failed" else "Completed" });
            }
        }
    }
};

fn findTarget(list: []const targets_mod.Target, arn: []const u8) ?targets_mod.Target {
    for (list) |t| if (std.mem.eql(u8, t.arn, arn)) return t;
    return null;
}

fn explicitDest(a: Allocator, t: targets_mod.Target, rule: config.Rule) Allocator.Error!Dest {
    const tc = try clone(targets_mod.Target, a, t);
    return .{
        .arn = tc.arn,
        .rule = try clone(config.Rule, a, rule),
        .remote = tc.remote(),
        .target_bucket = tc.target_bucket,
        .storage_class = if (rule.storage_class.len > 0) try a.dupe(u8, rule.storage_class) else tc.storage_class,
    };
}

fn peerDest(a: Allocator, st: site.State, p: site.Peer, bucket: []const u8) Allocator.Error!Dest {
    const ep = client.parseUrl(p.endpoint);
    return .{
        .arn = try site.peerArn(a, p.deployment_id, bucket),
        .rule = .{
            .id = "site-repl",
            .dest = "",
            .delete_marker = true,
            .delete = true,
            .existing = true,
            .replica_modifications = true,
        },
        .remote = .{
            .endpoint = try a.dupe(u8, if (ep) |e| e.endpoint else p.endpoint),
            .secure = if (ep) |e| e.secure else false,
            .access_key = try a.dupe(u8, st.svc_access_key),
            .secret_key = try a.dupe(u8, st.svc_secret),
        },
        .target_bucket = try a.dupe(u8, bucket),
        .peer = try a.dupe(u8, p.deployment_id),
    };
}

/// Deep copy through JSON; the types here are plain data.
pub fn clone(comptime T: type, a: Allocator, v: T) Allocator.Error!T {
    const bytes = std.json.Stringify.valueAlloc(a, v, .{}) catch return error.OutOfMemory;
    return std.json.parseFromSliceLeaky(T, a, bytes, .{ .allocate = .alloc_always }) catch |e| switch (e) {
        // Our own serialization always parses back; report anything else as exhaustion.
        else => error.OutOfMemory,
    };
}

pub fn decodeTags(a: Allocator, enc: []const u8) []const config.Tag {
    if (enc.len == 0) return &.{};
    const ts = object.decodeTags(a, enc) catch return &.{};
    const out = a.alloc(config.Tag, ts.len) catch return &.{};
    for (ts, out) |t, *o| o.* = .{ .key = t.key, .value = t.value };
    return out;
}

test "clone deep-copies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r: config.Rule = .{ .id = "x", .dest = "arn:minio:replication::a:b", .tags = &.{.{ .key = "k", .value = "v" }} };
    const c = try clone(config.Rule, arena.allocator(), r);
    try std.testing.expectEqualStrings("v", c.tags[0].value);
    try std.testing.expect(c.tags.ptr != r.tags.ptr);
}
