//! The event pipeline: target runners (persistent queue + delivery thread with
//! backoff), bucket rule lookup, fan-out to targets and live listeners, audit
//! fan-out, and per-target metrics.
const std = @import("std");
const object = @import("../object/root.zig");
const target = @import("target.zig");
const kinds = @import("kinds.zig");
const settings = @import("settings.zig");
const queue = @import("queue.zig");
const config = @import("config.zig");
const record = @import("record.zig");
const names = @import("names.zig");
const store = @import("store.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.events);

pub const Options = struct {
    /// Region in ARNs and records ("" like an unconfigured MinIO).
    region: []const u8 = "",
    /// Default parent of per-target queue directories.
    queue_root: []const u8,
    /// This node's endpoint, e.g. `http://10.0.0.1:9000`.
    endpoint: []const u8 = "",
    deployment_id: []const u8 = "",
    /// Targets from the environment; they override admin-configured ones.
    env_targets: []const settings.Entry = &.{},
    retry_max_ms: u64 = 30_000,
    /// How long a node trusts its cached copy of a bucket's rules.
    rules_ttl_ns: u64 = 2 * std.time.ns_per_s,
    default_queue_limit: u32 = 100_000,
};

pub const Stats = struct {
    sent: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(u64) = .init(0),
    dropped: std.atomic.Value(u64) = .init(0),
    corrupt: std.atomic.Value(u64) = .init(0),
    online: std.atomic.Value(bool) = .init(true),
};

/// One configured target: its client, queue, and delivery thread.
pub const Runner = struct {
    gpa: Allocator,
    kind: *const kinds.Kind,
    /// Owned copies.
    subsys: []const u8,
    id: []const u8,
    arn: []const u8,
    client: target.Client,
    queue: *queue.Queue,
    stats: Stats = .{},
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    retry_max_ms: u64,

    fn loop(r: *Runner) void {
        var backoff_ms: u64 = 0;
        var corrupt: u64 = 0;
        while (!r.stop.load(.acquire)) {
            var arena = std.heap.ArenaAllocator.init(r.gpa);
            defer arena.deinit();
            const item = r.queue.peek(arena.allocator(), 500 * std.time.ns_per_ms, &corrupt) catch {
                r.sleep(1000);
                continue;
            };
            if (corrupt > 0) {
                _ = r.stats.corrupt.fetchAdd(corrupt, .monotonic);
                corrupt = 0;
            }
            const it = item orelse continue;
            r.client.send(&it.msg) catch |e| {
                _ = r.stats.failed.fetchAdd(1, .monotonic);
                if (r.stats.online.swap(false, .monotonic)) log.warn("{s}:{s}: delivery failed ({t}); retrying", .{ r.subsys, r.id, e });
                backoff_ms = @min(r.retry_max_ms, @max(500, backoff_ms * 2));
                r.sleep(backoff_ms);
                continue;
            };
            r.queue.remove(it.seq);
            _ = r.stats.sent.fetchAdd(1, .monotonic);
            if (!r.stats.online.swap(true, .monotonic)) log.info("{s}:{s}: target is back online", .{ r.subsys, r.id });
            backoff_ms = 0;
        }
    }

    /// Sleeps in short steps so a stop request is seen quickly.
    fn sleep(r: *Runner, ms: u64) void {
        var left = ms;
        while (left > 0 and !r.stop.load(.acquire)) {
            const step: u64 = @min(left, 100);
            std.Thread.sleep(step * std.time.ns_per_ms);
            left -= step;
        }
    }

    fn halt(r: *Runner) void {
        r.stop.store(true, .release);
        r.queue.wake();
        if (r.thread) |t| t.join();
        r.thread = null;
    }

    fn destroy(r: *Runner) void {
        r.halt();
        r.client.deinit();
        r.queue.close();
        r.gpa.free(r.subsys);
        r.gpa.free(r.id);
        r.gpa.free(r.arn);
        r.gpa.destroy(r);
    }

    /// Enqueues one message; full or failing queues count a drop.
    pub fn enqueue(r: *Runner, msg: *const target.Message) void {
        r.queue.put(msg) catch |e| {
            _ = r.stats.dropped.fetchAdd(1, .monotonic);
            log.warn("{s}:{s}: event dropped: {t}", .{ r.subsys, r.id, e });
        };
    }
};

/// A `ListenBucketNotification` subscriber; records queue up to a bound.
pub const Listener = struct {
    gpa: Allocator,
    bucket: []const u8,
    prefix: []const u8,
    suffix: []const u8,
    mask: names.Mask,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    items: std.ArrayList([]u8) = .empty,
    dropped: u64 = 0,

    pub const max_pending = 10_000;

    fn wants(l: *const Listener, ev: record.Event) bool {
        if (l.bucket.len > 0 and !std.mem.eql(u8, l.bucket, ev.bucket)) return false;
        return names.has(l.mask, ev.name) and std.mem.startsWith(u8, ev.key, l.prefix) and std.mem.endsWith(u8, ev.key, l.suffix);
    }

    fn push(l: *Listener, rec: []const u8) void {
        l.mutex.lock();
        defer l.mutex.unlock();
        if (l.items.items.len >= max_pending) {
            l.dropped += 1;
            return;
        }
        const copy = l.gpa.dupe(u8, rec) catch return;
        l.items.append(l.gpa, copy) catch {
            l.gpa.free(copy);
            return;
        };
        l.cond.signal();
    }

    /// Takes the pending records (caller frees each and the slice), waiting up to `timeout_ns`.
    pub fn take(l: *Listener, timeout_ns: u64) error{OutOfMemory}![][]u8 {
        l.mutex.lock();
        defer l.mutex.unlock();
        if (l.items.items.len == 0) l.cond.timedWait(&l.mutex, timeout_ns) catch {};
        return l.items.toOwnedSlice(l.gpa);
    }

    pub fn deinit(l: *Listener) void {
        for (l.items.items) |i| l.gpa.free(i);
        l.items.deinit(l.gpa);
    }
};

const CachedRules = struct {
    arena: std.heap.ArenaAllocator,
    cfg: config.Config,
    loaded_ns: i128,
};

pub const Notifier = struct {
    gpa: Allocator,
    svc: *object.ObjectService,
    opts: Options,
    mutex: std.Thread.Mutex = .{},
    runners: std.ArrayList(*Runner) = .empty,
    /// Admin-configured target lines, as last loaded.
    admin_text: []u8 = &.{},
    rules_mutex: std.Thread.Mutex = .{},
    rules: std.StringHashMapUnmanaged(*CachedRules) = .empty,
    listen_mutex: std.Thread.Mutex = .{},
    listeners: std.ArrayList(*Listener) = .empty,
    /// Fast-path flags: skip all work when nothing could consume an event.
    has_notify: std.atomic.Value(bool) = .init(false),
    has_audit: std.atomic.Value(bool) = .init(false),
    n_listeners: std.atomic.Value(u32) = .init(0),
    /// Audit to stderr / a file, besides audit targets.
    audit_console: bool = false,
    audit_file: ?std.fs.File = null,
    audit_file_mutex: std.Thread.Mutex = .{},
    watcher: ?std.Thread = null,
    watch_stop: std.atomic.Value(bool) = .init(false),

    pub fn init(gpa: Allocator, svc: *object.ObjectService, opts: Options) Notifier {
        return .{ .gpa = gpa, .svc = svc, .opts = opts };
    }

    pub fn deinit(n: *Notifier) void {
        n.watch_stop.store(true, .release);
        if (n.watcher) |t| t.join();
        n.mutex.lock();
        for (n.runners.items) |r| r.destroy();
        n.runners.deinit(n.gpa);
        n.mutex.unlock();
        n.gpa.free(n.admin_text);
        var it = n.rules.iterator();
        while (it.next()) |e| {
            n.gpa.free(e.key_ptr.*);
            e.value_ptr.*.arena.deinit();
            n.gpa.destroy(e.value_ptr.*);
        }
        n.rules.deinit(n.gpa);
        n.listeners.deinit(n.gpa);
        if (n.audit_file) |f| f.close();
    }

    // ---- targets ----

    /// Loads the admin configuration from the store and (re)starts every target.
    pub fn reload(n: *Notifier) store.Error!void {
        var arena = std.heap.ArenaAllocator.init(n.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const text = try store.get(n.svc.store, a, store.key(.targets, "targets")) orelse "";
        try n.apply(text);
    }

    /// Re-reads the stored target configuration every `interval_s` and applies
    /// changes made through other nodes.
    pub fn startWatcher(n: *Notifier, interval_s: u64) std.Thread.SpawnError!void {
        n.watcher = try std.Thread.spawn(.{}, watchLoop, .{ n, interval_s });
    }

    fn watchLoop(n: *Notifier, interval_s: u64) void {
        while (!n.watch_stop.load(.acquire)) {
            var left = interval_s * 10;
            while (left > 0 and !n.watch_stop.load(.acquire)) : (left -= 1) std.Thread.sleep(100 * std.time.ns_per_ms);
            if (n.watch_stop.load(.acquire)) return;
            var arena = std.heap.ArenaAllocator.init(n.gpa);
            defer arena.deinit();
            const text = (store.get(n.svc.store, arena.allocator(), store.key(.targets, "targets")) catch continue) orelse "";
            n.mutex.lock();
            const same = std.mem.eql(u8, text, n.admin_text);
            n.mutex.unlock();
            if (!same) n.apply(text) catch {};
        }
    }

    /// Starts the targets described by `admin_text` plus the environment.
    pub fn apply(n: *Notifier, admin_text: []const u8) error{OutOfMemory}!void {
        var arena = std.heap.ArenaAllocator.init(n.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const admin_entries = settings.parse(a, admin_text) catch |e| blk: {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            log.warn("stored target configuration is invalid ({t}); ignoring it", .{e});
            break :blk &.{};
        };
        var all: std.ArrayList(settings.Entry) = .empty;
        for (admin_entries) |e| {
            const overridden = for (n.opts.env_targets) |x| {
                if (x.sameTarget(e)) break true;
            } else false;
            if (!overridden) try all.append(a, e);
        }
        try all.appendSlice(a, n.opts.env_targets);

        n.mutex.lock();
        defer n.mutex.unlock();
        for (n.runners.items) |r| r.destroy();
        n.runners.clearRetainingCapacity();
        var notify = false;
        var auditors = false;
        for (all.items) |e| {
            if (!e.enabled()) continue;
            const r = n.startRunner(a, e) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                log.err("{s}:{s}: target not started: {t}", .{ e.subsys, e.id, err });
                continue;
            };
            try n.runners.append(n.gpa, r);
            if (r.kind.audit) auditors = true else notify = true;
        }
        n.has_notify.store(notify, .release);
        n.has_audit.store(auditors, .release);
        const copy = try n.gpa.dupe(u8, admin_text);
        n.gpa.free(n.admin_text);
        n.admin_text = copy;
    }

    const StartError = error{ InvalidConfig, QueueFailed, ThreadFailed, OutOfMemory };

    fn startRunner(n: *Notifier, a: Allocator, e: settings.Entry) StartError!*Runner {
        const kind = kinds.bySubsys(e.subsys) orelse return error.InvalidConfig;
        const s = e.settings();
        const limit = s.int(u32, "queue_limit", n.opts.default_queue_limit) catch return error.InvalidConfig;
        const client = try kind.create(n.gpa, s);
        errdefer client.deinit();
        // Notify targets always persist (crash safety); audit loggers only with queue_dir.
        const dir = s.get("queue_dir");
        const q = if (dir.len > 0)
            queue.Queue.open(n.gpa, dir, limit) catch return error.QueueFailed
        else if (kind.audit)
            try queue.Queue.openMemory(n.gpa, limit)
        else blk: {
            const sub = try std.fmt.allocPrint(a, "{s}-{s}", .{ e.subsys, e.id });
            const path = try std.fs.path.join(a, &.{ n.opts.queue_root, sub });
            break :blk queue.Queue.open(n.gpa, path, limit) catch return error.QueueFailed;
        };
        errdefer q.close();
        const r = try n.gpa.create(Runner);
        errdefer n.gpa.destroy(r);
        r.* = .{
            .gpa = n.gpa,
            .kind = kind,
            .subsys = try n.gpa.dupe(u8, e.subsys),
            .id = try n.gpa.dupe(u8, e.id),
            .arn = if (kind.audit) try n.gpa.dupe(u8, "") else try std.fmt.allocPrint(n.gpa, "arn:minio:sqs:{s}:{s}:{s}", .{ n.opts.region, e.id, kind.arn_type }),
            .client = client,
            .queue = q,
            .retry_max_ms = n.opts.retry_max_ms,
        };
        r.thread = std.Thread.spawn(.{}, Runner.loop, .{r}) catch {
            n.gpa.free(r.subsys);
            n.gpa.free(r.id);
            n.gpa.free(r.arn);
            return error.ThreadFailed;
        };
        if (q.len() > 0) log.info("{s}:{s}: {d} queued event(s) from a previous run", .{ e.subsys, e.id, q.len() });
        return r;
    }

    /// ARNs of the running notify targets, in `a`.
    pub fn arns(n: *Notifier, a: Allocator) error{OutOfMemory}![]const []const u8 {
        n.mutex.lock();
        defer n.mutex.unlock();
        var out: std.ArrayList([]const u8) = .empty;
        for (n.runners.items) |r| if (!r.kind.audit) try out.append(a, try a.dupe(u8, r.arn));
        return out.items;
    }

    /// Whether `arn` names a running notify target (region must match or be empty).
    pub fn knowsArn(n: *Notifier, arn: []const u8) bool {
        const p = config.parseArn(arn) orelse return false;
        if (p.region.len > 0 and !std.mem.eql(u8, p.region, n.opts.region)) return false;
        n.mutex.lock();
        defer n.mutex.unlock();
        for (n.runners.items) |r| {
            if (r.kind.audit) continue;
            if (std.mem.eql(u8, r.id, p.id) and std.mem.eql(u8, r.kind.arn_type, p.kind)) return true;
        }
        return false;
    }

    // ---- bucket rules ----

    /// Stored notification XML of `bucket`, or null.
    pub fn getBucketXml(n: *Notifier, a: Allocator, bucket: []const u8) store.Error!?[]u8 {
        return store.get(n.svc.store, a, store.key(.bucket, bucket));
    }

    pub fn setBucketXml(n: *Notifier, bucket: []const u8, xml_doc: ?[]const u8) store.Error!void {
        const k = store.key(.bucket, bucket);
        if (xml_doc) |d| try store.put(n.svc.store, k, d) else try store.remove(n.svc.store, k);
        n.rules_mutex.lock();
        defer n.rules_mutex.unlock();
        if (n.rules.fetchRemove(bucket)) |kv| {
            n.gpa.free(kv.key);
            kv.value.arena.deinit();
            n.gpa.destroy(kv.value);
        }
    }

    const Match = struct { id: []const u8, arn: []const u8 };

    /// Rules of `bucket` matching (name, key), copied into `a`.
    fn matching(n: *Notifier, a: Allocator, bucket: []const u8, name: names.Name, key: []const u8) error{OutOfMemory}![]Match {
        const now = std.time.nanoTimestamp();
        n.rules_mutex.lock();
        const fresh = if (n.rules.get(bucket)) |c| now - c.loaded_ns < n.opts.rules_ttl_ns else false;
        n.rules_mutex.unlock();
        if (!fresh) try n.refreshRules(bucket, now);
        n.rules_mutex.lock();
        defer n.rules_mutex.unlock();
        const c = n.rules.get(bucket) orelse return &.{};
        var out: std.ArrayList(Match) = .empty;
        for (c.cfg.rules) |r| if (r.matches(name, key)) try out.append(a, .{ .id = try a.dupe(u8, r.id), .arn = try a.dupe(u8, r.arn) });
        return out.items;
    }

    fn refreshRules(n: *Notifier, bucket: []const u8, now: i128) error{OutOfMemory}!void {
        const c = try n.gpa.create(CachedRules);
        c.* = .{ .arena = .init(n.gpa), .cfg = .{}, .loaded_ns = now };
        const a = c.arena.allocator();
        const doc = store.get(n.svc.store, a, store.key(.bucket, bucket)) catch |e| switch (e) {
            error.OutOfMemory => {
                c.arena.deinit();
                n.gpa.destroy(c);
                return error.OutOfMemory;
            },
            // Keep serving the previous copy through a storage hiccup.
            error.StorageFailed => {
                c.arena.deinit();
                n.gpa.destroy(c);
                return;
            },
        };
        if (doc) |d| c.cfg = config.parse(a, d) catch .{};
        n.rules_mutex.lock();
        defer n.rules_mutex.unlock();
        const gop = n.rules.getOrPut(n.gpa, bucket) catch {
            c.arena.deinit();
            n.gpa.destroy(c);
            return error.OutOfMemory;
        };
        if (gop.found_existing) {
            gop.value_ptr.*.arena.deinit();
            n.gpa.destroy(gop.value_ptr.*);
        } else {
            gop.key_ptr.* = n.gpa.dupe(u8, bucket) catch {
                n.rules.removeByPtr(gop.key_ptr);
                c.arena.deinit();
                n.gpa.destroy(c);
                return error.OutOfMemory;
            };
        }
        gop.value_ptr.* = c;
    }

    // ---- publishing ----

    /// Whether any target or listener could want an event.
    pub fn active(n: *Notifier) bool {
        return n.has_notify.load(.acquire) or n.n_listeners.load(.acquire) > 0;
    }

    /// Routes one event to matching targets and listeners.
    pub fn publish(n: *Notifier, ev: record.Event) void {
        if (!n.active()) return;
        n.publishInner(ev) catch log.warn("event {s} for {s}/{s} dropped: out of memory", .{ ev.name.text(), ev.bucket, ev.key });
    }

    fn publishInner(n: *Notifier, ev0: record.Event) error{OutOfMemory}!void {
        var arena = std.heap.ArenaAllocator.init(n.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var ev = ev0;
        ev.region = n.opts.region;
        ev.endpoint = n.opts.endpoint;
        ev.deployment_id = n.opts.deployment_id;
        var tb: [24]u8 = undefined;
        const time = record.timeText(ev.time_ns, &tb);
        if (n.has_notify.load(.acquire)) {
            const ms = try n.matching(a, ev.bucket, ev.name, ev.key);
            for (ms) |m| {
                const rec = try record.renderRecord(a, ev, m.id);
                const msg: target.Message = .{
                    .key = try record.entryKey(a, ev),
                    .event_name = ev.name.text(),
                    .body = try record.renderPayload(a, ev, rec),
                    .record = rec,
                    .event_time = time,
                    .removed = record.isRemoval(ev.name),
                };
                n.mutex.lock();
                defer n.mutex.unlock();
                for (n.runners.items) |r| if (!r.kind.audit and std.mem.eql(u8, r.arn, m.arn)) r.enqueue(&msg);
            }
        }
        if (n.n_listeners.load(.acquire) > 0) {
            n.listen_mutex.lock();
            defer n.listen_mutex.unlock();
            var rec: ?[]const u8 = null;
            for (n.listeners.items) |l| if (l.wants(ev)) {
                if (rec == null) rec = try record.renderRecord(a, ev, "");
                l.push(rec.?);
            };
        }
    }

    pub fn subscribe(n: *Notifier, l: *Listener) error{OutOfMemory}!void {
        n.listen_mutex.lock();
        defer n.listen_mutex.unlock();
        try n.listeners.append(n.gpa, l);
        _ = n.n_listeners.fetchAdd(1, .release);
    }

    pub fn unsubscribe(n: *Notifier, l: *Listener) void {
        n.listen_mutex.lock();
        defer n.listen_mutex.unlock();
        for (n.listeners.items, 0..) |x, i| if (x == l) {
            _ = n.listeners.swapRemove(i);
            _ = n.n_listeners.fetchSub(1, .release);
            break;
        };
    }

    // ---- audit ----

    pub fn auditing(n: *Notifier) bool {
        return n.has_audit.load(.acquire) or n.audit_console or n.audit_file != null;
    }

    /// Hands one audit entry (JSON) to every audit logger.
    pub fn audit(n: *Notifier, entry: []const u8) void {
        if (n.audit_console) std.debug.print("{s}\n", .{entry});
        if (n.audit_file) |f| {
            n.audit_file_mutex.lock();
            defer n.audit_file_mutex.unlock();
            f.writeAll(entry) catch {};
            f.writeAll("\n") catch {};
        }
        if (!n.has_audit.load(.acquire)) return;
        const msg: target.Message = .{ .body = entry };
        n.mutex.lock();
        defer n.mutex.unlock();
        for (n.runners.items) |r| if (r.kind.audit) r.enqueue(&msg);
    }

    // ---- metrics ----

    pub fn render(ctx: *anyopaque, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const n: *Notifier = @ptrCast(@alignCast(ctx));
        n.mutex.lock();
        defer n.mutex.unlock();
        if (n.runners.items.len == 0) return;
        const families = [_]struct { []const u8, []const u8 }{
            .{ "events_sent_total", "counter" },
            .{ "events_failed_total", "counter" },
            .{ "events_dropped_total", "counter" },
            .{ "events_corrupt_total", "counter" },
            .{ "queue_length", "gauge" },
            .{ "online", "gauge" },
        };
        for ([_][]const u8{ "notify", "audit" }) |group| {
            const want_audit = std.mem.eql(u8, group, "audit");
            for (families, 0..) |f, fi| {
                var any = false;
                for (n.runners.items) |r| if (r.kind.audit == want_audit) {
                    if (!any) try w.print("# TYPE zkfsm_{s}_target_{s} {s}\n", .{ group, f[0], f[1] });
                    any = true;
                    const v: u64 = switch (fi) {
                        0 => r.stats.sent.load(.monotonic),
                        1 => r.stats.failed.load(.monotonic),
                        2 => r.stats.dropped.load(.monotonic),
                        3 => r.stats.corrupt.load(.monotonic),
                        4 => r.queue.len(),
                        else => @intFromBool(r.stats.online.load(.monotonic)),
                    };
                    try w.print("zkfsm_{s}_target_{s}{{target_id=\"{s}\",target_name=\"{s}\"}} {d}\n", .{ group, f[0], r.id, r.subsys, v });
                };
            }
        }
    }

    /// Per-target status for the admin API.
    pub const TargetStatus = struct { subsys: []const u8, id: []const u8, arn: []const u8, online: bool, queued: usize, sent: u64, failed: u64, dropped: u64 };

    pub fn status(n: *Notifier, a: Allocator) error{OutOfMemory}![]TargetStatus {
        n.mutex.lock();
        defer n.mutex.unlock();
        var out: std.ArrayList(TargetStatus) = .empty;
        for (n.runners.items) |r| try out.append(a, .{
            .subsys = try a.dupe(u8, r.subsys),
            .id = try a.dupe(u8, r.id),
            .arn = try a.dupe(u8, r.arn),
            .online = r.stats.online.load(.monotonic),
            .queued = r.queue.len(),
            .sent = r.stats.sent.load(.monotonic),
            .failed = r.stats.failed.load(.monotonic),
            .dropped = r.stats.dropped.load(.monotonic),
        });
        return out.items;
    }
};
