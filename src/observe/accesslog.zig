//! Server access logs: requests to a bucket with PutBucketLogging set are written
//! in the S3 log record format to a local journal, then batched into objects in the
//! target bucket. Batches are named deterministically, so redelivery after a crash
//! overwrites instead of duplicating; every node delivers its own journal.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");

const Ctx = s3.handler.Ctx;
const Allocator = std.mem.Allocator;

pub const service_principal = "logging.s3.amazonaws.com";

pub const Options = struct {
    /// Journal directory (created); one per node.
    dir: []const u8,
    /// Distinguishes this node's objects from its peers'.
    node_id: []const u8,
    interval_s: u32 = 300,
    /// How long a bucket's logging configuration is cached.
    config_ttl_s: u32 = 5,
    /// Deliver early once the journal holds this much.
    max_batch_bytes: u64 = 8 * 1024 * 1024,
};

pub const Target = struct {
    bucket: []const u8,
    prefix: []const u8,
    partitioned: bool = false,
    /// Partition by event time (else delivery time).
    event_time: bool = false,
};

const Cached = struct { target: ?Target, fetched_ns: i128 };

pub const Stats = struct {
    records: std.atomic.Value(u64) = .init(0),
    objects: std.atomic.Value(u64) = .init(0),
    denied: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(u64) = .init(0),
};

pub const Delivery = struct {
    gpa: Allocator,
    svc: *object.ObjectService,
    opts: Options,
    dir: std.fs.Dir,
    mutex: std.Thread.Mutex = .{},
    journal: ?std.fs.File = null,
    journal_bytes: u64 = 0,
    dirty: bool = false,
    cache_mutex: std.Thread.Mutex = .{},
    cache: std.StringHashMapUnmanaged(Cached) = .empty,
    cache_arena: std.heap.ArenaAllocator,
    stop_ev: std.Thread.ResetEvent = .{},
    kick: std.Thread.ResetEvent = .{},
    thread: ?std.Thread = null,
    stats: Stats = .{},
    /// Serializes delivery passes (the worker and explicit flushes).
    deliver_mutex: std.Thread.Mutex = .{},

    pub const InitError = error{ CannotOpen, OutOfMemory };

    pub fn init(gpa: Allocator, svc: *object.ObjectService, opts: Options) InitError!*Delivery {
        const d = try gpa.create(Delivery);
        errdefer gpa.destroy(d);
        const dir = std.fs.cwd().makeOpenPath(opts.dir, .{ .iterate = true }) catch return error.CannotOpen;
        d.* = .{ .gpa = gpa, .svc = svc, .opts = opts, .dir = dir, .cache_arena = .init(gpa) };
        return d;
    }

    pub fn start(d: *Delivery) std.Thread.SpawnError!void {
        d.thread = try std.Thread.spawn(.{}, loop, .{d});
    }

    pub fn deinit(d: *Delivery) void {
        d.stop_ev.set();
        d.kick.set();
        if (d.thread) |t| t.join();
        if (d.journal) |f| f.close();
        d.cache.deinit(d.gpa);
        d.cache_arena.deinit();
        d.dir.close();
        d.gpa.destroy(d);
    }

    /// The logging target of `bucket`, cached for `config_ttl_s`.
    fn targetOf(d: *Delivery, bucket: []const u8) ?Target {
        const now = std.time.nanoTimestamp();
        const ttl = @as(i128, d.opts.config_ttl_s) * std.time.ns_per_s;
        d.cache_mutex.lock();
        defer d.cache_mutex.unlock();
        if (d.cache.get(bucket)) |c| if (now - c.fetched_ns < ttl) return c.target;
        // The arena only grows with distinct buckets and configuration changes.
        if (d.cache.count() > 4096) {
            d.cache.clearRetainingCapacity();
            _ = d.cache_arena.reset(.retain_capacity);
        }
        const a = d.cache_arena.allocator();
        var tmp = std.heap.ArenaAllocator.init(d.gpa);
        defer tmp.deinit();
        const doc = object.bucket_meta.get(d.svc, tmp.allocator(), bucket, .logging) catch null;
        const t: ?Target = if (doc) |x| parseConfig(a, x) catch null else null;
        const key = if (d.cache.getKey(bucket)) |k| k else a.dupe(u8, bucket) catch return t;
        d.cache.put(d.gpa, key, .{ .target = t, .fetched_ns = now }) catch {};
        return t;
    }

    /// Journals one record for a finished request (called from the S3 observer).
    pub fn record(d: *Delivery, c: *Ctx, status: u16, tx: u64, dur_ns: u64) void {
        const bucket = c.route.bucket;
        if (bucket.len == 0) return;
        const t = d.targetOf(bucket) orelse return;
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        const now = std.time.nanoTimestamp();
        writeHeader(&w, t, bucket, now) catch return;
        formatRecord(&w, c, status, tx, dur_ns, now) catch {
            // Oversized fields: keep the record, without the long tail.
            w.end = @min(w.end, buf.len - 2);
        };
        w.writeByte('\n') catch return;
        d.append(w.buffered());
    }

    fn append(d: *Delivery, line: []const u8) void {
        d.mutex.lock();
        defer d.mutex.unlock();
        const f = d.journal orelse blk: {
            const f = d.dir.createFile("pending.log", .{ .truncate = false, .read = false }) catch return;
            f.seekFromEnd(0) catch {};
            d.journal_bytes = f.getEndPos() catch 0;
            d.journal = f;
            break :blk f;
        };
        f.writeAll(line) catch return;
        d.journal_bytes += line.len;
        d.dirty = true;
        _ = d.stats.records.fetchAdd(1, .monotonic);
        if (d.journal_bytes >= d.opts.max_batch_bytes) d.kick.set();
    }

    fn loop(d: *Delivery) void {
        var elapsed_ms: u64 = 0;
        const interval_ms = @as(u64, @max(1, d.opts.interval_s)) * 1000;
        while (!d.stop_ev.isSet()) {
            d.kick.timedWait(std.time.ns_per_s) catch {};
            const kicked = d.kick.isSet();
            d.kick.reset();
            d.sync();
            elapsed_ms += 1000;
            if (kicked or elapsed_ms >= interval_ms) {
                elapsed_ms = 0;
                d.deliverAll();
            }
        }
        d.sync();
    }

    /// Makes journaled records durable (once a second from the worker).
    fn sync(d: *Delivery) void {
        d.mutex.lock();
        defer d.mutex.unlock();
        if (!d.dirty) return;
        if (d.journal) |f| f.sync() catch {};
        d.dirty = false;
    }

    /// Seals the journal into a batch and delivers every pending batch.
    pub fn deliverAll(d: *Delivery) void {
        d.deliver_mutex.lock();
        defer d.deliver_mutex.unlock();
        d.rotate();
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |n| d.gpa.free(n);
            names.deinit(d.gpa);
        }
        var it = d.dir.iterate();
        while (it.next() catch null) |e| {
            if (e.kind != .file or !std.mem.startsWith(u8, e.name, "batch-") or !std.mem.endsWith(u8, e.name, ".log")) continue;
            const n = d.gpa.dupe(u8, e.name) catch continue;
            names.append(d.gpa, n) catch d.gpa.free(n);
        }
        std.mem.sort([]u8, names.items, {}, struct {
            fn lt(_: void, x: []u8, y: []u8) bool {
                return std.mem.order(u8, x, y) == .lt;
            }
        }.lt);
        for (names.items) |n| d.deliverBatch(n);
    }

    fn rotate(d: *Delivery) void {
        d.mutex.lock();
        defer d.mutex.unlock();
        if (d.journal_bytes == 0) {
            // A crash may have left records in an unopened journal.
            const st = d.dir.statFile("pending.log") catch return;
            if (st.size == 0) return;
        }
        if (d.journal) |f| {
            f.sync() catch {};
            f.close();
            d.journal = null;
        }
        var nb: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "batch-{d:0>20}.log", .{@as(u64, @intCast(@max(0, std.time.nanoTimestamp())))}) catch return;
        d.dir.rename("pending.log", name) catch return;
        d.journal_bytes = 0;
        d.dirty = false;
    }

    fn deliverBatch(d: *Delivery, name: []const u8) void {
        var arena_state = std.heap.ArenaAllocator.init(d.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const body = d.dir.readFileAlloc(a, name, 1 << 30) catch return;
        const batch_ns = std.fmt.parseInt(i128, name["batch-".len .. name.len - ".log".len], 10) catch 0;
        // Group records by destination object.
        var groups: std.StringArrayHashMapUnmanaged(std.ArrayList(u8)) = .empty;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const h = parseHeader(line) orelse continue;
            const when = if (h.event_time) h.time_ns else batch_ns;
            const key = objectKey(a, h, when, d.opts.node_id, name) catch continue;
            const gop = groups.getOrPut(a, key) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
                // The group key carries target and source for the delivery check.
            }
            gop.value_ptr.appendSlice(a, h.record) catch continue;
            gop.value_ptr.append(a, '\n') catch continue;
        }
        var ok = true;
        for (groups.keys(), groups.values()) |k, v| {
            const sep = std.mem.indexOfScalar(u8, k, 0).?;
            const meta = k[0..sep];
            const obj_key = k[sep + 1 ..];
            var mi = std.mem.splitScalar(u8, meta, '\t');
            const target = mi.next() orelse continue;
            const source = mi.next() orelse continue;
            switch (d.put(a, source, target, obj_key, v.items)) {
                .delivered => _ = d.stats.objects.fetchAdd(1, .monotonic),
                .denied => _ = d.stats.denied.fetchAdd(1, .monotonic),
                .retry => {
                    _ = d.stats.failed.fetchAdd(1, .monotonic);
                    ok = false;
                },
            }
        }
        if (ok) d.dir.deleteFile(name) catch {};
    }

    const Outcome = enum { delivered, denied, retry };

    fn put(d: *Delivery, a: Allocator, source: []const u8, target: []const u8, key: []const u8, bytes: []const u8) Outcome {
        switch (mayDeliver(d.svc, a, source, target, key)) {
            .allow => {},
            .deny => {
                std.log.warn("access log: {s} -> {s}: target bucket does not grant log delivery; records dropped", .{ source, target });
                return .denied;
            },
            .gone => return .denied,
            .retry => return .retry,
        }
        var r: std.Io.Reader = .fixed(bytes);
        _ = d.svc.put(target, key, &r, .{ .content_type = "text/plain", .content_length = bytes.len }) catch |e| switch (e) {
            error.NoSuchBucket => return .denied,
            error.OutOfMemory => return .retry,
            else => {
                std.log.warn("access log: delivery to {s}/{s} failed: {t}", .{ target, key, e });
                return .retry;
            },
        };
        return .delivered;
    }

    /// zkfsm_access_log_* series.
    pub fn render(ctx: *anyopaque, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const d: *Delivery = @ptrCast(@alignCast(ctx));
        inline for (.{ .{ "zkfsm_access_log_records_total", "records" }, .{ "zkfsm_access_log_objects_total", "objects" }, .{ "zkfsm_access_log_denied_total", "denied" }, .{ "zkfsm_access_log_failures_total", "failed" } }) |f|
            try w.print("# TYPE {s} counter\n{s} {d}\n", .{ f[0], f[0], @field(d.stats, f[1]).load(.monotonic) });
    }
};

pub const Verdict = enum { allow, deny, gone, retry };

/// Delivery needs the target bucket to grant the logging service principal
/// s3:PutObject (bucket policy) or LogDelivery WRITE (ACL), or to share the
/// source bucket's owner and tenant; an explicit policy Deny always wins.
pub fn mayDeliver(svc: *object.ObjectService, a: Allocator, source: []const u8, target: []const u8, key: []const u8) Verdict {
    const tacc = object.tenancy.access(svc, a, target) catch |e| return if (e == error.NoSuchBucket) .gone else .retry;
    const resource = std.fmt.allocPrint(a, "arn:aws:s3:::{s}/{s}", .{ target, key }) catch return .retry;
    var granted = false;
    if (tacc.policy) |doc| {
        const p = iam.policy.parse(a, doc) catch null;
        if (p) |pol| for (pol.statements) |st| {
            if (!appliesToLogging(st, resource)) continue;
            if (st.effect == .deny) return .deny;
            granted = true;
        };
    }
    if (granted) return .allow;
    const tacl = s3.acl.bucketAcl(svc, a, target) catch return .retry;
    for (tacl.grants) |g| if (g.kind == .group and std.mem.eql(u8, g.value, s3.acl.log_delivery) and (g.perm == .WRITE or g.perm == .FULL_CONTROL)) return .allow;
    const sacc = object.tenancy.access(svc, a, source) catch |e| return if (e == error.NoSuchBucket) .allow else .retry;
    const sacl = s3.acl.bucketAcl(svc, a, source) catch return .retry;
    if (std.mem.eql(u8, sacc.tenant, tacc.tenant) and std.mem.eql(u8, sacl.owner, tacl.owner)) return .allow;
    return .deny;
}

/// The statement applies to the logging service writing `resource`.
fn appliesToLogging(st: iam.policy.Statement, resource: []const u8) bool {
    if (st.not_principal or st.conditions.len > 0) return false;
    const pr = st.principal orelse return false;
    const who = pr.any or for (pr.values) |v| {
        if (v.kind == .service and std.mem.eql(u8, v.value, service_principal)) break true;
        if (v.kind == .account and std.mem.eql(u8, v.value, "*")) break true;
    } else false;
    if (!who) return false;
    const act = for (st.actions) |x| {
        if (glob(x, "s3:PutObject")) break true;
    } else false;
    if (act == st.not_action) return false;
    const rs = st.resources orelse return !st.not_resource;
    const hit = for (rs) |r| {
        if (glob(r, resource)) break true;
    } else false;
    return hit != st.not_resource;
}

/// IAM-style `*` and `?` matching, case-insensitive for action names.
fn glob(pattern: []const u8, s: []const u8) bool {
    if (pattern.len == 0) return s.len == 0;
    if (pattern[0] == '*') {
        var i: usize = 0;
        while (i <= s.len) : (i += 1) if (glob(pattern[1..], s[i..])) return true;
        return false;
    }
    if (s.len == 0) return false;
    if (pattern[0] != '?' and std.ascii.toLower(pattern[0]) != std.ascii.toLower(s[0])) return false;
    return glob(pattern[1..], s[1..]);
}

fn elem(doc: []const u8, name: []const u8) ?[]const u8 {
    var ob: [64]u8 = undefined;
    var cb: [64]u8 = undefined;
    const open = std.fmt.bufPrint(&ob, "<{s}>", .{name}) catch return null;
    const close = std.fmt.bufPrint(&cb, "</{s}>", .{name}) catch return null;
    const i = std.mem.indexOf(u8, doc, open) orelse return null;
    const j = std.mem.indexOfPos(u8, doc, i + open.len, close) orelse return null;
    return doc[i + open.len .. j];
}

fn unescape(a: Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '&') == null) return a.dupe(u8, s);
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    const ents = [_][2][]const u8{ .{ "&amp;", "&" }, .{ "&lt;", "<" }, .{ "&gt;", ">" }, .{ "&quot;", "\"" }, .{ "&apos;", "'" } };
    outer: while (i < s.len) {
        for (ents) |e| if (std.mem.startsWith(u8, s[i..], e[0])) {
            try out.appendSlice(a, e[1]);
            i += e[0].len;
            continue :outer;
        };
        try out.append(a, s[i]);
        i += 1;
    }
    return out.items;
}

/// The stored `<LoggingEnabled>` document.
pub fn parseConfig(a: Allocator, doc: []const u8) error{OutOfMemory}!?Target {
    const inner = elem(doc, "LoggingEnabled") orelse return null;
    const bucket = elem(inner, "TargetBucket") orelse return null;
    const prefix = elem(inner, "TargetPrefix") orelse "";
    const part = std.mem.indexOf(u8, inner, "<PartitionedPrefix") != null;
    const src = elem(inner, "PartitionDateSource") orelse "";
    return .{
        .bucket = try a.dupe(u8, std.mem.trim(u8, bucket, " \n\t")),
        .prefix = try unescape(a, prefix),
        .partitioned = part,
        .event_time = std.mem.eql(u8, src, "EventTime"),
    };
}

// ---------------------------------------------------------------- journal lines

/// `target \t pct(prefix) \t S|P[E] \t source \t event_ns \t record`
fn writeHeader(w: *std.Io.Writer, t: Target, source: []const u8, now: i128) std.Io.Writer.Error!void {
    try w.print("{s}\t", .{t.bucket});
    for (t.prefix) |ch| switch (ch) {
        '%', '\t', '\n', '\r' => try w.print("%{X:0>2}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.print("\t{s}{s}\t{s}\t{d}\t", .{ if (t.partitioned) "P" else "S", if (t.event_time) "E" else "", source, now });
}

const Header = struct { target: []const u8, prefix_pct: []const u8, partitioned: bool, event_time: bool, source: []const u8, time_ns: i128, record: []const u8 };

fn parseHeader(line: []const u8) ?Header {
    var it = std.mem.splitScalar(u8, line, '\t');
    const target = it.next() orelse return null;
    const prefix = it.next() orelse return null;
    const mode = it.next() orelse return null;
    const source = it.next() orelse return null;
    const t = std.fmt.parseInt(i128, it.next() orelse return null, 10) catch return null;
    const rec = it.rest();
    if (target.len == 0 or mode.len == 0 or rec.len == 0) return null;
    return .{ .target = target, .prefix_pct = prefix, .partitioned = mode[0] == 'P', .event_time = std.mem.indexOfScalar(u8, mode, 'E') != null, .source = source, .time_ns = t, .record = rec };
}

fn pctDecode(a: Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            const v = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch {
                try out.append(a, s[i]);
                continue;
            };
            try out.append(a, v);
            i += 2;
        } else try out.append(a, s[i]);
    }
    return out.items;
}

/// `target \t source \0 key`: SimplePrefix `[prefix]YYYY-MM-DD-hh-mm-ss-UNIQUE`, or
/// PartitionedPrefix `[prefix][account]/[region]/[source]/YYYY/MM/DD/YYYY-MM-DD-hh-mm-ss-UNIQUE`.
fn objectKey(a: Allocator, h: Header, when_ns: i128, node_id: []const u8, batch: []const u8) error{OutOfMemory}![]const u8 {
    const prefix = try pctDecode(a, h.prefix_pct);
    const secs: u64 = @intCast(@max(0, @divTrunc(when_ns, std.time.ns_per_s)));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for ([_][]const u8{ node_id, batch, h.target, h.source, prefix }) |p| {
        hasher.update(p);
        hasher.update("\x00");
    }
    var hb: [8]u8 = undefined;
    std.mem.writeInt(u64, &hb, secs, .little);
    hasher.update(&hb);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const unique = std.fmt.bytesToHex(digest[0..8].*, .upper);
    const stamp = try std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}-{d:0>2}-{d:0>2}-{d:0>2}-{s}", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), &unique,
    });
    const key = if (h.partitioned)
        try std.fmt.allocPrint(a, "{s}{s}/{s}/{s}/{d:0>4}/{d:0>2}/{d:0>2}/{s}", .{ prefix, s3.acl.owner_id, "us-east-1", h.source, yd.year, md.month.numeric(), md.day_index + 1, stamp })
    else
        try std.fmt.allocPrint(a, "{s}{s}", .{ prefix, stamp });
    return std.fmt.allocPrint(a, "{s}\t{s}\x00{s}", .{ h.target, h.source, key });
}

// ---------------------------------------------------------------- record format

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn header(c: *const Ctx, name: []const u8) ?[]const u8 {
    for (c.req_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

fn quoted(w: *std.Io.Writer, v: ?[]const u8) std.Io.Writer.Error!void {
    const s = v orelse return w.writeAll("\"-\"");
    try w.writeByte('"');
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        0...0x1f, 0x7f => try w.print("\\x{x:0>2}", .{ch}),
        else => try w.writeByte(ch),
    };
    try w.writeByte('"');
}

fn dash(w: *std.Io.Writer, v: []const u8) std.Io.Writer.Error!void {
    if (v.len == 0) return w.writeAll("-");
    for (v) |ch| try w.writeByte(if (ch <= 0x20 or ch == 0x7f) '_' else ch);
}

fn urlKey(w: *std.Io.Writer, key: []const u8) std.Io.Writer.Error!void {
    if (key.len == 0) return w.writeAll("-");
    for (key) |ch| switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~', '/' => try w.writeByte(ch),
        else => try w.print("%{X:0>2}", .{ch}),
    };
}

fn hasParam(q: []const u8, name: []const u8) bool {
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |p| {
        const k = p[0 .. std.mem.indexOfScalar(u8, p, '=') orelse p.len];
        if (std.mem.eql(u8, k, name)) return true;
    }
    return false;
}

/// REST.<METHOD>.<RESOURCE>, as S3 names operations in access logs.
pub fn operation(a: Allocator, c: *const Ctx) error{OutOfMemory}![]const u8 {
    const r = c.route;
    const q = r.query;
    const m = @tagName(c.method);
    if (c.method == .PUT and c.copy_source and r.key.len > 0) {
        return if (hasParam(q, "partNumber")) "REST.COPY.PART" else "REST.COPY.OBJECT";
    }
    const res: []const u8 = blk: {
        if (r.key.len > 0) {
            if (hasParam(q, "uploads")) break :blk "UPLOADS";
            if (hasParam(q, "partNumber") and c.method == .PUT) break :blk "PART";
            if (hasParam(q, "uploadId")) break :blk "UPLOAD";
            const subs = [_][2][]const u8{ .{ "acl", "ACL" }, .{ "tagging", "OBJECT_TAGGING" }, .{ "retention", "RETENTION" }, .{ "legal-hold", "LEGAL_HOLD" }, .{ "restore", "RESTORE" }, .{ "attributes", "OBJECT_ATTRIBUTES" }, .{ "select", "SELECT" } };
            for (subs) |s| if (hasParam(q, s[0])) break :blk s[1];
            break :blk "OBJECT";
        }
        if (r.bucket.len == 0) break :blk "SERVICE";
        if (hasParam(q, "delete") and c.method == .POST) break :blk "MULTI_OBJECT_DELETE";
        if (hasParam(q, "uploads")) break :blk "UPLOADS";
        if (hasParam(q, "versions")) break :blk "BUCKETVERSIONS";
        const subs = [_][]const u8{ "versioning", "acl", "policy", "cors", "lifecycle", "tagging", "encryption", "notification", "replication", "website", "logging", "location", "object-lock", "ownershipControls", "publicAccessBlock", "requestPayment", "accelerate", "policyStatus" };
        for (subs) |s| if (hasParam(q, s)) {
            const up = try a.alloc(u8, s.len);
            for (s, up) |ch, *o| o.* = if (ch == '-') '_' else std.ascii.toUpper(ch);
            break :blk up;
        };
        break :blk "BUCKET";
    };
    return std.fmt.allocPrint(a, "REST.{s}.{s}", .{ m, res });
}

pub fn formatRecord(w: *std.Io.Writer, c: *Ctx, status: u16, tx: u64, dur_ns: u64, now_ns: i128) std.Io.Writer.Error!void {
    var fba_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const a = fba.allocator();
    const owner = s3.acl.owner_id;
    // Bucket owner, bucket, [time]
    const secs: u64 = @intCast(@max(0, @divTrunc(now_ns, std.time.ns_per_s)));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{s} {s} [{d:0>2}/{s}/{d:0>4}:{d:0>2}:{d:0>2}:{d:0>2} +0000] ", .{
        owner, c.route.bucket, md.day_index + 1, months[md.month.numeric() - 1], yd.year, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
    // Remote IP, requester, request id, operation, key
    const ip = if (c.peer) |p| @import("../events/s3ext.zig").peerParts(a, p)[0] else "-";
    try dash(w, ip);
    try w.writeByte(' ');
    try dash(w, if (c.auth.anonymous) "" else c.auth.access_key);
    try w.print(" {s} ", .{&c.request_id});
    try w.writeAll(operation(a, c) catch "REST.UNKNOWN");
    try w.writeByte(' ');
    try urlKey(w, c.route.key);
    try w.writeByte(' ');
    // "Request-URI" status error-code bytes-sent object-size total-time turn-around
    const line = std.fmt.allocPrint(a, "{s} {s} HTTP/1.1", .{ @tagName(c.method), c.target }) catch "-";
    try quoted(w, line);
    try w.print(" {d} ", .{status});
    try dash(w, c.err_code);
    if (tx > 0) try w.print(" {d} ", .{tx}) else try w.writeAll(" - ");
    const size: ?u64 = if (c.method == .PUT and c.route.key.len > 0) c.req.head.content_length else if (c.method == .GET and c.route.key.len > 0 and status / 100 == 2) tx else null;
    if (size) |s| try w.print("{d} ", .{s}) else try w.writeAll("- ");
    const ms = dur_ns / std.time.ns_per_ms;
    try w.print("{d} {d} ", .{ ms, ms });
    // "Referer" "User-Agent" version-id host-id sig-version cipher auth-type host tls arn acl-required
    try quoted(w, header(c, "referer"));
    try w.writeByte(' ');
    try quoted(w, header(c, "user-agent"));
    try w.writeByte(' ');
    var vid: []const u8 = "";
    for (c.resp_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-amz-version-id")) {
        vid = h.value;
    };
    try dash(w, vid);
    try w.writeAll(" - ");
    const authz = header(c, "authorization") orelse "";
    const sig: []const u8, const kind: []const u8 = if (std.mem.startsWith(u8, authz, "AWS4-"))
        .{ "SigV4", "AuthHeader" }
    else if (std.mem.startsWith(u8, authz, "AWS "))
        .{ "SigV2", "AuthHeader" }
    else if (hasParam(c.route.query, "X-Amz-Signature"))
        .{ "SigV4", "QueryString" }
    else if (hasParam(c.route.query, "Signature"))
        .{ "SigV2", "QueryString" }
    else
        .{ "", "" };
    try dash(w, sig);
    try w.writeAll(" - ");
    try dash(w, kind);
    try w.writeByte(' ');
    try dash(w, c.host orelse "");
    try w.writeAll(" - - -");
}

test "logging configuration parse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = (try parseConfig(a, "<LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>a&amp;b/</TargetPrefix><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled>")).?;
    try std.testing.expectEqualStrings("logs", t.bucket);
    try std.testing.expectEqualStrings("a&b/", t.prefix);
    try std.testing.expect(t.partitioned and t.event_time);
    try std.testing.expect((try parseConfig(a, "")) == null);
}

test "journal header round trip and object keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeHeader(&w, .{ .bucket = "logs", .prefix = "p%\t/" }, "src", 1_700_000_000 * std.time.ns_per_s);
    try w.writeAll("REC");
    const h = parseHeader(w.buffered()).?;
    try std.testing.expectEqualStrings("logs", h.target);
    try std.testing.expectEqualStrings("p%\t/", try pctDecode(a, h.prefix_pct));
    try std.testing.expectEqualStrings("REC", h.record);
    const k1 = try objectKey(a, h, h.time_ns, "n1", "batch-1.log");
    const k2 = try objectKey(a, h, h.time_ns, "n1", "batch-1.log");
    const k3 = try objectKey(a, h, h.time_ns, "n2", "batch-1.log");
    try std.testing.expectEqualStrings(k1, k2);
    try std.testing.expect(!std.mem.eql(u8, k1, k3));
    try std.testing.expect(std.mem.indexOf(u8, k1, "\x00p%\t/2023-11-14-22-13-20-") != null);
    var hp = h;
    hp.partitioned = true;
    const kp = try objectKey(a, hp, h.time_ns, "n1", "b");
    try std.testing.expect(std.mem.indexOf(u8, kp, "/src/2023/11/14/2023-11-14-22-13-20-") != null);
}

test "glob and statement matching" {
    try std.testing.expect(glob("s3:*", "s3:PutObject"));
    try std.testing.expect(glob("arn:aws:s3:::logs/*", "arn:aws:s3:::logs/a/b"));
    try std.testing.expect(!glob("arn:aws:s3:::logs/x*", "arn:aws:s3:::logs/a"));
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const p = try iam.policy.parse(arena.allocator(),
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::logs/*"}]}
    );
    try std.testing.expect(appliesToLogging(p.statements[0], "arn:aws:s3:::logs/k"));
    try std.testing.expect(!appliesToLogging(p.statements[0], "arn:aws:s3:::other/k"));
}
