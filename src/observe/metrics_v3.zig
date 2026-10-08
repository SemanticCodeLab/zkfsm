//! MinIO-style metrics v3: `/minio/metrics/v3/<group path>` serves every group under
//! the path (the root serves all); `/bucket/{api,replication}/<bucket>` per bucket.
//! Scrapes authenticate with the `mc admin prometheus generate` bearer JWT unless public.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const metrics = @import("../metrics/root.zig");
const replication = @import("../replication/root.zig");
const events = @import("../events/root.zig");
const apistats = @import("apistats.zig");
const otlp = @import("otlp.zig");
const sysinfo = @import("sysinfo.zig");

const Writer = std.Io.Writer;
const WError = Writer.Error;

pub const root_path = "/minio/metrics/v3";

pub const NodeInfo = struct {
    ctx: *anyopaque,
    /// Total and online node counts.
    func: *const fn (ctx: *anyopaque) [2]usize,
};

pub const Sources = struct {
    svc: *object.ObjectService,
    stats: *apistats.Stats,
    server: []const u8,
    drives: []const []const u8 = &.{},
    profile: []const u8 = "",
    parity: u32 = 0,
    nodes: ?NodeInfo = null,
    repl: ?*replication.Replicator = null,
    notifier: ?*events.Notifier = null,
    exporter: ?*otlp.Exporter = null,
    started_ns: i128 = 0,
    access_log: ?*const fn (ctx: *anyopaque, w: *Writer) WError!void = null,
    access_log_ctx: ?*anyopaque = null,
};

pub const Auth = enum { jwt, public };

pub const Route = struct {
    src: *Sources,
    store: ?*iam.Store = null,
    auth: Auth = .jwt,

    pub fn raw(r: *Route) s3.server.RawRoute {
        return .{ .prefix = root_path, .ctx = r, .serve = serve };
    }

    fn serve(ctx: *anyopaque, req: *std.http.Server.Request, arena: std.mem.Allocator) s3.server.RawError!void {
        const r: *Route = @ptrCast(@alignCast(ctx));
        if (req.head.method != .GET and req.head.method != .HEAD) {
            return req.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false });
        }
        const target = req.head.target;
        const path = target[root_path.len .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        if (path.len > 0 and path[0] != '/') return req.respond("not found\n", .{ .status = .not_found });
        if (r.auth == .jwt and r.store != null) {
            var bearer: ?[]const u8 = null;
            var it = req.iterateHeaders();
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
                if (std.mem.startsWith(u8, h.value, "Bearer ")) bearer = h.value[7..];
            };
            if (!r.authorized(arena, bearer orelse "")) {
                return req.respond("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>", .{
                    .status = .forbidden,
                    .extra_headers = &.{.{ .name = "content-type", .value = "application/xml" }},
                });
            }
        }
        var out: std.Io.Writer.Allocating = .init(arena);
        const found = render(r.src, arena, &out.writer, path) catch return error.OutOfMemory;
        if (!found) return req.respond("not found\n", .{ .status = .not_found });
        try req.respond(if (req.head.method == .HEAD) "" else out.written(), .{ .extra_headers = &.{
            .{ .name = "content-type", .value = "text/plain; version=0.0.4; charset=utf-8" },
        } });
    }

    /// HS512/HS256 JWT: `sub` names a key whose secret signed it, `exp` in the future,
    /// and the identity may `admin:Prometheus`.
    fn authorized(r: *Route, arena: std.mem.Allocator, token: []const u8) bool {
        const store = r.store orelse return true;
        const claims = verifyJwt(arena, token, store) orelse return false;
        const now_s = std.time.timestamp();
        if (claims.exp != 0 and claims.exp < now_s) return false;
        const v = store.view();
        const principal = blk: {
            defer v.release();
            if (v.serviceAccount(claims.sub)) |sa| break :blk arena.dupe(u8, sa.parent) catch return false;
            break :blk claims.sub;
        };
        const id: iam.Identity = .{ .access_key = principal };
        const c: iam.Context = .{ .now_s = now_s };
        return store.authorize(id, "admin:Prometheus", iam.actions.admin_resource, &c).allowed();
    }
};

const Claims = struct { sub: []const u8, exp: i64 };

fn b64(arena: std.mem.Allocator, s: []const u8) ?[]u8 {
    const d = std.base64.url_safe_no_pad.Decoder;
    const n = d.calcSizeForSlice(s) catch return null;
    const out = arena.alloc(u8, n) catch return null;
    d.decode(out, s) catch return null;
    return out;
}

fn verifyJwt(arena: std.mem.Allocator, token: []const u8, store: *iam.Store) ?Claims {
    var parts = std.mem.splitScalar(u8, token, '.');
    const h64 = parts.next() orelse return null;
    const p64 = parts.next() orelse return null;
    const s64 = parts.next() orelse return null;
    if (parts.next() != null) return null;
    const header = b64(arena, h64) orelse return null;
    const payload = b64(arena, p64) orelse return null;
    const sig = b64(arena, s64) orelse return null;
    const H = struct { alg: []const u8 = "" };
    const hd = std.json.parseFromSliceLeaky(H, arena, header, .{ .ignore_unknown_fields = true }) catch return null;
    const P = struct { sub: []const u8 = "", exp: i64 = 0, iss: []const u8 = "" };
    const pl = std.json.parseFromSliceLeaky(P, arena, payload, .{ .ignore_unknown_fields = true }) catch return null;
    if (pl.sub.len == 0) return null;
    var sbuf: iam.Store.SecretBuf = undefined;
    const secret = store.secretFor(pl.sub, std.time.timestamp(), &sbuf) orelse return null;
    const signed = token[0 .. h64.len + 1 + p64.len];
    if (std.mem.eql(u8, hd.alg, "HS512")) {
        var mac: [64]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha512.create(&mac, signed, secret);
        if (sig.len != 64 or !std.crypto.timing_safe.eql([64]u8, mac, sig[0..64].*)) return null;
    } else if (std.mem.eql(u8, hd.alg, "HS256")) {
        var mac: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signed, secret);
        if (sig.len != 32 or !std.crypto.timing_safe.eql([32]u8, mac, sig[0..32].*)) return null;
    } else return null;
    return .{ .sub = pl.sub, .exp = pl.exp };
}

const Group = struct {
    path: []const u8,
    func: *const fn (src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void,
};

const groups = [_]Group{
    .{ .path = "/api/requests", .func = apiRequests },
    .{ .path = "/system/drive", .func = systemDrive },
    .{ .path = "/system/memory", .func = systemMemory },
    .{ .path = "/system/cpu", .func = systemCpu },
    .{ .path = "/system/process", .func = systemProcess },
    .{ .path = "/system/network/internode", .func = internode },
    .{ .path = "/debug/go", .func = debugRuntime },
    .{ .path = "/cluster/health", .func = clusterHealth },
    .{ .path = "/cluster/usage/objects", .func = usageObjects },
    .{ .path = "/cluster/usage/buckets", .func = usageBuckets },
    .{ .path = "/cluster/erasure-set", .func = erasureSet },
    .{ .path = "/cluster/iam", .func = clusterIam },
    .{ .path = "/cluster/config", .func = clusterConfig },
    .{ .path = "/ilm", .func = ilm },
    .{ .path = "/audit", .func = audit },
    .{ .path = "/logger/webhook", .func = loggerWebhook },
    .{ .path = "/replication", .func = replicationGroup },
    .{ .path = "/notification", .func = notification },
    .{ .path = "/scanner", .func = scanner },
};

/// True when `p` names `g` or one of its ancestors (segment-wise).
fn under(g: []const u8, p: []const u8) bool {
    const q = std.mem.trimRight(u8, p, "/");
    if (q.len == 0) return true;
    if (!std.mem.startsWith(u8, g, q)) return false;
    return g.len == q.len or g[q.len] == '/';
}

/// Writes the groups selected by `path`; false when it names no group.
pub fn render(src: *Sources, a: std.mem.Allocator, w: *Writer, path: []const u8) WError!bool {
    const p = std.mem.trimRight(u8, path, "/");
    if (std.mem.startsWith(u8, p, "/bucket")) return renderBucket(src, a, w, p["/bucket".len..]);
    var any = false;
    for (groups) |g| if (under(g.path, p)) {
        any = true;
        try g.func(src, a, w);
    };
    if (p.len == 0) {
        _ = try renderBucket(src, a, w, "");
        try zkfsmExtras(src, a, w);
    }
    return any;
}

fn renderBucket(src: *Sources, a: std.mem.Allocator, w: *Writer, rest: []const u8) WError!bool {
    // rest: "", "/api", "/api/<bucket>", "/replication", "/replication/<bucket>"
    var it = std.mem.tokenizeScalar(u8, rest, '/');
    const kind = it.next() orelse "";
    const bucket = it.rest();
    const do_api = kind.len == 0 or std.mem.eql(u8, kind, "api");
    const do_repl = kind.len == 0 or std.mem.eql(u8, kind, "replication");
    if (!do_api and !do_repl) return false;
    var names: []const []const u8 = &.{};
    if (bucket.len > 0) {
        names = &.{bucket};
    } else {
        const list = src.svc.listBuckets(a) catch &.{};
        const out = a.alloc([]const u8, list.len) catch return error.WriteFailed;
        for (list, out) |b, *o| o.* = b.name;
        names = out;
    }
    for (names) |b| {
        if (do_api) try src.stats.renderBucket(w, b, src.server);
        if (do_repl) try bucketReplication(src, w, b);
    }
    return true;
}

fn apiRequests(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    src.stats.inflight.store(metrics.global.counters.inflight.load(.monotonic), .monotonic);
    try src.stats.renderApi(w, src.server);
}

fn systemDrive(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const fams = .{
        .{ "minio_system_drive_used_bytes", "gauge", "Total storage used on a drive in bytes" },
        .{ "minio_system_drive_free_bytes", "gauge", "Total storage free on a drive in bytes" },
        .{ "minio_system_drive_total_bytes", "gauge", "Total storage on a drive in bytes" },
        .{ "minio_system_drive_used_inodes", "gauge", "Total used inodes on a drive" },
        .{ "minio_system_drive_free_inodes", "gauge", "Total free inodes on a drive" },
        .{ "minio_system_drive_total_inodes", "gauge", "Total inodes on a drive" },
        .{ "minio_system_drive_health", "gauge", "Drive health (0 = offline, 1 = healthy)" },
    };
    var stats: [256]?sysinfo.FsStat = @splat(null);
    const n = @min(src.drives.len, stats.len);
    for (src.drives[0..n], stats[0..n]) |d, *s| s.* = sysinfo.statfs(d);
    inline for (fams, 0..) |f, fi| {
        try w.print("# HELP {s} {s}\n# TYPE {s} {s}\n", .{ f[0], f[2], f[0], f[1] });
        for (src.drives[0..n], stats[0..n], 0..) |d, st, i| {
            const s = st orelse sysinfo.FsStat{};
            const v: u64 = switch (fi) {
                0 => s.total -| s.free,
                1 => s.free,
                2 => s.total,
                3 => s.files -| s.ffree,
                4 => s.ffree,
                5 => s.files,
                else => @intFromBool(st != null),
            };
            try w.print("{s}{{drive=\"{s}\",pool_index=\"0\",set_index=\"0\",drive_index=\"{d}\",server=\"{s}\"}} {d}\n", .{ f[0], d, i, src.server, v });
        }
    }
    var online: usize = 0;
    for (stats[0..n]) |s| online += @intFromBool(s != null);
    try w.print("# TYPE minio_system_drive_online_count gauge\nminio_system_drive_online_count{{server=\"{s}\"}} {d}\n", .{ src.server, online });
    try w.print("# TYPE minio_system_drive_offline_count gauge\nminio_system_drive_offline_count{{server=\"{s}\"}} {d}\n", .{ src.server, n - online });
    try w.print("# TYPE minio_system_drive_count gauge\nminio_system_drive_count{{server=\"{s}\"}} {d}\n", .{ src.server, n });
}

fn systemMemory(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    try sysinfo.memory(src.server, w);
}

fn systemCpu(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    try sysinfo.cpu(src.server, w);
}

fn systemProcess(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    try sysinfo.process(src.server, w);
    const up_ns = std.time.nanoTimestamp() - src.started_ns;
    try w.print("# TYPE minio_system_process_uptime_seconds gauge\nminio_system_process_uptime_seconds{{server=\"{s}\"}} {d}\n", .{ src.server, @divTrunc(@max(up_ns, 0), std.time.ns_per_s) });
}

fn internode(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const n = if (src.nodes) |ni| ni.func(ni.ctx) else [2]usize{ 1, 1 };
    try w.print("# HELP minio_system_network_internode_errors_total Peers seen offline\n# TYPE minio_system_network_internode_errors_total counter\nminio_system_network_internode_errors_total{{server=\"{s}\"}} {d}\n", .{ src.server, n[0] - n[1] });
}

fn debugRuntime(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const threads = sysinfo.threadCount();
    try w.print("# HELP minio_debug_go_goroutine_total Threads of the server process\n# TYPE minio_debug_go_goroutine_total gauge\nminio_debug_go_goroutine_total{{server=\"{s}\"}} {d}\n", .{ src.server, threads });
}

fn clusterHealth(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    var total: u64 = 0;
    var free: u64 = 0;
    var online: usize = 0;
    for (src.drives) |d| if (sysinfo.statfs(d)) |s| {
        total += s.total;
        free += s.free;
        online += 1;
    };
    const n = if (src.nodes) |ni| ni.func(ni.ctx) else [2]usize{ 1, 1 };
    const g = .{
        .{ "minio_cluster_health_drives_offline_count", src.drives.len - online },
        .{ "minio_cluster_health_drives_online_count", online },
        .{ "minio_cluster_health_drives_count", src.drives.len },
        .{ "minio_cluster_health_nodes_offline_count", n[0] - n[1] },
        .{ "minio_cluster_health_nodes_online_count", n[1] },
        .{ "minio_cluster_health_capacity_raw_total_bytes", total },
        .{ "minio_cluster_health_capacity_raw_free_bytes", free },
        .{ "minio_cluster_health_capacity_usable_total_bytes", total },
        .{ "minio_cluster_health_capacity_usable_free_bytes", free },
    };
    inline for (g) |m| try w.print("# TYPE {s} gauge\n{s} {d}\n", .{ m[0], m[0], m[1] });
}

fn usageObjects(src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void {
    const list = src.svc.listBuckets(a) catch &.{};
    var bytes: u64 = 0;
    var objects: u64 = 0;
    for (list) |b| if (object.quota.usage(src.svc, b.name)) |u| {
        bytes += u.bytes;
        objects += u.objects;
    } else |_| {};
    try w.print("# TYPE minio_cluster_usage_objects_since_last_update_seconds gauge\nminio_cluster_usage_objects_since_last_update_seconds 0\n", .{});
    try w.print("# HELP minio_cluster_usage_objects_total_bytes Total cluster usage in bytes\n# TYPE minio_cluster_usage_objects_total_bytes gauge\nminio_cluster_usage_objects_total_bytes {d}\n", .{bytes});
    try w.print("# HELP minio_cluster_usage_objects_count Total cluster objects count\n# TYPE minio_cluster_usage_objects_count gauge\nminio_cluster_usage_objects_count {d}\n", .{objects});
    try w.print("# HELP minio_cluster_usage_objects_buckets_count Total cluster buckets count\n# TYPE minio_cluster_usage_objects_buckets_count gauge\nminio_cluster_usage_objects_buckets_count {d}\n", .{list.len});
}

fn usageBuckets(src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void {
    const list = src.svc.listBuckets(a) catch &.{};
    const infos = a.alloc(?object.quota.Info, list.len) catch return error.WriteFailed;
    for (list, infos) |b, *i| i.* = object.quota.info(src.svc, b.name) catch null;
    const fams = .{
        .{ "minio_cluster_usage_buckets_total_bytes", "Total bucket size in bytes" },
        .{ "minio_cluster_usage_buckets_objects_count", "Total objects count in bucket" },
        .{ "minio_cluster_usage_buckets_quota_total_bytes", "Total bucket quota in bytes" },
    };
    inline for (fams, 0..) |f, fi| {
        try w.print("# HELP {s} {s}\n# TYPE {s} gauge\n", .{ f[0], f[1], f[0] });
        for (list, infos) |b, info| {
            const i = info orelse continue;
            const v = switch (fi) {
                0 => i.usage.bytes,
                1 => i.usage.objects,
                else => i.quota,
            };
            try w.print("{s}{{bucket=\"{s}\"}} {d}\n", .{ f[0], b.name, v });
        }
    }
}

fn erasureSet(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    var online: usize = 0;
    for (src.drives) |d| online += @intFromBool(sysinfo.statfs(d) != null);
    const n = src.drives.len;
    const read_q = if (n > src.parity) n - src.parity else 1;
    const write_q = if (src.parity * 2 == n) read_q + 1 else read_q;
    const g = .{
        .{ "minio_cluster_erasure_set_overall_write_quorum", write_q },
        .{ "minio_cluster_erasure_set_overall_health", @intFromBool(online >= write_q) },
        .{ "minio_cluster_erasure_set_read_quorum", read_q },
        .{ "minio_cluster_erasure_set_write_quorum", write_q },
        .{ "minio_cluster_erasure_set_online_drives_count", online },
        .{ "minio_cluster_erasure_set_healing_drives_count", @as(usize, 0) },
        .{ "minio_cluster_erasure_set_health", @intFromBool(online >= write_q) },
    };
    inline for (g) |m| try w.print("# TYPE {s} gauge\n{s}{{pool_id=\"0\",set_id=\"0\"}} {d}\n", .{ m[0], m[0], m[1] });
}

fn clusterIam(_: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    try w.writeAll("# TYPE minio_cluster_iam_sync_failures gauge\nminio_cluster_iam_sync_failures 0\n");
    try w.writeAll("# TYPE minio_cluster_iam_sync_successes gauge\nminio_cluster_iam_sync_successes 0\n");
}

fn clusterConfig(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    try w.print("# HELP minio_cluster_config_standard_parity Standard storage class parity\n# TYPE minio_cluster_config_standard_parity gauge\nminio_cluster_config_standard_parity {d}\n", .{src.parity});
    try w.print("# HELP minio_cluster_config_rrs_parity Reduced redundancy storage class parity\n# TYPE minio_cluster_config_rrs_parity gauge\nminio_cluster_config_rrs_parity {d}\n", .{src.parity});
}

fn ilm(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const reg = src.svc.tiers orelse return;
    const c = &reg.counters;
    const g = .{
        .{ "minio_cluster_ilm_transition_pending_tasks", "gauge", c.transition_failures.load(.monotonic) },
        .{ "minio_cluster_ilm_transition_active_tasks", "gauge", @as(u64, 0) },
        .{ "minio_cluster_ilm_transition_missed_immediate_tasks", "counter", c.transition_failures.load(.monotonic) },
        .{ "minio_cluster_ilm_transitioned_objects_total", "counter", c.transitions.load(.monotonic) },
        .{ "minio_cluster_ilm_transitioned_bytes_total", "counter", c.transitioned_bytes.load(.monotonic) },
        .{ "minio_cluster_ilm_expiry_pending_tasks", "gauge", c.cleanup_pending.load(.monotonic) },
        .{ "minio_cluster_ilm_restores_total", "counter", c.restores.load(.monotonic) },
    };
    inline for (g) |m| try w.print("# TYPE {s} {s}\n{s} {d}\n", .{ m[0], m[1], m[0], m[2] });
}

fn targetGroup(src: *Sources, a: std.mem.Allocator, w: *Writer, want_audit: bool, prefix: []const u8) WError!void {
    const n = src.notifier orelse return;
    const list = n.status(a) catch return;
    const fams = .{
        .{ "failed_messages", "counter" },
        .{ "target_queue_length", "gauge" },
        .{ "total_messages", "counter" },
        .{ "target_online", "gauge" },
    };
    inline for (fams, 0..) |f, fi| {
        try w.print("# TYPE {s}_{s} {s}\n", .{ prefix, f[0], f[1] });
        for (list) |t| {
            const is_audit = std.mem.startsWith(u8, t.subsys, "audit");
            if (is_audit != want_audit) continue;
            const v: u64 = switch (fi) {
                0 => t.failed + t.dropped,
                1 => t.queued,
                2 => t.sent + t.failed,
                else => @intFromBool(t.online),
            };
            try w.print("{s}_{s}{{target_id=\"{s}\",target_type=\"{s}\",server=\"{s}\"}} {d}\n", .{ prefix, f[0], t.id, t.subsys, src.server, v });
        }
    }
}

fn audit(src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void {
    try targetGroup(src, a, w, true, "minio_audit");
}

fn loggerWebhook(src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void {
    try targetGroup(src, a, w, true, "minio_logger_webhook");
}

fn notification(src: *Sources, a: std.mem.Allocator, w: *Writer) WError!void {
    const n = src.notifier orelse return;
    const list = n.status(a) catch return;
    var sent: u64 = 0;
    var failed: u64 = 0;
    var dropped: u64 = 0;
    var queued: u64 = 0;
    for (list) |t| if (!std.mem.startsWith(u8, t.subsys, "audit")) {
        sent += t.sent;
        failed += t.failed;
        dropped += t.dropped;
        queued += t.queued;
    };
    const g = .{
        .{ "minio_notify_events_sent_total", "counter", sent },
        .{ "minio_notify_events_errors_total", "counter", failed },
        .{ "minio_notify_events_skipped_total", "counter", dropped },
        .{ "minio_notify_current_send_in_progress", "gauge", queued },
    };
    inline for (g) |m| try w.print("# TYPE {s} {s}\n{s}{{server=\"{s}\"}} {d}\n", .{ m[0], m[1], m[0], src.server, m[2] });
    try targetGroup(src, a, w, false, "minio_notify_target");
}

fn replicationGroup(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const r = src.repl orelse return;
    const s = &r.stats;
    s.mutex.lock();
    defer s.mutex.unlock();
    var sent: u64 = 0;
    var failed: u64 = 0;
    var pending: u64 = 0;
    for (s.targets.values()) |t| {
        sent += t.sent_count;
        failed += t.failed_count;
        pending += t.pending_count;
    }
    const g = .{
        .{ "minio_replication_current_active_workers", "gauge", @as(u64, @intFromBool(pending > 0)) },
        .{ "minio_replication_queued_count", "gauge", s.queued },
        .{ "minio_replication_sent_count", "counter", sent },
        .{ "minio_replication_failed_count", "counter", failed },
        .{ "minio_replication_received_count", "counter", s.received_count },
        .{ "minio_replication_received_bytes", "counter", s.received_bytes },
        .{ "minio_replication_retries_total", "counter", s.retries },
    };
    inline for (g) |m| try w.print("# TYPE {s} {s}\n{s}{{server=\"{s}\"}} {d}\n", .{ m[0], m[1], m[0], src.server, m[2] });
}

fn bucketReplication(src: *Sources, w: *Writer, bucket: []const u8) WError!void {
    const r = src.repl orelse return;
    const s = &r.stats;
    s.mutex.lock();
    defer s.mutex.unlock();
    const fams = .{
        .{ "minio_bucket_replication_total_failed_count", "counter", "failed_count" },
        .{ "minio_bucket_replication_total_failed_bytes", "counter", "failed_bytes" },
        .{ "minio_bucket_replication_sent_count", "counter", "sent_count" },
        .{ "minio_bucket_replication_sent_bytes", "counter", "sent_bytes" },
        .{ "minio_bucket_replication_pending_count", "gauge", "pending_count" },
        .{ "minio_bucket_replication_proxied_get_requests_total", "counter", "" },
    };
    inline for (fams) |f| {
        try w.print("# TYPE {s} {s}\n", .{ f[0], f[1] });
        for (s.targets.values()) |t| {
            if (!std.mem.eql(u8, t.bucket, bucket)) continue;
            const v: u64 = if (f[2].len == 0) 0 else @field(t, f[2]);
            try w.print("{s}{{bucket=\"{s}\",target_arn=\"{s}\",server=\"{s}\"}} {d}\n", .{ f[0], bucket, t.arn, src.server, v });
        }
    }
    try w.print("# TYPE minio_bucket_replication_latency_ms gauge\n", .{});
    for (s.targets.values()) |t| if (std.mem.eql(u8, t.bucket, bucket))
        try w.print("minio_bucket_replication_latency_ms{{bucket=\"{s}\",target_arn=\"{s}\",server=\"{s}\"}} {d}\n", .{ bucket, t.arn, src.server, t.latency_ns / std.time.ns_per_ms });
}

fn scanner(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    const up_ns = std.time.nanoTimestamp() - src.started_ns;
    try w.print("# TYPE minio_scanner_last_activity_seconds gauge\nminio_scanner_last_activity_seconds{{server=\"{s}\"}} {d}\n", .{ src.server, @divTrunc(@max(up_ns, 0), std.time.ns_per_s) });
    try w.print("# TYPE minio_scanner_bucket_scans_finished counter\nminio_scanner_bucket_scans_finished{{server=\"{s}\"}} 0\n", .{src.server});
}

/// zkfsm-only series under the root: OTLP exporter and access-log delivery health.
fn zkfsmExtras(src: *Sources, _: std.mem.Allocator, w: *Writer) WError!void {
    if (src.exporter) |e| {
        const sigs = [_][]const u8{ "traces", "logs", "metrics" };
        inline for (.{ .{ "zkfsm_otlp_exported_total", "exported" }, .{ "zkfsm_otlp_failed_total", "failed" }, .{ "zkfsm_otlp_dropped_total", "dropped" } }) |f| {
            try w.print("# TYPE {s} counter\n", .{f[0]});
            for (sigs, 0..) |sg, i| try w.print("{s}{{signal=\"{s}\"}} {d}\n", .{ f[0], sg, @field(e.stats, f[1])[i].load(.monotonic) });
        }
    }
    if (src.access_log) |f| try f(src.access_log_ctx.?, w);
}

test "group selection by path prefix" {
    try std.testing.expect(under("/system/drive", ""));
    try std.testing.expect(under("/system/drive", "/system"));
    try std.testing.expect(under("/system/drive", "/system/drive/"));
    try std.testing.expect(!under("/system/drive", "/sys"));
    try std.testing.expect(!under("/system/drive", "/api"));
    try std.testing.expect(under("/cluster/usage/buckets", "/cluster/usage"));
}

test "jwt verification" {
    const gpa = std.testing.allocator;
    var store: iam.Store = undefined;
    var mem: iam.store.MemoryPersistence = .{ .gpa = gpa };
    defer mem.deinit();
    try store.open(gpa, mem.persistence(), .{ .root_access_key = "admin", .root_secret = "secret123" });
    defer store.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const enc = std.base64.url_safe_no_pad.Encoder;
    const h = "{\"alg\":\"HS512\",\"typ\":\"JWT\"}";
    const p = "{\"exp\":4102444800,\"sub\":\"admin\",\"iss\":\"prometheus\"}";
    var hb: [64]u8 = undefined;
    var pb: [128]u8 = undefined;
    const signed = try std.fmt.allocPrint(a, "{s}.{s}", .{ enc.encode(&hb, h), enc.encode(&pb, p) });
    var mac: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&mac, signed, "secret123");
    var sb: [128]u8 = undefined;
    const tok = try std.fmt.allocPrint(a, "{s}.{s}", .{ signed, enc.encode(&sb, &mac) });
    try std.testing.expectEqualStrings("admin", verifyJwt(a, tok, &store).?.sub);
    std.crypto.auth.hmac.sha2.HmacSha512.create(&mac, signed, "wrong-secret");
    const bad = try std.fmt.allocPrint(a, "{s}.{s}", .{ signed, enc.encode(&sb, &mac) });
    try std.testing.expect(verifyJwt(a, bad, &store) == null);
    try std.testing.expect(verifyJwt(a, "x.y", &store) == null);
}
