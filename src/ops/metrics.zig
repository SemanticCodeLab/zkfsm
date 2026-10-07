//! Realtime scanner metrics (`mc admin scanner status`, a stream of madmin
//! RealtimeMetrics lines) and the cluster lock view (`mc support top locks`).
const std = @import("std");
const admin = @import("../admin/root.zig");
const s3 = @import("../s3/root.zig");
const root = @import("root.zig");
const report = @import("report.zig");
const fmt = @import("fmt.zig");

const Allocator = std.mem.Allocator;
const Ops = root.Ops;
const Ctx = admin.api.Ctx;
const ConnError = s3.handler.ConnError;

/// madmin MetricType bit for scanner metrics.
pub const metric_scanner: u64 = 1;
const default_interval_ns = 3 * std.time.ns_per_s;
const min_interval_ns = 200 * std.time.ns_per_ms;

/// Merges node reports into one madmin ScannerMetrics object.
pub fn scannerJson(a: Allocator, reports: []const report.Report, buckets: usize, now_ms: i64) error{OutOfMemory}![]u8 {
    var passes: u64 = 0;
    var since: i64 = 0;
    var entries: u64 = 0;
    var checked: u64 = 0;
    var repaired: u64 = 0;
    var completed: []const i64 = &.{};
    var active: std.ArrayList([]const u8) = .empty;
    for (reports) |r| {
        if (!r.online) continue;
        const sc = r.scanner;
        entries += sc.entries;
        checked += sc.keys_checked;
        repaired += sc.repaired;
        if (sc.passes >= passes) {
            passes = sc.passes;
            if (sc.completed_ms.len >= completed.len) completed = sc.completed_ms;
        }
        if (sc.running_since_ms != 0 and (since == 0 or sc.running_since_ms < since)) since = sc.running_since_ms;
        for (sc.active) |p| try active.append(a, p);
    }
    var times: std.ArrayList([]const u8) = .empty;
    for (completed) |ms| try times.append(a, try fmt.timeAlloc(a, ms));
    var ops: std.json.ArrayHashMap(u64) = .{};
    try ops.map.put(a, "ScanObject", entries);
    try ops.map.put(a, "HealCheck", checked);
    try ops.map.put(a, "HealObject", repaired);
    const started = if (since != 0) since else if (completed.len > 0) completed[completed.len - 1] else 0;
    return std.json.Stringify.valueAlloc(a, .{
        .collected = try fmt.timeAlloc(a, now_ms),
        .current_cycle = passes + @intFromBool(since != 0),
        .current_started = try fmt.timeAlloc(a, started),
        .cycle_complete_times = times.items,
        .ongoing_buckets = if (since != 0) buckets else 0,
        .life_time_ops = ops,
        .last_minute = .{},
        .active = active.items,
    }, .{});
}

/// Streams samples until `n` were sent (0: until the client goes away).
pub fn stream(o: *Ops, c: *const Ctx, sc: *s3.handler.Ctx) ConnError!void {
    const n = std.fmt.parseInt(u64, try c.param("n") orelse "0", 10) catch 0;
    const types = std.fmt.parseInt(u64, try c.param("types") orelse "0", 10) catch 0;
    const interval = @max(min_interval_ns, fmt.goDuration(try c.param("interval") orelse "") orelse default_interval_ns);
    var wbuf: [16 * 1024]u8 = undefined;
    var bw = sc.req.respondStreaming(&wbuf, .{ .respond_options = .{ .extra_headers = &.{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-amz-request-id", .value = &sc.request_id },
    } } }) catch return error.WriteFailed;
    var sent: u64 = 0;
    while (true) {
        var arena_state = std.heap.ArenaAllocator.init(o.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        sent += 1;
        const final = n != 0 and sent >= n;
        const line = try sample(o, a, types, final);
        bw.writer.writeAll(line) catch return error.WriteFailed;
        bw.writer.writeByte('\n') catch return error.WriteFailed;
        bw.flush() catch return error.WriteFailed;
        if (final) break;
        if (o.server) |s| if (s.stopping.load(.acquire)) break;
        std.Thread.sleep(interval);
    }
    bw.end() catch return error.WriteFailed;
}

fn sample(o: *Ops, a: Allocator, types: u64, final: bool) error{OutOfMemory}![]u8 {
    const reports = try report.gather(o, a);
    var hosts: std.ArrayList([]const u8) = .empty;
    for (reports, 0..) |r, i| if (r.online) try hosts.append(a, o.nodeName(i));
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    const hosts_json = try std.json.Stringify.valueAlloc(a, hosts.items, .{});
    w.print("{{\"hosts\":{s},\"aggregated\":{{", .{hosts_json}) catch return error.OutOfMemory;
    if (types == 0 or types & metric_scanner != 0) {
        const buckets = (o.svc.listBuckets(a) catch &.{}).len;
        w.print("\"scanner\":{s}", .{try scannerJson(a, reports, buckets, std.time.milliTimestamp())}) catch return error.OutOfMemory;
    }
    w.print("}},\"final\":{}}}", .{final}) catch return error.OutOfMemory;
    return out.written();
}

pub const LockEntry = struct {
    time: []const u8,
    elapsed: i64,
    resource: []const u8,
    type: []const u8 = "WRITE",
    source: []const u8 = "",
    serverlist: []const []const u8,
    owner: []const u8,
    id: []const u8,
    quorum: usize,
};

const Group = struct { resource: []const u8, uid: u64, since_ms: i64, servers: std.ArrayList([]const u8) = .empty };

/// Lease table rows grouped into locks: one per (resource, uid), oldest first.
pub fn lockEntries(a: Allocator, reports: []const report.Report, names: []const []const u8, now_ms: i64) error{OutOfMemory}![]LockEntry {
    var groups: std.ArrayList(Group) = .empty;
    for (reports, 0..) |r, i| {
        if (!r.online) continue;
        for (r.locks) |l| {
            const g = for (groups.items) |*g| {
                if (g.uid == l.uid and std.mem.eql(u8, g.resource, l.resource)) break g;
            } else blk: {
                try groups.append(a, .{ .resource = l.resource, .uid = l.uid, .since_ms = l.since_ms });
                break :blk &groups.items[groups.items.len - 1];
            };
            g.since_ms = @min(g.since_ms, l.since_ms);
            try g.servers.append(a, names[i]);
        }
    }
    const Less = struct {
        fn f(_: void, x: Group, y: Group) bool {
            return x.since_ms < y.since_ms;
        }
    };
    std.mem.sort(Group, groups.items, {}, Less.f);
    const out = try a.alloc(LockEntry, groups.items.len);
    for (groups.items, out) |g, *e| {
        var owner: []const u8 = "";
        for (reports, 0..) |r, i| {
            if (std.mem.indexOfScalar(u64, r.held, g.uid) != null) owner = names[i];
        }
        e.* = .{
            .time = try fmt.timeAlloc(a, g.since_ms),
            .elapsed = (now_ms - g.since_ms) * std.time.ns_per_ms,
            .resource = g.resource,
            .serverlist = g.servers.items,
            .owner = owner,
            .id = try std.fmt.allocPrint(a, "{x:0>16}", .{g.uid}),
            .quorum = names.len / 2 + 1,
        };
    }
    return out;
}

pub fn topLocks(o: *Ops, c: *const Ctx) admin.api.Error!admin.api.Response {
    const count = std.fmt.parseInt(usize, try c.param("count") orelse "10", 10) catch 10;
    const stale = std.mem.eql(u8, try c.param("stale") orelse "false", "true");
    const reports = try report.gather(o, c.a);
    const names = try c.a.alloc([]const u8, o.nodeCount());
    for (names, 0..) |*nm, i| nm.* = o.nodeName(i);
    const all = try lockEntries(c.a, reports, names, std.time.milliTimestamp());
    var out: std.ArrayList(LockEntry) = .empty;
    for (all) |e| {
        if (!stale and e.quorum > e.serverlist.len) continue;
        if (out.items.len >= count) break;
        try out.append(c.a, e);
    }
    return .{ .body = try std.json.Stringify.valueAlloc(c.a, out.items, .{}) };
}

test "lock grouping and scanner merge" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const reports = [_]report.Report{
        .{ .node = 0, .locks = &.{ .{ .resource = "obj/b/k", .uid = 9, .since_ms = 2000, .expires_ms = 9 }, .{ .resource = "catalog//", .uid = 4, .since_ms = 1000, .expires_ms = 9 } }, .held = &.{9}, .scanner = .{ .passes = 3, .entries = 10, .completed_ms = &.{ 1000, 2000, 3000 } } },
        .{ .node = 1, .locks = &.{.{ .resource = "obj/b/k", .uid = 9, .since_ms = 1500, .expires_ms = 9 }}, .scanner = .{ .passes = 2, .entries = 5, .running_since_ms = 4000, .active = &.{"pool 1 set 1"} } },
        .{ .node = 2, .online = false },
    };
    const names = [_][]const u8{ "n0:1", "n1:1", "n2:1" };
    const e = try lockEntries(a, &reports, &names, 5000);
    try std.testing.expectEqual(@as(usize, 2), e.len);
    try std.testing.expectEqualStrings("catalog//", e[0].resource);
    try std.testing.expectEqualStrings("obj/b/k", e[1].resource);
    try std.testing.expectEqual(@as(usize, 2), e[1].serverlist.len);
    try std.testing.expectEqualStrings("n0:1", e[1].owner);
    try std.testing.expectEqual(@as(i64, 3500 * std.time.ns_per_ms), e[1].elapsed);
    try std.testing.expectEqual(@as(usize, 2), e[1].quorum);

    const js = try scannerJson(a, &reports, 4, 5000);
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, js, .{});
    try std.testing.expectEqual(@as(i64, 4), v.object.get("current_cycle").?.integer);
    try std.testing.expectEqual(@as(i64, 15), v.object.get("life_time_ops").?.object.get("ScanObject").?.integer);
    try std.testing.expectEqual(@as(usize, 3), v.object.get("cycle_complete_times").?.array.items.len);
    try std.testing.expectEqual(@as(i64, 4), v.object.get("ongoing_buckets").?.integer);
}
