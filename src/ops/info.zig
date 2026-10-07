//! `mc admin info` (madmin InfoMessage) and `mc admin heal` background status
//! (madmin BgHealState), built from live drive, node, and object service state.
const std = @import("std");
const backend = @import("../backend/root.zig");
const object = @import("../object/root.zig");
const admin = @import("../admin/root.zig");
const root = @import("root.zig");
const report = @import("report.zig");
const fmt = @import("fmt.zig");

const Allocator = std.mem.Allocator;
const Ops = root.Ops;
const Ctx = admin.api.Ctx;
const Response = admin.api.Response;
const Error = admin.api.Error;

pub const Disk = struct {
    endpoint: []const u8,
    path: []const u8,
    state: []const u8,
    healing: bool = false,
    major: u32 = 0,
    minor: u32 = 0,
    totalspace: u64 = 0,
    usedspace: u64 = 0,
    availspace: u64 = 0,
    used_inodes: u64 = 0,
    local: bool = false,
    pool_index: usize,
    set_index: usize,
    disk_index: usize,
};

/// Every drive of the deployment, in pool/set/slot order, with its owning node.
const Slot = struct { node: u16, disk: Disk };

fn drives(o: *Ops, a: Allocator, reports: []const report.Report) Error![]Slot {
    var out: std.ArrayList(Slot) = .empty;
    for (try o.sets(a)) |s| for (0..s.drives.count()) |i| {
        const node = o.driveNode(s, i);
        const row = report.findDrive(reports, node, s.pool, s.set, i);
        try out.append(a, .{ .node = node, .disk = .{
            .endpoint = o.driveEndpoint(s, i),
            .path = o.drivePath(s, i),
            .state = if (row) |r| r.state else "offline",
            .healing = if (row) |r| r.healing else false,
            .totalspace = if (row) |r| r.total else 0,
            .usedspace = if (row) |r| r.used else 0,
            .availspace = if (row) |r| r.avail else 0,
            .local = node == o.selfNode(),
            .pool_index = s.pool,
            .set_index = s.set,
            .disk_index = i,
        } });
    };
    return out.items;
}

const SetInfo = struct {
    id: usize,
    rawUsage: u64 = 0,
    rawCapacity: u64 = 0,
    usage: u64 = 0,
    objectsCount: u64 = 0,
    versionsCount: u64 = 0,
    deleteMarkersCount: u64 = 0,
    healDisks: usize = 0,
};

const Server = struct {
    state: []const u8,
    endpoint: []const u8,
    scheme: []const u8 = "http",
    uptime: i64 = 0,
    version: []const u8 = "",
    commitID: []const u8 = "",
    network: std.json.ArrayHashMap([]const u8) = .{},
    drives: []const Disk = &.{},
    poolNumber: ?usize = null,
    poolNumbers: []const usize = &.{},
    mem_stats: struct {} = .{},
    edition: []const u8 = "",
    is_leader: bool = false,
    ilm_expiry_in_progress: bool = false,
};

const Count = struct { count: u64 };

/// Records stored in a set (objects, versions, uploads), counted from its listing.
fn recordCount(s: root.SetRef) u64 {
    const C = struct {
        n: u64 = 0,
        fn f(ctx: *anyopaque, _: backend.PhysicalKey) backend.Error!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.n += 1;
        }
    };
    var c: C = .{};
    s.strategy.backend().list(.record, .{ .ctx = &c, .func = C.f }) catch {};
    return c.n;
}

pub fn serverInfo(o: *Ops, c: *const Ctx) Error!Response {
    const a = c.a;
    const reports = try report.gather(o, a);
    const slots = try drives(o, a, reports);
    const pools = o.poolCount();
    const all_sets = try o.sets(a);

    var online: usize = 0;
    for (slots) |s| online += @intFromBool(std.mem.eql(u8, s.disk.state, "ok"));
    const total_sets = try a.alloc(usize, pools);
    const per_set = try a.alloc(usize, pools);
    @memset(total_sets, 0);
    @memset(per_set, 0);
    for (all_sets) |s| {
        total_sets[s.pool] += 1;
        per_set[s.pool] = s.drives.count();
    }

    var servers: std.ArrayList(Server) = .empty;
    for (reports, 0..) |r, i| {
        var mine: std.ArrayList(Disk) = .empty;
        var pool_set: std.ArrayList(usize) = .empty;
        for (slots) |s| if (s.node == i) {
            try mine.append(a, s.disk);
            if (std.mem.indexOfScalar(usize, pool_set.items, s.disk.pool_index) == null) try pool_set.append(a, s.disk.pool_index);
        };
        var srv: Server = .{
            .state = if (r.online) "online" else "offline",
            .endpoint = o.nodeName(i),
            .uptime = if (r.online) r.uptime_s else 0,
            .version = if (r.online) r.version else "",
            .drives = mine.items,
            .poolNumbers = pool_set.items,
            .poolNumber = if (pool_set.items.len == 1) pool_set.items[0] else null,
            .is_leader = i == leader(o),
        };
        for (0..o.nodeCount()) |j| if (j != i) {
            try srv.network.map.put(a, o.nodeName(j), if (reports[j].online) "online" else "offline");
        };
        try servers.append(a, srv);
    }

    var pool_map: std.json.ArrayHashMap(std.json.ArrayHashMap(SetInfo)) = .{};
    for (all_sets) |s| {
        const pk = try std.fmt.allocPrint(a, "{d}", .{s.pool});
        const gop = try pool_map.map.getOrPut(a, pk);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        var si: SetInfo = .{ .id = s.set, .objectsCount = recordCount(s) };
        for (slots) |d| if (d.disk.pool_index == s.pool and d.disk.set_index == s.set) {
            si.rawUsage += d.disk.usedspace;
            si.rawCapacity += d.disk.totalspace;
            si.healDisks += @intFromBool(d.disk.healing);
        };
        si.usage = si.rawUsage;
        try gop.value_ptr.map.put(a, try std.fmt.allocPrint(a, "{d}", .{s.set}), si);
    }

    const PoolStatus = struct { pool: usize, status: []const u8 };
    var pool_status: std.ArrayList(PoolStatus) = .empty;
    for (0..pools) |p| try pool_status.append(a, .{ .pool = p, .status = o.poolState(p) });

    var buckets: u64 = 0;
    var objects: u64 = 0;
    var size: u64 = 0;
    for (o.svc.listBuckets(a) catch &.{}) |b| {
        buckets += 1;
        const u = object.quota.usage(o.svc, b.name) catch continue;
        objects += u.objects;
        size += u.bytes;
    }
    const parity = fmt.parity(o.profile());
    var dep_buf: [36]u8 = undefined;
    return c.json(.{
        .mode = mode(o),
        .region = c.env.region,
        .deploymentID = try a.dupe(u8, fmt.uuid(&dep_buf, deploymentId(o))),
        .buckets = Count{ .count = buckets },
        .objects = Count{ .count = objects },
        .usage = .{ .size = size },
        .services = .{},
        .backend = .{
            .backendType = "Erasure",
            .onlineDisks = online,
            .offlineDisks = slots.len - online,
            .standardSCParity = parity,
            .rrSCParity = parity,
            .totalSets = total_sets,
            .totalDrivesPerSet = per_set,
        },
        .servers = servers.items,
        .pools = pool_map,
        .poolsStatus = pool_status.items,
    });
}

fn mode(o: *Ops) []const u8 {
    if (o.node) |n| return if (n.ready()) "online" else "initializing";
    return "online";
}

fn leader(o: *Ops) usize {
    for (0..o.nodeCount()) |i| if (o.nodeOnline(i)) return i;
    return 0;
}

/// The deployment's identity: the cluster deployment id, else the drive set id.
fn deploymentId(o: *Ops) [16]u8 {
    if (o.node) |n| return n.deployment;
    if (o.local) |l| return l.drives.set.bytes;
    return @splat(0);
}

const SetStatus = struct {
    id: []const u8,
    pool_index: usize,
    set_index: usize,
    heal_status: []const u8,
    heal_priority: []const u8 = "",
    total_objects: u64,
    disks: []const Disk,
};

pub fn bgHealStatus(o: *Ops, c: *const Ctx) Error!Response {
    const a = c.a;
    const reports = try report.gather(o, a);
    const slots = try drives(o, a, reports);
    var offline: std.ArrayList([]const u8) = .empty;
    var scanned: u64 = 0;
    for (reports, 0..) |r, i| {
        if (!r.online) try offline.append(a, o.nodeName(i)) else scanned += r.scanner.entries;
    }
    var heal_disks: std.ArrayList([]const u8) = .empty;
    for (slots) |s| if (s.disk.healing) try heal_disks.append(a, s.disk.endpoint);
    var sets: std.ArrayList(SetStatus) = .empty;
    for (try o.sets(a)) |s| {
        var disks: std.ArrayList(Disk) = .empty;
        for (slots) |d| if (d.disk.pool_index == s.pool and d.disk.set_index == s.set) try disks.append(a, d.disk);
        try sets.append(a, .{
            .id = try std.fmt.allocPrint(a, "{d}-{d}", .{ s.pool, s.set }),
            .pool_index = s.pool,
            .set_index = s.set,
            .heal_status = if (s.healer.stats.running_since_ms.load(.acquire) != 0) "running" else "idle",
            .total_objects = recordCount(s),
            .disks = disks.items,
        });
    }
    const parity = fmt.parity(o.profile());
    var sc: std.json.ArrayHashMap(u8) = .{};
    try sc.map.put(a, "STANDARD", parity);
    try sc.map.put(a, "REDUCED_REDUNDANCY", parity);
    return c.json(.{
        .offline_nodes = offline.items,
        .ScannedItemsCount = scanned,
        .HealDisks = heal_disks.items,
        .sets = sets.items,
        .mrf = .{},
        .sc_parity = sc,
    });
}
