//! Per-node reports: this node's drives (state and space), scanner counters, and
//! lock table, built locally or fetched from peers, then merged into cluster views.
const std = @import("std");
const placement = @import("../placement/root.zig");
const heal = @import("../heal/root.zig");
const root = @import("root.zig");

const Allocator = std.mem.Allocator;
const Ops = root.Ops;

pub const DriveRow = struct {
    pool: u32,
    set: u32,
    index: u32,
    state: []const u8,
    total: u64 = 0,
    used: u64 = 0,
    avail: u64 = 0,
    healing: bool = false,
};

pub const ScanRow = struct {
    passes: u64 = 0,
    running_since_ms: i64 = 0,
    entries: u64 = 0,
    keys_checked: u64 = 0,
    repaired: u64 = 0,
    completed_ms: []const i64 = &.{},
    /// "pool N set M" of sets with a pass in progress.
    active: []const []const u8 = &.{},
};

pub const LockRow = struct { resource: []const u8, uid: u64, since_ms: i64, expires_ms: i64 };

pub const Report = struct {
    node: u16 = 0,
    online: bool = true,
    uptime_s: i64 = 0,
    version: []const u8 = root.version,
    drives: []const DriveRow = &.{},
    scanner: ScanRow = .{},
    locks: []const LockRow = &.{},
    /// Lock uids this node acquired (it is their owner).
    held: []const u64 = &.{},
};

/// Probes one local drive's identity; offline when taken out of service.
pub fn driveState(drives: *placement.DriveSet, i: usize) []const u8 {
    if (!drives.drives[i].online.load(.acquire)) return "offline";
    return switch (drives.probe(i)) {
        .ok => "ok",
        .unformatted => "unformatted",
        .foreign => "corrupt",
        .inaccessible => "offline",
    };
}

/// Capacity of the filesystem holding `path`: total, used, available bytes.
pub fn space(path: []const u8) [3]u64 {
    var dir = std.fs.cwd().openDir(path, .{}) catch return .{ 0, 0, 0 };
    defer dir.close();
    // struct statfs on 64-bit Linux: type, bsize, blocks, bfree, bavail, ..., frsize at word 9.
    var st: [16]u64 = @splat(0);
    if (std.os.linux.E.init(std.os.linux.syscall2(.fstatfs, @intCast(dir.fd), @intFromPtr(&st))) != .SUCCESS) return .{ 0, 0, 0 };
    const unit = if (st[9] != 0) st[9] else st[1];
    const total = st[2] *| unit;
    return .{ total, (st[2] -| st[3]) *| unit, st[4] *| unit };
}

/// State of `key` on drive `i`: ok, missing, or offline.
pub fn keyState(drives: *placement.DriveSet, i: usize, key: placement.PhysicalKey) []const u8 {
    const h = drives.acquire(i) orelse return "offline";
    defer drives.release(i);
    _ = h.store().stat(key) catch |e| return if (e == error.NotFound) "missing" else "offline";
    return "ok";
}

pub fn holdsKey(drives: *placement.DriveSet, key: placement.PhysicalKey) bool {
    var pbuf: [placement.max_drives]u8 = undefined;
    for (drives.placed(key, &pbuf)) |d| {
        if (std.mem.eql(u8, keyState(drives, d, key), "ok")) return true;
    }
    return false;
}

/// This node's own report.
pub fn local(o: *Ops, a: Allocator) error{OutOfMemory}!Report {
    var drives: std.ArrayList(DriveRow) = .empty;
    var sc: ScanRow = .{};
    var active: std.ArrayList([]const u8) = .empty;
    var best: ?*heal.Healer = null;
    for (try o.sets(a)) |s| {
        for (s.drives.drives, 0..) |*d, i| {
            if (!s.drives.isLocal(i)) continue;
            const sp = space(d.path);
            try drives.append(a, .{
                .pool = @intCast(s.pool),
                .set = @intCast(s.set),
                .index = @intCast(i),
                .state = driveState(s.drives, i),
                .total = sp[0],
                .used = sp[1],
                .avail = sp[2],
                .healing = d.fresh.load(.acquire),
            });
        }
        const st = &s.healer.stats;
        const passes = st.passes.load(.acquire);
        sc.entries += st.entries.load(.monotonic);
        sc.keys_checked += st.keys_checked.load(.monotonic);
        sc.repaired += st.repaired.load(.monotonic);
        const since = st.running_since_ms.load(.acquire);
        if (since != 0) {
            if (sc.running_since_ms == 0 or since < sc.running_since_ms) sc.running_since_ms = since;
            try active.append(a, try std.fmt.allocPrint(a, "pool {d} set {d}", .{ s.pool + 1, s.set + 1 }));
        }
        if (best == null or passes > best.?.stats.passes.load(.acquire)) best = s.healer;
        sc.passes = @max(sc.passes, passes);
    }
    if (best) |h| {
        var buf: [heal.stats.ring_len]i64 = undefined;
        sc.completed_ms = try a.dupe(i64, h.stats.completed(&buf));
    }
    sc.active = active.items;
    var r: Report = .{
        .node = o.selfNode(),
        .uptime_s = std.time.timestamp() - o.started_s,
        .drives = drives.items,
        .scanner = sc,
    };
    if (o.node) |n| {
        var locks: std.ArrayList(LockRow) = .empty;
        {
            n.table.mutex.lock();
            defer n.table.mutex.unlock();
            const now = std.time.milliTimestamp();
            var it = n.table.entries.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.expires_ms <= now) continue;
                try locks.append(a, .{ .resource = try a.dupe(u8, e.key_ptr.*), .uid = e.value_ptr.uid, .since_ms = e.value_ptr.since_ms, .expires_ms = e.value_ptr.expires_ms });
            }
        }
        var held: std.ArrayList(u64) = .empty;
        {
            n.locks.mutex.lock();
            defer n.locks.mutex.unlock();
            var it = n.locks.held.keyIterator();
            while (it.next()) |k| try held.append(a, k.*);
        }
        r.locks = locks.items;
        r.held = held.items;
    }
    return r;
}

pub fn encode(a: Allocator, r: Report) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(a, r, .{});
}

pub fn decode(a: Allocator, bytes: []const u8) ?Report {
    return std.json.parseFromSliceLeaky(Report, a, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null;
}

/// One report per node, in node order; unreachable peers come back offline.
pub fn gather(o: *Ops, a: Allocator) error{OutOfMemory}![]Report {
    const out = try a.alloc(Report, o.nodeCount());
    for (out, 0..) |*r, i| {
        if (i == o.selfNode()) {
            r.* = try local(o, a);
            continue;
        }
        r.* = (try root.peer.fetchReport(o, a, @intCast(i))) orelse .{ .node = @intCast(i), .online = false };
    }
    return out;
}

/// The report row for a drive slot, if its node answered.
pub fn findDrive(reports: []const Report, node: u16, pool: usize, set: usize, index: usize) ?DriveRow {
    if (node >= reports.len or !reports[node].online) return null;
    for (reports[node].drives) |d| if (d.pool == pool and d.set == set and d.index == index) return d;
    return null;
}

test "report json round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r: Report = .{
        .node = 2,
        .uptime_s = 42,
        .drives = &.{.{ .pool = 0, .set = 1, .index = 3, .state = "ok", .total = 100, .used = 40, .avail = 60 }},
        .scanner = .{ .passes = 5, .completed_ms = &.{ 1, 2 } },
        .locks = &.{.{ .resource = "obj/b/k", .uid = 7, .since_ms = 1000, .expires_ms = 31000 }},
        .held = &.{7},
    };
    const back = decode(a, try encode(a, r)).?;
    try std.testing.expectEqual(@as(u16, 2), back.node);
    try std.testing.expectEqualStrings("ok", back.drives[0].state);
    try std.testing.expectEqual(@as(u32, 3), back.drives[0].index);
    try std.testing.expectEqualStrings("obj/b/k", back.locks[0].resource);
    try std.testing.expectEqual(@as(u64, 7), back.held[0]);
    try std.testing.expect(findDrive(&.{back}, 0, 0, 1, 3) != null);
    try std.testing.expect(findDrive(&.{back}, 0, 0, 1, 2) == null);
    try std.testing.expect(findDrive(&.{back}, 1, 0, 1, 3) == null);
    try std.testing.expect(decode(a, "nope") == null);
}
