//! heal: HealthScanner → HealPlanner → HealExecutor, as a background loop or one-shot pass.
const std = @import("std");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");

pub const scanner = @import("scanner.zig");
pub const planner = @import("planner.zig");
pub const executor = @import("executor.zig");

pub const Config = scanner.Config;
pub const Report = executor.Report;

pub const Error = error{ OutOfMemory, Stopped };

pub const Healer = struct {
    gpa: std.mem.Allocator,
    drives: *placement.DriveSet,
    strategy: protection.Strategy,
    cfg: Config,
    /// One pass at a time, whether triggered by the loop or an admin.
    pass_lock: std.Thread.Mutex = .{},
    stop_ev: std.Thread.ResetEvent = .{},
    thread: ?std.Thread = null,
    /// Set to run the next pass early (a peer came back, a drive was replaced).
    wake_flag: std.atomic.Value(bool) = .init(false),
    /// Cluster sets: whether this node verifies keys now (the set's heal leader, or
    /// it holds a fresh drive). Null: always.
    leader: ?Leader = null,

    pub const Leader = struct {
        ctx: *anyopaque,
        func: *const fn (ctx: *anyopaque, drives: *placement.DriveSet) bool,
    };

    pub fn init(gpa: std.mem.Allocator, drives: *placement.DriveSet, strategy: protection.Strategy, cfg: Config) Healer {
        return .{ .gpa = gpa, .drives = drives, .strategy = strategy, .cfg = cfg };
    }

    /// One full scan → plan → execute pass. This is the admin trigger.
    pub fn runOnce(self: *Healer) Error!Report {
        self.pass_lock.lock();
        defer self.pass_lock.unlock();
        var throttle: scanner.Throttle = .{ .per_sec = self.cfg.rate_per_sec, .stop = &self.stop_ev };
        var cfg = self.cfg;
        if (self.leader) |l| cfg.walk_keys = self.hasFresh() or l.func(l.ctx, self.drives);
        var sc: scanner.HealthScanner = .{ .gpa = self.gpa, .drives = self.drives, .throttle = &throttle, .cfg = cfg };
        var scan = try sc.scan();
        defer scan.deinit(self.gpa);
        var plan = try planner.plan(self.gpa, self.drives, &scan);
        defer plan.deinit(self.gpa);
        var report: Report = .{ .entries_scanned = scan.entries };
        var ex: executor.HealExecutor = .{ .drives = self.drives, .strategy = self.strategy, .throttle = &throttle };
        try ex.run(&plan, &report);
        if (report.fullyRedundant() and cfg.walk_keys) {
            for (self.drives.drives) |*d| d.fresh.store(false, .release);
        }
        return report;
    }

    fn hasFresh(self: *Healer) bool {
        for (self.drives.drives) |*d| if (d.fresh.load(.acquire)) return true;
        return false;
    }

    /// Asks the background loop for a pass as soon as possible.
    pub fn wake(self: *Healer) void {
        self.wake_flag.store(true, .release);
    }

    /// Starts the background loop; a pass runs at once if a drive is fresh.
    /// `interval_ns` 0 runs only woken passes.
    pub fn start(self: *Healer, interval_ns: u64) error{SpawnFailed}!void {
        self.stop_ev.reset();
        self.thread = std.Thread.spawn(.{}, loop, .{ self, interval_ns }) catch return error.SpawnFailed;
    }

    pub fn stop(self: *Healer) void {
        self.stop_ev.set();
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    fn loop(self: *Healer, interval_ns: u64) void {
        var first = true;
        while (true) {
            const fresh = for (self.drives.drives) |*d| {
                if (d.fresh.load(.acquire)) break true;
            } else false;
            if (!(first and fresh)) {
                // Sleep in short steps so a wake request is served promptly. Interval 0:
                // no periodic passes; woken ones only, retried while a drive is fresh.
                const limit: u64 = if (interval_ns > 0) interval_ns else if (fresh) fresh_retry_ns else std.math.maxInt(u64);
                var waited: u64 = 0;
                while (waited < limit and !self.wake_flag.load(.acquire)) : (waited += wake_step_ns) {
                    self.stop_ev.timedWait(@min(wake_step_ns, limit - waited)) catch {};
                    if (self.stop_ev.isSet()) return;
                }
            }
            self.wake_flag.store(false, .release);
            first = false;
            const r = self.runOnce() catch |e| {
                if (e == error.Stopped) return;
                std.log.err("heal pass failed: {t}", .{e});
                continue;
            };
            logReport(r);
        }
    }
};

const wake_step_ns = std.time.ns_per_s;
const fresh_retry_ns = 30 * std.time.ns_per_s;

pub fn logReport(r: Report) void {
    std.log.info(
        "heal: scanned={d} checked={d} repaired={d} unrepaired={d} lost={d} temps={d} drives reinit={d} quarantined={d} restored={d}",
        .{ r.entries_scanned, r.keys_checked, r.replicas_repaired, r.replicas_unrepaired, r.keys_lost, r.temps_removed, r.drives_reinit, r.drives_quarantined, r.drives_restored },
    );
}

test "heal pass restores a wiped drive, fixes bitrot, and sweeps stale temps" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [4][std.fs.max_path_bytes]u8 = undefined;
    var paths: [4][]const u8 = undefined;
    var nb: [4]u8 = undefined;
    for (0..4) |i| {
        const name = try std.fmt.bufPrint(&nb, "d{d}", .{i});
        try tmp.dir.makePath(name);
        paths[i] = try tmp.dir.realpath(name, &bufs[i]);
    }
    var set = try placement.DriveSet.open(gpa, &paths, .{ .replica = 2 });
    defer set.deinit();
    var stores: protection.Stores = .{};
    const strat = try protection.Strategy.init(gpa, &set, &stores);
    const b = strat.backend();

    var keys: [20]iface.PhysicalKey = undefined;
    for (&keys, 0..) |*k, i| {
        k.* = .{ .space = .data, .hex = undefined };
        _ = try std.fmt.bufPrint(&k.hex, "{x:0>32}", .{i + 1});
        var src: std.Io.Reader = .fixed("payload-bytes");
        _ = try b.put(k.*, &src, .{});
    }
    try b.putRecord(.{ .space = .system, .hex = [_]u8{'0'} ** 32 }, "catalog");

    var healer = Healer.init(gpa, &set, strat, .{ .rate_per_sec = 0, .temp_grace_ns = 0 });
    const clean = try healer.runOnce();
    try std.testing.expectEqual(@as(u64, 21), clean.keys_checked);
    try std.testing.expectEqual(@as(u64, 0), clean.replicas_repaired);

    // Wipe drive 1, flip a byte in some replica on drive 2, leave a temp file on drive 3.
    try tmp.dir.deleteTree("d1");
    var flipped = false;
    for (keys) |k| {
        var pbuf: [placement.max_drives]u8 = undefined;
        const pl = set.placed(k, &pbuf);
        if (flipped or (pl[0] != 2 and pl[1] != 2) or pl[0] == 1 or pl[1] == 1) continue;
        var kb: [64]u8 = undefined;
        var pb: [128]u8 = undefined;
        const p = try std.fmt.bufPrint(&pb, "d2/{s}", .{try iface.local.keyPath(k, @ptrCast(&kb))});
        var f = try tmp.dir.openFile(p, .{ .mode = .read_write });
        defer f.close();
        try f.pwriteAll("X", protection.shard.header_len + 4);
        flipped = true;
    }
    try std.testing.expect(flipped);
    try tmp.dir.writeFile(.{ .sub_path = "d3/tmp/0123.tmp", .data = "partial" });

    const r = try healer.runOnce();
    try std.testing.expectEqual(@as(u32, 1), r.drives_reinit);
    try std.testing.expect(r.replicas_repaired >= 2);
    try std.testing.expectEqual(@as(u64, 1), r.temps_removed);
    try std.testing.expect(r.fullyRedundant());

    const after = try healer.runOnce();
    try std.testing.expectEqual(@as(u64, 0), after.replicas_repaired);
    try std.testing.expectEqual(@as(u64, 21), after.keys_checked);

    // Background loop starts and stops cleanly.
    try healer.start(std.time.ns_per_s);
    healer.stop();
}

test {
    _ = scanner;
    _ = planner;
    _ = executor;
}
