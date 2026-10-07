//! Pool decommission and rebalance. Every node keeps its router's pool modes in step
//! with the shared state record; one node at a time (holder of the worker lock) moves
//! keys. A drained pool is recorded as retired in every drive format, so the next
//! start accepts an endpoint list without it.
const std = @import("std");
const backend = @import("../backend/root.zig");
const cluster = @import("../cluster/root.zig");
const placement = @import("../placement/root.zig");
const state = @import("state.zig");
const mover = @import("mover.zig");

const Router = cluster.router.Router;
const Meta = state.Meta;
const Node = cluster.Node;

pub const meta_key: backend.PhysicalKey = .{ .space = .system, .hex = "7a6b66736d2d706f6f6c732d6d6574ff".* };

pub const Error = error{
    OutOfMemory,
    NoSuchPool,
    /// The request conflicts with the pool's or cluster's current state.
    Conflict,
    /// The state record could not be read or written.
    Unavailable,
};

const poll_ns = 2 * std.time.ns_per_s;
/// Peers poll the state every `poll_ns`; moves wait until all of them have seen it.
const grace_ns: i128 = 5 * std.time.ns_per_s;
const persist_ns: i128 = 2 * std.time.ns_per_s;
const max_idle_passes = 3;

pub const Manager = struct {
    gpa: std.mem.Allocator,
    node: *Node,
    /// Bytes per second for rebalance moves; 0 = unthrottled.
    rebalance_rate: u64,
    /// Same for decommission moves (ZKFSM_DECOMMISSION_MBPS); 0 by default.
    decom_rate: u64,
    stop_ev: std.Thread.ResetEvent = .{},
    wake_ev: std.Thread.ResetEvent = .{},
    thread: ?std.Thread = null,
    modes_thread: ?std.Thread = null,
    modes_ev: std.Thread.ResetEvent = .{},
    /// Job seen by this node's worker and since when (for the grace period).
    job: u64 = 0,
    job_since: i128 = 0,

    pub fn init(gpa: std.mem.Allocator, node: *Node) Manager {
        const mbps = if (std.posix.getenv("ZKFSM_REBALANCE_MBPS")) |v| std.fmt.parseInt(u64, v, 10) catch 64 else 64;
        const dm = if (std.posix.getenv("ZKFSM_DECOMMISSION_MBPS")) |v| std.fmt.parseInt(u64, v, 10) catch 0 else 0;
        return .{ .gpa = gpa, .node = node, .rebalance_rate = mbps * 1024 * 1024, .decom_rate = dm * 1024 * 1024 };
    }

    fn router(m: *Manager) *Router {
        return &m.node.router;
    }

    pub fn cmdline(m: *Manager, a: std.mem.Allocator, p: usize) error{OutOfMemory}![]const u8 {
        return state.cmdline(a, m.node.cfg.pools[p]);
    }

    /// Endpoint-list position of a pool named by its command line or 1-based number.
    pub fn findPool(m: *Manager, name: []const u8) ?usize {
        for (m.node.cfg.pools, 0..) |args, p| if (state.matches(name, args)) return p;
        const n = std.fmt.parseInt(usize, std.mem.trim(u8, name, " "), 10) catch return null;
        if (n >= 1 and n <= m.node.cfg.pools.len) return n - 1;
        return null;
    }

    pub fn bit(m: *Manager, p: usize) u64 {
        return @as(u64, 1) << @intCast(m.node.poolIndex(p));
    }

    // ---- state record ----

    /// Reads the state from every pool and keeps the highest epoch: the record moves
    /// with the system pool, and a crash mid-move may leave an older copy behind.
    pub fn loadFresh(m: *Manager, a: std.mem.Allocator) Error!Meta {
        var best: ?Meta = null;
        var reached = false;
        for (m.router().pools) |*p| {
            const bytes = Router.at(p, meta_key).getRecord(meta_key, a) catch |e| switch (e) {
                error.NotFound => {
                    reached = true;
                    continue;
                },
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            reached = true;
            const meta = Meta.decode(a, bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Corrupt => continue,
            };
            if (best == null or meta.epoch > best.?.epoch) best = meta;
        }
        if (!reached) return error.Unavailable;
        return best orelse .{};
    }

    /// Loads the state and sets pool modes; blocks until the record is readable.
    pub fn load(m: *Manager) void {
        var last_log: i64 = 0;
        while (!m.node.stop_ev.isSet()) {
            var arena = std.heap.ArenaAllocator.init(m.gpa);
            defer arena.deinit();
            if (m.loadFresh(arena.allocator())) |meta| {
                m.applyModes(meta);
                return;
            } else |_| {}
            const now = std.time.timestamp();
            if (now - last_log >= 5) {
                last_log = now;
                std.log.info("pools: waiting for the pool state record", .{});
            }
            m.node.stop_ev.timedWait(std.time.ns_per_s / 2) catch {};
        }
    }

    pub fn applyModes(m: *Manager, meta: Meta) void {
        var mm = meta;
        const r = m.router();
        for (0..r.pools.len) |p| {
            const idx = m.node.poolIndex(p);
            const mode: cluster.router.Mode = blk: {
                if (m.node.retired & m.bit(p) != 0) break :blk .retired;
                if (mm.pool(idx)) |ps| switch (ps.decom.status) {
                    .draining => break :blk .draining,
                    .complete => break :blk .retired,
                    else => {},
                };
                if (mm.rebalance.status == .started) if (mm.rebalPool(idx)) |rp| if (rp.source and !rp.done) break :blk .draining;
                break :blk .active;
            };
            if (r.mode(p) != mode) {
                std.log.info("pools: pool {d} is now {t}", .{ p + 1, mode });
                r.setMode(p, mode);
            }
        }
    }

    pub const Mutator = struct {
        ctx: *anyopaque,
        func: *const fn (ctx: *anyopaque, m: *Manager, a: std.mem.Allocator, meta: *Meta) Error!void,
    };

    /// Read-modify-write of the state under the cluster lock; peers are told to reload.
    pub fn update(m: *Manager, mut: Mutator) Error!void {
        const tok = m.node.locks.lock("pools-meta") catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Unavailable;
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var meta = m.loadFresh(a) catch |e| {
            m.node.locks.unlock(tok);
            return e;
        };
        const res = mut.func(mut.ctx, m, a, &meta);
        if (res) |_| {
            meta.epoch += 1;
            const bytes = try meta.encode(a);
            m.node.storage().putRecord(meta_key, bytes) catch |e| {
                m.node.locks.unlock(tok);
                return if (e == error.OutOfMemory) error.OutOfMemory else error.Unavailable;
            };
        } else |_| {}
        m.node.locks.unlock(tok);
        try res;
        m.applyModes(meta);
        m.node.broadcast(&.{.pools});
        m.wake_ev.set();
    }

    // ---- space ----

    pub const Usage = struct { total: u64, free: u64 };

    pub fn usage(m: *Manager, p: usize) Usage {
        const rp = &m.router().pools[p];
        return .{ .total = rp.total.load(.monotonic), .free = rp.free.load(.monotonic) };
    }

    /// Raw bytes a blob of `n` bytes takes across its set's drives.
    fn raw(m: *Manager, n: u64) u64 {
        return switch (m.node.profile) {
            .erasure => |e| n * (@as(u64, e.data) + e.parity) / @max(e.data, 1),
            .replica => |r| n * r,
            .single => n,
        };
    }

    // ---- admin operations ----

    pub fn decommissionStart(m: *Manager, p: usize) Error!void {
        const Ctx = struct {
            p: usize,
            fn f(ctx: *anyopaque, mg: *Manager, a: std.mem.Allocator, meta: *Meta) Error!void {
                const p_: usize = @as(*@This(), @ptrCast(@alignCast(ctx))).p;
                if (meta.rebalance.status == .started) return error.Conflict;
                if (mg.node.retired & mg.bit(p_) != 0) return error.Conflict;
                if (meta.draining()) |d| if (d != mg.node.poolIndex(p_)) return error.Conflict;
                var others: usize = 0;
                for (0..mg.router().pools.len) |q| {
                    if (q == p_) continue;
                    const st = if (meta.pool(mg.node.poolIndex(q))) |ps| ps.decom.status else .none;
                    if (mg.node.retired & mg.bit(q) == 0 and st != .complete and st != .draining) others += 1;
                }
                if (others == 0) return error.Conflict;
                const ps = try meta.ensure(a, mg.node.poolIndex(p_), try mg.cmdline(a, p_));
                if (ps.decom.status == .complete) return error.Conflict;
                if (ps.decom.status == .draining) return;
                const u = mg.usage(p_);
                ps.decom = .{ .status = .draining, .start_ns = @intCast(std.time.nanoTimestamp()), .total_size = u.total, .start_free = u.free };
            }
        };
        var c: Ctx = .{ .p = p };
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        std.log.info("pools: decommission of pool {d} started", .{p + 1});
    }

    pub fn decommissionCancel(m: *Manager, p: usize) Error!void {
        const Ctx = struct {
            p: usize,
            fn f(ctx: *anyopaque, mg: *Manager, a: std.mem.Allocator, meta: *Meta) Error!void {
                _ = a;
                const p_: usize = @as(*@This(), @ptrCast(@alignCast(ctx))).p;
                const ps = meta.pool(mg.node.poolIndex(p_)) orelse return error.Conflict;
                if (ps.decom.status != .draining) return error.Conflict;
                ps.decom.status = .canceled;
                ps.decom.end_ns = @intCast(std.time.nanoTimestamp());
            }
        };
        var c: Ctx = .{ .p = p };
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        std.log.info("pools: decommission of pool {d} canceled", .{p + 1});
    }

    pub fn rebalanceStart(m: *Manager, a: std.mem.Allocator) Error![]const u8 {
        const Ctx = struct {
            id: []const u8 = "",
            fn f(ctx: *anyopaque, mg: *Manager, ma: std.mem.Allocator, meta: *Meta) Error!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                if (meta.draining() != null or meta.rebalance.status == .started) return error.Conflict;
                var active: usize = 0;
                for (0..mg.router().pools.len) |q| active += @intFromBool(mg.router().mode(q) == .active);
                if (active < 2) return error.Conflict;
                var idb: [16]u8 = undefined;
                std.crypto.random.bytes(&idb);
                const hex = std.fmt.bytesToHex(idb, .lower);
                const id = try std.fmt.allocPrint(ma, "{s}-{s}-{s}-{s}-{s}", .{ hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32] });
                self.id = id;
                const thr = if (std.posix.getenv("ZKFSM_REBALANCE_THRESHOLD")) |v| std.fmt.parseFloat(f64, v) catch 0.1 else 0.1;
                meta.rebalance = .{ .id = id, .status = .started, .threshold = thr, .start_ns = @intCast(std.time.nanoTimestamp()) };
            }
        };
        var c: Ctx = .{};
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        std.log.info("pools: rebalance {s} started", .{c.id});
        return a.dupe(u8, c.id);
    }

    pub fn rebalanceStop(m: *Manager) Error!void {
        const Ctx = struct {
            fn f(_: *anyopaque, _: *Manager, _: std.mem.Allocator, meta: *Meta) Error!void {
                if (meta.rebalance.status != .started) return error.Conflict;
                meta.rebalance.status = .stopped;
                meta.rebalance.stop_ns = @intCast(std.time.nanoTimestamp());
            }
        };
        var c: Ctx = .{};
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        std.log.info("pools: rebalance stopped", .{});
    }

    // ---- worker ----

    pub fn start(m: *Manager) void {
        m.node.pools_hook = .{ .ctx = m, .func = wake };
        m.thread = std.Thread.spawn(.{}, workerLoop, .{m}) catch blk: {
            std.log.err("pools: worker not started", .{});
            break :blk null;
        };
        m.modes_thread = std.Thread.spawn(.{}, modesLoop, .{m}) catch null;
    }

    pub fn stop(m: *Manager) void {
        m.stop_ev.set();
        m.wake_ev.set();
        m.modes_ev.set();
        if (m.thread) |t| t.join();
        if (m.modes_thread) |t| t.join();
        m.thread = null;
        m.modes_thread = null;
    }

    fn wake(ctx: *anyopaque) void {
        const m: *Manager = @ptrCast(@alignCast(ctx));
        m.wake_ev.set();
        m.modes_ev.set();
    }

    /// Keeps pool modes current while the worker may be busy or waiting for its lock.
    fn modesLoop(m: *Manager) void {
        while (!m.stopping()) {
            m.modes_ev.timedWait(poll_ns) catch {};
            m.modes_ev.reset();
            if (m.stopping()) return;
            var arena = std.heap.ArenaAllocator.init(m.gpa);
            defer arena.deinit();
            const meta = m.loadFresh(arena.allocator()) catch continue;
            m.applyModes(meta);
        }
    }

    fn stopping(m: *Manager) bool {
        return m.stop_ev.isSet() or m.node.stop_ev.isSet();
    }

    fn workerLoop(m: *Manager) void {
        while (!m.stopping()) {
            m.wake_ev.timedWait(poll_ns) catch {};
            m.wake_ev.reset();
            if (m.stopping()) return;
            var arena = std.heap.ArenaAllocator.init(m.gpa);
            defer arena.deinit();
            const meta = m.loadFresh(arena.allocator()) catch continue;
            m.applyModes(meta);
            const job = jobId(meta) orelse {
                m.job = 0;
                continue;
            };
            const now = std.time.nanoTimestamp();
            if (job != m.job) {
                m.job = job;
                m.job_since = now;
            }
            if (now - m.job_since < grace_ns or !m.node.ready()) continue;
            const tok = m.node.locks.lock("pools-worker") catch continue;
            defer m.node.locks.unlock(tok);
            m.runJob() catch |e| std.log.warn("pools: job interrupted: {t}", .{e});
        }
    }

    fn jobId(meta: Meta) ?u64 {
        if (meta.draining()) |d| return 0x1_0000_0000 | @as(u64, d);
        if (meta.rebalance.status == .started) return std.hash.Wyhash.hash(7, meta.rebalance.id) | 1;
        return null;
    }

    fn runJob(m: *Manager) Error!void {
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        const meta = try m.loadFresh(arena.allocator());
        m.applyModes(meta);
        if (meta.draining()) |idx| {
            for (0..m.router().pools.len) |p| if (m.node.poolIndex(p) == idx) return m.drain(p);
            return;
        }
        if (meta.rebalance.status == .started) return m.rebalance(meta.rebalance.id);
    }

    /// Live counters of the running job, folded into the record now and then.
    const Progress = struct {
        objects: u64 = 0,
        bytes: u64 = 0,
        objects_failed: u64 = 0,
        bytes_failed: u64 = 0,
        last_persist: i128 = 0,

        fn add(p: *Progress, res: mover.Result) void {
            if (res.outcome != .moved) return;
            p.objects += 1;
            p.bytes += res.bytes;
        }
    };

    const Check = enum { go, stop };

    /// Folds progress into the record; `stop` once the job was canceled elsewhere.
    fn persistDecom(m: *Manager, p: usize, prog: *Progress, final: ?state.DecomStatus) Error!Check {
        const Ctx = struct {
            p: usize,
            prog: *Progress,
            final: ?state.DecomStatus,
            check: Check = .go,
            fn f(ctx: *anyopaque, mg: *Manager, a: std.mem.Allocator, meta: *Meta) Error!void {
                _ = a;
                const self: *@This() = @ptrCast(@alignCast(ctx));
                const ps = meta.pool(mg.node.poolIndex(self.p)) orelse {
                    self.check = .stop;
                    return;
                };
                if (ps.decom.status != .draining) {
                    self.check = .stop;
                    return;
                }
                ps.decom.objects += self.prog.objects;
                ps.decom.bytes += self.prog.bytes;
                ps.decom.objects_failed += self.prog.objects_failed;
                ps.decom.bytes_failed += self.prog.bytes_failed;
                if (self.final) |s| {
                    ps.decom.status = s;
                    ps.decom.end_ns = @intCast(std.time.nanoTimestamp());
                }
            }
        };
        var c: Ctx = .{ .p = p, .prog = prog, .final = final };
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        if (c.check == .go) prog.* = .{ .last_persist = std.time.nanoTimestamp() };
        return c.check;
    }

    fn keysOf(a: std.mem.Allocator, set: backend.StorageBackend, space: backend.KeySpace) Error![]backend.PhysicalKey {
        const Collect = struct {
            a: std.mem.Allocator,
            keys: std.ArrayList(backend.PhysicalKey) = .empty,
            fn f(ctx: *anyopaque, k: backend.PhysicalKey) backend.Error!void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                try c.keys.append(c.a, k);
            }
        };
        var c: Collect = .{ .a = a };
        set.list(space, .{ .ctx = &c, .func = Collect.f }) catch |e| switch (e) {
            error.NotFound => {},
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Unavailable,
        };
        return c.keys.items;
    }

    /// Moves every key out of pool `p` (data, then records, then system records);
    /// passes repeat until the pool is empty.
    fn drain(m: *Manager, p: usize) Error!void {
        std.log.info("pools: draining pool {d}", .{p + 1});
        const buf = try m.gpa.alloc(u8, mover.chunk);
        defer m.gpa.free(buf);
        var prog: Progress = .{ .last_persist = std.time.nanoTimestamp() };
        var idle: usize = 0;
        const r = m.router();
        const started = std.time.nanoTimestamp();
        var total: u64 = 0;
        while (true) {
            var left: usize = 0;
            var moved: usize = 0;
            var kinds: [3]usize = @splat(0);
            for (r.pools[p].sets) |set| for ([_]backend.KeySpace{ .data, .record, .system }) |space| {
                var arena = std.heap.ArenaAllocator.init(m.gpa);
                defer arena.deinit();
                const keys = keysOf(arena.allocator(), set, space) catch |e| {
                    if (e == error.OutOfMemory) return e;
                    left += 1;
                    continue;
                };
                for (keys) |key| {
                    if (m.stopping()) return persistQuiet(m, p, &prog);
                    if (r.mode(p) != .draining) return persistQuiet(m, p, &prog);
                    if (mover.moveKey(r, m.gpa, key, p, buf)) |res| {
                        prog.add(res);
                        moved += 1;
                        kinds[@intFromEnum(res.outcome)] += 1;
                        total += res.bytes;
                        throttle(&m.stop_ev, m.decom_rate, started, total);
                    } else |e| {
                        if (e == error.OutOfMemory) return error.OutOfMemory;
                        std.log.warn("pools: cannot move {t} key {s} out of pool {d}: {t}", .{ key.space, &key.hex, p + 1, e });
                        left += 1;
                    }
                    if (std.time.nanoTimestamp() - prog.last_persist >= persist_ns) {
                        if (try m.persistDecom(p, &prog, null) == .stop) return;
                    }
                }
            };
            std.log.info("pools: pool {d} pass: {d} moved, {d} gone, {d} dup, {d} left", .{ p + 1, kinds[0], kinds[1], kinds[2], left });
            // Listed but unreadable keys are delete tombstones, purged by heal later.
            if (left == 0 and kinds[0] == 0 and kinds[2] == 0) break;
            idle = if (moved == 0) idle + 1 else 0;
            if (idle >= max_idle_passes) {
                std.log.err("pools: decommission of pool {d} failed: {d} key(s) cannot be moved", .{ p + 1, left });
                prog.objects_failed = left;
                _ = try m.persistDecom(p, &prog, .failed);
                return;
            }
            m.stop_ev.timedWait(std.time.ns_per_s) catch {};
            if (m.stopping()) return persistQuiet(m, p, &prog);
        }
        // Retire the pool in the drive formats before reporting it complete.
        const failed = m.node.markRetired(m.bit(p));
        if (failed > 0) std.log.warn("pools: {d} drive format(s) could not record pool {d} as decommissioned", .{ failed, p + 1 });
        if (try m.persistDecom(p, &prog, .complete) == .go)
            std.log.info("pools: decommission of pool {d} complete; it may be removed from the endpoint list", .{p + 1});
    }

    fn persistQuiet(m: *Manager, p: usize, prog: *Progress) Error!void {
        _ = m.persistDecom(p, prog, null) catch {};
    }

    // ---- rebalance ----

    fn ratio(u: Usage) f64 {
        if (u.total == 0) return 0;
        return @as(f64, @floatFromInt(u.total -| u.free)) / @as(f64, @floatFromInt(u.total));
    }

    fn persistRebal(m: *Manager, id: []const u8, srcs: []const RebalSrc, final: ?state.RebalStatus, goal: f64) Error!Check {
        const Ctx = struct {
            id: []const u8,
            srcs: []const RebalSrc,
            final: ?state.RebalStatus,
            goal: f64,
            check: Check = .go,
            fn f(ctx: *anyopaque, mg: *Manager, a: std.mem.Allocator, meta: *Meta) Error!void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                if (meta.rebalance.status != .started or !std.mem.eql(u8, meta.rebalance.id, self.id)) {
                    self.check = .stop;
                    return;
                }
                meta.rebalance.goal = self.goal;
                for (self.srcs) |s| {
                    const idx = mg.node.poolIndex(s.p);
                    const rp = meta.rebalPool(idx) orelse blk: {
                        const grown = try a.alloc(state.RebalPool, meta.rebalance.pools.len + 1);
                        @memcpy(grown[0..meta.rebalance.pools.len], meta.rebalance.pools);
                        grown[grown.len - 1] = .{ .index = idx };
                        meta.rebalance.pools = grown;
                        break :blk &grown[grown.len - 1];
                    };
                    rp.source = s.source;
                    rp.done = s.done;
                    rp.objects += s.objects;
                    rp.bytes += s.bytes;
                }
                if (self.final) |st| {
                    meta.rebalance.status = st;
                    meta.rebalance.stop_ns = @intCast(std.time.nanoTimestamp());
                }
            }
        };
        var c: Ctx = .{ .id = id, .srcs = srcs, .final = final, .goal = goal };
        try m.update(.{ .ctx = &c, .func = Ctx.f });
        return c.check;
    }

    const RebalSrc = struct { p: usize, source: bool, done: bool = false, objects: u64 = 0, bytes: u64 = 0 };

    /// Moves blobs out of pools above the cluster-wide used ratio (by more than the
    /// threshold) until each is at or below it.
    fn rebalance(m: *Manager, id_in: []const u8) Error!void {
        var ida: [64]u8 = undefined;
        const id = ida[0..@min(id_in.len, ida.len)];
        @memcpy(id, id_in[0..id.len]);
        m.node.refreshSpace();
        const r = m.router();
        var used_sum: u64 = 0;
        var total_sum: u64 = 0;
        for (0..r.pools.len) |p| {
            if (r.mode(p) == .retired) continue;
            const u = m.usage(p);
            used_sum += u.total -| u.free;
            total_sum += u.total;
        }
        if (total_sum == 0) return;
        const goal = @as(f64, @floatFromInt(used_sum)) / @as(f64, @floatFromInt(total_sum));
        var arena0 = std.heap.ArenaAllocator.init(m.gpa);
        defer arena0.deinit();
        const meta = try m.loadFresh(arena0.allocator());
        var mm = meta;
        const thr = meta.rebalance.threshold;
        var srcs: std.ArrayList(RebalSrc) = .empty;
        defer srcs.deinit(m.gpa);
        for (0..r.pools.len) |p| {
            if (r.mode(p) == .retired) continue;
            const prev = mm.rebalPool(m.node.poolIndex(p));
            const over = ratio(m.usage(p)) > goal * (1 + thr);
            // A resumed run keeps its sources; a finished source stays finished.
            const source = if (prev) |pp| pp.source and !pp.done else over;
            try srcs.append(m.gpa, .{ .p = p, .source = source, .done = if (prev) |pp| pp.done else false });
        }
        if (try m.persistRebal(id, srcs.items, null, goal) == .stop) return;
        try m.loadAndApply();
        std.log.info("pools: rebalancing toward {d:.4} used", .{goal});
        const buf = try m.gpa.alloc(u8, mover.chunk);
        defer m.gpa.free(buf);
        var last_persist = std.time.nanoTimestamp();
        const started = std.time.nanoTimestamp();
        var moved_bytes: u64 = 0;
        for (srcs.items) |*s| {
            if (!s.source or s.done) continue;
            const p = s.p;
            var enough = false;
            for (r.pools[p].sets) |set| {
                if (enough) break;
                var arena = std.heap.ArenaAllocator.init(m.gpa);
                defer arena.deinit();
                const keys = keysOf(arena.allocator(), set, .data) catch |e| {
                    if (e == error.OutOfMemory) return e;
                    continue;
                };
                for (keys) |key| {
                    if (ratio(m.usage(p)) <= goal) {
                        enough = true;
                        break;
                    }
                    if (m.stopping()) return;
                    if (mover.moveKey(r, m.gpa, key, p, buf)) |res| {
                        if (res.outcome == .moved) {
                            s.objects += 1;
                            s.bytes += res.bytes;
                            moved_bytes += res.bytes;
                            const rb = m.raw(res.bytes);
                            _ = r.pools[p].free.fetchAdd(rb, .monotonic);
                            const d = r.pickPool();
                            _ = r.pools[d].free.fetchSub(@min(rb, r.pools[d].free.load(.monotonic)), .monotonic);
                        }
                    } else |e| {
                        if (e == error.OutOfMemory) return error.OutOfMemory;
                        std.log.warn("pools: rebalance cannot move key {s}: {t}", .{ &key.hex, e });
                    }
                    throttle(&m.stop_ev, m.rebalance_rate, started, moved_bytes);
                    if (std.time.nanoTimestamp() - last_persist >= persist_ns) {
                        if (try m.persistRebal(id, srcs.items, null, goal) == .stop) return;
                        for (srcs.items) |*x| {
                            x.objects = 0;
                            x.bytes = 0;
                        }
                        last_persist = std.time.nanoTimestamp();
                    }
                }
            }
            s.done = true;
            if (try m.persistRebal(id, srcs.items, null, goal) == .stop) return;
            for (srcs.items) |*x| {
                x.objects = 0;
                x.bytes = 0;
            }
            try m.loadAndApply();
        }
        if (try m.persistRebal(id, srcs.items, .completed, goal) == .go) std.log.info("pools: rebalance complete", .{});
    }

    fn loadAndApply(m: *Manager) Error!void {
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        m.applyModes(try m.loadFresh(arena.allocator()));
    }

    fn throttle(ev: *std.Thread.ResetEvent, rate: u64, started: i128, bytes: u64) void {
        if (rate == 0) return;
        const due: i128 = @divTrunc(@as(i128, bytes) * std.time.ns_per_s, rate);
        const ahead = due - (std.time.nanoTimestamp() - started);
        if (ahead > 0) ev.timedWait(@intCast(@min(ahead, std.time.ns_per_s))) catch {};
    }
};

test {
    _ = state;
    _ = mover;
}
