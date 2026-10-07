//! Node: this process's view of the cluster. Bootstraps the deployment (format
//! negotiation), opens every erasure set with local and remote drives, and runs the
//! background work: heartbeats, healing, cache refresh, and pool space accounting.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");
const heal = @import("../heal/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const auth = @import("auth.zig");
const topology = @import("topology.zig");
const rpc_mod = @import("rpc.zig");
const wire = @import("wire.zig");
const locks = @import("locks.zig");
const router_mod = @import("router.zig");
const remote_drive = @import("remote_drive.zig");
const handles = @import("handles.zig");

const layout = placement.layout;
const FormatV2 = layout.FormatV2;
const Profile = placement.Profile;

pub const Error = error{
    BadTopology,
    BadLayout,
    /// A drive or peer belongs to another deployment or layout.
    LayoutMismatch,
    ProfileMismatch,
    /// Peers run with other root credentials or cluster secret.
    CredentialMismatch,
    DriveUnavailable,
    Stopped,
    OutOfMemory,
};

pub const Config = struct {
    /// Per pool, its endpoint arguments.
    pools: []const []const []const u8,
    node_address: ?[]const u8 = null,
    listen_host: []const u8,
    listen_port: u16,
    profile: ?Profile = null,
    set_size: ?usize = null,
    secret: auth.Secret,
    /// Fingerprint of the root credentials; all zeros in anonymous mode.
    root_fp: [16]u8 = @splat(0),
    /// PEM files trusted for peer certificates (TLS clusters).
    ca_files: []const []const u8 = &.{},
    scan_interval_s: u64 = 600,
    /// Seconds between catalog and IAM reloads (the backstop for missed notifications).
    refresh_s: u64 = 10,
};

/// A local endpoint and, once opened, the set slot it serves.
pub const LocalEp = struct {
    path: []const u8,
    total: std.atomic.Value(u64) = .init(0),
    used: std.atomic.Value(u64) = .init(0),
    set: ?*placement.DriveSet = null,
    slot: u8 = 0,
};

pub const SetState = struct {
    drives: placement.DriveSet,
    stores: protection.Stores = .{},
    strategy: protection.Strategy,
    healer: heal.Healer,
    /// Endpoint index (within the pool) of each slot.
    endpoints: []u32,
};

pub const PoolState = struct {
    set_size: usize,
    sets: []SetState,
    backends: []backend.StorageBackend,
};

pub const Hook = struct { ctx: *anyopaque, func: *const fn (ctx: *anyopaque) void };

pub const Node = struct {
    gpa: std.mem.Allocator,
    arena_state: std.heap.ArenaAllocator,
    cfg: Config,
    topo: topology.Topology,
    rpc: rpc_mod.Rpc,
    guard: auth.ReplayGuard,
    secret: auth.Secret,
    root_fp: [16]u8,
    topo_fp: [16]u8,
    table: locks.Table,
    locks: locks.Manager = undefined,
    /// Blobs peers are reading by lease.
    leases: handles.Table,
    profile: Profile = .single,
    deployment: [16]u8 = @splat(0),
    local_eps: [][]?LocalEp,
    remotes: [][]?remote_drive.RemoteDrive,
    pools: []PoolState = &.{},
    router: router_mod.Router = undefined,
    router_pools: []router_mod.Pool = &.{},
    /// Drives are open: peers may do I/O here.
    drives_open: std.atomic.Value(bool) = .init(false),
    /// S3 service is up (the server's gate).
    open: std.atomic.Value(bool) = .init(false),
    svc: std.atomic.Value(?*object.ObjectService) = .init(null),
    iam_store: std.atomic.Value(?*iam.Store) = .init(null),
    stop_ev: std.Thread.ResetEvent = .{},
    threads: std.ArrayList(std.Thread) = .empty,
    stopped: bool = false,
    /// A note arrived before the object service was up.
    missed: std.atomic.Value(bool) = .init(false),
    iam_persist: IamPersist = undefined,
    /// Per endpoint-list pool, its index in the deployment (kept when pools are removed).
    orig: []u32 = &.{},
    /// Deployment pools that finished decommissioning (bit per index).
    retired: u64 = 0,
    /// Deployment pools ever formatted; recorded in drive formats.
    pool_count: u32 = 0,
    /// Called when a peer announces a pool state change.
    pools_hook: ?Hook = null,

    /// Parses the topology and prepares RPC; nothing touches peers yet.
    pub fn create(gpa: std.mem.Allocator, cfg: Config) Error!*Node {
        const n = try gpa.create(Node);
        errdefer gpa.destroy(n);
        n.* = .{
            .gpa = gpa,
            .arena_state = .init(gpa),
            .cfg = cfg,
            .topo = undefined,
            .rpc = undefined,
            .guard = .{ .gpa = gpa },
            .secret = cfg.secret,
            .root_fp = cfg.root_fp,
            .topo_fp = undefined,
            .table = .{ .gpa = gpa },
            .leases = .{ .gpa = gpa },
            .local_eps = &.{},
            .remotes = &.{},
        };
        errdefer n.arena_state.deinit();
        const a = n.arena_state.allocator();
        n.topo = topology.parse(a, cfg.pools, cfg.node_address, cfg.listen_host, cfg.listen_port) catch |e| {
            std.log.err("cluster endpoints: {t}", .{e});
            return error.BadTopology;
        };
        n.topo_fp = topoFingerprint(&n.topo);
        if (n.topo.pools.len > router_mod.max_pools) {
            std.log.err("cluster: at most {d} pools", .{router_mod.max_pools});
            return error.BadTopology;
        }
        n.orig = try a.alloc(u32, n.topo.pools.len);
        for (n.orig, 0..) |*o, p| o.* = @intCast(p);
        n.rpc = rpc_mod.Rpc.init(gpa, &n.topo, cfg.secret) catch return error.OutOfMemory;
        errdefer n.rpc.deinit();
        if (n.topo.tls) try n.loadCa();
        n.local_eps = try a.alloc([]?LocalEp, n.topo.pools.len);
        n.remotes = try a.alloc([]?remote_drive.RemoteDrive, n.topo.pools.len);
        for (n.topo.pools, 0..) |pool, p| {
            n.local_eps[p] = try a.alloc(?LocalEp, pool.endpoints.len);
            n.remotes[p] = try a.alloc(?remote_drive.RemoteDrive, pool.endpoints.len);
            for (pool.endpoints, 0..) |ep, i| {
                n.local_eps[p][i] = null;
                n.remotes[p][i] = null;
                if (n.topo.isLocal(ep)) {
                    n.local_eps[p][i] = .{ .path = ep.path };
                } else {
                    n.remotes[p][i] = remote_drive.RemoteDrive.init(gpa, &n.rpc, ep.node, @intCast(p), @intCast(i));
                }
            }
        }
        n.locks = .{ .gpa = gpa, .rpc = &n.rpc, .table = &n.table };
        n.rpc.on_change = .{ .ctx = n, .func = onPeerChange };
        std.log.info("cluster: node {d} of {d} ({s}), {d} pool(s)", .{ n.topo.local + 1, n.topo.nodes.len, n.topo.nodes[n.topo.local].name, n.topo.pools.len });
        return n;
    }

    fn loadCa(n: *Node) Error!void {
        var b: std.crypto.Certificate.Bundle = .{};
        for (n.cfg.ca_files) |f| b.addCertsFromFilePathAbsolute(n.gpa, f) catch |e| {
            std.log.warn("cluster tls: cannot load {s}: {t}", .{ f, e });
        };
        if (b.map.count() == 0) {
            std.log.warn("cluster tls: no trusted certificates; peers are only checked to be self-signed", .{});
            b.deinit(n.gpa);
            return;
        }
        n.rpc.ca = b;
    }

    pub fn destroy(n: *Node) void {
        n.stop();
        for (n.pools) |*p| for (p.sets) |*s| s.drives.deinit();
        n.locks.deinit();
        n.table.deinit();
        n.leases.deinit();
        n.guard.deinit();
        n.rpc.deinit();
        n.threads.deinit(n.gpa);
        n.arena_state.deinit();
        n.gpa.destroy(n);
    }

    /// Stops background threads (healers, heartbeat, refresh).
    pub fn stop(n: *Node) void {
        if (n.stopped) return;
        n.stopped = true;
        n.stop_ev.set();
        for (n.pools) |*p| for (p.sets) |*s| s.healer.stop();
        for (n.threads.items) |t| t.join();
        n.threads.clearRetainingCapacity();
    }

    fn spawn(n: *Node, comptime f: anytype) void {
        const t = std.Thread.spawn(.{}, f, .{n}) catch {
            std.log.err("cluster: cannot start a background thread", .{});
            return;
        };
        n.threads.append(n.gpa, t) catch t.detach();
    }

    // ---- lookups used by the RPC server ----

    fn parseAddr(n: *Node, addr: []const u8) ?struct { usize, usize } {
        const dot = std.mem.indexOfScalar(u8, addr, '.') orelse return null;
        const p = std.fmt.parseInt(usize, addr[0..dot], 10) catch return null;
        const i = std.fmt.parseInt(usize, addr[dot + 1 ..], 10) catch return null;
        if (p >= n.local_eps.len or i >= n.local_eps[p].len) return null;
        return .{ p, i };
    }

    pub fn endpoint(n: *Node, addr: []const u8) ?*LocalEp {
        const pi = n.parseAddr(addr) orelse return null;
        return if (n.local_eps[pi[0]][pi[1]]) |*e| e else null;
    }

    pub const Slot = struct { set: *placement.DriveSet, slot: u8 };

    pub fn localDrive(n: *Node, addr: []const u8) ?Slot {
        if (!n.drives_open.load(.acquire)) return null;
        const e = n.endpoint(addr) orelse return null;
        return .{ .set = e.set orelse return null, .slot = e.slot };
    }

    // ---- bootstrap ----

    const Seen = union(enum) { unknown, none, bad, fmt: FormatV2 };

    /// Waits for peers, formats a new deployment or pool, verifies every reachable
    /// drive against the layout, and opens all sets. Blocks until done.
    pub fn bootstrap(n: *Node) Error!void {
        n.spawn(heartbeatLoop);
        const a = n.arena_state.allocator();
        const seen = try a.alloc([]Seen, n.topo.pools.len);
        for (seen, n.topo.pools) |*s, pool| s.* = try a.alloc(Seen, pool.endpoints.len);
        var last_log: i64 = 0;
        while (true) {
            if (n.stop_ev.isSet()) return error.Stopped;
            try n.checkPeers();
            n.gather(seen);
            const done = try n.decide(seen);
            if (done) break;
            const now = std.time.timestamp();
            if (now - last_log >= 5) {
                last_log = now;
                var unknown: usize = 0;
                var total: usize = 0;
                for (seen) |s| for (s) |e| {
                    total += 1;
                    unknown += @intFromBool(e == .unknown);
                };
                std.log.info("cluster: waiting for drives ({d} of {d} unreachable)", .{ unknown, total });
            }
            n.stop_ev.timedWait(500 * std.time.ns_per_ms) catch {};
        }
        try n.openSets(seen);
        n.recordPoolCount(seen);
        n.drives_open.store(true, .release);
        n.refreshSpace();
        std.log.info("cluster: deployment {s}, protection {s}, {d} set(s)", .{ &std.fmt.bytesToHex(n.deployment, .lower), n.profile.name(), n.setCount() });
    }

    fn setCount(n: *const Node) usize {
        var c: usize = 0;
        for (n.pools) |p| c += p.sets.len;
        return c;
    }

    /// Hello to every peer: refuses a peer with another endpoint list or root.
    fn checkPeers(n: *Node) Error!void {
        for (n.topo.nodes, 0..) |_, i| {
            const node: u16 = @intCast(i);
            if (node == n.topo.local) continue;
            const h = n.hello(node) catch |e| {
                if (e == error.CredentialMismatch) return error.CredentialMismatch;
                continue;
            };
            if (!std.mem.eql(u8, &h.topo, &n.topo_fp)) {
                std.log.err("cluster: node {s} runs with a different endpoint list", .{n.topo.nodes[i].name});
                return error.LayoutMismatch;
            }
            if (!std.mem.eql(u8, &h.root, &n.root_fp)) {
                std.log.err("cluster: node {s} runs with different root credentials", .{n.topo.nodes[i].name});
                return error.CredentialMismatch;
            }
        }
    }

    const Hello = struct { topo: [16]u8, root: [16]u8, ready: bool, drives: bool };

    fn hello(n: *Node, node: u16) error{ Unreachable, CredentialMismatch }!Hello {
        var c = n.rpc.call(node, "hello", "", .{ .bytes = "" }, .{ .probe = true, .timeout_ms = 2000 }) catch return error.Unreachable;
        defer c.deinit();
        if (c.status == 401) {
            std.log.err("cluster: node {s} rejected our requests: cluster secret or root credentials differ", .{n.topo.nodes[node].name});
            return error.CredentialMismatch;
        }
        if (!c.ok()) return error.Unreachable;
        var buf: [512]u8 = undefined;
        if (c.body_left > buf.len) return error.Unreachable;
        const body = buf[0..@intCast(c.body_left)];
        c.readInto(body) catch return error.Unreachable;
        var h: Hello = .{ .topo = undefined, .root = undefined, .ready = false, .drives = false };
        var have: u8 = 0;
        var it = std.mem.tokenizeScalar(u8, body, '\n');
        while (it.next()) |line| {
            const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            const k = line[0..sp];
            const v = line[sp + 1 ..];
            if (std.mem.eql(u8, k, "topology") and v.len == 32) {
                _ = std.fmt.hexToBytes(&h.topo, v) catch return error.Unreachable;
                have |= 1;
            } else if (std.mem.eql(u8, k, "root") and v.len == 32) {
                _ = std.fmt.hexToBytes(&h.root, v) catch return error.Unreachable;
                have |= 2;
            } else if (std.mem.eql(u8, k, "ready")) {
                h.ready = std.mem.eql(u8, v, "1");
            } else if (std.mem.eql(u8, k, "drives")) h.drives = std.mem.eql(u8, v, "1");
        }
        if (have != 3) return error.Unreachable;
        return h;
    }

    fn gather(n: *Node, seen: [][]Seen) void {
        for (n.topo.pools, 0..) |pool, p| for (pool.endpoints, 0..) |_, i| {
            seen[p][i] = n.readFormat(p, i);
        };
    }

    fn readFormat(n: *Node, p: usize, i: usize) Seen {
        var buf: [layout.format_max]u8 = undefined;
        const bytes: []const u8 = if (n.local_eps[p][i]) |le| blk: {
            var lb = backend.local.LocalBackend.open(le.path) catch return .unknown;
            defer lb.close();
            break :blk lb.readFormat(&buf) catch |e| return if (e == error.NotFound) .none else .unknown;
        } else blk: {
            // Probe past the breaker: peers still bootstrapping answer format queries.
            const rd = &n.remotes[p][i].?;
            var qb: [32]u8 = undefined;
            const q = std.fmt.bufPrint(&qb, "d={d}.{d}", .{ p, i }) catch unreachable;
            var c = n.rpc.call(rd.node, "format", q, .{ .bytes = "" }, .{ .probe = true, .timeout_ms = 2000 }) catch return .unknown;
            defer c.deinit();
            if (c.status == 404) return .none;
            if (!c.ok() or c.body_left > buf.len) return .unknown;
            const out = buf[0..@intCast(c.body_left)];
            c.readInto(out) catch return .unknown;
            break :blk out;
        };
        return .{ .fmt = FormatV2.parse(bytes) catch return .bad };
    }

    /// The node that formats a pool: the owner of its first endpoint.
    fn formatter(n: *const Node, p: usize) bool {
        return n.topo.pools[p].endpoints[0].node == n.topo.local;
    }

    fn decide(n: *Node, seen: [][]Seen) Error!bool {
        // The deployment every formatted drive should agree on.
        var dep: ?[16]u8 = null;
        var profile: ?Profile = null;
        var votes: usize = 0;
        for (seen) |s| for (s) |e| if (e == .fmt) {
            var c: usize = 0;
            for (seen) |s2| for (s2) |e2| {
                if (e2 == .fmt and std.mem.eql(u8, &e2.fmt.deployment, &e.fmt.deployment)) c += 1;
            };
            if (c > votes) {
                votes = c;
                dep = e.fmt.deployment;
                profile = e.fmt.profile;
            }
        };
        for (seen, 0..) |s, p| for (s, 0..) |e, i| {
            const foreign = switch (e) {
                .bad => true,
                .fmt => |f| !std.mem.eql(u8, &f.deployment, &dep.?),
                else => false,
            };
            if (e == .bad and dep == null and n.local_eps[p][i] == null) continue;
            if (!foreign) continue;
            if (n.local_eps[p][i] != null) {
                std.log.err("cluster: drive {s} holds another deployment's or an unreadable format", .{n.topo.pools[p].endpoints[i].url});
                return error.LayoutMismatch;
            }
            std.log.warn("cluster: remote drive {s} holds a foreign format", .{n.topo.pools[p].endpoints[i].url});
        };
        if (dep != null and !try n.resolvePools(seen, dep.?)) return false;
        if (dep == null) {
            // Brand-new cluster: format once every drive can be reached.
            for (seen) |s| for (s) |e| if (e == .unknown) return false;
            if (!n.formatter(0)) return false;
            var d: [16]u8 = undefined;
            std.crypto.random.bytes(&d);
            n.deployment = d;
            n.profile = n.cfg.profile orelse n.defaultProfile();
            n.pool_count = @intCast(n.topo.pools.len);
            for (0..n.topo.pools.len) |p| try n.formatPool(p, seen[p]);
            return false;
        }
        n.deployment = dep.?;
        n.profile = profile.?;
        if (n.cfg.profile) |want| if (!want.eql(n.profile)) {
            std.log.err("cluster: drives are formatted {s}, --protection asks for {s}", .{ n.profile.name(), want.name() });
            return error.ProfileMismatch;
        };
        var complete = true;
        for (seen, 0..) |s, p| {
            const any = for (s) |e| {
                if (e == .fmt) break true;
            } else false;
            if (any) continue;
            complete = false;
            // An appended pool: its first endpoint's owner formats it when all are reachable.
            const reachable = for (s) |e| {
                if (e == .unknown) break false;
            } else true;
            if (reachable and n.formatter(p)) try n.formatPool(p, s);
        }
        return complete;
    }

    /// Maps endpoint-list pools to deployment pool indexes from their formats. A pool
    /// may leave the list only once its formats record it as decommissioned.
    fn resolvePools(n: *Node, seen: [][]Seen, dep: [16]u8) Error!bool {
        var retired: u64 = 0;
        var present: u64 = 0;
        var count: u32 = 0;
        var known = try n.gpa.alloc(bool, seen.len);
        defer n.gpa.free(known);
        for (seen, 0..) |s, p| {
            known[p] = false;
            for (s) |e| if (e == .fmt and std.mem.eql(u8, &e.fmt.deployment, &dep)) {
                retired |= e.fmt.retired;
                count = @max(count, e.fmt.pools);
                if (e.fmt.pool >= router_mod.max_pools - 1) return error.LayoutMismatch;
                if (known[p] and n.orig[p] != e.fmt.pool) {
                    std.log.err("cluster: pool {d} mixes drives of deployment pools {d} and {d}", .{ p + 1, n.orig[p] + 1, e.fmt.pool + 1 });
                    return error.LayoutMismatch;
                }
                n.orig[p] = e.fmt.pool;
                known[p] = true;
            };
            if (known[p]) {
                const bit = @as(u64, 1) << @intCast(n.orig[p]);
                if (present & bit != 0) {
                    std.log.err("cluster: deployment pool {d} appears twice in the endpoint list", .{n.orig[p] + 1});
                    return error.LayoutMismatch;
                }
                present |= bit;
            }
        }
        n.retired = retired;
        // New pools take the next unused indexes, in endpoint-list order.
        var next: u32 = @intCast(64 - @clz(present | retired));
        var fresh = false;
        for (seen, 0..) |s, p| if (!known[p]) {
            for (s) |e| if (e != .none) return false;
            n.orig[p] = next;
            next += 1;
            fresh = true;
        };
        // Judged once every pool is formatted (a peer may be formatting right now).
        if (fresh) {
            n.pool_count = next;
            return true;
        }
        const hi: u32 = @max(count, @as(u32, @intCast(64 - @clz(present | retired))));
        n.pool_count = @max(hi, next);
        const missing = ~(present | retired) & ((@as(u64, 1) << @intCast(@min(hi, 63))) -% 1);
        if (missing != 0) {
            std.log.err("cluster: deployment pool {d} is missing from the endpoint list and was not decommissioned", .{@ctz(missing) + 1});
            return error.LayoutMismatch;
        }
        return true;
    }

    /// Records pools as decommissioned in every reachable drive format; returns the
    /// number of drives that could not be updated.
    pub fn markRetired(n: *Node, mask: u64) usize {
        n.retired |= mask;
        var failed: usize = 0;
        for (n.topo.pools, 0..) |pool, p| for (pool.endpoints, 0..) |_, i| {
            const f = switch (n.readFormat(p, i)) {
                .fmt => |f| f,
                else => {
                    failed += 1;
                    continue;
                },
            };
            var g = f;
            g.retired |= n.retired;
            var buf: [layout.format_max]u8 = undefined;
            const bytes = g.encode(&buf) catch {
                failed += 1;
                continue;
            };
            n.writeFormat(p, i, bytes) catch {
                failed += 1;
            };
        };
        for (n.pools) |*ps| for (ps.sets) |*st| if (st.drives.cluster) |*c| {
            c.format.retired = n.retired;
        };
        return failed;
    }

    /// Local drives learn how many pools the deployment has, so dropping one that
    /// was never decommissioned is refused even when only older drives remain.
    fn recordPoolCount(n: *Node, seen: [][]Seen) void {
        for (seen, 0..) |s, p| for (s, 0..) |e, i| {
            if (n.local_eps[p][i] == null) continue;
            const f = switch (e) {
                .fmt => |f| f,
                else => continue,
            };
            if (f.pools >= n.pool_count and f.retired == n.retired) continue;
            var g = f;
            g.pools = @max(f.pools, n.pool_count);
            g.retired |= n.retired;
            var buf: [layout.format_max]u8 = undefined;
            const bytes = g.encode(&buf) catch continue;
            n.writeFormat(p, i, bytes) catch std.log.warn("cluster: cannot update the format of {s}", .{n.topo.pools[p].endpoints[i].url});
        };
    }

    /// Deployment index of endpoint-list pool `p`.
    pub fn poolIndex(n: *const Node, p: usize) u32 {
        return n.orig[p];
    }

    fn defaultProfile(n: *const Node) Profile {
        var smallest: usize = std.math.maxInt(usize);
        for (n.topo.pools) |p| smallest = @min(smallest, p.endpoints.len);
        return if (smallest >= 6) .{ .erasure = .{ .data = 4, .parity = 2 } } else if (smallest >= 2) .{ .replica = 2 } else .single;
    }

    fn nodesOf(n: *const Node, p: usize) usize {
        var set = std.AutoHashMap(u16, void).init(n.gpa);
        defer set.deinit();
        for (n.topo.pools[p].endpoints) |e| set.put(e.node, {}) catch {};
        return set.count();
    }

    fn poolSetSize(n: *const Node, p: usize) Error!usize {
        const pool = n.topo.pools[p];
        return layout.chooseSetSize(pool.endpoints.len, n.nodesOf(p), n.profile.width(), n.cfg.set_size) catch {
            std.log.err("cluster: pool {d}: {d} drives cannot form sets for {s}", .{ p + 1, pool.endpoints.len, n.profile.name() });
            return error.BadLayout;
        };
    }

    fn assignment(n: *const Node, p: usize, set_size: usize) Error![][]u32 {
        const eps = n.topo.pools[p].endpoints;
        const nodes = try n.gpa.alloc(u16, eps.len);
        defer n.gpa.free(nodes);
        for (eps, nodes) |e, *o| o.* = e.node;
        return layout.assign(n.gpa, nodes, set_size) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadLayout => error.BadLayout,
        };
    }

    fn formatPool(n: *Node, p: usize, s: []const Seen) Error!void {
        const size = try n.poolSetSize(p);
        const sets = try n.assignment(p, size);
        defer layout.freeSets(n.gpa, sets);
        const fp = topology.poolFingerprint(n.topo.pools[p], size, n.profile);
        std.log.info("cluster: formatting pool {d}: {d} set(s) of {d} drives, {s}", .{ p + 1, sets.len, size, n.profile.name() });
        for (sets, 0..) |members, si| for (members, 0..) |ep, idx| {
            if (s[ep] != .none) continue;
            const f: FormatV2 = .{ .deployment = n.deployment, .layout = fp, .pool = n.orig[p], .set = @intCast(si), .index = @intCast(idx), .set_size = @intCast(size), .profile = n.profile, .retired = n.retired, .pools = n.pool_count };
            var buf: [layout.format_max]u8 = undefined;
            const bytes = f.encode(&buf) catch return error.BadLayout;
            n.writeFormat(p, ep, bytes) catch std.log.warn("cluster: cannot format {s}", .{n.topo.pools[p].endpoints[ep].url});
        };
    }

    fn writeFormat(n: *Node, p: usize, i: usize, bytes: []const u8) Error!void {
        if (n.local_eps[p][i]) |le| {
            var lb = backend.local.LocalBackend.open(le.path) catch return error.DriveUnavailable;
            defer lb.close();
            lb.writeFormat(bytes) catch return error.DriveUnavailable;
            return;
        }
        const rd = &n.remotes[p][i].?;
        var qb: [32]u8 = undefined;
        const q = std.fmt.bufPrint(&qb, "d={d}.{d}", .{ p, i }) catch unreachable;
        var c = n.rpc.call(rd.node, "format_put", q, .{ .bytes = bytes }, .{ .probe = true }) catch return error.DriveUnavailable;
        defer c.deinit();
        if (!c.ok()) return error.DriveUnavailable;
    }

    /// Verifies formats against the computed layout, then opens every set.
    fn openSets(n: *Node, seen: [][]Seen) Error!void {
        const a = n.arena_state.allocator();
        n.pools = try a.alloc(PoolState, n.topo.pools.len);
        n.router_pools = try a.alloc(router_mod.Pool, n.topo.pools.len);
        for (n.topo.pools, 0..) |pool, p| {
            var size: usize = 0;
            for (seen[p]) |e| if (e == .fmt) {
                size = e.fmt.set_size;
                break;
            };
            const fp = topology.poolFingerprint(pool, size, n.profile);
            const sets = try n.assignment(p, size);
            defer layout.freeSets(n.gpa, sets);
            // Every reachable drive must sit exactly where the layout puts it.
            for (sets, 0..) |members, si| for (members, 0..) |ep, idx| {
                const f = switch (seen[p][ep]) {
                    .fmt => |f| f,
                    else => continue,
                };
                const ok = std.mem.eql(u8, &f.layout, &fp) and f.pool == n.orig[p] and f.set == si and f.index == idx and f.set_size == size and f.profile.eql(n.profile);
                if (!ok) {
                    std.log.err("cluster: drive {s} was formatted for a different layout (endpoint list, order, or protection changed)", .{pool.endpoints[ep].url});
                    return error.LayoutMismatch;
                }
            };
            const ps = &n.pools[p];
            ps.* = .{ .set_size = size, .sets = try a.alloc(SetState, sets.len), .backends = try a.alloc(backend.StorageBackend, sets.len) };
            for (sets, 0..) |members, si| {
                const st = &ps.sets[si];
                const ms = try a.alloc(placement.drives.Member, members.len);
                st.endpoints = try a.dupe(u32, members);
                for (members, ms) |ep, *m| {
                    const e = pool.endpoints[ep];
                    m.* = .{ .path = if (n.local_eps[p][ep]) |le| le.path else e.url, .node = e.node, .remote = if (n.remotes[p][ep]) |*rd| rd.ext() else null };
                }
                const tmpl: FormatV2 = .{ .deployment = n.deployment, .layout = fp, .pool = n.orig[p], .set = @intCast(si), .index = 0, .set_size = @intCast(size), .profile = n.profile, .retired = n.retired, .pools = n.pool_count };
                st.drives = placement.DriveSet.openCluster(n.gpa, ms, tmpl, true) catch |e| {
                    std.log.err("cluster: pool {d} set {d}: {t}", .{ p + 1, si + 1, e });
                    return error.LayoutMismatch;
                };
                st.stores = .{};
                st.strategy = protection.Strategy.init(n.gpa, &st.drives, &st.stores) catch return error.BadLayout;
                st.healer = heal.Healer.init(n.gpa, &st.drives, st.strategy, .{});
                st.healer.leader = .{ .ctx = n, .func = healLeader };
                ps.backends[si] = st.strategy.backend();
                for (members, 0..) |ep, idx| if (n.local_eps[p][ep]) |*le| {
                    le.set = &st.drives;
                    le.slot = @intCast(idx);
                };
            }
            var seed: [8]u8 = undefined;
            @memcpy(&seed, n.deployment[0..8]);
            n.router_pools[p] = .{ .sets = ps.backends, .seed = std.mem.readInt(u64, &seed, .little) +% n.orig[p] };
            if (n.retired & (@as(u64, 1) << @intCast(n.orig[p])) != 0) n.router_pools[p].mode = .init(.retired);
        }
        n.router = .{ .gpa = n.gpa, .pools = n.router_pools, .guard = .{ .ctx = n, .lock = guardLock, .unlock = unlockFn } };
    }

    pub fn storage(n: *Node) backend.StorageBackend {
        return n.router.backend();
    }

    /// Creates the object service once the catalog is readable (needs read quorum).
    pub fn initService(n: *Node, out: *object.ObjectService) Error!void {
        var last_log: i64 = 0;
        while (true) {
            if (n.stop_ev.isSet()) return error.Stopped;
            if (object.ObjectService.initWith(n.gpa, n.storage(), false)) |svc| {
                out.* = svc;
                out.cluster = .{ .ctx = n, .vtable = &cluster_vtable };
                n.svc.store(out, .release);
                return;
            } else |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                const now = std.time.timestamp();
                if (now - last_log >= 5) {
                    last_log = now;
                    std.log.info("cluster: waiting for metadata read quorum ({t})", .{e});
                }
            }
            n.stop_ev.timedWait(time_ns(1)) catch {};
        }
    }

    fn time_ns(s: u64) u64 {
        return s * std.time.ns_per_s;
    }

    /// IAM persistence on the cluster store; mutations lock and notify peers.
    pub fn iamPersistence(n: *Node) iam.store.Persistence {
        n.iam_persist = .{ .node = n };
        return n.iam_persist.persistence();
    }

    /// Starts serving S3 and all background work.
    pub fn start(n: *Node, iam_store: ?*iam.Store) void {
        n.iam_store.store(iam_store, .release);
        n.locks.start();
        for (n.pools) |*p| for (p.sets) |*s| {
            s.healer.start(time_ns(n.cfg.scan_interval_s)) catch std.log.err("cluster: healer not started", .{});
        };
        n.spawn(refreshLoop);
        n.spawn(spaceLoop);
        n.open.store(true, .release);
        // Notes that arrived before the service existed were dropped: catch up.
        if (n.missed.swap(false, .acq_rel)) if (n.svc.load(.acquire)) |svc| {
            svc.applyChange(.resync);
        };
    }

    // ---- health ----

    /// Ready: serving, a lock majority is reachable, and every set has write quorum.
    pub fn ready(n: *Node) bool {
        if (!n.open.load(.acquire) or !n.locks.haveQuorum()) return false;
        for (n.pools) |*p| for (p.sets) |*s| if (!s.drives.writable()) return false;
        return true;
    }

    /// The lowest-numbered reachable node runs cluster-wide chores (lifecycle, sweeps).
    pub fn isLeader(n: *Node) bool {
        for (0..n.topo.nodes.len) |i| {
            if (n.rpc.isOnline(@intCast(i))) return i == n.topo.local;
        }
        return false;
    }

    fn healLeader(ctx: *anyopaque, drives: *placement.DriveSet) bool {
        const n: *Node = @ptrCast(@alignCast(ctx));
        var best: ?u16 = null;
        for (drives.drives) |d| {
            if (!n.rpc.isOnline(d.node)) continue;
            if (best == null or d.node < best.?) best = d.node;
        }
        return best == n.topo.local;
    }

    fn onPeerChange(ctx: *anyopaque, node: u16, up: bool) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        if (!up) return;
        // A returning node may miss shards and cached state: heal and resync it.
        for (n.pools) |*p| for (p.sets) |*s| {
            for (s.drives.drives) |d| if (d.node == node) {
                s.healer.wake();
                break;
            };
        };
        if (n.open.load(.acquire)) n.sendNotes(node, &.{.{ .change = .resync }});
    }

    // ---- change notifications ----

    const cluster_vtable: object.service.Cluster.VTable = .{ .lock = lockFn, .unlock = unlockFn, .publish = publishFn };

    fn lockFn(ctx: *anyopaque, resource: []const u8) object.Error!u64 {
        const n: *Node = @ptrCast(@alignCast(ctx));
        return n.locks.lock(resource) catch |e| switch (e) {
            error.NoQuorum => error.WriteQuorum,
            error.LockTimeout => error.LockTimeout,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    fn guardLock(ctx: *anyopaque, key: backend.PhysicalKey) backend.Error!u64 {
        const n: *Node = @ptrCast(@alignCast(ctx));
        var buf: [40]u8 = undefined;
        const res = std.fmt.bufPrint(&buf, "pk/{c}{s}", .{ wire.spaceChar(key.space), &key.hex }) catch unreachable;
        return n.locks.lock(res) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.WriteQuorum,
        };
    }

    fn unlockFn(ctx: *anyopaque, token: u64) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        n.locks.unlock(token);
    }

    fn publishFn(ctx: *anyopaque, changes: []const object.service.Change) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        const notes = n.gpa.alloc(wire.Note, changes.len) catch return;
        defer n.gpa.free(notes);
        for (changes, notes) |c, *o| o.* = .{ .change = c };
        n.broadcast(notes);
    }

    pub fn broadcast(n: *Node, notes: []const wire.Note) void {
        for (0..n.topo.nodes.len) |i| {
            const node: u16 = @intCast(i);
            if (node == n.topo.local or !n.rpc.isOnline(node)) continue;
            n.sendNotes(node, notes);
        }
    }

    fn sendNotes(n: *Node, node: u16, notes: []const wire.Note) void {
        const body = wire.encodeNotes(n.gpa, notes) catch return;
        defer n.gpa.free(body);
        if (body.len > wire.max_notify) return n.sendNotes(node, &.{.{ .change = .resync }});
        var c = n.rpc.call(node, "notify", "", .{ .bytes = body }, .{ .timeout_ms = 5000 }) catch return;
        c.deinit();
    }

    /// Applies a peer's note to this node's caches.
    pub fn applyNote(n: *Node, note: wire.Note) void {
        switch (note) {
            .pools => if (n.pools_hook) |h| h.func(h.ctx),
            .iam => if (n.iam_store.load(.acquire)) |s| s.reload() catch |e| std.log.warn("iam reload failed: {t}", .{e}),
            .change => |c| {
                const svc = n.svc.load(.acquire) orelse {
                    n.missed.store(true, .release);
                    return;
                };
                svc.applyChange(c);
                if (c == .resync) if (n.iam_store.load(.acquire)) |s| s.reload() catch {};
            },
        }
    }

    // ---- background loops ----

    fn heartbeatLoop(n: *Node) void {
        while (!n.stop_ev.isSet()) {
            for (0..n.topo.nodes.len) |i| {
                const node: u16 = @intCast(i);
                if (node == n.topo.local) continue;
                // A peer still bootstrapping cannot serve drive I/O yet.
                if (n.hello(node)) |h| n.rpc.setOnline(node, h.drives) else |_| n.rpc.setOnline(node, false);
            }
            _ = n.leases.sweep(std.time.milliTimestamp());
            if (n.svc.load(.acquire)) |svc| svc.collectDeferred(false);
            n.stop_ev.timedWait(heartbeat_ns) catch {};
        }
    }

    fn refreshLoop(n: *Node) void {
        var round: u64 = 0;
        while (true) {
            n.stop_ev.timedWait(time_ns(@max(n.cfg.refresh_s, 1))) catch {};
            if (n.stop_ev.isSet()) return;
            round += 1;
            if (n.svc.load(.acquire)) |svc| {
                svc.reloadCatalog() catch |e| std.log.debug("catalog refresh: {t}", .{e});
                // A full index rebuild is the slow backstop for lost notifications.
                if (round % 60 == 0) svc.rebuildIndex() catch |e| std.log.warn("key index refresh: {t}", .{e});
            }
            if (n.iam_store.load(.acquire)) |s| s.reload() catch |e| std.log.debug("iam refresh: {t}", .{e});
        }
    }

    fn spaceLoop(n: *Node) void {
        while (true) {
            n.stop_ev.timedWait(time_ns(30)) catch {};
            if (n.stop_ev.isSet()) return;
            n.refreshSpace();
        }
    }

    /// Pool room: per drive, capacity minus what this deployment stores there.
    pub fn refreshSpace(n: *Node) void {
        for (n.topo.pools, 0..) |pool, p| {
            var free: u64 = 0;
            var total: u64 = 0;
            for (pool.endpoints, 0..) |_, i| {
                if (n.local_eps[p][i]) |*le| {
                    measure(le);
                    free += le.total.load(.monotonic) -| le.used.load(.monotonic);
                    total += le.total.load(.monotonic);
                } else if (n.remoteSpace(p, i)) |sp| {
                    free += sp.total -| sp.used;
                    total += sp.total;
                }
            }
            if (p < n.router_pools.len) {
                n.router_pools[p].free.store(free, .monotonic);
                n.router_pools[p].total.store(total, .monotonic);
            }
        }
    }

    pub const Space = struct { total: u64, used: u64 };

    pub fn remoteSpace(n: *Node, p: usize, i: usize) ?Space {
        const rd = &n.remotes[p][i].?;
        if (!n.rpc.isOnline(rd.node)) return null;
        var qb: [32]u8 = undefined;
        var c = n.rpc.call(rd.node, "diskinfo", std.fmt.bufPrint(&qb, "d={d}.{d}", .{ p, i }) catch unreachable, .{ .bytes = "" }, .{ .timeout_ms = 5000 }) catch return null;
        defer c.deinit();
        if (!c.ok()) return null;
        var buf: [128]u8 = undefined;
        if (c.body_left > buf.len) return null;
        const body = buf[0..@intCast(c.body_left)];
        c.readInto(body) catch return null;
        var total: u64 = 0;
        var used: u64 = 0;
        var it = std.mem.tokenizeScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (std.mem.startsWith(u8, line, "total ")) total = std.fmt.parseInt(u64, line[6..], 10) catch 0;
            if (std.mem.startsWith(u8, line, "used ")) used = std.fmt.parseInt(u64, line[5..], 10) catch 0;
        }
        return .{ .total = total, .used = used };
    }
};

const heartbeat_ns = std.time.ns_per_s;

/// Capacity from statvfs and bytes held under the drive's key spaces.
fn measure(le: *LocalEp) void {
    var dir = std.fs.cwd().openDir(le.path, .{ .iterate = true }) catch return;
    defer dir.close();
    // struct statfs on 64-bit Linux: type, bsize, blocks, ..., frsize at word 9.
    var st: [16]u64 = @splat(0);
    if (std.os.linux.E.init(std.os.linux.syscall2(.fstatfs, @intCast(dir.fd), @intFromPtr(&st))) == .SUCCESS) {
        const unit = if (st[9] != 0) st[9] else st[1];
        le.total.store(st[2] *| unit, .monotonic);
    }
    var used: u64 = 0;
    for ([_][]const u8{ "data", "record", "system" }) |sub| {
        var d = dir.openDir(sub, .{ .iterate = true }) catch continue;
        defer d.close();
        var w = d.walk(std.heap.page_allocator) catch continue;
        defer w.deinit();
        while (w.next() catch null) |e| {
            if (e.kind != .file) continue;
            const fst = e.dir.statFile(e.basename) catch continue;
            used += fst.size;
        }
    }
    le.used.store(used, .monotonic);
}

fn topoFingerprint(t: *const topology.Topology) [16]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zkfsm-topology-v1\n");
    for (t.pools) |p| {
        h.update("pool\n");
        for (p.endpoints) |e| {
            h.update(e.url);
            h.update("\n");
        }
    }
    var d: [32]u8 = undefined;
    h.final(&d);
    return d[0..16].*;
}

/// IAM snapshot as one system record, guarded by a cluster lock while it changes.
pub const IamPersist = struct {
    node: *Node,
    /// Serializes local mutations so one lock uid is held at a time.
    mutex: std.Thread.Mutex = .{},
    uid: u64 = 0,

    const key: backend.PhysicalKey = .{ .space = .system, .hex = "7a6b66736d2d69616d2d736e617073ff".* };

    pub fn persistence(self: *IamPersist) iam.store.Persistence {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save, .lock = lock, .unlock = unlock } };
    }

    fn cast(ptr: *anyopaque) *IamPersist {
        return @ptrCast(@alignCast(ptr));
    }

    fn load(ptr: *anyopaque, gpa: std.mem.Allocator) iam.store.PersistError!?[]u8 {
        const self = cast(ptr);
        return self.node.storage().getRecord(key, gpa) catch |e| switch (e) {
            error.NotFound => null,
            error.OutOfMemory => error.OutOfMemory,
            error.TooLarge => error.StoreTooLarge,
            else => error.PersistFailed,
        };
    }

    fn save(ptr: *anyopaque, bytes: []const u8) iam.store.PersistError!void {
        const self = cast(ptr);
        self.node.storage().putRecord(key, bytes) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.TooLarge => error.StoreTooLarge,
            else => error.PersistFailed,
        };
    }

    fn lock(ptr: *anyopaque) iam.store.PersistError!void {
        const self = cast(ptr);
        self.mutex.lock();
        self.uid = self.node.locks.lock("iam") catch |e| {
            self.mutex.unlock();
            return if (e == error.OutOfMemory) error.OutOfMemory else error.PersistFailed;
        };
    }

    fn unlock(ptr: *anyopaque) void {
        const self = cast(ptr);
        self.node.locks.unlock(self.uid);
        self.mutex.unlock();
        self.node.broadcast(&.{.iam});
    }
};
