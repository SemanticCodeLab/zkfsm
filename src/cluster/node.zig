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
const journal_mod = @import("journal.zig");
const catchup = @import("catchup.zig");

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
    /// A membership update is applied but a new pool cannot open yet; call again.
    NotReady,
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
    /// Membership is managed at runtime (`applyMembership`): peers may briefly run
    /// with other endpoint lists, so their fingerprints are not compared.
    dynamic: bool = false,
};

/// A runtime membership update: every pool, in order (the current list as prefix).
pub const Membership = struct {
    /// Reported to peers in hello once nonzero (see `allApplied`).
    epoch: u64,
    /// Per pool, its endpoint arguments, as in `Config.pools`.
    pools: []const []const []const u8,
    /// The change is still settling: locks also need a majority of the previous voters.
    settling: bool = false,
};

/// Peer-call channels: 0 is `Node.ext`, the rest are for embedding builds.
pub const ext_channels = 4;

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

/// A peer-call handler owned by a higher layer; returns the response body in `arena`.
pub const Ext = struct {
    ctx: *anyopaque,
    handle: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, body: []const u8) error{OutOfMemory}![]const u8,
};
pub const Hook = struct { ctx: *anyopaque, func: *const fn (ctx: *anyopaque) void };
/// Applies the latest pool state and drains unguarded writes; returns its epoch.
pub const SyncHook = struct { ctx: *anyopaque, func: *const fn (ctx: *anyopaque) ?u64 };

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
    /// Requests refused for a clock difference beyond the window (served, and sent).
    clock_rejects: std.atomic.Value(u64) = .init(0),
    clock_refused: std.atomic.Value(u64) = .init(0),
    clock_log_ms: std.atomic.Value(i64) = .init(0),
    /// Random per process: tells peers a restart from an uninterrupted run.
    boot_id: u64 = 0,
    /// This node is writing a pool's formats: peers must not judge the pool yet.
    formatting: std.atomic.Value(bool) = .init(false),
    /// S3 service is up (the server's gate).
    open: std.atomic.Value(bool) = .init(false),
    svc: std.atomic.Value(?*object.ObjectService) = .init(null),
    iam_store: std.atomic.Value(?*iam.Store) = .init(null),
    stop_ev: std.Thread.ResetEvent = .{},
    threads: std.ArrayList(std.Thread) = .empty,
    stopped: bool = false,
    /// Per peer: it came back online (IAM and caches may lag).
    returned: []std.atomic.Value(bool) = &.{},
    sync_ev: std.Thread.ResetEvent = .{},
    /// This node's index changes, in order; peers pull what they missed.
    journal: journal_mod.Journal = undefined,
    journal_ok: std.atomic.Value(bool) = .init(false),
    /// How far each peer's journal is applied to our key index.
    origins: catchup.Origins = undefined,
    /// Node-local files (journal, index snapshot) on the first local drive.
    node_dir: ?std.fs.Dir = null,
    last_snapshot_ms: i64 = 0,
    /// Our journal position when we started serving (peers pull from there).
    jopen: std.atomic.Value(u64) = .init(0),
    gc: Gc = .{},
    iam_persist: IamPersist = undefined,
    /// Handler for "ext" calls from peers (subsystems above the cluster layer).
    ext: std.atomic.Value(?*const Ext) = .init(null),
    /// Per endpoint-list pool, its index in the deployment (kept when pools are removed).
    orig: []u32 = &.{},
    /// Deployment pools that finished decommissioning (bit per index).
    retired: u64 = 0,
    retire_mu: std.Thread.Mutex = .{},
    /// Deployment pools ever formatted; recorded in drive formats.
    pool_count: u32 = 0,
    /// Called when a peer announces a pool state change.
    pools_hook: ?Hook = null,
    pools_sync: ?SyncHook = null,
    /// "ext" handlers for channels 1.. (`setExt`).
    ext_more: [ext_channels - 1]std.atomic.Value(?*const Ext) = @splat(.init(null)),
    /// Membership epoch applied here, and the last one each peer reported.
    epoch: std.atomic.Value(u64) = .init(0),
    peer_epochs: []std.atomic.Value(u64) = &.{},
    member_mutex: std.Thread.Mutex = .{},
    /// Lock voters after the last update (zero: never set), and the settling set.
    voters: u256 = 0,
    prev_voters: u256 = 0,

    /// Parses the topology and prepares RPC; nothing touches peers yet.
    pub fn create(gpa: std.mem.Allocator, cfg: Config) Error!*Node {
        const n = try gpa.create(Node);
        errdefer gpa.destroy(n);
        if (std.posix.getenv("ZKFSM_TEST_CLOCK_SKEW_S")) |v| auth.clock_offset_ms = (std.fmt.parseInt(i64, v, 10) catch 0) * std.time.ms_per_s;
        n.* = .{
            .gpa = gpa,
            .arena_state = .init(gpa),
            .cfg = cfg,
            .topo = undefined,
            .rpc = undefined,
            .guard = .{ .gpa = gpa },
            .boot_id = std.crypto.random.int(u64) | 1,
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
        const parsed = topology.parse(a, cfg.pools, cfg.node_address, cfg.listen_host, cfg.listen_port) catch |e| {
            std.log.err("cluster endpoints: {t}", .{e});
            return error.BadTopology;
        };
        if (parsed.pools.len > router_mod.max_pools) {
            std.log.err("cluster: at most {d} pools", .{router_mod.max_pools});
            return error.BadTopology;
        }
        // Fixed capacity: `applyMembership` appends nodes and pools while others read.
        n.topo = parsed;
        n.topo.nodes = try capacity(a, topology.Node, parsed.nodes, topology.max_nodes);
        n.topo.pools = try capacity(a, topology.Pool, parsed.pools, router_mod.max_pools);
        n.topo_fp = topoFingerprint(&n.topo);
        n.orig = (try a.alloc(u32, router_mod.max_pools))[0..n.topo.pools.len];
        for (n.orig, 0..) |*o, p| o.* = @intCast(p);
        n.rpc = rpc_mod.Rpc.init(gpa, &n.topo, cfg.secret) catch return error.OutOfMemory;
        errdefer n.rpc.deinit();
        if (n.topo.tls) try n.loadCa();
        n.returned = try a.alloc(std.atomic.Value(bool), topology.max_nodes);
        for (n.returned) |*r| r.* = .init(false);
        n.returned.len = n.topo.nodes.len;
        n.peer_epochs = try a.alloc(std.atomic.Value(u64), topology.max_nodes);
        for (n.peer_epochs) |*e| e.* = .init(0);
        n.origins = try catchup.Origins.init(gpa, n.topo.nodes.len, topology.max_nodes);
        errdefer n.origins.deinit();
        n.local_eps = (try a.alloc([]?LocalEp, router_mod.max_pools))[0..n.topo.pools.len];
        n.remotes = (try a.alloc([]?remote_drive.RemoteDrive, router_mod.max_pools))[0..n.topo.pools.len];
        for (0..n.topo.pools.len) |p| try n.initEndpoints(p);
        n.locks = .{ .gpa = gpa, .rpc = &n.rpc, .table = &n.table };
        n.rpc.on_change = .{ .ctx = n, .func = onPeerChange };
        std.log.info("cluster: node {d} of {d} ({s}), {d} pool(s)", .{ n.topo.local + 1, n.topo.nodes.len, n.topo.nodes[n.topo.local].name, n.topo.pools.len });
        return n;
    }

    fn capacity(a: std.mem.Allocator, comptime T: type, items: []const T, cap: usize) Error![]T {
        const buf = try a.alloc(T, @max(cap, items.len));
        @memcpy(buf[0..items.len], items);
        return buf[0..items.len];
    }

    fn initEndpoints(n: *Node, p: usize) Error!void {
        const a = n.arena_state.allocator();
        const pool = n.topo.pools.ptr[p];
        const le = try a.alloc(?LocalEp, pool.endpoints.len);
        const re = try a.alloc(?remote_drive.RemoteDrive, pool.endpoints.len);
        for (pool.endpoints, 0..) |ep, i| {
            le[i] = null;
            re[i] = null;
            if (n.topo.isLocal(ep)) {
                le[i] = .{ .path = ep.path };
            } else {
                re[i] = remote_drive.RemoteDrive.init(n.gpa, &n.rpc, ep.node, @intCast(p), @intCast(i));
            }
        }
        n.local_eps.ptr[p] = le;
        n.remotes.ptr[p] = re;
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
        for (n.pools) |*p| for (p.sets) |*s| {
            s.strategy.deinit();
            s.drives.deinit();
        };
        n.locks.deinit();
        n.table.deinit();
        n.leases.deinit();
        n.origins.deinit();
        n.gc.deinit(n.gpa);
        if (n.journal_ok.load(.acquire)) n.journal.deinit();
        if (n.node_dir) |*d| d.close();
        n.guard.deinit();
        n.rpc.deinit();
        n.threads.deinit(n.gpa);
        n.arena_state.deinit();
        n.gpa.destroy(n);
    }

    /// Stops background threads (healers, heartbeat, refresh); saves the index
    /// snapshot and closes the journal cleanly. Call before the service goes away.
    pub fn stop(n: *Node) void {
        if (n.stopped) return;
        n.stopped = true;
        n.stop_ev.set();
        n.sync_ev.set();
        for (n.pools) |*p| for (p.sets) |*s| s.healer.stop();
        for (n.threads.items) |t| t.join();
        n.threads.clearRetainingCapacity();
        if (n.drives_open.load(.acquire)) n.collectGarbage(true);
        if (n.open.load(.acquire)) if (n.svc.load(.acquire)) |svc| n.saveSnapshot(svc);
        n.svc.store(null, .release);
        if (n.journal_ok.load(.acquire)) n.journal.sync(true);
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
        // Measured once while no writes can arrive; commits and deletes keep it exact.
        n.trackUsage();
        n.openJournal();
        n.drives_open.store(true, .release);
        // Learn which peers are up, and tell them we are, before serving anything:
        // a write that misses a live peer's drives would be stored degraded.
        n.heartbeatRound();
        n.refreshSpace();
        std.log.info("cluster: deployment {s}, protection {s}, {d} set(s)", .{ &std.fmt.bytesToHex(n.deployment, .lower), n.profile.name(), n.setCount() });
    }

    /// True at most once every ten seconds per `last`: keeps a repeating error readable.
    pub fn logNow(n: *Node, last: *std.atomic.Value(i64)) bool {
        _ = n;
        const now = std.time.milliTimestamp();
        const prev = last.load(.monotonic);
        if (now - prev < 10_000) return false;
        return last.cmpxchgStrong(prev, now, .monotonic, .monotonic) == null;
    }

    /// Prometheus lines for node-to-node health.
    pub fn renderMetrics(ctx: *anyopaque, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        try w.writeAll("# HELP zkfsm_cluster_rpc_clock_skew_rejected_total Node-to-node requests refused because the sender's clock is outside the allowed window.\n# TYPE zkfsm_cluster_rpc_clock_skew_rejected_total counter\n");
        try w.print("zkfsm_cluster_rpc_clock_skew_rejected_total{{direction=\"received\"}} {d}\n", .{n.clock_rejects.load(.monotonic)});
        try w.print("zkfsm_cluster_rpc_clock_skew_rejected_total{{direction=\"sent\"}} {d}\n", .{n.clock_refused.load(.monotonic)});
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
            if (node == n.topo.local or !n.isMember(i)) continue;
            const h = n.hello(node) catch |e| {
                if (e == error.CredentialMismatch) return error.CredentialMismatch;
                continue;
            };
            if (!n.cfg.dynamic and !std.mem.eql(u8, &h.topo, &n.topo_fp)) {
                std.log.err("cluster: node {s} runs with a different endpoint list", .{n.topo.nodes[i].name});
                return error.LayoutMismatch;
            }
            if (!std.mem.eql(u8, &h.root, &n.root_fp)) {
                std.log.err("cluster: node {s} runs with different root credentials", .{n.topo.nodes[i].name});
                return error.CredentialMismatch;
            }
        }
    }

    const Hello = struct { topo: [16]u8, root: [16]u8, ready: bool, drives: bool, formatting: bool = false, boot: u64 = 0, jepoch: u64 = 0, jseq: u64 = 0, jopen: ?u64 = null, epoch: u64 = 0 };

    /// Asks a peer who it is; once our drives are open the call also tells the peer
    /// to count us online at once rather than at its next heartbeat.
    fn hello(n: *Node, node: u16) error{ Unreachable, Busy, CredentialMismatch }!Hello {
        const q = if (n.drives_open.load(.acquire)) "drives=1" else "";
        var c = n.rpc.call(node, "hello", q, .{ .bytes = "" }, .{ .probe = true, .timeout_ms = 2000 }) catch |e| {
            if (e == error.Busy) return error.Busy;
            std.log.debug("hello to {s}: {t}", .{ n.topo.nodes[node].name, e });
            return error.Unreachable;
        };
        defer c.deinit();
        if (c.status == 401 and std.mem.eql(u8, c.meta.err(), "Expired")) {
            // Not a credential problem, and time sync may still fix it: keep trying.
            _ = n.clock_refused.fetchAdd(1, .monotonic);
            if (n.logNow(&n.clock_log_ms)) std.log.err("cluster: node {s} refused our requests: our clocks differ by more than {d} s; synchronize the clocks", .{ n.topo.nodes[node].name, @divTrunc(auth.window_ms, 1000) });
            return error.Unreachable;
        }
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
            } else if (std.mem.eql(u8, k, "drives")) {
                h.drives = std.mem.eql(u8, v, "1");
            } else if (std.mem.eql(u8, k, "formatting")) {
                h.formatting = std.mem.eql(u8, v, "1");
            } else if (std.mem.eql(u8, k, "boot")) {
                h.boot = std.fmt.parseInt(u64, v, 10) catch 0;
            } else if (std.mem.eql(u8, k, "jepoch")) {
                h.jepoch = std.fmt.parseInt(u64, v, 10) catch 0;
            } else if (std.mem.eql(u8, k, "jseq")) {
                h.jseq = std.fmt.parseInt(u64, v, 10) catch 0;
            } else if (std.mem.eql(u8, k, "epoch")) {
                h.epoch = std.fmt.parseInt(u64, v, 10) catch 0;
            } else if (std.mem.eql(u8, k, "jopen")) h.jopen = std.fmt.parseInt(u64, v, 10) catch null;
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
            if (any) {
                // Formatted drives next to empty ones: a replaced drive, or a pool whose
                // formats are being written right now. Only its formatter can tell.
                const partial = for (s) |e| {
                    if (e == .none) break true;
                } else false;
                const owner = n.topo.pools[p].endpoints[0].node;
                if (partial and owner != n.topo.local) {
                    if (n.hello(owner)) |h| {
                        if (h.formatting) return false;
                    } else |_| {}
                }
                continue;
            }
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

    /// Records pools as decommissioned in drive formats (remote drives too unless
    /// `local_only`); returns the number of drives that could not be updated.
    pub fn markRetired(n: *Node, mask: u64, local_only: bool) usize {
        n.retire_mu.lock();
        defer n.retire_mu.unlock();
        const want = n.retired | mask;
        var failed: usize = 0;
        for (n.topo.pools, 0..) |pool, p| for (pool.endpoints, 0..) |_, i| {
            if (n.local_eps[p][i]) |le| {
                retireLocal(le.path, want) catch {
                    failed += 1;
                };
            } else if (!local_only) {
                const f = switch (n.readFormat(p, i)) {
                    .fmt => |f| f,
                    else => {
                        failed += 1;
                        continue;
                    },
                };
                var g = f;
                g.retired |= want;
                var buf: [layout.format_max]u8 = undefined;
                const bytes = g.encode(&buf) catch {
                    failed += 1;
                    continue;
                };
                n.writeFormat(p, i, bytes) catch {
                    failed += 1;
                };
            }
        };
        // Applied in memory only once recorded, so a failed attempt is retried.
        if (failed > 0) return failed;
        n.retired = want;
        for (n.pools) |*ps| for (ps.sets) |*st| if (st.drives.cluster) |*c| {
            c.format.retired = n.retired;
        };
        return failed;
    }

    /// ORs `mask` into the retired pools of the format on the drive at `path`.
    pub fn retireLocal(path: []const u8, mask: u64) !void {
        var lb = try backend.local.LocalBackend.open(path);
        defer lb.close();
        var buf: [layout.format_max]u8 = undefined;
        const f = try FormatV2.parse(try lb.readFormat(&buf));
        if (f.retired & mask == mask) return;
        var g = f;
        g.retired |= mask;
        var out: [layout.format_max]u8 = undefined;
        try lb.writeFormat(try g.encode(&out));
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
        n.formatting.store(true, .release);
        defer n.formatting.store(false, .release);
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
        // Empty until opened, so a failed bootstrap stops and frees cleanly.
        n.pools = (try a.alloc(PoolState, router_mod.max_pools))[0..n.topo.pools.len];
        for (n.pools) |*p| p.* = .{ .set_size = 0, .sets = &.{}, .backends = &.{} };
        n.router_pools = (try a.alloc(router_mod.Pool, router_mod.max_pools))[0..n.topo.pools.len];
        for (0..n.topo.pools.len) |p| try n.openPool(p, seen[p]);
        n.router = .{ .gpa = n.gpa, .pools = n.router_pools, .guard = .{ .ctx = n, .lock = guardLock, .unlock = unlockFn } };
    }

    /// Opens pool `p`'s sets and fills its router entry (not yet published).
    fn openPool(n: *Node, p: usize, seen: []const Seen) Error!void {
        const a = n.arena_state.allocator();
        const pool = n.topo.pools[p];
        var size: usize = 0;
        for (seen) |e| if (e == .fmt) {
            size = e.fmt.set_size;
            break;
        };
        const fp = topology.poolFingerprint(pool, size, n.profile);
        const sets = try n.assignment(p, size);
        defer layout.freeSets(n.gpa, sets);
        // Every reachable drive must sit exactly where the layout puts it.
        for (sets, 0..) |members, si| for (members, 0..) |ep, idx| {
            const f = switch (seen[ep]) {
                .fmt => |f| f,
                else => continue,
            };
            const ok = std.mem.eql(u8, &f.layout, &fp) and f.pool == n.orig[p] and f.set == si and f.index == idx and f.set_size == size and f.profile.eql(n.profile);
            if (!ok) {
                std.log.err("cluster: drive {s} was formatted for a different layout (endpoint list, order, or protection changed)", .{pool.endpoints[ep].url});
                return error.LayoutMismatch;
            }
        };
        const ps = &n.pools.ptr[p];
        const set_states = try a.alloc(SetState, sets.len);
        ps.* = .{ .set_size = size, .sets = set_states[0..0], .backends = try a.alloc(backend.StorageBackend, sets.len) };
        for (sets, 0..) |members, si| {
            const st = &set_states[si];
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
            st.strategy = protection.Strategy.init(n.gpa, &st.drives, &st.stores) catch {
                st.drives.deinit();
                return error.BadLayout;
            };
            st.healer = heal.Healer.init(n.gpa, &st.drives, st.strategy, .{});
            st.healer.leader = .{ .ctx = n, .func = healLeader };
            ps.backends[si] = st.strategy.backend();
            ps.sets = set_states[0 .. si + 1];
            for (members, 0..) |ep, idx| if (n.local_eps[p][ep]) |*le| {
                le.set = &st.drives;
                le.slot = @intCast(idx);
            };
        }
        var seed: [8]u8 = undefined;
        @memcpy(&seed, n.deployment[0..8]);
        n.router_pools.ptr[p] = .{ .sets = ps.backends, .seed = std.mem.readInt(u64, &seed, .little) +% n.orig[p] };
        if (n.retired & (@as(u64, 1) << @intCast(n.orig[p])) != 0) n.router_pools.ptr[p].mode = .init(.retired);
    }

    // ---- runtime membership (extension point) ----

    /// Applies a membership update on a running node: appends new nodes and pools,
    /// formats and opens new pools once their drives answer, and sets lock voters
    /// (nodes with a drive in a pool that is not retired). Idempotent: call it again
    /// after `error.NotReady`, or after pool modes change. Pool modes themselves stay
    /// with the pools manager (decommission, rebalance).
    pub fn applyMembership(n: *Node, m: Membership) Error!void {
        if (!n.drives_open.load(.acquire)) return error.NotReady;
        n.member_mutex.lock();
        defer n.member_mutex.unlock();
        if (m.pools.len < n.topo.pools.len or m.pools.len > router_mod.max_pools) return error.LayoutMismatch;
        if (m.pools.len > n.topo.pools.len) try n.extend(m.pools);
        // New pools open in order: the router only shows a prefix of the list.
        var pending = false;
        while (n.router.pools.len < n.topo.pools.len) {
            n.tryOpenPool(n.router.pools.len) catch |e| switch (e) {
                error.NotReady => {
                    pending = true;
                    break;
                },
                else => return e,
            };
        }
        const old = if (n.voters == 0) allNodes(n.topo.nodes.len) else n.voters;
        const cur = n.memberMask();
        if (cur != old) n.prev_voters = old;
        n.voters = cur;
        if (!m.settling) n.prev_voters = 0;
        n.markMembers();
        n.locks.setVoters(n.voters, n.prev_voters);
        n.epoch.store(m.epoch, .release);
        if (pending) return error.NotReady;
    }

    /// Appends the nodes and pools `specs` adds to the live arrays.
    fn extend(n: *Node, specs_in: []const []const []const u8) Error!void {
        const a = n.arena_state.allocator();
        const specs = try a.alloc([]const []const u8, specs_in.len);
        for (specs_in, specs) |ps, *o| {
            const eps = try a.alloc([]const u8, ps.len);
            for (ps, eps) |e, *d| d.* = try a.dupe(u8, e);
            o.* = eps;
        }
        const t = topology.parse(a, specs, n.topo.nodes[n.topo.local].name, n.cfg.listen_host, n.cfg.listen_port) catch |e| {
            std.log.err("cluster: membership endpoints: {t}", .{e});
            return error.BadTopology;
        };
        if (t.tls != n.topo.tls or t.local != n.topo.local) return error.LayoutMismatch;
        for (n.topo.nodes, 0..) |old, i| if (!std.mem.eql(u8, old.name, t.nodes[i].name)) return error.LayoutMismatch;
        for (n.topo.pools, 0..) |old, p| {
            if (old.endpoints.len != t.pools[p].endpoints.len) return error.LayoutMismatch;
            for (old.endpoints, t.pools[p].endpoints) |x, y| if (!std.mem.eql(u8, x.url, y.url)) return error.LayoutMismatch;
        }
        const nn = t.nodes.len;
        @memcpy(n.topo.nodes.ptr[n.topo.nodes.len..nn], t.nodes[n.topo.nodes.len..]);
        n.origins.grow(nn);
        n.rpc.grow(t.nodes) catch return error.OutOfMemory;
        @atomicStore(usize, &n.returned.len, nn, .release);
        @atomicStore(usize, &n.topo.nodes.len, nn, .release);
        const np = t.pools.len;
        for (n.topo.pools.len..np) |p| {
            n.topo.pools.ptr[p] = t.pools[p];
            n.orig.ptr[p] = n.pool_count;
            n.pool_count += 1;
            try n.initEndpoints(p);
            n.pools.ptr[p] = .{ .set_size = 0, .sets = &.{}, .backends = &.{} };
        }
        n.cfg.pools = specs;
        @atomicStore(usize, &n.orig.len, np, .release);
        @atomicStore(usize, &n.local_eps.len, np, .release);
        @atomicStore(usize, &n.remotes.len, np, .release);
        @atomicStore(usize, &n.pools.len, np, .release);
        @atomicStore(usize, &n.topo.pools.len, np, .release);
        n.topo_fp = topoFingerprint(&n.topo);
        std.log.info("cluster: membership now {d} node(s), {d} pool(s)", .{ nn, np });
    }

    /// Formats a new pool (its first endpoint's owner does) or opens and publishes it.
    fn tryOpenPool(n: *Node, p: usize) Error!void {
        const seen = try n.gpa.alloc(Seen, n.topo.pools[p].endpoints.len);
        defer n.gpa.free(seen);
        for (seen, 0..) |*e, i| e.* = n.readFormat(p, i);
        var formatted = false;
        var partial = false;
        var reachable = true;
        for (seen) |e| switch (e) {
            .fmt => |f| {
                if (!std.mem.eql(u8, &f.deployment, &n.deployment)) return error.LayoutMismatch;
                // The formatter numbered the pool; follow it.
                n.orig[p] = f.pool;
                n.pool_count = @max(n.pool_count, f.pool + 1);
                formatted = true;
            },
            .none => partial = true,
            .unknown => reachable = false,
            .bad => return error.LayoutMismatch,
        };
        if (!formatted or (partial and n.formatter(p))) {
            if (reachable and n.formatter(p)) try n.formatPool(p, seen);
            return error.NotReady;
        }
        // The formatter may be writing formats right now.
        const owner = n.topo.pools[p].endpoints[0].node;
        if (partial and owner != n.topo.local) {
            const h = n.hello(owner) catch return error.NotReady;
            if (h.formatting) return error.NotReady;
        }
        try n.openPool(p, seen);
        for (n.pools[p].sets) |*st| for (st.endpoints, 0..) |ep, slot| if (n.local_eps[p][ep]) |*le| {
            measure(le);
            st.drives.drives[slot].kind.local.usage = &le.used;
        };
        @atomicStore(usize, &n.router_pools.len, p + 1, .release);
        n.router.publish(p + 1);
        n.refreshSpace();
        if (n.open.load(.acquire)) for (n.pools[p].sets) |*st| {
            st.healer.start(time_ns(n.cfg.scan_interval_s)) catch std.log.err("cluster: healer not started", .{});
        };
        std.log.info("cluster: pool {d} open: {d} set(s)", .{ p + 1, n.pools[p].sets.len });
    }

    /// Nodes with a drive in a pool that is not retired.
    fn memberMask(n: *const Node) u256 {
        var m: u256 = 0;
        for (n.topo.pools, 0..) |pool, p| {
            if (p < n.router.pools.len and n.router.mode(p) == .retired) continue;
            for (pool.endpoints) |e| m |= @as(u256, 1) << @intCast(e.node);
        }
        return m;
    }

    /// Voters and, while a change settles, the previous ones get heartbeats; others
    /// are taken offline and left alone.
    fn markMembers(n: *Node) void {
        const m = n.voters | n.prev_voters;
        for (n.rpc.peers, 0..) |*peer, i| {
            const member = m & (@as(u256, 1) << @intCast(i)) != 0;
            peer.member.store(member, .release);
            if (!member and i != n.topo.local) n.rpc.setOnline(@intCast(i), false);
        }
    }

    pub fn isMember(n: *const Node, node: usize) bool {
        return node < n.rpc.peers.len and n.rpc.peers[node].member.load(.acquire);
    }

    /// True once this node and every reachable-member peer report `epoch` or later.
    pub fn allApplied(n: *Node, epoch: u64) bool {
        if (n.epoch.load(.acquire) < epoch) return false;
        for (0..n.topo.nodes.len) |i| {
            if (i == n.topo.local or !n.isMember(i)) continue;
            if (!n.rpc.isOnline(@intCast(i)) or n.peer_epochs[i].load(.acquire) < epoch) return false;
        }
        return true;
    }

    /// Installs the handler for "ext" channel `channel` (0 is `ext`).
    pub fn setExt(n: *Node, channel: u8, x: ?*const Ext) void {
        std.debug.assert(channel < ext_channels);
        if (channel == 0) return n.ext.store(x, .release);
        n.ext_more[channel - 1].store(x, .release);
    }

    pub fn extHandler(n: *Node, channel: u8) ?*const Ext {
        if (channel == 0) return n.ext.load(.acquire);
        if (channel >= ext_channels) return null;
        return n.ext_more[channel - 1].load(.acquire);
    }

    /// `extCall` on channel `channel` with a timeout.
    pub fn extCallOn(n: *Node, channel: u8, peer: usize, arena: std.mem.Allocator, body: []const u8, limit: usize, timeout_ms: u32) ?[]u8 {
        if (peer >= n.topo.nodes.len or peer == n.topo.local) return null;
        const node: u16 = @intCast(peer);
        if (!n.rpc.isOnline(node)) return null;
        var qb: [8]u8 = undefined;
        const q = if (channel == 0) "" else std.fmt.bufPrint(&qb, "c={d}", .{channel}) catch unreachable;
        var c = n.rpc.call(node, "ext", q, .{ .bytes = body }, .{ .timeout_ms = timeout_ms }) catch return null;
        defer c.deinit();
        if (!c.ok()) return null;
        return c.readAll(arena, limit) catch null;
    }

    /// Sends `body` to peer `peer`'s "ext" handler; null when the peer is this node,
    /// offline, or fails.
    pub fn extCall(n: *Node, peer: usize, arena: std.mem.Allocator, body: []const u8, limit: usize) ?[]u8 {
        return n.extCallOn(0, peer, arena, body, limit, 5000);
    }

    pub fn nodeCount(n: *const Node) usize {
        return n.topo.nodes.len;
    }

    /// Path of this node's first local drive, if it has one.
    pub fn localPath(n: *Node) ?[]const u8 {
        for (n.local_eps) |pool| for (pool) |ep| if (ep) |e| return e.path;
        return null;
    }

    pub fn storage(n: *Node) backend.StorageBackend {
        return n.router.backend();
    }

    const rebuild_strict_ns = 30 * std.time.ns_per_s;

    /// Creates the object service once the catalog is readable (needs read quorum),
    /// then brings its key index up to date: the local snapshot plus what every peer
    /// journaled since, or a rebuild from the records when that cannot be done.
    pub fn initService(n: *Node, out: *object.ObjectService) Error!void {
        var last_log: i64 = 0;
        while (true) {
            if (n.stop_ev.isSet()) return error.Stopped;
            if (object.ObjectService.initCluster(n.gpa, n.storage())) |svc| {
                out.* = svc;
                out.cluster = .{ .ctx = n, .vtable = &cluster_vtable };
                n.svc.store(out, .release);
                break;
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
        const t0 = std.time.milliTimestamp();
        if (n.resumeIndex(out)) {
            std.log.info("cluster: key index loaded from snapshot and peer journals in {d} ms", .{std.time.milliTimestamp() - t0});
            return;
        }
        // Records still out of reach after a while are skipped (heal and reads recover them).
        var since = std.time.Timer.start() catch unreachable;
        var tries: u32 = 0;
        while (true) {
            if (n.stop_ev.isSet()) return error.Stopped;
            out.rebuild_skip_unreachable = tries >= 3 and since.read() >= rebuild_strict_ns;
            defer out.rebuild_skip_unreachable = false;
            if (n.rebuildIndex(out)) |_| {
                std.log.info("cluster: key index rebuilt from records in {d} ms", .{std.time.milliTimestamp() - t0});
                return;
            } else |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                tries += 1;
                std.log.info("cluster: key index rebuild: {t}; retrying", .{e});
            }
            n.stop_ev.timedWait(time_ns(1)) catch {};
        }
    }

    // ---- key index: journal, snapshot, catch-up ----

    fn openJournal(n: *Node) void {
        find: for (n.local_eps) |eps| for (eps) |e| if (e) |le| {
            var root = std.fs.cwd().openDir(le.path, .{}) catch continue;
            defer root.close();
            n.node_dir = core.fsync.makeOpenPathSynced(root, "node") catch continue;
            break :find;
        };
        n.journal = journal_mod.Journal.open(n.gpa, n.node_dir);
        n.journal_ok.store(true, .release);
    }

    fn journalFn(ctx: *anyopaque, change: object.service.Change) u64 {
        const n: *Node = @ptrCast(@alignCast(ctx));
        _ = n.origins.dirty.fetchAdd(1, .monotonic);
        return n.journal.append(.{ .change = change });
    }

    /// Full rebuild from the records. Peers count as caught up to the heads they
    /// reported before it started; changes after that arrive as notes or pulls.
    fn rebuildIndex(n: *Node, svc: *object.ObjectService) object.Error!void {
        const heads = try n.gpa.alloc(catchup.Origins.Want, n.topo.nodes.len);
        defer n.gpa.free(heads);
        n.origins.heads(heads);
        heads[n.topo.local] = .{ .epoch = 0, .seq = 0 };
        try svc.reloadCatalog();
        try svc.rebuildIndex();
        n.origins.rebuilt(heads);
        _ = n.origins.dirty.fetchAdd(1, .monotonic);
    }

    /// Loads the snapshot and pulls every peer's journal past it. False (with the
    /// index cleared) when any part is missing: no snapshot, a lost journal epoch,
    /// or a peer that cannot be asked.
    fn resumeIndex(n: *Node, svc: *object.ObjectService) bool {
        const dir = n.node_dir orelse return false;
        const bytes = dir.readFileAlloc(n.gpa, catchup.snapshot_name, 1 << 34) catch return false;
        defer n.gpa.free(bytes);
        const marks = blk: {
            svc.mutex.lock();
            defer svc.mutex.unlock();
            break :blk catchup.decode(n.gpa, svc, bytes, n.deployment, n.topo.nodes.len) catch |e| {
                std.log.warn("cluster: index snapshot unusable ({t}); rebuilding", .{e});
                return false;
            };
        };
        defer n.gpa.free(marks);
        n.origins.restore(marks);
        const ok = n.resumeFrom(svc, marks);
        if (!ok) {
            svc.mutex.lock();
            defer svc.mutex.unlock();
            svc.index.clear();
        }
        return ok;
    }

    fn resumeFrom(n: *Node, svc: *object.ObjectService, marks: []const catchup.Origins.Want) bool {
        // Our own changes after the snapshot, then every peer's.
        const own = marks[n.topo.local];
        if (own.epoch != n.journal.head().epoch) {
            std.log.info("cluster: own journal epoch changed since the snapshot; rebuilding", .{});
            return false;
        }
        n.applyOwn(svc, own) catch return false;
        for (0..n.topo.nodes.len) |i| {
            const node: u16 = @intCast(i);
            if (node == n.topo.local) continue;
            if (!n.rpc.isOnline(node)) {
                std.log.info("cluster: node {s} is down; its changes need a rebuild", .{n.topo.nodes[i].name});
                return false;
            }
            n.pull(svc, node) catch |e| {
                std.log.info("cluster: journal of {s} not usable ({t}); rebuilding", .{ n.topo.nodes[i].name, e });
                return false;
            };
            if (n.origins.want(node) != null) return false;
        }
        return true;
    }

    fn applyOwn(n: *Node, svc: *object.ObjectService, from: catchup.Origins.Want) error{ OutOfMemory, Gone }!void {
        var after = from.seq;
        while (true) {
            const page = try n.journal.read(n.gpa, from.epoch, after, pull_page);
            defer n.gpa.free(page.bytes);
            var it: journal_mod.PageIter = .{ .bytes = page.bytes };
            while (it.next() catch return error.Gone) |e| {
                if (e.note == .change) svc.applyChange(e.note.change);
                after = e.seq;
            }
            if (!page.more) return;
        }
    }

    const PullError = error{ Unreachable, Gone };

    /// Applies a peer's journal entries past our watermark (when it is behind).
    fn pull(n: *Node, svc: *object.ObjectService, node: u16) PullError!void {
        while (true) {
            const w = n.origins.want(node) orelse return;
            if (w.epoch == 0) return error.Gone;
            var qb: [96]u8 = undefined;
            const q = std.fmt.bufPrint(&qb, "e={d}&after={d}&max={d}", .{ w.epoch, w.seq, pull_page }) catch unreachable;
            var c = n.rpc.call(node, "jread", q, .{ .bytes = "" }, .{ .timeout_ms = 10_000 }) catch return error.Unreachable;
            defer c.deinit();
            if (c.status == 409) return error.Gone;
            if (!c.ok()) return error.Unreachable;
            const body = c.readAll(n.gpa, pull_page + 64 * 1024) catch return error.Unreachable;
            defer n.gpa.free(body);
            var it: journal_mod.PageIter = .{ .bytes = body };
            var last = w.seq;
            var count: usize = 0;
            while (it.next() catch return error.Unreachable) |e| {
                if (e.note == .change) svc.applyChange(e.note.change);
                last = e.seq;
                count += 1;
            }
            n.origins.pulled(node, w.epoch, last, !c.meta.more);
            if (count > 0) std.log.info("cluster: caught up {d} change(s) from {s}", .{ count, n.topo.nodes[node].name });
            if (!c.meta.more) return;
        }
    }

    /// Writes the index snapshot with the watermarks it reflects.
    fn saveSnapshot(n: *Node, svc: *object.ObjectService) void {
        const dir = n.node_dir orelse return;
        const marks = n.gpa.alloc(catchup.Origins.Want, n.topo.nodes.len) catch return;
        defer n.gpa.free(marks);
        const dirty = n.origins.dirty.load(.monotonic);
        const bytes = blk: {
            // Under the service lock every applied change is in the index and every
            // own journal entry is reflected.
            svc.mutex.lock();
            defer svc.mutex.unlock();
            if (svc.index.stale) return;
            n.origins.marks(marks);
            // A peer without a watermark makes the snapshot unusable; keep the older one.
            for (marks, 0..) |m, i| if (i != n.topo.local and m.epoch == 0) return;
            const h = n.journal.lastAppended();
            marks[n.topo.local] = .{ .epoch = h.epoch, .seq = h.stable };
            break :blk catchup.encode(n.gpa, svc, n.deployment, marks) catch return;
        };
        defer n.gpa.free(bytes);
        catchup.save(dir, bytes) catch |e| {
            std.log.warn("cluster: index snapshot not saved: {t}", .{e});
            return;
        };
        _ = n.origins.dirty.fetchSub(dirty, .monotonic);
        n.last_snapshot_ms = core.time.monoMs();
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
        n.spawn(gcLoop);
        n.spawn(spaceLoop);
        n.spawn(syncLoop);
        n.jopen.store(n.journal.lastAppended().stable, .release);
        n.open.store(true, .release);
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
            if (n.isMember(i) and n.rpc.isOnline(@intCast(i))) return i == n.topo.local;
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

    /// Runs on heartbeat and RPC threads: never blocks, the sync thread does the work.
    fn onPeerChange(ctx: *anyopaque, node: u16, up: bool) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        if (!up) return;
        n.returned[node].store(true, .release);
        n.sync_ev.set();
        // Sets are still being opened during bootstrap.
        if (!n.drives_open.load(.acquire)) return;
        // A returning node may miss shards: heal them.
        for (n.pools) |*p| for (p.sets) |*s| {
            for (s.drives.drives) |d| if (d.node == node) {
                s.healer.wake();
                break;
            };
        };
    }

    /// Keeps the key index current: pulls journal entries from peers that are
    /// behind (a returning peer, a lost note), rebuilds only when a pull cannot
    /// work (a peer lost its journal), and saves the snapshot now and then.
    fn syncLoop(n: *Node) void {
        while (true) {
            n.sync_ev.timedWait(time_ns(1)) catch {};
            n.sync_ev.reset();
            if (n.stop_ev.isSet()) return;
            if (!n.open.load(.acquire)) continue;
            const svc = n.svc.load(.acquire) orelse continue;
            for (n.returned) |*r| {
                if (!r.swap(false, .acq_rel)) continue;
                if (n.iam_store.load(.acquire)) |s| s.reload() catch {};
            }
            var rebuild = false;
            for (0..n.topo.nodes.len) |i| {
                const node: u16 = @intCast(i);
                // A peer that just said hello is pulled once our heartbeat knows its head.
                if (node == n.topo.local or !n.rpc.isOnline(node) or !n.origins.knowsHead(node)) continue;
                n.pull(svc, node) catch |e| switch (e) {
                    error.Gone => rebuild = true,
                    error.Unreachable => {},
                };
            }
            if (rebuild) {
                std.log.warn("cluster: a peer's journal does not reach back far enough; rebuilding the key index", .{});
                n.rebuildIndex(svc) catch |e| std.log.warn("cluster: key index rebuild: {t}", .{e});
            }
            const now = core.time.monoMs();
            if (n.origins.dirty.load(.monotonic) > 0 and now - n.last_snapshot_ms > snapshot_every_ms) n.saveSnapshot(svc);
        }
    }

    // ---- change notifications ----

    const cluster_vtable: object.service.Cluster.VTable = .{ .lock = lockFn, .unlock = unlockFn, .publish = publishFn, .journal = journalFn, .garbage = garbageFn };

    // ---- deferred blob deletion ----

    fn garbageFn(ctx: *anyopaque, id: core.ObjectId) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        if (!n.gc.add(n.gpa, id, gc_grace_ns, null)) n.storage().delete(placement.dataKey(id)) catch {};
    }

    /// Deletes blobs whose grace passed (all with `all`) and tells the next online
    /// peer about new ones, so they go even if this node dies before their time.
    fn collectGarbage(n: *Node, all: bool) void {
        var due: std.ArrayListUnmanaged(Gc.Item) = .empty;
        defer due.deinit(n.gpa);
        var fresh: std.ArrayListUnmanaged(core.ObjectId) = .empty;
        defer fresh.deinit(n.gpa);
        n.gc.take(n.gpa, core.time.monoNs(), all, &due, &fresh);
        // The backup hears of new ids before a long run of deletes, not after it.
        if (fresh.items.len > 0 and !all) if (n.successor()) |next| {
            if (n.gpa.alloc(wire.Note, fresh.items.len)) |notes| {
                defer n.gpa.free(notes);
                for (fresh.items, notes) |id, *o| o.* = .{ .garbage = id.bytes };
                n.sendNotes(next, notes);
            } else |_| {}
        };
        for (due.items) |item| {
            if (!all and n.stop_ev.isSet()) {
                // Shutting down: hand the rest back; the final pass deletes them.
                _ = n.gc.add(n.gpa, item.id, 0, item.owner);
                continue;
            }
            // A backup entry covers its owner dying before the blob's time. An owner
            // that is still the same process deleted it itself.
            if (item.owner) |o| if (!all and o.boot != 0 and o.node < n.topo.nodes.len and n.rpc.isOnline(o.node) and n.rpc.bootOf(o.node) == o.boot) continue;
            n.storage().delete(placement.dataKey(item.id)) catch {};
        }
    }

    fn successor(n: *Node) ?u16 {
        const count = n.topo.nodes.len;
        for (1..count) |k| {
            const node: u16 = @intCast((n.topo.local + k) % count);
            if (n.rpc.isOnline(node)) return node;
        }
        return null;
    }

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

    /// Sends each change with its journal mark, then lets the entries turn stable:
    /// a peer that sees the head move without the note knows it missed one.
    fn publishFn(ctx: *anyopaque, changes: []const object.service.Change, seqs: []const u64) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        defer n.journal.finish(seqs);
        const notes = n.gpa.alloc(wire.Note, 2 * changes.len) catch return;
        defer n.gpa.free(notes);
        const epoch = n.journal.head().epoch;
        var k: usize = 0;
        for (changes, seqs) |c, sq| {
            if (sq != 0) {
                notes[k] = .{ .mark = .{ .epoch = epoch, .seq = sq } };
                k += 1;
            }
            notes[k] = .{ .change = c };
            k += 1;
        }
        n.broadcast(notes[0..k]);
    }

    /// Asks every online peer to apply the pool state; true when each reports
    /// `epoch` or later and has no unguarded write in flight.
    pub fn poolsSynced(n: *Node, epoch: u64) bool {
        const Each = struct {
            n: *Node,
            epoch: u64,
            ok: std.atomic.Value(bool) = .init(true),
            fn f(c: *@This(), i: usize) void {
                const node: u16 = @intCast(i);
                if (node == c.n.topo.local or !c.n.rpc.isOnline(node)) return;
                if (!c.ask(node)) c.ok.store(false, .release);
            }
            fn ask(c: *@This(), node: u16) bool {
                var call = c.n.rpc.call(node, "pools_sync", "", .{ .bytes = "" }, .{ .timeout_ms = 20_000 }) catch return false;
                defer call.deinit();
                if (!call.ok() or call.body_left > 20) return false;
                var b: [20]u8 = undefined;
                const body = b[0..@intCast(call.body_left)];
                call.readInto(body) catch return false;
                const e = std.fmt.parseInt(u64, body, 10) catch return false;
                return e >= c.epoch;
            }
        };
        var each: Each = .{ .n = n, .epoch = epoch };
        protection.fanout.run(n.topo.nodes.len, true, &each, Each.f);
        return each.ok.load(.acquire);
    }

    /// Sends notes to every online peer at once.
    pub fn broadcast(n: *Node, notes: []const wire.Note) void {
        const Each = struct {
            n: *Node,
            notes: []const wire.Note,
            fn f(c: *@This(), i: usize) void {
                const node: u16 = @intCast(i);
                if (node == c.n.topo.local or !c.n.rpc.isOnline(node)) return;
                c.n.sendNotes(node, c.notes);
            }
        };
        var each: Each = .{ .n = n, .notes = notes };
        protection.fanout.run(n.topo.nodes.len, true, &each, Each.f);
    }

    fn sendNotes(n: *Node, node: u16, notes: []const wire.Note) void {
        const body = wire.encodeNotes(n.gpa, notes) catch return;
        defer n.gpa.free(body);
        if (body.len > wire.max_notify) return n.sendNotes(node, &.{.{ .change = .resync }});
        var c = n.rpc.call(node, "notify", "", .{ .bytes = body }, .{ .timeout_ms = 5000 }) catch return;
        c.deinit();
    }

    /// Applies a peer's notes to this node's caches; a mark before a change says
    /// which journal entry it is, so the watermark can follow.
    pub fn applyNotes(n: *Node, from: u16, it: *wire.NoteIter) void {
        var mark: ?wire.Mark = null;
        while (it.next() catch null) |note| switch (note) {
            .mark => |m| mark = m,
            .garbage => |id| _ = n.gc.add(n.gpa, .{ .bytes = id }, backup_grace_ns, .{ .node = from, .boot = if (from < n.topo.nodes.len) n.rpc.bootOf(from) else 0 }),
            .pools => if (n.pools_hook) |h| h.func(h.ctx),
            .iam => if (n.iam_store.load(.acquire)) |s| s.reload() catch |e| std.log.warn("iam reload failed: {t}", .{e}),
            .change => |c| {
                defer mark = null;
                // Before the service exists the startup catch-up covers it.
                const svc = n.svc.load(.acquire) orelse continue;
                svc.applyChange(c);
                if (c == .resync) if (n.iam_store.load(.acquire)) |s| s.reload() catch {};
                if (mark) |m| if (from < n.topo.nodes.len) n.origins.applied(from, m);
            },
        };
    }

    // ---- background loops ----

    /// One hello to every peer at once; their answers set our view of them.
    fn heartbeatRound(n: *Node) void {
        const Each = struct {
            fn f(nn: *Node, i: usize) void {
                const node: u16 = @intCast(i);
                if (node == nn.topo.local or !nn.isMember(i)) return;
                // A peer still bootstrapping cannot serve drive I/O yet.
                const h = nn.hello(node) catch |e| {
                    // Every connection busy means the peer is up and working.
                    // A refusal already took it down in the call; this covers late answers.
                    if (e != error.Busy) nn.rpc.markDown(node, "no answer to probes", true);
                    return;
                };
                nn.rpc.heardBoot(node, h.boot);
                nn.peer_epochs[i].store(h.epoch, .release);
                nn.rpc.setOnline(node, h.drives);
                if (h.drives and h.jepoch != 0 and nn.origins.heard(node, h.jepoch, h.jseq, h.jopen, core.time.monoMs())) nn.sync_ev.set();
            }
        };
        protection.fanout.run(n.topo.nodes.len, true, n, Each.f);
    }

    /// A peer's hello says its drives are open: it is up, whatever our last probe saw.
    pub fn peerSaysUp(n: *Node, node: u16) void {
        if (node == n.topo.local or node >= n.topo.nodes.len) return;
        n.rpc.setOnline(node, true);
    }

    fn heartbeatLoop(n: *Node) void {
        while (!n.stop_ev.isSet()) {
            n.heartbeatRound();
            _ = n.leases.sweep(core.time.monoMs());
            if (n.journal_ok.load(.acquire)) {
                n.journal.expireStuck(core.time.monoMs());
                n.journal.sync(false);
            }
            n.stop_ev.timedWait(heartbeat_ns) catch {};
        }
    }

    /// Deferred blob deletion on its own thread: a long backlog (a bulk delete) must
    /// not hold up heartbeats and lease sweeps.
    fn gcLoop(n: *Node) void {
        while (!n.stop_ev.isSet()) {
            n.collectGarbage(false);
            n.stop_ev.timedWait(heartbeat_ns) catch {};
        }
    }

    fn refreshLoop(n: *Node) void {
        var round: u64 = 0;
        while (true) {
            n.stop_ev.timedWait(time_ns(@max(n.cfg.refresh_s, 1))) catch {};
            if (n.stop_ev.isSet()) return;
            round += 1;
            // Lost notes are found through the journal heads peers report.
            if (n.svc.load(.acquire)) |svc| svc.reloadCatalog() catch |e| std.log.debug("catalog refresh: {t}", .{e});
            if (n.iam_store.load(.acquire)) |s| s.reload() catch |e| std.log.debug("iam refresh: {t}", .{e});
        }
    }

    fn trackUsage(n: *Node) void {
        for (n.pools, 0..) |*ps, p| for (ps.sets) |*st| for (st.endpoints, 0..) |ep, slot| {
            if (n.local_eps[p][ep]) |*le| {
                measure(le);
                st.drives.drives[slot].kind.local.usage = &le.used;
            }
        };
    }

    fn spaceLoop(n: *Node) void {
        while (true) {
            n.stop_ev.timedWait(time_ns(space_refresh_s)) catch {};
            if (n.stop_ev.isSet()) return;
            n.refreshSpace();
        }
    }

    /// Pool room: per drive, capacity minus what this deployment stores there.
    /// Drives not heard from yet are estimated from the pool's known ones, so a
    /// peer that is late to report cannot tilt the choice between pools.
    pub fn refreshSpace(n: *Node) void {
        for (n.topo.pools, 0..) |pool, p| {
            var free: u64 = 0;
            var total: u64 = 0;
            var known: u64 = 0;
            for (pool.endpoints, 0..) |_, i| {
                const sp = if (n.local_eps[p][i]) |*le| localSpace(le) else n.remoteSpace(p, i);
                const s = sp orelse continue;
                free += s.total -| s.used;
                total += s.total;
                known += 1;
            }
            if (known == 0 or p >= n.router_pools.len) continue;
            n.router_pools[p].free.store(free / known * pool.endpoints.len, .monotonic);
            n.router_pools[p].total.store(total / known * pool.endpoints.len, .monotonic);
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
        // Zero capacity: the owner has not measured the drive yet.
        return if (total == 0) null else .{ .total = total, .used = used };
    }
};

const space_refresh_s = 5;

/// Capacity from statfs (cheap) and the tracked usage; null until measured.
fn localSpace(le: *LocalEp) ?Node.Space {
    statCapacity(le);
    const total = le.total.load(.monotonic);
    return if (total == 0) null else .{ .total = total, .used = le.used.load(.monotonic) };
}

fn statCapacity(le: *LocalEp) void {
    var dir = std.fs.cwd().openDir(le.path, .{}) catch return;
    defer dir.close();
    // struct statfs on 64-bit Linux: type, bsize, blocks, ..., frsize at word 9.
    var st: [16]u64 = @splat(0);
    if (std.os.linux.E.init(std.os.linux.syscall2(.fstatfs, @intCast(dir.fd), @intFromPtr(&st))) == .SUCCESS) {
        const unit = if (st[9] != 0) st[9] else st[1];
        le.total.store(st[2] *| unit, .monotonic);
    }
}

const heartbeat_ns = std.time.ns_per_s;
/// Replaced blobs outlive their record this long (reads that resolved it finish).
const gc_grace_ns: i128 = 10 * std.time.ns_per_s;
/// A peer deletes our garbage after this, in case we could not.
const backup_grace_ns: i128 = 30 * std.time.ns_per_s;

/// Blobs waiting out their grace: ours (announced to a peer once) and peers'.
const Gc = struct {
    mutex: std.Thread.Mutex = .{},
    own: std.ArrayListUnmanaged(Item) = .empty,
    backup: std.ArrayListUnmanaged(Item) = .empty,
    announce: std.ArrayListUnmanaged(core.ObjectId) = .empty,

    /// `owner` set: a peer's blob, kept in case that peer dies before deleting it.
    const Item = struct { id: core.ObjectId, due_ns: i128, owner: ?Owner = null };
    const Owner = struct { node: u16, boot: u64 };
    const cap = 1 << 20;

    fn deinit(g: *Gc, gpa: std.mem.Allocator) void {
        g.own.deinit(gpa);
        g.backup.deinit(gpa);
        g.announce.deinit(gpa);
    }

    /// False when the list is full; the caller deletes at once then.
    fn add(g: *Gc, gpa: std.mem.Allocator, id: core.ObjectId, grace: i128, owner: ?Owner) bool {
        g.mutex.lock();
        defer g.mutex.unlock();
        const list = if (owner == null) &g.own else &g.backup;
        if (list.items.len >= cap) return false;
        list.append(gpa, .{ .id = id, .due_ns = core.time.monoNs() + grace, .owner = owner }) catch return false;
        if (owner == null) g.announce.append(gpa, id) catch {};
        return true;
    }

    /// Moves due ids (lists are in due order) into `due`, new ones into `fresh`.
    fn take(g: *Gc, gpa: std.mem.Allocator, now: i128, all: bool, due: *std.ArrayListUnmanaged(Item), fresh: *std.ArrayListUnmanaged(core.ObjectId)) void {
        g.mutex.lock();
        defer g.mutex.unlock();
        for ([_]*std.ArrayListUnmanaged(Item){ &g.own, &g.backup }) |list| {
            var k: usize = 0;
            while (k < list.items.len and (all or list.items[k].due_ns <= now)) : (k += 1) {
                due.append(gpa, list.items[k]) catch break;
            }
            list.replaceRangeAssumeCapacity(0, k, &.{});
        }
        fresh.appendSlice(gpa, g.announce.items) catch return;
        g.announce.clearRetainingCapacity();
    }
};
/// Bytes of journal entries per pull.
const pull_page = 1024 * 1024;
const snapshot_every_ms = 60_000;

/// Capacity, and bytes held under the drive's key spaces by a full walk (startup only).
fn measure(le: *LocalEp) void {
    statCapacity(le);
    var dir = std.fs.cwd().openDir(le.path, .{ .iterate = true }) catch return;
    defer dir.close();
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

fn allNodes(count: usize) u256 {
    if (count >= topology.max_nodes) return std.math.maxInt(u256);
    return (@as(u256, 1) << @intCast(count)) - 1;
}

fn topoFingerprint(t: *const topology.Topology) [16]u8 {
    var h = @import("../core/hwhash.zig").Sha256.init(.{});
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

test "runtime membership: a pool appended to a running node opens; ext channels route" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try tmp.dir.realpathAlloc(a, ".");
    const p1 = [_][]const u8{try std.fmt.allocPrint(a, "http://127.0.0.1:1/{s}/a{{1...2}}", .{root})};
    const p2 = [_][]const u8{try std.fmt.allocPrint(a, "http://127.0.0.1:1/{s}/b{{1...2}}", .{root})};
    for ([_][]const u8{ "a1", "a2", "b1", "b2" }) |d| try tmp.dir.makeDir(d);
    const one = [_][]const []const u8{&p1};
    const two = [_][]const []const u8{ &p1, &p2 };
    const n = try Node.create(gpa, .{ .pools = &one, .node_address = "127.0.0.1:1", .listen_host = "127.0.0.1", .listen_port = 1, .secret = @splat(7) });
    defer n.destroy();
    try n.bootstrap();
    try std.testing.expectEqual(@as(usize, 1), n.router.pools.len);
    // Not a prefix of the current layout.
    try std.testing.expectError(error.LayoutMismatch, n.applyMembership(.{ .epoch = 1, .pools = &.{} }));
    // First call formats the new pool, the next opens it.
    var tries: usize = 0;
    while (true) : (tries += 1) {
        n.applyMembership(.{ .epoch = 2, .pools = &two }) catch |e| {
            try std.testing.expectEqual(error.NotReady, e);
            try std.testing.expect(tries < 3);
            continue;
        };
        break;
    }
    try std.testing.expectEqual(@as(usize, 2), n.router.pools.len);
    try std.testing.expectEqual(@as(usize, 2), n.cfg.pools.len);
    try std.testing.expectEqual(@as(u32, 1), n.poolIndex(1));
    try std.testing.expect(n.allApplied(2) and !n.allApplied(3));
    try std.testing.expect(n.isMember(0));
    // Idempotent.
    try n.applyMembership(.{ .epoch = 2, .pools = &two });

    const Double = struct {
        fn handle(_: *anyopaque, _: std.mem.Allocator, _: []const u8) error{OutOfMemory}![]const u8 {
            return "x";
        }
    };
    var dummy: u8 = 0;
    const x: Ext = .{ .ctx = &dummy, .handle = Double.handle };
    try std.testing.expect(n.extHandler(2) == null);
    n.setExt(2, &x);
    try std.testing.expectEqual(&x, n.extHandler(2).?);
    try std.testing.expect(n.extHandler(0) == null and n.extHandler(ext_channels) == null);
    // Calls to this node itself are refused.
    try std.testing.expect(n.extCallOn(2, 0, a, "", 16, 100) == null);
}
