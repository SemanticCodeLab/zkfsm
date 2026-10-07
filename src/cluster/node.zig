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
        n.rpc = rpc_mod.Rpc.init(gpa, &n.topo, cfg.secret) catch return error.OutOfMemory;
        errdefer n.rpc.deinit();
        if (n.topo.tls) try n.loadCa();
        n.returned = try a.alloc(std.atomic.Value(bool), n.topo.nodes.len);
        for (n.returned) |*r| r.* = .init(false);
        n.origins = try catchup.Origins.init(gpa, n.topo.nodes.len);
        errdefer n.origins.deinit();
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

    const Hello = struct { topo: [16]u8, root: [16]u8, ready: bool, drives: bool, jepoch: u64 = 0, jseq: u64 = 0, jopen: ?u64 = null };

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
            } else if (std.mem.eql(u8, k, "jepoch")) {
                h.jepoch = std.fmt.parseInt(u64, v, 10) catch 0;
            } else if (std.mem.eql(u8, k, "jseq")) {
                h.jseq = std.fmt.parseInt(u64, v, 10) catch 0;
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
        if (dep == null) {
            // Brand-new cluster: format once every drive can be reached.
            for (seen) |s| for (s) |e| if (e == .unknown) return false;
            if (!n.formatter(0)) return false;
            var d: [16]u8 = undefined;
            std.crypto.random.bytes(&d);
            n.deployment = d;
            n.profile = n.cfg.profile orelse n.defaultProfile();
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
            const f: FormatV2 = .{ .deployment = n.deployment, .layout = fp, .pool = @intCast(p), .set = @intCast(si), .index = @intCast(idx), .set_size = @intCast(size), .profile = n.profile };
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
        // Empty until opened, so a failed bootstrap stops and frees cleanly.
        for (n.pools) |*p| p.* = .{ .set_size = 0, .sets = &.{}, .backends = &.{} };
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
                const ok = std.mem.eql(u8, &f.layout, &fp) and f.pool == p and f.set == si and f.index == idx and f.set_size == size and f.profile.eql(n.profile);
                if (!ok) {
                    std.log.err("cluster: drive {s} was formatted for a different layout (endpoint list, order, or protection changed)", .{pool.endpoints[ep].url});
                    return error.LayoutMismatch;
                }
            };
            const ps = &n.pools[p];
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
                const tmpl: FormatV2 = .{ .deployment = n.deployment, .layout = fp, .pool = @intCast(p), .set = @intCast(si), .index = 0, .set_size = @intCast(size), .profile = n.profile };
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
            n.router_pools[p] = .{ .sets = ps.backends, .seed = std.mem.readInt(u64, &seed, .little) +% p };
        }
        n.router = .{ .gpa = n.gpa, .pools = n.router_pools };
    }

    pub fn storage(n: *Node) backend.StorageBackend {
        return n.router.backend();
    }

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
        while (true) {
            if (n.stop_ev.isSet()) return error.Stopped;
            if (n.rebuildIndex(out)) |_| {
                std.log.info("cluster: key index rebuilt from records in {d} ms", .{std.time.milliTimestamp() - t0});
                return;
            } else |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
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
            n.node_dir = root.makeOpenPath("node", .{}) catch continue;
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
        if (own.epoch != n.journal.head().epoch) return false;
        n.applyOwn(svc, own) catch return false;
        for (0..n.topo.nodes.len) |i| {
            const node: u16 = @intCast(i);
            if (node == n.topo.local) continue;
            if (!n.rpc.isOnline(node)) {
                std.log.info("cluster: node {s} is down; its changes need a rebuild", .{n.topo.nodes[i].name});
                return false;
            }
            n.pull(svc, node) catch return false;
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
        n.last_snapshot_ms = std.time.milliTimestamp();
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
            const now = std.time.milliTimestamp();
            if (n.origins.dirty.load(.monotonic) > 0 and now - n.last_snapshot_ms > snapshot_every_ms) n.saveSnapshot(svc);
        }
    }

    // ---- change notifications ----

    const cluster_vtable: object.service.Cluster.VTable = .{ .lock = lockFn, .unlock = unlockFn, .publish = publishFn, .journal = journalFn, .garbage = garbageFn };

    // ---- deferred blob deletion ----

    fn garbageFn(ctx: *anyopaque, id: core.ObjectId) void {
        const n: *Node = @ptrCast(@alignCast(ctx));
        if (!n.gc.add(n.gpa, id, gc_grace_ns, true)) n.storage().delete(placement.dataKey(id)) catch {};
    }

    /// Deletes blobs whose grace passed (all with `all`) and tells the next online
    /// peer about new ones, so they go even if this node dies before their time.
    fn collectGarbage(n: *Node, all: bool) void {
        var due: std.ArrayListUnmanaged(core.ObjectId) = .empty;
        defer due.deinit(n.gpa);
        var fresh: std.ArrayListUnmanaged(core.ObjectId) = .empty;
        defer fresh.deinit(n.gpa);
        n.gc.take(n.gpa, core.time.nowNs(), all, &due, &fresh);
        for (due.items) |id| n.storage().delete(placement.dataKey(id)) catch {};
        if (fresh.items.len == 0 or all) return;
        const next = n.successor() orelse return;
        const notes = n.gpa.alloc(wire.Note, fresh.items.len) catch return;
        defer n.gpa.free(notes);
        for (fresh.items, notes) |id, *o| o.* = .{ .garbage = id.bytes };
        n.sendNotes(next, notes);
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
            .garbage => |id| _ = n.gc.add(n.gpa, .{ .bytes = id }, backup_grace_ns, false),
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
                if (node == nn.topo.local) return;
                // A peer still bootstrapping cannot serve drive I/O yet.
                const h = nn.hello(node) catch |e| {
                    // Every connection busy means the peer is up and working.
                    if (e != error.Busy) nn.rpc.setOnline(node, false);
                    return;
                };
                nn.rpc.setOnline(node, h.drives);
                if (h.drives and h.jepoch != 0 and nn.origins.heard(node, h.jepoch, h.jseq, h.jopen, std.time.milliTimestamp())) nn.sync_ev.set();
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
            _ = n.leases.sweep(std.time.milliTimestamp());
            if (n.journal_ok.load(.acquire)) {
                n.journal.expireStuck(std.time.milliTimestamp());
                n.journal.sync(false);
            }
            if (n.drives_open.load(.acquire)) n.collectGarbage(false);
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
    fn refreshSpace(n: *Node) void {
        for (n.topo.pools, 0..) |pool, p| {
            var free: u64 = 0;
            var known: u64 = 0;
            for (pool.endpoints, 0..) |_, i| {
                const f = if (n.local_eps[p][i]) |*le| localFree(le) else n.remoteSpace(p, i);
                free += f orelse continue;
                known += 1;
            }
            if (known == 0 or p >= n.router_pools.len) continue;
            n.router_pools[p].free.store(free / known * pool.endpoints.len, .monotonic);
        }
    }

    fn remoteSpace(n: *Node, p: usize, i: usize) ?u64 {
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
        return if (total == 0) null else total -| used;
    }
};

const space_refresh_s = 5;

/// Capacity from statfs (cheap), minus the tracked usage; null until measured.
fn localFree(le: *LocalEp) ?u64 {
    statCapacity(le);
    const total = le.total.load(.monotonic);
    return if (total == 0) null else total -| le.used.load(.monotonic);
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

    const Item = struct { id: core.ObjectId, due_ns: i128 };
    const cap = 1 << 20;

    fn deinit(g: *Gc, gpa: std.mem.Allocator) void {
        g.own.deinit(gpa);
        g.backup.deinit(gpa);
        g.announce.deinit(gpa);
    }

    /// False when the list is full; the caller deletes at once then.
    fn add(g: *Gc, gpa: std.mem.Allocator, id: core.ObjectId, grace: i128, own: bool) bool {
        g.mutex.lock();
        defer g.mutex.unlock();
        const list = if (own) &g.own else &g.backup;
        if (list.items.len >= cap) return false;
        list.append(gpa, .{ .id = id, .due_ns = core.time.nowNs() + grace }) catch return false;
        if (own) g.announce.append(gpa, id) catch {};
        return true;
    }

    /// Moves due ids (lists are in due order) into `due`, new ones into `fresh`.
    fn take(g: *Gc, gpa: std.mem.Allocator, now: i128, all: bool, due: *std.ArrayListUnmanaged(core.ObjectId), fresh: *std.ArrayListUnmanaged(core.ObjectId)) void {
        g.mutex.lock();
        defer g.mutex.unlock();
        for ([_]*std.ArrayListUnmanaged(Item){ &g.own, &g.backup }) |list| {
            var k: usize = 0;
            while (k < list.items.len and (all or list.items[k].due_ns <= now)) : (k += 1) {
                due.append(gpa, list.items[k].id) catch break;
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
