//! ops: MinIO-compatible admin observability and control (server info, heal,
//! service restart/stop, scanner metrics, top locks) for single-node and cluster
//! deployments. Per-node data is gathered from peers over signed cluster RPC.
const std = @import("std");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");
const heal = @import("../heal/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const s3 = @import("../s3/root.zig");
const cluster = @import("../cluster/root.zig");

pub const fmt = @import("fmt.zig");
pub const report = @import("report.zig");
pub const info = @import("info.zig");
pub const healseq = @import("healseq.zig");
pub const metrics = @import("metrics.zig");
pub const service = @import("service.zig");
pub const peer = @import("peer.zig");

const Allocator = std.mem.Allocator;
const ConnError = s3.handler.ConnError;

pub const version = "zkfsm-0.1.0";

/// Single-node storage: one drive set and its healer.
pub const Local = struct {
    drives: *placement.DriveSet,
    strategy: protection.Strategy,
    healer: *heal.Healer,
};

/// Per-pool status string ("active", "draining", "decommissioned").
pub const PoolStateFn = struct {
    ctx: ?*anyopaque = null,
    func: *const fn (ctx: ?*anyopaque, pool: usize) []const u8,
};

/// One erasure set as the admin views see it.
pub const SetRef = struct {
    pool: usize,
    set: usize,
    drives: *placement.DriveSet,
    strategy: protection.Strategy,
    healer: *heal.Healer,
    /// Cluster: endpoint index within the pool for each slot.
    endpoints: ?[]const u32 = null,
};

/// What `handle` did with a request.
pub const Reply = union(enum) {
    /// Not an ops request; the caller routes it on.
    none,
    res: admin.api.Response,
    /// The response was already written (streams).
    sent,
};

pub const Ops = struct {
    gpa: Allocator,
    svc: *object.ObjectService,
    started_s: i64,
    /// This server's "host:port" (single node; cluster nodes use the topology).
    endpoint: []const u8 = "",
    node: ?*cluster.Node = null,
    local: ?Local = null,
    /// Stopped on service restart/stop; set before serving.
    server: ?*s3.Server = null,
    pool_state: ?PoolStateFn = null,
    heals: healseq.Registry = .{},
    restart: std.atomic.Value(bool) = .init(false),

    /// Raw route for peer calls; list it before the cluster RPC route.
    pub fn route(o: *Ops) s3.server.RawRoute {
        return peer.route(o);
    }

    pub fn handle(o: *Ops, c: *s3.handler.Ctx, store: *iam.Store, req: admin.api.Request) ConnError!Reply {
        const actx: admin.api.Ctx = .{ .a = c.arena, .env = .{ .store = store, .svc = o.svc }, .req = req };
        const op = req.target.op;
        const m = req.method;
        const R = struct { path: []const u8, method: std.http.Method, action: []const u8 };
        const table = [_]R{
            .{ .path = "/info", .method = .GET, .action = "admin:ServerInfo" },
            .{ .path = "/background-heal/status", .method = .POST, .action = "admin:Heal" },
            .{ .path = "/service", .method = .POST, .action = "" },
            .{ .path = "/metrics", .method = .GET, .action = "admin:ServerInfo" },
            .{ .path = "/top/locks", .method = .GET, .action = "admin:TopLocksInfo" },
            .{ .path = "/get-config-kv", .method = .GET, .action = "admin:ConfigUpdate" },
        };
        const is_heal = std.mem.eql(u8, op, "/heal") or std.mem.startsWith(u8, op, "/heal/");
        var hit: ?R = if (is_heal) .{ .path = "/heal", .method = .POST, .action = "admin:Heal" } else null;
        for (table) |r| if (std.mem.eql(u8, op, r.path)) {
            hit = r;
        };
        const r = hit orelse return .none;
        if (std.mem.eql(u8, r.path, "/get-config-kv")) {
            // Only the subnet sub-system is answered here; other keys go on.
            const key = try actx.param("key") orelse return .none;
            if (!std.mem.eql(u8, key, "subnet") and !std.mem.startsWith(u8, key, "subnet:")) return .none;
        }
        if (m != r.method) return .{ .res = try admin.api.fail(c.arena, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.") };
        if (r.action.len > 0 and !try actx.canAction(r.action)) return .{ .res = try admin.api.denied(c.arena) };
        if (std.mem.eql(u8, r.path, "/info")) return .{ .res = try info.serverInfo(o, &actx) };
        if (std.mem.eql(u8, r.path, "/background-heal/status")) return .{ .res = try info.bgHealStatus(o, &actx) };
        if (std.mem.eql(u8, r.path, "/heal")) return .{ .res = try healseq.handle(o, &actx) };
        if (std.mem.eql(u8, r.path, "/service")) return .{ .res = try service.handle(o, &actx) };
        if (std.mem.eql(u8, r.path, "/top/locks")) return .{ .res = try metrics.topLocks(o, &actx) };
        if (std.mem.eql(u8, r.path, "/get-config-kv"))
            return .{ .res = try admin.api.fail(c.arena, .bad_request, "XMinioConfigError", "unknown sub-system subnet") };
        try metrics.stream(o, &actx, c);
        return .sent;
    }

    /// Every erasure set, in pool/set order.
    pub fn sets(o: *Ops, a: Allocator) error{OutOfMemory}![]SetRef {
        var out: std.ArrayList(SetRef) = .empty;
        if (o.node) |n| {
            for (n.pools, 0..) |*p, pi| for (p.sets, 0..) |*s, si| {
                try out.append(a, .{ .pool = pi, .set = si, .drives = &s.drives, .strategy = s.strategy, .healer = &s.healer, .endpoints = s.endpoints });
            };
        } else if (o.local) |l| {
            try out.append(a, .{ .pool = 0, .set = 0, .drives = l.drives, .strategy = l.strategy, .healer = l.healer });
        }
        return out.items;
    }

    pub fn profile(o: *Ops) placement.Profile {
        if (o.node) |n| return n.profile;
        if (o.local) |l| return l.drives.profile;
        return .single;
    }

    pub fn poolCount(o: *Ops) usize {
        if (o.node) |n| return n.pools.len;
        return 1;
    }

    pub fn poolState(o: *Ops, pool: usize) []const u8 {
        const f = o.pool_state orelse return "active";
        return f.func(f.ctx, pool);
    }

    /// Endpoint URL (cluster) or path (single node) of a set slot.
    pub fn driveEndpoint(o: *Ops, s: SetRef, slot: usize) []const u8 {
        if (o.node) |n| if (s.endpoints) |eps| return n.topo.pools[s.pool].endpoints[eps[slot]].url;
        return s.drives.drives[slot].path;
    }

    pub fn drivePath(o: *Ops, s: SetRef, slot: usize) []const u8 {
        if (o.node) |n| if (s.endpoints) |eps| return n.topo.pools[s.pool].endpoints[eps[slot]].path;
        return s.drives.drives[slot].path;
    }

    /// Owning node of a set slot (0 on a single node).
    pub fn driveNode(o: *Ops, s: SetRef, slot: usize) u16 {
        _ = o;
        return s.drives.drives[slot].node;
    }

    pub fn nodeCount(o: *Ops) usize {
        if (o.node) |n| return n.topo.nodes.len;
        return 1;
    }

    pub fn selfNode(o: *Ops) u16 {
        if (o.node) |n| return n.topo.local;
        return 0;
    }

    /// "host:port" of node `i`.
    pub fn nodeName(o: *Ops, i: usize) []const u8 {
        if (o.node) |n| return n.topo.nodes[i].name;
        return o.endpoint;
    }

    pub fn nodeOnline(o: *Ops, i: usize) bool {
        if (o.node) |n| return n.rpc.isOnline(@intCast(i));
        return true;
    }

    /// The set a key lives in: the first pool whose set holds it, else where a new
    /// key would go in pool 0. System keys always live in pool 0.
    pub fn locate(o: *Ops, a: Allocator, key: placement.PhysicalKey) error{OutOfMemory}!SetRef {
        const all = try o.sets(a);
        const n = o.node orelse return all[0];
        var first: ?SetRef = null;
        for (n.router_pools, 0..) |*rp, p| {
            const si = cluster.router.Router.setIndex(rp, key);
            const s = for (all) |x| {
                if (x.pool == p and x.set == si) break x;
            } else continue;
            if (first == null) first = s;
            if (key.space == .system) return s;
            if (report.holdsKey(s.drives, key)) return s;
        }
        return first orelse all[0];
    }

    /// Re-executes the process image if a restart was requested; returns otherwise.
    pub fn finish(o: *Ops) void {
        if (o.restart.load(.acquire)) service.reexec();
    }
};

test {
    _ = fmt;
    _ = report;
    _ = info;
    _ = healseq;
    _ = metrics;
    _ = service;
    _ = peer;
}
