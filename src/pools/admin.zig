//! Admin endpoints for pools: decommission start/cancel/status/list and rebalance
//! start/status/stop, in the shapes `mc admin decommission` and `mc admin rebalance` read.
const std = @import("std");
const core = @import("../core/root.zig");
const admin = @import("../admin/root.zig");
const state = @import("state.zig");
const manager = @import("manager.zig");

const Manager = manager.Manager;
const api = admin.api;
const Response = api.Response;
const Allocator = std.mem.Allocator;

const zero_time = "0001-01-01T00:00:00Z";

fn time(a: Allocator, ns: i64) Allocator.Error![]const u8 {
    if (ns == 0) return zero_time;
    const b = try a.create([24]u8);
    return core.time.iso8601(ns, b);
}

/// Answers pool and rebalance requests; null for any other operation.
pub fn handle(m: *Manager, c: *const api.Ctx) api.Error!?Response {
    const op = c.req.target.op;
    const routes = .{
        .{ "/pools/decommission", .POST, "admin:Decommission", decomStart },
        .{ "/pools/cancel", .POST, "admin:Decommission", decomCancel },
        .{ "/pools/status", .GET, "admin:Decommission", poolStatus },
        .{ "/pools/list", .GET, "admin:Decommission", poolList },
        .{ "/rebalance/start", .POST, "admin:Rebalance", rebalStart },
        .{ "/rebalance/status", .GET, "admin:Rebalance", rebalStatus },
        .{ "/rebalance/stop", .POST, "admin:Rebalance", rebalStop },
    };
    inline for (routes) |r| if (std.mem.eql(u8, op, r[0])) {
        if (c.req.method != r[1]) return try api.fail(c.a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
        if (!try c.canAction(r[2])) return try api.denied(c.a);
        return try r[3](m, c);
    };
    return null;
}

fn failure(c: *const api.Ctx, e: manager.Error, what: []const u8) api.Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchPool => api.badRequest(c.a, "No such pool on the server command line."),
        error.Conflict => api.fail(c.a, .bad_request, "XMinioAdminInvalidArgument", what),
        error.Unavailable => api.fail(c.a, .service_unavailable, "XMinioServerNotInitialized", "Pool state is not reachable (no quorum)."),
    };
}

fn poolArg(m: *Manager, c: *const api.Ctx) api.Error!?usize {
    const name = try c.param("pool") orelse return null;
    return m.findPool(name);
}

fn decomStart(m: *Manager, c: *const api.Ctx) api.Error!Response {
    const p = try poolArg(m, c) orelse return failure(c, error.NoSuchPool, "");
    m.decommissionStart(p) catch |e| return failure(c, e, "Decommission cannot start: the pool is retired or already decommissioned, another pool is draining, a rebalance is running, or no other pool would remain.");
    return .{};
}

fn decomCancel(m: *Manager, c: *const api.Ctx) api.Error!Response {
    const p = try poolArg(m, c) orelse return failure(c, error.NoSuchPool, "");
    m.decommissionCancel(p) catch |e| return failure(c, e, "No decommission is in progress on this pool.");
    return .{};
}

const DecomInfo = struct {
    startTime: []const u8 = zero_time,
    startSize: i64 = 0,
    totalSize: i64 = 0,
    currentSize: i64 = 0,
    complete: bool = false,
    failed: bool = false,
    canceled: bool = false,
    objectsDecommissioned: i64 = 0,
    objectsDecommissionedFailed: i64 = 0,
    bytesDecommissioned: i64 = 0,
    bytesDecommissionedFailed: i64 = 0,
};

const PoolStatus = struct {
    id: usize,
    cmdline: []const u8,
    lastUpdate: []const u8,
    decommissionInfo: DecomInfo,
};

fn i(v: u64) i64 {
    return @intCast(@min(v, std.math.maxInt(i64)));
}

fn statusOf(m: *Manager, a: Allocator, meta: *state.Meta, p: usize) api.Error!PoolStatus {
    const u = m.usage(p);
    var info: DecomInfo = .{ .totalSize = i(u.total), .currentSize = i(u.free), .startSize = i(u.free) };
    if (meta.pool(m.node.poolIndex(p))) |ps| if (ps.decom.status != .none) {
        const d = ps.decom;
        info = .{
            .startTime = try time(a, d.start_ns),
            .startSize = i(d.start_free),
            .totalSize = i(if (u.total > 0) u.total else d.total_size),
            .currentSize = i(u.free),
            .complete = d.status == .complete,
            .failed = d.status == .failed,
            .canceled = d.status == .canceled,
            .objectsDecommissioned = i(d.objects),
            .objectsDecommissionedFailed = i(d.objects_failed),
            .bytesDecommissioned = i(d.bytes),
            .bytesDecommissionedFailed = i(d.bytes_failed),
        };
    };
    if (m.node.retired & m.bit(p) != 0) info.complete = true;
    return .{
        .id = p,
        .cmdline = try m.cmdline(a, p),
        .lastUpdate = try time(a, @intCast(std.time.nanoTimestamp())),
        .decommissionInfo = info,
    };
}

fn poolStatus(m: *Manager, c: *const api.Ctx) api.Error!Response {
    const p = try poolArg(m, c) orelse return failure(c, error.NoSuchPool, "");
    m.node.refreshSpace();
    var meta = m.loadFresh(c.a) catch |e| return failure(c, e, "");
    return c.json(try statusOf(m, c.a, &meta, p));
}

fn poolList(m: *Manager, c: *const api.Ctx) api.Error!Response {
    m.node.refreshSpace();
    var meta = m.loadFresh(c.a) catch |e| return failure(c, e, "");
    const out = try c.a.alloc(PoolStatus, m.node.cfg.pools.len);
    for (out, 0..) |*o, p| o.* = try statusOf(m, c.a, &meta, p);
    return c.json(out);
}

fn rebalStart(m: *Manager, c: *const api.Ctx) api.Error!Response {
    const id = m.rebalanceStart(c.a) catch |e| return failure(c, e, "Rebalance cannot start: one is running, a pool is draining, or fewer than two active pools exist.");
    return c.json(.{ .id = id });
}

fn rebalStop(m: *Manager, c: *const api.Ctx) api.Error!Response {
    m.rebalanceStop() catch |e| return failure(c, e, "No rebalance is in progress.");
    return .{};
}

const Progress = struct {
    objects: u64 = 0,
    versions: u64 = 0,
    bytes: u64 = 0,
    bucket: []const u8 = "",
    object: []const u8 = "",
    elapsed: i64 = 0,
    eta: i64 = 0,
};

fn rebalStatus(m: *Manager, c: *const api.Ctx) api.Error!Response {
    var meta = m.loadFresh(c.a) catch |e| return failure(c, e, "");
    const rb = meta.rebalance;
    if (rb.status == .none) return try api.fail(c.a, .bad_request, "XMinioAdminRebalanceNotStarted", "Pool rebalance is not started.");
    m.node.refreshSpace();
    const Pool = struct { id: usize, status: []const u8, used: f64, progress: Progress };
    const out = try c.a.alloc(Pool, m.node.cfg.pools.len);
    const now: i64 = @intCast(std.time.nanoTimestamp());
    const end = if (rb.stop_ns != 0) rb.stop_ns else now;
    for (out, 0..) |*o, p| {
        const u = m.usage(p);
        const used = if (u.total == 0) 0 else @as(f64, @floatFromInt(u.total -| u.free)) / @as(f64, @floatFromInt(u.total));
        o.* = .{ .id = p, .status = "", .used = used, .progress = .{} };
        const rp = meta.rebalPool(m.node.poolIndex(p)) orelse continue;
        if (!rp.source) continue;
        o.status = switch (rb.status) {
            .started => if (rp.done) "Completed" else "Started",
            .completed => "Completed",
            .stopped => "Stopped",
            .failed => "Failed",
            .none => "",
        };
        o.progress = .{ .objects = rp.objects, .versions = rp.objects, .bytes = rp.bytes, .elapsed = end - rb.start_ns };
    }
    return c.json(.{ .ID = rb.id, .stoppedAt = try time(c.a, rb.stop_ns), .pools = out });
}
