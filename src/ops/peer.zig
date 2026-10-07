//! Node-to-node ops calls under the cluster RPC path (`<rpc prefix>ops/...`),
//! signed and verified with the cluster secret like every other peer call.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const cluster = @import("../cluster/root.zig");
const root = @import("root.zig");
const report = @import("report.zig");
const service = @import("service.zig");

const Ops = root.Ops;
const Request = std.http.Server.Request;
const RawError = s3.server.RawError;
const auth = cluster.auth;

pub const prefix = cluster.rpc.prefix ++ "ops/";
const max_body = 64 * 1024;
const max_report = 16 * 1024 * 1024;

pub fn route(o: *Ops) s3.server.RawRoute {
    return .{ .prefix = prefix, .ctx = o, .serve = serve };
}

fn fail(req: *Request, status: std.http.Status, why: []const u8) RawError!void {
    try req.respond("", .{ .status = status, .keep_alive = false, .extra_headers = &.{.{ .name = "x-zkfsm-error", .value = why }} });
}

fn serve(ctx: *anyopaque, req: *Request, arena: std.mem.Allocator) RawError!void {
    const o: *Ops = @ptrCast(@alignCast(ctx));
    const n = o.node orelse return fail(req, .not_found, "op");
    if (req.head.method != .POST) return fail(req, .method_not_allowed, "method");
    var h: auth.Fields = .{ .method = "POST", .target = req.head.target, .node = "", .time = "", .nonce = "", .body = "" };
    var sig: []const u8 = "";
    var it = req.iterateHeaders();
    while (it.next()) |hd| {
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_node)) h.node = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_time)) h.time = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_nonce)) h.nonce = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_body)) h.body = hd.value;
        if (std.ascii.eqlIgnoreCase(hd.name, auth.header_sig)) sig = hd.value;
    }
    n.guard.verify(n.secret, h, sig, std.time.milliTimestamp()) catch |e| {
        return fail(req, if (e == error.Busy) .service_unavailable else .unauthorized, @errorName(e));
    };
    const len = req.head.content_length orelse return fail(req, .length_required, "length");
    if (len > max_body) return fail(req, .payload_too_large, "body");
    var rb: [4096]u8 = undefined;
    const r = req.readerExpectContinue(&rb) catch return error.ReadFailed;
    const body = r.readAlloc(arena, @intCast(len)) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ReadFailed,
    };
    if (!std.mem.eql(u8, &auth.bodyDigest(body), h.body)) return fail(req, .bad_request, "digest");

    const path = req.head.target[prefix.len..];
    const q = std.mem.indexOfScalar(u8, path, '?');
    const op = path[0 .. q orelse path.len];
    const query = if (q) |i| path[i + 1 ..] else "";
    if (std.mem.eql(u8, op, "report")) {
        const rep = try report.local(o, arena);
        return req.respond(try report.encode(arena, rep), .{});
    }
    if (std.mem.eql(u8, op, "service")) {
        const action = service.Action.parse(queryValue(query, "action") orelse "") orelse return fail(req, .bad_request, "action");
        try req.respond("", .{});
        service.schedule(o, action);
        return;
    }
    return fail(req, .not_found, "op");
}

fn queryValue(q: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
    }
    return null;
}

/// A peer's report; null when it cannot be reached or answers badly.
pub fn fetchReport(o: *Ops, a: std.mem.Allocator, node: u16) error{OutOfMemory}!?report.Report {
    const n = o.node orelse return null;
    var c = n.rpc.call(node, "ops/report", "", .{ .bytes = "" }, .{ .timeout_ms = 5000 }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else null;
    defer c.deinit();
    if (!c.ok()) return null;
    const body = c.readAll(a, max_report) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else null;
    var r = report.decode(a, body) orelse return null;
    r.node = node;
    r.online = true;
    return r;
}

/// Asks a peer to restart or stop; the error text when it could not be told.
pub fn sendService(o: *Ops, node: u16, action: service.Action) ?[]const u8 {
    const n = o.node orelse return "not a cluster";
    var qb: [32]u8 = undefined;
    const q = std.fmt.bufPrint(&qb, "action={s}", .{@tagName(action)}) catch unreachable;
    var c = n.rpc.call(node, "ops/service", q, .{ .bytes = "" }, .{ .timeout_ms = 5000 }) catch |e| return @errorName(e);
    defer c.deinit();
    if (!c.ok()) return "peer refused the request";
    return null;
}

test "query values" {
    try std.testing.expectEqualStrings("restart", queryValue("a=1&action=restart", "action").?);
    try std.testing.expect(queryValue("a=1", "action") == null);
}
