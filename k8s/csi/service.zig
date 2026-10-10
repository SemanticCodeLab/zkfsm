//! gRPC method dispatch for the Identity, Controller and Node services.
const std = @import("std");
const csi = @import("csi.zig");
const h2 = @import("h2.zig");
const node_mod = @import("node.zig");
const Allocator = std.mem.Allocator;
const Code = csi.Code;

pub const Mode = enum { node, controller };

pub const default_capacity: u64 = 1 << 30;

pub const Service = struct {
    mode: Mode,
    node: ?*node_mod.Node = null,

    pub fn handler(self: *Service) h2.Handler {
        return .{ .ctx = self, .call = call };
    }

    fn call(ctx: *anyopaque, arena: Allocator, path: []const u8, req: []const u8) h2.Response {
        const self: *Service = @ptrCast(@alignCast(ctx));
        const resp = self.dispatch(arena, path, req) catch |e| switch (e) {
            error.ProtobufInvalid => h2.Response{ .status = Code.invalid_argument, .message = "malformed protobuf request" },
            else => h2.Response{ .status = Code.internal, .message = @errorName(e) },
        };
        if (resp.status != 0) std.log.warn("{s}: code {d}: {s}", .{ path, resp.status, resp.message });
        return resp;
    }

    fn dispatch(self: *Service, arena: Allocator, path: []const u8, req: []const u8) !h2.Response {
        const eql = std.mem.eql;
        if (eql(u8, path, "/csi.v1.Identity/GetPluginInfo")) return .{ .body = try csi.encodePluginInfo(arena) };
        if (eql(u8, path, "/csi.v1.Identity/GetPluginCapabilities")) return .{ .body = try csi.encodePluginCapabilities(arena) };
        if (eql(u8, path, "/csi.v1.Identity/Probe")) return .{ .body = try csi.encodeProbe(arena) };
        switch (self.mode) {
            .controller => {
                if (eql(u8, path, "/csi.v1.Controller/CreateVolume")) return createVolume(arena, try csi.CreateVolumeRequest.decode(arena, req));
                if (eql(u8, path, "/csi.v1.Controller/DeleteVolume")) {
                    const id = try csi.decodeVolumeIdOnly(req);
                    if (id.len == 0) return .{ .status = Code.invalid_argument, .message = "volume_id is required" };
                    // the node keeps the data until `zkfsm-csi node --gc`
                    std.log.info("DeleteVolume {s}: accepted; data retained on the node until gc", .{id});
                    return .{};
                }
                if (eql(u8, path, "/csi.v1.Controller/ControllerGetCapabilities"))
                    return .{ .body = try csi.encodeRpcCapabilities(arena, &.{csi.controller_create_delete_volume}) };
                if (eql(u8, path, "/csi.v1.Controller/ValidateVolumeCapabilities")) return validate(arena, try csi.ValidateRequest.decode(arena, req));
            },
            .node => {
                const n = self.node.?;
                if (eql(u8, path, "/csi.v1.Node/NodeGetInfo")) return .{ .body = try csi.encodeNodeGetInfo(arena, n.cfg.node_id) };
                if (eql(u8, path, "/csi.v1.Node/NodeGetCapabilities"))
                    return .{ .body = try csi.encodeRpcCapabilities(arena, &.{csi.node_get_volume_stats}) };
                if (eql(u8, path, "/csi.v1.Node/NodePublishVolume")) {
                    const st = n.publish(arena, try csi.NodePublishRequest.decode(arena, req));
                    return .{ .status = st.code, .message = st.msg };
                }
                if (eql(u8, path, "/csi.v1.Node/NodeUnpublishVolume")) {
                    const st = n.unpublish(arena, try csi.IdPath.decode(req));
                    return .{ .status = st.code, .message = st.msg };
                }
                if (eql(u8, path, "/csi.v1.Node/NodeGetVolumeStats")) {
                    const r = n.stats(arena, try csi.IdPath.decode(req));
                    if (r[0].code != 0) return .{ .status = r[0].code, .message = r[0].msg };
                    return .{ .body = try csi.encodeVolumeStats(arena, r[1]) };
                }
            },
        }
        return .{ .status = Code.unimplemented, .message = try std.fmt.allocPrint(arena, "unknown method {s}", .{path}) };
    }
};

/// Node from the first preferred, then requisite, topology carrying our key.
fn chooseNode(q: csi.CreateVolumeRequest) ?[]const u8 {
    for ([_][]const csi.Topology{ q.preferred, q.requisite }) |list| {
        for (list) |t| if (csi.get(t.segments, csi.topology_key)) |n| {
            if (n.len > 0) return n;
        };
    }
    return null;
}

fn createVolume(arena: Allocator, q: csi.CreateVolumeRequest) !h2.Response {
    if (!node_mod.validName(q.name)) return .{ .status = Code.invalid_argument, .message = "name is required and must not contain '/'" };
    if (q.caps.len == 0) return .{ .status = Code.invalid_argument, .message = "volume_capabilities are required" };
    for (q.caps) |c| if (!c.supported())
        return .{ .status = Code.invalid_argument, .message = "only single-node filesystem (mount) volumes are supported" };
    if (q.has_content_source) return .{ .status = Code.invalid_argument, .message = "volume content sources are not supported" };
    if (q.limit_bytes > 0 and q.required_bytes > q.limit_bytes) return .{ .status = Code.invalid_argument, .message = "required_bytes exceeds limit_bytes" };
    const node = chooseNode(q) orelse return .{
        .status = Code.invalid_argument,
        .message = "accessibility_requirements with " ++ csi.topology_key ++ " are required (use volumeBindingMode WaitForFirstConsumer)",
    };
    const capacity = if (q.required_bytes > 0) q.required_bytes else if (q.limit_bytes > 0) q.limit_bytes else default_capacity;
    const seg = try arena.dupe(csi.KV, &.{.{ .key = csi.topology_key, .value = node }});
    const v: csi.Volume = .{
        .capacity_bytes = capacity,
        .volume_id = try std.fmt.allocPrint(arena, "{s}/{s}", .{ node, q.name }),
        .context = try arena.dupe(csi.KV, &.{.{ .key = "capacity", .value = try std.fmt.allocPrint(arena, "{d}", .{capacity}) }}),
        .topology = try arena.dupe(csi.Topology, &.{.{ .segments = seg }}),
    };
    std.log.info("CreateVolume {s} on {s}: {d} bytes", .{ q.name, node, capacity });
    return .{ .body = try csi.encodeCreateVolumeResponse(arena, v) };
}

fn validate(arena: Allocator, q: csi.ValidateRequest) !h2.Response {
    if (q.volume_id.len == 0) return .{ .status = Code.invalid_argument, .message = "volume_id is required" };
    if (q.caps.len == 0) return .{ .status = Code.invalid_argument, .message = "volume_capabilities are required" };
    if (std.mem.indexOfScalar(u8, q.volume_id, '/') == null) return .{ .status = Code.not_found, .message = "unknown volume id format" };
    for (q.caps) |c| if (!c.supported())
        return .{ .body = try csi.encodeValidateResponse(arena, q, false, "only single-node filesystem volumes are supported") };
    return .{ .body = try csi.encodeValidateResponse(arena, q, true, "") };
}

const testing = std.testing;
const pb = @import("pb.zig");

test "identity over h2: GetPluginInfo, capabilities, probe, unknown" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var svc: Service = .{ .mode = .controller };
    const r = try h2.testCall(svc.handler(), arena, "/csi.v1.Identity/GetPluginInfo", "");
    try testing.expectEqual(@as(u32, 0), r.status);
    try testing.expectEqualStrings(csi.plugin_name, try csi.decodePluginName(r.body));

    const caps = try h2.testCall(svc.handler(), arena, "/csi.v1.Identity/GetPluginCapabilities", "");
    // two entries: service{type=1}, service{type=2}
    try testing.expectEqualSlices(u8, &.{ 0x0a, 4, 0x0a, 2, 0x08, 1, 0x0a, 4, 0x0a, 2, 0x08, 2 }, caps.body);
    const probe = try h2.testCall(svc.handler(), arena, "/csi.v1.Identity/Probe", "");
    try testing.expectEqualSlices(u8, &.{ 0x0a, 2, 0x08, 1 }, probe.body);

    const u = try h2.testCall(svc.handler(), arena, "/csi.v1.Node/NodeGetInfo", "");
    try testing.expectEqual(@as(u32, Code.unimplemented), u.status);
    const bad = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/CreateVolume", &.{ 0x0a, 0x7f });
    try testing.expectEqual(@as(u32, Code.invalid_argument), bad.status);
}

test "controller CreateVolume / DeleteVolume / Validate over h2" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var svc: Service = .{ .mode = .controller };
    const seg = [_]csi.KV{.{ .key = csi.topology_key, .value = "worker-1" }};
    const q: csi.CreateVolumeRequest = .{ .name = "pvc-42", .required_bytes = 10 << 30, .preferred = &.{.{ .segments = &seg }} };
    const r = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/CreateVolume", try q.encode(arena, "xfs", 1));
    try testing.expectEqual(@as(u32, 0), r.status);
    const v = try csi.decodeCreateVolumeResponse(arena, r.body);
    try testing.expectEqualStrings("worker-1/pvc-42", v.volume_id);
    try testing.expectEqual(@as(u64, 10 << 30), v.capacity_bytes);
    try testing.expectEqualStrings("10737418240", csi.get(v.context, "capacity").?);
    try testing.expectEqualStrings("worker-1", csi.get(v.topology[0].segments, csi.topology_key).?);

    const noTopo: csi.CreateVolumeRequest = .{ .name = "pvc-43" };
    const e = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/CreateVolume", try noTopo.encode(arena, "", 1));
    try testing.expectEqual(@as(u32, Code.invalid_argument), e.status);
    try testing.expect(std.mem.indexOf(u8, e.message, "WaitForFirstConsumer") != null);
    const multi = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/CreateVolume", try q.encode(arena, "", csi.AccessMode.multi_node_multi_writer));
    try testing.expectEqual(@as(u32, Code.invalid_argument), multi.status);

    const d = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/DeleteVolume", try (csi.IdPath{ .volume_id = "worker-1/pvc-42" }).encode(arena));
    try testing.expectEqual(@as(u32, 0), d.status);
    const cc = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/ControllerGetCapabilities", "");
    try testing.expectEqualSlices(u8, &.{ 0x0a, 4, 0x0a, 2, 0x08, 1 }, cc.body);

    var w = pb.Writer.init(arena);
    try w.string(1, "worker-1/pvc-42");
    try csi.VolumeCapability.encodeMount(&w, 3, "", 1);
    const val = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/ValidateVolumeCapabilities", w.list.items);
    try testing.expectEqual(@as(u32, 0), val.status);
    try testing.expectEqual(@as(u8, 0x0a), val.body[0]); // confirmed present
}

test "node service over h2 in dir-drive mode" {
    var env = try node_mod.TestEnv.init(&.{"d1"});
    defer env.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var svc: Service = .{ .mode = .node, .node = env.node };

    const info = try h2.testCall(svc.handler(), arena, "/csi.v1.Node/NodeGetInfo", "");
    const ni = try csi.decodeNodeGetInfo(arena, info.body);
    try testing.expectEqualStrings("n1", ni.node_id);
    try testing.expectEqualStrings("n1", csi.get(ni.topology.?.segments, csi.topology_key).?);

    const target = try std.fs.path.join(arena, &.{ env.root, "target" });
    const pq: csi.NodePublishRequest = .{ .volume_id = "n1/pvc-z", .target_path = target, .context = &.{.{ .key = "capacity", .value = "4096" }} };
    const p = try h2.testCall(svc.handler(), arena, "/csi.v1.Node/NodePublishVolume", try pq.encode(arena, 1));
    try testing.expectEqual(@as(u32, 0), p.status);
    try testing.expect(env.fake.mounted.contains(target));

    const stats = try h2.testCall(svc.handler(), arena, "/csi.v1.Node/NodeGetVolumeStats", try (csi.IdPath{ .volume_id = "n1/pvc-z", .path = target }).encode(arena));
    try testing.expectEqual(@as(u32, 0), stats.status);
    try testing.expectEqual(@as(usize, 2), (try csi.decodeVolumeStats(arena, stats.body)).len);

    const u = try h2.testCall(svc.handler(), arena, "/csi.v1.Node/NodeUnpublishVolume", try (csi.IdPath{ .volume_id = "n1/pvc-z", .path = target }).encode(arena));
    try testing.expectEqual(@as(u32, 0), u.status);
    try testing.expect(!env.fake.mounted.contains(target));
    const ctl = try h2.testCall(svc.handler(), arena, "/csi.v1.Controller/CreateVolume", "");
    try testing.expectEqual(@as(u32, Code.unimplemented), ctl.status);
}
