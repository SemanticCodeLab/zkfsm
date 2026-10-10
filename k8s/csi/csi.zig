//! CSI v1 messages (csi.proto v1.9 field numbers), hand-coded on top of pb.zig.
//! Only the fields this driver reads or writes are modeled; others are skipped.
const std = @import("std");
const pb = @import("pb.zig");
const Allocator = std.mem.Allocator;

pub const plugin_name = "csi.zkfsm.io";
pub const plugin_version = "0.1.0";
pub const topology_key = "topology.csi.zkfsm.io/node";

/// gRPC status codes used by the driver.
pub const Code = struct {
    pub const ok = 0;
    pub const invalid_argument = 3;
    pub const not_found = 5;
    pub const resource_exhausted = 8;
    pub const failed_precondition = 9;
    pub const unimplemented = 12;
    pub const internal = 13;
};

pub const KV = struct { key: []const u8, value: []const u8 };

pub fn get(map: []const KV, key: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    for (map) |kv| if (std.mem.eql(u8, kv.key, key)) {
        found = kv.value; // last entry wins, like protobuf maps
    };
    return found;
}

fn decodeEntry(bytes: []const u8) pb.Error!KV {
    var kv: KV = .{ .key = "", .value = "" };
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| switch (f.num) {
        1 => kv.key = f.bytes,
        2 => kv.value = f.bytes,
        else => {},
    };
    return kv;
}

pub const AccessType = enum { unset, block, mount };

/// VolumeCapability.AccessMode.Mode
pub const AccessMode = struct {
    pub const single_node_writer = 1;
    pub const single_node_reader_only = 2;
    pub const multi_node_reader_only = 3;
    pub const multi_node_single_writer = 4;
    pub const multi_node_multi_writer = 5;
    pub const single_node_single_writer = 6;
    pub const single_node_multi_writer = 7;
};

/// VolumeCapability: block=1 mount=2 access_mode=3; MountVolume fs_type=1 mount_flags=2.
pub const VolumeCapability = struct {
    access_type: AccessType = .unset,
    fs_type: []const u8 = "",
    access_mode: u64 = 0,
    raw: []const u8 = "",

    pub fn decode(bytes: []const u8) pb.Error!VolumeCapability {
        var c: VolumeCapability = .{ .raw = bytes };
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => c.access_type = .block,
            2 => {
                c.access_type = .mount;
                var m = pb.Reader.init(f.bytes);
                while (try m.next()) |mf| if (mf.num == 1) {
                    c.fs_type = mf.bytes;
                };
            },
            3 => {
                var m = pb.Reader.init(f.bytes);
                while (try m.next()) |mf| if (mf.num == 1) {
                    c.access_mode = mf.int;
                };
            },
            else => {},
        };
        return c;
    }

    /// Filesystem volumes on one node only.
    pub fn supported(c: VolumeCapability) bool {
        if (c.access_type != .mount) return false;
        return switch (c.access_mode) {
            AccessMode.single_node_writer, AccessMode.single_node_reader_only, AccessMode.single_node_single_writer, AccessMode.single_node_multi_writer => true,
            else => false,
        };
    }

    pub fn readOnly(c: VolumeCapability) bool {
        return c.access_mode == AccessMode.single_node_reader_only;
    }

    pub fn encodeMount(w: *pb.Writer, num: u32, fs_type: []const u8, mode: u64) !void {
        var sub = pb.Writer.init(w.gpa);
        var mount = pb.Writer.init(w.gpa);
        try mount.string(1, fs_type);
        try sub.bytes(2, mount.list.items);
        var am = pb.Writer.init(w.gpa);
        try am.uint(1, mode);
        try sub.bytes(3, am.list.items);
        try w.bytes(num, sub.list.items);
    }
};

/// Topology: segments=1 (map<string,string>).
pub const Topology = struct {
    segments: []const KV,

    pub fn decode(arena: Allocator, bytes: []const u8) pb.Error!Topology {
        var segs: std.ArrayList(KV) = .empty;
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| if (f.num == 1) try segs.append(arena, try decodeEntry(f.bytes));
        return .{ .segments = segs.items };
    }

    pub fn encode(w: *pb.Writer, num: u32, segments: []const KV) !void {
        var sub = pb.Writer.init(w.gpa);
        for (segments) |kv| try sub.mapEntry(1, kv.key, kv.value);
        try w.bytes(num, sub.list.items);
    }
};

/// CreateVolumeRequest: name=1 capacity_range=2 volume_capabilities=3 parameters=4
/// secrets=5 volume_content_source=6 accessibility_requirements=7 mutable_parameters=8.
pub const CreateVolumeRequest = struct {
    name: []const u8 = "",
    required_bytes: u64 = 0,
    limit_bytes: u64 = 0,
    caps: []const VolumeCapability = &.{},
    parameters: []const KV = &.{},
    has_content_source: bool = false,
    requisite: []const Topology = &.{},
    preferred: []const Topology = &.{},

    pub fn decode(arena: Allocator, bytes: []const u8) pb.Error!CreateVolumeRequest {
        var q: CreateVolumeRequest = .{};
        var caps: std.ArrayList(VolumeCapability) = .empty;
        var params: std.ArrayList(KV) = .empty;
        var req: std.ArrayList(Topology) = .empty;
        var pref: std.ArrayList(Topology) = .empty;
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => q.name = f.bytes,
            2 => { // CapacityRange: required_bytes=1 limit_bytes=2
                var m = pb.Reader.init(f.bytes);
                while (try m.next()) |mf| switch (mf.num) {
                    1 => q.required_bytes = mf.int,
                    2 => q.limit_bytes = mf.int,
                    else => {},
                };
            },
            3 => try caps.append(arena, try VolumeCapability.decode(f.bytes)),
            4 => try params.append(arena, try decodeEntry(f.bytes)),
            6 => q.has_content_source = true,
            7 => { // TopologyRequirement: requisite=1 preferred=2
                var m = pb.Reader.init(f.bytes);
                while (try m.next()) |mf| switch (mf.num) {
                    1 => try req.append(arena, try Topology.decode(arena, mf.bytes)),
                    2 => try pref.append(arena, try Topology.decode(arena, mf.bytes)),
                    else => {},
                };
            },
            else => {},
        };
        q.caps = caps.items;
        q.parameters = params.items;
        q.requisite = req.items;
        q.preferred = pref.items;
        return q;
    }

    pub fn encode(q: CreateVolumeRequest, gpa: Allocator, fs_type: []const u8, mode: u64) ![]u8 {
        var w = pb.Writer.init(gpa);
        try w.string(1, q.name);
        var cr = pb.Writer.init(gpa);
        try cr.uint(1, q.required_bytes);
        try cr.uint(2, q.limit_bytes);
        try w.bytes(2, cr.list.items);
        try VolumeCapability.encodeMount(&w, 3, fs_type, mode);
        for (q.parameters) |kv| try w.mapEntry(4, kv.key, kv.value);
        var tr = pb.Writer.init(gpa);
        for (q.requisite) |t| try Topology.encode(&tr, 1, t.segments);
        for (q.preferred) |t| try Topology.encode(&tr, 2, t.segments);
        if (q.requisite.len + q.preferred.len > 0) try w.bytes(7, tr.list.items);
        return w.list.items;
    }
};

/// Volume: capacity_bytes=1 volume_id=2 volume_context=3 content_source=4 accessible_topology=5.
pub const Volume = struct {
    capacity_bytes: u64 = 0,
    volume_id: []const u8 = "",
    context: []const KV = &.{},
    topology: []const Topology = &.{},

    pub fn encode(v: Volume, w: *pb.Writer, num: u32) !void {
        var sub = pb.Writer.init(w.gpa);
        try sub.uint(1, v.capacity_bytes);
        try sub.string(2, v.volume_id);
        for (v.context) |kv| try sub.mapEntry(3, kv.key, kv.value);
        for (v.topology) |t| try Topology.encode(&sub, 5, t.segments);
        try w.bytes(num, sub.list.items);
    }

    pub fn decode(arena: Allocator, bytes: []const u8) pb.Error!Volume {
        var v: Volume = .{};
        var ctx: std.ArrayList(KV) = .empty;
        var topo: std.ArrayList(Topology) = .empty;
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => v.capacity_bytes = f.int,
            2 => v.volume_id = f.bytes,
            3 => try ctx.append(arena, try decodeEntry(f.bytes)),
            5 => try topo.append(arena, try Topology.decode(arena, f.bytes)),
            else => {},
        };
        v.context = ctx.items;
        v.topology = topo.items;
        return v;
    }
};

/// CreateVolumeResponse: volume=1.
pub fn encodeCreateVolumeResponse(gpa: Allocator, v: Volume) ![]u8 {
    var w = pb.Writer.init(gpa);
    try v.encode(&w, 1);
    return w.list.items;
}

pub fn decodeCreateVolumeResponse(arena: Allocator, bytes: []const u8) !Volume {
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| if (f.num == 1) return Volume.decode(arena, f.bytes);
    return error.ProtobufInvalid;
}

/// DeleteVolumeRequest: volume_id=1 secrets=2.
pub fn decodeVolumeIdOnly(bytes: []const u8) pb.Error![]const u8 {
    var id: []const u8 = "";
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| if (f.num == 1) {
        id = f.bytes;
    };
    return id;
}

/// ValidateVolumeCapabilitiesRequest: volume_id=1 volume_context=2 volume_capabilities=3 parameters=4.
pub const ValidateRequest = struct {
    volume_id: []const u8 = "",
    context: []const KV = &.{},
    caps: []const VolumeCapability = &.{},
    parameters: []const KV = &.{},

    pub fn decode(arena: Allocator, bytes: []const u8) pb.Error!ValidateRequest {
        var q: ValidateRequest = .{};
        var ctx: std.ArrayList(KV) = .empty;
        var caps: std.ArrayList(VolumeCapability) = .empty;
        var params: std.ArrayList(KV) = .empty;
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => q.volume_id = f.bytes,
            2 => try ctx.append(arena, try decodeEntry(f.bytes)),
            3 => try caps.append(arena, try VolumeCapability.decode(f.bytes)),
            4 => try params.append(arena, try decodeEntry(f.bytes)),
            else => {},
        };
        q.context = ctx.items;
        q.caps = caps.items;
        q.parameters = params.items;
        return q;
    }
};

/// ValidateVolumeCapabilitiesResponse: confirmed=1 {volume_context=1 volume_capabilities=2 parameters=3} message=2.
pub fn encodeValidateResponse(gpa: Allocator, q: ValidateRequest, confirmed: bool, message: []const u8) ![]u8 {
    var w = pb.Writer.init(gpa);
    if (confirmed) {
        var c = pb.Writer.init(gpa);
        for (q.context) |kv| try c.mapEntry(1, kv.key, kv.value);
        for (q.caps) |cap| try c.bytes(2, cap.raw);
        for (q.parameters) |kv| try c.mapEntry(3, kv.key, kv.value);
        try w.bytes(1, c.list.items);
    }
    try w.string(2, message);
    return w.list.items;
}

/// NodePublishVolumeRequest: volume_id=1 publish_context=2 staging_target_path=3 target_path=4
/// volume_capability=5 readonly=6 secrets=7 volume_context=8.
pub const NodePublishRequest = struct {
    volume_id: []const u8 = "",
    target_path: []const u8 = "",
    cap: ?VolumeCapability = null,
    readonly: bool = false,
    context: []const KV = &.{},

    pub fn decode(arena: Allocator, bytes: []const u8) pb.Error!NodePublishRequest {
        var q: NodePublishRequest = .{};
        var ctx: std.ArrayList(KV) = .empty;
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => q.volume_id = f.bytes,
            4 => q.target_path = f.bytes,
            5 => q.cap = try VolumeCapability.decode(f.bytes),
            6 => q.readonly = f.int != 0,
            8 => try ctx.append(arena, try decodeEntry(f.bytes)),
            else => {},
        };
        q.context = ctx.items;
        return q;
    }

    pub fn encode(q: NodePublishRequest, gpa: Allocator, mode: u64) ![]u8 {
        var w = pb.Writer.init(gpa);
        try w.string(1, q.volume_id);
        try w.string(4, q.target_path);
        try VolumeCapability.encodeMount(&w, 5, "", mode);
        try w.boolean(6, q.readonly);
        for (q.context) |kv| try w.mapEntry(8, kv.key, kv.value);
        return w.list.items;
    }
};

/// NodeUnpublishVolumeRequest: volume_id=1 target_path=2;
/// NodeGetVolumeStatsRequest: volume_id=1 volume_path=2 staging_target_path=3.
pub const IdPath = struct {
    volume_id: []const u8 = "",
    path: []const u8 = "",

    pub fn decode(bytes: []const u8) pb.Error!IdPath {
        var q: IdPath = .{};
        var r = pb.Reader.init(bytes);
        while (try r.next()) |f| switch (f.num) {
            1 => q.volume_id = f.bytes,
            2 => q.path = f.bytes,
            else => {},
        };
        return q;
    }

    pub fn encode(q: IdPath, gpa: Allocator) ![]u8 {
        var w = pb.Writer.init(gpa);
        try w.string(1, q.volume_id);
        try w.string(2, q.path);
        return w.list.items;
    }
};

/// GetPluginInfoResponse: name=1 vendor_version=2 manifest=3.
pub fn encodePluginInfo(gpa: Allocator) ![]u8 {
    var w = pb.Writer.init(gpa);
    try w.string(1, plugin_name);
    try w.string(2, plugin_version);
    return w.list.items;
}

/// GetPluginCapabilitiesResponse: capabilities=1 { service=1 { type=1 } };
/// CONTROLLER_SERVICE=1, VOLUME_ACCESSIBILITY_CONSTRAINTS=2.
pub fn encodePluginCapabilities(gpa: Allocator) ![]u8 {
    var w = pb.Writer.init(gpa);
    for ([_]u64{ 1, 2 }) |t| {
        var typ = pb.Writer.init(gpa);
        try typ.uint(1, t);
        var svc = pb.Writer.init(gpa);
        try svc.bytes(1, typ.list.items);
        try w.bytes(1, svc.list.items);
    }
    return w.list.items;
}

/// ProbeResponse: ready=1 (google.protobuf.BoolValue{value=1}).
pub fn encodeProbe(gpa: Allocator) ![]u8 {
    var w = pb.Writer.init(gpa);
    var b = pb.Writer.init(gpa);
    try b.boolean(1, true);
    try w.bytes(1, b.list.items);
    return w.list.items;
}

/// Controller/NodeGetCapabilitiesResponse: capabilities=1 { rpc=1 { type=1 } }.
pub fn encodeRpcCapabilities(gpa: Allocator, types: []const u64) ![]u8 {
    var w = pb.Writer.init(gpa);
    for (types) |t| {
        var typ = pb.Writer.init(gpa);
        try typ.uint(1, t);
        var cap = pb.Writer.init(gpa);
        try cap.bytes(1, typ.list.items);
        try w.bytes(1, cap.list.items);
    }
    return w.list.items;
}

pub const controller_create_delete_volume = 1;
pub const node_get_volume_stats = 2;

/// NodeGetInfoResponse: node_id=1 max_volumes_per_node=2 accessible_topology=3.
pub fn encodeNodeGetInfo(gpa: Allocator, node_id: []const u8) ![]u8 {
    var w = pb.Writer.init(gpa);
    try w.string(1, node_id);
    try Topology.encode(&w, 3, &.{.{ .key = topology_key, .value = node_id }});
    return w.list.items;
}

pub const NodeInfo = struct { node_id: []const u8 = "", topology: ?Topology = null };

pub fn decodeNodeGetInfo(arena: Allocator, bytes: []const u8) !NodeInfo {
    var n: NodeInfo = .{};
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| switch (f.num) {
        1 => n.node_id = f.bytes,
        3 => n.topology = try Topology.decode(arena, f.bytes),
        else => {},
    };
    return n;
}

/// GetPluginInfoResponse decoder (tests and `call`).
pub fn decodePluginName(bytes: []const u8) ![]const u8 {
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| if (f.num == 1) return f.bytes;
    return "";
}

/// NodeGetVolumeStatsResponse: usage=1 { available=1 total=2 used=3 unit=4 }; BYTES=1 INODES=2.
pub const Usage = struct { available: u64, total: u64, used: u64, unit: u64 };

pub fn encodeVolumeStats(gpa: Allocator, usages: []const Usage) ![]u8 {
    var w = pb.Writer.init(gpa);
    for (usages) |u| {
        var sub = pb.Writer.init(gpa);
        try sub.uint(1, u.available);
        try sub.uint(2, u.total);
        try sub.uint(3, u.used);
        try sub.uint(4, u.unit);
        try w.bytes(1, sub.list.items);
    }
    return w.list.items;
}

pub fn decodeVolumeStats(arena: Allocator, bytes: []const u8) ![]Usage {
    var out: std.ArrayList(Usage) = .empty;
    var r = pb.Reader.init(bytes);
    while (try r.next()) |f| if (f.num == 1) {
        var u: Usage = .{ .available = 0, .total = 0, .used = 0, .unit = 0 };
        var m = pb.Reader.init(f.bytes);
        while (try m.next()) |mf| switch (mf.num) {
            1 => u.available = mf.int,
            2 => u.total = mf.int,
            3 => u.used = mf.int,
            4 => u.unit = mf.int,
            else => {},
        };
        try out.append(arena, u);
    };
    return out.items;
}

const testing = std.testing;

test "CreateVolumeRequest round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const seg = [_]KV{.{ .key = topology_key, .value = "node-a" }};
    const q: CreateVolumeRequest = .{
        .name = "pvc-1",
        .required_bytes = 5 << 30,
        .parameters = &.{.{ .key = "fs", .value = "xfs" }},
        .preferred = &.{.{ .segments = &seg }},
    };
    const bytes = try q.encode(arena, "xfs", AccessMode.single_node_writer);
    // name=1 is the first field: tag 0x0a, len 5
    try testing.expectEqualSlices(u8, &.{ 0x0a, 5, 'p', 'v', 'c', '-', '1', 0x12 }, bytes[0..8]);
    const d = try CreateVolumeRequest.decode(arena, bytes);
    try testing.expectEqualStrings("pvc-1", d.name);
    try testing.expectEqual(@as(u64, 5 << 30), d.required_bytes);
    try testing.expectEqual(@as(usize, 1), d.caps.len);
    try testing.expect(d.caps[0].supported());
    try testing.expectEqualStrings("xfs", d.caps[0].fs_type);
    try testing.expectEqualStrings("xfs", get(d.parameters, "fs").?);
    try testing.expectEqual(@as(usize, 0), d.requisite.len);
    try testing.expectEqualStrings("node-a", get(d.preferred[0].segments, topology_key).?);
    try testing.expect(!d.has_content_source);
}

test "Volume and NodeGetInfo round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const seg = [_]KV{.{ .key = topology_key, .value = "n1" }};
    const v: Volume = .{ .capacity_bytes = 1234, .volume_id = "n1/pvc-x", .context = &.{.{ .key = "capacity", .value = "1234" }}, .topology = &.{.{ .segments = &seg }} };
    const bytes = try encodeCreateVolumeResponse(arena, v);
    const d = try decodeCreateVolumeResponse(arena, bytes);
    try testing.expectEqual(@as(u64, 1234), d.capacity_bytes);
    try testing.expectEqualStrings("n1/pvc-x", d.volume_id);
    try testing.expectEqualStrings("1234", get(d.context, "capacity").?);
    try testing.expectEqualStrings("n1", get(d.topology[0].segments, topology_key).?);

    const info = try decodeNodeGetInfo(arena, try encodeNodeGetInfo(arena, "n1"));
    try testing.expectEqualStrings("n1", info.node_id);
    try testing.expectEqualStrings("n1", get(info.topology.?.segments, topology_key).?);
}

test "NodePublish and capability round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const q: NodePublishRequest = .{ .volume_id = "n/v", .target_path = "/t", .readonly = true, .context = &.{.{ .key = "capacity", .value = "9" }} };
    const d = try NodePublishRequest.decode(arena, try q.encode(arena, AccessMode.multi_node_multi_writer));
    try testing.expectEqualStrings("n/v", d.volume_id);
    try testing.expectEqualStrings("/t", d.target_path);
    try testing.expect(d.readonly);
    try testing.expect(!d.cap.?.supported());
    try testing.expectEqualStrings("9", get(d.context, "capacity").?);
    // block access type is rejected
    const block_cap = [_]u8{ 0x0a, 0x00, 0x1a, 0x02, 0x08, 0x01 };
    try testing.expectEqual(AccessType.block, (try VolumeCapability.decode(&block_cap)).access_type);
    try testing.expect(!(try VolumeCapability.decode(&block_cap)).supported());
    const u = try decodeVolumeStats(arena, try encodeVolumeStats(arena, &.{.{ .available = 1, .total = 3, .used = 2, .unit = 1 }}));
    try testing.expectEqual(@as(u64, 3), u[0].total);
}
