//! Cluster layout: erasure-set sizing, the deterministic drive-to-set assignment that
//! spreads every set across nodes, derived drive identities, and the v2 format file.
const std = @import("std");
const core = @import("../core/root.zig");
const profile_mod = @import("profile.zig");
const rendezvous = @import("rendezvous.zig");

const Profile = profile_mod.Profile;
const DriveId = core.DriveId;
const SetId = core.SetId;

pub const max_set_size = 16;
pub const max_sets = 1024;

pub const Error = error{ BadLayout, OutOfMemory };

/// Parity share of a profile as (data, parity); replica(N) is 1 data + N-1 copies.
fn geometry(p: Profile) struct { usize, usize } {
    return switch (p) {
        .single => .{ 1, 0 },
        .replica => |n| .{ 1, @as(usize, n) - 1 },
        .erasure => |e| .{ e.data, e.parity },
    };
}

/// Set size for `total` drives on `nodes` nodes: the largest divisor of `total` within
/// [width, 16] that is symmetric with the node count, else the largest divisor.
pub fn chooseSetSize(total: usize, nodes: usize, width: usize, want: ?usize) Error!usize {
    if (want) |w| {
        if (w < width or w > max_set_size or w == 0 or total % w != 0) return error.BadLayout;
        return w;
    }
    var best: ?usize = null;
    var best_sym: ?usize = null;
    var s: usize = @min(total, max_set_size);
    while (s >= width and s > 0) : (s -= 1) {
        if (total % s != 0) continue;
        if (best == null) best = s;
        if (best_sym == null and (s % nodes == 0 or nodes % s == 0)) best_sym = s;
    }
    const size = best_sym orelse best orelse return error.BadLayout;
    if (total / size > max_sets) return error.BadLayout;
    return size;
}

/// Drives a set tolerates losing, scaled from the profile's parity share.
pub fn tolerance(set_size: usize, p: Profile) usize {
    const g = geometry(p);
    return set_size * g[1] / (g[0] + g[1]);
}

/// Online drives a set needs before it accepts writes (data, +1 when data == parity).
pub fn setWriteQuorum(set_size: usize, p: Profile) usize {
    const tol = tolerance(set_size, p);
    const data = set_size - tol;
    return if (data == tol) data + 1 else data;
}

/// Per-object write quorum: data shards, +1 when data == parity (replicas: majority).
pub fn objectWriteQuorum(p: Profile) usize {
    const g = geometry(p);
    return switch (p) {
        .erasure => if (g[0] == g[1]) g[0] + 1 else g[0],
        else => (g[0] + g[1]) / 2 + 1,
    };
}

/// Assigns pool endpoints (given by the node index of each) to sets. Endpoints are
/// interleaved round-robin across nodes, then cut into consecutive sets, so every set
/// takes as few drives from any one node as the layout allows.
pub fn assign(gpa: std.mem.Allocator, drive_nodes: []const u16, set_size: usize) Error![][]u32 {
    if (set_size == 0 or drive_nodes.len % set_size != 0) return error.BadLayout;
    var order: std.ArrayList(u16) = .empty;
    defer order.deinit(gpa);
    for (drive_nodes) |n| {
        if (std.mem.indexOfScalar(u16, order.items, n) == null) try order.append(gpa, n);
    }
    const seq = try gpa.alloc(u32, drive_nodes.len);
    defer gpa.free(seq);
    var len: usize = 0;
    var round: usize = 0;
    while (len < drive_nodes.len) : (round += 1) {
        for (order.items) |node| {
            var seen: usize = 0;
            for (drive_nodes, 0..) |dn, i| {
                if (dn != node) continue;
                if (seen == round) {
                    seq[len] = @intCast(i);
                    len += 1;
                    break;
                }
                seen += 1;
            }
        }
    }
    const nsets = drive_nodes.len / set_size;
    const sets = try gpa.alloc([]u32, nsets);
    var made: usize = 0;
    errdefer {
        for (sets[0..made]) |s| gpa.free(s);
        gpa.free(sets);
    }
    for (sets, 0..) |*s, i| {
        s.* = try gpa.dupe(u32, seq[i * set_size ..][0..set_size]);
        made += 1;
    }
    return sets;
}

pub fn freeSets(gpa: std.mem.Allocator, sets: [][]u32) void {
    for (sets) |s| gpa.free(s);
    gpa.free(sets);
}

fn derive(comptime T: type, deployment: [16]u8, parts: []const u32) T {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zkfsm-layout-v2");
    h.update(&deployment);
    for (parts) |p| h.update(std.mem.asBytes(&std.mem.nativeToLittle(u32, p)));
    var d: [32]u8 = undefined;
    h.final(&d);
    return .{ .bytes = d[0..16].* };
}

pub fn driveId(deployment: [16]u8, pool: u32, set: u32, index: u32) DriveId {
    return derive(DriveId, deployment, &.{ pool, set, index });
}

pub fn setId(deployment: [16]u8, pool: u32, set: u32) SetId {
    return derive(SetId, deployment, &.{ pool, set, 0xffff_ffff });
}

/// Contents of a cluster drive's format file.
pub const FormatV2 = struct {
    deployment: [16]u8,
    /// Fingerprint of the pool's endpoint list, set size, and profile.
    layout: [16]u8,
    pool: u32,
    set: u32,
    index: u32,
    set_size: u32,
    profile: Profile,

    pub const magic = "zkfsm-format 2";

    pub fn drive(f: FormatV2) DriveId {
        return driveId(f.deployment, f.pool, f.set, f.index);
    }

    pub fn encode(f: FormatV2, buf: []u8) error{NoSpaceLeft}![]u8 {
        var w: std.Io.Writer = .fixed(buf);
        const dep = std.fmt.bytesToHex(f.deployment, .lower);
        const lay = std.fmt.bytesToHex(f.layout, .lower);
        w.print("{s}\ndeployment {s}\nlayout {s}\npool {d}\nset {d}\nindex {d}\nsize {d}\nprofile {s}\ndrive {s}\ndrives ", .{
            magic, &dep, &lay, f.pool, f.set, f.index, f.set_size, f.profile.name(), &f.drive().toHex(),
        }) catch return error.NoSpaceLeft;
        for (0..f.set_size) |i| {
            const id = driveId(f.deployment, f.pool, f.set, @intCast(i)).toHex();
            w.print("{s}{s}", .{ if (i == 0) "" else ",", &id }) catch return error.NoSpaceLeft;
        }
        w.writeAll("\n") catch return error.NoSpaceLeft;
        return w.buffered();
    }

    pub fn parse(bytes: []const u8) error{CorruptFormat}!FormatV2 {
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        if (!std.mem.eql(u8, lines.next() orelse "", magic)) return error.CorruptFormat;
        var f: FormatV2 = undefined;
        f.deployment = try hex16(try field(lines.next(), "deployment "));
        f.layout = try hex16(try field(lines.next(), "layout "));
        f.pool = try num(try field(lines.next(), "pool "));
        f.set = try num(try field(lines.next(), "set "));
        f.index = try num(try field(lines.next(), "index "));
        f.set_size = try num(try field(lines.next(), "size "));
        f.profile = Profile.parse(try field(lines.next(), "profile ")) catch return error.CorruptFormat;
        const self_id = DriveId.parseHex(try field(lines.next(), "drive ")) catch return error.CorruptFormat;
        if (f.set_size == 0 or f.set_size > max_set_size or f.index >= f.set_size) return error.CorruptFormat;
        if (!self_id.eql(f.drive())) return error.CorruptFormat;
        var ids = std.mem.splitScalar(u8, try field(lines.next(), "drives "), ',');
        var n: u32 = 0;
        while (ids.next()) |h| : (n += 1) {
            const id = DriveId.parseHex(h) catch return error.CorruptFormat;
            if (n >= f.set_size or !id.eql(driveId(f.deployment, f.pool, f.set, n))) return error.CorruptFormat;
        }
        if (n != f.set_size) return error.CorruptFormat;
        return f;
    }

    /// Same deployment and slot; used to verify a drive sits where the layout says.
    pub fn sameSlot(a: FormatV2, b: FormatV2) bool {
        return std.mem.eql(u8, &a.deployment, &b.deployment) and std.mem.eql(u8, &a.layout, &b.layout) and
            a.pool == b.pool and a.set == b.set and a.index == b.index and a.set_size == b.set_size and a.profile.eql(b.profile);
    }

    fn field(line: ?[]const u8, prefix: []const u8) error{CorruptFormat}![]const u8 {
        const l = line orelse return error.CorruptFormat;
        if (!std.mem.startsWith(u8, l, prefix)) return error.CorruptFormat;
        return l[prefix.len..];
    }

    fn hex16(s: []const u8) error{CorruptFormat}![16]u8 {
        if (s.len != 32) return error.CorruptFormat;
        var out: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch return error.CorruptFormat;
        return out;
    }

    fn num(s: []const u8) error{CorruptFormat}!u32 {
        return std.fmt.parseInt(u32, s, 10) catch error.CorruptFormat;
    }
};

pub const format_max = 4096;

/// Ranks `n` set drives for a key, keeping at most ceil(width / nodes) per node when
/// possible so a node loss costs no more shards than the layout must.
pub fn spread(ids: []const DriveId, nodes: []const u16, key: []const u8, width: usize, out: *[rendezvous.max_drives]u8) []const u8 {
    var ranked: [rendezvous.max_drives]u8 = undefined;
    const r = rendezvous.rank(ids, key, &ranked);
    var distinct: usize = 0;
    var seen: [rendezvous.max_drives]u16 = undefined;
    for (nodes[0..r.len]) |nd| {
        if (std.mem.indexOfScalar(u16, seen[0..distinct], nd) == null) {
            seen[distinct] = nd;
            distinct += 1;
        }
    }
    const cap = std.math.divCeil(usize, width, @max(distinct, 1)) catch unreachable;
    var taken: [rendezvous.max_drives]bool = @splat(false);
    var per: [rendezvous.max_drives]u8 = @splat(0);
    var n: usize = 0;
    for (r) |d| {
        if (n == width) break;
        const slot = std.mem.indexOfScalar(u16, seen[0..distinct], nodes[d]).?;
        if (per[slot] >= cap) continue;
        per[slot] += 1;
        taken[d] = true;
        out[n] = d;
        n += 1;
    }
    for (r) |d| {
        if (n == width) break;
        if (taken[d]) continue;
        out[n] = d;
        n += 1;
    }
    return out[0..n];
}

test "set size choice" {
    try std.testing.expectEqual(@as(usize, 16), try chooseSetSize(16, 4, 6, null));
    try std.testing.expectEqual(@as(usize, 12), try chooseSetSize(12, 3, 6, null));
    try std.testing.expectEqual(@as(usize, 6), try chooseSetSize(12, 3, 6, 6));
    try std.testing.expectEqual(@as(usize, 8), try chooseSetSize(16, 4, 6, 8));
    try std.testing.expectError(error.BadLayout, chooseSetSize(16, 4, 6, 7));
    try std.testing.expectError(error.BadLayout, chooseSetSize(5, 5, 6, null));
    try std.testing.expectEqual(@as(usize, 12), try chooseSetSize(24, 4, 6, null));
}

test "quorums follow the parity share" {
    const ec42: Profile = .{ .erasure = .{ .data = 4, .parity = 2 } };
    try std.testing.expectEqual(@as(usize, 2), tolerance(6, ec42));
    try std.testing.expectEqual(@as(usize, 4), setWriteQuorum(6, ec42));
    try std.testing.expectEqual(@as(usize, 11), setWriteQuorum(16, ec42));
    try std.testing.expectEqual(@as(usize, 4), objectWriteQuorum(ec42));
    try std.testing.expectEqual(@as(usize, 2), objectWriteQuorum(.{ .replica = 2 }));
    try std.testing.expectEqual(@as(usize, 3), setWriteQuorum(4, .{ .replica = 2 }));
}

test "assignment spreads sets across nodes" {
    const gpa = std.testing.allocator;
    // 4 nodes x 4 drives, node-major endpoint order.
    var nodes: [16]u16 = undefined;
    for (&nodes, 0..) |*n, i| n.* = @intCast(i / 4);
    const sets = try assign(gpa, &nodes, 8);
    defer freeSets(gpa, sets);
    try std.testing.expectEqual(@as(usize, 2), sets.len);
    for (sets) |s| {
        var per: [4]u8 = @splat(0);
        for (s) |e| per[nodes[e]] += 1;
        for (per) |c| try std.testing.expectEqual(@as(u8, 2), c);
    }
}

test "spread caps shards per node" {
    var ids: [16]DriveId = undefined;
    var nodes: [16]u16 = undefined;
    for (&ids, 0..) |*d, i| d.* = .{ .bytes = [_]u8{@intCast(i + 1)} ** 16 };
    for (&nodes, 0..) |*n, i| n.* = @intCast(i % 4);
    var out: [rendezvous.max_drives]u8 = undefined;
    for (0..200) |k| {
        var kb: [8]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "k{d}", .{k}) catch unreachable;
        const pl = spread(&ids, &nodes, key, 6, &out);
        try std.testing.expectEqual(@as(usize, 6), pl.len);
        var per: [4]u8 = @splat(0);
        for (pl) |d| per[nodes[d]] += 1;
        for (per) |c| try std.testing.expect(c <= 2);
    }
}

test "format v2 roundtrip and slot check" {
    const f: FormatV2 = .{
        .deployment = [_]u8{1} ** 16,
        .layout = [_]u8{2} ** 16,
        .pool = 1,
        .set = 3,
        .index = 5,
        .set_size = 6,
        .profile = .{ .erasure = .{ .data = 4, .parity = 2 } },
    };
    var buf: [format_max]u8 = undefined;
    const g = try FormatV2.parse(try f.encode(&buf));
    try std.testing.expect(g.sameSlot(f));
    try std.testing.expect(g.drive().eql(f.drive()));
    var h = f;
    h.index = 4;
    try std.testing.expect(!h.sameSlot(f));
    try std.testing.expectError(error.CorruptFormat, FormatV2.parse("zkfsm-format 2\ndeployment x\n"));
}
