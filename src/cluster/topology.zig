//! Cluster topology from the endpoint list every node is started with: pools of
//! `http(s)://host:port/path` drives, the nodes behind them, and which node is this one.
const std = @import("std");
const placement = @import("../placement/root.zig");

pub const Error = error{ BadEndpoint, MixedSchemes, DuplicateEndpoint, UnknownLocalNode, AmbiguousLocalNode, TooManyNodes, OutOfMemory };

pub const max_nodes = 256;
pub const default_port: u16 = 9000;

pub const Endpoint = struct {
    url: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
    node: u16,
};

pub const Node = struct {
    host: []const u8,
    port: u16,
    /// "host:port", the node's identity.
    name: []const u8,
};

pub const Pool = struct {
    endpoints: []Endpoint,
};

pub const Topology = struct {
    tls: bool,
    nodes: []Node,
    pools: []Pool,
    local: u16,

    pub fn isLocal(t: *const Topology, e: Endpoint) bool {
        return e.node == t.local;
    }
};

/// True when a `--data` argument names cluster endpoints rather than local paths.
pub fn isUrl(s: []const u8) bool {
    return std.mem.startsWith(u8, s, "http://") or std.mem.startsWith(u8, s, "https://");
}

const Parsed = struct { tls: bool, host: []const u8, port: u16, path: []const u8 };

fn parseEndpoint(s: []const u8) Error!Parsed {
    const tls = std.mem.startsWith(u8, s, "https://");
    const rest = s[if (tls) 8 else 7..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.BadEndpoint;
    const authority = rest[0..slash];
    const path = rest[slash..];
    if (path.len < 2 or authority.len == 0) return error.BadEndpoint;
    var host = authority;
    var port: u16 = default_port;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |c| {
        if (authority[0] != '[' or std.mem.indexOfScalar(u8, authority, ']').? < c) {
            host = authority[0..c];
            port = std.fmt.parseInt(u16, authority[c + 1 ..], 10) catch return error.BadEndpoint;
        }
    }
    if (host.len == 0 or port == 0) return error.BadEndpoint;
    for (host) |ch| if (!(std.ascii.isAlphanumeric(ch) or std.mem.indexOfScalar(u8, ".-_[]:", ch) != null)) return error.BadEndpoint;
    return .{ .tls = tls, .host = host, .port = port, .path = path };
}

/// `pool_specs`: per pool, its endpoint arguments with `{a...b}` patterns. `self_addr`
/// is `--node-address`; without it the node is found from the listen address.
pub fn parse(arena: std.mem.Allocator, pool_specs: []const []const []const u8, self_addr: ?[]const u8, listen_host: []const u8, listen_port: u16) Error!Topology {
    var nodes: std.ArrayList(Node) = .empty;
    var pools: std.ArrayList(Pool) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var tls: ?bool = null;
    for (pool_specs) |specs| {
        var urls: std.ArrayList([]const u8) = .empty;
        for (specs) |spec| placement.ellipsis.expand(arena, spec, &urls) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadEndpoint,
        };
        const eps = try arena.alloc(Endpoint, urls.items.len);
        for (urls.items, eps) |u, *ep| {
            if (!isUrl(u)) return error.BadEndpoint;
            const p = try parseEndpoint(u);
            if (tls) |t| if (t != p.tls) return error.MixedSchemes;
            tls = p.tls;
            const name = try std.fmt.allocPrint(arena, "{s}:{d}", .{ p.host, p.port });
            const key = try std.fmt.allocPrint(arena, "{s}{s}", .{ name, p.path });
            if ((try seen.getOrPut(arena, key)).found_existing) return error.DuplicateEndpoint;
            const node: u16 = for (nodes.items, 0..) |n, i| {
                if (std.mem.eql(u8, n.name, name)) break @intCast(i);
            } else blk: {
                if (nodes.items.len >= max_nodes) return error.TooManyNodes;
                try nodes.append(arena, .{ .host = p.host, .port = p.port, .name = name });
                break :blk @intCast(nodes.items.len - 1);
            };
            ep.* = .{ .url = u, .host = p.host, .port = p.port, .path = p.path, .node = node };
        }
        try pools.append(arena, .{ .endpoints = eps });
    }
    if (pools.items.len == 0) return error.BadEndpoint;
    const local = try findLocal(nodes.items, self_addr, listen_host, listen_port);
    return .{ .tls = tls.?, .nodes = nodes.items, .pools = pools.items, .local = local };
}

fn findLocal(nodes: []const Node, self_addr: ?[]const u8, listen_host: []const u8, listen_port: u16) Error!u16 {
    if (self_addr) |a| {
        for (nodes, 0..) |n, i| if (std.mem.eql(u8, n.name, a)) return @intCast(i);
        return error.UnknownLocalNode;
    }
    var hn_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = std.posix.gethostname(&hn_buf) catch "";
    const wildcard = std.mem.eql(u8, listen_host, "0.0.0.0") or std.mem.eql(u8, listen_host, "::");
    var found: ?u16 = null;
    for (nodes, 0..) |n, i| {
        if (n.port != listen_port) continue;
        const mine = std.mem.eql(u8, n.host, listen_host) or
            (wildcard and (std.mem.eql(u8, n.host, hostname) or std.mem.eql(u8, n.host, "localhost") or std.mem.startsWith(u8, n.host, "127.")));
        if (!mine) continue;
        if (found != null) return error.AmbiguousLocalNode;
        found = @intCast(i);
    }
    return found orelse error.UnknownLocalNode;
}

/// Fingerprint of one pool's layout: its endpoint list, set size, and profile.
pub fn poolFingerprint(pool: Pool, set_size: usize, profile: placement.Profile) [16]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("zkfsm-pool-v1\n");
    for (pool.endpoints) |e| {
        h.update(e.url);
        h.update("\n");
    }
    var nb: [32]u8 = undefined;
    h.update(std.fmt.bufPrint(&nb, "{d}\n", .{set_size}) catch unreachable);
    h.update(profile.name());
    var d: [32]u8 = undefined;
    h.final(&d);
    return d[0..16].*;
}

test "endpoint parsing and node grouping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try parse(a, &.{&.{"http://127.0.0.1:{9001...9004}/d/n{1...4}"}}, "127.0.0.1:9002", "0.0.0.0", 9002);
    try std.testing.expectEqual(@as(usize, 4), t.nodes.len);
    try std.testing.expectEqual(@as(usize, 16), t.pools[0].endpoints.len);
    try std.testing.expectEqual(@as(u16, 1), t.local);
    try std.testing.expectEqualStrings("/d/n1", t.pools[0].endpoints[4].path);
    try std.testing.expectEqual(@as(u16, 1), t.pools[0].endpoints[4].node);
    // Found from the listen address alone.
    const u = try parse(a, &.{ &.{"http://node{1...2}:9000/data{1...2}"}, &.{ "http://node3:9000/data{1...2}", "http://node4:9000/data{1...2}" } }, null, "node3", 9000);
    try std.testing.expectEqual(@as(usize, 2), u.pools.len);
    try std.testing.expectEqual(@as(usize, 4), u.pools[1].endpoints.len);
    try std.testing.expectEqual(@as(u16, 2), u.local);
    try std.testing.expectError(error.UnknownLocalNode, parse(a, &.{&.{"http://h{1...2}:9000/d"}}, null, "other", 9000));
    try std.testing.expectError(error.DuplicateEndpoint, parse(a, &.{ &.{"http://h:9000/d"}, &.{"http://h:9000/d"} }, "h:9000", "h", 9000));
    try std.testing.expectError(error.MixedSchemes, parse(a, &.{&.{ "http://h:9000/d", "https://g:9000/d" }}, "h:9000", "h", 9000));
    try std.testing.expectError(error.BadEndpoint, parse(a, &.{&.{"http://h:99999/d"}}, null, "h", 9000));
    try std.testing.expectError(error.BadEndpoint, parse(a, &.{&.{"http://h:9000"}}, null, "h", 9000));
    try std.testing.expect(isUrl("https://x/y") and !isUrl("/data"));
}
