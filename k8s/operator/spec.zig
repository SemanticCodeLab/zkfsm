//! zkfsm.io/v1 Cluster: the spec the operator reads and the names it derives.
const std = @import("std");

pub const group = "zkfsm.io";
pub const version = "zkfsm.io/v1";
pub const default_image = "ghcr.io/semanticcodelab/zkfsm:latest";
pub const port = 9000;

pub const Pool = struct {
    name: []const u8,
    servers: u32,
    drivesPerServer: u32 = 1,
    size: []const u8 = "10Gi",
    storageClassName: ?[]const u8 = null,
    resources: ?std.json.Value = null,
    nodeSelector: ?std.json.Value = null,
    tolerations: ?std.json.Value = null,
    affinity: ?std.json.Value = null,
    /// Drain this pool through the admin API, then drop it from the endpoint list.
    decommission: bool = false,
};

pub const Tls = struct {
    /// none | selfSigned | certManager
    mode: []const u8 = "none",
    issuerRef: ?struct { name: []const u8, kind: []const u8 = "Issuer", group: []const u8 = "cert-manager.io" } = null,
};

pub const Kms = struct {
    backend: []const u8,
    defaultKey: ?[]const u8 = null,
    /// Secret whose keys become environment variables (backend settings, tokens).
    secretName: ?[]const u8 = null,
};

pub const User = struct {
    /// Secret with accessKey / secretKey.
    secretName: []const u8,
    policies: []const []const u8 = &.{},
};

pub const Policy = struct {
    name: []const u8,
    /// IAM policy document as a JSON string.
    document: []const u8,
};

pub const Bucket = struct {
    name: []const u8,
    objectLock: bool = false,
};

pub const Iam = struct {
    policies: []const Policy = &.{},
    users: []const User = &.{},
    buckets: []const Bucket = &.{},
};

pub const Ingress = struct {
    enabled: bool = false,
    host: ?[]const u8 = null,
    className: ?[]const u8 = null,
    tlsSecretName: ?[]const u8 = null,
    annotations: ?std.json.Value = null,
};

pub const Console = struct {
    enabled: bool = false,
    image: ?[]const u8 = null,
    port: u16 = 9090,
    env: ?std.json.Value = null,
    ingress: Ingress = .{},
};

pub const Spec = struct {
    image: []const u8 = default_image,
    imagePullPolicy: []const u8 = "IfNotPresent",
    pools: []const Pool,
    protection: ?[]const u8 = null,
    setSize: u32 = 0,
    /// Secret with accessKey / secretKey for the root user.
    credsSecret: []const u8,
    tls: Tls = .{},
    kms: ?Kms = null,
    iam: Iam = .{},
    ingress: Ingress = .{},
    console: Console = .{},
    env: ?std.json.Value = null,
    clusterDomain: []const u8 = "cluster.local",
    serviceType: []const u8 = "ClusterIP",
    podAnnotations: ?std.json.Value = null,
    priorityClassName: ?[]const u8 = null,
};

/// Pool progress recorded in status.pools, keyed by name.
pub const PoolState = enum { active, decommissioning, decommissioned };

pub const Cluster = struct {
    name: []const u8,
    namespace: []const u8,
    uid: []const u8,
    generation: i64,
    spec: Spec,
    /// Raw status from the API object (may be null).
    status: ?std.json.Value,

    pub fn parse(a: std.mem.Allocator, obj: std.json.Value) !Cluster {
        const meta = obj.object.get("metadata") orelse return error.BadObject;
        const spec_v = obj.object.get("spec") orelse return error.BadObject;
        const spec = try std.json.parseFromValueLeaky(Spec, a, spec_v, .{ .ignore_unknown_fields = true });
        try validate(spec);
        return .{
            .name = meta.object.get("name").?.string,
            .namespace = meta.object.get("namespace").?.string,
            .uid = if (meta.object.get("uid")) |u| u.string else "",
            .generation = if (meta.object.get("generation")) |g| g.integer else 0,
            .spec = spec,
            .status = obj.object.get("status"),
        };
    }

    pub fn poolState(c: Cluster, pool: []const u8) PoolState {
        const st = c.status orelse return .active;
        if (st != .object) return .active;
        const pools = st.object.get("pools") orelse return .active;
        if (pools != .array) return .active;
        for (pools.array.items) |p| {
            const n = p.object.get("name") orelse continue;
            if (n != .string or !std.mem.eql(u8, n.string, pool)) continue;
            const s = p.object.get("state") orelse return .active;
            return std.meta.stringToEnum(PoolState, s.string) orelse .active;
        }
        return .active;
    }

    pub fn tlsOn(c: Cluster) bool {
        return !std.mem.eql(u8, c.spec.tls.mode, "none");
    }

    pub fn scheme(c: Cluster) []const u8 {
        return if (c.tlsOn()) "https" else "http";
    }

    pub fn headless(c: Cluster, a: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(a, "{s}-hl", .{c.name});
    }

    pub fn stsName(c: Cluster, a: std.mem.Allocator, pool: []const u8) ![]u8 {
        return std.fmt.allocPrint(a, "{s}-{s}", .{ c.name, pool });
    }

    /// FQDN suffix shared by every pod: <name>-hl.<ns>.svc.<domain>
    pub fn podDomain(c: Cluster, a: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(a, "{s}-hl.{s}.svc.{s}", .{ c.name, c.namespace, c.spec.clusterDomain });
    }

    pub fn podHost(c: Cluster, a: std.mem.Allocator, pool: []const u8, i: u32) ![]u8 {
        return std.fmt.allocPrint(a, "{s}-{s}-{d}.{s}", .{ c.name, pool, i, try c.podDomain(a) });
    }

    /// The pool's --data pattern, e.g. http://c-p0-{0...3}.c-hl.ns.svc.cluster.local:9000/data{1...4}
    pub fn poolEndpoint(c: Cluster, a: std.mem.Allocator, p: Pool) ![]u8 {
        const hosts = if (p.servers == 1)
            try std.fmt.allocPrint(a, "{s}-{s}-0", .{ c.name, p.name })
        else
            try std.fmt.allocPrint(a, "{s}-{s}-{{0...{d}}}", .{ c.name, p.name, p.servers - 1 });
        const drives = if (p.drivesPerServer == 1) try a.dupe(u8, "/data1") else try std.fmt.allocPrint(a, "/data{{1...{d}}}", .{p.drivesPerServer});
        return std.fmt.allocPrint(a, "{s}://{s}.{s}:{d}{s}", .{ c.scheme(), hosts, try c.podDomain(a), port, drives });
    }

    /// Pools still in the endpoint list: everything not yet fully decommissioned.
    pub fn livePools(c: Cluster, a: std.mem.Allocator) ![]const Pool {
        var out: std.ArrayList(Pool) = .empty;
        for (c.spec.pools) |p| if (c.poolState(p.name) != .decommissioned) try out.append(a, p);
        return out.items;
    }
};

pub fn validate(s: Spec) !void {
    if (s.pools.len == 0) return error.NoPools;
    for (s.pools, 0..) |p, i| {
        if (p.servers == 0 or p.drivesPerServer == 0 or p.drivesPerServer > 16) return error.BadPool;
        if (!dnsLabel(p.name)) return error.BadPoolName;
        for (s.pools[0..i]) |q| if (std.mem.eql(u8, p.name, q.name)) return error.DuplicatePool;
    }
    const modes = [_][]const u8{ "none", "selfSigned", "certManager" };
    for (modes) |m| {
        if (std.mem.eql(u8, m, s.tls.mode)) break;
    } else return error.BadTlsMode;
    if (std.mem.eql(u8, s.tls.mode, "certManager") and s.tls.issuerRef == null) return error.MissingIssuer;
    if (s.console.enabled and s.console.image == null) return error.ConsoleImage;
}

fn dnsLabel(n: []const u8) bool {
    if (n.len == 0 or n.len > 40) return false;
    for (n) |ch| if (!(std.ascii.isLower(ch) or std.ascii.isDigit(ch) or ch == '-')) return false;
    return n[0] != '-' and n[n.len - 1] != '-';
}

test "parse and endpoints" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        \\{"metadata":{"name":"s3","namespace":"prod","generation":3,"uid":"u"},
        \\ "spec":{"credsSecret":"root","pools":[{"name":"p0","servers":4,"drivesPerServer":4},{"name":"p1","servers":1}],"unknown":1},
        \\ "status":{"pools":[{"name":"p1","state":"decommissioned"}]}}
    ;
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
    const c = try Cluster.parse(a, v);
    try std.testing.expectEqualStrings("http://s3-p0-{0...3}.s3-hl.prod.svc.cluster.local:9000/data{1...4}", try c.poolEndpoint(a, c.spec.pools[0]));
    try std.testing.expectEqualStrings("http://s3-p1-0.s3-hl.prod.svc.cluster.local:9000/data1", try c.poolEndpoint(a, c.spec.pools[1]));
    try std.testing.expectEqual(PoolState.decommissioned, c.poolState("p1"));
    try std.testing.expectEqual(@as(usize, 1), (try c.livePools(a)).len);
}

test "validation" {
    const p = [_]Pool{ .{ .name = "a", .servers = 1 }, .{ .name = "a", .servers = 2 } };
    try std.testing.expectError(error.DuplicatePool, validate(.{ .pools = &p, .credsSecret = "x" }));
    const q = [_]Pool{.{ .name = "A", .servers = 1 }};
    try std.testing.expectError(error.BadPoolName, validate(.{ .pools = &q, .credsSecret = "x" }));
    const r = [_]Pool{.{ .name = "a", .servers = 1 }};
    try std.testing.expectError(error.MissingIssuer, validate(.{ .pools = &r, .credsSecret = "x", .tls = .{ .mode = "certManager" } }));
    try validate(.{ .pools = &r, .credsSecret = "x" });
}
