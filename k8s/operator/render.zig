//! Desired Kubernetes objects for a Cluster. Pure: the controller applies them
//! with server-side apply and owns their lifecycle through ownerReferences.
const std = @import("std");
const spec = @import("spec.zig");
const jv = @import("jv.zig");

const Value = std.json.Value;
const A = std.mem.Allocator;
const Cluster = spec.Cluster;
const Pool = spec.Pool;

pub const topology_annotation = "zkfsm.io/topology";

pub const Object = struct {
    /// API path of the object, e.g. /apis/apps/v1/namespaces/ns/statefulsets/x
    path: []const u8,
    kind: []const u8,
    name: []const u8,
    body: Value,
};

fn labels(a: A, c: Cluster, pool: ?[]const u8) !Value {
    return jv.v(a, .{
        .@"app.kubernetes.io/name" = "zkfsm",
        .@"app.kubernetes.io/managed-by" = "zkfsm-operator",
        .@"zkfsm.io/cluster" = c.name,
        .@"zkfsm.io/pool" = pool,
    });
}

fn meta(a: A, c: Cluster, name: []const u8, pool: ?[]const u8) !Value {
    return jv.v(a, .{
        .name = name,
        .namespace = c.namespace,
        .labels = try labels(a, c, pool),
        .ownerReferences = .{.{
            .apiVersion = spec.version,
            .kind = "Cluster",
            .name = c.name,
            .uid = c.uid,
            .controller = true,
            .blockOwnerDeletion = true,
        }},
    });
}

fn nsPath(a: A, gv: []const u8, c: Cluster, plural: []const u8, name: []const u8) ![]u8 {
    const prefix = if (std.mem.indexOfScalar(u8, gv, '/') == null) "/api/" else "/apis/";
    return std.fmt.allocPrint(a, "{s}{s}/namespaces/{s}/{s}/{s}", .{ prefix, gv, c.namespace, plural, name });
}

pub fn tlsSecretName(a: A, c: Cluster) ![]u8 {
    return std.fmt.allocPrint(a, "{s}-tls", .{c.name});
}

/// Hash of everything every node must agree on; a change restarts all pods at once.
pub fn topologyHash(a: A, c: Cluster) ![]u8 {
    var h = std.hash.Wyhash.init(0);
    h.update(c.scheme());
    for (try c.livePools(a)) |p| {
        h.update(try c.poolEndpoint(a, p));
        h.update("\x00");
    }
    if (c.spec.protection) |p| h.update(p);
    h.update(std.mem.asBytes(&c.spec.setSize));
    return std.fmt.allocPrint(a, "{x:0>16}", .{h.final()});
}

pub fn services(a: A, c: Cluster) ![2]Object {
    const hl = try c.headless(a);
    const port_name = if (c.tlsOn()) "https-s3" else "http-s3";
    const ports = .{.{ .name = port_name, .port = spec.port, .targetPort = spec.port }};
    const sel = .{ .@"zkfsm.io/cluster" = c.name };
    return .{
        .{ .path = try nsPath(a, "v1", c, "services", hl), .kind = "Service", .name = hl, .body = try jv.v(a, .{
            .apiVersion = "v1",
            .kind = "Service",
            .metadata = try meta(a, c, hl, null),
            .spec = .{ .clusterIP = "None", .publishNotReadyAddresses = true, .selector = sel, .ports = ports },
        }) },
        .{ .path = try nsPath(a, "v1", c, "services", c.name), .kind = "Service", .name = c.name, .body = try jv.v(a, .{
            .apiVersion = "v1",
            .kind = "Service",
            .metadata = try meta(a, c, c.name, null),
            .spec = .{ .type = c.spec.serviceType, .selector = sel, .ports = ports },
        }) },
    };
}

pub fn args(a: A, c: Cluster) !Value {
    var l: std.ArrayList(Value) = .empty;
    const s = struct {
        fn add(al: A, list: *std.ArrayList(Value), x: []const u8) !void {
            try list.append(al, .{ .string = x });
        }
    };
    try s.add(a, &l, "--listen");
    try s.add(a, &l, "0.0.0.0:9000");
    try s.add(a, &l, "--node-address");
    try s.add(a, &l, try std.fmt.allocPrint(a, "$(POD_NAME).{s}:{d}", .{ try c.podDomain(a), spec.port }));
    for (try c.livePools(a)) |p| {
        try s.add(a, &l, "--data");
        try s.add(a, &l, try c.poolEndpoint(a, p));
    }
    if (c.spec.protection) |p| {
        try s.add(a, &l, "--protection");
        try s.add(a, &l, p);
    }
    if (c.spec.setSize > 0) {
        try s.add(a, &l, "--set-size");
        try s.add(a, &l, try std.fmt.allocPrint(a, "{d}", .{c.spec.setSize}));
    }
    if (c.tlsOn()) {
        for ([_][]const u8{ "--certs-dir", "/certs", "--cluster-ca", "/certs/ca.crt" }) |x| try s.add(a, &l, x);
    }
    return jv.list(a, l.items);
}

fn env(a: A, c: Cluster) !Value {
    var l: std.ArrayList(Value) = .empty;
    try l.append(a, try jv.v(a, .{ .name = "POD_NAME", .valueFrom = .{ .fieldRef = .{ .fieldPath = "metadata.name" } } }));
    try l.append(a, try jv.v(a, .{ .name = "ZKFSM_ACCESS_KEY", .valueFrom = .{ .secretKeyRef = .{ .name = c.spec.credsSecret, .key = "accessKey" } } }));
    try l.append(a, try jv.v(a, .{ .name = "ZKFSM_SECRET_KEY", .valueFrom = .{ .secretKeyRef = .{ .name = c.spec.credsSecret, .key = "secretKey" } } }));
    if (c.spec.kms) |k| {
        try l.append(a, try jv.v(a, .{ .name = "ZKFSM_KMS_BACKEND", .value = k.backend }));
        if (k.defaultKey) |d| try l.append(a, try jv.v(a, .{ .name = "ZKFSM_KMS_DEFAULT_KEY", .value = d }));
    }
    if (c.spec.env) |e| if (e == .array) try l.appendSlice(a, e.array.items);
    return jv.list(a, l.items);
}

pub fn statefulSet(a: A, c: Cluster, p: Pool) !Object {
    const name = try c.stsName(a, p.name);
    const scheme: []const u8 = if (c.tlsOn()) "HTTPS" else "HTTP";
    const topo = try topologyHash(a, c);

    var mounts: std.ArrayList(Value) = .empty;
    var claims: std.ArrayList(Value) = .empty;
    try mounts.append(a, try jv.v(a, .{ .name = "tmp", .mountPath = "/tmp" }));
    if (c.tlsOn()) try mounts.append(a, try jv.v(a, .{ .name = "certs", .mountPath = "/certs", .readOnly = true }));
    for (1..p.drivesPerServer + 1) |i| {
        const dn = try std.fmt.allocPrint(a, "data{d}", .{i});
        try mounts.append(a, try jv.v(a, .{ .name = dn, .mountPath = try std.fmt.allocPrint(a, "/data{d}", .{i}) }));
        try claims.append(a, try jv.v(a, .{
            .metadata = .{ .name = dn, .labels = try labels(a, c, p.name) },
            .spec = .{
                .accessModes = .{"ReadWriteOnce"},
                .storageClassName = p.storageClassName,
                .resources = .{ .requests = .{ .storage = p.size } },
            },
        }));
    }
    var volumes: std.ArrayList(Value) = .empty;
    try volumes.append(a, try jv.v(a, .{ .name = "tmp", .emptyDir = .{} }));
    if (c.tlsOn()) try volumes.append(a, try jv.v(a, .{ .name = "certs", .secret = .{
        .secretName = try tlsSecretName(a, c),
        .items = .{
            .{ .key = "tls.crt", .path = "public.crt" },
            .{ .key = "tls.key", .path = "private.key" },
            .{ .key = "ca.crt", .path = "ca.crt" },
        },
    } }));

    var annotations = try jv.v(a, .{});
    if (c.spec.podAnnotations) |pa| if (pa == .object) {
        var it = pa.object.iterator();
        while (it.next()) |e| try annotations.object.put(e.key_ptr.*, e.value_ptr.*);
    };
    try annotations.object.put(topology_annotation, .{ .string = topo });

    const sel = .{ .@"zkfsm.io/cluster" = c.name, .@"zkfsm.io/pool" = p.name };
    const default_affinity = try jv.v(a, .{ .podAntiAffinity = .{ .preferredDuringSchedulingIgnoredDuringExecution = .{.{
        .weight = 100,
        .podAffinityTerm = .{ .topologyKey = "kubernetes.io/hostname", .labelSelector = .{ .matchLabels = sel } },
    }} } });
    const env_from: ?Value = if (c.spec.kms) |k| if (k.secretName) |sn| try jv.v(a, .{.{ .secretRef = .{ .name = sn } }}) else null else null;

    return .{
        .path = try nsPath(a, "apps/v1", c, "statefulsets", name),
        .kind = "StatefulSet",
        .name = name,
        .body = try jv.v(a, .{
            .apiVersion = "apps/v1",
            .kind = "StatefulSet",
            .metadata = try meta(a, c, name, p.name),
            .spec = .{
                .serviceName = try c.headless(a),
                .replicas = p.servers,
                .podManagementPolicy = "Parallel",
                // The operator deletes pods itself: one at a time, gated on quorum.
                .updateStrategy = .{ .type = "OnDelete" },
                .selector = .{ .matchLabels = sel },
                .template = .{
                    .metadata = .{ .labels = try labels(a, c, p.name), .annotations = annotations },
                    .spec = .{
                        .terminationGracePeriodSeconds = 60,
                        .priorityClassName = c.spec.priorityClassName,
                        .securityContext = .{ .runAsNonRoot = true, .runAsUser = 10001, .runAsGroup = 10001, .fsGroup = 10001, .fsGroupChangePolicy = "OnRootMismatch" },
                        .nodeSelector = p.nodeSelector,
                        .tolerations = p.tolerations,
                        .affinity = p.affinity orelse default_affinity,
                        .containers = .{.{
                            .name = "zkfsm",
                            .image = c.spec.image,
                            .imagePullPolicy = c.spec.imagePullPolicy,
                            .args = try args(a, c),
                            .env = try env(a, c),
                            .envFrom = env_from,
                            .ports = .{.{ .name = "s3", .containerPort = spec.port }},
                            .readinessProbe = .{ .httpGet = .{ .path = "/health/ready", .port = spec.port, .scheme = scheme }, .periodSeconds = 5, .failureThreshold = 3 },
                            .livenessProbe = .{ .httpGet = .{ .path = "/health/live", .port = spec.port, .scheme = scheme }, .initialDelaySeconds = 10, .periodSeconds = 10, .failureThreshold = 6 },
                            .resources = p.resources,
                            .securityContext = .{ .allowPrivilegeEscalation = false, .readOnlyRootFilesystem = true, .capabilities = .{ .drop = .{"ALL"} } },
                            .volumeMounts = try jv.list(a, mounts.items),
                        }},
                        .volumes = try jv.list(a, volumes.items),
                    },
                },
                .volumeClaimTemplates = try jv.list(a, claims.items),
            },
        }),
    };
}

pub fn pdb(a: A, c: Cluster, p: Pool) !Object {
    const name = try c.stsName(a, p.name);
    return .{ .path = try nsPath(a, "policy/v1", c, "poddisruptionbudgets", name), .kind = "PodDisruptionBudget", .name = name, .body = try jv.v(a, .{
        .apiVersion = "policy/v1",
        .kind = "PodDisruptionBudget",
        .metadata = try meta(a, c, name, p.name),
        .spec = .{ .maxUnavailable = 1, .selector = .{ .matchLabels = .{ .@"zkfsm.io/cluster" = c.name, .@"zkfsm.io/pool" = p.name } } },
    }) };
}

/// DNS names the server certificate must cover.
pub fn dnsNames(a: A, c: Cluster) ![]const []const u8 {
    const d = c.spec.clusterDomain;
    var l: std.ArrayList([]const u8) = .empty;
    try l.append(a, try std.fmt.allocPrint(a, "*.{s}-hl.{s}.svc.{s}", .{ c.name, c.namespace, d }));
    try l.append(a, try std.fmt.allocPrint(a, "{s}.{s}.svc.{s}", .{ c.name, c.namespace, d }));
    try l.append(a, try std.fmt.allocPrint(a, "{s}.{s}.svc", .{ c.name, c.namespace }));
    try l.append(a, try std.fmt.allocPrint(a, "{s}.{s}", .{ c.name, c.namespace }));
    try l.append(a, c.name);
    try l.append(a, "localhost");
    if (c.spec.ingress.host) |h| try l.append(a, h);
    return l.items;
}

pub fn certificate(a: A, c: Cluster) !Object {
    const name = try tlsSecretName(a, c);
    const ref = c.spec.tls.issuerRef.?;
    return .{ .path = try nsPath(a, "cert-manager.io/v1", c, "certificates", name), .kind = "Certificate", .name = name, .body = try jv.v(a, .{
        .apiVersion = "cert-manager.io/v1",
        .kind = "Certificate",
        .metadata = try meta(a, c, name, null),
        .spec = .{
            .secretName = name,
            .dnsNames = try dnsNames(a, c),
            .privateKey = .{ .algorithm = "ECDSA", .size = 256, .encoding = "PKCS8" },
            .usages = .{ "server auth", "client auth", "digital signature" },
            .issuerRef = .{ .name = ref.name, .kind = ref.kind, .group = ref.group },
        },
    }) };
}

pub fn tlsSecret(a: A, c: Cluster, cert: []const u8, key: []const u8, ca: []const u8) !Object {
    const name = try tlsSecretName(a, c);
    return .{ .path = try nsPath(a, "v1", c, "secrets", name), .kind = "Secret", .name = name, .body = try jv.v(a, .{
        .apiVersion = "v1",
        .kind = "Secret",
        .metadata = try meta(a, c, name, null),
        .type = "kubernetes.io/tls",
        .stringData = .{ .@"tls.crt" = cert, .@"tls.key" = key, .@"ca.crt" = ca },
    }) };
}

pub fn caSecret(a: A, c: Cluster, cert: []const u8, key: []const u8) !Object {
    const name = try std.fmt.allocPrint(a, "{s}-ca", .{c.name});
    return .{ .path = try nsPath(a, "v1", c, "secrets", name), .kind = "Secret", .name = name, .body = try jv.v(a, .{
        .apiVersion = "v1",
        .kind = "Secret",
        .metadata = try meta(a, c, name, null),
        .stringData = .{ .@"ca.crt" = cert, .@"ca.key" = key },
    }) };
}

fn ingressFor(a: A, c: Cluster, name: []const u8, ing: spec.Ingress, svc: []const u8, svc_port: u16) !Object {
    const tls: ?Value = if (ing.tlsSecretName) |s| try jv.v(a, .{.{ .hosts = .{ing.host}, .secretName = s }}) else null;
    var m = try meta(a, c, name, null);
    if (ing.annotations) |an| try m.object.put("annotations", an);
    if (c.tlsOn()) {
        if (m.object.getPtr("annotations") == null) try m.object.put("annotations", try jv.v(a, .{}));
        try m.object.getPtr("annotations").?.object.put("nginx.ingress.kubernetes.io/backend-protocol", .{ .string = "HTTPS" });
    }
    return .{ .path = try nsPath(a, "networking.k8s.io/v1", c, "ingresses", name), .kind = "Ingress", .name = name, .body = try jv.v(a, .{
        .apiVersion = "networking.k8s.io/v1",
        .kind = "Ingress",
        .metadata = m,
        .spec = .{
            .ingressClassName = ing.className,
            .tls = tls,
            .rules = .{.{
                .host = ing.host,
                .http = .{ .paths = .{.{ .path = "/", .pathType = "Prefix", .backend = .{ .service = .{ .name = svc, .port = .{ .number = svc_port } } } }} },
            }},
        },
    }) };
}

pub fn ingress(a: A, c: Cluster) !Object {
    return ingressFor(a, c, c.name, c.spec.ingress, c.name, spec.port);
}

pub fn consoleObjects(a: A, c: Cluster) ![3]Object {
    const name = try std.fmt.allocPrint(a, "{s}-console", .{c.name});
    const sel = .{ .@"zkfsm.io/console" = c.name };
    const endpoint = try std.fmt.allocPrint(a, "{s}://{s}.{s}.svc.{s}:{d}", .{ c.scheme(), c.name, c.namespace, c.spec.clusterDomain, spec.port });
    var envs: std.ArrayList(Value) = .empty;
    try envs.append(a, try jv.v(a, .{ .name = "ZKFSM_ENDPOINT", .value = endpoint }));
    if (c.spec.console.env) |e| if (e == .array) try envs.appendSlice(a, e.array.items);
    var m = try meta(a, c, name, null);
    try m.object.getPtr("labels").?.object.put("zkfsm.io/console", .{ .string = c.name });
    return .{
        .{ .path = try nsPath(a, "apps/v1", c, "deployments", name), .kind = "Deployment", .name = name, .body = try jv.v(a, .{
            .apiVersion = "apps/v1",
            .kind = "Deployment",
            .metadata = m,
            .spec = .{
                .replicas = 1,
                .selector = .{ .matchLabels = sel },
                .template = .{
                    .metadata = .{ .labels = sel },
                    .spec = .{ .containers = .{.{
                        .name = "console",
                        .image = c.spec.console.image.?,
                        .env = try jv.list(a, envs.items),
                        .ports = .{.{ .name = "http", .containerPort = c.spec.console.port }},
                    }} },
                },
            },
        }) },
        .{ .path = try nsPath(a, "v1", c, "services", name), .kind = "Service", .name = name, .body = try jv.v(a, .{
            .apiVersion = "v1",
            .kind = "Service",
            .metadata = m,
            .spec = .{ .selector = sel, .ports = .{.{ .name = "http", .port = c.spec.console.port, .targetPort = c.spec.console.port }} },
        }) },
        try ingressFor(a, c, name, c.spec.console.ingress, name, c.spec.console.port),
    };
}

fn testCluster(a: A, extra: []const u8) !Cluster {
    const text = try std.fmt.allocPrint(a,
        \\{{"metadata":{{"name":"s3","namespace":"ns","generation":1,"uid":"u1"}},
        \\ "spec":{{"credsSecret":"root","protection":"EC:4+2","pools":[{{"name":"p0","servers":4,"drivesPerServer":4,"storageClassName":"zkfsm-direct"}}]{s}}}}}
    , .{extra});
    return Cluster.parse(a, try std.json.parseFromSliceLeaky(Value, a, text, .{}));
}

test "statefulset shape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try testCluster(a, "");
    const o = try statefulSet(a, c, c.spec.pools[0]);
    try std.testing.expectEqualStrings("/apis/apps/v1/namespaces/ns/statefulsets/s3-p0", o.path);
    const s = try jv.stringify(a, o.body);
    for ([_][]const u8{
        "\"--data\",\"http://s3-p0-{0...3}.s3-hl.ns.svc.cluster.local:9000/data{1...4}\"",
        "\"--node-address\",\"$(POD_NAME).s3-hl.ns.svc.cluster.local:9000\"",
        "\"--protection\",\"EC:4+2\"",
        "\"updateStrategy\":{\"type\":\"OnDelete\"}",
        "\"name\":\"data4\"",
        "\"storageClassName\":\"zkfsm-direct\"",
        "\"uid\":\"u1\"",
    }) |want| if (std.mem.indexOf(u8, s, want) == null) {
        std.debug.print("missing {s} in {s}\n", .{ want, s });
        return error.TestUnexpectedResult;
    };
    try std.testing.expect(std.mem.indexOf(u8, s, "/certs") == null);
}

test "tls and appended pool change the topology" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c1 = try testCluster(a, "");
    const c2 = try testCluster(a, ",\"tls\":{\"mode\":\"selfSigned\"}");
    try std.testing.expect(!std.mem.eql(u8, try topologyHash(a, c1), try topologyHash(a, c2)));
    const s = try jv.stringify(a, (try statefulSet(a, c2, c2.spec.pools[0])).body);
    try std.testing.expect(std.mem.indexOf(u8, s, "https://s3-p0-{0...3}") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"--cluster-ca\",\"/certs/ca.crt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"scheme\":\"HTTPS\"") != null);

    const text =
        \\{"metadata":{"name":"s3","namespace":"ns","uid":"u"},"spec":{"credsSecret":"r","pools":[
        \\ {"name":"p0","servers":4,"drivesPerServer":4},{"name":"p1","servers":2,"drivesPerServer":2}]}}
    ;
    const c3 = try Cluster.parse(a, try std.json.parseFromSliceLeaky(Value, a, text, .{}));
    try std.testing.expect(!std.mem.eql(u8, try topologyHash(a, c1), try topologyHash(a, c3)));
    const s3 = try jv.stringify(a, try args(a, c3));
    try std.testing.expect(std.mem.indexOf(u8, s3, "\"--data\",\"http://s3-p1-{0...1}.s3-hl.ns.svc.cluster.local:9000/data{1...2}\"") != null);
}

test "services, pdb, certificate, ingress, console" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try testCluster(a,
        \\,"tls":{"mode":"certManager","issuerRef":{"name":"ca"}},"ingress":{"enabled":true,"host":"s3.example.test","className":"nginx"},
        \\"console":{"enabled":true,"image":"example/console:1"},"kms":{"backend":"static","defaultKey":"k1","secretName":"kms"}
    );
    const svcs = try services(a, c);
    try std.testing.expect(std.mem.indexOf(u8, try jv.stringify(a, svcs[0].body), "\"publishNotReadyAddresses\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, try jv.stringify(a, (try pdb(a, c, c.spec.pools[0])).body), "\"maxUnavailable\":1") != null);
    const cert = try jv.stringify(a, (try certificate(a, c)).body);
    try std.testing.expect(std.mem.indexOf(u8, cert, "*.s3-hl.ns.svc.cluster.local") != null);
    try std.testing.expect(std.mem.indexOf(u8, cert, "s3.example.test") != null);
    const ing = try jv.stringify(a, (try ingress(a, c)).body);
    try std.testing.expect(std.mem.indexOf(u8, ing, "backend-protocol\":\"HTTPS\"") != null);
    const con = try consoleObjects(a, c);
    try std.testing.expect(std.mem.indexOf(u8, try jv.stringify(a, con[0].body), "https://s3.ns.svc.cluster.local:9000") != null);
    const sts = try jv.stringify(a, (try statefulSet(a, c, c.spec.pools[0])).body);
    try std.testing.expect(std.mem.indexOf(u8, sts, "\"envFrom\":[{\"secretRef\":{\"name\":\"kms\"}}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, sts, "ZKFSM_KMS_DEFAULT_KEY") != null);
}
