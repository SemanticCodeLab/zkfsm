//! Reconciles zkfsm.io/v1 Clusters: TLS material, services, one StatefulSet and
//! PDB per pool, rollouts (topology changes restart all pods together, other
//! changes roll one pod at a time gated on /health/ready), IAM bootstrap,
//! pool decommission, and status conditions.
const std = @import("std");
const kube = @import("kube");
const spec = @import("spec.zig");
const render = @import("render.zig");
const tlsgen = @import("tlsgen.zig");
const admin = @import("admin.zig");
const jv = @import("jv.zig");

const A = std.mem.Allocator;
const Value = std.json.Value;
const Cluster = spec.Cluster;

pub const Options = struct {
    namespace: ?[]const u8 = null,
    interval_s: u32 = 5,
    work_dir: []const u8 = "/tmp/zkfsm-operator",
};

pub const Controller = struct {
    gpa: A,
    kc: *kube.Client,
    opts: Options,

    pub fn run(ctl: *Controller) void {
        std.fs.cwd().makePath(ctl.opts.work_dir) catch {};
        while (true) {
            ctl.pass();
            std.Thread.sleep(@as(u64, ctl.opts.interval_s) * std.time.ns_per_s);
        }
    }

    pub fn pass(ctl: *Controller) void {
        var arena: std.heap.ArenaAllocator = .init(ctl.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const list_path = kube.resPath(a, spec.version, ctl.opts.namespace, "clusters", null) catch return;
        const list = (ctl.kc.getJson(a, list_path) catch |e| {
            std.log.err("list clusters: {t}", .{e});
            return;
        }) orelse return;
        for (kube.items(list)) |obj| {
            var one: std.heap.ArenaAllocator = .init(ctl.gpa);
            defer one.deinit();
            ctl.reconcileObject(one.allocator(), obj);
        }
    }

    fn reconcileObject(ctl: *Controller, a: A, obj: Value) void {
        const name = kube.str(obj, &.{ "metadata", "name" }) orelse return;
        const ns = kube.str(obj, &.{ "metadata", "namespace" }) orelse return;
        if (kube.lookup(obj, &.{ "metadata", "deletionTimestamp" }) != null) return;
        const c = Cluster.parse(a, obj) catch |e| {
            std.log.warn("{s}/{s}: invalid spec: {t}", .{ ns, name, e });
            var st: Status = .{};
            st.setCond(a, "Available", "False", "InvalidSpec", @errorName(e)) catch return;
            ctl.writeStatus(a, ns, name, obj, &st) catch {};
            return;
        };
        var st = Status.fromExisting(a, c) catch return;
        ctl.reconcile(a, c, &st) catch |e| {
            std.log.warn("{s}/{s}: reconcile: {t}", .{ ns, name, e });
            st.setCond(a, "Degraded", "True", "ReconcileError", @errorName(e)) catch {};
        };
        st.observed_generation = c.generation;
        ctl.writeStatus(a, ns, name, obj, &st) catch |e| std.log.warn("{s}/{s}: status: {t}", .{ ns, name, e });
    }

    fn apply(ctl: *Controller, a: A, o: render.Object) !void {
        const r = try ctl.kc.apply(a, o.path, try jv.stringify(a, o.body));
        if (!r.ok()) {
            std.log.warn("apply {s} {s}: {d} {s}", .{ o.kind, o.name, r.status, r.body[0..@min(r.body.len, 400)] });
            return error.ApplyFailed;
        }
    }

    fn secretData(ctl: *Controller, a: A, ns: []const u8, name: []const u8) !?Value {
        const s = try ctl.kc.getJson(a, try kube.resPath(a, "v1", ns, "secrets", name)) orelse return null;
        return kube.lookup(s, &.{"data"});
    }

    fn secretKey(a: A, data: Value, key: []const u8) !?[]u8 {
        if (data != .object) return null;
        const v = data.object.get(key) orelse return null;
        if (v != .string) return null;
        const dec = std.base64.standard.Decoder;
        const out = try a.alloc(u8, dec.calcSizeForSlice(v.string) catch return error.BadSecret);
        dec.decode(out, v.string) catch return error.BadSecret;
        return out;
    }

    fn reconcile(ctl: *Controller, a: A, c: Cluster, st: *Status) !void {
        const ns = c.namespace;
        // Pools dropped from spec while still holding data would lose objects.
        for (st.pools.items) |p| {
            if (p.state == .decommissioned) continue;
            for (c.spec.pools) |q| {
                if (std.mem.eql(u8, p.name, q.name)) break;
            } else {
                try st.setCond(a, "Degraded", "True", "PoolRemoved", try std.fmt.allocPrint(a, "pool {s} was removed from spec without decommission; restore it", .{p.name}));
                return;
            }
        }

        // The scheme is in every drive's endpoint fingerprint: never switch it live.
        if (st.tls_mode.len > 0 and !std.mem.eql(u8, st.tls_mode, c.spec.tls.mode)) {
            try st.setCond(a, "Degraded", "True", "TlsModeChanged", try std.fmt.allocPrint(a, "tls.mode was {s}; changing it would orphan every drive", .{st.tls_mode}));
            return;
        }
        st.tls_mode = c.spec.tls.mode;

        const creds_data = try ctl.secretData(a, ns, c.spec.credsSecret) orelse {
            try st.setCond(a, "Available", "False", "MissingCredentials", c.spec.credsSecret);
            return;
        };
        const creds: admin.Creds = .{
            .access = try secretKey(a, creds_data, "accessKey") orelse return error.MissingAccessKey,
            .secret = try secretKey(a, creds_data, "secretKey") orelse return error.MissingSecretKey,
        };

        var ca_pem: ?[]const u8 = null;
        if (std.mem.eql(u8, c.spec.tls.mode, "selfSigned")) {
            ca_pem = try ctl.ensureSelfSigned(a, c);
        } else if (std.mem.eql(u8, c.spec.tls.mode, "certManager")) {
            try ctl.apply(a, try render.certificate(a, c));
            const d = try ctl.secretData(a, ns, try render.tlsSecretName(a, c)) orelse {
                try st.setCond(a, "Available", "False", "WaitingForCertificate", "cert-manager has not issued the certificate yet");
                return;
            };
            ca_pem = try secretKey(a, d, "ca.crt");
        }

        for (try render.services(a, c)) |o| try ctl.apply(a, o);
        const live = try c.livePools(a);
        for (live) |p| {
            try ctl.apply(a, try render.statefulSet(a, c, p));
            if (p.servers > 1) try ctl.apply(a, try render.pdb(a, c, p));
        }
        if (c.spec.ingress.enabled) try ctl.apply(a, try render.ingress(a, c));
        if (c.spec.console.enabled) {
            const objs = try render.consoleObjects(a, c);
            try ctl.apply(a, objs[0]);
            try ctl.apply(a, objs[1]);
            if (c.spec.console.ingress.enabled) try ctl.apply(a, objs[2]);
        }
        try ctl.pruneRetired(a, c, live);

        var ac = try ctl.adminClient(a, c, creds, ca_pem);
        defer ac.deinit();
        const avail = try ctl.rollout(a, c, st, &ac);
        if (!avail) return;

        // Bootstrap again whenever the spec generation moves.
        if (st.bootstrapped_generation != c.generation) {
            ctl.bootstrap(a, c, &ac) catch |e| {
                try st.setCond(a, "Bootstrapped", "False", "BootstrapFailed", @errorName(e));
                return;
            };
            st.bootstrapped_generation = c.generation;
            try st.setCond(a, "Bootstrapped", "True", "Done", "policies, users and buckets applied");
        }
        try ctl.decommission(a, c, st, &ac);
    }

    fn adminClient(ctl: *Controller, a: A, c: Cluster, creds: admin.Creds, ca_pem: ?[]const u8) !admin.Client {
        if (ca_pem) |pem| {
            const f = try std.fmt.allocPrint(a, "{s}/{s}-{s}-ca.crt", .{ ctl.opts.work_dir, c.namespace, c.name });
            try std.fs.cwd().writeFile(.{ .sub_path = f, .data = pem });
            return admin.Client.init(ctl.gpa, creds, f);
        }
        return admin.Client.init(ctl.gpa, creds, null);
    }

    fn serviceUrl(a: A, c: Cluster) ![]u8 {
        return std.fmt.allocPrint(a, "{s}://{s}.{s}.svc.{s}:{d}", .{ c.scheme(), c.name, c.namespace, c.spec.clusterDomain, spec.port });
    }

    /// CA kept in <name>-ca; the server certificate is reissued when its DNS names change.
    fn ensureSelfSigned(ctl: *Controller, a: A, c: Cluster) ![]const u8 {
        const now = std.time.timestamp();
        const ca_name = try std.fmt.allocPrint(a, "{s}-ca", .{c.name});
        var ca_cert: []const u8 = undefined;
        var issuer: tlsgen.Issuer = undefined;
        if (try ctl.secretData(a, c.namespace, ca_name)) |d| {
            ca_cert = try secretKey(a, d, "ca.crt") orelse return error.BadCaSecret;
            issuer = try tlsgen.loadIssuer(a, "zkfsm-ca", try secretKey(a, d, "ca.key") orelse return error.BadCaSecret);
        } else {
            const ca = try tlsgen.issue(a, .{ .cn = "zkfsm-ca", .is_ca = true, .now = now }, null);
            try ctl.apply(a, try render.caSecret(a, c, ca.cert_pem, ca.key_pem));
            ca_cert = ca.cert_pem;
            issuer = try tlsgen.loadIssuer(a, "zkfsm-ca", ca.key_pem);
        }
        const dns = try render.dnsNames(a, c);
        var h = std.hash.Wyhash.init(1);
        for (dns) |d| h.update(d);
        h.update(ca_cert);
        const want = try std.fmt.allocPrint(a, "{x:0>16}", .{h.final()});
        const tls_name = try render.tlsSecretName(a, c);
        if (try ctl.kc.getJson(a, try kube.resPath(a, "v1", c.namespace, "secrets", tls_name))) |s| {
            if (kube.str(s, &.{ "metadata", "annotations", "zkfsm.io/cert-hash" })) |got| {
                if (std.mem.eql(u8, got, want)) return ca_cert;
            }
        }
        const leaf = try tlsgen.issue(a, .{ .cn = c.name, .dns = dns, .ips = &.{.{ 127, 0, 0, 1 }}, .now = now, .days = 825 }, issuer);
        var o = try render.tlsSecret(a, c, leaf.cert_pem, leaf.key_pem, ca_cert);
        try o.body.object.getPtr("metadata").?.object.put("annotations", try jv.v(a, .{ .@"zkfsm.io/cert-hash" = want }));
        try ctl.apply(a, o);
        std.log.info("{s}/{s}: issued server certificate", .{ c.namespace, c.name });
        return ca_cert;
    }

    /// Deletes StatefulSets, PDBs and PVCs of pools that finished decommissioning.
    fn pruneRetired(ctl: *Controller, a: A, c: Cluster, live: []const spec.Pool) !void {
        const sel = try std.fmt.allocPrint(a, "?labelSelector=zkfsm.io%2Fcluster%3D{s}", .{c.name});
        const kinds = [_][3][]const u8{
            .{ "apps/v1", "statefulsets", "" },
            .{ "policy/v1", "poddisruptionbudgets", "" },
            .{ "v1", "persistentvolumeclaims", "" },
        };
        for (kinds) |k| {
            const base = try kube.resPath(a, k[0], c.namespace, k[1], null);
            const list = try ctl.kc.getJson(a, try std.mem.concat(a, u8, &.{ base, sel })) orelse continue;
            for (kube.items(list)) |it| {
                const pool = kube.str(it, &.{ "metadata", "labels", "zkfsm.io/pool" }) orelse continue;
                var keep = false;
                for (live) |p| keep = keep or std.mem.eql(u8, p.name, pool);
                if (keep or c.poolState(pool) != .decommissioned) continue;
                const n = kube.str(it, &.{ "metadata", "name" }) orelse continue;
                std.log.info("{s}/{s}: removing {s} {s} of retired pool {s}", .{ c.namespace, c.name, k[1], n, pool });
                _ = try ctl.kc.delete(a, try kube.resPath(a, k[0], c.namespace, k[1], n));
            }
        }
    }

    /// Returns true once every pod is current and ready and the cluster answers ready.
    fn rollout(ctl: *Controller, a: A, c: Cluster, st: *Status, ac: *admin.Client) !bool {
        const topo = try render.topologyHash(a, c);
        st.topology = topo;
        st.image = c.spec.image;
        const live = try c.livePools(a);
        var outdated: std.ArrayList(Value) = .empty;
        var topo_changed = false;
        var total: u32 = 0;
        var ready_n: u32 = 0;
        for (live) |p| {
            total += p.servers;
            const sts = try ctl.kc.getJson(a, try kube.resPath(a, "apps/v1", c.namespace, "statefulsets", try c.stsName(a, p.name))) orelse continue;
            const rev = kube.str(sts, &.{ "status", "updateRevision" }) orelse "";
            const sel = try std.fmt.allocPrint(a, "?labelSelector=zkfsm.io%2Fcluster%3D{s},zkfsm.io%2Fpool%3D{s}", .{ c.name, p.name });
            const pods = try ctl.kc.getJson(a, try std.mem.concat(a, u8, &.{ try kube.resPath(a, "v1", c.namespace, "pods", null), sel })) orelse continue;
            var pool_ready: u32 = 0;
            for (kube.items(pods)) |pod| {
                if (podReady(pod)) pool_ready += 1;
                const prev = kube.str(pod, &.{ "metadata", "labels", "controller-revision-hash" }) orelse "";
                if (rev.len > 0 and !std.mem.eql(u8, prev, rev) and kube.lookup(pod, &.{ "metadata", "deletionTimestamp" }) == null) {
                    try outdated.append(a, pod);
                    const t = kube.str(pod, &.{ "metadata", "annotations", render.topology_annotation }) orelse "";
                    if (!std.mem.eql(u8, t, topo)) topo_changed = true;
                }
            }
            ready_n += pool_ready;
            try st.setPoolServers(a, p.name, p.servers, pool_ready);
        }
        st.ready_servers = ready_n;
        st.servers = total;

        if (outdated.items.len > 0 and topo_changed) {
            // Every node must start with the same endpoint list: restart together.
            for (outdated.items) |pod| try ctl.deletePod(a, c, pod);
            try st.setCond(a, "Progressing", "True", "TopologyRestart", try std.fmt.allocPrint(a, "restarting {d} pods with the new endpoint list", .{outdated.items.len}));
            try st.setCond(a, "Available", "False", "Restarting", "endpoint list changed");
            return false;
        }
        const cluster_ready = ready_n == total and ac.ready(a, try serviceUrl(a, c));
        if (outdated.items.len > 0) {
            try st.setCond(a, "Progressing", "True", "RollingUpdate", try std.fmt.allocPrint(a, "{d} pods outdated", .{outdated.items.len}));
            // Gate: every pod reports ready (quorum) before the next one goes down.
            // Kubelet's readiness probe is /health/ready (quorum); dialing pods by DNS
            // can hit a stale address and stall in connect, so the service is asked instead.
            if (ready_n == total and cluster_ready) {
                try ctl.deletePod(a, c, pickLast(outdated.items));
            }
            try st.setCond(a, "Available", if (cluster_ready) "True" else "False", if (cluster_ready) "Ready" else "Updating", "rolling update in progress");
            return false;
        }
        if (cluster_ready) {
            try st.setCond(a, "Progressing", "False", "Current", "all pods run the current revision");
            try st.setCond(a, "Available", "True", "Ready", try std.fmt.allocPrint(a, "{d}/{d} servers ready", .{ ready_n, total }));
            try st.setCond(a, "Degraded", "False", "Ready", "");
            return true;
        }
        try st.setCond(a, "Available", "False", "Initializing", try std.fmt.allocPrint(a, "{d}/{d} servers ready", .{ ready_n, total }));
        return false;
    }

    fn deletePod(ctl: *Controller, a: A, c: Cluster, pod: Value) !void {
        const n = kube.str(pod, &.{ "metadata", "name" }) orelse return;
        std.log.info("{s}/{s}: restarting pod {s}", .{ c.namespace, c.name, n });
        const r = try ctl.kc.delete(a, try kube.resPath(a, "v1", c.namespace, "pods", n));
        if (!r.ok() and r.status != 404) return error.DeleteFailed;
    }

    fn bootstrap(ctl: *Controller, a: A, c: Cluster, ac: *admin.Client) !void {
        const base = try serviceUrl(a, c);
        for (c.spec.iam.policies) |p| {
            const r = try ac.addPolicy(a, base, p.name, p.document);
            if (!r.ok()) return logFail("add policy", p.name, r);
        }
        for (c.spec.iam.users) |u| {
            const d = try ctl.secretData(a, c.namespace, u.secretName) orelse return error.MissingUserSecret;
            const ak = try secretKey(a, d, "accessKey") orelse return error.MissingUserSecret;
            const sk = try secretKey(a, d, "secretKey") orelse return error.MissingUserSecret;
            var r = try ac.addUser(a, base, ak, sk);
            if (!r.ok()) return logFail("add user", ak, r);
            if (u.policies.len > 0) {
                r = try ac.setPolicies(a, base, ak, u.policies);
                if (!r.ok()) return logFail("set policy", ak, r);
            }
        }
        for (c.spec.iam.buckets) |b| {
            const r = try ac.makeBucket(a, base, b.name, b.objectLock);
            if (!r.ok()) return logFail("make bucket", b.name, r);
        }
        std.log.info("{s}/{s}: bootstrap applied ({d} policies, {d} users, {d} buckets)", .{ c.namespace, c.name, c.spec.iam.policies.len, c.spec.iam.users.len, c.spec.iam.buckets.len });
    }

    fn decommission(ctl: *Controller, a: A, c: Cluster, st: *Status, ac: *admin.Client) !void {
        _ = ctl;
        const base = try serviceUrl(a, c);
        for (c.spec.pools) |p| {
            if (!p.decommission) continue;
            const ep = try c.poolEndpoint(a, p);
            switch (c.poolState(p.name)) {
                .decommissioned => {},
                .active => {
                    const r = try ac.decommission(a, base, ep);
                    if (r.ok()) {
                        try st.setPoolState(a, p.name, .decommissioning);
                        try st.setCond(a, "Decommissioning", "True", "Started", p.name);
                    } else {
                        try st.setCond(a, "Decommissioning", "False", "AdminApiRefused", try std.fmt.allocPrint(a, "pool {s}: HTTP {d} {s}", .{ p.name, r.status, r.body[0..@min(r.body.len, 200)] }));
                    }
                },
                .decommissioning => {
                    const r = try ac.poolStatus(a, base, ep);
                    const prog = admin.parseDecom(a, r.body) orelse continue;
                    if (prog.complete) {
                        try st.setPoolState(a, p.name, .decommissioned);
                        try st.setCond(a, "Decommissioning", "False", "Complete", p.name);
                    } else if (prog.failed or prog.canceled) {
                        try st.setPoolState(a, p.name, .active);
                        try st.setCond(a, "Decommissioning", "False", if (prog.failed) "Failed" else "Canceled", p.name);
                    }
                },
            }
        }
    }

    fn writeStatus(ctl: *Controller, a: A, ns: []const u8, name: []const u8, obj: Value, st: *Status) !void {
        const body = try st.toJson(a);
        // Skip no-op writes so watchers and etcd stay quiet.
        if (kube.lookup(obj, &.{"status"})) |old| {
            if (std.mem.eql(u8, try jv.stringify(a, old), try jv.stringify(a, body))) return;
        }
        const p = try std.fmt.allocPrint(a, "{s}/status", .{try kube.resPath(a, spec.version, ns, "clusters", name)});
        const r = try ctl.kc.mergePatch(a, p, try jv.stringify(a, try jv.v(a, .{ .status = body })));
        if (!r.ok()) std.log.warn("status {s}/{s}: {d} {s}", .{ ns, name, r.status, r.body[0..@min(r.body.len, 300)] });
    }
};

fn logFail(what: []const u8, name: []const u8, r: admin.Result) error{AdminCallFailed} {
    std.log.warn("{s} {s}: HTTP {d} {s}", .{ what, name, r.status, r.body[0..@min(r.body.len, 300)] });
    return error.AdminCallFailed;
}

fn podReady(pod: Value) bool {
    const conds = kube.lookup(pod, &.{ "status", "conditions" }) orelse return false;
    if (conds != .array) return false;
    for (conds.array.items) |cd| {
        const t = kube.str(cd, &.{"type"}) orelse continue;
        if (std.mem.eql(u8, t, "Ready")) return std.mem.eql(u8, kube.str(cd, &.{"status"}) orelse "", "True");
    }
    return false;
}

/// Highest ordinal first, like a StatefulSet rolling update.
fn pickLast(pods: []const Value) Value {
    var best = pods[0];
    for (pods[1..]) |p| {
        const n = kube.str(p, &.{ "metadata", "name" }) orelse continue;
        const b = kube.str(best, &.{ "metadata", "name" }) orelse "";
        if (ordinal(n) > ordinal(b) or (ordinal(n) == ordinal(b) and std.mem.order(u8, n, b) == .gt)) best = p;
    }
    return best;
}

fn ordinal(name: []const u8) u32 {
    const i = std.mem.lastIndexOfScalar(u8, name, '-') orelse return 0;
    return std.fmt.parseInt(u32, name[i + 1 ..], 10) catch 0;
}

pub const PoolStatus = struct {
    name: []const u8,
    state: spec.PoolState = .active,
    servers: u32 = 0,
    readyServers: u32 = 0,
};

pub const Condition = struct {
    type: []const u8,
    status: []const u8,
    reason: []const u8,
    message: []const u8,
    lastTransitionTime: []const u8,
};

/// Status under construction; starts from the stored one so pool states persist.
pub const Status = struct {
    pools: std.ArrayList(PoolStatus) = .empty,
    conditions: std.ArrayList(Condition) = .empty,
    servers: u32 = 0,
    ready_servers: u32 = 0,
    image: []const u8 = "",
    topology: []const u8 = "",
    observed_generation: i64 = 0,
    bootstrapped_generation: i64 = 0,
    tls_mode: []const u8 = "",

    pub fn fromExisting(a: A, c: Cluster) !Status {
        var st: Status = .{};
        const old = c.status orelse Value.null;
        if (old == .object) {
            st.bootstrapped_generation = kube.int(old, &.{"bootstrappedGeneration"}) orelse 0;
            st.tls_mode = kube.str(old, &.{"tlsMode"}) orelse "";
            if (old.object.get("conditions")) |cs| if (cs == .array) for (cs.array.items) |cd| {
                try st.conditions.append(a, .{
                    .type = kube.str(cd, &.{"type"}) orelse continue,
                    .status = kube.str(cd, &.{"status"}) orelse "Unknown",
                    .reason = kube.str(cd, &.{"reason"}) orelse "",
                    .message = kube.str(cd, &.{"message"}) orelse "",
                    .lastTransitionTime = kube.str(cd, &.{"lastTransitionTime"}) orelse "",
                });
            };
            if (old.object.get("pools")) |ps| if (ps == .array) for (ps.array.items) |p| {
                try st.pools.append(a, .{
                    .name = kube.str(p, &.{"name"}) orelse continue,
                    .state = std.meta.stringToEnum(spec.PoolState, kube.str(p, &.{"state"}) orelse "active") orelse .active,
                    .servers = @intCast(kube.int(p, &.{"servers"}) orelse 0),
                    .readyServers = @intCast(kube.int(p, &.{"readyServers"}) orelse 0),
                });
            };
        }
        for (c.spec.pools) |p| _ = try st.pool(a, p.name);
        return st;
    }

    fn pool(st: *Status, a: A, name: []const u8) !*PoolStatus {
        for (st.pools.items) |*p| if (std.mem.eql(u8, p.name, name)) return p;
        try st.pools.append(a, .{ .name = name });
        return &st.pools.items[st.pools.items.len - 1];
    }

    pub fn setPoolServers(st: *Status, a: A, name: []const u8, servers: u32, ready: u32) !void {
        const p = try st.pool(a, name);
        p.servers = servers;
        p.readyServers = ready;
    }

    pub fn setPoolState(st: *Status, a: A, name: []const u8, s: spec.PoolState) !void {
        (try st.pool(a, name)).state = s;
    }

    /// lastTransitionTime only moves when the status value flips.
    pub fn setCond(st: *Status, a: A, t: []const u8, status: []const u8, reason: []const u8, msg: []const u8) !void {
        const now = try rfc3339(a, std.time.timestamp());
        for (st.conditions.items) |*cd| if (std.mem.eql(u8, cd.type, t)) {
            if (!std.mem.eql(u8, cd.status, status)) cd.lastTransitionTime = now;
            cd.status = status;
            cd.reason = reason;
            cd.message = msg;
            return;
        };
        try st.conditions.append(a, .{ .type = t, .status = status, .reason = reason, .message = msg, .lastTransitionTime = now });
    }

    fn cond(st: *const Status, t: []const u8) ?Condition {
        for (st.conditions.items) |cd| if (std.mem.eql(u8, cd.type, t)) return cd;
        return null;
    }

    pub fn phase(st: *const Status) []const u8 {
        for (st.pools.items) |p| if (p.state == .decommissioning) return "Decommissioning";
        if (st.cond("Progressing")) |p| if (std.mem.eql(u8, p.status, "True")) return "Updating";
        if (st.cond("Available")) |p| if (std.mem.eql(u8, p.status, "True")) return "Ready";
        if (st.cond("Degraded")) |p| if (std.mem.eql(u8, p.status, "True")) return "Degraded";
        return "Initializing";
    }

    pub fn toJson(st: *const Status, a: A) !Value {
        return jv.v(a, .{
            .phase = st.phase(),
            .observedGeneration = st.observed_generation,
            .bootstrappedGeneration = st.bootstrapped_generation,
            .servers = st.servers,
            .readyServers = st.ready_servers,
            .currentImage = st.image,
            .topologyHash = st.topology,
            .tlsMode = st.tls_mode,
            .pools = st.pools.items,
            .conditions = st.conditions.items,
        });
    }
};

fn rfc3339(a: A, t: i64) ![]u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(t) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
}

test "status keeps pool states and condition transitions" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        \\{"metadata":{"name":"s3","namespace":"ns","uid":"u","generation":2},"spec":{"credsSecret":"r","pools":[{"name":"p0","servers":4},{"name":"p1","servers":2,"decommission":true}]},
        \\ "status":{"bootstrappedGeneration":1,"pools":[{"name":"p1","state":"decommissioning"}],"conditions":[{"type":"Available","status":"True","reason":"Ready","message":"","lastTransitionTime":"2020-01-01T00:00:00Z"}]}}
    ;
    const c = try Cluster.parse(a, try std.json.parseFromSliceLeaky(Value, a, text, .{}));
    var st = try Status.fromExisting(a, c);
    try std.testing.expectEqual(@as(usize, 2), st.pools.items.len);
    try std.testing.expectEqualStrings("Decommissioning", st.phase());
    try st.setCond(a, "Available", "True", "Ready", "4/4");
    try std.testing.expectEqualStrings("2020-01-01T00:00:00Z", st.cond("Available").?.lastTransitionTime);
    try st.setCond(a, "Available", "False", "Restarting", "");
    try std.testing.expect(!std.mem.eql(u8, "2020-01-01T00:00:00Z", st.cond("Available").?.lastTransitionTime));
    const s = try jv.stringify(a, try st.toJson(a));
    try std.testing.expect(std.mem.indexOf(u8, s, "\"bootstrappedGeneration\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"state\":\"decommissioning\"") != null);
}

test "rolling order and readiness" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pods = try std.json.parseFromSliceLeaky(Value, a,
        \\[{"metadata":{"name":"s3-p0-2"}},{"metadata":{"name":"s3-p0-10"}},{"metadata":{"name":"s3-p0-1"}}]
    , .{});
    try std.testing.expectEqualStrings("s3-p0-10", kube.str(pickLast(pods.array.items), &.{ "metadata", "name" }).?);
    const pod = try std.json.parseFromSliceLeaky(Value, a, "{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}}", .{});
    try std.testing.expect(podReady(pod));
}
