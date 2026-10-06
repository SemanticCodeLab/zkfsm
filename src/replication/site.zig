//! Site replication: deployments linked as peers replicate every bucket (existence and
//! configuration), IAM changes, and all objects in all directions. Objects ride on the
//! bucket replication engine with one implicit target per peer; buckets and IAM go
//! through queued site jobs that replay changes on each peer with a shared service account.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const client = @import("client.zig");
const queue = @import("queue.zig");
const store = @import("store.zig");
const engine = @import("engine.zig");
const deliver = @import("deliver.zig");

const Allocator = std.mem.Allocator;
const Entry = queue.Entry;
const Outcome = deliver.Outcome;
const ov = object.versioning;

/// Peers talk to each other through the always-available native admin prefix.
pub const peer_prefix = "/zkfsm/admin/v3/site-replication";
pub const svc_access_key = "site-replicator-0";

pub const Peer = struct {
    name: []const u8,
    /// `http(s)://host:port` as given to `mc admin replicate add`.
    endpoint: []const u8,
    deployment_id: []const u8,
};

pub const State = struct {
    enabled: bool = false,
    name: []const u8 = "",
    deployment_id: []const u8 = "",
    svc_access_key: []const u8 = "",
    svc_secret: []const u8 = "",
    /// Every site, this one included.
    peers: []const Peer = &.{},
    updated_ns: i64 = 0,

    pub fn self(st: State) ?Peer {
        for (st.peers) |p| if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) return p;
        return null;
    }

    pub fn peer(st: State, dep: []const u8) ?Peer {
        for (st.peers) |p| if (std.mem.eql(u8, p.deployment_id, dep)) return p;
        return null;
    }
};

/// Wiring set by the embedding binary.
pub const Context = struct {
    iam: ?*iam.Store = null,
};

const state_name = "site-replication";

pub fn load(s: anytype, a: Allocator) store.Error!?State {
    return store.getJson(State, s, a, store.key(.site, state_name));
}

pub fn save(r: *engine.Replicator, st: State) store.Error!void {
    try store.putJson(r.svc.store, r.gpa, store.key(.site, state_name), st);
    r.invalidateSite();
}

/// This deployment's id, created on first use.
pub fn deploymentId(r: *engine.Replicator, a: Allocator) store.Error![]const u8 {
    const k = store.key(.deployment, "deployment-id");
    if (try store.getJson([]const u8, r.svc.store, a, k)) |id| return id;
    var b: [16]u8 = undefined;
    std.crypto.random.bytes(&b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = std.fmt.bytesToHex(b, .lower);
    const id = try std.fmt.allocPrint(a, "{s}-{s}-{s}-{s}-{s}", .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] });
    try store.putJson(r.svc.store, r.gpa, k, id);
    return id;
}

pub fn peerArn(a: Allocator, dep: []const u8, bucket: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(a, "arn:minio:replication::{s}:{s}", .{ dep, bucket });
}

/// Admin/S3 credentials for talking to `p`.
pub fn remoteFor(st: State, p: Peer) client.Remote {
    const u = client.parseUrl(p.endpoint);
    return .{
        .endpoint = if (u) |x| x.endpoint else p.endpoint,
        .secure = if (u) |x| x.secure else false,
        .access_key = st.svc_access_key,
        .secret_key = st.svc_secret,
    };
}

// ---- change capture ----

/// Queues a push of `bucket` (existence and configuration) to every peer.
pub fn bucketChanged(r: *engine.Replicator, bucket: []const u8) void {
    var arena = std.heap.ArenaAllocator.init(r.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const st = (r.siteState(a) catch return) orelse return;
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
        r.enqueue(.{ .op = .bucket, .bucket = bucket, .arn = p.deployment_id }) catch |e|
            std.log.warn("site replication: cannot queue bucket {s}: {t}", .{ bucket, e });
    }
}

/// Queues an IAM admin call for replay on every peer. `plain` is the decrypted body;
/// `sealed` says the original was encrypted and the replay must be too.
pub fn iamChanged(r: *engine.Replicator, method: std.http.Method, path: []const u8, plain: []const u8, sealed: bool) void {
    var arena = std.heap.ArenaAllocator.init(r.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const st = (r.siteState(a) catch return) orelse return;
    const payload = sealPayload(a, st, plain, sealed) catch return;
    var idb: [16]u8 = undefined;
    std.crypto.random.bytes(&idb);
    const id = std.fmt.bytesToHex(idb, .lower);
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
        r.enqueue(.{ .op = .iam, .arn = p.deployment_id, .method = @tagName(method), .path = path, .payload = payload, .sealed = sealed, .id = &id }) catch |e|
            std.log.warn("site replication: cannot queue IAM change {s}: {t}", .{ path, e });
    }
}

/// Base64 of the body; encrypted with the service account secret when sealed.
fn sealPayload(a: Allocator, st: State, plain: []const u8, sealed: bool) (Allocator.Error || admin.sio.Error)![]const u8 {
    const bytes = if (sealed) try admin.sio.encrypt(a, st.svc_secret, plain) else plain;
    const out = try a.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    return std.base64.standard.Encoder.encode(out, bytes);
}

fn unbase64(a: Allocator, s: []const u8) ?[]u8 {
    const n = std.base64.standard.Decoder.calcSizeForSlice(s) catch return null;
    const out = a.alloc(u8, n) catch return null;
    std.base64.standard.Decoder.decode(out, s) catch return null;
    return out;
}

// ---- job processing ----

const max_bucket_attempts = 40;

pub fn process(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, e: Entry) Outcome {
    const st = (r.siteState(a) catch return .retry) orelse return .drop;
    const p = st.peer(e.arn) orelse return .drop;
    const remote = remoteFor(st, p);
    const out = switch (e.op) {
        .bucket => pushBucket(r, hc, a, st, remote, e.bucket) catch .retry,
        .iam => replayIam(hc, a, remote, e),
        else => Outcome.drop,
    };
    if (out == .retry and e.attempts == 0) std.log.warn("site replication: {t} {s}{s} to {s} pending (peer unavailable?)", .{ e.op, e.bucket, e.path, p.name });
    if (out == .retry and e.op == .bucket and e.attempts + 1 >= max_bucket_attempts) return .drop;
    return out;
}

fn replayIam(hc: *std.http.Client, a: Allocator, remote: client.Remote, e: Entry) Outcome {
    const body = unbase64(a, e.payload) orelse return .drop;
    const method = std.meta.stringToEnum(std.http.Method, e.method) orelse return .drop;
    const q = std.mem.indexOfScalar(u8, e.path, '?');
    const op = e.path[0 .. q orelse e.path.len];
    var params: std.ArrayList(client.Param) = .empty;
    if (q) |i| {
        var it = std.mem.splitScalar(u8, e.path[i + 1 ..], '&');
        while (it.next()) |kv| {
            if (kv.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, kv, '=');
            const name = admin.api.formDecode(a, kv[0 .. eq orelse kv.len]) catch return .retry;
            const value = admin.api.formDecode(a, if (eq) |j| kv[j + 1 ..] else "") catch return .retry;
            params.append(a, .{ .name = name orelse return .drop, .value = value orelse return .drop }) catch return .retry;
        }
    }
    const path = std.fmt.allocPrint(a, "/zkfsm/admin/v3{s}", .{op}) catch return .retry;
    const res = client.send(hc, a, remote, .{ .method = method, .path = path, .query = params.items, .body = if (body.len > 0 or method.requestHasBody()) .{ .bytes = body } else .none }) catch return .retry;
    if (res.ok()) return .done;
    if (e.attempts == 0) std.log.warn("site replication: peer answered {s} with {d} {s}", .{ op, res.status, res.code() });
    // The peer already has (or lacks) the entity: replaying again cannot help.
    if (res.status == 404 or res.status == 409 or res.status == 400) {
        std.log.info("site replication: peer refused {s} ({d} {s})", .{ op, res.status, res.code() });
        return .drop;
    }
    return .retry;
}

/// Bucket configuration subresources mirrored to peers, with the root element a
/// valid document must carry (anything else, e.g. a listing, is not synced).
const subresources = [_]struct { name: []const u8, root: []const u8, deletable: bool }{
    .{ .name = "versioning", .root = "<VersioningConfiguration", .deletable = false },
    .{ .name = "object-lock", .root = "<ObjectLockConfiguration", .deletable = false },
    .{ .name = "policy", .root = "{", .deletable = true },
    .{ .name = "lifecycle", .root = "<LifecycleConfiguration", .deletable = true },
    .{ .name = "tagging", .root = "<Tagging", .deletable = true },
    .{ .name = "encryption", .root = "<ServerSideEncryptionConfiguration", .deletable = true },
    .{ .name = "cors", .root = "<CORSConfiguration", .deletable = true },
};

fn pushBucket(r: *engine.Replicator, hc: *std.http.Client, a: Allocator, st: State, remote: client.Remote, bucket: []const u8) client.Error!Outcome {
    const path = try std.fmt.allocPrint(a, "/{s}", .{bucket});
    r.svc.headBucket(bucket) catch |e| {
        if (e != error.NoSuchBucket) return .retry;
        const res = try client.send(hc, a, remote, .{ .method = .DELETE, .path = path });
        if (res.ok() or res.status == 404) return .done;
        return .retry;
    };
    var cfg = ov.getConfig(r.svc, a, bucket) catch return .retry;
    // Replicated buckets are always versioned.
    if (cfg.versioning != .enabled) {
        ov.setVersioning(r.svc, bucket, .enabled) catch return .retry;
        cfg.versioning = .enabled;
    }
    const lock_hdr = [_]client.Header{.{ .name = "x-amz-bucket-object-lock-enabled", .value = "true" }};
    const mk = try client.send(hc, a, remote, .{ .method = .PUT, .path = path, .headers = if (cfg.lock_enabled) &lock_hdr else &.{} });
    if (!mk.ok() and mk.status != 409) return .retry;
    const me = st.self() orelse return .drop;
    const local = remoteFor(st, me);
    for (subresources) |sub| {
        const q = [_]client.Param{.{ .name = sub.name, .value = "" }};
        const got = try client.send(hc, a, local, .{ .method = .GET, .path = path, .query = &q });
        const doc = std.mem.trimLeft(u8, got.body, " \t\r\n");
        const body = if (std.mem.startsWith(u8, doc, "<?xml")) std.mem.trimLeft(u8, doc[(std.mem.indexOf(u8, doc, "?>") orelse 0) + 2 ..], " \t\r\n") else doc;
        if (got.status == 200 and std.mem.startsWith(u8, body, sub.root)) {
            var md5: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(got.body, &md5, .{});
            var b64: [24]u8 = undefined;
            const hs = [_]client.Header{.{ .name = "content-md5", .value = std.base64.standard.Encoder.encode(&b64, &md5) }};
            const put = try client.send(hc, a, remote, .{ .method = .PUT, .path = path, .query = &q, .headers = &hs, .body = .{ .bytes = got.body }, .content_type = if (sub.root[0] == '{') "application/json" else "application/xml" });
            if (!put.ok()) std.log.warn("site replication: {s}?{s} not applied on peer: {d} {s}", .{ bucket, sub.name, put.status, put.code() });
            if (put.status >= 500) return .retry;
        } else if (got.status == 404 and sub.deletable) {
            const del = try client.send(hc, a, remote, .{ .method = .DELETE, .path = path, .query = &q });
            if (del.status >= 500) return .retry;
        } else if (got.status >= 500) return .retry;
    }
    return .done;
}

// ---- joining and leaving ----

pub const JoinRequest = struct {
    svcAcctAccessKey: []const u8,
    svcAcctSecretKey: []const u8,
    svcAcctParent: []const u8 = "",
    peers: []const Peer,
    updatedAt: i64 = 0,
};

pub const JoinError = error{ NoIam, IamFailed, StorageFailed, OutOfMemory, NotAPeer };

/// Applies a join on this deployment: service account, state, versioning on every
/// bucket, then the initial push of buckets, IAM, and existing objects to all peers.
pub fn joinLocal(r: *engine.Replicator, a: Allocator, req: JoinRequest) JoinError!void {
    const st_iam = r.site_ctx.iam orelse return error.NoIam;
    const dep = try deploymentId(r, a);
    var me: ?Peer = null;
    for (req.peers) |p| if (std.mem.eql(u8, p.deployment_id, dep)) {
        me = p;
    };
    const self_peer = me orelse return error.NotAPeer;
    const exists = blk: {
        const v = st_iam.view();
        defer v.release();
        break :blk v.serviceAccount(req.svcAcctAccessKey) != null;
    };
    if (exists) {
        st_iam.updateServiceAccount(req.svcAcctAccessKey, .{ .secret = req.svcAcctSecretKey, .enabled = true }) catch return error.IamFailed;
    } else {
        st_iam.createServiceAccount(.{
            .access_key = req.svcAcctAccessKey,
            .secret = req.svcAcctSecretKey,
            .parent = st_iam.opts.root_access_key,
            .name = "site-replicator",
            .description = "site replication service account",
        }) catch return error.IamFailed;
    }
    const prev = (try r.siteState(a));
    try save(r, .{
        .enabled = true,
        .name = self_peer.name,
        .deployment_id = dep,
        .svc_access_key = req.svcAcctAccessKey,
        .svc_secret = req.svcAcctSecretKey,
        .peers = req.peers,
        .updated_ns = @intCast(std.time.nanoTimestamp()),
    });
    // New peers get everything this site has.
    const buckets = r.svc.listBuckets(a) catch return error.StorageFailed;
    for (buckets) |b| {
        ov.setVersioning(r.svc, b.name, .enabled) catch {};
    }
    const st = (try r.siteState(a)) orelse return;
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, dep)) continue;
        if (prev) |old| if (old.peer(p.deployment_id) != null) continue;
        for (buckets) |b| {
            r.enqueue(.{ .op = .bucket, .bucket = b.name, .arn = p.deployment_id }) catch {};
            const arn = try peerArn(a, p.deployment_id, b.name);
            r.startScan(b.name, arn, "", std.math.maxInt(i64)) catch {};
        }
        const snap = try exportIam(a, st_iam, req.svcAcctAccessKey);
        const payload = sealPayload(a, st, snap, true) catch return error.OutOfMemory;
        r.enqueue(.{ .op = .iam, .arn = p.deployment_id, .method = "PUT", .path = "/site-replication/peer/iam-import", .payload = payload, .sealed = true, .id = "initial" }) catch {};
    }
}

/// Removes peers (by name) from this site's state; `all` or naming this site disables it.
pub fn removeLocal(r: *engine.Replicator, a: Allocator, names: []const []const u8, all: bool) JoinError!void {
    const st = (try r.siteState(a)) orelse return;
    var self_gone = all;
    var keep: std.ArrayList(Peer) = .empty;
    for (st.peers) |p| {
        const gone = for (names) |n| {
            if (std.mem.eql(u8, n, p.name)) break true;
        } else false;
        if (gone and std.mem.eql(u8, p.deployment_id, st.deployment_id)) self_gone = true;
        if (!gone) try keep.append(a, p);
    }
    if (self_gone or keep.items.len <= 1) {
        try save(r, .{ .enabled = false, .deployment_id = st.deployment_id });
        if (r.site_ctx.iam) |s| s.deleteServiceAccount(st.svc_access_key) catch {};
        return;
    }
    var next = st;
    next.peers = keep.items;
    next.updated_ns = @intCast(std.time.nanoTimestamp());
    try save(r, next);
}

pub const IamSnapshot = struct {
    users: []const struct { name: []const u8, secret: []const u8, enabled: bool, policies: []const []const u8 } = &.{},
    groups: []const struct { name: []const u8, enabled: bool, members: []const []const u8, policies: []const []const u8 } = &.{},
    policies: []const struct { name: []const u8, document: []const u8 } = &.{},
    service_accounts: []const iam.store.ServiceAccount = &.{},
};

/// IAM entities as JSON, without the site service account.
pub fn exportIam(a: Allocator, s: *iam.Store, skip_key: []const u8) Allocator.Error![]const u8 {
    const v = s.view();
    defer v.release();
    var sas: std.ArrayList(iam.store.ServiceAccount) = .empty;
    for (v.snap.service_accounts) |sa| if (!std.mem.eql(u8, sa.access_key, skip_key)) try sas.append(a, sa);
    const snap = .{
        .users = v.snap.users,
        .groups = v.snap.groups,
        .policies = v.snap.policies,
        .service_accounts = sas.items,
    };
    return std.json.Stringify.valueAlloc(a, snap, .{}) catch error.OutOfMemory;
}

/// Merges a peer's IAM snapshot: creates what is missing, updates what differs.
pub fn importIam(a: Allocator, s: *iam.Store, doc: []const u8) error{ Malformed, OutOfMemory }!void {
    const snap = std.json.parseFromSliceLeaky(IamSnapshot, a, doc, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e|
        return if (e == error.OutOfMemory) error.OutOfMemory else error.Malformed;
    for (snap.policies) |p| s.putPolicy(p.name, p.document) catch |e| log("policy", p.name, e);
    for (snap.users) |u| {
        s.upsertUser(u.name, u.secret, u.enabled) catch |e| log("user", u.name, e);
        if (u.policies.len > 0) s.setPolicies(.user, u.name, u.policies) catch |e| log("user policy", u.name, e);
    }
    for (snap.groups) |g| {
        if (g.members.len > 0) s.updateGroupMembers(g.name, g.members, false) catch |e| log("group", g.name, e);
        if (g.policies.len > 0) s.setPolicies(.group, g.name, g.policies) catch |e| log("group policy", g.name, e);
        if (!g.enabled) s.setGroupEnabled(g.name, false) catch {};
    }
    for (snap.service_accounts) |sa| {
        s.createServiceAccount(sa) catch |e| switch (e) {
            error.AlreadyExists => s.updateServiceAccount(sa.access_key, .{ .secret = sa.secret, .enabled = sa.enabled }) catch {},
            else => log("service account", sa.access_key, e),
        };
    }
}

fn log(what: []const u8, name: []const u8, e: iam.store.StoreError) void {
    std.log.warn("site replication: IAM import of {s} {s} failed: {t}", .{ what, name, e });
}

// ---- status ----

pub const BucketMeta = struct {
    name: []const u8,
    versioning: []const u8,
    lock: bool,
    policy: []const u8,
    tags: []const u8,
    lifecycle: []const u8,
};

pub const MetaInfo = struct {
    deploymentID: []const u8,
    name: []const u8,
    buckets: []const BucketMeta = &.{},
    users: []const [2][]const u8 = &.{},
    groups: []const [2][]const u8 = &.{},
    policies: []const [2][]const u8 = &.{},
};

fn digest(a: Allocator, bytes: []const u8) Allocator.Error![]const u8 {
    if (bytes.len == 0) return "";
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return a.dupe(u8, std.fmt.bytesToHex(d[0..8].*, .lower)[0..]);
}

/// This site's buckets and IAM entities, reduced to comparable digests.
pub fn metaInfo(r: *engine.Replicator, a: Allocator, st: State) (Allocator.Error || object.Error)!MetaInfo {
    var buckets: std.ArrayList(BucketMeta) = .empty;
    for (try r.svc.listBuckets(a)) |b| {
        const cfg = ov.getConfig(r.svc, a, b.name) catch continue;
        try buckets.append(a, .{
            .name = b.name,
            .versioning = @tagName(cfg.versioning),
            .lock = cfg.lock_enabled,
            .policy = try digest(a, cfg.policy),
            .tags = if (cfg.has_tags) try digest(a, cfg.tags) else "",
            .lifecycle = try digest(a, cfg.lifecycle),
        });
    }
    var info: MetaInfo = .{ .deploymentID = st.deployment_id, .name = st.name, .buckets = buckets.items };
    const s = r.site_ctx.iam orelse return info;
    const v = s.view();
    defer v.release();
    var users: std.ArrayList([2][]const u8) = .empty;
    for (v.snap.users) |u| try users.append(a, .{ try a.dupe(u8, u.name), try digest(a, try std.mem.join(a, ",", u.policies)) });
    var groups: std.ArrayList([2][]const u8) = .empty;
    for (v.snap.groups) |g| try groups.append(a, .{ try a.dupe(u8, g.name), try digest(a, try std.mem.concat(a, u8, &.{ try std.mem.join(a, ",", g.members), "|", try std.mem.join(a, ",", g.policies) })) });
    var pols: std.ArrayList([2][]const u8) = .empty;
    for (v.snap.policies) |p| try pols.append(a, .{ try a.dupe(u8, p.name), try digest(a, p.document) });
    info.users = users.items;
    info.groups = groups.items;
    info.policies = pols.items;
    return info;
}

test "state helpers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const st: State = .{ .enabled = true, .deployment_id = "d1", .svc_access_key = "k", .svc_secret = "s", .peers = &.{
        .{ .name = "a", .endpoint = "http://127.0.0.1:9001", .deployment_id = "d1" },
        .{ .name = "b", .endpoint = "https://h:9002", .deployment_id = "d2" },
    } };
    try std.testing.expectEqualStrings("a", st.self().?.name);
    const rm = remoteFor(st, st.peer("d2").?);
    try std.testing.expect(rm.secure);
    try std.testing.expectEqualStrings("h:9002", rm.endpoint);
    try std.testing.expectEqualStrings("arn:minio:replication::d2:bk", try peerArn(a, "d2", "bk"));
    const p = try sealPayload(a, st, "plain", false);
    try std.testing.expectEqualStrings("plain", unbase64(a, p).?);
}
