//! Admin API for replication: remote bucket targets (`mc admin bucket remote`,
//! `mc replicate add`) and site replication (`mc admin replicate`), plus the
//! peer-to-peer calls sites make to each other. Also captures IAM changes for peers.
const std = @import("std");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const engine = @import("engine.zig");
const targets = @import("targets.zig");
const client = @import("client.zig");
const site = @import("site.zig");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;
const api = admin.api;
const Request = api.Request;
const Response = api.Response;
const Error = api.Error;
const Stringify = std.json.Stringify;

const Ctx = struct {
    r: *engine.Replicator,
    a: Allocator,
    store: *iam.Store,
    req: Request,

    fn param(c: Ctx, name: []const u8) Error!?[]const u8 {
        return api.queryParam(c.a, c.req.target.query, name);
    }

    fn allowed(c: Ctx, action: []const u8) bool {
        const who = c.req.caller;
        var sp: ?iam.Policy = null;
        if (who.session_policy) |doc| sp = iam.policy.parse(c.a, doc) catch return false;
        const id: iam.Identity = .{ .access_key = who.principal, .session_policy = if (sp) |*p| p else null };
        const ctx: iam.Context = .{ .now_s = c.req.now_s };
        return c.store.authorize(id, action, iam.actions.admin_resource, &ctx).allowed();
    }

    fn decrypted(c: Ctx) Error!?[]u8 {
        return admin.sio.decrypt(c.a, c.req.caller.secret, c.req.body) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }

    fn json(c: Ctx, v: anytype) Error!Response {
        return .{ .body = Stringify.valueAlloc(c.a, v, .{}) catch return error.OutOfMemory };
    }
};

fn bad(a: Allocator, code: []const u8, msg: []const u8) Error!Response {
    return api.fail(a, .bad_request, code, msg);
}

fn denied(a: Allocator) Error!Response {
    return api.fail(a, .forbidden, "AccessDenied", "Access Denied.");
}

/// Handles replication admin operations; null when `req` is not one of them.
pub fn handle(r: *engine.Replicator, a: Allocator, store: *iam.Store, req: Request) Error!?Response {
    const c: Ctx = .{ .r = r, .a = a, .store = store, .req = req };
    const routes = .{
        .{ "/set-remote-target", .PUT, "admin:SetBucketTarget", setRemoteTarget },
        .{ "/list-remote-targets", .GET, "admin:GetBucketTarget", listRemoteTargets },
        .{ "/remove-remote-target", .DELETE, "admin:SetBucketTarget", removeRemoteTarget },
        .{ "/site-replication/add", .PUT, "admin:SiteReplicationAdd", siteAdd },
        .{ "/site-replication/info", .GET, "admin:SiteReplicationInfo", siteInfo },
        .{ "/site-replication/status", .GET, "admin:SiteReplicationInfo", siteStatus },
        .{ "/site-replication/remove", .PUT, "admin:SiteReplicationRemove", siteRemove },
        .{ "/site-replication/peer/whoami", .GET, "admin:SiteReplicationAdd", peerWhoami },
        .{ "/site-replication/peer/join", .PUT, "admin:SiteReplicationAdd", peerJoin },
        .{ "/site-replication/peer/remove", .PUT, "admin:SiteReplicationRemove", peerRemove },
        .{ "/site-replication/peer/metainfo", .GET, "admin:SiteReplicationInfo", peerMetaInfo },
        .{ "/site-replication/peer/iam-import", .PUT, "admin:SiteReplicationOperation", peerIamImport },
    };
    inline for (routes) |rt| if (std.mem.eql(u8, req.target.op, rt[0])) {
        if (req.method != rt[1]) return try api.fail(a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
        if (!c.allowed(rt[2])) return try denied(a);
        return try rt[3](c);
    };
    if (std.mem.startsWith(u8, req.target.op, "/site-replication/"))
        return try api.fail(a, .not_implemented, "NotImplemented", "This site replication operation is not supported.");
    return null;
}

// ---- remote targets ----

fn bucketCheck(c: Ctx, bucket: []const u8) Error!?Response {
    c.r.svc.headBucket(bucket) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchBucket => try api.fail(c.a, .not_found, "NoSuchBucket", "The specified bucket does not exist"),
        else => try api.fail(c.a, .internal_server_error, "XMinioInternalError", "bucket lookup failed"),
    };
    return null;
}

fn setRemoteTarget(c: Ctx) Error!Response {
    const bucket = try c.param("bucket") orelse return bad(c.a, "XMinioAdminInvalidArgument", "bucket is required");
    if (try bucketCheck(c, bucket)) |res| return res;
    const plain = try c.decrypted() orelse return bad(c.a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted.");
    var t = targets.parseRequest(c.a, plain) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => bad(c.a, "XMinioAdminConfigBadJSON", "Malformed remote target."),
    };
    t.source_bucket = bucket;
    const cfg = object.versioning.getConfig(c.r.svc, c.a, bucket) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "bucket config unreadable");
    if (cfg.versioning != .enabled) return bad(c.a, "XMinioAdminReplicationSourceNotVersioned", "Replication source bucket does not have versioning enabled.");
    if (try probeRemote(c, t)) |res| return res;
    const view = c.r.view(c.a, bucket) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "replication state unreadable");
    var list: std.ArrayList(targets.Target) = .empty;
    const update = std.mem.eql(u8, (try c.param("update")) orelse "", "true");
    var arn: ?[]const u8 = null;
    for (view.targets) |old| {
        const same = if (update) std.mem.eql(u8, old.arn, t.arn) else std.mem.eql(u8, old.endpoint, t.endpoint) and std.mem.eql(u8, old.target_bucket, t.target_bucket);
        if (same and arn == null) {
            arn = old.arn;
            var n = t;
            n.arn = old.arn;
            if (n.access_key.len == 0) {
                n.access_key = old.access_key;
                n.secret_key = old.secret_key;
            }
            try list.append(c.a, n);
        } else try list.append(c.a, old);
    }
    if (arn == null) {
        if (update) return api.fail(c.a, .not_found, "XMinioAdminRemoteTargetNotFoundError", "The remote target does not exist.");
        t.arn = try targets.newArn(c.a, t.region, t.target_bucket);
        arn = t.arn;
        try list.append(c.a, t);
    }
    c.r.putTargets(bucket, list.items) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "cannot save remote targets");
    return c.json(arn.?);
}

/// Target bucket must exist and be versioned; returns an error response otherwise.
fn probeRemote(c: Ctx, t: targets.Target) Error!?Response {
    if (t.access_key.len == 0) return try bad(c.a, "XMinioAdminInvalidArgument", "Remote target credentials are required.");
    var hc: std.http.Client = .{ .allocator = c.r.gpa };
    defer hc.deinit();
    const path = try std.fmt.allocPrint(c.a, "/{s}", .{t.target_bucket});
    const q = [_]client.Param{.{ .name = "versioning", .value = "" }};
    const res = client.send(&hc, c.a, t.remote(), .{ .method = .GET, .path = path, .query = &q }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => try bad(c.a, "XMinioAdminReplicationRemoteConnectionError", "Remote service endpoint is offline or unreachable."),
    };
    if (res.status == 404) return try api.fail(c.a, .not_found, "XMinioAdminRemoteTargetNotFoundError", "The remote target bucket does not exist.");
    if (res.status == 403) return try bad(c.a, "XMinioAdminReplicationRemoteConnectionError", "Remote target credentials were rejected.");
    if (!res.ok()) return try bad(c.a, "XMinioAdminReplicationRemoteConnectionError", "Remote target is not usable.");
    if (std.mem.indexOf(u8, res.body, "<Status>Enabled</Status>") == null)
        return try bad(c.a, "XMinioAdminRemoteTargetNotVersionedError", "Remote target bucket does not have versioning enabled.");
    return null;
}

fn listRemoteTargets(c: Ctx) Error!Response {
    const only = try c.param("bucket") orelse "";
    var out: std.Io.Writer.Allocating = .init(c.a);
    var w: Stringify = .{ .writer = &out.writer };
    w.beginArray() catch return error.OutOfMemory;
    const buckets = if (only.len > 0) blk: {
        if (try bucketCheck(c, only)) |res| return res;
        break :blk &[_]object.BucketInfo{.{ .name = only, .created_ns = 0 }};
    } else c.r.svc.listBuckets(c.a) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "bucket listing failed");
    for (buckets) |b| {
        const view = c.r.view(c.a, b.name) catch continue;
        for (view.targets) |t| {
            const s = c.r.stats.snapshot(t.arn);
            const h: targets.Health = if (s) |x| .{
                .online = x.online,
                .last_online_ns = x.last_online_ns,
                .offline_count = x.offline_count,
                .downtime_ns = x.downtime_ns,
                .latency_ns = x.latency_ns,
            } else .{ .online = true };
            targets.writeJson(&w, t, h) catch return error.OutOfMemory;
        }
    }
    w.endArray() catch return error.OutOfMemory;
    return .{ .body = out.written() };
}

fn removeRemoteTarget(c: Ctx) Error!Response {
    const bucket = try c.param("bucket") orelse return bad(c.a, "XMinioAdminInvalidArgument", "bucket is required");
    const arn = try c.param("arn") orelse return bad(c.a, "XMinioAdminInvalidArgument", "arn is required");
    if (try bucketCheck(c, bucket)) |res| return res;
    const view = c.r.view(c.a, bucket) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "replication state unreadable");
    if (view.cfg) |cfg| for (cfg.rules) |rule| if (std.mem.eql(u8, rule.dest, arn))
        return bad(c.a, "XMinioAdminReplicationRemoteTargetInUse", "A replication rule still uses this remote target.");
    var list: std.ArrayList(targets.Target) = .empty;
    var found = false;
    for (view.targets) |t| {
        if (std.mem.eql(u8, t.arn, arn)) found = true else try list.append(c.a, t);
    }
    if (!found) return api.fail(c.a, .not_found, "XMinioAdminRemoteTargetNotFoundError", "The remote target does not exist.");
    c.r.putTargets(bucket, list.items) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "cannot save remote targets");
    return .{ .status = .no_content };
}

// ---- site replication ----

const add_ok = "Requested sites were configured for replication successfully.";
const remove_ok = "Requested site(s) were removed from cluster replication successfully.";

fn addFailed(c: Ctx, detail: []const u8) Error!Response {
    return c.json(.{ .success = false, .status = "Some sites could not be configured for replication.", .errorDetail = detail });
}

const PeerSite = struct { name: []const u8 = "", endpoints: []const u8 = "", accessKey: []const u8 = "", secretKey: []const u8 = "" };

fn siteAdd(c: Ctx) Error!Response {
    const plain = try c.decrypted() orelse return bad(c.a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted.");
    const sites = std.json.parseFromSliceLeaky([]const PeerSite, c.a, plain, .{ .ignore_unknown_fields = true }) catch
        return bad(c.a, "XMinioAdminConfigBadJSON", "Malformed site list.");
    if (sites.len < 1) return bad(c.a, "XMinioAdminInvalidArgument", "At least two sites are needed.");
    const self_dep = site.deploymentId(c.r, c.a) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "deployment id unavailable");
    const cur = try c.r.siteState(c.a);
    var hc: std.http.Client = .{ .allocator = c.r.gpa };
    defer hc.deinit();

    // Identify every site by deployment id, with the credentials given for it.
    var peers: std.ArrayList(site.Peer) = .empty;
    var creds: std.ArrayList(client.Remote) = .empty;
    if (cur) |st| for (st.peers) |p| {
        try peers.append(c.a, p);
        try creds.append(c.a, site.remoteFor(st, p));
    };
    var has_self = false;
    for (sites) |s| {
        const u = client.parseUrl(s.endpoints) orelse return addFailed(c, try std.fmt.allocPrint(c.a, "invalid endpoint {s}", .{s.endpoints}));
        const remote: client.Remote = .{ .endpoint = u.endpoint, .secure = u.secure, .access_key = s.accessKey, .secret_key = s.secretKey };
        const res = client.send(&hc, c.a, remote, .{ .method = .GET, .path = site.peer_prefix ++ "/peer/whoami" }) catch
            return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} ({s}) is unreachable", .{ s.name, s.endpoints }));
        if (!res.ok()) return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} refused the request: {d} {s}", .{ s.name, res.status, res.code() }));
        const who = std.json.parseFromSliceLeaky(struct { deploymentID: []const u8, enabled: bool = false }, c.a, res.body, .{ .ignore_unknown_fields = true }) catch
            return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} is not a zkfsm deployment", .{s.name}));
        if (std.mem.eql(u8, who.deploymentID, self_dep)) has_self = true;
        const p: site.Peer = .{ .name = s.name, .endpoint = s.endpoints, .deployment_id = who.deploymentID };
        const known = for (peers.items, 0..) |q, i| {
            if (std.mem.eql(u8, q.deployment_id, p.deployment_id)) break i;
        } else null;
        if (known) |i| {
            peers.items[i] = p;
            creds.items[i] = remote;
        } else {
            if (who.enabled) return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} is already replicating with other sites", .{s.name}));
            try peers.append(c.a, p);
            try creds.append(c.a, remote);
        }
    }
    if (!has_self) return addFailed(c, "the site receiving the request must be one of the sites");
    if (peers.items.len < 2) return addFailed(c, "at least two distinct sites are needed");
    var secret: [40]u8 = undefined;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (&secret) |*ch| ch.* = alphabet[std.crypto.random.uintLessThan(usize, alphabet.len)];
    const join: site.JoinRequest = .{
        .svcAcctAccessKey = if (cur) |st| st.svc_access_key else site.svc_access_key,
        .svcAcctSecretKey = if (cur) |st| st.svc_secret else &secret,
        .peers = peers.items,
        .updatedAt = std.time.timestamp(),
    };
    const doc = Stringify.valueAlloc(c.a, join, .{}) catch return error.OutOfMemory;
    for (peers.items, creds.items) |p, remote| {
        if (std.mem.eql(u8, p.deployment_id, self_dep)) continue;
        const body = admin.sio.encrypt(c.a, remote.secret_key, doc) catch return error.OutOfMemory;
        const res = client.send(&hc, c.a, remote, .{ .method = .PUT, .path = site.peer_prefix ++ "/peer/join", .body = .{ .bytes = body } }) catch
            return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} became unreachable during join", .{p.name}));
        if (!res.ok()) return addFailed(c, try std.fmt.allocPrint(c.a, "site {s} could not join: {s}", .{ p.name, res.body }));
    }
    site.joinLocal(c.r, c.a, join) catch |e| return addFailed(c, try std.fmt.allocPrint(c.a, "local join failed: {t}", .{e}));
    return c.json(.{ .success = true, .status = add_ok });
}

fn peerWhoami(c: Ctx) Error!Response {
    const dep = site.deploymentId(c.r, c.a) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "deployment id unavailable");
    const st = try c.r.siteState(c.a);
    return c.json(.{ .deploymentID = dep, .enabled = st != null, .name = if (st) |s| s.name else "" });
}

fn peerJoin(c: Ctx) Error!Response {
    const plain = try c.decrypted() orelse return bad(c.a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted.");
    const req = std.json.parseFromSliceLeaky(site.JoinRequest, c.a, plain, .{ .ignore_unknown_fields = true }) catch
        return bad(c.a, "XMinioAdminConfigBadJSON", "Malformed join request.");
    site.joinLocal(c.r, c.a, req) catch |e| return api.fail(c.a, .internal_server_error, "XMinioSiteReplicationJoinFailed", @errorName(e));
    return .{};
}

fn siteInfo(c: Ctx) Error!Response {
    const st = try c.r.siteState(c.a) orelse return c.json(.{ .enabled = false, .apiVersion = "1" });
    var out: std.Io.Writer.Allocating = .init(c.a);
    var w: Stringify = .{ .writer = &out.writer };
    writeInfo(&w, st) catch return error.OutOfMemory;
    return .{ .body = out.written() };
}

fn writePeer(w: *Stringify, p: site.Peer) std.Io.Writer.Error!void {
    try w.write(.{
        .endpoint = p.endpoint,
        .name = p.name,
        .deploymentID = p.deployment_id,
        .sync = "disable",
        .defaultbandwidth = .{ .bandwidthLimitPerBucket = 0, .set = false },
        .@"replicate-ilm-expiry" = false,
        .apiVersion = "1",
    });
}

fn writeInfo(w: *Stringify, st: site.State) std.Io.Writer.Error!void {
    try w.beginObject();
    try w.objectField("enabled");
    try w.write(true);
    try w.objectField("name");
    try w.write(st.name);
    try w.objectField("sites");
    try w.beginArray();
    for (st.peers) |p| try writePeer(w, p);
    try w.endArray();
    try w.objectField("serviceAccountAccessKey");
    try w.write(st.svc_access_key);
    try w.objectField("apiVersion");
    try w.write("1");
    try w.endObject();
}

const RemoveReq = struct { requestingDepID: []const u8 = "", sites: []const []const u8 = &.{}, all: bool = false };

fn siteRemove(c: Ctx) Error!Response {
    const body = if (admin.sio.isEncrypted(c.req.body)) try c.decrypted() orelse return bad(c.a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted.") else c.req.body;
    const req = std.json.parseFromSliceLeaky(RemoveReq, c.a, body, .{ .ignore_unknown_fields = true }) catch
        return bad(c.a, "XMinioAdminConfigBadJSON", "Malformed remove request.");
    const st = try c.r.siteState(c.a) orelse return bad(c.a, "XMinioSiteReplicationNotEnabled", "Site replication is not enabled.");
    var hc: std.http.Client = .{ .allocator = c.r.gpa };
    defer hc.deinit();
    var detail: std.ArrayList(u8) = .empty;
    var removed: std.ArrayList([]const u8) = .empty;
    for (st.peers) |p| {
        const gone = req.all or for (req.sites) |n| {
            if (std.mem.eql(u8, n, p.name)) break true;
        } else false;
        if (gone) try removed.append(c.a, p.name);
    }
    if (removed.items.len == 0) return bad(c.a, "XMinioAdminInvalidArgument", "None of the named sites take part in site replication.");
    const doc = Stringify.valueAlloc(c.a, RemoveReq{ .requestingDepID = st.deployment_id, .sites = removed.items, .all = req.all }, .{}) catch return error.OutOfMemory;
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) continue;
        const res = client.send(&hc, c.a, site.remoteFor(st, p), .{ .method = .PUT, .path = site.peer_prefix ++ "/peer/remove", .body = .{ .bytes = doc } }) catch {
            try detail.print(c.a, "site {s} unreachable; ", .{p.name});
            continue;
        };
        if (!res.ok()) try detail.print(c.a, "site {s}: {d} {s}; ", .{ p.name, res.status, res.code() });
    }
    site.removeLocal(c.r, c.a, removed.items, req.all) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "cannot update site replication state");
    if (detail.items.len > 0) return c.json(.{ .status = "Some site(s) could not be removed from cluster replication configuration.", .errorDetail = detail.items, .apiVersion = "1" });
    return c.json(.{ .status = remove_ok, .apiVersion = "1" });
}

fn peerRemove(c: Ctx) Error!Response {
    const req = std.json.parseFromSliceLeaky(RemoveReq, c.a, c.req.body, .{ .ignore_unknown_fields = true }) catch
        return bad(c.a, "XMinioAdminConfigBadJSON", "Malformed remove request.");
    site.removeLocal(c.r, c.a, req.sites, req.all) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "cannot update site replication state");
    return c.json(.{ .status = remove_ok, .apiVersion = "1" });
}

fn peerMetaInfo(c: Ctx) Error!Response {
    const st = try c.r.siteState(c.a) orelse return bad(c.a, "XMinioSiteReplicationNotEnabled", "Site replication is not enabled.");
    const info = site.metaInfo(c.r, c.a, st) catch return api.fail(c.a, .internal_server_error, "XMinioInternalError", "metadata unavailable");
    return c.json(info);
}

fn peerIamImport(c: Ctx) Error!Response {
    const plain = try c.decrypted() orelse return bad(c.a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted.");
    site.importIam(c.a, c.store, plain) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => bad(c.a, "XMinioAdminConfigBadJSON", "Malformed IAM snapshot."),
    };
    return .{};
}

/// One site's view, gathered locally or from the peer.
const SiteView = struct { peer: site.Peer, info: ?site.MetaInfo };

fn siteStatus(c: Ctx) Error!Response {
    const st = try c.r.siteState(c.a) orelse return c.json(.{ .Enabled = false, .apiVersion = "1" });
    var hc: std.http.Client = .{ .allocator = c.r.gpa };
    defer hc.deinit();
    var views: std.ArrayList(SiteView) = .empty;
    for (st.peers) |p| {
        if (std.mem.eql(u8, p.deployment_id, st.deployment_id)) {
            try views.append(c.a, .{ .peer = p, .info = site.metaInfo(c.r, c.a, st) catch null });
            continue;
        }
        const res = client.send(&hc, c.a, site.remoteFor(st, p), .{ .method = .GET, .path = site.peer_prefix ++ "/peer/metainfo" }) catch null;
        const info: ?site.MetaInfo = if (res) |x| (if (x.ok()) std.json.parseFromSliceLeaky(site.MetaInfo, c.a, x.body, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null else null) else null;
        try views.append(c.a, .{ .peer = p, .info = info });
    }
    var out: std.Io.Writer.Allocating = .init(c.a);
    var w: Stringify = .{ .writer = &out.writer, .options = .{} };
    writeStatus(c, &w, views.items) catch return error.OutOfMemory;
    return .{ .body = out.written() };
}

fn findBucket(info: site.MetaInfo, name: []const u8) ?site.BucketMeta {
    for (info.buckets) |b| if (std.mem.eql(u8, b.name, name)) return b;
    return null;
}

fn findPair(list: []const [2][]const u8, name: []const u8) ?[]const u8 {
    for (list) |p| if (std.mem.eql(u8, p[0], name)) return p[1];
    return null;
}

/// Union of names across sites for one entity kind.
fn names(a: Allocator, views: []const SiteView, comptime field: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (views) |v| if (v.info) |info| for (@field(info, field)) |e| {
        const n = if (@TypeOf(e) == site.BucketMeta) e.name else e[0];
        for (out.items) |x| {
            if (std.mem.eql(u8, x, n)) break;
        } else try out.append(a, n);
    };
    return out.items;
}

fn writeStatus(c: Ctx, w: *Stringify, views: []const SiteView) std.Io.Writer.Error!void {
    const a = c.a;
    const bucket_names = names(a, views, "buckets") catch return error.WriteFailed;
    const user_names = names(a, views, "users") catch return error.WriteFailed;
    const group_names = names(a, views, "groups") catch return error.WriteFailed;
    const policy_names = names(a, views, "policies") catch return error.WriteFailed;
    try w.beginObject();
    try w.objectField("Enabled");
    try w.write(true);
    var max_b: usize = 0;
    var max_u: usize = 0;
    var max_g: usize = 0;
    var max_p: usize = 0;
    for (views) |v| if (v.info) |i| {
        max_b = @max(max_b, i.buckets.len);
        max_u = @max(max_u, i.users.len);
        max_g = @max(max_g, i.groups.len);
        max_p = @max(max_p, i.policies.len);
    };
    try w.objectField("MaxBuckets");
    try w.write(max_b);
    try w.objectField("MaxUsers");
    try w.write(max_u);
    try w.objectField("MaxGroups");
    try w.write(max_g);
    try w.objectField("MaxPolicies");
    try w.write(max_p);
    try w.objectField("Sites");
    try w.beginObject();
    for (views) |v| {
        try w.objectField(v.peer.deployment_id);
        try writePeer(w, v.peer);
    }
    try w.endObject();

    // Per site: totals, and how many entities match on every reachable site.
    try w.objectField("StatsSummary");
    try w.beginObject();
    for (views) |v| {
        const info = v.info orelse continue;
        var rb: usize = 0;
        var rt: usize = 0;
        var rp: usize = 0;
        var rv: usize = 0;
        var rl: usize = 0;
        var tags: usize = 0;
        var pols: usize = 0;
        var locks: usize = 0;
        for (info.buckets) |b| {
            if (b.tags.len > 0) tags += 1;
            if (b.policy.len > 0) pols += 1;
            if (b.lock) locks += 1;
            var everywhere = true;
            var same_tags = true;
            var same_pol = true;
            var same_ver = true;
            var same_lock = true;
            for (views) |o| {
                const oi = o.info orelse continue;
                const ob = findBucket(oi, b.name) orelse {
                    everywhere = false;
                    continue;
                };
                same_tags = same_tags and std.mem.eql(u8, ob.tags, b.tags);
                same_pol = same_pol and std.mem.eql(u8, ob.policy, b.policy);
                same_ver = same_ver and std.mem.eql(u8, ob.versioning, b.versioning);
                same_lock = same_lock and ob.lock == b.lock;
            }
            if (!everywhere) continue;
            rb += 1;
            if (same_tags and b.tags.len > 0) rt += 1;
            if (same_pol and b.policy.len > 0) rp += 1;
            if (same_ver) rv += 1;
            if (same_lock and b.lock) rl += 1;
        }
        try w.objectField(info.deploymentID);
        try w.write(.{
            .ReplicatedBuckets = rb,
            .ReplicatedTags = rt,
            .ReplicatedBucketPolicies = rp,
            .ReplicatedIAMPolicies = countSame(views, info.policies, "policies"),
            .ReplicatedUsers = countSame(views, info.users, "users"),
            .ReplicatedGroups = countSame(views, info.groups, "groups"),
            .ReplicatedLockConfig = rl,
            .ReplicatedSSEConfig = 0,
            .ReplicatedVersioningConfig = rv,
            .ReplicatedQuotaConfig = 0,
            .ReplicatedUserPolicyMappings = countSame(views, info.users, "users"),
            .ReplicatedGroupPolicyMappings = countSame(views, info.groups, "groups"),
            .ReplicatedILMExpiryRules = 0,
            .ReplicatedCorsConfig = 0,
            .TotalBucketsCount = info.buckets.len,
            .TotalTagsCount = tags,
            .TotalBucketPoliciesCount = pols,
            .TotalIAMPoliciesCount = info.policies.len,
            .TotalLockConfigCount = locks,
            .TotalSSEConfigCount = 0,
            .TotalVersioningConfigCount = info.buckets.len,
            .TotalQuotaConfigCount = 0,
            .TotalUsersCount = info.users.len,
            .TotalGroupsCount = info.groups.len,
            .TotalUserPolicyMappingCount = info.users.len,
            .TotalGroupPolicyMappingCount = info.groups.len,
            .TotalILMExpiryRulesCount = 0,
            .TotalCorsConfigCount = 0,
            .APIVersion = "1",
        });
    }
    try w.endObject();

    // Only mismatches are listed per entity, as the reference implementation does.
    try w.objectField("BucketStats");
    try w.beginObject();
    for (bucket_names) |bn| {
        var first: ?site.BucketMeta = null;
        var mismatch = false;
        for (views) |v| {
            const i = v.info orelse continue;
            const b = findBucket(i, bn) orelse {
                mismatch = true;
                continue;
            };
            if (first) |f| {
                if (!std.mem.eql(u8, f.tags, b.tags) or !std.mem.eql(u8, f.policy, b.policy) or !std.mem.eql(u8, f.versioning, b.versioning) or f.lock != b.lock) mismatch = true;
            } else first = b;
        }
        if (!mismatch) continue;
        try w.objectField(bn);
        try w.beginObject();
        for (views) |v| {
            const i = v.info orelse continue;
            const b = findBucket(i, bn);
            const f = first.?;
            try w.objectField(i.deploymentID);
            try w.write(.{
                .DeploymentID = i.deploymentID,
                .HasBucket = b != null,
                .BucketMarkedDeleted = false,
                .TagMismatch = if (b) |x| !std.mem.eql(u8, x.tags, f.tags) else false,
                .VersioningConfigMismatch = if (b) |x| !std.mem.eql(u8, x.versioning, f.versioning) else false,
                .OLockConfigMismatch = if (b) |x| x.lock != f.lock else false,
                .PolicyMismatch = if (b) |x| !std.mem.eql(u8, x.policy, f.policy) else false,
                .SSEConfigMismatch = false,
                .ReplicationCfgMismatch = false,
                .QuotaCfgMismatch = false,
                .CorsCfgMismatch = false,
                .HasTagsSet = if (b) |x| x.tags.len > 0 else false,
                .HasOLockConfigSet = if (b) |x| x.lock else false,
                .HasPolicySet = if (b) |x| x.policy.len > 0 else false,
                .HasSSECfgSet = false,
                .HasReplicationCfg = true,
                .HasQuotaCfgSet = false,
                .HasCorsCfgSet = false,
                .APIVersion = "1",
            });
        }
        try w.endObject();
    }
    try w.endObject();
    try entityStats(w, views, policy_names, "policies", "PolicyStats");
    try entityStats(w, views, user_names, "users", "UserStats");
    try entityStats(w, views, group_names, "groups", "GroupStats");

    try w.objectField("Metrics");
    try w.beginObject();
    try w.objectField("activeWorkers");
    try w.write(.{ .curr = c.r.opts.workers, .avg = c.r.opts.workers, .max = c.r.opts.workers });
    c.r.stats.mutex.lock();
    const recv_n = c.r.stats.received_count;
    const recv_b = c.r.stats.received_bytes;
    const queued = c.r.stats.queued;
    const retries = c.r.stats.retries;
    c.r.stats.mutex.unlock();
    try w.objectField("replicaSize");
    try w.write(recv_b);
    try w.objectField("replicaCount");
    try w.write(recv_n);
    try w.objectField("queued");
    try w.write(.{ .curr = .{ .count = queued, .bytes = 0 }, .avg = .{ .count = queued, .bytes = 0 }, .peak = .{ .count = queued, .bytes = 0 } });
    try w.objectField("uptime");
    try w.write(@divTrunc(std.time.nanoTimestamp() - c.r.stats.started_ns, std.time.ns_per_s));
    try w.objectField("retries");
    try w.write(.{ .last1hr = 0, .last1m = 0, .total = retries });
    try w.objectField("errors");
    try w.write(.{ .last1hr = 0, .last1m = 0, .total = retries });
    try w.endObject();
    // Not part of the reference shape; clients ignore it.
    try w.objectField("PeerOnline");
    try w.beginObject();
    for (views) |v| {
        try w.objectField(v.peer.name);
        try w.write(v.info != null);
    }
    try w.endObject();
    try w.objectField("apiVersion");
    try w.write("1");
    try w.endObject();
}

fn countSame(views: []const SiteView, mine: []const [2][]const u8, comptime field: []const u8) usize {
    var n: usize = 0;
    for (mine) |e| {
        const all = for (views) |v| {
            const i = v.info orelse continue;
            const d = findPair(@field(i, field), e[0]) orelse break false;
            if (!std.mem.eql(u8, d, e[1])) break false;
        } else true;
        if (all) n += 1;
    }
    return n;
}

fn entityStats(w: *Stringify, views: []const SiteView, list: []const []const u8, comptime field: []const u8, title: []const u8) std.Io.Writer.Error!void {
    try w.objectField(title);
    try w.beginObject();
    for (list) |n| {
        var first: ?[]const u8 = null;
        var mismatch = false;
        for (views) |v| {
            const i = v.info orelse continue;
            const d = findPair(@field(i, field), n) orelse {
                mismatch = true;
                continue;
            };
            if (first) |f| {
                if (!std.mem.eql(u8, f, d)) mismatch = true;
            } else first = d;
        }
        if (!mismatch) continue;
        try w.objectField(n);
        try w.beginObject();
        for (views) |v| {
            const i = v.info orelse continue;
            const d = findPair(@field(i, field), n);
            try w.objectField(i.deploymentID);
            const pm = if (d) |x| (if (first) |f| !std.mem.eql(u8, x, f) else false) else false;
            if (comptime std.mem.eql(u8, field, "policies")) {
                try w.write(.{ .DeploymentID = i.deploymentID, .PolicyMismatch = pm, .HasPolicy = d != null, .APIVersion = "1" });
            } else if (comptime std.mem.eql(u8, field, "users")) {
                try w.write(.{ .DeploymentID = i.deploymentID, .PolicyMismatch = pm, .UserInfoMismatch = false, .HasUser = d != null, .HasPolicyMapping = d != null, .APIVersion = "1" });
            } else {
                try w.write(.{ .DeploymentID = i.deploymentID, .PolicyMismatch = pm, .HasGroup = d != null, .GroupDescMismatch = false, .HasPolicyMapping = d != null, .APIVersion = "1" });
            }
        }
        try w.endObject();
    }
    try w.endObject();
}

// ---- IAM change capture ----

const iam_mutations = [_][]const u8{
    "/add-user",                  "/remove-user",              "/set-user-status",
    "/add-canned-policy",         "/remove-canned-policy",     "/idp/builtin/policy/attach",
    "/idp/builtin/policy/detach", "/set-user-or-group-policy", "/update-group-members",
    "/set-group-status",          "/add-service-account",      "/update-service-account",
    "/delete-service-account",
};

/// After a successful IAM admin call, queues its replay on every peer. Calls made by
/// peers themselves (the site service account) are not sent on again.
pub fn observe(r: *engine.Replicator, a: Allocator, req: Request, res: Response) void {
    const code = @intFromEnum(res.status);
    if (code < 200 or code >= 300) return;
    const op = req.target.op;
    const known = for (iam_mutations) |m| {
        if (std.mem.eql(u8, m, op)) break true;
    } else false;
    if (!known) return;
    const st = (r.siteState(a) catch return) orelse return;
    if (std.mem.eql(u8, req.caller.access_key, st.svc_access_key)) return;
    const sealed = req.body.len > 0 and admin.sio.isEncrypted(req.body);
    var plain: []const u8 = if (sealed) admin.sio.decrypt(a, req.caller.secret, req.body) catch return else req.body;
    if (std.mem.eql(u8, op, "/add-service-account")) plain = withCredentials(a, req, res, plain, if (r.site_ctx.iam) |s| s.opts.root_access_key else "") orelse return;
    const path = if (req.target.query.len > 0) std.fmt.allocPrint(a, "{s}?{s}", .{ op, req.target.query }) catch return else op;
    site.iamChanged(r, req.method, path, plain, sealed);
}

/// The replayed request carries the generated keys so every site has the same account.
fn withCredentials(a: Allocator, req: Request, res: Response, plain: []const u8, root: []const u8) ?[]const u8 {
    const out = admin.sio.decrypt(a, req.caller.secret, res.body) catch return null;
    const Creds = struct { credentials: struct { accessKey: []const u8, secretKey: []const u8 } };
    const creds = std.json.parseFromSliceLeaky(Creds, a, out, .{ .ignore_unknown_fields = true }) catch return null;
    var v = std.json.parseFromSliceLeaky(std.json.Value, a, plain, .{}) catch return null;
    if (v != .object) return null;
    v.object.put("accessKey", .{ .string = creds.credentials.accessKey }) catch return null;
    v.object.put("secretKey", .{ .string = creds.credentials.secretKey }) catch return null;
    const target = v.object.get("targetUser");
    const has_target = target != null and target.? == .string and target.?.string.len > 0;
    // Accounts the caller made for itself belong to the same user on every site.
    if (!has_target and !std.mem.eql(u8, req.caller.principal, root))
        v.object.put("targetUser", .{ .string = req.caller.principal }) catch return null;
    return Stringify.valueAlloc(a, v, .{}) catch null;
}

test "route table compiles" {
    _ = &handle;
    _ = config;
}
