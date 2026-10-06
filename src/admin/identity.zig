//! Admin API for external identity, quotas, and tenants: MinIO-compatible
//! `idp-config`, LDAP policy mappings, and bucket quotas, plus native tenant routes.
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const api = @import("api.zig");

const Allocator = std.mem.Allocator;
const Ctx = api.Ctx;
const Response = api.Response;
const Error = api.Error;
const idp = iam.idp;

const config_update = "admin:ConfigUpdate";
const set_quota = "admin:SetBucketQuota";
const get_quota = "admin:GetBucketQuota";
const tenant_admin = "admin:TenantAdmin";

/// Handles operations this module owns; null leaves the request to the caller.
pub fn route(c: *const Ctx) Error!?Response {
    const op = c.req.target.op;
    const m = c.req.method;
    const idp_prefix = "/idp-config/";
    if (std.mem.startsWith(u8, op, idp_prefix)) return try idpConfig(c, op[idp_prefix.len..]);
    const routes = .{
        .{ "/idp/ldap/policy/attach", std.http.Method.POST, ldapAttach },
        .{ "/idp/ldap/policy/detach", std.http.Method.POST, ldapDetach },
        .{ "/idp/ldap/policy-entities", std.http.Method.GET, ldapEntities },
        .{ "/set-bucket-quota", std.http.Method.PUT, setBucketQuota },
        .{ "/get-bucket-quota", std.http.Method.GET, getBucketQuota },
        .{ "/tenant/add", std.http.Method.PUT, tenantAdd },
        .{ "/tenant/remove", std.http.Method.DELETE, tenantRemove },
        .{ "/tenant/list", std.http.Method.GET, tenantList },
        .{ "/tenant/set-status", std.http.Method.PUT, tenantStatus },
        .{ "/tenant/assign-user", std.http.Method.PUT, tenantAssignUser },
        .{ "/tenant/assign-bucket", std.http.Method.PUT, tenantAssignBucket },
    };
    inline for (routes) |r| {
        if (std.mem.eql(u8, op, r[0])) {
            if (m != r[1]) return try api.fail(c.a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
            return try r[2](c);
        }
    }
    return null;
}

// ---------------------------------------------------------------- idp-config

/// `<type>` lists; `<type>/<name>` adds (PUT), updates (POST), shows (GET), removes (DELETE).
fn idpConfig(c: *const Ctx, rest: []const u8) Error!Response {
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const kind = std.meta.stringToEnum(idp.Kind, rest[0 .. slash orelse rest.len]) orelse
        return api.badRequest(c.a, "Unknown identity provider type.");
    if (!try c.canAction(config_update)) return api.denied(c.a);
    const name_raw = if (slash) |i| rest[i + 1 ..] else "";
    if (slash == null or name_raw.len == 0) {
        if (c.req.method != .GET) return api.fail(c.a, .method_not_allowed, "MethodNotAllowed", "Listing takes GET.");
        return listIdp(c, kind);
    }
    const name = try api.formDecode(c.a, name_raw) orelse return api.badRequest(c.a, "Invalid configuration name.");
    return switch (c.req.method) {
        .PUT, .POST => upsertIdp(c, kind, name, c.req.method == .POST),
        .GET => infoIdp(c, kind, name),
        .DELETE => removeIdp(c, kind, name),
        else => api.fail(c.a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource."),
    };
}

fn upsertIdp(c: *const Ctx, kind: idp.Kind, name: []const u8, update: bool) Error!Response {
    const plain = try c.decryptBody() orelse return api.badRequest(c.a, "Request body could not be decrypted.");
    const settings = idp.parseSettings(c.a, kind, plain) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnknownKey => api.fail(c.a, .bad_request, "XMinioConfigError", "Unknown configuration key."),
        error.InvalidSyntax, error.InvalidValue => api.fail(c.a, .bad_request, "XMinioConfigError", "Configuration must be key=value pairs."),
    };
    idp.upsert(c.env.store, kind, name, settings, update) catch |e| return idpFail(c.a, e);
    return .{ .config_applied = true };
}

fn removeIdp(c: *const Ctx, kind: idp.Kind, name: []const u8) Error!Response {
    idp.remove(c.env.store, kind, name) catch |e| return idpFail(c.a, e);
    return .{ .config_applied = true };
}

fn idpFail(a: Allocator, e: idp.UpdateError) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.ConfigExists => api.fail(a, .bad_request, "XMinioAdminConfigIDPCfgNameAlreadyExists", "An identity provider configuration with this name already exists."),
        error.ConfigNotFound => api.fail(a, .not_found, "XMinioAdminConfigIDPCfgNameDoesNotExist", "No identity provider configuration with this name exists."),
        error.TooManyConfigs => api.badRequest(a, "Too many identity provider configurations."),
        error.InvalidConfigName => api.badRequest(a, "Invalid configuration name (LDAP takes only the default)."),
        error.MissingKey => api.fail(a, .bad_request, "XMinioConfigError", "A required key is missing (openid: config_url, client_id; ldap: server_addr, lookup_bind_dn, user_dn_search_base_dn, user_dn_search_filter)."),
        error.InvalidValue => api.fail(a, .bad_request, "XMinioConfigError", "A configuration value is invalid."),
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "IAM store update failed."),
    };
}

fn listIdp(c: *const Ctx, kind: idp.Kind) Error!Response {
    const entries = try idp.effective(c.a, c.env.store, c.env.idp_env, kind);
    const Item = struct { type: []const u8, name: []const u8, enabled: bool, roleARN: ?[]const u8 = null };
    const out = try c.a.alloc(Item, entries.len);
    for (entries, out) |e, *o| {
        o.* = .{ .type = @tagName(kind), .name = e.name, .enabled = !std.mem.eql(u8, idp.get(e.settings, "enable") orelse "on", "off") };
        if (kind == .openid) {
            const buf = try c.a.alloc(u8, 128);
            const arn = idp.OpenId.from(e.name, e.settings).roleArn(buf);
            if (arn.len > 0) o.roleARN = arn;
        }
    }
    return c.encrypted(out);
}

fn infoIdp(c: *const Ctx, kind: idp.Kind, name: []const u8) Error!Response {
    const entries = try idp.effective(c.a, c.env.store, c.env.idp_env, kind);
    const e = for (entries) |x| {
        if (std.mem.eql(u8, x.name, name)) break x;
    } else return idpFail(c.a, error.ConfigNotFound);
    const Info = struct { key: []const u8, value: []const u8, isCfg: bool = true, isEnv: bool };
    var info: std.ArrayList(Info) = .empty;
    for (e.settings) |s| {
        var from_env = false;
        for (e.env_keys) |k| from_env = from_env or std.mem.eql(u8, k, s.key);
        try info.append(c.a, .{ .key = s.key, .value = if (idp.isSecret(s.key)) "*redacted*" else s.value, .isEnv = from_env });
    }
    if (kind == .openid) {
        const buf = try c.a.alloc(u8, 128);
        const arn = idp.OpenId.from(e.name, e.settings).roleArn(buf);
        if (arn.len > 0) try info.append(c.a, .{ .key = "roleARN", .value = arn, .isCfg = false, .isEnv = false });
    }
    return c.encrypted(.{ .type = @tagName(kind), .name = e.name, .info = info.items });
}

// ---------------------------------------------------------------- LDAP policy mappings

fn ldapAttach(c: *const Ctx) Error!Response {
    return ldapAssociate(c, true);
}

fn ldapDetach(c: *const Ctx) Error!Response {
    return ldapAssociate(c, false);
}

fn ldapAssociate(c: *const Ctx, attach: bool) Error!Response {
    if (!try c.can(.attach_policy)) return api.denied(c.a);
    const plain = try c.decryptBody() orelse return api.badRequest(c.a, "Request body could not be decrypted.");
    const body = api.parseObject(c.a, plain) orelse return api.fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const policies = api.strList(c.a, body.get("policies")) orelse return api.badRequest(c.a, "policies must be a list of names.");
    const user = api.str(body, "user") orelse "";
    const group = api.str(body, "group") orelse "";
    if (policies.len == 0 or (user.len == 0) == (group.len == 0)) return api.badRequest(c.a, "Give policies and exactly one of user or group.");
    const ch = idp.associate(c.env.store, c.a, if (user.len > 0) user else group, group.len > 0, policies, attach) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidDn => api.badRequest(c.a, "Not a distinguished name."),
        error.NoChange => api.fail(c.a, .bad_request, "XMinioAdminPolicyChangeAlreadyApplied", "The specified policy change is already in effect."),
        error.PolicyNotFound => api.fail(c.a, .not_found, "XMinioAdminNoSuchPolicy", "The canned policy does not exist."),
        error.LimitExceeded => api.badRequest(c.a, "Too many attached policies."),
        else => api.fail(c.a, .internal_server_error, "XMinioInternalError", "IAM store update failed."),
    };
    var tb: [24]u8 = undefined;
    const now = core.time.iso8601(@as(i128, c.req.now_s) * std.time.ns_per_s, &tb);
    return c.encrypted(.{
        .policiesAttached = if (attach) ch.attached else null,
        .policiesDetached = if (attach) null else ch.detached,
        .updatedAt = now,
    });
}

fn ldapEntities(c: *const Ctx) Error!Response {
    if (!try c.can(.list_policies)) return api.denied(c.a);
    const q = c.req.target.query;
    const users = try normalizeAll(c.a, try api.queryParams(c.a, q, "user"));
    const groups = try normalizeAll(c.a, try api.queryParams(c.a, q, "group"));
    const policies = try api.queryParams(c.a, q, "policy");
    const all = users.len == 0 and groups.len == 0 and policies.len == 0;
    const UserMap = struct { user: []const u8, policies: []const []const u8 };
    const GroupMap = struct { group: []const u8, policies: []const []const u8 };
    const PolicyMap = struct { policy: []const u8, users: []const []const u8, groups: []const []const u8 };
    var um: std.ArrayList(UserMap) = .empty;
    var gm: std.ArrayList(GroupMap) = .empty;
    var pm: std.ArrayList(PolicyMap) = .empty;
    var pnames: std.ArrayList([]const u8) = .empty;
    {
        const v = c.env.store.view();
        defer v.release();
        for (v.snap.ldap_mappings) |m| {
            const ps = try dupeAll(c.a, m.policies);
            if (!m.group and (all or contains(users, m.dn))) try um.append(c.a, .{ .user = try c.a.dupe(u8, m.dn), .policies = ps });
            if (m.group and (all or contains(groups, m.dn))) try gm.append(c.a, .{ .group = try c.a.dupe(u8, m.dn), .policies = ps });
            for (ps) |p| if (!contains(pnames.items, p) and (all or contains(policies, p))) try pnames.append(c.a, p);
        }
        for (pnames.items) |p| {
            var us: std.ArrayList([]const u8) = .empty;
            var gs: std.ArrayList([]const u8) = .empty;
            for (v.snap.ldap_mappings) |m| if (contains(m.policies, p)) {
                if (m.group) try gs.append(c.a, try c.a.dupe(u8, m.dn)) else try us.append(c.a, try c.a.dupe(u8, m.dn));
            };
            try pm.append(c.a, .{ .policy = p, .users = us.items, .groups = gs.items });
        }
    }
    var tb: [24]u8 = undefined;
    return c.encrypted(.{
        .timestamp = core.time.iso8601(@as(i128, c.req.now_s) * std.time.ns_per_s, &tb),
        .userMappings = if (all or users.len > 0) um.items else null,
        .groupMappings = if (all or groups.len > 0) gm.items else null,
        .policyMappings = if (all or policies.len > 0) pm.items else null,
    });
}

fn normalizeAll(a: Allocator, dns: []const []const u8) Error![]const []const u8 {
    const out = try a.alloc([]const u8, dns.len);
    for (dns, out) |d, *o| o.* = try idp.normalizeDn(a, d);
    return out;
}

fn dupeAll(a: Allocator, xs: []const []const u8) Error![]const []const u8 {
    const out = try a.alloc([]const u8, xs.len);
    for (xs, out) |x, *o| o.* = try a.dupe(u8, x);
    return out;
}

fn contains(list: []const []const u8, name: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

// ---------------------------------------------------------------- bucket quotas

fn setBucketQuota(c: *const Ctx) Error!Response {
    if (!try c.canAction(set_quota)) return api.denied(c.a);
    const svc = c.env.svc orelse return api.fail(c.a, .not_implemented, "NotImplemented", "No object service.");
    const bucket = try c.param("bucket") orelse return api.badRequest(c.a, "bucket is required.");
    const body = api.parseObject(c.a, c.req.body) orelse return api.fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const size = uintField(body, "size") orelse uintField(body, "quota") orelse 0;
    const legacy = uintField(body, "quota") orelse 0;
    const limit = if (size > 0) size else legacy;
    if (api.str(body, "quotatype")) |t| if (t.len > 0 and !std.mem.eql(u8, t, "hard"))
        return api.fail(c.a, .bad_request, "XMinioAdminBucketQuotaConfigInvalid", "Only hard quotas are supported.");
    object.quota.set(svc, bucket, limit) catch |e| return objectFail(c.a, e);
    return .{};
}

fn getBucketQuota(c: *const Ctx) Error!Response {
    if (!try c.canAction(get_quota)) return api.denied(c.a);
    const svc = c.env.svc orelse return api.fail(c.a, .not_implemented, "NotImplemented", "No object service.");
    const bucket = try c.param("bucket") orelse return api.badRequest(c.a, "bucket is required.");
    const info = object.quota.info(svc, bucket) catch |e| return objectFail(c.a, e);
    if (info.quota == 0) return api.fail(c.a, .not_found, "XMinioAdminNoSuchQuotaConfiguration", "The quota configuration does not exist");
    return c.json(.{
        .quota = info.quota,
        .size = info.quota,
        .rate = 0,
        .requests = 0,
        .quotatype = "hard",
        .usage = info.usage.bytes,
        .objects = info.usage.objects,
    });
}

fn uintField(o: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .float => |f| if (f >= 0 and f < 1.8e19) @intFromFloat(f) else null,
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

fn objectFail(a: Allocator, e: object.Error) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchBucket => api.fail(a, .not_found, "NoSuchBucket", "The specified bucket does not exist"),
        error.InvalidRequest => api.badRequest(a, "Invalid request."),
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "Bucket configuration update failed."),
    };
}

// ---------------------------------------------------------------- tenants

fn tenantFail(a: Allocator, e: iam.tenants.Error) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.TenantExists => api.fail(a, .conflict, "XZkfsmTenantExists", "The tenant already exists."),
        error.NoSuchTenant => api.fail(a, .not_found, "XZkfsmNoSuchTenant", "The tenant does not exist."),
        error.TenantNotEmpty => api.fail(a, .conflict, "XZkfsmTenantNotEmpty", "The tenant still has users or buckets."),
        error.InvalidTenantName => api.badRequest(a, "Tenant names are 1-63 lowercase letters, digits, or '-'."),
        error.TooManyTenants => api.badRequest(a, "Too many tenants."),
        error.NotFound => api.fail(a, .not_found, "XMinioAdminNoSuchUser", "The specified user does not exist."),
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "IAM store update failed."),
    };
}

fn tenantAdd(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const name = try c.param("name") orelse return api.badRequest(c.a, "name is required.");
    iam.tenants.add(c.env.store, name) catch |e| return tenantFail(c.a, e);
    return .{};
}

fn tenantRemove(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const name = try c.param("name") orelse return api.badRequest(c.a, "name is required.");
    if (c.env.svc) |svc| {
        const owned = object.tenancy.listOwned(svc, c.a, name) catch |e| return objectFail(c.a, e);
        if (owned.len > 0) return tenantFail(c.a, error.TenantNotEmpty);
    }
    iam.tenants.remove(c.env.store, name) catch |e| return tenantFail(c.a, e);
    return .{};
}

fn tenantStatus(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const name = try c.param("name") orelse return api.badRequest(c.a, "name is required.");
    const status = try c.param("status") orelse return api.badRequest(c.a, "status is required.");
    const on = std.mem.eql(u8, status, "enabled");
    if (!on and !std.mem.eql(u8, status, "disabled")) return api.badRequest(c.a, "status must be enabled or disabled.");
    iam.tenants.setEnabled(c.env.store, name, on) catch |e| return tenantFail(c.a, e);
    return .{};
}

fn tenantAssignUser(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const user = try c.param("accessKey") orelse return api.badRequest(c.a, "accessKey is required.");
    const name = try c.param("name") orelse "";
    iam.tenants.assignUser(c.env.store, user, if (name.len == 0) null else name) catch |e| return tenantFail(c.a, e);
    return .{};
}

fn tenantAssignBucket(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const svc = c.env.svc orelse return api.fail(c.a, .not_implemented, "NotImplemented", "No object service.");
    const bucket = try c.param("bucket") orelse return api.badRequest(c.a, "bucket is required.");
    const name = try c.param("name") orelse "";
    if (name.len > 0 and !iam.federation.tenantUsable(c.env.store, name)) {
        const v = c.env.store.view();
        defer v.release();
        const exists = for (v.snap.tenants) |t| {
            if (std.mem.eql(u8, t.name, name)) break true;
        } else false;
        if (!exists) return tenantFail(c.a, error.NoSuchTenant);
    }
    object.tenancy.setTenant(svc, bucket, name) catch |e| return objectFail(c.a, e);
    return .{};
}

fn tenantList(c: *const Ctx) Error!Response {
    if (!try c.canAction(tenant_admin)) return api.denied(c.a);
    const ts = try iam.tenants.list(c.a, c.env.store);
    const Bucket = struct { name: []const u8, size: u64, objects: u64 };
    const Item = struct { name: []const u8, status: []const u8, users: []const []const u8, buckets: []const Bucket, size: u64 };
    const out = try c.a.alloc(Item, ts.len);
    for (ts, out) |t, *o| {
        var buckets: std.ArrayList(Bucket) = .empty;
        var total: u64 = 0;
        if (c.env.svc) |svc| {
            const owned = object.tenancy.listOwned(svc, c.a, t.name) catch &.{};
            for (owned) |b| {
                const u = object.quota.usage(svc, b.name) catch object.quota.Usage{};
                total +|= u.bytes;
                try buckets.append(c.a, .{ .name = b.name, .size = u.bytes, .objects = u.objects });
            }
        }
        o.* = .{ .name = t.name, .status = if (t.enabled) "enabled" else "disabled", .users = t.users, .buckets = buckets.items, .size = total };
    }
    return c.json(out);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const sio = @import("sio.zig");

test "idp-config, ldap mappings, and tenants over the admin API" {
    var mem: iam.store.MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(testing.allocator, mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
    defer st.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root: api.Caller = .{ .access_key = "rootkey", .secret = "rootsecret", .principal = "rootkey" };
    const H = struct {
        fn call(al: Allocator, s: *iam.Store, who: api.Caller, m: std.http.Method, target: []const u8, body: []const u8) !Response {
            const t = api.match(api.default_prefix, target) orelse return error.NoMatch;
            return api.handle(al, .{ .store = s }, .{ .method = m, .target = t, .body = body, .caller = who, .now_s = 1000 });
        }
    };

    const cfg = try sio.encryptWith(a, .pbkdf2_aes_gcm, "rootsecret", "config_url=https://idp.example/.well-known/openid-configuration client_id=zk client_secret=s3cr3t", @splat(1), @splat(2));
    const added = try H.call(a, &st, root, .PUT, "/minio/admin/v3/idp-config/openid/corp", cfg);
    try testing.expectEqual(std.http.Status.ok, added.status);
    try testing.expect(added.config_applied);
    try testing.expectEqual(std.http.Status.bad_request, (try H.call(a, &st, root, .PUT, "/minio/admin/v3/idp-config/openid/corp", cfg)).status);
    const ls = try H.call(a, &st, root, .GET, "/minio/admin/v3/idp-config/openid", "");
    try testing.expectEqualStrings("[{\"type\":\"openid\",\"name\":\"corp\",\"enabled\":true}]", try sio.decrypt(a, "rootsecret", ls.body));
    const info = try sio.decrypt(a, "rootsecret", (try H.call(a, &st, root, .GET, "/minio/admin/v3/idp-config/openid/corp", "")).body);
    try testing.expect(std.mem.indexOf(u8, info, "s3cr3t") == null);
    try testing.expect(std.mem.indexOf(u8, info, "*redacted*") != null);
    try testing.expectEqual(std.http.Status.not_found, (try H.call(a, &st, root, .DELETE, "/minio/admin/v3/idp-config/openid/other", "")).status);
    try testing.expectEqual(std.http.Status.bad_request, (try H.call(a, &st, root, .GET, "/minio/admin/v3/idp-config/saml", "")).status);

    const att = try sio.encryptWith(a, .pbkdf2_aes_gcm, "rootsecret", "{\"policies\":[\"readonly\"],\"group\":\"cn=devs,dc=example,dc=org\"}", @splat(3), @splat(4));
    const ar = try H.call(a, &st, root, .POST, "/minio/admin/v3/idp/ldap/policy/attach", att);
    try testing.expect(std.mem.indexOf(u8, try sio.decrypt(a, "rootsecret", ar.body), "\"policiesAttached\":[\"readonly\"]") != null);
    const ents = try sio.decrypt(a, "rootsecret", (try H.call(a, &st, root, .GET, "/minio/admin/v3/idp/ldap/policy-entities", "")).body);
    try testing.expect(std.mem.indexOf(u8, ents, "\"group\":\"cn=devs,dc=example,dc=org\"") != null);

    try testing.expectEqual(std.http.Status.ok, (try H.call(a, &st, root, .PUT, "/minio/admin/v3/tenant/add?name=acme", "")).status);
    try st.createUser("alice", "alicesecret");
    try testing.expectEqual(std.http.Status.ok, (try H.call(a, &st, root, .PUT, "/minio/admin/v3/tenant/assign-user?name=acme&accessKey=alice", "")).status);
    const tl = try H.call(a, &st, root, .GET, "/minio/admin/v3/tenant/list", "");
    try testing.expectEqualStrings("[{\"name\":\"acme\",\"status\":\"enabled\",\"users\":[\"alice\"],\"buckets\":[],\"size\":0}]", tl.body);
    // Tenant identities hold no admin rights, even with an admin policy.
    try st.attachPolicy(.user, "alice", "consoleAdmin");
    const alice: api.Caller = .{ .access_key = "alice", .secret = "alicesecret", .principal = "alice", .tenant = "acme" };
    try testing.expectEqual(std.http.Status.forbidden, (try H.call(a, &st, alice, .GET, "/minio/admin/v3/tenant/list", "")).status);
    try testing.expectEqual(std.http.Status.not_implemented, (try H.call(a, &st, root, .GET, "/minio/admin/v3/get-bucket-quota?bucket=b", "")).status);
}
