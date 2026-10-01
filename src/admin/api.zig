//! MinIO-compatible IAM admin API (`<prefix>/v3/...`). Protocol-neutral: the caller
//! authenticates the request and hands over the body; this module authorizes against
//! `admin:*` actions, applies the change through the IAM store, and builds the response.
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const sio = @import("sio.zig");
const tier = @import("tier.zig");

const Allocator = std.mem.Allocator;
const Op = iam.actions.AdminOp;
const Value = std.json.Value;

pub const default_prefix = "/minio/admin";
/// Always accepted in addition to the configured prefix.
pub const native_prefix = "/zkfsm/admin";
/// madmin v3 and v4 clients share the operation names.
const versions = [_][]const u8{ "/v3", "/v4" };
pub const max_body = 1024 * 1024;

pub const PrefixError = error{InvalidAdminPrefix};

/// A prefix is an absolute path of one or more segments without a trailing slash.
pub fn validatePrefix(p: []const u8) PrefixError!void {
    if (p.len < 2 or p[0] != '/' or p[p.len - 1] == '/') return error.InvalidAdminPrefix;
    if (std.mem.indexOfAny(u8, p, "?#%") != null or std.mem.indexOf(u8, p, "..") != null or std.mem.indexOf(u8, p, "//") != null)
        return error.InvalidAdminPrefix;
    for (p) |c| if (c <= 0x20 or c >= 0x7f) return error.InvalidAdminPrefix;
}

/// Path-style, requests to bucket `<first segment>` whose key starts with the rest of
/// the prefix plus `/v3/` or `/v4/` are routed to the admin API instead of S3.
pub fn shadowedBucket(p: []const u8) []const u8 {
    const rest = p[1..];
    return rest[0 .. std.mem.indexOfScalar(u8, rest, '/') orelse rest.len];
}

pub const Target = struct { op: []const u8, query: []const u8 };

/// Splits `target` when it is under `prefix` or the native prefix.
pub fn match(prefix: []const u8, target: []const u8) ?Target {
    const q = std.mem.indexOfScalar(u8, target, '?');
    const path = target[0 .. q orelse target.len];
    const query = if (q) |i| target[i + 1 ..] else "";
    for ([_][]const u8{ prefix, native_prefix }) |p| {
        if (p.len == 0 or !std.mem.startsWith(u8, path, p)) continue;
        const rest = path[p.len..];
        for (versions) |v| if (rest.len > v.len and std.mem.startsWith(u8, rest, v) and rest[v.len] == '/')
            return .{ .op = rest[v.len..], .query = query };
    }
    return null;
}

pub const Caller = struct {
    /// Key that signed the request; its secret encrypts admin payloads.
    access_key: []const u8,
    secret: []const u8,
    /// Identity to authorize (an STS session's parent).
    principal: []const u8,
    session_policy: ?[]const u8 = null,
};

pub const Request = struct {
    method: std.http.Method,
    target: Target,
    body: []const u8,
    caller: Caller,
    now_s: i64,
};

pub const Response = struct {
    status: std.http.Status = .ok,
    body: []const u8 = "",
    content_type: []const u8 = "application/json",
};

pub const Env = struct {
    store: *iam.Store,
    svc: ?*object.ObjectService = null,
    region: []const u8 = "us-east-1",
    started_s: i64 = 0,
};

pub const Error = error{OutOfMemory};

const Ctx = struct {
    a: Allocator,
    env: Env,
    req: Request,

    fn param(c: *const Ctx, name: []const u8) Error!?[]const u8 {
        return queryParam(c.a, c.req.target.query, name);
    }

    fn can(c: *const Ctx, op: Op) Error!bool {
        const store = c.env.store;
        const who = c.req.caller;
        var sp: ?iam.Policy = null;
        if (who.session_policy) |doc| sp = iam.policy.parse(c.a, doc) catch return false;
        const id: iam.Identity = .{ .access_key = who.principal, .session_policy = if (sp) |*p| p else null };
        const ctx: iam.Context = .{ .now_s = c.req.now_s };
        return store.authorize(id, op.action(), iam.actions.admin_resource, &ctx).allowed();
    }

    /// Plain (non-session, non-service-account) identity acting for itself.
    fn isSelf(c: *const Ctx, user: []const u8) bool {
        const who = c.req.caller;
        return std.mem.eql(u8, who.principal, user) and std.mem.eql(u8, who.access_key, user);
    }

    fn json(c: *const Ctx, v: anytype) Error!Response {
        return .{ .body = try std.json.Stringify.valueAlloc(c.a, v, .{ .emit_null_optional_fields = false }) };
    }

    fn encrypted(c: *const Ctx, v: anytype) Error!Response {
        const plain = try std.json.Stringify.valueAlloc(c.a, v, .{ .emit_null_optional_fields = false });
        const ct = sio.encrypt(c.a, c.req.caller.secret, plain) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => fail(c.a, .internal_server_error, "XMinioInternalError", "payload encryption failed"),
        };
        return .{ .body = ct, .content_type = "application/octet-stream" };
    }

    fn decryptBody(c: *const Ctx) Error!?[]u8 {
        return sio.decrypt(c.a, c.req.caller.secret, c.req.body) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }
};

pub fn fail(a: Allocator, status: std.http.Status, code: []const u8, message: []const u8) Error!Response {
    const body = try std.json.Stringify.valueAlloc(a, .{ .Code = code, .Message = message, .Resource = "", .RequestId = "" }, .{});
    return .{ .status = status, .body = body };
}

fn denied(a: Allocator) Error!Response {
    return fail(a, .forbidden, "AccessDenied", "Access Denied.");
}

fn badRequest(a: Allocator, message: []const u8) Error!Response {
    return fail(a, .bad_request, "XMinioAdminInvalidArgument", message);
}

const Subject = enum { user, group, policy, service_account };

fn storeFail(a: Allocator, e: iam.store.StoreError, subject: Subject) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NotFound => switch (subject) {
            .user => fail(a, .not_found, "XMinioAdminNoSuchUser", "The specified user does not exist."),
            .group => fail(a, .not_found, "XMinioAdminNoSuchGroup", "The specified group does not exist."),
            .policy => fail(a, .not_found, "XMinioAdminNoSuchPolicy", "The canned policy does not exist."),
            .service_account => fail(a, .not_found, "XMinioAdminServiceAccountNotFound", "The specified service account is not found."),
        },
        error.PolicyNotFound => fail(a, .not_found, "XMinioAdminNoSuchPolicy", "The canned policy does not exist."),
        error.AlreadyExists => fail(a, .conflict, "XMinioAdminUserExists", "The access key is already in use."),
        error.InvalidName => badRequest(a, "Invalid name."),
        error.InvalidSecret => fail(a, .bad_request, "XMinioAdminInvalidSecretKey", "Secret key must be 8 to 40 printable characters."),
        error.InvalidPolicy => fail(a, .bad_request, "XMinioMalformedPolicy", "Policy has invalid syntax."),
        error.PolicyInUse => fail(a, .bad_request, "XMinioAdminPolicyInUse", "The policy is attached to a user or group."),
        error.BuiltinPolicy => badRequest(a, "Built-in policies cannot be changed."),
        error.LimitExceeded => badRequest(a, "Too many attached policies."),
        error.GroupNotEmpty => fail(a, .bad_request, "XMinioAdminGroupNotEmpty", "The specified group is not empty - cannot remove it."),
        error.PersistFailed, error.StoreTooLarge, error.CorruptStore, error.UnsupportedFormat => fail(a, .internal_server_error, "XMinioInternalError", "IAM store update failed."),
    };
}

/// Routes one admin request; unknown operations get a JSON NotImplemented.
pub fn handle(a: Allocator, env: Env, req: Request) Error!Response {
    const c: Ctx = .{ .a = a, .env = env, .req = req };
    const op = req.target.op;
    const m = req.method;
    const routes = .{
        .{ "/add-user", .PUT, addUser },
        .{ "/remove-user", .DELETE, removeUser },
        .{ "/list-users", .GET, listUsers },
        .{ "/user-info", .GET, userInfo },
        .{ "/set-user-status", .PUT, setUserStatus },
        .{ "/add-canned-policy", .PUT, addPolicy },
        .{ "/remove-canned-policy", .DELETE, removePolicy },
        .{ "/list-canned-policies", .GET, listPolicies },
        .{ "/info-canned-policy", .GET, infoPolicy },
        .{ "/idp/builtin/policy/attach", .POST, attachPolicy },
        .{ "/idp/builtin/policy/detach", .POST, detachPolicy },
        .{ "/set-user-or-group-policy", .PUT, setPolicy },
        .{ "/update-group-members", .PUT, updateGroupMembers },
        .{ "/group", .GET, groupInfo },
        .{ "/groups", .GET, listGroups },
        .{ "/set-group-status", .PUT, setGroupStatus },
        .{ "/add-service-account", .PUT, addServiceAccount },
        .{ "/update-service-account", .POST, updateServiceAccount },
        .{ "/delete-service-account", .DELETE, deleteServiceAccount },
        .{ "/list-service-accounts", .GET, listServiceAccounts },
        .{ "/info-service-account", .GET, infoServiceAccount },
        .{ "/list-access-keys-bulk", .GET, listAccessKeysBulk },
        .{ "/info-access-key", .GET, infoAccessKey },
        .{ "/info", .GET, serverInfo },
        .{ "/accountinfo", .GET, accountInfo },
    };
    inline for (routes) |r| {
        if (std.mem.eql(u8, op, r[0])) {
            if (m != r[1]) return fail(a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
            return r[2](&c);
        }
    }
    if (try tier.handle(a, env, req)) |res| return res;
    return fail(a, .not_implemented, "NotImplemented", "A header you provided implies functionality that is not implemented.");
}

// ---------------------------------------------------------------- users

fn statusText(enabled: bool) []const u8 {
    return if (enabled) "enabled" else "disabled";
}

fn joinNames(a: Allocator, names: []const []const u8) Error![]const u8 {
    return std.mem.join(a, ",", names);
}

fn memberOf(a: Allocator, v: iam.Store.View, user: []const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (v.snap.groups) |g| for (g.members) |mem| if (std.mem.eql(u8, mem, user)) try out.append(a, try a.dupe(u8, g.name));
    return out.items;
}

fn addUser(c: *const Ctx) Error!Response {
    if (!try c.can(.create_user)) return denied(c.a);
    const name = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    if (std.mem.eql(u8, name, c.req.caller.access_key)) return badRequest(c.a, "Cannot modify the calling identity.");
    const plain = try c.decryptBody() orelse return badRequest(c.a, "Request body could not be decrypted.");
    const body = parseObject(c.a, plain) orelse return fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const secret = str(body, "secretKey") orelse return fail(c.a, .bad_request, "XMinioAdminInvalidSecretKey", "secretKey is required.");
    const status = str(body, "status") orelse "enabled";
    c.env.store.upsertUser(name, secret, !std.mem.eql(u8, status, "disabled")) catch |e| return storeFail(c.a, e, .user);
    return .{};
}

fn removeUser(c: *const Ctx) Error!Response {
    if (!try c.can(.delete_user)) return denied(c.a);
    const name = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    c.env.store.deleteUser(name) catch |e| return storeFail(c.a, e, .user);
    return .{};
}

const UserInfo = struct {
    policyName: ?[]const u8 = null,
    status: []const u8,
    memberOf: ?[]const []const u8 = null,
};

fn userInfoLocked(a: Allocator, v: iam.Store.View, u: *const iam.store.User) Error!UserInfo {
    const groups = try memberOf(a, v, u.name);
    return .{
        .policyName = if (u.policies.len > 0) try joinNames(a, u.policies) else null,
        .status = statusText(u.enabled),
        .memberOf = if (groups.len > 0) groups else null,
    };
}

fn listUsers(c: *const Ctx) Error!Response {
    if (!try c.can(.list_users)) return denied(c.a);
    var map: std.json.ArrayHashMap(UserInfo) = .{};
    {
        const v = c.env.store.view();
        defer v.release();
        for (v.snap.users) |*u| try map.map.put(c.a, try c.a.dupe(u8, u.name), try userInfoLocked(c.a, v, u));
    }
    return c.encrypted(map);
}

fn userInfo(c: *const Ctx) Error!Response {
    const name = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    if (!c.isSelf(name) and !try c.can(.get_user)) return denied(c.a);
    const v = c.env.store.view();
    defer v.release();
    const u = v.user(name) orelse return storeFail(c.a, error.NotFound, .user);
    return c.json(try userInfoLocked(c.a, v, u));
}

fn setUserStatus(c: *const Ctx) Error!Response {
    const name = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    const status = try c.param("status") orelse return badRequest(c.a, "status is required.");
    const enable = std.mem.eql(u8, status, "enabled");
    if (!enable and !std.mem.eql(u8, status, "disabled")) return badRequest(c.a, "status must be enabled or disabled.");
    if (!try c.can(if (enable) .enable_user else .disable_user)) return denied(c.a);
    c.env.store.setUserEnabled(name, enable) catch |e| return storeFail(c.a, e, .user);
    return .{};
}

// ---------------------------------------------------------------- policies

fn addPolicy(c: *const Ctx) Error!Response {
    if (!try c.can(.create_policy)) return denied(c.a);
    const name = try c.param("name") orelse return badRequest(c.a, "name is required.");
    if (c.req.body.len == 0) return fail(c.a, .bad_request, "XMinioMalformedPolicy", "Policy document is empty.");
    c.env.store.putPolicy(name, c.req.body) catch |e| return storeFail(c.a, e, .policy);
    return .{};
}

fn removePolicy(c: *const Ctx) Error!Response {
    if (!try c.can(.delete_policy)) return denied(c.a);
    const name = try c.param("name") orelse return badRequest(c.a, "name is required.");
    c.env.store.deletePolicy(name) catch |e| return storeFail(c.a, e, .policy);
    return .{};
}

fn listPolicies(c: *const Ctx) Error!Response {
    if (!try c.can(.list_policies)) return denied(c.a);
    var map: std.json.ArrayHashMap(Value) = .{};
    const names = try c.env.store.list(c.a, .policies);
    const v = c.env.store.view();
    defer v.release();
    for (names) |n| {
        const doc = v.policyDocument(n) orelse continue;
        try map.map.put(c.a, n, parseValue(c.a, doc) orelse continue);
    }
    return c.json(map);
}

fn infoPolicy(c: *const Ctx) Error!Response {
    if (!try c.can(.get_policy)) return denied(c.a);
    const name = try c.param("name") orelse return badRequest(c.a, "name is required.");
    const v2 = try c.param("v") != null;
    const v = c.env.store.view();
    defer v.release();
    const doc = v.policyDocument(name) orelse return storeFail(c.a, error.PolicyNotFound, .policy);
    if (!v2) return .{ .body = try c.a.dupe(u8, doc) };
    return c.json(.{ .PolicyName = name, .Policy = parseValue(c.a, doc) orelse Value{ .null = {} } });
}

fn attachPolicy(c: *const Ctx) Error!Response {
    return associate(c, true);
}

fn detachPolicy(c: *const Ctx) Error!Response {
    return associate(c, false);
}

fn associate(c: *const Ctx, attach: bool) Error!Response {
    if (!try c.can(.attach_policy)) return denied(c.a);
    const plain = try c.decryptBody() orelse return badRequest(c.a, "Request body could not be decrypted.");
    const body = parseObject(c.a, plain) orelse return fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const policies = strList(c.a, body.get("policies")) orelse return badRequest(c.a, "policies must be a list of names.");
    const user = str(body, "user") orelse "";
    const group = str(body, "group") orelse "";
    if (policies.len == 0 or (user.len == 0) == (group.len == 0)) return badRequest(c.a, "Give policies and exactly one of user or group.");
    const target: iam.store.AttachTarget = if (user.len > 0) .user else .group;
    const name = if (user.len > 0) user else group;
    const subject: Subject = if (user.len > 0) .user else .group;

    // Compute the new set under a view, then commit it in one step.
    var next: std.ArrayList([]const u8) = .empty;
    var changed: std.ArrayList([]const u8) = .empty;
    {
        const v = c.env.store.view();
        defer v.release();
        const current: []const []const u8 = if (user.len > 0)
            (v.user(user) orelse return storeFail(c.a, error.NotFound, .user)).policies
        else
            (v.group(group) orelse return storeFail(c.a, error.NotFound, .group)).policies;
        for (current) |p| {
            const drop = !attach and contains(policies, p);
            if (drop) try changed.append(c.a, try c.a.dupe(u8, p)) else try next.append(c.a, try c.a.dupe(u8, p));
        }
        if (attach) for (policies) |p| if (!contains(next.items, p) and !contains(changed.items, p)) {
            if (v.policyDocument(p) == null) return storeFail(c.a, error.PolicyNotFound, .policy);
            try next.append(c.a, p);
            try changed.append(c.a, p);
        };
    }
    if (changed.items.len == 0)
        return fail(c.a, .bad_request, "XMinioAdminPolicyChangeAlreadyApplied", "The specified policy change is already in effect.");
    c.env.store.setPolicies(target, name, next.items) catch |e| return storeFail(c.a, e, subject);
    var tb: [24]u8 = undefined;
    const now = core.time.iso8601(@as(i128, c.req.now_s) * std.time.ns_per_s, &tb);
    return c.encrypted(.{
        .policiesAttached = if (attach) changed.items else null,
        .policiesDetached = if (attach) null else changed.items,
        .updatedAt = now,
    });
}

fn setPolicy(c: *const Ctx) Error!Response {
    if (!try c.can(.attach_policy)) return denied(c.a);
    const names = try c.param("policyName") orelse "";
    const who = try c.param("userOrGroup") orelse return badRequest(c.a, "userOrGroup is required.");
    const is_group = std.mem.eql(u8, try c.param("isGroup") orelse "false", "true");
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, names, ',');
    while (it.next()) |n| try list.append(c.a, std.mem.trim(u8, n, " "));
    c.env.store.setPolicies(if (is_group) .group else .user, who, list.items) catch |e| return storeFail(c.a, e, if (is_group) .group else .user);
    return .{};
}

// ---------------------------------------------------------------- groups

fn updateGroupMembers(c: *const Ctx) Error!Response {
    const body = parseObject(c.a, c.req.body) orelse return fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const group = str(body, "group") orelse return badRequest(c.a, "group is required.");
    const members = strList(c.a, body.get("members")) orelse &.{};
    const remove = if (body.get("isRemove")) |v| v == .bool and v.bool else false;
    if (!try c.can(if (remove) .remove_user_from_group else .add_user_to_group)) return denied(c.a);
    c.env.store.updateGroupMembers(group, members, remove) catch |e| return storeFail(c.a, e, if (e == error.NotFound and !remove) .user else .group);
    return .{};
}

fn groupInfo(c: *const Ctx) Error!Response {
    if (!try c.can(.get_group)) return denied(c.a);
    const name = try c.param("group") orelse return badRequest(c.a, "group is required.");
    const v = c.env.store.view();
    defer v.release();
    const g = v.group(name) orelse return storeFail(c.a, error.NotFound, .group);
    return c.json(.{ .name = g.name, .status = statusText(g.enabled), .members = g.members, .policy = try joinNames(c.a, g.policies) });
}

fn listGroups(c: *const Ctx) Error!Response {
    if (!try c.can(.list_groups)) return denied(c.a);
    return c.json(try c.env.store.list(c.a, .groups));
}

fn setGroupStatus(c: *const Ctx) Error!Response {
    const name = try c.param("group") orelse return badRequest(c.a, "group is required.");
    const status = try c.param("status") orelse return badRequest(c.a, "status is required.");
    const enable = std.mem.eql(u8, status, "enabled");
    if (!enable and !std.mem.eql(u8, status, "disabled")) return badRequest(c.a, "status must be enabled or disabled.");
    if (!try c.can(if (enable) .enable_group else .disable_group)) return denied(c.a);
    c.env.store.setGroupEnabled(name, enable) catch |e| return storeFail(c.a, e, .group);
    return .{};
}

// ---------------------------------------------------------------- service accounts

fn randomKey(comptime n: usize, alphabet: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out) |*ch| ch.* = alphabet[std.crypto.random.uintLessThan(usize, alphabet.len)];
    return out;
}

const key_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const secret_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Owner of a service account: its parent user acting with its own long-term key.
fn ownsAccount(c: *const Ctx, parent: []const u8) bool {
    return c.isSelf(parent);
}

fn addServiceAccount(c: *const Ctx) Error!Response {
    const plain = try c.decryptBody() orelse return badRequest(c.a, "Request body could not be decrypted.");
    const body = parseObject(c.a, plain) orelse return fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    const target = str(body, "targetUser") orelse "";
    const parent = if (target.len > 0) target else c.req.caller.principal;
    if (!ownsAccount(c, parent) and !try c.can(.create_service_account)) return denied(c.a);
    const gen_key = randomKey(20, key_alphabet);
    const gen_secret = randomKey(40, secret_alphabet);
    const ak = nonEmpty(str(body, "accessKey")) orelse try c.a.dupe(u8, &gen_key);
    const sk = nonEmpty(str(body, "secretKey")) orelse try c.a.dupe(u8, &gen_secret);
    const pol = try policyField(c.a, body.get("policy"));
    const exp = if (str(body, "expiration")) |s| parseTime(s) orelse return badRequest(c.a, "Invalid expiration.") else null;
    if (exp) |e| if (e <= c.req.now_s) return badRequest(c.a, "Expiration must be in the future.");
    c.env.store.createServiceAccount(.{
        .access_key = ak,
        .secret = sk,
        .parent = parent,
        .policy = pol,
        .expires_s = exp,
        .name = nonEmpty(str(body, "name")),
        .description = nonEmpty(str(body, "description")),
    }) catch |e| return storeFail(c.a, e, .user);
    var tb: [24]u8 = undefined;
    const exp_text: ?[]const u8 = if (exp) |e| core.time.iso8601(@as(i128, e) * std.time.ns_per_s, &tb) else null;
    return c.encrypted(.{ .credentials = .{ .accessKey = ak, .secretKey = sk, .expiration = exp_text } });
}

fn updateServiceAccount(c: *const Ctx) Error!Response {
    const key = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    if (!try mayManage(c, key, .update_service_account)) return denied(c.a);
    const plain = try c.decryptBody() orelse return badRequest(c.a, "Request body could not be decrypted.");
    const body = parseObject(c.a, plain) orelse return fail(c.a, .bad_request, "XMinioAdminConfigBadJSON", "Malformed JSON.");
    var u: iam.Store.ServiceAccountUpdate = .{
        .secret = nonEmpty(str(body, "newSecretKey")),
        .name = nonEmpty(str(body, "newName")),
        .description = nonEmpty(str(body, "newDescription")),
    };
    if (nonEmpty(str(body, "newStatus"))) |s| {
        const on = std.mem.eql(u8, s, "on") or std.mem.eql(u8, s, "enabled");
        if (!on and !std.mem.eql(u8, s, "off") and !std.mem.eql(u8, s, "disabled")) return badRequest(c.a, "newStatus must be on or off.");
        u.enabled = on;
    }
    if (body.get("newPolicy")) |p| if (p == .object) {
        u.policy = .{ .set = try policyField(c.a, p) };
    };
    if (str(body, "newExpiration")) |s| {
        const e = parseTime(s) orelse return badRequest(c.a, "Invalid expiration.");
        if (e <= c.req.now_s) return badRequest(c.a, "Expiration must be in the future.");
        u.expires_s = e;
    }
    c.env.store.updateServiceAccount(key, u) catch |e| return storeFail(c.a, e, .service_account);
    return .{ .status = .no_content };
}

fn deleteServiceAccount(c: *const Ctx) Error!Response {
    const key = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    if (!try mayManage(c, key, .remove_service_account)) return denied(c.a);
    c.env.store.deleteServiceAccount(key) catch |e| return storeFail(c.a, e, .service_account);
    return .{ .status = .no_content };
}

/// Admins manage any account; users manage their own. Unknown keys fall to the admin check.
fn mayManage(c: *const Ctx, key: []const u8, op: Op) Error!bool {
    {
        const v = c.env.store.view();
        defer v.release();
        if (v.serviceAccount(key)) |sa| if (ownsAccount(c, sa.parent)) return true;
    }
    return c.can(op);
}

const AccountInfo = struct {
    parentUser: []const u8,
    accountStatus: []const u8,
    impliedPolicy: bool,
    accessKey: []const u8,
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    expiration: ?[]const u8 = null,
};

fn accountInfoLocked(a: Allocator, sa: *const iam.store.ServiceAccount) Error!AccountInfo {
    // Clients expect a timestamp; the Unix epoch is MinIO's "never expires" sentinel.
    const tb = try a.create([24]u8);
    const exp = core.time.iso8601(@as(i128, sa.expires_s orelse 0) * std.time.ns_per_s, tb);
    return .{
        .parentUser = try a.dupe(u8, sa.parent),
        .accountStatus = if (sa.enabled) "on" else "off",
        .impliedPolicy = sa.policy == null,
        .accessKey = try a.dupe(u8, sa.access_key),
        .name = if (sa.name) |n| try a.dupe(u8, n) else null,
        .description = if (sa.description) |d| try a.dupe(u8, d) else null,
        .expiration = exp,
    };
}

fn listServiceAccounts(c: *const Ctx) Error!Response {
    const user = nonEmpty(try c.param("user")) orelse c.req.caller.principal;
    if (!c.isSelf(user) and !try c.can(.list_service_accounts)) return denied(c.a);
    var out: std.ArrayList(AccountInfo) = .empty;
    {
        const v = c.env.store.view();
        defer v.release();
        if (!v.isRoot(user) and v.user(user) == null) return storeFail(c.a, error.NotFound, .user);
        for (v.snap.service_accounts) |*sa| if (std.mem.eql(u8, sa.parent, user)) try out.append(c.a, try accountInfoLocked(c.a, sa));
    }
    return c.encrypted(.{ .accounts = out.items });
}

fn infoServiceAccount(c: *const Ctx) Error!Response {
    return describeAccount(c, false);
}

fn infoAccessKey(c: *const Ctx) Error!Response {
    return describeAccount(c, true);
}

fn describeAccount(c: *const Ctx, access_key_form: bool) Error!Response {
    const key = try c.param("accessKey") orelse return badRequest(c.a, "accessKey is required.");
    if (!try mayManage(c, key, .list_service_accounts)) return denied(c.a);
    const v = c.env.store.view();
    defer v.release();
    const sa = v.serviceAccount(key) orelse return storeFail(c.a, error.NotFound, .service_account);
    const info = try accountInfoLocked(c.a, sa);
    const pol = if (sa.policy) |p| try c.a.dupe(u8, p) else try effectivePolicy(c.a, v, sa.parent);
    if (access_key_form) return c.encrypted(.{
        .AccessKey = info.accessKey,
        .parentUser = info.parentUser,
        .accountStatus = info.accountStatus,
        .impliedPolicy = info.impliedPolicy,
        .policy = pol,
        .name = info.name,
        .description = info.description,
        .expiration = info.expiration,
        .userType = "Service Account",
        .userProvider = "builtin",
    });
    return c.encrypted(.{
        .parentUser = info.parentUser,
        .accountStatus = info.accountStatus,
        .impliedPolicy = info.impliedPolicy,
        .policy = pol,
        .name = info.name,
        .description = info.description,
        .expiration = info.expiration,
    });
}

/// Service accounts per user; the builtin store has no persisted STS keys to list.
fn listAccessKeysBulk(c: *const Ctx) Error!Response {
    const all = std.mem.eql(u8, try c.param("all") orelse "", "true");
    const list_type = try c.param("listType") orelse "all";
    const want_sa = std.mem.eql(u8, list_type, "all") or std.mem.eql(u8, list_type, "svcacc-only");
    var users = try queryParams(c.a, c.req.target.query, "users");
    if (!all and users.len == 0) users = try c.a.dupe([]const u8, &.{c.req.caller.principal});
    const self_only = !all and users.len == 1 and c.isSelf(users[0]);
    if (!self_only and !try c.can(.list_service_accounts)) return denied(c.a);
    const Entry = struct { serviceAccounts: []const AccountInfo, stsKeys: []const AccountInfo = &.{} };
    var map: std.json.ArrayHashMap(Entry) = .{};
    const v = c.env.store.view();
    defer v.release();
    if (all) {
        var names: std.ArrayList([]const u8) = .empty;
        for (v.snap.users) |u| try names.append(c.a, try c.a.dupe(u8, u.name));
        users = names.items;
    }
    for (users) |user| {
        if (!v.isRoot(user) and v.user(user) == null) return storeFail(c.a, error.NotFound, .user);
        var out: std.ArrayList(AccountInfo) = .empty;
        if (want_sa) for (v.snap.service_accounts) |*sa| if (std.mem.eql(u8, sa.parent, user)) try out.append(c.a, try accountInfoLocked(c.a, sa));
        try map.map.put(c.a, user, .{ .serviceAccounts = out.items });
    }
    return c.encrypted(map);
}

// ---------------------------------------------------------------- info

fn serverInfo(c: *const Ctx) Error!Response {
    if (!try c.can(.server_info)) return denied(c.a);
    const buckets: usize = if (c.env.svc) |svc| (svc.listBuckets(c.a) catch &.{}).len else 0;
    return c.json(.{
        .mode = "online",
        .region = c.env.region,
        .deploymentID = "zkfsm",
        .buckets = .{ .count = buckets },
        .objects = .{ .count = 0 },
        .usage = .{ .size = 0 },
        .backend = .{ .backendType = "FS", .onlineDisks = 1, .offlineDisks = 0 },
        .servers = .{.{
            .state = "online",
            .endpoint = "zkfsm",
            .uptime = c.req.now_s - c.env.started_s,
            .version = "zkfsm",
            .network = .{ .zkfsm = "online" },
        }},
    });
}

fn accountInfo(c: *const Ctx) Error!Response {
    const who = c.req.caller.principal;
    const store = c.env.store;
    const pol = blk: {
        const v = store.view();
        defer v.release();
        if (v.serviceAccount(who)) |sa| if (sa.policy) |p| break :blk try c.a.dupe(u8, p);
        const user = if (v.serviceAccount(who)) |sa| sa.parent else who;
        break :blk try effectivePolicy(c.a, v, user);
    };
    const Access = struct { read: bool, write: bool };
    const Bucket = struct { name: []const u8, created: []const u8, size: u64 = 0, objects: u64 = 0, access: Access };
    var list: std.ArrayList(Bucket) = .empty;
    if (c.env.svc) |svc| {
        const buckets = svc.listBuckets(c.a) catch &.{};
        var sp: ?iam.Policy = null;
        if (c.req.caller.session_policy) |doc| sp = iam.policy.parse(c.a, doc) catch null;
        const id: iam.Identity = .{ .access_key = who, .session_policy = if (sp) |*p| p else null };
        const ctx: iam.Context = .{ .now_s = c.req.now_s };
        for (buckets) |b| {
            const arn = try std.fmt.allocPrint(c.a, "arn:aws:s3:::{s}/*", .{b.name});
            const tb = try c.a.create([24]u8);
            try list.append(c.a, .{
                .name = b.name,
                .created = core.time.iso8601(b.created_ns, tb),
                .access = .{
                    .read = store.authorize(id, "s3:GetObject", arn, &ctx).allowed(),
                    .write = store.authorize(id, "s3:PutObject", arn, &ctx).allowed(),
                },
            });
        }
    }
    return c.json(.{
        .AccountName = who,
        .Server = .{ .Type = 1 },
        .Policy = parseValue(c.a, pol) orelse Value{ .null = {} },
        .Buckets = list.items,
    });
}

/// All statements from a user's own and group policies, as one policy document.
fn effectivePolicy(a: Allocator, v: iam.Store.View, user: []const u8) Error![]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    if (v.isRoot(user)) {
        try names.append(a, "consoleAdmin");
    } else if (v.user(user)) |u| {
        try names.appendSlice(a, u.policies);
        for (v.snap.groups) |g| if (g.enabled and contains(g.members, user)) try names.appendSlice(a, g.policies);
    }
    var stmts: std.json.Array = .init(a);
    for (names.items) |n| {
        const doc = v.policyDocument(n) orelse continue;
        const val = parseValue(a, doc) orelse continue;
        if (val != .object) continue;
        const s = val.object.get("Statement") orelse continue;
        switch (s) {
            .array => |arr| try stmts.appendSlice(arr.items),
            .object => try stmts.append(s),
            else => {},
        }
    }
    return std.json.Stringify.valueAlloc(a, .{ .Version = "2012-10-17", .Statement = Value{ .array = stmts } }, .{});
}

// ---------------------------------------------------------------- helpers

fn parseValue(a: Allocator, doc: []const u8) ?Value {
    return std.json.parseFromSliceLeaky(Value, a, doc, .{}) catch null;
}

fn parseObject(a: Allocator, doc: []const u8) ?std.json.ObjectMap {
    const v = parseValue(a, doc) orelse return null;
    return if (v == .object) v.object else null;
}

fn str(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn nonEmpty(s: ?[]const u8) ?[]const u8 {
    const v = s orelse return null;
    return if (v.len == 0) null else v;
}

fn strList(a: Allocator, v: ?Value) ?[]const []const u8 {
    const val = v orelse return null;
    if (val == .null) return &.{};
    if (val != .array) return null;
    const out = a.alloc([]const u8, val.array.items.len) catch return null;
    for (val.array.items, out) |item, *o| {
        if (item != .string) return null;
        o.* = item.string;
    }
    return out;
}

fn contains(list: []const []const u8, name: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

/// A policy given as an embedded JSON object; empty objects and null mean none.
fn policyField(a: Allocator, v: ?Value) Error!?[]const u8 {
    const val = v orelse return null;
    return switch (val) {
        .object => |o| if (o.count() == 0) null else try std.json.Stringify.valueAlloc(a, val, .{}),
        .string => |s| nonEmpty(s),
        else => null,
    };
}

/// RFC 3339 timestamp with `Z` or a numeric offset, to Unix seconds.
pub fn parseTime(s: []const u8) ?i64 {
    var buf: [40]u8 = undefined;
    var offset_s: i64 = 0;
    var base = s;
    if (s.len > 6 and (s[s.len - 6] == '+' or s[s.len - 6] == '-') and s[s.len - 3] == ':') {
        const h = std.fmt.parseInt(i64, s[s.len - 5 .. s.len - 3], 10) catch return null;
        const m = std.fmt.parseInt(i64, s[s.len - 2 ..], 10) catch return null;
        offset_s = (h * 3600 + m * 60) * @as(i64, if (s[s.len - 6] == '+') 1 else -1);
        if (s.len - 6 + 1 > buf.len) return null;
        @memcpy(buf[0 .. s.len - 6], s[0 .. s.len - 6]);
        buf[s.len - 6] = 'Z';
        base = buf[0 .. s.len - 5];
    }
    // Go emits up to nine fractional digits; the core parser takes up to nine as well.
    const ns = core.time.parseIso8601(base) catch return null;
    return @as(i64, @intCast(@divFloor(ns, std.time.ns_per_s))) - offset_s;
}

/// Decoded value of query parameter `name` ("" for a bare flag), or null if absent.
pub fn queryParam(a: Allocator, query: []const u8, name: []const u8) Error!?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const k = try formDecode(a, pair[0 .. eq orelse pair.len]) orelse continue;
        if (!std.mem.eql(u8, k, name)) continue;
        return if (eq) |i| try formDecode(a, pair[i + 1 ..]) orelse null else "";
    }
    return null;
}

/// All decoded values of a repeated query parameter.
pub fn queryParams(a: Allocator, query: []const u8, name: []const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = try formDecode(a, pair[0..eq]) orelse continue;
        if (!std.mem.eql(u8, k, name)) continue;
        try out.append(a, try formDecode(a, pair[eq + 1 ..]) orelse continue);
    }
    return out.items;
}

/// Percent-decoding with `+` as space; null on malformed escapes.
pub fn formDecode(a: Allocator, s: []const u8) Error!?[]const u8 {
    if (std.mem.indexOfAny(u8, s, "%+") == null) return s;
    const out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        out[n] = switch (s[i]) {
            '%' => blk: {
                if (s.len - i < 3) return null;
                const b = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return null;
                i += 2;
                break :blk b;
            },
            '+' => ' ',
            else => |ch| ch,
        };
        n += 1;
    }
    return out[0..n];
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "prefix validation and matching" {
    try validatePrefix("/minio/admin");
    try validatePrefix("/ops");
    for ([_][]const u8{ "", "/", "minio/admin", "/minio/admin/", "/a?b", "/a/../b", "/a//b", "/a b" }) |bad|
        try testing.expectError(error.InvalidAdminPrefix, validatePrefix(bad));
    try testing.expectEqualStrings("minio", shadowedBucket("/minio/admin"));
    try testing.expectEqualStrings("ops", shadowedBucket("/ops"));

    const t = match("/minio/admin", "/minio/admin/v3/add-user?accessKey=bob").?;
    try testing.expectEqualStrings("/add-user", t.op);
    try testing.expectEqualStrings("accessKey=bob", t.query);
    try testing.expectEqualStrings("/list-users", match("/ops", "/zkfsm/admin/v3/list-users").?.op);
    try testing.expectEqualStrings("/idp/builtin/policy/attach", match("/ops", "/ops/v3/idp/builtin/policy/attach").?.op);
    try testing.expect(match("/ops", "/minio/admin/v3/list-users") == null);
    try testing.expect(match("/minio/admin", "/minio/adminx/v3/list-users") == null);
    try testing.expect(match("/minio/admin", "/minio/admin/v2/list-users") == null);
    try testing.expectEqualStrings("/list-users", match("/minio/admin", "/minio/admin/v4/list-users").?.op);
    try testing.expect(match("/minio/admin", "/bucket/key") == null);
}

test "query and time parsing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("a b/c", (try queryParam(a, "x=1&accessKey=a+b%2Fc", "accessKey")).?);
    try testing.expectEqualStrings("", (try queryParam(a, "flag&x=1", "flag")).?);
    try testing.expect(try queryParam(a, "x=1", "y") == null);
    try testing.expect(try queryParam(a, "y=%zz", "y") == null);
    const us = try queryParams(a, "users=a&x=1&users=b%40c", "users");
    try testing.expectEqual(@as(usize, 2), us.len);
    try testing.expectEqualStrings("b@c", us[1]);
    try testing.expectEqual(@as(?i64, 784111777), parseTime("1994-11-06T08:49:37Z"));
    try testing.expectEqual(@as(?i64, 784111777), parseTime("1994-11-06T10:49:37.123+02:00"));
    try testing.expectEqual(@as(?i64, 784111777), parseTime("1994-11-06T03:49:37-05:00"));
    try testing.expect(parseTime("yesterday") == null);
}

const TestEnv = struct {
    mem: iam.store.MemoryPersistence,
    store: iam.Store,
    arena: std.heap.ArenaAllocator,

    fn init(self: *TestEnv) !void {
        self.mem = .{ .gpa = testing.allocator };
        try self.store.open(testing.allocator, self.mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
        self.arena = .init(testing.allocator);
    }
    fn deinit(self: *TestEnv) void {
        self.arena.deinit();
        self.store.deinit();
        self.mem.deinit();
    }
    fn call(self: *TestEnv, who: Caller, m: std.http.Method, target: []const u8, body: []const u8) !Response {
        const t = match(default_prefix, target) orelse return error.NoMatch;
        return handle(self.arena.allocator(), .{ .store = &self.store }, .{ .method = m, .target = t, .body = body, .caller = who, .now_s = 1000 });
    }
};

const root_caller: Caller = .{ .access_key = "rootkey", .secret = "rootsecret", .principal = "rootkey" };

test "admin API over the store: users, policies, groups, service accounts" {
    var te: TestEnv = undefined;
    try te.init();
    defer te.deinit();
    const a = te.arena.allocator();

    // Encrypted add-user, then the new user cannot administer.
    const add_body = try sio.encryptWith(a, .pbkdf2_aes_gcm, "rootsecret",
        \\{"secretKey":"alicesecret","status":"enabled"}
    , @splat(3), @splat(4));
    try testing.expectEqual(std.http.Status.ok, (try te.call(root_caller, .PUT, "/minio/admin/v3/add-user?accessKey=alice", add_body)).status);
    const alice: Caller = .{ .access_key = "alice", .secret = "alicesecret", .principal = "alice" };
    try testing.expectEqual(std.http.Status.forbidden, (try te.call(alice, .GET, "/minio/admin/v3/list-users", "")).status);
    // Bad ciphertext is rejected.
    try testing.expectEqual(std.http.Status.bad_request, (try te.call(root_caller, .PUT, "/minio/admin/v3/add-user?accessKey=x", "junk")).status);

    // list-users response decrypts with the caller's secret.
    const lu = try te.call(root_caller, .GET, "/minio/admin/v3/list-users", "");
    const plain = try sio.decrypt(a, "rootsecret", lu.body);
    try testing.expect(std.mem.indexOf(u8, plain, "\"alice\":{\"status\":\"enabled\"}") != null);

    // Canned policy + attach via the encrypted builtin endpoint.
    try testing.expectEqual(std.http.Status.ok, (try te.call(root_caller, .PUT, "/minio/admin/v3/add-canned-policy?name=admins",
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]}]}
    )).status);
    const att = try sio.encryptWith(a, .pbkdf2_aes_gcm, "rootsecret",
        \\{"policies":["admins"],"user":"alice"}
    , @splat(5), @splat(6));
    const ar = try te.call(root_caller, .POST, "/minio/admin/v3/idp/builtin/policy/attach", att);
    try testing.expectEqual(std.http.Status.ok, ar.status);
    try testing.expect(std.mem.indexOf(u8, try sio.decrypt(a, "rootsecret", ar.body), "\"policiesAttached\":[\"admins\"]") != null);
    try testing.expectEqual(std.http.Status.bad_request, (try te.call(root_caller, .POST, "/minio/admin/v3/idp/builtin/policy/attach", att)).status);
    // Now alice holds admin:* and may list users.
    try testing.expectEqual(std.http.Status.ok, (try te.call(alice, .GET, "/minio/admin/v3/list-users", "")).status);
    const ui = try te.call(root_caller, .GET, "/minio/admin/v3/user-info?accessKey=alice", "");
    try testing.expectEqualStrings("{\"policyName\":\"admins\",\"status\":\"enabled\"}", ui.body);

    // Groups.
    try testing.expectEqual(std.http.Status.ok, (try te.call(root_caller, .PUT, "/minio/admin/v3/update-group-members",
        \\{"group":"devs","members":["alice"],"isRemove":false}
    )).status);
    const gi = try te.call(root_caller, .GET, "/minio/admin/v3/group?group=devs", "");
    try testing.expectEqualStrings("{\"name\":\"devs\",\"status\":\"enabled\",\"members\":[\"alice\"],\"policy\":\"\"}", gi.body);
    try testing.expectEqualStrings("[\"devs\"]", (try te.call(root_caller, .GET, "/minio/admin/v3/groups", "")).body);
    try testing.expectEqual(std.http.Status.bad_request, (try te.call(root_caller, .PUT, "/minio/admin/v3/update-group-members",
        \\{"group":"devs","members":[],"isRemove":true}
    )).status);

    // Self-service account for alice; key and secret generated.
    const sa_req = try sio.encryptWith(a, .pbkdf2_aes_gcm, "alicesecret", "{\"name\":\"ci\"}", @splat(7), @splat(8));
    const sr = try te.call(alice, .PUT, "/minio/admin/v3/add-service-account", sa_req);
    try testing.expectEqual(std.http.Status.ok, sr.status);
    const creds = parseObject(a, try sio.decrypt(a, "alicesecret", sr.body)).?.get("credentials").?.object;
    const key = str(creds, "accessKey").?;
    try testing.expectEqual(@as(usize, 20), key.len);
    const ls = try te.call(alice, .GET, "/minio/admin/v3/list-service-accounts", "");
    try testing.expect(std.mem.indexOf(u8, try sio.decrypt(a, "alicesecret", ls.body), key) != null);
    const del = try std.fmt.allocPrint(a, "/minio/admin/v3/delete-service-account?accessKey={s}", .{key});
    try testing.expectEqual(std.http.Status.no_content, (try te.call(alice, .DELETE, del, "")).status);

    // Errors are JSON with MinIO codes; unknown operations are NotImplemented.
    const nf = try te.call(root_caller, .DELETE, "/minio/admin/v3/remove-user?accessKey=ghost", "");
    try testing.expectEqual(std.http.Status.not_found, nf.status);
    try testing.expect(std.mem.indexOf(u8, nf.body, "XMinioAdminNoSuchUser") != null);
    try testing.expectEqual(std.http.Status.not_implemented, (try te.call(root_caller, .GET, "/minio/admin/v3/heal", "")).status);
    try testing.expectEqual(std.http.Status.method_not_allowed, (try te.call(root_caller, .GET, "/minio/admin/v3/add-user", "")).status);

    // Disabled user: status recorded; persisted state survives reopen.
    try testing.expectEqual(std.http.Status.ok, (try te.call(root_caller, .PUT, "/minio/admin/v3/set-user-status?accessKey=alice&status=disabled", "")).status);
    var re: iam.Store = undefined;
    try re.open(testing.allocator, te.mem.persistence(), .{ .root_access_key = "rootkey" });
    defer re.deinit();
    const v = re.view();
    defer v.release();
    try testing.expect(!v.user("alice").?.enabled);
    try testing.expectEqualStrings("devs", v.snap.groups[0].name);
}
