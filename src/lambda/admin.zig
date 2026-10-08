//! Admin config API for lambda targets (`mc admin config set|get|reset
//! lambda_webhook[:id] ...`): set/get/del/help-config-kv.
const std = @import("std");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const config = @import("config.zig");
const s3ext = @import("s3ext.zig");

const Allocator = std.mem.Allocator;
const api = admin.api;
const Request = api.Request;
const Response = api.Response;
const Error = api.Error;

fn allowed(store: *iam.Store, a: Allocator, req: Request) bool {
    const who = req.caller;
    if (who.tenant.len > 0) return false;
    var sp: ?iam.Policy = null;
    if (who.session_policy) |doc| sp = iam.policy.parse(a, doc) catch return false;
    const id: iam.Identity = .{ .access_key = who.principal, .session_policy = if (sp) |*p| p else null, .federated_policies = who.federated_policies };
    const ctx: iam.Context = .{ .now_s = req.now_s };
    return store.authorize(id, "admin:ConfigUpdate", iam.actions.admin_resource, &ctx).allowed();
}

/// First word of a config line, without `:id`.
fn subsysOf(line: []const u8) []const u8 {
    const t = std.mem.trim(u8, line, " \t\r\n");
    const w = t[0 .. std.mem.indexOfAny(u8, t, " \t\n") orelse t.len];
    return w[0 .. std.mem.indexOfScalar(u8, w, ':') orelse w.len];
}

fn ours(line: []const u8) bool {
    return std.mem.eql(u8, subsysOf(line), config.subsys);
}

/// Handles the request when it concerns `lambda_webhook`; null otherwise.
pub fn handle(reg: *s3ext.Registry, a: Allocator, store: *iam.Store, req: Request) Error!?Response {
    const op = req.target.op;
    const is_set = std.mem.eql(u8, op, "/set-config-kv");
    const is_del = std.mem.eql(u8, op, "/del-config-kv");
    const is_get = std.mem.eql(u8, op, "/get-config-kv");
    const is_help = std.mem.eql(u8, op, "/help-config-kv");
    if (is_help) {
        const sub = try api.queryParam(a, req.target.query, "subSys") orelse return null;
        if (!std.mem.eql(u8, sub, config.subsys)) return null;
        return try help(a);
    }
    if (is_get) {
        const key = try api.queryParam(a, req.target.query, "key") orelse return null;
        if (!ours(key)) return null;
        if (!allowed(store, a, req)) return try api.denied(a);
        return try get(reg, a, req, key);
    }
    if (!is_set and !is_del) return null;
    const plain = admin.sio.decrypt(a, req.caller.secret, req.body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (!ours(plain)) return null;
    if (!allowed(store, a, req)) return try api.denied(a);
    return try update(reg, a, plain, is_del);
}

fn unavailable(a: Allocator) Error!Response {
    return api.fail(a, .service_unavailable, "XMinioServerNotInitialized", "configuration storage is unavailable");
}

fn update(reg: *s3ext.Registry, a: Allocator, plain: []const u8, del: bool) Error!Response {
    var table = reg.stored(a) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StorageFailed => unavailable(a),
    };
    var lines = std.mem.splitScalar(u8, plain, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const t = config.parseLine(a, line) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnknownKey => api.badRequest(a, "unknown key for lambda_webhook"),
            error.UnknownSubsys => api.badRequest(a, "unknown configuration subsystem"),
            error.InvalidConfig => api.badRequest(a, "malformed configuration line"),
        };
        if (del) {
            const head = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
            table = try config.remove(a, table, if (std.mem.indexOfScalar(u8, head, ':') == null) null else t.id);
            continue;
        }
        const merged = try config.merge(a, table, t);
        for (merged) |m| if (std.mem.eql(u8, m.id, t.id) and m.enabled()) {
            _ = config.endpoint(a, m) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidConfig => api.badRequest(a, "invalid lambda target: need an http(s) endpoint; client certificates are not supported"),
            };
        };
        table = merged;
    }
    const text = try config.render(a, table, false);
    reg.save(text) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StorageFailed => unavailable(a),
    };
    return .{ .body = "", .config_applied = true };
}

fn withAllKeys(a: Allocator, t: config.Target) error{OutOfMemory}!config.Target {
    var kvs: std.ArrayList(config.Kv) = .empty;
    try kvs.append(a, .{ .key = "enable", .value = if (t.enabled()) "on" else "off" });
    for (config.keys[1..]) |k| try kvs.append(a, .{ .key = k, .value = t.get(k) });
    return .{ .id = t.id, .kvs = kvs.items };
}

fn get(reg: *s3ext.Registry, a: Allocator, req: Request, key: []const u8) Error!Response {
    const table = reg.stored(a) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StorageFailed => &.{},
    };
    const id: ?[]const u8 = if (std.mem.indexOfScalar(u8, key, ':')) |c| std.mem.trim(u8, key[c + 1 ..], " \t\r\n") else null;
    var picked: std.ArrayList(config.Target) = .empty;
    for ([_][]const config.Target{ table, reg.env_targets }) |list| for (list) |t| {
        if (id) |want| if (!std.mem.eql(u8, t.id, want)) continue;
        try picked.append(a, try withAllKeys(a, t));
    };
    if (picked.items.len == 0 and id == null) try picked.append(a, try withAllKeys(a, .{ .kvs = &.{.{ .key = "enable", .value = "off" }} }));
    const text = try config.render(a, picked.items, false);
    const ct = admin.sio.encrypt(a, req.caller.secret, text) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "payload encryption failed"),
    };
    return .{ .body = ct, .content_type = "application/octet-stream" };
}

const KeyHelp = struct { key: []const u8, type: []const u8 = "string", description: []const u8 = "", optional: bool = true, multipleTargets: bool = false };

fn help(a: Allocator) Error!Response {
    var ks: std.ArrayList(KeyHelp) = .empty;
    try ks.append(a, .{ .key = "enable", .type = "on|off", .description = "enable or disable this lambda target" });
    try ks.append(a, .{ .key = "endpoint", .description = "webhook server endpoint e.g. http://localhost:8080/minio/lambda", .optional = false });
    for (config.keys[2..]) |k| try ks.append(a, .{ .key = k });
    const body = std.json.Stringify.valueAlloc(a, .{
        .subSys = config.subsys,
        .description = "object lambda webhook target",
        .multipleTargets = true,
        .keysHelp = ks.items,
    }, .{}) catch return error.OutOfMemory;
    return .{ .body = body };
}
