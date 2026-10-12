//! Admin config API for event and audit targets (`mc admin config set|get|reset
//! notify_*|audit_*`): set/get/del/help-config-kv for those subsystems.
const std = @import("std");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const notifier = @import("notifier.zig");
const settings = @import("settings.zig");
const kinds = @import("kinds.zig");
const store = @import("store.zig");

const Allocator = std.mem.Allocator;
const api = admin.api;
const Request = api.Request;
const Response = api.Response;
const Error = api.Error;

const targets_record = "targets";

fn allowed(store_: *iam.Store, a: Allocator, req: Request, action: []const u8) bool {
    const who = req.caller;
    if (who.tenant.len > 0) return false;
    var sp: ?iam.Policy = null;
    if (who.session_policy) |doc| sp = iam.policy.parse(a, doc) catch return false;
    const id: iam.Identity = .{ .access_key = who.principal, .session_policy = if (sp) |*p| p else null, .federated_policies = who.federated_policies };
    const ctx: iam.Context = .{ .now_s = req.now_s };
    return store_.authorize(id, action, iam.actions.admin_resource, &ctx).allowed();
}

fn ours(subsys: []const u8) bool {
    return kinds.bySubsys(subsys) != null;
}

/// First word of a config line, without `:id`.
fn subsysOf(line: []const u8) []const u8 {
    const t = std.mem.trim(u8, line, " \t\r\n");
    const w = t[0 .. std.mem.indexOfAny(u8, t, " \t\n") orelse t.len];
    return w[0 .. std.mem.indexOfScalar(u8, w, ':') orelse w.len];
}

/// Handles the request when it concerns an event or audit subsystem; null otherwise.
pub fn handle(n: *notifier.Notifier, a: Allocator, iam_store: *iam.Store, req: Request) Error!?Response {
    const op = req.target.op;
    const is_set = std.mem.eql(u8, op, "/set-config-kv");
    const is_del = std.mem.eql(u8, op, "/del-config-kv");
    const is_get = std.mem.eql(u8, op, "/get-config-kv");
    const is_help = std.mem.eql(u8, op, "/help-config-kv");
    if (!is_set and !is_del and !is_get and !is_help) return null;
    if (is_help) {
        const sub = try api.queryParam(a, req.target.query, "subSys") orelse return null;
        if (!ours(sub)) return null;
        return try help(a, sub);
    }
    if (is_get) {
        const key = try api.queryParam(a, req.target.query, "key") orelse return null;
        if (!ours(subsysOf(key))) return null;
        if (!allowed(iam_store, a, req, "admin:ConfigUpdate")) return try api.denied(a);
        return try get(n, a, req, key);
    }
    const plain = admin.sio.decrypt(a, req.caller.secret, req.body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (!ours(subsysOf(plain))) return null;
    if (!allowed(iam_store, a, req, "admin:ConfigUpdate")) return try api.denied(a);
    return try update(n, a, plain, is_del);
}

fn loadTable(n: *notifier.Notifier, a: Allocator) Error!?[]settings.Entry {
    const got = store.get(n.svc.store, a, store.key(.targets, targets_record)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StorageFailed => return null,
    };
    const text = got orelse "";
    return settings.parse(a, text) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => &.{},
    };
}

fn update(n: *notifier.Notifier, a: Allocator, plain: []const u8, del: bool) Error!Response {
    var table = try loadTable(n, a) orelse return api.fail(a, .service_unavailable, "XMinioServerNotInitialized", "configuration storage is unavailable");
    var lines = std.mem.splitScalar(u8, plain, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const e = settings.parseLine(a, line) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.UnknownKey => api.badRequest(a, "unknown key for this target type"),
            error.UnknownSubsys => api.badRequest(a, "unknown configuration subsystem"),
            error.InvalidConfig => api.badRequest(a, "malformed configuration line"),
        };
        if (del) {
            const head = line[0 .. std.mem.indexOfAny(u8, line, " \t") orelse line.len];
            const all = std.mem.indexOfScalar(u8, head, ':') == null;
            table = try settings.remove(a, table, e, all);
            continue;
        }
        const merged = try settings.merge(a, table, e);
        // Reject settings the target itself refuses before storing them.
        for (merged) |m| if (m.sameTarget(e) and m.enabled()) {
            const k = kinds.bySubsys(m.subsys).?;
            const client = k.create(a, m.settings()) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidConfig => api.badRequest(a, "invalid target settings"),
            };
            client.deinit();
        };
        table = merged;
    }
    const text = try settings.render(a, table, false);
    store.put(n.svc.store, store.key(.targets, targets_record), text) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StorageFailed => api.fail(a, .service_unavailable, "XMinioServerNotInitialized", "configuration storage is unavailable"),
    };
    try n.apply(text);
    return .{ .body = "", .config_applied = true };
}

fn get(n: *notifier.Notifier, a: Allocator, req: Request, key: []const u8) Error!Response {
    const table = try loadTable(n, a) orelse &.{};
    const sub = subsysOf(key);
    const id: ?[]const u8 = if (std.mem.indexOfScalar(u8, key, ':')) |c| key[c + 1 ..] else null;
    var picked: std.ArrayList(settings.Entry) = .empty;
    for (table) |e| {
        if (!std.mem.eql(u8, e.subsys, sub)) continue;
        if (id) |want| if (!std.mem.eql(u8, e.id, want)) continue;
        try picked.append(a, try withAllKeys(a, e));
    }
    for (n.opts.env_targets) |e| {
        if (!std.mem.eql(u8, e.subsys, sub)) continue;
        if (id) |want| if (!std.mem.eql(u8, e.id, want)) continue;
        try picked.append(a, try withAllKeys(a, e));
    }
    if (picked.items.len == 0 and id == null) try picked.append(a, try withAllKeys(a, .{ .subsys = sub, .kvs = &.{.{ .key = "enable", .value = "off" }} }));
    const text = try settings.render(a, picked.items, false);
    const ct = admin.sio.encryptAlg(a, req.kdf, req.caller.secret, text) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "payload encryption failed"),
    };
    return .{ .body = ct, .content_type = "application/octet-stream" };
}

/// Every key of the target type, set ones first, blank for the rest.
fn withAllKeys(a: Allocator, e: settings.Entry) Error!settings.Entry {
    const k = kinds.bySubsys(e.subsys) orelse return e;
    var kvs: std.ArrayList(settings.Kv) = .empty;
    try kvs.append(a, .{ .key = "enable", .value = if (e.enabled()) "on" else "off" });
    for (k.keys) |key| try kvs.append(a, .{ .key = key, .value = e.settings().get(key) });
    for ([_][]const u8{ "queue_dir", "queue_limit", "comment" }) |key| {
        const dup = for (k.keys) |x| {
            if (std.mem.eql(u8, x, key)) break true;
        } else false;
        if (!dup) try kvs.append(a, .{ .key = key, .value = e.settings().get(key) });
    }
    return .{ .subsys = e.subsys, .id = e.id, .kvs = kvs.items };
}

const KeyHelp = struct { key: []const u8, type: []const u8 = "string", description: []const u8 = "", optional: bool = true, multipleTargets: bool = false };

fn help(a: Allocator, sub: []const u8) Error!Response {
    const k = kinds.bySubsys(sub).?;
    var keys: std.ArrayList(KeyHelp) = .empty;
    try keys.append(a, .{ .key = "enable", .type = "on|off", .description = "enable or disable this target" });
    for (k.keys) |key| try keys.append(a, .{ .key = key });
    const body = std.json.Stringify.valueAlloc(a, .{
        .subSys = sub,
        .description = if (k.audit) "audit log target" else "bucket notification target",
        .multipleTargets = true,
        .keysHelp = keys.items,
    }, .{}) catch return error.OutOfMemory;
    return .{ .body = body };
}
