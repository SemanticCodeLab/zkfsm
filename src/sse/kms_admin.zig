//! KMS admin API at /minio/kms/v1/ (also /zkfsm/kms/v1/), as used by
//! `mc admin kms key create|list|status`: status, version, key create, rotate,
//! list and status. Callers need the matching `kms:*` action, or root.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const kms = @import("../kms/root.zig");
const handler = @import("handler.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const Status = std.http.Status;

const prefixes = [_][]const u8{ "/minio/kms/v1", "/zkfsm/kms/v1" };

pub const KmsAdmin = struct {
    sse: *handler.SseExt,
    /// Null in anonymous mode, where the API is unavailable.
    store: ?*iam.Store,
    backend_name: []const u8,

    pub fn extension(self: *KmsAdmin) s3.Extension {
        return .{ .name = "kms-admin", .ctx = self, .route = route, .before_authz = true };
    }

    fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *KmsAdmin = @ptrCast(@alignCast(ptr));
        const path = std.mem.sliceTo(c.target, '?');
        const op = for (prefixes) |p| {
            if (std.mem.startsWith(u8, path, p) and (path.len == p.len or path[p.len] == '/')) break path[p.len..];
        } else return false;
        const store = self.store orelse return fail(c, .not_implemented, "NotImplemented", "The KMS API requires authenticated mode.");
        const ops = [_]struct { []const u8, std.http.Method, []const u8, *const fn (*KmsAdmin, *Ctx, kms.Kms) ConnError!bool }{
            .{ "/status", .GET, "kms:Status", status },
            .{ "/version", .GET, "kms:API", version },
            .{ "/apis", .GET, "kms:API", apis },
            .{ "/key/create", .POST, "kms:CreateKey", createKey },
            .{ "/key/rotate", .POST, "kms:CreateKey", rotateKey },
            .{ "/key/list", .GET, "kms:ListKeys", listKeys },
            .{ "/key/status", .GET, "kms:KeyStatus", keyStatus },
        };
        for (ops) |o| if (std.mem.eql(u8, op, o[0])) {
            if (c.method != o[1]) return fail(c, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
            if (!try allowed(c, store, o[2])) return fail(c, .forbidden, "AccessDenied", "Access Denied.");
            const k = self.sse.kms orelse return fail(c, .not_implemented, "XMinioKMSNotConfigured", "KMS is not configured.");
            return o[3](self, c, k);
        };
        return fail(c, .not_found, "XMinioKMSNotFound", "Unknown KMS API.");
    }

    fn status(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        _ = k;
        const State = struct { Version: []const u8 = "zkfsm", KeyStoreReachable: bool = true, KeystoreAvailable: bool = true };
        const Endpoints = struct {};
        return json(c, .{ .name = self.backend_name, .@"default-key-id" = self.sse.default_key, .endpoints = Endpoints{}, .state = State{} });
    }

    fn version(_: *KmsAdmin, c: *Ctx, _: kms.Kms) ConnError!bool {
        return json(c, .{ .version = "zkfsm" });
    }

    fn apis(_: *KmsAdmin, c: *Ctx, _: kms.Kms) ConnError!bool {
        const Api = struct { Method: []const u8, Path: []const u8, MaxBody: i64 = 0, Timeout: i64 = 0 };
        return json(c, [_]Api{
            .{ .Method = "GET", .Path = "/v1/status" },      .{ .Method = "GET", .Path = "/v1/version" },
            .{ .Method = "POST", .Path = "/v1/key/create" }, .{ .Method = "POST", .Path = "/v1/key/rotate" },
            .{ .Method = "GET", .Path = "/v1/key/list" },    .{ .Method = "GET", .Path = "/v1/key/status" },
        });
    }

    fn keyParam(c: *Ctx) ConnError!?[]const u8 {
        const id = try s3.handler.param(c, "key-id") orelse return null;
        return if (kms.types.validKeyName(id)) id else null;
    }

    fn createKey(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        const id = try keyParam(c) orelse return fail(c, .bad_request, "XMinioKMSInvalidKeyID", "A valid key-id is required.");
        self.sse.mutex.lock();
        defer self.sse.mutex.unlock();
        var ki = k.createKey(c.arena, id) catch |e| return kmsFail(c, e);
        ki.deinit(c.arena);
        return json(c, .{});
    }

    fn rotateKey(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        const id = try keyParam(c) orelse self.sse.default_key;
        self.sse.mutex.lock();
        defer self.sse.mutex.unlock();
        var ki = k.rotateKey(c.arena, id) catch |e| return kmsFail(c, e);
        ki.deinit(c.arena);
        return json(c, .{});
    }

    fn listKeys(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        const pattern = try s3.handler.param(c, "pattern") orelse "*";
        const list = blk: {
            self.sse.mutex.lock();
            defer self.sse.mutex.unlock();
            break :blk k.listKeys(c.arena) catch |e| return kmsFail(c, e);
        };
        const Item = struct { name: []const u8, createdAt: []const u8, createdBy: []const u8 = "" };
        var out: std.ArrayList(Item) = .empty;
        for (list) |ki| {
            if (!glob(pattern, ki.id)) continue;
            const ts = try c.arena.create([24]u8);
            try out.append(c.arena, .{ .name = ki.id, .createdAt = core.time.iso8601(@as(i128, ki.created_unix) * std.time.ns_per_s, ts) });
        }
        return json(c, out.items);
    }

    /// Round-trips a data key through the master key, as MinIO does.
    fn keyStatus(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        const id = (try s3.handler.param(c, "key-id")) orelse self.sse.default_key;
        const key_id = if (id.len == 0) self.sse.default_key else id;
        if (!kms.types.validKeyName(key_id)) return fail(c, .bad_request, "XMinioKMSInvalidKeyID", "Invalid key-id.");
        self.sse.mutex.lock();
        defer self.sse.mutex.unlock();
        const ctx: kms.Context = .{ .pairs = &.{.{ .key = "zkfsm:key-status", .value = key_id }} };
        var dk = k.generateDataKey(c.arena, key_id, ctx) catch |e| return json(c, .{ .@"key-id" = key_id, .@"encryption-error" = @errorName(e) });
        defer dk.deinit(c.arena);
        const back = k.decryptDataKey(c.arena, key_id, dk.sealed, ctx) catch |e| return json(c, .{ .@"key-id" = key_id, .@"decryption-error" = @errorName(e) });
        if (!std.mem.eql(u8, &back, &dk.plaintext)) return json(c, .{ .@"key-id" = key_id, .@"decryption-error" = "key mismatch" });
        return json(c, .{ .@"key-id" = key_id });
    }
};

fn allowed(c: *Ctx, store: *iam.Store, action: []const u8) ConnError!bool {
    if (c.auth.principal.len == 0 or c.tenant.len > 0) return false;
    var sp: ?iam.Policy = null;
    if (c.auth.session_policy) |doc| sp = iam.policy.parse(c.arena, doc) catch return false;
    const id: iam.Identity = .{ .access_key = c.auth.principal, .session_policy = if (sp) |*p| p else null, .federated_policies = c.auth.federated_policies };
    const ctx: iam.Context = .{ .now_s = std.time.timestamp() };
    return store.authorize(id, action, iam.actions.admin_resource, &ctx).allowed();
}

/// `*` matches any run of characters; everything else is literal.
fn glob(pattern: []const u8, s: []const u8) bool {
    const star = std.mem.indexOfScalar(u8, pattern, '*') orelse return std.mem.eql(u8, pattern, s);
    if (!std.mem.startsWith(u8, s, pattern[0..star])) return false;
    const rest = pattern[star + 1 ..];
    var i: usize = star;
    while (i <= s.len) : (i += 1) if (glob(rest, s[i..])) return true;
    return false;
}

fn json(c: *Ctx, v: anytype) ConnError!bool {
    const body = try std.json.Stringify.valueAlloc(c.arena, v, .{});
    try send(c, .ok, body);
    return true;
}

fn fail(c: *Ctx, st: Status, code: []const u8, message: []const u8) ConnError!bool {
    const body = try std.json.Stringify.valueAlloc(c.arena, .{ .Code = code, .Message = message, .Resource = std.mem.sliceTo(c.target, '?'), .RequestId = &c.request_id }, .{});
    try send(c, st, body);
    return true;
}

fn kmsFail(c: *Ctx, e: kms.Error) ConnError!bool {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.KeyExists => fail(c, .conflict, "XMinioKMSKeyExists", "The key already exists."),
        error.KeyNotFound => fail(c, .not_found, "XMinioKMSKeyNotFound", "The key does not exist."),
        error.InvalidArgument => fail(c, .bad_request, "XMinioKMSInvalidKeyID", "Invalid key-id."),
        error.Unsupported => fail(c, .not_implemented, "NotImplemented", "The KMS backend does not support this operation."),
        error.AccessDenied => fail(c, .forbidden, "AccessDenied", "The KMS backend denied the request."),
        else => fail(c, .internal_server_error, "XMinioKMSInternalError", @errorName(e)),
    };
}

fn send(c: *Ctx, st: Status, body: []const u8) ConnError!void {
    const hs = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    };
    try c.req.respond(body, .{ .status = st, .extra_headers = &hs });
}

test "glob" {
    try std.testing.expect(glob("*", "abc"));
    try std.testing.expect(glob("a*", "abc"));
    try std.testing.expect(glob("*c", "abc"));
    try std.testing.expect(!glob("b*", "abc"));
    try std.testing.expect(glob("abc", "abc"));
}
