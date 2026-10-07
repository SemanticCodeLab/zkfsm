//! KMS admin API at /minio/kms/v1/ (also /zkfsm/kms/v1/), as used by
//! `mc admin kms key create|list|status`, plus rotate, backup and restore.
//! Callers need the matching `kms:*` action, or root.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const kms = @import("../kms/root.zig");
const handler = @import("handler.zig");
const common = @import("common.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const Status = std.http.Status;

const prefixes = [_][]const u8{ "/minio/kms/v1", "/zkfsm/kms/v1" };

pub const KmsAdmin = struct {
    sse: *handler.SseExt,
    /// Null in anonymous mode, where the API is unavailable.
    store: ?*iam.Store,
    backend_name: []const u8,
    /// Key records for backups that carry key material (local, KV2).
    key_store: ?kms.keyring.KeyStore = null,

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
            .{ "/backup", .POST, "kms:Backup", backup },
            .{ "/restore", .POST, "kms:Restore", restore },
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
            .{ .Method = "POST", .Path = "/v1/backup" },     .{ .Method = "POST", .Path = "/v1/restore" },
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

    /// Manifest of all keys; with a backup key header, also the sealed key records.
    fn backup(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        var bk: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &bk);
        const has_key = (try backupKey(c, &bk)) orelse return true;
        const now = std.time.timestamp();
        var b = blk: {
            self.sse.mutex.lock();
            defer self.sse.mutex.unlock();
            break :blk kms.backup.exportBackup(c.arena, k, if (has_key) self.key_store else null, if (has_key) &bk else null, now) catch |e| return backupFail(c, e);
        };
        defer b.deinit(c.arena);
        if (has_key and b.bundle == null) return fail(c, .not_implemented, "NotImplemented", "This KMS backend keeps key material server-side; back up the backend itself.");
        const bundle: ?[]const u8 = if (b.bundle) |x| try b64Alloc(c, x) else null;
        return json(c, .{ .manifest = b.manifest, .bundle = bundle });
    }

    fn restore(self: *KmsAdmin, c: *Ctx, k: kms.Kms) ConnError!bool {
        var bk: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &bk);
        const has_key = (try backupKey(c, &bk)) orelse return true;
        const dry = if (try s3.handler.param(c, "dry-run")) |v| std.mem.eql(u8, v, "true") else false;
        var rejected: ?s3.errors.Code = null;
        const body = common.readBody(c, 16 * 1024 * 1024, &rejected) catch |e| switch (e) {
            error.TooLarge => return fail(c, .payload_too_large, "EntityTooLarge", "Backup document is too large."),
            error.Rejected => return fail(c, .forbidden, @tagName(rejected.?), "Request body rejected."),
            else => |ce| return ce,
        };
        const Doc = struct { manifest: []const u8, bundle: ?[]const u8 = null };
        const doc = std.json.parseFromSliceLeaky(Doc, c.arena, body, .{ .ignore_unknown_fields = true }) catch
            return fail(c, .bad_request, "XMinioKMSInvalidBackup", "Malformed backup document.");
        const bundle: ?[]u8 = if (doc.bundle) |b64| blk: {
            const dec = std.base64.standard.Decoder;
            const n = dec.calcSizeForSlice(b64) catch return fail(c, .bad_request, "XMinioKMSInvalidBackup", "Malformed bundle.");
            const out = try c.arena.alloc(u8, n);
            dec.decode(out, b64) catch return fail(c, .bad_request, "XMinioKMSInvalidBackup", "Malformed bundle.");
            break :blk out;
        } else null;
        self.sse.mutex.lock();
        defer self.sse.mutex.unlock();
        const r = kms.backup.restore(c.arena, doc.manifest, bundle, k, self.key_store, if (has_key) &bk else null, .{ .dry_run = dry }) catch |e| return backupFail(c, e);
        return json(c, .{ .restored = r.restored, .already_present = r.already_present, .missing = r.missing, .dry_run = dry });
    }
};

/// Optional `x-zkfsm-kms-backup-key` (64 hex chars); null after an error response.
fn backupKey(c: *Ctx, out: *[32]u8) ConnError!?bool {
    const v = try common.header(c, "x-zkfsm-kms-backup-key") orelse return false;
    if (v.len != 64) {
        _ = try fail(c, .bad_request, "XMinioKMSInvalidBackupKey", "The backup key must be 64 hex characters.");
        return null;
    }
    _ = std.fmt.hexToBytes(out, v) catch {
        _ = try fail(c, .bad_request, "XMinioKMSInvalidBackupKey", "The backup key must be 64 hex characters.");
        return null;
    };
    return true;
}

fn b64Alloc(c: *Ctx, bytes: []const u8) error{OutOfMemory}![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try c.arena.alloc(u8, enc.calcSize(bytes.len));
    return enc.encode(out, bytes);
}

fn backupFail(c: *Ctx, e: kms.backup.Error) ConnError!bool {
    return switch (e) {
        error.UnsupportedVersion, error.DigestMismatch, error.BadBundle => fail(c, .bad_request, "XMinioKMSInvalidBackup", @errorName(e)),
        error.BundleRequired => fail(c, .bad_request, "XMinioKMSInvalidBackup", "This backup carries key material; send the backup key and a backend that stores keys locally."),
        else => |ke| kmsFail(c, @errorCast(ke)),
    };
}

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
