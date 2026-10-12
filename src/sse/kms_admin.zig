//! KMS admin API at /minio/kms/v1/ (also /zkfsm/kms/v1/ and
//! /minio/admin/v3/kms/), as used by `mc admin kms key create|list|status`,
//! plus key lifecycle, tags, rekey, metrics, runtime config, backup and restore.
//! Callers need the matching `kms:*` action, or root.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const kms = @import("../kms/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const common = @import("common.zig");
const setup = @import("setup.zig");
const rekey = @import("kms_rekey.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const Status = std.http.Status;

const prefixes = [_][]const u8{ "/minio/kms/v1", "/zkfsm/kms/v1", "/minio/admin/v3/kms" };
const max_json_body = 64 * 1024;

const Handler = *const fn (*KmsAdmin, *Ctx) ConnError!bool;
const Op = struct { path: []const u8, method: std.http.Method, action: []const u8, h: Handler, needs_kms: bool = true };

const ops = [_]Op{
    .{ .path = "/status", .method = .GET, .action = "kms:Status", .h = KmsAdmin.status },
    .{ .path = "/metrics", .method = .GET, .action = "kms:Metrics", .h = KmsAdmin.metricsApi, .needs_kms = false },
    .{ .path = "/version", .method = .GET, .action = "kms:API", .h = KmsAdmin.version },
    .{ .path = "/apis", .method = .GET, .action = "kms:API", .h = KmsAdmin.apis },
    .{ .path = "/key/create", .method = .POST, .action = "kms:CreateKey", .h = KmsAdmin.createKey },
    .{ .path = "/key/rotate", .method = .POST, .action = "kms:CreateKey", .h = KmsAdmin.rotateKey },
    .{ .path = "/key/list", .method = .GET, .action = "kms:ListKeys", .h = KmsAdmin.listKeys },
    .{ .path = "/key/status", .method = .GET, .action = "kms:KeyStatus", .h = KmsAdmin.keyStatus },
    .{ .path = "/key/enable", .method = .POST, .action = "kms:EnableKey", .h = KmsAdmin.enableKey },
    .{ .path = "/key/disable", .method = .POST, .action = "kms:DisableKey", .h = KmsAdmin.disableKey },
    .{ .path = "/key/delete", .method = .DELETE, .action = "kms:DeleteKey", .h = KmsAdmin.deleteKey },
    .{ .path = "/key/delete", .method = .POST, .action = "kms:DeleteKey", .h = KmsAdmin.deleteKey },
    .{ .path = "/key/tags", .method = .GET, .action = "kms:KeyStatus", .h = KmsAdmin.getTags },
    .{ .path = "/key/tags", .method = .PUT, .action = "kms:TagKey", .h = KmsAdmin.putTags },
    .{ .path = "/key/tags", .method = .POST, .action = "kms:TagKey", .h = KmsAdmin.putTags },
    .{ .path = "/key/tags", .method = .DELETE, .action = "kms:TagKey", .h = KmsAdmin.clearTags },
    .{ .path = "/key/rekey", .method = .POST, .action = "kms:Rekey", .h = KmsAdmin.rekeyApi },
    .{ .path = "/config", .method = .GET, .action = "kms:Configure", .h = KmsAdmin.getConfig, .needs_kms = false },
    .{ .path = "/config", .method = .POST, .action = "kms:Configure", .h = KmsAdmin.setConfig, .needs_kms = false },
    .{ .path = "/backup", .method = .POST, .action = "kms:Backup", .h = KmsAdmin.backup },
    .{ .path = "/restore", .method = .POST, .action = "kms:Restore", .h = KmsAdmin.restore },
};

pub const KmsAdmin = struct {
    sse: *handler.SseExt,
    /// Null in anonymous mode, where the API is unavailable.
    store: ?*iam.Store,

    pub fn extension(self: *KmsAdmin) s3.Extension {
        return .{ .name = "kms-admin", .ctx = self, .route = route, .before_authz = true };
    }

    fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *KmsAdmin = @ptrCast(@alignCast(ptr));
        const path = std.mem.sliceTo(c.target, '?');
        const op_path = for (prefixes) |p| {
            if (std.mem.startsWith(u8, path, p) and (path.len == p.len or path[p.len] == '/')) break path[p.len..];
        } else return false;
        const store = self.store orelse return fail(c, .not_implemented, "NotImplemented", "The KMS API requires authenticated mode.");
        var known = false;
        for (ops) |o| if (std.mem.eql(u8, op_path, o.path)) {
            known = true;
            if (c.method != o.method) continue;
            if (!try allowed(c, store, o.action)) return fail(c, .forbidden, "AccessDenied", "Access Denied.");
            if (o.needs_kms) {
                _ = self.sse.lockKms() orelse return notConfigured(c);
                self.sse.unlockKms();
            }
            return o.h(self, c);
        };
        if (known) return fail(c, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
        return fail(c, .not_found, "XMinioKMSNotFound", "Unknown KMS API.");
    }

    fn status(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const a = self.sse.lockKms() orelse return notConfigured(c);
        const default_key = try c.arena.dupe(u8, a.default_key);
        self.sse.unlockKms();
        const State = struct { Version: []const u8 = "zkfsm", KeyStoreReachable: bool = true, KeystoreAvailable: bool = true };
        const Endpoints = struct {};
        return json(c, .{ .name = self.sse.backend_name, .@"default-key-id" = default_key, .endpoints = Endpoints{}, .state = State{} });
    }

    /// KES-style metrics document, plus per-operation counters and key counts.
    fn metricsApi(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const st = &self.sse.stats;
        const t = st.totals();
        var out: std.Io.Writer.Allocating = .init(c.arena);
        var js: std.json.Stringify = .{ .writer = &out.writer };
        writeMetrics(&js, st, t.ok, t.err, self.sse.backend_name) catch return error.OutOfMemory;
        try send(c, .ok, out.written());
        return true;
    }

    fn writeMetrics(js: *std.json.Stringify, st: *const kms.metered.Stats, ok: u64, err: u64, backend: []const u8) std.Io.Writer.Error!void {
        try js.beginObject();
        try js.objectField("kes_http_request_success");
        try js.write(ok);
        try js.objectField("kes_http_request_error");
        try js.write(err);
        try js.objectField("kes_http_request_failure");
        try js.write(0);
        try js.objectField("kes_http_request_active");
        try js.write(st.active.load(.monotonic));
        try js.objectField("kes_log_audit_events");
        try js.write(0);
        try js.objectField("kes_log_error_events");
        try js.write(err);
        try js.objectField("kes_http_response_time");
        try js.beginObject();
        var prev: u64 = 0;
        for (kms.metered.bucket_bounds_us, 0..) |b, i| {
            var cum: u64 = 0;
            for (&st.ops) |*o| cum += o.buckets[i].load(.monotonic);
            var nb: [24]u8 = undefined;
            try js.objectField(std.fmt.bufPrint(&nb, "{d}", .{b / 1000}) catch unreachable);
            try js.write(cum - @min(cum, prev));
            prev = cum;
        }
        try js.endObject();
        try js.objectField("kes_system_up_time");
        try js.write(@max(0, std.time.timestamp() - st.started_s));
        try js.objectField("kes_system_num_cpu");
        try js.write(std.Thread.getCpuCount() catch 1);
        try js.objectField("kes_system_num_cpu_used");
        try js.write(std.Thread.getCpuCount() catch 1);
        try js.objectField("kes_system_mem_heap_used");
        try js.write(0);
        try js.objectField("kes_system_mem_stack_used");
        try js.write(0);
        try js.objectField("backend");
        try js.write(backend);
        try js.objectField("operations");
        try js.beginObject();
        for (&st.ops, 0..) |*o, i| {
            try js.objectField(@tagName(@as(kms.metered.Op, @enumFromInt(i))));
            try js.write(.{ .requests = o.requests.load(.monotonic), .errors = o.errors.load(.monotonic), .latency_sum_us = o.latency_sum_us.load(.monotonic) });
        }
        try js.endObject();
        try js.objectField("keys");
        try js.write(.{ .enabled = @max(0, st.keys_enabled.load(.monotonic)), .disabled = @max(0, st.keys_disabled.load(.monotonic)) });
        try js.objectField("reconfigurations");
        try js.write(st.reconfigs.load(.monotonic));
        try js.objectField("rekeyed_objects");
        try js.write(st.rekeyed_objects.load(.monotonic));
        try js.endObject();
    }

    fn version(_: *KmsAdmin, c: *Ctx) ConnError!bool {
        return json(c, .{ .version = "zkfsm" });
    }

    fn apis(_: *KmsAdmin, c: *Ctx) ConnError!bool {
        const Api = struct { Method: []const u8, Path: []const u8, MaxBody: i64 = 0, Timeout: i64 = 0 };
        var out: [ops.len]Api = undefined;
        inline for (ops, 0..) |o, i| out[i] = .{ .Method = @tagName(o.method), .Path = "/v1" ++ o.path };
        return json(c, out);
    }

    fn keyParam(c: *Ctx) ConnError!?[]const u8 {
        const id = try s3.handler.param(c, "key-id") orelse return null;
        return if (kms.types.validKeyName(id)) id else null;
    }

    fn requireKey(c: *Ctx) ConnError!?[]const u8 {
        if (try keyParam(c)) |id| return id;
        _ = try fail(c, .bad_request, "XMinioKMSInvalidKeyID", "A valid key-id is required.");
        return null;
    }

    fn createKey(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        var ki = a.kms.createKey(c.arena, id) catch |e| return kmsFail(c, e);
        ki.deinit(c.arena);
        return json(c, .{});
    }

    fn rotateKey(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const given = try keyParam(c);
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        var ki = a.kms.rotateKey(c.arena, given orelse a.default_key) catch |e| return kmsFail(c, e);
        ki.deinit(c.arena);
        return json(c, .{});
    }

    fn listKeys(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const pattern = try s3.handler.param(c, "pattern") orelse "*";
        const want: ?kms.types.KeyState = if (try s3.handler.param(c, "state")) |v| kms.types.KeyState.parse(v) else null;
        const list = blk: {
            const a = self.sse.lockKms() orelse return notConfigured(c);
            defer self.sse.unlockKms();
            break :blk a.kms.listKeys(c.arena) catch |e| return kmsFail(c, e);
        };
        const Item = struct { name: []const u8, createdAt: []const u8, createdBy: []const u8 = "", state: []const u8, version: u32 };
        var out: std.ArrayList(Item) = .empty;
        for (list) |ki| {
            if (!glob(pattern, ki.id)) continue;
            if (want) |w| if (ki.state != w) continue;
            const ts = try c.arena.create([24]u8);
            try out.append(c.arena, .{ .name = ki.id, .createdAt = core.time.iso8601(@as(i128, ki.created_unix) * std.time.ns_per_s, ts), .state = ki.state.text(), .version = ki.version });
        }
        return json(c, out.items);
    }

    /// Round-trips a data key through the master key, as MinIO does.
    fn keyStatus(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const given = (try s3.handler.param(c, "key-id")) orelse "";
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        const key_id = if (given.len == 0) try c.arena.dupe(u8, a.default_key) else given;
        if (!kms.types.validKeyName(key_id)) return fail(c, .bad_request, "XMinioKMSInvalidKeyID", "Invalid key-id.");
        const state: []const u8 = if (a.kms.keyStatus(c.arena, key_id)) |ki| ki.state.text() else |_| "unknown";
        const ctx: kms.Context = .{ .pairs = &.{.{ .key = "zkfsm:key-status", .value = key_id }} };
        var dk = a.kms.generateDataKey(c.arena, key_id, ctx) catch |e| return json(c, .{ .@"key-id" = key_id, .state = state, .@"encryption-error" = @errorName(e) });
        defer dk.deinit(c.arena);
        const back = a.kms.decryptDataKey(c.arena, key_id, dk.sealed, ctx) catch |e| return json(c, .{ .@"key-id" = key_id, .state = state, .@"decryption-error" = @errorName(e) });
        if (!std.crypto.timing_safe.eql([kms.types.dek_len]u8, back, dk.plaintext)) return json(c, .{ .@"key-id" = key_id, .state = state, .@"decryption-error" = "key mismatch" });
        return json(c, .{ .@"key-id" = key_id, .state = state });
    }

    fn enableKey(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        return self.setState(c, .enabled);
    }

    /// A disabled key cannot seal new data keys; existing objects stay readable.
    fn disableKey(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        return self.setState(c, .disabled);
    }

    fn setState(self: *KmsAdmin, c: *Ctx, state: kms.types.KeyState) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        a.kms.setKeyState(c.arena, id, state) catch |e| return kmsFail(c, e);
        return json(c, .{ .@"key-id" = id, .state = state.text() });
    }

    /// Refuses while the key is the default, a bucket default, or seals any
    /// object version (or the scan was incomplete), unless `force=true`.
    fn deleteKey(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        const force = if (try s3.handler.param(c, "force")) |v| std.mem.eql(u8, v, "true") else false;
        const is_default = blk: {
            const a = self.sse.lockKms() orelse return notConfigured(c);
            defer self.sse.unlockKms();
            var ki = a.kms.keyStatus(c.arena, id) catch |e| return kmsFail(c, e);
            ki.deinit(c.arena);
            break :blk std.mem.eql(u8, a.default_key, id);
        };
        const use = rekey.keyUsage(c.svc, c.arena, id) catch |e| return objFail(c, e);
        const in_use = is_default or use.buckets.items.len > 0 or use.objects > 0 or use.incomplete;
        if (in_use and !force) {
            const body = try std.json.Stringify.valueAlloc(c.arena, .{
                .Code = "XMinioKMSKeyInUse",
                .Message = "The key is still in use; re-key the objects or pass force=true.",
                .@"key-id" = id,
                .default = is_default,
                .buckets = use.buckets.items,
                .objects = use.objects,
                .scan_incomplete = use.incomplete,
            }, .{});
            try send(c, .conflict, body);
            return true;
        }
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        a.kms.deleteKey(c.arena, id) catch |e| return kmsFail(c, e);
        return json(c, .{ .@"key-id" = id, .deleted = true, .forced = in_use, .objects = use.objects });
    }

    fn getTags(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        const tags = a.kms.keyTags(c.arena, id) catch |e| return kmsFail(c, e);
        var out: std.Io.Writer.Allocating = .init(c.arena);
        var js: std.json.Stringify = .{ .writer = &out.writer };
        writeTags(&js, id, tags) catch return error.OutOfMemory;
        try send(c, .ok, out.written());
        return true;
    }

    fn writeTags(js: *std.json.Stringify, id: []const u8, tags: []const kms.types.Tag) std.Io.Writer.Error!void {
        try js.beginObject();
        try js.objectField("key-id");
        try js.write(id);
        try js.objectField("tags");
        try js.beginObject();
        for (tags) |t| {
            try js.objectField(t.key);
            try js.write(t.value);
        }
        try js.endObject();
        try js.endObject();
    }

    /// Body `{"tags":{"k":"v",...}}` replaces the whole tag set.
    fn putTags(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        const body = try readJsonBody(c) orelse return true;
        const v = std.json.parseFromSliceLeaky(std.json.Value, c.arena, body, .{}) catch return fail(c, .bad_request, "XMinioKMSInvalidTags", "Malformed tag document.");
        const obj = if (v == .object) v.object.get("tags") orelse v else return fail(c, .bad_request, "XMinioKMSInvalidTags", "Malformed tag document.");
        if (obj != .object or obj.object.count() > kms.types.max_tags) return fail(c, .bad_request, "XMinioKMSInvalidTags", "Tags must be an object of at most 50 strings.");
        const tags = try c.arena.alloc(kms.types.Tag, obj.object.count());
        for (obj.object.keys(), obj.object.values(), tags) |k, val, *t| {
            if (val != .string) return fail(c, .bad_request, "XMinioKMSInvalidTags", "Tag values must be strings.");
            t.* = .{ .key = @constCast(k), .value = @constCast(val.string) };
        }
        return self.applyTags(c, id, tags);
    }

    fn clearTags(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const id = try requireKey(c) orelse return true;
        return self.applyTags(c, id, &.{});
    }

    fn applyTags(self: *KmsAdmin, c: *Ctx, id: []const u8, tags: []const kms.types.Tag) ConnError!bool {
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        a.kms.setKeyTags(c.arena, id, tags) catch |e| return kmsFail(c, e);
        return json(c, .{ .@"key-id" = id, .tags = tags.len });
    }

    /// One page: `bucket` (required), `prefix`, `key-id` (target, default
    /// key if absent), `from-key-id`, `marker`, `version-marker`, `max-keys`.
    fn rekeyApi(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const bucket = try s3.handler.param(c, "bucket") orelse return fail(c, .bad_request, "InvalidArgument", "bucket is required.");
        if (!object.service.validBucketName(bucket)) return fail(c, .bad_request, "InvalidBucketName", "Invalid bucket name.");
        const from = try s3.handler.param(c, "from-key-id");
        if (from) |f| if (!kms.types.validKeyName(f)) return fail(c, .bad_request, "XMinioKMSInvalidKeyID", "Invalid from-key-id.");
        const target = if (try s3.handler.param(c, "key-id")) |t| blk: {
            if (!kms.types.validKeyName(t)) return fail(c, .bad_request, "XMinioKMSInvalidKeyID", "Invalid key-id.");
            break :blk t;
        } else blk: {
            const a = self.sse.lockKms() orelse return notConfigured(c);
            defer self.sse.unlockKms();
            break :blk try c.arena.dupe(u8, a.default_key);
        };
        const max = if (try s3.handler.param(c, "max-keys")) |m| std.fmt.parseInt(usize, m, 10) catch return fail(c, .bad_request, "InvalidArgument", "Invalid max-keys.") else 1000;
        const vm: ?core.VersionId = if (try s3.handler.param(c, "version-marker")) |v|
            object.versioning.parseVersionId(v) catch return fail(c, .bad_request, "InvalidArgument", "Invalid version-marker.")
        else
            null;
        {
            // The target must accept new data keys before any object is touched.
            const a = self.sse.lockKms() orelse return notConfigured(c);
            defer self.sse.unlockKms();
            var probe: [kms.types.dek_len]u8 = @splat(0);
            var dk = a.kms.sealDataKey(c.arena, target, &probe, .{}) catch |e| return kmsFail(c, e);
            dk.deinit(c.arena);
        }
        const r = rekey.rekeyPage(self.sse, c.svc, c.arena, .{
            .bucket = bucket,
            .prefix = try s3.handler.param(c, "prefix") orelse "",
            .target_key = target,
            .from_key = from,
            .key_marker = try s3.handler.param(c, "marker") orelse "",
            .version_marker = vm,
            .max = max,
        }) catch |e| switch (e) {
            error.KmsNotConfigured => return notConfigured(c),
            else => |oe| return objFail(c, oe),
        };
        return json(c, .{
            .bucket = bucket,
            .@"key-id" = target,
            .scanned = r.scanned,
            .rekeyed = r.rekeyed,
            .skipped = r.skipped,
            .changed = r.changed,
            .failed = r.failed,
            .@"first-error" = r.first_error,
            .truncated = r.truncated,
            .@"next-marker" = r.next_key_marker,
            .@"next-version-marker" = r.next_version_marker,
        });
    }

    /// Current backend settings; secrets are never returned.
    fn getConfig(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        self.sse.mutex.lock();
        defer self.sse.mutex.unlock();
        const h = self.sse.holder orelse return json(c, .{ .backend = "none" });
        const sp = h.spec;
        return json(c, .{
            .backend = sp.backend.text(),
            .@"default-key-id" = h.default_key,
            .dir = if (sp.backend == .local) sp.dir else null,
            .vault = if (sp.backend == .vault) .{
                .addr = sp.vault.addr,
                .engine = sp.vault.engine,
                .namespace = sp.vault.namespace,
                .auth = if (sp.vault.token != null) "token" else "approle",
            } else null,
            .@"kms-api" = if (sp.backend == .kms_api) .{ .region = sp.kms_api.region, .endpoint = sp.kms_api.endpoint } else null,
        });
    }

    /// Opens and validates the new backend, then swaps it in; the old one
    /// keeps serving until the swap and is closed after in-flight calls end.
    fn setConfig(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        const body = try readJsonBody(c) orelse return true;
        defer std.crypto.secureZero(u8, body);
        const Wire = struct {
            backend: []const u8,
            default_key: ?[]const u8 = null,
            dir: ?[]const u8 = null,
            secret_key: ?[]const u8 = null,
            vault: setup.VaultSpec = .{},
            kms_api: setup.ApiSpec = .{},
        };
        const w = std.json.parseFromSliceLeaky(Wire, c.arena, body, .{ .allocate = .alloc_always }) catch
            return fail(c, .bad_request, "XMinioKMSConfigInvalid", "Malformed KMS configuration.");
        var spec: setup.Spec = .{
            .backend = setup.Backend.parse(w.backend) orelse return fail(c, .bad_request, "XMinioKMSConfigInvalid", "Unknown backend."),
            .secret_key = w.secret_key,
            .vault = w.vault,
            .kms_api = w.kms_api,
        };
        defer spec.wipeSecrets();
        if (w.dir) |d| spec.dir = d;
        if (w.default_key) |k| {
            if (!kms.types.validKeyName(k)) return fail(c, .bad_request, "XMinioKMSConfigInvalid", "Invalid default_key.");
            spec.default_key = k;
            spec.default_key_set = true;
        }
        const h = setup.Holder.create(self.sse.gpa, spec) catch |e| {
            _ = self.sse.stats.reconfig_failures.fetchAdd(1, .monotonic);
            return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.MissingConfig => fail(c, .bad_request, "XMinioKMSConfigInvalid", "The configuration is incomplete for this backend."),
                error.BackendFailed => fail(c, .bad_request, "XMinioKMSConfigInvalid", "The backend could not be opened."),
                error.ValidationFailed => fail(c, .bad_request, "XMinioKMSConfigInvalid", "The backend failed a data key round trip with the default key."),
            };
        };
        self.sse.swap(h);
        _ = self.sse.stats.reconfigs.fetchAdd(1, .monotonic);
        std.log.info("kms: reconfigured to backend {s}, default key {s}", .{ spec.backend.text(), h.default_key });
        return json(c, .{ .backend = spec.backend.text(), .@"default-key-id" = h.default_key, .applied = true });
    }

    /// Manifest of all keys; with a backup key header, also the sealed key records.
    fn backup(self: *KmsAdmin, c: *Ctx) ConnError!bool {
        var bk: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &bk);
        const has_key = (try backupKey(c, &bk)) orelse return true;
        const now = std.time.timestamp();
        var b = blk: {
            const a = self.sse.lockKms() orelse return notConfigured(c);
            defer self.sse.unlockKms();
            const ks = if (a.holder) |h| h.key_store else null;
            break :blk kms.backup.exportBackup(c.arena, a.kms, if (has_key) ks else null, if (has_key) &bk else null, now) catch |e| return backupFail(c, e);
        };
        defer b.deinit(c.arena);
        if (has_key and b.bundle == null) return fail(c, .not_implemented, "NotImplemented", "This KMS backend keeps key material server-side; back up the backend itself.");
        const bundle: ?[]const u8 = if (b.bundle) |x| try b64Alloc(c, x) else null;
        return json(c, .{ .manifest = b.manifest, .bundle = bundle });
    }

    fn restore(self: *KmsAdmin, c: *Ctx) ConnError!bool {
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
        const a = self.sse.lockKms() orelse return notConfigured(c);
        defer self.sse.unlockKms();
        const ks = if (a.holder) |h| h.key_store else null;
        const r = kms.backup.restore(c.arena, doc.manifest, bundle, a.kms, ks, if (has_key) &bk else null, .{ .dry_run = dry }) catch |e| return backupFail(c, e);
        return json(c, .{ .restored = r.restored, .already_present = r.already_present, .missing = r.missing, .dry_run = dry });
    }
};

/// Bounded JSON body; null after an error response was sent.
fn readJsonBody(c: *Ctx) ConnError!?[]u8 {
    var rejected: ?s3.errors.Code = null;
    return common.readBody(c, max_json_body, &rejected) catch |e| switch (e) {
        error.TooLarge => {
            _ = try fail(c, .payload_too_large, "EntityTooLarge", "Request body is too large.");
            return null;
        },
        error.Rejected => {
            _ = try fail(c, .forbidden, @tagName(rejected.?), "Request body rejected.");
            return null;
        },
        else => |ce| return ce,
    };
}

fn notConfigured(c: *Ctx) ConnError!bool {
    return fail(c, .not_implemented, "XMinioKMSNotConfigured", "KMS is not configured.");
}

fn objFail(c: *Ctx, e: object.Error) ConnError!bool {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchBucket => fail(c, .not_found, "NoSuchBucket", "The specified bucket does not exist."),
        error.InvalidBucketName => fail(c, .bad_request, "InvalidBucketName", "Invalid bucket name."),
        else => fail(c, .internal_server_error, "InternalError", @errorName(e)),
    };
}

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
        error.KeyDisabled => fail(c, .conflict, "XMinioKMSKeyDisabled", "The key is disabled."),
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
