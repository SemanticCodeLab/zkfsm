//! Chooses and opens the KMS backend (static, local, vault, kms-api) from
//! --kms-* flags and the environment; see `usage` and README "Server-side
//! encryption and KMS" for the variables each backend reads.
const std = @import("std");
const kms = @import("../kms/root.zig");
const tls = @import("../tls/root.zig");

pub const Backend = enum {
    none,
    static,
    local,
    vault,
    kms_api,

    pub fn parse(s: []const u8) ?Backend {
        if (std.mem.eql(u8, s, "kms-api")) return .kms_api;
        if (std.mem.eql(u8, s, "kms_api")) return null;
        return std.meta.stringToEnum(Backend, s);
    }

    pub fn text(b: Backend) []const u8 {
        return if (b == .kms_api) "kms-api" else @tagName(b);
    }
};

pub const Flags = struct {
    backend: Backend = .none,
    dir: []const u8 = "./.zkfsm-kms",
    secret_key: ?[]const u8 = null,
    /// Key for SSE-S3 and for aws:kms requests without a key id.
    default_key: []const u8 = "zkfsm-sse-s3",
    default_key_set: bool = false,

    pub fn isFlag(flag: []const u8) bool {
        return std.mem.startsWith(u8, flag, "--kms-");
    }

    /// Accepts one `--kms-*` flag; false if the flag or value is unknown.
    pub fn set(f: *Flags, flag: []const u8, value: []const u8) bool {
        if (std.mem.eql(u8, flag, "--kms-backend")) {
            f.backend = Backend.parse(value) orelse return false;
        } else if (std.mem.eql(u8, flag, "--kms-dir")) {
            f.dir = value;
        } else if (std.mem.eql(u8, flag, "--kms-secret-key")) {
            f.secret_key = value;
        } else if (std.mem.eql(u8, flag, "--kms-default-key")) {
            if (!kms.types.validKeyName(value)) return false;
            f.default_key = value;
            f.default_key_set = true;
        } else return false;
        return true;
    }

    /// Fills unset values from the environment; a secret key alone selects `static`.
    pub fn applyEnv(f: *Flags, gpa: std.mem.Allocator) bool {
        var ok = true;
        if (f.backend == .none) if (env(gpa, "ZKFSM_KMS_BACKEND")) |v| {
            ok = ok and f.set("--kms-backend", v);
        };
        if (f.secret_key == null) f.secret_key = env(gpa, "ZKFSM_KMS_SECRET_KEY") orelse env(gpa, "MINIO_KMS_SECRET_KEY");
        if (std.mem.eql(u8, f.dir, "./.zkfsm-kms")) if (env(gpa, "ZKFSM_KMS_DIR")) |v| {
            f.dir = v;
        };
        if (!f.default_key_set) if (env(gpa, "ZKFSM_KMS_DEFAULT_KEY")) |v| {
            ok = ok and f.set("--kms-default-key", v);
        };
        if (f.backend == .none and f.secret_key != null) f.backend = .static;
        return ok;
    }
};

pub const usage =
    \\kms and server-side encryption (SSE-C works without a KMS):
    \\  --kms-backend      static | local | vault | kms-api (default: $ZKFSM_KMS_BACKEND, else
    \\                     static when a secret key is set, else none)
    \\  --kms-secret-key   static master key <name>:<base64 32 bytes>
    \\                     (or $ZKFSM_KMS_SECRET_KEY / $MINIO_KMS_SECRET_KEY)
    \\  --kms-dir          key directory for the local development backend
    \\                     (default: $ZKFSM_KMS_DIR, else ./.zkfsm-kms)
    \\  --kms-default-key  key for SSE-S3 and default aws:kms (default: zkfsm-sse-s3,
    \\                     or the static key's name)
    \\
;

fn env(gpa: std.mem.Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(gpa, name) catch null;
}

pub const InitError = error{ MissingConfig, BackendFailed, ValidationFailed, OutOfMemory };

pub const VaultSpec = struct {
    addr: ?[]const u8 = null,
    token: ?[]const u8 = null,
    role_id: ?[]const u8 = null,
    secret_id: ?[]const u8 = null,
    namespace: ?[]const u8 = null,
    ca_file: ?[]const u8 = null,
    client_cert: ?[]const u8 = null,
    client_key: ?[]const u8 = null,
    tls_server_name: ?[]const u8 = null,
    skip_verify: ?[]const u8 = null,
    cert_mount: ?[]const u8 = null,
    cert_role: ?[]const u8 = null,
    engine: []const u8 = "transit",
};

pub const ApiSpec = struct {
    region: ?[]const u8 = null,
    endpoint: ?[]const u8 = null,
    access_key: ?[]const u8 = null,
    secret_key: ?[]const u8 = null,
    session_token: ?[]const u8 = null,
};

/// Complete backend description: from flags plus environment at startup, or
/// from a JSON document for runtime reconfiguration.
pub const Spec = struct {
    backend: Backend = .none,
    default_key: []const u8 = "zkfsm-sse-s3",
    default_key_set: bool = false,
    dir: []const u8 = "./.zkfsm-kms",
    secret_key: ?[]const u8 = null,
    vault: VaultSpec = .{},
    kms_api: ApiSpec = .{},

    pub fn fromFlags(gpa: std.mem.Allocator, f: Flags) Spec {
        var s: Spec = .{ .backend = f.backend, .default_key = f.default_key, .default_key_set = f.default_key_set, .dir = f.dir, .secret_key = f.secret_key };
        switch (f.backend) {
            .vault => s.vault = .{
                .addr = env(gpa, "VAULT_ADDR"),
                .token = env(gpa, "VAULT_TOKEN"),
                .role_id = env(gpa, "VAULT_ROLE_ID"),
                .secret_id = env(gpa, "VAULT_SECRET_ID"),
                .namespace = env(gpa, "VAULT_NAMESPACE"),
                .ca_file = env(gpa, "VAULT_CACERT") orelse env(gpa, "KMS_VAULT_CAPATH"),
                .client_cert = env(gpa, "VAULT_CLIENT_CERT"),
                .client_key = env(gpa, "VAULT_CLIENT_KEY"),
                .tls_server_name = env(gpa, "VAULT_TLS_SERVER_NAME"),
                .skip_verify = env(gpa, "VAULT_SKIP_VERIFY"),
                .cert_mount = env(gpa, "VAULT_CERT_AUTH_MOUNT"),
                .cert_role = env(gpa, "VAULT_CERT_ROLE"),
                .engine = env(gpa, "ZKFSM_KMS_VAULT_ENGINE") orelse "transit",
            },
            .kms_api => s.kms_api = .{
                .region = env(gpa, "AWS_REGION") orelse env(gpa, "AWS_DEFAULT_REGION"),
                .endpoint = env(gpa, "ZKFSM_KMS_API_ENDPOINT"),
                .access_key = env(gpa, "AWS_ACCESS_KEY_ID"),
                .secret_key = env(gpa, "AWS_SECRET_ACCESS_KEY"),
                .session_token = env(gpa, "AWS_SESSION_TOKEN"),
            },
            else => {},
        }
        return s;
    }

    /// Deep copy into `a`.
    fn dupe(s: Spec, a: std.mem.Allocator) error{OutOfMemory}!Spec {
        var out = s;
        out.default_key = try a.dupe(u8, s.default_key);
        out.dir = try a.dupe(u8, s.dir);
        out.secret_key = try dupeOpt(a, s.secret_key);
        inline for (std.meta.fields(VaultSpec)) |fd| {
            if (fd.type == ?[]const u8) @field(out.vault, fd.name) = try dupeOpt(a, @field(s.vault, fd.name));
        }
        out.vault.engine = try a.dupe(u8, s.vault.engine);
        inline for (std.meta.fields(ApiSpec)) |fd| @field(out.kms_api, fd.name) = try dupeOpt(a, @field(s.kms_api, fd.name));
        return out;
    }

    pub fn wipeSecrets(s: *Spec) void {
        const secrets = [_]?[]const u8{ s.secret_key, s.vault.token, s.vault.secret_id, s.kms_api.secret_key, s.kms_api.session_token };
        for (secrets) |v| if (v) |x| std.crypto.secureZero(u8, @constCast(x));
    }
};

fn dupeOpt(a: std.mem.Allocator, v: ?[]const u8) error{OutOfMemory}!?[]const u8 {
    return if (v) |x| try a.dupe(u8, x) else null;
}

/// Owns the selected backend and copies of its configuration. The startup
/// holder lives for the process; reconfigured holders are freed when replaced.
pub const Holder = struct {
    arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator),
    spec: Spec = .{},
    local: kms.local.LocalKms = undefined,
    vault_client: kms.vault.Client = undefined,
    transit: kms.vault.TransitKms = undefined,
    kv2: kms.vault.Kv2Kms = undefined,
    static: kms.static.StaticKms = undefined,
    api: kms.kms_api.KmsApi = undefined,
    /// Unwrapped backend handle.
    handle: ?kms.Kms = null,
    /// Counting wrapper over `handle`, set by `SseExt.attach`.
    metered: kms.metered.Metered = undefined,
    /// Key records of locally wrapped backends (local, KV2), for backups.
    key_store: ?kms.keyring.KeyStore = null,
    default_key: []const u8 = "",
    /// Allocated by `create`; freed by `destroy`.
    heap: bool = false,

    /// `self` must not move after init.
    pub fn init(self: *Holder, gpa: std.mem.Allocator, f: Flags) InitError!void {
        return self.open(gpa, Spec.fromFlags(gpa, f), false);
    }

    /// Heap holder for a runtime reconfiguration, validated end to end.
    pub fn create(gpa: std.mem.Allocator, spec: Spec) InitError!*Holder {
        if (spec.backend == .none) return error.MissingConfig;
        const h = try gpa.create(Holder);
        h.* = .{ .arena = .init(gpa), .heap = true };
        h.open(gpa, spec, true) catch |e| {
            h.destroy(gpa);
            return e;
        };
        return h;
    }

    pub fn destroy(self: *Holder, gpa: std.mem.Allocator) void {
        if (self.handle != null) switch (self.spec.backend) {
            .local => self.local.deinit(),
            .vault => self.vault_client.deinit(),
            .kms_api => self.api.deinit(),
            .static => std.crypto.secureZero(u8, &self.static.key),
            .none => {},
        };
        self.spec.wipeSecrets();
        self.arena.deinit();
        if (self.heap) gpa.destroy(self);
    }

    fn open(self: *Holder, gpa: std.mem.Allocator, spec0: Spec, strict: bool) InitError!void {
        const spec = try spec0.dupe(self.arena.allocator());
        self.spec = spec;
        self.default_key = spec.default_key;
        if (!kms.types.validKeyName(spec.default_key)) return error.MissingConfig;
        switch (spec.backend) {
            .none => return,
            .static => {
                self.static.init(spec.secret_key orelse return error.MissingConfig) catch return error.MissingConfig;
                if (!spec.default_key_set) self.default_key = self.static.name;
                self.handle = self.static.kms();
                self.spec.default_key = self.default_key;
                if (strict) try self.validate(gpa);
                return;
            },
            .local => {
                self.local.init(spec.dir) catch return error.BackendFailed;
                self.handle = self.local.kms();
                self.key_store = self.local.files.keyStore();
            },
            .vault => {
                const v = spec.vault;
                const addr = v.addr orelse return error.MissingConfig;
                const tls_opts: tls.TlsOptions = .{
                    .ca_file = v.ca_file orelse "",
                    .client_cert_file = v.client_cert orelse "",
                    .client_key_file = v.client_key orelse "",
                    .server_name = v.tls_server_name orelse "",
                    .skip_verify = if (v.skip_verify) |x| std.mem.eql(u8, x, "true") or std.mem.eql(u8, x, "1") else false,
                };
                tls_opts.check(gpa) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.MissingConfig;
                // Token, then AppRole, then TLS certificate auth.
                const auth: kms.vault.Auth = if (v.token) |t| .{ .token = t } else if (v.role_id) |rid| .{ .approle = .{
                    .role_id = rid,
                    .secret_id = v.secret_id orelse return error.MissingConfig,
                } } else if (tls_opts.hasClientCert()) .{ .cert = .{
                    .mount = v.cert_mount orelse "cert",
                    .role = v.cert_role orelse "",
                } } else return error.MissingConfig;
                if (!std.mem.eql(u8, v.engine, "kv2") and !std.mem.eql(u8, v.engine, "transit")) return error.MissingConfig;
                self.vault_client = kms.vault.Client.init(gpa, .{ .addr = addr, .auth = auth, .namespace = v.namespace, .http = .{ .tls = tls_opts } });
                if (std.mem.eql(u8, v.engine, "kv2")) {
                    self.kv2.init(&self.vault_client);
                    self.handle = self.kv2.kms();
                    self.key_store = self.kv2.store.keyStore();
                } else {
                    self.transit = .{ .client = &self.vault_client };
                    self.handle = self.transit.kms();
                }
            },
            .kms_api => {
                const a = spec.kms_api;
                self.api = kms.kms_api.KmsApi.init(gpa, .{
                    .region = a.region orelse return error.MissingConfig,
                    .endpoint = a.endpoint,
                    .credentials = .{
                        .access_key_id = a.access_key orelse return error.MissingConfig,
                        .secret_access_key = a.secret_key orelse return error.MissingConfig,
                        .session_token = a.session_token,
                    },
                }) catch return error.BackendFailed;
                self.handle = self.api.kms();
            },
        }
        // Make sure the default key exists; external backends may forbid creation.
        var ki = self.handle.?.createKey(gpa, spec.default_key) catch |e| switch (e) {
            error.KeyExists => null,
            error.OutOfMemory => return error.OutOfMemory,
            else => blk: {
                if (strict) return error.ValidationFailed;
                std.log.warn("kms: cannot create default key {s}: {t}", .{ spec.default_key, e });
                break :blk null;
            },
        };
        if (ki) |*k| {
            k.deinit(gpa);
            std.log.info("kms: created default key {s}", .{spec.default_key});
        }
        if (strict) try self.validate(gpa);
    }

    /// Round-trips a data key through the default key.
    fn validate(self: *Holder, gpa: std.mem.Allocator) InitError!void {
        const k = self.handle orelse return error.MissingConfig;
        const ctx: kms.Context = .{ .pairs = &.{.{ .key = "zkfsm:kms-validate", .value = self.default_key }} };
        var dk = k.generateDataKey(gpa, self.default_key, ctx) catch return error.ValidationFailed;
        defer dk.deinit(gpa);
        var back = k.decryptDataKey(gpa, self.default_key, dk.sealed, ctx) catch return error.ValidationFailed;
        defer std.crypto.secureZero(u8, &back);
        if (!std.crypto.timing_safe.eql([kms.types.dek_len]u8, back, dk.plaintext)) return error.ValidationFailed;
    }
};

test "kms flags" {
    var f: Flags = .{};
    try std.testing.expect(f.set("--kms-backend", "vault"));
    try std.testing.expectEqual(Backend.vault, f.backend);
    try std.testing.expect(!f.set("--kms-backend", "gcp"));
    try std.testing.expect(f.set("--kms-backend", "kms-api"));
    try std.testing.expectEqual(Backend.kms_api, f.backend);
    try std.testing.expect(!f.set("--kms-backend", "kms_api"));
    try std.testing.expect(!f.set("--kms-default-key", "bad name;"));
    try std.testing.expect(!f.set("--other", "x"));
}
