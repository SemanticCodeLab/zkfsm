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

pub const InitError = error{ MissingConfig, BackendFailed, OutOfMemory };

/// Owns the selected backend. Lives for the process; strings are leaked on purpose.
pub const Holder = struct {
    local: kms.local.LocalKms = undefined,
    vault_client: kms.vault.Client = undefined,
    transit: kms.vault.TransitKms = undefined,
    kv2: kms.vault.Kv2Kms = undefined,
    static: kms.static.StaticKms = undefined,
    api_creds: kms.kms_api.EnvCredentials = undefined,
    api: kms.kms_api.KmsApi = undefined,
    handle: ?kms.Kms = null,
    /// Key records of locally wrapped backends (local, KV2), for backups.
    key_store: ?kms.keyring.KeyStore = null,
    default_key: []const u8 = "",

    /// `self` must not move after init.
    pub fn init(self: *Holder, gpa: std.mem.Allocator, f: Flags) InitError!void {
        self.default_key = f.default_key;
        switch (f.backend) {
            .none => return,
            .static => {
                self.static.init(f.secret_key orelse return error.MissingConfig) catch return error.MissingConfig;
                if (!f.default_key_set) self.default_key = self.static.name;
                self.handle = self.static.kms();
                return;
            },
            .local => {
                self.local.init(f.dir) catch return error.BackendFailed;
                self.handle = self.local.kms();
                self.key_store = self.local.files.keyStore();
            },
            .vault => {
                const addr = env(gpa, "VAULT_ADDR") orelse return error.MissingConfig;
                const tls_opts: tls.TlsOptions = .{
                    .ca_file = env(gpa, "VAULT_CACERT") orelse env(gpa, "KMS_VAULT_CAPATH") orelse "",
                    .client_cert_file = env(gpa, "VAULT_CLIENT_CERT") orelse "",
                    .client_key_file = env(gpa, "VAULT_CLIENT_KEY") orelse "",
                    .server_name = env(gpa, "VAULT_TLS_SERVER_NAME") orelse "",
                    .skip_verify = if (env(gpa, "VAULT_SKIP_VERIFY")) |v| std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1") else false,
                };
                tls_opts.check(gpa) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.MissingConfig;
                // Token, then AppRole, then TLS certificate auth.
                const auth: kms.vault.Auth = if (env(gpa, "VAULT_TOKEN")) |t| .{ .token = t } else if (env(gpa, "VAULT_ROLE_ID")) |rid| .{ .approle = .{
                    .role_id = rid,
                    .secret_id = env(gpa, "VAULT_SECRET_ID") orelse return error.MissingConfig,
                } } else if (tls_opts.hasClientCert()) .{ .cert = .{
                    .mount = env(gpa, "VAULT_CERT_AUTH_MOUNT") orelse "cert",
                    .role = env(gpa, "VAULT_CERT_ROLE") orelse "",
                } } else return error.MissingConfig;
                self.vault_client = kms.vault.Client.init(gpa, .{ .addr = addr, .auth = auth, .namespace = env(gpa, "VAULT_NAMESPACE"), .http = .{ .tls = tls_opts } });
                const engine = env(gpa, "ZKFSM_KMS_VAULT_ENGINE") orelse "transit";
                if (std.mem.eql(u8, engine, "kv2")) {
                    self.kv2.init(&self.vault_client);
                    self.handle = self.kv2.kms();
                    self.key_store = self.kv2.store.keyStore();
                } else if (std.mem.eql(u8, engine, "transit")) {
                    self.transit = .{ .client = &self.vault_client };
                    self.handle = self.transit.kms();
                } else return error.MissingConfig;
            },
            .kms_api => {
                self.api_creds = kms.kms_api.EnvCredentials.load(gpa) catch return error.MissingConfig;
                self.api = kms.kms_api.KmsApi.init(gpa, .{
                    .region = self.api_creds.region,
                    .endpoint = env(gpa, "ZKFSM_KMS_API_ENDPOINT"),
                    .credentials = self.api_creds.credentials(),
                }) catch return error.BackendFailed;
                self.handle = self.api.kms();
            },
        }
        // Make sure the default key exists; external backends may forbid creation.
        var ki = self.handle.?.createKey(gpa, f.default_key) catch |e| switch (e) {
            error.KeyExists => return,
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                std.log.warn("kms: cannot create default key {s}: {t}", .{ f.default_key, e });
                return;
            },
        };
        ki.deinit(gpa);
        std.log.info("kms: created default key {s}", .{f.default_key});
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
