//! Remote tier admin API (MinIO-compatible, `mc ilm tier ...`): add, list, edit,
//! verify, remove, and tier-stats. Request bodies carrying credentials are encrypted
//! with the caller's secret; listings redact secrets.
const std = @import("std");
const core = @import("../core/root.zig");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const api = @import("api.zig");
const sio = @import("sio.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Response = api.Response;
const Error = api.Error;
const Config = object.tier.Config;
const redacted = "REDACTED";

/// Null when the operation is not a tier operation.
pub fn handle(a: Allocator, env: api.Env, req: api.Request) Error!?Response {
    const op = req.target.op;
    if (std.mem.eql(u8, op, "/tier-stats")) {
        if (req.method != .GET) return try notAllowed(a);
        return try stats(a, env, req);
    }
    if (!std.mem.eql(u8, op, "/tier") and !std.mem.startsWith(u8, op, "/tier/")) return null;
    const name = if (op.len > "/tier/".len) op["/tier/".len..] else "";
    const reg = (if (env.svc) |s| s.tiers else null) orelse
        return try api.fail(a, .not_implemented, "NotImplemented", "Remote tiers are not available on this server.");
    const force = std.mem.eql(u8, try api.queryParam(a, req.target.query, "force") orelse "false", "true");
    if (name.len == 0) return switch (req.method) {
        .PUT => try add(a, env, req, reg, force),
        .GET => try list(a, env, req, reg),
        else => try notAllowed(a),
    };
    return switch (req.method) {
        .GET => try verify(a, env, req, reg, name),
        .POST => try edit(a, env, req, reg, name),
        .DELETE => try remove(a, env, req, reg, name, force),
        else => try notAllowed(a),
    };
}

fn notAllowed(a: Allocator) Error!Response {
    return api.fail(a, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
}

fn can(a: Allocator, env: api.Env, req: api.Request, op: iam.actions.AdminOp) bool {
    const who = req.caller;
    var sp: ?iam.Policy = null;
    if (who.session_policy) |doc| sp = iam.policy.parse(a, doc) catch return false;
    const id: iam.Identity = .{ .access_key = who.principal, .session_policy = if (sp) |*p| p else null };
    const ctx: iam.Context = .{ .now_s = req.now_s };
    return env.store.authorize(id, op.action(), iam.actions.admin_resource, &ctx).allowed();
}

fn denied(a: Allocator) Error!Response {
    return api.fail(a, .forbidden, "AccessDenied", "Access Denied.");
}

fn badRequest(a: Allocator, code: []const u8, message: []const u8) Error!Response {
    return api.fail(a, .bad_request, code, message);
}

fn tierFail(a: Allocator, e: object.tier.AdminError) Error!Response {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchTier => api.fail(a, .not_found, "XMinioAdminTierNotFound", "Specified remote tier was not found"),
        error.TierExists => api.fail(a, .conflict, "XMinioAdminTierAlreadyExists", "Specified remote tier already exists"),
        error.InvalidTierName => badRequest(a, "XMinioAdminTierNameNotUppercase", "Tier name must be upper case letters, digits, '-' or '_' (and not STANDARD)"),
        error.InvalidTierConfig => badRequest(a, "XMinioAdminTierInvalidConfig", "Invalid remote tier configuration"),
        error.BackendInUse => api.fail(a, .conflict, "XMinioAdminTierBackendInUse", "Specified remote tier is already in use (the bucket/prefix is not empty)"),
        error.BackendUnreachable => badRequest(a, "XMinioAdminTierBackendUnreachable", "Remote tier backend could not be reached or rejected the credentials"),
        error.TiersDisabled => api.fail(a, .not_implemented, "NotImplemented", "Remote tiers need root credentials."),
        error.LockTimeout, error.WriteQuorum, error.ReadQuorum => api.fail(a, .service_unavailable, "XMinioServerNotInitialized", "Cluster lock or quorum unavailable; retry."),
        else => api.fail(a, .internal_server_error, "XMinioInternalError", "Remote tier configuration could not be saved."),
    };
}

fn decryptJson(a: Allocator, req: api.Request) ?std.json.ObjectMap {
    const plain = sio.decrypt(a, req.caller.secret, req.body) catch return null;
    const v = std.json.parseFromSliceLeaky(Value, a, plain, .{}) catch return null;
    return if (v == .object) v.object else null;
}

fn str(o: ?std.json.ObjectMap, key: []const u8) []const u8 {
    const m = o orelse return "";
    const v = m.get(key) orelse return "";
    return if (v == .string) v.string else "";
}

fn sub(o: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const v = o.get(key) orelse return null;
    return if (v == .object) v.object else null;
}

/// GCS credentials file (base64 JSON): a service-account key or an HMAC key pair.
const GcsCreds = union(enum) {
    hmac: [2][]const u8,
    /// client_email, private_key (PEM), token_uri.
    service_account: [3][]const u8,
};

fn gcsCreds(a: Allocator, b64: []const u8) ?GcsCreds {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return null;
    const raw = a.alloc(u8, n) catch return null;
    dec.decode(raw, b64) catch return null;
    const v = std.json.parseFromSliceLeaky(Value, a, raw, .{}) catch return null;
    if (v != .object) return null;
    const email = str(v.object, "client_email");
    const pem = str(v.object, "private_key");
    if (email.len > 0 and pem.len > 0) return .{ .service_account = .{ email, pem, str(v.object, "token_uri") } };
    const pairs = [_][2][]const u8{
        .{ "access_key", "secret_key" },           .{ "accessKey", "secretKey" },
        .{ "access_key_id", "secret_access_key" }, .{ "hmac_access_id", "hmac_secret" },
    };
    for (pairs) |p| {
        const ak = str(v.object, p[0]);
        const sk = str(v.object, p[1]);
        if (ak.len > 0 and sk.len > 0) return .{ .hmac = .{ ak, sk } };
    }
    return null;
}

fn applyGcs(cfg: anytype, g: GcsCreds) void {
    switch (g) {
        .hmac => |p| {
            cfg.auth = .keys;
            cfg.access_key = p[0];
            cfg.secret_key = p[1];
        },
        .service_account => |p| {
            cfg.auth = .service_account;
            cfg.access_key = p[0];
            cfg.secret_key = p[1];
            cfg.token_uri = p[2];
        },
    }
}

fn isTrue(o: ?std.json.ObjectMap, key: []const u8) bool {
    const m = o orelse return false;
    const v = m.get(key) orelse return false;
    return v == .bool and v.bool;
}

const gcs_creds_msg = "GCS tiers need a service-account key file or an HMAC key pair (access_key, secret_key)";

fn add(a: Allocator, env: api.Env, req: api.Request, reg: *object.tier.Registry, force: bool) Error!Response {
    if (!can(a, env, req, .set_tier)) return denied(a);
    const body = decryptJson(a, req) orelse return badRequest(a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted or parsed.");
    if (!std.mem.eql(u8, str(body, "Version"), "v1")) return badRequest(a, "XMinioAdminTierInvalidConfig", "Unsupported tier config version");
    const kind = object.tier.Kind.parse(str(body, "Type")) orelse return badRequest(a, "XMinioAdminTierInvalidConfig", "Unsupported tier type");
    const section = switch (kind) {
        .s3 => "S3",
        .azure => "Azure",
        .gcs => "GCS",
        .minio => "MinIO",
    };
    const s = sub(body, section) orelse return badRequest(a, "XMinioAdminTierInvalidConfig", "Missing tier section");
    var cfg: Config = .{
        .name = str(body, "Name"),
        .kind = kind,
        .endpoint = str(s, "Endpoint"),
        .bucket = str(s, "Bucket"),
        .prefix = str(s, "Prefix"),
        .region = str(s, "Region"),
        .storage_class = str(s, "StorageClass"),
    };
    switch (kind) {
        .s3, .minio => {
            cfg.access_key = str(s, "AccessKey");
            cfg.secret_key = str(s, "SecretKey");
            // Role credentials: the node's own (AWSRole) or a web identity token for a role.
            if (isTrue(s, "AWSRole") or str(s, "AWSRoleARN").len > 0 or str(s, "AWSRoleWebIdentityTokenFile").len > 0) {
                cfg.auth = .role;
                cfg.role_arn = str(s, "AWSRoleARN");
                cfg.token_file = str(s, "AWSRoleWebIdentityTokenFile");
            }
        },
        .azure => {
            cfg.access_key = str(s, "AccountName");
            cfg.secret_key = str(s, "AccountKey");
            const sp = sub(s, "SPAuth");
            if (str(sp, "ClientID").len > 0) {
                cfg.auth = .service_principal;
                cfg.tenant_id = str(sp, "TenantID");
                cfg.client_id = str(sp, "ClientID");
                cfg.secret_key = str(sp, "ClientSecret");
                if (cfg.tenant_id.len == 0 or cfg.secret_key.len == 0) return badRequest(a, "XMinioAdminTierMissingCredentials", "Service principal needs a tenant id, client id and client secret");
            }
        },
        .gcs => applyGcs(&cfg, gcsCreds(a, str(s, "Creds")) orelse return badRequest(a, "XMinioAdminTierInvalidCredentials", gcs_creds_msg)),
    }
    if (cfg.auth == .keys and (cfg.access_key.len == 0 or cfg.secret_key.len == 0)) return badRequest(a, "XMinioAdminTierMissingCredentials", "Specified remote credentials are empty");
    reg.add(cfg, .{ .force = force }) catch |e| return tierFail(a, e);
    return .{ .status = .no_content };
}

fn list(a: Allocator, env: api.Env, req: api.Request, reg: *object.tier.Registry) Error!Response {
    if (!can(a, env, req, .list_tier)) return denied(a);
    const cfgs = try reg.list(a);
    var out: std.Io.Writer.Allocating = .init(a);
    var js: std.json.Stringify = .{ .writer = &out.writer };
    writeList(&js, cfgs) catch return error.OutOfMemory;
    return .{ .body = out.written() };
}

fn writeList(js: *std.json.Stringify, cfgs: []const Config) std.Io.Writer.Error!void {
    try js.beginArray();
    for (cfgs) |c| {
        try js.beginObject();
        try field(js, "Version", "v1");
        try field(js, "Type", @tagName(c.kind));
        try field(js, "Name", c.name);
        try js.objectField(switch (c.kind) {
            .s3 => "S3",
            .azure => "Azure",
            .gcs => "GCS",
            .minio => "MinIO",
        });
        try js.beginObject();
        try optField(js, "Endpoint", c.endpoint);
        switch (c.kind) {
            .s3, .minio => if (c.auth == .role) {
                try js.objectField("AWSRole");
                try js.write(c.token_file.len == 0);
                try optField(js, "AWSRoleARN", c.role_arn);
                try optField(js, "AWSRoleWebIdentityTokenFile", c.token_file);
            } else {
                try optField(js, "AccessKey", c.access_key);
                try field(js, "SecretKey", redacted);
            },
            .azure => {
                try optField(js, "AccountName", c.access_key);
                if (c.auth == .service_principal) {
                    try js.objectField("SPAuth");
                    try js.beginObject();
                    try field(js, "TenantID", c.tenant_id);
                    try field(js, "ClientID", c.client_id);
                    try field(js, "ClientSecret", redacted);
                    try js.endObject();
                } else try field(js, "AccountKey", redacted);
            },
            .gcs => try field(js, "Creds", redacted),
        }
        try optField(js, "Bucket", c.bucket);
        try optField(js, "Prefix", c.prefix);
        try optField(js, "Region", c.region);
        if (c.kind != .minio) try optField(js, "StorageClass", c.storage_class);
        try js.endObject();
        try js.endObject();
    }
    try js.endArray();
}

fn field(js: *std.json.Stringify, name: []const u8, v: []const u8) std.Io.Writer.Error!void {
    try js.objectField(name);
    try js.write(v);
}

fn optField(js: *std.json.Stringify, name: []const u8, v: []const u8) std.Io.Writer.Error!void {
    if (v.len > 0) try field(js, name, v);
}

fn verify(a: Allocator, env: api.Env, req: api.Request, reg: *object.tier.Registry, name: []const u8) Error!Response {
    if (!can(a, env, req, .list_tier)) return denied(a);
    reg.verify(name) catch |e| return tierFail(a, e);
    return .{ .status = .no_content };
}

fn edit(a: Allocator, env: api.Env, req: api.Request, reg: *object.tier.Registry, name: []const u8) Error!Response {
    if (!can(a, env, req, .set_tier)) return denied(a);
    const body = decryptJson(a, req) orelse return badRequest(a, "XMinioAdminConfigBadJSON", "Request body could not be decrypted or parsed.");
    var creds: object.tier.Registry.Creds = .{};
    const ak = str(body, "access");
    const sk = str(body, "secret");
    if (ak.len > 0) creds.access_key = ak;
    if (sk.len > 0) creds.secret_key = sk;
    if (isTrue(body, "awsrole")) creds = .{ .auth = .role, .role_arn = str(body, "awsroleARN"), .token_file = str(body, "awsroleWebIdentity") };
    const sp = sub(body, "azSP");
    if (str(sp, "ClientID").len > 0) creds = .{
        .auth = .service_principal,
        .secret_key = str(sp, "ClientSecret"),
        .tenant_id = str(sp, "TenantID"),
        .client_id = str(sp, "ClientID"),
    };
    // GCS: `creds` is the credentials file as base64 (Go []byte).
    const gcs = str(body, "creds");
    if (gcs.len > 0) switch (gcsCreds(a, gcs) orelse return badRequest(a, "XMinioAdminTierInvalidCredentials", gcs_creds_msg)) {
        .hmac => |p| creds = .{ .access_key = p[0], .secret_key = p[1], .auth = .keys },
        .service_account => |p| creds = .{ .access_key = p[0], .secret_key = p[1], .auth = .service_account, .token_uri = p[2] },
    };
    if (creds.access_key == null and creds.secret_key == null and creds.auth == null) return badRequest(a, "XMinioAdminTierMissingCredentials", "Specified remote credentials are empty");
    reg.edit(name, creds) catch |e| return tierFail(a, e);
    return .{ .status = .no_content };
}

fn remove(a: Allocator, env: api.Env, req: api.Request, reg: *object.tier.Registry, name: []const u8, force: bool) Error!Response {
    if (!can(a, env, req, .set_tier)) return denied(a);
    reg.remove(name, force) catch |e| return tierFail(a, e);
    return .{ .status = .no_content };
}

const Stats = struct { totalSize: u64, numVersions: u64, numObjects: u64 };
const Daily = struct { Bins: [24]Stats, UpdatedAt: []const u8 };
const Info = struct { Name: []const u8, Type: []const u8, Stats: Stats, DailyStats: Daily };

fn daily(a: Allocator, d: object.tier.Daily) Error!Daily {
    var out: Daily = .{ .Bins = undefined, .UpdatedAt = "0001-01-01T00:00:00Z" };
    for (d.bins, &out.Bins) |b, *o| o.* = usage(b);
    if (d.updated_ns > 0) out.UpdatedAt = core.time.iso8601(d.updated_ns, try a.create([24]u8));
    return out;
}

fn usage(u: object.tier.Usage) Stats {
    return .{ .totalSize = u.bytes, .numVersions = u.versions, .numObjects = u.objects };
}

fn stats(a: Allocator, env: api.Env, req: api.Request) Error!Response {
    if (!can(a, env, req, .list_tier)) return denied(a);
    const reg = (if (env.svc) |s| s.tiers else null) orelse
        return api.fail(a, .not_implemented, "NotImplemented", "Remote tiers are not available on this server.");
    const view = try reg.statsCopy(a);
    const out = try a.alloc(Info, view.tiers.len + 1);
    out[0] = .{ .Name = "STANDARD", .Type = "internal", .Stats = usage(view.hot), .DailyStats = try daily(a, .{}) };
    for (view.tiers, out[1..]) |t, *o| o.* = .{ .Name = t.name, .Type = t.kind, .Stats = usage(t.usage), .DailyStats = try daily(a, t.daily) };
    return .{ .body = try std.json.Stringify.valueAlloc(a, out, .{}) };
}

test "gcs hmac credentials file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = "{\"access_key\":\"GOOG1\",\"secret_key\":\"s3cr3t\"}";
    const b64 = try a.alloc(u8, std.base64.standard.Encoder.calcSize(doc.len));
    _ = std.base64.standard.Encoder.encode(b64, doc);
    const p = gcsCreds(a, b64).?.hmac;
    try std.testing.expectEqualStrings("GOOG1", p[0]);
    try std.testing.expect(gcsCreds(a, "!!") == null);
    const sa = "{\"type\":\"service_account\",\"client_email\":\"t@p.iam\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nAA\\n-----END PRIVATE KEY-----\\n\",\"token_uri\":\"http://x/token\"}";
    const b2 = try a.alloc(u8, std.base64.standard.Encoder.calcSize(sa.len));
    _ = std.base64.standard.Encoder.encode(b2, sa);
    const g = gcsCreds(a, b2).?.service_account;
    try std.testing.expectEqualStrings("t@p.iam", g[0]);
    try std.testing.expect(std.mem.indexOfScalar(u8, g[1], '\n') != null);
}

test "tier list json for role and service principal" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var js: std.json.Stringify = .{ .writer = &out.writer };
    try writeList(&js, &.{
        .{ .name = "R", .kind = .s3, .bucket = "b", .auth = .role, .role_arn = "arn:x" },
        .{ .name = "Z", .kind = .azure, .bucket = "c", .access_key = "acct", .secret_key = "cs", .auth = .service_principal, .tenant_id = "t", .client_id = "c" },
    });
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"AWSRole\":true,\"AWSRoleARN\":\"arn:x\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"SPAuth\":{\"TenantID\":\"t\",\"ClientID\":\"c\",\"ClientSecret\":\"REDACTED\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "cs\"") == null);
}

test "tier list json redacts secrets" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var js: std.json.Stringify = .{ .writer = &out.writer };
    try writeList(&js, &.{.{ .name = "WARM", .kind = .minio, .endpoint = "http://h:9000", .access_key = "ak", .secret_key = "sk", .bucket = "b" }});
    try std.testing.expectEqualStrings(
        \\[{"Version":"v1","Type":"minio","Name":"WARM","MinIO":{"Endpoint":"http://h:9000","AccessKey":"ak","SecretKey":"REDACTED","Bucket":"b"}}]
    , out.written());
}
