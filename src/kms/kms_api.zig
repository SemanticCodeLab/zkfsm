//! Cloud KMS backend speaking the TrentService JSON 1.1 protocol, SigV4-signed.
//! Logical key names map to aliases `<alias_prefix><name>`; raw key ids,
//! ARNs and `alias/...` names are passed through unchanged.
const std = @import("std");
const types = @import("types.zig");
const http = @import("http.zig");
const sigv4 = @import("sigv4.zig");
const vault = @import("vault.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Error = types.Error;
const b64 = std.base64.standard;

pub const Config = struct {
    region: []const u8,
    /// Defaults to the provider's regional endpoint; override for emulators.
    endpoint: ?[]const u8 = null,
    credentials: sigv4.Credentials,
    alias_prefix: []const u8 = "alias/zkfsm-",
    http: http.Options = .{},
};

/// Credentials and region read from the standard AWS_* environment variables.
pub const EnvCredentials = struct {
    access_key_id: []u8,
    secret_access_key: []u8,
    session_token: ?[]u8,
    region: []u8,

    pub fn load(gpa: Allocator) Error!EnvCredentials {
        const ak = envOwned(gpa, "AWS_ACCESS_KEY_ID") orelse return error.AccessDenied;
        errdefer gpa.free(ak);
        const sk = envOwned(gpa, "AWS_SECRET_ACCESS_KEY") orelse return error.AccessDenied;
        errdefer wipeFree(gpa, sk);
        const st = envOwned(gpa, "AWS_SESSION_TOKEN");
        errdefer if (st) |s| wipeFree(gpa, s);
        const region = envOwned(gpa, "AWS_REGION") orelse envOwned(gpa, "AWS_DEFAULT_REGION") orelse return error.InvalidArgument;
        return .{ .access_key_id = ak, .secret_access_key = sk, .session_token = st, .region = region };
    }

    pub fn credentials(e: EnvCredentials) sigv4.Credentials {
        return .{ .access_key_id = e.access_key_id, .secret_access_key = e.secret_access_key, .session_token = e.session_token };
    }

    pub fn deinit(e: *EnvCredentials, gpa: Allocator) void {
        gpa.free(e.access_key_id);
        wipeFree(gpa, e.secret_access_key);
        if (e.session_token) |s| wipeFree(gpa, s);
        gpa.free(e.region);
    }
};

fn envOwned(gpa: Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(gpa, name) catch null;
}

fn wipeFree(gpa: Allocator, s: []u8) void {
    std.crypto.secureZero(u8, s);
    gpa.free(s);
}

pub const KmsApi = struct {
    gpa: Allocator,
    cfg: Config,
    http: http.Client,
    endpoint: []u8,
    host: []u8,

    /// Config strings are borrowed and must outlive the backend.
    pub fn init(gpa: Allocator, cfg: Config) Error!KmsApi {
        const endpoint = if (cfg.endpoint) |e| try gpa.dupe(u8, std.mem.trimRight(u8, e, "/")) else try std.fmt.allocPrint(gpa, "https://kms.{s}.amazonaws.com", .{cfg.region});
        errdefer gpa.free(endpoint);
        const uri = std.Uri.parse(endpoint) catch return error.InvalidArgument;
        const h = uri.host orelse return error.InvalidArgument;
        const hs = switch (h) {
            .raw, .percent_encoded => |s| s,
        };
        const host = if (uri.port) |p| try std.fmt.allocPrint(gpa, "{s}:{d}", .{ hs, p }) else try gpa.dupe(u8, hs);
        return .{ .gpa = gpa, .cfg = cfg, .http = http.Client.init(gpa, cfg.http), .endpoint = endpoint, .host = host };
    }

    pub fn deinit(a: *KmsApi) void {
        a.http.deinit();
        a.gpa.free(a.endpoint);
        a.gpa.free(a.host);
    }

    pub fn kms(a: *KmsApi) types.Kms {
        return .{ .ptr = a, .vtable = &.{
            .kind = .kms_api,
            .createKey = createKey,
            .generateDataKey = generateDataKey,
            .decryptDataKey = decryptDataKey,
            .listKeys = listKeys,
            .keyStatus = keyStatus,
            .rotateKey = rotateKey,
        } };
    }

    fn cast(p: *anyopaque) *KmsApi {
        return @ptrCast(@alignCast(p));
    }

    /// Returns an owned KMS KeyId for a logical name or pass-through id.
    fn resolve(a: *KmsApi, gpa: Allocator, id: []const u8) Error![]u8 {
        if (std.mem.startsWith(u8, id, "alias/") or std.mem.startsWith(u8, id, "arn:") or isUuid(id)) {
            if (id.len > 2048 or std.mem.indexOfAny(u8, id, "\"\\\r\n") != null) return error.InvalidArgument;
            return gpa.dupe(u8, id);
        }
        if (!types.validKeyName(id)) return error.InvalidArgument;
        return std.mem.concat(gpa, u8, &.{ a.cfg.alias_prefix, id });
    }

    const Parsed = std.json.Parsed(Value);

    /// Signs and sends one KMS action; returns parsed JSON on 200.
    fn call(a: *KmsApi, gpa: Allocator, action: []const u8, body: []const u8) Error!Parsed {
        var db: [16]u8 = undefined;
        const date = sigv4.amzDate(&db, std.time.timestamp());
        const target = try std.fmt.allocPrint(gpa, "TrentService.{s}", .{action});
        defer gpa.free(target);
        const ctype = "application/x-amz-json-1.1";
        var sh: [5]sigv4.Header = undefined;
        sh[0] = .{ .name = "content-type", .value = ctype };
        sh[1] = .{ .name = "host", .value = a.host };
        sh[2] = .{ .name = "x-amz-date", .value = date };
        sh[3] = .{ .name = "x-amz-target", .value = target };
        var n: usize = 4;
        if (a.cfg.credentials.session_token) |t| {
            sh[4] = .{ .name = "x-amz-security-token", .value = t };
            n = 5;
        }
        const auth = sigv4.sign(gpa, a.cfg.credentials, a.cfg.region, "kms", date, .{ .method = "POST", .headers = sh[0..n], .payload = body }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidArgument => return error.InvalidArgument,
        };
        defer gpa.free(auth);
        var hh: [5]std.http.Header = undefined;
        hh[0] = .{ .name = "Content-Type", .value = ctype };
        hh[1] = .{ .name = "X-Amz-Date", .value = date };
        hh[2] = .{ .name = "X-Amz-Target", .value = target };
        hh[3] = .{ .name = "Authorization", .value = auth };
        if (n == 5) hh[4] = .{ .name = "X-Amz-Security-Token", .value = sh[4].value };
        const url = try std.fmt.allocPrint(gpa, "{s}/", .{a.endpoint});
        defer gpa.free(url);
        var resp = a.http.send(gpa, .POST, url, hh[0..n], body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidArgument => return error.InvalidArgument,
            error.BackendUnavailable => return error.BackendUnavailable,
            error.InvalidResponse => return error.InvalidResponse,
        };
        defer {
            std.crypto.secureZero(u8, resp.body);
            resp.deinit(gpa);
        }
        const parsed = std.json.parseFromSlice(Value, gpa, if (resp.body.len == 0) "{}" else resp.body, .{ .allocate = .alloc_always }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return if (resp.status == 200) error.InvalidResponse else statusOnly(resp.status),
        };
        if (resp.status == 200) return parsed;
        defer parsed.deinit();
        return mapApiError(resp.status, vault.getStr(parsed.value, &.{"__type"}) orelse "");
    }

    fn createKey(p: *anyopaque, gpa: Allocator, name: []const u8) Error!types.KeyInfo {
        const a = cast(p);
        if (!types.validKeyName(name)) return error.InvalidArgument;
        const alias = try a.resolve(gpa, name);
        defer gpa.free(alias);
        if (keyStatus(p, gpa, name)) |ki| {
            var k = ki;
            k.deinit(gpa);
            return error.KeyExists;
        } else |e| if (e != error.KeyNotFound) return e;

        const desc = try std.fmt.allocPrint(gpa, "zkfsm master key {s}", .{name});
        defer gpa.free(desc);
        const body = try jsonFields(gpa, &.{ .{ "Description", .{ .string = desc } }, .{ "KeySpec", .{ .string = "SYMMETRIC_DEFAULT" } }, .{ "KeyUsage", .{ .string = "ENCRYPT_DECRYPT" } } });
        defer gpa.free(body);
        const created = try a.call(gpa, "CreateKey", body);
        defer created.deinit();
        const key_id = vault.getStr(created.value, &.{ "KeyMetadata", "KeyId" }) orelse return error.InvalidResponse;
        const ab = try jsonFields(gpa, &.{ .{ "AliasName", .{ .string = alias } }, .{ "TargetKeyId", .{ .string = key_id } } });
        defer gpa.free(ab);
        const al = try a.call(gpa, "CreateAlias", ab);
        al.deinit();
        return keyStatus(p, gpa, name);
    }

    fn contextObject(gpa: Allocator, ctx: types.Context) Error!std.json.ObjectMap {
        // canonical() rejects duplicate keys.
        gpa.free(try ctx.canonical(gpa));
        var m: std.json.ObjectMap = .init(gpa);
        errdefer m.deinit();
        for (ctx.pairs) |pr| try m.put(pr.key, .{ .string = pr.value });
        return m;
    }

    fn generateDataKey(p: *anyopaque, gpa: Allocator, name: []const u8, ctx: types.Context) Error!types.DataKey {
        const a = cast(p);
        const kid = try a.resolve(gpa, name);
        defer gpa.free(kid);
        var cm = try contextObject(gpa, ctx);
        defer cm.deinit();
        const body = try jsonFields(gpa, &.{ .{ "KeyId", .{ .string = kid } }, .{ "KeySpec", .{ .string = "AES_256" } }, .{ "EncryptionContext", .{ .object = cm } } });
        defer gpa.free(body);
        const r = try a.call(gpa, "GenerateDataKey", body);
        defer r.deinit();
        const pt = vault.getStr(r.value, &.{"Plaintext"}) orelse return error.InvalidResponse;
        defer std.crypto.secureZero(u8, @constCast(pt));
        const ct = vault.getStr(r.value, &.{"CiphertextBlob"}) orelse return error.InvalidResponse;
        var dk: types.DataKey = .{ .plaintext = undefined, .sealed = &.{}, .key_version = 0 };
        const n = b64.Decoder.calcSizeForSlice(pt) catch return error.InvalidResponse;
        if (n != types.dek_len) return error.InvalidResponse;
        b64.Decoder.decode(&dk.plaintext, pt) catch return error.InvalidResponse;
        errdefer std.crypto.secureZero(u8, &dk.plaintext);
        const cn = b64.Decoder.calcSizeForSlice(ct) catch return error.InvalidResponse;
        dk.sealed = try gpa.alloc(u8, cn);
        errdefer gpa.free(dk.sealed);
        b64.Decoder.decode(dk.sealed, ct) catch return error.InvalidResponse;
        return dk;
    }

    fn decryptDataKey(p: *anyopaque, gpa: Allocator, name: []const u8, sealed: []const u8, ctx: types.Context) Error![types.dek_len]u8 {
        const a = cast(p);
        if (sealed.len == 0 or sealed.len > 6144) return error.InvalidCiphertext;
        const kid = try a.resolve(gpa, name);
        defer gpa.free(kid);
        var cm = try contextObject(gpa, ctx);
        defer cm.deinit();
        const blob = try gpa.alloc(u8, b64.Encoder.calcSize(sealed.len));
        defer gpa.free(blob);
        _ = b64.Encoder.encode(blob, sealed);
        const body = try jsonFields(gpa, &.{ .{ "KeyId", .{ .string = kid } }, .{ "CiphertextBlob", .{ .string = blob } }, .{ "EncryptionContext", .{ .object = cm } } });
        defer gpa.free(body);
        const r = try a.call(gpa, "Decrypt", body);
        defer r.deinit();
        const pt = vault.getStr(r.value, &.{"Plaintext"}) orelse return error.InvalidResponse;
        defer std.crypto.secureZero(u8, @constCast(pt));
        var out: [types.dek_len]u8 = undefined;
        const n = b64.Decoder.calcSizeForSlice(pt) catch return error.InvalidResponse;
        if (n != types.dek_len) return error.InvalidResponse;
        b64.Decoder.decode(&out, pt) catch return error.InvalidResponse;
        return out;
    }

    fn describe(a: *KmsApi, gpa: Allocator, kid: []const u8) Error!Parsed {
        const body = try jsonFields(gpa, &.{.{ "KeyId", .{ .string = kid } }});
        defer gpa.free(body);
        return a.call(gpa, "DescribeKey", body);
    }

    fn keyStatus(p: *anyopaque, gpa: Allocator, name: []const u8) Error!types.KeyInfo {
        const a = cast(p);
        const kid = try a.resolve(gpa, name);
        defer gpa.free(kid);
        const d = try a.describe(gpa, kid);
        defer d.deinit();
        const md = vault.getPath(d.value, &.{"KeyMetadata"}) orelse return error.InvalidResponse;
        const state_s = vault.getStr(md, &.{"KeyState"}) orelse "";
        const state: types.KeyState = if (std.mem.eql(u8, state_s, "Enabled")) .enabled else if (std.mem.eql(u8, state_s, "Disabled")) .disabled else if (std.mem.eql(u8, state_s, "PendingDeletion")) .pending_deletion else .unknown;
        const real = vault.getStr(md, &.{"KeyId"}) orelse return error.InvalidResponse;
        const rb = try jsonFields(gpa, &.{.{ "KeyId", .{ .string = real } }});
        defer gpa.free(rb);
        var rotation = false;
        if (a.call(gpa, "GetKeyRotationStatus", rb)) |rs| {
            defer rs.deinit();
            const v = vault.getPath(rs.value, &.{"KeyRotationEnabled"});
            rotation = v != null and v.? == .bool and v.?.bool;
        } else |e| switch (e) {
            error.Unsupported, error.AccessDenied => {},
            else => return e,
        }
        return .{
            .id = try gpa.dupe(u8, name),
            .state = state,
            .version = 0,
            .created_unix = vault.getInt(md, &.{"CreationDate"}) orelse 0,
            .rotation_enabled = rotation,
        };
    }

    fn listKeys(p: *anyopaque, gpa: Allocator) Error![]types.KeyInfo {
        const a = cast(p);
        var out: std.ArrayList(types.KeyInfo) = .empty;
        errdefer {
            for (out.items) |*k| k.deinit(gpa);
            out.deinit(gpa);
        }
        var marker: ?[]u8 = null;
        defer if (marker) |m| gpa.free(m);
        while (true) {
            const body = if (marker) |m| try jsonFields(gpa, &.{ .{ "Limit", .{ .integer = 100 } }, .{ "Marker", .{ .string = m } } }) else try jsonFields(gpa, &.{.{ "Limit", .{ .integer = 100 } }});
            defer gpa.free(body);
            const r = try a.call(gpa, "ListAliases", body);
            defer r.deinit();
            const aliases = vault.getPath(r.value, &.{"Aliases"}) orelse return error.InvalidResponse;
            if (aliases != .array) return error.InvalidResponse;
            for (aliases.array.items) |al| {
                const an = vault.getStr(al, &.{"AliasName"}) orelse continue;
                if (vault.getStr(al, &.{"TargetKeyId"}) == null) continue;
                if (!std.mem.startsWith(u8, an, a.cfg.alias_prefix)) continue;
                const name = an[a.cfg.alias_prefix.len..];
                if (!types.validKeyName(name)) continue;
                var ki = keyStatus(p, gpa, name) catch |e| switch (e) {
                    error.KeyNotFound => continue,
                    else => return e,
                };
                out.append(gpa, ki) catch {
                    ki.deinit(gpa);
                    return error.OutOfMemory;
                };
            }
            const trunc = vault.getPath(r.value, &.{"Truncated"});
            const next = vault.getStr(r.value, &.{"NextMarker"});
            if (trunc == null or trunc.? != .bool or !trunc.?.bool or next == null) break;
            if (marker) |m| gpa.free(m);
            marker = null;
            marker = try gpa.dupe(u8, next.?);
        }
        return out.toOwnedSlice(gpa);
    }

    /// Enables yearly automatic rotation (old material stays usable for decrypt).
    fn rotateKey(p: *anyopaque, gpa: Allocator, name: []const u8) Error!types.KeyInfo {
        const a = cast(p);
        const kid = try a.resolve(gpa, name);
        defer gpa.free(kid);
        const d = try a.describe(gpa, kid);
        defer d.deinit();
        const real = vault.getStr(d.value, &.{ "KeyMetadata", "KeyId" }) orelse return error.InvalidResponse;
        const body = try jsonFields(gpa, &.{.{ "KeyId", .{ .string = real } }});
        defer gpa.free(body);
        const r = try a.call(gpa, "EnableKeyRotation", body);
        r.deinit();
        return keyStatus(p, gpa, name);
    }
};

fn isUuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => if (c != '-') return false,
        else => if (!std.ascii.isHex(c)) return false,
    };
    return true;
}

const Field = struct { []const u8, Value };

fn jsonFields(gpa: Allocator, fields: []const Field) Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var js: std.json.Stringify = .{ .writer = &out.writer };
    js.beginObject() catch return error.OutOfMemory;
    for (fields) |f| {
        js.objectField(f[0]) catch return error.OutOfMemory;
        js.write(f[1]) catch return error.OutOfMemory;
    }
    js.endObject() catch return error.OutOfMemory;
    return out.toOwnedSlice() catch error.OutOfMemory;
}

fn statusOnly(status: u16) Error {
    return switch (status) {
        401, 403 => error.AccessDenied,
        404 => error.KeyNotFound,
        429, 500...599 => error.BackendUnavailable,
        else => error.InvalidResponse,
    };
}

fn mapApiError(status: u16, type_full: []const u8) Error {
    const t = if (std.mem.lastIndexOfScalar(u8, type_full, '#')) |i| type_full[i + 1 ..] else type_full;
    const eq = struct {
        fn f(a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }
    }.f;
    if (eq(t, "NotFoundException")) return error.KeyNotFound;
    if (eq(t, "InvalidCiphertextException") or eq(t, "IncorrectKeyException")) return error.InvalidCiphertext;
    if (eq(t, "DisabledException") or eq(t, "KMSInvalidStateException")) return error.KeyDisabled;
    if (eq(t, "AlreadyExistsException")) return error.KeyExists;
    if (eq(t, "AccessDeniedException") or eq(t, "UnrecognizedClientException") or eq(t, "InvalidSignatureException") or eq(t, "IncompleteSignature") or eq(t, "ExpiredTokenException")) return error.AccessDenied;
    if (eq(t, "ValidationException") or eq(t, "InvalidKeyUsageException") or eq(t, "InvalidAliasNameException")) return error.InvalidArgument;
    if (eq(t, "UnsupportedOperationException")) return error.Unsupported;
    if (eq(t, "ThrottlingException") or eq(t, "LimitExceededException") or eq(t, "KMSInternalException") or eq(t, "DependencyTimeoutException")) return error.BackendUnavailable;
    return statusOnly(status);
}

test "kms-api error mapping and id resolution" {
    try std.testing.expectEqual(Error.KeyNotFound, mapApiError(400, "com.amazonaws.kms#NotFoundException"));
    try std.testing.expectEqual(Error.InvalidCiphertext, mapApiError(400, "InvalidCiphertextException"));
    try std.testing.expectEqual(Error.InvalidResponse, mapApiError(400, "Weird"));
    try std.testing.expect(isUuid("1234abcd-12ab-34cd-56ef-1234567890ab"));
    try std.testing.expect(!isUuid("1234abcd"));
    const gpa = std.testing.allocator;
    var a = try KmsApi.init(gpa, .{ .region = "us-east-1", .credentials = .{ .access_key_id = "x", .secret_access_key = "y" } });
    defer a.deinit();
    try std.testing.expectEqualStrings("kms.us-east-1.amazonaws.com", a.host);
    const r = try a.resolve(gpa, "tenant1");
    defer gpa.free(r);
    try std.testing.expectEqualStrings("alias/zkfsm-tenant1", r);
    try std.testing.expectError(error.InvalidArgument, a.resolve(gpa, "bad name"));
}

// Live: set ZKFSM_KMS_API_TEST_ENDPOINT (e.g. local-kms emulator) or
// ZKFSM_KMS_API_LIVE=1 with real AWS_* credentials. Skipped otherwise.
test "kms-api live" {
    const gpa = std.testing.allocator;
    const endpoint = envOwned(gpa, "ZKFSM_KMS_API_TEST_ENDPOINT");
    defer if (endpoint) |e| gpa.free(e);
    const live = envOwned(gpa, "ZKFSM_KMS_API_LIVE");
    defer if (live) |l| gpa.free(l);
    if (endpoint == null and live == null) return error.SkipZigTest;
    var env = EnvCredentials.load(gpa) catch return error.SkipZigTest;
    defer env.deinit(gpa);
    var a = try KmsApi.init(gpa, .{ .region = env.region, .endpoint = endpoint, .credentials = env.credentials(), .http = .{ .timeout_ms = 10_000 } });
    defer a.deinit();
    const k = a.kms();
    var nb: [48]u8 = undefined;
    const name = std.fmt.bufPrint(&nb, "zkfsm-test-live-{x}", .{std.crypto.random.int(u32)}) catch unreachable;
    var ki = try k.createKey(gpa, name);
    try std.testing.expectEqual(types.KeyState.enabled, ki.state);
    ki.deinit(gpa);
    try std.testing.expectError(error.KeyExists, k.createKey(gpa, name));
    const ctx: types.Context = .{ .pairs = &.{.{ .key = "bucket", .value = "b" }} };
    var dk = try k.generateDataKey(gpa, name, ctx);
    defer dk.deinit(gpa);
    const back = try k.decryptDataKey(gpa, name, dk.sealed, ctx);
    try std.testing.expectEqualSlices(u8, &dk.plaintext, &back);
    const wrong: types.Context = .{ .pairs = &.{.{ .key = "bucket", .value = "x" }} };
    try std.testing.expectError(error.InvalidCiphertext, k.decryptDataKey(gpa, name, dk.sealed, wrong));
    var rk = try k.rotateKey(gpa, name);
    try std.testing.expect(rk.rotation_enabled);
    rk.deinit(gpa);
    const l = try k.listKeys(gpa);
    defer types.freeKeyInfos(gpa, l);
    var found = false;
    for (l) |x| found = found or std.mem.eql(u8, x.id, name);
    try std.testing.expect(found);
    try std.testing.expectError(error.KeyNotFound, k.keyStatus(gpa, "zkfsm-test-missing-key"));
}
