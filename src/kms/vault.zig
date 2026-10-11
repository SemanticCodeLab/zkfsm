//! HashiCorp Vault backends: Transit (Vault holds keys, derives per-context
//! keys so the encryption context is cryptographically bound) and KV v2
//! (Vault stores master key records, DEKs are wrapped locally).
const std = @import("std");
const types = @import("types.zig");
const keyring = @import("keyring.zig");
const http = @import("http.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const Error = types.Error;
const b64 = std.base64.standard;
const log = std.log.scoped(.kms_vault);

pub const Auth = union(enum) {
    token: []const u8,
    approle: struct { role_id: []const u8, secret_id: []const u8, mount: []const u8 = "approle" },
    /// TLS certificate auth: the client certificate in `Config.http.tls` is the credential.
    cert: struct { mount: []const u8 = "cert", role: []const u8 = "" },
};

pub const Config = struct {
    /// e.g. "https://vault.example:8200" (no trailing slash).
    addr: []const u8,
    auth: Auth,
    namespace: ?[]const u8 = null,
    transit_mount: []const u8 = "transit",
    kv_mount: []const u8 = "secret",
    kv_prefix: []const u8 = "zkfsm/kms/keys",
    http: http.Options = .{},
};

pub const Client = struct {
    gpa: Allocator,
    cfg: Config,
    http: http.Client,
    token: ?[]u8 = null,
    mutex: std.Thread.Mutex = .{},

    /// Config strings are borrowed and must outlive the client.
    pub fn init(gpa: Allocator, cfg: Config) Client {
        return .{ .gpa = gpa, .cfg = cfg, .http = http.Client.init(gpa, cfg.http) };
    }

    pub fn deinit(c: *Client) void {
        c.dropToken();
        c.http.deinit();
    }

    fn dropToken(c: *Client) void {
        if (c.token) |t| {
            std.crypto.secureZero(u8, t);
            c.gpa.free(t);
            c.token = null;
        }
    }

    fn login(c: *Client) Error!void {
        var mount: []const u8 = undefined;
        const body = switch (c.cfg.auth) {
            .token => return,
            .approle => |ar| b: {
                mount = ar.mount;
                break :b try jsonObject(c.gpa, &.{ .{ "role_id", .{ .string = ar.role_id } }, .{ "secret_id", .{ .string = ar.secret_id } } });
            },
            .cert => |ca| b: {
                mount = ca.mount;
                break :b if (ca.role.len > 0) try jsonObject(c.gpa, &.{.{ "name", .{ .string = ca.role } }}) else try c.gpa.dupe(u8, "{}");
            },
        };
        defer wipeFree(c.gpa, body);
        const path = try std.fmt.allocPrint(c.gpa, "auth/{s}/login", .{mount});
        defer c.gpa.free(path);
        var resp = try c.raw(c.gpa, .POST, path, body, null);
        defer wipeResp(c.gpa, &resp);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(c.gpa, resp.body);
        defer parsed.deinit();
        const tok = getStr(parsed.value, &.{ "auth", "client_token" }) orelse return error.InvalidResponse;
        c.dropToken();
        c.token = try c.gpa.dupe(u8, tok);
        wipeConst(tok);
    }

    fn raw(c: *Client, gpa: Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8, token: ?[]const u8) Error!http.Response {
        const url = try std.fmt.allocPrint(gpa, "{s}/v1/{s}", .{ c.cfg.addr, path });
        defer gpa.free(url);
        var hs: [3]std.http.Header = undefined;
        var n: usize = 0;
        if (token) |t| {
            hs[n] = .{ .name = "X-Vault-Token", .value = t };
            n += 1;
        }
        if (c.cfg.namespace) |ns| {
            hs[n] = .{ .name = "X-Vault-Namespace", .value = ns };
            n += 1;
        }
        if (body != null) {
            hs[n] = .{ .name = "Content-Type", .value = "application/json" };
            n += 1;
        }
        return c.http.send(gpa, method, url, hs[0..n], body) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidArgument => error.InvalidArgument,
            error.BackendUnavailable => error.BackendUnavailable,
            error.InvalidResponse => error.InvalidResponse,
        };
    }

    /// Authenticated call; AppRole tokens are refreshed once on 403.
    pub fn call(c: *Client, gpa: Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8) Error!http.Response {
        c.mutex.lock();
        defer c.mutex.unlock();
        const is_token = c.cfg.auth == .token;
        if (!is_token and c.token == null) try c.login();
        const tok = if (is_token) c.cfg.auth.token else c.token.?;
        var resp = try c.raw(gpa, method, path, body, tok);
        if (resp.status == 403 and !is_token) {
            wipeResp(gpa, &resp);
            try c.login();
            resp = try c.raw(gpa, method, path, body, c.token.?);
        }
        return resp;
    }
};

// ---------- JSON helpers ----------

const Field = struct { []const u8, Value };

fn jsonObject(gpa: Allocator, fields: []const Field) Error![]u8 {
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

fn parseJson(gpa: Allocator, body: []const u8) Error!std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, gpa, body, .{ .allocate = .alloc_always }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidResponse,
    };
}

pub fn getPath(v: Value, path: []const []const u8) ?Value {
    var cur = v;
    for (path) |p| {
        if (cur != .object) return null;
        cur = cur.object.get(p) orelse return null;
    }
    return cur;
}

pub fn getStr(v: Value, path: []const []const u8) ?[]const u8 {
    const x = getPath(v, path) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn getInt(v: Value, path: []const []const u8) ?i64 {
    const x = getPath(v, path) orelse return null;
    return switch (x) {
        .integer => |i| i,
        .float => |f| if (std.math.isFinite(f) and @abs(f) < 1e15) @intFromFloat(f) else null,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn wipeConst(s: []const u8) void {
    std.crypto.secureZero(u8, @constCast(s));
}

fn wipeFree(gpa: Allocator, s: []u8) void {
    std.crypto.secureZero(u8, s);
    gpa.free(s);
}

fn wipeResp(gpa: Allocator, r: *http.Response) void {
    std.crypto.secureZero(u8, r.body);
    r.deinit(gpa);
}

fn statusError(status: u16, is_decrypt: bool) Error {
    return switch (status) {
        400 => if (is_decrypt) error.InvalidCiphertext else error.InvalidArgument,
        401, 403 => error.AccessDenied,
        404 => error.KeyNotFound,
        429, 500...599 => error.BackendUnavailable,
        else => error.InvalidResponse,
    };
}

fn decodeDek(s: []const u8) Error![types.dek_len]u8 {
    var out: [types.dek_len]u8 = undefined;
    const n = b64.Decoder.calcSizeForSlice(s) catch return error.InvalidResponse;
    if (n != types.dek_len) return error.InvalidResponse;
    b64.Decoder.decode(&out, s) catch return error.InvalidResponse;
    return out;
}

// ---------- Transit ----------

pub const TransitKms = struct {
    client: *Client,

    pub fn kms(self: *TransitKms) types.Kms {
        return .{ .ptr = self, .vtable = &.{
            .kind = .vault_transit,
            .createKey = createKey,
            .generateDataKey = generateDataKey,
            .decryptDataKey = decryptDataKey,
            .listKeys = listKeys,
            .keyStatus = keyStatus,
            .rotateKey = rotateKey,
        } };
    }

    fn cast(p: *anyopaque) *TransitKms {
        return @ptrCast(@alignCast(p));
    }

    fn path(self: *TransitKms, gpa: Allocator, op: []const u8, id: []const u8, suffix: []const u8) Error![]u8 {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        return std.fmt.allocPrint(gpa, "{s}/{s}/{s}{s}", .{ self.client.cfg.transit_mount, op, id, suffix });
    }

    fn contextB64(gpa: Allocator, ctx: types.Context) Error![]u8 {
        const c = try ctx.canonical(gpa);
        defer gpa.free(c);
        const out = try gpa.alloc(u8, b64.Encoder.calcSize(c.len));
        _ = b64.Encoder.encode(out, c);
        return out;
    }

    fn createKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const self = cast(p);
        if (keyStatus(p, gpa, id)) |ki| {
            var k = ki;
            k.deinit(gpa);
            return error.KeyExists;
        } else |e| if (e != error.KeyNotFound) return e;
        const pa = try self.path(gpa, "keys", id, "");
        defer gpa.free(pa);
        const body = try jsonObject(gpa, &.{ .{ "type", .{ .string = "aes256-gcm96" } }, .{ "derived", .{ .bool = true } } });
        defer gpa.free(body);
        var resp = try self.client.call(gpa, .POST, pa, body);
        defer resp.deinit(gpa);
        if (resp.status != 200 and resp.status != 204) return statusError(resp.status, false);
        return keyStatus(p, gpa, id);
    }

    fn generateDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, ctx: types.Context) Error!types.DataKey {
        const self = cast(p);
        const pa = try self.path(gpa, "datakey/plaintext", id, "");
        defer gpa.free(pa);
        const cb = try contextB64(gpa, ctx);
        defer gpa.free(cb);
        const body = try jsonObject(gpa, &.{ .{ "context", .{ .string = cb } }, .{ "bits", .{ .integer = 256 } } });
        defer gpa.free(body);
        var resp = try self.client.call(gpa, .POST, pa, body);
        defer wipeResp(gpa, &resp);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const pt = getStr(parsed.value, &.{ "data", "plaintext" }) orelse return error.InvalidResponse;
        defer wipeConst(pt);
        const ct = getStr(parsed.value, &.{ "data", "ciphertext" }) orelse return error.InvalidResponse;
        const ver = getInt(parsed.value, &.{ "data", "key_version" }) orelse 0;
        var dk: types.DataKey = .{ .plaintext = try decodeDek(pt), .sealed = &.{}, .key_version = std.math.cast(u32, ver) orelse 0 };
        errdefer std.crypto.secureZero(u8, &dk.plaintext);
        dk.sealed = try gpa.dupe(u8, ct);
        return dk;
    }

    fn decryptDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, sealed: []const u8, ctx: types.Context) Error![types.dek_len]u8 {
        const self = cast(p);
        if (!std.mem.startsWith(u8, sealed, "vault:v")) return error.InvalidCiphertext;
        const pa = try self.path(gpa, "decrypt", id, "");
        defer gpa.free(pa);
        const cb = try contextB64(gpa, ctx);
        defer gpa.free(cb);
        const body = try jsonObject(gpa, &.{ .{ "ciphertext", .{ .string = sealed } }, .{ "context", .{ .string = cb } } });
        defer gpa.free(body);
        var resp = try self.client.call(gpa, .POST, pa, body);
        defer wipeResp(gpa, &resp);
        if (resp.status != 200) return statusError(resp.status, true);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const pt = getStr(parsed.value, &.{ "data", "plaintext" }) orelse return error.InvalidResponse;
        defer wipeConst(pt);
        return decodeDek(pt);
    }

    fn keyStatus(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const self = cast(p);
        const pa = try self.path(gpa, "keys", id, "");
        defer gpa.free(pa);
        var resp = try self.client.call(gpa, .GET, pa, null);
        defer resp.deinit(gpa);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const latest = getInt(parsed.value, &.{ "data", "latest_version" }) orelse return error.InvalidResponse;
        const created = getInt(parsed.value, &.{ "data", "keys", "1" }) orelse 0;
        const auto = getInt(parsed.value, &.{ "data", "auto_rotate_period" }) orelse 0;
        return .{
            .id = try gpa.dupe(u8, id),
            .state = .enabled,
            .version = std.math.cast(u32, latest) orelse return error.InvalidResponse,
            .created_unix = created,
            .rotation_enabled = auto > 0,
        };
    }

    fn listKeys(p: *anyopaque, gpa: Allocator) Error![]types.KeyInfo {
        const self = cast(p);
        const pa = try std.fmt.allocPrint(gpa, "{s}/keys?list=true", .{self.client.cfg.transit_mount});
        defer gpa.free(pa);
        var resp = try self.client.call(gpa, .GET, pa, null);
        defer resp.deinit(gpa);
        if (resp.status == 404) return gpa.alloc(types.KeyInfo, 0);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const keys = getPath(parsed.value, &.{ "data", "keys" }) orelse return error.InvalidResponse;
        if (keys != .array) return error.InvalidResponse;
        var out: std.ArrayList(types.KeyInfo) = .empty;
        errdefer {
            for (out.items) |*k| k.deinit(gpa);
            out.deinit(gpa);
        }
        for (keys.array.items) |k| {
            if (k != .string or !types.validKeyName(k.string)) continue;
            var ki = keyStatus(p, gpa, k.string) catch |e| switch (e) {
                error.KeyNotFound => continue,
                else => return e,
            };
            out.append(gpa, ki) catch {
                ki.deinit(gpa);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(gpa);
    }

    fn rotateKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const self = cast(p);
        const pa = try self.path(gpa, "keys", id, "/rotate");
        defer gpa.free(pa);
        var resp = try self.client.call(gpa, .POST, pa, "{}");
        defer resp.deinit(gpa);
        if (resp.status != 200 and resp.status != 204) return statusError(resp.status, false);
        return keyStatus(p, gpa, id);
    }
};

// ---------- KV v2 ----------

pub const Kv2Store = struct {
    client: *Client,

    pub fn keyStore(self: *Kv2Store) keyring.KeyStore {
        return .{ .ptr = self, .vtable = &.{ .load = load, .store = store, .list = list } };
    }

    fn cast(p: *anyopaque) *Kv2Store {
        return @ptrCast(@alignCast(p));
    }

    fn load(p: *anyopaque, gpa: Allocator, id: []const u8) Error!keyring.KeyRecord {
        const self = cast(p);
        if (!types.validKeyName(id)) return error.InvalidArgument;
        const cfg = self.client.cfg;
        const pa = try std.fmt.allocPrint(gpa, "{s}/data/{s}/{s}", .{ cfg.kv_mount, cfg.kv_prefix, id });
        defer gpa.free(pa);
        var resp = try self.client.call(gpa, .GET, pa, null);
        defer wipeResp(gpa, &resp);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const rec_js = getStr(parsed.value, &.{ "data", "data", "record" }) orelse return error.InvalidResponse;
        defer wipeConst(rec_js);
        var rec = try keyring.KeyRecord.fromJson(gpa, rec_js);
        if (!std.mem.eql(u8, rec.id, id)) {
            rec.deinit(gpa);
            return error.InvalidResponse;
        }
        return rec;
    }

    fn store(p: *anyopaque, gpa: Allocator, rec: keyring.KeyRecord, mode: keyring.KeyStore.Mode) Error!void {
        const self = cast(p);
        const cfg = self.client.cfg;
        const pa = try std.fmt.allocPrint(gpa, "{s}/data/{s}/{s}", .{ cfg.kv_mount, cfg.kv_prefix, rec.id });
        defer gpa.free(pa);
        const rec_js = try rec.toJson(gpa);
        defer wipeFree(gpa, rec_js);
        var data: std.json.ObjectMap = .init(gpa);
        defer data.deinit();
        try data.put("record", .{ .string = rec_js });
        var opts: std.json.ObjectMap = .init(gpa);
        defer opts.deinit();
        if (mode == .create) try opts.put("cas", .{ .integer = 0 });
        const body = try jsonObject(gpa, &.{ .{ "options", .{ .object = opts } }, .{ "data", .{ .object = data } } });
        defer wipeFree(gpa, body);
        var resp = try self.client.call(gpa, .POST, pa, body);
        defer resp.deinit(gpa);
        if (resp.status == 400 and mode == .create and std.mem.indexOf(u8, resp.body, "check-and-set") != null) return error.KeyExists;
        if (resp.status != 200 and resp.status != 204) return statusError(resp.status, false);
    }

    fn list(p: *anyopaque, gpa: Allocator) Error![][]u8 {
        const self = cast(p);
        const cfg = self.client.cfg;
        const pa = try std.fmt.allocPrint(gpa, "{s}/metadata/{s}?list=true", .{ cfg.kv_mount, cfg.kv_prefix });
        defer gpa.free(pa);
        var resp = try self.client.call(gpa, .GET, pa, null);
        defer resp.deinit(gpa);
        if (resp.status == 404) return gpa.alloc([]u8, 0);
        if (resp.status != 200) return statusError(resp.status, false);
        const parsed = try parseJson(gpa, resp.body);
        defer parsed.deinit();
        const keys = getPath(parsed.value, &.{ "data", "keys" }) orelse return error.InvalidResponse;
        if (keys != .array) return error.InvalidResponse;
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |n| gpa.free(n);
            out.deinit(gpa);
        }
        for (keys.array.items) |k| {
            if (k != .string or !types.validKeyName(k.string)) continue;
            const d = try gpa.dupe(u8, k.string);
            out.append(gpa, d) catch {
                gpa.free(d);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(gpa);
    }
};

/// KV2-backed Kms; keep alive as long as the returned handle is used.
pub const Kv2Kms = struct {
    store: Kv2Store,
    ring: keyring.KeyringKms,

    pub fn init(self: *Kv2Kms, client: *Client) void {
        self.store = .{ .client = client };
        self.ring = .{ .store = self.store.keyStore(), .kind = .vault_kv2 };
    }

    pub fn kms(self: *Kv2Kms) types.Kms {
        return self.ring.kms();
    }
};

// ---------- Live tests (ZKFSM_KMS_TEST_VAULT_ADDR + ZKFSM_KMS_TEST_VAULT_TOKEN; see tests/kms.sh) ----------

const testing = std.testing;

fn liveEnv(gpa: Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(gpa, name) catch null;
}

fn uniqueName(buf: []u8, prefix: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}-{x}", .{ prefix, std.crypto.random.int(u32) }) catch unreachable;
}

fn exerciseKms(gpa: Allocator, k: types.Kms, name: []const u8) !void {
    var ki = try k.createKey(gpa, name);
    ki.deinit(gpa);
    try testing.expectError(error.KeyExists, k.createKey(gpa, name));
    const ctx: types.Context = .{ .pairs = &.{ .{ .key = "bucket", .value = "b" }, .{ .key = "object", .value = "o" } } };
    var dk = try k.generateDataKey(gpa, name, ctx);
    defer dk.deinit(gpa);
    const back = try k.decryptDataKey(gpa, name, dk.sealed, ctx);
    try testing.expectEqualSlices(u8, &dk.plaintext, &back);
    const wrong: types.Context = .{ .pairs = &.{.{ .key = "bucket", .value = "x" }} };
    try testing.expectError(error.InvalidCiphertext, k.decryptDataKey(gpa, name, dk.sealed, wrong));
    var st = try k.keyStatus(gpa, name);
    try testing.expectEqual(@as(u32, 1), st.version);
    st.deinit(gpa);
    var r = try k.rotateKey(gpa, name);
    try testing.expectEqual(@as(u32, 2), r.version);
    r.deinit(gpa);
    const again = try k.decryptDataKey(gpa, name, dk.sealed, ctx);
    try testing.expectEqualSlices(u8, &dk.plaintext, &again);
    var dk2 = try k.generateDataKey(gpa, name, ctx);
    defer dk2.deinit(gpa);
    try testing.expectEqual(@as(u32, 2), dk2.key_version);
    const l = try k.listKeys(gpa);
    defer types.freeKeyInfos(gpa, l);
    var found = false;
    for (l) |x| found = found or std.mem.eql(u8, x.id, name);
    try testing.expect(found);
    try testing.expectError(error.KeyNotFound, k.keyStatus(gpa, "does-not-exist-zz"));
}

test "vault live: transit and kv2" {
    const gpa = testing.allocator;
    const addr = liveEnv(gpa, "ZKFSM_KMS_TEST_VAULT_ADDR") orelse return error.SkipZigTest;
    defer gpa.free(addr);
    const token = liveEnv(gpa, "ZKFSM_KMS_TEST_VAULT_TOKEN") orelse return error.SkipZigTest;
    defer wipeFree(gpa, token);

    var client = Client.init(gpa, .{ .addr = addr, .auth = .{ .token = token }, .http = .{ .timeout_ms = 5000 } });
    defer client.deinit();

    var nb: [64]u8 = undefined;
    var transit: TransitKms = .{ .client = &client };
    try exerciseKms(gpa, transit.kms(), uniqueName(&nb, "zkfsm-test-transit"));
    // Tampered transit ciphertext is rejected.
    try testing.expectError(error.InvalidCiphertext, transit.kms().decryptDataKey(gpa, "zkfsm-test-nokey", "not-vault", .{}));

    var kv: Kv2Kms = undefined;
    kv.init(&client);
    var nb2: [64]u8 = undefined;
    try exerciseKms(gpa, kv.kms(), uniqueName(&nb2, "zkfsm-test-kv"));

    // AppRole auth, if the harness provisioned a role.
    const role = liveEnv(gpa, "ZKFSM_KMS_TEST_VAULT_ROLE_ID") orelse return;
    defer gpa.free(role);
    const secret = liveEnv(gpa, "ZKFSM_KMS_TEST_VAULT_SECRET_ID") orelse return;
    defer wipeFree(gpa, secret);
    var ac = Client.init(gpa, .{ .addr = addr, .auth = .{ .approle = .{ .role_id = role, .secret_id = secret } } });
    defer ac.deinit();
    var at: TransitKms = .{ .client = &ac };
    var nb3: [64]u8 = undefined;
    try exerciseKms(gpa, at.kms(), uniqueName(&nb3, "zkfsm-test-approle"));
    log.info("vault live test passed", .{});
}
