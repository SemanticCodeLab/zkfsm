//! Locally-wrapped master keys: a versioned key record kept in some store
//! (dev file, Vault KV2) and a Kms implementation that wraps DEKs with
//! AES-256-GCM under the record's current version.
const std = @import("std");
const types = @import("types.zig");

const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
const b64 = std.base64.standard;
const Error = types.Error;
const Allocator = std.mem.Allocator;

pub const format_version: u32 = 1;
const seal_magic = [2]u8{ 'K', '1' };
const sealed_len = 2 + 4 + Aes.nonce_length + types.dek_len + Aes.tag_length;

pub const Version = struct { n: u32, key: [32]u8 };

/// One master key with all its versions. Owns `id` and `versions`.
pub const KeyRecord = struct {
    id: []u8,
    state: types.KeyState,
    created_unix: i64,
    current: u32,
    versions: []Version,
    tags: []types.Tag = &.{},

    pub fn deinit(r: *KeyRecord, gpa: Allocator) void {
        for (r.versions) |*v| std.crypto.secureZero(u8, &v.key);
        gpa.free(r.versions);
        types.freeTags(gpa, r.tags);
        gpa.free(r.id);
        r.* = undefined;
    }

    pub fn generate(gpa: Allocator, id: []const u8, now: i64) Error!KeyRecord {
        const vs = try gpa.alloc(Version, 1);
        errdefer gpa.free(vs);
        vs[0] = .{ .n = 1, .key = undefined };
        std.crypto.random.bytes(&vs[0].key);
        return .{ .id = try gpa.dupe(u8, id), .state = .enabled, .created_unix = now, .current = 1, .versions = vs };
    }

    pub fn find(r: KeyRecord, n: u32) ?*const Version {
        for (r.versions) |*v| if (v.n == n) return v;
        return null;
    }

    /// Appends a fresh version and makes it current.
    pub fn rotate(r: *KeyRecord, gpa: Allocator) Error!void {
        const vs = try gpa.alloc(Version, r.versions.len + 1);
        @memcpy(vs[0..r.versions.len], r.versions);
        const next = r.current + 1;
        vs[r.versions.len] = .{ .n = next, .key = undefined };
        std.crypto.random.bytes(&vs[r.versions.len].key);
        for (r.versions) |*v| std.crypto.secureZero(u8, &v.key);
        gpa.free(r.versions);
        r.versions = vs;
        r.current = next;
    }

    pub fn info(r: KeyRecord, gpa: Allocator) Error!types.KeyInfo {
        return .{ .id = try gpa.dupe(u8, r.id), .state = r.state, .version = r.current, .created_unix = r.created_unix };
    }

    /// Serialized record contains key material; caller must secureZero + free.
    pub fn toJson(r: KeyRecord, gpa: Allocator) Error![]u8 {
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer {
            std.crypto.secureZero(u8, out.writer.buffer);
            out.deinit();
        }
        var js: std.json.Stringify = .{ .writer = &out.writer };
        writeJson(r, &js) catch return error.OutOfMemory;
        return out.toOwnedSlice() catch error.OutOfMemory;
    }

    fn writeJson(r: KeyRecord, js: *std.json.Stringify) std.Io.Writer.Error!void {
        try js.beginObject();
        try js.objectField("format");
        try js.write(format_version);
        try js.objectField("id");
        try js.write(r.id);
        try js.objectField("state");
        try js.write(r.state.text());
        try js.objectField("created");
        try js.write(r.created_unix);
        try js.objectField("current");
        try js.write(r.current);
        try js.objectField("versions");
        try js.beginArray();
        for (r.versions) |v| {
            var enc: [b64.Encoder.calcSize(32)]u8 = undefined;
            defer std.crypto.secureZero(u8, &enc);
            try js.beginObject();
            try js.objectField("v");
            try js.write(v.n);
            try js.objectField("key");
            try js.write(b64.Encoder.encode(&enc, &v.key));
            try js.endObject();
        }
        try js.endArray();
        if (r.tags.len > 0) {
            try js.objectField("tags");
            try js.beginArray();
            for (r.tags) |t| {
                try js.beginObject();
                try js.objectField("k");
                try js.write(t.key);
                try js.objectField("v");
                try js.write(t.value);
                try js.endObject();
            }
            try js.endArray();
        }
        try js.endObject();
    }

    pub fn fromJson(gpa: Allocator, bytes: []const u8) Error!KeyRecord {
        const Wire = struct {
            format: u32,
            id: []const u8,
            state: []const u8,
            created: i64,
            current: u32,
            versions: []const struct { v: u32, key: []const u8 },
            tags: []const struct { k: []const u8, v: []const u8 } = &.{},
        };
        const parsed = std.json.parseFromSlice(Wire, gpa, bytes, .{ .allocate = .alloc_always }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidResponse,
        };
        defer {
            for (parsed.value.versions) |v| std.crypto.secureZero(u8, @constCast(v.key));
            parsed.deinit();
        }
        const w = parsed.value;
        if (w.format != format_version or !types.validKeyName(w.id) or w.versions.len == 0) return error.InvalidResponse;
        if (w.tags.len > types.max_tags) return error.InvalidResponse;
        for (w.tags) |t| if (!types.validTag(t.k, t.v)) return error.InvalidResponse;
        const vs = try gpa.alloc(Version, w.versions.len);
        errdefer {
            for (vs) |*v| std.crypto.secureZero(u8, &v.key);
            gpa.free(vs);
        }
        for (w.versions, vs) |src, *dst| {
            dst.n = src.v;
            const n = b64.Decoder.calcSizeForSlice(src.key) catch return error.InvalidResponse;
            if (n != 32) return error.InvalidResponse;
            b64.Decoder.decode(&dst.key, src.key) catch return error.InvalidResponse;
        }
        const id = try gpa.dupe(u8, w.id);
        errdefer gpa.free(id);
        const tags = try gpa.alloc(types.Tag, w.tags.len);
        var nt: usize = 0;
        errdefer types.freeTags(gpa, tags[0..nt]);
        for (w.tags) |t| {
            const k = try gpa.dupe(u8, t.k);
            const v = gpa.dupe(u8, t.v) catch |e| {
                gpa.free(k);
                return e;
            };
            tags[nt] = .{ .key = k, .value = v };
            nt += 1;
        }
        var rec: KeyRecord = .{ .id = id, .state = types.KeyState.parse(w.state), .created_unix = w.created, .current = w.current, .versions = vs, .tags = tags };
        if (rec.find(rec.current) == null) {
            rec.deinit(gpa);
            return error.InvalidResponse;
        }
        return rec;
    }
};

fn buildAad(gpa: Allocator, key_id: []const u8, ctx: types.Context) Error![]u8 {
    const c = try ctx.canonical(gpa);
    defer gpa.free(c);
    return std.mem.concat(gpa, u8, &.{ "zkfsm-kms-v1\x00", key_id, "\x00", c });
}

pub fn seal(gpa: Allocator, rec: KeyRecord, dek: *const [types.dek_len]u8, ctx: types.Context) Error![]u8 {
    const v = rec.find(rec.current) orelse return error.InvalidResponse;
    const aad = try buildAad(gpa, rec.id, ctx);
    defer gpa.free(aad);
    const out = try gpa.alloc(u8, sealed_len);
    out[0..2].* = seal_magic;
    std.mem.writeInt(u32, out[2..6], v.n, .big);
    const nonce = out[6..][0..Aes.nonce_length];
    std.crypto.random.bytes(nonce);
    const ct = out[6 + Aes.nonce_length ..][0..types.dek_len];
    const tag = out[sealed_len - Aes.tag_length ..][0..Aes.tag_length];
    Aes.encrypt(ct, tag, dek, aad, nonce.*, v.key);
    return out;
}

pub fn unseal(gpa: Allocator, rec: KeyRecord, sealed: []const u8, ctx: types.Context) Error![types.dek_len]u8 {
    if (sealed.len != sealed_len or !std.mem.eql(u8, sealed[0..2], &seal_magic)) return error.InvalidCiphertext;
    const vn = std.mem.readInt(u32, sealed[2..6], .big);
    const v = rec.find(vn) orelse return error.InvalidCiphertext;
    const aad = try buildAad(gpa, rec.id, ctx);
    defer gpa.free(aad);
    var dek: [types.dek_len]u8 = undefined;
    Aes.decrypt(&dek, sealed[6 + Aes.nonce_length ..][0..types.dek_len], sealed[sealed_len - Aes.tag_length ..][0..Aes.tag_length].*, aad, sealed[6..][0..Aes.nonce_length].*, v.key) catch return error.InvalidCiphertext;
    return dek;
}

/// Persistence for key records. `store` with `.create` fails with KeyExists.
pub const KeyStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Mode = enum { create, replace };
    pub const VTable = struct {
        load: *const fn (*anyopaque, Allocator, []const u8) Error!KeyRecord,
        store: *const fn (*anyopaque, Allocator, KeyRecord, Mode) Error!void,
        list: *const fn (*anyopaque, Allocator) Error![][]u8,
        /// Null when the store cannot delete records.
        remove: ?*const fn (*anyopaque, Allocator, []const u8) Error!void = null,
    };

    pub fn load(s: KeyStore, gpa: Allocator, id: []const u8) Error!KeyRecord {
        return s.vtable.load(s.ptr, gpa, id);
    }
    pub fn store(s: KeyStore, gpa: Allocator, rec: KeyRecord, mode: Mode) Error!void {
        return s.vtable.store(s.ptr, gpa, rec, mode);
    }
    pub fn list(s: KeyStore, gpa: Allocator) Error![][]u8 {
        return s.vtable.list(s.ptr, gpa);
    }
    pub fn remove(s: KeyStore, gpa: Allocator, id: []const u8) Error!void {
        const f = s.vtable.remove orelse return error.Unsupported;
        return f(s.ptr, gpa, id);
    }
};

pub fn freeNames(gpa: Allocator, names: [][]u8) void {
    for (names) |n| gpa.free(n);
    gpa.free(names);
}

/// Kms over a KeyStore; DEKs are wrapped locally.
pub const KeyringKms = struct {
    store: KeyStore,
    kind: types.BackendKind,

    pub fn kms(self: *KeyringKms) types.Kms {
        return .{ .ptr = self, .vtable = switch (self.kind) {
            .vault_kv2 => &vt_kv2,
            else => &vt_local,
        } };
    }

    const vt_local = makeVTable(.local);
    const vt_kv2 = makeVTable(.vault_kv2);

    fn makeVTable(comptime k: types.BackendKind) types.Kms.VTable {
        return .{
            .kind = k,
            .createKey = createKey,
            .generateDataKey = generateDataKey,
            .decryptDataKey = decryptDataKey,
            .listKeys = listKeys,
            .keyStatus = keyStatus,
            .rotateKey = rotateKey,
            .setKeyState = setKeyState,
            .deleteKey = deleteKey,
            .keyTags = keyTags,
            .setKeyTags = setKeyTags,
            .sealDataKey = sealDataKey,
        };
    }

    fn cast(p: *anyopaque) *KeyringKms {
        return @ptrCast(@alignCast(p));
    }

    fn createKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try KeyRecord.generate(gpa, id, std.time.timestamp());
        defer rec.deinit(gpa);
        try cast(p).store.store(gpa, rec, .create);
        return rec.info(gpa);
    }

    fn loadEnabled(self: *KeyringKms, gpa: Allocator, id: []const u8) Error!KeyRecord {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try self.store.load(gpa, id);
        if (rec.state != .enabled) {
            rec.deinit(gpa);
            return error.KeyDisabled;
        }
        return rec;
    }

    fn generateDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, ctx: types.Context) Error!types.DataKey {
        var rec = try cast(p).loadEnabled(gpa, id);
        defer rec.deinit(gpa);
        var dk: types.DataKey = .{ .plaintext = undefined, .sealed = &.{}, .key_version = rec.current };
        std.crypto.random.bytes(&dk.plaintext);
        errdefer std.crypto.secureZero(u8, &dk.plaintext);
        dk.sealed = try seal(gpa, rec, &dk.plaintext, ctx);
        return dk;
    }

    /// A disabled key still opens existing objects; only new use is refused.
    fn decryptDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, sealed: []const u8, ctx: types.Context) Error![types.dek_len]u8 {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try cast(p).store.load(gpa, id);
        defer rec.deinit(gpa);
        if (rec.state != .enabled and rec.state != .disabled) return error.KeyDisabled;
        return unseal(gpa, rec, sealed, ctx);
    }

    fn sealDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, dek: *const [types.dek_len]u8, ctx: types.Context) Error!types.DataKey {
        var rec = try cast(p).loadEnabled(gpa, id);
        defer rec.deinit(gpa);
        var dk: types.DataKey = .{ .plaintext = dek.*, .sealed = &.{}, .key_version = rec.current };
        errdefer std.crypto.secureZero(u8, &dk.plaintext);
        dk.sealed = try seal(gpa, rec, dek, ctx);
        return dk;
    }

    fn setKeyState(p: *anyopaque, gpa: Allocator, id: []const u8, state: types.KeyState) Error!void {
        const self = cast(p);
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try self.store.load(gpa, id);
        defer rec.deinit(gpa);
        if (rec.state == state) return;
        rec.state = state;
        try self.store.store(gpa, rec, .replace);
    }

    fn deleteKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!void {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        return cast(p).store.remove(gpa, id);
    }

    fn keyTags(p: *anyopaque, gpa: Allocator, id: []const u8) Error![]types.Tag {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try cast(p).store.load(gpa, id);
        defer rec.deinit(gpa);
        return types.dupeTags(gpa, rec.tags);
    }

    fn setKeyTags(p: *anyopaque, gpa: Allocator, id: []const u8, tags: []const types.Tag) Error!void {
        const self = cast(p);
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try self.store.load(gpa, id);
        defer rec.deinit(gpa);
        const fresh = try types.dupeTags(gpa, tags);
        types.freeTags(gpa, rec.tags);
        rec.tags = fresh;
        try self.store.store(gpa, rec, .replace);
    }

    fn listKeys(p: *anyopaque, gpa: Allocator) Error![]types.KeyInfo {
        const self = cast(p);
        const names = try self.store.list(gpa);
        defer freeNames(gpa, names);
        var out: std.ArrayList(types.KeyInfo) = .empty;
        errdefer {
            for (out.items) |*k| k.deinit(gpa);
            out.deinit(gpa);
        }
        for (names) |n| {
            var rec = self.store.load(gpa, n) catch |e| switch (e) {
                error.KeyNotFound => continue,
                else => return e,
            };
            defer rec.deinit(gpa);
            const ki = try rec.info(gpa);
            out.append(gpa, ki) catch {
                gpa.free(ki.id);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(gpa);
    }

    fn keyStatus(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        var rec = try cast(p).store.load(gpa, id);
        defer rec.deinit(gpa);
        return rec.info(gpa);
    }

    fn rotateKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const self = cast(p);
        var rec = try self.loadEnabled(gpa, id);
        defer rec.deinit(gpa);
        try rec.rotate(gpa);
        try self.store.store(gpa, rec, .replace);
        return rec.info(gpa);
    }
};

/// In-memory store for tests.
pub const MemoryStore = struct {
    gpa: Allocator,
    map: std.StringArrayHashMapUnmanaged([]u8) = .empty,

    pub fn deinit(m: *MemoryStore) void {
        for (m.map.keys(), m.map.values()) |k, v| {
            std.crypto.secureZero(u8, v);
            m.gpa.free(k);
            m.gpa.free(v);
        }
        m.map.deinit(m.gpa);
    }

    pub fn keyStore(m: *MemoryStore) KeyStore {
        return .{ .ptr = m, .vtable = &.{ .load = load, .store = store, .list = list, .remove = remove } };
    }

    fn remove(p: *anyopaque, _: Allocator, id: []const u8) Error!void {
        const m: *MemoryStore = @ptrCast(@alignCast(p));
        const kv = m.map.fetchSwapRemove(id) orelse return error.KeyNotFound;
        std.crypto.secureZero(u8, kv.value);
        m.gpa.free(kv.key);
        m.gpa.free(kv.value);
    }

    fn load(p: *anyopaque, gpa: Allocator, id: []const u8) Error!KeyRecord {
        const m: *MemoryStore = @ptrCast(@alignCast(p));
        const v = m.map.get(id) orelse return error.KeyNotFound;
        return KeyRecord.fromJson(gpa, v);
    }

    fn store(p: *anyopaque, gpa: Allocator, rec: KeyRecord, mode: KeyStore.Mode) Error!void {
        const m: *MemoryStore = @ptrCast(@alignCast(p));
        const js = try rec.toJson(m.gpa);
        errdefer {
            std.crypto.secureZero(u8, js);
            m.gpa.free(js);
        }
        _ = gpa;
        const gop = try m.map.getOrPut(m.gpa, rec.id);
        if (gop.found_existing) {
            if (mode == .create) return error.KeyExists;
            std.crypto.secureZero(u8, gop.value_ptr.*);
            m.gpa.free(gop.value_ptr.*);
        } else {
            gop.key_ptr.* = m.gpa.dupe(u8, rec.id) catch |e| {
                m.map.swapRemoveAt(gop.index);
                return e;
            };
        }
        gop.value_ptr.* = js;
    }

    fn list(p: *anyopaque, gpa: Allocator) Error![][]u8 {
        const m: *MemoryStore = @ptrCast(@alignCast(p));
        const out = try gpa.alloc([]u8, m.map.count());
        var n: usize = 0;
        errdefer freeNames(gpa, out[0..n]);
        for (m.map.keys()) |k| {
            out[n] = try gpa.dupe(u8, k);
            n += 1;
        }
        return out;
    }
};

test "keyring record json round trip" {
    const gpa = std.testing.allocator;
    var r = try KeyRecord.generate(gpa, "k1", 1700000000);
    defer r.deinit(gpa);
    try r.rotate(gpa);
    const js = try r.toJson(gpa);
    defer gpa.free(js);
    var back = try KeyRecord.fromJson(gpa, js);
    defer back.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), back.current);
    try std.testing.expectEqualSlices(u8, &r.versions[1].key, &back.versions[1].key);
    try std.testing.expectError(error.InvalidResponse, KeyRecord.fromJson(gpa, "{\"format\":9}"));
}

test "keyring kms full lifecycle" {
    const gpa = std.testing.allocator;
    var mem: MemoryStore = .{ .gpa = gpa };
    defer mem.deinit();
    var kr: KeyringKms = .{ .store = mem.keyStore(), .kind = .local };
    const k = kr.kms();
    var ki = try k.createKey(gpa, "master");
    ki.deinit(gpa);
    try std.testing.expectError(error.KeyExists, k.createKey(gpa, "master"));
    try std.testing.expectError(error.InvalidArgument, k.createKey(gpa, "../x"));

    const ctx: types.Context = .{ .pairs = &.{.{ .key = "bucket", .value = "b1" }} };
    var dk = try k.generateDataKey(gpa, "master", ctx);
    defer dk.deinit(gpa);
    const back = try k.decryptDataKey(gpa, "master", dk.sealed, ctx);
    try std.testing.expectEqualSlices(u8, &dk.plaintext, &back);

    const other: types.Context = .{ .pairs = &.{.{ .key = "bucket", .value = "b2" }} };
    try std.testing.expectError(error.InvalidCiphertext, k.decryptDataKey(gpa, "master", dk.sealed, other));
    dk.sealed[10] ^= 1;
    try std.testing.expectError(error.InvalidCiphertext, k.decryptDataKey(gpa, "master", dk.sealed, ctx));
    dk.sealed[10] ^= 1;

    var rk = try k.rotateKey(gpa, "master");
    defer rk.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), rk.version);
    // Old DEKs stay decryptable after rotation.
    _ = try k.decryptDataKey(gpa, "master", dk.sealed, ctx);
    var dk2 = try k.generateDataKey(gpa, "master", ctx);
    defer dk2.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), dk2.key_version);

    const list = try k.listKeys(gpa);
    defer types.freeKeyInfos(gpa, list);
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectError(error.KeyNotFound, k.keyStatus(gpa, "nope"));

    // Disabled: no new data keys, existing ones still open; tags persist.
    try k.setKeyState(gpa, "master", .disabled);
    try std.testing.expectError(error.KeyDisabled, k.generateDataKey(gpa, "master", ctx));
    try std.testing.expectError(error.KeyDisabled, k.sealDataKey(gpa, "master", &dk.plaintext, ctx));
    _ = try k.decryptDataKey(gpa, "master", dk.sealed, ctx);
    try k.setKeyState(gpa, "master", .enabled);
    var ka = "env".*;
    var va = "prod".*;
    try k.setKeyTags(gpa, "master", &.{.{ .key = &ka, .value = &va }});
    const tags = try k.keyTags(gpa, "master");
    defer types.freeTags(gpa, tags);
    try std.testing.expectEqualStrings("prod", tags[0].value);
    try std.testing.expectError(error.InvalidArgument, k.setKeyTags(gpa, "master", &.{ .{ .key = &ka, .value = &va }, .{ .key = &ka, .value = &va } }));
    var resealed = try k.sealDataKey(gpa, "master", &dk.plaintext, other);
    defer resealed.deinit(gpa);
    const again = try k.decryptDataKey(gpa, "master", resealed.sealed, other);
    try std.testing.expectEqualSlices(u8, &dk.plaintext, &again);
    try k.deleteKey(gpa, "master");
    try std.testing.expectError(error.KeyNotFound, k.keyStatus(gpa, "master"));
    try std.testing.expectError(error.KeyNotFound, k.deleteKey(gpa, "master"));
}
