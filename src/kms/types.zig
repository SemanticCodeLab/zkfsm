//! Core KMS interface shared by every backend.
//! A backend owns master keys; callers only ever see per-object data keys
//! (DEKs) in plaintext, plus an opaque sealed form to persist with the object.
const std = @import("std");

pub const dek_len = 32;

pub const Error = error{
    OutOfMemory,
    InvalidArgument,
    KeyNotFound,
    KeyExists,
    KeyDisabled,
    AccessDenied,
    /// Sealed key failed authentication (tampered, wrong key or context).
    InvalidCiphertext,
    BackendUnavailable,
    InvalidResponse,
    Unsupported,
    StorageFailed,
};

pub const KeyState = enum {
    enabled,
    disabled,
    pending_deletion,
    unknown,

    pub fn text(s: KeyState) []const u8 {
        return @tagName(s);
    }

    pub fn parse(s: []const u8) KeyState {
        return std.meta.stringToEnum(KeyState, s) orelse .unknown;
    }
};

pub const BackendKind = enum { local, vault_transit, vault_kv2, kms_api };

/// Metadata about a master key. Strings are owned by `allocator` passed to
/// the producing call; free with `deinit`.
pub const KeyInfo = struct {
    id: []u8,
    state: KeyState,
    /// Latest key version (1-based); 0 when the backend does not expose it.
    version: u32,
    created_unix: i64,
    rotation_enabled: bool = false,

    pub fn deinit(k: *KeyInfo, gpa: std.mem.Allocator) void {
        gpa.free(k.id);
        k.* = undefined;
    }
};

pub fn freeKeyInfos(gpa: std.mem.Allocator, list: []KeyInfo) void {
    for (list) |*k| k.deinit(gpa);
    gpa.free(list);
}

/// A freshly generated DEK. `plaintext` must be wiped via `deinit` as soon as
/// the object cipher is keyed.
pub const DataKey = struct {
    plaintext: [dek_len]u8,
    sealed: []u8,
    key_version: u32,

    pub fn deinit(d: *DataKey, gpa: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &d.plaintext);
        gpa.free(d.sealed);
        d.* = undefined;
    }
};

/// Encryption context: string pairs bound to a sealed DEK as AAD. Order of
/// pairs is irrelevant; canonical form sorts by key.
pub const Context = struct {
    pairs: []const Pair = &.{},

    pub const Pair = struct { key: []const u8, value: []const u8 };

    /// Canonical JSON object with keys sorted bytewise; duplicate keys rejected.
    pub fn canonical(c: Context, gpa: std.mem.Allocator) Error![]u8 {
        const idx = try gpa.alloc(usize, c.pairs.len);
        defer gpa.free(idx);
        for (idx, 0..) |*v, i| v.* = i;
        std.mem.sort(usize, idx, c, lessThan);
        for (idx[0..idx.len -| 1], 1..) |a, j| {
            if (std.mem.eql(u8, c.pairs[a].key, c.pairs[idx[j]].key)) return error.InvalidArgument;
        }
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        var js: std.json.Stringify = .{ .writer = &out.writer };
        js.beginObject() catch return error.OutOfMemory;
        for (idx) |i| {
            js.objectField(c.pairs[i].key) catch return error.OutOfMemory;
            js.write(c.pairs[i].value) catch return error.OutOfMemory;
        }
        js.endObject() catch return error.OutOfMemory;
        return out.toOwnedSlice() catch error.OutOfMemory;
    }

    fn lessThan(c: Context, a: usize, b: usize) bool {
        return std.mem.lessThan(u8, c.pairs[a].key, c.pairs[b].key);
    }
};

/// Type-erased KMS handle. All returned memory is owned by the `gpa` passed in.
pub const Kms = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        kind: BackendKind,
        createKey: *const fn (*anyopaque, std.mem.Allocator, []const u8) Error!KeyInfo,
        generateDataKey: *const fn (*anyopaque, std.mem.Allocator, []const u8, Context) Error!DataKey,
        decryptDataKey: *const fn (*anyopaque, std.mem.Allocator, []const u8, []const u8, Context) Error![dek_len]u8,
        listKeys: *const fn (*anyopaque, std.mem.Allocator) Error![]KeyInfo,
        keyStatus: *const fn (*anyopaque, std.mem.Allocator, []const u8) Error!KeyInfo,
        rotateKey: *const fn (*anyopaque, std.mem.Allocator, []const u8) Error!KeyInfo,
    };

    pub fn kind(k: Kms) BackendKind {
        return k.vtable.kind;
    }
    pub fn createKey(k: Kms, gpa: std.mem.Allocator, key_id: []const u8) Error!KeyInfo {
        return k.vtable.createKey(k.ptr, gpa, key_id);
    }
    pub fn generateDataKey(k: Kms, gpa: std.mem.Allocator, key_id: []const u8, ctx: Context) Error!DataKey {
        return k.vtable.generateDataKey(k.ptr, gpa, key_id, ctx);
    }
    pub fn decryptDataKey(k: Kms, gpa: std.mem.Allocator, key_id: []const u8, sealed: []const u8, ctx: Context) Error![dek_len]u8 {
        return k.vtable.decryptDataKey(k.ptr, gpa, key_id, sealed, ctx);
    }
    pub fn listKeys(k: Kms, gpa: std.mem.Allocator) Error![]KeyInfo {
        return k.vtable.listKeys(k.ptr, gpa);
    }
    pub fn keyStatus(k: Kms, gpa: std.mem.Allocator, key_id: []const u8) Error!KeyInfo {
        return k.vtable.keyStatus(k.ptr, gpa, key_id);
    }
    pub fn rotateKey(k: Kms, gpa: std.mem.Allocator, key_id: []const u8) Error!KeyInfo {
        return k.vtable.rotateKey(k.ptr, gpa, key_id);
    }
};

/// Key names for Vault/local/KV2: 1..128 of [A-Za-z0-9._-], not starting with '.'.
pub fn validKeyName(id: []const u8) bool {
    if (id.len == 0 or id.len > 128 or id[0] == '.') return false;
    for (id) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

test "context canonical form is order independent" {
    const gpa = std.testing.allocator;
    const a: Context = .{ .pairs = &.{ .{ .key = "b", .value = "2" }, .{ .key = "a", .value = "x\"y" } } };
    const b: Context = .{ .pairs = &.{ .{ .key = "a", .value = "x\"y" }, .{ .key = "b", .value = "2" } } };
    const ca = try a.canonical(gpa);
    defer gpa.free(ca);
    const cb = try b.canonical(gpa);
    defer gpa.free(cb);
    try std.testing.expectEqualStrings("{\"a\":\"x\\\"y\",\"b\":\"2\"}", ca);
    try std.testing.expectEqualStrings(ca, cb);
    const empty = try (Context{}).canonical(gpa);
    defer gpa.free(empty);
    try std.testing.expectEqualStrings("{}", empty);
    const dup: Context = .{ .pairs = &.{ .{ .key = "a", .value = "1" }, .{ .key = "a", .value = "2" } } };
    try std.testing.expectError(error.InvalidArgument, dup.canonical(gpa));
}

test "key name validation" {
    try std.testing.expect(validKeyName("tenant-1.master_key"));
    try std.testing.expect(!validKeyName(""));
    try std.testing.expect(!validKeyName("../etc"));
    try std.testing.expect(!validKeyName("a/b"));
    try std.testing.expect(!validKeyName(".hidden"));
}
