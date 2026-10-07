//! Server-side encryption glue: per-object DEK sealing for SSE-KMS / SSE-S3,
//! SSE-C customer key handling, and the internal object metadata that
//! carries the sealed key.
const std = @import("std");
const types = @import("types.zig");

const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
const b64 = std.base64.standard;
const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidArgument, MissingMetadata, InvalidMetadata, KeyMd5Mismatch, WrongCustomerKey };

pub const seal_algorithm = "DARE-AES256GCM-64K-v1";
/// Context key reserved for binding a DEK to its object path.
pub const object_context_key = "zkfsm:object";

/// Internal object headers (lowercase, as the core requires); lookups are
/// case-insensitive so legacy mixed-case envelope names still decode.
pub const hdr_scheme = "x-zkfsm-internal-sse-scheme";
pub const hdr_key_id = "x-zkfsm-internal-sse-kms-key-id";
pub const hdr_key_version = "x-zkfsm-internal-sse-key-version";
pub const hdr_sealed = "x-zkfsm-internal-sse-sealed-key";
pub const hdr_algorithm = "x-zkfsm-internal-sse-seal-algorithm";
pub const hdr_context = "x-zkfsm-internal-sse-context";
pub const hdr_key_md5 = "x-zkfsm-internal-sse-c-key-md5";

pub const Scheme = enum {
    /// SSE-KMS (`aws:kms`), caller-chosen key.
    kms,
    /// SSE-S3 (`AES256`), server default key.
    s3,
    /// SSE-C, customer-supplied key.
    c,

    pub fn wire(s: Scheme) []const u8 {
        return switch (s) {
            .kms => "aws:kms",
            .s3 => "AES256",
            .c => "SSE-C",
        };
    }
    pub fn parse(s: []const u8) ?Scheme {
        inline for (.{ Scheme.kms, Scheme.s3, Scheme.c }) |v| if (std.mem.eql(u8, s, v.wire())) return v;
        return null;
    }
};

pub const Header = struct { name: []const u8, value: []const u8 };

/// Sealed-key metadata persisted with an object. Slices either borrow from
/// the headers passed to `decode` or are owned after `encode` (see `Owned`).
pub const SealedMeta = struct {
    scheme: Scheme,
    /// Empty for SSE-C.
    key_id: []const u8 = "",
    key_version: u32 = 0,
    sealed_key: []const u8,
    /// Canonical user encryption context JSON (without the object binding).
    context_json: []const u8 = "{}",
    /// SSE-C only.
    key_md5: ?[16]u8 = null,

    /// Returns headers whose names are static and values are owned by `gpa`.
    pub fn encode(m: SealedMeta, gpa: Allocator) Error![]Header {
        var list: std.ArrayList(Header) = .empty;
        errdefer freeHeaders(gpa, list.items);
        defer list.deinit(gpa);
        try appendOwned(gpa, &list, hdr_scheme, m.scheme.wire());
        try appendOwned(gpa, &list, hdr_algorithm, seal_algorithm);
        try appendB64(gpa, &list, hdr_sealed, m.sealed_key);
        switch (m.scheme) {
            .kms, .s3 => {
                try appendOwned(gpa, &list, hdr_key_id, m.key_id);
                var vb: [10]u8 = undefined;
                try appendOwned(gpa, &list, hdr_key_version, std.fmt.bufPrint(&vb, "{d}", .{m.key_version}) catch unreachable);
                try appendB64(gpa, &list, hdr_context, m.context_json);
            },
            .c => {
                const md5 = m.key_md5 orelse return error.InvalidArgument;
                try appendB64(gpa, &list, hdr_key_md5, &md5);
            },
        }
        return list.toOwnedSlice(gpa);
    }

    /// Decoded binary fields are written into `scratch` (≥ 1 KiB suffices
    /// for typical contexts); returned slices borrow `headers` and `scratch`.
    pub fn decode(headers: []const Header, scratch: []u8) Error!SealedMeta {
        const alg = find(headers, hdr_algorithm) orelse return error.MissingMetadata;
        if (!std.mem.eql(u8, alg, seal_algorithm)) return error.InvalidMetadata;
        const scheme = Scheme.parse(find(headers, hdr_scheme) orelse return error.MissingMetadata) orelse return error.InvalidMetadata;
        var used: usize = 0;
        var m: SealedMeta = .{ .scheme = scheme, .sealed_key = try decodeInto(scratch, &used, find(headers, hdr_sealed) orelse return error.MissingMetadata) };
        switch (scheme) {
            .kms, .s3 => {
                m.key_id = find(headers, hdr_key_id) orelse return error.MissingMetadata;
                m.key_version = std.fmt.parseInt(u32, find(headers, hdr_key_version) orelse return error.MissingMetadata, 10) catch return error.InvalidMetadata;
                m.context_json = try decodeInto(scratch, &used, find(headers, hdr_context) orelse return error.MissingMetadata);
            },
            .c => {
                const md5 = try decodeInto(scratch, &used, find(headers, hdr_key_md5) orelse return error.MissingMetadata);
                if (md5.len != 16) return error.InvalidMetadata;
                m.key_md5 = md5[0..16].*;
            },
        }
        return m;
    }
};

pub fn freeHeaders(gpa: Allocator, hs: []const Header) void {
    for (hs) |h| gpa.free(h.value);
}

fn appendOwned(gpa: Allocator, list: *std.ArrayList(Header), name: []const u8, value: []const u8) Error!void {
    const v = try gpa.dupe(u8, value);
    list.append(gpa, .{ .name = name, .value = v }) catch {
        gpa.free(v);
        return error.OutOfMemory;
    };
}

fn appendB64(gpa: Allocator, list: *std.ArrayList(Header), name: []const u8, raw: []const u8) Error!void {
    const v = try gpa.alloc(u8, b64.Encoder.calcSize(raw.len));
    _ = b64.Encoder.encode(v, raw);
    list.append(gpa, .{ .name = name, .value = v }) catch {
        gpa.free(v);
        return error.OutOfMemory;
    };
}

fn find(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

fn decodeInto(scratch: []u8, used: *usize, text: []const u8) Error![]const u8 {
    const n = b64.Decoder.calcSizeForSlice(text) catch return error.InvalidMetadata;
    if (n > scratch.len - used.*) return error.InvalidMetadata;
    const out = scratch[used.*..][0..n];
    b64.Decoder.decode(out, text) catch return error.InvalidMetadata;
    used.* += n;
    return out;
}

/// Builds the KMS context: user pairs plus the object binding.
fn objectContext(gpa: Allocator, user: []const types.Context.Pair, object_path: []const u8) Error![]types.Context.Pair {
    const pairs = try gpa.alloc(types.Context.Pair, user.len + 1);
    for (user, pairs[0..user.len]) |u, *p| {
        if (std.mem.eql(u8, u.key, object_context_key)) {
            gpa.free(pairs);
            return error.InvalidArgument;
        }
        p.* = u;
    }
    pairs[user.len] = .{ .key = object_context_key, .value = object_path };
    return pairs;
}

pub const KmsError = Error || types.Error;

/// A new object DEK plus its metadata. `deinit` wipes the DEK.
pub const NewObjectKey = struct {
    dek: [32]u8,
    headers: []Header,

    pub fn deinit(k: *NewObjectKey, gpa: Allocator) void {
        std.crypto.secureZero(u8, &k.dek);
        freeHeaders(gpa, k.headers);
        gpa.free(k.headers);
    }
};

/// SSE-KMS / SSE-S3 on PUT: fresh DEK bound to `object_path` and `user_ctx`.
pub fn newKmsObjectKey(gpa: Allocator, kms: types.Kms, scheme: Scheme, key_id: []const u8, object_path: []const u8, user_ctx: []const types.Context.Pair) KmsError!NewObjectKey {
    if (scheme == .c) return error.InvalidArgument;
    const pairs = try objectContext(gpa, user_ctx, object_path);
    defer gpa.free(pairs);
    var dk = try kms.generateDataKey(gpa, key_id, .{ .pairs = pairs });
    defer dk.deinit(gpa);
    const user_json = try (types.Context{ .pairs = user_ctx }).canonical(gpa);
    defer gpa.free(user_json);
    const meta: SealedMeta = .{ .scheme = scheme, .key_id = key_id, .key_version = dk.key_version, .sealed_key = dk.sealed, .context_json = user_json };
    return .{ .dek = dk.plaintext, .headers = try meta.encode(gpa) };
}

/// SSE-KMS / SSE-S3 on GET: recover the DEK from stored metadata.
pub fn openKmsObjectKey(gpa: Allocator, kms: types.Kms, meta: SealedMeta, object_path: []const u8) KmsError![32]u8 {
    if (meta.scheme == .c) return error.InvalidArgument;
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, meta.context_json, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidMetadata,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidMetadata;
    const obj = parsed.value.object;
    const user = try gpa.alloc(types.Context.Pair, obj.count());
    defer gpa.free(user);
    for (obj.keys(), obj.values(), user) |k, v, *p| {
        if (v != .string) return error.InvalidMetadata;
        p.* = .{ .key = k, .value = v.string };
    }
    const pairs = try objectContext(gpa, user, object_path);
    defer gpa.free(pairs);
    return kms.decryptDataKey(gpa, meta.key_id, meta.sealed_key, .{ .pairs = pairs });
}

/// SSE-C customer key after header validation. Wipe with `deinit`.
pub const CustomerKey = struct {
    key: [32]u8,
    md5: [16]u8,

    pub fn deinit(c: *CustomerKey) void {
        std.crypto.secureZero(u8, &c.key);
    }
};

/// Validates the three SSE-C request headers (algorithm, key, key-MD5).
pub fn parseCustomerKey(algorithm: []const u8, key_b64: []const u8, md5_b64: []const u8) Error!CustomerKey {
    if (!std.mem.eql(u8, algorithm, "AES256")) return error.InvalidArgument;
    var ck: CustomerKey = .{ .key = undefined, .md5 = undefined };
    errdefer ck.deinit();
    if ((b64.Decoder.calcSizeForSlice(key_b64) catch return error.InvalidArgument) != 32) return error.InvalidArgument;
    b64.Decoder.decode(&ck.key, key_b64) catch return error.InvalidArgument;
    if ((b64.Decoder.calcSizeForSlice(md5_b64) catch return error.InvalidArgument) != 16) return error.InvalidArgument;
    var given: [16]u8 = undefined;
    b64.Decoder.decode(&given, md5_b64) catch return error.InvalidArgument;
    std.crypto.hash.Md5.hash(&ck.key, &ck.md5, .{});
    if (!std.crypto.timing_safe.eql([16]u8, given, ck.md5)) return error.KeyMd5Mismatch;
    return ck;
}

fn sseCAad(buf: []u8, object_path: []const u8) Error![]const u8 {
    return std.fmt.bufPrint(buf, "zkfsm-sse-c-v1\x00{s}", .{object_path}) catch error.InvalidArgument;
}

const sse_c_sealed_len = Aes.nonce_length + 32 + Aes.tag_length;

/// SSE-C on PUT: random object DEK sealed under the customer key.
pub fn newCustomerObjectKey(gpa: Allocator, ck: *const CustomerKey, object_path: []const u8) Error!NewObjectKey {
    var ab: [1100]u8 = undefined;
    const aad = try sseCAad(&ab, object_path);
    var dek: [32]u8 = undefined;
    errdefer std.crypto.secureZero(u8, &dek);
    std.crypto.random.bytes(&dek);
    var sealed: [sse_c_sealed_len]u8 = undefined;
    std.crypto.random.bytes(sealed[0..Aes.nonce_length]);
    Aes.encrypt(sealed[Aes.nonce_length..][0..32], sealed[Aes.nonce_length + 32 ..][0..Aes.tag_length], &dek, aad, sealed[0..Aes.nonce_length].*, ck.key);
    const meta: SealedMeta = .{ .scheme = .c, .sealed_key = &sealed, .key_md5 = ck.md5 };
    return .{ .dek = dek, .headers = try meta.encode(gpa) };
}

/// SSE-C on GET: the request key must match the stored MD5 and unseal.
pub fn openCustomerObjectKey(meta: SealedMeta, ck: *const CustomerKey, object_path: []const u8) Error![32]u8 {
    if (meta.scheme != .c) return error.InvalidArgument;
    const stored = meta.key_md5 orelse return error.InvalidMetadata;
    if (!std.crypto.timing_safe.eql([16]u8, stored, ck.md5)) return error.WrongCustomerKey;
    if (meta.sealed_key.len != sse_c_sealed_len) return error.InvalidMetadata;
    var ab: [1100]u8 = undefined;
    const aad = try sseCAad(&ab, object_path);
    var dek: [32]u8 = undefined;
    const s = meta.sealed_key;
    Aes.decrypt(&dek, s[Aes.nonce_length..][0..32], s[Aes.nonce_length + 32 ..][0..Aes.tag_length].*, aad, s[0..Aes.nonce_length].*, ck.key) catch return error.WrongCustomerKey;
    return dek;
}

const testing = std.testing;
const keyring = @import("keyring.zig");

test "sse-c key header validation" {
    const key = [_]u8{0x11} ** 32;
    var kb: [44]u8 = undefined;
    _ = b64.Encoder.encode(&kb, &key);
    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&key, &md5, .{});
    var mb: [24]u8 = undefined;
    _ = b64.Encoder.encode(&mb, &md5);
    var ck = try parseCustomerKey("AES256", &kb, &mb);
    defer ck.deinit();
    try testing.expectEqualSlices(u8, &key, &ck.key);
    try testing.expectError(error.InvalidArgument, parseCustomerKey("aws:kms", &kb, &mb));
    try testing.expectError(error.InvalidArgument, parseCustomerKey("AES256", "c2hvcnQ=", &mb));
    var bad = mb;
    bad[0] = if (bad[0] == 'A') 'B' else 'A';
    try testing.expectError(error.KeyMd5Mismatch, parseCustomerKey("AES256", &kb, &bad));
}

test "sse-c object key round trip through metadata" {
    const gpa = testing.allocator;
    var ck: CustomerKey = .{ .key = [_]u8{7} ** 32, .md5 = undefined };
    std.crypto.hash.Md5.hash(&ck.key, &ck.md5, .{});
    var nk = try newCustomerObjectKey(gpa, &ck, "b/o");
    defer nk.deinit(gpa);
    var scratch: [1024]u8 = undefined;
    const meta = try SealedMeta.decode(nk.headers, &scratch);
    const dek = try openCustomerObjectKey(meta, &ck, "b/o");
    try testing.expectEqualSlices(u8, &nk.dek, &dek);
    try testing.expectError(error.WrongCustomerKey, openCustomerObjectKey(meta, &ck, "b/other"));
    var other: CustomerKey = .{ .key = [_]u8{8} ** 32, .md5 = undefined };
    std.crypto.hash.Md5.hash(&other.key, &other.md5, .{});
    try testing.expectError(error.WrongCustomerKey, openCustomerObjectKey(meta, &other, "b/o"));
}

test "sse-kms object key round trip and binding" {
    const gpa = testing.allocator;
    var mem: keyring.MemoryStore = .{ .gpa = gpa };
    defer mem.deinit();
    var kr: keyring.KeyringKms = .{ .store = mem.keyStore(), .kind = .local };
    const kms = kr.kms();
    var ki = try kms.createKey(gpa, "tenant");
    ki.deinit(gpa);
    const uctx = [_]types.Context.Pair{.{ .key = "dept", .value = "fin" }};
    var nk = try newKmsObjectKey(gpa, kms, .kms, "tenant", "bkt/a.txt", &uctx);
    defer nk.deinit(gpa);
    var scratch: [1024]u8 = undefined;
    const meta = try SealedMeta.decode(nk.headers, &scratch);
    try testing.expectEqualStrings("tenant", meta.key_id);
    try testing.expectEqualStrings("{\"dept\":\"fin\"}", meta.context_json);
    const dek = try openKmsObjectKey(gpa, kms, meta, "bkt/a.txt");
    try testing.expectEqualSlices(u8, &nk.dek, &dek);
    try testing.expectError(error.InvalidCiphertext, openKmsObjectKey(gpa, kms, meta, "bkt/b.txt"));
    const reserved = [_]types.Context.Pair{.{ .key = object_context_key, .value = "x" }};
    try testing.expectError(error.InvalidArgument, newKmsObjectKey(gpa, kms, .kms, "tenant", "bkt/a", &reserved));
    try testing.expectError(error.MissingMetadata, SealedMeta.decode(nk.headers[0..2], &scratch));
}
