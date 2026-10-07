//! KMS backup/restore. A versioned manifest lists key metadata and carries a
//! self-digest; for locally-wrapped backends (local, KV2) an optional bundle
//! holds the key records sealed under a caller-provided 32-byte backup key.
//! External backends (Transit, KMS-API) keep material server-side, so restore
//! only verifies that every listed key is reachable.
const std = @import("std");
const types = @import("types.zig");
const keyring = @import("keyring.zig");

const Allocator = std.mem.Allocator;
const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const format_version: u32 = 1;
const bundle_aad = "zkfsm-kms-backup-bundle-v1";

pub const Error = types.Error || error{ UnsupportedVersion, DigestMismatch, BundleRequired, BadBundle };

pub const KeyEntry = struct { id: []const u8, state: []const u8, version: u32, created_unix: i64, rotation_enabled: bool };
pub const BundleInfo = struct { algorithm: []const u8, sha256: []const u8 };

/// Wire form; unknown fields are rejected on decode.
pub const Manifest = struct {
    format_version: u32,
    created_unix: i64,
    backend: []const u8,
    keys: []const KeyEntry,
    bundle: ?BundleInfo,
    digest: []const u8,
};

pub const Backup = struct {
    manifest: []u8,
    /// nonce || ciphertext || tag, when key material was exported.
    bundle: ?[]u8,

    pub fn deinit(b: *Backup, gpa: Allocator) void {
        gpa.free(b.manifest);
        if (b.bundle) |x| gpa.free(x);
    }
};

fn hex(out: *[64]u8, d: [32]u8) []const u8 {
    return std.fmt.bufPrint(out, "{x}", .{&d}) catch unreachable;
}

fn stringify(gpa: Allocator, m: Manifest) Error![]u8 {
    return std.json.Stringify.valueAlloc(gpa, m, .{}) catch error.OutOfMemory;
}

/// Digest over the manifest serialized with an empty digest field.
fn manifestDigest(gpa: Allocator, m: Manifest, out: *[64]u8) Error![]const u8 {
    var tmp = m;
    tmp.digest = "";
    const bytes = try stringify(gpa, tmp);
    defer gpa.free(bytes);
    var d: [32]u8 = undefined;
    Sha256.hash(bytes, &d, .{});
    return hex(out, d);
}

/// Exports key metadata from `kms`; when `store` and `backup_key` are given
/// also seals every key record into the bundle.
pub fn exportBackup(gpa: Allocator, kms: types.Kms, store: ?keyring.KeyStore, backup_key: ?*const [32]u8, now: i64) Error!Backup {
    const infos = try kms.listKeys(gpa);
    defer types.freeKeyInfos(gpa, infos);
    const entries = try gpa.alloc(KeyEntry, infos.len);
    defer gpa.free(entries);
    for (infos, entries) |k, *e| e.* = .{ .id = k.id, .state = k.state.text(), .version = k.version, .created_unix = k.created_unix, .rotation_enabled = k.rotation_enabled };

    var bundle: ?[]u8 = null;
    errdefer if (bundle) |b| gpa.free(b);
    var bundle_hex: [64]u8 = undefined;
    var binfo: ?BundleInfo = null;
    if (store != null and backup_key != null) {
        bundle = try sealBundle(gpa, store.?, infos, backup_key.?);
        var d: [32]u8 = undefined;
        Sha256.hash(bundle.?, &d, .{});
        binfo = .{ .algorithm = "aes-256-gcm", .sha256 = hex(&bundle_hex, d) };
    }
    var m: Manifest = .{ .format_version = format_version, .created_unix = now, .backend = @tagName(kms.kind()), .keys = entries, .bundle = binfo, .digest = "" };
    var dh: [64]u8 = undefined;
    m.digest = try manifestDigest(gpa, m, &dh);
    return .{ .manifest = try stringify(gpa, m), .bundle = bundle };
}

fn sealBundle(gpa: Allocator, store: keyring.KeyStore, infos: []const types.KeyInfo, key: *const [32]u8) Error![]u8 {
    var plain: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, plain.allocatedSlice());
        plain.deinit(gpa);
    }
    try plain.append(gpa, '[');
    for (infos, 0..) |k, i| {
        var rec = try store.load(gpa, k.id);
        defer rec.deinit(gpa);
        const js = try rec.toJson(gpa);
        defer {
            std.crypto.secureZero(u8, js);
            gpa.free(js);
        }
        if (i != 0) try plain.append(gpa, ',');
        try plain.appendSlice(gpa, js);
    }
    try plain.append(gpa, ']');
    const out = try gpa.alloc(u8, Aes.nonce_length + plain.items.len + Aes.tag_length);
    std.crypto.random.bytes(out[0..Aes.nonce_length]);
    Aes.encrypt(out[Aes.nonce_length..][0..plain.items.len], out[out.len - Aes.tag_length ..][0..Aes.tag_length], plain.items, bundle_aad, out[0..Aes.nonce_length].*, key.*);
    return out;
}

pub const Report = struct {
    restored: u32 = 0,
    already_present: u32 = 0,
    /// Keys listed in the manifest but absent from the target (external backends).
    missing: u32 = 0,
};

pub const RestoreOptions = struct {
    /// Validate everything but write nothing.
    dry_run: bool = false,
};

/// Verifies `manifest_json` and restores into `target`. Existing keys are
/// never overwritten.
pub fn restore(gpa: Allocator, manifest_json: []const u8, bundle: ?[]const u8, target: types.Kms, store: ?keyring.KeyStore, backup_key: ?*const [32]u8, opts: RestoreOptions) Error!Report {
    const parsed = std.json.parseFromSlice(Manifest, gpa, manifest_json, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidArgument,
    };
    defer parsed.deinit();
    const m = parsed.value;
    if (m.format_version != format_version) return error.UnsupportedVersion;
    var dh: [64]u8 = undefined;
    if (!std.mem.eql(u8, try manifestDigest(gpa, m, &dh), m.digest)) return error.DigestMismatch;
    for (m.keys) |k| if (!types.validKeyName(k.id)) return error.InvalidArgument;

    var report: Report = .{};
    if (m.bundle) |bi| {
        const b = bundle orelse return error.BundleRequired;
        const st = store orelse return error.BundleRequired;
        const key = backup_key orelse return error.BundleRequired;
        var d: [32]u8 = undefined;
        Sha256.hash(b, &d, .{});
        var bh: [64]u8 = undefined;
        if (!std.mem.eql(u8, hex(&bh, d), bi.sha256)) return error.DigestMismatch;
        try restoreBundle(gpa, b, st, key, m.keys, opts, &report);
        return report;
    }
    for (m.keys) |k| {
        var ki = target.keyStatus(gpa, k.id) catch |e| switch (e) {
            error.KeyNotFound => {
                report.missing += 1;
                continue;
            },
            else => return e,
        };
        ki.deinit(gpa);
        report.already_present += 1;
    }
    return report;
}

fn restoreBundle(gpa: Allocator, b: []const u8, st: keyring.KeyStore, key: *const [32]u8, keys: []const KeyEntry, opts: RestoreOptions, report: *Report) Error!void {
    if (b.len < Aes.nonce_length + Aes.tag_length) return error.BadBundle;
    const ct = b[Aes.nonce_length .. b.len - Aes.tag_length];
    const plain = try gpa.alloc(u8, ct.len);
    defer {
        std.crypto.secureZero(u8, plain);
        gpa.free(plain);
    }
    Aes.decrypt(plain, ct, b[b.len - Aes.tag_length ..][0..Aes.tag_length].*, bundle_aad, b[0..Aes.nonce_length].*, key.*) catch return error.BadBundle;
    const arr = std.json.parseFromSlice(std.json.Value, gpa, plain, .{ .allocate = .alloc_always }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadBundle,
    };
    defer arr.deinit();
    if (arr.value != .array or arr.value.array.items.len != keys.len) return error.BadBundle;
    // Decode all first so a bad record aborts before any write.
    const recs = try gpa.alloc(keyring.KeyRecord, keys.len);
    var n: usize = 0;
    defer {
        for (recs[0..n]) |*r| r.deinit(gpa);
        gpa.free(recs);
    }
    for (arr.value.array.items, keys) |item, k| {
        const js = std.json.Stringify.valueAlloc(gpa, item, .{}) catch return error.OutOfMemory;
        defer {
            std.crypto.secureZero(u8, js);
            gpa.free(js);
        }
        recs[n] = keyring.KeyRecord.fromJson(gpa, js) catch return error.BadBundle;
        n += 1;
        if (!std.mem.eql(u8, recs[n - 1].id, k.id)) return error.BadBundle;
    }
    for (recs[0..n]) |r| {
        if (opts.dry_run) {
            var existing = st.load(gpa, r.id) catch |e| switch (e) {
                error.KeyNotFound => {
                    report.restored += 1;
                    continue;
                },
                else => return e,
            };
            existing.deinit(gpa);
            report.already_present += 1;
            continue;
        }
        st.store(gpa, r, .create) catch |e| switch (e) {
            error.KeyExists => {
                report.already_present += 1;
                continue;
            },
            else => return e,
        };
        report.restored += 1;
    }
}

const testing = std.testing;

test "backup and restore keyring backend" {
    const gpa = testing.allocator;
    var src: keyring.MemoryStore = .{ .gpa = gpa };
    defer src.deinit();
    var skr: keyring.KeyringKms = .{ .store = src.keyStore(), .kind = .local };
    const sk = skr.kms();
    for ([_][]const u8{ "a", "b" }) |id| {
        var ki = try sk.createKey(gpa, id);
        ki.deinit(gpa);
    }
    var r = try sk.rotateKey(gpa, "b");
    r.deinit(gpa);
    var dk = try sk.generateDataKey(gpa, "b", .{});
    defer dk.deinit(gpa);

    const bkey = [_]u8{0x42} ** 32;
    var bk = try exportBackup(gpa, sk, src.keyStore(), &bkey, 1700000000);
    defer bk.deinit(gpa);

    var dst: keyring.MemoryStore = .{ .gpa = gpa };
    defer dst.deinit();
    var dkr: keyring.KeyringKms = .{ .store = dst.keyStore(), .kind = .local };
    const dry = try restore(gpa, bk.manifest, bk.bundle, dkr.kms(), dst.keyStore(), &bkey, .{ .dry_run = true });
    try testing.expectEqual(@as(u32, 2), dry.restored);
    try testing.expectEqual(@as(usize, 0), dst.map.count());
    const rep = try restore(gpa, bk.manifest, bk.bundle, dkr.kms(), dst.keyStore(), &bkey, .{});
    try testing.expectEqual(@as(u32, 2), rep.restored);
    const back = try dkr.kms().decryptDataKey(gpa, "b", dk.sealed, .{});
    try testing.expectEqualSlices(u8, &dk.plaintext, &back);
    const again = try restore(gpa, bk.manifest, bk.bundle, dkr.kms(), dst.keyStore(), &bkey, .{});
    try testing.expectEqual(@as(u32, 2), again.already_present);

    // Tampering with manifest, bundle, or key.
    const tm = try gpa.dupe(u8, bk.manifest);
    defer gpa.free(tm);
    const pos = std.mem.indexOf(u8, tm, "1700000000").?;
    tm[pos] = '2';
    try testing.expectError(error.DigestMismatch, restore(gpa, tm, bk.bundle, dkr.kms(), dst.keyStore(), &bkey, .{}));
    const tb = try gpa.dupe(u8, bk.bundle.?);
    defer gpa.free(tb);
    tb[20] ^= 1;
    try testing.expectError(error.DigestMismatch, restore(gpa, bk.manifest, tb, dkr.kms(), dst.keyStore(), &bkey, .{}));
    const wrong = [_]u8{0x43} ** 32;
    try testing.expectError(error.BadBundle, restore(gpa, bk.manifest, bk.bundle, dkr.kms(), dst.keyStore(), &wrong, .{}));
    try testing.expectError(error.BundleRequired, restore(gpa, bk.manifest, null, dkr.kms(), dst.keyStore(), &bkey, .{}));
}

test "metadata-only backup reports missing keys" {
    const gpa = testing.allocator;
    var src: keyring.MemoryStore = .{ .gpa = gpa };
    defer src.deinit();
    var skr: keyring.KeyringKms = .{ .store = src.keyStore(), .kind = .local };
    var ki = try skr.kms().createKey(gpa, "only");
    ki.deinit(gpa);
    var bk = try exportBackup(gpa, skr.kms(), null, null, 1);
    defer bk.deinit(gpa);
    try testing.expect(bk.bundle == null);
    var dst: keyring.MemoryStore = .{ .gpa = gpa };
    defer dst.deinit();
    var dkr: keyring.KeyringKms = .{ .store = dst.keyStore(), .kind = .local };
    const rep = try restore(gpa, bk.manifest, null, dkr.kms(), null, null, .{});
    try testing.expectEqual(@as(u32, 1), rep.missing);
    const rep2 = try restore(gpa, bk.manifest, null, skr.kms(), null, null, .{});
    try testing.expectEqual(@as(u32, 1), rep2.already_present);
    try testing.expectError(error.InvalidArgument, restore(gpa, "{\"format_version\":1,\"extra\":1}", null, dkr.kms(), null, null, .{}));
}
