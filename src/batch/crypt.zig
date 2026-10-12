//! Plaintext access to stored versions and sealed rewrites, shared by keyrotate
//! (same path, new key) and replicate (SSE objects copied to a new path).
const std = @import("std");
const object = @import("../object/root.zig");
const kms = @import("../kms/root.zig");
const sse_mod = @import("../sse/root.zig");

const Allocator = std.mem.Allocator;
const ksse = kms.sse;
const sh = sse_mod.handler;

pub const Error = object.Error || error{ KmsUnavailable, KmsFailed, Unsupported };

pub const sse_prefix = object.internal_prefix ++ "sse-";

/// Sealing parameters of an encrypted version (SSE-S3 or SSE-KMS).
pub const Sealing = struct {
    scheme: ksse.Scheme,
    key_id: []const u8,
    key_version: u32,
    context_json: []const u8,
};

/// Null for plaintext versions; Unsupported for SSE-C and legacy envelopes.
pub fn sealing(arena: Allocator, info: object.ObjectInfo) Error!?Sealing {
    if (!sh.isEncrypted(info)) return null;
    if (std.mem.startsWith(u8, info.content_type, sh.marker)) return error.Unsupported;
    const hs = try arena.alloc(ksse.Header, info.internal.len);
    for (info.internal, hs) |h, *o| o.* = .{ .name = h.name, .value = h.value };
    const scratch = try arena.alloc(u8, 2048);
    const m = ksse.SealedMeta.decode(hs, scratch) catch return error.Corrupt;
    if (m.scheme == .c) return error.Unsupported;
    return .{ .scheme = m.scheme, .key_id = m.key_id, .key_version = m.key_version, .context_json = m.context_json };
}

/// Plaintext reader over a whole version; `deinit` releases it.
pub const Plain = struct {
    size: u64,
    raw: ?*object.tier.Source = null,
    dec: ?*sh.Plain = null,

    pub fn reader(p: *Plain) *std.Io.Reader {
        if (p.dec) |d| return d.reader();
        return p.raw.?.reader();
    }

    pub fn failure(p: *Plain) ?object.Error {
        if (p.raw) |r| return r.failure();
        return null;
    }

    pub fn deinit(p: *Plain) void {
        if (p.raw) |r| r.deinit();
        if (p.dec) |d| d.deinit();
    }
};

/// Opens `info` (stored at `bucket/key`) for reading as plaintext.
pub fn open(arena: Allocator, s: ?*sse_mod.Sse, svc: *object.ObjectService, info: object.ObjectInfo, bucket: []const u8, key: []const u8) Error!Plain {
    if (!sh.isEncrypted(info)) {
        const src = try arena.create(object.tier.Source);
        try src.init(svc, info, 0, info.blob_size, try arena.alloc(u8, 64 * 1024));
        return .{ .size = info.blob_size, .raw = src };
    }
    _ = try sealing(arena, info);
    const ext = s orelse return error.KmsUnavailable;
    const k = ext.kms orelse return error.KmsUnavailable;
    const st = sh.stored(arena, info) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    const scratch = try arena.alloc(u8, 2048);
    const meta = ksse.SealedMeta.decode(st.meta_headers, scratch) catch return error.Corrupt;
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ bucket, key });
    var dek = blk: {
        ext.mutex.lock();
        defer ext.mutex.unlock();
        break :blk ksse.openKmsObjectKey(ext.gpa, k, meta, path) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.KmsFailed;
    };
    defer std.crypto.secureZero(u8, &dek);
    const p = sh.openPlain(arena, svc, info, &dek, st.segs, path, 0, st.size) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed => error.ReadFailed,
        error.Corrupt => error.Corrupt,
    };
    return .{ .size = st.size, .dec = p };
}

/// Internal headers of `info` minus its encryption headers.
pub fn plainInternal(arena: Allocator, info: object.ObjectInfo) Error![]const object.Header {
    var out: std.ArrayList(object.Header) = .empty;
    for (info.internal) |h| if (!std.mem.startsWith(u8, h.name, sse_prefix)) try out.append(arena, h);
    return out.items;
}

pub const Target = struct {
    scheme: ksse.Scheme,
    /// Empty selects the server default key.
    key_id: []const u8 = "",
    context: []const kms.Context.Pair = &.{},
};

/// Writes `len` plaintext bytes from `src` to `bucket/key`, sealed per `t`.
/// `base` carries content type, metadata, tags and lock fields.
pub fn putSealed(arena: Allocator, s: ?*sse_mod.Sse, svc: *object.ObjectService, bucket: []const u8, key: []const u8, src: *std.Io.Reader, len: u64, t: Target, base: object.PutInput) Error!object.ObjectInfo {
    const ext = s orelse return error.KmsUnavailable;
    const k = ext.kms orelse return error.KmsUnavailable;
    const key_id = if (t.key_id.len > 0) t.key_id else ext.default_key;
    if (!kms.types.validKeyName(key_id)) return error.KmsFailed;
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ bucket, key });
    var nk = blk: {
        ext.mutex.lock();
        defer ext.mutex.unlock();
        break :blk ksse.newKmsObjectKey(ext.gpa, k, t.scheme, key_id, path, t.context) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.KmsFailed;
    };
    defer nk.deinit(ext.gpa);
    var in = base;
    const internal = try arena.alloc(object.Header, base.internal.len + nk.headers.len);
    @memcpy(internal[0..base.internal.len], base.internal);
    for (nk.headers, internal[base.internal.len..]) |h, *o| o.* = .{ .name = h.name, .value = try arena.dupe(u8, h.value) };
    in.internal = internal;
    in.content_length = kms.stream.encryptedSize(len);
    in.logical_size = len;
    const er = try arena.create(sse_mod.common.EncryptReader);
    er.init(src, &nk.dek, path, try arena.alloc(u8, sse_mod.common.EncryptReader.min_buffer));
    defer er.deinit();
    return svc.put(bucket, key, &er.interface, in) catch |e| {
        if (er.err != null) return error.StorageFailed;
        return e;
    };
}

/// Sealing of `info` reused for a copy (same scheme, key and context).
pub fn sameTarget(arena: Allocator, sl: Sealing) Error!Target {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, sl.context_json, .{}) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    if (v != .object) return error.Corrupt;
    const pairs = try arena.alloc(kms.Context.Pair, v.object.count());
    for (v.object.keys(), v.object.values(), pairs) |kk, vv, *p| {
        if (vv != .string) return error.Corrupt;
        p.* = .{ .key = kk, .value = vv.string };
    }
    return .{ .scheme = sl.scheme, .key_id = sl.key_id, .context = pairs };
}
