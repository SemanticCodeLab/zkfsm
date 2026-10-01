//! ObjectRecord: per-object metadata, versioned binary encoding.
const std = @import("std");
const core = @import("../core/root.zig");
const codec = @import("codec.zig");
const headers = @import("headers.zig");

pub const magic = "ZKOR";
/// v2 adds flags, retention, and tags; v3 the multipart part count; v4 user and
/// internal metadata, system headers, and size/ETag overrides; v5 multipart part sizes;
/// v6 the remote tier pointer and restored-copy expiry. Older records still decode.
pub const format_version: u16 = 6;
pub const max_tier_name = 64;
pub const max_parts = 10000;
pub const max_key_len = 1024;

pub const Error = codec.DecodeError || error{ KeyTooLong, MetadataTooLarge, OutOfMemory };

pub const StorageClass = enum(u8) { standard = 0, _ };
pub const PlacementKind = enum(u8) { local_single = 0, _ };

pub const Flags = packed struct(u8) {
    delete_marker: bool = false,
    /// The "null" version: written while versioning was unset or suspended.
    null_version: bool = false,
    legal_hold: bool = false,
    _pad: u5 = 0,
};

pub const RetentionMode = enum(u8) { none = 0, governance = 1, compliance = 2 };

pub const ObjectRecord = struct {
    object_id: core.ObjectId,
    bucket_id: core.BucketId,
    version: core.VersionId,
    size: u64,
    etag: core.ETag,
    checksum: core.Checksum,
    storage_class: StorageClass = .standard,
    placement: PlacementKind = .local_single,
    created_ns: i128,
    /// Borrowed; for decoded records these point into the input bytes.
    key: []const u8,
    content_type: []const u8 = "",
    flags: Flags = .{},
    retention_mode: RetentionMode = .none,
    retain_until_ns: i128 = 0,
    /// Encoded tag set (see tags.zig); borrowed like `key`.
    tags: []const u8 = "",
    /// Encoded header lists (see headers.zig); borrowed like `key`.
    user_meta: []const u8 = "",
    internal_meta: []const u8 = "",
    system: headers.System = .{},
    /// Reported size/ETag when they differ from the stored blob's.
    logical_size: ?u64 = null,
    etag_override: ?core.ETag = null,
    /// Multipart part sizes as little-endian u64s; empty for single-part objects.
    part_sizes: []const u8 = "",
    /// Remote tier holding the data blob (empty: data is local); borrowed like `key`.
    tier: []const u8 = "",
    /// Name of the blob on the tier.
    tier_object: [16]u8 = @splat(0),
    /// A restored local copy of tiered data lives until this time; 0 means none.
    restore_expiry_ns: i128 = 0,

    pub fn reportedSize(r: ObjectRecord) u64 {
        return r.logical_size orelse r.size;
    }

    pub fn reportedEtag(r: ObjectRecord) core.ETag {
        return r.etag_override orelse r.etag;
    }

    /// The id S3 clients see; all zeros stands for "null".
    pub fn versionId(r: ObjectRecord) core.VersionId {
        return if (r.flags.null_version) null_version_id else r.version;
    }
};

pub const null_version_id: core.VersionId = .{ .bytes = [_]u8{0} ** 16 };

pub fn encode(r: ObjectRecord, gpa: std.mem.Allocator) Error![]u8 {
    if (r.key.len > max_key_len or r.content_type.len > std.math.maxInt(u16) or r.tags.len > std.math.maxInt(u16)) return error.KeyTooLong;
    // Lists come from headers.encode; recheck so decode never rejects what we wrote.
    for ([_]struct { []const u8, headers.Kind }{ .{ r.user_meta, .user }, .{ r.internal_meta, .internal } }) |l| {
        var c: codec.Cursor = .{ .bytes = l[0] };
        if (l[0].len > 0 and ((headers.take(&c, l[1]) catch return error.MetadataTooLarge).len != l[0].len)) return error.MetadataTooLarge;
    }
    r.system.validate() catch return error.MetadataTooLarge;
    if (r.part_sizes.len % 8 != 0 or r.part_sizes.len / 8 > max_parts) return error.MetadataTooLarge;
    if (r.tier.len > max_tier_name) return error.MetadataTooLarge;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    encodeTo(r, &a.writer) catch return error.OutOfMemory;
    return a.toOwnedSlice() catch error.OutOfMemory;
}

fn encodeTo(r: ObjectRecord, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(magic);
    try codec.putInt(w, u16, format_version);
    try w.writeAll(&r.object_id.bytes);
    try w.writeAll(&r.bucket_id.bytes);
    try w.writeAll(&r.version.bytes);
    try codec.putInt(w, u64, r.size);
    try w.writeAll(&r.etag.md5);
    try w.writeByte(@intFromEnum(r.checksum.algorithm));
    try w.writeByte(r.checksum.len);
    try w.writeAll(r.checksum.digest[0..r.checksum.len]);
    try w.writeByte(@intFromEnum(r.storage_class));
    try w.writeByte(@intFromEnum(r.placement));
    try w.writeByte(0); // encryption: none
    try codec.putInt(w, i128, r.created_ns);
    try codec.putInt(w, u16, @intCast(r.key.len));
    try w.writeAll(r.key);
    try codec.putInt(w, u16, @intCast(r.content_type.len));
    try w.writeAll(r.content_type);
    try headers.put(w, r.user_meta);
    try w.writeByte(@bitCast(r.flags));
    try w.writeByte(@intFromEnum(r.retention_mode));
    try codec.putInt(w, i128, r.retain_until_ns);
    try codec.putInt(w, u16, @intCast(r.tags.len));
    try w.writeAll(r.tags);
    try codec.putInt(w, u32, r.etag.parts);
    try headers.put(w, r.internal_meta);
    try headers.putSystem(w, r.system);
    try w.writeByte(@as(u8, @intFromBool(r.logical_size != null)) | @as(u8, @intFromBool(r.etag_override != null)) << 1 |
        @as(u8, @intFromBool(r.part_sizes.len > 0)) << 2 | @as(u8, @intFromBool(r.tier.len > 0)) << 3 |
        @as(u8, @intFromBool(r.restore_expiry_ns != 0)) << 4);
    if (r.logical_size) |n| try codec.putInt(w, u64, n);
    if (r.etag_override) |e| {
        try w.writeAll(&e.md5);
        try codec.putInt(w, u32, e.parts);
    }
    if (r.part_sizes.len > 0) {
        try codec.putInt(w, u16, @intCast(r.part_sizes.len / 8));
        try w.writeAll(r.part_sizes);
    }
    if (r.tier.len > 0) {
        try w.writeByte(@intCast(r.tier.len));
        try w.writeAll(r.tier);
        try w.writeAll(&r.tier_object);
    }
    if (r.restore_expiry_ns != 0) try codec.putInt(w, i128, r.restore_expiry_ns);
}

/// Size of part `i` (0-based) from an encoded part-size list.
pub fn partSize(part_sizes: []const u8, i: usize) u64 {
    return std.mem.readInt(u64, part_sizes[i * 8 ..][0..8], .little);
}

pub fn decode(bytes: []const u8) codec.DecodeError!ObjectRecord {
    var c: codec.Cursor = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try c.take(4), magic)) return error.Corrupt;
    const ver = try c.int(u16);
    if (ver < 1 or ver > format_version) return error.Corrupt;
    var r: ObjectRecord = .{
        .object_id = undefined,
        .bucket_id = undefined,
        .version = undefined,
        .size = undefined,
        .etag = undefined,
        .checksum = undefined,
        .created_ns = undefined,
        .key = undefined,
    };
    r.object_id = .{ .bytes = try c.fixed(16) };
    r.bucket_id = .{ .bytes = try c.fixed(16) };
    r.version = .{ .bytes = try c.fixed(16) };
    r.size = try c.int(u64);
    r.etag = .{ .md5 = try c.fixed(16) };
    const alg = std.meta.intToEnum(core.checksum.ChecksumAlgorithm, (try c.take(1))[0]) catch return error.Corrupt;
    const clen = (try c.take(1))[0];
    if (clen > 32) return error.Corrupt;
    r.checksum = .{ .algorithm = alg, .len = clen };
    @memcpy(r.checksum.digest[0..clen], try c.take(clen));
    r.storage_class = @enumFromInt((try c.take(1))[0]);
    r.placement = @enumFromInt((try c.take(1))[0]);
    if ((try c.take(1))[0] != 0) return error.Corrupt; // encryption unsupported in v1
    r.created_ns = try c.int(i128);
    r.key = try c.take(try c.int(u16));
    if (r.key.len > max_key_len) return error.Corrupt;
    r.content_type = try c.take(try c.int(u16));
    if (ver >= 4) {
        r.user_meta = try headers.take(&c, .user);
    } else if (try c.int(u16) != 0) return error.Corrupt;
    if (ver == 1) {
        r.flags = .{ .null_version = true };
    } else {
        r.flags = @bitCast((try c.take(1))[0]);
        if (r.flags._pad != 0) return error.Corrupt;
        r.retention_mode = std.meta.intToEnum(RetentionMode, (try c.take(1))[0]) catch return error.Corrupt;
        r.retain_until_ns = try c.int(i128);
        r.tags = try c.take(try c.int(u16));
    }
    if (ver >= 3) r.etag.parts = try c.int(u32);
    if (ver >= 4) {
        r.internal_meta = try headers.take(&c, .internal);
        r.system = try headers.takeSystem(&c);
        const has = (try c.take(1))[0];
        const known: u8 = if (ver >= 6) 31 else if (ver >= 5) 7 else 3;
        if (has & ~known != 0) return error.Corrupt;
        if (has & 1 != 0) r.logical_size = try c.int(u64);
        if (has & 2 != 0) r.etag_override = .{ .md5 = try c.fixed(16), .parts = try c.int(u32) };
        if (has & 4 != 0) {
            const n = try c.int(u16);
            if (n == 0 or n > max_parts) return error.Corrupt;
            r.part_sizes = try c.take(@as(usize, n) * 8);
        }
        if (has & 8 != 0) {
            const n = (try c.take(1))[0];
            if (n == 0 or n > max_tier_name) return error.Corrupt;
            r.tier = try c.take(n);
            r.tier_object = try c.fixed(16);
        }
        if (has & 16 != 0) {
            r.restore_expiry_ns = try c.int(i128);
            if (r.restore_expiry_ns == 0) return error.Corrupt;
        }
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return r;
}

test "record encode/decode roundtrip" {
    const gpa = std.testing.allocator;
    var md5: [16]u8 = undefined;
    core.checksum.Md5.hash("x", &md5, .{});
    const r: ObjectRecord = .{
        .object_id = core.ObjectId.random(),
        .bucket_id = core.BucketId.random(),
        .version = core.VersionId.random(),
        .size = 1,
        .etag = .{ .md5 = md5, .parts = 3 },
        .checksum = core.Checksum.fromMd5(md5),
        .created_ns = 1234567890123,
        .key = "photos/dog.jpg",
        .content_type = "image/jpeg",
    };
    const bytes = try encode(r, gpa);
    defer gpa.free(bytes);
    const d = try decode(bytes);
    try std.testing.expect(d.object_id.eql(r.object_id));
    try std.testing.expectEqualStrings(r.key, d.key);
    try std.testing.expectEqualStrings(r.content_type, d.content_type);
    try std.testing.expectEqual(r.size, d.size);
    try std.testing.expectEqual(r.created_ns, d.created_ns);
    try std.testing.expectEqual(@as(u32, 3), d.etag.parts);
    try std.testing.expectEqualSlices(u8, &md5, d.checksum.digest[0..16]);

    try std.testing.expect(!d.flags.null_version);

    // Every truncation must be rejected, never crash.
    for (0..bytes.len) |n| try std.testing.expectError(error.Corrupt, decode(bytes[0..n]));
    var bad = try gpa.dupe(u8, bytes);
    defer gpa.free(bad);
    bad[0] = 'X';
    try std.testing.expectError(error.Corrupt, decode(bad));
}

test "v2 fields roundtrip and v1 records still decode" {
    const gpa = std.testing.allocator;
    const base: ObjectRecord = .{
        .object_id = core.ObjectId.random(),
        .bucket_id = core.BucketId.random(),
        .version = core.VersionId.random(),
        .size = 0,
        .etag = .{ .md5 = [_]u8{0} ** 16 },
        .checksum = core.Checksum.fromMd5([_]u8{0} ** 16),
        .created_ns = 7,
        .key = "k",
        .flags = .{ .delete_marker = true, .legal_hold = true },
        .retention_mode = .compliance,
        .retain_until_ns = 99,
        .tags = "\x01",
    };
    const bytes = try encode(base, gpa);
    defer gpa.free(bytes);
    const d = try decode(bytes);
    try std.testing.expect(d.flags.delete_marker and d.flags.legal_hold and !d.flags.null_version);
    try std.testing.expectEqual(RetentionMode.compliance, d.retention_mode);
    try std.testing.expectEqual(@as(i128, 99), d.retain_until_ns);
    try std.testing.expectEqualStrings("\x01", d.tags);

    // A v1 record is the v4 prefix up to the user-metadata count (empty v4 tail: 2 + 10 + 1).
    const v1_len = bytes.len - (1 + 1 + 16 + 2 + 1 + 4) - (2 + 10 + 1);
    const v1 = try gpa.dupe(u8, bytes[0..v1_len]);
    defer gpa.free(v1);
    v1[4] = 1;
    const o = try decode(v1);
    try std.testing.expect(o.flags.null_version and !o.flags.delete_marker);
    try std.testing.expect(o.versionId().eql(null_version_id));
    try std.testing.expectEqualStrings("k", o.key);
}

test "v4 metadata roundtrip; v3 records still decode; oversized lists rejected" {
    const gpa = std.testing.allocator;
    const user = try headers.encode(gpa, &.{ .{ .name = "k", .value = "v" }, .{ .name = "owner", .value = "me" } }, .user);
    defer gpa.free(user);
    const internal = try headers.encode(gpa, &.{.{ .name = headers.internal_prefix ++ "alg", .value = "x" }}, .internal);
    defer gpa.free(internal);
    var r: ObjectRecord = .{
        .object_id = core.ObjectId.random(),
        .bucket_id = core.BucketId.random(),
        .version = core.VersionId.random(),
        .size = 100,
        .etag = .{ .md5 = [_]u8{1} ** 16 },
        .checksum = .{},
        .created_ns = 7,
        .key = "k",
        .user_meta = user,
        .internal_meta = internal,
        .system = .{ .cache_control = "no-cache", .expires = "Thu, 01 Jan 2030 00:00:00 GMT" },
        .logical_size = 42,
        .etag_override = .{ .md5 = [_]u8{2} ** 16, .parts = 3 },
    };
    const bytes = try encode(r, gpa);
    defer gpa.free(bytes);
    const d = try decode(bytes);
    try std.testing.expectEqualSlices(u8, user, d.user_meta);
    try std.testing.expectEqualSlices(u8, internal, d.internal_meta);
    try std.testing.expectEqualStrings("no-cache", d.system.cache_control);
    try std.testing.expectEqual(@as(u64, 42), d.reportedSize());
    try std.testing.expectEqual(@as(u64, 100), d.size);
    try std.testing.expectEqual(@as(u32, 3), d.reportedEtag().parts);
    for (0..bytes.len) |n| try std.testing.expectError(error.Corrupt, decode(bytes[0..n]));
    const again = try encode(d, gpa);
    defer gpa.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);

    var sizes: [16]u8 = undefined;
    std.mem.writeInt(u64, sizes[0..8], 60, .little);
    std.mem.writeInt(u64, sizes[8..16], 40, .little);
    r.part_sizes = &sizes;
    const withparts = try encode(r, gpa);
    defer gpa.free(withparts);
    const dp = try decode(withparts);
    try std.testing.expectEqual(@as(u64, 40), partSize(dp.part_sizes, 1));
    r.tier = "WARM";
    r.tier_object = @splat(9);
    r.restore_expiry_ns = 77;
    const tiered = try encode(r, gpa);
    defer gpa.free(tiered);
    const dt = try decode(tiered);
    try std.testing.expectEqualStrings("WARM", dt.tier);
    try std.testing.expectEqual(@as(u8, 9), dt.tier_object[15]);
    try std.testing.expectEqual(@as(i128, 77), dt.restore_expiry_ns);
    for (0..tiered.len) |n| try std.testing.expectError(error.Corrupt, decode(tiered[0..n]));
    r.tier = "";
    r.restore_expiry_ns = 0;
    for (0..withparts.len) |n| try std.testing.expectError(error.Corrupt, decode(withparts[0..n]));
    r.part_sizes = "";

    // A v3 record is a v4 record without metadata, minus the tail, with version 3.
    r.user_meta = "";
    r.internal_meta = "";
    r.system = .{};
    r.logical_size = null;
    r.etag_override = null;
    const plain = try encode(r, gpa);
    defer gpa.free(plain);
    const v3 = try gpa.dupe(u8, plain[0 .. plain.len - (2 + 10 + 1)]);
    defer gpa.free(v3);
    v3[4] = 3;
    const o = try decode(v3);
    try std.testing.expectEqual(@as(u64, 100), o.reportedSize());
    try std.testing.expectEqualStrings("", o.user_meta);
    v3[4] = 7;
    try std.testing.expectError(error.Corrupt, decode(v3));

    // A list over the user limit neither encodes nor decodes.
    var big: std.Io.Writer.Allocating = .init(gpa);
    defer big.deinit();
    try codec.putInt(&big.writer, u16, 1);
    try codec.putInt(&big.writer, u16, 1);
    try big.writer.writeAll("a");
    try codec.putInt(&big.writer, u16, headers.user_limit);
    try big.writer.splatByteAll('x', headers.user_limit);
    r.user_meta = big.written();
    try std.testing.expectError(error.MetadataTooLarge, encode(r, gpa));
}
