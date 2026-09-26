//! ObjectRecord: per-object metadata, versioned binary encoding.
const std = @import("std");
const core = @import("../core/root.zig");
const codec = @import("codec.zig");

pub const magic = "ZKOR";
/// v2 adds flags, retention, and tags; v3 adds the multipart part count.
/// Older records still decode (v1 as null versions).
pub const format_version: u16 = 3;
pub const max_key_len = 1024;

pub const Error = codec.DecodeError || error{ KeyTooLong, OutOfMemory };

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

    /// The id S3 clients see; all zeros stands for "null".
    pub fn versionId(r: ObjectRecord) core.VersionId {
        return if (r.flags.null_version) null_version_id else r.version;
    }
};

pub const null_version_id: core.VersionId = .{ .bytes = [_]u8{0} ** 16 };

pub fn encode(r: ObjectRecord, gpa: std.mem.Allocator) Error![]u8 {
    if (r.key.len > max_key_len or r.content_type.len > std.math.maxInt(u16) or r.tags.len > std.math.maxInt(u16)) return error.KeyTooLong;
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
    try codec.putInt(w, u16, 0); // user metadata count
    try w.writeByte(@bitCast(r.flags));
    try w.writeByte(@intFromEnum(r.retention_mode));
    try codec.putInt(w, i128, r.retain_until_ns);
    try codec.putInt(w, u16, @intCast(r.tags.len));
    try w.writeAll(r.tags);
    try codec.putInt(w, u32, r.etag.parts);
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
    if (try c.int(u16) != 0) return error.Corrupt;
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

    // A v1 record is the v2 prefix up to the user-metadata count.
    const v1_len = bytes.len - (1 + 1 + 16 + 2 + 1 + 4);
    const v1 = try gpa.dupe(u8, bytes[0..v1_len]);
    defer gpa.free(v1);
    v1[4] = 1;
    const o = try decode(v1);
    try std.testing.expect(o.flags.null_version and !o.flags.delete_marker);
    try std.testing.expect(o.versionId().eql(null_version_id));
    try std.testing.expectEqualStrings("k", o.key);
}
