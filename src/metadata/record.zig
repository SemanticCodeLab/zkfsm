//! ObjectRecord: per-object metadata, versioned binary encoding.
const std = @import("std");
const core = @import("../core/root.zig");
const codec = @import("codec.zig");

pub const magic = "ZKOR";
pub const format_version: u16 = 1;
pub const max_key_len = 1024;

pub const Error = codec.DecodeError || error{ KeyTooLong, OutOfMemory };

pub const StorageClass = enum(u8) { standard = 0, _ };
pub const PlacementKind = enum(u8) { local_single = 0, _ };

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
};

pub fn encode(r: ObjectRecord, gpa: std.mem.Allocator) Error![]u8 {
    if (r.key.len > max_key_len or r.content_type.len > std.math.maxInt(u16)) return error.KeyTooLong;
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
}

pub fn decode(bytes: []const u8) codec.DecodeError!ObjectRecord {
    var c: codec.Cursor = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try c.take(4), magic)) return error.Corrupt;
    if (try c.int(u16) != format_version) return error.Corrupt;
    var r: ObjectRecord = undefined;
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
        .etag = .{ .md5 = md5 },
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
    try std.testing.expectEqualSlices(u8, &md5, d.checksum.digest[0..16]);

    // Every truncation must be rejected, never crash.
    for (0..bytes.len) |n| try std.testing.expectError(error.Corrupt, decode(bytes[0..n]));
    var bad = try gpa.dupe(u8, bytes);
    defer gpa.free(bad);
    bad[0] = 'X';
    try std.testing.expectError(error.Corrupt, decode(bad));
}
