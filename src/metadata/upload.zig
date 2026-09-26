//! UploadRecord: state of one in-progress multipart upload, versioned binary encoding.
const std = @import("std");
const core = @import("../core/root.zig");
const codec = @import("codec.zig");
const record = @import("record.zig");
const headers = @import("headers.zig");

pub const magic = "ZKMU";
/// v2 adds user/internal metadata and system headers; v1 still decodes.
pub const format_version: u16 = 2;
pub const max_parts = 10000;

pub const Error = codec.DecodeError || error{ KeyTooLong, MetadataTooLarge, OutOfMemory };

/// Upload ids share the 128-bit id shape; they also address the upload record.
pub const UploadId = core.ids.ObjectId;

pub const Part = struct {
    number: u16,
    size: u64,
    md5: [16]u8,
    /// Data blob holding the part bytes.
    blob: core.ObjectId,
    created_ns: i128,
};

pub const UploadRecord = struct {
    upload_id: UploadId,
    bucket_id: core.BucketId,
    created_ns: i128,
    /// Borrowed; for decoded records these point into the input bytes.
    key: []const u8,
    content_type: []const u8 = "",
    /// Applied to the object on complete: encoded tag set, retention, legal hold.
    tags: []const u8 = "",
    retention_mode: record.RetentionMode = .none,
    retain_until_ns: i128 = 0,
    legal_hold: bool = false,
    /// Encoded header lists and system headers, as in ObjectRecord.
    user_meta: []const u8 = "",
    internal_meta: []const u8 = "",
    system: headers.System = .{},
    /// Sorted by part number, unique.
    parts: []const Part = &.{},

    pub fn findPart(self: UploadRecord, number: u16) ?Part {
        for (self.parts) |p| if (p.number == number) return p;
        return null;
    }
};

pub fn encode(r: UploadRecord, gpa: std.mem.Allocator) Error![]u8 {
    if (r.key.len > record.max_key_len or r.content_type.len > std.math.maxInt(u16) or r.tags.len > std.math.maxInt(u16))
        return error.KeyTooLong;
    if (r.parts.len > max_parts) return error.OutOfMemory;
    for ([_]struct { []const u8, headers.Kind }{ .{ r.user_meta, .user }, .{ r.internal_meta, .internal } }) |l| {
        var c: codec.Cursor = .{ .bytes = l[0] };
        if (l[0].len > 0 and ((headers.take(&c, l[1]) catch return error.MetadataTooLarge).len != l[0].len)) return error.MetadataTooLarge;
    }
    r.system.validate() catch return error.MetadataTooLarge;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    encodeTo(r, &a.writer) catch return error.OutOfMemory;
    return a.toOwnedSlice() catch error.OutOfMemory;
}

fn encodeTo(r: UploadRecord, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(magic);
    try codec.putInt(w, u16, format_version);
    try w.writeAll(&r.upload_id.bytes);
    try w.writeAll(&r.bucket_id.bytes);
    try codec.putInt(w, i128, r.created_ns);
    try codec.putInt(w, u16, @intCast(r.key.len));
    try w.writeAll(r.key);
    try codec.putInt(w, u16, @intCast(r.content_type.len));
    try w.writeAll(r.content_type);
    try codec.putInt(w, u16, @intCast(r.tags.len));
    try w.writeAll(r.tags);
    try w.writeByte(@intFromEnum(r.retention_mode));
    try codec.putInt(w, i128, r.retain_until_ns);
    try w.writeByte(@intFromBool(r.legal_hold));
    try headers.put(w, r.user_meta);
    try headers.put(w, r.internal_meta);
    try headers.putSystem(w, r.system);
    try codec.putInt(w, u16, @intCast(r.parts.len));
    for (r.parts) |p| {
        try codec.putInt(w, u16, p.number);
        try codec.putInt(w, u64, p.size);
        try w.writeAll(&p.md5);
        try w.writeAll(&p.blob.bytes);
        try codec.putInt(w, i128, p.created_ns);
    }
}

/// True when `bytes` look like an upload record (vs. an object record).
pub fn isUpload(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, magic);
}

/// Strings borrow from `bytes`; the part list is allocated in `arena`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8) Error!UploadRecord {
    var c: codec.Cursor = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try c.take(4), magic)) return error.Corrupt;
    const ver = try c.int(u16);
    if (ver < 1 or ver > format_version) return error.Corrupt;
    var r: UploadRecord = .{ .upload_id = undefined, .bucket_id = undefined, .created_ns = undefined, .key = undefined };
    r.upload_id = .{ .bytes = try c.fixed(16) };
    r.bucket_id = .{ .bytes = try c.fixed(16) };
    r.created_ns = try c.int(i128);
    r.key = try c.take(try c.int(u16));
    if (r.key.len > record.max_key_len) return error.Corrupt;
    r.content_type = try c.take(try c.int(u16));
    r.tags = try c.take(try c.int(u16));
    r.retention_mode = std.meta.intToEnum(record.RetentionMode, (try c.take(1))[0]) catch return error.Corrupt;
    r.retain_until_ns = try c.int(i128);
    r.legal_hold = switch ((try c.take(1))[0]) {
        0 => false,
        1 => true,
        else => return error.Corrupt,
    };
    if (ver >= 2) {
        r.user_meta = try headers.take(&c, .user);
        r.internal_meta = try headers.take(&c, .internal);
        r.system = try headers.takeSystem(&c);
    }
    const n = try c.int(u16);
    if (n > max_parts) return error.Corrupt;
    const parts = try arena.alloc(Part, n);
    var prev: u16 = 0;
    for (parts) |*p| {
        p.number = try c.int(u16);
        if (p.number <= prev) return error.Corrupt;
        prev = p.number;
        p.size = try c.int(u64);
        p.md5 = try c.fixed(16);
        p.blob = .{ .bytes = try c.fixed(16) };
        p.created_ns = try c.int(i128);
    }
    if (c.pos != bytes.len) return error.Corrupt;
    r.parts = parts;
    return r;
}

test "upload record roundtrip and truncation" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const parts = [_]Part{
        .{ .number = 1, .size = 5, .md5 = [_]u8{1} ** 16, .blob = core.ObjectId.random(), .created_ns = 7 },
        .{ .number = 3, .size = 9, .md5 = [_]u8{3} ** 16, .blob = core.ObjectId.random(), .created_ns = 8 },
    };
    const r: UploadRecord = .{
        .upload_id = UploadId.random(),
        .bucket_id = core.BucketId.random(),
        .created_ns = 42,
        .key = "a/b",
        .content_type = "text/plain",
        .tags = "\x01",
        .retention_mode = .governance,
        .retain_until_ns = 5,
        .legal_hold = true,
        .user_meta = "\x01\x00\x01\x00k\x01\x00v",
        .system = .{ .content_language = "en" },
        .parts = &parts,
    };
    const bytes = try encode(r, gpa);
    defer gpa.free(bytes);
    try std.testing.expect(isUpload(bytes));
    const d = try decode(arena.allocator(), bytes);
    try std.testing.expect(d.upload_id.eql(r.upload_id));
    try std.testing.expectEqualStrings("a/b", d.key);
    try std.testing.expectEqualStrings("\x01", d.tags);
    try std.testing.expect(d.legal_hold and d.retention_mode == .governance and d.retain_until_ns == 5);
    try std.testing.expectEqual(@as(usize, 2), d.parts.len);
    try std.testing.expectEqual(@as(u64, 9), d.findPart(3).?.size);
    try std.testing.expect(d.findPart(2) == null);
    try std.testing.expectEqualStrings(r.user_meta, d.user_meta);
    try std.testing.expectEqualStrings("en", d.system.content_language);
    for (0..bytes.len) |n| try std.testing.expectError(error.Corrupt, decode(arena.allocator(), bytes[0..n]));

    // v1: no metadata section.
    const plain = try encode(.{ .upload_id = r.upload_id, .bucket_id = r.bucket_id, .created_ns = 1, .key = "k" }, gpa);
    defer gpa.free(plain);
    var v1: std.ArrayList(u8) = .empty;
    defer v1.deinit(gpa);
    const meta_at = plain.len - 2 - (2 + 2 + 10);
    try v1.appendSlice(gpa, plain[0..meta_at]);
    try v1.appendSlice(gpa, plain[plain.len - 2 ..]);
    v1.items[4] = 1;
    const o = try decode(arena.allocator(), v1.items);
    try std.testing.expectEqualStrings("k", o.key);
    try std.testing.expectEqualStrings("", o.user_meta);
}
