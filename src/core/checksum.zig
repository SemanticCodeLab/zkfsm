//! Checksum and ETag value types.
const std = @import("std");

pub const Md5 = std.crypto.hash.Md5;

/// CRC32C (Castagnoli), used for per-chunk bitrot detection.
pub const Crc32c = std.hash.crc.Crc32Iscsi;

pub const ETag = struct {
    /// Object MD5, or for multipart objects the MD5 of the part MD5s.
    md5: [16]u8,
    /// Multipart part count; 0 for single-part objects.
    parts: u32 = 0,

    pub const quoted_max = 46;

    /// Quoted hex form as sent in HTTP headers and XML: "<md5>" or "<md5>-<n>".
    pub fn quoted(self: ETag, buf: *[quoted_max]u8) []const u8 {
        const hex = std.fmt.bytesToHex(self.md5, .lower);
        if (self.parts == 0) return std.fmt.bufPrint(buf, "\"{s}\"", .{&hex}) catch unreachable; // fits
        return std.fmt.bufPrint(buf, "\"{s}-{d}\"", .{ &hex, self.parts }) catch unreachable; // u32 fits
    }
};

pub const ChecksumAlgorithm = enum(u8) { none = 0, md5 = 1, crc32c = 2, sha256 = 3 };

pub const Checksum = struct {
    algorithm: ChecksumAlgorithm = .none,
    len: u8 = 0,
    digest: [32]u8 = [_]u8{0} ** 32,

    pub fn fromMd5(d: [16]u8) Checksum {
        var c: Checksum = .{ .algorithm = .md5, .len = 16 };
        @memcpy(c.digest[0..16], &d);
        return c;
    }
};

test "etag quoted" {
    var d: [16]u8 = undefined;
    Md5.hash("", &d, .{});
    var buf: [ETag.quoted_max]u8 = undefined;
    try std.testing.expectEqualStrings("\"d41d8cd98f00b204e9800998ecf8427e\"", (ETag{ .md5 = d }).quoted(&buf));
    try std.testing.expectEqualStrings("\"d41d8cd98f00b204e9800998ecf8427e-12\"", (ETag{ .md5 = d, .parts = 12 }).quoted(&buf));
}

test "crc32c check value" {
    try std.testing.expectEqual(@as(u32, 0xE3069283), Crc32c.hash("123456789"));
}
