//! Checksum and ETag value types.
const std = @import("std");

pub const Md5 = std.crypto.hash.Md5;

pub const ETag = struct {
    md5: [16]u8,

    /// Quoted hex form as sent in HTTP headers and XML.
    pub fn quoted(self: ETag) [34]u8 {
        var out: [34]u8 = undefined;
        out[0] = '"';
        out[33] = '"';
        out[1..33].* = std.fmt.bytesToHex(self.md5, .lower);
        return out;
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
    const q = (ETag{ .md5 = d }).quoted();
    try std.testing.expectEqualStrings("\"d41d8cd98f00b204e9800998ecf8427e\"", &q);
}
