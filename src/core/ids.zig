//! 128-bit identifiers. Object identity is decoupled from S3 names.
const std = @import("std");

pub const ParseError = error{InvalidId};

fn Id128(comptime tag: []const u8) type {
    return struct {
        bytes: [16]u8,

        const Self = @This();
        pub const kind = tag;
        pub const hex_len = 32;

        pub fn random() Self {
            var b: [16]u8 = undefined;
            std.crypto.random.bytes(&b);
            return .{ .bytes = b };
        }

        pub fn toHex(self: Self) [32]u8 {
            return std.fmt.bytesToHex(self.bytes, .lower);
        }

        pub fn parseHex(s: []const u8) ParseError!Self {
            if (s.len != 32) return error.InvalidId;
            var out: Self = undefined;
            _ = std.fmt.hexToBytes(&out.bytes, s) catch return error.InvalidId;
            return out;
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u8, &a.bytes, &b.bytes);
        }
    };
}

pub const ObjectId = Id128("object");
pub const BucketId = Id128("bucket");
pub const VersionId = Id128("version");
/// Identity of one drive and of the drive set it was formatted into.
pub const DriveId = Id128("drive");
pub const SetId = Id128("set");

/// Stable id for a (bucket, key) name; addresses the object record.
pub const NameId = Id128("name");

pub fn nameId(bucket: BucketId, key: []const u8) NameId {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&bucket.bytes);
    h.update(key);
    var d: [32]u8 = undefined;
    h.final(&d);
    return .{ .bytes = d[0..16].* };
}

/// Version ids start with a big-endian timestamp so hex order is creation order.
pub fn newVersionId(now_ns: i128) VersionId {
    var v = VersionId.random();
    const t: u64 = std.math.cast(u64, now_ns) orelse 0;
    std.mem.writeInt(u64, v.bytes[0..8], t, .big);
    return v;
}

/// Stable id for one version of a (bucket, key); addresses noncurrent versions.
pub fn versionNameId(bucket: BucketId, key: []const u8, version: VersionId) NameId {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("version\x00");
    h.update(&bucket.bytes);
    h.update(&version.bytes);
    h.update(key);
    var d: [32]u8 = undefined;
    h.final(&d);
    return .{ .bytes = d[0..16].* };
}

test "id hex roundtrip" {
    const a = ObjectId.random();
    const h = a.toHex();
    const b = try ObjectId.parseHex(&h);
    try std.testing.expect(a.eql(b));
    try std.testing.expectError(error.InvalidId, ObjectId.parseHex("zz"));
}

test "nameId depends on bucket and key" {
    const b1 = BucketId{ .bytes = [_]u8{1} ** 16 };
    const b2 = BucketId{ .bytes = [_]u8{2} ** 16 };
    try std.testing.expect(!nameId(b1, "k").eql(nameId(b2, "k")));
    try std.testing.expect(nameId(b1, "k").eql(nameId(b1, "k")));
    const v = newVersionId(5);
    try std.testing.expect(!versionNameId(b1, "k", v).eql(nameId(b1, "k")));
    try std.testing.expect(std.mem.lessThan(u8, &newVersionId(5).toHex(), &newVersionId(6).toHex()));
}
