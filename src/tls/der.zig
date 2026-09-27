//! Minimal bounded DER reader for key files; never reads past its slice.
const std = @import("std");

pub const Error = error{BadDer};

pub const Tag = struct {
    pub const integer: u8 = 0x02;
    pub const bit_string: u8 = 0x03;
    pub const octet_string: u8 = 0x04;
    pub const null_: u8 = 0x05;
    pub const oid: u8 = 0x06;
    pub const sequence: u8 = 0x30;
    pub const ctx0: u8 = 0xa0;
    pub const ctx1: u8 = 0xa1;
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn done(r: Reader) bool {
        return r.pos >= r.bytes.len;
    }

    pub fn peekTag(r: Reader) ?u8 {
        return if (r.pos < r.bytes.len) r.bytes[r.pos] else null;
    }

    /// Reads one element with the expected tag and returns its contents.
    pub fn expect(r: *Reader, tag: u8) Error![]const u8 {
        if (r.pos + 2 > r.bytes.len or r.bytes[r.pos] != tag) return error.BadDer;
        var i = r.pos + 1;
        const first = r.bytes[i];
        i += 1;
        var len: usize = 0;
        if (first < 0x80) {
            len = first;
        } else {
            const n = first & 0x7f;
            if (n == 0 or n > 3 or i + n > r.bytes.len) return error.BadDer;
            for (r.bytes[i..][0..n]) |b| len = (len << 8) | b;
            i += n;
        }
        if (len > r.bytes.len - i) return error.BadDer;
        r.pos = i + len;
        return r.bytes[i..][0..len];
    }

    pub fn sub(r: *Reader, tag: u8) Error!Reader {
        return .{ .bytes = try r.expect(tag) };
    }

    /// Unsigned big-endian integer with the sign padding byte stripped.
    pub fn uint(r: *Reader) Error![]const u8 {
        var v = try r.expect(Tag.integer);
        if (v.len == 0 or v[0] & 0x80 != 0) return error.BadDer;
        while (v.len > 1 and v[0] == 0) v = v[1..];
        return v;
    }

    pub fn skip(r: *Reader) Error!void {
        const t = r.peekTag() orelse return error.BadDer;
        _ = try r.expect(t);
    }
};

test "der reader bounds" {
    var r: Reader = .{ .bytes = &.{ 0x30, 0x03, 0x02, 0x01, 0x05 } };
    var s = try r.sub(Tag.sequence);
    try std.testing.expectEqualSlices(u8, &.{5}, try s.uint());
    try std.testing.expect(r.done());
    var bad: Reader = .{ .bytes = &.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff } };
    try std.testing.expectError(error.BadDer, bad.expect(Tag.sequence));
    var short: Reader = .{ .bytes = &.{ 0x30, 0x05, 0x00 } };
    try std.testing.expectError(error.BadDer, short.expect(Tag.sequence));
}
