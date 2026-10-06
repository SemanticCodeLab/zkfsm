//! SSH wire encoding (RFC 4251 section 5): bounded readers and writers for
//! byte, boolean, uint32, uint64, string, mpint and name-list values.
const std = @import("std");

pub const DecodeError = error{BadMessage};
pub const EncodeError = error{NoSpace};

/// Reads values from a received message; every length is checked against the input.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn rest(r: *const Reader) []const u8 {
        return r.buf[r.pos..];
    }

    pub fn done(r: *const Reader) bool {
        return r.pos == r.buf.len;
    }

    pub fn bytes(r: *Reader, n: usize) DecodeError![]const u8 {
        if (n > r.buf.len - r.pos) return error.BadMessage;
        const s = r.buf[r.pos..][0..n];
        r.pos += n;
        return s;
    }

    pub fn byte(r: *Reader) DecodeError!u8 {
        return (try r.bytes(1))[0];
    }

    pub fn boolean(r: *Reader) DecodeError!bool {
        return try r.byte() != 0;
    }

    pub fn u32be(r: *Reader) DecodeError!u32 {
        return std.mem.readInt(u32, (try r.bytes(4))[0..4], .big);
    }

    pub fn u64be(r: *Reader) DecodeError!u64 {
        return std.mem.readInt(u64, (try r.bytes(8))[0..8], .big);
    }

    pub fn string(r: *Reader) DecodeError![]const u8 {
        const n = try r.u32be();
        return r.bytes(n);
    }

    /// A string no longer than `max`.
    pub fn stringMax(r: *Reader, max: usize) DecodeError![]const u8 {
        const s = try r.string();
        if (s.len > max) return error.BadMessage;
        return s;
    }

    /// Unsigned mpint magnitude without leading zeros; negatives are rejected.
    pub fn mpintUnsigned(r: *Reader) DecodeError![]const u8 {
        const s = try r.string();
        if (s.len > 0 and s[0] & 0x80 != 0) return error.BadMessage;
        var i: usize = 0;
        while (i < s.len and s[i] == 0) i += 1;
        return s[i..];
    }
};

/// Appends values to a fixed buffer.
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn written(w: *const Writer) []u8 {
        return w.buf[0..w.len];
    }

    pub fn reserve(w: *Writer, n: usize) EncodeError![]u8 {
        if (n > w.buf.len - w.len) return error.NoSpace;
        const s = w.buf[w.len..][0..n];
        w.len += n;
        return s;
    }

    pub fn bytes(w: *Writer, s: []const u8) EncodeError!void {
        @memcpy(try w.reserve(s.len), s);
    }

    pub fn byte(w: *Writer, b: u8) EncodeError!void {
        (try w.reserve(1))[0] = b;
    }

    pub fn boolean(w: *Writer, b: bool) EncodeError!void {
        return w.byte(@intFromBool(b));
    }

    pub fn u32be(w: *Writer, v: u32) EncodeError!void {
        std.mem.writeInt(u32, (try w.reserve(4))[0..4], v, .big);
    }

    pub fn u64be(w: *Writer, v: u64) EncodeError!void {
        std.mem.writeInt(u64, (try w.reserve(8))[0..8], v, .big);
    }

    pub fn string(w: *Writer, s: []const u8) EncodeError!void {
        if (s.len > std.math.maxInt(u32)) return error.NoSpace;
        try w.u32be(@intCast(s.len));
        try w.bytes(s);
    }

    /// Positive big-endian magnitude as an mpint (adds a zero byte when the top bit is set).
    pub fn mpint(w: *Writer, mag: []const u8) EncodeError!void {
        var i: usize = 0;
        while (i < mag.len and mag[i] == 0) i += 1;
        const m = mag[i..];
        const pad: usize = if (m.len > 0 and m[0] & 0x80 != 0) 1 else 0;
        try w.u32be(@intCast(m.len + pad));
        if (pad == 1) try w.byte(0);
        try w.bytes(m);
    }

    /// Starts a length-prefixed string whose body is written next; finish with `endString`.
    pub fn beginString(w: *Writer) EncodeError!usize {
        _ = try w.reserve(4);
        return w.len;
    }

    pub fn endString(w: *Writer, start: usize) void {
        std.mem.writeInt(u32, w.buf[start - 4 ..][0..4], @intCast(w.len - start), .big);
    }
};

/// Iterates a comma-separated name-list.
pub fn names(list: []const u8) std.mem.TokenIterator(u8, .scalar) {
    return std.mem.tokenizeScalar(u8, list, ',');
}

pub fn hasName(list: []const u8, name: []const u8) bool {
    var it = names(list);
    while (it.next()) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

test "wire round trip" {
    var buf: [128]u8 = undefined;
    var w = Writer.init(&buf);
    try w.byte(7);
    try w.boolean(true);
    try w.u32be(0xdeadbeef);
    try w.u64be(42);
    try w.string("ssh");
    try w.mpint(&.{ 0x00, 0x80, 0x01 });
    try w.mpint(&.{0x7f});
    try w.mpint(&.{});
    var r = Reader.init(w.written());
    try std.testing.expectEqual(@as(u8, 7), try r.byte());
    try std.testing.expect(try r.boolean());
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), try r.u32be());
    try std.testing.expectEqual(@as(u64, 42), try r.u64be());
    try std.testing.expectEqualStrings("ssh", try r.string());
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, try r.mpintUnsigned());
    try std.testing.expectEqualSlices(u8, &.{0x7f}, try r.mpintUnsigned());
    try std.testing.expectEqualSlices(u8, &.{}, try r.mpintUnsigned());
    try std.testing.expect(r.done());
}

test "mpint encodings match RFC 4251 examples" {
    var buf: [32]u8 = undefined;
    var w = Writer.init(&buf);
    try w.mpint(&.{ 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 });
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 }, w.written());
    w = Writer.init(&buf);
    try w.mpint(&.{0x80});
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 2, 0, 0x80 }, w.written());
}

test "reader rejects truncated and oversize values" {
    var r = Reader.init(&.{ 0, 0, 0, 9, 'a' });
    try std.testing.expectError(error.BadMessage, r.string());
    r = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff });
    try std.testing.expectError(error.BadMessage, r.string());
    r = Reader.init(&.{ 0, 0, 0, 3, 'a', 'b', 'c' });
    try std.testing.expectError(error.BadMessage, r.stringMax(2));
    r = Reader.init(&.{ 0, 0, 0, 1, 0x80 });
    try std.testing.expectError(error.BadMessage, r.mpintUnsigned());
    var small: [3]u8 = undefined;
    var w = Writer.init(&small);
    try std.testing.expectError(error.NoSpace, w.u32be(1));
}

test "name lists" {
    try std.testing.expect(hasName("a,b,kex-strict-c-v00@openssh.com", "kex-strict-c-v00@openssh.com"));
    try std.testing.expect(!hasName("ab,c", "a"));
}
