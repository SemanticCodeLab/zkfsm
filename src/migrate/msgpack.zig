//! Bounded MessagePack reader over an in-memory slice. Every length is checked
//! against the remaining input and nesting is capped, so hostile bytes only error.
const std = @import("std");

pub const Error = error{ Truncated, BadType, TooDeep, Overflow };

pub const Kind = enum { nil, boolean, uint, int, float, str, bin, array, map, ext };

pub const max_depth = 32;

/// msgp's time extension: 8-byte big-endian seconds, 4-byte nanoseconds.
pub const time_ext_type: i8 = 5;

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn remaining(r: *const Reader) usize {
        return r.buf.len - r.pos;
    }

    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (n > r.remaining()) return error.Truncated;
        const s = r.buf[r.pos .. r.pos + n];
        r.pos += n;
        return s;
    }

    fn byte(r: *Reader) Error!u8 {
        return (try r.take(1))[0];
    }

    fn be(r: *Reader, comptime T: type) Error!T {
        const s = try r.take(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .big);
    }

    pub fn peek(r: *const Reader) Error!Kind {
        if (r.pos >= r.buf.len) return error.Truncated;
        const b = r.buf[r.pos];
        return switch (b) {
            0x00...0x7f, 0xcc...0xcf => .uint,
            0xe0...0xff, 0xd0...0xd3 => .int,
            0x80...0x8f, 0xde, 0xdf => .map,
            0x90...0x9f, 0xdc, 0xdd => .array,
            0xa0...0xbf, 0xd9...0xdb => .str,
            0xc0 => .nil,
            0xc2, 0xc3 => .boolean,
            0xc4...0xc6 => .bin,
            0xca, 0xcb => .float,
            0xc7...0xc9, 0xd4...0xd8 => .ext,
            0xc1 => error.BadType,
        };
    }

    /// Consumes a nil if present.
    pub fn nil(r: *Reader) Error!bool {
        if (try r.peek() != .nil) return false;
        r.pos += 1;
        return true;
    }

    pub fn boolean(r: *Reader) Error!bool {
        return switch (try r.byte()) {
            0xc2 => false,
            0xc3 => true,
            else => error.BadType,
        };
    }

    /// Any integer encoding that fits an i64.
    pub fn int(r: *Reader) Error!i64 {
        const b = try r.byte();
        return switch (b) {
            0x00...0x7f => b,
            0xe0...0xff => @as(i8, @bitCast(b)),
            0xcc => try r.be(u8),
            0xcd => try r.be(u16),
            0xce => try r.be(u32),
            0xcf => std.math.cast(i64, try r.be(u64)) orelse error.Overflow,
            0xd0 => try r.be(i8),
            0xd1 => try r.be(i16),
            0xd2 => try r.be(i32),
            0xd3 => try r.be(i64),
            else => error.BadType,
        };
    }

    pub fn uint(r: *Reader) Error!u64 {
        if (try r.peek() == .uint and r.buf[r.pos] == 0xcf) {
            r.pos += 1;
            return r.be(u64);
        }
        return std.math.cast(u64, try r.int()) orelse error.Overflow;
    }

    pub fn str(r: *Reader) Error![]const u8 {
        const b = try r.byte();
        const n: usize = switch (b) {
            0xa0...0xbf => b & 0x1f,
            0xd9 => try r.be(u8),
            0xda => try r.be(u16),
            0xdb => try r.be(u32),
            else => return error.BadType,
        };
        return r.take(n);
    }

    pub fn bin(r: *Reader) Error![]const u8 {
        const b = try r.byte();
        const n: usize = switch (b) {
            0xc4 => try r.be(u8),
            0xc5 => try r.be(u16),
            0xc6 => try r.be(u32),
            else => return error.BadType,
        };
        return r.take(n);
    }

    /// Bin or str payload.
    pub fn bytes(r: *Reader) Error![]const u8 {
        return if (try r.peek() == .bin) r.bin() else r.str();
    }

    /// Element count, bounded by the bytes left (each element is at least one byte).
    pub fn arrayLen(r: *Reader) Error!u32 {
        const b = try r.byte();
        const n: u32 = switch (b) {
            0x90...0x9f => b & 0x0f,
            0xdc => try r.be(u16),
            0xdd => try r.be(u32),
            else => return error.BadType,
        };
        if (n > r.remaining()) return error.Truncated;
        return n;
    }

    pub fn mapLen(r: *Reader) Error!u32 {
        const b = try r.byte();
        const n: u32 = switch (b) {
            0x80...0x8f => b & 0x0f,
            0xde => try r.be(u16),
            0xdf => try r.be(u32),
            else => return error.BadType,
        };
        if (@as(u64, n) * 2 > r.remaining()) return error.Truncated;
        return n;
    }

    pub const Ext = struct { type: i8, data: []const u8 };

    pub fn ext(r: *Reader) Error!Ext {
        const b = try r.byte();
        const n: usize = switch (b) {
            0xd4 => 1,
            0xd5 => 2,
            0xd6 => 4,
            0xd7 => 8,
            0xd8 => 16,
            0xc7 => try r.be(u8),
            0xc8 => try r.be(u16),
            0xc9 => try r.be(u32),
            else => return error.BadType,
        };
        const t: i8 = @bitCast(try r.byte());
        return .{ .type = t, .data = try r.take(n) };
    }

    /// Unix nanoseconds from a msgp time extension or a plain integer.
    pub fn time(r: *Reader) Error!i128 {
        if (try r.peek() != .ext) return try r.int();
        const e = try r.ext();
        if (e.type != time_ext_type or e.data.len != 12) return error.BadType;
        const secs = std.mem.readInt(i64, e.data[0..8], .big);
        const nanos = std.mem.readInt(u32, e.data[8..12], .big);
        return @as(i128, secs) * std.time.ns_per_s + nanos;
    }

    pub fn skip(r: *Reader) Error!void {
        return r.skipDepth(0);
    }

    fn skipDepth(r: *Reader, depth: usize) Error!void {
        if (depth >= max_depth) return error.TooDeep;
        switch (try r.peek()) {
            .nil => r.pos += 1,
            .boolean => _ = try r.boolean(),
            .uint, .int => _ = r.int() catch |e| if (e != error.Overflow) return e,
            .float => {
                const b = try r.byte();
                _ = try r.take(if (b == 0xca) 4 else 8);
            },
            .str => _ = try r.str(),
            .bin => _ = try r.bin(),
            .ext => _ = try r.ext(),
            .array => {
                const n = try r.arrayLen();
                for (0..n) |_| try r.skipDepth(depth + 1);
            },
            .map => {
                const n = try r.mapLen();
                for (0..n * 2) |_| try r.skipDepth(depth + 1);
            },
        }
    }
};

const testing = std.testing;

test "scalars and containers" {
    const doc = [_]u8{ 0x83, 0xa1, 'a', 0x7f, 0xa1, 'b', 0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xa1, 'c', 0x92, 0xc4, 0x02, 1, 2, 0xc0 };
    var r: Reader = .{ .buf = &doc };
    try testing.expectEqual(@as(u32, 3), try r.mapLen());
    try testing.expectEqualStrings("a", try r.str());
    try testing.expectEqual(@as(i64, 127), try r.int());
    try testing.expectEqualStrings("b", try r.str());
    try testing.expectEqual(@as(i64, -2), try r.int());
    try testing.expectEqualStrings("c", try r.str());
    try testing.expectEqual(@as(u32, 2), try r.arrayLen());
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, try r.bin());
    try testing.expect(try r.nil());
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "hostile lengths and nesting error out" {
    // bin32 claiming 4 GiB, array32 claiming 4 billion entries, map past the end.
    const cases = [_][]const u8{
        &.{ 0xc6, 0xff, 0xff, 0xff, 0xff, 0x00 },
        &.{ 0xdd, 0xff, 0xff, 0xff, 0xff },
        &.{ 0xdf, 0x00, 0x00, 0x00, 0x02, 0xa0 },
        &.{ 0xdb, 0x00, 0x00, 0x00, 0x09, 'x' },
        &.{0xc1},
        &.{ 0xc9, 0x7f, 0xff, 0xff, 0xff, 0x05 },
        &.{},
    };
    for (cases) |c| {
        var r: Reader = .{ .buf = c };
        try testing.expect(std.meta.isError(r.skip()));
    }
    var deep: [200]u8 = @splat(0x91);
    var r: Reader = .{ .buf = &deep };
    try testing.expectError(error.TooDeep, r.skip());
    var bad: Reader = .{ .buf = &.{0xa1} };
    try testing.expectError(error.BadType, bad.int());
    var ov: Reader = .{ .buf = &.{ 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
    try testing.expectError(error.Overflow, ov.int());
}

test "random bytes never crash the skipper" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    var buf: [64]u8 = undefined;
    for (0..20000) |_| {
        prng.random().bytes(&buf);
        const n = prng.random().uintAtMost(usize, buf.len);
        var r: Reader = .{ .buf = buf[0..n] };
        r.skip() catch {};
    }
}

test "time extension" {
    const doc = [_]u8{ 0xc7, 12, 5, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 7 };
    var r: Reader = .{ .buf = &doc };
    try testing.expectEqual(@as(i128, 10 * std.time.ns_per_s + 7), try r.time());
}
