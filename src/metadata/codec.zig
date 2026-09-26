//! Bounds-checked little-endian cursor for binary metadata.
const std = @import("std");

pub const DecodeError = error{Corrupt};

pub const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(c: *Cursor, n: usize) DecodeError![]const u8 {
        if (c.bytes.len - c.pos < n) return error.Corrupt;
        defer c.pos += n;
        return c.bytes[c.pos..][0..n];
    }

    pub fn int(c: *Cursor, comptime T: type) DecodeError!T {
        const s = try c.take(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }

    pub fn fixed(c: *Cursor, comptime n: usize) DecodeError![n]u8 {
        return (try c.take(n))[0..n].*;
    }
};

pub fn putInt(w: *std.Io.Writer, comptime T: type, v: T) std.Io.Writer.Error!void {
    try w.writeInt(T, v, .little);
}
