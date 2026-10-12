//! Protobuf wire-format writer: varints, fixed fields, and length-delimited
//! nested messages (the length is inserted when the message closes).
const std = @import("std");

pub const Error = error{OutOfMemory};

pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// Start offsets of the open nested messages.
    stack: [16]usize = undefined,
    depth: u8 = 0,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(w: *Writer) void {
        w.buf.deinit(w.gpa);
    }

    pub fn bytes(w: *const Writer) []const u8 {
        return w.buf.items;
    }

    fn varint(w: *Writer, v0: u64) Error!void {
        var v = v0;
        while (v >= 0x80) : (v >>= 7) try w.buf.append(w.gpa, @as(u8, @truncate(v)) | 0x80);
        try w.buf.append(w.gpa, @truncate(v));
    }

    fn tag(w: *Writer, field: u32, wire: u3) Error!void {
        try w.varint((@as(u64, field) << 3) | wire);
    }

    pub fn uint(w: *Writer, field: u32, v: u64) Error!void {
        if (v == 0) return;
        try w.tag(field, 0);
        try w.varint(v);
    }

    pub fn int64(w: *Writer, field: u32, v: i64) Error!void {
        try w.uint(field, @bitCast(v));
    }

    pub fn boolean(w: *Writer, field: u32, v: bool) Error!void {
        try w.uint(field, @intFromBool(v));
    }

    pub fn fixed64(w: *Writer, field: u32, v: u64) Error!void {
        try w.tag(field, 1);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try w.buf.appendSlice(w.gpa, &b);
    }

    pub fn fixed32(w: *Writer, field: u32, v: u32) Error!void {
        try w.tag(field, 5);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try w.buf.appendSlice(w.gpa, &b);
    }

    pub fn double(w: *Writer, field: u32, v: f64) Error!void {
        try w.fixed64(field, @bitCast(v));
    }

    /// Length-delimited bytes; empty values are omitted (proto3 default).
    pub fn str(w: *Writer, field: u32, v: []const u8) Error!void {
        if (v.len == 0) return;
        try w.tag(field, 2);
        try w.varint(v.len);
        try w.buf.appendSlice(w.gpa, v);
    }

    /// Packed repeated fixed64.
    pub fn packedFixed64(w: *Writer, field: u32, vs: []const u64) Error!void {
        try w.tag(field, 2);
        try w.varint(vs.len * 8);
        for (vs) |v| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, v, .little);
            try w.buf.appendSlice(w.gpa, &b);
        }
    }

    pub fn packedDouble(w: *Writer, field: u32, vs: []const f64) Error!void {
        try w.tag(field, 2);
        try w.varint(vs.len * 8);
        for (vs) |v| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, @bitCast(v), .little);
            try w.buf.appendSlice(w.gpa, &b);
        }
    }

    /// Opens a nested message; close it with `end`.
    pub fn begin(w: *Writer, field: u32) Error!void {
        std.debug.assert(w.depth < w.stack.len);
        try w.tag(field, 2);
        w.stack[w.depth] = w.buf.items.len;
        w.depth += 1;
    }

    pub fn end(w: *Writer) Error!void {
        w.depth -= 1;
        const start = w.stack[w.depth];
        const len = w.buf.items.len - start;
        var tmp: [10]u8 = undefined;
        var n: usize = 0;
        var v: u64 = len;
        while (v >= 0x80) : (v >>= 7) {
            tmp[n] = @as(u8, @truncate(v)) | 0x80;
            n += 1;
        }
        tmp[n] = @truncate(v);
        n += 1;
        try w.buf.insertSlice(w.gpa, start, tmp[0..n]);
    }
};

/// Minimal reader for tests and the in-process receiver checks.
pub const Reader = struct {
    s: []const u8,
    i: usize = 0,

    pub const Field = struct { num: u32, wire: u3, int: u64 = 0, data: []const u8 = "" };

    fn varint(r: *Reader) ?u64 {
        var v: u64 = 0;
        var shift: u6 = 0;
        while (r.i < r.s.len) {
            const b = r.s[r.i];
            r.i += 1;
            v |= @as(u64, b & 0x7f) << shift;
            if (b < 0x80) return v;
            if (shift >= 63) return null;
            shift += 7;
        }
        return null;
    }

    pub fn next(r: *Reader) ?Field {
        if (r.i >= r.s.len) return null;
        const t = r.varint() orelse return null;
        var f: Field = .{ .num = @intCast(t >> 3), .wire = @intCast(t & 7) };
        switch (f.wire) {
            0 => f.int = r.varint() orelse return null,
            1 => {
                if (r.i + 8 > r.s.len) return null;
                f.int = std.mem.readInt(u64, r.s[r.i..][0..8], .little);
                r.i += 8;
            },
            5 => {
                if (r.i + 4 > r.s.len) return null;
                f.int = std.mem.readInt(u32, r.s[r.i..][0..4], .little);
                r.i += 4;
            },
            2 => {
                const n = r.varint() orelse return null;
                if (n > r.s.len - r.i) return null;
                f.data = r.s[r.i..][0..@intCast(n)];
                r.i += @intCast(n);
            },
            else => return null,
        }
        return f;
    }
};

test "nested lengths are inserted" {
    var w: Writer = .init(std.testing.allocator);
    defer w.deinit();
    try w.begin(1);
    try w.str(1, "x" ** 200);
    try w.uint(2, 300);
    try w.end();
    var r: Reader = .{ .s = w.bytes() };
    const outer = r.next().?;
    try std.testing.expectEqual(@as(u32, 1), outer.num);
    var in: Reader = .{ .s = outer.data };
    try std.testing.expectEqual(@as(usize, 200), in.next().?.data.len);
    try std.testing.expectEqual(@as(u64, 300), in.next().?.int);
    try std.testing.expect(in.next() == null);
    try std.testing.expect(r.next() == null);
}
