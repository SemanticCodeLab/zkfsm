//! Minimal protobuf wire-format reader and writer.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{ ProtobufInvalid, OutOfMemory };

pub const Wire = enum(u3) { varint = 0, i64 = 1, len = 2, sgroup = 3, egroup = 4, i32 = 5, _ };

pub const Field = struct {
    num: u32,
    wire: Wire,
    int: u64 = 0,
    bytes: []const u8 = "",
};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    fn varint(self: *Reader) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (shift < 64) : (shift += 7) {
            if (self.pos >= self.buf.len) return error.ProtobufInvalid;
            const b = self.buf[self.pos];
            self.pos += 1;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) return v;
        }
        return error.ProtobufInvalid;
    }

    fn take(self: *Reader, n: u64) Error![]const u8 {
        if (n > self.buf.len - self.pos) return error.ProtobufInvalid;
        const s = self.buf[self.pos..][0..@intCast(n)];
        self.pos += @intCast(n);
        return s;
    }

    pub fn next(self: *Reader) Error!?Field {
        if (self.pos >= self.buf.len) return null;
        const key = try self.varint();
        const num: u32 = @intCast(key >> 3 & 0x1fffffff);
        if (num == 0) return error.ProtobufInvalid;
        const wire: Wire = @enumFromInt(@as(u3, @truncate(key)));
        var f: Field = .{ .num = num, .wire = wire };
        switch (wire) {
            .varint => f.int = try self.varint(),
            .i64 => f.bytes = try self.take(8),
            .i32 => f.bytes = try self.take(4),
            .len => f.bytes = try self.take(try self.varint()),
            else => return error.ProtobufInvalid,
        }
        return f;
    }
};

pub const Writer = struct {
    gpa: Allocator,
    list: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) Writer {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Writer) void {
        self.list.deinit(self.gpa);
    }

    pub fn varint(self: *Writer, value: u64) !void {
        var v = value;
        while (v >= 0x80) : (v >>= 7) try self.list.append(self.gpa, @as(u8, @intCast(v & 0x7f)) | 0x80);
        try self.list.append(self.gpa, @intCast(v));
    }

    pub fn tag(self: *Writer, num: u32, wire: Wire) !void {
        try self.varint(@as(u64, num) << 3 | @intFromEnum(wire));
    }

    /// Proto3 scalar: zero values are omitted.
    pub fn uint(self: *Writer, num: u32, v: u64) !void {
        if (v == 0) return;
        try self.tag(num, .varint);
        try self.varint(v);
    }

    pub fn boolean(self: *Writer, num: u32, v: bool) !void {
        try self.uint(num, @intFromBool(v));
    }

    pub fn string(self: *Writer, num: u32, s: []const u8) !void {
        if (s.len == 0) return;
        try self.bytes(num, s);
    }

    /// Length-delimited field that is always emitted (sub-messages, repeated entries).
    pub fn bytes(self: *Writer, num: u32, s: []const u8) !void {
        try self.tag(num, .len);
        try self.varint(s.len);
        try self.list.appendSlice(self.gpa, s);
    }

    pub fn mapEntry(self: *Writer, num: u32, key: []const u8, value: []const u8) !void {
        var sub = Writer.init(self.gpa);
        defer sub.deinit();
        try sub.string(1, key);
        try sub.string(2, value);
        try self.bytes(num, sub.list.items);
    }
};

test "varint and fields round trip" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.uint(1, 300);
    try w.string(2, "hello");
    try w.uint(3, 0); // omitted
    try w.uint(4, std.math.maxInt(u64));
    try w.mapEntry(5, "k", "v");
    var r = Reader.init(w.list.items);
    const a = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 300), a.int);
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0xac, 0x02 }, w.list.items[0..3]);
    const b = (try r.next()).?;
    try std.testing.expectEqualStrings("hello", b.bytes);
    const c = (try r.next()).?;
    try std.testing.expectEqual(@as(u32, 4), c.num);
    try std.testing.expectEqual(std.math.maxInt(u64), c.int);
    const d = (try r.next()).?;
    try std.testing.expectEqual(@as(u32, 5), d.num);
    try std.testing.expect((try r.next()) == null);
    var bad = Reader.init(&.{ 0x0a, 0x05, 0x01 });
    try std.testing.expectError(error.ProtobufInvalid, bad.next());
}
