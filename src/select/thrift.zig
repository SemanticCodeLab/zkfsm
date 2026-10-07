//! Thrift compact protocol decoder (read side only) over an in-memory slice.
const std = @import("std");

pub const Error = error{ InvalidThrift, ThriftTooDeep };

pub const Type = enum(u4) {
    stop = 0,
    bool_true = 1,
    bool_false = 2,
    byte = 3,
    i16 = 4,
    i32 = 5,
    i64 = 6,
    double = 7,
    binary = 8,
    list = 9,
    set = 10,
    map = 11,
    @"struct" = 12,
    uuid = 13,
    _,
};

pub const max_depth = 32;
pub const max_list_len = 1 << 24;

pub const FieldHeader = struct { id: i16, type: Type };
pub const ListHeader = struct { len: usize, elem: Type };

pub const Reader = struct {
    s: []const u8,
    i: usize = 0,
    depth: usize = 0,

    fn byte(r: *Reader) Error!u8 {
        if (r.i >= r.s.len) return error.InvalidThrift;
        const b = r.s[r.i];
        r.i += 1;
        return b;
    }

    pub fn varint(r: *Reader) Error!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            const b = try r.byte();
            if (shift >= 64) return error.InvalidThrift;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b & 0x80 == 0) return v;
            shift += 7;
        }
    }

    fn zigzag(u: u64) i64 {
        return @bitCast((u >> 1) ^ (0 -% (u & 1)));
    }

    pub fn readI64(r: *Reader) Error!i64 {
        return zigzag(try r.varint());
    }

    pub fn readI32(r: *Reader) Error!i32 {
        const v = try r.readI64();
        return std.math.cast(i32, v) orelse error.InvalidThrift;
    }

    pub fn readBinary(r: *Reader) Error![]const u8 {
        const n = try r.varint();
        if (n > r.s.len - r.i) return error.InvalidThrift;
        const out = r.s[r.i .. r.i + @as(usize, @intCast(n))];
        r.i += @intCast(n);
        return out;
    }

    /// Returns null at STOP. `last_id` tracks delta encoding per struct.
    pub fn fieldHeader(r: *Reader, last_id: *i16) Error!?FieldHeader {
        const b = try r.byte();
        if (b == 0) return null;
        const t: Type = @enumFromInt(@as(u4, @truncate(b)));
        const delta: u4 = @truncate(b >> 4);
        const id: i16 = if (delta == 0)
            std.math.cast(i16, try r.readI64()) orelse return error.InvalidThrift
        else
            std.math.add(i16, last_id.*, delta) catch return error.InvalidThrift;
        last_id.* = id;
        return .{ .id = id, .type = t };
    }

    pub fn listHeader(r: *Reader) Error!ListHeader {
        const b = try r.byte();
        var n: u64 = b >> 4;
        if (n == 15) n = try r.varint();
        if (n > max_list_len or n > r.s.len - r.i) return error.InvalidThrift;
        return .{ .len = @intCast(n), .elem = @enumFromInt(@as(u4, @truncate(b))) };
    }

    pub fn enter(r: *Reader) Error!void {
        r.depth += 1;
        if (r.depth > max_depth) return error.ThriftTooDeep;
    }

    pub fn leave(r: *Reader) void {
        r.depth -= 1;
    }

    /// Bool field values are encoded in the field type nibble.
    pub fn fieldBool(t: Type) Error!bool {
        return switch (t) {
            .bool_true => true,
            .bool_false => false,
            else => error.InvalidThrift,
        };
    }

    pub fn skip(r: *Reader, t: Type) Error!void {
        switch (t) {
            .bool_true, .bool_false => {},
            .byte => _ = try r.byte(),
            .i16, .i32, .i64 => _ = try r.varint(),
            .double => {
                if (r.s.len - r.i < 8) return error.InvalidThrift;
                r.i += 8;
            },
            .uuid => {
                if (r.s.len - r.i < 16) return error.InvalidThrift;
                r.i += 16;
            },
            .binary => _ = try r.readBinary(),
            .list, .set => {
                try r.enter();
                defer r.leave();
                const h = try r.listHeader();
                for (0..h.len) |_| {
                    // Bools inside collections take one byte each.
                    if (h.elem == .bool_true or h.elem == .bool_false) {
                        _ = try r.byte();
                    } else try r.skip(h.elem);
                }
            },
            .map => {
                try r.enter();
                defer r.leave();
                const n = try r.varint();
                if (n == 0) return;
                if (n > r.s.len - r.i) return error.InvalidThrift;
                const kv = try r.byte();
                const kt: Type = @enumFromInt(@as(u4, @truncate(kv >> 4)));
                const vt: Type = @enumFromInt(@as(u4, @truncate(kv)));
                for (0..@intCast(n)) |_| {
                    try r.skip(kt);
                    try r.skip(vt);
                }
            },
            .@"struct" => {
                try r.enter();
                defer r.leave();
                var last: i16 = 0;
                while (try r.fieldHeader(&last)) |h| try r.skip(h.type);
            },
            .stop, _ => return error.InvalidThrift,
        }
    }
};

test "varint zigzag and skip" {
    // struct { 1: i32 = -3, 2: binary "hi", 5: list<i32> [1,2], 6: bool true } STOP
    const bytes = [_]u8{ 0x15, 0x05, 0x18, 0x02, 'h', 'i', 0x39, 0x25, 0x02, 0x04, 0x11, 0x00 };
    var r: Reader = .{ .s = &bytes };
    var last: i16 = 0;
    const h1 = (try r.fieldHeader(&last)).?;
    try std.testing.expectEqual(@as(i16, 1), h1.id);
    try std.testing.expectEqual(@as(i32, -3), try r.readI32());
    const h2 = (try r.fieldHeader(&last)).?;
    try std.testing.expectEqualStrings("hi", try r.readBinary());
    try std.testing.expectEqual(@as(i16, 2), h2.id);
    const h3 = (try r.fieldHeader(&last)).?;
    try std.testing.expectEqual(@as(i16, 5), h3.id);
    try r.skip(h3.type);
    const h4 = (try r.fieldHeader(&last)).?;
    try std.testing.expect(try Reader.fieldBool(h4.type));
    try std.testing.expect(try r.fieldHeader(&last) == null);
    var r2: Reader = .{ .s = &bytes };
    try r2.skip(.@"struct");
    try std.testing.expectEqual(bytes.len, r2.i);
}

test "hostile thrift" {
    var r: Reader = .{ .s = &[_]u8{ 0x18, 0xff, 0xff, 0x03 } };
    try std.testing.expectError(error.InvalidThrift, r.skip(.@"struct"));
    const nested = [_]u8{0x1c} ** 100;
    var r2: Reader = .{ .s = &nested };
    try std.testing.expectError(error.ThriftTooDeep, r2.skip(.@"struct"));
    var r3: Reader = .{ .s = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 } };
    try std.testing.expectError(error.InvalidThrift, r3.varint());
}
