//! Dynamic values flowing through the S3 Select evaluator.
const std = @import("std");
const datetime = @import("datetime.zig");
pub const Timestamp = datetime.Timestamp;

pub const Value = union(enum) {
    null,
    missing,
    bool: bool,
    int: i64,
    float: f64,
    string: []const u8,
    timestamp: Timestamp,
    list: []const Value,
    object: Object,

    pub fn isAbsent(v: Value) bool {
        return v == .null or v == .missing;
    }
};

pub const Object = struct {
    keys: []const []const u8,
    values: []const Value,
    /// CSV rows also answer `_N` positional lookups.
    positional: bool = false,

    pub fn get(o: Object, name: []const u8, case_sensitive: bool) ?Value {
        for (o.keys, 0..) |k, i| {
            if (std.mem.eql(u8, k, name)) return o.values[i];
        }
        if (!case_sensitive) {
            for (o.keys, 0..) |k, i| {
                if (std.ascii.eqlIgnoreCase(k, name)) return o.values[i];
            }
        }
        if (o.positional and name.len > 1 and name[0] == '_') {
            const n = std.fmt.parseInt(usize, name[1..], 10) catch return null;
            if (n >= 1 and n <= o.values.len) return o.values[n - 1];
        }
        return null;
    }
};

pub const Number = union(enum) { int: i64, float: f64 };

/// Numeric view of a value; strings are parsed leniently (CSV cells are text).
pub fn toNumber(v: Value) ?Number {
    return switch (v) {
        .int => |i| .{ .int = i },
        .float => |f| .{ .float = f },
        .string => |s| parseNumber(s),
        else => null,
    };
}

pub fn parseNumber(s_in: []const u8) ?Number {
    const s = std.mem.trim(u8, s_in, " \t");
    if (s.len == 0 or s.len > 64) return null;
    if (std.fmt.parseInt(i64, s, 10)) |i| return .{ .int = i } else |_| {}
    for (s) |c| {
        if (!(std.ascii.isDigit(c) or c == '.' or c == 'e' or c == 'E' or c == '-' or c == '+')) return null;
    }
    const f = std.fmt.parseFloat(f64, s) catch return null;
    return .{ .float = f };
}

pub fn numToFloat(n: Number) f64 {
    return switch (n) {
        .int => |i| @floatFromInt(i),
        .float => |f| f,
    };
}

fn orderNum(a: Number, b: Number) ?std.math.Order {
    if (a == .int and b == .int) return std.math.order(a.int, b.int);
    const x = numToFloat(a);
    const y = numToFloat(b);
    if (std.math.isNan(x) or std.math.isNan(y)) return null;
    return std.math.order(x, y);
}

/// SQL comparison; null means unknown (either side absent or incomparable).
pub fn compare(a: Value, b: Value) ?std.math.Order {
    if (a.isAbsent() or b.isAbsent()) return null;
    switch (a) {
        .string => |sa| switch (b) {
            .string => |sb| return std.mem.order(u8, sa, sb),
            .int, .float => return orderNum(parseNumber(sa) orelse return null, toNumber(b).?),
            .timestamp => |tb| {
                const ta = datetime.parse(sa) catch return null;
                return std.math.order(ta.micros, tb.micros);
            },
            .bool => |bb| {
                const ba = parseBool(sa) orelse return null;
                return std.math.order(@intFromBool(ba), @intFromBool(bb));
            },
            else => return null,
        },
        .int, .float => return orderNum(toNumber(a).?, toNumber(b) orelse return null),
        .bool => |ba| switch (b) {
            .bool => |bb| return std.math.order(@intFromBool(ba), @intFromBool(bb)),
            .string => return if (compare(b, a)) |o| o.invert() else null,
            else => return null,
        },
        .timestamp => |ta| switch (b) {
            .timestamp => |tb| return std.math.order(ta.micros, tb.micros),
            .string => return if (compare(b, a)) |o| o.invert() else null,
            else => return null,
        },
        else => return null,
    }
}

pub fn parseBool(s: []const u8) ?bool {
    const t = std.mem.trim(u8, s, " \t");
    if (std.ascii.eqlIgnoreCase(t, "true")) return true;
    if (std.ascii.eqlIgnoreCase(t, "false")) return false;
    return null;
}

pub fn formatFloat(f: f64, w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (std.math.isNan(f)) return w.writeAll("nan");
    if (std.math.isInf(f)) return w.writeAll(if (f > 0) "+inf" else "-inf");
    try w.print("{d}", .{f});
}

/// Plain text rendering used for CSV cells and CAST(... AS STRING).
pub fn writeText(v: Value, w: *std.Io.Writer) std.Io.Writer.Error!void {
    switch (v) {
        .null, .missing => {},
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |f| try formatFloat(f, w),
        .string => |s| try w.writeAll(s),
        .timestamp => |t| try datetime.format(t, w),
        .list, .object => try writeJson(v, w, 0),
    }
}

const max_json_depth = 64;

pub fn writeJson(v: Value, w: *std.Io.Writer, depth: usize) std.Io.Writer.Error!void {
    if (depth > max_json_depth) return w.writeAll("null");
    switch (v) {
        .null, .missing => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .int => |i| try w.print("{d}", .{i}),
        .float => |f| {
            if (std.math.isNan(f) or std.math.isInf(f)) return w.writeAll("null");
            try w.print("{d}", .{f});
        },
        .string => |s| try writeJsonString(s, w),
        .timestamp => |t| {
            try w.writeByte('"');
            try datetime.format(t, w);
            try w.writeByte('"');
        },
        .list => |l| {
            try w.writeByte('[');
            for (l, 0..) |item, i| {
                if (i > 0) try w.writeByte(',');
                try writeJson(item, w, depth + 1);
            }
            try w.writeByte(']');
        },
        .object => |o| {
            try w.writeByte('{');
            var first = true;
            for (o.keys, o.values) |k, val| {
                if (val == .missing) continue;
                if (!first) try w.writeByte(',');
                first = false;
                try writeJsonString(k, w);
                try w.writeByte(':');
                try writeJson(val, w, depth + 1);
            }
            try w.writeByte('}');
        },
    }
}

pub fn writeJsonString(s: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeByte('"');
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const esc: ?[]const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            else => null,
        };
        if (esc != null or c < 0x20) {
            try w.writeAll(s[start..i]);
            if (esc) |e| try w.writeAll(e) else try w.print("\\u{x:0>4}", .{c});
            start = i + 1;
        }
    }
    try w.writeAll(s[start..]);
    try w.writeByte('"');
}

test "compare coercions" {
    try std.testing.expectEqual(std.math.Order.gt, compare(.{ .string = "10" }, .{ .int = 9 }).?);
    try std.testing.expectEqual(std.math.Order.lt, compare(.{ .int = 1 }, .{ .float = 1.5 }).?);
    try std.testing.expectEqual(std.math.Order.lt, compare(.{ .string = "abc" }, .{ .string = "abd" }).?);
    try std.testing.expect(compare(.null, .{ .int = 1 }) == null);
    try std.testing.expect(compare(.{ .string = "x" }, .{ .int = 1 }) == null);
}

test "object lookup" {
    const o: Object = .{ .keys = &.{ "Name", "age" }, .values = &.{ .{ .string = "a" }, .{ .int = 3 } }, .positional = true };
    try std.testing.expectEqualStrings("a", o.get("name", false).?.string);
    try std.testing.expect(o.get("name", true) == null);
    try std.testing.expectEqual(@as(i64, 3), o.get("_2", true).?.int);
    try std.testing.expect(o.get("_3", true) == null);
}

test "json writer escapes" {
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const o: Object = .{ .keys = &.{"k"}, .values = &.{.{ .string = "a\"b\n\x01" }} };
    try writeJson(.{ .object = o }, &w, 0);
    try std.testing.expectEqualStrings("{\"k\":\"a\\\"b\\n\\u0001\"}", w.buffered());
}
