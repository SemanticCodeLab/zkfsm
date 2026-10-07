//! Row serialization per OutputSerialization (CSV or JSON).
const std = @import("std");
const request = @import("request.zig");
const value = @import("value.zig");
const Value = value.Value;
const W = std.Io.Writer;

pub fn writeRow(fmt: request.OutputFormat, w: *W, scratch: std.mem.Allocator, names: []const []const u8, vals: []const Value) W.Error!void {
    switch (fmt) {
        .csv => |c| {
            for (vals, 0..) |v, i| {
                if (i > 0) try w.writeAll(c.field_delimiter);
                try csvField(c, w, scratch, v);
            }
            try w.writeAll(c.record_delimiter);
        },
        .json => |delim| {
            try w.writeByte('{');
            var first = true;
            for (names, vals) |n, v| {
                if (v == .missing) continue;
                if (!first) try w.writeByte(',');
                first = false;
                try value.writeJsonString(n, w);
                try w.writeByte(':');
                try value.writeJson(v, w, 0);
            }
            try w.writeByte('}');
            try w.writeAll(delim);
        },
    }
}

fn csvField(c: request.CsvOutput, w: *W, scratch: std.mem.Allocator, v: Value) W.Error!void {
    var buf: [128]u8 = undefined;
    var tmp: W = .fixed(&buf);
    const text: []const u8 = switch (v) {
        .string => |s| s,
        .list, .object => {
            // Nested values are rendered as JSON text and always quoted.
            var aw: std.Io.Writer.Allocating = .init(scratch);
            defer aw.deinit();
            value.writeJson(v, &aw.writer, 0) catch return error.WriteFailed;
            return quoted(c, w, aw.written());
        },
        else => blk: {
            value.writeText(v, &tmp) catch return error.WriteFailed;
            break :blk tmp.buffered();
        },
    };
    const need = c.quote_fields == .always or
        std.mem.indexOf(u8, text, c.field_delimiter) != null or
        std.mem.indexOf(u8, text, c.record_delimiter) != null or
        std.mem.indexOfAny(u8, text, &.{ c.quote, c.quote_escape, '\n', '\r' }) != null;
    if (need) return quoted(c, w, text);
    try w.writeAll(text);
}

fn quoted(c: request.CsvOutput, w: *W, text: []const u8) W.Error!void {
    try w.writeByte(c.quote);
    var start: usize = 0;
    for (text, 0..) |ch, i| {
        if (ch == c.quote or (ch == c.quote_escape and c.quote_escape != c.quote)) {
            try w.writeAll(text[start..i]);
            try w.writeByte(c.quote_escape);
            try w.writeByte(ch);
            start = i + 1;
        }
    }
    try w.writeAll(text[start..]);
    try w.writeByte(c.quote);
}

test "csv output quoting" {
    var buf: [256]u8 = undefined;
    var w: W = .fixed(&buf);
    const vals = [_]Value{ .{ .string = "a,b" }, .{ .int = 3 }, .null, .{ .string = "say \"hi\"" }, .{ .float = 1.5 } };
    try writeRow(.{ .csv = .{} }, &w, std.testing.allocator, &.{ "x", "y", "z", "q", "f" }, &vals);
    try std.testing.expectEqualStrings("\"a,b\",3,,\"say \"\"hi\"\"\",1.5\n", w.buffered());
    w.end = 0;
    try writeRow(.{ .csv = .{ .quote_fields = .always, .field_delimiter = "\t" } }, &w, std.testing.allocator, &.{ "x", "y" }, vals[0..2]);
    try std.testing.expectEqualStrings("\"a,b\"\t\"3\"\n", w.buffered());
}

test "json output skips missing" {
    var buf: [256]u8 = undefined;
    var w: W = .fixed(&buf);
    try writeRow(.{ .json = "\n" }, &w, std.testing.allocator, &.{ "a", "b", "c" }, &.{ .{ .int = 1 }, .missing, .null });
    try std.testing.expectEqualStrings("{\"a\":1,\"c\":null}\n", w.buffered());
}
