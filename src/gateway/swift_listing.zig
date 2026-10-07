//! Swift account and container listings in plain, JSON, and XML.
const std = @import("std");
const util = @import("swift_util.zig");

const W = std.Io.Writer;

pub const max_limit = 10_000;

pub const Format = enum {
    plain,
    json,
    xml,

    pub fn contentType(f: Format) []const u8 {
        return switch (f) {
            .plain => "text/plain; charset=utf-8",
            .json => "application/json; charset=utf-8",
            .xml => "application/xml; charset=utf-8",
        };
    }
};

/// format= wins over Accept; plain by default.
pub fn pickFormat(format_q: ?[]const u8, accept: ?[]const u8) Format {
    if (format_q) |f| {
        if (std.ascii.eqlIgnoreCase(f, "json")) return .json;
        if (std.ascii.eqlIgnoreCase(f, "xml")) return .xml;
        return .plain;
    }
    const a = accept orelse return .plain;
    if (std.mem.indexOf(u8, a, "application/json") != null) return .json;
    if (std.mem.indexOf(u8, a, "application/xml") != null or std.mem.indexOf(u8, a, "text/xml") != null) return .xml;
    return .plain;
}

pub const ObjectRow = struct {
    name: []const u8,
    hash: []const u8,
    bytes: u64,
    content_type: []const u8,
    mtime_ns: i128,
};

pub const Row = union(enum) { object: ObjectRow, subdir: []const u8 };

pub const ContainerRow = struct { name: []const u8, count: u64 = 0, bytes: u64 = 0, mtime_ns: i128 = 0, subdir: bool = false };

pub fn renderContainer(w: *W, f: Format, container: []const u8, rows: []const Row) W.Error!void {
    switch (f) {
        .plain => for (rows) |r| switch (r) {
            .object => |o| try w.print("{s}\n", .{o.name}),
            .subdir => |s| try w.print("{s}\n", .{s}),
        },
        .json => {
            try w.writeByte('[');
            for (rows, 0..) |r, i| {
                if (i > 0) try w.writeByte(',');
                switch (r) {
                    .object => |o| {
                        var lb: [26]u8 = undefined;
                        try w.writeAll("{\"name\":");
                        try util.jsonString(w, o.name);
                        try w.writeAll(",\"hash\":");
                        try util.jsonString(w, o.hash);
                        try w.print(",\"bytes\":{d},\"content_type\":", .{o.bytes});
                        try util.jsonString(w, o.content_type);
                        try w.print(",\"last_modified\":\"{s}\"}}", .{util.isoListing(&lb, o.mtime_ns)});
                    },
                    .subdir => |s| {
                        try w.writeAll("{\"subdir\":");
                        try util.jsonString(w, s);
                        try w.writeByte('}');
                    },
                }
            }
            try w.writeByte(']');
        },
        .xml => {
            try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<container name=\"");
            try util.xmlEscape(w, container);
            try w.writeAll("\">");
            for (rows) |r| switch (r) {
                .object => |o| {
                    var lb: [26]u8 = undefined;
                    try w.writeAll("<object><name>");
                    try util.xmlEscape(w, o.name);
                    try w.print("</name><hash>{s}</hash><bytes>{d}</bytes><content_type>", .{ o.hash, o.bytes });
                    try util.xmlEscape(w, o.content_type);
                    try w.print("</content_type><last_modified>{s}</last_modified></object>", .{util.isoListing(&lb, o.mtime_ns)});
                },
                .subdir => |s| {
                    try w.writeAll("<subdir name=\"");
                    try util.xmlEscape(w, s);
                    try w.writeAll("\"><name>");
                    try util.xmlEscape(w, s);
                    try w.writeAll("</name></subdir>");
                },
            };
            try w.writeAll("</container>");
        },
    }
}

pub fn renderAccount(w: *W, f: Format, account: []const u8, rows: []const ContainerRow) W.Error!void {
    switch (f) {
        .plain => for (rows) |r| try w.print("{s}\n", .{r.name}),
        .json => {
            try w.writeByte('[');
            for (rows, 0..) |r, i| {
                var lb: [26]u8 = undefined;
                if (i > 0) try w.writeByte(',');
                if (r.subdir) {
                    try w.writeAll("{\"subdir\":");
                    try util.jsonString(w, r.name);
                    try w.writeByte('}');
                    continue;
                }
                try w.writeAll("{\"name\":");
                try util.jsonString(w, r.name);
                try w.print(",\"count\":{d},\"bytes\":{d},\"last_modified\":\"{s}\"}}", .{ r.count, r.bytes, util.isoListing(&lb, r.mtime_ns) });
            }
            try w.writeByte(']');
        },
        .xml => {
            try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<account name=\"");
            try util.xmlEscape(w, account);
            try w.writeAll("\">");
            for (rows) |r| {
                var lb: [26]u8 = undefined;
                if (r.subdir) {
                    try w.writeAll("<subdir name=\"");
                    try util.xmlEscape(w, r.name);
                    try w.writeAll("\"><name>");
                    try util.xmlEscape(w, r.name);
                    try w.writeAll("</name></subdir>");
                    continue;
                }
                try w.writeAll("<container><name>");
                try util.xmlEscape(w, r.name);
                try w.print("</name><count>{d}</count><bytes>{d}</bytes><last_modified>{s}</last_modified></container>", .{ r.count, r.bytes, util.isoListing(&lb, r.mtime_ns) });
            }
            try w.writeAll("</account>");
        },
    }
}

/// Parses limit=; null when absent, error when out of range.
pub fn parseLimit(s: ?[]const u8) error{BadLimit}!usize {
    const v = s orelse return max_limit;
    const n = std.fmt.parseInt(usize, v, 10) catch return error.BadLimit;
    if (n > max_limit) return error.BadLimit;
    return n;
}

test "format selection" {
    try std.testing.expectEqual(Format.json, pickFormat("json", "text/plain"));
    try std.testing.expectEqual(Format.xml, pickFormat(null, "application/xml"));
    try std.testing.expectEqual(Format.plain, pickFormat(null, null));
    try std.testing.expectEqual(Format.json, pickFormat(null, "application/json;q=1"));
}

test "container listing renders and escapes" {
    const rows = [_]Row{
        .{ .object = .{ .name = "a\"<&>.txt", .hash = "d41d8cd98f00b204e9800998ecf8427e", .bytes = 0, .content_type = "text/plain", .mtime_ns = 0 } },
        .{ .subdir = "dir/" },
    };
    var buf: [1024]u8 = undefined;
    var w: W = .fixed(&buf);
    try renderContainer(&w, .json, "c", &rows);
    try std.testing.expectEqualStrings(
        "[{\"name\":\"a\\\"<&>.txt\",\"hash\":\"d41d8cd98f00b204e9800998ecf8427e\",\"bytes\":0,\"content_type\":\"text/plain\",\"last_modified\":\"1970-01-01T00:00:00.000000\"},{\"subdir\":\"dir/\"}]",
        w.buffered(),
    );
    w = .fixed(&buf);
    try renderContainer(&w, .xml, "c&d", &rows);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<container name=\"c&amp;d\">") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<name>a&quot;&lt;&amp;&gt;.txt</name>") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<subdir name=\"dir/\"><name>dir/</name></subdir>") != null);
    w = .fixed(&buf);
    try renderContainer(&w, .plain, "c", &rows);
    try std.testing.expectEqualStrings("a\"<&>.txt\ndir/\n", w.buffered());
}

test "account listing" {
    const rows = [_]ContainerRow{.{ .name = "photos", .count = 2, .bytes = 10, .mtime_ns = 0 }};
    var buf: [512]u8 = undefined;
    var w: W = .fixed(&buf);
    try renderAccount(&w, .json, "AUTH_t", &rows);
    try std.testing.expectEqualStrings("[{\"name\":\"photos\",\"count\":2,\"bytes\":10,\"last_modified\":\"1970-01-01T00:00:00.000000\"}]", w.buffered());
    w = .fixed(&buf);
    try renderAccount(&w, .xml, "AUTH_t", &rows);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<container><name>photos</name><count>2</count><bytes>10</bytes>") != null);
    try std.testing.expectEqual(@as(usize, 10_000), try parseLimit(null));
    try std.testing.expectError(error.BadLimit, parseLimit("10001"));
    try std.testing.expectError(error.BadLimit, parseLimit("-1"));
}
