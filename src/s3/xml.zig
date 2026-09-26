//! Minimal XML writer for S3 responses: escaping plus element helpers.
const std = @import("std");
const Writer = std.Io.Writer;

pub const declaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
pub const s3_ns = "http://s3.amazonaws.com/doc/2006-03-01/";

pub fn escape(w: *Writer, s: []const u8) Writer.Error!void {
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&apos;",
            else => continue,
        };
        try w.writeAll(s[start..i]);
        try w.writeAll(rep);
        start = i + 1;
    }
    try w.writeAll(s[start..]);
}

pub fn open(w: *Writer, name: []const u8) Writer.Error!void {
    try w.print("<{s}>", .{name});
}

pub fn close(w: *Writer, name: []const u8) Writer.Error!void {
    try w.print("</{s}>", .{name});
}

/// Root element with the S3 namespace.
pub fn openRoot(w: *Writer, name: []const u8) Writer.Error!void {
    try w.writeAll(declaration);
    try w.print("<{s} xmlns=\"{s}\">", .{ name, s3_ns });
}

pub fn elem(w: *Writer, name: []const u8, text: []const u8) Writer.Error!void {
    try open(w, name);
    try escape(w, text);
    try close(w, name);
}

pub fn elemInt(w: *Writer, name: []const u8, v: anytype) Writer.Error!void {
    try w.print("<{s}>{d}</{s}>", .{ name, v, name });
}

pub fn elemBool(w: *Writer, name: []const u8, v: bool) Writer.Error!void {
    try elem(w, name, if (v) "true" else "false");
}

test "xml escape and elements" {
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try elem(&w, "Key", "a<b>&\"c'");
    try elemInt(&w, "Size", @as(u64, 42));
    try elemBool(&w, "IsTruncated", false);
    try std.testing.expectEqualStrings(
        "<Key>a&lt;b&gt;&amp;&quot;c&apos;</Key><Size>42</Size><IsTruncated>false</IsTruncated>",
        w.buffered(),
    );
}

test "xml root has namespace" {
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try openRoot(&w, "R");
    try std.testing.expect(std.mem.endsWith(u8, w.buffered(), "<R xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"));
}
