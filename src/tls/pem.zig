//! PEM block iteration and base64 decoding (RFC 7468).
const std = @import("std");

pub const Error = error{ BadPem, OutOfMemory };

pub const Block = struct {
    label: []const u8,
    body: []const u8,
};

pub const Iterator = struct {
    text: []const u8,
    pos: usize = 0,

    pub fn next(it: *Iterator) Error!?Block {
        const begin = "-----BEGIN ";
        const start = std.mem.indexOfPos(u8, it.text, it.pos, begin) orelse return null;
        const label_start = start + begin.len;
        const label_end = std.mem.indexOfPos(u8, it.text, label_start, "-----") orelse return error.BadPem;
        const label = it.text[label_start..label_end];
        const body_start = label_end + 5;
        var end_buf: [96]u8 = undefined;
        const end_marker = std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{label}) catch return error.BadPem;
        const body_end = std.mem.indexOfPos(u8, it.text, body_start, end_marker) orelse return error.BadPem;
        it.pos = body_end + end_marker.len;
        return .{ .label = label, .body = it.text[body_start..body_end] };
    }
};

/// Decodes a block body; caller owns the result.
pub fn decode(gpa: std.mem.Allocator, body: []const u8) Error![]u8 {
    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const max = dec.calcSizeUpperBound(body.len) catch return error.BadPem;
    const out = try gpa.alloc(u8, max);
    defer {
        std.crypto.secureZero(u8, out);
        gpa.free(out);
    }
    const n = dec.decode(out, body) catch return error.BadPem;
    if (n == 0) return error.BadPem;
    return gpa.dupe(u8, out[0..n]);
}

test "pem iterate and decode" {
    const text = "junk\n-----BEGIN X-----\naGVs\nbG8=\n-----END X-----\n-----BEGIN Y-----\nAA==\n-----END Y-----\n";
    var it: Iterator = .{ .text = text };
    const a = (try it.next()).?;
    try std.testing.expectEqualStrings("X", a.label);
    const d = try decode(std.testing.allocator, a.body);
    defer std.testing.allocator.free(d);
    try std.testing.expectEqualStrings("hello", d);
    try std.testing.expectEqualStrings("Y", (try it.next()).?.label);
    try std.testing.expect((try it.next()) == null);
    var bad: Iterator = .{ .text = "-----BEGIN X-----\nAA==\n" };
    try std.testing.expectError(error.BadPem, bad.next());
}
