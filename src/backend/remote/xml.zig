//! Minimal XML helpers for provider responses: flat tag scanning, entity (un)escaping.
const std = @import("std");

/// Scans forward for `<tag>text</tag>`; attributes and nesting of the same tag are unsupported.
pub const Scanner = struct {
    doc: []const u8,
    pos: usize = 0,

    /// Raw (still escaped) inner text of the next `tag`, or null.
    pub fn next(s: *Scanner, tag: []const u8) ?[]const u8 {
        var open_buf: [64]u8 = undefined;
        var close_buf: [64]u8 = undefined;
        const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
        const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
        const a = std.mem.indexOfPos(u8, s.doc, s.pos, open) orelse return null;
        const start = a + open.len;
        const b = std.mem.indexOfPos(u8, s.doc, start, close) orelse return null;
        s.pos = b + close.len;
        return s.doc[start..b];
    }
};

/// First `tag` text anywhere in `doc`.
pub fn find(doc: []const u8, tag: []const u8) ?[]const u8 {
    var s: Scanner = .{ .doc = doc };
    return s.next(tag);
}

pub const UnescapeError = error{ NoSpaceLeft, InvalidEntity };

pub fn unescape(raw: []const u8, out: []u8) UnescapeError![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        if (n >= out.len) return error.NoSpaceLeft;
        if (raw[i] != '&') {
            out[n] = raw[i];
            n += 1;
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse return error.InvalidEntity;
        const ent = raw[i + 1 .. semi];
        const c: u8 = if (std.mem.eql(u8, ent, "amp")) '&' else if (std.mem.eql(u8, ent, "lt")) '<' else if (std.mem.eql(u8, ent, "gt")) '>' else if (std.mem.eql(u8, ent, "quot")) '"' else if (std.mem.eql(u8, ent, "apos")) '\'' else blk: {
            if (ent.len < 2 or ent[0] != '#') return error.InvalidEntity;
            const v = if (ent[1] == 'x' or ent[1] == 'X')
                std.fmt.parseInt(u8, ent[2..], 16)
            else
                std.fmt.parseInt(u8, ent[1..], 10);
            break :blk v catch return error.InvalidEntity;
        };
        out[n] = c;
        n += 1;
        i = semi + 1;
    }
    return out[0..n];
}

pub fn escape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&apos;"),
        else => try w.writeByte(c),
    };
}

test "scanner walks repeated tags" {
    const doc =
        \\<ListBucketResult><IsTruncated>true</IsTruncated>
        \\<Contents><Key>a&amp;b</Key></Contents><Contents><Key>c</Key></Contents>
        \\<NextContinuationToken>tok</NextContinuationToken></ListBucketResult>
    ;
    var s: Scanner = .{ .doc = doc };
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("a&b", try unescape(s.next("Key").?, &buf));
    try std.testing.expectEqualStrings("c", s.next("Key").?);
    try std.testing.expectEqual(@as(?[]const u8, null), s.next("Key"));
    try std.testing.expectEqualStrings("tok", find(doc, "NextContinuationToken").?);
    try std.testing.expectEqualStrings("A", try unescape("&#65;", &buf));
    try std.testing.expectError(error.InvalidEntity, unescape("&bogus;", &buf));
}
