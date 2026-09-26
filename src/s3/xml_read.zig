//! Minimal XML reading for S3 request bodies (CompleteMultipartUpload, Delete).
//! Finds child elements by name in document order; no DTDs, no same-name nesting.
const std = @import("std");

pub const Error = error{ MalformedXML, OutOfMemory };

pub const Scanner = struct {
    s: []const u8,
    pos: usize = 0,

    /// Raw inner text of the next `<name>` element at or after the cursor, or null.
    pub fn next(self: *Scanner, name: []const u8) Error!?[]const u8 {
        while (std.mem.indexOfScalarPos(u8, self.s, self.pos, '<')) |lt| {
            const rest = self.s[lt + 1 ..];
            self.pos = lt + 1;
            if (!std.mem.startsWith(u8, rest, name) or rest.len == name.len) continue;
            const after = rest[name.len];
            if (after != '>' and after != '/' and !std.ascii.isWhitespace(after)) continue;
            const gt = std.mem.indexOfScalarPos(u8, self.s, lt, '>') orelse return error.MalformedXML;
            if (self.s[gt - 1] == '/') {
                self.pos = gt + 1;
                return "";
            }
            var close_buf: [64]u8 = undefined;
            const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return error.MalformedXML;
            const end = std.mem.indexOfPos(u8, self.s, gt + 1, close) orelse return error.MalformedXML;
            self.pos = end + close.len;
            return self.s[gt + 1 .. end];
        }
        self.pos = self.s.len;
        return null;
    }
};

/// Decodes the five predefined entities and numeric character references.
pub fn unescape(arena: std.mem.Allocator, s: []const u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '&') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] != '&') {
            try out.append(arena, s[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, s, i, ';') orelse return error.MalformedXML;
        const ent = s[i + 1 .. semi];
        i = semi + 1;
        const named = [_]struct { []const u8, u8 }{ .{ "amp", '&' }, .{ "lt", '<' }, .{ "gt", '>' }, .{ "quot", '"' }, .{ "apos", '\'' } };
        const ch: ?u8 = for (named) |n| {
            if (std.mem.eql(u8, ent, n[0])) break n[1];
        } else null;
        if (ch) |c| {
            try out.append(arena, c);
            continue;
        }
        if (ent.len < 2 or ent[0] != '#') return error.MalformedXML;
        const cp = (if (ent[1] == 'x' or ent[1] == 'X')
            std.fmt.parseInt(u21, ent[2..], 16)
        else
            std.fmt.parseInt(u21, ent[1..], 10)) catch return error.MalformedXML;
        var enc: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &enc) catch return error.MalformedXML;
        try out.appendSlice(arena, enc[0..n]);
    }
    return out.items;
}

test "scanner finds elements in order" {
    const doc =
        \\<?xml version="1.0"?><CompleteMultipartUpload xmlns="x">
        \\<Part><PartNumber>1</PartNumber><ETag>"a"</ETag></Part>
        \\<Part ><PartNumber>2</PartNumber><ETag>b</ETag></Part><Parts/></CompleteMultipartUpload>
    ;
    var sc: Scanner = .{ .s = doc };
    const p1 = (try sc.next("Part")).?;
    var in1: Scanner = .{ .s = p1 };
    try std.testing.expectEqualStrings("1", (try in1.next("PartNumber")).?);
    try std.testing.expectEqualStrings("\"a\"", (try in1.next("ETag")).?);
    const p2 = (try sc.next("Part")).?;
    try std.testing.expect(std.mem.indexOf(u8, p2, "<PartNumber>2</PartNumber>") != null);
    try std.testing.expect((try sc.next("Part")) == null);

    var bad: Scanner = .{ .s = "<Key>unterminated" };
    try std.testing.expectError(error.MalformedXML, bad.next("Key"));
}

test "unescape entities" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("a&b<c>\"'", try unescape(a, "a&amp;b&lt;c&gt;&quot;&apos;"));
    try std.testing.expectEqualStrings("A\xc3\xa9", try unescape(a, "&#65;&#xE9;"));
    try std.testing.expectEqualStrings("plain", try unescape(a, "plain"));
    try std.testing.expectError(error.MalformedXML, unescape(a, "&bogus;"));
    try std.testing.expectError(error.MalformedXML, unescape(a, "&amp"));
}
