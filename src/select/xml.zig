//! Minimal non-validating XML reader for S3 request bodies. Builds a small
//! element tree; bounded depth and node count. No DTDs or external entities.
const std = @import("std");

pub const Error = error{ OutOfMemory, InvalidXml, XmlTooDeep, XmlTooLarge };

pub const Node = struct {
    /// Local name (namespace prefix stripped).
    name: []const u8,
    text: []const u8,
    children: []const Node,

    pub fn child(n: Node, name: []const u8) ?Node {
        for (n.children) |c| {
            if (std.mem.eql(u8, c.name, name)) return c;
        }
        return null;
    }

    pub fn childText(n: Node, name: []const u8) ?[]const u8 {
        const c = n.child(name) orelse return null;
        return c.text;
    }
};

pub const Limits = struct { max_depth: usize = 16, max_nodes: usize = 256, max_bytes: usize = 256 * 1024 };

const Parser = struct {
    arena: std.mem.Allocator,
    s: []const u8,
    i: usize = 0,
    nodes: usize = 0,
    limits: Limits,

    fn startsWith(p: *Parser, lit: []const u8) bool {
        return std.mem.startsWith(u8, p.s[p.i..], lit);
    }

    fn skipUntil(p: *Parser, lit: []const u8) Error!void {
        const idx = std.mem.indexOfPos(u8, p.s, p.i, lit) orelse return error.InvalidXml;
        p.i = idx + lit.len;
    }

    fn skipWs(p: *Parser) void {
        while (p.i < p.s.len and std.ascii.isWhitespace(p.s[p.i])) p.i += 1;
    }

    /// Skips prolog, comments, processing instructions and whitespace.
    fn skipMisc(p: *Parser) Error!void {
        while (true) {
            p.skipWs();
            if (p.startsWith("<?")) {
                try p.skipUntil("?>");
            } else if (p.startsWith("<!--")) {
                try p.skipUntil("-->");
            } else if (p.startsWith("<!DOCTYPE") or p.startsWith("<!doctype")) {
                return error.InvalidXml;
            } else return;
        }
    }

    fn name(p: *Parser) Error![]const u8 {
        const start = p.i;
        while (p.i < p.s.len) : (p.i += 1) {
            const c = p.s[p.i];
            if (std.ascii.isWhitespace(c) or c == '>' or c == '/' or c == '=') break;
        }
        if (p.i == start) return error.InvalidXml;
        const full = p.s[start..p.i];
        if (std.mem.lastIndexOfScalar(u8, full, ':')) |colon| return full[colon + 1 ..];
        return full;
    }

    fn element(p: *Parser, depth: usize) Error!Node {
        if (depth > p.limits.max_depth) return error.XmlTooDeep;
        p.nodes += 1;
        if (p.nodes > p.limits.max_nodes) return error.XmlTooLarge;
        if (p.i >= p.s.len or p.s[p.i] != '<') return error.InvalidXml;
        p.i += 1;
        const raw_start = p.i;
        const nm = try p.name();
        const raw_name = p.s[raw_start..p.i];
        // Attributes are ignored (only xmlns appears in S3 bodies).
        while (true) {
            p.skipWs();
            if (p.i >= p.s.len) return error.InvalidXml;
            const c = p.s[p.i];
            if (c == '/') {
                if (p.i + 1 >= p.s.len or p.s[p.i + 1] != '>') return error.InvalidXml;
                p.i += 2;
                return .{ .name = nm, .text = "", .children = &.{} };
            }
            if (c == '>') {
                p.i += 1;
                break;
            }
            _ = try p.name();
            p.skipWs();
            if (p.i >= p.s.len or p.s[p.i] != '=') return error.InvalidXml;
            p.i += 1;
            p.skipWs();
            if (p.i >= p.s.len) return error.InvalidXml;
            const q = p.s[p.i];
            if (q != '"' and q != '\'') return error.InvalidXml;
            p.i += 1;
            const end = std.mem.indexOfScalarPos(u8, p.s, p.i, q) orelse return error.InvalidXml;
            p.i = end + 1;
        }
        var children: std.ArrayList(Node) = .empty;
        var text: std.ArrayList(u8) = .empty;
        while (true) {
            if (p.i >= p.s.len) return error.InvalidXml;
            if (p.startsWith("</")) {
                p.i += 2;
                const close_start = p.i;
                _ = try p.name();
                if (!std.mem.eql(u8, p.s[close_start..p.i], raw_name)) return error.InvalidXml;
                p.skipWs();
                if (p.i >= p.s.len or p.s[p.i] != '>') return error.InvalidXml;
                p.i += 1;
                break;
            } else if (p.startsWith("<!--")) {
                try p.skipUntil("-->");
            } else if (p.startsWith("<![CDATA[")) {
                p.i += 9;
                const end = std.mem.indexOfPos(u8, p.s, p.i, "]]>") orelse return error.InvalidXml;
                try text.appendSlice(p.arena, p.s[p.i..end]);
                p.i = end + 3;
            } else if (p.startsWith("<?")) {
                try p.skipUntil("?>");
            } else if (p.s[p.i] == '<') {
                try children.append(p.arena, try p.element(depth + 1));
            } else if (p.s[p.i] == '&') {
                try p.entity(&text);
            } else {
                try text.append(p.arena, p.s[p.i]);
                p.i += 1;
            }
        }
        return .{ .name = nm, .text = text.items, .children = children.items };
    }

    fn entity(p: *Parser, out: *std.ArrayList(u8)) Error!void {
        const end = std.mem.indexOfScalarPos(u8, p.s, p.i, ';') orelse return error.InvalidXml;
        if (end - p.i > 12) return error.InvalidXml;
        const ent = p.s[p.i + 1 .. end];
        p.i = end + 1;
        const simple: ?u8 = if (std.mem.eql(u8, ent, "amp")) '&' else if (std.mem.eql(u8, ent, "lt")) '<' else if (std.mem.eql(u8, ent, "gt")) '>' else if (std.mem.eql(u8, ent, "quot")) '"' else if (std.mem.eql(u8, ent, "apos")) '\'' else null;
        if (simple) |c| return out.append(p.arena, c);
        if (ent.len < 2 or ent[0] != '#') return error.InvalidXml;
        const cp = (if (ent[1] == 'x' or ent[1] == 'X')
            std.fmt.parseInt(u21, ent[2..], 16)
        else
            std.fmt.parseInt(u21, ent[1..], 10)) catch return error.InvalidXml;
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidXml;
        try out.appendSlice(p.arena, buf[0..n]);
    }
};

/// Parses a document; all returned memory lives in `arena`.
pub fn parse(arena: std.mem.Allocator, s: []const u8, limits: Limits) Error!Node {
    if (s.len > limits.max_bytes) return error.XmlTooLarge;
    var p: Parser = .{ .arena = arena, .s = s, .limits = limits };
    try p.skipMisc();
    const root = try p.element(0);
    try p.skipMisc();
    if (p.i != s.len) return error.InvalidXml;
    return root;
}

test "parse nested with entities and namespace" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const doc =
        \\<?xml version="1.0"?>
        \\<!-- c --><x:A xmlns:x="u"><B>1 &lt; 2 &amp; &#65;</B><C/><D><![CDATA[<raw>]]></D></x:A>
    ;
    const root = try parse(arena.allocator(), doc, .{});
    try std.testing.expectEqualStrings("A", root.name);
    try std.testing.expectEqualStrings("1 < 2 & A", root.childText("B").?);
    try std.testing.expectEqualStrings("", root.childText("C").?);
    try std.testing.expectEqualStrings("<raw>", root.childText("D").?);
}

test "hostile xml" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.InvalidXml, parse(a, "<A><B></A>", .{}));
    try std.testing.expectError(error.InvalidXml, parse(a, "<!DOCTYPE x><A/>", .{}));
    try std.testing.expectError(error.InvalidXml, parse(a, "<A>&bogus;</A>", .{}));
    try std.testing.expectError(error.InvalidXml, parse(a, "<A", .{}));
    var deep: [400]u8 = undefined;
    for (0..100) |i| @memcpy(deep[i * 3 ..][0..3], "<a>");
    try std.testing.expectError(error.XmlTooDeep, parse(a, deep[0..300], .{}));
}
