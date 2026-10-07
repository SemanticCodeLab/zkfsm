//! Minimal namespace-aware XML reader for WebDAV request bodies, plus escaping.
//! No DTDs, no custom entities: `<!DOCTYPE`/`<!ENTITY` are rejected outright.
const std = @import("std");

pub const dav_ns = "DAV:";
pub const max_input = 64 * 1024;
pub const max_nodes = 1024;
pub const max_depth = 32;
const max_bindings = 64;
const max_attrs = 32;
const max_name = 256;

pub const Error = error{ Malformed, Unsupported, TooLarge, OutOfMemory };

pub const Node = struct {
    ns: []const u8,
    name: []const u8,
    parent: ?u16,
    /// Raw content between the start and end tag.
    inner: []const u8,
};

const Binding = struct { prefix: []const u8, uri: []const u8, depth: u8 };

pub const Doc = struct {
    nodes: []Node,

    pub fn root(d: Doc) ?u16 {
        return if (d.nodes.len == 0) null else 0;
    }

    pub fn is(d: Doc, i: u16, ns: []const u8, name: []const u8) bool {
        return std.mem.eql(u8, d.nodes[i].ns, ns) and std.mem.eql(u8, d.nodes[i].name, name);
    }

    /// First child of `parent` with the given DAV: name.
    pub fn child(d: Doc, parent: u16, name: []const u8) ?u16 {
        var it = d.children(parent);
        while (it.next()) |c| if (d.is(c, dav_ns, name)) return c;
        return null;
    }

    pub fn children(d: Doc, parent: u16) ChildIter {
        return .{ .doc = d, .parent = parent, .i = parent + 1 };
    }
};

pub const ChildIter = struct {
    doc: Doc,
    parent: u16,
    i: usize,

    pub fn next(it: *ChildIter) ?u16 {
        while (it.i < it.doc.nodes.len) {
            const i: u16 = @intCast(it.i);
            it.i += 1;
            if (it.doc.nodes[i].parent == it.parent) return i;
        }
        return null;
    }
};

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

fn isNameEnd(c: u8) bool {
    return isSpace(c) or c == '/' or c == '>' or c == '=';
}

/// Parses `src` into a flat node list (document order) allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, src_in: []const u8) Error!Doc {
    if (src_in.len > max_input) return error.TooLarge;
    var src = src_in;
    if (std.mem.startsWith(u8, src, "\xEF\xBB\xBF")) src = src[3..];
    var nodes: std.ArrayList(Node) = .empty;
    var stack: [max_depth]u16 = undefined;
    var inner_start: [max_depth]usize = undefined;
    var qnames: [max_depth][]const u8 = undefined;
    var sp: usize = 0;
    var binds: [max_bindings]Binding = undefined;
    var nb: usize = 0;
    var pos: usize = 0;
    var done = false;
    while (pos < src.len) {
        const lt = std.mem.indexOfScalarPos(u8, src, pos, '<') orelse src.len;
        if (sp == 0) for (src[pos..lt]) |c| if (!isSpace(c)) return error.Malformed;
        pos = lt;
        if (pos >= src.len) break;
        const rest = src[pos..];
        if (std.mem.startsWith(u8, rest, "<?")) {
            pos += (std.mem.indexOf(u8, rest, "?>") orelse return error.Malformed) + 2;
        } else if (std.mem.startsWith(u8, rest, "<!--")) {
            pos += (std.mem.indexOf(u8, rest, "-->") orelse return error.Malformed) + 3;
        } else if (std.mem.startsWith(u8, rest, "<![CDATA[")) {
            if (sp == 0) return error.Malformed;
            pos += (std.mem.indexOf(u8, rest, "]]>") orelse return error.Malformed) + 3;
        } else if (std.mem.startsWith(u8, rest, "<!")) {
            return error.Unsupported;
        } else if (std.mem.startsWith(u8, rest, "</")) {
            const gt = std.mem.indexOfScalar(u8, rest, '>') orelse return error.Malformed;
            const qname = std.mem.trim(u8, rest[2..gt], " \t\r\n");
            if (sp == 0) return error.Malformed;
            const top = stack[sp - 1];
            if (!std.mem.eql(u8, qname, qnames[sp - 1])) return error.Malformed;
            nodes.items[top].inner = src[inner_start[sp - 1]..pos];
            sp -= 1;
            while (nb > 0 and binds[nb - 1].depth > sp) nb -= 1;
            pos += gt + 1;
            if (sp == 0) done = true;
        } else {
            if (done) return error.Malformed;
            if (sp == max_depth) return error.TooLarge;
            var i: usize = 1;
            while (i < rest.len and !isNameEnd(rest[i])) i += 1;
            const qname = rest[1..i];
            if (qname.len == 0 or qname.len > max_name) return error.Malformed;
            var attrs: [max_attrs][2][]const u8 = undefined;
            var na: usize = 0;
            var self_close = false;
            while (true) {
                while (i < rest.len and isSpace(rest[i])) i += 1;
                if (i >= rest.len) return error.Malformed;
                if (rest[i] == '>') {
                    i += 1;
                    break;
                }
                if (rest[i] == '/') {
                    if (i + 1 >= rest.len or rest[i + 1] != '>') return error.Malformed;
                    self_close = true;
                    i += 2;
                    break;
                }
                const ns0 = i;
                while (i < rest.len and !isNameEnd(rest[i])) i += 1;
                const an = rest[ns0..i];
                while (i < rest.len and isSpace(rest[i])) i += 1;
                if (an.len == 0 or i >= rest.len or rest[i] != '=') return error.Malformed;
                i += 1;
                while (i < rest.len and isSpace(rest[i])) i += 1;
                if (i >= rest.len or (rest[i] != '"' and rest[i] != '\'')) return error.Malformed;
                const q = rest[i];
                const vend = std.mem.indexOfScalarPos(u8, rest, i + 1, q) orelse return error.Malformed;
                if (na == max_attrs) return error.TooLarge;
                attrs[na] = .{ an, rest[i + 1 .. vend] };
                na += 1;
                i = vend + 1;
            }
            const depth: u8 = @intCast(sp + 1);
            for (attrs[0..na]) |a| {
                const prefix = if (std.mem.eql(u8, a[0], "xmlns"))
                    ""
                else if (std.mem.startsWith(u8, a[0], "xmlns:"))
                    a[0][6..]
                else
                    continue;
                if (std.mem.indexOfScalar(u8, a[1], '&') != null) return error.Unsupported;
                if (nb == max_bindings) return error.TooLarge;
                binds[nb] = .{ .prefix = prefix, .uri = a[1], .depth = depth };
                nb += 1;
            }
            const colon = std.mem.indexOfScalar(u8, qname, ':');
            const prefix = if (colon) |c| qname[0..c] else "";
            const local = if (colon) |c| qname[c + 1 ..] else qname;
            if (local.len == 0) return error.Malformed;
            const ns = lookup(binds[0..nb], prefix) orelse
                if (prefix.len == 0) "" else return error.Malformed;
            if (nodes.items.len == max_nodes) return error.TooLarge;
            const parent: ?u16 = if (sp == 0) null else stack[sp - 1];
            try nodes.append(arena, .{ .ns = ns, .name = local, .parent = parent, .inner = "" });
            const idx: u16 = @intCast(nodes.items.len - 1);
            pos += i;
            if (self_close) {
                while (nb > 0 and binds[nb - 1].depth > sp) nb -= 1;
                if (sp == 0) done = true;
            } else {
                stack[sp] = idx;
                inner_start[sp] = pos;
                qnames[sp] = qname;
                sp += 1;
            }
        }
    }
    if (sp != 0 or nodes.items.len == 0) return error.Malformed;
    return .{ .nodes = nodes.items };
}

fn lookup(binds: []const Binding, prefix: []const u8) ?[]const u8 {
    var i = binds.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, binds[i].prefix, prefix)) return binds[i].uri;
    }
    return null;
}

/// Decoded character data of `raw` (tags dropped, CDATA kept), at most `max` bytes.
pub fn text(arena: std.mem.Allocator, raw: []const u8, max: usize) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        if (out.items.len > max) return error.TooLarge;
        const c = raw[i];
        if (std.mem.startsWith(u8, raw[i..], "<![CDATA[")) {
            const end = std.mem.indexOfPos(u8, raw, i, "]]>") orelse return error.Malformed;
            try out.appendSlice(arena, raw[i + 9 .. end]);
            i = end + 3;
        } else if (c == '<') {
            i = (std.mem.indexOfScalarPos(u8, raw, i, '>') orelse return error.Malformed) + 1;
        } else if (c == '&') {
            const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse return error.Malformed;
            if (semi - i > 10) return error.Malformed;
            try decodeRef(arena, &out, raw[i + 1 .. semi]);
            i = semi + 1;
        } else {
            try out.append(arena, c);
            i += 1;
        }
    }
    if (out.items.len > max) return error.TooLarge;
    return out.items;
}

fn decodeRef(arena: std.mem.Allocator, out: *std.ArrayList(u8), ref: []const u8) Error!void {
    const named = [_][2][]const u8{ .{ "lt", "<" }, .{ "gt", ">" }, .{ "amp", "&" }, .{ "quot", "\"" }, .{ "apos", "'" } };
    for (named) |n| if (std.mem.eql(u8, ref, n[0])) return out.appendSlice(arena, n[1]);
    if (ref.len < 2 or ref[0] != '#') return error.Unsupported;
    const cp = if (ref[1] == 'x')
        std.fmt.parseInt(u21, ref[2..], 16) catch return error.Malformed
    else
        std.fmt.parseInt(u21, ref[1..], 10) catch return error.Malformed;
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch return error.Malformed;
    try out.appendSlice(arena, buf[0..n]);
}

/// Writes `s` with the five XML special characters escaped; control bytes dropped.
pub fn escape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const rep: ?[]const u8 = switch (c) {
            '<' => "&lt;",
            '>' => "&gt;",
            '&' => "&amp;",
            '"' => "&quot;",
            '\'' => "&apos;",
            0...8, 11, 12, 14...31 => "",
            else => null,
        };
        if (rep) |r| {
            try w.writeAll(s[start..i]);
            try w.writeAll(r);
            start = i + 1;
        }
    }
    try w.writeAll(s[start..]);
}

test "parse propfind with namespaces" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try parse(a,
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<D:propfind xmlns:D="DAV:"><D:prop xmlns:x="urn:x">
        \\  <D:getetag/><x:color/><plain/>
        \\</D:prop></D:propfind>
    );
    const r = d.root().?;
    try std.testing.expect(d.is(r, dav_ns, "propfind"));
    const p = d.child(r, "prop").?;
    var it = d.children(p);
    try std.testing.expect(d.is(it.next().?, dav_ns, "getetag"));
    try std.testing.expect(d.is(it.next().?, "urn:x", "color"));
    try std.testing.expect(d.is(it.next().?, "", "plain"));
    try std.testing.expect(it.next() == null);
}

test "default namespace and text" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try parse(a, "<lockinfo xmlns='DAV:'><owner><href>a&amp;b&#x41;<![CDATA[<c>]]></href></owner></lockinfo>");
    const o = d.child(0, "owner").?;
    try std.testing.expectEqualStrings("a&bA<c>", try text(a, d.nodes[o].inner, 100));
}

test "rejects doctype, entities, bad nesting, unbound prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.Unsupported, parse(a, "<!DOCTYPE x [<!ENTITY e \"boom\">]><x>&e;</x>"));
    try std.testing.expectError(error.Malformed, parse(a, "<a><b></a></b>"));
    try std.testing.expectError(error.Malformed, parse(a, "<p:a/>"));
    try std.testing.expectError(error.Malformed, parse(a, "<a>"));
    try std.testing.expectError(error.Malformed, parse(a, "<a/><b/>"));
    try std.testing.expectError(error.Malformed, parse(a, "junk<a/>"));
    try std.testing.expectError(error.Unsupported, text(a, "&e;", 10));
    var deep: [2 * (max_depth + 1) * 3]u8 = undefined;
    var w: std.Io.Writer = .fixed(&deep);
    for (0..max_depth + 1) |_| try w.writeAll("<a>");
    try std.testing.expectError(error.TooLarge, parse(a, w.buffered()));
}

test "escape" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try escape(&w, "a<b>&\"'\x01c");
    try std.testing.expectEqualStrings("a&lt;b&gt;&amp;&quot;&apos;c", w.buffered());
}
