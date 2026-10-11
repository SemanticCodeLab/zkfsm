//! Minimal YAML subset for batch job specs: block mappings and sequences by
//! indentation, plain/single/double-quoted scalars, `#` comments, empty `[]`/`{}`
//! and flat flow sequences. Every size is bounded; anchors and block scalars are refused.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, InvalidYaml, TooLarge };

pub const max_input = 1024 * 1024;
pub const max_depth = 32;
pub const max_nodes = 16 * 1024;
pub const max_lines = 64 * 1024;

pub const Pair = struct { key: []const u8, value: Node };

pub const Node = union(enum) {
    null,
    scalar: []const u8,
    map: []const Pair,
    seq: []const Node,

    /// Value under `key` of a mapping, or null.
    pub fn get(n: Node, key: []const u8) ?Node {
        if (n != .map) return null;
        for (n.map) |p| if (std.mem.eql(u8, p.key, key)) return p.value;
        return null;
    }

    /// Scalar text, or null for anything else (null nodes included).
    pub fn str(n: Node) ?[]const u8 {
        return if (n == .scalar) n.scalar else null;
    }

    pub fn getStr(n: Node, key: []const u8) ?[]const u8 {
        const v = n.get(key) orelse return null;
        return v.str();
    }
};

const Line = struct { indent: usize, text: []const u8 };

const Parser = struct {
    a: Allocator,
    lines: []Line,
    i: usize = 0,
    nodes: usize = 0,
    depth: usize = 0,

    fn count(p: *Parser) Error!void {
        p.nodes += 1;
        if (p.nodes > max_nodes) return error.TooLarge;
    }

    fn enter(p: *Parser) Error!void {
        p.depth += 1;
        if (p.depth > max_depth) return error.TooLarge;
    }

    fn node(p: *Parser, min_indent: usize) Error!Node {
        if (p.i >= p.lines.len or p.lines[p.i].indent < min_indent) return .null;
        try p.enter();
        defer p.depth -= 1;
        const l = p.lines[p.i];
        if (isSeqItem(l.text)) return p.seq(l.indent);
        if (try splitKey(p.a, l.text) != null) return p.map(l.indent);
        p.i += 1;
        const v = try scalar(p.a, l.text);
        try p.count();
        if (p.i < p.lines.len and p.lines[p.i].indent > l.indent) return error.InvalidYaml;
        return v;
    }

    fn map(p: *Parser, indent: usize) Error!Node {
        var out: std.ArrayList(Pair) = .empty;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.indent < indent) break;
            if (l.indent > indent or isSeqItem(l.text)) return error.InvalidYaml;
            const kv = try splitKey(p.a, l.text) orelse return error.InvalidYaml;
            for (out.items) |o| if (std.mem.eql(u8, o.key, kv.key)) return error.InvalidYaml;
            try p.count();
            p.i += 1;
            var value: Node = .null;
            if (kv.value.len > 0) {
                value = try scalar(p.a, kv.value);
                if (p.i < p.lines.len and p.lines[p.i].indent > indent) return error.InvalidYaml;
            } else if (p.i < p.lines.len) {
                const n = p.lines[p.i];
                // A sequence may sit at its key's own indentation.
                if (n.indent > indent or (n.indent == indent and isSeqItem(n.text))) value = try p.node(n.indent);
            }
            try out.append(p.a, .{ .key = kv.key, .value = value });
        }
        return .{ .map = out.items };
    }

    fn seq(p: *Parser, indent: usize) Error!Node {
        var out: std.ArrayList(Node) = .empty;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.indent < indent or (l.indent == indent and !isSeqItem(l.text))) break;
            if (l.indent > indent) return error.InvalidYaml;
            try p.count();
            const rest_raw = l.text[1..];
            const rest = std.mem.trimLeft(u8, rest_raw, " ");
            if (rest.len == 0) {
                p.i += 1;
                const n = if (p.i < p.lines.len and p.lines[p.i].indent > indent) try p.node(p.lines[p.i].indent) else Node.null;
                try out.append(p.a, n);
                continue;
            }
            // `- key: v` opens a mapping at the column of `key`.
            const col = indent + 1 + (rest_raw.len - rest.len);
            p.lines[p.i] = .{ .indent = col, .text = rest };
            try out.append(p.a, try p.node(col));
        }
        return .{ .seq = out.items };
    }
};

fn isSeqItem(t: []const u8) bool {
    return t.len > 0 and t[0] == '-' and (t.len == 1 or t[1] == ' ');
}

const KeyValue = struct { key: []const u8, value: []const u8 };

/// `key: value` or `key:`; quoted keys allowed. Null when the line is not a mapping entry.
fn splitKey(a: Allocator, t: []const u8) Error!?KeyValue {
    if (t[0] == '"' or t[0] == '\'') {
        const end = quotedEnd(t) orelse return error.InvalidYaml;
        const after = t[end..];
        if (after.len == 0 or after[0] != ':') return null;
        if (after.len > 1 and after[1] != ' ') return null;
        const k = try scalar(a, t[0..end]);
        return .{ .key = k.scalar, .value = std.mem.trim(u8, after[1..], " ") };
    }
    if (t[0] == '[' or t[0] == '{') return null;
    var i: usize = 0;
    while (i < t.len) : (i += 1) {
        if (t[i] != ':') continue;
        if (i + 1 == t.len or t[i + 1] == ' ') {
            const k = std.mem.trimRight(u8, t[0..i], " ");
            if (k.len == 0) return error.InvalidYaml;
            return .{ .key = k, .value = std.mem.trim(u8, t[i + 1 ..], " ") };
        }
    }
    return null;
}

/// Index just past the closing quote of a quoted scalar starting at t[0].
fn quotedEnd(t: []const u8) ?usize {
    const q = t[0];
    var i: usize = 1;
    while (i < t.len) : (i += 1) {
        if (q == '"' and t[i] == '\\') {
            i += 1;
            continue;
        }
        if (t[i] == q) {
            if (q == '\'' and i + 1 < t.len and t[i + 1] == '\'') {
                i += 1;
                continue;
            }
            return i + 1;
        }
    }
    return null;
}

fn scalar(a: Allocator, t0: []const u8) Error!Node {
    const t = std.mem.trim(u8, t0, " ");
    if (t.len == 0) return .null;
    switch (t[0]) {
        '"', '\'' => {
            const end = quotedEnd(t) orelse return error.InvalidYaml;
            if (end != t.len) return error.InvalidYaml;
            return .{ .scalar = try unquote(a, t[1 .. end - 1], t[0]) };
        },
        '[' => return flowSeq(a, t),
        '{' => {
            if (!std.mem.eql(u8, std.mem.trim(u8, t[1..], " "), "}")) return error.InvalidYaml;
            return .{ .map = &.{} };
        },
        '&', '*', '!', '|', '>', '%', '@', '`' => return error.InvalidYaml,
        else => {},
    }
    if (std.mem.eql(u8, t, "~") or std.mem.eql(u8, t, "null")) return .null;
    return .{ .scalar = t };
}

fn flowSeq(a: Allocator, t: []const u8) Error!Node {
    if (t[t.len - 1] != ']') return error.InvalidYaml;
    const body = std.mem.trim(u8, t[1 .. t.len - 1], " ");
    var out: std.ArrayList(Node) = .empty;
    if (body.len == 0) return .{ .seq = out.items };
    if (std.mem.indexOfAny(u8, body, "[]{}\"'") != null) return error.InvalidYaml;
    var it = std.mem.splitScalar(u8, body, ',');
    while (it.next()) |item| {
        const s = std.mem.trim(u8, item, " ");
        if (s.len == 0) return error.InvalidYaml;
        try out.append(a, try scalar(a, s));
    }
    return .{ .seq = out.items };
}

fn unquote(a: Allocator, s: []const u8, q: u8) Error![]const u8 {
    if (std.mem.indexOfScalar(u8, s, if (q == '"') '\\' else '\'') == null) return s;
    var out = try std.ArrayList(u8).initCapacity(a, s.len);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const ch = s[i];
        if (q == '\'' and ch == '\'') {
            i += 1; // '' is a literal quote
            out.appendAssumeCapacity('\'');
            continue;
        }
        if (q != '"' or ch != '\\') {
            out.appendAssumeCapacity(ch);
            continue;
        }
        i += 1;
        if (i >= s.len) return error.InvalidYaml;
        out.appendAssumeCapacity(switch (s[i]) {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '0' => 0,
            '"', '\\', '/', ' ' => s[i],
            else => return error.InvalidYaml,
        });
    }
    return out.items;
}

/// Drops a trailing comment (` #...`) outside quotes.
fn stripComment(t: []const u8) []const u8 {
    var q: u8 = 0;
    var i: usize = 0;
    while (i < t.len) : (i += 1) {
        const ch = t[i];
        if (q != 0) {
            if (q == '"' and ch == '\\') i += 1 else if (ch == q) q = 0;
            continue;
        }
        if ((ch == '"' or ch == '\'') and (i == 0 or t[i - 1] == ' ' or t[i - 1] == ':' or t[i - 1] == '-' or t[i - 1] == '[' or t[i - 1] == ',')) {
            q = ch;
            continue;
        }
        if (ch == '#' and (i == 0 or t[i - 1] == ' ')) return t[0..i];
    }
    return t;
}

/// Parses one document; all returned slices point into `src` or `a`.
pub fn parse(a: Allocator, src: []const u8) Error!Node {
    if (src.len > max_input) return error.TooLarge;
    var lines: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, src, '\n');
    var first = true;
    while (it.next()) |raw0| {
        const raw = std.mem.trimRight(u8, raw0, "\r");
        var ind: usize = 0;
        while (ind < raw.len and raw[ind] == ' ') ind += 1;
        if (ind < raw.len and raw[ind] == '\t') return error.InvalidYaml;
        const text = std.mem.trimRight(u8, stripComment(raw[ind..]), " \t");
        if (text.len == 0) continue;
        if (std.mem.eql(u8, text, "---") and first) {
            first = false;
            continue;
        }
        first = false;
        if (std.mem.eql(u8, text, "---") or std.mem.eql(u8, text, "...")) return error.InvalidYaml;
        if (lines.items.len >= max_lines) return error.TooLarge;
        for (text) |ch| if (ch < 0x20 and ch != '\t') return error.InvalidYaml;
        try lines.append(a, .{ .indent = ind, .text = text });
    }
    var p: Parser = .{ .a = a, .lines = lines.items };
    if (lines.items.len == 0) return .null;
    const root = try p.node(lines.items[0].indent);
    if (p.i != lines.items.len) return error.InvalidYaml;
    return root;
}

const testing = std.testing;

test "job-shaped document" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const doc =
        \\# comment
        \\expire:
        \\  apiVersion: v1
        \\  bucket: "my bucket" # trailing
        \\  rules:
        \\    - type: object
        \\      name: 'it''s*'
        \\      tags:
        \\        - key: k
        \\          value: v*
        \\      purge:
        \\        # retainVersions: 2
        \\    - type: deleted
        \\  flags: []
        \\  list:
        \\  - a
        \\  - "b#c"
        \\  url: http://h:9/x#frag
    ;
    const n = try parse(arena.allocator(), doc);
    const e = n.get("expire").?;
    try testing.expectEqualStrings("v1", e.getStr("apiVersion").?);
    try testing.expectEqualStrings("my bucket", e.getStr("bucket").?);
    const rules = e.get("rules").?.seq;
    try testing.expectEqual(@as(usize, 2), rules.len);
    try testing.expectEqualStrings("it's*", rules[0].getStr("name").?);
    try testing.expectEqualStrings("v*", rules[0].get("tags").?.seq[0].getStr("value").?);
    try testing.expect(rules[0].get("purge").? == .null);
    try testing.expectEqualStrings("deleted", rules[1].getStr("type").?);
    try testing.expectEqual(@as(usize, 0), e.get("flags").?.seq.len);
    try testing.expectEqualStrings("b#c", e.get("list").?.seq[1].str().?);
    try testing.expectEqualStrings("http://h:9/x#frag", e.getStr("url").?);
}

test "hostile input is refused, never crashes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bad = [_][]const u8{
        "a: 1\n  b: 2",      "a:\n\tb: 1",      "a: \"unterminated", "a: &anchor x",
        "a: *alias",         "a: |\n  block",   "a: 1\na: 2",        "- a\nb: 1",
        "a: [x, [y]]",       "a: {x: 1}",       "a: \"bad \\q\"",    ": v",
        "a\n  b",            "a: 1\n---\nb: 2", "\"k\"x: 1",         "a: [x,,y]",
        "a: \"x\" trailing", "k: \x01",
    };
    for (bad) |b| {
        if (parse(a, b)) |_| {
            std.debug.print("accepted: {s}\n", .{b});
            return error.TestUnexpectedResult;
        } else |e| try testing.expect(e == error.InvalidYaml or e == error.TooLarge);
    }
    // Deep nesting hits the depth bound instead of the stack.
    var deep: std.ArrayList(u8) = .empty;
    for (0..200) |i| {
        try deep.appendNTimes(a, ' ', i);
        try deep.appendSlice(a, "k:\n");
    }
    try testing.expectError(error.TooLarge, parse(a, deep.items));
    var dash: std.ArrayList(u8) = .empty;
    for (0..200) |_| try dash.appendSlice(a, "- ");
    try dash.appendSlice(a, "x");
    try testing.expectError(error.TooLarge, parse(a, dash.items));
    // Too many nodes and oversized input.
    var wide: std.ArrayList(u8) = .empty;
    for (0..max_nodes + 1) |_| try wide.appendSlice(a, "- x\n");
    try testing.expectError(error.TooLarge, parse(a, wide.items));
    const big = try a.alloc(u8, max_input + 1);
    @memset(big, 'a');
    try testing.expectError(error.TooLarge, parse(a, big));
    // Fuzz-ish: random bytes over a YAML alphabet never panic.
    var prng = std.Random.DefaultPrng.init(42);
    const alphabet = " \n-:#'\"[]{}abc\\&*|";
    var buf: [96]u8 = undefined;
    for (0..20000) |_| {
        const n = prng.random().uintLessThan(usize, buf.len);
        for (buf[0..n]) |*ch| ch.* = alphabet[prng.random().uintLessThan(usize, alphabet.len)];
        _ = parse(a, buf[0..n]) catch {};
    }
}

test "empty and scalar documents" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expect(try parse(arena.allocator(), "# only\n\n") == .null);
    try testing.expectEqualStrings("x", (try parse(arena.allocator(), "---\nx")).str().?);
}
