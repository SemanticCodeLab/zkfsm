//! Streaming JSON record reader (DOCUMENT and LINES) with a bounded,
//! depth-limited value parser.
const std = @import("std");
const value = @import("value.zig");
const Value = value.Value;
const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, ReadFailed, RecordTooLarge, InvalidJson, JsonTooDeep };

pub const max_depth = 128;

pub const Reader = struct {
    in: *std.Io.Reader,
    gpa: Allocator,
    max_record: usize,
    /// Emit elements of a top-level array as separate records (FROM S3Object[*]).
    unwrap_array: bool,
    buf: std.ArrayList(u8) = .empty,
    offset: u64 = 0,
    end_offset: ?u64 = null,
    in_array: bool = false,
    done: bool = false,

    pub fn init(gpa: Allocator, in: *std.Io.Reader, max_record: usize, unwrap_array: bool) Reader {
        return .{ .in = in, .gpa = gpa, .max_record = max_record, .unwrap_array = unwrap_array };
    }

    pub fn deinit(r: *Reader) void {
        r.buf.deinit(r.gpa);
    }

    fn take(r: *Reader) Error!?u8 {
        const b = r.in.takeByte() catch |e| switch (e) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
        r.offset += 1;
        return b;
    }

    fn append(r: *Reader, b: u8) Error!void {
        if (r.buf.items.len >= r.max_record) return error.RecordTooLarge;
        try r.buf.append(r.gpa, b);
    }

    fn skipWs(r: *Reader) Error!?u8 {
        while (try r.take()) |b| {
            if (!std.ascii.isWhitespace(b)) return b;
        }
        return null;
    }

    /// Copies one complete JSON value starting with `first` into buf.
    fn scanValue(r: *Reader, first: u8) Error!void {
        r.buf.clearRetainingCapacity();
        try r.append(first);
        if (first == '{' or first == '[') {
            var depth: usize = 1;
            var in_str = false;
            var esc = false;
            while (depth > 0) {
                const b = (try r.take()) orelse return error.InvalidJson;
                try r.append(b);
                if (in_str) {
                    if (esc) {
                        esc = false;
                    } else if (b == '\\') {
                        esc = true;
                    } else if (b == '"') in_str = false;
                    continue;
                }
                switch (b) {
                    '"' => in_str = true,
                    '{', '[' => {
                        depth += 1;
                        if (depth > max_depth) return error.JsonTooDeep;
                    },
                    '}', ']' => depth -= 1,
                    else => {},
                }
            }
        } else if (first == '"') {
            var esc = false;
            while (true) {
                const b = (try r.take()) orelse return error.InvalidJson;
                try r.append(b);
                if (esc) {
                    esc = false;
                } else if (b == '\\') {
                    esc = true;
                } else if (b == '"') break;
            }
        } else {
            while (true) {
                const b = r.in.peekByte() catch |e| switch (e) {
                    error.EndOfStream => break,
                    error.ReadFailed => return error.ReadFailed,
                };
                if (std.ascii.isWhitespace(b) or b == ',' or b == ']' or b == '}' or b == '[' or b == '{') break;
                _ = try r.take();
                try r.append(b);
            }
        }
    }

    pub fn next(r: *Reader, arena: Allocator) Error!?Value {
        while (!r.done) {
            if (r.end_offset) |e| if (r.offset > e and !r.in_array) {
                r.done = true;
                return null;
            };
            var b = (try r.skipWs()) orelse {
                if (r.in_array) return error.InvalidJson;
                r.done = true;
                return null;
            };
            if (r.in_array) {
                if (b == ']') {
                    r.in_array = false;
                    continue;
                }
                if (b == ',') b = (try r.skipWs()) orelse return error.InvalidJson;
            } else if (b == '[' and r.unwrap_array) {
                r.in_array = true;
                const c = (try r.skipWs()) orelse return error.InvalidJson;
                if (c == ']') {
                    r.in_array = false;
                    continue;
                }
                b = c;
            }
            try r.scanValue(b);
            return try parseValue(arena, r.buf.items);
        }
        return null;
    }

    /// LINES scan range: start at the first line beginning at or after `start`.
    pub fn seekScanRange(r: *Reader, start: u64, end: ?u64) Error!void {
        r.end_offset = end;
        if (start == 0) return;
        var left = start - 1;
        while (left > 0) {
            const m = r.in.discard(.limited64(left)) catch |e| switch (e) {
                error.EndOfStream => 0,
                error.ReadFailed => return error.ReadFailed,
            };
            if (m == 0) {
                r.done = true;
                return;
            }
            left -= m;
            r.offset += m;
        }
        while (try r.take()) |b| if (b == '\n') return;
        r.done = true;
    }
};

const Parser = struct {
    arena: Allocator,
    s: []const u8,
    i: usize = 0,

    fn ws(p: *Parser) void {
        while (p.i < p.s.len and std.ascii.isWhitespace(p.s[p.i])) p.i += 1;
    }

    fn lit(p: *Parser, word: []const u8, v: Value) Error!Value {
        if (!std.mem.startsWith(u8, p.s[p.i..], word)) return error.InvalidJson;
        p.i += word.len;
        return v;
    }

    fn hex4(p: *Parser) Error!u21 {
        if (p.i + 4 > p.s.len) return error.InvalidJson;
        const v = std.fmt.parseInt(u16, p.s[p.i .. p.i + 4], 16) catch return error.InvalidJson;
        p.i += 4;
        return v;
    }

    fn string(p: *Parser) Error![]const u8 {
        p.i += 1; // opening quote
        const start = p.i;
        while (p.i < p.s.len and p.s[p.i] != '"' and p.s[p.i] != '\\') p.i += 1;
        if (p.i < p.s.len and p.s[p.i] == '"') {
            p.i += 1;
            return p.s[start .. p.i - 1];
        }
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(p.arena, p.s[start..p.i]);
        while (true) {
            if (p.i >= p.s.len) return error.InvalidJson;
            const c = p.s[p.i];
            p.i += 1;
            if (c == '"') return out.items;
            if (c != '\\') {
                try out.append(p.arena, c);
                continue;
            }
            if (p.i >= p.s.len) return error.InvalidJson;
            const e = p.s[p.i];
            p.i += 1;
            const simple: ?u8 = switch (e) {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => 8,
                'f' => 12,
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                else => null,
            };
            if (simple) |ch| {
                try out.append(p.arena, ch);
                continue;
            }
            if (e != 'u') return error.InvalidJson;
            var cp = try p.hex4();
            if (cp >= 0xD800 and cp < 0xDC00) {
                if (p.i + 2 <= p.s.len and p.s[p.i] == '\\' and p.s[p.i + 1] == 'u') {
                    p.i += 2;
                    const lo = try p.hex4();
                    if (lo < 0xDC00 or lo > 0xDFFF) return error.InvalidJson;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else cp = 0xFFFD;
            } else if (cp >= 0xDC00 and cp <= 0xDFFF) cp = 0xFFFD;
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(cp, &buf) catch return error.InvalidJson;
            try out.appendSlice(p.arena, buf[0..n]);
        }
    }

    fn number(p: *Parser) Error!Value {
        const start = p.i;
        var is_float = false;
        while (p.i < p.s.len) : (p.i += 1) {
            switch (p.s[p.i]) {
                '0'...'9', '-', '+' => {},
                '.', 'e', 'E' => is_float = true,
                else => break,
            }
        }
        const t = p.s[start..p.i];
        if (t.len == 0) return error.InvalidJson;
        if (!is_float) {
            if (std.fmt.parseInt(i64, t, 10)) |i| return .{ .int = i } else |_| {}
        }
        return .{ .float = std.fmt.parseFloat(f64, t) catch return error.InvalidJson };
    }

    fn parse(p: *Parser, depth: usize) Error!Value {
        if (depth > max_depth) return error.JsonTooDeep;
        p.ws();
        if (p.i >= p.s.len) return error.InvalidJson;
        switch (p.s[p.i]) {
            '{' => {
                p.i += 1;
                var keys: std.ArrayList([]const u8) = .empty;
                var vals: std.ArrayList(Value) = .empty;
                p.ws();
                if (p.i < p.s.len and p.s[p.i] == '}') {
                    p.i += 1;
                    return .{ .object = .{ .keys = &.{}, .values = &.{} } };
                }
                while (true) {
                    p.ws();
                    if (p.i >= p.s.len or p.s[p.i] != '"') return error.InvalidJson;
                    try keys.append(p.arena, try p.string());
                    p.ws();
                    if (p.i >= p.s.len or p.s[p.i] != ':') return error.InvalidJson;
                    p.i += 1;
                    try vals.append(p.arena, try p.parse(depth + 1));
                    p.ws();
                    if (p.i >= p.s.len) return error.InvalidJson;
                    const c = p.s[p.i];
                    p.i += 1;
                    if (c == '}') break;
                    if (c != ',') return error.InvalidJson;
                }
                return .{ .object = .{ .keys = keys.items, .values = vals.items } };
            },
            '[' => {
                p.i += 1;
                var items: std.ArrayList(Value) = .empty;
                p.ws();
                if (p.i < p.s.len and p.s[p.i] == ']') {
                    p.i += 1;
                    return .{ .list = &.{} };
                }
                while (true) {
                    try items.append(p.arena, try p.parse(depth + 1));
                    p.ws();
                    if (p.i >= p.s.len) return error.InvalidJson;
                    const c = p.s[p.i];
                    p.i += 1;
                    if (c == ']') break;
                    if (c != ',') return error.InvalidJson;
                }
                return .{ .list = items.items };
            },
            '"' => return .{ .string = try p.string() },
            't' => return p.lit("true", .{ .bool = true }),
            'f' => return p.lit("false", .{ .bool = false }),
            'n' => return p.lit("null", .null),
            else => return p.number(),
        }
    }
};

/// Parses one JSON value; strings may alias `s`.
pub fn parseValue(arena: Allocator, s: []const u8) Error!Value {
    var p: Parser = .{ .arena = arena, .s = s };
    const v = try p.parse(0);
    p.ws();
    if (p.i != s.len) return error.InvalidJson;
    return v;
}

fn render(v: Value) ![]const u8 {
    const S = struct {
        var buf: [1024]u8 = undefined;
    };
    var w: std.Io.Writer = .fixed(&S.buf);
    try value.writeJson(v, &w, 0);
    return w.buffered();
}

test "document stream of values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var in: std.Io.Reader = .fixed(" {\"a\": [1, 2.5, \"x\\u00e9\\n\"]}\n{\"b\":{\"c\":null,\"d\":true}} {\"s\":\"}\"}");
    var r = Reader.init(std.testing.allocator, &in, 1024, false);
    defer r.deinit();
    try std.testing.expectEqualStrings("{\"a\":[1,2.5,\"xé\\n\"]}", try render((try r.next(arena.allocator())).?));
    try std.testing.expectEqualStrings("{\"b\":{\"c\":null,\"d\":true}}", try render((try r.next(arena.allocator())).?));
    try std.testing.expectEqualStrings("{\"s\":\"}\"}", try render((try r.next(arena.allocator())).?));
    try std.testing.expect(try r.next(arena.allocator()) == null);
}

test "unwrap top-level array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var in: std.Io.Reader = .fixed("[{\"a\":1}, {\"a\":2} ,3]");
    var r = Reader.init(std.testing.allocator, &in, 1024, true);
    defer r.deinit();
    try std.testing.expectEqual(@as(i64, 1), (try r.next(arena.allocator())).?.object.values[0].int);
    try std.testing.expectEqual(@as(i64, 2), (try r.next(arena.allocator())).?.object.values[0].int);
    try std.testing.expectEqual(@as(i64, 3), (try r.next(arena.allocator())).?.int);
    try std.testing.expect(try r.next(arena.allocator()) == null);
}

test "hostile json" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.InvalidJson, parseValue(a, "{\"a\" 1}"));
    try std.testing.expectError(error.InvalidJson, parseValue(a, "[1,]x"));
    try std.testing.expectError(error.InvalidJson, parseValue(a, "\"\\u12\""));
    const deep = "[" ** 200 ++ "]" ** 200;
    try std.testing.expectError(error.JsonTooDeep, parseValue(a, deep));
    var in: std.Io.Reader = .fixed(deep);
    var r = Reader.init(std.testing.allocator, &in, 1 << 20, false);
    defer r.deinit();
    try std.testing.expectError(error.JsonTooDeep, r.next(a));
    var in2: std.Io.Reader = .fixed("{\"a\":1");
    var r2 = Reader.init(std.testing.allocator, &in2, 1 << 20, false);
    defer r2.deinit();
    try std.testing.expectError(error.InvalidJson, r2.next(a));
}
