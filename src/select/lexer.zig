//! Tokenizer for the S3 Select SQL dialect.
const std = @import("std");

pub const Tag = enum {
    ident,
    quoted_ident,
    string,
    int,
    float,
    lparen,
    rparen,
    comma,
    dot,
    lbracket,
    rbracket,
    star,
    plus,
    minus,
    slash,
    percent,
    concat,
    eq,
    ne,
    lt,
    le,
    gt,
    ge,
    semicolon,
    eof,
};

pub const Token = struct {
    tag: Tag,
    /// Raw source text; string and quoted_ident exclude the outer quotes.
    text: []const u8,
    pos: usize,
};

pub const Error = error{ OutOfMemory, UnexpectedCharacter, UnterminatedString, ExpressionTooLong };

pub const max_expression_len = 256 * 1024;
pub const max_tokens = 16 * 1024;

pub fn tokenize(arena: std.mem.Allocator, src: []const u8) Error![]Token {
    if (src.len > max_expression_len) return error.ExpressionTooLong;
    var out: std.ArrayList(Token) = .empty;
    var i: usize = 0;
    while (true) {
        while (i < src.len and std.ascii.isWhitespace(src[i])) i += 1;
        if (out.items.len >= max_tokens) return error.ExpressionTooLong;
        if (i >= src.len) {
            try out.append(arena, .{ .tag = .eof, .text = "", .pos = i });
            return out.items;
        }
        const c = src[i];
        const start = i;
        if (c == '-' and i + 1 < src.len and src[i + 1] == '-') {
            while (i < src.len and src[i] != '\n') i += 1;
            continue;
        }
        if (std.ascii.isAlphabetic(c) or c == '_') {
            while (i < src.len and (std.ascii.isAlphanumeric(src[i]) or src[i] == '_')) i += 1;
            try out.append(arena, .{ .tag = .ident, .text = src[start..i], .pos = start });
            continue;
        }
        if (std.ascii.isDigit(c) or (c == '.' and i + 1 < src.len and std.ascii.isDigit(src[i + 1]))) {
            var is_float = false;
            while (i < src.len and std.ascii.isDigit(src[i])) i += 1;
            if (i < src.len and src[i] == '.') {
                is_float = true;
                i += 1;
                while (i < src.len and std.ascii.isDigit(src[i])) i += 1;
            }
            if (i < src.len and (src[i] == 'e' or src[i] == 'E')) {
                var j = i + 1;
                if (j < src.len and (src[j] == '+' or src[j] == '-')) j += 1;
                if (j < src.len and std.ascii.isDigit(src[j])) {
                    is_float = true;
                    i = j;
                    while (i < src.len and std.ascii.isDigit(src[i])) i += 1;
                }
            }
            try out.append(arena, .{ .tag = if (is_float) .float else .int, .text = src[start..i], .pos = start });
            continue;
        }
        if (c == '\'' or c == '"') {
            // Doubled quote inside is an escaped quote; parser unescapes.
            i += 1;
            while (true) {
                if (i >= src.len) return error.UnterminatedString;
                if (src[i] == c) {
                    if (i + 1 < src.len and src[i + 1] == c) {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            try out.append(arena, .{ .tag = if (c == '\'') .string else .quoted_ident, .text = src[start + 1 .. i], .pos = start });
            i += 1;
            continue;
        }
        const two: ?Tag = if (i + 1 < src.len) switch (c) {
            '<' => switch (src[i + 1]) {
                '=' => .le,
                '>' => .ne,
                else => null,
            },
            '>' => if (src[i + 1] == '=') .ge else null,
            '!' => if (src[i + 1] == '=') .ne else null,
            '|' => if (src[i + 1] == '|') .concat else null,
            else => null,
        } else null;
        if (two) |t| {
            try out.append(arena, .{ .tag = t, .text = src[i .. i + 2], .pos = start });
            i += 2;
            continue;
        }
        const one: Tag = switch (c) {
            '(' => .lparen,
            ')' => .rparen,
            ',' => .comma,
            '.' => .dot,
            '[' => .lbracket,
            ']' => .rbracket,
            '*' => .star,
            '+' => .plus,
            '-' => .minus,
            '/' => .slash,
            '%' => .percent,
            '=' => .eq,
            '<' => .lt,
            '>' => .gt,
            ';' => .semicolon,
            else => return error.UnexpectedCharacter,
        };
        try out.append(arena, .{ .tag = one, .text = src[i .. i + 1], .pos = start });
        i += 1;
    }
}

test "tokenize" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const toks = try tokenize(arena.allocator(), "SELECT s.\"a b\", 'it''s', 1.5e3, 42 FROM S3Object[*] WHERE x <> 3 -- c\n || y");
    const tags = [_]Tag{ .ident, .ident, .dot, .quoted_ident, .comma, .string, .comma, .float, .comma, .int, .ident, .ident, .lbracket, .star, .rbracket, .ident, .ident, .ne, .int, .concat, .ident, .eof };
    try std.testing.expectEqual(tags.len, toks.len);
    for (tags, toks) |t, tok| try std.testing.expectEqual(t, tok.tag);
    try std.testing.expectEqualStrings("it''s", toks[5].text);
    try std.testing.expectError(error.UnterminatedString, tokenize(arena.allocator(), "'abc"));
    try std.testing.expectError(error.UnexpectedCharacter, tokenize(arena.allocator(), "a # b"));
}
