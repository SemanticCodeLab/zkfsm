//! Pratt parser for S3 Select SQL.
const std = @import("std");
const lexer = @import("lexer.zig");
const ast = @import("ast.zig");
const datetime = @import("datetime.zig");
const Value = @import("value.zig").Value;
const Token = lexer.Token;
const Expr = ast.Expr;

pub const Error = lexer.Error || error{
    SyntaxError,
    ExpressionTooDeep,
    InvalidAggregate,
    UnknownFunction,
    InvalidCastType,
    InvalidDatePart,
    TooManyItems,
};

pub const max_depth = 128;
const max_list_items = 4096;

const bp_or = 1;
const bp_and = 2;
const bp_not = 3;
const bp_cmp = 4;
const bp_concat = 5;
const bp_add = 6;
const bp_mul = 7;
const bp_unary = 8;

const Parser = struct {
    arena: std.mem.Allocator,
    toks: []const Token,
    i: usize = 0,
    depth: usize = 0,
    agg_depth: usize = 0,
    aggs: std.ArrayList(*const Expr) = .empty,
    allow_aggs: bool = false,
    bare_path: bool = false,

    fn peek(p: *Parser) Token {
        return p.toks[p.i];
    }
    fn peekAt(p: *Parser, n: usize) Token {
        return p.toks[@min(p.i + n, p.toks.len - 1)];
    }
    fn next(p: *Parser) Token {
        const t = p.toks[p.i];
        if (t.tag != .eof) p.i += 1;
        return t;
    }
    fn expect(p: *Parser, tag: lexer.Tag) Error!Token {
        if (p.peek().tag != tag) return error.SyntaxError;
        return p.next();
    }
    fn isKw(t: Token, kw: []const u8) bool {
        return t.tag == .ident and std.ascii.eqlIgnoreCase(t.text, kw);
    }
    fn atKw(p: *Parser, kw: []const u8) bool {
        return isKw(p.peek(), kw);
    }
    fn eatKw(p: *Parser, kw: []const u8) bool {
        if (p.atKw(kw)) {
            p.i += 1;
            return true;
        }
        return false;
    }
    fn expectKw(p: *Parser, kw: []const u8) Error!void {
        if (!p.eatKw(kw)) return error.SyntaxError;
    }

    fn new(p: *Parser, e: Expr) Error!*const Expr {
        const ptr = try p.arena.create(Expr);
        ptr.* = e;
        return ptr;
    }

    fn unescape(p: *Parser, raw: []const u8, q: u8) Error![]const u8 {
        if (std.mem.indexOfScalar(u8, raw, q) == null) return raw;
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < raw.len) : (i += 1) {
            try out.append(p.arena, raw[i]);
            if (raw[i] == q) i += 1;
        }
        return out.items;
    }

    fn infixBp(p: *Parser) ?u8 {
        const t = p.peek();
        return switch (t.tag) {
            .eq, .ne, .lt, .le, .gt, .ge => bp_cmp,
            .concat => bp_concat,
            .plus, .minus => bp_add,
            .star, .slash, .percent => bp_mul,
            .ident => if (isKw(t, "OR"))
                bp_or
            else if (isKw(t, "AND"))
                bp_and
            else if (isKw(t, "LIKE") or isKw(t, "BETWEEN") or isKw(t, "IN") or isKw(t, "IS"))
                bp_cmp
            else if (isKw(t, "NOT") and (isKw(p.peekAt(1), "LIKE") or isKw(p.peekAt(1), "BETWEEN") or isKw(p.peekAt(1), "IN")))
                bp_cmp
            else
                null,
            else => null,
        };
    }

    fn expr(p: *Parser, min_bp: u8) Error!*const Expr {
        p.depth += 1;
        defer p.depth -= 1;
        if (p.depth > max_depth) return error.ExpressionTooDeep;
        var lhs = try p.prefix();
        while (p.infixBp()) |bp| {
            if (bp < min_bp) break;
            lhs = try p.infix(lhs, bp);
        }
        return lhs;
    }

    fn binary(p: *Parser, op: ast.BinaryOp, lhs: *const Expr, rhs: *const Expr) Error!*const Expr {
        return p.new(.{ .binary = .{ .op = op, .lhs = lhs, .rhs = rhs } });
    }

    fn infix(p: *Parser, lhs: *const Expr, bp: u8) Error!*const Expr {
        const t = p.next();
        const op: ?ast.BinaryOp = switch (t.tag) {
            .eq => .eq,
            .ne => .ne,
            .lt => .lt,
            .le => .le,
            .gt => .gt,
            .ge => .ge,
            .concat => .concat,
            .plus => .add,
            .minus => .sub,
            .star => .mul,
            .slash => .div,
            .percent => .mod,
            else => if (isKw(t, "OR")) .@"or" else if (isKw(t, "AND")) .@"and" else null,
        };
        if (op) |o| return p.binary(o, lhs, try p.expr(bp + 1));
        var negated = false;
        var kw = t;
        if (isKw(t, "NOT")) {
            negated = true;
            kw = p.next();
        }
        if (isKw(kw, "LIKE")) {
            const pat = try p.expr(bp_cmp + 1);
            const esc = if (p.eatKw("ESCAPE")) try p.expr(bp_cmp + 1) else null;
            return p.new(.{ .like = .{ .operand = lhs, .pattern = pat, .escape = esc, .negated = negated } });
        }
        if (isKw(kw, "BETWEEN")) {
            const lo = try p.expr(bp_cmp + 1);
            try p.expectKw("AND");
            const hi = try p.expr(bp_cmp + 1);
            return p.new(.{ .between = .{ .operand = lhs, .low = lo, .high = hi, .negated = negated } });
        }
        if (isKw(kw, "IN")) {
            _ = try p.expect(.lparen);
            const items = try p.exprList(.rparen);
            if (items.len == 0) return error.SyntaxError;
            return p.new(.{ .in_list = .{ .operand = lhs, .items = items, .negated = negated } });
        }
        if (isKw(kw, "IS")) {
            const neg = p.eatKw("NOT");
            const what: ast.IsWhat = if (p.eatKw("NULL")) .null else if (p.eatKw("MISSING")) .missing else if (p.eatKw("TRUE")) .true else if (p.eatKw("FALSE")) .false else return error.SyntaxError;
            return p.new(.{ .is = .{ .operand = lhs, .what = what, .negated = neg } });
        }
        return error.SyntaxError;
    }

    /// Comma-separated expressions up to and including `close`.
    fn exprList(p: *Parser, close: lexer.Tag) Error![]const *const Expr {
        var items: std.ArrayList(*const Expr) = .empty;
        if (p.peek().tag == close) {
            _ = p.next();
            return items.items;
        }
        while (true) {
            if (items.items.len >= max_list_items) return error.TooManyItems;
            try items.append(p.arena, try p.expr(0));
            if (p.peek().tag == .comma) {
                _ = p.next();
                continue;
            }
            _ = try p.expect(close);
            return items.items;
        }
    }

    fn intLiteral(text: []const u8, neg: bool) Value {
        const mag = std.fmt.parseInt(u64, text, 10) catch
            return .{ .float = (std.fmt.parseFloat(f64, text) catch 0) * @as(f64, if (neg) -1 else 1) };
        if (neg) {
            if (mag <= @as(u64, std.math.maxInt(i64)) + 1) return .{ .int = @intCast(-@as(i128, mag)) };
            return .{ .float = -@as(f64, @floatFromInt(mag)) };
        }
        if (mag <= std.math.maxInt(i64)) return .{ .int = @intCast(mag) };
        return .{ .float = @floatFromInt(mag) };
    }

    fn prefix(p: *Parser) Error!*const Expr {
        const t = p.next();
        switch (t.tag) {
            .minus => {
                const nt = p.peek();
                if (nt.tag == .int) {
                    _ = p.next();
                    return p.new(.{ .literal = intLiteral(nt.text, true) });
                }
                return p.new(.{ .unary = .{ .op = .neg, .operand = try p.expr(bp_unary) } });
            },
            .plus => return p.expr(bp_unary),
            .lparen => {
                const e = try p.expr(0);
                _ = try p.expect(.rparen);
                return e;
            },
            .string => return p.new(.{ .literal = .{ .string = try p.unescape(t.text, '\'') } }),
            .int => return p.new(.{ .literal = intLiteral(t.text, false) }),
            .float => return p.new(.{ .literal = .{ .float = std.fmt.parseFloat(f64, t.text) catch return error.SyntaxError } }),
            .quoted_ident => return p.path(.{ .field = .{ .name = try p.unescape(t.text, '"'), .quoted = true } }),
            .ident => return p.identPrefix(t),
            else => return error.SyntaxError,
        }
    }

    fn identPrefix(p: *Parser, t: Token) Error!*const Expr {
        if (isKw(t, "NOT")) return p.new(.{ .unary = .{ .op = .not, .operand = try p.expr(bp_not) } });
        if (isKw(t, "TRUE")) return p.new(.{ .literal = .{ .bool = true } });
        if (isKw(t, "FALSE")) return p.new(.{ .literal = .{ .bool = false } });
        if (isKw(t, "NULL")) return p.new(.{ .literal = .null });
        if (isKw(t, "MISSING")) return p.new(.{ .literal = .missing });
        if (isKw(t, "CASE")) return p.caseExpr();
        if (p.peek().tag == .lparen) return p.call(t);
        const reserved = [_][]const u8{ "SELECT", "FROM", "WHERE", "LIMIT", "AND", "OR", "AS", "LIKE", "BETWEEN", "IN", "IS", "WHEN", "THEN", "ELSE", "END" };
        for (reserved) |r| if (isKw(t, r)) return error.SyntaxError;
        return p.path(.{ .field = .{ .name = t.text, .quoted = false } });
    }

    fn path(p: *Parser, first: ast.Step) Error!*const Expr {
        var steps: std.ArrayList(ast.Step) = .empty;
        try steps.append(p.arena, first);
        try p.pathSteps(&steps);
        if (p.agg_depth == 0) p.bare_path = true;
        return p.new(.{ .path = .{ .steps = steps.items } });
    }

    fn pathSteps(p: *Parser, steps: *std.ArrayList(ast.Step)) Error!void {
        while (true) {
            if (steps.items.len > max_depth) return error.ExpressionTooDeep;
            switch (p.peek().tag) {
                .dot => {
                    _ = p.next();
                    const n = p.next();
                    switch (n.tag) {
                        .ident => try steps.append(p.arena, .{ .field = .{ .name = n.text, .quoted = false } }),
                        .quoted_ident => try steps.append(p.arena, .{ .field = .{ .name = try p.unescape(n.text, '"'), .quoted = true } }),
                        .star => try steps.append(p.arena, .wildcard),
                        else => return error.SyntaxError,
                    }
                },
                .lbracket => {
                    _ = p.next();
                    const n = p.next();
                    switch (n.tag) {
                        .star => try steps.append(p.arena, .wildcard),
                        .int => try steps.append(p.arena, .{ .index = std.fmt.parseInt(u64, n.text, 10) catch return error.SyntaxError }),
                        .string => try steps.append(p.arena, .{ .field = .{ .name = try p.unescape(n.text, '\''), .quoted = true } }),
                        else => return error.SyntaxError,
                    }
                    _ = try p.expect(.rbracket);
                },
                else => return,
            }
        }
    }

    fn caseExpr(p: *Parser) Error!*const Expr {
        const operand = if (p.atKw("WHEN")) null else try p.expr(0);
        var whens: std.ArrayList(ast.When) = .empty;
        while (p.eatKw("WHEN")) {
            if (whens.items.len >= max_list_items) return error.TooManyItems;
            const c = try p.expr(0);
            try p.expectKw("THEN");
            try whens.append(p.arena, .{ .cond = c, .result = try p.expr(0) });
        }
        if (whens.items.len == 0) return error.SyntaxError;
        const else_e = if (p.eatKw("ELSE")) try p.expr(0) else null;
        try p.expectKw("END");
        return p.new(.{ .case = .{ .operand = operand, .whens = whens.items, .@"else" = else_e } });
    }

    fn datePart(p: *Parser) Error!datetime.Part {
        const t = p.next();
        if (t.tag != .ident and t.tag != .string) return error.InvalidDatePart;
        return datetime.partFromName(t.text) orelse error.InvalidDatePart;
    }

    fn call(p: *Parser, name_tok: Token) Error!*const Expr {
        _ = try p.expect(.lparen);
        const name = name_tok.text;
        const eq = std.ascii.eqlIgnoreCase;
        const agg: ?ast.AggKind = if (eq(name, "COUNT")) .count else if (eq(name, "SUM")) .sum else if (eq(name, "AVG")) .avg else if (eq(name, "MIN")) .min else if (eq(name, "MAX")) .max else null;
        if (agg) |kind| {
            if (!p.allow_aggs or p.agg_depth > 0) return error.InvalidAggregate;
            var arg: ?*const Expr = null;
            if (kind == .count and p.peek().tag == .star) {
                _ = p.next();
            } else {
                p.agg_depth += 1;
                defer p.agg_depth -= 1;
                arg = try p.expr(0);
            }
            _ = try p.expect(.rparen);
            const e = try p.new(.{ .aggregate = .{ .kind = kind, .arg = arg, .slot = @intCast(p.aggs.items.len) } });
            try p.aggs.append(p.arena, e);
            return e;
        }
        if (eq(name, "CAST")) {
            const operand = try p.expr(0);
            try p.expectKw("AS");
            const tt = p.next();
            if (tt.tag != .ident) return error.InvalidCastType;
            const to: ast.CastType = blk: {
                const n = tt.text;
                if (eq(n, "INT") or eq(n, "INTEGER") or eq(n, "BIGINT") or eq(n, "SMALLINT")) break :blk .int;
                if (eq(n, "FLOAT") or eq(n, "DOUBLE") or eq(n, "REAL")) break :blk .float;
                if (eq(n, "DECIMAL") or eq(n, "NUMERIC")) break :blk .decimal;
                if (eq(n, "STRING") or eq(n, "VARCHAR") or eq(n, "CHAR") or eq(n, "TEXT")) break :blk .string;
                if (eq(n, "BOOL") or eq(n, "BOOLEAN")) break :blk .bool;
                if (eq(n, "TIMESTAMP")) break :blk .timestamp;
                return error.InvalidCastType;
            };
            if (p.peek().tag == .lparen) {
                _ = p.next();
                _ = try p.expect(.int);
                if (p.peek().tag == .comma) {
                    _ = p.next();
                    _ = try p.expect(.int);
                }
                _ = try p.expect(.rparen);
            }
            _ = try p.expect(.rparen);
            return p.new(.{ .cast = .{ .operand = operand, .to = to } });
        }
        if (eq(name, "EXTRACT")) {
            const part = try p.datePart();
            try p.expectKw("FROM");
            const operand = try p.expr(0);
            _ = try p.expect(.rparen);
            return p.new(.{ .extract = .{ .part = part, .operand = operand } });
        }
        if (eq(name, "DATE_ADD") or eq(name, "DATE_DIFF")) {
            const part = try p.datePart();
            if (part == .timezone_hour or part == .timezone_minute) return error.InvalidDatePart;
            _ = try p.expect(.comma);
            const a = try p.expr(0);
            _ = try p.expect(.comma);
            const b = try p.expr(0);
            _ = try p.expect(.rparen);
            if (eq(name, "DATE_ADD")) return p.new(.{ .date_add = .{ .part = part, .qty = a, .ts = b } });
            return p.new(.{ .date_diff = .{ .part = part, .a = a, .b = b } });
        }
        if (eq(name, "TRIM")) {
            var mode: ast.TrimMode = .both;
            var explicit_mode = false;
            if (p.eatKw("LEADING")) {
                mode = .leading;
                explicit_mode = true;
            } else if (p.eatKw("TRAILING")) {
                mode = .trailing;
                explicit_mode = true;
            } else if (p.eatKw("BOTH")) {
                explicit_mode = true;
            }
            var chars: ?*const Expr = null;
            var operand: *const Expr = undefined;
            if (explicit_mode and p.eatKw("FROM")) {
                operand = try p.expr(0);
            } else {
                const first = try p.expr(0);
                if (p.eatKw("FROM")) {
                    chars = first;
                    operand = try p.expr(0);
                } else {
                    if (explicit_mode) return error.SyntaxError;
                    operand = first;
                }
            }
            _ = try p.expect(.rparen);
            return p.new(.{ .trim = .{ .mode = mode, .chars = chars, .operand = operand } });
        }
        if (eq(name, "SUBSTRING")) {
            const s = try p.expr(0);
            var args: std.ArrayList(*const Expr) = .empty;
            try args.append(p.arena, s);
            if (p.eatKw("FROM")) {
                try args.append(p.arena, try p.expr(0));
                if (p.eatKw("FOR")) try args.append(p.arena, try p.expr(0));
            } else {
                _ = try p.expect(.comma);
                try args.append(p.arena, try p.expr(0));
                if (p.peek().tag == .comma) {
                    _ = p.next();
                    try args.append(p.arena, try p.expr(0));
                }
            }
            _ = try p.expect(.rparen);
            return p.new(.{ .call = .{ .func = .substring, .args = args.items } });
        }
        const Spec = struct { n: []const u8, f: ast.Func, min: usize, max: usize };
        const specs = [_]Spec{
            .{ .n = "LOWER", .f = .lower, .min = 1, .max = 1 },
            .{ .n = "UPPER", .f = .upper, .min = 1, .max = 1 },
            .{ .n = "CHAR_LENGTH", .f = .char_length, .min = 1, .max = 1 },
            .{ .n = "CHARACTER_LENGTH", .f = .char_length, .min = 1, .max = 1 },
            .{ .n = "COALESCE", .f = .coalesce, .min = 1, .max = max_list_items },
            .{ .n = "NULLIF", .f = .nullif, .min = 2, .max = 2 },
            .{ .n = "TO_TIMESTAMP", .f = .to_timestamp, .min = 1, .max = 1 },
            .{ .n = "TO_STRING", .f = .to_string, .min = 1, .max = 2 },
            .{ .n = "UTCNOW", .f = .utcnow, .min = 0, .max = 0 },
            .{ .n = "ABS", .f = .abs, .min = 1, .max = 1 },
        };
        for (specs) |sp| {
            if (eq(name, sp.n)) {
                const args = try p.exprList(.rparen);
                if (args.len < sp.min or args.len > sp.max) return error.SyntaxError;
                return p.new(.{ .call = .{ .func = sp.f, .args = args } });
            }
        }
        return error.UnknownFunction;
    }

    fn alias(p: *Parser) Error!?[]const u8 {
        if (p.eatKw("AS")) {
            const t = p.next();
            return switch (t.tag) {
                .ident => t.text,
                .quoted_ident => try p.unescape(t.text, '"'),
                else => error.SyntaxError,
            };
        }
        const t = p.peek();
        if (t.tag == .quoted_ident) {
            _ = p.next();
            return try p.unescape(t.text, '"');
        }
        if (t.tag == .ident and !isKw(t, "FROM") and !isKw(t, "WHERE") and !isKw(t, "LIMIT")) {
            _ = p.next();
            return t.text;
        }
        return null;
    }

    fn query(p: *Parser) Error!ast.Query {
        try p.expectKw("SELECT");
        var items: ?[]const ast.SelectItem = null;
        if (p.peek().tag == .star) {
            _ = p.next();
        } else {
            var list: std.ArrayList(ast.SelectItem) = .empty;
            p.allow_aggs = true;
            while (true) {
                if (list.items.len >= max_list_items) return error.TooManyItems;
                const e = try p.expr(0);
                try list.append(p.arena, .{ .expr = e, .alias = try p.alias() });
                if (p.peek().tag != .comma) break;
                _ = p.next();
            }
            p.allow_aggs = false;
            items = list.items;
            if (p.aggs.items.len > 0 and p.bare_path) return error.InvalidAggregate;
        }
        try p.expectKw("FROM");
        const src = p.next();
        const src_ok = (src.tag == .ident and std.ascii.eqlIgnoreCase(src.text, "S3Object")) or
            (src.tag == .quoted_ident and std.mem.eql(u8, src.text, "S3Object"));
        if (!src_ok) return error.SyntaxError;
        var steps: std.ArrayList(ast.Step) = .empty;
        try p.pathSteps(&steps);
        const from_alias = try p.alias();
        var where: ?*const Expr = null;
        if (p.eatKw("WHERE")) where = try p.expr(0);
        var limit: ?u64 = null;
        if (p.eatKw("LIMIT")) {
            const t = try p.expect(.int);
            limit = std.fmt.parseInt(u64, t.text, 10) catch return error.SyntaxError;
        }
        if (p.peek().tag == .semicolon) _ = p.next();
        if (p.peek().tag != .eof) return error.SyntaxError;
        return .{
            .items = items,
            .from_steps = steps.items,
            .alias = from_alias,
            .where = where,
            .limit = limit,
            .aggregates = p.aggs.items,
        };
    }
};

/// Parses `src`; all AST memory is allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, src: []const u8) Error!ast.Query {
    const toks = try lexer.tokenize(arena, src);
    var p: Parser = .{ .arena = arena, .toks = toks };
    return p.query();
}

test "parse basic query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try parse(arena.allocator(), "SELECT s._1 AS a, s.name n, UPPER(s.x) FROM S3Object s WHERE s._2 > 3 AND NOT s.b LIKE 'x%' LIMIT 5;");
    try std.testing.expectEqual(@as(usize, 3), q.items.?.len);
    try std.testing.expectEqualStrings("a", q.items.?[0].alias.?);
    try std.testing.expectEqualStrings("n", q.items.?[1].alias.?);
    try std.testing.expectEqualStrings("s", q.alias.?);
    try std.testing.expectEqual(@as(?u64, 5), q.limit);
    const w = q.where.?.binary;
    try std.testing.expectEqual(ast.BinaryOp.@"and", w.op);
    try std.testing.expectEqual(ast.UnaryOp.not, w.rhs.unary.op);
}

test "precedence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const q = try parse(arena.allocator(), "SELECT 1 + 2 * 3 - 4 FROM S3Object WHERE a = 1 OR b = 2 AND c NOT BETWEEN 1 AND 2");
    const e = q.items.?[0].expr.binary;
    try std.testing.expectEqual(ast.BinaryOp.sub, e.op);
    try std.testing.expectEqual(ast.BinaryOp.add, e.lhs.binary.op);
    try std.testing.expectEqual(ast.BinaryOp.mul, e.lhs.binary.rhs.binary.op);
    const w = q.where.?.binary;
    try std.testing.expectEqual(ast.BinaryOp.@"or", w.op);
    try std.testing.expect(w.rhs.binary.rhs.between.negated);
}

test "special forms and aggregates" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const q = try parse(a, "SELECT COUNT(*), SUM(CAST(s.x AS DECIMAL(10,2))), MAX(EXTRACT(YEAR FROM TO_TIMESTAMP(s.t))) FROM S3Object[*].items[*] AS s");
    try std.testing.expectEqual(@as(usize, 3), q.aggregates.len);
    try std.testing.expectEqual(@as(usize, 3), q.from_steps.len);
    _ = try parse(a, "SELECT TRIM(LEADING 'x' FROM s.a), TRIM(s.b), TRIM(BOTH FROM s.c), SUBSTRING(s.a FROM 2 FOR 3), SUBSTRING(s.a, 2), DATE_ADD(day, 1, UTCNOW()), DATE_DIFF(year, TO_TIMESTAMP('2000T'), UTCNOW()) FROM S3Object s");
    _ = try parse(a, "SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END, CASE a WHEN 1 THEN 2 END FROM S3Object WHERE a IN (1, 2, 3) AND b IS NOT NULL AND c LIKE 'a!%' ESCAPE '!'");
    try std.testing.expectError(error.InvalidAggregate, parse(a, "SELECT COUNT(*), s.a FROM S3Object s"));
    try std.testing.expectError(error.InvalidAggregate, parse(a, "SELECT * FROM S3Object WHERE COUNT(*) > 1"));
    try std.testing.expectError(error.InvalidAggregate, parse(a, "SELECT SUM(MAX(a)) FROM S3Object"));
    try std.testing.expectError(error.UnknownFunction, parse(a, "SELECT FOO(a) FROM S3Object"));
    try std.testing.expectError(error.SyntaxError, parse(a, "SELECT a FROM Other"));
    try std.testing.expectError(error.SyntaxError, parse(a, "SELECT a FROM S3Object LIMIT x"));
}

test "depth limit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("SELECT ");
    for (0..500) |_| try w.writeByte('(');
    try w.writeAll("1 FROM S3Object");
    try std.testing.expectError(error.ExpressionTooDeep, parse(arena.allocator(), w.buffered()));
    w.end = 0;
    try w.writeAll("SELECT ");
    for (0..500) |_| try w.writeAll("NOT ");
    try w.writeAll("1 FROM S3Object");
    try std.testing.expectError(error.ExpressionTooDeep, parse(arena.allocator(), w.buffered()));
}
