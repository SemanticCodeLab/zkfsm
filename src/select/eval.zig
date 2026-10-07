//! Expression evaluation with SQL three-valued logic.
const std = @import("std");
const ast = @import("ast.zig");
const datetime = @import("datetime.zig");
const value = @import("value.zig");
const Value = value.Value;
const Expr = ast.Expr;
const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    TypeMismatch,
    DivisionByZero,
    InvalidCast,
    InvalidTimestamp,
    Overflow,
    InvalidArgument,
    UnsupportedPath,
    AggregateMisuse,
};

pub const Env = struct {
    /// Per-row scratch; reset by the caller between rows.
    arena: Allocator,
    record: Value,
    alias: ?[]const u8,
    now: datetime.Timestamp,
    agg_results: ?[]const Value = null,
};

pub fn resolvePath(env: *const Env, path: ast.Path) Error!Value {
    var steps = path.steps;
    if (steps.len > 0 and steps[0] == .field and !steps[0].field.quoted) {
        const n = steps[0].field.name;
        const is_alias = if (env.alias) |a| std.ascii.eqlIgnoreCase(a, n) else false;
        if (is_alias or std.ascii.eqlIgnoreCase(n, "S3Object")) steps = steps[1..];
    }
    return walk(env.record, steps);
}

pub fn walk(start: Value, steps: []const ast.Step) Error!Value {
    var cur = start;
    for (steps) |s| {
        cur = switch (s) {
            .field => |f| switch (cur) {
                .object => |o| o.get(f.name, f.quoted) orelse .missing,
                else => .missing,
            },
            .index => |i| switch (cur) {
                .list => |l| if (i < l.len) l[@intCast(i)] else .missing,
                else => .missing,
            },
            .wildcard => return error.UnsupportedPath,
        };
    }
    return cur;
}

/// null = unknown.
fn truth(v: Value) Error!?bool {
    return switch (v) {
        .bool => |b| b,
        .null, .missing => null,
        .string => |s| value.parseBool(s) orelse error.TypeMismatch,
        else => error.TypeMismatch,
    };
}

fn fromTruth(t: ?bool) Value {
    return if (t) |b| .{ .bool = b } else .null;
}

/// WHERE semantics: only TRUE passes.
pub fn isTrue(env: *const Env, e: *const Expr) Error!bool {
    return (try truth(try eval(env, e))) orelse false;
}

fn number(v: Value) Error!value.Number {
    return value.toNumber(v) orelse error.TypeMismatch;
}

fn arith(op: ast.BinaryOp, a: Value, b: Value) Error!Value {
    if (a.isAbsent() or b.isAbsent()) return .null;
    const x = try number(a);
    const y = try number(b);
    if (x == .int and y == .int) {
        const i = x.int;
        const j = y.int;
        switch (op) {
            .add => if (std.math.add(i64, i, j)) |r| return .{ .int = r } else |_| {},
            .sub => if (std.math.sub(i64, i, j)) |r| return .{ .int = r } else |_| {},
            .mul => if (std.math.mul(i64, i, j)) |r| return .{ .int = r } else |_| {},
            .div => {
                if (j == 0) return error.DivisionByZero;
                if (std.math.divTrunc(i64, i, j)) |r| return .{ .int = r } else |_| {}
            },
            .mod => {
                if (j == 0) return error.DivisionByZero;
                if (j == -1) return .{ .int = 0 };
                return .{ .int = @rem(i, j) };
            },
            else => unreachable,
        }
    }
    const f = value.numToFloat(x);
    const g = value.numToFloat(y);
    return .{ .float = switch (op) {
        .add => f + g,
        .sub => f - g,
        .mul => f * g,
        .div => if (g == 0) return error.DivisionByZero else f / g,
        .mod => if (g == 0) return error.DivisionByZero else @rem(f, g),
        else => unreachable,
    } };
}

fn cmpOp(op: ast.BinaryOp, a: Value, b: Value) Value {
    if (op == .eq or op == .ne) {
        if (a.isAbsent() or b.isAbsent()) return .null;
        const o = value.compare(a, b) orelse return .{ .bool = op == .ne };
        return .{ .bool = (o == .eq) == (op == .eq) };
    }
    const o = value.compare(a, b) orelse return .null;
    return .{ .bool = switch (op) {
        .lt => o == .lt,
        .le => o != .gt,
        .gt => o == .gt,
        .ge => o != .lt,
        else => unreachable,
    } };
}

fn text(env: *const Env, v: Value) Error![]const u8 {
    return switch (v) {
        .string => |s| s,
        .list, .object => error.TypeMismatch,
        else => blk: {
            var aw: std.Io.Writer.Allocating = .init(env.arena);
            value.writeText(v, &aw.writer) catch return error.OutOfMemory;
            break :blk aw.written();
        },
    };
}

fn cpLen(b: u8) usize {
    return std.unicode.utf8ByteSequenceLength(b) catch 1;
}

/// SQL LIKE with % and _ (codepoint-aware) and optional escape byte.
pub fn likeMatch(s: []const u8, p: []const u8, esc: ?u8) bool {
    var si: usize = 0;
    var pi: usize = 0;
    var star_pi: ?usize = null;
    var star_si: usize = 0;
    while (si < s.len) {
        if (pi < p.len) {
            const c = p[pi];
            if (esc != null and c == esc.? and pi + 1 < p.len) {
                if (p[pi + 1] == s[si]) {
                    pi += 2;
                    si += 1;
                    continue;
                }
            } else if (c == '%') {
                star_pi = pi;
                pi += 1;
                star_si = si;
                continue;
            } else if (c == '_') {
                pi += 1;
                si = @min(s.len, si + cpLen(s[si]));
                continue;
            } else if (c == s[si]) {
                pi += 1;
                si += 1;
                continue;
            }
        }
        if (star_pi) |sp| {
            pi = sp + 1;
            star_si = @min(s.len, star_si + cpLen(s[star_si]));
            si = star_si;
            continue;
        }
        return false;
    }
    while (pi < p.len and p[pi] == '%') pi += 1;
    return pi == p.len;
}

fn toInt(v: Value) Error!i64 {
    return switch (v) {
        .int => |i| i,
        .float => |f| floatToInt(f),
        .bool => |b| @intFromBool(b),
        .string => |s| blk: {
            const n = value.parseNumber(s) orelse return error.InvalidCast;
            break :blk switch (n) {
                .int => |i| i,
                .float => |f| try floatToInt(f),
            };
        },
        else => error.InvalidCast,
    };
}

fn floatToInt(f: f64) Error!i64 {
    if (std.math.isNan(f) or std.math.isInf(f)) return error.InvalidCast;
    const t = @trunc(f);
    if (t < -9.223372036854775808e18 or t >= 9.223372036854775808e18) return error.Overflow;
    return @intFromFloat(t);
}

pub fn cast(env: *const Env, v: Value, to: ast.CastType) Error!Value {
    if (v.isAbsent()) return v;
    return switch (to) {
        .int => .{ .int = try toInt(v) },
        .float, .decimal => switch (v) {
            .int => |i| .{ .float = @floatFromInt(i) },
            .float => v,
            .bool => |b| .{ .float = if (b) 1 else 0 },
            .string => |s| .{ .float = value.numToFloat(value.parseNumber(s) orelse return error.InvalidCast) },
            else => error.InvalidCast,
        },
        .string => .{ .string = text(env, v) catch return error.InvalidCast },
        .bool => switch (v) {
            .bool => v,
            .int => |i| .{ .bool = i != 0 },
            .float => |f| .{ .bool = f != 0 },
            .string => |s| .{ .bool = value.parseBool(s) orelse return error.InvalidCast },
            else => error.InvalidCast,
        },
        .timestamp => switch (v) {
            .timestamp => v,
            .string => |s| .{ .timestamp = datetime.parse(s) catch return error.InvalidTimestamp },
            else => error.InvalidCast,
        },
    };
}

fn timestampArg(v: Value) Error!?datetime.Timestamp {
    return switch (v) {
        .null, .missing => null,
        .timestamp => |t| t,
        .string => |s| datetime.parse(s) catch error.InvalidTimestamp,
        else => error.TypeMismatch,
    };
}

fn substring(s: []const u8, start: i64, len: ?i64) Error![]const u8 {
    if (len) |l| if (l < 0) return error.InvalidArgument;
    // Codepoint positions [from, to) in 1-based SQL coordinates.
    const from: i64 = @max(start, 1);
    const to: i64 = if (len) |l| (std.math.add(i64, start, l) catch std.math.maxInt(i64)) else std.math.maxInt(i64);
    if (to <= from) return s[0..0];
    var pos: i64 = 1;
    var i: usize = 0;
    var begin: ?usize = null;
    while (i < s.len) {
        if (pos == from) begin = i;
        if (pos == to) break;
        i = @min(s.len, i + cpLen(s[i]));
        pos += 1;
    }
    const b = begin orelse return s[0..0];
    return s[b..i];
}

fn trimSet(s: []const u8, set: []const u8, mode: ast.TrimMode) []const u8 {
    var a: usize = 0;
    var b: usize = s.len;
    if (mode != .trailing) while (a < b and std.mem.indexOfScalar(u8, set, s[a]) != null) : (a += 1) {};
    if (mode != .leading) while (b > a and std.mem.indexOfScalar(u8, set, s[b - 1]) != null) : (b -= 1) {};
    return s[a..b];
}

fn mapAscii(env: *const Env, s: []const u8, upper: bool) Error![]const u8 {
    const out = try env.arena.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = if (upper) std.ascii.toUpper(c) else std.ascii.toLower(c);
    return out;
}

/// TO_STRING pattern subset: y M d H h m s S a X/x n and 'quoted' literals.
fn formatTimestamp(env: *const Env, ts: datetime.Timestamp, pat: []const u8) Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(env.arena);
    const w = &aw.writer;
    const f = datetime.fields(ts);
    var i: usize = 0;
    while (i < pat.len) {
        const c = pat[i];
        var n: usize = 1;
        while (i + n < pat.len and pat[i + n] == c) n += 1;
        const r = switch (c) {
            'y' => if (n == 2) w.print("{d:0>2}", .{@as(u64, @intCast(@mod(f.year, 100)))}) else w.print("{d:0>[1]}", .{ @as(u64, @intCast(@max(f.year, 0))), n }),
            'M' => w.print("{d:0>[1]}", .{ f.month, n }),
            'd' => w.print("{d:0>[1]}", .{ f.day, n }),
            'H' => w.print("{d:0>[1]}", .{ f.hour, n }),
            'h' => w.print("{d:0>[1]}", .{ if (f.hour % 12 == 0) 12 else f.hour % 12, n }),
            'm' => w.print("{d:0>[1]}", .{ f.minute, n }),
            's' => w.print("{d:0>[1]}", .{ f.second, n }),
            'a' => w.writeAll(if (f.hour < 12) "AM" else "PM"),
            'n' => w.print("{d}", .{@as(u64, f.micro) * 1000}),
            'S' => blk: {
                var buf: [9]u8 = undefined;
                _ = std.fmt.bufPrint(&buf, "{d:0>9}", .{@as(u64, f.micro) * 1000}) catch unreachable;
                break :blk w.writeAll(buf[0..@min(n, 9)]);
            },
            'X', 'x' => blk: {
                if (c == 'X' and ts.offset_min == 0) break :blk w.writeAll("Z");
                const off: u32 = @abs(ts.offset_min);
                const sign: u8 = if (ts.offset_min < 0) '-' else '+';
                break :blk if (n == 1)
                    w.print("{c}{d:0>2}", .{ sign, off / 60 })
                else if (n == 2)
                    w.print("{c}{d:0>2}{d:0>2}", .{ sign, off / 60, off % 60 })
                else
                    w.print("{c}{d:0>2}:{d:0>2}", .{ sign, off / 60, off % 60 });
            },
            '\'' => blk: {
                const end = std.mem.indexOfScalarPos(u8, pat, i + 1, '\'') orelse return error.InvalidArgument;
                n = end - i + 1;
                break :blk w.writeAll(if (end == i + 1) "'" else pat[i + 1 .. end]);
            },
            else => blk: {
                if (std.ascii.isAlphabetic(c)) return error.InvalidArgument;
                break :blk w.writeAll(pat[i .. i + n]);
            },
        };
        r catch return error.OutOfMemory;
        i += n;
    }
    return aw.written();
}

fn callFunc(env: *const Env, func: ast.Func, args: []const *const Expr) Error!Value {
    switch (func) {
        .utcnow => return .{ .timestamp = env.now },
        .coalesce => {
            for (args) |a| {
                const v = try eval(env, a);
                if (!v.isAbsent()) return v;
            }
            return .null;
        },
        .nullif => {
            const a = try eval(env, args[0]);
            const b = try eval(env, args[1]);
            if (a.isAbsent()) return a;
            if (value.compare(a, b)) |o| if (o == .eq) return .null;
            return a;
        },
        else => {},
    }
    const a = try eval(env, args[0]);
    if (a.isAbsent()) return .null;
    switch (func) {
        .lower, .upper => return .{ .string = try mapAscii(env, try text(env, a), func == .upper) },
        .char_length => {
            const s = try text(env, a);
            return .{ .int = @intCast(std.unicode.utf8CountCodepoints(s) catch s.len) };
        },
        .substring => {
            const s = try text(env, a);
            const st = try eval(env, args[1]);
            if (st.isAbsent()) return .null;
            var len: ?i64 = null;
            if (args.len == 3) {
                const l = try eval(env, args[2]);
                if (l.isAbsent()) return .null;
                len = toInt(l) catch return error.TypeMismatch;
            }
            return .{ .string = try substring(s, toInt(st) catch return error.TypeMismatch, len) };
        },
        .to_timestamp => return .{ .timestamp = (try timestampArg(a)).? },
        .to_string => {
            if (args.len == 1) return .{ .string = try text(env, a) };
            const ts = (try timestampArg(a)).?;
            const pat = try eval(env, args[1]);
            if (pat != .string) return error.TypeMismatch;
            return .{ .string = try formatTimestamp(env, ts, pat.string) };
        },
        .abs => return switch (try number(a)) {
            .int => |i| if (i == std.math.minInt(i64)) .{ .float = 9.223372036854775808e18 } else .{ .int = @intCast(@abs(i)) },
            .float => |f| .{ .float = @abs(f) },
        },
        .utcnow, .coalesce, .nullif => unreachable,
    }
}

pub fn eval(env: *const Env, e: *const Expr) Error!Value {
    switch (e.*) {
        .literal => |v| return v,
        .path => |p| return resolvePath(env, p),
        .unary => |u| {
            const v = try eval(env, u.operand);
            return switch (u.op) {
                .not => fromTruth(if (try truth(v)) |b| !b else null),
                .neg => arith(.sub, .{ .int = 0 }, v),
            };
        },
        .binary => |b| switch (b.op) {
            .@"and" => {
                const l = try truth(try eval(env, b.lhs));
                if (l) |x| if (!x) return .{ .bool = false };
                const r = try truth(try eval(env, b.rhs));
                if (r) |y| if (!y) return .{ .bool = false };
                return if (l == null or r == null) .null else .{ .bool = true };
            },
            .@"or" => {
                const l = try truth(try eval(env, b.lhs));
                if (l) |x| if (x) return .{ .bool = true };
                const r = try truth(try eval(env, b.rhs));
                if (r) |y| if (y) return .{ .bool = true };
                return if (l == null or r == null) .null else .{ .bool = false };
            },
            .eq, .ne, .lt, .le, .gt, .ge => return cmpOp(b.op, try eval(env, b.lhs), try eval(env, b.rhs)),
            .add, .sub, .mul, .div, .mod => return arith(b.op, try eval(env, b.lhs), try eval(env, b.rhs)),
            .concat => {
                const l = try eval(env, b.lhs);
                const r = try eval(env, b.rhs);
                if (l.isAbsent() or r.isAbsent()) return .null;
                return .{ .string = try std.mem.concat(env.arena, u8, &.{ try text(env, l), try text(env, r) }) };
            },
        },
        .like => |l| {
            const v = try eval(env, l.operand);
            const p = try eval(env, l.pattern);
            if (v.isAbsent() or p.isAbsent()) return .null;
            var esc: ?u8 = null;
            if (l.escape) |ee| {
                const ev = try eval(env, ee);
                if (ev != .string or ev.string.len != 1) return error.InvalidArgument;
                esc = ev.string[0];
            }
            const m = likeMatch(try text(env, v), try text(env, p), esc);
            return .{ .bool = m != l.negated };
        },
        .between => |bt| {
            const v = try eval(env, bt.operand);
            const lo = cmpOp(.ge, v, try eval(env, bt.low));
            const hi = cmpOp(.le, v, try eval(env, bt.high));
            if (lo == .null or hi == .null) return .null;
            return .{ .bool = (lo.bool and hi.bool) != bt.negated };
        },
        .in_list => |in| {
            const v = try eval(env, in.operand);
            if (v.isAbsent()) return .null;
            var unknown = false;
            for (in.items) |item| {
                const r = cmpOp(.eq, v, try eval(env, item));
                if (r == .null) {
                    unknown = true;
                } else if (r.bool) return .{ .bool = !in.negated };
            }
            if (unknown) return .null;
            return .{ .bool = in.negated };
        },
        .is => |is| {
            const v = try eval(env, is.operand);
            const r = switch (is.what) {
                .null => v.isAbsent(),
                .missing => v == .missing,
                .true => v == .bool and v.bool,
                .false => v == .bool and !v.bool,
            };
            return .{ .bool = r != is.negated };
        },
        .cast => |c| return cast(env, try eval(env, c.operand), c.to),
        .call => |c| return callFunc(env, c.func, c.args),
        .extract => |x| {
            const ts = try timestampArg(try eval(env, x.operand)) orelse return .null;
            return .{ .int = datetime.extract(x.part, ts) };
        },
        .date_add => |d| {
            const q = try eval(env, d.qty);
            const ts = try timestampArg(try eval(env, d.ts)) orelse return .null;
            if (q.isAbsent()) return .null;
            const n = toInt(q) catch return error.TypeMismatch;
            return .{ .timestamp = datetime.add(ts, d.part, n) catch |err| return switch (err) {
                error.Overflow => error.Overflow,
                error.InvalidTimestamp => error.InvalidTimestamp,
            } };
        },
        .date_diff => |d| {
            const a = try timestampArg(try eval(env, d.a)) orelse return .null;
            const b = try timestampArg(try eval(env, d.b)) orelse return .null;
            return .{ .int = datetime.diff(d.part, a, b) catch return error.InvalidArgument };
        },
        .trim => |t| {
            const v = try eval(env, t.operand);
            if (v.isAbsent()) return .null;
            var set: []const u8 = " ";
            if (t.chars) |ce| {
                const cv = try eval(env, ce);
                if (cv.isAbsent()) return .null;
                set = try text(env, cv);
            }
            return .{ .string = trimSet(try text(env, v), set, t.mode) };
        },
        .case => |c| {
            const subject = if (c.operand) |o| try eval(env, o) else null;
            for (c.whens) |w| {
                const hit = if (subject) |s| blk: {
                    const r = cmpOp(.eq, s, try eval(env, w.cond));
                    break :blk r == .bool and r.bool;
                } else try isTrue(env, w.cond);
                if (hit) return eval(env, w.result);
            }
            return if (c.@"else") |el| eval(env, el) else .null;
        },
        .aggregate => |a| {
            const res = env.agg_results orelse return error.AggregateMisuse;
            return res[a.slot];
        },
    }
}

pub const AggState = struct {
    count: u64 = 0,
    int_sum: i64 = 0,
    float_sum: f64 = 0,
    use_float: bool = false,
    extreme: Value = .null,
    /// Owns string bytes for MIN/MAX so they outlive the row arena.
    extreme_buf: std.ArrayList(u8) = .empty,

    pub fn deinit(s: *AggState, gpa: Allocator) void {
        s.extreme_buf.deinit(gpa);
    }

    pub fn update(s: *AggState, gpa: Allocator, env: *const Env, node: *const Expr) Error!void {
        const a = node.aggregate;
        const arg = a.arg orelse {
            s.count += 1;
            return;
        };
        const v = try eval(env, arg);
        if (v.isAbsent()) return;
        s.count += 1;
        switch (a.kind) {
            .count => {},
            .sum, .avg => switch (try number(v)) {
                .int => |i| {
                    if (std.math.add(i64, s.int_sum, i)) |r| {
                        s.int_sum = r;
                    } else |_| {
                        s.float_sum += @as(f64, @floatFromInt(s.int_sum)) + @as(f64, @floatFromInt(i));
                        s.int_sum = 0;
                        s.use_float = true;
                    }
                },
                .float => |f| {
                    s.float_sum += f;
                    s.use_float = true;
                },
            },
            .min, .max => {
                var cand = v;
                if (cand == .string) {
                    // CSV cells are text; compare numerically when they parse.
                    if (value.parseNumber(cand.string)) |n| cand = switch (n) {
                        .int => |i| .{ .int = i },
                        .float => |f| .{ .float = f },
                    };
                }
                if (cand == .list or cand == .object) return error.TypeMismatch;
                if (s.extreme != .null) {
                    const o = value.compare(cand, s.extreme) orelse return error.TypeMismatch;
                    const better = if (a.kind == .min) o == .lt else o == .gt;
                    if (!better) return;
                }
                if (cand == .string) {
                    s.extreme_buf.clearRetainingCapacity();
                    try s.extreme_buf.appendSlice(gpa, cand.string);
                    cand = .{ .string = s.extreme_buf.items };
                }
                s.extreme = cand;
            },
        }
    }

    pub fn result(s: *const AggState, kind: ast.AggKind) Value {
        return switch (kind) {
            .count => .{ .int = @intCast(@min(s.count, std.math.maxInt(i64))) },
            .sum => if (s.count == 0) .null else if (s.use_float) .{ .float = s.float_sum + @as(f64, @floatFromInt(s.int_sum)) } else .{ .int = s.int_sum },
            .avg => if (s.count == 0) .null else .{ .float = (s.float_sum + @as(f64, @floatFromInt(s.int_sum))) / @as(f64, @floatFromInt(s.count)) },
            .min, .max => s.extreme,
        };
    }
};

const parser = @import("parser.zig");

fn evalStr(arena: Allocator, sql_expr: []const u8, rec: Value) !Value {
    var buf: [512]u8 = undefined;
    const q = try parser.parse(arena, try std.fmt.bufPrint(&buf, "SELECT {s} FROM S3Object s", .{sql_expr}));
    const env: Env = .{ .arena = arena, .record = rec, .alias = q.alias, .now = .{ .micros = 0 } };
    return eval(&env, q.items.?[0].expr);
}

test "eval scalars" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rec: Value = .{ .object = .{
        .keys = &.{ "name", "age", "tags" },
        .values = &.{ .{ .string = "Ünïcode Name" }, .{ .string = "42" }, .{ .list = &.{ .{ .int = 7 }, .{ .int = 8 } } } },
        .positional = true,
    } };
    try std.testing.expectEqual(@as(i64, 7), (try evalStr(a, "1 + 2 * 3", rec)).int);
    try std.testing.expectEqual(@as(i64, 43), (try evalStr(a, "CAST(s.age AS INT) + 1", rec)).int);
    try std.testing.expectEqual(@as(i64, 84), (try evalStr(a, "s._2 * 2", rec)).int);
    try std.testing.expectEqual(@as(i64, 8), (try evalStr(a, "s.tags[1]", rec)).int);
    try std.testing.expectEqual(Value.missing, try evalStr(a, "s.nope", rec));
    try std.testing.expectEqualStrings("ÜNïCODE NAME", (try evalStr(a, "UPPER(s.name)", rec)).string);
    try std.testing.expectEqual(@as(i64, 12), (try evalStr(a, "CHAR_LENGTH(s.name)", rec)).int);
    try std.testing.expectEqualStrings("nïc", (try evalStr(a, "SUBSTRING(s.name, 2, 3)", rec)).string);
    try std.testing.expectEqualStrings("Ü", (try evalStr(a, "SUBSTRING(s.name FROM -1 FOR 3)", rec)).string);
    try std.testing.expectEqualStrings("ab", (try evalStr(a, "TRIM('  ab  ')", rec)).string);
    try std.testing.expectEqualStrings("abxx", (try evalStr(a, "TRIM(LEADING 'x' FROM 'xxabxx')", rec)).string);
    try std.testing.expect((try evalStr(a, "s.name LIKE '_n%Name'", rec)).bool);
    try std.testing.expect((try evalStr(a, "'a%b' LIKE 'a!%b' ESCAPE '!'", rec)).bool);
    try std.testing.expect(!(try evalStr(a, "'axb' LIKE 'a!%b' ESCAPE '!'", rec)).bool);
    try std.testing.expect((try evalStr(a, "s.age BETWEEN 40 AND 50", rec)).bool);
    try std.testing.expect((try evalStr(a, "s.age IN (1, 42)", rec)).bool);
    try std.testing.expect((try evalStr(a, "s.nope IS MISSING AND s.nope IS NULL", rec)).bool);
    try std.testing.expectEqual(Value.null, try evalStr(a, "NULL AND TRUE", rec));
    try std.testing.expect(!(try evalStr(a, "NULL AND FALSE", rec)).bool);
    try std.testing.expect((try evalStr(a, "NULL OR TRUE", rec)).bool);
    try std.testing.expectEqualStrings("big", (try evalStr(a, "CASE WHEN s.age > 10 THEN 'big' ELSE 'small' END", rec)).string);
    try std.testing.expectEqual(@as(i64, 2020), (try evalStr(a, "EXTRACT(YEAR FROM TO_TIMESTAMP('2020-05-06T'))", rec)).int);
    try std.testing.expectEqual(@as(i64, 3), (try evalStr(a, "DATE_DIFF(day, TO_TIMESTAMP('2020-05-06T'), DATE_ADD(day, 3, TO_TIMESTAMP('2020-05-06T')))", rec)).int);
    try std.testing.expectEqualStrings("2020/05/06 07:08", (try evalStr(a, "TO_STRING(TO_TIMESTAMP('2020-05-06T07:08Z'), 'yyyy/MM/dd HH:mm')", rec)).string);
    try std.testing.expectEqualStrings("a1", (try evalStr(a, "'a' || 1", rec)).string);
    try std.testing.expectEqual(@as(f64, 2.5), (try evalStr(a, "5 / 2.0", rec)).float);
    try std.testing.expectEqual(@as(i64, 2), (try evalStr(a, "5 / 2", rec)).int);
    try std.testing.expectError(error.DivisionByZero, evalStr(a, "1 / 0", rec));
    try std.testing.expectError(error.TypeMismatch, evalStr(a, "'x' + 1", rec));
    try std.testing.expectError(error.InvalidCast, evalStr(a, "CAST('x' AS INT)", rec));
    try std.testing.expectEqual(@as(f64, 9.223372036854775807e18 + 1), (try evalStr(a, "9223372036854775807 + 1", rec)).float);
}

test "like edge cases" {
    try std.testing.expect(likeMatch("", "%", null));
    try std.testing.expect(!likeMatch("", "_", null));
    try std.testing.expect(likeMatch("abcabc", "%abc", null));
    try std.testing.expect(likeMatch("aXbXc", "a%b%c", null));
    try std.testing.expect(!likeMatch("abc", "a%d", null));
    try std.testing.expect(likeMatch("a!", "a!", '!'));
}
