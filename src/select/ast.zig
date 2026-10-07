//! Parsed S3 Select query.
const std = @import("std");
const Value = @import("value.zig").Value;
const datetime = @import("datetime.zig");

pub const Step = union(enum) {
    field: struct { name: []const u8, quoted: bool },
    index: u64,
    wildcard,
};

pub const Path = struct { steps: []const Step };

pub const UnaryOp = enum { neg, not };
pub const BinaryOp = enum { @"or", @"and", eq, ne, lt, le, gt, ge, add, sub, mul, div, mod, concat };
pub const CastType = enum { int, float, decimal, string, bool, timestamp };
pub const AggKind = enum { count, sum, avg, min, max };
pub const IsWhat = enum { null, missing, true, false };
pub const TrimMode = enum { both, leading, trailing };

pub const Func = enum {
    lower,
    upper,
    char_length,
    substring,
    coalesce,
    nullif,
    to_timestamp,
    to_string,
    utcnow,
    abs,
};

pub const When = struct { cond: *const Expr, result: *const Expr };

pub const Expr = union(enum) {
    literal: Value,
    path: Path,
    unary: struct { op: UnaryOp, operand: *const Expr },
    binary: struct { op: BinaryOp, lhs: *const Expr, rhs: *const Expr },
    like: struct { operand: *const Expr, pattern: *const Expr, escape: ?*const Expr, negated: bool },
    between: struct { operand: *const Expr, low: *const Expr, high: *const Expr, negated: bool },
    in_list: struct { operand: *const Expr, items: []const *const Expr, negated: bool },
    is: struct { operand: *const Expr, what: IsWhat, negated: bool },
    cast: struct { operand: *const Expr, to: CastType },
    call: struct { func: Func, args: []const *const Expr },
    extract: struct { part: datetime.Part, operand: *const Expr },
    date_add: struct { part: datetime.Part, qty: *const Expr, ts: *const Expr },
    date_diff: struct { part: datetime.Part, a: *const Expr, b: *const Expr },
    trim: struct { mode: TrimMode, chars: ?*const Expr, operand: *const Expr },
    case: struct { operand: ?*const Expr, whens: []const When, @"else": ?*const Expr },
    /// arg == null means COUNT(*); slot indexes the aggregate state array.
    aggregate: struct { kind: AggKind, arg: ?*const Expr, slot: u32 },
};

pub const SelectItem = struct {
    expr: *const Expr,
    alias: ?[]const u8,
};

pub const Query = struct {
    /// null means SELECT *.
    items: ?[]const SelectItem,
    /// Path applied to each input document (after S3Object).
    from_steps: []const Step,
    alias: ?[]const u8,
    where: ?*const Expr,
    limit: ?u64,
    /// Aggregate nodes in slot order.
    aggregates: []const *const Expr,

    pub fn isAggregate(q: *const Query) bool {
        return q.aggregates.len > 0;
    }
};
