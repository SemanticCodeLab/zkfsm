//! Condition operators: parsing of operator names and values, and evaluation against a request.
const std = @import("std");
const wildcard = @import("wildcard.zig");
const context = @import("context.zig");

pub const Operator = enum {
    string_equals,
    string_not_equals,
    string_equals_ignore_case,
    string_not_equals_ignore_case,
    string_like,
    string_not_like,
    numeric_equals,
    numeric_not_equals,
    numeric_less_than,
    numeric_less_than_equals,
    numeric_greater_than,
    numeric_greater_than_equals,
    date_equals,
    date_not_equals,
    date_less_than,
    date_less_than_equals,
    date_greater_than,
    date_greater_than_equals,
    bool,
    binary_equals,
    ip_address,
    not_ip_address,
    arn_equals,
    arn_not_equals,
    arn_like,
    arn_not_like,
    null,

    const names = [_]struct { []const u8, Operator }{
        .{ "StringEquals", .string_equals },
        .{ "StringNotEquals", .string_not_equals },
        .{ "StringEqualsIgnoreCase", .string_equals_ignore_case },
        .{ "StringNotEqualsIgnoreCase", .string_not_equals_ignore_case },
        .{ "StringLike", .string_like },
        .{ "StringNotLike", .string_not_like },
        .{ "NumericEquals", .numeric_equals },
        .{ "NumericNotEquals", .numeric_not_equals },
        .{ "NumericLessThan", .numeric_less_than },
        .{ "NumericLessThanEquals", .numeric_less_than_equals },
        .{ "NumericGreaterThan", .numeric_greater_than },
        .{ "NumericGreaterThanEquals", .numeric_greater_than_equals },
        .{ "DateEquals", .date_equals },
        .{ "DateNotEquals", .date_not_equals },
        .{ "DateLessThan", .date_less_than },
        .{ "DateLessThanEquals", .date_less_than_equals },
        .{ "DateGreaterThan", .date_greater_than },
        .{ "DateGreaterThanEquals", .date_greater_than_equals },
        .{ "Bool", .bool },
        .{ "BinaryEquals", .binary_equals },
        .{ "IpAddress", .ip_address },
        .{ "NotIpAddress", .not_ip_address },
        .{ "ArnEquals", .arn_equals },
        .{ "ArnNotEquals", .arn_not_equals },
        .{ "ArnLike", .arn_like },
        .{ "ArnNotLike", .arn_not_like },
        .{ "Null", .null },
    };

    pub fn fromName(name: []const u8) ?Operator {
        for (names) |n| if (std.mem.eql(u8, n[0], name)) return n[1];
        return null;
    }

    /// Negated operators are true when no policy value matches.
    pub fn negated(op: Operator) bool {
        return switch (op) {
            .string_not_equals, .string_not_equals_ignore_case, .string_not_like => true,
            .numeric_not_equals, .date_not_equals, .not_ip_address => true,
            .arn_not_equals, .arn_not_like => true,
            else => false,
        };
    }

    /// Operators whose policy values may contain policy variables.
    pub fn allowsVariables(op: Operator) bool {
        return switch (op) {
            .string_equals, .string_not_equals, .string_equals_ignore_case => true,
            .string_not_equals_ignore_case, .string_like, .string_not_like => true,
            .arn_equals, .arn_not_equals, .arn_like, .arn_not_like => true,
            else => false,
        };
    }
};

pub const SetQualifier = enum { none, for_any_value, for_all_values };

pub const Condition = struct {
    op: Operator,
    set: SetQualifier = .none,
    if_exists: bool = false,
    key: []const u8,
    values: []const []const u8,
};

pub const Qualified = struct { op: Operator, set: SetQualifier, if_exists: bool };

/// Parses `ForAnyValue:StringLikeIfExists`-style operator names.
pub fn parseQualified(full: []const u8) ?Qualified {
    var name = full;
    var set: SetQualifier = .none;
    if (std.mem.startsWith(u8, name, "ForAnyValue:")) {
        set = .for_any_value;
        name = name["ForAnyValue:".len..];
    } else if (std.mem.startsWith(u8, name, "ForAllValues:")) {
        set = .for_all_values;
        name = name["ForAllValues:".len..];
    }
    if (Operator.fromName(name)) |op| return .{ .op = op, .set = set, .if_exists = false };
    if (!std.mem.endsWith(u8, name, "IfExists")) return null;
    const op = Operator.fromName(name[0 .. name.len - "IfExists".len]) orelse return null;
    if (op == .null) return null;
    return .{ .op = op, .set = set, .if_exists = true };
}

/// Checks a policy-side value at parse time so evaluation never sees malformed input.
pub fn validValue(op: Operator, v: []const u8) bool {
    return switch (op) {
        .numeric_equals, .numeric_not_equals, .numeric_less_than => parseNumber(v) != null,
        .numeric_less_than_equals, .numeric_greater_than, .numeric_greater_than_equals => parseNumber(v) != null,
        .date_equals, .date_not_equals, .date_less_than, .date_less_than_equals => parseDate(v) != null,
        .date_greater_than, .date_greater_than_equals => parseDate(v) != null,
        .bool, .null => std.ascii.eqlIgnoreCase(v, "true") or std.ascii.eqlIgnoreCase(v, "false"),
        .ip_address, .not_ip_address => Cidr.parse(v) != null,
        else => true,
    };
}

pub const Variables = enum { literal, expand };

/// Evaluates one condition. `vars` is `.expand` for policies with Version 2012-10-17.
pub fn evaluate(c: *const Condition, env: *context.Env, vars: Variables) bool {
    if (c.op == .null) {
        const absent = if (env.get(c.key)) |vs| vs.len == 0 else true;
        for (c.values) |v| {
            if (std.ascii.eqlIgnoreCase(v, "true") == absent) return true;
        }
        return false;
    }
    const req: []const []const u8 = env.get(c.key) orelse &.{};
    if (req.len == 0) {
        if (c.if_exists) return true;
        return switch (c.set) {
            .for_all_values => true,
            .for_any_value => false,
            .none => c.op.negated(),
        };
    }
    const all = switch (c.set) {
        .for_all_values => true,
        .for_any_value => false,
        .none => c.op.negated(),
    };
    for (req) |rv| {
        const ok = valueSatisfies(c, rv, env, vars);
        if (all and !ok) return false;
        if (!all and ok) return true;
    }
    return all;
}

fn valueSatisfies(c: *const Condition, rv: []const u8, env: *context.Env, vars: Variables) bool {
    var any = false;
    for (c.values) |pv| {
        const m = baseMatch(c.op, pv, rv, env, vars) orelse return false;
        if (m) {
            any = true;
            break;
        }
    }
    return if (c.op.negated()) !any else any;
}

/// Positive form of the operator. Null when the request value is not comparable.
fn baseMatch(op: Operator, pv: []const u8, rv: []const u8, env: *context.Env, vars: Variables) ?bool {
    var buf: [2048]u8 = undefined;
    const glob = switch (op) {
        .string_like, .string_not_like, .arn_equals, .arn_not_equals, .arn_like, .arn_not_like => true,
        else => false,
    };
    const exp: context.Expanded = if (vars == .expand and op.allowsVariables())
        context.expand(pv, env, glob, &buf) orelse return null
    else
        .{ .text = pv, .escaped = false };
    const p = exp.text;
    return switch (op) {
        .string_equals, .string_not_equals, .binary_equals => std.mem.eql(u8, p, rv),
        .string_equals_ignore_case, .string_not_equals_ignore_case => std.ascii.eqlIgnoreCase(p, rv),
        .string_like, .string_not_like => wildcard.match(p, rv, .{ .escaped = exp.escaped }),
        .arn_equals, .arn_not_equals, .arn_like, .arn_not_like => arnLike(p, rv, exp.escaped),
        .bool => std.ascii.eqlIgnoreCase(p, rv),
        .numeric_equals, .numeric_not_equals => cmpNum(p, rv, .eq),
        .numeric_less_than => cmpNum(p, rv, .lt),
        .numeric_less_than_equals => cmpNum(p, rv, .lte),
        .numeric_greater_than => cmpNum(p, rv, .gt),
        .numeric_greater_than_equals => cmpNum(p, rv, .gte),
        .date_equals, .date_not_equals => cmpDate(p, rv, .eq),
        .date_less_than => cmpDate(p, rv, .lt),
        .date_less_than_equals => cmpDate(p, rv, .lte),
        .date_greater_than => cmpDate(p, rv, .gt),
        .date_greater_than_equals => cmpDate(p, rv, .gte),
        .ip_address, .not_ip_address => blk: {
            const net = Cidr.parse(p) orelse break :blk null;
            const ip = Cidr.parse(rv) orelse break :blk null;
            break :blk net.contains(ip);
        },
        .null => null,
    };
}

/// Request value compared against policy value: `rv <op> pv`.
fn cmpNum(pv: []const u8, rv: []const u8, op: std.math.CompareOperator) ?bool {
    const a = parseNumber(rv) orelse return null;
    const b = parseNumber(pv) orelse return null;
    return std.math.compare(a, op, b);
}

fn cmpDate(pv: []const u8, rv: []const u8, op: std.math.CompareOperator) ?bool {
    const a = parseDate(rv) orelse return null;
    const b = parseDate(pv) orelse return null;
    return std.math.compare(a, op, b);
}

pub fn parseNumber(s: []const u8) ?f64 {
    if (s.len == 0 or s.len > 64) return null;
    const v = std.fmt.parseFloat(f64, s) catch return null;
    return if (std.math.isFinite(v)) v else null;
}

/// ArnLike: six colon-separated fields matched independently; the last field keeps its colons.
fn arnLike(pattern: []const u8, arn: []const u8, escaped: bool) bool {
    var pi = std.mem.splitScalar(u8, pattern, ':');
    var ai = std.mem.splitScalar(u8, arn, ':');
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const p = pi.next() orelse return false;
        const a = ai.next() orelse return false;
        if (!wildcard.match(p, a, .{ .escaped = escaped })) return false;
    }
    return wildcard.match(pi.rest(), ai.rest(), .{ .escaped = escaped });
}

/// ISO 8601 (`2024-01-02`, `2024-01-02T03:04:05Z`, fractional seconds, `+hh:mm` offsets)
/// or epoch seconds. Returns unix milliseconds.
pub fn parseDate(s: []const u8) ?i64 {
    if (s.len == 0 or s.len > 40) return null;
    if (std.fmt.parseInt(i64, s, 10)) |secs| {
        return std.math.mul(i64, secs, 1000) catch null;
    } else |_| {}
    if (s.len < 10 or s[4] != '-' or s[7] != '-') return null;
    const year = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    if (month < 1 or month > 12 or day < 1 or day > 31) return null;
    var ms: i64 = daysFromCivil(year, month, day) * std.time.ms_per_day;
    if (s.len == 10) return ms;
    if (s[10] != 'T' or s.len < 19 or s[13] != ':' or s[16] != ':') return null;
    const hh = std.fmt.parseInt(u8, s[11..13], 10) catch return null;
    const mm = std.fmt.parseInt(u8, s[14..16], 10) catch return null;
    const ss = std.fmt.parseInt(u8, s[17..19], 10) catch return null;
    if (hh > 23 or mm > 59 or ss > 60) return null;
    ms += (@as(i64, hh) * 3600 + @as(i64, mm) * 60 + ss) * 1000;
    var i: usize = 19;
    if (i < s.len and s[i] == '.') {
        i += 1;
        var frac: i64 = 0;
        var digits: usize = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
            if (digits < 3) frac = frac * 10 + (s[i] - '0');
            digits += 1;
        }
        if (digits == 0) return null;
        while (digits < 3) : (digits += 1) frac *= 10;
        ms += frac;
    }
    const tz = s[i..];
    if (tz.len == 0 or std.mem.eql(u8, tz, "Z")) return ms;
    if (tz.len != 6 or (tz[0] != '+' and tz[0] != '-') or tz[3] != ':') return null;
    const oh = std.fmt.parseInt(u8, tz[1..3], 10) catch return null;
    const om = std.fmt.parseInt(u8, tz[4..6], 10) catch return null;
    const off = (@as(i64, oh) * 60 + om) * 60 * 1000;
    return if (tz[0] == '+') ms - off else ms + off;
}

fn daysFromCivil(y0: i64, m: u8, d: u8) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// An IPv4 or IPv6 network; a bare address is a /32 or /128.
pub const Cidr = struct {
    bytes: [16]u8,
    v6: bool,
    prefix: u8,

    pub fn parse(s: []const u8) ?Cidr {
        if (s.len == 0 or s.len > 64) return null;
        const slash = std.mem.indexOfScalar(u8, s, '/');
        const host = s[0 .. slash orelse s.len];
        var out: Cidr = .{ .bytes = @splat(0), .v6 = false, .prefix = 0 };
        if (std.mem.indexOfScalar(u8, host, ':') != null) {
            const a = std.net.Ip6Address.parse(host, 0) catch return null;
            out.bytes = a.sa.addr;
            out.v6 = true;
        } else {
            const a = std.net.Ip4Address.parse(host, 0) catch return null;
            @memcpy(out.bytes[0..4], std.mem.asBytes(&a.sa.addr));
        }
        const max: u8 = if (out.v6) 128 else 32;
        out.prefix = max;
        if (slash) |i| {
            out.prefix = std.fmt.parseInt(u8, s[i + 1 ..], 10) catch return null;
            if (out.prefix > max) return null;
        }
        return out;
    }

    pub fn contains(net: Cidr, ip: Cidr) bool {
        if (net.v6 != ip.v6) return false;
        const full = net.prefix / 8;
        if (!std.mem.eql(u8, net.bytes[0..full], ip.bytes[0..full])) return false;
        const rem: u3 = @intCast(net.prefix % 8);
        if (rem == 0) return true;
        const mask: u8 = @as(u8, 0xff) << @intCast(8 - @as(u4, rem));
        return (net.bytes[full] & mask) == (ip.bytes[full] & mask);
    }
};

test "operator names" {
    const q = parseQualified("ForAllValues:StringLikeIfExists").?;
    try std.testing.expectEqual(Operator.string_like, q.op);
    try std.testing.expectEqual(SetQualifier.for_all_values, q.set);
    try std.testing.expect(q.if_exists);
    try std.testing.expect(parseQualified("NullIfExists") == null);
    try std.testing.expect(parseQualified("StringFoo") == null);
    try std.testing.expect(parseQualified("ForAnyValue:") == null);
}

test "cidr" {
    const Case = struct { net: []const u8, ip: []const u8, want: bool };
    const cases = [_]Case{
        .{ .net = "10.0.0.0/8", .ip = "10.255.1.2", .want = true },
        .{ .net = "10.0.0.0/8", .ip = "11.0.0.1", .want = false },
        .{ .net = "192.168.1.0/25", .ip = "192.168.1.127", .want = true },
        .{ .net = "192.168.1.0/25", .ip = "192.168.1.128", .want = false },
        .{ .net = "0.0.0.0/0", .ip = "8.8.8.8", .want = true },
        .{ .net = "1.2.3.4", .ip = "1.2.3.4", .want = true },
        .{ .net = "2001:db8::/32", .ip = "2001:db8:1::5", .want = true },
        .{ .net = "2001:db8::/32", .ip = "2001:db9::5", .want = false },
        .{ .net = "2001:db8::/32", .ip = "10.0.0.1", .want = false },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.want, Cidr.parse(c.net).?.contains(Cidr.parse(c.ip).?));
    }
    try std.testing.expect(Cidr.parse("10.0.0.0/33") == null);
    try std.testing.expect(Cidr.parse("nope") == null);
}

test "dates" {
    try std.testing.expectEqual(@as(?i64, 0), parseDate("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 86_400_000), parseDate("1970-01-02"));
    try std.testing.expectEqual(parseDate("2024-03-01T12:00:00Z"), parseDate("2024-03-01T13:00:00+01:00"));
    try std.testing.expectEqual(@as(?i64, 1_700_000_000_000), parseDate("1700000000"));
    try std.testing.expectEqual(parseDate("2023-11-14T22:13:20.000Z"), parseDate("1700000000"));
    try std.testing.expect(parseDate("2024-13-01") == null);
    try std.testing.expect(parseDate("garbage") == null);
}

fn evalWith(cond: Condition, entries: []const context.Entry) bool {
    const ctx: context.Context = .{ .entries = entries, .now_s = 1_700_000_000 };
    var env: context.Env = .{ .ctx = &ctx, .who = .{ .username = "alice" } };
    return evaluate(&cond, &env, .expand);
}

test "condition table" {
    const E = context.Entry;
    const Case = struct { name: []const u8, c: Condition, e: []const E, want: bool };
    const ip = [_]E{.{ .key = "aws:SourceIp", .values = &.{"10.1.2.3"} }};
    const tags = [_]E{.{ .key = "aws:TagKeys", .values = &.{ "env", "team" } }};
    const empty = [_]E{.{ .key = "aws:TagKeys", .values = &.{} }};
    const cases = [_]Case{
        .{ .name = "eq hit", .c = .{ .op = .string_equals, .key = "s3:prefix", .values = &.{ "a", "b" } }, .e = &.{.{ .key = "s3:prefix", .values = &.{"b"} }}, .want = true },
        .{ .name = "eq miss", .c = .{ .op = .string_equals, .key = "s3:prefix", .values = &.{"a"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"B"} }}, .want = false },
        .{ .name = "eq ic", .c = .{ .op = .string_equals_ignore_case, .key = "s3:prefix", .values = &.{"a"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"A"} }}, .want = true },
        .{ .name = "eq absent", .c = .{ .op = .string_equals, .key = "s3:prefix", .values = &.{"a"} }, .e = &.{}, .want = false },
        .{ .name = "not eq absent", .c = .{ .op = .string_not_equals, .key = "s3:prefix", .values = &.{"a"} }, .e = &.{}, .want = true },
        .{ .name = "not eq present", .c = .{ .op = .string_not_equals, .key = "s3:prefix", .values = &.{ "a", "b" } }, .e = &.{.{ .key = "s3:prefix", .values = &.{"b"} }}, .want = false },
        .{ .name = "like var", .c = .{ .op = .string_like, .key = "s3:prefix", .values = &.{"home/${aws:username}/*"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"home/alice/x"} }}, .want = true },
        .{ .name = "like var other user", .c = .{ .op = .string_like, .key = "s3:prefix", .values = &.{"home/${aws:username}/*"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"home/bob/x"} }}, .want = false },
        .{ .name = "not like", .c = .{ .op = .string_not_like, .key = "s3:prefix", .values = &.{"tmp/*"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"data/x"} }}, .want = true },
        .{ .name = "ifexists absent", .c = .{ .op = .string_equals, .if_exists = true, .key = "s3:x-amz-acl", .values = &.{"private"} }, .e = &.{}, .want = true },
        .{ .name = "ifexists present wrong", .c = .{ .op = .string_equals, .if_exists = true, .key = "s3:x-amz-acl", .values = &.{"private"} }, .e = &.{.{ .key = "s3:x-amz-acl", .values = &.{"public-read"} }}, .want = false },
        .{ .name = "num lt", .c = .{ .op = .numeric_less_than_equals, .key = "s3:max-keys", .values = &.{"100"} }, .e = &.{.{ .key = "s3:max-keys", .values = &.{"50"} }}, .want = true },
        .{ .name = "num gt", .c = .{ .op = .numeric_greater_than, .key = "s3:max-keys", .values = &.{"100"} }, .e = &.{.{ .key = "s3:max-keys", .values = &.{"50"} }}, .want = false },
        .{ .name = "num bad request", .c = .{ .op = .numeric_not_equals, .key = "s3:max-keys", .values = &.{"100"} }, .e = &.{.{ .key = "s3:max-keys", .values = &.{"lots"} }}, .want = false },
        .{ .name = "date now before", .c = .{ .op = .date_less_than, .key = "aws:CurrentTime", .values = &.{"2030-01-01T00:00:00Z"} }, .e = &.{}, .want = true },
        .{ .name = "date now after", .c = .{ .op = .date_greater_than, .key = "aws:CurrentTime", .values = &.{"2030-01-01T00:00:00Z"} }, .e = &.{}, .want = false },
        .{ .name = "bool", .c = .{ .op = .bool, .key = "aws:SecureTransport", .values = &.{"false"} }, .e = &.{.{ .key = "aws:SecureTransport", .values = &.{"FALSE"} }}, .want = true },
        .{ .name = "bool absent", .c = .{ .op = .bool, .key = "aws:SecureTransport", .values = &.{"false"} }, .e = &.{}, .want = false },
        .{ .name = "ip in", .c = .{ .op = .ip_address, .key = "aws:SourceIp", .values = &.{ "192.168.0.0/16", "10.0.0.0/8" } }, .e = &ip, .want = true },
        .{ .name = "not ip in", .c = .{ .op = .not_ip_address, .key = "aws:SourceIp", .values = &.{"10.0.0.0/8"} }, .e = &ip, .want = false },
        .{ .name = "not ip absent", .c = .{ .op = .not_ip_address, .key = "aws:SourceIp", .values = &.{"10.0.0.0/8"} }, .e = &.{}, .want = true },
        .{ .name = "arn like", .c = .{ .op = .arn_like, .key = "aws:PrincipalArn", .values = &.{"arn:aws:iam::*:user/al*"} }, .e = &.{.{ .key = "aws:PrincipalArn", .values = &.{"arn:aws:iam::123:user/alice"} }}, .want = true },
        .{ .name = "arn field boundary", .c = .{ .op = .arn_like, .key = "aws:PrincipalArn", .values = &.{"arn:aws:iam::1*"} }, .e = &.{.{ .key = "aws:PrincipalArn", .values = &.{"arn:aws:iam::123:user/alice"} }}, .want = false },
        .{ .name = "null true absent", .c = .{ .op = .null, .key = "s3:x-amz-acl", .values = &.{"true"} }, .e = &.{}, .want = true },
        .{ .name = "null false absent", .c = .{ .op = .null, .key = "s3:x-amz-acl", .values = &.{"false"} }, .e = &.{}, .want = false },
        .{ .name = "null false present", .c = .{ .op = .null, .key = "s3:x-amz-acl", .values = &.{"false"} }, .e = &.{.{ .key = "s3:x-amz-acl", .values = &.{"private"} }}, .want = true },
        .{ .name = "any hit", .c = .{ .op = .string_equals, .set = .for_any_value, .key = "aws:TagKeys", .values = &.{"team"} }, .e = &tags, .want = true },
        .{ .name = "all miss", .c = .{ .op = .string_equals, .set = .for_all_values, .key = "aws:TagKeys", .values = &.{"team"} }, .e = &tags, .want = false },
        .{ .name = "all hit", .c = .{ .op = .string_equals, .set = .for_all_values, .key = "aws:TagKeys", .values = &.{ "team", "env", "x" } }, .e = &tags, .want = true },
        .{ .name = "all on empty set", .c = .{ .op = .string_equals, .set = .for_all_values, .key = "aws:TagKeys", .values = &.{"team"} }, .e = &empty, .want = true },
        .{ .name = "all on absent key", .c = .{ .op = .string_equals, .set = .for_all_values, .key = "aws:TagKeys", .values = &.{"team"} }, .e = &.{}, .want = true },
        .{ .name = "any on empty set", .c = .{ .op = .string_equals, .set = .for_any_value, .key = "aws:TagKeys", .values = &.{"team"} }, .e = &empty, .want = false },
        .{ .name = "any not-eq", .c = .{ .op = .string_not_equals, .set = .for_any_value, .key = "aws:TagKeys", .values = &.{"env"} }, .e = &tags, .want = true },
        .{ .name = "all not-eq", .c = .{ .op = .string_not_equals, .set = .for_all_values, .key = "aws:TagKeys", .values = &.{"env"} }, .e = &tags, .want = false },
        .{ .name = "tag key", .c = .{ .op = .string_equals, .key = "s3:ExistingObjectTag/env", .values = &.{"prod"} }, .e = &.{.{ .key = "s3:ExistingObjectTag/env", .values = &.{"prod"} }}, .want = true },
        .{ .name = "missing var fails", .c = .{ .op = .string_equals, .key = "s3:prefix", .values = &.{"${aws:SourceIp}"} }, .e = &.{.{ .key = "s3:prefix", .values = &.{"x"} }}, .want = false },
    };
    for (cases) |c| {
        if (evalWith(c.c, c.e) != c.want) {
            std.debug.print("condition case failed: {s}\n", .{c.name});
            return error.TestUnexpectedResult;
        }
    }
}
