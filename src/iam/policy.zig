//! IAM policy document model and JSON parser. Policies are user input, so every
//! dimension (bytes, nesting, statements, list lengths, string lengths) is bounded.
const std = @import("std");
const condition = @import("condition.zig");

pub const Condition = condition.Condition;

pub const limits = struct {
    pub const max_doc_bytes = 20 * 1024;
    pub const max_depth = 8;
    pub const max_statements = 128;
    pub const max_list = 256;
    pub const max_string = 1024;
    pub const max_conditions = 64;
};

pub const ParseError = error{
    OutOfMemory,
    PolicyTooLarge,
    PolicyTooDeep,
    MalformedJson,
    UnsupportedVersion,
    MalformedStatement,
    InvalidEffect,
    InvalidPrincipal,
    InvalidCondition,
    LimitExceeded,
};

pub const Version = enum {
    /// Policy variables are treated as literal text.
    v2008_10_17,
    v2012_10_17,
};

pub const Effect = enum { allow, deny };

pub const PrincipalKind = enum { account, service, federated, canonical_user };

pub const PrincipalValue = struct { kind: PrincipalKind, value: []const u8 };

/// `"Principal": "*"` sets `any`; the object form fills `values`.
pub const Principal = struct {
    any: bool = false,
    values: []const PrincipalValue = &.{},
};

pub const Statement = struct {
    sid: []const u8 = "",
    effect: Effect,
    principal: ?Principal = null,
    not_principal: bool = false,
    actions: []const []const u8,
    not_action: bool = false,
    /// Null when the statement has neither Resource nor NotResource (matches every resource).
    resources: ?[]const []const u8 = null,
    not_resource: bool = false,
    conditions: []const Condition = &.{},
};

pub const Policy = struct {
    arena: std.heap.ArenaAllocator,
    version: Version,
    id: []const u8,
    statements: []const Statement,

    pub fn deinit(self: *Policy) void {
        self.arena.deinit();
    }
};

const Value = std.json.Value;

pub fn parse(gpa: std.mem.Allocator, doc: []const u8) ParseError!Policy {
    if (doc.len > limits.max_doc_bytes) return error.PolicyTooLarge;
    if (nestingDepth(doc) > limits.max_depth) return error.PolicyTooDeep;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const root = std.json.parseFromSliceLeaky(Value, a, doc, .{
        .parse_numbers = false,
        .max_value_len = limits.max_doc_bytes,
    }) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedJson,
    };
    const obj = switch (root) {
        .object => |o| o,
        else => return error.MalformedJson,
    };
    var version: Version = .v2008_10_17;
    var id: []const u8 = "";
    var stmts: ?Value = null;
    var it = obj.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        if (std.mem.eql(u8, k, "Version")) {
            const v = try str(kv.value_ptr.*);
            version = if (std.mem.eql(u8, v, "2012-10-17"))
                .v2012_10_17
            else if (std.mem.eql(u8, v, "2008-10-17"))
                .v2008_10_17
            else
                return error.UnsupportedVersion;
        } else if (std.mem.eql(u8, k, "Id")) {
            id = try str(kv.value_ptr.*);
        } else if (std.mem.eql(u8, k, "Statement")) {
            stmts = kv.value_ptr.*;
        } else return error.MalformedStatement;
    }
    const raw = stmts orelse return error.MalformedStatement;
    const items: []const Value = switch (raw) {
        .array => |arr| arr.items,
        .object => (&raw)[0..1],
        else => return error.MalformedStatement,
    };
    if (items.len == 0) return error.MalformedStatement;
    if (items.len > limits.max_statements) return error.LimitExceeded;
    const out = try a.alloc(Statement, items.len);
    for (items, out) |item, *s| s.* = try parseStatement(a, item);
    return .{ .arena = arena, .version = version, .id = id, .statements = out };
}

fn parseStatement(a: std.mem.Allocator, v: Value) ParseError!Statement {
    const obj = switch (v) {
        .object => |o| o,
        else => return error.MalformedStatement,
    };
    var effect: ?Effect = null;
    var s: Statement = .{ .effect = .deny, .actions = &.{} };
    var have_action = false;
    var have_principal = false;
    var it = obj.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        const val = kv.value_ptr.*;
        if (std.mem.eql(u8, k, "Sid")) {
            s.sid = try str(val);
        } else if (std.mem.eql(u8, k, "Effect")) {
            const e = try str(val);
            effect = if (std.mem.eql(u8, e, "Allow")) .allow else if (std.mem.eql(u8, e, "Deny")) .deny else return error.InvalidEffect;
        } else if (std.mem.eql(u8, k, "Action") or std.mem.eql(u8, k, "NotAction")) {
            if (have_action) return error.MalformedStatement;
            have_action = true;
            s.not_action = k[0] == 'N';
            s.actions = try strList(a, val);
        } else if (std.mem.eql(u8, k, "Resource") or std.mem.eql(u8, k, "NotResource")) {
            if (s.resources != null) return error.MalformedStatement;
            s.not_resource = k[0] == 'N';
            s.resources = try strList(a, val);
        } else if (std.mem.eql(u8, k, "Principal") or std.mem.eql(u8, k, "NotPrincipal")) {
            if (have_principal) return error.MalformedStatement;
            have_principal = true;
            s.not_principal = k[0] == 'N';
            s.principal = try parsePrincipal(a, val);
        } else if (std.mem.eql(u8, k, "Condition")) {
            s.conditions = try parseConditions(a, val);
        } else return error.MalformedStatement;
    }
    s.effect = effect orelse return error.InvalidEffect;
    if (!have_action or s.actions.len == 0) return error.MalformedStatement;
    return s;
}

fn parsePrincipal(a: std.mem.Allocator, v: Value) ParseError!Principal {
    switch (v) {
        .string => |s| {
            if (!std.mem.eql(u8, s, "*")) return error.InvalidPrincipal;
            return .{ .any = true };
        },
        .object => |o| {
            var list: std.ArrayList(PrincipalValue) = .empty;
            var it = o.iterator();
            while (it.next()) |kv| {
                const k = kv.key_ptr.*;
                const kind: PrincipalKind = if (std.mem.eql(u8, k, "AWS"))
                    .account
                else if (std.mem.eql(u8, k, "Service"))
                    .service
                else if (std.mem.eql(u8, k, "Federated"))
                    .federated
                else if (std.mem.eql(u8, k, "CanonicalUser"))
                    .canonical_user
                else
                    return error.InvalidPrincipal;
                for (try strList(a, kv.value_ptr.*)) |s| {
                    if (list.items.len >= limits.max_list) return error.LimitExceeded;
                    try list.append(a, .{ .kind = kind, .value = s });
                }
            }
            if (list.items.len == 0) return error.InvalidPrincipal;
            return .{ .values = list.items };
        },
        else => return error.InvalidPrincipal,
    }
}

fn parseConditions(a: std.mem.Allocator, v: Value) ParseError![]const Condition {
    const ops = switch (v) {
        .object => |o| o,
        else => return error.InvalidCondition,
    };
    var list: std.ArrayList(Condition) = .empty;
    var it = ops.iterator();
    while (it.next()) |op_kv| {
        const q = condition.parseQualified(op_kv.key_ptr.*) orelse return error.InvalidCondition;
        const keys = switch (op_kv.value_ptr.*) {
            .object => |o| o,
            else => return error.InvalidCondition,
        };
        var kit = keys.iterator();
        while (kit.next()) |kv| {
            if (list.items.len >= limits.max_conditions) return error.LimitExceeded;
            const key = kv.key_ptr.*;
            if (key.len == 0 or key.len > limits.max_string) return error.InvalidCondition;
            const values = try strList(a, kv.value_ptr.*);
            if (values.len == 0) return error.InvalidCondition;
            for (values) |cv| if (!condition.validValue(q.op, cv)) return error.InvalidCondition;
            try list.append(a, .{ .op = q.op, .set = q.set, .if_exists = q.if_exists, .key = key, .values = values });
        }
    }
    return list.items;
}

fn str(v: Value) ParseError![]const u8 {
    return switch (v) {
        .string => |s| if (s.len > limits.max_string) error.LimitExceeded else s,
        else => error.MalformedStatement,
    };
}

/// A string, number, bool, or array of those; numbers and bools become their text.
fn strList(a: std.mem.Allocator, v: Value) ParseError![]const []const u8 {
    switch (v) {
        .array => |arr| {
            if (arr.items.len > limits.max_list) return error.LimitExceeded;
            const out = try a.alloc([]const u8, arr.items.len);
            for (arr.items, out) |item, *o| o.* = try scalar(a, item);
            return out;
        },
        else => {
            const out = try a.alloc([]const u8, 1);
            out[0] = try scalar(a, v);
            return out;
        },
    }
}

fn scalar(a: std.mem.Allocator, v: Value) ParseError![]const u8 {
    return switch (v) {
        .string, .number_string => |s| if (s.len > limits.max_string) error.LimitExceeded else s,
        .bool => |b| if (b) "true" else "false",
        .integer => |i| try std.fmt.allocPrint(a, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(a, "{d}", .{f}),
        else => error.MalformedStatement,
    };
}

/// Maximum bracket nesting outside strings; checked before the recursive JSON parse.
fn nestingDepth(doc: []const u8) usize {
    var depth: usize = 0;
    var max: usize = 0;
    var in_str = false;
    var esc = false;
    for (doc) |c| {
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') in_str = false;
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '{', '[' => {
                depth += 1;
                max = @max(max, depth);
            },
            '}', ']' => depth -|= 1,
            else => {},
        }
    }
    return max;
}

test "parse full policy" {
    const doc =
        \\{"Version":"2012-10-17","Id":"p1","Statement":[
        \\ {"Sid":"a","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:user/x","2"]},
        \\  "Action":"s3:GetObject","Resource":["arn:aws:s3:::b/*"],
        \\  "Condition":{"NumericLessThan":{"s3:max-keys":10},"Bool":{"aws:SecureTransport":true},
        \\   "ForAnyValue:StringLikeIfExists":{"s3:prefix":["a*","b?"]}}},
        \\ {"Effect":"Deny","NotPrincipal":"*","NotAction":["s3:*"],"NotResource":"arn:aws:s3:::c"}
        \\]}
    ;
    var p = try parse(std.testing.allocator, doc);
    defer p.deinit();
    try std.testing.expectEqual(Version.v2012_10_17, p.version);
    try std.testing.expectEqualStrings("p1", p.id);
    try std.testing.expectEqual(@as(usize, 2), p.statements.len);
    const s0 = p.statements[0];
    try std.testing.expectEqual(Effect.allow, s0.effect);
    try std.testing.expectEqual(@as(usize, 2), s0.principal.?.values.len);
    try std.testing.expectEqual(@as(usize, 3), s0.conditions.len);
    for (s0.conditions) |c| {
        if (c.op == .numeric_less_than) try std.testing.expectEqualStrings("10", c.values[0]);
        if (c.op == .bool) try std.testing.expectEqualStrings("true", c.values[0]);
        if (c.op == .string_like) {
            try std.testing.expect(c.if_exists);
            try std.testing.expectEqual(condition.SetQualifier.for_any_value, c.set);
        }
    }
    const s1 = p.statements[1];
    try std.testing.expect(s1.not_principal and s1.not_action and s1.not_resource);
    try std.testing.expect(s1.principal.?.any);
}

test "single statement object and default version" {
    var p = try parse(std.testing.allocator,
        \\{"Statement":{"Effect":"Allow","Action":"admin:*"}}
    );
    defer p.deinit();
    try std.testing.expectEqual(Version.v2008_10_17, p.version);
    try std.testing.expect(p.statements[0].resources == null);
}

test "rejects malformed policies" {
    const Case = struct { doc: []const u8, err: ParseError };
    const cases = [_]Case{
        .{ .doc = "not json", .err = error.MalformedJson },
        .{ .doc = "[]", .err = error.MalformedJson },
        .{ .doc = "{\"Version\":\"2020-01-01\",\"Statement\":[]}", .err = error.UnsupportedVersion },
        .{ .doc = "{\"Statement\":[]}", .err = error.MalformedStatement },
        .{ .doc = "{\"Statement\":[{\"Action\":\"s3:*\"}]}", .err = error.InvalidEffect },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Maybe\",\"Action\":\"s3:*\"}]}", .err = error.InvalidEffect },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\"}]}", .err = error.MalformedStatement },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"NotAction\":\"b\"}]}", .err = error.MalformedStatement },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Resource\":\"a\",\"NotResource\":\"b\"}]}", .err = error.MalformedStatement },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Bogus\":1}]}", .err = error.MalformedStatement },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Principal\":\"bob\"}]}", .err = error.InvalidPrincipal },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Principal\":{\"Alien\":\"x\"}}]}", .err = error.InvalidPrincipal },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Condition\":{\"StringWat\":{\"k\":\"v\"}}}]}", .err = error.InvalidCondition },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"300.1.1.1\"}}}]}", .err = error.InvalidCondition },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Condition\":{\"NumericEquals\":{\"k\":\"ten\"}}}]}", .err = error.InvalidCondition },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"a\",\"Condition\":{\"StringEquals\":{\"k\":[]}}}]}", .err = error.InvalidCondition },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[[[[[[[[[\"a\"]]]]]]]]]}]}", .err = error.PolicyTooDeep },
        .{ .doc = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":{\"a\":1}}]}", .err = error.MalformedStatement },
    };
    for (cases) |c| {
        try std.testing.expectError(c.err, parse(std.testing.allocator, c.doc));
    }
}

test "size limits" {
    const big = try std.testing.allocator.alloc(u8, limits.max_doc_bytes + 1);
    defer std.testing.allocator.free(big);
    @memset(big, ' ');
    try std.testing.expectError(error.PolicyTooLarge, parse(std.testing.allocator, big));

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try buf.appendSlice(std.testing.allocator, "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[");
    for (0..limits.max_list + 1) |i| {
        if (i != 0) try buf.append(std.testing.allocator, ',');
        try buf.appendSlice(std.testing.allocator, "\"a\"");
    }
    try buf.appendSlice(std.testing.allocator, "]}]}");
    try std.testing.expectError(error.LimitExceeded, parse(std.testing.allocator, buf.items));
}
