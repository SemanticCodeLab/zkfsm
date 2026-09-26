//! Request context for policy evaluation: condition keys, principal, and policy variables.
const std = @import("std");
const Policy = @import("policy.zig").Policy;

/// One condition key with its values (multi-valued keys have several).
pub const Entry = struct { key: []const u8, values: []const []const u8 };

pub const Context = struct {
    /// Request keys such as aws:SourceIp, s3:prefix, s3:ExistingObjectTag/<k>.
    entries: []const Entry = &.{},
    /// Request time in unix seconds; backs aws:CurrentTime and aws:EpochTime when not in `entries`.
    now_s: ?i64 = null,
    /// Bucket policy of the target bucket, if any.
    resource_policy: ?*const Policy = null,
    /// Owner (account or user name) of the target bucket, for the owner bypass.
    bucket_owner: ?[]const u8 = null,

    /// Key names are case-insensitive; the tag name after `s3:ExistingObjectTag/` etc. is not.
    pub fn lookup(self: *const Context, key: []const u8) ?[]const []const u8 {
        for (self.entries) |e| if (keyEql(e.key, key)) return e.values;
        return null;
    }
};

pub fn keyEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    const split = std.mem.indexOfScalar(u8, a, '/') orelse a.len;
    if (!std.ascii.eqlIgnoreCase(a[0..split], b[0..split])) return false;
    return std.mem.eql(u8, a[split..], b[split..]);
}

/// Identity attributes exposed as global condition keys during evaluation.
pub const PrincipalKeys = struct {
    username: []const u8 = "",
    userid: []const u8 = "",
    arn: []const u8 = "",
    account: []const u8 = "",
};

/// Resolves condition keys from the request context, then principal-derived keys.
pub const Env = struct {
    ctx: *const Context,
    who: PrincipalKeys,
    one: [1][]const u8 = undefined,
    time_buf: [32]u8 = undefined,

    pub fn get(self: *Env, key: []const u8) ?[]const []const u8 {
        if (self.ctx.lookup(key)) |v| return v;
        const v: []const u8 = if (std.ascii.eqlIgnoreCase(key, "aws:username"))
            self.who.username
        else if (std.ascii.eqlIgnoreCase(key, "aws:userid"))
            self.who.userid
        else if (std.ascii.eqlIgnoreCase(key, "aws:PrincipalArn"))
            self.who.arn
        else if (std.ascii.eqlIgnoreCase(key, "aws:PrincipalAccount"))
            self.who.account
        else if (std.ascii.eqlIgnoreCase(key, "aws:CurrentTime") or std.ascii.eqlIgnoreCase(key, "aws:EpochTime")) blk: {
            const now = self.ctx.now_s orelse return null;
            break :blk std.fmt.bufPrint(&self.time_buf, "{d}", .{now}) catch return null;
        } else return null;
        if (v.len == 0) return null;
        self.one[0] = v;
        return &self.one;
    }

    /// Single value of a key, or null when absent or multi-valued.
    pub fn single(self: *Env, key: []const u8) ?[]const u8 {
        const vs = self.get(key) orelse return null;
        return if (vs.len == 1) vs[0] else null;
    }
};

pub const Expanded = struct { text: []const u8, escaped: bool };

/// Replaces `${key}` with the key's value. With `for_glob`, literal text is escaped
/// so variable values never act as wildcards. Null when a variable is missing or `buf` overflows.
pub fn expand(template: []const u8, env: *Env, for_glob: bool, buf: []u8) ?Expanded {
    if (std.mem.indexOf(u8, template, "${") == null) return .{ .text = template, .escaped = false };
    var n: usize = 0;
    var i: usize = 0;
    while (i < template.len) {
        if (template[i] == '$' and i + 1 < template.len and template[i + 1] == '{') {
            const end = std.mem.indexOfScalarPos(u8, template, i + 2, '}') orelse return null;
            const name = template[i + 2 .. end];
            const value: []const u8 = if (std.mem.eql(u8, name, "*"))
                "*"
            else if (std.mem.eql(u8, name, "?"))
                "?"
            else if (std.mem.eql(u8, name, "$"))
                "$"
            else
                env.single(name) orelse return null;
            for (value) |c| n = put(buf, n, c, for_glob) orelse return null;
            i = end + 1;
            continue;
        }
        const c = template[i];
        if (for_glob and c == '\\') {
            n = put(buf, n, c, true) orelse return null;
        } else {
            if (n >= buf.len) return null;
            buf[n] = c;
            n += 1;
        }
        i += 1;
    }
    return .{ .text = buf[0..n], .escaped = for_glob };
}

fn put(buf: []u8, n: usize, c: u8, escape: bool) ?usize {
    const need: usize = if (escape and (c == '*' or c == '?' or c == '\\')) 2 else 1;
    if (n + need > buf.len) return null;
    if (need == 2) buf[n] = '\\';
    buf[n + need - 1] = c;
    return n + need;
}

test "lookup is case-insensitive on key, sensitive on tag name" {
    const ctx: Context = .{ .entries = &.{
        .{ .key = "aws:SourceIp", .values = &.{"10.0.0.1"} },
        .{ .key = "s3:ExistingObjectTag/Env", .values = &.{"prod"} },
    } };
    try std.testing.expect(ctx.lookup("AWS:sourceip") != null);
    try std.testing.expect(ctx.lookup("S3:existingobjecttag/Env") != null);
    try std.testing.expect(ctx.lookup("s3:ExistingObjectTag/env") == null);
}

test "expand variables" {
    const ctx: Context = .{ .entries = &.{.{ .key = "s3:prefix", .values = &.{"a*b"} }} };
    var env: Env = .{ .ctx = &ctx, .who = .{ .username = "alice" } };
    var buf: [128]u8 = undefined;
    const e1 = expand("arn:aws:s3:::home/${aws:username}/*", &env, true, &buf).?;
    try std.testing.expectEqualStrings("arn:aws:s3:::home/alice/*", e1.text);
    const e2 = expand("${s3:prefix}${*}", &env, true, &buf).?;
    try std.testing.expectEqualStrings("a\\*b\\*", e2.text);
    const e3 = expand("${s3:prefix}", &env, false, &buf).?;
    try std.testing.expectEqualStrings("a*b", e3.text);
    try std.testing.expect(expand("${aws:SourceIp}", &env, true, &buf) == null);
    try std.testing.expect(expand("${unterminated", &env, true, &buf) == null);
    var tiny: [3]u8 = undefined;
    try std.testing.expect(expand("${aws:username}", &env, false, &tiny) == null);
}
