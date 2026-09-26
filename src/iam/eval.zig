//! Policy evaluation: explicit deny > allow > implicit deny.
//! Identity and bucket policies are unioned; session policies intersect.
const std = @import("std");
const policy = @import("policy.zig");
const condition = @import("condition.zig");
const context = @import("context.zig");
const wildcard = @import("wildcard.zig");

const Policy = policy.Policy;
const Statement = policy.Statement;
pub const Context = context.Context;

pub const Decision = enum {
    allow,
    explicit_deny,
    implicit_deny,

    pub fn allowed(d: Decision) bool {
        return d == .allow;
    }
};

pub const Principal = struct {
    /// Account (tenant) id; also matched by `"AWS": "<account>"` in bucket policies.
    account: []const u8 = "",
    arn: []const u8 = "",
    username: []const u8 = "",
    userid: []const u8 = "",
    /// The deployment root: bypasses every policy.
    is_root: bool = false,
    /// Policies attached to the user and its groups.
    identity_policies: []const *const Policy = &.{},
    /// Service-account or STS session policies; each must also allow.
    session_policies: []const *const Policy = &.{},
};

const PolicyKind = enum { identity, resource };

const Outcome = struct { allow: bool = false, deny: bool = false };

pub fn authorize(principal: *const Principal, action: []const u8, resource: []const u8, ctx: *const Context) Decision {
    if (principal.is_root) return .allow;
    var env: context.Env = .{ .ctx = ctx, .who = .{
        .username = principal.username,
        .userid = principal.userid,
        .arn = principal.arn,
        .account = principal.account,
    } };
    var deny = false;
    var identity_allow = false;
    for (principal.identity_policies) |p| {
        const o = evalPolicy(p, .identity, principal, action, resource, &env);
        deny = deny or o.deny;
        identity_allow = identity_allow or o.allow;
    }
    var resource_allow = false;
    if (ctx.resource_policy) |p| {
        const o = evalPolicy(p, .resource, principal, action, resource, &env);
        deny = deny or o.deny;
        resource_allow = o.allow;
    }
    var session_allow = true;
    for (principal.session_policies) |p| {
        const o = evalPolicy(p, .identity, principal, action, resource, &env);
        deny = deny or o.deny;
        session_allow = session_allow and o.allow;
    }
    if (deny) return .explicit_deny;
    const owner = if (ctx.bucket_owner) |o| o.len > 0 and
        (std.mem.eql(u8, o, principal.account) or std.mem.eql(u8, o, principal.username)) else false;
    if ((identity_allow or resource_allow or owner) and session_allow) return .allow;
    return .implicit_deny;
}

fn evalPolicy(p: *const Policy, kind: PolicyKind, who: *const Principal, action: []const u8, resource: []const u8, env: *context.Env) Outcome {
    var out: Outcome = .{};
    const vars: condition.Variables = if (p.version == .v2012_10_17) .expand else .literal;
    for (p.statements) |*s| {
        if (s.effect == .allow and out.allow) continue;
        if (!statementApplies(s, kind, who, action, resource, env, vars)) continue;
        switch (s.effect) {
            .deny => {
                out.deny = true;
                return out;
            },
            .allow => out.allow = true,
        }
    }
    return out;
}

fn statementApplies(s: *const Statement, kind: PolicyKind, who: *const Principal, action: []const u8, resource: []const u8, env: *context.Env, vars: condition.Variables) bool {
    if (kind == .resource) {
        const pr = s.principal orelse return false;
        if (principalMatches(pr, who) == s.not_principal) return false;
    }
    if (anyAction(s.actions, action) == s.not_action) return false;
    if (s.resources) |rs| {
        if (anyResource(rs, resource, env, vars) == s.not_resource) return false;
    }
    for (s.conditions) |*c| if (!condition.evaluate(c, env, vars)) return false;
    return true;
}

fn anyAction(patterns: []const []const u8, action: []const u8) bool {
    for (patterns) |p| if (wildcard.match(p, action, .{ .ignore_case = true })) return true;
    return false;
}

fn anyResource(patterns: []const []const u8, resource: []const u8, env: *context.Env, vars: condition.Variables) bool {
    var buf: [2048]u8 = undefined;
    for (patterns) |p| {
        const e: context.Expanded = if (vars == .expand)
            context.expand(p, env, true, &buf) orelse continue
        else
            .{ .text = p, .escaped = false };
        if (wildcard.match(e.text, resource, .{ .escaped = e.escaped })) return true;
    }
    return false;
}

/// Principals match by exact ARN, account id, account root ARN, or `*`.
fn principalMatches(pr: policy.Principal, who: *const Principal) bool {
    if (pr.any) return true;
    for (pr.values) |v| {
        if (v.kind != .aws) continue;
        const s = v.value;
        if (std.mem.eql(u8, s, "*")) return true;
        if (s.len == 0) continue;
        if (std.mem.eql(u8, s, who.arn) or std.mem.eql(u8, s, who.account)) return true;
        if (who.account.len > 0 and std.mem.startsWith(u8, s, "arn:aws:iam::") and
            std.mem.endsWith(u8, s, ":root") and
            std.mem.eql(u8, s["arn:aws:iam::".len .. s.len - ":root".len], who.account)) return true;
    }
    return false;
}

// ---------------------------------------------------------------- tests

const T = struct {
    const Case = struct {
        name: []const u8,
        identity: []const []const u8 = &.{},
        bucket: ?[]const u8 = null,
        session: []const []const u8 = &.{},
        action: []const u8,
        resource: []const u8,
        entries: []const context.Entry = &.{},
        owner: ?[]const u8 = null,
        root: bool = false,
        want: Decision,
    };

    fn run(c: Case) !void {
        const a = std.testing.allocator;
        var owned: std.ArrayList(Policy) = .empty;
        defer {
            for (owned.items) |*p| p.deinit();
            owned.deinit(a);
        }
        try owned.ensureTotalCapacity(a, c.identity.len + c.session.len + 1);
        var ids: [8]*const Policy = undefined;
        var sess: [8]*const Policy = undefined;
        for (c.identity, 0..) |d, i| {
            owned.appendAssumeCapacity(try policy.parse(a, d));
            ids[i] = &owned.items[owned.items.len - 1];
        }
        for (c.session, 0..) |d, i| {
            owned.appendAssumeCapacity(try policy.parse(a, d));
            sess[i] = &owned.items[owned.items.len - 1];
        }
        var bp: ?*const Policy = null;
        if (c.bucket) |d| {
            owned.appendAssumeCapacity(try policy.parse(a, d));
            bp = &owned.items[owned.items.len - 1];
        }
        const who: Principal = .{
            .account = "111122223333",
            .arn = "arn:aws:iam::111122223333:user/alice",
            .username = "alice",
            .userid = "AIDAALICE",
            .is_root = c.root,
            .identity_policies = ids[0..c.identity.len],
            .session_policies = sess[0..c.session.len],
        };
        const ctx: Context = .{ .entries = c.entries, .resource_policy = bp, .bucket_owner = c.owner, .now_s = 1_700_000_000 };
        const got = authorize(&who, c.action, c.resource, &ctx);
        if (got != c.want) {
            std.debug.print("eval case '{s}': want {t}, got {t}\n", .{ c.name, c.want, got });
            return error.TestUnexpectedResult;
        }
    }
};

const allow_all =
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}
;
const get_only =
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
;

test "evaluation table" {
    const cases = [_]T.Case{
        .{ .name = "no policies: implicit deny", .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "root bypasses deny", .root = true, .identity = &.{
            \\{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "simple allow", .identity = &.{get_only}, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "action case-insensitive", .identity = &.{get_only}, .action = "S3:getobject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "resource case-sensitive", .identity = &.{get_only}, .action = "s3:GetObject", .resource = "arn:aws:s3:::B/k", .want = .implicit_deny },
        .{ .name = "other action", .identity = &.{get_only}, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "deny beats allow across policies", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}
        }, .action = "s3:DeleteObject", .resource = "arn:aws:s3:::b/k", .want = .explicit_deny },
        .{ .name = "NotAction deny blocks everything else", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","NotAction":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}
        }, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .explicit_deny },
        .{ .name = "NotAction deny lets listed action through", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","NotAction":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "NotAction allow does not grant listed", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","NotAction":"s3:Delete*","Resource":"*"}]}
        }, .action = "s3:DeleteObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "NotResource deny outside bucket", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::safe","arn:aws:s3:::safe/*"]}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::other/k", .want = .explicit_deny },
        .{ .name = "NotResource deny inside bucket", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::safe","arn:aws:s3:::safe/*"]}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::safe/k", .want = .allow },
        .{ .name = "policy variable home dir", .identity = &.{
            \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::home/${aws:username}/*"}]}
        }, .action = "s3:PutObject", .resource = "arn:aws:s3:::home/alice/f", .want = .allow },
        .{ .name = "policy variable other home", .identity = &.{
            \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::home/${aws:username}/*"}]}
        }, .action = "s3:PutObject", .resource = "arn:aws:s3:::home/bob/f", .want = .implicit_deny },
        .{ .name = "2008 version keeps variables literal", .identity = &.{
            \\{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::home/${aws:username}/*"}]}
        }, .action = "s3:PutObject", .resource = "arn:aws:s3:::home/alice/f", .want = .implicit_deny },
        .{ .name = "deny IfExists on absent key denies", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"s3:x-amz-acl":"private"}}}]}
        }, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .explicit_deny },
        .{ .name = "deny IfExists with matching value", .identity = &.{
            allow_all,
            \\{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"s3:x-amz-acl":"private"}}}]}
        }, .entries = &.{.{ .key = "s3:x-amz-acl", .values = &.{"private"} }}, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "allow IfExists absent grants", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"NumericLessThanEqualsIfExists":{"s3:max-keys":"10"}}}]}
        }, .action = "s3:ListBucket", .resource = "arn:aws:s3:::b", .want = .allow },
        .{ .name = "allow without IfExists absent denies", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"NumericLessThanEquals":{"s3:max-keys":"10"}}}]}
        }, .action = "s3:ListBucket", .resource = "arn:aws:s3:::b", .want = .implicit_deny },
        .{ .name = "ForAllValues on absent key allows", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]}}}]}
        }, .action = "s3:PutObjectTagging", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "ForAllValues with extra key denies", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:PutObjectTagging","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]}}}]}
        }, .entries = &.{.{ .key = "aws:TagKeys", .values = &.{ "env", "cost" } }}, .action = "s3:PutObjectTagging", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "conditions AND across keys", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}
        }, .entries = &.{ .{ .key = "aws:SecureTransport", .values = &.{"true"} }, .{ .key = "aws:SourceIp", .values = &.{"192.168.1.1"} } }, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "deny insecure transport", .identity = &.{allow_all}, .bucket = 
        \\{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}
        , .entries = &.{.{ .key = "aws:SecureTransport", .values = &.{"false"} }}, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .explicit_deny },
        .{ .name = "bucket policy grants without identity", .bucket = 
        \\{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "bucket policy for other principal", .bucket = 
        \\{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/bob"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "bucket policy account root", .bucket = 
        \\{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "bucket policy without principal ignored", .bucket = 
        \\{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "NotPrincipal deny excludes listed", .identity = &.{allow_all}, .bucket = 
        \\{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"s3:*","Resource":"*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "NotPrincipal deny hits others", .identity = &.{allow_all}, .bucket = 
        \\{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/bob"},"Action":"s3:*","Resource":"*"}]}
        , .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .explicit_deny },
        .{ .name = "identity policy Principal element ignored", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Principal":{"AWS":"nobody"},"Action":"s3:*","Resource":"*"}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "owner bypass", .owner = "alice", .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "owner still hits explicit deny", .owner = "111122223333", .bucket = 
        \\{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::b"}]}
        , .action = "s3:DeleteBucket", .resource = "arn:aws:s3:::b", .want = .explicit_deny },
        .{ .name = "session policy narrows", .identity = &.{allow_all}, .session = &.{get_only}, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "session policy intersect allow", .identity = &.{allow_all}, .session = &.{get_only}, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
        .{ .name = "session policy cannot widen", .identity = &.{get_only}, .session = &.{allow_all}, .action = "s3:PutObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "prefix-scoped list", .identity = &.{
            \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":["${aws:username}/*",""]}}}]}
        }, .entries = &.{.{ .key = "s3:prefix", .values = &.{"alice/docs/"} }}, .action = "s3:ListBucket", .resource = "arn:aws:s3:::b", .want = .allow },
        .{ .name = "existing object tag", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"s3:ExistingObjectTag/class":"public"}}}]}
        }, .entries = &.{.{ .key = "s3:ExistingObjectTag/class", .values = &.{"secret"} }}, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .implicit_deny },
        .{ .name = "date window", .identity = &.{
            \\{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"},"DateLessThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}}]}
        }, .action = "s3:GetObject", .resource = "arn:aws:s3:::b/k", .want = .allow },
    };
    for (cases) |c| try T.run(c);
}
