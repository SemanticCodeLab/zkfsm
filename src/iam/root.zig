//! iam: identities, policies, and authorization decisions. Imports only std.
pub const wildcard = @import("wildcard.zig");
pub const context = @import("context.zig");
pub const condition = @import("condition.zig");
pub const policy = @import("policy.zig");
pub const eval = @import("eval.zig");
pub const actions = @import("actions.zig");
pub const sts = @import("sts.zig");
pub const store = @import("store.zig");
pub const jwt = @import("jwt.zig");
pub const ldap = @import("ldap.zig");
pub const idp = @import("idp.zig");
pub const federation = @import("federation.zig");
pub const tenants = @import("tenants.zig");
pub const sessions = @import("sessions.zig");
pub const ratelimit = @import("ratelimit.zig");
pub const oidc_login = @import("oidc_login.zig");

pub const Policy = policy.Policy;
pub const Context = context.Context;
pub const Principal = eval.Principal;
pub const Decision = eval.Decision;
pub const authorize = eval.authorize;
pub const Store = store.Store;
pub const Identity = store.Identity;

test "sts session end to end: token, store lookup, S3 op mapping" {
    const std = @import("std");
    const a = std.testing.allocator;
    var mem: store.MemoryPersistence = .{ .gpa = a };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(a, mem.persistence(), .{ .root_access_key = "root" });
    defer s.deinit();
    try s.createUser("alice", "alicesecret");
    try s.attachPolicy(.user, "alice", "readwrite");

    const issuer: sts.Issuer = .{ .key = @splat(1) };
    var prng = std.Random.DefaultPrng.init(9);
    var creds = try issuer.issue(a, .{ .parent = "alice", .session_policy = 
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::shared/${aws:username}/*"}]}
    }, 1000, prng.random());
    defer creds.deinit(a);

    var buf: sts.DecodeBuffer = undefined;
    const claims = try issuer.verify(&creds.access_key, creds.session_token, 1100, &buf);
    var sp = try policy.parse(a, claims.session_policy.?);
    defer sp.deinit();
    const who: Identity = .{ .access_key = claims.parent, .session_policy = &sp };
    const ctx: Context = .{ .now_s = 1100 };
    var arn: [256]u8 = undefined;
    const own = try actions.resourceArn(&arn, .put_object, "shared", "alice/f");
    try std.testing.expectEqual(Decision.allow, s.authorize(who, actions.mapping(.put_object).action, own, &ctx));
    const other = try actions.resourceArn(&arn, .put_object, "shared", "bob/f");
    try std.testing.expectEqual(Decision.implicit_deny, s.authorize(who, actions.mapping(.put_object).action, other, &ctx));
}

test {
    _ = wildcard;
    _ = context;
    _ = condition;
    _ = policy;
    _ = eval;
    _ = actions;
    _ = sts;
    _ = store;
    _ = jwt;
    _ = ldap;
    _ = idp;
    _ = federation;
    _ = tenants;
    _ = sessions;
    _ = ratelimit;
    _ = oidc_login;
}
