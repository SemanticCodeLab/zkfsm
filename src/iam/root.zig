//! iam: identities, policies, and authorization decisions. Imports only std.
pub const wildcard = @import("wildcard.zig");
pub const context = @import("context.zig");
pub const condition = @import("condition.zig");
pub const policy = @import("policy.zig");
pub const eval = @import("eval.zig");
pub const actions = @import("actions.zig");

pub const Policy = policy.Policy;
pub const Context = context.Context;
pub const Principal = eval.Principal;
pub const Decision = eval.Decision;
pub const authorize = eval.authorize;

test {
    _ = wildcard;
    _ = context;
    _ = condition;
    _ = policy;
    _ = eval;
    _ = actions;
}
