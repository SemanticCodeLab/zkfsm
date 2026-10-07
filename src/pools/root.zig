//! pools: decommission and rebalance of server pools in a cluster deployment.
pub const state = @import("state.zig");
pub const mover = @import("mover.zig");
pub const manager = @import("manager.zig");
pub const admin = @import("admin.zig");

pub const Manager = manager.Manager;

test {
    _ = state;
    _ = mover;
    _ = manager;
    _ = admin;
}
