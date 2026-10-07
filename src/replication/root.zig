//! replication: bucket replication (rules, remote targets, durable queue, delivery,
//! resync, metrics) and site replication across deployments.
pub const config = @import("config.zig");
pub const targets = @import("targets.zig");
pub const client = @import("client.zig");
pub const store = @import("store.zig");
pub const queue = @import("queue.zig");
pub const stats = @import("stats.zig");
pub const engine = @import("engine.zig");
pub const deliver = @import("deliver.zig");
pub const site = @import("site.zig");
pub const admin = @import("admin.zig");
pub const s3ext = @import("s3ext.zig");

pub const Replicator = engine.Replicator;

test {
    _ = config;
    _ = targets;
    _ = client;
    _ = store;
    _ = queue;
    _ = stats;
    _ = engine;
    _ = deliver;
    _ = site;
    _ = admin;
    _ = s3ext;
}
