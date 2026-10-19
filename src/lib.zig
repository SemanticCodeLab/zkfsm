//! Package root for embedding zkfsm (e.g. by extension builds). Re-exports
//! the layers; the binary entry point stays in main.zig.
pub const core = @import("core/root.zig");
pub const io = @import("io/root.zig");
pub const device = @import("device/root.zig");
pub const backend = @import("backend/root.zig");
pub const metadata = @import("metadata/root.zig");
pub const placement = @import("placement/root.zig");
pub const protection = @import("protection/root.zig");
pub const heal = @import("heal/root.zig");
pub const object = @import("object/root.zig");
pub const s3 = @import("s3/root.zig");
pub const metrics = @import("metrics/root.zig");
pub const license = core.license;
/// Full server entry: `app.run(.{ .extensions = ... })`.
pub const app = @import("main.zig");

/// Stable surface for cluster extensions (see README "Cluster extension points").
pub const cluster = struct {
    const impl = @import("cluster/root.zig");
    pub const Node = impl.node.Node;
    pub const Config = impl.node.Config;
    pub const Membership = impl.node.Membership;
    pub const Ext = impl.node.Ext;
    pub const ext_channels = impl.node.ext_channels;
    pub const Error = impl.node.Error;
    pub const Topology = impl.topology.Topology;
    pub const TopologyError = impl.topology.Error;
    pub const Endpoint = impl.topology.Endpoint;
    pub const Rpc = impl.rpc.Rpc;
    pub const Secret = impl.auth.Secret;
    pub const PoolMode = impl.router.Mode;
    pub const StartLayout = app.StartLayout;
    pub const Hooks = app.ClusterHooks;
    /// Pool decommission and rebalance (`Hooks.pools` hands the running manager over).
    pub const Pools = @import("pools/root.zig").Manager;
    /// Parses endpoint arguments (with `{a...b}` ranges), one slice per pool.
    pub const parseTopology = impl.topology.parse;
    /// Expands `{1...4}` ranges in one endpoint argument.
    pub const expandEndpoints = placement.ellipsis.expand;
    pub const isUrl = impl.topology.isUrl;
    /// The cluster secret derived from root credentials, or from `--cluster-secret`.
    pub const fromRoot = impl.auth.fromRoot;
    pub const fromString = impl.auth.fromString;
    /// Every internal module, without stability promises.
    pub const internal = impl;
};

test {
    _ = core;
    _ = cluster;
}
