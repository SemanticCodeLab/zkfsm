//! cluster: static multi-node deployments. Every node starts with the same endpoint
//! list; erasure sets span nodes, remote drives are reached over signed RPC on the S3
//! port, namespace locks take a node majority, and caches follow change notifications.
pub const auth = @import("auth.zig");
pub const topology = @import("topology.zig");
pub const rpc = @import("rpc.zig");
pub const wire = @import("wire.zig");
pub const locks = @import("locks.zig");
pub const router = @import("router.zig");
pub const remote_drive = @import("remote_drive.zig");
pub const node = @import("node.zig");
pub const server = @import("server.zig");
pub const handles = @import("handles.zig");

pub const Node = node.Node;
pub const Config = node.Config;
pub const isUrl = topology.isUrl;

test {
    _ = auth;
    _ = topology;
    _ = rpc;
    _ = wire;
    _ = locks;
    _ = router;
    _ = remote_drive;
    _ = node;
    _ = server;
    _ = handles;
}
