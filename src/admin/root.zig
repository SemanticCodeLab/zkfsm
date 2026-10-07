//! admin: MinIO-compatible IAM admin API and its payload encryption.
pub const api = @import("api.zig");
pub const sio = @import("sio.zig");
pub const tier = @import("tier.zig");
pub const identity = @import("identity.zig");

test {
    _ = api;
    _ = sio;
    _ = tier;
    _ = identity;
}
