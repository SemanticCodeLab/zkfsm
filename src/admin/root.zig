//! admin: MinIO-compatible IAM admin API and its payload encryption.
pub const api = @import("api.zig");
pub const sio = @import("sio.zig");
pub const tier = @import("tier.zig");
pub const identity = @import("identity.zig");
pub const oidc = @import("oidc.zig");

test {
    _ = api;
    _ = sio;
    _ = tier;
    _ = identity;
    _ = oidc;
}
