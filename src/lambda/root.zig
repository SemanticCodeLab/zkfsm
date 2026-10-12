//! lambda: Object Lambda (GET object through a webhook function, MinIO-compatible).
pub const config = @import("config.zig");
pub const event = @import("event.zig");
pub const client = @import("client.zig");
pub const s3ext = @import("s3ext.zig");
pub const admin = @import("admin.zig");
pub const Registry = s3ext.Registry;

test {
    _ = config;
    _ = event;
    _ = client;
    _ = s3ext;
    _ = admin;
}
