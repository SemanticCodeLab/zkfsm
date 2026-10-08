//! tables: S3 Tables control plane and an Iceberg REST catalog over table buckets.
pub const route = @import("route.zig");
pub const iceberg = @import("iceberg.zig");
pub const control = @import("control.zig");
pub const catalog = @import("catalog.zig");
pub const metadata = @import("metadata.zig");
pub const store = @import("store.zig");
pub const json = @import("json.zig");
pub const http = @import("http.zig");

pub const Tables = route.Tables;

test {
    _ = route;
    _ = iceberg;
    _ = control;
    _ = catalog;
    _ = metadata;
    _ = store;
    _ = json;
    _ = http;
}
