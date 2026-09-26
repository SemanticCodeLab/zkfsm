//! metadata: ObjectRecord, bucket catalog, bucket config, and tag encodings. Pure; no I/O.
pub const record = @import("record.zig");
pub const catalog = @import("catalog.zig");
pub const bucket_config = @import("bucket_config.zig");
pub const tags = @import("tags.zig");
pub const ObjectRecord = record.ObjectRecord;
pub const Catalog = catalog.Catalog;
pub const Bucket = catalog.Bucket;
pub const BucketConfig = bucket_config.BucketConfig;

test {
    _ = record;
    _ = catalog;
    _ = bucket_config;
    _ = tags;
}
