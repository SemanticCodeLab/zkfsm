//! metadata: ObjectRecord and bucket catalog encodings. Pure; no I/O.
pub const record = @import("record.zig");
pub const catalog = @import("catalog.zig");
pub const ObjectRecord = record.ObjectRecord;
pub const Catalog = catalog.Catalog;
pub const Bucket = catalog.Bucket;

test {
    _ = record;
    _ = catalog;
}
