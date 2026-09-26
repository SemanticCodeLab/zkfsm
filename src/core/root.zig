//! core: ids, errors, time, checksum and range types. Imports only std.
pub const ids = @import("ids.zig");
pub const checksum = @import("checksum.zig");
pub const range = @import("range.zig");
pub const time = @import("time.zig");
pub const errors = @import("errors.zig");
pub const license = @import("license.zig");

pub const ObjectId = ids.ObjectId;
pub const BucketId = ids.BucketId;
pub const VersionId = ids.VersionId;
pub const NameId = ids.NameId;
pub const ETag = checksum.ETag;
pub const Checksum = checksum.Checksum;
pub const Range = range.Range;
pub const RangeSpec = range.RangeSpec;

test {
    _ = license;
    _ = ids;
    _ = checksum;
    _ = range;
    _ = time;
}
