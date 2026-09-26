//! object: ObjectService, the protocol-neutral object API. Multipart lands here in step 9.
pub const service = @import("service.zig");
pub const list = @import("list.zig");

pub const ObjectService = service.ObjectService;
pub const Error = service.Error;
pub const ObjectInfo = service.ObjectInfo;
pub const BucketInfo = service.BucketInfo;
pub const PutInput = service.PutInput;
pub const ListParams = service.ListParams;
pub const ListResult = service.ListResult;

test {
    _ = service;
    _ = list;
}
