//! object: ObjectService, the protocol-neutral object API.
pub const service = @import("service.zig");
pub const list = @import("list.zig");
pub const blob = @import("blob.zig");
pub const copy = @import("copy.zig");
pub const multipart = @import("multipart.zig");

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
    _ = blob;
    _ = copy;
    _ = multipart;
}
