//! object: ObjectService, the protocol-neutral object API, plus versioning and object lock.
pub const service = @import("service.zig");
pub const list = @import("list.zig");
pub const versioning = @import("versioning.zig");
pub const lock = @import("lock.zig");
pub const conditional = @import("conditional.zig");
pub const blob = @import("blob.zig");
pub const copy = @import("copy.zig");
pub const multipart = @import("multipart.zig");
pub const index = @import("index.zig");
pub const index_store = @import("index_store.zig");
pub const lifecycle = @import("lifecycle.zig");
pub const policy = @import("policy.zig");
pub const replica = @import("replica.zig");

pub const ObjectService = service.ObjectService;
pub const Error = service.Error;
pub const ObjectInfo = service.ObjectInfo;
pub const BucketInfo = service.BucketInfo;
pub const PutInput = service.PutInput;
pub const Finalizer = service.Finalizer;
pub const ListParams = service.ListParams;
pub const ListResult = service.ListResult;
pub const Tag = versioning.Tag;
pub const Header = service.Header;
pub const SystemHeaders = service.SystemHeaders;
pub const user_meta_limit = @import("../metadata/root.zig").headers.user_limit;
pub const internal_prefix = @import("../metadata/root.zig").headers.internal_prefix;
pub const partSize = @import("../metadata/root.zig").record.partSize;

/// Decodes an encoded tag set (ObjectInfo.tags) into `arena`.
pub fn decodeTags(arena: @import("std").mem.Allocator, bytes: []const u8) Error![]Tag {
    return @import("../metadata/root.zig").tags.decode(arena, bytes) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Corrupt => error.Corrupt,
    };
}

test {
    _ = service;
    _ = list;
    _ = versioning;
    _ = lock;
    _ = conditional;
    _ = blob;
    _ = copy;
    _ = multipart;
    _ = index;
    _ = index_store;
    _ = lifecycle;
    _ = policy;
    _ = replica;
}
