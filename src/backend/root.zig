//! backend: the StorageBackend vtable. Backends see physical keys only, never S3 names.
const std = @import("std");
const core = @import("../core/root.zig");

pub const local = @import("local.zig");
pub const remote = @import("remote.zig");
pub const s3 = @import("s3.zig");
pub const azure = @import("azure.zig");
pub const gcs = @import("gcs.zig");

pub const Range = core.Range;

pub const Error = error{
    NotFound,
    InvalidKey,
    NoSpace,
    IoFailed,
    TooLarge,
    /// The caller's source reader failed.
    ReadFailed,
    /// The caller's sink writer failed.
    WriteFailed,
    OutOfMemory,
};

/// Streamed blobs live in `data`; small atomic records in `record`/`system`.
pub const KeySpace = enum { data, record, system };

pub const PhysicalKey = struct {
    space: KeySpace,
    hex: [32]u8,
};

pub const ObjectMeta = struct {
    size: u64,
    mtime_ns: i128,
};

pub const PutOptions = struct {
    /// Expected size if known; lets backends preallocate.
    size_hint: ?u64 = null,
};

pub const ListCallback = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!void,
};

pub const Capabilities = packed struct {
    atomic_rename: bool = false,
    direct_io: bool = false,
    durable_sync: bool = false,
    sparse_files: bool = false,
    reflink: bool = false,
    range_read: bool = false,
    multipart_native: bool = false,
    object_versioning: bool = false,
    conditional_write: bool = false,
    checksums: bool = false,
};

pub const StorageBackend = struct {
    ctx: *anyopaque,
    capabilities: Capabilities,
    vtable: *const VTable,

    pub const VTable = struct {
        put: *const fn (ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: PutOptions) Error!ObjectMeta,
        get: *const fn (ctx: *anyopaque, key: PhysicalKey, range: ?Range, sink: *std.Io.Writer) Error!ObjectMeta,
        stat: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta,
        delete: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!void,
        list: *const fn (ctx: *anyopaque, space: KeySpace, cb: ListCallback) Error!void,
        putRecord: *const fn (ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void,
        getRecord: *const fn (ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8,
        deleteRecord: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!void,
        sync: *const fn (ctx: *anyopaque) Error!void,
    };

    pub fn put(b: StorageBackend, key: PhysicalKey, source: *std.Io.Reader, opts: PutOptions) Error!ObjectMeta {
        return b.vtable.put(b.ctx, key, source, opts);
    }
    pub fn get(b: StorageBackend, key: PhysicalKey, range: ?Range, sink: *std.Io.Writer) Error!ObjectMeta {
        return b.vtable.get(b.ctx, key, range, sink);
    }
    pub fn stat(b: StorageBackend, key: PhysicalKey) Error!ObjectMeta {
        return b.vtable.stat(b.ctx, key);
    }
    pub fn delete(b: StorageBackend, key: PhysicalKey) Error!void {
        return b.vtable.delete(b.ctx, key);
    }
    pub fn list(b: StorageBackend, space: KeySpace, cb: ListCallback) Error!void {
        return b.vtable.list(b.ctx, space, cb);
    }
    pub fn putRecord(b: StorageBackend, key: PhysicalKey, bytes: []const u8) Error!void {
        return b.vtable.putRecord(b.ctx, key, bytes);
    }
    pub fn getRecord(b: StorageBackend, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        return b.vtable.getRecord(b.ctx, key, gpa);
    }
    pub fn deleteRecord(b: StorageBackend, key: PhysicalKey) Error!void {
        return b.vtable.deleteRecord(b.ctx, key);
    }
    pub fn sync(b: StorageBackend) Error!void {
        return b.vtable.sync(b.ctx);
    }
};

test {
    _ = local;
    _ = remote;
    _ = s3;
    _ = azure;
    _ = gcs;
    _ = @import("s3/sign.zig");
    _ = @import("remote/http.zig");
    _ = @import("remote/xml.zig");
}
