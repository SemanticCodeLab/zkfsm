//! ObjectService: protocol-neutral buckets and objects over a StorageBackend.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const io = @import("../io/root.zig");
const list_mod = @import("list.zig");

const Md5 = core.checksum.Md5;

pub const Error = error{
    NoSuchBucket,
    NoSuchKey,
    BucketAlreadyExists,
    BucketNotEmpty,
    InvalidBucketName,
    KeyTooLong,
    InvalidKey,
    IncompleteBody,
    NoSpace,
    StorageFailed,
    Corrupt,
    /// The caller's source reader failed.
    ReadFailed,
    /// The caller's sink writer failed.
    WriteFailed,
    OutOfMemory,
};

pub const BucketInfo = struct { name: []const u8, created_ns: i128 };

pub const ObjectInfo = struct {
    key: []const u8,
    size: u64,
    etag: core.ETag,
    created_ns: i128,
    content_type: []const u8,
    object_id: core.ObjectId,
};

pub const PutInput = struct {
    content_type: []const u8 = "",
    /// When set, the body must be exactly this long.
    content_length: ?u64 = null,
};

pub const ListParams = list_mod.Params;
pub const ListResult = list_mod.Result;

pub const ObjectService = struct {
    gpa: std.mem.Allocator,
    store: backend.StorageBackend,
    catalog: metadata.Catalog,
    /// Guards the catalog and record swaps; data streaming runs unlocked.
    mutex: std.Thread.Mutex = .{},

    pub fn init(gpa: std.mem.Allocator, store: backend.StorageBackend) Error!ObjectService {
        const bytes = store.getRecord(placement.catalog_key, gpa) catch |e| switch (e) {
            error.NotFound => return .{ .gpa = gpa, .store = store, .catalog = metadata.Catalog.init(gpa) },
            else => return mapBackend(e),
        };
        defer gpa.free(bytes);
        const cat = metadata.Catalog.decode(gpa, bytes) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Corrupt => error.Corrupt,
        };
        return .{ .gpa = gpa, .store = store, .catalog = cat };
    }

    pub fn deinit(self: *ObjectService) void {
        self.catalog.deinit();
    }

    pub fn createBucket(self: *ObjectService, name: []const u8) Error!void {
        if (!validBucketName(name)) return error.InvalidBucketName;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.catalog.find(name) != null) return error.BucketAlreadyExists;
        try self.catalog.add(.{ .name = name, .id = core.BucketId.random(), .created_ns = core.time.nowNs() });
        self.persistCatalog() catch |e| {
            _ = self.catalog.remove(name);
            return e;
        };
    }

    pub fn deleteBucket(self: *ObjectService, name: []const u8) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const b = self.catalog.find(name) orelse return error.NoSuchBucket;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        var it = try self.scanRecords(arena.allocator());
        if (try it.next(self, b.id) != null) return error.BucketNotEmpty;
        const saved = b;
        const name_copy = try arena.allocator().dupe(u8, name);
        _ = self.catalog.remove(name);
        self.persistCatalog() catch |e| {
            self.catalog.add(.{ .name = name_copy, .id = saved.id, .created_ns = saved.created_ns }) catch {};
            return e;
        };
    }

    pub fn headBucket(self: *ObjectService, name: []const u8) Error!void {
        _ = try self.bucketId(name);
    }

    /// Bucket names are duplicated into `arena`.
    pub fn listBuckets(self: *ObjectService, arena: std.mem.Allocator) Error![]BucketInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = try arena.alloc(BucketInfo, self.catalog.buckets.items.len);
        for (self.catalog.buckets.items, out) |b, *o| o.* = .{ .name = try arena.dupe(u8, b.name), .created_ns = b.created_ns };
        return out;
    }

    /// Streams `source` into a new data blob, then swaps the record in atomically.
    pub fn put(self: *ObjectService, bucket: []const u8, key: []const u8, source: *std.Io.Reader, in: PutInput) Error!ObjectInfo {
        try validKey(key);
        const bid = try self.bucketId(bucket);
        const oid = core.ObjectId.random();
        const data_key = placement.dataKey(oid);

        var hbuf: [8 * 1024]u8 = undefined;
        var hr = io.HashingReader(Md5).init(source, Md5.init(.{}), &hbuf);
        _ = self.store.put(data_key, &hr.reader, .{ .size_hint = in.content_length }) catch |e| return mapBackend(e);
        var keep_blob = false;
        defer if (!keep_blob) self.store.delete(data_key) catch {};
        if (in.content_length) |n| if (hr.count != n) return error.IncompleteBody;

        var digest: [16]u8 = undefined;
        hr.hasher.final(&digest);
        const rec: metadata.ObjectRecord = .{
            .object_id = oid,
            .bucket_id = bid,
            .version = core.VersionId.random(),
            .size = hr.count,
            .etag = .{ .md5 = digest },
            .checksum = core.Checksum.fromMd5(digest),
            .created_ns = core.time.nowNs(),
            .key = key,
            .content_type = in.content_type,
        };
        try self.commitRecord(bucket, rec);
        keep_blob = true;
        return infoFrom(rec);
    }

    /// Swaps `rec` in as the current version of its name; its blob must already exist.
    /// On success the previous version's blob is deleted.
    pub fn commitRecord(self: *ObjectService, bucket: []const u8, rec: metadata.ObjectRecord) Error!void {
        const bytes = metadata.record.encode(rec, self.gpa) catch |e| return switch (e) {
            error.KeyTooLong => error.KeyTooLong,
            else => error.OutOfMemory,
        };
        defer self.gpa.free(bytes);

        const rkey = placement.recordKey(core.ids.nameId(rec.bucket_id, rec.key));
        var old: ?core.ObjectId = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.catalog.find(bucket) == null) return error.NoSuchBucket;
            old = self.loadOldId(rkey);
            self.store.putRecord(rkey, bytes) catch |e| return mapBackend(e);
        }
        if (old) |o| if (!o.eql(rec.object_id)) self.store.delete(placement.dataKey(o)) catch {};
    }

    /// Returns object metadata; strings are duplicated into `arena`.
    pub fn head(self: *ObjectService, arena: std.mem.Allocator, bucket: []const u8, key: []const u8) Error!ObjectInfo {
        try validKey(key);
        const bid = try self.bucketId(bucket);
        const rkey = placement.recordKey(core.ids.nameId(bid, key));
        const bytes = self.store.getRecord(rkey, arena) catch |e| return switch (e) {
            error.NotFound => error.NoSuchKey,
            else => mapBackend(e),
        };
        const rec = metadata.record.decode(bytes) catch return error.Corrupt;
        if (!rec.bucket_id.eql(bid) or !std.mem.eql(u8, rec.key, key)) return error.NoSuchKey;
        return infoFrom(rec);
    }

    /// Streams the object's bytes (or `range` of them) into `sink`.
    pub fn read(self: *ObjectService, info: ObjectInfo, range: ?core.Range, sink: *std.Io.Writer) Error!void {
        _ = self.store.get(placement.dataKey(info.object_id), range, sink) catch |e| return switch (e) {
            error.NotFound => error.NoSuchKey,
            else => mapBackend(e),
        };
    }

    /// Deleting a missing key succeeds, as in S3.
    pub fn delete(self: *ObjectService, bucket: []const u8, key: []const u8) Error!void {
        try validKey(key);
        const bid = try self.bucketId(bucket);
        const rkey = placement.recordKey(core.ids.nameId(bid, key));
        var old: ?core.ObjectId = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            old = self.loadOldId(rkey);
            self.store.deleteRecord(rkey) catch |e| switch (e) {
                error.NotFound => {},
                else => return mapBackend(e),
            };
        }
        if (old) |o| self.store.delete(placement.dataKey(o)) catch {};
    }

    /// Full scan of the record space; fine for 0.1, indexed later.
    pub fn list(self: *ObjectService, arena: std.mem.Allocator, bucket: []const u8, p: ListParams) Error!ListResult {
        const bid = try self.bucketId(bucket);
        var entries: std.ArrayList(list_mod.Entry) = .empty;
        var it = try self.scanRecords(arena);
        while (try it.next(self, bid)) |rec| {
            if (!std.mem.startsWith(u8, rec.key, p.prefix)) continue;
            try entries.append(arena, .{ .key = rec.key, .size = rec.size, .etag = rec.etag, .mtime_ns = rec.created_ns });
        }
        return list_mod.apply(arena, entries.items, p);
    }

    pub fn bucketId(self: *ObjectService, name: []const u8) Error!core.BucketId {
        self.mutex.lock();
        defer self.mutex.unlock();
        const b = self.catalog.find(name) orelse return error.NoSuchBucket;
        return b.id;
    }

    fn loadOldId(self: *ObjectService, rkey: backend.PhysicalKey) ?core.ObjectId {
        const bytes = self.store.getRecord(rkey, self.gpa) catch return null;
        defer self.gpa.free(bytes);
        const rec = metadata.record.decode(bytes) catch return null;
        return rec.object_id;
    }

    fn persistCatalog(self: *ObjectService) Error!void {
        const bytes = try self.catalog.encode(self.gpa);
        defer self.gpa.free(bytes);
        self.store.putRecord(placement.catalog_key, bytes) catch |e| return mapBackend(e);
    }

    const RecordIter = struct {
        keys: []const backend.PhysicalKey,
        i: usize = 0,
        arena: std.mem.Allocator,

        /// Next record belonging to `bid`; records deleted mid-scan are skipped.
        fn next(it: *RecordIter, svc: *ObjectService, bid: core.BucketId) Error!?metadata.ObjectRecord {
            while (it.i < it.keys.len) {
                const k = it.keys[it.i];
                it.i += 1;
                const bytes = svc.store.getRecord(k, it.arena) catch |e| switch (e) {
                    error.NotFound => continue,
                    else => return mapBackend(e),
                };
                const rec = metadata.record.decode(bytes) catch continue;
                if (rec.bucket_id.eql(bid)) return rec;
            }
            return null;
        }
    };

    fn scanRecords(self: *ObjectService, arena: std.mem.Allocator) Error!RecordIter {
        const Collect = struct {
            arena: std.mem.Allocator,
            keys: std.ArrayList(backend.PhysicalKey) = .empty,
            fn f(ctx: *anyopaque, k: backend.PhysicalKey) backend.Error!void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                try c.keys.append(c.arena, k);
            }
        };
        var c: Collect = .{ .arena = arena };
        self.store.list(.record, .{ .ctx = &c, .func = Collect.f }) catch |e| switch (e) {
            error.NotFound => {},
            else => return mapBackend(e),
        };
        return .{ .keys = c.keys.items, .arena = arena };
    }
};

fn infoFrom(r: metadata.ObjectRecord) ObjectInfo {
    return .{
        .key = r.key,
        .size = r.size,
        .etag = r.etag,
        .created_ns = r.created_ns,
        .content_type = r.content_type,
        .object_id = r.object_id,
    };
}

pub fn mapBackend(e: backend.Error) Error {
    return switch (e) {
        error.NoSpace => error.NoSpace,
        error.ReadFailed => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
        error.OutOfMemory => error.OutOfMemory,
        error.NotFound, error.InvalidKey, error.IoFailed, error.TooLarge => error.StorageFailed,
    };
}

pub fn validKey(key: []const u8) Error!void {
    if (key.len == 0) return error.InvalidKey;
    if (key.len > metadata.record.max_key_len) return error.KeyTooLong;
}

/// S3 naming rules: 3-63 chars of [a-z0-9.-], alnum at both ends.
pub fn validBucketName(name: []const u8) bool {
    if (name.len < 3 or name.len > 63) return false;
    for (name) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '.' or c == '-')) return false;
    return std.ascii.isAlphanumeric(name[0]) and std.ascii.isAlphanumeric(name[name.len - 1]) and
        std.mem.indexOf(u8, name, "..") == null;
}

test "bucket name rules" {
    try std.testing.expect(validBucketName("my-bucket.1"));
    try std.testing.expect(!validBucketName("ab"));
    try std.testing.expect(!validBucketName("Upper"));
    try std.testing.expect(!validBucketName("-lead"));
    try std.testing.expect(!validBucketName("a..b"));
}

test "service put/head/read/list/delete over local backend" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try ObjectService.init(gpa, lb.backend());
    defer svc.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    try svc.createBucket("bkt");
    try std.testing.expectError(error.BucketAlreadyExists, svc.createBucket("bkt"));
    var src: std.Io.Reader = .fixed("hello");
    const info = try svc.put("bkt", "dir/a.txt", &src, .{ .content_length = 5 });
    var want: [16]u8 = undefined;
    Md5.hash("hello", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &info.etag.md5);

    var src2: std.Io.Reader = .fixed("world!");
    _ = try svc.put("bkt", "dir/a.txt", &src2, .{});
    const h = try svc.head(a, "bkt", "dir/a.txt");
    try std.testing.expectEqual(@as(u64, 6), h.size);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try svc.read(h, .{ .offset = 1, .length = 3 }, &out.writer);
    try std.testing.expectEqualStrings("orl", out.written());

    const r = try svc.list(a, "bkt", .{ .delimiter = "/" });
    try std.testing.expectEqualStrings("dir/", r.common_prefixes[0]);
    try std.testing.expectError(error.BucketNotEmpty, svc.deleteBucket("bkt"));
    try svc.delete("bkt", "dir/a.txt");
    try std.testing.expectError(error.NoSuchKey, svc.head(a, "bkt", "dir/a.txt"));
    try svc.deleteBucket("bkt");
    try std.testing.expectError(error.NoSuchBucket, svc.headBucket("bkt"));

    var bad: std.Io.Reader = .fixed("abc");
    try svc.createBucket("bkt2");
    try std.testing.expectError(error.IncompleteBody, svc.put("bkt2", "k", &bad, .{ .content_length = 10 }));
}
