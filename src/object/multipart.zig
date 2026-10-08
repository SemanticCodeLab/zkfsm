//! Multipart uploads. Each part is its own data blob; the upload's state is one
//! UploadRecord in the record space. Complete streams the parts into a single new
//! blob, so reads and ranges of the final object stay plain single-blob reads.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const io = @import("../io/root.zig");
const service = @import("service.zig");
const lock = @import("lock.zig");
const blob = @import("blob.zig");
const tier = @import("tier.zig");
const copy = @import("copy.zig");
const versioning = @import("versioning.zig");
const quota = @import("quota.zig");

const ObjectService = service.ObjectService;
const Md5 = core.checksum.Md5;
const upload = metadata.upload;

pub const UploadId = upload.UploadId;
pub const UploadRecord = upload.UploadRecord;
pub const Part = upload.Part;

pub const Error = service.Error || error{
    NoSuchUpload,
    /// A listed part was never uploaded or its ETag does not match.
    InvalidPart,
    /// Listed parts are not in strictly ascending order.
    InvalidPartOrder,
    /// A part other than the last is below `min_part_size`.
    EntityTooSmall,
    /// Part number outside 1..10000, or an empty part list.
    InvalidPartNumber,
    /// Copy source range outside the source object.
    InvalidRange,
};

pub const min_part_size: u64 = 5 * 1024 * 1024;
pub const max_part_number: u16 = upload.max_parts;

/// Inclusive byte range of a copy source.
pub const CopyRange = struct { first: u64, last: u64 };

/// A part as named by the client in CompleteMultipartUpload.
pub const PartRef = struct { number: u16, md5: [16]u8 };

/// Starts an upload. Content type, tags, lock settings, and metadata from `in` are
/// applied to the object on complete; `in.conditions` and overrides are ignored.
pub fn create(svc: *ObjectService, bucket: []const u8, key: []const u8, in: service.PutInput) Error!UploadId {
    try service.validKey(key);
    const bid = try svc.bucketId(bucket);
    if (in.retention != null or in.legal_hold) {
        var arena = std.heap.ArenaAllocator.init(svc.gpa);
        defer arena.deinit();
        if (!(try versioning.getConfig(svc, arena.allocator(), bucket)).lock_enabled) return error.InvalidRequest;
    }
    const ret = in.retention orelse lock.Retention{};
    const meta = try service.EncodedMeta.init(svc.gpa, in.metadata, in.internal, in.system);
    defer meta.deinit(svc.gpa);
    const rec: UploadRecord = .{
        .upload_id = UploadId.random(),
        .bucket_id = bid,
        .created_ns = core.time.nowNs(),
        .key = key,
        .content_type = in.content_type,
        .tags = in.tags,
        .retention_mode = ret.mode,
        .retain_until_ns = ret.until_ns,
        .legal_hold = in.legal_hold,
        .user_meta = meta.user,
        .internal_meta = meta.internal,
        .system = in.system,
    };
    defer svc.publishPending();
    svc.mutex.lock();
    defer svc.mutex.unlock();
    try storeUpload(svc, rec);
    return rec.upload_id;
}

/// Streams one part into its own blob and records it, replacing any earlier part with the same number.
pub fn uploadPart(
    svc: *ObjectService,
    bucket: []const u8,
    key: []const u8,
    id: UploadId,
    number: u16,
    source: *std.Io.Reader,
    content_length: ?u64,
) Error!core.ETag {
    return uploadPartWith(svc, bucket, key, id, number, source, content_length, null);
}

/// Additional checksum of a part, filled by the caller's reader once the body is read.
pub const PartChecksum = struct { len: u8 = 0, bytes: [upload.max_checksum_len]u8 = @splat(0) };

/// `uploadPart` that records `checksum` (read after the body is stored) with the part.
pub fn uploadPartWith(
    svc: *ObjectService,
    bucket: []const u8,
    key: []const u8,
    id: UploadId,
    number: u16,
    source: *std.Io.Reader,
    content_length: ?u64,
    checksum: ?*const PartChecksum,
) Error!core.ETag {
    if (number == 0 or number > max_part_number) return error.InvalidPartNumber;
    const bid = try svc.bucketId(bucket);
    if (content_length) |n| try quota.precheck(svc, bucket, null, n);
    {
        var arena = std.heap.ArenaAllocator.init(svc.gpa);
        defer arena.deinit();
        _ = try loadUpload(svc, arena.allocator(), bid, key, id);
    }
    const oid = core.ObjectId.random();
    const data_key = placement.dataKey(oid);
    var hbuf: [8 * 1024]u8 = undefined;
    var hr = io.HashingReader(Md5).init(source, Md5.init(.{}), &hbuf);
    _ = svc.store.put(data_key, &hr.reader, .{ .size_hint = content_length }) catch |e| return service.mapBackend(e);
    var keep_blob = false;
    defer if (!keep_blob) svc.store.delete(data_key) catch {};
    if (content_length) |n| if (hr.count != n) return error.IncompleteBody;
    var digest: [16]u8 = undefined;
    hr.hasher.final(&digest);
    var part: Part = .{ .number = number, .size = hr.count, .md5 = digest, .blob = oid, .created_ns = core.time.nowNs() };
    if (checksum) |ck| {
        part.checksum_len = ck.len;
        part.checksum_bytes = ck.bytes;
    }

    var replaced: ?core.ObjectId = null;
    {
        const held = try svc.clusterLock("upload", &id.toHex(), "");
        defer svc.clusterUnlock(held);
        var arena = std.heap.ArenaAllocator.init(svc.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        svc.mutex.lock();
        defer svc.mutex.unlock();
        var rec = try loadUpload(svc, a, bid, key, id);
        var parts: std.ArrayList(Part) = .empty;
        try parts.ensureTotalCapacity(a, rec.parts.len + 1);
        var placed = false;
        for (rec.parts) |p| {
            if (!placed and p.number >= number) {
                parts.appendAssumeCapacity(part);
                placed = true;
                if (p.number == number) {
                    replaced = p.blob;
                    continue;
                }
            }
            parts.appendAssumeCapacity(p);
        }
        if (!placed) parts.appendAssumeCapacity(part);
        rec.parts = parts.items;
        try storeUpload(svc, rec);
    }
    keep_blob = true;
    if (replaced) |r| svc.store.delete(placement.dataKey(r)) catch {};
    return .{ .md5 = digest };
}

/// UploadPartCopy: the part's bytes come from an existing object, optionally a
/// byte range `first..last` (inclusive) of it.
pub fn uploadPartCopy(
    svc: *ObjectService,
    bucket: []const u8,
    key: []const u8,
    id: UploadId,
    number: u16,
    src: copy.Source,
    range: ?CopyRange,
) Error!core.ETag {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const info = try copy.resolveSource(svc, arena.allocator(), src);
    var off: u64 = 0;
    var len: u64 = info.size;
    if (range) |r| {
        if (r.last < r.first or r.last >= info.size) return error.InvalidRange;
        off = r.first;
        len = r.last - r.first + 1;
    }
    var buf: [64 * 1024]u8 = undefined;
    var src_rd: tier.Source = undefined;
    try src_rd.init(svc, info, off, len, &buf);
    defer src_rd.deinit();
    return uploadPart(svc, bucket, key, id, number, src_rd.reader(), len) catch |e| switch (e) {
        error.ReadFailed => src_rd.failure() orelse error.ReadFailed,
        else => e,
    };
}

/// Validates the client's part list, concatenates the parts into the final object,
/// then drops the upload and every part blob. ETag is md5(part md5s) with a part count.
pub fn complete(svc: *ObjectService, bucket: []const u8, key: []const u8, id: UploadId, refs: []const PartRef) Error!service.ObjectInfo {
    return completeWith(svc, bucket, key, id, refs, .{});
}

pub const CompleteOptions = struct {
    /// If-Match / If-None-Match against the current object, checked atomically at commit.
    conditions: @import("conditional.zig").Conditions = .{},
    /// Internal headers added to the object's (replacing same-named ones from the upload).
    internal: []const service.Header = &.{},
};

pub fn completeWith(svc: *ObjectService, bucket: []const u8, key: []const u8, id: UploadId, refs: []const PartRef, opts: CompleteOptions) Error!service.ObjectInfo {
    const bid = try svc.bucketId(bucket);
    const held = try svc.clusterLock("upload", &id.toHex(), "");
    defer svc.clusterUnlock(held);
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const rec = try loadUploadLocked(svc, a, bid, key, id);
    const segs = try a.alloc(blob.Segment, refs.len);
    try planComplete(rec, refs, segs);

    var etag_hash = Md5.init(.{});
    for (refs) |r| etag_hash.update(&r.md5);
    var etag: core.ETag = .{ .md5 = undefined, .parts = @intCast(refs.len) };
    etag_hash.final(&etag.md5);

    const oid = core.ObjectId.random();
    const data_key = placement.dataKey(oid);
    var bbuf: [64 * 1024]u8 = undefined;
    var br = blob.BlobReader.init(svc.store, segs, &bbuf);
    var hbuf: [8 * 1024]u8 = undefined;
    var hr = io.HashingReader(Md5).init(&br.reader, Md5.init(.{}), &hbuf);
    const total = blob.BlobReader.totalLen(segs);
    _ = svc.store.put(data_key, &hr.reader, .{ .size_hint = total }) catch |e| return switch (e) {
        // A part blob vanished: the upload was aborted concurrently.
        error.ReadFailed => if (br.err) |be| (if (be == error.NotFound) error.NoSuchUpload else service.mapBackend(be)) else error.StorageFailed,
        else => service.mapBackend(e),
    };
    var keep_blob = false;
    defer if (!keep_blob) svc.store.delete(data_key) catch {};
    if (hr.count != total) return error.StorageFailed;
    var full: [16]u8 = undefined;
    hr.hasher.final(&full);
    const sizes = try a.alloc(u8, segs.len * 8);
    for (segs, 0..) |s, i| std.mem.writeInt(u64, sizes[i * 8 ..][0..8], s.length, .little);

    var obj: metadata.ObjectRecord = .{
        .object_id = oid,
        .bucket_id = bid,
        .version = core.VersionId.random(),
        .size = total,
        .etag = etag,
        .checksum = core.Checksum.fromMd5(full),
        .created_ns = core.time.nowNs(),
        .key = key,
        .content_type = rec.content_type,
        .tags = rec.tags,
        .user_meta = rec.user_meta,
        .internal_meta = rec.internal_meta,
        .system = rec.system,
        .part_sizes = sizes,
    };
    for (opts.internal) |h| obj.internal_meta = try @import("objmeta.zig").withHeader(a, obj.internal_meta, h.name, h.value);
    // Versioning assigns the version id and applies lock defaults.
    const garbage = try versioning.commitPut(svc, bucket, &obj, .{
        .content_type = rec.content_type,
        .tags = rec.tags,
        .retention = if (rec.retention_mode != .none) .{ .mode = rec.retention_mode, .until_ns = rec.retain_until_ns } else null,
        .legal_hold = rec.legal_hold,
        .conditions = opts.conditions,
    });
    keep_blob = true;
    garbage.collect(svc);
    dropUpload(svc, id);
    // Strings in `obj` die with the arena.
    var info = service.infoFrom(obj);
    info.content_type = "";
    info.tags = "";
    info.system = .{};
    info.part_sizes = "";
    return info;
}

/// Checks refs against the recorded parts and fills one segment per ref.
fn planComplete(rec: UploadRecord, refs: []const PartRef, segs: []blob.Segment) Error!void {
    if (refs.len == 0) return error.InvalidPartNumber;
    var prev: u16 = 0;
    for (refs) |r| {
        if (r.number <= prev) return error.InvalidPartOrder;
        prev = r.number;
    }
    for (refs, segs, 0..) |r, *s, i| {
        const p = rec.findPart(r.number) orelse return error.InvalidPart;
        if (!std.mem.eql(u8, &p.md5, &r.md5)) return error.InvalidPart;
        if (i + 1 < refs.len and p.size < min_part_size) return error.EntityTooSmall;
        s.* = .{ .blob = p.blob, .offset = 0, .length = p.size };
    }
}

pub fn abort(svc: *ObjectService, bucket: []const u8, key: []const u8, id: UploadId) Error!void {
    const bid = try svc.bucketId(bucket);
    const held = try svc.clusterLock("upload", &id.toHex(), "");
    defer svc.clusterUnlock(held);
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    _ = try loadUploadLocked(svc, arena.allocator(), bid, key, id);
    dropUpload(svc, id);
}

/// Value of one internal header of an upload record, if set.
pub fn uploadHeader(arena: std.mem.Allocator, rec: UploadRecord, name: []const u8) Error!?[]const u8 {
    const hs = metadata.headers.decode(arena, rec.internal_meta) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    for (hs) |h| if (std.mem.eql(u8, h.name, name)) return h.value;
    return null;
}

/// The upload with its sorted part list; strings and parts live in `arena`.
pub fn listParts(svc: *ObjectService, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, id: UploadId) Error!UploadRecord {
    const bid = try svc.bucketId(bucket);
    return loadUploadLocked(svc, arena, bid, key, id);
}

/// In-progress uploads of `bucket` whose key starts with `prefix`, sorted by key then start time.
pub fn listUploads(svc: *ObjectService, arena: std.mem.Allocator, bucket: []const u8, prefix: []const u8) Error![]UploadRecord {
    const bid = try svc.bucketId(bucket);
    if (svc.index.stale) try svc.rebuildIndex();
    var out: std.ArrayList(UploadRecord) = .empty;
    for (try svc.index.uploadsOf(arena, bid, prefix)) |u| {
        const r = loadUploadLocked(svc, arena, bid, u.upload.key, u.id) catch |e| switch (e) {
            error.NoSuchUpload => continue,
            else => return e,
        };
        try out.append(arena, r);
    }
    std.mem.sort(UploadRecord, out.items, {}, lessUpload);
    return out.items;
}

fn lessUpload(_: void, a: UploadRecord, b: UploadRecord) bool {
    return switch (std.mem.order(u8, a.key, b.key)) {
        .lt => true,
        .gt => false,
        .eq => a.created_ns < b.created_ns,
    };
}

/// Aborts uploads started before `now_ns - max_age_ns`, and uploads whose bucket is gone.
/// Returns the number removed. Safe to call from a timer thread.
pub fn sweepStale(svc: *ObjectService, now_ns: i128, max_age_ns: i128) Error!usize {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    if (svc.index.stale) try svc.rebuildIndex();
    var n: usize = 0;
    for (try svc.index.uploadsOf(arena.allocator(), null, "")) |u| {
        const orphan = blk: {
            svc.mutex.lock();
            defer svc.mutex.unlock();
            for (svc.catalog.buckets.items) |b| if (b.id.eql(u.upload.bucket)) break :blk false;
            break :blk true;
        };
        if (!orphan and now_ns - u.upload.created_ns < max_age_ns) continue;
        dropUpload(svc, u.id);
        svc.publishPending();
        n += 1;
    }
    return n;
}

fn loadUploadLocked(svc: *ObjectService, arena: std.mem.Allocator, bid: core.BucketId, key: []const u8, id: UploadId) Error!UploadRecord {
    svc.mutex.lock();
    defer svc.mutex.unlock();
    return loadUpload(svc, arena, bid, key, id);
}

/// Caller holds svc.mutex, or accepts a racy snapshot.
fn loadUpload(svc: *ObjectService, arena: std.mem.Allocator, bid: core.BucketId, key: []const u8, id: UploadId) Error!UploadRecord {
    const bytes = svc.store.getRecord(placement.uploadKey(id), arena) catch |e| return switch (e) {
        error.NotFound => error.NoSuchUpload,
        else => service.mapBackend(e),
    };
    if (!upload.isUpload(bytes)) return error.NoSuchUpload;
    const r = upload.decode(arena, bytes) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Corrupt,
    };
    if (!r.bucket_id.eql(bid) or !std.mem.eql(u8, r.key, key) or !r.upload_id.eql(id)) return error.NoSuchUpload;
    return r;
}

fn storeUpload(svc: *ObjectService, rec: UploadRecord) Error!void {
    const bytes = upload.encode(rec, svc.gpa) catch |e| return switch (e) {
        error.KeyTooLong => error.KeyTooLong,
        error.MetadataTooLarge => error.MetadataTooLarge,
        else => error.OutOfMemory,
    };
    defer svc.gpa.free(bytes);
    try svc.beginIndexChange();
    // Indexed first: a failed write may still have landed, and a stale entry is skipped on read.
    svc.index.putUpload(rec.upload_id, .{ .bucket = rec.bucket_id, .key = rec.key, .created_ns = rec.created_ns });
    const change: service.Change = .{ .upload = rec.upload_id };
    defer svc.emitSeq(change, svc.journal(change));
    svc.store.putRecord(placement.uploadKey(rec.upload_id), bytes) catch |e| return service.mapBackend(e);
}

/// Deletes the upload record, then its part blobs. Best effort; a missing record is fine.
fn dropUpload(svc: *ObjectService, id: UploadId) void {
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const rec = blk: {
        svc.mutex.lock();
        defer svc.mutex.unlock();
        const bytes = svc.store.getRecord(placement.uploadKey(id), arena.allocator()) catch |e| {
            if (e == error.NotFound) svc.index.removeUpload(id);
            return;
        };
        if (!upload.isUpload(bytes)) return;
        const r = upload.decode(arena.allocator(), bytes) catch return;
        svc.beginIndexChange() catch return;
        const seq = svc.journal(.{ .upload = id });
        defer svc.emitSeq(.{ .upload = id }, seq);
        svc.store.deleteRecord(placement.uploadKey(id)) catch return;
        svc.index.removeUpload(id);
        break :blk r;
    };
    for (rec.parts) |p| svc.store.delete(placement.dataKey(p.blob)) catch {};
}

const testing = std.testing;

const Fixture = struct {
    tmp: testing.TmpDir,
    lb: backend.local.LocalBackend,
    svc: ObjectService,

    fn init(self: *Fixture) !void {
        self.tmp = testing.tmpDir(.{});
        var pbuf: [std.fs.max_path_bytes]u8 = undefined;
        self.lb = try backend.local.LocalBackend.open(try self.tmp.dir.realpath(".", &pbuf));
        self.svc = try ObjectService.init(testing.allocator, self.lb.backend());
        try self.svc.createBucket("bkt");
    }

    fn deinit(self: *Fixture) void {
        self.svc.deinit();
        self.lb.close();
        self.tmp.cleanup();
    }

    fn put(self: *Fixture, id: UploadId, n: u16, bytes: []const u8) !PartRef {
        var r: std.Io.Reader = .fixed(bytes);
        const e = try uploadPart(&self.svc, "bkt", "big", id, n, &r, bytes.len);
        return .{ .number = n, .md5 = e.md5 };
    }

    fn dataBlobs(self: *Fixture) !usize {
        const C = struct {
            n: usize = 0,
            fn f(ctx: *anyopaque, _: backend.PhysicalKey) backend.Error!void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                c.n += 1;
            }
        };
        var c: C = .{};
        try self.svc.store.list(.data, .{ .ctx = &c, .func = C.f });
        return c.n;
    }
};

test "multipart upload, complete, and md5-of-md5s etag" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const big = try gpa.alloc(u8, min_part_size);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 31);

    const id = try create(&fx.svc, "bkt", "big", .{
        .content_type = "application/x-test",
        .metadata = &.{.{ .name = "k", .value = "v" }},
        .system = .{ .content_disposition = "inline" },
    });
    _ = try fx.put(id, 2, "stale"); // replaced below
    const p2 = try fx.put(id, 2, "tail");
    const p1 = try fx.put(id, 1, big);
    try testing.expectEqual(@as(usize, 2), try fx.dataBlobs());

    const lp = try listParts(&fx.svc, a, "bkt", "big", id);
    try testing.expectEqual(@as(usize, 2), lp.parts.len);
    try testing.expectEqual(@as(u16, 1), lp.parts[0].number);
    try testing.expectEqual(@as(u64, 4), lp.parts[1].size);
    try testing.expectEqual(@as(usize, 1), (try listUploads(&fx.svc, a, "bkt", "b")).len);
    try testing.expectEqual(@as(usize, 0), (try listUploads(&fx.svc, a, "bkt", "x")).len);

    // Validation failures leave the upload intact.
    try testing.expectError(error.InvalidPartOrder, complete(&fx.svc, "bkt", "big", id, &.{ p2, p1 }));
    try testing.expectError(error.InvalidPart, complete(&fx.svc, "bkt", "big", id, &.{ p1, .{ .number = 3, .md5 = p2.md5 } }));
    try testing.expectError(error.InvalidPart, complete(&fx.svc, "bkt", "big", id, &.{ p1, .{ .number = 2, .md5 = p1.md5 } }));
    try testing.expectError(error.EntityTooSmall, complete(&fx.svc, "bkt", "big", id, &.{ p2, .{ .number = 3, .md5 = p1.md5 } }));
    try testing.expectError(error.InvalidPartNumber, complete(&fx.svc, "bkt", "big", id, &.{}));
    try testing.expectError(error.NoSuchUpload, complete(&fx.svc, "bkt", "other", id, &.{p1}));

    const info = try complete(&fx.svc, "bkt", "big", id, &.{ p1, p2 });
    var h = Md5.init(.{});
    h.update(&p1.md5);
    h.update(&p2.md5);
    var want: [16]u8 = undefined;
    h.final(&want);
    try testing.expectEqualSlices(u8, &want, &info.etag.md5);
    try testing.expectEqual(@as(u32, 2), info.etag.parts);

    const hd = try fx.svc.head(a, "bkt", "big");
    try testing.expectEqual(@as(u64, min_part_size + 4), hd.size);
    try testing.expectEqual(@as(u32, 2), hd.etag.parts);
    try testing.expectEqual(@as(usize, 16), hd.part_sizes.len);
    try testing.expectEqual(@as(u64, 4), metadata.record.partSize(hd.part_sizes, 1));
    try testing.expectEqualStrings("application/x-test", hd.content_type);
    try testing.expectEqualStrings("v", hd.metadata[0].value);
    try testing.expectEqualStrings("inline", hd.system.content_disposition);
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try fx.svc.read(hd, .{ .offset = min_part_size - 2, .length = 6 }, &out.writer);
    try testing.expectEqualSlices(u8, big[big.len - 2 ..], out.written()[0..2]);
    try testing.expectEqualStrings("tail", out.written()[2..]);

    // Parts are gone; only the final blob remains.
    try testing.expectEqual(@as(usize, 1), try fx.dataBlobs());
    try testing.expectError(error.NoSuchUpload, listParts(&fx.svc, a, "bkt", "big", id));
}

test "multipart abort, part number bounds, and stale sweep" {
    var fx: Fixture = undefined;
    try fx.init();
    defer fx.deinit();
    const id = try create(&fx.svc, "bkt", "big", .{});
    _ = try fx.put(id, 1, "x");
    try testing.expectError(error.InvalidPartNumber, fx.put(id, 0, "x"));
    try testing.expectError(error.InvalidPartNumber, fx.put(id, max_part_number + 1, "x"));
    try testing.expectError(error.NoSuchUpload, fx.put(UploadId.random(), 1, "x"));
    try fx.svc.createBucket("src");
    var body: std.Io.Reader = .fixed("0123456789");
    _ = try fx.svc.put("src", "obj", &body, .{});
    const cp = try uploadPartCopy(&fx.svc, "bkt", "big", id, 2, .{ .bucket = "src", .key = "obj" }, .{ .first = 2, .last = 4 });
    var want: [16]u8 = undefined;
    Md5.hash("234", &want, .{});
    try testing.expectEqualSlices(u8, &want, &cp.md5);
    const src: copy.Source = .{ .bucket = "src", .key = "obj" };
    try testing.expectError(error.InvalidRange, uploadPartCopy(&fx.svc, "bkt", "big", id, 3, src, .{ .first = 5, .last = 10 }));
    try testing.expectError(error.NoSuchKey, uploadPartCopy(&fx.svc, "bkt", "big", id, 3, .{ .bucket = "src", .key = "no" }, null));
    try abort(&fx.svc, "bkt", "big", id);
    try testing.expectError(error.NoSuchUpload, abort(&fx.svc, "bkt", "big", id));
    try testing.expectEqual(@as(usize, 1), try fx.dataBlobs()); // src/obj

    const old = try create(&fx.svc, "bkt", "big", .{});
    _ = try fx.put(old, 1, "x");
    const now = core.time.nowNs();
    try testing.expectEqual(@as(usize, 0), try sweepStale(&fx.svc, now, std.time.ns_per_hour));
    try testing.expectEqual(@as(usize, 1), try sweepStale(&fx.svc, now + 2 * std.time.ns_per_hour, std.time.ns_per_hour));
    try testing.expectEqual(@as(usize, 1), try fx.dataBlobs()); // src/obj
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(@as(usize, 0), (try listUploads(&fx.svc, arena.allocator(), "bkt", "")).len);
}
