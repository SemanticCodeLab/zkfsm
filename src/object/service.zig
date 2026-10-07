//! ObjectService: protocol-neutral buckets and objects over a StorageBackend.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const io = @import("../io/root.zig");
const list_mod = @import("list.zig");
const events_mod = @import("events.zig");
const versioning = @import("versioning.zig");
const lock = @import("lock.zig");
const conditional = @import("conditional.zig");
const index_mod = @import("index.zig");
const replica = @import("replica.zig");

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
    PreconditionFailed,
    /// Retention or legal hold forbids the change.
    ObjectLocked,
    NoSuchVersion,
    InvalidVersionId,
    InvalidRequest,
    InvalidBucketState,
    MethodNotAllowed,
    NoSuchTagSet,
    InvalidTag,
    /// User, internal, or system headers over their size bounds.
    MetadataTooLarge,
    /// Malformed header name/value, or a name in the wrong namespace.
    InvalidMetadata,
    /// The body's MD5 differs from the client's Content-MD5.
    BadDigest,
    /// Too many drives or nodes offline to write.
    WriteQuorum,
    /// Too many drives or nodes offline to read.
    ReadQuorum,
    /// A cluster namespace lock could not be taken in time.
    LockTimeout,
    /// The remote tier holding the data could not be reached.
    TierUnavailable,
    /// The operation needs tiered data (restore of a local object).
    InvalidObjectState,
    RestoreInProgress,
    /// A lifecycle rule names a tier that is not configured.
    InvalidStorageClass,
    /// The write would take the bucket past its hard quota.
    QuotaExceeded,
};

/// Cluster coordination hooks; null on a single node, where `mutex` is enough.
pub const Cluster = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Majority lock on `resource` across nodes; returns an unlock token.
        lock: *const fn (ctx: *anyopaque, resource: []const u8) Error!u64,
        unlock: *const fn (ctx: *anyopaque, token: u64) void,
        /// Delivers changes to every peer; called with no service lock held.
        publish: *const fn (ctx: *anyopaque, changes: []const Change) void,
    };
};

/// A committed change peers must mirror in their caches.
pub const Change = union(enum) {
    /// A record slot was written or removed; `version` null is the current slot.
    record: struct { pk: backend.PhysicalKey, bid: core.BucketId, key: []const u8, version: ?core.VersionId },
    upload: core.ObjectId,
    catalog,
    /// Reload everything (a peer may have missed changes).
    resync,
};

/// Held cluster lock on one resource; release with `ObjectService.clusterUnlock`.
pub const Held = struct { token: ?u64 = null };

pub const Header = metadata.headers.Header;
pub const SystemHeaders = metadata.headers.System;

pub const BucketInfo = struct { name: []const u8, created_ns: i128 };

pub const ObjectInfo = struct {
    key: []const u8,
    /// Reported size and ETag: the overrides when set, else the stored blob's.
    size: u64,
    etag: core.ETag,
    /// Bytes in the stored data blob.
    blob_size: u64 = 0,
    created_ns: i128,
    content_type: []const u8,
    object_id: core.ObjectId,
    /// All zeros is the null version.
    version_id: core.VersionId,
    delete_marker: bool = false,
    is_latest: bool = true,
    retention_mode: lock.Mode = .none,
    retain_until_ns: i128 = 0,
    legal_hold: bool = false,
    /// Encoded tag set; decode with `object.decodeTags`.
    tags: []const u8 = "",
    /// Filled by head/headVersion; put echoes the input.
    metadata: []const Header = &.{},
    internal: []const Header = &.{},
    system: SystemHeaders = .{},
    logical_size: ?u64 = null,
    etag_override: ?core.ETag = null,
    /// Multipart part sizes (metadata.record.partSize); empty for single-part objects.
    part_sizes: []const u8 = "",
    /// Remote tier holding the data; empty when local.
    tier: []const u8 = "",
    tier_object: [16]u8 = @splat(0),
    /// Expiry of a restored local copy of tiered data; 0 when none.
    restore_expiry_ns: i128 = 0,

    /// The bytes must come from the tier (no live restored copy).
    pub fn remote(i: ObjectInfo, now_ns: i128) bool {
        return i.tier.len > 0 and i.restore_expiry_ns <= now_ns;
    }
};

pub const PutInput = struct {
    content_type: []const u8 = "",
    /// When set, the body must be exactly this long.
    content_length: ?u64 = null,
    /// Encoded tag set (versioning.encodeObjectTags).
    tags: []const u8 = "",
    /// Explicit retention; otherwise the bucket default applies.
    retention: ?lock.Retention = null,
    legal_hold: bool = false,
    conditions: conditional.Conditions = .{},
    /// Content-MD5 the stored body must match.
    content_md5: ?[16]u8 = null,
    /// User metadata (names without `x-amz-meta-`) and reserved `x-zkfsm-internal-*` headers.
    metadata: []const Header = &.{},
    internal: []const Header = &.{},
    system: SystemHeaders = .{},
    /// Embedding builds that transform the blob (e.g. encryption) set the size and ETag
    /// clients see; the stored blob keeps its own size and MD5 for reads and healing.
    logical_size: ?u64 = null,
    etag_override: ?core.ETag = null,
    /// Called after the body is stored, before commit; its non-null values win.
    /// Lets a transforming reader report plaintext size/MD5 known only at the end.
    finalize: ?Finalizer = null,
};

pub const Finalizer = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque) Final,

    pub const Final = struct { logical_size: ?u64 = null, etag_override: ?core.ETag = null };
};

/// Encoded user and internal lists; free with `deinit`.
pub const EncodedMeta = struct {
    user: []u8,
    internal: []u8,

    pub fn init(gpa: std.mem.Allocator, user: []const Header, internal: []const Header, system: SystemHeaders) Error!EncodedMeta {
        system.validate() catch |e| return mapMeta(e);
        const u = metadata.headers.encode(gpa, user, .user) catch |e| return mapMeta(e);
        errdefer gpa.free(u);
        const i = metadata.headers.encode(gpa, internal, .internal) catch |e| return mapMeta(e);
        return .{ .user = u, .internal = i };
    }

    pub fn deinit(m: EncodedMeta, gpa: std.mem.Allocator) void {
        gpa.free(m.user);
        gpa.free(m.internal);
    }
};

fn mapMeta(e: metadata.headers.Error) Error {
    return switch (e) {
        error.MetadataTooLarge => error.MetadataTooLarge,
        error.InvalidMetadata => error.InvalidMetadata,
        error.OutOfMemory => error.OutOfMemory,
    };
}

pub const ListParams = list_mod.Params;
pub const ListResult = list_mod.Result;

pub const ObjectService = struct {
    gpa: std.mem.Allocator,
    store: backend.StorageBackend,
    catalog: metadata.Catalog,
    /// Guards the catalog and record swaps; data streaming runs unlocked.
    mutex: std.Thread.Mutex = .{},
    /// Names and uploads per bucket; every record write updates it under `mutex`.
    index: index_mod.Index,
    /// The on-disk index state is clean (snapshot matches); guarded by `mutex`.
    index_clean: bool = false,
    index_gen: u64 = 0,
    /// False in cluster mode: the index is always rebuilt from records.
    persist_index: bool = true,
    /// Cluster hooks; set right after init, before serving.
    cluster: ?Cluster = null,
    /// Changes made under `mutex`, published when the operation's lock is released.
    pending: std.ArrayList(Change) = .empty,
    pending_mutex: std.Thread.Mutex = .{},
    /// Remote tiers; set right after init when tiering is available.
    tiers: ?*tier_mod.Registry = null,
    /// Replication engine; set right after init, before serving.
    replication: ?replica.Sink = null,
    /// Bucket notifications; set right after init, before serving.
    events: ?events_mod.Sink = null,

    pub fn init(gpa: std.mem.Allocator, store: backend.StorageBackend) Error!ObjectService {
        return initWith(gpa, store, true);
    }

    /// `persist_index` false always rebuilds the key index from records (cluster mode,
    /// where the snapshot state cannot be kept exact across nodes).
    pub fn initWith(gpa: std.mem.Allocator, store: backend.StorageBackend, persist_index: bool) Error!ObjectService {
        var cat = metadata.Catalog.init(gpa);
        if (store.getRecord(placement.catalog_key, gpa)) |bytes| {
            defer gpa.free(bytes);
            cat = metadata.Catalog.decode(gpa, bytes) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.Corrupt => error.Corrupt,
            };
        } else |e| if (e != error.NotFound) return mapBackend(e);
        var svc: ObjectService = .{ .gpa = gpa, .store = store, .catalog = cat, .index = index_mod.Index.init(gpa), .persist_index = persist_index };
        errdefer svc.deinit();
        try index_store.open(&svc);
        return svc;
    }

    pub fn deinit(self: *ObjectService) void {
        self.index.deinit();
        self.catalog.deinit();
        for (self.pending.items) |c| self.freeChange(c);
        self.pending.deinit(self.gpa);
    }

    /// Hands a committed change to the notification subsystem.
    pub fn emitEvent(self: *ObjectService, ch: events_mod.Change) void {
        const s = self.events orelse return;
        s.notify(s.ctx, ch);
    }

    /// Hands a committed change to the replication engine; replica writes are not re-sent.
    pub fn notifyReplication(self: *ObjectService, ev: replica.Event) void {
        if (replica.origin != null) return;
        const s = self.replication orelse return;
        s.vtable.notify(s.ctx, ev);
    }

    // ---- cluster coordination ----

    /// Takes the cluster lock on `kind/a/b`; a no-op without a cluster.
    pub fn clusterLock(self: *ObjectService, kind: []const u8, a: []const u8, b: []const u8) Error!Held {
        const c = self.cluster orelse return .{};
        var buf: [1400]u8 = undefined;
        const res = std.fmt.bufPrint(&buf, "{s}/{s}/{s}", .{ kind, a, b }) catch return error.KeyTooLong;
        return .{ .token = try c.vtable.lock(c.ctx, res) };
    }

    /// Publishes pending changes, then releases the lock. Call with `mutex` released.
    pub fn clusterUnlock(self: *ObjectService, h: Held) void {
        self.publishPending();
        const c = self.cluster orelse return;
        if (h.token) |t| c.vtable.unlock(c.ctx, t);
    }

    /// Queues a change for peers. Caller holds `mutex`; the key is copied.
    pub fn emit(self: *ObjectService, change: Change) void {
        if (self.cluster == null) return;
        var c = change;
        if (c == .record) c.record.key = self.gpa.dupe(u8, change.record.key) catch return;
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();
        self.pending.append(self.gpa, c) catch self.freeChange(c);
    }

    fn freeChange(self: *ObjectService, c: Change) void {
        if (c == .record) self.gpa.free(c.record.key);
    }

    pub fn publishPending(self: *ObjectService) void {
        const c = self.cluster orelse return;
        var changes: std.ArrayList(Change) = blk: {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            const l = self.pending;
            self.pending = .empty;
            break :blk l;
        };
        defer {
            for (changes.items) |ch| self.freeChange(ch);
            changes.deinit(self.gpa);
        }
        if (changes.items.len > 0) c.vtable.publish(c.ctx, changes.items);
    }

    /// Mirrors a peer's change in this node's caches.
    pub fn applyChange(self: *ObjectService, change: Change) void {
        switch (change) {
            .record => |r| {
                self.mutex.lock();
                defer self.mutex.unlock();
                self.indexResync(r.pk, r.bid, r.key, r.version);
            },
            .upload => |id| {
                self.mutex.lock();
                defer self.mutex.unlock();
                const bytes = self.store.getRecord(placement.uploadKey(id), self.gpa) catch |e| {
                    if (e == error.NotFound) self.index.removeUpload(id) else self.index.markStale();
                    return;
                };
                defer self.gpa.free(bytes);
                var ua = std.heap.ArenaAllocator.init(self.gpa);
                defer ua.deinit();
                const u = metadata.upload.decode(ua.allocator(), bytes) catch return;
                self.index.putUpload(u.upload_id, .{ .bucket = u.bucket_id, .key = u.key, .created_ns = u.created_ns });
            },
            .catalog => self.reloadCatalog() catch |e| std.log.warn("catalog reload failed: {t}", .{e}),
            .resync => {
                self.reloadCatalog() catch |e| std.log.warn("catalog reload failed: {t}", .{e});
                self.rebuildIndex() catch |e| std.log.warn("key index rebuild failed: {t}", .{e});
            },
        }
    }

    /// Re-reads the bucket catalog; buckets that vanished leave the index too.
    pub fn reloadCatalog(self: *ObjectService) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.reloadCatalogLocked();
    }

    fn reloadCatalogLocked(self: *ObjectService) Error!void {
        var cat = metadata.Catalog.init(self.gpa);
        if (self.store.getRecord(placement.catalog_key, self.gpa)) |bytes| {
            defer self.gpa.free(bytes);
            cat = metadata.Catalog.decode(self.gpa, bytes) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.Corrupt => error.Corrupt,
            };
        } else |e| if (e != error.NotFound) return mapBackend(e);
        for (self.catalog.buckets.items) |old| {
            const kept = for (cat.buckets.items) |b| {
                if (b.id.eql(old.id)) break true;
            } else false;
            if (!kept) self.index.dropBucket(old.id);
        }
        self.catalog.deinit();
        self.catalog = cat;
    }

    /// Persists the key index so the next start skips the rebuild. Call on clean shutdown;
    /// a later write marks the snapshot stale again before touching any record.
    pub fn flush(self: *ObjectService) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try index_store.flushLocked(self);
    }

    /// Rebuilds the key index from the records.
    pub fn rebuildIndex(self: *ObjectService) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try index_store.rebuildLocked(self);
    }

    /// Caller holds `mutex`; call before changing any record the index covers.
    pub fn beginIndexChange(self: *ObjectService) Error!void {
        try index_store.markDirtyLocked(self);
        if (self.index.stale) try index_store.rebuildLocked(self);
    }

    fn freshIndex(self: *ObjectService) Error!void {
        if (!self.index.stale) return;
        try self.rebuildIndex();
    }

    pub fn createBucket(self: *ObjectService, name: []const u8) Error!void {
        if (!validBucketName(name)) return error.InvalidBucketName;
        const held = try self.clusterLock("catalog", "", "");
        defer self.clusterUnlock(held);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cluster != null) try self.reloadCatalogLocked();
        if (self.catalog.find(name) != null) return error.BucketAlreadyExists;
        try self.catalog.add(.{ .name = name, .id = core.BucketId.random(), .created_ns = core.time.nowNs() });
        self.persistCatalog() catch |e| {
            _ = self.catalog.remove(name);
            return e;
        };
        self.emit(.catalog);
    }

    pub fn deleteBucket(self: *ObjectService, name: []const u8) Error!void {
        const held = try self.clusterLock("catalog", "", "");
        defer self.clusterUnlock(held);
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.cluster != null) try self.reloadCatalogLocked();
        const b = self.catalog.find(name) orelse return error.NoSuchBucket;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        if (self.index.stale) try index_store.rebuildLocked(self);
        if (!self.index.isEmpty(b.id)) return error.BucketNotEmpty;
        const saved = b;
        const name_copy = try arena.allocator().dupe(u8, name);
        _ = self.catalog.remove(name);
        self.persistCatalog() catch |e| {
            self.catalog.add(.{ .name = name_copy, .id = saved.id, .created_ns = saved.created_ns }) catch {};
            return e;
        };
        self.store.deleteRecord(placement.bucketConfigKey(saved.id)) catch {};
        self.index.dropBucket(saved.id);
        index_store.dropStream(self, saved.id.bytes);
        self.emit(.catalog);
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
        if (in.content_length) |n| try @import("quota.zig").precheck(self, bucket, key, n);
        const meta = try EncodedMeta.init(self.gpa, in.metadata, in.internal, in.system);
        defer meta.deinit(self.gpa);
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
        if (in.content_md5) |want| if (!std.mem.eql(u8, &want, &digest)) return error.BadDigest;
        var logical_size = in.logical_size;
        var etag_override = in.etag_override;
        if (in.finalize) |f| {
            const fin = f.func(f.ctx);
            if (fin.logical_size) |v| logical_size = v;
            if (fin.etag_override) |v| etag_override = v;
        }
        var rec: metadata.ObjectRecord = .{
            .object_id = oid,
            .bucket_id = bid,
            .version = core.VersionId.random(),
            .size = hr.count,
            .etag = .{ .md5 = digest },
            .checksum = core.Checksum.fromMd5(digest),
            .created_ns = core.time.nowNs(),
            .key = key,
            .content_type = in.content_type,
            .tags = in.tags,
            .user_meta = meta.user,
            .internal_meta = meta.internal,
            .system = in.system,
            .logical_size = logical_size,
            .etag_override = etag_override,
        };
        const garbage = try versioning.commitPut(self, bucket, &rec, in);
        keep_blob = true;
        garbage.collect(self);
        var info = infoFrom(rec);
        info.metadata = in.metadata;
        info.internal = in.internal;
        return info;
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
        if (rec.flags.delete_marker) return error.NoSuchKey;
        return decodeInfo(arena, rec);
    }

    /// Streams the object's bytes (or `range` of them) into `sink`.
    pub fn read(self: *ObjectService, info: ObjectInfo, range: ?core.Range, sink: *std.Io.Writer) Error!void {
        if (info.remote(core.time.nowNs())) return tier_mod.readRemote(self, info, range, sink);
        _ = self.store.get(placement.dataKey(info.object_id), range, sink) catch |e| return switch (e) {
            // A restored copy may have just expired.
            error.NotFound => if (info.tier.len > 0) tier_mod.readRemote(self, info, range, sink) else error.NoSuchKey,
            else => mapBackend(e),
        };
    }

    /// Deleting a missing key succeeds, as in S3. Versioned buckets get a delete marker.
    pub fn delete(self: *ObjectService, bucket: []const u8, key: []const u8) Error!void {
        _ = try versioning.deleteObject(self, bucket, key, .{});
    }

    /// Served from the key index: cost follows the page size, not the bucket size.
    pub fn list(self: *ObjectService, arena: std.mem.Allocator, bucket: []const u8, p: ListParams) Error!ListResult {
        const bid = try self.bucketId(bucket);
        try self.freshIndex();
        return list_mod.apply(arena, try self.index.collectList(arena, bid, p), p);
    }

    /// Updates the index after `rec` was stored at `pk`. Caller holds `mutex`.
    pub fn indexStored(self: *ObjectService, pk: backend.PhysicalKey, rec: metadata.ObjectRecord) void {
        const v = index_mod.Version.of(rec);
        if (std.mem.eql(u8, &pk.hex, &placement.recordKey(core.ids.nameId(rec.bucket_id, rec.key)).hex))
            self.index.setCurrent(rec.bucket_id, rec.key, v)
        else
            self.index.putNoncurrent(rec.bucket_id, rec.key, v);
    }

    /// Re-reads one record slot after a failed write and fixes the index from it.
    /// `version` null is the current slot. Caller holds `mutex`.
    pub fn indexResync(self: *ObjectService, pk: backend.PhysicalKey, bid: core.BucketId, key: []const u8, version: ?core.VersionId) void {
        const bytes = self.store.getRecord(pk, self.gpa) catch |e| {
            if (e != error.NotFound) return self.index.markStale();
            if (version) |v| self.index.removeNoncurrent(bid, key, v) else self.index.setCurrent(bid, key, null);
            return;
        };
        defer self.gpa.free(bytes);
        const rec = metadata.record.decode(bytes) catch return self.index.markStale();
        self.indexStored(pk, rec);
    }

    pub fn bucketId(self: *ObjectService, name: []const u8) Error!core.BucketId {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.catalog.find(name)) |b| return b.id;
        // A peer may have created it moments ago.
        if (self.cluster == null) return error.NoSuchBucket;
        try self.reloadCatalogLocked();
        const b = self.catalog.find(name) orelse return error.NoSuchBucket;
        return b.id;
    }

    fn persistCatalog(self: *ObjectService) Error!void {
        const bytes = try self.catalog.encode(self.gpa);
        defer self.gpa.free(bytes);
        self.store.putRecord(placement.catalog_key, bytes) catch |e| return mapBackend(e);
    }

    pub const RecordIter = struct {
        keys: []const backend.PhysicalKey,
        i: usize = 0,
        arena: std.mem.Allocator,

        /// Next record belonging to `bid`; records deleted mid-scan are skipped.
        pub fn next(it: *RecordIter, svc: *ObjectService, bid: core.BucketId) Error!?metadata.ObjectRecord {
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

        /// Physical key of the record last returned by `next`.
        pub fn lastKey(it: *const RecordIter) backend.PhysicalKey {
            return it.keys[it.i - 1];
        }
    };

    pub fn scanRecords(self: *ObjectService, arena: std.mem.Allocator) Error!RecordIter {
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

const index_store = @import("index_store.zig");
const tier_mod = @import("tier.zig");

/// Header lists are left empty; see `decodeInfo`.
pub fn infoFrom(r: metadata.ObjectRecord) ObjectInfo {
    return .{
        .key = r.key,
        .size = r.reportedSize(),
        .etag = r.reportedEtag(),
        .blob_size = r.size,
        .system = r.system,
        .logical_size = r.logical_size,
        .etag_override = r.etag_override,
        .created_ns = r.created_ns,
        .content_type = r.content_type,
        .object_id = r.object_id,
        .version_id = r.versionId(),
        .delete_marker = r.flags.delete_marker,
        .retention_mode = r.retention_mode,
        .retain_until_ns = r.retain_until_ns,
        .legal_hold = r.flags.legal_hold,
        .tags = r.tags,
        .part_sizes = r.part_sizes,
        .tier = r.tier,
        .tier_object = r.tier_object,
        .restore_expiry_ns = r.restore_expiry_ns,
    };
}

/// `infoFrom` plus the decoded header lists (allocated in `arena`, borrowing from `r`).
pub fn decodeInfo(arena: std.mem.Allocator, r: metadata.ObjectRecord) Error!ObjectInfo {
    var info = infoFrom(r);
    info.metadata = metadata.headers.decode(arena, r.user_meta) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    info.internal = metadata.headers.decode(arena, r.internal_meta) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    return info;
}

pub fn mapBackend(e: backend.Error) Error {
    return switch (e) {
        error.NoSpace => error.NoSpace,
        error.ReadFailed => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
        error.OutOfMemory => error.OutOfMemory,
        error.NotFound, error.InvalidKey, error.IoFailed, error.TooLarge => error.StorageFailed,
        error.WriteQuorum => error.WriteQuorum,
        error.ReadQuorum => error.ReadQuorum,
    };
}

pub fn validKey(key: []const u8) Error!void {
    if (key.len == 0) return error.InvalidKey;
    if (key.len > metadata.record.max_key_len) return error.KeyTooLong;
}

/// S3 naming rules: 3-63 chars of [a-z0-9.-], alnum at both ends, not an IPv4 address.
pub fn validBucketName(name: []const u8) bool {
    if (name.len < 3 or name.len > 63) return false;
    for (name) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '.' or c == '-')) return false;
    if (std.net.Address.parseIp4(name, 0)) |_| return false else |_| {}
    return std.ascii.isAlphanumeric(name[0]) and std.ascii.isAlphanumeric(name[name.len - 1]) and
        std.mem.indexOf(u8, name, "..") == null;
}

test "bucket name rules" {
    try std.testing.expect(validBucketName("my-bucket.1"));
    try std.testing.expect(!validBucketName("ab"));
    try std.testing.expect(!validBucketName("Upper"));
    try std.testing.expect(!validBucketName("-lead"));
    try std.testing.expect(!validBucketName("a..b"));
    try std.testing.expect(!validBucketName("192.168.1.1"));
    try std.testing.expect(validBucketName("192.168.1.1.x"));
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
    var md5_src: std.Io.Reader = .fixed("hello");
    try std.testing.expectError(error.BadDigest, svc.put("bkt2", "md5", &md5_src, .{ .content_md5 = @splat(0) }));
}

test "finalizer sets reported size and etag after streaming" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try ObjectService.init(gpa, lb.backend());
    defer svc.deinit();
    try svc.createBucket("fin");

    const Probe = struct {
        called: bool = false,
        fn func(ctx: *anyopaque) Finalizer.Final {
            const p: *@This() = @ptrCast(@alignCast(ctx));
            p.called = true;
            return .{ .logical_size = 2, .etag_override = .{ .md5 = [_]u8{7} ** 16 } };
        }
    };
    var probe: Probe = .{};
    var body: std.Io.Reader = .fixed("ciphertext");
    const info = try svc.put("fin", "k", &body, .{ .logical_size = 99, .finalize = .{ .ctx = &probe, .func = Probe.func } });
    try std.testing.expect(probe.called);
    try std.testing.expectEqual(@as(u64, 2), info.size);
    try std.testing.expectEqual([_]u8{7} ** 16, info.etag.md5);

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const h = try svc.head(arena.allocator(), "fin", "k");
    try std.testing.expectEqual(@as(u64, 2), h.size);
    try std.testing.expectEqual(@as(u64, 10), h.blob_size);
}
