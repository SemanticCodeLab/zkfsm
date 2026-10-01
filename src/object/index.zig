//! Key index: per bucket, the names in S3 byte order with a summary of each stored
//! version, plus the set of in-progress uploads. The records stay the source of truth;
//! the index is rebuilt from them whenever its snapshot is missing or not clean.
const std = @import("std");
const core = @import("../core/root.zig");
const metadata = @import("../metadata/root.zig");
const codec = @import("../metadata/codec.zig");
const list = @import("list.zig");

/// Listing fields of one stored version.
pub const Version = struct {
    /// Client-visible id; all zeros is the null version.
    id: core.VersionId,
    size: u64,
    etag: core.ETag,
    mtime_ns: i128,
    delete_marker: bool,
    /// Data lives on a remote tier (listings report its storage class).
    tiered: bool = false,

    pub fn of(r: metadata.ObjectRecord) Version {
        return .{ .id = r.versionId(), .size = r.reportedSize(), .etag = r.reportedEtag(), .mtime_ns = r.created_ns, .delete_marker = r.flags.delete_marker, .tiered = r.tier.len > 0 };
    }

    fn newer(x: Version, y: Version) bool {
        if (x.mtime_ns != y.mtime_ns) return x.mtime_ns > y.mtime_ns;
        return std.mem.order(u8, &x.id.bytes, &y.id.bytes) == .gt;
    }
};

const Name = struct {
    key: []u8,
    current: ?Version = null,
    noncurrent: std.ArrayList(Version) = .empty,

    fn destroy(n: *Name, gpa: std.mem.Allocator) void {
        n.noncurrent.deinit(gpa);
        gpa.free(n.key);
        gpa.destroy(n);
    }
};

const chunk_cap = 256;
const Chunk = struct { len: usize = 0, items: [chunk_cap]*Name = undefined };

/// Sorted names as a list of bounded sorted chunks: O(log n) seek, O(chunk) insert.
const Names = struct {
    chunks: std.ArrayList(*Chunk) = .empty,
    count: usize = 0,

    const Pos = struct { c: usize, i: usize };

    fn deinit(self: *Names, gpa: std.mem.Allocator) void {
        for (self.chunks.items) |ch| {
            for (ch.items[0..ch.len]) |n| n.destroy(gpa);
            gpa.destroy(ch);
        }
        self.chunks.deinit(gpa);
    }

    /// Position of the first name >= `key` (or the end).
    fn lowerBound(self: *const Names, key: []const u8) Pos {
        const cs = self.chunks.items;
        var lo: usize = 0;
        var hi: usize = cs.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (std.mem.lessThan(u8, cs[mid].items[cs[mid].len - 1].key, key)) lo = mid + 1 else hi = mid;
        }
        if (lo == cs.len) return .{ .c = lo, .i = 0 };
        const ch = cs[lo];
        var a: usize = 0;
        var b: usize = ch.len;
        while (a < b) {
            const mid = (a + b) / 2;
            if (std.mem.lessThan(u8, ch.items[mid].key, key)) a = mid + 1 else b = mid;
        }
        return .{ .c = lo, .i = a };
    }

    fn at(self: *const Names, p: Pos) ?*Name {
        if (p.c >= self.chunks.items.len) return null;
        return self.chunks.items[p.c].items[p.i];
    }

    fn next(self: *const Names, p: Pos) Pos {
        if (p.i + 1 < self.chunks.items[p.c].len) return .{ .c = p.c, .i = p.i + 1 };
        return .{ .c = p.c + 1, .i = 0 };
    }

    /// First position past every name that starts with `prefix`.
    fn seekPast(self: *const Names, from: Pos, prefix: []const u8) Pos {
        var buf: [2048]u8 = undefined;
        var n = prefix.len;
        if (n <= buf.len) {
            @memcpy(buf[0..n], prefix);
            while (n > 0 and buf[n - 1] == 0xff) n -= 1;
            if (n == 0) return .{ .c = self.chunks.items.len, .i = 0 };
            buf[n - 1] += 1;
            return self.lowerBound(buf[0..n]);
        }
        var p = from;
        while (self.at(p)) |nm| : (p = self.next(p)) if (!std.mem.startsWith(u8, nm.key, prefix)) break;
        return p;
    }

    fn find(self: *const Names, key: []const u8) ?struct { *Name, Pos } {
        const p = self.lowerBound(key);
        const n = self.at(p) orelse return null;
        return if (std.mem.eql(u8, n.key, key)) .{ n, p } else null;
    }

    fn insertAt(self: *Names, gpa: std.mem.Allocator, p0: Pos, n: *Name) error{OutOfMemory}!void {
        var p = p0;
        if (self.chunks.items.len == 0) {
            const ch = try gpa.create(Chunk);
            ch.* = .{};
            self.chunks.append(gpa, ch) catch |e| {
                gpa.destroy(ch);
                return e;
            };
            p = .{ .c = 0, .i = 0 };
        } else if (p.c == self.chunks.items.len) {
            const last = p.c - 1;
            p = .{ .c = last, .i = self.chunks.items[last].len };
        }
        var ch = self.chunks.items[p.c];
        if (ch.len == chunk_cap) {
            const half = chunk_cap / 2;
            const nc = try gpa.create(Chunk);
            self.chunks.insert(gpa, p.c + 1, nc) catch |e| {
                gpa.destroy(nc);
                return e;
            };
            nc.* = .{ .len = chunk_cap - half };
            @memcpy(nc.items[0..nc.len], ch.items[half..chunk_cap]);
            ch.len = half;
            if (p.i > half) {
                const c1 = p.c + 1;
                const ni = p.i - half;
                p = .{ .c = c1, .i = ni };
                ch = nc;
            }
        }
        std.mem.copyBackwards(*Name, ch.items[p.i + 1 .. ch.len + 1], ch.items[p.i..ch.len]);
        ch.items[p.i] = n;
        ch.len += 1;
        self.count += 1;
    }

    fn removeAt(self: *Names, gpa: std.mem.Allocator, p: Pos) void {
        const ch = self.chunks.items[p.c];
        std.mem.copyForwards(*Name, ch.items[p.i .. ch.len - 1], ch.items[p.i + 1 .. ch.len]);
        ch.len -= 1;
        self.count -= 1;
        if (ch.len == 0) {
            gpa.destroy(ch);
            _ = self.chunks.orderedRemove(p.c);
        }
    }
};

pub const Upload = struct { bucket: core.BucketId, key: []const u8, created_ns: i128 };
pub const UploadEntry = struct { id: core.ObjectId, upload: Upload };

/// One row of a version listing; `key` lives in the caller's arena.
pub const VersionRow = struct { key: []const u8, v: Version, is_latest: bool };

pub const VersionQuery = struct {
    prefix: []const u8 = "",
    delimiter: []const u8 = "",
    key_marker: []const u8 = "",
    max_keys: usize = 1000,
};

/// Thread-safe; callers that pair an index change with a record write serialize
/// those pairs themselves (ObjectService.mutex).
pub const Index = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    buckets: std.AutoHashMapUnmanaged([16]u8, *Names) = .empty,
    uploads: std.AutoHashMapUnmanaged([16]u8, Upload) = .empty,
    /// Set when an update could not be applied; the owner must rebuild.
    stale: bool = false,

    pub fn init(gpa: std.mem.Allocator) Index {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Index) void {
        self.clear();
        self.buckets.deinit(self.gpa);
        self.uploads.deinit(self.gpa);
    }

    pub fn clear(self: *Index) void {
        var it = self.buckets.valueIterator();
        while (it.next()) |b| {
            b.*.deinit(self.gpa);
            self.gpa.destroy(b.*);
        }
        self.buckets.clearRetainingCapacity();
        var ut = self.uploads.valueIterator();
        while (ut.next()) |u| self.gpa.free(u.key);
        self.uploads.clearRetainingCapacity();
        self.stale = false;
    }

    fn bucketFor(self: *Index, bid: core.BucketId) error{OutOfMemory}!*Names {
        const gop = try self.buckets.getOrPut(self.gpa, bid.bytes);
        if (!gop.found_existing) {
            const b = self.gpa.create(Names) catch |e| {
                self.buckets.removeByPtr(gop.key_ptr);
                return e;
            };
            b.* = .{};
            gop.value_ptr.* = b;
        }
        return gop.value_ptr.*;
    }

    fn nameFor(self: *Index, bid: core.BucketId, key: []const u8) error{OutOfMemory}!*Name {
        const b = try self.bucketFor(bid);
        const p = b.lowerBound(key);
        if (b.at(p)) |n| if (std.mem.eql(u8, n.key, key)) return n;
        const n = try self.gpa.create(Name);
        errdefer self.gpa.destroy(n);
        n.* = .{ .key = try self.gpa.dupe(u8, key) };
        errdefer self.gpa.free(n.key);
        try b.insertAt(self.gpa, p, n);
        return n;
    }

    fn prune(self: *Index, bid: core.BucketId, key: []const u8) void {
        const b = self.buckets.get(bid.bytes) orelse return;
        const f = b.find(key) orelse return;
        if (f[0].current != null or f[0].noncurrent.items.len > 0) return;
        b.removeAt(self.gpa, f[1]);
        f[0].destroy(self.gpa);
    }

    /// Records the name's current version; null means the name has none.
    pub fn setCurrent(self: *Index, bid: core.BucketId, key: []const u8, v: ?Version) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (v == null) {
            const b = self.buckets.get(bid.bytes) orelse return;
            const f = b.find(key) orelse return;
            f[0].current = null;
            return self.prune(bid, key);
        }
        const n = self.nameFor(bid, key) catch return self.markStale();
        n.current = v;
    }

    /// Adds or replaces a noncurrent version.
    pub fn putNoncurrent(self: *Index, bid: core.BucketId, key: []const u8, v: Version) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = self.nameFor(bid, key) catch return self.markStale();
        for (n.noncurrent.items) |*x| if (x.id.eql(v.id)) {
            x.* = v;
            return;
        };
        n.noncurrent.append(self.gpa, v) catch {
            self.prune(bid, key);
            self.markStale();
        };
    }

    pub fn removeNoncurrent(self: *Index, bid: core.BucketId, key: []const u8, id: core.VersionId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const b = self.buckets.get(bid.bytes) orelse return;
        const f = b.find(key) orelse return;
        for (f[0].noncurrent.items, 0..) |x, i| if (x.id.eql(id)) {
            _ = f[0].noncurrent.swapRemove(i);
            break;
        };
        self.prune(bid, key);
    }

    pub fn markStale(self: *Index) void {
        self.stale = true;
    }

    /// The newest noncurrent version of a name, if any.
    pub fn newestNoncurrent(self: *Index, bid: core.BucketId, key: []const u8) ?Version {
        self.mutex.lock();
        defer self.mutex.unlock();
        const b = self.buckets.get(bid.bytes) orelse return null;
        const f = b.find(key) orelse return null;
        var best: ?Version = null;
        for (f[0].noncurrent.items) |v| if (best == null or v.newer(best.?)) {
            best = v;
        };
        return best;
    }

    /// True when the bucket holds no version of any name.
    pub fn isEmpty(self: *Index, bid: core.BucketId) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const b = self.buckets.get(bid.bytes) orelse return true;
        return b.count == 0;
    }

    pub fn dropBucket(self: *Index, bid: core.BucketId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const kv = self.buckets.fetchRemove(bid.bytes) orelse return;
        kv.value.deinit(self.gpa);
        self.gpa.destroy(kv.value);
    }

    pub fn putUpload(self: *Index, id: core.ObjectId, u: Upload) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.uploads.contains(id.bytes)) return;
        const key = self.gpa.dupe(u8, u.key) catch return self.markStale();
        self.uploads.put(self.gpa, id.bytes, .{ .bucket = u.bucket, .key = key, .created_ns = u.created_ns }) catch {
            self.gpa.free(key);
            self.markStale();
        };
    }

    pub fn removeUpload(self: *Index, id: core.ObjectId) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const kv = self.uploads.fetchRemove(id.bytes) orelse return;
        self.gpa.free(kv.value.key);
    }

    /// Uploads of `bucket` (every bucket when null) whose key starts with `prefix`; keys copied into `arena`.
    pub fn uploadsOf(self: *Index, arena: std.mem.Allocator, bucket: ?core.BucketId, prefix: []const u8) error{OutOfMemory}![]UploadEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out: std.ArrayList(UploadEntry) = .empty;
        var it = self.uploads.iterator();
        while (it.next()) |e| {
            const u = e.value_ptr.*;
            if (bucket) |b| if (!b.eql(u.bucket)) continue;
            if (!std.mem.startsWith(u8, u.key, prefix)) continue;
            try out.append(arena, .{ .id = .{ .bytes = e.key_ptr.* }, .upload = .{ .bucket = u.bucket, .key = try arena.dupe(u8, u.key), .created_ns = u.created_ns } });
        }
        return out.items;
    }

    /// Candidate entries for one ListObjectsV2 page, in key order: every live key from the
    /// start point, one representative key per common prefix, and one past `max_keys` so
    /// `list.apply` can tell truncation. Keys are copied into `arena`.
    pub fn collectList(self: *Index, arena: std.mem.Allocator, bid: core.BucketId, p: list.Params) error{OutOfMemory}![]list.Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out: std.ArrayList(list.Entry) = .empty;
        const b = self.buckets.get(bid.bytes) orelse return out.items;
        const start = if (std.mem.lessThan(u8, p.prefix, p.start_after)) p.start_after else p.prefix;
        var pos = b.lowerBound(start);
        while (out.items.len <= p.max_keys) {
            const n = b.at(pos) orelse break;
            if (!std.mem.startsWith(u8, n.key, p.prefix)) break;
            const cur = n.current orelse {
                pos = b.next(pos);
                continue;
            };
            if (cur.delete_marker) {
                pos = b.next(pos);
                continue;
            }
            if (commonPrefix(n.key, p.prefix, p.delimiter)) |cp| {
                if (std.mem.lessThan(u8, p.start_after, cp)) try out.append(arena, entry(try arena.dupe(u8, n.key), cur));
                pos = b.seekPast(pos, cp);
                continue;
            }
            if (std.mem.lessThan(u8, p.start_after, n.key)) try out.append(arena, entry(try arena.dupe(u8, n.key), cur));
            pos = b.next(pos);
        }
        return out.items;
    }

    /// Candidate rows for one ListObjectVersions page, like `collectList`: all versions of
    /// each name, one representative per common prefix, and at least `max_keys + 1`
    /// rows past the key marker when that many exist.
    pub fn collectVersions(self: *Index, arena: std.mem.Allocator, bid: core.BucketId, q: VersionQuery) error{OutOfMemory}![]VersionRow {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out: std.ArrayList(VersionRow) = .empty;
        const b = self.buckets.get(bid.bytes) orelse return out.items;
        const start = if (std.mem.lessThan(u8, q.prefix, q.key_marker)) q.key_marker else q.prefix;
        var pos = b.lowerBound(start);
        var units: usize = 0;
        while (units <= q.max_keys) {
            const n = b.at(pos) orelse break;
            if (!std.mem.startsWith(u8, n.key, q.prefix)) break;
            if (commonPrefix(n.key, q.prefix, q.delimiter)) |cp| {
                if (std.mem.lessThan(u8, q.key_marker, cp)) {
                    const v = n.current orelse n.noncurrent.items[0];
                    try out.append(arena, .{ .key = try arena.dupe(u8, n.key), .v = v, .is_latest = n.current != null });
                    units += 1;
                }
                pos = b.seekPast(pos, cp);
                continue;
            }
            const key = try arena.dupe(u8, n.key);
            const at_marker = std.mem.eql(u8, n.key, q.key_marker);
            if (n.current) |c| {
                try out.append(arena, .{ .key = key, .v = c, .is_latest = true });
                if (!at_marker) units += 1;
            }
            for (n.noncurrent.items) |v| {
                // A crash between demote and overwrite can leave the current version twice.
                if (n.current) |c| if (c.id.eql(v.id)) continue;
                try out.append(arena, .{ .key = key, .v = v, .is_latest = false });
                if (!at_marker) units += 1;
            }
            pos = b.next(pos);
        }
        return out.items;
    }

    // ---- snapshot encoding ----

    pub const bucket_magic = "ZKIX";
    pub const uploads_magic = "ZKIU";
    const format_version: u16 = 1;

    /// Encodes one bucket's names. Caller holds no lock.
    pub fn encodeBucket(self: *Index, gpa: std.mem.Allocator, bid: core.BucketId) error{OutOfMemory}![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var a: std.Io.Writer.Allocating = .init(gpa);
        defer a.deinit();
        const w = &a.writer;
        encodeNames(w, self.buckets.get(bid.bytes)) catch return error.OutOfMemory;
        return a.toOwnedSlice() catch error.OutOfMemory;
    }

    fn encodeNames(w: *std.Io.Writer, b: ?*Names) std.Io.Writer.Error!void {
        try w.writeAll(bucket_magic);
        try codec.putInt(w, u16, format_version);
        try codec.putInt(w, u64, if (b) |x| x.count else 0);
        const names = b orelse return;
        for (names.chunks.items) |ch| for (ch.items[0..ch.len]) |n| {
            try codec.putInt(w, u16, @intCast(n.key.len));
            try w.writeAll(n.key);
            try w.writeByte(@intFromBool(n.current != null));
            if (n.current) |c| try putVersion(w, c);
            try codec.putInt(w, u32, @intCast(n.noncurrent.items.len));
            for (n.noncurrent.items) |v| try putVersion(w, v);
        };
    }

    fn putVersion(w: *std.Io.Writer, v: Version) std.Io.Writer.Error!void {
        try w.writeAll(&v.id.bytes);
        try codec.putInt(w, u64, v.size);
        try w.writeAll(&v.etag.md5);
        try codec.putInt(w, u32, v.etag.parts);
        try codec.putInt(w, i128, v.mtime_ns);
        try w.writeByte(@as(u8, @intFromBool(v.delete_marker)) | @as(u8, @intFromBool(v.tiered)) << 1);
    }

    fn takeVersion(c: *codec.Cursor) codec.DecodeError!Version {
        const id: core.VersionId = .{ .bytes = try c.fixed(16) };
        const size = try c.int(u64);
        const etag: core.ETag = .{ .md5 = try c.fixed(16), .parts = try c.int(u32) };
        const mtime = try c.int(i128);
        const dm = (try c.take(1))[0];
        if (dm > 3) return error.Corrupt;
        return .{ .id = id, .size = size, .etag = etag, .mtime_ns = mtime, .delete_marker = dm & 1 != 0, .tiered = dm & 2 != 0 };
    }

    /// Loads one bucket's names from `bytes` into an index that holds none for it.
    pub fn decodeBucket(self: *Index, bid: core.BucketId, bytes: []const u8) error{ OutOfMemory, Corrupt }!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var c: codec.Cursor = .{ .bytes = bytes };
        if (!std.mem.eql(u8, try c.take(4), bucket_magic) or try c.int(u16) != format_version) return error.Corrupt;
        const count = try c.int(u64);
        const b = try self.bucketFor(bid);
        var prev: ?[]const u8 = null;
        for (0..count) |_| {
            const key = try c.take(try c.int(u16));
            // Names must be strictly ascending, so appending keeps the order.
            if (prev) |pk| if (!std.mem.lessThan(u8, pk, key)) return error.Corrupt;
            const has = (try c.take(1))[0];
            if (has > 1) return error.Corrupt;
            const cur: ?Version = if (has == 1) try takeVersion(&c) else null;
            const nn = try c.int(u32);
            if (nn > c.bytes.len) return error.Corrupt;
            if (cur == null and nn == 0) return error.Corrupt;
            const n = try self.gpa.create(Name);
            n.* = .{ .key = self.gpa.dupe(u8, key) catch |e| {
                self.gpa.destroy(n);
                return e;
            }, .current = cur };
            b.insertAt(self.gpa, .{ .c = b.chunks.items.len, .i = 0 }, n) catch |e| {
                n.destroy(self.gpa);
                return e;
            };
            prev = n.key;
            try n.noncurrent.ensureTotalCapacity(self.gpa, nn);
            for (0..nn) |_| n.noncurrent.appendAssumeCapacity(try takeVersion(&c));
        }
        if (c.pos != bytes.len) return error.Corrupt;
    }

    pub fn encodeUploads(self: *Index, gpa: std.mem.Allocator) error{OutOfMemory}![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var a: std.Io.Writer.Allocating = .init(gpa);
        defer a.deinit();
        const w = &a.writer;
        self.encodeUploadsTo(w) catch return error.OutOfMemory;
        return a.toOwnedSlice() catch error.OutOfMemory;
    }

    fn encodeUploadsTo(self: *Index, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(uploads_magic);
        try codec.putInt(w, u16, format_version);
        try codec.putInt(w, u32, self.uploads.count());
        var it = self.uploads.iterator();
        while (it.next()) |e| {
            try w.writeAll(e.key_ptr);
            try w.writeAll(&e.value_ptr.bucket.bytes);
            try codec.putInt(w, i128, e.value_ptr.created_ns);
            try codec.putInt(w, u16, @intCast(e.value_ptr.key.len));
            try w.writeAll(e.value_ptr.key);
        }
    }

    pub fn decodeUploads(self: *Index, bytes: []const u8) error{ OutOfMemory, Corrupt }!void {
        var c: codec.Cursor = .{ .bytes = bytes };
        if (!std.mem.eql(u8, try c.take(4), uploads_magic) or try c.int(u16) != format_version) return error.Corrupt;
        const n = try c.int(u32);
        for (0..n) |_| {
            const id: core.ObjectId = .{ .bytes = try c.fixed(16) };
            const bid: core.BucketId = .{ .bytes = try c.fixed(16) };
            const created = try c.int(i128);
            const key = try c.take(try c.int(u16));
            self.putUpload(id, .{ .bucket = bid, .key = key, .created_ns = created });
        }
        if (c.pos != bytes.len) return error.Corrupt;
        if (self.stale) return error.OutOfMemory;
    }
};

fn entry(key: []const u8, v: Version) list.Entry {
    return .{ .key = key, .size = v.size, .etag = v.etag, .mtime_ns = v.mtime_ns, .tiered = v.tiered };
}

fn commonPrefix(key: []const u8, prefix: []const u8, delimiter: []const u8) ?[]const u8 {
    if (delimiter.len == 0) return null;
    const i = std.mem.indexOf(u8, key[prefix.len..], delimiter) orelse return null;
    return key[0 .. prefix.len + i + delimiter.len];
}

// ---- tests ----

const testing = std.testing;

fn ver(t: i128, dm: bool) Version {
    var id = core.VersionId.random();
    id.bytes[0] = @intCast(@mod(t, 256));
    return .{ .id = id, .size = @intCast(t), .etag = .{ .md5 = [_]u8{0} ** 16 }, .mtime_ns = t, .delete_marker = dm };
}

/// Brute-force ListObjectsV2 over a plain key set, for comparison.
fn bruteList(arena: std.mem.Allocator, keys: []const []const u8, p: list.Params) !list.Result {
    const es = try arena.alloc(list.Entry, keys.len);
    for (keys, es) |k, *e| e.* = entry(k, ver(1, false));
    return list.apply(arena, es, p);
}

fn expectSameList(a: list.Result, b: list.Result) !void {
    try testing.expectEqual(a.contents.len, b.contents.len);
    for (a.contents, b.contents) |x, y| try testing.expectEqualStrings(x.key, y.key);
    try testing.expectEqual(a.common_prefixes.len, b.common_prefixes.len);
    for (a.common_prefixes, b.common_prefixes) |x, y| try testing.expectEqualStrings(x, y);
    try testing.expectEqual(a.is_truncated, b.is_truncated);
    try testing.expectEqual(a.next_marker == null, b.next_marker == null);
    if (a.is_truncated and a.next_marker != null) try testing.expectEqualStrings(a.next_marker.?, b.next_marker.?);
}

test "index listing matches brute force on random keys with delimiters" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rnd = prng.random();
    const alphabet = "ab/c\xff";
    for (0..6) |round| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var idx = Index.init(gpa);
        defer idx.deinit();
        const bid = core.BucketId.random();
        var set: std.StringArrayHashMapUnmanaged(void) = .empty;
        const n = 20 + round * 60;
        for (0..n) |_| {
            const len = 1 + rnd.uintLessThan(usize, 7);
            const k = try arena.alloc(u8, len);
            for (k) |*ch| ch.* = alphabet[rnd.uintLessThan(usize, alphabet.len)];
            try set.put(arena, k, {});
            idx.setCurrent(bid, k, ver(1, false));
        }
        // Remove some names and hide some behind delete markers.
        var live: std.ArrayList([]const u8) = .empty;
        for (set.keys()) |k| switch (rnd.uintLessThan(u8, 5)) {
            0 => idx.setCurrent(bid, k, null),
            1 => {
                idx.setCurrent(bid, k, ver(2, true));
                idx.putNoncurrent(bid, k, ver(1, false));
            },
            else => try live.append(arena, k),
        };
        try testing.expect(!idx.stale);
        const prefixes = [_][]const u8{ "", "a", "b/", "\xff", "ab/c" };
        const delims = [_][]const u8{ "", "/", "c", "b/" };
        for (prefixes) |pre| for (delims) |d| for ([_]usize{ 0, 2, 7, 1000 }) |mk| {
            // Walk every page via the continuation marker and compare page by page.
            var after: []const u8 = "";
            var pages: usize = 0;
            while (pages < 10000) : (pages += 1) {
                const p: list.Params = .{ .prefix = pre, .delimiter = d, .start_after = after, .max_keys = mk };
                const want = try bruteList(arena, live.items, p);
                const got = try list.apply(arena, try idx.collectList(arena, bid, p), p);
                try expectSameList(want, got);
                if (!got.is_truncated or mk == 0) break;
                after = got.next_marker.?;
            }
        };
    }
}

test "index versions, newest noncurrent, prune, and snapshot roundtrip" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var idx = Index.init(gpa);
    defer idx.deinit();
    const bid = core.BucketId.random();
    const v1 = ver(1, false);
    const v2 = ver(2, false);
    idx.putNoncurrent(bid, "k", v1);
    idx.putNoncurrent(bid, "k", v2);
    idx.setCurrent(bid, "k", ver(3, true));
    idx.setCurrent(bid, "d/x", ver(4, false));
    for (0..1000) |i| {
        var buf: [16]u8 = undefined;
        idx.setCurrent(bid, try std.fmt.bufPrint(&buf, "m{d:0>5}", .{i}), ver(5, false));
    }
    try testing.expect(idx.newestNoncurrent(bid, "k").?.id.eql(v2.id));
    const rows = try idx.collectVersions(arena, bid, .{ .delimiter = "/", .max_keys = 2 });
    try testing.expectEqualStrings("d/x", rows[0].key);
    try testing.expectEqual(@as(usize, 1 + 3), rows.len);
    try testing.expectEqual(@as(usize, 1), (try idx.collectVersions(arena, bid, .{ .prefix = "d/" })).len);

    const uid = core.ObjectId.random();
    idx.putUpload(uid, .{ .bucket = bid, .key = "up", .created_ns = 9 });
    const bytes = try idx.encodeBucket(gpa, bid);
    defer gpa.free(bytes);
    const ub = try idx.encodeUploads(gpa);
    defer gpa.free(ub);

    var back = Index.init(gpa);
    defer back.deinit();
    try back.decodeBucket(bid, bytes);
    try back.decodeUploads(ub);
    try testing.expectEqual(@as(usize, 1002), back.buckets.get(bid.bytes).?.count);
    try testing.expect(back.newestNoncurrent(bid, "k").?.id.eql(v2.id));
    try testing.expectEqualStrings("up", (try back.uploadsOf(arena, bid, "u"))[0].upload.key);
    var cut: usize = 0;
    while (cut < bytes.len) : (cut += 1 + cut / 8) try testing.expectError(error.Corrupt, back.decodeBucket(core.BucketId.random(), bytes[0..cut]));

    idx.removeNoncurrent(bid, "k", v1.id);
    idx.removeNoncurrent(bid, "k", v2.id);
    idx.setCurrent(bid, "k", null);
    idx.setCurrent(bid, "d/x", null);
    for (0..1000) |i| {
        var buf: [16]u8 = undefined;
        idx.setCurrent(bid, try std.fmt.bufPrint(&buf, "m{d:0>5}", .{i}), null);
    }
    try testing.expect(idx.isEmpty(bid));
}
