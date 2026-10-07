//! Replica(N): a StorageBackend over a DriveSet. Quorum writes, CRC-verified reads
//! with replica fallback, inline repair. N=1 is the `single` profile. Cluster records
//! carry a clock stamp (newest wins) and deletes leave tombstones.
const std = @import("std");
const core = @import("../core/root.zig");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const shard = @import("shard.zig");
const fanout = @import("fanout.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const ObjectMeta = iface.ObjectMeta;
const DriveSet = placement.DriveSet;
const Handle = iface.drive.Handle;
const Pending = iface.drive.Pending;
const ShardFile = iface.drive.ShardFile;
const max_drives = placement.max_drives;

/// Per-key outcome of a verify-and-repair pass.
pub const KeyReport = struct {
    healthy: u8 = 0,
    repaired: u8 = 0,
    /// Bad replicas that could not be rewritten (drive offline or write failed).
    unrepaired: u8 = 0,
    /// Replicas were present but none verified.
    lost: bool = false,
};

const stripe_count = 64;

/// Tombstones younger than this are kept so every drive learns about the delete.
pub const tombstone_grace_ns: u64 = 15 * std.time.ns_per_min;

pub fn quorum(n: usize) usize {
    return n / 2 + 1;
}

pub const ReplicaStore = struct {
    gpa: std.mem.Allocator,
    drives: *DriveSet,
    /// Serialises mutations of one key: commit, delete, repair.
    stripes: [stripe_count]std.Thread.Mutex = @splat(.{}),

    pub const capabilities: iface.Capabilities = .{
        .atomic_rename = true,
        .durable_sync = true,
        .range_read = true,
        .checksums = true,
    };

    pub fn init(gpa: std.mem.Allocator, drives: *DriveSet) ReplicaStore {
        return .{ .gpa = gpa, .drives = drives };
    }

    pub fn backend(self: *ReplicaStore) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = capabilities, .vtable = &vtable };
    }

    const vtable: iface.StorageBackend.VTable = .{
        .put = put,
        .get = get,
        .stat = stat,
        .delete = delete,
        .list = list,
        .putRecord = putRecord,
        .getRecord = getRecord,
        .deleteRecord = delete,
        .sync = sync,
    };

    fn cast(ctx: *anyopaque) *ReplicaStore {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn stripe(self: *ReplicaStore, key: PhysicalKey) *std.Thread.Mutex {
        return &self.stripes[std.hash.Wyhash.hash(@intFromEnum(key.space), &key.hex) % stripe_count];
    }

    fn clustered(self: *const ReplicaStore) bool {
        return self.drives.isCluster();
    }

    /// Shared holds on a list of drives; null slots are offline. Lock order: drives, then stripe.
    pub const Holds = struct {
        set: *DriveSet,
        idx: []const u8,
        lbs: [max_drives]?Handle = @splat(null),

        pub fn acquire(set: *DriveSet, idx: []const u8) Holds {
            var h: Holds = .{ .set = set, .idx = idx };
            for (idx, 0..) |d, j| h.lbs[j] = set.acquire(d);
            return h;
        }

        pub fn release(h: *Holds) void {
            for (h.idx, 0..) |d, j| if (h.lbs[j] != null) h.set.release(d);
        }

        /// Fan out when a held drive is remote; local calls are cheap enough in line.
        pub fn parallel(h: *const Holds) bool {
            var remote: usize = 0;
            for (h.lbs[0..h.idx.len]) |l| if (l) |x| {
                remote += @intFromBool(x == .ext);
            };
            return remote > 0;
        }

        pub fn reachable(h: *const Holds) usize {
            var n: usize = 0;
            for (h.lbs[0..h.idx.len]) |l| n += @intFromBool(l != null);
            return n;
        }
    };

    /// Error for a quorum miss: a quorum error when unreachable drives caused it.
    pub fn short(self: *const ReplicaStore, holds: *const Holds, need: usize, worst: Error, comptime q: Error) Error {
        if (self.drives.isCluster() and holds.reachable() < need) return q;
        return worst;
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return error.InvalidKey;
        if (!self.drives.writable()) return error.WriteQuorum;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        const need = quorum(placed.len);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();

        var pend: [max_drives]?Pending = @splat(null);
        defer for (&pend) |*slot| if (slot.*) |*w| w.abort();
        var worst: Error = error.IoFailed;
        var live: usize = 0;
        const hdr = shard.header();
        for (placed, 0..) |_, j| {
            const lb = holds.lbs[j] orelse continue;
            var w = lb.begin() catch |e| {
                worst = worse(worst, e);
                continue;
            };
            w.writeAll(&hdr) catch |e| {
                w.abort();
                worst = worse(worst, e);
                continue;
            };
            pend[j] = w;
            live += 1;
        }
        if (live < need) return self.short(&holds, need, worst, error.WriteQuorum);

        const buf = try self.gpa.alloc(u8, shard.chunk_size);
        defer self.gpa.free(buf);
        var total: u64 = 0;
        while (true) {
            // Never read past a known length: HTTP body readers must not be polled after their end.
            const want: usize = if (opts.size_hint) |h| @intCast(@min(buf.len, h -| total)) else buf.len;
            if (want == 0) break;
            const n = try fill(source, buf[0..want]);
            if (n == 0) break;
            const crc = shard.chunkCrc(buf[0..n]);
            for (&pend) |*slot| if (slot.*) |*w| {
                w.writeAll(&crc) catch |e| {
                    dropWriter(slot, &live, &worst, e);
                    continue;
                };
                w.writeAll(buf[0..n]) catch |e| dropWriter(slot, &live, &worst, e);
            };
            if (live < need) return if (self.clustered()) error.WriteQuorum else worst;
            total += n;
            if (n < want) break;
        }

        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        var committed: [max_drives]bool = @splat(false);
        var ok: usize = 0;
        for (&pend, 0..) |*slot, j| if (slot.*) |*w| {
            var pw = w.*;
            slot.* = null;
            pw.commit(key) catch |e| {
                worst = worse(worst, e);
                continue;
            };
            committed[j] = true;
            ok += 1;
        };
        if (ok < need) {
            for (placed, 0..) |_, j| if (committed[j]) holds.lbs[j].?.store().delete(key) catch {};
            return if (self.clustered() and worst == error.IoFailed) error.WriteQuorum else worst;
        }
        return .{ .size = total, .mtime_ns = core.time.nowNs() };
    }

    /// Reads until `buf` is full or the source ends, never asking for more than `buf.len`.
    pub fn fill(source: *std.Io.Reader, buf: []u8) Error!usize {
        var w: std.Io.Writer = .fixed(buf);
        while (w.end < buf.len) {
            _ = source.stream(&w, .limited(buf.len - w.end)) catch |e| switch (e) {
                error.EndOfStream => break,
                error.ReadFailed => return error.ReadFailed,
                error.WriteFailed => break,
            };
        }
        return w.end;
    }

    fn dropWriter(slot: *?Pending, live: *usize, worst: *Error, e: Error) void {
        slot.*.?.abort();
        slot.* = null;
        live.* -= 1;
        worst.* = worse(worst.*, e);
    }

    pub fn worse(a: Error, b: Error) Error {
        return if (b == error.NoSpace or b == error.OutOfMemory) b else a;
    }

    const Outcome = union(enum) {
        ok: ObjectMeta,
        missing,
        corrupt,
        io,
        bad_range,
        sink_failed,
    };

    /// Streams verified bytes of `range` past `delivered.*` into `sink` (null: verify only).
    fn readShard(self: *ReplicaStore, lb: Handle, key: PhysicalKey, range: ?core.Range, sink: ?*std.Io.Writer, delivered: *u64, expect: ?u64) Outcome {
        var file = lb.openRead(key) catch |e| return if (e == error.NotFound) .missing else .io;
        defer file.close();
        const st = file.stat() catch return .io;
        const size = shard.logicalSize(st.size) orelse return .corrupt;
        if (expect) |x| if (x != size) return .corrupt;
        var hb: [shard.header_len]u8 = undefined;
        const hn = file.preadAll(&hb, 0) catch return .io;
        if (!shard.headerValid(hb[0..hn])) return .corrupt;
        const r = range orelse core.Range{ .offset = 0, .length = size };
        if (r.length > 0 and (r.offset >= size or r.length > size - r.offset)) return .bad_range;
        const end = r.offset + r.length;
        const buf = self.gpa.alloc(u8, shard.chunk_size + 4) catch return .io;
        defer self.gpa.free(buf);
        while (r.offset + delivered.* < end) {
            const pos = r.offset + delivered.*;
            const ci = pos / shard.chunk_size;
            const cstart = ci * shard.chunk_size;
            const clen: usize = @intCast(@min(shard.chunk_size, size - cstart));
            const got = file.preadAll(buf[0 .. 4 + clen], shard.chunkOffset(ci)) catch return .io;
            if (got != 4 + clen) return .corrupt;
            const data = shard.verifyChunk(buf[0 .. 4 + clen]) orelse return .corrupt;
            const lo: usize = @intCast(pos - cstart);
            const hi: usize = @intCast(@min(end - cstart, clen));
            if (sink) |s| s.writeAll(data[lo..hi]) catch return .sink_failed;
            delivered.* += hi - lo;
        }
        return .{ .ok = .{ .size = size, .mtime_ns = st.mtime_ns } };
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?core.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return error.InvalidKey;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var delivered: u64 = 0;
        var known: ?u64 = null;
        var bad: [max_drives]u8 = undefined;
        var nbad: usize = 0;
        var saw_other = false;
        var offline = false;
        for (placed) |d| {
            const lb = self.drives.acquire(d) orelse {
                saw_other = true;
                offline = true;
                continue;
            };
            const out = self.readShard(lb, key, range, sink, &delivered, known);
            self.drives.release(d);
            switch (out) {
                .ok => |meta| {
                    if (nbad > 0) _ = self.repair(key, d, bad[0..nbad]);
                    return meta;
                },
                .missing => {
                    bad[nbad] = d;
                    nbad += 1;
                },
                .corrupt => {
                    std.log.warn("drive {s}: corrupt shard {s}", .{ self.drives.drives[d].path, &key.hex });
                    bad[nbad] = d;
                    nbad += 1;
                    saw_other = true;
                },
                .io => {
                    saw_other = true;
                    offline = true;
                },
                .bad_range => return error.IoFailed,
                .sink_failed => return error.WriteFailed,
            }
            if (delivered > 0 and known == null) known = self.sizeOf(d, key);
        }
        if (offline and self.clustered()) return error.ReadQuorum;
        return if (saw_other) error.IoFailed else error.NotFound;
    }

    fn sizeOf(self: *ReplicaStore, d: u8, key: PhysicalKey) ?u64 {
        const lb = self.drives.acquire(d) orelse return null;
        defer self.drives.release(d);
        const m = lb.store().stat(key) catch return null;
        return shard.logicalSize(m.size);
    }

    /// Verifies one replica in full.
    fn check(self: *ReplicaStore, lb: Handle, key: PhysicalKey) Outcome {
        if (key.space == .data) {
            var n: u64 = 0;
            return self.readShard(lb, key, null, null, &n, null);
        }
        const raw = lb.store().getRecord(key, self.gpa) catch |e| return if (e == error.NotFound) .missing else .io;
        defer self.gpa.free(raw);
        return if (shard.unframeAny(raw) != null) .{ .ok = .{ .size = raw.len, .mtime_ns = 0 } } else .corrupt;
    }

    /// Rewrites `bad` replicas from `good` after re-verifying it; returns how many were fixed.
    fn repair(self: *ReplicaStore, key: PhysicalKey, good: u8, bad: []const u8) usize {
        var idx: [max_drives]u8 = undefined;
        idx[0] = good;
        @memcpy(idx[1 .. 1 + bad.len], bad);
        var holds = Holds.acquire(self.drives, idx[0 .. 1 + bad.len]);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        const src = holds.lbs[0] orelse return 0;
        if (self.check(src, key) != .ok) return 0;
        var fixed: usize = 0;
        for (bad, 1..) |d, j| {
            const dst = holds.lbs[j] orelse continue;
            self.copy(src, dst, key) catch |e| {
                std.log.warn("drive {s}: repair of {s} failed: {t}", .{ self.drives.drives[d].path, &key.hex, e });
                continue;
            };
            std.log.info("drive {s}: repaired {t} {s}", .{ self.drives.drives[d].path, key.space, &key.hex });
            fixed += 1;
        }
        return fixed;
    }

    fn copy(self: *ReplicaStore, src: Handle, dst: Handle, key: PhysicalKey) Error!void {
        if (key.space == .data) {
            var file = try src.openRead(key);
            defer file.close();
            const size = (try file.stat()).size;
            var w = try dst.begin();
            errdefer w.abort();
            const buf = try self.gpa.alloc(u8, 256 * 1024);
            defer self.gpa.free(buf);
            var off: u64 = 0;
            while (off < size) {
                const n = try file.preadAll(buf[0..@intCast(@min(buf.len, size - off))], off);
                if (n == 0) return error.IoFailed;
                try w.writeAll(buf[0..n]);
                off += n;
            }
            return w.commit(key);
        }
        const raw = try src.store().getRecord(key, self.gpa);
        defer self.gpa.free(raw);
        try dst.store().putRecord(key, raw);
    }

    /// Verifies every placed replica of `key` and rewrites missing or corrupt ones.
    pub fn healKey(self: *ReplicaStore, key: PhysicalKey) KeyReport {
        if (key.space != .data and self.clustered()) return self.healRecord(key);
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();

        var rep: KeyReport = .{};
        var good: ?Handle = null;
        var bad: [max_drives]u8 = undefined;
        var nbad: usize = 0;
        var corrupt = false;
        for (placed, 0..) |_, j| {
            const lb = holds.lbs[j] orelse {
                rep.unrepaired += 1;
                continue;
            };
            switch (self.check(lb, key)) {
                .ok => {
                    rep.healthy += 1;
                    if (good == null) good = lb;
                },
                .missing => {
                    bad[nbad] = @intCast(j);
                    nbad += 1;
                },
                .corrupt => {
                    std.log.warn("drive {s}: corrupt {t} {s}", .{ self.drives.drives[placed[j]].path, key.space, &key.hex });
                    corrupt = true;
                    bad[nbad] = @intCast(j);
                    nbad += 1;
                },
                else => rep.unrepaired += 1,
            }
        }
        const src = good orelse {
            // All missing means the key was deleted meanwhile.
            rep.lost = corrupt;
            rep.unrepaired += @intCast(if (corrupt) nbad else 0);
            return rep;
        };
        for (bad[0..nbad]) |j| {
            const d = placed[j];
            self.copy(src, holds.lbs[j].?, key) catch |e| {
                std.log.warn("drive {s}: heal of {s} failed: {t}", .{ self.drives.drives[d].path, &key.hex, e });
                rep.unrepaired += 1;
                continue;
            };
            rep.repaired += 1;
        }
        return rep;
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data and self.clustered()) {
            const bytes = try getRecord(ctx, key, self.gpa);
            defer self.gpa.free(bytes);
            return .{ .size = bytes.len, .mtime_ns = 0 };
        }
        var pbuf: [max_drives]u8 = undefined;
        var saw_other = false;
        for (self.drives.placed(key, &pbuf)) |d| {
            const lb = self.drives.acquire(d) orelse continue;
            defer self.drives.release(d);
            const m = lb.store().stat(key) catch |e| {
                if (e != error.NotFound) saw_other = true;
                continue;
            };
            if (key.space != .data) return .{ .size = m.size -| shard.record_overhead, .mtime_ns = m.mtime_ns };
            const size = shard.logicalSize(m.size) orelse {
                saw_other = true;
                continue;
            };
            return .{ .size = size, .mtime_ns = m.mtime_ns };
        }
        return if (saw_other) error.IoFailed else error.NotFound;
    }

    /// Deletes all placed replicas; data or record depending on the key space.
    pub fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        const self = cast(ctx);
        if (key.space != .data and self.clustered()) return self.tombstone(key);
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        const Each = struct {
            holds: *Holds,
            key: PhysicalKey,
            res: [max_drives]?Error = @splat(error.IoFailed),
            fn f(c: *@This(), j: usize) void {
                const b = (c.holds.lbs[j] orelse return).store();
                const r = if (c.key.space == .data) b.delete(c.key) else b.deleteRecord(c.key);
                c.res[j] = if (r) |_| null else |e| e;
            }
        };
        var each: Each = .{ .holds = &holds, .key = key };
        fanout.run(placed.len, holds.parallel(), &each, Each.f);
        var removed: usize = 0;
        var absent: usize = 0;
        var worst: Error = error.IoFailed;
        for (placed, 0..) |_, j| {
            if (holds.lbs[j] == null) continue;
            const e = each.res[j] orelse {
                removed += 1;
                continue;
            };
            if (e == error.NotFound) absent += 1 else worst = worse(worst, e);
        }
        if (removed + absent < quorum(placed.len)) return self.short(&holds, quorum(placed.len), worst, error.WriteQuorum);
        if (removed == 0) return error.NotFound;
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        const self = cast(ctx);
        if (key.space == .data) return error.InvalidKey;
        const framed = if (self.clustered())
            try shard.frameRecord2(self.gpa, bytes, shard.nextStamp(), false)
        else
            try shard.frameRecord(self.gpa, bytes);
        defer self.gpa.free(framed);
        return self.writeFramed(key, framed);
    }

    /// Writes one framed record to every placed drive; needs a majority.
    fn writeFramed(self: *ReplicaStore, key: PhysicalKey, framed: []const u8) Error!void {
        if (!self.drives.writable()) return error.WriteQuorum;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        const Each = struct {
            self: *ReplicaStore,
            holds: *Holds,
            key: PhysicalKey,
            framed: []const u8,
            res: [max_drives]?Error = @splat(error.IoFailed),
            fn f(c: *@This(), j: usize) void {
                const lb = c.holds.lbs[j] orelse return;
                c.res[j] = if (c.self.putFramed(lb, c.key, c.framed)) |_| null else |e| e;
            }
        };
        var each: Each = .{ .self = self, .holds = &holds, .key = key, .framed = framed };
        fanout.run(placed.len, holds.parallel(), &each, Each.f);
        var ok: usize = 0;
        var worst: Error = error.IoFailed;
        for (placed, 0..) |_, j| {
            if (holds.lbs[j] == null) continue;
            if (each.res[j]) |e| worst = worse(worst, e) else ok += 1;
        }
        if (ok < quorum(placed.len)) return self.short(&holds, quorum(placed.len), worst, error.WriteQuorum);
    }

    /// Cluster records never move backwards: a drive keeps whichever stamp is newer.
    fn putFramed(self: *ReplicaStore, lb: Handle, key: PhysicalKey, framed: []const u8) Error!void {
        if (!self.clustered()) return lb.store().putRecord(key, framed);
        return switch (lb) {
            .local => |l| shard.putRecordNewer(l, self.gpa, key, framed),
            .ext => lb.store().putRecord(key, framed),
        };
    }

    /// Cluster delete: a newer tombstone replaces the record on a majority.
    fn tombstone(self: *ReplicaStore, key: PhysicalKey) Error!void {
        const cur = try self.getRecord2(key, self.gpa);
        self.gpa.free(cur);
        const framed = try shard.frameRecord2(self.gpa, "", shard.nextStamp(), true);
        defer self.gpa.free(framed);
        return self.writeFramed(key, framed);
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        const self = cast(ctx);
        if (key.space == .data) return error.InvalidKey;
        if (self.clustered()) return self.getRecord2(key, gpa);
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var bad: [max_drives]u8 = undefined;
        var nbad: usize = 0;
        var saw_other = false;
        for (placed) |d| {
            const raw = blk: {
                const lb = self.drives.acquire(d) orelse {
                    saw_other = true;
                    continue;
                };
                defer self.drives.release(d);
                break :blk lb.store().getRecord(key, self.gpa) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.NotFound => {
                        bad[nbad] = d;
                        nbad += 1;
                        continue;
                    },
                    else => {
                        saw_other = true;
                        continue;
                    },
                };
            };
            defer self.gpa.free(raw);
            const payload = (shard.unframeAny(raw) orelse {
                std.log.warn("drive {s}: corrupt record {s}", .{ self.drives.drives[d].path, &key.hex });
                bad[nbad] = d;
                nbad += 1;
                saw_other = true;
                continue;
            }).payload;
            const out = try gpa.dupe(u8, payload);
            if (nbad > 0) _ = self.repair(key, d, bad[0..nbad]);
            return out;
        }
        return if (saw_other) error.IoFailed else error.NotFound;
    }

    /// What one drive holds for a record slot.
    const Replica = union(enum) {
        offline,
        missing,
        corrupt,
        /// Framed bytes (owned) and their stamp.
        present: struct { raw: []u8, stamp: u64, tombstone: bool },
    };

    fn readReplica(self: *ReplicaStore, d: u8, key: PhysicalKey) Error!Replica {
        const lb = self.drives.acquire(d) orelse return .offline;
        defer self.drives.release(d);
        const raw = lb.store().getRecord(key, self.gpa) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.NotFound => .missing,
            else => .offline,
        };
        const u = shard.unframeAny(raw) orelse {
            self.gpa.free(raw);
            std.log.warn("drive {s}: corrupt record {s}", .{ self.drives.drives[d].path, &key.hex });
            return .corrupt;
        };
        shard.observeStamp(u.stamp);
        return .{ .present = .{ .raw = raw, .stamp = u.stamp, .tombstone = u.tombstone } };
    }

    /// Concurrent replica reads of one record slot.
    const ReadMany = struct {
        self: *ReplicaStore,
        placed: []const u8,
        key: PhysicalKey,
        reps: [max_drives]Replica = @splat(.offline),
        oom: bool = false,
        lo: usize = 0,

        fn run(r: *ReadMany, lo: usize, hi: usize) void {
            if (hi <= lo) return;
            r.lo = lo;
            var remote = false;
            for (r.placed[lo..hi]) |d| remote = remote or !r.self.drives.isLocal(d);
            fanout.run(hi - lo, remote, r, one);
        }

        fn one(r: *ReadMany, i: usize) void {
            const j = r.lo + i;
            r.reps[j] = r.self.readReplica(r.placed[j], r.key) catch blk: {
                r.oom = true;
                break :blk .offline;
            };
        }

        fn answered(r: *const ReadMany) usize {
            var n: usize = 0;
            for (r.reps[0..r.placed.len]) |x| n += @intFromBool(x == .missing or x == .present);
            return n;
        }

        fn newest(r: *const ReadMany) ?usize {
            var best: ?usize = null;
            for (r.reps[0..r.placed.len], 0..) |x, j| if (x == .present) {
                if (best == null or x.present.stamp > r.reps[best.?].present.stamp) best = j;
            };
            return best;
        }

        fn deinit(r: *ReadMany) void {
            for (r.reps[0..r.placed.len]) |x| if (x == .present) r.self.gpa.free(x.present.raw);
        }
    };

    /// Concurrent rewrites of chosen replicas with one framed record.
    const FixMany = struct {
        self: *ReplicaStore,
        placed: []const u8,
        key: PhysicalKey,
        raw: []const u8,
        todo: [max_drives]bool = @splat(false),
        ok: [max_drives]bool = @splat(false),

        fn run(x: *FixMany) void {
            var remote = false;
            for (x.placed, 0..) |d, j| remote = remote or (x.todo[j] and !x.self.drives.isLocal(d));
            fanout.run(x.placed.len, remote, x, one);
        }

        fn one(x: *FixMany, j: usize) void {
            if (!x.todo[j]) return;
            const d = x.placed[j];
            const lb = x.self.drives.acquire(d) orelse return;
            defer x.self.drives.release(d);
            x.self.putFramed(lb, x.key, x.raw) catch return;
            x.ok[j] = true;
        }
    };

    /// Reads replicas until enough answered to overlap every write majority; the newest wins.
    fn getRecord2(self: *ReplicaStore, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        const need = placed.len - quorum(placed.len) + 1;
        var reads: ReadMany = .{ .self = self, .placed = placed, .key = key };
        defer reads.deinit();
        const reps = &reads.reps;
        // The first `need` drives at once; the rest only if some did not answer.
        reads.run(0, need);
        if (reads.answered() < need) reads.run(need, placed.len);
        if (reads.oom) return error.OutOfMemory;
        if (reads.answered() < need) return error.ReadQuorum;
        const b = reads.newest() orelse return error.NotFound;
        const win = reps[b].present;
        // Bring lagging replicas we read up to the winner.
        var fix: FixMany = .{ .self = self, .placed = placed, .key = key, .raw = win.raw };
        for (placed, 0..) |_, j| {
            const stale = switch (reps[j]) {
                .missing, .corrupt => true,
                .present => |p| p.stamp < win.stamp,
                .offline => false,
            };
            fix.todo[j] = stale and !(reps[j] == .missing and win.tombstone);
        }
        fix.run();
        if (win.tombstone) return error.NotFound;
        return gpa.dupe(u8, shard.unframeAny(win.raw).?.payload);
    }

    /// Cluster heal of one record slot: spread the newest replica; purge old tombstones.
    fn healRecord(self: *ReplicaStore, key: PhysicalKey) KeyReport {
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        var rep: KeyReport = .{};
        var reads: ReadMany = .{ .self = self, .placed = placed, .key = key };
        defer reads.deinit();
        const reps = &reads.reps;
        reads.run(0, placed.len);
        const best = reads.newest();
        var corrupt = false;
        for (reps[0..placed.len]) |r| corrupt = corrupt or r == .corrupt;
        const b = best orelse {
            rep.lost = corrupt;
            return rep;
        };
        const win = reps[b].present;
        var all_same = true;
        for (reps[0..placed.len]) |r| {
            const same = r == .present and r.present.stamp == win.stamp;
            all_same = all_same and same;
        }
        const now: u64 = @intCast(@max(0, std.time.nanoTimestamp()));
        if (win.tombstone and all_same and now -| win.stamp > tombstone_grace_ns) {
            for (placed) |d| {
                const lb = self.drives.acquire(d) orelse continue;
                defer self.drives.release(d);
                switch (lb) {
                    .local => |l| shard.deleteRecordIf(l, self.gpa, key, win.stamp) catch {},
                    .ext => |x| x.vtable.deleteRecordIf(x.ctx, key, win.stamp) catch {},
                }
            }
            return rep;
        }
        var fix: FixMany = .{ .self = self, .placed = placed, .key = key, .raw = win.raw };
        for (placed, 0..) |_, j| {
            switch (reps[j]) {
                .offline => rep.unrepaired += 1,
                .present => |p| if (p.stamp == win.stamp) {
                    rep.healthy += 1;
                } else {
                    fix.todo[j] = true;
                },
                else => fix.todo[j] = true,
            }
        }
        fix.run();
        for (fix.todo[0..placed.len], fix.ok[0..placed.len]) |t, ok| {
            if (!t) continue;
            if (ok) rep.repaired += 1 else rep.unrepaired += 1;
        }
        return rep;
    }

    /// Union of keys across online drives, deduplicated.
    fn list(ctx: *anyopaque, space: iface.KeySpace, cb: iface.ListCallback) Error!void {
        const self = cast(ctx);
        const State = struct {
            seen: std.AutoHashMap([32]u8, void),
            cb: iface.ListCallback,
            user_err: ?Error = null,
            fn f(c: *anyopaque, key: PhysicalKey) Error!void {
                const st: *@This() = @ptrCast(@alignCast(c));
                const gop = try st.seen.getOrPut(key.hex);
                if (gop.found_existing) return;
                st.cb.func(st.cb.ctx, key) catch |e| {
                    st.user_err = e;
                    return e;
                };
            }
        };
        var st: State = .{ .seen = .init(self.gpa), .cb = cb };
        defer st.seen.deinit();
        var reached: usize = 0;
        for (0..self.drives.count()) |d| {
            const lb = self.drives.acquire(d) orelse continue;
            defer self.drives.release(d);
            lb.store().list(space, .{ .ctx = &st, .func = State.f }) catch |e| {
                if (st.user_err) |ue| return ue;
                if (e == error.OutOfMemory) return e;
                continue;
            };
            reached += 1;
        }
        if (reached == 0) return if (self.clustered()) error.ReadQuorum else error.IoFailed;
    }

    fn sync(ctx: *anyopaque) Error!void {
        const self = cast(ctx);
        for (0..self.drives.count()) |d| {
            const lb = self.drives.acquire(d) orelse continue;
            defer self.drives.release(d);
            lb.store().sync() catch |e| if (!self.clustered() or lb == .local) return e;
        }
    }
};

const testing = std.testing;

const Fixture = struct {
    tmp: testing.TmpDir,
    bufs: [4][std.fs.max_path_bytes]u8 = undefined,
    paths: [4][]const u8 = undefined,
    set: DriveSet = undefined,
    store: ReplicaStore = undefined,

    fn init(self: *Fixture, profile: placement.Profile) !void {
        self.tmp = testing.tmpDir(.{});
        var nb: [4]u8 = undefined;
        for (0..4) |i| {
            const name = try std.fmt.bufPrint(&nb, "d{d}", .{i});
            try self.tmp.dir.makePath(name);
            self.paths[i] = try self.tmp.dir.realpath(name, &self.bufs[i]);
        }
        self.set = try DriveSet.open(testing.allocator, &self.paths, profile);
        self.store = ReplicaStore.init(testing.allocator, &self.set);
    }

    fn deinit(self: *Fixture) void {
        self.set.deinit();
        self.tmp.cleanup();
    }

    fn shardPath(_: *Fixture, d: u8, key: PhysicalKey, buf: []u8) ![]const u8 {
        var kb: [64]u8 = undefined;
        return std.fmt.bufPrint(buf, "d{d}/{s}", .{ d, try iface.local.keyPath(key, @ptrCast(&kb)) });
    }
};

fn readAll(b: iface.StorageBackend, key: PhysicalKey, range: ?core.Range) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    _ = try b.get(key, range, &out.writer);
    return out.toOwnedSlice();
}

test "replica:2 put, ranged get, fallback on missing and corrupt, inline repair" {
    var fx: Fixture = .{ .tmp = undefined };
    try fx.init(.{ .replica = 2 });
    defer fx.deinit();
    const b = fx.store.backend();

    const data = try testing.allocator.alloc(u8, 3 * shard.chunk_size + 123);
    defer testing.allocator.free(data);
    for (data, 0..) |*c, i| c.* = @truncate(i *% 31);
    const key: PhysicalKey = .{ .space = .data, .hex = "0123456789abcdef0123456789abcdef".* };
    var src: std.Io.Reader = .fixed(data);
    try testing.expectEqual(@as(u64, data.len), (try b.put(key, &src, .{})).size);
    try testing.expectEqual(@as(u64, data.len), (try b.stat(key)).size);

    const got = try readAll(b, key, null);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, data, got);
    const part = try readAll(b, key, .{ .offset = shard.chunk_size - 5, .length = 10 });
    defer testing.allocator.free(part);
    try testing.expectEqualSlices(u8, data[shard.chunk_size - 5 ..][0..10], part);

    var pbuf: [max_drives]u8 = undefined;
    const placed = fx.set.placed(key, &pbuf);
    var path_buf: [128]u8 = undefined;

    // Flip a byte in the primary's second chunk: reads fall back and repair it.
    const p0 = try fx.shardPath(placed[0], key, &path_buf);
    {
        var f = try fx.tmp.dir.openFile(p0, .{ .mode = .read_write });
        defer f.close();
        var one: [1]u8 = undefined;
        const off = shard.chunkOffset(1) + 10;
        _ = try f.preadAll(&one, off);
        one[0] ^= 0xff;
        try f.pwriteAll(&one, off);
    }
    const got2 = try readAll(b, key, null);
    defer testing.allocator.free(got2);
    try testing.expectEqualSlices(u8, data, got2);
    try testing.expectEqual(KeyReport{ .healthy = 2 }, fx.store.healKey(key));

    // Remove the primary replica: reads still succeed and the replica is rewritten.
    try fx.tmp.dir.deleteFile(p0);
    const got3 = try readAll(b, key, .{ .offset = 1, .length = 2 });
    defer testing.allocator.free(got3);
    try testing.expectEqualSlices(u8, data[1..3], got3);
    try testing.expectEqual(KeyReport{ .healthy = 2 }, fx.store.healKey(key));

    // Heal fixes a missing secondary without any read.
    try fx.tmp.dir.deleteFile(try fx.shardPath(placed[1], key, &path_buf));
    try testing.expectEqual(KeyReport{ .healthy = 1, .repaired = 1 }, fx.store.healKey(key));

    try b.delete(key);
    try testing.expectError(error.NotFound, b.stat(key));
    try testing.expectError(error.NotFound, b.delete(key));
}

test "records are framed, verified, and listed once" {
    var fx: Fixture = .{ .tmp = undefined };
    try fx.init(.{ .replica = 3 });
    defer fx.deinit();
    const b = fx.store.backend();
    const key: PhysicalKey = .{ .space = .record, .hex = "fedcba9876543210fedcba9876543210".* };
    try b.putRecord(key, "record-bytes");

    var pbuf: [max_drives]u8 = undefined;
    const placed = fx.set.placed(key, &pbuf);
    var path_buf: [128]u8 = undefined;
    const p0 = try fx.shardPath(placed[0], key, &path_buf);
    try fx.tmp.dir.writeFile(.{ .sub_path = p0, .data = "garbage!!!!!!!!!!!!!" });
    const r = try b.getRecord(key, testing.allocator);
    defer testing.allocator.free(r);
    try testing.expectEqualStrings("record-bytes", r);
    try testing.expectEqual(@as(u8, 3), fx.store.healKey(key).healthy);

    const Count = struct {
        n: usize = 0,
        fn f(c: *anyopaque, _: PhysicalKey) Error!void {
            const s: *@This() = @ptrCast(@alignCast(c));
            s.n += 1;
        }
    };
    var c: Count = .{};
    try b.list(.record, .{ .ctx = &c, .func = Count.f });
    try testing.expectEqual(@as(usize, 1), c.n);

    // The catalog-style system key lives on every drive.
    try b.putRecord(.{ .space = .system, .hex = [_]u8{'0'} ** 32 }, "cat");
    try testing.expectEqual(@as(u8, 4), fx.store.healKey(.{ .space = .system, .hex = [_]u8{'0'} ** 32 }).healthy);
    try b.deleteRecord(key);
    try testing.expectError(error.NotFound, b.getRecord(key, testing.allocator));
}

test "empty object and quorum failure" {
    var fx: Fixture = .{ .tmp = undefined };
    try fx.init(.single);
    defer fx.deinit();
    const b = fx.store.backend();
    const key: PhysicalKey = .{ .space = .data, .hex = "00000000000000000000000000000001".* };
    var src: std.Io.Reader = .fixed("");
    try testing.expectEqual(@as(u64, 0), (try b.put(key, &src, .{})).size);
    const got = try readAll(b, key, null);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 0), got.len);

    var pbuf: [max_drives]u8 = undefined;
    const d = fx.set.placed(key, &pbuf)[0];
    fx.set.quarantine(d);
    var src2: std.Io.Reader = .fixed("x");
    try testing.expectError(error.IoFailed, b.put(key, &src2, .{}));
    try testing.expectError(error.IoFailed, readAll(b, key, null));
}
