//! Replica(N): a StorageBackend over a DriveSet. Quorum writes, CRC-verified reads
//! with replica fallback, inline repair of bad replicas. N=1 is the `single` profile.
const std = @import("std");
const core = @import("../core/root.zig");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const shard = @import("shard.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const ObjectMeta = iface.ObjectMeta;
const DriveSet = placement.DriveSet;
const LocalBackend = iface.local.LocalBackend;
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

    fn stripe(self: *ReplicaStore, key: PhysicalKey) *std.Thread.Mutex {
        return &self.stripes[std.hash.Wyhash.hash(@intFromEnum(key.space), &key.hex) % stripe_count];
    }

    /// Shared holds on a list of drives; null slots are offline. Lock order: drives, then stripe.
    const Holds = struct {
        set: *DriveSet,
        idx: []const u8,
        lbs: [max_drives]?*LocalBackend = @splat(null),

        fn acquire(set: *DriveSet, idx: []const u8) Holds {
            var h: Holds = .{ .set = set, .idx = idx };
            for (idx, 0..) |d, j| h.lbs[j] = set.acquire(d);
            return h;
        }

        fn release(h: *Holds) void {
            for (h.idx, 0..) |d, j| if (h.lbs[j] != null) h.set.release(d);
        }
    };

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, _: iface.PutOptions) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return error.InvalidKey;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        const need = quorum(placed.len);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();

        var pend: [max_drives]?LocalBackend.PendingWrite = @splat(null);
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
        if (live < need) return worst;

        const buf = try self.gpa.alloc(u8, shard.chunk_size);
        defer self.gpa.free(buf);
        var total: u64 = 0;
        while (true) {
            const n = source.readSliceShort(buf) catch return error.ReadFailed;
            if (n == 0) break;
            const crc = shard.chunkCrc(buf[0..n]);
            for (&pend) |*slot| if (slot.*) |*w| {
                w.writeAll(&crc) catch |e| {
                    dropWriter(slot, &live, &worst, e);
                    continue;
                };
                w.writeAll(buf[0..n]) catch |e| dropWriter(slot, &live, &worst, e);
            };
            if (live < need) return worst;
            total += n;
            if (n < buf.len) break;
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
            for (placed, 0..) |_, j| if (committed[j]) holds.lbs[j].?.backend().delete(key) catch {};
            return worst;
        }
        return .{ .size = total, .mtime_ns = core.time.nowNs() };
    }

    fn dropWriter(slot: *?LocalBackend.PendingWrite, live: *usize, worst: *Error, e: Error) void {
        slot.*.?.abort();
        slot.* = null;
        live.* -= 1;
        worst.* = worse(worst.*, e);
    }

    fn worse(a: Error, b: Error) Error {
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
    fn readShard(self: *ReplicaStore, lb: *LocalBackend, key: PhysicalKey, range: ?core.Range, sink: ?*std.Io.Writer, delivered: *u64, expect: ?u64) Outcome {
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
        return .{ .ok = .{ .size = size, .mtime_ns = st.mtime } };
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
        for (placed) |d| {
            const lb = self.drives.acquire(d) orelse {
                saw_other = true;
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
                .io => saw_other = true,
                .bad_range => return error.IoFailed,
                .sink_failed => return error.WriteFailed,
            }
            if (delivered > 0 and known == null) known = self.sizeOf(d, key);
        }
        return if (saw_other) error.IoFailed else error.NotFound;
    }

    fn sizeOf(self: *ReplicaStore, d: u8, key: PhysicalKey) ?u64 {
        const lb = self.drives.acquire(d) orelse return null;
        defer self.drives.release(d);
        const m = lb.backend().stat(key) catch return null;
        return shard.logicalSize(m.size);
    }

    /// Verifies one replica in full.
    fn check(self: *ReplicaStore, lb: *LocalBackend, key: PhysicalKey) Outcome {
        if (key.space == .data) {
            var n: u64 = 0;
            return self.readShard(lb, key, null, null, &n, null);
        }
        const raw = lb.backend().getRecord(key, self.gpa) catch |e| return if (e == error.NotFound) .missing else .io;
        defer self.gpa.free(raw);
        return if (shard.unframeRecord(raw) != null) .{ .ok = .{ .size = raw.len, .mtime_ns = 0 } } else .corrupt;
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

    fn copy(self: *ReplicaStore, src: *LocalBackend, dst: *LocalBackend, key: PhysicalKey) Error!void {
        if (key.space == .data) {
            var file = try src.openRead(key);
            defer file.close();
            var rbuf: [64 * 1024]u8 = undefined;
            var fr = file.reader(&rbuf);
            _ = dst.backend().put(key, &fr.interface, .{}) catch |e| return if (e == error.ReadFailed) error.IoFailed else e;
            return;
        }
        const raw = try src.backend().getRecord(key, self.gpa);
        defer self.gpa.free(raw);
        try dst.backend().putRecord(key, raw);
    }

    /// Verifies every placed replica of `key` and rewrites missing or corrupt ones.
    pub fn healKey(self: *ReplicaStore, key: PhysicalKey) KeyReport {
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();

        var rep: KeyReport = .{};
        var good: ?*LocalBackend = null;
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
        var pbuf: [max_drives]u8 = undefined;
        var saw_other = false;
        for (self.drives.placed(key, &pbuf)) |d| {
            const lb = self.drives.acquire(d) orelse continue;
            defer self.drives.release(d);
            const m = lb.backend().stat(key) catch |e| {
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
    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        const self = cast(ctx);
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        var removed: usize = 0;
        var absent: usize = 0;
        var worst: Error = error.IoFailed;
        for (placed, 0..) |_, j| {
            const b = (holds.lbs[j] orelse continue).backend();
            const r = if (key.space == .data) b.delete(key) else b.deleteRecord(key);
            r catch |e| {
                if (e == error.NotFound) absent += 1 else worst = worse(worst, e);
                continue;
            };
            removed += 1;
        }
        if (removed + absent < quorum(placed.len)) return worst;
        if (removed == 0) return error.NotFound;
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        const self = cast(ctx);
        if (key.space == .data) return error.InvalidKey;
        const framed = try shard.frameRecord(self.gpa, bytes);
        defer self.gpa.free(framed);
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const m = self.stripe(key);
        m.lock();
        defer m.unlock();
        var ok: usize = 0;
        var worst: Error = error.IoFailed;
        for (placed, 0..) |_, j| {
            const lb = holds.lbs[j] orelse continue;
            lb.backend().putRecord(key, framed) catch |e| {
                worst = worse(worst, e);
                continue;
            };
            ok += 1;
        }
        if (ok < quorum(placed.len)) return worst;
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        const self = cast(ctx);
        if (key.space == .data) return error.InvalidKey;
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
                break :blk lb.backend().getRecord(key, self.gpa) catch |e| switch (e) {
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
            const payload = shard.unframeRecord(raw) orelse {
                std.log.warn("drive {s}: corrupt record {s}", .{ self.drives.drives[d].path, &key.hex });
                bad[nbad] = d;
                nbad += 1;
                saw_other = true;
                continue;
            };
            const out = try gpa.dupe(u8, payload);
            if (nbad > 0) _ = self.repair(key, d, bad[0..nbad]);
            return out;
        }
        return if (saw_other) error.IoFailed else error.NotFound;
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
            lb.backend().list(space, .{ .ctx = &st, .func = State.f }) catch |e| {
                if (st.user_err) |ue| return ue;
                if (e == error.OutOfMemory) return e;
                continue;
            };
            reached += 1;
        }
        if (reached == 0) return error.IoFailed;
    }

    fn sync(ctx: *anyopaque) Error!void {
        const self = cast(ctx);
        for (0..self.drives.count()) |d| {
            const lb = self.drives.acquire(d) orelse continue;
            defer self.drives.release(d);
            try lb.backend().sync();
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
