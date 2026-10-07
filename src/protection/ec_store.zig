//! Erasure(k,m) as a StorageBackend: 1 MiB blocks striped over k+m drives with RS parity.
//! Shard file: header | (crc32c | shard block)*. Records stay replicated on all k+m drives.
const std = @import("std");
const core = @import("../core/root.zig");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const shard = @import("shard.zig");
const erasure = @import("erasure.zig");
const replica = @import("replica.zig");
const fanout = @import("fanout.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const ObjectMeta = iface.ObjectMeta;
const Handle = iface.drive.Handle;
const Pending = iface.drive.Pending;
const ShardFile = iface.drive.ShardFile;
const ReplicaStore = replica.ReplicaStore;
const Holds = ReplicaStore.Holds;
const KeyReport = replica.KeyReport;
const Layout = erasure.stripe.Layout;
const max_drives = placement.max_drives;
const max_n = 16;

pub const block_size: u32 = erasure.stripe.default_block_size;

const header_magic = "ZKE1";
const header_len = 24;

/// Per-shard header; the object size is written last, once known.
const Header = struct {
    k: u8,
    m: u8,
    index: u8,
    block_size: u32,
    size: u64,

    fn encode(h: Header) [header_len]u8 {
        var b: [header_len]u8 = @splat(0);
        b[0..4].* = header_magic.*;
        b[4] = h.k;
        b[5] = h.m;
        b[6] = h.index;
        std.mem.writeInt(u32, b[8..12], h.block_size, .little);
        std.mem.writeInt(u64, b[12..20], h.size, .little);
        std.mem.writeInt(u32, b[20..24], core.checksum.Crc32c.hash(b[0..20]), .little);
        return b;
    }

    fn decode(b: []const u8) ?Header {
        if (b.len != header_len or !std.mem.eql(u8, b[0..4], header_magic)) return null;
        if (std.mem.readInt(u32, b[20..24], .little) != core.checksum.Crc32c.hash(b[0..20])) return null;
        return .{
            .k = b[4],
            .m = b[5],
            .index = b[6],
            .block_size = std.mem.readInt(u32, b[8..12], .little),
            .size = std.mem.readInt(u64, b[12..20], .little),
        };
    }
};

/// Open shard files of one object with their agreed header.
const Shards = struct {
    files: [max_n]?ShardFile = @splat(null),
    bad: [max_n]bool = @splat(false),
    missing: usize = 0,
    /// Drives that could not be asked (offline or unreachable).
    offline: usize = 0,
    down: [max_n]bool = @splat(false),
    header: ?Header = null,
    mtime: i128 = 0,

    fn close(s: *Shards) void {
        for (&s.files) |*f| if (f.*) |*file| {
            file.close();
            f.* = null;
        };
    }

    fn drop(s: *Shards, i: usize) void {
        if (s.files[i]) |*f| f.close();
        s.files[i] = null;
        s.bad[i] = true;
    }
};

pub const ErasureStore = struct {
    gpa: std.mem.Allocator,
    drives: *placement.DriveSet,
    codec: erasure.Codec,
    /// Records and system keys: replicated on every placed drive.
    meta: ReplicaStore,

    pub fn init(gpa: std.mem.Allocator, drives: *placement.DriveSet, profile: erasure.Profile) ErasureStore {
        return .{ .gpa = gpa, .drives = drives, .codec = .init(profile), .meta = .init(gpa, drives) };
    }

    pub fn backend(self: *ErasureStore) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = ReplicaStore.capabilities, .vtable = &vtable };
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

    fn cast(ctx: *anyopaque) *ErasureStore {
        return @ptrCast(@alignCast(ctx));
    }

    fn width(self: *const ErasureStore) usize {
        return @as(usize, self.codec.k) + self.codec.m;
    }

    /// Single node: k+1 shards so one parity survives any later loss. Cluster: data
    /// shards, +1 when data == parity, so two write quorums always overlap.
    fn writeQuorum(self: *const ErasureStore) usize {
        if (self.drives.isCluster()) return placement.layout.objectWriteQuorum(self.drives.profile);
        return @min(self.width(), @as(usize, self.codec.k) + 1);
    }

    fn clustered(self: *const ErasureStore) bool {
        return self.drives.isCluster();
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return error.InvalidKey;
        if (!self.drives.writable()) return error.WriteQuorum;
        const n = self.width();
        const k = self.codec.k;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();

        var pend: [max_n]?Pending = @splat(null);
        defer for (&pend) |*slot| if (slot.*) |*w| w.abort();
        var worst: Error = error.IoFailed;
        var live: usize = 0;
        const blank: [header_len]u8 = @splat(0);
        for (0..n) |i| {
            const lb = holds.lbs[i] orelse continue;
            var w = lb.begin() catch |e| {
                worst = ReplicaStore.worse(worst, e);
                continue;
            };
            w.writeAll(&blank) catch |e| {
                w.abort();
                worst = ReplicaStore.worse(worst, e);
                continue;
            };
            pend[i] = w;
            live += 1;
        }
        if (live < self.writeQuorum()) return self.meta.short(&holds, self.writeQuorum(), worst, error.WriteQuorum);

        const lay0 = Layout.init(0, block_size, k) catch return error.IoFailed;
        const sl = lay0.shardLen();
        const blk = try self.gpa.alloc(u8, block_size);
        defer self.gpa.free(blk);
        const sbuf = try self.gpa.alloc(u8, n * sl);
        defer self.gpa.free(sbuf);
        var slices: [max_n][]u8 = undefined;
        for (0..n) |i| slices[i] = sbuf[i * sl ..][0..sl];

        var total: u64 = 0;
        while (true) {
            const want: usize = if (opts.size_hint) |h| @intCast(@min(block_size, h -| total)) else block_size;
            if (want == 0) break;
            const got = try ReplicaStore.fill(source, blk[0..want]);
            if (got == 0) break;
            erasure.stripe.split(blk[0..got], slices[0..k]);
            self.codec.encode(constSlices(slices[0..k]), slices[k..n]) catch return error.IoFailed;
            for (0..n) |i| if (pend[i]) |*w| {
                const crc = shard.chunkCrc(slices[i]);
                w.writeAll(&crc) catch |e| {
                    dropWriter(&pend[i], &live, &worst, e);
                    continue;
                };
                w.writeAll(slices[i]) catch |e| dropWriter(&pend[i], &live, &worst, e);
            };
            if (live < self.writeQuorum()) return if (self.clustered()) error.WriteQuorum else worst;
            total += got;
            if (got < want) break;
        }

        for (0..n) |i| if (pend[i]) |*w| {
            const h = (Header{ .k = k, .m = self.codec.m, .index = @intCast(i), .block_size = block_size, .size = total }).encode();
            w.pwrite(&h, 0) catch dropWriter(&pend[i], &live, &worst, error.IoFailed);
        };
        if (live < self.writeQuorum()) return if (self.clustered()) error.WriteQuorum else worst;

        const mtx = self.meta.stripe(key);
        mtx.lock();
        defer mtx.unlock();
        const Commit = struct {
            pend: *[max_n]?Pending,
            key: PhysicalKey,
            res: [max_n]?Error = @splat(null),
            done: [max_n]bool = @splat(false),
            fn f(c: *@This(), i: usize) void {
                var pw = c.pend[i] orelse return;
                c.pend[i] = null;
                if (pw.commit(c.key)) |_| {
                    c.done[i] = true;
                } else |e| c.res[i] = e;
            }
        };
        var cm: Commit = .{ .pend = &pend, .key = key };
        fanout.run(n, holds.parallel(), &cm, Commit.f);
        const committed = cm.done;
        var ok: usize = 0;
        for (0..n) |i| {
            if (cm.res[i]) |e| worst = ReplicaStore.worse(worst, e);
            ok += @intFromBool(committed[i]);
        }
        if (ok < self.writeQuorum()) {
            for (0..n) |i| if (committed[i]) holds.lbs[i].?.store().delete(key) catch {};
            return if (self.clustered() and worst == error.IoFailed) error.WriteQuorum else worst;
        }
        return .{ .size = total, .mtime_ns = core.time.nowNs() };
    }

    fn dropWriter(slot: *?Pending, live: *usize, worst: *Error, e: Error) void {
        slot.*.?.abort();
        slot.* = null;
        live.* -= 1;
        worst.* = ReplicaStore.worse(worst.*, e);
    }

    /// Opens every shard and settles on one header; disagreeing shards are marked bad.
    fn openShards(self: *ErasureStore, holds: *const Holds, key: PhysicalKey) Shards {
        var s: Shards = .{};
        const n = self.width();
        const Open = struct {
            holds: *const Holds,
            key: PhysicalKey,
            files: [max_n]?ShardFile = @splat(null),
            err: [max_n]?Error = @splat(null),
            headers: [max_n]?Header = @splat(null),
            fn f(c: *@This(), i: usize) void {
                const lb = c.holds.lbs[i] orelse return;
                var file = lb.openRead(c.key) catch |e| {
                    c.err[i] = e;
                    return;
                };
                var hb: [header_len]u8 = undefined;
                const got = file.preadAll(&hb, 0) catch 0;
                c.files[i] = file;
                c.headers[i] = Header.decode(hb[0..got]);
            }
        };
        var op: Open = .{ .holds = holds, .key = key };
        fanout.run(n, holds.parallel(), &op, Open.f);
        const headers = op.headers;
        for (0..n) |i| {
            if (holds.lbs[i] == null) {
                s.bad[i] = true;
                s.down[i] = true;
                s.offline += 1;
                continue;
            }
            if (op.err[i]) |e| {
                if (e == error.NotFound) {
                    s.missing += 1;
                } else {
                    s.offline += 1;
                    s.down[i] = true;
                }
                s.bad[i] = true;
                continue;
            }
            s.files[i] = op.files[i];
            if (headers[i] == null) s.drop(i);
        }
        // The header shared by the most shards wins.
        var best: usize = 0;
        for (0..n) |i| if (headers[i]) |h| {
            var votes: usize = 0;
            for (0..n) |j| if (headers[j]) |o| {
                if (o.size == h.size and o.block_size == h.block_size) votes += 1;
            };
            if (votes > best) {
                best = votes;
                s.header = h;
            }
        };
        const h = s.header orelse return s;
        for (0..n) |i| if (headers[i]) |o| {
            if (o.size != h.size or o.block_size != h.block_size or o.index != i or o.k != self.codec.k or o.m != self.codec.m) {
                s.drop(i);
            } else if (s.mtime == 0) {
                if (s.files[i].?.stat()) |st| {
                    s.mtime = st.mtime_ns;
                } else |_| {}
            }
        };
        return s;
    }

    fn readBlock(file: *ShardFile, b: u64, out: []u8, scratch: []u8) bool {
        const want = 4 + out.len;
        const got = file.preadAll(scratch[0..want], header_len + b * want) catch return false;
        if (got != want) return false;
        const data = shard.verifyChunk(scratch[0..want]) orelse return false;
        @memcpy(out, data);
        return true;
    }

    /// Fills all k+m slices of block `b`, reconstructing what is missing; false if < k survive.
    fn loadBlock(self: *ErasureStore, s: *Shards, b: u64, slices: []const []u8, scratch: []u8, all: bool) bool {
        const n = self.width();
        const k = self.codec.k;
        var present: [max_n]bool = @splat(false);
        var have: usize = 0;
        for (0..n) |i| {
            if (!all and i >= k and have == k) break;
            const f = if (s.files[i]) |*f| f else continue;
            if (readBlock(f, b, slices[i], scratch)) {
                present[i] = true;
                have += 1;
            } else s.drop(i);
        }
        if (have < k) return false;
        var complete = true;
        for (present[0..n]) |p| complete = complete and p;
        if (complete) return true;
        const data_ok = for (present[0..k]) |p| {
            if (!p) break false;
        } else true;
        if (!all and data_ok) return true;
        self.codec.reconstruct(slices[0..n], present[0..n]) catch return false;
        return true;
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?core.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return error.InvalidKey;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var needs_heal = false;
        const meta = blk: {
            var holds = Holds.acquire(self.drives, placed);
            defer holds.release();
            var s = self.openShards(&holds, key);
            defer s.close();
            const h = s.header orelse return self.noHeader(&s);
            const size = h.size;
            const r = range orelse core.Range{ .offset = 0, .length = size };
            if (r.length > 0 and (r.offset >= size or r.length > size - r.offset)) return error.IoFailed;
            if (r.length > 0) self.streamRange(&s, h, r, sink) catch |e| {
                return if (e == error.IoFailed and self.clustered() and s.offline > 0) error.ReadQuorum else e;
            };
            // Shards on unreachable drives are the healer's job once they return.
            for (s.bad[0..self.width()], s.down[0..self.width()]) |x, u| needs_heal = needs_heal or (x and !u);
            break :blk ObjectMeta{ .size = size, .mtime_ns = s.mtime };
        };
        if (needs_heal) {
            const rep = self.healData(key);
            if (rep.repaired > 0) std.log.info("repaired {d} shard(s) of {s} inline", .{ rep.repaired, &key.hex });
        }
        return meta;
    }

    fn streamRange(self: *ErasureStore, s: *Shards, h: Header, r: core.Range, sink: *std.Io.Writer) Error!void {
        const n = self.width();
        const k = self.codec.k;
        const lay = Layout.init(h.size, h.block_size, k) catch return error.IoFailed;
        const sl = lay.shardLen();
        const sbuf = try self.gpa.alloc(u8, n * sl + 4 + sl + h.block_size);
        defer self.gpa.free(sbuf);
        var slices: [max_n][]u8 = undefined;
        for (0..n) |i| slices[i] = sbuf[i * sl ..][0..sl];
        const scratch = sbuf[n * sl ..][0 .. 4 + sl];
        const joined = sbuf[n * sl + 4 + sl ..][0..h.block_size];
        const end = r.offset + r.length;
        var b = r.offset / h.block_size;
        while (b * h.block_size < end) : (b += 1) {
            if (!self.loadBlock(s, b, slices[0..n], scratch, false)) {
                std.log.warn("{d}-shard object: fewer than {d} healthy shards in block {d}", .{ n, k, b });
                return error.IoFailed;
            }
            const blen = lay.blockLen(b);
            erasure.stripe.join(constSlices(slices[0..k]), joined[0..blen]);
            const bstart = b * h.block_size;
            const lo: usize = @intCast(@max(r.offset, bstart) - bstart);
            const hi: usize = @intCast(@min(end, bstart + blen) - bstart);
            sink.writeAll(joined[lo..hi]) catch return error.WriteFailed;
        }
    }

    /// Verifies every shard block and rebuilds bad shards from the survivors.
    fn healData(self: *ErasureStore, key: PhysicalKey) KeyReport {
        const n = self.width();
        const k = self.codec.k;
        var pbuf: [max_drives]u8 = undefined;
        const placed = self.drives.placed(key, &pbuf);
        var holds = Holds.acquire(self.drives, placed);
        defer holds.release();
        const mtx = self.meta.stripe(key);
        mtx.lock();
        defer mtx.unlock();

        var rep: KeyReport = .{};
        var s = self.openShards(&holds, key);
        defer s.close();
        const h = s.header orelse {
            // Every shard missing means the object was deleted meanwhile.
            if (s.missing < n) rep.lost = true;
            return rep;
        };
        const lay = Layout.init(h.size, h.block_size, k) catch return .{ .lost = true };
        const sl = lay.shardLen();
        const sbuf = self.gpa.alloc(u8, n * sl + 4 + sl) catch return .{ .unrepaired = 1 };
        defer self.gpa.free(sbuf);
        var slices: [max_n][]u8 = undefined;
        for (0..n) |i| slices[i] = sbuf[i * sl ..][0..sl];
        const scratch = sbuf[n * sl ..][0 .. 4 + sl];

        // Pass 1: find shards with bad blocks.
        var b: u64 = 0;
        while (b < lay.blockCount()) : (b += 1) {
            for (0..n) |i| if (s.files[i]) |*f| {
                if (!readBlock(f, b, slices[i], scratch)) {
                    std.log.warn("drive {s}: corrupt shard {d} of {s}", .{ self.drives.drives[placed[i]].path, i, &key.hex });
                    s.drop(i);
                }
            };
        }
        var pend: [max_n]?Pending = @splat(null);
        defer for (&pend) |*slot| if (slot.*) |*w| w.abort();
        for (0..n) |i| {
            if (!s.bad[i]) {
                rep.healthy += 1;
                continue;
            }
            const lb = holds.lbs[i] orelse {
                rep.unrepaired += 1;
                continue;
            };
            var w = lb.begin() catch {
                rep.unrepaired += 1;
                continue;
            };
            const hdr = (Header{ .k = k, .m = self.codec.m, .index = @intCast(i), .block_size = h.block_size, .size = h.size }).encode();
            w.writeAll(&hdr) catch {
                w.abort();
                rep.unrepaired += 1;
                continue;
            };
            pend[i] = w;
        }
        if (rep.healthy < k) {
            if (self.dangling(&s)) {
                std.log.warn("purging dangling shards of {s} (partial write or delete)", .{&key.hex});
                s.close();
                for (0..n) |i| if (holds.lbs[i]) |lb| lb.store().delete(key) catch {};
                return .{};
            }
            rep.lost = true;
            return rep;
        }
        // Pass 2: rebuild bad shards block by block.
        b = 0;
        while (b < lay.blockCount()) : (b += 1) {
            if (!self.loadBlock(&s, b, slices[0..n], scratch, true)) {
                rep.lost = true;
                return rep;
            }
            for (0..n) |i| if (pend[i]) |*w| {
                const crc = shard.chunkCrc(slices[i]);
                w.writeAll(&crc) catch {
                    w.abort();
                    pend[i] = null;
                    rep.unrepaired += 1;
                    continue;
                };
                w.writeAll(slices[i]) catch {
                    w.abort();
                    pend[i] = null;
                    rep.unrepaired += 1;
                };
            };
        }
        for (0..n) |i| if (pend[i]) |*w| {
            var pw = w.*;
            pend[i] = null;
            pw.commit(key) catch {
                rep.unrepaired += 1;
                continue;
            };
            rep.repaired += 1;
        };
        return rep;
    }

    /// Why no header could be settled: absent everywhere, unreachable, or damaged.
    fn noHeader(self: *const ErasureStore, s: *const Shards) Error {
        if (s.missing == self.width()) return error.NotFound;
        if (self.clustered() and s.offline > 0) return error.ReadQuorum;
        return error.IoFailed;
    }

    /// Fewer than k shards while every drive answered, all older than the grace:
    /// leftovers of an interrupted write or delete, never readable again.
    fn dangling(self: *const ErasureStore, s: *const Shards) bool {
        if (!self.clustered() or s.offline > 0) return false;
        const now = core.time.nowNs();
        return s.mtime != 0 and now - s.mtime > replica.tombstone_grace_ns;
    }

    pub fn healKey(self: *ErasureStore, key: PhysicalKey) KeyReport {
        return if (key.space == .data) self.healData(key) else self.meta.healKey(key);
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta {
        const self = cast(ctx);
        if (key.space != .data) return self.meta.backend().stat(key);
        var pbuf: [max_drives]u8 = undefined;
        var holds = Holds.acquire(self.drives, self.drives.placed(key, &pbuf));
        defer holds.release();
        var s = self.openShards(&holds, key);
        defer s.close();
        const h = s.header orelse return self.noHeader(&s);
        return .{ .size = h.size, .mtime_ns = s.mtime };
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        return ReplicaStore.delete(&cast(ctx).meta, key);
    }

    fn list(ctx: *anyopaque, space: iface.KeySpace, cb: iface.ListCallback) Error!void {
        return cast(ctx).meta.backend().list(space, cb);
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        return cast(ctx).meta.backend().putRecord(key, bytes);
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        return cast(ctx).meta.backend().getRecord(key, gpa);
    }

    fn sync(ctx: *anyopaque) Error!void {
        return cast(ctx).meta.backend().sync();
    }
};

fn constSlices(s: []const []u8) []const []const u8 {
    return @ptrCast(s);
}

const testing = std.testing;

test "header roundtrip and corruption" {
    const h: Header = .{ .k = 4, .m = 2, .index = 5, .block_size = block_size, .size = 12345 };
    var b = h.encode();
    try testing.expectEqual(@as(u64, 12345), Header.decode(&b).?.size);
    b[13] ^= 1;
    try testing.expect(Header.decode(&b) == null);
}

test "EC:4+2 survives two lost shards and heals them" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [6][std.fs.max_path_bytes]u8 = undefined;
    var paths: [6][]const u8 = undefined;
    var nb: [4]u8 = undefined;
    for (0..6) |i| {
        const name = try std.fmt.bufPrint(&nb, "d{d}", .{i});
        try tmp.dir.makePath(name);
        paths[i] = try tmp.dir.realpath(name, &bufs[i]);
    }
    var set = try placement.DriveSet.open(gpa, &paths, .{ .erasure = .{ .data = 4, .parity = 2 } });
    defer set.deinit();
    var store = ErasureStore.init(gpa, &set, .ec4_2);
    const be = store.backend();

    const data = try gpa.alloc(u8, block_size + 777);
    defer gpa.free(data);
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(data);
    const key: PhysicalKey = .{ .space = .data, .hex = "aaaabbbbccccddddeeeeffff00001111".* };
    var src: std.Io.Reader = .fixed(data);
    try testing.expectEqual(@as(u64, data.len), (try be.put(key, &src, .{ .size_hint = data.len })).size);
    try testing.expectEqual(@as(u64, data.len), (try be.stat(key)).size);

    var pbuf: [max_drives]u8 = undefined;
    const placed = set.placed(key, &pbuf);
    var kb: [64]u8 = undefined;
    const rel = try iface.local.keyPath(key, @ptrCast(&kb));
    var pb: [128]u8 = undefined;
    // Lose data shard 0 entirely and flip a byte in data shard 2's second block.
    try tmp.dir.deleteFile(try std.fmt.bufPrint(&pb, "d{d}/{s}", .{ placed[0], rel }));
    {
        var f = try tmp.dir.openFile(try std.fmt.bufPrint(&pb, "d{d}/{s}", .{ placed[2], rel }), .{ .mode = .read_write });
        defer f.close();
        const off = header_len + (4 + (try Layout.init(0, block_size, 4)).shardLen()) + 50;
        try f.pwriteAll("\x99", off);
    }
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    _ = try be.get(key, .{ .offset = block_size - 3, .length = 100 }, &out.writer);
    try testing.expectEqualSlices(u8, data[block_size - 3 ..][0..100], out.written());
    // The read repaired both shards inline.
    try testing.expectEqual(KeyReport{ .healthy = 6 }, store.healKey(key));

    // Three losses exceed m=2.
    for (0..3) |i| try tmp.dir.deleteFile(try std.fmt.bufPrint(&pb, "d{d}/{s}", .{ placed[i], rel }));
    out.clearRetainingCapacity();
    try testing.expectError(error.IoFailed, be.get(key, null, &out.writer));

    var empty: std.Io.Reader = .fixed("");
    const ek: PhysicalKey = .{ .space = .data, .hex = "00000000000000000000000000000002".* };
    try testing.expectEqual(@as(u64, 0), (try be.put(ek, &empty, .{})).size);
    out.clearRetainingCapacity();
    try testing.expectEqual(@as(u64, 0), (try be.get(ek, null, &out.writer)).size);
    try be.delete(ek);
    try testing.expectError(error.NotFound, be.stat(ek));
}
