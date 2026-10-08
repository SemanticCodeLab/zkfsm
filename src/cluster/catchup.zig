//! Index catch-up state: per peer, how far into its change journal this node's key
//! index is known to be applied, and the node-local snapshot of the index with those
//! watermarks, so a restart or a returning peer costs the missed changes, not a
//! rebuild from every record.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const wire = @import("wire.zig");

/// Out-of-order applied entries remembered per peer before giving up on notes.
const max_above = 65536;
/// A peer's stable head may run ahead of us this long before we pull.
pub const lag_ms: i64 = 1500;

/// Watermark for one peer's journal.
pub const Origin = struct {
    /// 0: unknown; only a rebuild or a successful pull sets it.
    epoch: u64 = 0,
    /// Every entry up to here is applied.
    seq: u64 = 0,
    /// Applied entries past `seq + 1`, from notes that overtook each other.
    above: std.AutoHashMapUnmanaged(u64, void) = .empty,
    /// The peer's last reported stable head.
    head_epoch: u64 = 0,
    head_seq: u64 = 0,
    lag_since_ms: i64 = 0,
    /// Pull (or rebuild) before trusting this watermark again.
    behind: bool = true,

    fn deinit(o: *Origin, gpa: std.mem.Allocator) void {
        o.above.deinit(gpa);
    }

    fn advance(o: *Origin, seq: u64) void {
        if (seq <= o.seq) return;
        o.seq = seq;
        while (o.above.remove(o.seq + 1)) o.seq += 1;
        if (o.above.count() == 0) return;
        // Drop anything the jump passed.
        var it = o.above.keyIterator();
        var stale: [64]u64 = undefined;
        var n: usize = 0;
        while (it.next()) |k| if (k.* <= o.seq and n < stale.len) {
            stale[n] = k.*;
            n += 1;
        };
        for (stale[0..n]) |k| _ = o.above.remove(k);
    }
};

pub const Origins = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    list: []Origin,
    /// Index changes since the last snapshot (applied or made here).
    dirty: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: std.mem.Allocator, nodes: usize) error{OutOfMemory}!Origins {
        const l = try gpa.alloc(Origin, nodes);
        for (l) |*o| o.* = .{};
        return .{ .gpa = gpa, .list = l };
    }

    pub fn deinit(s: *Origins) void {
        for (s.list) |*o| o.deinit(s.gpa);
        s.gpa.free(s.list);
    }

    /// A note's change from `node`, entry `m`, was applied.
    pub fn applied(s: *Origins, node: u16, m: wire.Mark) void {
        _ = s.dirty.fetchAdd(1, .monotonic);
        s.mutex.lock();
        defer s.mutex.unlock();
        const o = &s.list[node];
        if (m.epoch != o.epoch or o.behind) {
            o.behind = true;
            return;
        }
        if (m.seq <= o.seq) return;
        if (m.seq == o.seq + 1) return o.advance(m.seq);
        if (o.above.count() >= max_above) {
            o.above.clearRetainingCapacity();
            o.behind = true;
            return;
        }
        o.above.put(s.gpa, m.seq, {}) catch {
            o.behind = true;
        };
    }

    /// A heartbeat told us the peer's stable head, and where it stood when it
    /// started serving (null while it does not serve). Returns true when a pull is due.
    pub fn heard(s: *Origins, node: u16, epoch: u64, stable: u64, opened: ?u64, now_ms: i64) bool {
        s.mutex.lock();
        defer s.mutex.unlock();
        const o = &s.list[node];
        // A new epoch (the peer lost its journal) after we had all it published:
        // nothing earlier is missing, so it is as good as unknown-since-a-rebuild.
        if (o.epoch != 0 and epoch != o.epoch and o.head_epoch == o.epoch and !o.behind and o.seq >= o.head_seq) o.epoch = 0;
        o.head_epoch = epoch;
        o.head_seq = stable;
        // Unknown since our last rebuild: what it journaled before it started serving
        // predates that rebuild, so only later entries need a pull.
        if (o.epoch == 0) if (opened) |start| if (start <= stable) {
            o.epoch = epoch;
            o.seq = start;
            o.above.clearRetainingCapacity();
            o.behind = stable > start;
        };
        if (epoch != o.epoch) o.behind = true;
        if (o.behind) return true;
        if (stable <= o.seq) {
            o.lag_since_ms = 0;
            return false;
        }
        // Notes for entries up to the head were sent before it advanced; a gap that
        // outlives a heartbeat is a lost note.
        if (o.lag_since_ms == 0) o.lag_since_ms = now_ms;
        if (now_ms - o.lag_since_ms > lag_ms) o.behind = true;
        return o.behind;
    }

    pub const Want = struct { epoch: u64, seq: u64 };

    pub fn knowsHead(s: *Origins, node: u16) bool {
        s.mutex.lock();
        defer s.mutex.unlock();
        return s.list[node].head_epoch != 0;
    }

    /// Where to pull from, or null when the peer needs no pull.
    pub fn want(s: *Origins, node: u16) ?Want {
        s.mutex.lock();
        defer s.mutex.unlock();
        const o = &s.list[node];
        if (!o.behind) return null;
        return .{ .epoch = o.epoch, .seq = o.seq };
    }

    /// A pull applied entries up to `seq`; `done` when it reached the peer's head.
    pub fn pulled(s: *Origins, node: u16, epoch: u64, seq: u64, done: bool) void {
        _ = s.dirty.fetchAdd(1, .monotonic);
        s.mutex.lock();
        defer s.mutex.unlock();
        const o = &s.list[node];
        if (o.epoch != epoch) return;
        o.advance(seq);
        if (done) {
            o.behind = false;
            o.lag_since_ms = 0;
        }
    }

    /// After a rebuild that started once these heads were known: each peer is
    /// caught up to its head then (later entries are re-read by notes or pulls).
    pub fn rebuilt(s: *Origins, hs: []const Want) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        for (s.list, hs) |*o, h| {
            o.above.clearRetainingCapacity();
            o.epoch = h.epoch;
            o.seq = h.seq;
            o.lag_since_ms = 0;
            o.behind = h.epoch == 0;
        }
    }

    /// The peers' last reported heads (epoch 0 where never heard).
    pub fn heads(s: *Origins, out: []Want) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        for (s.list, out) |o, *w| w.* = .{ .epoch = o.head_epoch, .seq = o.head_seq };
    }

    pub fn marks(s: *Origins, out: []Want) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        for (s.list, out) |o, *w| w.* = if (o.behind) .{ .epoch = 0, .seq = 0 } else .{ .epoch = o.epoch, .seq = o.seq };
    }

    /// Loaded from a snapshot: trusted only once each peer is pulled from there.
    pub fn restore(s: *Origins, from: []const Want) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        for (s.list, from) |*o, w| {
            o.epoch = w.epoch;
            o.seq = w.seq;
            o.behind = true;
        }
    }
};

// ---- snapshot file: header, watermarks, buckets, uploads, crc ----

pub const snapshot_name = "index.snap";
const snap_magic = "ZKNS";
const snap_version: u16 = 1;

pub const Snapshot = struct {
    deployment: [16]u8,
    /// Per node; this node's own entry is its own journal position.
    marks: []Origins.Want,
};

/// Encodes the index of `svc` (caller holds `svc.mutex`) with `marks`.
pub fn encode(gpa: std.mem.Allocator, svc: *object.ObjectService, deployment: [16]u8, marks: []const Origins.Want) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    encodeTo(w, gpa, svc, deployment, marks) catch return error.OutOfMemory;
    const crc = core.checksum.Crc32c.hash(out.written());
    w.writeInt(u32, crc, .little) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

fn encodeTo(w: *std.Io.Writer, gpa: std.mem.Allocator, svc: *object.ObjectService, deployment: [16]u8, marks: []const Origins.Want) !void {
    try w.writeAll(snap_magic);
    try w.writeInt(u16, snap_version, .little);
    try w.writeAll(&deployment);
    try w.writeInt(u16, @intCast(marks.len), .little);
    for (marks) |m| {
        try w.writeInt(u64, m.epoch, .little);
        try w.writeInt(u64, m.seq, .little);
    }
    try w.writeInt(u32, @intCast(svc.catalog.buckets.items.len), .little);
    for (svc.catalog.buckets.items) |b| {
        const bytes = try svc.index.encodeBucket(gpa, b.id);
        defer gpa.free(bytes);
        try w.writeAll(&b.id.bytes);
        try w.writeInt(u64, bytes.len, .little);
        try w.writeAll(bytes);
    }
    const ub = try svc.index.encodeUploads(gpa);
    defer gpa.free(ub);
    try w.writeInt(u64, ub.len, .little);
    try w.writeAll(ub);
}

pub const DecodeError = error{ OutOfMemory, Corrupt };

/// Loads a snapshot into the (empty) index of `svc`; caller holds `svc.mutex`.
/// Buckets no longer in the catalog are skipped. Returns the marks (owned by `gpa`).
pub fn decode(gpa: std.mem.Allocator, svc: *object.ObjectService, bytes: []const u8, deployment: [16]u8, nodes: usize) DecodeError![]Origins.Want {
    if (bytes.len < 4) return error.Corrupt;
    const body = bytes[0 .. bytes.len - 4];
    if (std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little) != core.checksum.Crc32c.hash(body)) return error.Corrupt;
    var r: std.Io.Reader = .fixed(body);
    const magic = r.takeArray(4) catch return error.Corrupt;
    if (!std.mem.eql(u8, magic, snap_magic)) return error.Corrupt;
    if ((r.takeInt(u16, .little) catch return error.Corrupt) != snap_version) return error.Corrupt;
    const dep = r.takeArray(16) catch return error.Corrupt;
    if (!std.mem.eql(u8, dep, &deployment)) return error.Corrupt;
    const n = r.takeInt(u16, .little) catch return error.Corrupt;
    if (n != nodes) return error.Corrupt;
    const marks = try gpa.alloc(Origins.Want, n);
    errdefer gpa.free(marks);
    for (marks) |*m| m.* = .{
        .epoch = r.takeInt(u64, .little) catch return error.Corrupt,
        .seq = r.takeInt(u64, .little) catch return error.Corrupt,
    };
    errdefer svc.index.clear();
    const nb = r.takeInt(u32, .little) catch return error.Corrupt;
    for (0..nb) |_| {
        const bid: core.BucketId = .{ .bytes = (r.takeArray(16) catch return error.Corrupt).* };
        const len = r.takeInt(u64, .little) catch return error.Corrupt;
        if (len > r.bufferedLen()) return error.Corrupt;
        const chunk = r.take(@intCast(len)) catch return error.Corrupt;
        const known = for (svc.catalog.buckets.items) |b| {
            if (b.id.eql(bid)) break true;
        } else false;
        if (known) try svc.index.decodeBucket(bid, chunk);
    }
    const ul = r.takeInt(u64, .little) catch return error.Corrupt;
    if (ul != r.bufferedLen()) return error.Corrupt;
    try svc.index.decodeUploads(r.take(@intCast(ul)) catch return error.Corrupt);
    return marks;
}

/// Writes `bytes` as the snapshot atomically (temp, fsync, rename).
pub fn save(dir: std.fs.Dir, bytes: []const u8) !void {
    const tmp = snapshot_name ++ ".tmp";
    {
        var f = try dir.createFile(tmp, .{ .truncate = true });
        defer f.close();
        try f.writeAll(bytes);
        try f.sync();
    }
    try dir.rename(tmp, snapshot_name);
}

test "watermarks: in order, overtaken, gaps, epochs, heads" {
    const gpa = std.testing.allocator;
    var s = try Origins.init(gpa, 2);
    defer s.deinit();
    s.rebuilt(&.{ .{ .epoch = 0, .seq = 0 }, .{ .epoch = 9, .seq = 10 } });
    try std.testing.expect(s.want(1) == null);
    s.applied(1, .{ .epoch = 9, .seq = 12 });
    s.applied(1, .{ .epoch = 9, .seq = 11 });
    try std.testing.expectEqual(@as(u64, 12), s.list[1].seq);
    // A head past us is fine for one heartbeat, a pull once it lingers.
    s.applied(1, .{ .epoch = 9, .seq = 14 });
    try std.testing.expect(!s.heard(1, 9, 14, null, 1000));
    try std.testing.expect(s.heard(1, 9, 14, null, 1000 + lag_ms + 1));
    try std.testing.expectEqual(Origins.Want{ .epoch = 9, .seq = 12 }, s.want(1).?);
    s.pulled(1, 9, 14, true);
    try std.testing.expect(s.want(1) == null);
    try std.testing.expectEqual(@as(u64, 14), s.list[1].seq);
    // A new epoch (the peer lost its journal) after we had everything: adopted.
    try std.testing.expect(!s.heard(1, 10, 1, 1, 5000));
    try std.testing.expectEqual(@as(u64, 10), s.list[1].epoch);
    // A new epoch while we lagged: behind, and only a rebuild can help.
    s.list[1].behind = true;
    try std.testing.expect(s.heard(1, 11, 1, 1, 5000));
    // Node 0 was unknown at the rebuild: pulled from where it started serving.
    try std.testing.expect(s.want(0) != null);
    try std.testing.expect(s.heard(0, 3, 7, 5, 6000));
    try std.testing.expectEqual(Origins.Want{ .epoch = 3, .seq = 5 }, s.want(0).?);
}
