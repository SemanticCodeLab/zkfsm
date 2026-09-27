//! Key index persistence through the StorageBackend (so it gets the store's replication
//! or erasure coding). A state record says whether the snapshot streams match the
//! records: it is marked dirty before the first record change after a clean snapshot,
//! and clean only after a full snapshot is written. Anything else means rebuild.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const metadata = @import("../metadata/root.zig");
const codec = @import("../metadata/codec.zig");
const service = @import("service.zig");

const Svc = service.ObjectService;
const Error = service.Error;

const state_magic = "ZKIS";
const chunk_magic = "ZKIC";
const format_version: u16 = 1;
const chunk_header_len = 4 + 2 + 8 + 4 + 4;
/// Snapshot payload per record; well under every backend's record limit.
const chunk_payload = 4 * 1024 * 1024;
const uploads_stream: [16]u8 = [_]u8{0xff} ** 16;

fn hashKey(parts: []const []const u8) backend.PhysicalKey {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |p| h.update(p);
    var d: [32]u8 = undefined;
    h.final(&d);
    return .{ .space = .system, .hex = std.fmt.bytesToHex(d[0..16].*, .lower) };
}

fn stateKey() backend.PhysicalKey {
    return hashKey(&.{"zkfsm-index-state"});
}

fn chunkKey(stream: [16]u8, i: u32) backend.PhysicalKey {
    var ib: [4]u8 = undefined;
    std.mem.writeInt(u32, &ib, i, .little);
    return hashKey(&.{ "zkfsm-index\x00", &stream, &ib });
}

const State = struct { clean: bool, gen: u64 };

fn readState(svc: *Svc) ?State {
    const bytes = svc.store.getRecord(stateKey(), svc.gpa) catch return null;
    defer svc.gpa.free(bytes);
    var c: codec.Cursor = .{ .bytes = bytes };
    const m = c.take(4) catch return null;
    if (!std.mem.eql(u8, m, state_magic) or (c.int(u16) catch return null) != format_version) return null;
    const clean = (c.take(1) catch return null)[0];
    const gen = c.int(u64) catch return null;
    if (clean > 1 or c.pos != bytes.len) return null;
    return .{ .clean = clean == 1, .gen = gen };
}

fn writeState(svc: *Svc, s: State) Error!void {
    var buf: [4 + 2 + 1 + 8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    w.writeAll(state_magic) catch unreachable;
    codec.putInt(&w, u16, format_version) catch unreachable;
    w.writeByte(@intFromBool(s.clean)) catch unreachable;
    codec.putInt(&w, u64, s.gen) catch unreachable;
    svc.store.putRecord(stateKey(), &buf) catch |e| return service.mapBackend(e);
}

/// Loads the snapshot when the state is clean, else rebuilds from the records.
pub fn open(svc: *Svc) Error!void {
    const st = readState(svc);
    if (st) |s| {
        svc.index_gen = s.gen;
        if (s.clean) {
            if (loadSnapshot(svc, s.gen)) {
                svc.index_clean = true;
                return;
            } else |e| if (e == error.OutOfMemory) return e;
            std.log.warn("key index snapshot unusable; rebuilding from records", .{});
            try writeState(svc, .{ .clean = false, .gen = s.gen });
        }
    }
    const t0 = std.time.milliTimestamp();
    try rebuildLocked(svc);
    std.log.info("key index rebuilt from records in {d} ms", .{std.time.milliTimestamp() - t0});
}

fn loadSnapshot(svc: *Svc, gen: u64) error{ OutOfMemory, Corrupt }!void {
    errdefer svc.index.clear();
    for (svc.catalog.buckets.items) |b| {
        const bytes = try readStream(svc, b.id.bytes, gen);
        defer svc.gpa.free(bytes);
        try svc.index.decodeBucket(b.id, bytes);
    }
    const ub = try readStream(svc, uploads_stream, gen);
    defer svc.gpa.free(ub);
    try svc.index.decodeUploads(ub);
}

/// Caller holds `svc.mutex`.
pub fn markDirtyLocked(svc: *Svc) Error!void {
    if (!svc.index_clean) return;
    try writeState(svc, .{ .clean = false, .gen = svc.index_gen });
    svc.index_clean = false;
}

/// Caller holds `svc.mutex`.
pub fn flushLocked(svc: *Svc) Error!void {
    if (svc.index_clean) return;
    if (svc.index.stale) try rebuildLocked(svc);
    const gen = svc.index_gen + 1;
    for (svc.catalog.buckets.items) |b| {
        const bytes = try svc.index.encodeBucket(svc.gpa, b.id);
        defer svc.gpa.free(bytes);
        try writeStream(svc, b.id.bytes, gen, bytes);
    }
    const ub = try svc.index.encodeUploads(svc.gpa);
    defer svc.gpa.free(ub);
    try writeStream(svc, uploads_stream, gen, ub);
    svc.store.sync() catch |e| return service.mapBackend(e);
    try writeState(svc, .{ .clean = true, .gen = gen });
    svc.index_gen = gen;
    svc.index_clean = true;
}

fn writeStream(svc: *Svc, stream: [16]u8, gen: u64, payload: []const u8) Error!void {
    const n: u32 = @intCast(@max(1, std.math.divCeil(usize, payload.len, chunk_payload) catch unreachable));
    const buf = try svc.gpa.alloc(u8, chunk_header_len + @min(payload.len, chunk_payload));
    defer svc.gpa.free(buf);
    for (0..n) |i| {
        const part = payload[i * chunk_payload .. @min(payload.len, (i + 1) * chunk_payload)];
        var w: std.Io.Writer = .fixed(buf);
        w.writeAll(chunk_magic) catch unreachable;
        codec.putInt(&w, u16, format_version) catch unreachable;
        codec.putInt(&w, u64, gen) catch unreachable;
        codec.putInt(&w, u32, @intCast(i)) catch unreachable;
        codec.putInt(&w, u32, n) catch unreachable;
        w.writeAll(part) catch unreachable;
        svc.store.putRecord(chunkKey(stream, @intCast(i)), w.buffered()) catch |e| return service.mapBackend(e);
    }
    dropChunksFrom(svc, stream, n);
}

/// Deletes leftover chunks from a longer earlier snapshot. Best effort.
fn dropChunksFrom(svc: *Svc, stream: [16]u8, first: u32) void {
    var i = first;
    while (true) : (i += 1) svc.store.deleteRecord(chunkKey(stream, i)) catch return;
}

pub fn dropStream(svc: *Svc, stream: [16]u8) void {
    dropChunksFrom(svc, stream, 0);
}

fn readStream(svc: *Svc, stream: [16]u8, gen: u64) error{ OutOfMemory, Corrupt }![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(svc.gpa);
    var n: u32 = 1;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const bytes = svc.store.getRecord(chunkKey(stream, i), svc.gpa) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Corrupt,
        };
        defer svc.gpa.free(bytes);
        var c: codec.Cursor = .{ .bytes = bytes };
        if (!std.mem.eql(u8, try c.take(4), chunk_magic) or try c.int(u16) != format_version) return error.Corrupt;
        if (try c.int(u64) != gen or try c.int(u32) != i) return error.Corrupt;
        const total = try c.int(u32);
        if (i == 0) n = total else if (total != n) return error.Corrupt;
        if (n == 0) return error.Corrupt;
        try out.appendSlice(svc.gpa, bytes[c.pos..]);
    }
    return out.toOwnedSlice(svc.gpa);
}

/// Rebuilds the index from the record space. Caller holds `svc.mutex`.
pub fn rebuildLocked(svc: *Svc) Error!void {
    svc.index.clear();
    errdefer svc.index.markStale();
    var arena = std.heap.ArenaAllocator.init(svc.gpa);
    defer arena.deinit();
    const it = try svc.scanRecords(arena.allocator());
    var known: std.AutoHashMapUnmanaged([16]u8, void) = .empty;
    for (svc.catalog.buckets.items) |b| try known.put(arena.allocator(), b.id.bytes, {});
    for (it.keys) |pk| {
        const bytes = svc.store.getRecord(pk, svc.gpa) catch |e| switch (e) {
            error.NotFound => continue,
            else => return service.mapBackend(e),
        };
        defer svc.gpa.free(bytes);
        if (metadata.upload.isUpload(bytes)) {
            var ua = std.heap.ArenaAllocator.init(svc.gpa);
            defer ua.deinit();
            const u = metadata.upload.decode(ua.allocator(), bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            svc.index.putUpload(u.upload_id, .{ .bucket = u.bucket_id, .key = u.key, .created_ns = u.created_ns });
            continue;
        }
        const rec = metadata.record.decode(bytes) catch continue;
        if (!known.contains(rec.bucket_id.bytes)) continue;
        svc.indexStored(pk, rec);
    }
    if (svc.index.stale) return error.OutOfMemory;
}

// ---- tests ----

const testing = std.testing;

fn openLocal(tmp: *testing.TmpDir) !backend.local.LocalBackend {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    return backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
}

fn putObj(svc: *Svc, key: []const u8) !void {
    var r: std.Io.Reader = .fixed("x");
    _ = try svc.put("bkt", key, &r, .{});
}

fn keysOf(svc: *Svc, a: std.mem.Allocator) ![]const u8 {
    const r = try svc.list(a, "bkt", .{});
    var out: std.ArrayList(u8) = .empty;
    for (r.contents) |e| {
        try out.appendSlice(a, e.key);
        try out.append(a, ',');
    }
    return out.items;
}

test "index snapshot survives clean restart; unclean or missing snapshot rebuilds" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var lb = try openLocal(&tmp);
    defer lb.close();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    {
        var svc = try Svc.init(gpa, lb.backend());
        defer svc.deinit();
        try svc.createBucket("bkt");
        try putObj(&svc, "b");
        try putObj(&svc, "a");
        try svc.flush();
        try testing.expect(svc.index_clean);
    }
    {
        // Clean state: loaded from the snapshot. A write marks it dirty; no flush = crash.
        var svc = try Svc.init(gpa, lb.backend());
        defer svc.deinit();
        try testing.expect(svc.index_clean);
        try testing.expectEqualStrings("a,b,", try keysOf(&svc, a));
        try putObj(&svc, "c");
        try testing.expect(!svc.index_clean);
        try testing.expect(!readState(&svc).?.clean);
    }
    {
        // Dirty state: rebuilt from records, including the unflushed write.
        var svc = try Svc.init(gpa, lb.backend());
        defer svc.deinit();
        try testing.expect(!svc.index_clean);
        try testing.expectEqualStrings("a,b,c,", try keysOf(&svc, a));
        try svc.flush();
        const bid = try svc.bucketId("bkt");
        // A deleted snapshot chunk under a clean state: rebuild, not an empty listing.
        try svc.store.deleteRecord(chunkKey(bid.bytes, 0));
    }
    {
        var svc = try Svc.init(gpa, lb.backend());
        defer svc.deinit();
        try testing.expectEqualStrings("a,b,c,", try keysOf(&svc, a));
        try svc.delete("bkt", "a");
        try svc.delete("bkt", "b");
        try svc.delete("bkt", "c");
        try svc.flush();
        try svc.deleteBucket("bkt");
    }
}
