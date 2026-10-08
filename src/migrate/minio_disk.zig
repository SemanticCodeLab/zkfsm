//! Offline reader for a stopped source deployment's drives: drive order from
//! format.json, per-object metadata from every drive of the erasure set, and object
//! bytes rebuilt from bitrot-checked shards (inline or part files).
const std = @import("std");
const xlmeta = @import("xlmeta.zig");
const rs = @import("rs.zig");
const highway = @import("highway.zig");
const model = @import("model.zig");

pub const Error = error{ OutOfMemory, NoFormat, Corrupt, ReadFailed, TooManyMissing, Unsupported, NotFound };

pub const meta_bucket = ".minio.sys";
const dir_suffix = "__XLDIR__";
const max_meta_file = 64 * 1024 * 1024;
const max_path = 4096;

const Drive = struct { path: []const u8, dir: std.fs.Dir };

pub const Stats = struct {
    bitrot_failures: u64 = 0,
    shards_rebuilt: u64 = 0,
    missing_drives: u64 = 0,
};

pub const Source = struct {
    gpa: std.mem.Allocator,
    /// Per erasure set, its drives in format order; null where a drive is absent.
    sets: [][]?Drive,
    stats: Stats = .{},

    pub fn open(gpa: std.mem.Allocator, arena: std.mem.Allocator, paths: []const []const u8) Error!Source {
        const Fmt = struct { id: []const u8 = "", xl: struct { this: []const u8, sets: [][][]const u8 } };
        // Each pool's drives list that pool's sets; the union covers every pool.
        var layout: std.ArrayList([][]const u8) = .empty;
        var deployment: ?[]const u8 = null;
        const thises = try arena.alloc(?[]const u8, paths.len);
        const dirs = try arena.alloc(?std.fs.Dir, paths.len);
        for (paths, thises, dirs) |p, *t, *d| {
            t.* = null;
            d.* = std.fs.cwd().openDir(p, .{ .iterate = true }) catch null;
            const dir = d.* orelse continue;
            const bytes = dir.readFileAlloc(arena, meta_bucket ++ "/format.json", 1 << 20) catch continue;
            const f = std.json.parseFromSliceLeaky(Fmt, arena, bytes, .{ .ignore_unknown_fields = true }) catch continue;
            if (deployment) |dep| if (!std.mem.eql(u8, dep, f.id)) {
                std.log.err("{s}: drive belongs to another deployment ({s})", .{ p, f.id });
                return error.NoFormat;
            };
            deployment = f.id;
            for (f.xl.sets) |set| {
                if (set.len == 0) return error.NoFormat;
                const known = for (layout.items) |have| {
                    if (std.mem.eql(u8, have[0], set[0])) break true;
                } else false;
                if (!known) try layout.append(arena, set);
            }
            t.* = f.xl.this;
        }
        const sets_doc = layout.items;
        if (sets_doc.len == 0 or sets_doc.len > 1024) return error.NoFormat;
        const sets = try gpa.alloc([]?Drive, sets_doc.len);
        var missing: u64 = 0;
        for (sets_doc, sets) |ids, *s| {
            if (ids.len == 0 or ids.len > rs.max_shards) return error.NoFormat;
            s.* = try gpa.alloc(?Drive, ids.len);
            for (ids, s.*) |id, *slot| {
                slot.* = null;
                for (thises, dirs, paths) |t, d, p| if (t) |tt| if (std.mem.eql(u8, tt, id)) {
                    slot.* = .{ .path = p, .dir = d.? };
                };
                if (slot.* == null) missing += 1;
            }
        }
        for (dirs, thises) |*d, t| if (d.*) |*x| {
            const used = if (t) |tt| for (sets_doc) |ids| {
                if (for (ids) |id| {
                    if (std.mem.eql(u8, id, tt)) break true;
                } else false) break true;
            } else false else false;
            if (!used) x.close();
        };
        return .{ .gpa = gpa, .sets = sets, .stats = .{ .missing_drives = missing } };
    }

    pub fn deinit(s: *Source) void {
        for (s.sets) |set| {
            for (set) |*d| if (d.*) |*x| x.dir.close();
            s.gpa.free(set);
        }
        s.gpa.free(s.sets);
    }

    /// Bucket names present on any drive, sorted.
    pub fn listBuckets(s: *Source, arena: std.mem.Allocator) Error![][]const u8 {
        var names: std.StringArrayHashMapUnmanaged(void) = .empty;
        for (s.sets) |set| for (set) |dd| {
            const d = dd orelse continue;
            var it = d.dir.iterate();
            while (it.next() catch null) |e| {
                if (e.kind != .directory or e.name.len == 0 or e.name[0] == '.') continue;
                try names.put(arena, try arena.dupe(u8, e.name), {});
            }
        };
        const out = try arena.dupe([]const u8, names.keys());
        std.mem.sort([]const u8, out, {}, lessStr);
        return out;
    }

    /// Calls `cb(ctx, set, key)` for every object under `bucket`/`prefix_dir`.
    pub fn walk(s: *Source, bucket: []const u8, prefix_dir: []const u8, comptime E: type, ctx: anytype, comptime cb: fn (@TypeOf(ctx), usize, []const u8) E!void) (E || Error)!void {
        for (s.sets, 0..) |_, si| {
            var arena = std.heap.ArenaAllocator.init(s.gpa);
            defer arena.deinit();
            try s.walkDir(arena.allocator(), si, bucket, prefix_dir, 0, E, ctx, cb);
        }
    }

    fn walkDir(s: *Source, arena: std.mem.Allocator, si: usize, bucket: []const u8, rel: []const u8, depth: usize, comptime E: type, ctx: anytype, comptime cb: fn (@TypeOf(ctx), usize, []const u8) E!void) (E || Error)!void {
        if (depth > 512) return;
        var children: std.StringArrayHashMapUnmanaged(void) = .empty;
        var is_object = false;
        for (s.sets[si]) |dd| {
            const d = dd orelse continue;
            var pbuf: [max_path]u8 = undefined;
            const p = joinPath(&pbuf, &.{ bucket, rel }) orelse continue;
            var sub = d.dir.openDir(p, .{ .iterate = true }) catch continue;
            defer sub.close();
            var it = sub.iterate();
            while (it.next() catch null) |e| {
                if (e.kind == .directory) {
                    try children.put(arena, try arena.dupe(u8, e.name), {});
                } else if (std.mem.eql(u8, e.name, "xl.meta")) is_object = true;
            }
        }
        if (is_object and rel.len > 0) {
            var kbuf: [max_path]u8 = undefined;
            const key = objectKey(&kbuf, rel) orelse return;
            try cb(ctx, si, key);
        }
        const names = try arena.dupe([]const u8, children.keys());
        std.mem.sort([]const u8, names, {}, lessStr);
        for (names) |n| {
            // Data directories of an object are UUID-named.
            if (is_object and xlmeta.parseUuid(n) != null and n.len == 36) continue;
            var rbuf: [max_path]u8 = undefined;
            const child = (if (rel.len == 0) joinPath(&rbuf, &.{n}) else joinPath(&rbuf, &.{ rel, n })) orelse continue;
            var sub_arena = std.heap.ArenaAllocator.init(s.gpa);
            defer sub_arena.deinit();
            try s.walkDir(sub_arena.allocator(), si, bucket, try sub_arena.allocator().dupe(u8, child), depth + 1, E, ctx, cb);
        }
    }

    /// Finds the set holding `bucket/key` (the meta bucket may live in any set).
    pub fn findSet(s: *Source, bucket: []const u8, key: []const u8) ?usize {
        var pbuf: [max_path]u8 = undefined;
        var dbuf: [max_path]u8 = undefined;
        const kd = diskKey(&dbuf, key) orelse return null;
        const p = joinPath(&pbuf, &.{ bucket, kd, "xl.meta" }) orelse return null;
        for (s.sets, 0..) |set, si| for (set) |dd| {
            const d = dd orelse continue;
            d.dir.access(p, .{}) catch continue;
            return si;
        };
        return null;
    }

    /// Merges every drive's metadata for one object. Strings live in `arena`.
    pub fn loadObject(s: *Source, arena: std.mem.Allocator, si: usize, bucket: []const u8, key: []const u8) Error!Object {
        const set = s.sets[si];
        var pbuf: [max_path]u8 = undefined;
        var dbuf: [max_path]u8 = undefined;
        const kd = diskKey(&dbuf, key) orelse return error.Corrupt;
        const p = joinPath(&pbuf, &.{ bucket, kd, "xl.meta" }) orelse return error.Corrupt;
        const files = try arena.alloc(?xlmeta.File, set.len);
        var any = false;
        for (set, files) |dd, *f| {
            f.* = null;
            const d = dd orelse continue;
            const bytes = d.dir.readFileAlloc(arena, p, max_meta_file) catch continue;
            f.* = xlmeta.parse(arena, bytes) catch |e| {
                std.log.warn("{s}/{s}: unreadable metadata ({t}); treating drive as missing", .{ d.path, p, e });
                continue;
            };
            any = true;
        }
        if (!any) return error.NotFound;
        var merged: std.ArrayList(Merged) = .empty;
        for (files, 0..) |mf, di| {
            const f = mf orelse continue;
            for (f.versions) |v| {
                const m = for (merged.items) |*m| {
                    if (std.mem.eql(u8, &m.v.id, &v.id) and m.v.mod_time_ns == v.mod_time_ns and m.v.kind == v.kind) break m;
                } else blk: {
                    try merged.append(arena, .{ .v = v });
                    break :blk &merged.items[merged.items.len - 1];
                };
                m.votes += 1;
                if (v.kind != .object or v.ec_index == 0 or v.ec_index > set.len) continue;
                if (!std.mem.eql(u8, &v.data_dir, &m.v.data_dir)) continue;
                const shard = v.ec_index - 1;
                if (m.shards[shard] != null) continue;
                m.shards[shard] = .{ .drive = @intCast(di), .inline_data = f.inlineFor(v) catch null };
            }
        }
        // A version seen by fewer drives than the data count is a leftover of a failed write.
        var kept: std.ArrayList(Merged) = .empty;
        for (merged.items) |m| {
            const quorum: usize = if (m.v.kind == .object) @max(1, m.v.ec_m) else (set.len + 1) / 2;
            if (m.votes >= @min(quorum, set.len)) try kept.append(arena, m);
        }
        return .{ .set = si, .bucket = bucket, .key = key, .disk_key = try arena.dupe(u8, kd), .versions = kept.items };
    }

    /// Whole content of a small object (configuration files); newest version.
    pub fn readSmall(s: *Source, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, max: usize) Error!?[]u8 {
        const si = s.findSet(bucket, key) orelse return null;
        const obj = try s.loadObject(arena, si, bucket, key);
        var best: ?*const Merged = null;
        for (obj.versions) |*m| if (best == null or m.v.mod_time_ns > best.?.v.mod_time_ns) {
            best = m;
        };
        const m = best orelse return null;
        if (m.v.kind != .object) return null;
        if (m.v.size < 0 or @as(u64, @intCast(m.v.size)) > max) return error.Corrupt;
        var out: std.Io.Writer.Allocating = .init(arena);
        var rd = try ObjectReader.init(s, arena, &obj, m, &.{});
        defer rd.deinit();
        _ = rd.interface.streamRemaining(&out.writer) catch return rd.err orelse error.ReadFailed;
        return out.written();
    }

    /// Source-neutral view of one version.
    pub fn info(arena: std.mem.Allocator, m: *const Merged) model.ApplyError!model.VersionInfo {
        var vi: model.VersionInfo = .{ .id = m.v.id, .mtime_ns = m.v.mod_time_ns, .delete_marker = m.v.kind == .delete_marker };
        if (m.v.kind == .delete_marker) return vi;
        vi.size = @intCast(m.v.size);
        const pairs = try arena.alloc(model.Header, m.v.meta_usr.len + m.v.meta_sys.len);
        for (m.v.meta_usr, 0..) |kv, i| pairs[i] = .{ .name = kv.name, .value = kv.value };
        for (m.v.meta_sys, 0..) |kv, i| pairs[m.v.meta_usr.len + i] = .{ .name = kv.name, .value = kv.value };
        try model.applyMeta(arena, &vi, pairs);
        if (m.v.checksum_algo != 1 and m.v.size > 0) vi.skip_reason = "unknown bitrot algorithm";
        if (m.v.ec_m == 0 or @as(usize, m.v.ec_m) + m.v.ec_n > rs.max_shards) vi.skip_reason = "bad erasure geometry";
        return vi;
    }
};

pub const ShardSource = struct { drive: u8, inline_data: ?[]const u8 };

pub const Merged = struct {
    v: xlmeta.Version,
    votes: usize = 0,
    shards: [rs.max_shards]?ShardSource = @splat(null),
};

pub const Object = struct {
    set: usize,
    bucket: []const u8,
    key: []const u8,
    disk_key: []const u8,
    versions: []Merged,
};

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn joinPath(buf: []u8, parts: []const []const u8) ?[]const u8 {
    var n: usize = 0;
    for (parts, 0..) |p, i| {
        if (i > 0) {
            if (n >= buf.len) return null;
            buf[n] = '/';
            n += 1;
        }
        if (n + p.len > buf.len) return null;
        @memcpy(buf[n..][0..p.len], p);
        n += p.len;
    }
    return buf[0..n];
}

/// On-disk path of a key: a trailing '/' is stored as the directory-object suffix.
fn diskKey(buf: []u8, key: []const u8) ?[]const u8 {
    if (key.len == 0 or key[0] == '/') return null;
    var it = std.mem.splitScalar(u8, key, '/');
    while (it.next()) |c| if (std.mem.eql(u8, c, "..") or std.mem.eql(u8, c, ".")) return null;
    const is_dir = std.mem.endsWith(u8, key, "/");
    const base = if (is_dir) key[0 .. key.len - 1] else key;
    const suffix = if (is_dir) dir_suffix else "";
    if (base.len + suffix.len > buf.len) return null;
    @memcpy(buf[0..base.len], base);
    @memcpy(buf[base.len..][0..suffix.len], suffix);
    return buf[0 .. base.len + suffix.len];
}

fn objectKey(buf: []u8, rel: []const u8) ?[]const u8 {
    if (std.mem.endsWith(u8, rel, dir_suffix)) {
        const base = rel[0 .. rel.len - dir_suffix.len];
        if (base.len + 1 > buf.len) return null;
        @memcpy(buf[0..base.len], base);
        buf[base.len] = '/';
        return buf[0 .. base.len + 1];
    }
    if (rel.len > buf.len) return null;
    @memcpy(buf[0..rel.len], rel);
    return buf[0..rel.len];
}

/// Streams one version's bytes: part by part, block by block, verifying each
/// shard chunk's checksum and rebuilding missing data shards.
pub const ObjectReader = struct {
    interface: std.Io.Reader,
    src: *Source,
    obj: *const Object,
    m: *const Merged,
    codec: rs.Codec,
    part: usize = 0,
    part_left: u64 = 0,
    part_open: bool = false,
    files: [rs.max_shards]?std.fs.File = @splat(null),
    inline_pos: [rs.max_shards]usize = @splat(0),
    alive: [rs.max_shards]bool = @splat(false),
    shard_mem: []u8,
    rebuild_mem: []u8,
    block: []u8,
    pos: usize = 0,
    len: usize = 0,
    err: ?Error = null,
    gpa: std.mem.Allocator,

    pub fn init(src: *Source, gpa: std.mem.Allocator, obj: *const Object, m: *const Merged, buffer: []u8) Error!ObjectReader {
        const v = m.v;
        if (v.ec_m == 0) return error.Corrupt;
        const codec = rs.Codec.init(v.ec_m, v.ec_n) catch return error.Corrupt;
        if (v.ec_block_size == 0 and v.size > 0) return error.Corrupt;
        const shard_size = std.math.divCeil(u64, v.ec_block_size, v.ec_m) catch return error.Corrupt;
        const total: usize = @as(usize, v.ec_m) + v.ec_n;
        const shard_mem = try gpa.alloc(u8, total * shard_size);
        errdefer gpa.free(shard_mem);
        const rebuild_mem = try gpa.alloc(u8, @as(usize, v.ec_m) * shard_size);
        errdefer gpa.free(rebuild_mem);
        const block = try gpa.alloc(u8, @as(usize, v.ec_m) * shard_size);
        return .{
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .src = src,
            .obj = obj,
            .m = m,
            .codec = codec,
            .shard_mem = shard_mem,
            .rebuild_mem = rebuild_mem,
            .block = block,
            .gpa = gpa,
        };
    }

    pub fn deinit(r: *ObjectReader) void {
        r.closeFiles();
        r.gpa.free(r.shard_mem);
        r.gpa.free(r.rebuild_mem);
        r.gpa.free(r.block);
    }

    fn closeFiles(r: *ObjectReader) void {
        for (&r.files) |*f| if (f.*) |x| {
            x.close();
            f.* = null;
        };
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const r: *ObjectReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (r.pos == r.len) {
            r.nextBlock() catch |e| {
                r.err = e;
                return error.ReadFailed;
            };
            if (r.len == 0) return error.EndOfStream;
        }
        const n = limit.minInt(r.len - r.pos);
        try w.writeAll(r.block[r.pos..][0..n]);
        r.pos += n;
        return n;
    }

    fn openPart(r: *ObjectReader) Error!void {
        const v = r.m.v;
        const part = v.parts[r.part];
        r.part_left = part.size;
        r.part_open = true;
        r.closeFiles();
        const set = r.src.sets[r.obj.set];
        var dd_buf: [36]u8 = undefined;
        const dd = xlmeta.formatUuid(v.data_dir, &dd_buf);
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "part.{d}", .{part.number}) catch return error.Corrupt;
        var pbuf: [max_path]u8 = undefined;
        const p = joinPath(&pbuf, &.{ r.obj.bucket, r.obj.disk_key, dd, name }) orelse return error.Corrupt;
        const total = @as(usize, v.ec_m) + v.ec_n;
        for (0..total) |i| {
            r.alive[i] = false;
            r.inline_pos[i] = 0;
            const sh = r.m.shards[i] orelse continue;
            if (sh.inline_data != null) {
                r.alive[i] = true;
                continue;
            }
            if (v.isInline()) continue;
            const d = set[sh.drive] orelse continue;
            r.files[i] = d.dir.openFile(p, .{}) catch continue;
            r.alive[i] = true;
        }
    }

    /// Reads exactly `out.len` bytes of shard `i`; false when the drive came up short.
    fn readShard(r: *ObjectReader, i: usize, out: []u8) bool {
        if (r.m.shards[i].?.inline_data) |d| {
            if (r.inline_pos[i] + out.len > d.len) return false;
            @memcpy(out, d[r.inline_pos[i]..][0..out.len]);
            r.inline_pos[i] += out.len;
            return true;
        }
        const f = r.files[i] orelse return false;
        const n = f.readAll(out) catch return false;
        return n == out.len;
    }

    fn nextBlock(r: *ObjectReader) Error!void {
        const v = r.m.v;
        r.pos = 0;
        r.len = 0;
        while (!r.part_open or r.part_left == 0) {
            if (r.part_open) r.part += 1;
            r.part_open = false;
            if (r.part >= v.parts.len) return;
            try r.openPart();
        }
        const k: usize = v.ec_m;
        const total = k + v.ec_n;
        const block_len: usize = @intCast(@min(v.ec_block_size, r.part_left));
        const chunk = std.math.divCeil(usize, block_len, k) catch unreachable;
        var shards: [rs.max_shards]?[]u8 = @splat(null);
        var have: usize = 0;
        for (0..total) |i| {
            if (!r.alive[i]) continue;
            var sum: [32]u8 = undefined;
            const buf = r.shard_mem[i * chunk ..][0..chunk];
            if (!r.readShard(i, &sum) or !r.readShard(i, buf)) {
                r.alive[i] = false;
                continue;
            }
            const got = highway.hash256(&highway.bitrot_key, buf);
            if (!std.mem.eql(u8, &got, &sum)) {
                r.src.stats.bitrot_failures += 1;
                std.log.warn("{s}/{s}: bitrot in shard {d}, rebuilding from parity", .{ r.obj.bucket, r.obj.key, i });
                continue;
            }
            shards[i] = buf;
            have += 1;
        }
        if (have < k) return error.TooManyMissing;
        var rebuilt = false;
        for (shards[0..k]) |s| if (s == null) {
            rebuilt = true;
        };
        if (rebuilt) {
            var bufs: [rs.max_shards][]u8 = undefined;
            for (0..k) |i| bufs[i] = r.rebuild_mem[i * chunk ..][0..chunk];
            r.codec.reconstructData(shards[0..total], bufs[0..k]) catch return error.TooManyMissing;
            r.src.stats.shards_rebuilt += 1;
        }
        for (0..k) |i| @memcpy(r.block[i * chunk ..][0..chunk], shards[i].?);
        r.len = block_len;
        r.part_left -= block_len;
    }
};

test "pools merge into sets; hostile metadata is skipped" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ids = [_][]const u8{ "a1", "a2", "b1", "b2" };
    for (ids, 0..) |id, i| {
        var buf: [256]u8 = undefined;
        const pool = if (i < 2) "[[\"a1\",\"a2\"]]" else "[[\"b1\",\"b2\"]]";
        const doc = try std.fmt.bufPrint(&buf, "{{\"id\":\"dep\",\"xl\":{{\"this\":\"{s}\",\"sets\":{s}}}}}", .{ id, pool });
        var d = try tmp.dir.makeOpenPath(id, .{});
        defer d.close();
        try d.makePath(meta_bucket);
        try d.writeFile(.{ .sub_path = meta_bucket ++ "/format.json", .data = doc });
        try d.makePath("bkt/obj");
        try d.writeFile(.{ .sub_path = "bkt/obj/xl.meta", .data = "XL2 \x01\x00\x03\x00\xc6\xff\xff\xff\xff" });
    }
    var paths: [4][]const u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (ids, &paths) |id, *p| p.* = try tmp.dir.realpathAlloc(a, id);
    var src = try Source.open(std.testing.allocator, a, &paths);
    defer src.deinit();
    try std.testing.expectEqual(@as(usize, 2), src.sets.len);
    try std.testing.expectEqual(@as(u64, 0), src.stats.missing_drives);
    const Ctx = struct { n: usize = 0 };
    var ctx: Ctx = .{};
    try src.walk("bkt", "", Error, &ctx, struct {
        fn f(c: *Ctx, _: usize, key: []const u8) Error!void {
            if (std.mem.eql(u8, key, "obj")) c.n += 1;
        }
    }.f);
    try std.testing.expectEqual(@as(usize, 2), ctx.n);
    try std.testing.expectError(error.NotFound, src.loadObject(a, 0, "bkt", "obj"));
    var kb: [64]u8 = undefined;
    try std.testing.expect(diskKey(&kb, "a/../b") == null);
    try std.testing.expectEqualStrings("d" ++ dir_suffix, diskKey(&kb, "d/").?);
}
