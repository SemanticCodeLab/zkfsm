//! Drive discovery (sysfs scan, filesystem signature check), statfs, and the
//! persistent volume -> drive allocation state.
const std = @import("std");
const mount = @import("mount.zig");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const label = "ZKFSM-CSI";
pub const head_size = 64 << 10;
pub const default_min_size: u64 = 512 << 20;

/// Simple glob: `*` matches any run, `?` one byte.
pub fn globMatch(pattern: []const u8, s: []const u8) bool {
    if (pattern.len == 0) return s.len == 0;
    if (pattern[0] == '*') {
        var i: usize = 0;
        while (i <= s.len) : (i += 1) if (globMatch(pattern[1..], s[i..])) return true;
        return false;
    }
    if (s.len == 0) return false;
    if (pattern[0] != '?' and pattern[0] != s[0]) return false;
    return globMatch(pattern[1..], s[1..]);
}

pub fn anyGlob(globs: []const []const u8, s: []const u8) bool {
    for (globs) |g| if (globMatch(g, s)) return true;
    return false;
}

pub const ScanOptions = struct {
    sysfs: []const u8 = "/sys",
    dev_root: []const u8 = "/dev",
    mountinfo: []const u8 = "/proc/self/mountinfo",
    globs: []const []const u8 = &.{},
    min_size: u64 = default_min_size,
    /// devices mounted only below this prefix are ours and stay eligible
    own_prefix: []const u8 = "",
};

pub const Candidate = struct { name: []const u8, dev_path: []const u8, size: u64 };

const skip_prefixes = [_][]const u8{ "loop", "ram", "dm-", "zram", "sr", "md", "nbd" };

fn readTrim(arena: Allocator, dir: std.fs.Dir, path: []const u8) ?[]const u8 {
    const data = dir.readFileAlloc(arena, path, 4096) catch return null;
    return std.mem.trim(u8, data, " \t\r\n");
}

fn isTrue(v: ?[]const u8) bool {
    return v != null and std.mem.eql(u8, v.?, "1");
}

/// Lists whole block devices eligible to become drives; reasons for skips are logged.
pub fn scanBlock(arena: Allocator, opts: ScanOptions) ![]Candidate {
    const block_path = try std.fs.path.join(arena, &.{ opts.sysfs, "block" });
    var block = std.fs.cwd().openDir(block_path, .{ .iterate = true }) catch |e| {
        std.log.warn("cannot open {s}: {s}", .{ block_path, @errorName(e) });
        return &.{};
    };
    defer block.close();
    const mounts = std.fs.cwd().readFileAlloc(arena, opts.mountinfo, 16 << 20) catch "";

    var out: std.ArrayList(Candidate) = .empty;
    var it = block.iterate();
    while (try it.next()) |entry| {
        const name = try arena.dupe(u8, entry.name);
        const dev_path = try std.fs.path.join(arena, &.{ opts.dev_root, name });
        const globbed = anyGlob(opts.globs, dev_path);
        if (!globbed) {
            var skip = false;
            for (skip_prefixes) |p| skip = skip or std.mem.startsWith(u8, name, p);
            if (skip) continue;
        }
        var dev = block.openDir(name, .{ .iterate = true }) catch continue;
        defer dev.close();
        if (isTrue(readTrim(arena, dev, "removable"))) {
            std.log.info("skip {s}: removable", .{name});
            continue;
        }
        if (isTrue(readTrim(arena, dev, "ro"))) {
            std.log.info("skip {s}: read-only", .{name});
            continue;
        }
        const sectors = std.fmt.parseInt(u64, readTrim(arena, dev, "size") orelse "0", 10) catch 0;
        const size = sectors * 512;
        if (size < opts.min_size) {
            if (globbed or size > 0) std.log.info("skip {s}: size {d} below minimum", .{ name, size });
            continue;
        }
        if (try hasPartitions(arena, dev, name)) {
            std.log.info("skip {s}: partitioned", .{name});
            continue;
        }
        if (try dirNonEmpty(dev, "holders")) {
            std.log.info("skip {s}: has holders", .{name});
            continue;
        }
        if (mountedElsewhere(mounts, dev_path, opts.own_prefix)) {
            std.log.info("skip {s}: mounted", .{name});
            continue;
        }
        try out.append(arena, .{ .name = name, .dev_path = dev_path, .size = size });
    }
    std.mem.sort(Candidate, out.items, {}, struct {
        fn lt(_: void, a: Candidate, b: Candidate) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    return out.items;
}

fn hasPartitions(arena: Allocator, dev: std.fs.Dir, name: []const u8) !bool {
    var it = dev.iterate();
    while (try it.next()) |e| {
        if (!std.mem.startsWith(u8, e.name, name)) continue;
        const p = try std.fs.path.join(arena, &.{ e.name, "partition" });
        dev.access(p, .{}) catch continue;
        return true;
    }
    return false;
}

fn dirNonEmpty(dev: std.fs.Dir, sub: []const u8) !bool {
    var d = dev.openDir(sub, .{ .iterate = true }) catch return false;
    defer d.close();
    var it = d.iterate();
    return (try it.next()) != null;
}

fn mountedElsewhere(mounts: []const u8, dev_path: []const u8, own_prefix: []const u8) bool {
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        const mi = mount.parseMountinfo(line) orelse continue;
        if (!std.mem.eql(u8, mi.source, dev_path)) continue;
        if (own_prefix.len > 0 and std.mem.startsWith(u8, mi.mount_point, own_prefix)) continue;
        return true;
    }
    return false;
}

pub const FsKind = enum { blank, ours_xfs, ours_ext4, foreign };

pub const Classified = struct { kind: FsKind, uuid: [16]u8 = @splat(0) };

fn labelIs(field: []const u8) bool {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    return std.mem.eql(u8, field[0..end], label);
}

/// Looks at the first 64 KiB: blank, one of our filesystems, or anything else.
pub fn classify(head: []const u8) Classified {
    if (std.mem.allEqual(u8, head, 0)) return .{ .kind = .blank };
    // XFS superblock: magic "XFSB" @0, uuid @32, label sb_fname[12] @108
    if (head.len >= 120 and std.mem.eql(u8, head[0..4], "XFSB")) {
        if (!labelIs(head[108..120])) return .{ .kind = .foreign };
        return .{ .kind = .ours_xfs, .uuid = head[32..48].* };
    }
    // ext4 superblock @1024: magic 0xEF53 @+56, uuid @+104, volume name @+120
    if (head.len >= 1024 + 136 and std.mem.readInt(u16, head[1024 + 56 ..][0..2], .little) == 0xEF53) {
        if (!labelIs(head[1024 + 120 .. 1024 + 136])) return .{ .kind = .foreign };
        return .{ .kind = .ours_ext4, .uuid = head[1024 + 104 ..][0..16].* };
    }
    return .{ .kind = .foreign };
}

pub fn readHead(path: []const u8, buf: *[head_size]u8) ![]const u8 {
    var f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    const n = try f.readAll(buf);
    return buf[0..n];
}

pub const FsStat = struct { total: u64, available: u64, used: u64, inodes: u64, inodes_free: u64 };

/// Kernel `struct statfs` on 64-bit Linux (x86_64, aarch64).
const KStatfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};

pub fn statfs(path: []const u8) !FsStat {
    var buf: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    var st: KStatfs = undefined;
    const rc = linux.syscall2(.statfs, @intFromPtr(&buf), @intFromPtr(&st));
    if (std.posix.errno(rc) != .SUCCESS) return error.StatfsFailed;
    const bs: u64 = @intCast(if (st.frsize > 0) st.frsize else st.bsize);
    return .{
        .total = st.blocks * bs,
        .available = st.bavail * bs,
        .used = (st.blocks - st.bfree) * bs,
        .inodes = st.files,
        .inodes_free = st.ffree,
    };
}

pub const Drive = struct {
    id: []const u8,
    /// directory where the drive's filesystem is mounted
    path: []const u8,
    size: u64,
    dev: []const u8 = "",
};

pub const VolumeRec = struct {
    name: []const u8,
    drive: []const u8,
    capacity: u64,
};

/// state.json: {"volumes":[{"name":..,"drive":..,"capacity":..}]}
pub const Store = struct {
    gpa: Allocator,
    path: []const u8,
    arena: std.heap.ArenaAllocator,
    volumes: std.ArrayList(VolumeRec) = .empty,

    const Json = struct { volumes: []const VolumeRec = &.{} };

    pub fn load(gpa: Allocator, path: []const u8) !Store {
        var s: Store = .{ .gpa = gpa, .path = path, .arena = std.heap.ArenaAllocator.init(gpa) };
        errdefer s.deinit();
        const data = std.fs.cwd().readFileAlloc(gpa, path, 64 << 20) catch |e| switch (e) {
            error.FileNotFound => return s,
            else => return e,
        };
        defer gpa.free(data);
        const a = s.arena.allocator();
        const parsed = try std.json.parseFromSliceLeaky(Json, a, data, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        try s.volumes.appendSlice(gpa, parsed.volumes);
        return s;
    }

    pub fn deinit(self: *Store) void {
        self.volumes.deinit(self.gpa);
        self.arena.deinit();
    }

    /// Atomic replace: write a temp file, fsync, rename.
    pub fn save(self: *Store) !void {
        const json = try std.json.Stringify.valueAlloc(self.gpa, Json{ .volumes = self.volumes.items }, .{ .whitespace = .indent_2 });
        defer self.gpa.free(json);
        const tmp = try std.fmt.allocPrint(self.gpa, "{s}.tmp", .{self.path});
        defer self.gpa.free(tmp);
        {
            var f = try std.fs.cwd().createFile(tmp, .{ .truncate = true });
            defer f.close();
            try f.writeAll(json);
            try f.sync();
        }
        try std.fs.cwd().rename(tmp, self.path);
    }

    pub fn find(self: *Store, name: []const u8) ?*VolumeRec {
        for (self.volumes.items) |*v| if (std.mem.eql(u8, v.name, name)) return v;
        return null;
    }

    pub fn add(self: *Store, name: []const u8, drive: []const u8, capacity: u64) !void {
        const a = self.arena.allocator();
        try self.volumes.append(self.gpa, .{ .name = try a.dupe(u8, name), .drive = try a.dupe(u8, drive), .capacity = capacity });
    }

    pub fn remove(self: *Store, name: []const u8) bool {
        for (self.volumes.items, 0..) |v, i| if (std.mem.eql(u8, v.name, name)) {
            _ = self.volumes.orderedRemove(i);
            return true;
        };
        return false;
    }

    pub fn allocated(self: *const Store, drive: []const u8) u64 {
        var sum: u64 = 0;
        for (self.volumes.items) |v| if (std.mem.eql(u8, v.drive, drive)) {
            sum += v.capacity;
        };
        return sum;
    }
};

/// Index of the drive with the most unallocated bytes that still fits `need`.
pub fn pick(drives: []const Drive, store: *const Store, need: u64) ?usize {
    var best: ?usize = null;
    var best_free: u64 = 0;
    for (drives, 0..) |d, i| {
        const used = store.allocated(d.id);
        const free = if (d.size > used) d.size - used else 0;
        if (free < need) continue;
        if (best == null or free > best_free) {
            best = i;
            best_free = free;
        }
    }
    return best;
}

const testing = std.testing;

test "glob" {
    try testing.expect(globMatch("/dev/loop*", "/dev/loop12"));
    try testing.expect(globMatch("/dev/sd?", "/dev/sdb"));
    try testing.expect(!globMatch("/dev/sd?", "/dev/sdb1"));
    try testing.expect(!globMatch("/dev/loop*", "/dev/nvme0n1"));
    try testing.expect(anyGlob(&.{ "/dev/nvme*", "/dev/vd*" }, "/dev/vdc"));
}

test "classify signatures" {
    var head: [head_size]u8 = @splat(0);
    try testing.expectEqual(FsKind.blank, classify(&head).kind);
    @memcpy(head[0..4], "XFSB");
    try testing.expectEqual(FsKind.foreign, classify(&head).kind);
    @memcpy(head[108 .. 108 + label.len], label);
    head[32] = 0xab;
    const c = classify(&head);
    try testing.expectEqual(FsKind.ours_xfs, c.kind);
    try testing.expectEqual(@as(u8, 0xab), c.uuid[0]);

    head = @splat(0);
    std.mem.writeInt(u16, head[1024 + 56 ..][0..2], 0xEF53, .little);
    try testing.expectEqual(FsKind.foreign, classify(&head).kind);
    @memcpy(head[1024 + 120 ..][0..label.len], label);
    try testing.expectEqual(FsKind.ours_ext4, classify(&head).kind);

    head = @splat(0);
    head[510] = 0x55; // MBR boot signature without partitions: not ours
    try testing.expectEqual(FsKind.foreign, classify(&head).kind);
}

fn fakeDev(root: std.fs.Dir, name: []const u8, size_sectors: []const u8, extra: []const []const u8) !void {
    var buf: [256]u8 = undefined;
    const base = try std.fmt.bufPrint(&buf, "sys/block/{s}", .{name});
    try root.makePath(base);
    var d = try root.openDir(base, .{});
    defer d.close();
    try d.writeFile(.{ .sub_path = "size", .data = size_sectors });
    try d.writeFile(.{ .sub_path = "removable", .data = "0\n" });
    try d.writeFile(.{ .sub_path = "ro", .data = "0\n" });
    try d.makePath("holders");
    for (extra) |e| {
        if (std.mem.indexOfScalar(u8, e, '=')) |eq| {
            try d.writeFile(.{ .sub_path = e[0..eq], .data = e[eq + 1 ..] });
        } else try d.makePath(e);
    }
}

test "scan fake sysfs" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const big = "4194304\n"; // 2 GiB
    try fakeDev(tmp.dir, "sdb", big, &.{});
    try fakeDev(tmp.dir, "sdc", big, &.{"removable=1"});
    try fakeDev(tmp.dir, "sdd", big, &.{"ro=1"});
    try fakeDev(tmp.dir, "sde", "1024\n", &.{});
    try fakeDev(tmp.dir, "sda", big, &.{ "sda1", "sda1/partition=1" });
    try fakeDev(tmp.dir, "sdf", big, &.{"holders/dm-0"});
    try fakeDev(tmp.dir, "sdg", big, &.{});
    try fakeDev(tmp.dir, "sdh", big, &.{});
    try fakeDev(tmp.dir, "loop0", big, &.{});
    try fakeDev(tmp.dir, "loop1", big, &.{});
    try fakeDev(tmp.dir, "dm-0", big, &.{});
    try tmp.dir.writeFile(.{ .sub_path = "mountinfo", .data = 
        \\22 1 8:96 / /data rw - ext4 /dev/sdg rw
        \\23 1 8:112 / /state/drives/abc rw - xfs /dev/sdh rw
        \\
    });
    const root = try tmp.dir.realpathAlloc(arena, ".");
    const opts: ScanOptions = .{
        .sysfs = try std.fs.path.join(arena, &.{ root, "sys" }),
        .mountinfo = try std.fs.path.join(arena, &.{ root, "mountinfo" }),
        .globs = &.{"/dev/loop1"},
        .own_prefix = "/state/drives/",
    };
    const got = try scanBlock(arena, opts);
    var names: std.ArrayList(u8) = .empty;
    for (got) |c| try names.print(arena, "{s} ", .{c.name});
    try testing.expectEqualStrings("loop1 sdb sdh ", names.items);
    try testing.expectEqual(@as(u64, 2 << 30), got[0].size);
    try testing.expectEqualStrings("/dev/loop1", got[0].dev_path);
}

test "state store allocation and persistence" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const path = try std.fs.path.join(testing.allocator, &.{ root, "state.json" });
    defer testing.allocator.free(path);
    const drives = [_]Drive{
        .{ .id = "a", .path = "/a", .size = 100 },
        .{ .id = "b", .path = "/b", .size = 80 },
    };
    {
        var s = try Store.load(testing.allocator, path);
        defer s.deinit();
        try testing.expectEqual(@as(?usize, 0), pick(&drives, &s, 10));
        try s.add("v1", "a", 50); // a: 50 free, b: 80 free
        try testing.expectEqual(@as(?usize, 1), pick(&drives, &s, 10));
        try testing.expectEqual(@as(?usize, null), pick(&drives, &s, 81));
        try s.add("v2", "b", 70); // a: 50, b: 10
        try testing.expectEqual(@as(?usize, 0), pick(&drives, &s, 20));
        try s.save();
    }
    var s = try Store.load(testing.allocator, path);
    defer s.deinit();
    try testing.expectEqual(@as(usize, 2), s.volumes.items.len);
    try testing.expectEqual(@as(u64, 70), s.allocated("b"));
    try testing.expectEqualStrings("a", s.find("v1").?.drive);
    try testing.expect(s.remove("v1"));
    try testing.expect(!s.remove("v1"));
    try testing.expectEqual(@as(u64, 0), s.allocated("a"));
}

test "statfs on tmp" {
    const st = try statfs("/");
    try testing.expect(st.total > 0 and st.total >= st.used);
}
