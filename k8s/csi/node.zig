//! Node plugin: owns local drives, allocates volumes onto them, bind-mounts
//! volume directories into pod target paths.
const std = @import("std");
const csi = @import("csi.zig");
const drives = @import("drives.zig");
const mount = @import("mount.zig");
const Allocator = std.mem.Allocator;
const Code = csi.Code;

pub const Config = struct {
    node_id: []const u8,
    state_dir: []const u8,
    /// test mode: each subdirectory is an already-mounted drive
    drive_dir: ?[]const u8 = null,
    scan: drives.ScanOptions = .{},
    mounter: mount.Mounter = .{},
    mkfs: bool = true,
};

pub const Status = struct {
    code: u32 = 0,
    msg: []const u8 = "",

    pub fn err(arena: Allocator, code: u32, comptime fmt: []const u8, args: anytype) Status {
        return .{ .code = code, .msg = std.fmt.allocPrint(arena, fmt, args) catch "out of memory" };
    }
};

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 200) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| if (c == '/' or c == 0) return false;
    return true;
}

/// volume_id is "<node>/<name>"; returns the name when it belongs to `node_id`.
pub fn parseVolumeId(node_id: []const u8, volume_id: []const u8) ?[]const u8 {
    const slash = std.mem.indexOfScalar(u8, volume_id, '/') orelse return null;
    if (!std.mem.eql(u8, volume_id[0..slash], node_id)) return null;
    const name = volume_id[slash + 1 ..];
    return if (validName(name)) name else null;
}

pub const Node = struct {
    gpa: Allocator,
    cfg: Config,
    mutex: std.Thread.Mutex = .{},
    store: drives.Store,
    drives_arena: std.heap.ArenaAllocator,
    drives: []const drives.Drive = &.{},
    drives_root: []const u8,

    pub fn init(gpa: Allocator, cfg: Config) !*Node {
        try std.fs.cwd().makePath(cfg.state_dir);
        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);
        const drives_root = try std.fs.path.join(gpa, &.{ cfg.state_dir, "drives" });
        errdefer gpa.free(drives_root);
        try std.fs.cwd().makePath(drives_root);
        const state_path = try std.fs.path.join(gpa, &.{ cfg.state_dir, "state.json" });
        errdefer gpa.free(state_path);
        self.* = .{
            .gpa = gpa,
            .cfg = cfg,
            .store = try drives.Store.load(gpa, state_path),
            .drives_arena = std.heap.ArenaAllocator.init(gpa),
            .drives_root = drives_root,
        };
        return self;
    }

    pub fn deinit(self: *Node) void {
        const gpa = self.gpa;
        gpa.free(self.store.path);
        self.store.deinit();
        self.drives_arena.deinit();
        gpa.free(self.drives_root);
        gpa.destroy(self);
    }

    /// Cross-process lock on state.json (`node --gc` runs beside the server);
    /// the store is reloaded so the other process's edits are not overwritten.
    fn lockState(self: *Node) !std.fs.File {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const lock_path = try std.fmt.bufPrint(&buf, "{s}.lock", .{self.store.path});
        const f = try std.fs.cwd().createFile(lock_path, .{ .truncate = false, .lock = .exclusive });
        errdefer f.close();
        const fresh = try drives.Store.load(self.gpa, self.store.path);
        self.store.deinit();
        self.store = fresh;
        return f;
    }

    pub fn refresh(self: *Node) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.refreshLocked();
    }

    fn refreshLocked(self: *Node) !void {
        _ = self.drives_arena.reset(.retain_capacity);
        const arena = self.drives_arena.allocator();
        var list: std.ArrayList(drives.Drive) = .empty;
        if (self.cfg.drive_dir) |dir| {
            try self.scanDirs(arena, dir, &list);
        } else {
            var opts = self.cfg.scan;
            opts.own_prefix = try std.fmt.allocPrint(arena, "{s}/", .{self.drives_root});
            for (try drives.scanBlock(arena, opts)) |c| {
                if (self.prepare(arena, c)) |d| {
                    if (d) |drive| try list.append(arena, drive);
                } else |e| std.log.warn("drive {s}: {s}", .{ c.dev_path, @errorName(e) });
            }
        }
        self.drives = list.items;
        for (self.drives) |d| std.log.info("drive {s} at {s}: {d} bytes, {d} allocated", .{ d.id, d.path, d.size, self.store.allocated(d.id) });
    }

    fn scanDirs(self: *Node, arena: Allocator, dir: []const u8, list: *std.ArrayList(drives.Drive)) !void {
        _ = self;
        var d = try std.fs.cwd().openDir(dir, .{ .iterate = true });
        defer d.close();
        var it = d.iterate();
        while (try it.next()) |e| {
            if (e.kind != .directory) continue;
            const path = try std.fs.path.join(arena, &.{ dir, e.name });
            const st = drives.statfs(path) catch continue;
            try list.append(arena, .{ .id = try arena.dupe(u8, e.name), .path = path, .size = st.total });
        }
        std.mem.sort(drives.Drive, list.items, {}, struct {
            fn lt(_: void, a: drives.Drive, b: drives.Drive) bool {
                return std.mem.lessThan(u8, a.id, b.id);
            }
        }.lt);
    }

    /// Formats a blank device (never a foreign one), then mounts it under drives/<uuid>.
    fn prepare(self: *Node, arena: Allocator, c: drives.Candidate) !?drives.Drive {
        var buf: [drives.head_size]u8 = undefined;
        var cls = drives.classify(try drives.readHead(c.dev_path, &buf));
        if (cls.kind == .foreign) {
            std.log.info("skip {s}: carries a filesystem or data not labeled {s}", .{ c.dev_path, drives.label });
            return null;
        }
        if (cls.kind == .blank) {
            if (!self.cfg.mkfs) return null;
            try mkfs(arena, c.dev_path);
            cls = drives.classify(try drives.readHead(c.dev_path, &buf));
            if (cls.kind != .ours_xfs and cls.kind != .ours_ext4) return error.FormatNotRecognized;
        }
        const hex = std.fmt.bytesToHex(cls.uuid, .lower);
        const id = try arena.dupe(u8, &hex);
        const mp = try std.fs.path.join(arena, &.{ self.drives_root, id });
        try std.fs.cwd().makePath(mp);
        if (!try self.cfg.mounter.isMounted(arena, mp)) {
            try self.cfg.mounter.mountDev(c.dev_path, mp, if (cls.kind == .ours_xfs) "xfs" else "ext4");
        }
        const st = try drives.statfs(mp);
        return .{ .id = id, .path = mp, .size = st.total, .dev = c.dev_path };
    }

    fn findDrive(self: *Node, id: []const u8) ?drives.Drive {
        for (self.drives) |d| if (std.mem.eql(u8, d.id, id)) return d;
        return null;
    }

    pub fn publish(self: *Node, arena: Allocator, q: csi.NodePublishRequest) Status {
        if (q.volume_id.len == 0) return .{ .code = Code.invalid_argument, .msg = "volume_id is required" };
        if (q.target_path.len == 0) return .{ .code = Code.invalid_argument, .msg = "target_path is required" };
        const cap = q.cap orelse return .{ .code = Code.invalid_argument, .msg = "volume_capability is required" };
        if (!cap.supported()) return .{ .code = Code.invalid_argument, .msg = "only single-node filesystem volumes are supported" };
        const name = parseVolumeId(self.cfg.node_id, q.volume_id) orelse
            return Status.err(arena, Code.not_found, "volume {s} does not belong to node {s}", .{ q.volume_id, self.cfg.node_id });
        const ro = q.readonly or cap.readOnly();

        self.mutex.lock();
        defer self.mutex.unlock();
        const mounted = self.cfg.mounter.isMounted(arena, q.target_path) catch |e|
            return Status.err(arena, Code.internal, "mountinfo: {s}", .{@errorName(e)});
        if (mounted) return .{};

        const lock = self.lockState() catch |e| return Status.err(arena, Code.internal, "lock state: {s}", .{@errorName(e)});
        defer lock.close();
        const rec = self.store.find(name) orelse blk: {
            const need = std.fmt.parseInt(u64, csi.get(q.context, "capacity") orelse "0", 10) catch
                return .{ .code = Code.invalid_argument, .msg = "volume_context capacity is not a number" };
            var idx = drives.pick(self.drives, &self.store, need);
            if (idx == null) {
                self.refreshLocked() catch |e| std.log.warn("refresh: {s}", .{@errorName(e)});
                idx = drives.pick(self.drives, &self.store, need);
            }
            const i = idx orelse return Status.err(arena, Code.resource_exhausted, "no drive on {s} has {d} free bytes", .{ self.cfg.node_id, need });
            self.store.add(name, self.drives[i].id, need) catch return .{ .code = Code.internal, .msg = "out of memory" };
            self.store.save() catch |e| {
                _ = self.store.remove(name);
                return Status.err(arena, Code.internal, "save state: {s}", .{@errorName(e)});
            };
            std.log.info("allocated {s} ({d} bytes) on drive {s}", .{ name, need, self.drives[i].id });
            break :blk self.store.find(name).?;
        };
        const drive = self.findDrive(rec.drive) orelse
            return Status.err(arena, Code.failed_precondition, "drive {s} holding {s} is not available", .{ rec.drive, name });
        const src = std.fs.path.join(arena, &.{ drive.path, "volumes", name }) catch return .{ .code = Code.internal, .msg = "oom" };
        std.fs.cwd().makePath(src) catch |e| return Status.err(arena, Code.internal, "mkdir {s}: {s}", .{ src, @errorName(e) });
        std.fs.cwd().makePath(q.target_path) catch |e| return Status.err(arena, Code.internal, "mkdir {s}: {s}", .{ q.target_path, @errorName(e) });
        self.cfg.mounter.bind(src, q.target_path, ro) catch |e|
            return Status.err(arena, Code.internal, "bind {s} -> {s}: {s}", .{ src, q.target_path, @errorName(e) });
        std.log.info("published {s} at {s} (ro={})", .{ name, q.target_path, ro });
        return .{};
    }

    pub fn unpublish(self: *Node, arena: Allocator, q: csi.IdPath) Status {
        if (q.volume_id.len == 0) return .{ .code = Code.invalid_argument, .msg = "volume_id is required" };
        if (q.path.len == 0) return .{ .code = Code.invalid_argument, .msg = "target_path is required" };
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cfg.mounter.umount(q.path) catch |e| return Status.err(arena, Code.internal, "umount {s}: {s}", .{ q.path, @errorName(e) });
        std.fs.cwd().deleteDir(q.path) catch |e| switch (e) {
            error.FileNotFound => {},
            else => std.log.warn("rmdir {s}: {s}", .{ q.path, @errorName(e) }),
        };
        std.log.info("unpublished {s} from {s}", .{ q.volume_id, q.path });
        return .{};
    }

    pub fn stats(self: *Node, arena: Allocator, q: csi.IdPath) struct { Status, []const csi.Usage } {
        _ = self;
        if (q.volume_id.len == 0 or q.path.len == 0) return .{ .{ .code = Code.invalid_argument, .msg = "volume_id and volume_path are required" }, &.{} };
        const st = drives.statfs(q.path) catch
            return .{ Status.err(arena, Code.not_found, "volume path {s} not found", .{q.path}), &.{} };
        const out = arena.dupe(csi.Usage, &.{
            .{ .available = st.available, .total = st.total, .used = st.used, .unit = 1 },
            .{ .available = st.inodes_free, .total = st.inodes, .used = st.inodes - st.inodes_free, .unit = 2 },
        }) catch return .{ .{ .code = Code.internal, .msg = "oom" }, &.{} };
        return .{ .{}, out };
    }

    /// Deletes a retained volume's data and frees its allocation (`node --gc`).
    pub fn gcVolume(self: *Node, arena: Allocator, name: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const lock = try self.lockState();
        defer lock.close();
        const rec = self.store.find(name) orelse return error.VolumeNotFound;
        const suffix = try std.fmt.allocPrint(arena, "/volumes/{s}", .{name});
        if (try self.cfg.mounter.sourceInUse(arena, suffix)) return error.VolumePublished;
        if (self.findDrive(rec.drive)) |d| {
            const dir = try std.fs.path.join(arena, &.{ d.path, "volumes", name });
            try std.fs.cwd().deleteTree(dir);
        } else std.log.warn("drive {s} not present; dropping allocation only", .{rec.drive});
        _ = self.store.remove(name);
        try self.store.save();
    }
};

fn mkfs(arena: Allocator, dev: []const u8) !void {
    const attempts = [_][]const []const u8{
        &.{ "mkfs.xfs", "-f", "-L", drives.label, dev },
        &.{ "mkfs.ext4", "-F", "-L", drives.label, dev },
    };
    for (attempts) |argv| {
        std.log.info("formatting {s} with {s}", .{ dev, argv[0] });
        const r = std.process.Child.run(.{ .allocator = arena, .argv = argv }) catch |e| {
            std.log.warn("{s}: {s}", .{ argv[0], @errorName(e) });
            continue;
        };
        if (r.term == .Exited and r.term.Exited == 0) return;
        std.log.warn("{s} failed: {s}", .{ argv[0], r.stderr });
    }
    return error.MkfsFailed;
}

const testing = std.testing;

pub const TestEnv = struct {
    tmp: std.testing.TmpDir,
    root: []const u8,
    fake: *mount.Fake,
    node: *Node,

    pub fn init(drive_names: []const []const u8) !TestEnv {
        const gpa = testing.allocator;
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(gpa, ".");
        errdefer gpa.free(root);
        for (drive_names) |n| {
            var buf: [64]u8 = undefined;
            try tmp.dir.makePath(try std.fmt.bufPrint(&buf, "drives/{s}", .{n}));
        }
        const fake = try gpa.create(mount.Fake);
        fake.* = .{ .gpa = gpa };
        const dd = try std.fs.path.join(gpa, &.{ root, "drives" });
        const sd = try std.fs.path.join(gpa, &.{ root, "state" });
        const node = try Node.init(gpa, .{ .node_id = "n1", .state_dir = sd, .drive_dir = dd, .mounter = .{ .fake = fake } });
        try node.refresh();
        return .{ .tmp = tmp, .root = root, .fake = fake, .node = node };
    }

    pub fn deinit(self: *TestEnv) void {
        const gpa = testing.allocator;
        const dd = self.node.cfg.drive_dir.?;
        const sd = self.node.cfg.state_dir;
        self.node.deinit();
        gpa.free(dd);
        gpa.free(sd);
        self.fake.deinit();
        gpa.destroy(self.fake);
        gpa.free(self.root);
        self.tmp.cleanup();
    }
};

fn mountCap() csi.VolumeCapability {
    return .{ .access_type = .mount, .access_mode = csi.AccessMode.single_node_writer };
}

test "volume id parsing" {
    try testing.expectEqualStrings("pvc-1", parseVolumeId("n1", "n1/pvc-1").?);
    try testing.expect(parseVolumeId("n1", "n2/pvc-1") == null);
    try testing.expect(parseVolumeId("n1", "n1/..") == null);
    try testing.expect(parseVolumeId("n1", "n1/a/b") == null);
    try testing.expect(parseVolumeId("n1", "pvc") == null);
}

test "publish in dir-drive mode" {
    var env = try TestEnv.init(&.{ "d1", "d2" });
    defer env.deinit();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n = env.node;
    try testing.expectEqual(@as(usize, 2), n.drives.len);

    const target = try std.fs.path.join(arena, &.{ env.root, "pods", "p1", "mount" });
    const q: csi.NodePublishRequest = .{ .volume_id = "n1/pvc-a", .target_path = target, .cap = mountCap(), .context = &.{.{ .key = "capacity", .value = "1024" }} };
    var st = n.publish(arena, q);
    try testing.expectEqual(@as(u32, 0), st.code);
    const rec = n.store.find("pvc-a").?;
    try testing.expectEqual(@as(u64, 1024), rec.capacity);
    // both drives share one filesystem, so the first wins the tie
    try testing.expectEqualStrings("d1", rec.drive);
    try testing.expectEqualStrings(try std.fs.path.join(arena, &.{ env.root, "drives", "d1", "volumes", "pvc-a" }), env.fake.mounted.get(target).?);
    try std.fs.cwd().access(target, .{});

    // idempotent; second volume lands on the drive with more free space
    try testing.expectEqual(@as(u32, 0), n.publish(arena, q).code);
    const q2: csi.NodePublishRequest = .{ .volume_id = "n1/pvc-b", .target_path = try std.fs.path.join(arena, &.{ env.root, "t2" }), .cap = mountCap(), .readonly = true, .context = &.{.{ .key = "capacity", .value = "1024" }} };
    try testing.expectEqual(@as(u32, 0), n.publish(arena, q2).code);
    try testing.expectEqualStrings("d2", n.store.find("pvc-b").?.drive);
    try testing.expect(env.fake.readonly.contains(q2.target_path));

    // errors
    var bad = q;
    bad.volume_id = "n2/pvc-a";
    try testing.expectEqual(@as(u32, Code.not_found), n.publish(arena, bad).code);
    bad = q2;
    bad.volume_id = "n1/huge";
    bad.target_path = "/nonexistent-target";
    bad.context = &.{.{ .key = "capacity", .value = "18446744073709551615" }};
    try testing.expectEqual(@as(u32, Code.resource_exhausted), n.publish(arena, bad).code);
    bad.cap = .{ .access_type = .block, .access_mode = 1 };
    try testing.expectEqual(@as(u32, Code.invalid_argument), n.publish(arena, bad).code);

    // state persisted
    var reloaded = try drives.Store.load(testing.allocator, n.store.path);
    defer reloaded.deinit();
    try testing.expectEqual(@as(usize, 2), reloaded.volumes.items.len);

    // gc refuses while published, then unpublish + gc removes data
    try testing.expectError(error.VolumePublished, n.gcVolume(arena, "pvc-a"));
    st = n.unpublish(arena, .{ .volume_id = "n1/pvc-a", .path = target });
    try testing.expectEqual(@as(u32, 0), st.code);
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(target, .{}));
    try testing.expectEqual(@as(u32, 0), n.unpublish(arena, .{ .volume_id = "n1/pvc-a", .path = target }).code);
    try n.gcVolume(arena, "pvc-a");
    try testing.expect(n.store.find("pvc-a") == null);
    try testing.expectError(error.VolumeNotFound, n.gcVolume(arena, "pvc-a"));

    // gc from a second process: the server must not resurrect the record
    {
        const other = try Node.init(testing.allocator, n.cfg);
        defer other.deinit();
        try other.refresh();
        try testing.expectError(error.VolumePublished, other.gcVolume(arena, "pvc-b"));
        try testing.expectEqual(@as(u32, 0), n.unpublish(arena, .{ .volume_id = "n1/pvc-b", .path = q2.target_path }).code);
        try other.gcVolume(arena, "pvc-b");
    }
    var q3 = q;
    q3.volume_id = "n1/pvc-c";
    try testing.expectEqual(@as(u32, 0), n.publish(arena, q3).code);
    var after = try drives.Store.load(testing.allocator, n.store.path);
    defer after.deinit();
    try testing.expect(after.find("pvc-b") == null);
    try testing.expect(after.find("pvc-c") != null);

    const s = n.stats(arena, .{ .volume_id = "n1/pvc-b", .path = env.root });
    try testing.expectEqual(@as(u32, 0), s[0].code);
    try testing.expect(s[1][0].total > 0);
}
