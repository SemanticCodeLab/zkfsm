//! DriveSet: formatted local drives, their identity files, and runtime drive state.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const profile_mod = @import("profile.zig");
const rendezvous = @import("rendezvous.zig");
const layout = @import("layout.zig");

const LocalBackend = backend.local.LocalBackend;
const Handle = backend.drive.Handle;
const Profile = profile_mod.Profile;
const DriveId = core.DriveId;
const SetId = core.SetId;

pub const max_drives = rendezvous.max_drives;

pub const OpenError = error{
    NoDrives,
    TooManyDrives,
    DriveUnavailable,
    /// Format file belongs to another drive set.
    ForeignDrive,
    /// Drive is from this set but sits at another position or the set size changed.
    DriveMismatch,
    /// Stored profile differs from the requested one.
    ProfileMismatch,
    /// Profile needs more drives than configured.
    NotEnoughDrives,
    CorruptFormat,
    OutOfMemory,
};

/// Parsed contents of a drive's format file.
pub const Format = struct {
    set: SetId,
    index: u8,
    profile: Profile,
    count: u8,
    ids: [max_drives]DriveId,

    pub fn drive(self: *const Format) DriveId {
        return self.ids[self.index];
    }

    pub fn encode(self: *const Format, buf: []u8) error{NoSpaceLeft}![]u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.print("zkfsm-format 1\nset {s}\ndrive {s}\nindex {d}\nprofile {s}\ndrives ", .{
            self.set.toHex(), self.drive().toHex(), self.index, self.profile.name(),
        }) catch return error.NoSpaceLeft;
        for (self.ids[0..self.count], 0..) |id, i| {
            w.print("{s}{s}", .{ if (i == 0) "" else ",", id.toHex() }) catch return error.NoSpaceLeft;
        }
        w.writeAll("\n") catch return error.NoSpaceLeft;
        return w.buffered();
    }

    pub fn parse(bytes: []const u8) error{CorruptFormat}!Format {
        var f: Format = .{ .set = undefined, .index = 0, .profile = .single, .count = 0, .ids = undefined };
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        if (!std.mem.eql(u8, lines.next() orelse "", "zkfsm-format 1")) return error.CorruptFormat;
        f.set = SetId.parseHex(try field(lines.next(), "set ")) catch return error.CorruptFormat;
        const self_id = DriveId.parseHex(try field(lines.next(), "drive ")) catch return error.CorruptFormat;
        f.index = std.fmt.parseInt(u8, try field(lines.next(), "index "), 10) catch return error.CorruptFormat;
        f.profile = Profile.parse(try field(lines.next(), "profile ")) catch return error.CorruptFormat;
        var ids = std.mem.splitScalar(u8, try field(lines.next(), "drives "), ',');
        while (ids.next()) |h| {
            if (f.count >= max_drives) return error.CorruptFormat;
            f.ids[f.count] = DriveId.parseHex(h) catch return error.CorruptFormat;
            f.count += 1;
        }
        if (f.index >= f.count or !f.drive().eql(self_id)) return error.CorruptFormat;
        return f;
    }

    fn field(line: ?[]const u8, prefix: []const u8) error{CorruptFormat}![]const u8 {
        const l = line orelse return error.CorruptFormat;
        if (!std.mem.startsWith(u8, l, prefix)) return error.CorruptFormat;
        return l[prefix.len..];
    }
};

/// Where a drive lives: a local directory or a remote drive behind RPC.
pub const Kind = union(enum) {
    local: LocalBackend,
    remote: backend.drive.Ext,
};

pub const Drive = struct {
    /// Local path, or the endpoint URL of a remote drive (for logs).
    path: []const u8,
    kind: Kind,
    /// Owning node; placement spreads shards across distinct nodes.
    node: u16 = 0,
    /// Shared for I/O, exclusive while the drive is reopened.
    lock: std.Thread.RwLock = .{},
    online: std.atomic.Value(bool) = .init(true),
    /// Set when the drive was (re)formatted empty and still needs a heal pass.
    fresh: std.atomic.Value(bool) = .init(false),
};

/// What a probe of a drive's identity found.
pub const Probe = enum { ok, unformatted, foreign, inaccessible };

/// Cluster identity of a set; null on single-node drive sets.
pub const ClusterInfo = struct {
    /// Format of drive 0; other drives differ only in `index`.
    format: layout.FormatV2,
    /// Online drives the set needs before it accepts writes.
    write_quorum: usize,
};

/// One drive of a cluster set as the caller found it.
pub const Member = struct {
    path: []const u8,
    node: u16,
    /// Null for a local drive at `path`.
    remote: ?backend.drive.Ext = null,
};

/// Keys stored below full width (a drive was unreachable), for the healer to repair
/// as soon as every drive is back instead of at the next full pass.
pub const Degraded = struct {
    mutex: std.Thread.Mutex = .{},
    keys: std.ArrayListUnmanaged(backend.PhysicalKey) = .empty,
    /// More keys than the cap arrived: only a full pass finds them all.
    overflow: bool = false,

    pub const cap = 65536;
};

pub const DriveSet = struct {
    gpa: std.mem.Allocator,
    drives: []Drive,
    set: SetId,
    profile: Profile,
    ids: [max_drives]DriveId,
    cluster: ?ClusterInfo = null,
    degraded: Degraded = .{},

    /// Opens and verifies every drive; formats a brand-new set or empty replacement drives.
    pub fn open(gpa: std.mem.Allocator, paths: []const []const u8, want: ?Profile) OpenError!DriveSet {
        if (paths.len == 0) return error.NoDrives;
        if (paths.len > max_drives) return error.TooManyDrives;
        const drives = try gpa.alloc(Drive, paths.len);
        var opened: usize = 0;
        errdefer {
            for (drives[0..opened]) |*d| {
                d.kind.local.close();
                gpa.free(d.path);
            }
            gpa.free(drives);
        }
        var formats: [max_drives]?Format = undefined;
        for (paths, 0..) |p, i| {
            const lb = LocalBackend.open(p) catch return error.DriveUnavailable;
            drives[i] = .{ .path = gpa.dupe(u8, p) catch |e| {
                var l = lb;
                l.close();
                return e;
            }, .kind = .{ .local = lb } };
            opened += 1;
            formats[i] = try readFormat(&drives[i].kind.local);
        }

        var ref: ?Format = null;
        for (formats[0..paths.len]) |f| if (f) |v| {
            ref = v;
            break;
        };
        var set: DriveSet = .{ .gpa = gpa, .drives = drives, .set = undefined, .profile = undefined, .ids = undefined };
        if (ref) |r| {
            if (r.count != paths.len) return error.DriveMismatch;
            if (want) |w| if (!w.eql(r.profile)) return error.ProfileMismatch;
            for (formats[0..paths.len], 0..) |f, i| if (f) |v| {
                if (!v.set.eql(r.set)) return error.ForeignDrive;
                if (v.index != i or v.count != r.count or !sameIds(v.ids[0..v.count], r.ids[0..r.count]))
                    return error.DriveMismatch;
            };
            set.set = r.set;
            set.profile = r.profile;
            set.ids = r.ids;
        } else {
            set.set = SetId.random();
            set.profile = want orelse profile_mod.StorageClassConfig.defaultFor(paths.len).standard;
            for (set.ids[0..paths.len]) |*id| id.* = DriveId.random();
        }
        if (set.profile.width() > paths.len) return error.NotEnoughDrives;
        for (formats[0..paths.len], 0..) |f, i| if (f == null) {
            set.writeFormat(i) catch return error.DriveUnavailable;
            if (ref != null) {
                drives[i].fresh.store(true, .release);
                std.log.warn("drive {s}: empty, formatted as replacement", .{drives[i].path});
            }
        };
        return set;
    }

    /// Opens a cluster set. Local drives are verified against `tmpl` (their slot in the
    /// layout) or formatted when empty; `fresh` marks such drives as needing a heal.
    pub fn openCluster(gpa: std.mem.Allocator, members: []const Member, tmpl: layout.FormatV2, fresh: bool) OpenError!DriveSet {
        if (members.len == 0) return error.NoDrives;
        if (members.len > max_drives or members.len != tmpl.set_size) return error.TooManyDrives;
        const drives = try gpa.alloc(Drive, members.len);
        var opened: usize = 0;
        errdefer {
            for (drives[0..opened]) |*d| {
                if (d.kind == .local) d.kind.local.close();
                gpa.free(d.path);
            }
            gpa.free(drives);
        }
        var set: DriveSet = .{ .gpa = gpa, .drives = drives, .set = layout.setId(tmpl.deployment, tmpl.pool, tmpl.set), .profile = tmpl.profile, .ids = undefined };
        set.cluster = .{ .format = tmpl, .write_quorum = layout.setWriteQuorum(members.len, tmpl.profile) };
        set.cluster.?.format.index = 0;
        for (members, 0..) |m, i| {
            set.ids[i] = layout.driveId(tmpl.deployment, tmpl.pool, tmpl.set, @intCast(i));
            const path = try gpa.dupe(u8, m.path);
            if (m.remote) |x| {
                drives[i] = .{ .path = path, .kind = .{ .remote = x }, .node = m.node };
                opened += 1;
                continue;
            }
            const lb = LocalBackend.open(m.path) catch {
                gpa.free(path);
                return error.DriveUnavailable;
            };
            drives[i] = .{ .path = path, .kind = .{ .local = lb }, .node = m.node };
            opened += 1;
            var buf: [layout.format_max]u8 = undefined;
            const bytes = drives[i].kind.local.readFormat(&buf) catch |e| switch (e) {
                error.NotFound => {
                    set.writeFormat(i) catch return error.DriveUnavailable;
                    if (fresh) {
                        drives[i].fresh.store(true, .release);
                        std.log.warn("drive {s}: empty, formatted as replacement", .{m.path});
                    }
                    continue;
                },
                else => return error.DriveUnavailable,
            };
            const f = layout.FormatV2.parse(bytes) catch return error.CorruptFormat;
            var want = tmpl;
            want.index = @intCast(i);
            if (!std.mem.eql(u8, &f.deployment, &tmpl.deployment)) return error.ForeignDrive;
            if (!f.sameSlot(want)) return error.DriveMismatch;
        }
        if (tmpl.profile.width() > members.len) return error.NotEnoughDrives;
        return set;
    }

    /// Remembers a key that was written without every placed drive.
    pub fn noteDegraded(self: *DriveSet, key: backend.PhysicalKey) void {
        const g = &self.degraded;
        g.mutex.lock();
        defer g.mutex.unlock();
        if (g.keys.items.len >= Degraded.cap) {
            g.overflow = true;
            return;
        }
        g.keys.append(self.gpa, key) catch {
            g.overflow = true;
        };
    }

    /// Hands the remembered keys to the caller (who frees them with `self.gpa`).
    pub fn takeDegraded(self: *DriveSet) struct { keys: []backend.PhysicalKey, overflow: bool } {
        const g = &self.degraded;
        g.mutex.lock();
        defer g.mutex.unlock();
        const out: []backend.PhysicalKey = g.keys.toOwnedSlice(self.gpa) catch blk: {
            g.keys.clearRetainingCapacity();
            g.overflow = true;
            break :blk &.{};
        };
        defer g.overflow = false;
        return .{ .keys = out, .overflow = g.overflow };
    }

    pub fn hasDegraded(self: *DriveSet) bool {
        const g = &self.degraded;
        g.mutex.lock();
        defer g.mutex.unlock();
        return g.keys.items.len > 0 or g.overflow;
    }

    pub fn deinit(self: *DriveSet) void {
        self.degraded.keys.deinit(self.gpa);
        for (self.drives) |*d| {
            if (d.kind == .local) d.kind.local.close();
            self.gpa.free(d.path);
        }
        self.gpa.free(self.drives);
    }

    pub fn isCluster(self: *const DriveSet) bool {
        return self.cluster != null;
    }

    /// Drives usable right now (online and, for remote drives, reachable).
    pub fn onlineCount(self: *DriveSet) usize {
        var n: usize = 0;
        for (self.drives) |*d| {
            if (!d.online.load(.acquire)) continue;
            if (d.kind == .remote and !d.kind.remote.vtable.online(d.kind.remote.ctx)) continue;
            n += 1;
        }
        return n;
    }

    /// Cluster sets refuse writes below their set write quorum; local sets always try.
    pub fn writable(self: *DriveSet) bool {
        const c = self.cluster orelse return true;
        return self.onlineCount() >= c.write_quorum;
    }

    pub fn count(self: *const DriveSet) usize {
        return self.drives.len;
    }

    /// Takes a shared hold on drive `i`; null when it is offline or unreachable.
    pub fn acquire(self: *DriveSet, i: usize) ?Handle {
        const d = &self.drives[i];
        d.lock.lockShared();
        const reachable = switch (d.kind) {
            .local => true,
            .remote => |x| x.vtable.online(x.ctx),
        };
        if (!d.online.load(.acquire) or !reachable) {
            d.lock.unlockShared();
            return null;
        }
        return switch (d.kind) {
            .local => |*lb| .{ .local = lb },
            .remote => |x| .{ .ext = x },
        };
    }

    pub fn release(self: *DriveSet, i: usize) void {
        self.drives[i].lock.unlockShared();
    }

    /// Drive indexes holding `key`, best first. System keys live on every drive.
    pub fn placed(self: *const DriveSet, key: backend.PhysicalKey, out: *[max_drives]u8) []const u8 {
        const n = self.drives.len;
        if (key.space == .system) {
            for (out[0..n], 0..) |*o, i| o.* = @intCast(i);
            return out[0..n];
        }
        if (self.cluster != null) {
            var nodes: [max_drives]u16 = undefined;
            for (self.drives, 0..) |d, i| nodes[i] = d.node;
            return layout.spread(self.ids[0..n], nodes[0..n], &key.hex, self.profile.width(), out);
        }
        const ranked = rendezvous.rank(self.ids[0..n], &key.hex, out);
        return ranked[0..self.profile.width()];
    }

    /// Re-reads drive `i`'s identity by path, bypassing the open handle.
    pub fn probe(self: *DriveSet, i: usize) Probe {
        if (self.cluster) |c| return self.probeCluster(i, c);
        var dir = std.fs.cwd().openDir(self.drives[i].path, .{}) catch |e| return switch (e) {
            error.FileNotFound => .unformatted,
            else => .inaccessible,
        };
        defer dir.close();
        var buf: [format_max]u8 = undefined;
        const bytes = dir.readFile(LocalBackend.format_file, &buf) catch |e| return switch (e) {
            error.FileNotFound => .unformatted,
            else => .inaccessible,
        };
        const f = Format.parse(bytes) catch return .foreign;
        if (!f.set.eql(self.set) or f.index != i or !f.drive().eql(self.ids[i])) return .foreign;
        return .ok;
    }

    fn probeCluster(self: *DriveSet, i: usize, c: ClusterInfo) Probe {
        var buf: [layout.format_max]u8 = undefined;
        const bytes: []const u8 = switch (self.drives[i].kind) {
            .remote => |x| x.vtable.readFormat(x.ctx, &buf) catch |e| return if (e == error.NotFound) .unformatted else .inaccessible,
            .local => blk: {
                var dir = std.fs.cwd().openDir(self.drives[i].path, .{}) catch |e| return switch (e) {
                    error.FileNotFound => .unformatted,
                    else => .inaccessible,
                };
                defer dir.close();
                break :blk dir.readFile(LocalBackend.format_file, &buf) catch |e| return switch (e) {
                    error.FileNotFound => .unformatted,
                    else => .inaccessible,
                };
            },
        };
        const f = layout.FormatV2.parse(bytes) catch return .foreign;
        var want = c.format;
        want.index = @intCast(i);
        return if (f.sameSlot(want)) .ok else .foreign;
    }

    /// True when one of drives `idx` was formatted empty and is not fully healed yet;
    /// remote drives are asked (unreachable ones count as fresh, to stay safe).
    pub fn anyFresh(self: *DriveSet, idx: []const u8) bool {
        for (idx) |i| {
            const d = &self.drives[i];
            const fresh = switch (d.kind) {
                .local => d.fresh.load(.acquire),
                .remote => |x| x.vtable.fresh(x.ctx) catch true,
            };
            if (fresh) return true;
        }
        return false;
    }

    pub fn isLocal(self: *const DriveSet, i: usize) bool {
        return self.drives[i].kind == .local;
    }

    /// Recreates drive `i` in place and formats it empty; it then needs healing.
    pub fn reinit(self: *DriveSet, i: usize) OpenError!void {
        const d = &self.drives[i];
        if (d.kind != .local) return error.DriveUnavailable;
        d.lock.lock();
        defer d.lock.unlock();
        d.online.store(false, .release);
        var lb = LocalBackend.open(d.path) catch return error.DriveUnavailable;
        // The drive came back empty: its usage restarts from zero.
        lb.usage = d.kind.local.usage;
        if (lb.usage) |u| u.store(0, .monotonic);
        d.kind.local.close();
        d.kind.local = lb;
        self.writeFormat(i) catch return error.DriveUnavailable;
        d.fresh.store(true, .release);
        d.online.store(true, .release);
    }

    /// Takes drive `i` out of service without touching its contents.
    pub fn quarantine(self: *DriveSet, i: usize) void {
        const d = &self.drives[i];
        d.lock.lock();
        defer d.lock.unlock();
        d.online.store(false, .release);
    }

    pub fn setOnline(self: *DriveSet, i: usize) void {
        self.drives[i].online.store(true, .release);
    }

    fn writeFormat(self: *DriveSet, i: usize) backend.Error!void {
        if (self.cluster) |c| {
            var f = c.format;
            f.index = @intCast(i);
            var buf: [layout.format_max]u8 = undefined;
            const bytes = f.encode(&buf) catch return error.IoFailed;
            return self.drives[i].kind.local.writeFormat(bytes);
        }
        const f: Format = .{
            .set = self.set,
            .index = @intCast(i),
            .profile = self.profile,
            .count = @intCast(self.drives.len),
            .ids = self.ids,
        };
        var buf: [format_max]u8 = undefined;
        const bytes = f.encode(&buf) catch return error.IoFailed;
        try self.drives[i].kind.local.writeFormat(bytes);
    }
};

const format_max = 4096;

fn sameIds(a: []const DriveId, b: []const DriveId) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!x.eql(y)) return false;
    return true;
}

fn readFormat(lb: *LocalBackend) OpenError!?Format {
    var buf: [format_max]u8 = undefined;
    const bytes = lb.readFormat(&buf) catch |e| return switch (e) {
        error.NotFound => null,
        else => error.DriveUnavailable,
    };
    return Format.parse(bytes) catch error.CorruptFormat;
}

fn tmpPaths(tmp: *std.testing.TmpDir, buf: *[4][std.fs.max_path_bytes]u8, n: usize) ![4][]const u8 {
    var out: [4][]const u8 = undefined;
    var nb: [8]u8 = undefined;
    for (0..n) |i| {
        const name = try std.fmt.bufPrint(&nb, "d{d}", .{i});
        try tmp.dir.makePath(name);
        out[i] = try tmp.dir.realpath(name, &buf[i]);
    }
    return out;
}

test "format roundtrip" {
    var f: Format = .{ .set = SetId.random(), .index = 1, .profile = .{ .replica = 2 }, .count = 3, .ids = undefined };
    for (f.ids[0..3]) |*id| id.* = DriveId.random();
    var buf: [format_max]u8 = undefined;
    const g = try Format.parse(try f.encode(&buf));
    try std.testing.expect(g.set.eql(f.set) and g.drive().eql(f.ids[1]) and g.count == 3);
    try std.testing.expect(g.profile.eql(.{ .replica = 2 }));
    try std.testing.expectError(error.CorruptFormat, Format.parse("zkfsm-format 1\nset zz\n"));
}

test "drive set formats, reopens, refuses foreign and reordered drives" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [4][std.fs.max_path_bytes]u8 = undefined;
    const p = try tmpPaths(&tmp, &bufs, 4);

    {
        var s = try DriveSet.open(gpa, p[0..4], .{ .replica = 2 });
        defer s.deinit();
        var out: [max_drives]u8 = undefined;
        const key: backend.PhysicalKey = .{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* };
        const pl = s.placed(key, &out);
        try std.testing.expectEqual(@as(usize, 2), pl.len);
        try std.testing.expect(pl[0] != pl[1]);
        try std.testing.expectEqual(Probe.ok, s.probe(0));
    }
    {
        var s = try DriveSet.open(gpa, p[0..4], null);
        defer s.deinit();
        try std.testing.expect(s.profile.eql(.{ .replica = 2 }));
        try std.testing.expect(!s.drives[0].fresh.load(.acquire));
    }
    try std.testing.expectError(error.ProfileMismatch, DriveSet.open(gpa, p[0..4], .{ .replica = 3 }));
    const swapped = [_][]const u8{ p[1], p[0], p[2], p[3] };
    try std.testing.expectError(error.DriveMismatch, DriveSet.open(gpa, &swapped, null));
    try std.testing.expectError(error.DriveMismatch, DriveSet.open(gpa, p[0..3], null));

    // A wiped drive comes back as a fresh replacement.
    try tmp.dir.deleteTree("d2");
    {
        var s = try DriveSet.open(gpa, p[0..4], null);
        defer s.deinit();
        try std.testing.expect(s.drives[2].fresh.load(.acquire));
        try tmp.dir.deleteTree("d3");
        try std.testing.expectEqual(Probe.unformatted, s.probe(3));
        try s.reinit(3);
        try std.testing.expectEqual(Probe.ok, s.probe(3));
    }

    // A drive from another set is refused.
    var other = std.testing.tmpDir(.{});
    defer other.cleanup();
    var obufs: [4][std.fs.max_path_bytes]u8 = undefined;
    const op = try tmpPaths(&other, &obufs, 2);
    {
        var s = try DriveSet.open(gpa, op[0..2], null);
        s.deinit();
    }
    const mixed = [_][]const u8{ p[0], p[1], p[2], op[0] };
    try std.testing.expectError(error.ForeignDrive, DriveSet.open(gpa, &mixed, null));
}

test "cluster set: formats by layout slot, refuses moved and foreign drives" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [4][std.fs.max_path_bytes]u8 = undefined;
    const p = try tmpPaths(&tmp, &bufs, 4);
    var members: [4]Member = undefined;
    for (&members, 0..) |*m, i| m.* = .{ .path = p[i], .node = @intCast(i / 2) };
    const tmpl: layout.FormatV2 = .{ .deployment = @splat(7), .layout = @splat(8), .pool = 0, .set = 2, .index = 0, .set_size = 4, .profile = .{ .replica = 2 } };
    {
        var s = try DriveSet.openCluster(gpa, &members, tmpl, false);
        defer s.deinit();
        try std.testing.expect(s.isCluster());
        try std.testing.expectEqual(Probe.ok, s.probe(3));
        try std.testing.expect(s.writable());
        var out: [max_drives]u8 = undefined;
        const pl = s.placed(.{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* }, &out);
        // Two nodes, two copies: one per node.
        try std.testing.expect(s.drives[pl[0]].node != s.drives[pl[1]].node);
    }
    const swapped = [_]Member{ members[1], members[0], members[2], members[3] };
    try std.testing.expectError(error.DriveMismatch, DriveSet.openCluster(gpa, &swapped, tmpl, true));
    var other = tmpl;
    other.deployment = @splat(9);
    try std.testing.expectError(error.ForeignDrive, DriveSet.openCluster(gpa, &members, other, true));
    try tmp.dir.deleteTree("d1");
    var s = try DriveSet.openCluster(gpa, &members, tmpl, true);
    defer s.deinit();
    try std.testing.expect(s.drives[1].fresh.load(.acquire));
}
