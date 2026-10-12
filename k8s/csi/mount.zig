//! mount(2)/umount2(2) wrappers with an injectable in-memory fake for tests.
const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const Fake = struct {
    gpa: Allocator,
    mounted: std.StringHashMapUnmanaged([]const u8) = .empty,
    readonly: std.StringHashMapUnmanaged(void) = .empty,

    pub fn deinit(self: *Fake) void {
        var it = self.mounted.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.mounted.deinit(self.gpa);
        self.readonly.deinit(self.gpa);
    }
};

pub const Mounter = struct {
    fake: ?*Fake = null,
    mountinfo: []const u8 = "/proc/self/mountinfo",

    fn check(rc: usize) !void {
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            .BUSY => return error.Busy,
            .NOENT => return error.FileNotFound,
            .INVAL => return error.InvalidArgument,
            else => return error.MountFailed,
        }
    }

    pub fn bind(self: Mounter, src: []const u8, dst: []const u8, ro: bool) !void {
        if (self.fake) |f| {
            const v = try f.gpa.dupe(u8, src);
            errdefer f.gpa.free(v);
            const k = try f.gpa.dupe(u8, dst);
            try f.mounted.put(f.gpa, k, v);
            if (ro) try f.readonly.put(f.gpa, k, {});
            return;
        }
        var a: [2][std.fs.max_path_bytes:0]u8 = undefined;
        const s = try z(&a[0], src);
        const d = try z(&a[1], dst);
        try check(linux.mount(s, d, null, linux.MS.BIND, 0));
        // read-only bind needs a second remount pass
        if (ro) check(linux.mount(null, d, null, linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY, 0)) catch |e| {
            _ = linux.umount2(d, 0);
            return e;
        };
    }

    pub fn mountDev(self: Mounter, dev: []const u8, dst: []const u8, fstype: []const u8) !void {
        if (self.fake != null) return self.bind(dev, dst, false);
        var a: [3][std.fs.max_path_bytes:0]u8 = undefined;
        try check(linux.mount(try z(&a[0], dev), try z(&a[1], dst), try z(&a[2], fstype), 0, 0));
    }

    /// Not-mounted and missing targets count as success (idempotent).
    pub fn umount(self: Mounter, path: []const u8) !void {
        if (self.fake) |f| {
            if (f.mounted.fetchRemove(path)) |kv| {
                _ = f.readonly.remove(kv.key);
                f.gpa.free(kv.key);
                f.gpa.free(kv.value);
            }
            return;
        }
        var a: [std.fs.max_path_bytes:0]u8 = undefined;
        check(linux.umount2(try z(&a, path), 0)) catch |e| switch (e) {
            error.InvalidArgument, error.FileNotFound => {},
            else => return e,
        };
    }

    /// True when some mount's source (bind root or fake source) ends with `suffix`.
    pub fn sourceInUse(self: Mounter, gpa: Allocator, suffix: []const u8) !bool {
        if (self.fake) |f| {
            var it = f.mounted.valueIterator();
            while (it.next()) |v| if (std.mem.endsWith(u8, v.*, suffix)) return true;
            return false;
        }
        const data = try std.fs.cwd().readFileAlloc(gpa, self.mountinfo, 16 << 20);
        defer gpa.free(data);
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            var i: usize = 0;
            while (it.next()) |tok| : (i += 1) if (i == 3) {
                if (std.mem.endsWith(u8, tok, suffix)) return true;
                break;
            };
        }
        return false;
    }

    pub fn isMounted(self: Mounter, gpa: Allocator, path: []const u8) !bool {
        if (self.fake) |f| return f.mounted.contains(path);
        const data = try std.fs.cwd().readFileAlloc(gpa, self.mountinfo, 16 << 20);
        defer gpa.free(data);
        var lines = std.mem.splitScalar(u8, data, '\n');
        while (lines.next()) |line| {
            const mi = parseMountinfo(line) orelse continue;
            if (unescapedEql(mi.mount_point, path)) return true;
        }
        return false;
    }
};

fn z(buf: *[std.fs.max_path_bytes:0]u8, s: []const u8) ![*:0]const u8 {
    if (s.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

pub const MountinfoLine = struct { mount_point: []const u8, source: []const u8 };

/// Fields: id parent maj:min root mount_point opts [optional...] - fstype source superopts.
pub fn parseMountinfo(line: []const u8) ?MountinfoLine {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    var i: usize = 0;
    var mp: []const u8 = "";
    while (it.next()) |tok| : (i += 1) {
        if (i == 4) mp = tok;
        if (i >= 6 and std.mem.eql(u8, tok, "-")) {
            _ = it.next() orelse return null;
            const src = it.next() orelse return null;
            return .{ .mount_point = mp, .source = src };
        }
    }
    return null;
}

/// Compares a mountinfo path (octal escapes like \040) against a plain path.
pub fn unescapedEql(escaped: []const u8, plain: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < escaped.len) : (j += 1) {
        var c = escaped[i];
        if (c == '\\' and i + 4 <= escaped.len) {
            if (std.fmt.parseInt(u8, escaped[i + 1 .. i + 4], 8)) |v| {
                c = v;
                i += 4;
            } else |_| i += 1;
        } else i += 1;
        if (j >= plain.len or plain[j] != c) return false;
    }
    return j == plain.len;
}

test "mountinfo parsing" {
    const line = "36 35 98:0 /mnt1 /var/lib/kubelet/pods/x/my\\040vol rw,noatime master:1 - xfs /dev/sdb rw";
    const mi = parseMountinfo(line).?;
    try std.testing.expectEqualStrings("/dev/sdb", mi.source);
    try std.testing.expect(unescapedEql(mi.mount_point, "/var/lib/kubelet/pods/x/my vol"));
    try std.testing.expect(!unescapedEql(mi.mount_point, "/var/lib/kubelet/pods/x/my"));
    try std.testing.expect(parseMountinfo("garbage") == null);
}

test "fake mounter" {
    var f: Fake = .{ .gpa = std.testing.allocator };
    defer f.deinit();
    const m: Mounter = .{ .fake = &f };
    try m.bind("/a", "/b", true);
    try std.testing.expect(try m.isMounted(std.testing.allocator, "/b"));
    try std.testing.expect(f.readonly.contains("/b"));
    try m.umount("/b");
    try m.umount("/b");
    try std.testing.expect(!try m.isMounted(std.testing.allocator, "/b"));
}
