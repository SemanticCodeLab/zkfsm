//! HealthScanner: probes drive identity and walks drive trees (explicit stack, rate-bounded).
const std = @import("std");
const core = @import("../core/root.zig");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");

const PhysicalKey = iface.PhysicalKey;
const Probe = placement.drives.Probe;
const max_drives = placement.max_drives;

pub const Error = error{ OutOfMemory, Stopped };

pub const Config = struct {
    /// Upper bound on scanned entries and healed keys per second; 0 = unbounded.
    rate_per_sec: u32 = 2000,
    /// Temp files older than this are leftovers of interrupted writes.
    temp_grace_ns: u64 = std.time.ns_per_hour,
    /// Collect keys for verification; off, a pass only probes drives and sweeps temps.
    walk_keys: bool = true,
};

pub const StaleTemp = struct {
    drive: u8,
    name_buf: [64]u8,
    name_len: u8,

    pub fn name(self: *const StaleTemp) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const ScanResult = struct {
    probes: [max_drives]Probe = undefined,
    drive_count: usize = 0,
    /// Every key seen on any drive, with a bitmask of drives it was seen on.
    keys: std.AutoArrayHashMapUnmanaged(PhysicalKey, u32) = .empty,
    temps: std.ArrayList(StaleTemp) = .empty,
    entries: u64 = 0,
    /// A drive's keys could not all be listed: the pass cannot vouch for every key.
    incomplete: bool = false,

    pub fn deinit(self: *ScanResult, gpa: std.mem.Allocator) void {
        self.keys.deinit(gpa);
        self.temps.deinit(gpa);
    }
};

/// Token bucket over one-second windows; waits are interruptible by `stop`.
pub const Throttle = struct {
    per_sec: u32,
    stop: ?*std.Thread.ResetEvent = null,
    n: u32 = 0,
    window_start: i128 = 0,

    pub fn tick(self: *Throttle) Error!void {
        if (self.stop) |s| if (s.isSet()) return error.Stopped;
        if (self.per_sec == 0) return;
        const now = core.time.nowNs();
        if (now - self.window_start >= std.time.ns_per_s) {
            self.window_start = now;
            self.n = 0;
        }
        self.n += 1;
        if (self.n <= self.per_sec) return;
        const wait: u64 = @intCast(@max(0, self.window_start + std.time.ns_per_s - now));
        if (self.stop) |s| {
            s.timedWait(wait) catch {};
            if (s.isSet()) return error.Stopped;
        } else std.Thread.sleep(wait);
        self.window_start = core.time.nowNs();
        self.n = 1;
    }
};

const Where = enum { root, fan0, fan1, leaf, system, tmp };

const Frame = struct {
    path_buf: [32]u8 = undefined,
    path_len: u8 = 0,
    where: Where,
    space: iface.KeySpace = .data,

    fn path(self: *const Frame) []const u8 {
        return if (self.path_len == 0) "." else self.path_buf[0..self.path_len];
    }

    fn child(self: *const Frame, name: []const u8, where: Where, space: iface.KeySpace) ?Frame {
        var f: Frame = .{ .where = where, .space = space };
        const p = if (self.path_len == 0)
            std.fmt.bufPrint(&f.path_buf, "{s}", .{name})
        else
            std.fmt.bufPrint(&f.path_buf, "{s}/{s}", .{ self.path(), name });
        f.path_len = @intCast((p catch return null).len);
        return f;
    }
};

pub const HealthScanner = struct {
    gpa: std.mem.Allocator,
    drives: *placement.DriveSet,
    throttle: *Throttle,
    cfg: Config,

    pub fn scan(self: *HealthScanner) Error!ScanResult {
        var res: ScanResult = .{ .drive_count = self.drives.count() };
        errdefer res.deinit(self.gpa);
        for (0..res.drive_count) |i| {
            res.probes[i] = self.drives.probe(i);
            if (res.probes[i] != .ok) {
                res.incomplete = true;
                continue;
            }
            const h = self.drives.acquire(i) orelse {
                res.incomplete = true;
                continue;
            };
            defer self.drives.release(i);
            switch (h) {
                .local => |lb| try self.walk(@intCast(i), lb.root, &res),
                .ext => |x| if (self.cfg.walk_keys) try self.scanRemote(@intCast(i), x, &res),
            }
        }
        return res;
    }

    /// Remote drives are listed page by page; their temps are the owner's to sweep.
    fn scanRemote(self: *HealthScanner, drive: u8, x: iface.drive.Ext, res: *ScanResult) Error!void {
        for ([_]iface.KeySpace{ .data, .record, .system }) |space| {
            var after: ?[32]u8 = null;
            while (true) {
                var page: iface.drive.ScanPage = .{};
                defer page.deinit(self.gpa);
                x.vtable.scan(x.ctx, self.gpa, space, after, &page) catch |e| {
                    if (e == error.OutOfMemory) return error.OutOfMemory;
                    std.log.warn("heal scan of remote drive {d} stopped: {t}", .{ drive, e });
                    res.incomplete = true;
                    return;
                };
                for (page.keys.items) |k| {
                    try self.throttle.tick();
                    res.entries += 1;
                    const gop = try res.keys.getOrPut(self.gpa, k);
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* |= @as(u32, 1) << @intCast(drive);
                }
                if (!page.more or page.keys.items.len == 0) break;
                after = page.keys.items[page.keys.items.len - 1].hex;
            }
        }
    }

    fn walk(self: *HealthScanner, drive: u8, root: std.fs.Dir, res: *ScanResult) Error!void {
        var stack: std.ArrayList(Frame) = .empty;
        defer stack.deinit(self.gpa);
        try stack.append(self.gpa, .{ .where = .root });
        const now = core.time.nowNs();
        while (stack.pop()) |frame| {
            var dir = root.openDir(frame.path(), .{ .iterate = true }) catch continue;
            defer dir.close();
            var it = dir.iterate();
            while (it.next() catch null) |ent| {
                try self.throttle.tick();
                res.entries += 1;
                switch (frame.where) {
                    .root => {
                        if (ent.kind != .directory) continue;
                        const sub: ?struct { Where, iface.KeySpace } =
                            if (std.mem.eql(u8, ent.name, "data")) .{ .fan0, .data } else if (std.mem.eql(u8, ent.name, "record")) .{ .fan0, .record } else if (std.mem.eql(u8, ent.name, "system")) .{ .system, .system } else if (std.mem.eql(u8, ent.name, "tmp")) .{ .tmp, .data } else null;
                        const s = sub orelse continue;
                        if (!self.cfg.walk_keys and s[0] != .tmp) continue;
                        if (frame.child(ent.name, s[0], s[1])) |c| try stack.append(self.gpa, c);
                    },
                    .fan0, .fan1 => {
                        if (ent.kind != .directory or ent.name.len != 2) continue;
                        const next: Where = if (frame.where == .fan0) .fan1 else .leaf;
                        if (frame.child(ent.name, next, frame.space)) |c| try stack.append(self.gpa, c);
                    },
                    .leaf, .system => {
                        if (ent.kind != .file) continue;
                        const hex = keyName(frame.space, ent.name) orelse continue;
                        const gop = try res.keys.getOrPut(self.gpa, .{ .space = frame.space, .hex = hex });
                        if (!gop.found_existing) gop.value_ptr.* = 0;
                        gop.value_ptr.* |= @as(u32, 1) << @intCast(drive);
                    },
                    .tmp => {
                        if (ent.kind != .file or !std.mem.endsWith(u8, ent.name, ".tmp") or ent.name.len > 64) continue;
                        const st = dir.statFile(ent.name) catch continue;
                        if (now - st.mtime < self.cfg.temp_grace_ns) continue;
                        var t: StaleTemp = .{ .drive = drive, .name_buf = undefined, .name_len = @intCast(ent.name.len) };
                        @memcpy(t.name_buf[0..ent.name.len], ent.name);
                        try res.temps.append(self.gpa, t);
                    },
                }
            }
        }
    }
};

fn keyName(space: iface.KeySpace, name: []const u8) ?[32]u8 {
    const hex = if (space == .data) name else if (std.mem.endsWith(u8, name, ".meta")) name[0 .. name.len - 5] else return null;
    if (hex.len != 32) return null;
    for (hex) |c| if (!std.ascii.isHex(c)) return null;
    return hex[0..32].*;
}

test "key names by space" {
    const h = "0123456789abcdef0123456789abcdef";
    try std.testing.expect(keyName(.data, h) != null);
    try std.testing.expect(keyName(.record, h ++ ".meta") != null);
    try std.testing.expect(keyName(.record, h) == null);
    try std.testing.expect(keyName(.data, "short") == null);
}

test "throttle bounds rate and honours stop" {
    var ev: std.Thread.ResetEvent = .{};
    var t: Throttle = .{ .per_sec = 1000, .stop = &ev };
    for (0..1000) |_| try t.tick();
    ev.set();
    try std.testing.expectError(error.Stopped, t.tick());
}
