//! HealPlanner: turns a scan into an ordered action list. Drives first, then keys, then temps.
const std = @import("std");
const iface = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");
const scanner = @import("scanner.zig");

pub const Action = union(enum) {
    /// Drive lost its identity (wiped or replaced): recreate and format it empty.
    reinit_drive: u8,
    /// Drive carries another set's identity: stop using it.
    quarantine_drive: u8,
    /// Drive was offline and now probes healthy.
    restore_drive: u8,
    /// A placed replica was not seen on disk.
    repair_key: iface.PhysicalKey,
    /// All replicas present; verify checksums (scrub).
    verify_key: iface.PhysicalKey,
    remove_temp: scanner.StaleTemp,
};

pub const Plan = struct {
    actions: std.ArrayList(Action) = .empty,

    pub fn deinit(self: *Plan, gpa: std.mem.Allocator) void {
        self.actions.deinit(gpa);
    }
};

pub fn plan(gpa: std.mem.Allocator, drives: *const placement.DriveSet, scan: *const scanner.ScanResult) error{OutOfMemory}!Plan {
    var p: Plan = .{};
    errdefer p.deinit(gpa);
    for (scan.probes[0..scan.drive_count], 0..) |probe, i| {
        const d: u8 = @intCast(i);
        // A remote drive's identity is its owner's to repair.
        if (!drives.isLocal(i)) continue;
        const online = drives.drives[i].online.load(.acquire);
        switch (probe) {
            .unformatted => try p.actions.append(gpa, .{ .reinit_drive = d }),
            .foreign => if (online) try p.actions.append(gpa, .{ .quarantine_drive = d }),
            .ok => if (!online) try p.actions.append(gpa, .{ .restore_drive = d }),
            .inaccessible => {},
        }
    }
    var verify: std.ArrayList(iface.PhysicalKey) = .empty;
    defer verify.deinit(gpa);
    var it = scan.keys.iterator();
    while (it.next()) |e| {
        var pbuf: [placement.max_drives]u8 = undefined;
        var want: u32 = 0;
        for (drives.placed(e.key_ptr.*, &pbuf)) |d| want |= @as(u32, 1) << @intCast(d);
        if (want & ~e.value_ptr.* != 0) {
            try p.actions.append(gpa, .{ .repair_key = e.key_ptr.* });
        } else try verify.append(gpa, e.key_ptr.*);
    }
    for (verify.items) |k| try p.actions.append(gpa, .{ .verify_key = k });
    for (scan.temps.items) |t| try p.actions.append(gpa, .{ .remove_temp = t });
    return p;
}

test "planner orders drive actions, repairs, verifies, temps" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var bufs: [2][std.fs.max_path_bytes]u8 = undefined;
    try tmp.dir.makePath("a");
    try tmp.dir.makePath("b");
    const paths = [_][]const u8{ try tmp.dir.realpath("a", &bufs[0]), try tmp.dir.realpath("b", &bufs[1]) };
    var set = try placement.DriveSet.open(std.testing.allocator, &paths, .{ .replica = 2 });
    defer set.deinit();

    const gpa = std.testing.allocator;
    var scan: scanner.ScanResult = .{ .drive_count = 2 };
    defer scan.deinit(gpa);
    scan.probes[0] = .ok;
    scan.probes[1] = .unformatted;
    const k1: iface.PhysicalKey = .{ .space = .data, .hex = [_]u8{'1'} ** 32 };
    const k2: iface.PhysicalKey = .{ .space = .data, .hex = [_]u8{'2'} ** 32 };
    try scan.keys.put(gpa, k1, 0b01);
    try scan.keys.put(gpa, k2, 0b11);
    try scan.temps.append(gpa, .{ .drive = 0, .name_buf = undefined, .name_len = 0 });

    var p = try plan(gpa, &set, &scan);
    defer p.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 4), p.actions.items.len);
    try std.testing.expectEqual(@as(u8, 1), p.actions.items[0].reinit_drive);
    try std.testing.expect(p.actions.items[1].repair_key.hex[0] == '1');
    try std.testing.expect(p.actions.items[2].verify_key.hex[0] == '2');
    try std.testing.expect(p.actions.items[3] == .remove_temp);
}
