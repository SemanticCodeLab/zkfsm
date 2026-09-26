//! HealExecutor: carries out a plan through the protection strategy.
const std = @import("std");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");
const scanner = @import("scanner.zig");
const planner = @import("planner.zig");

pub const Error = error{ Stopped, NotImplemented };

pub const Report = struct {
    entries_scanned: u64 = 0,
    drives_reinit: u32 = 0,
    drives_quarantined: u32 = 0,
    drives_restored: u32 = 0,
    keys_checked: u64 = 0,
    replicas_repaired: u64 = 0,
    replicas_unrepaired: u64 = 0,
    keys_lost: u64 = 0,
    temps_removed: u64 = 0,

    /// True when every placed replica is present and verified.
    pub fn fullyRedundant(self: Report) bool {
        return self.replicas_unrepaired == 0 and self.keys_lost == 0;
    }
};

pub const HealExecutor = struct {
    drives: *placement.DriveSet,
    strategy: protection.Strategy,
    throttle: *scanner.Throttle,

    pub fn run(self: *HealExecutor, p: *const planner.Plan, report: *Report) Error!void {
        for (p.actions.items) |a| switch (a) {
            .reinit_drive => |d| {
                self.drives.reinit(d) catch |e| {
                    std.log.err("drive {s}: reinit failed: {t}", .{ self.drives.drives[d].path, e });
                    continue;
                };
                std.log.warn("drive {s}: formatted as replacement", .{self.drives.drives[d].path});
                report.drives_reinit += 1;
            },
            .quarantine_drive => |d| {
                std.log.err("drive {s}: foreign format, taken offline", .{self.drives.drives[d].path});
                self.drives.quarantine(d);
                report.drives_quarantined += 1;
            },
            .restore_drive => |d| {
                self.drives.setOnline(d);
                report.drives_restored += 1;
            },
            .repair_key, .verify_key => |k| {
                self.throttle.tick() catch return error.Stopped;
                const r = try self.strategy.healKey(k);
                report.keys_checked += 1;
                report.replicas_repaired += r.repaired;
                report.replicas_unrepaired += r.unrepaired;
                if (r.lost) {
                    std.log.err("{t} {s}: no healthy replica left", .{ k.space, &k.hex });
                    report.keys_lost += 1;
                }
            },
            .remove_temp => |t| {
                const lb = self.drives.acquire(t.drive) orelse continue;
                defer self.drives.release(t.drive);
                lb.removeTemp(t.name()) catch continue;
                report.temps_removed += 1;
            },
        };
    }
};
