//! Object Lock (WORM): retention and legal-hold rules for deletes and retention changes.
const std = @import("std");
const metadata = @import("../metadata/root.zig");

pub const Mode = metadata.record.RetentionMode;
pub const BucketConfig = metadata.BucketConfig;

pub const Retention = struct { mode: Mode = .none, until_ns: i128 = 0 };

const day_ns: i128 = 86400 * std.time.ns_per_s;

pub fn isActive(r: Retention, now_ns: i128) bool {
    return r.mode != .none and r.until_ns > now_ns;
}

/// A version may be removed only if unheld and out of retention (governance: or bypassed).
pub fn checkDelete(r: Retention, legal_hold: bool, bypass_governance: bool, now_ns: i128) error{ObjectLocked}!void {
    if (legal_hold) return error.ObjectLocked;
    if (!isActive(r, now_ns)) return;
    if (r.mode == .governance and bypass_governance) return;
    return error.ObjectLocked;
}

/// Tightening is always allowed; loosening governance needs bypass; compliance never loosens.
pub fn checkChange(old: Retention, new: Retention, bypass_governance: bool, now_ns: i128) error{ObjectLocked}!void {
    if (!isActive(old, now_ns)) return;
    // Any mode change of an active governance lock needs the bypass, as does weakening it.
    const weaker = new.mode == .none or new.until_ns < old.until_ns or
        (old.mode == .compliance and new.mode != .compliance) or (old.mode == .governance and new.mode != .governance);
    if (!weaker) return;
    if (old.mode == .governance and bypass_governance) return;
    return error.ObjectLocked;
}

/// Retention a new version receives from the bucket default, if any.
pub fn defaultRetention(cfg: BucketConfig, now_ns: i128) Retention {
    if (!cfg.lock_enabled or cfg.default_mode == .none) return .{};
    const days: i128 = @as(i128, cfg.default_days) + @as(i128, cfg.default_years) * 365;
    return .{ .mode = cfg.default_mode, .until_ns = now_ns + days * day_ns };
}

test "delete rules" {
    const g: Retention = .{ .mode = .governance, .until_ns = 100 };
    const c: Retention = .{ .mode = .compliance, .until_ns = 100 };
    try std.testing.expectError(error.ObjectLocked, checkDelete(g, false, false, 50));
    try checkDelete(g, false, true, 50);
    try std.testing.expectError(error.ObjectLocked, checkDelete(c, false, true, 50));
    try checkDelete(c, false, false, 150);
    try std.testing.expectError(error.ObjectLocked, checkDelete(.{}, true, true, 0));
    try checkDelete(.{}, false, false, 0);
}

test "retention change rules" {
    const g: Retention = .{ .mode = .governance, .until_ns = 100 };
    const c: Retention = .{ .mode = .compliance, .until_ns = 100 };
    try checkChange(g, .{ .mode = .governance, .until_ns = 200 }, false, 0);
    // Changing the mode of an active governance lock (even to compliance) needs the bypass.
    try std.testing.expectError(error.ObjectLocked, checkChange(g, .{ .mode = .compliance, .until_ns = 100 }, false, 0));
    try checkChange(g, .{ .mode = .compliance, .until_ns = 100 }, true, 0);
    try std.testing.expectError(error.ObjectLocked, checkChange(g, .{}, false, 0));
    try checkChange(g, .{}, true, 0);
    try std.testing.expectError(error.ObjectLocked, checkChange(c, .{ .mode = .governance, .until_ns = 300 }, true, 0));
    try std.testing.expectError(error.ObjectLocked, checkChange(c, .{ .mode = .compliance, .until_ns = 50 }, true, 0));
    try checkChange(c, .{ .mode = .compliance, .until_ns = 300 }, false, 0);
}

test "default retention" {
    const r = defaultRetention(.{ .lock_enabled = true, .default_mode = .governance, .default_days = 1 }, 0);
    try std.testing.expectEqual(Mode.governance, r.mode);
    try std.testing.expectEqual(day_ns, r.until_ns);
    try std.testing.expectEqual(Mode.none, defaultRetention(.{ .default_mode = .governance, .default_days = 1 }, 0).mode);
}
