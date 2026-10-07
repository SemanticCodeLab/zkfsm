//! Bucket lifecycle rules (expiration and transition) and their compact binary encoding.
const std = @import("std");
const codec = @import("codec.zig");
const tags_mod = @import("tags.zig");

pub const Tag = tags_mod.Tag;

pub const max_rules = 1000;
pub const max_id_len = 255;
pub const max_prefix_len = 1024;

pub const Filter = struct {
    prefix: []const u8 = "",
    tags: []const Tag = &.{},
    /// Object size must be strictly greater / less than these.
    size_gt: ?u64 = null,
    size_lt: ?u64 = null,
};

pub const Rule = struct {
    id: []const u8 = "",
    enabled: bool = true,
    filter: Filter = .{},
    expiration_days: ?u32 = null,
    /// Midnight UTC, in nanoseconds.
    expiration_date_ns: ?i128 = null,
    expired_object_delete_marker: bool = false,
    noncurrent_days: ?u32 = null,
    newer_noncurrent_versions: ?u32 = null,
    abort_upload_days: ?u32 = null,
    /// Transition of the current version to the remote tier `transition_tier`.
    transition_days: ?u32 = null,
    transition_date_ns: ?i128 = null,
    transition_tier: []const u8 = "",
    /// NoncurrentVersionTransition to `noncurrent_transition_tier`.
    noncurrent_transition_days: ?u32 = null,
    noncurrent_transition_newer: ?u32 = null,
    noncurrent_transition_tier: []const u8 = "",

    pub fn hasTransition(r: Rule) bool {
        return r.transition_tier.len > 0 or r.noncurrent_transition_tier.len > 0;
    }
};

pub const max_tier_len = 64;

pub const Error = error{ InvalidRule, OutOfMemory };

pub fn encode(gpa: std.mem.Allocator, rules: []const Rule) Error![]u8 {
    if (rules.len > max_rules) return error.InvalidRule;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    const w = &a.writer;
    codec.putInt(w, u16, @intCast(rules.len)) catch return error.OutOfMemory;
    for (rules) |r| {
        if (r.id.len > max_id_len or r.filter.prefix.len > max_prefix_len) return error.InvalidRule;
        if (r.transition_tier.len > max_tier_len or r.noncurrent_transition_tier.len > max_tier_len) return error.InvalidRule;
        const t = tags_mod.encode(gpa, r.filter.tags) catch |e| return switch (e) {
            error.InvalidTag => error.InvalidRule,
            error.OutOfMemory => error.OutOfMemory,
        };
        defer gpa.free(t);
        encodeRule(w, r, t) catch return error.OutOfMemory;
    }
    return a.toOwnedSlice() catch error.OutOfMemory;
}

fn encodeRule(w: *std.Io.Writer, r: Rule, tags: []const u8) std.Io.Writer.Error!void {
    try codec.putInt(w, u16, @intCast(r.id.len));
    try w.writeAll(r.id);
    try w.writeByte(@as(u8, @intFromBool(r.enabled)) | @as(u8, @intFromBool(r.expired_object_delete_marker)) << 1 |
        @as(u8, @intFromBool(r.hasTransition())) << 2);
    try codec.putInt(w, u16, @intCast(r.filter.prefix.len));
    try w.writeAll(r.filter.prefix);
    try codec.putInt(w, u16, @intCast(tags.len));
    try w.writeAll(tags);
    var has: u8 = 0;
    inline for (.{ r.filter.size_gt, r.filter.size_lt, r.expiration_days, r.expiration_date_ns, r.noncurrent_days, r.newer_noncurrent_versions, r.abort_upload_days }, 0..) |v, i| {
        if (v != null) has |= 1 << i;
    }
    try w.writeByte(has);
    inline for (.{ r.filter.size_gt, r.filter.size_lt, r.expiration_days, r.expiration_date_ns, r.noncurrent_days, r.newer_noncurrent_versions, r.abort_upload_days }) |v| {
        if (v) |x| try codec.putInt(w, @TypeOf(x), x);
    }
    if (!r.hasTransition()) return;
    const tv = .{ r.transition_days, r.transition_date_ns, r.noncurrent_transition_days, r.noncurrent_transition_newer };
    var th: u8 = 0;
    inline for (tv, 0..) |v, i| {
        if (v != null) th |= 1 << i;
    }
    try w.writeByte(th);
    inline for (tv) |v| {
        if (v) |x| try codec.putInt(w, @TypeOf(x), x);
    }
    for ([_][]const u8{ r.transition_tier, r.noncurrent_transition_tier }) |t| {
        try w.writeByte(@intCast(t.len));
        try w.writeAll(t);
    }
}

/// Decodes into `arena`; strings borrow from `bytes`. Empty bytes mean no rules.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8) (codec.DecodeError || error{OutOfMemory})![]Rule {
    if (bytes.len == 0) return &.{};
    var c: codec.Cursor = .{ .bytes = bytes };
    const n = try c.int(u16);
    if (n > max_rules) return error.Corrupt;
    const out = try arena.alloc(Rule, n);
    for (out) |*r| {
        r.* = .{};
        r.id = try c.take(try c.int(u16));
        const flags = (try c.take(1))[0];
        if (flags & ~@as(u8, 7) != 0) return error.Corrupt;
        r.enabled = flags & 1 != 0;
        r.expired_object_delete_marker = flags & 2 != 0;
        r.filter.prefix = try c.take(try c.int(u16));
        r.filter.tags = try tags_mod.decode(arena, try c.take(try c.int(u16)));
        const has = (try c.take(1))[0];
        if (has & 0x80 != 0) return error.Corrupt;
        if (has & 1 != 0) r.filter.size_gt = try c.int(u64);
        if (has & 2 != 0) r.filter.size_lt = try c.int(u64);
        if (has & 4 != 0) r.expiration_days = try c.int(u32);
        if (has & 8 != 0) r.expiration_date_ns = try c.int(i128);
        if (has & 16 != 0) r.noncurrent_days = try c.int(u32);
        if (has & 32 != 0) r.newer_noncurrent_versions = try c.int(u32);
        if (has & 64 != 0) r.abort_upload_days = try c.int(u32);
        if (flags & 4 != 0) {
            const th = (try c.take(1))[0];
            if (th & 0xf0 != 0) return error.Corrupt;
            if (th & 1 != 0) r.transition_days = try c.int(u32);
            if (th & 2 != 0) r.transition_date_ns = try c.int(i128);
            if (th & 4 != 0) r.noncurrent_transition_days = try c.int(u32);
            if (th & 8 != 0) r.noncurrent_transition_newer = try c.int(u32);
            r.transition_tier = try c.take((try c.take(1))[0]);
            r.noncurrent_transition_tier = try c.take((try c.take(1))[0]);
            if (!r.hasTransition()) return error.Corrupt;
        }
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return out;
}

test "lifecycle rules roundtrip" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const rules = [_]Rule{
        .{ .id = "logs", .filter = .{ .prefix = "logs/", .tags = &.{.{ .key = "k", .value = "v" }}, .size_gt = 10 }, .expiration_days = 30 },
        .{ .enabled = false, .expiration_date_ns = 86400 * std.time.ns_per_s, .noncurrent_days = 7, .newer_noncurrent_versions = 2, .abort_upload_days = 3 },
        .{ .expired_object_delete_marker = true, .filter = .{ .size_lt = 5 } },
        .{ .transition_days = 3, .transition_tier = "WARM", .noncurrent_transition_days = 1, .noncurrent_transition_newer = 2, .noncurrent_transition_tier = "COLD" },
    };
    const b = try encode(gpa, &rules);
    defer gpa.free(b);
    const d = try decode(arena.allocator(), b);
    try std.testing.expectEqual(@as(usize, 4), d.len);
    try std.testing.expectEqualStrings("WARM", d[3].transition_tier);
    try std.testing.expectEqualStrings("COLD", d[3].noncurrent_transition_tier);
    try std.testing.expectEqual(@as(?u32, 2), d[3].noncurrent_transition_newer);
    try std.testing.expectEqual(@as(?i128, null), d[3].transition_date_ns);
    try std.testing.expectEqualStrings("logs/", d[0].filter.prefix);
    try std.testing.expectEqualStrings("v", d[0].filter.tags[0].value);
    try std.testing.expectEqual(@as(?u64, 10), d[0].filter.size_gt);
    try std.testing.expectEqual(@as(?u32, 30), d[0].expiration_days);
    try std.testing.expect(!d[1].enabled);
    try std.testing.expectEqual(@as(?u32, 2), d[1].newer_noncurrent_versions);
    try std.testing.expectEqual(@as(?i128, 86400 * std.time.ns_per_s), d[1].expiration_date_ns);
    try std.testing.expect(d[2].expired_object_delete_marker and d[2].expiration_days == null);
    for (0..b.len) |n| {
        if (decode(arena.allocator(), b[0..n])) |r| {
            try std.testing.expect(n == 0 and r.len == 0);
        } else |e| try std.testing.expectEqual(error.Corrupt, e);
    }
    try std.testing.expectError(error.InvalidRule, encode(gpa, &.{.{ .id = "x" ** 256 }}));
}
