//! Per-bucket configuration: versioning state, object lock, bucket tags, bucket
//! policy, and lifecycle rules.
const std = @import("std");
const codec = @import("codec.zig");
const record = @import("record.zig");

pub const magic = "ZKBG";
/// v2 adds the bucket policy and lifecycle rules; v1 configs still decode.
pub const format_version: u16 = 2;

pub const Versioning = enum(u8) { unset = 0, enabled = 1, suspended = 2 };

pub const BucketConfig = struct {
    versioning: Versioning = .unset,
    lock_enabled: bool = false,
    default_mode: record.RetentionMode = .none,
    /// Default retention period; exactly one of days/years is non-zero when a mode is set.
    default_days: u32 = 0,
    default_years: u32 = 0,
    /// Encoded tag set (see tags.zig); borrowed from the decoded bytes.
    tags: []const u8 = "",
    has_tags: bool = false,
    /// Bucket policy JSON; empty when none.
    policy: []const u8 = "",
    /// Encoded lifecycle rules (see lifecycle.zig); empty when none.
    lifecycle: []const u8 = "",
};

pub fn encode(cfg: BucketConfig, gpa: std.mem.Allocator) error{ OutOfMemory, InvalidTag }![]u8 {
    if (cfg.tags.len > std.math.maxInt(u16) or cfg.policy.len > std.math.maxInt(u16)) return error.InvalidTag;
    if (cfg.lifecycle.len > std.math.maxInt(u32)) return error.InvalidTag;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    encodeTo(cfg, &a.writer) catch return error.OutOfMemory;
    return a.toOwnedSlice() catch error.OutOfMemory;
}

fn encodeTo(cfg: BucketConfig, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(magic);
    try codec.putInt(w, u16, format_version);
    try w.writeByte(@intFromEnum(cfg.versioning));
    try w.writeByte(@intFromBool(cfg.lock_enabled));
    try w.writeByte(@intFromEnum(cfg.default_mode));
    try codec.putInt(w, u32, cfg.default_days);
    try codec.putInt(w, u32, cfg.default_years);
    try w.writeByte(@intFromBool(cfg.has_tags));
    try codec.putInt(w, u16, @intCast(cfg.tags.len));
    try w.writeAll(cfg.tags);
    try codec.putInt(w, u16, @intCast(cfg.policy.len));
    try w.writeAll(cfg.policy);
    try codec.putInt(w, u32, @intCast(cfg.lifecycle.len));
    try w.writeAll(cfg.lifecycle);
}

pub fn decode(bytes: []const u8) codec.DecodeError!BucketConfig {
    var c: codec.Cursor = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try c.take(4), magic)) return error.Corrupt;
    const ver = try c.int(u16);
    if (ver < 1 or ver > format_version) return error.Corrupt;
    var cfg: BucketConfig = .{};
    cfg.versioning = std.meta.intToEnum(Versioning, (try c.take(1))[0]) catch return error.Corrupt;
    cfg.lock_enabled = (try c.take(1))[0] != 0;
    cfg.default_mode = std.meta.intToEnum(record.RetentionMode, (try c.take(1))[0]) catch return error.Corrupt;
    cfg.default_days = try c.int(u32);
    cfg.default_years = try c.int(u32);
    cfg.has_tags = (try c.take(1))[0] != 0;
    cfg.tags = try c.take(try c.int(u16));
    if (ver >= 2) {
        cfg.policy = try c.take(try c.int(u16));
        cfg.lifecycle = try c.take(try c.int(u32));
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return cfg;
}

test "bucket config roundtrip" {
    const gpa = std.testing.allocator;
    const cfg: BucketConfig = .{ .versioning = .enabled, .lock_enabled = true, .default_mode = .governance, .default_days = 3, .tags = "ab", .has_tags = true, .policy = "{}", .lifecycle = "LC" };
    const b = try encode(cfg, gpa);
    defer gpa.free(b);
    const d = try decode(b);
    try std.testing.expectEqual(Versioning.enabled, d.versioning);
    try std.testing.expect(d.lock_enabled and d.has_tags);
    try std.testing.expectEqual(@as(u32, 3), d.default_days);
    try std.testing.expectEqualStrings("ab", d.tags);
    try std.testing.expectEqualStrings("{}", d.policy);
    try std.testing.expectEqualStrings("LC", d.lifecycle);
    for (0..b.len) |n| try std.testing.expectError(error.Corrupt, decode(b[0..n]));
    // A v1 config is the v2 one without the policy and lifecycle tail.
    const v1 = try gpa.dupe(u8, b[0 .. b.len - (2 + 2 + 4 + 2)]);
    defer gpa.free(v1);
    v1[4] = 1;
    const o = try decode(v1);
    try std.testing.expectEqualStrings("ab", o.tags);
    try std.testing.expectEqualStrings("", o.policy);
}
