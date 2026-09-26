//! Tag sets: validation and a compact encoding (u8 count, then u16-length key/value pairs).
const std = @import("std");
const codec = @import("codec.zig");

pub const max_tags = 50;
pub const max_key_len = 128;
pub const max_value_len = 256;

pub const Tag = struct { key: []const u8, value: []const u8 };

pub const Error = error{ InvalidTag, OutOfMemory };

/// Validates `tags` against S3 limits (`limit` is 10 for objects, 50 for buckets).
pub fn validate(tags: []const Tag, limit: usize) error{InvalidTag}!void {
    if (tags.len > limit) return error.InvalidTag;
    for (tags, 0..) |t, i| {
        if (t.key.len == 0 or t.key.len > max_key_len or t.value.len > max_value_len) return error.InvalidTag;
        for (tags[0..i]) |p| if (std.mem.eql(u8, p.key, t.key)) return error.InvalidTag;
    }
}

pub fn encode(gpa: std.mem.Allocator, tags: []const Tag) Error![]u8 {
    try validate(tags, max_tags);
    if (tags.len == 0) return gpa.alloc(u8, 0);
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    const w = &a.writer;
    w.writeByte(@intCast(tags.len)) catch return error.OutOfMemory;
    for (tags) |t| {
        codec.putInt(w, u16, @intCast(t.key.len)) catch return error.OutOfMemory;
        w.writeAll(t.key) catch return error.OutOfMemory;
        codec.putInt(w, u16, @intCast(t.value.len)) catch return error.OutOfMemory;
        w.writeAll(t.value) catch return error.OutOfMemory;
    }
    return a.toOwnedSlice() catch error.OutOfMemory;
}

/// Decodes into `arena`; strings borrow from `bytes`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8) (codec.DecodeError || error{OutOfMemory})![]Tag {
    if (bytes.len == 0) return &.{};
    var c: codec.Cursor = .{ .bytes = bytes };
    const n = (try c.take(1))[0];
    const out = try arena.alloc(Tag, n);
    for (out) |*t| {
        t.key = try c.take(try c.int(u16));
        t.value = try c.take(try c.int(u16));
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return out;
}

test "tags roundtrip and validation" {
    const gpa = std.testing.allocator;
    const tags = [_]Tag{ .{ .key = "env", .value = "prod" }, .{ .key = "team", .value = "" } };
    const b = try encode(gpa, &tags);
    defer gpa.free(b);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d = try decode(arena.allocator(), b);
    try std.testing.expectEqual(@as(usize, 2), d.len);
    try std.testing.expectEqualStrings("prod", d[0].value);
    try std.testing.expectEqual(@as(usize, 0), (try decode(arena.allocator(), "")).len);
    try std.testing.expectError(error.Corrupt, decode(arena.allocator(), b[0 .. b.len - 1]));
    const dup = [_]Tag{ .{ .key = "a", .value = "" }, .{ .key = "a", .value = "" } };
    try std.testing.expectError(error.InvalidTag, validate(&dup, 10));
    try std.testing.expectError(error.InvalidTag, validate(&.{.{ .key = "", .value = "" }}, 10));
}
