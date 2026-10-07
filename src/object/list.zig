//! ListObjectsV2 semantics over a set of keys: prefix, delimiter, start-after, max-keys.
const std = @import("std");
const core = @import("../core/root.zig");

pub const Entry = struct {
    key: []const u8,
    size: u64,
    etag: core.ETag,
    mtime_ns: i128,
    tiered: bool = false,
};

pub const Params = struct {
    prefix: []const u8 = "",
    delimiter: []const u8 = "",
    start_after: []const u8 = "",
    max_keys: usize = 1000,
};

pub const Result = struct {
    contents: []Entry,
    common_prefixes: [][]const u8,
    is_truncated: bool,
    /// Last key or prefix returned; the continuation point when truncated.
    next_marker: ?[]const u8,
};

fn lessKey(_: void, a: Entry, b: Entry) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}

/// Sorts `entries` in place; result slices borrow from `entries` and `arena`.
pub fn apply(arena: std.mem.Allocator, entries: []Entry, p: Params) error{OutOfMemory}!Result {
    std.mem.sort(Entry, entries, {}, lessKey);
    var contents: std.ArrayList(Entry) = .empty;
    var prefixes: std.ArrayList([]const u8) = .empty;
    var truncated = false;
    var last: ?[]const u8 = null;

    for (entries) |e| {
        if (!std.mem.startsWith(u8, e.key, p.prefix)) continue;
        if (p.start_after.len > 0 and !std.mem.lessThan(u8, p.start_after, e.key)) continue;
        var cp: ?[]const u8 = null;
        if (p.delimiter.len > 0) {
            if (std.mem.indexOf(u8, e.key[p.prefix.len..], p.delimiter)) |i| {
                cp = e.key[0 .. p.prefix.len + i + p.delimiter.len];
            }
        }
        if (cp) |c| {
            if (last != null and std.mem.eql(u8, last.?, c)) continue;
            if (p.start_after.len > 0 and !std.mem.lessThan(u8, p.start_after, c)) continue;
        }
        if (contents.items.len + prefixes.items.len >= p.max_keys) {
            truncated = true;
            break;
        }
        if (cp) |c| {
            try prefixes.append(arena, c);
            last = c;
        } else {
            try contents.append(arena, e);
            last = e.key;
        }
    }
    return .{
        .contents = contents.items,
        .common_prefixes = prefixes.items,
        .is_truncated = truncated,
        .next_marker = last,
    };
}

fn mk(keys: []const []const u8, out: []Entry) []Entry {
    for (keys, 0..) |k, i| out[i] = .{ .key = k, .size = 0, .etag = .{ .md5 = [_]u8{0} ** 16 }, .mtime_ns = 0 };
    return out[0..keys.len];
}

test "list prefix and delimiter" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buf: [8]Entry = undefined;
    const e = mk(&.{ "b/2", "a.txt", "b/1", "c/x/y", "c/z", "d" }, &buf);
    const r = try apply(arena.allocator(), e, .{ .delimiter = "/" });
    try std.testing.expectEqual(@as(usize, 2), r.contents.len);
    try std.testing.expectEqualStrings("a.txt", r.contents[0].key);
    try std.testing.expectEqualStrings("d", r.contents[1].key);
    try std.testing.expectEqual(@as(usize, 2), r.common_prefixes.len);
    try std.testing.expectEqualStrings("b/", r.common_prefixes[0]);
    try std.testing.expectEqualStrings("c/", r.common_prefixes[1]);

    const r2 = try apply(arena.allocator(), e, .{ .prefix = "c/", .delimiter = "/" });
    try std.testing.expectEqual(@as(usize, 1), r2.contents.len);
    try std.testing.expectEqualStrings("c/z", r2.contents[0].key);
    try std.testing.expectEqualStrings("c/x/", r2.common_prefixes[0]);
}

test "list max_keys and continuation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var buf: [8]Entry = undefined;
    const e = mk(&.{ "a", "b/1", "b/2", "c" }, &buf);
    const r = try apply(arena.allocator(), e, .{ .delimiter = "/", .max_keys = 2 });
    try std.testing.expect(r.is_truncated);
    try std.testing.expectEqualStrings("b/", r.next_marker.?);
    const r2 = try apply(arena.allocator(), e, .{ .delimiter = "/", .start_after = r.next_marker.? });
    try std.testing.expect(!r2.is_truncated);
    try std.testing.expectEqual(@as(usize, 1), r2.contents.len);
    try std.testing.expectEqualStrings("c", r2.contents[0].key);
    try std.testing.expectEqual(@as(usize, 0), r2.common_prefixes.len);

    const r3 = try apply(arena.allocator(), e, .{ .max_keys = 0 });
    try std.testing.expect(r3.is_truncated);
    try std.testing.expectEqual(@as(usize, 0), r3.contents.len);
}
