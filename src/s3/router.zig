//! Path-style routing: `/`, `/{bucket}`, `/{bucket}/{key}` plus query parsing.
const std = @import("std");

pub const Error = error{ InvalidUri, OutOfMemory };

pub const Target = struct {
    bucket: []const u8,
    key: []const u8,
    query: []const u8,
};

/// Decoded strings are allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, target: []const u8) Error!Target {
    if (target.len == 0 or target[0] != '/') return error.InvalidUri;
    const q = std.mem.indexOfScalar(u8, target, '?');
    const path = target[1 .. q orelse target.len];
    const query = if (q) |i| target[i + 1 ..] else "";
    const slash = std.mem.indexOfScalar(u8, path, '/');
    const raw_bucket = path[0 .. slash orelse path.len];
    const raw_key = if (slash) |i| path[i + 1 ..] else "";
    return .{
        .bucket = try percentDecode(arena, raw_bucket, false),
        .key = try percentDecode(arena, raw_key, false),
        .query = query,
    };
}

/// Returns the decoded value of `name`; "" for a bare flag, null if absent.
pub fn queryParam(arena: std.mem.Allocator, query: []const u8, name: []const u8) Error!?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const k = try percentDecode(arena, pair[0 .. eq orelse pair.len], true);
        if (!std.mem.eql(u8, k, name)) continue;
        return if (eq) |i| try percentDecode(arena, pair[i + 1 ..], true) else "";
    }
    return null;
}

pub fn percentDecode(arena: std.mem.Allocator, s: []const u8, plus_is_space: bool) Error![]const u8 {
    if (std.mem.indexOfAny(u8, s, "%+") == null) return s;
    const out = try arena.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '%') {
            if (s.len - i < 3) return error.InvalidUri;
            out[n] = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.InvalidUri;
            i += 2;
        } else if (c == '+' and plus_is_space) {
            out[n] = ' ';
        } else out[n] = c;
        n += 1;
    }
    return out[0..n];
}

test "route parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try parse(a, "/bkt/dir/my%20file.txt?list-type=2&prefix=a%2Fb+c");
    try std.testing.expectEqualStrings("bkt", t.bucket);
    try std.testing.expectEqualStrings("dir/my file.txt", t.key);
    try std.testing.expectEqualStrings("a/b c", (try queryParam(a, t.query, "prefix")).?);
    try std.testing.expectEqualStrings("2", (try queryParam(a, t.query, "list-type")).?);
    try std.testing.expect((try queryParam(a, t.query, "delimiter")) == null);
    const root = try parse(a, "/");
    try std.testing.expectEqualStrings("", root.bucket);
    const b = try parse(a, "/bkt?location");
    try std.testing.expectEqualStrings("", (try queryParam(a, b.query, "location")).?);
    try std.testing.expectError(error.InvalidUri, parse(a, "/b/%zz"));
    try std.testing.expectError(error.InvalidUri, parse(a, "/b/%2"));
    try std.testing.expectError(error.InvalidUri, parse(a, "nope"));
}
