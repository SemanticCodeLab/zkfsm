//! Walks a local bucket key by key with all versions of each key together
//! (newest first), resuming after a checkpoint key.
const std = @import("std");
const object = @import("../object/root.zig");

const ov = object.versioning;
pub const Version = ov.VersionEntry;

pub const page = 1000;
/// A key with more versions than this is handled in one oversized page.
pub const max_versions_per_key = 100_000;

pub const Error = object.Error;

/// Calls `visit(ctx, key, versions)` per key in order; it returns false to stop.
/// `start_after` skips keys up to and including it.
pub fn keys(svc: *object.ObjectService, gpa: std.mem.Allocator, bucket: []const u8, prefix: []const u8, start_after: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), []const u8, []const Version) bool) Error!void {
    var marker: std.ArrayList(u8) = .empty;
    defer marker.deinit(gpa);
    try marker.appendSlice(gpa, start_after);
    var max: usize = page;
    while (true) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const res = try ov.listVersions(svc, arena.allocator(), bucket, .{ .prefix = prefix, .key_marker = marker.items, .max_keys = max });
        const es = res.entries;
        if (es.len == 0) return;
        // The last key of a truncated page may continue on the next one.
        var end = es.len;
        if (res.is_truncated) {
            const last = es[es.len - 1].key;
            while (end > 0 and std.mem.eql(u8, es[end - 1].key, last)) end -= 1;
            if (end == 0) {
                if (max < max_versions_per_key) {
                    max = @min(max * 4, max_versions_per_key);
                    continue;
                }
                end = es.len;
            }
        }
        var i: usize = 0;
        while (i < end) {
            var n: usize = 1;
            while (i + n < end and std.mem.eql(u8, es[i + n].key, es[i].key)) n += 1;
            if (!visit(ctx, es[i].key, es[i .. i + n])) return;
            i += n;
        }
        if (!res.is_truncated) return;
        marker.clearRetainingCapacity();
        try marker.appendSlice(gpa, es[end - 1].key);
        max = page;
    }
}

test "walks every version once across pages" {
    const backend = @import("../backend/root.zig");
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try object.ObjectService.init(gpa, lb.backend());
    defer svc.deinit();
    try svc.createBucket("walkb");
    try ov.setVersioning(&svc, "walkb", .enabled);
    var names: [1203][8]u8 = undefined;
    for (&names, 0..) |*n, i| {
        _ = std.fmt.bufPrint(n, "k{d:0>7}", .{i / 3}) catch unreachable;
        var body: std.Io.Reader = .fixed("x");
        _ = try svc.put("walkb", n, &body, .{});
    }
    const C = struct {
        keys: usize = 0,
        versions: usize = 0,
        fn f(c: *@This(), key: []const u8, vs: []const Version) bool {
            _ = key;
            c.keys += 1;
            c.versions += vs.len;
            return true;
        }
    };
    var c: C = .{};
    try keys(&svc, gpa, "walkb", "", "", &c, C.f);
    try std.testing.expectEqual(@as(usize, 401), c.keys);
    try std.testing.expectEqual(@as(usize, 1203), c.versions);
    var d: C = .{};
    try keys(&svc, gpa, "walkb", "", "k0000199", &d, C.f);
    try std.testing.expectEqual(@as(usize, 201), d.keys);
}
