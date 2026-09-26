//! Drive path expansion: `/data{1...4}` → /data1 .. /data4; several patterns multiply.
const std = @import("std");

pub const Error = error{ BadPattern, TooManyDrives, OutOfMemory };

pub const max_expansion = 1024;

/// Appends the expansion of `arg` to `out`; strings are allocated in `arena`.
pub fn expand(arena: std.mem.Allocator, arg: []const u8, out: *std.ArrayList([]const u8)) Error!void {
    var work: std.ArrayList([]const u8) = .empty;
    try work.append(arena, arg);
    while (work.pop()) |s| {
        const open = std.mem.indexOf(u8, s, "{") orelse {
            if (out.items.len >= max_expansion) return error.TooManyDrives;
            try out.append(arena, s);
            continue;
        };
        const close = std.mem.indexOfScalarPos(u8, s, open, '}') orelse return error.BadPattern;
        const body = s[open + 1 .. close];
        const dots = std.mem.indexOf(u8, body, "...") orelse return error.BadPattern;
        const lo_s = body[0..dots];
        const hi_s = body[dots + 3 ..];
        const lo = std.fmt.parseInt(u32, lo_s, 10) catch return error.BadPattern;
        const hi = std.fmt.parseInt(u32, hi_s, 10) catch return error.BadPattern;
        if (hi < lo or hi - lo >= max_expansion) return error.BadPattern;
        // Zero padding follows the lower bound: {01...12} → 01..12.
        const pad: usize = if (lo_s.len > 1 and lo_s[0] == '0') lo_s.len else 0;
        // Push in reverse so the stack yields ascending order.
        var i = hi + 1;
        while (i > lo) {
            i -= 1;
            if (work.items.len + out.items.len >= max_expansion) return error.TooManyDrives;
            const n = try std.fmt.allocPrint(arena, "{s}{d:0>[3]}{s}", .{ s[0..open], i, s[close + 1 ..], pad });
            try work.append(arena, n);
        }
    }
}

test "ellipsis expansion" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var out: std.ArrayList([]const u8) = .empty;
    try expand(a, "/data{1...4}", &out);
    try std.testing.expectEqual(@as(usize, 4), out.items.len);
    try std.testing.expectEqualStrings("/data1", out.items[0]);
    try std.testing.expectEqualStrings("/data4", out.items[3]);

    out.clearRetainingCapacity();
    try expand(a, "/d{1...2}/x{01...02}", &out);
    try std.testing.expectEqual(@as(usize, 4), out.items.len);
    try std.testing.expectEqualStrings("/d1/x01", out.items[0]);
    try std.testing.expectEqualStrings("/d2/x02", out.items[3]);

    out.clearRetainingCapacity();
    try expand(a, "/plain", &out);
    try std.testing.expectEqualStrings("/plain", out.items[0]);
    try std.testing.expectError(error.BadPattern, expand(a, "/d{4...1}", &out));
    try std.testing.expectError(error.BadPattern, expand(a, "/d{1..2}", &out));
}
