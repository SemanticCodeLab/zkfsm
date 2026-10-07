//! Pure encoding helpers for the admin wire formats (Go time, durations, UUIDs).
const std = @import("std");
const placement = @import("../placement/root.zig");

/// Go's zero `time.Time` in JSON.
pub const zero_time = "0001-01-01T00:00:00Z";

/// RFC 3339 UTC with milliseconds, as Go's `time.Time` marshals; 0 is the zero time.
pub fn time(buf: *[32]u8, ms: i64) []const u8 {
    if (ms <= 0) return zero_time;
    const secs: u64 = @intCast(@divTrunc(ms, 1000));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), @as(u64, @intCast(@mod(ms, 1000))),
    }) catch unreachable;
}

pub fn timeAlloc(a: std.mem.Allocator, ms: i64) error{OutOfMemory}![]const u8 {
    var b: [32]u8 = undefined;
    return a.dupe(u8, time(&b, ms));
}

/// 16 id bytes in the 8-4-4-4-12 UUID text form.
pub fn uuid(buf: *[36]u8, id: [16]u8) []const u8 {
    const h = std.fmt.bytesToHex(id, .lower);
    _ = std.fmt.bufPrint(buf, "{s}-{s}-{s}-{s}-{s}", .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] }) catch unreachable;
    return buf;
}

/// Parses a Go `time.Duration` string such as "3s", "1m30s", "500ms"; null when invalid.
pub fn goDuration(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    if (std.mem.eql(u8, s, "0")) return 0;
    var total: f64 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const start = i;
        while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '.')) i += 1;
        if (i == start) return null;
        const num = std.fmt.parseFloat(f64, s[start..i]) catch return null;
        const ustart = i;
        while (i < s.len and !std.ascii.isDigit(s[i]) and s[i] != '.') i += 1;
        const unit = s[ustart..i];
        const mult: f64 = if (std.mem.eql(u8, unit, "ns")) 1 else if (std.mem.eql(u8, unit, "us") or std.mem.eql(u8, unit, "µs")) 1e3 else if (std.mem.eql(u8, unit, "ms")) 1e6 else if (std.mem.eql(u8, unit, "s")) 1e9 else if (std.mem.eql(u8, unit, "m")) 60e9 else if (std.mem.eql(u8, unit, "h")) 3600e9 else return null;
        total += num * mult;
    }
    return @intFromFloat(total);
}

/// Parity drives per object in the madmin sense; replicas count copies beyond the first.
pub fn parity(p: placement.Profile) u8 {
    return switch (p) {
        .single => 0,
        .replica => |n| n - 1,
        .erasure => |e| e.parity,
    };
}

/// Data and parity blocks reported on heal items. mc colours items only for parity
/// 1..8, so a single copy reports one parity block and no data block: present is
/// green, missing is red.
pub fn blocks(p: placement.Profile) struct { data: u8, parity: u8 } {
    return switch (p) {
        .single => .{ .data = 0, .parity = 1 },
        .replica => |n| .{ .data = 1, .parity = n - 1 },
        .erasure => |e| .{ .data = e.data, .parity = e.parity },
    };
}

test "go time and durations" {
    var b: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2023-11-14T22:13:20.123Z", time(&b, 1_700_000_000_123));
    try std.testing.expectEqualStrings(zero_time, time(&b, 0));
    try std.testing.expectEqual(@as(?u64, 3 * std.time.ns_per_s), goDuration("3s"));
    try std.testing.expectEqual(@as(?u64, 90 * std.time.ns_per_s), goDuration("1m30s"));
    try std.testing.expectEqual(@as(?u64, 500 * std.time.ns_per_ms), goDuration("500ms"));
    try std.testing.expectEqual(@as(?u64, 1500 * std.time.ns_per_ms), goDuration("1.5s"));
    try std.testing.expect(goDuration("3x") == null);
    try std.testing.expect(goDuration("") == null);
}

test "uuid and parity" {
    var u: [36]u8 = undefined;
    try std.testing.expectEqualStrings("00112233-4455-6677-8899-aabbccddeeff", uuid(&u, .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }));
    try std.testing.expectEqual(@as(u8, 2), parity(.{ .erasure = .{ .data = 4, .parity = 2 } }));
    try std.testing.expectEqual(@as(u8, 1), parity(.{ .replica = 2 }));
    const s = blocks(.single);
    try std.testing.expect(s.parity >= 1 and s.parity <= 8);
}
