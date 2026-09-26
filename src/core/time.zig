//! Wall-clock helpers and HTTP/ISO-8601 formatting.
const std = @import("std");
const epoch = std.time.epoch;

pub fn nowNs() i128 {
    return std.time.nanoTimestamp();
}

const Parts = struct { year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8, wday: u8 };

fn split(ns: i128) Parts {
    const secs_i: i128 = @divFloor(ns, std.time.ns_per_s);
    const secs: u64 = if (secs_i < 0) 0 else std.math.cast(u64, secs_i) orelse 0;
    const es = epoch.EpochSeconds{ .secs = secs };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = @as(u8, md.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .min = ds.getMinutesIntoHour(),
        .sec = ds.getSecondsIntoMinute(),
        .wday = @intCast((ed.day + 4) % 7), // 1970-01-01 was a Thursday
    };
}

/// ISO-8601 as used in S3 XML: 2006-02-03T16:45:09.000Z
pub fn iso8601(ns: i128, buf: *[24]u8) []const u8 {
    const p = split(ns);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{
        p.year, p.month, p.day, p.hour, p.min, p.sec,
    }) catch unreachable; // fixed width fits
}

/// RFC 7231 IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
pub fn httpDate(ns: i128, buf: *[29]u8) []const u8 {
    const days = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const p = split(ns);
    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        days[p.wday], p.day, months[p.month - 1], p.year, p.hour, p.min, p.sec,
    }) catch unreachable; // fixed width fits
}

test "time formatting" {
    const ns: i128 = 784111777 * std.time.ns_per_s;
    var b1: [29]u8 = undefined;
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", httpDate(ns, &b1));
    var b2: [24]u8 = undefined;
    try std.testing.expectEqualStrings("1994-11-06T08:49:37.000Z", iso8601(ns, &b2));
}
