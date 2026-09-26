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

pub const ParseError = error{InvalidDate};

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's algorithm).
fn daysFromCivil(y0: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y0 - 1 else y0;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn num(s: []const u8) ParseError!i64 {
    for (s) |c| if (!std.ascii.isDigit(c)) return error.InvalidDate;
    return std.fmt.parseInt(i64, s, 10) catch error.InvalidDate;
}

fn toNs(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) ParseError!i128 {
    if (y < 1970 or y > 9999 or mo < 1 or mo > 12 or d < 1 or d > 31 or h > 23 or mi > 59 or s > 60) return error.InvalidDate;
    const secs = daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
    return @as(i128, secs) * std.time.ns_per_s;
}

/// Parses `2030-01-02T03:04:05Z`, optionally with fractional seconds.
pub fn parseIso8601(s: []const u8) ParseError!i128 {
    if (s.len < 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return error.InvalidDate;
    if (s[s.len - 1] != 'Z') return error.InvalidDate;
    if (s.len > 20 and (s[19] != '.' or s.len > 30)) return error.InvalidDate;
    if (s.len > 20) _ = try num(s[20 .. s.len - 1]);
    return toNs(try num(s[0..4]), try num(s[5..7]), try num(s[8..10]), try num(s[11..13]), try num(s[14..16]), try num(s[17..19]));
}

/// Parses an RFC 7231 IMF-fixdate.
pub fn parseHttpDate(s: []const u8) ParseError!i128 {
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    if (s.len != 29 or s[3] != ',' or s[4] != ' ' or s[7] != ' ' or s[11] != ' ' or s[16] != ' ') return error.InvalidDate;
    if (s[19] != ':' or s[22] != ':' or !std.mem.eql(u8, s[25..], " GMT")) return error.InvalidDate;
    var mo: i64 = 0;
    for (months, 1..) |m, i| if (std.mem.eql(u8, m, s[8..11])) {
        mo = @intCast(i);
    };
    if (mo == 0) return error.InvalidDate;
    return toNs(try num(s[12..16]), mo, try num(s[5..7]), try num(s[17..19]), try num(s[20..22]), try num(s[23..25]));
}

test "time parsing" {
    const ns: i128 = 784111777 * std.time.ns_per_s;
    try std.testing.expectEqual(ns, try parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT"));
    try std.testing.expectEqual(ns, try parseIso8601("1994-11-06T08:49:37Z"));
    try std.testing.expectEqual(ns, try parseIso8601("1994-11-06T08:49:37.000Z"));
    try std.testing.expectError(error.InvalidDate, parseIso8601("1994-11-06 08:49:37Z"));
    try std.testing.expectError(error.InvalidDate, parseHttpDate("Sun, 06 Xyz 1994 08:49:37 GMT"));
    try std.testing.expectError(error.InvalidDate, parseIso8601("1994-13-06T08:49:37Z"));
}

test "time formatting" {
    const ns: i128 = 784111777 * std.time.ns_per_s;
    var b1: [29]u8 = undefined;
    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", httpDate(ns, &b1));
    var b2: [24]u8 = undefined;
    try std.testing.expectEqualStrings("1994-11-06T08:49:37.000Z", iso8601(ns, &b2));
}
