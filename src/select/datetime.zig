//! Timestamps for S3 Select: UTC instant in microseconds plus the original
//! offset and precision, formatted in the Ion text style S3 Select emits.
const std = @import("std");

pub const Precision = enum(u8) { year, month, day, minute, second, frac };

pub const Timestamp = struct {
    /// Microseconds since 1970-01-01T00:00:00Z.
    micros: i64,
    offset_min: i16 = 0,
    precision: Precision = .second,
    frac_digits: u8 = 0,
};

pub const Part = enum { year, month, day, hour, minute, second, timezone_hour, timezone_minute };

pub const Error = error{ InvalidTimestamp, Overflow };

pub const us_per_sec: i64 = 1_000_000;
pub const us_per_min: i64 = 60 * us_per_sec;
pub const us_per_hour: i64 = 60 * us_per_min;
pub const us_per_day: i64 = 24 * us_per_hour;

// Supported year range keeps all arithmetic far from i64 overflow.
const min_year: i64 = 0;
const max_year: i64 = 9999;

/// Instants representable as years 0000..9999 in any offset.
pub fn inRange(micros: i64) bool {
    const lo = -62167219200 * us_per_sec + us_per_day;
    const hi = 253402300799 * us_per_sec - us_per_day;
    return micros >= lo and micros <= hi;
}

pub fn daysFromCivil(y: i64, m: u32, d: u32) i64 {
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = @intCast((m + 9) % 12);
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

pub const Civil = struct { year: i64, month: u32, day: u32 };

pub fn civilFromDays(z0: i64) Civil {
    const z = z0 + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return .{ .year = y, .month = @intCast(m), .day = @intCast(d) };
}

fn isLeap(y: i64) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

pub fn daysInMonth(y: i64, m: u32) u32 {
    const t = [_]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (m == 2 and isLeap(y)) return 29;
    return t[m - 1];
}

/// Broken-down local time (in the timestamp's own offset).
pub const Fields = struct { year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32, micro: u32 };

pub fn fields(ts: Timestamp) Fields {
    const local = ts.micros + @as(i64, ts.offset_min) * us_per_min;
    const days = @divFloor(local, us_per_day);
    const rem: u64 = @intCast(local - days * us_per_day);
    const c = civilFromDays(days);
    return .{
        .year = c.year,
        .month = c.month,
        .day = c.day,
        .hour = @intCast(rem / @as(u64, us_per_hour)),
        .minute = @intCast((rem / @as(u64, us_per_min)) % 60),
        .second = @intCast((rem / @as(u64, us_per_sec)) % 60),
        .micro = @intCast(rem % @as(u64, us_per_sec)),
    };
}

fn fromFields(f: Fields, offset_min: i16) Error!i64 {
    if (f.year < min_year or f.year > max_year) return error.Overflow;
    const days = daysFromCivil(f.year, f.month, f.day);
    const local = days * us_per_day + @as(i64, f.hour) * us_per_hour + @as(i64, f.minute) * us_per_min +
        @as(i64, f.second) * us_per_sec + f.micro;
    return local - @as(i64, offset_min) * us_per_min;
}

/// Parses the ISO 8601 subset accepted by S3 Select TO_TIMESTAMP.
pub fn parse(s_in: []const u8) Error!Timestamp {
    const s = std.mem.trim(u8, s_in, " \t");
    var p: Cursor = .{ .s = s };
    var f: Fields = .{ .year = 0, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0, .micro = 0 };
    var ts: Timestamp = .{ .micros = 0, .precision = .year };
    f.year = try p.digits(4);
    if (p.eat('-')) {
        f.month = @intCast(try p.digits(2));
        ts.precision = .month;
        if (p.eat('-')) {
            f.day = @intCast(try p.digits(2));
            ts.precision = .day;
        }
    }
    if (f.month < 1 or f.month > 12) return error.InvalidTimestamp;
    if (f.day < 1 or f.day > daysInMonth(f.year, f.month)) return error.InvalidTimestamp;
    const has_t = p.eat('T') or p.eat('t') or (ts.precision == .day and p.peekIs(' ') and p.eat(' '));
    if (has_t and ts.precision == .day and p.more()) {
        f.hour = @intCast(try p.digits(2));
        if (!p.eat(':')) return error.InvalidTimestamp;
        f.minute = @intCast(try p.digits(2));
        ts.precision = .minute;
        if (p.eat(':')) {
            f.second = @intCast(try p.digits(2));
            ts.precision = .second;
            if (p.eat('.')) {
                const start = p.i;
                var micro: u32 = 0;
                var n: u8 = 0;
                while (p.more() and std.ascii.isDigit(p.s[p.i])) : (p.i += 1) {
                    if (n < 6) {
                        micro = micro * 10 + (p.s[p.i] - '0');
                        n += 1;
                    }
                }
                if (p.i == start) return error.InvalidTimestamp;
                var k = n;
                while (k < 6) : (k += 1) micro *= 10;
                f.micro = micro;
                ts.precision = .frac;
                ts.frac_digits = n;
            }
        }
        if (f.hour > 23 or f.minute > 59 or f.second > 59) return error.InvalidTimestamp;
        if (p.eat('Z') or p.eat('z')) {
            ts.offset_min = 0;
        } else if (p.more() and (p.s[p.i] == '+' or p.s[p.i] == '-')) {
            const neg = p.s[p.i] == '-';
            p.i += 1;
            const oh = try p.digits(2);
            _ = p.eat(':');
            const om = try p.digits(2);
            if (oh > 23 or om > 59) return error.InvalidTimestamp;
            const off: i16 = @intCast(oh * 60 + om);
            ts.offset_min = if (neg) -off else off;
        }
    } else if (ts.precision != .day and !has_t and p.more()) {
        return error.InvalidTimestamp;
    }
    if (p.more()) return error.InvalidTimestamp;
    ts.micros = try fromFields(f, ts.offset_min);
    return ts;
}

const Cursor = struct {
    s: []const u8,
    i: usize = 0,
    fn more(c: *const Cursor) bool {
        return c.i < c.s.len;
    }
    fn peekIs(c: *const Cursor, ch: u8) bool {
        return c.i < c.s.len and c.s[c.i] == ch;
    }
    fn eat(c: *Cursor, ch: u8) bool {
        if (c.peekIs(ch)) {
            c.i += 1;
            return true;
        }
        return false;
    }
    fn digits(c: *Cursor, n: usize) Error!i64 {
        if (c.i + n > c.s.len) return error.InvalidTimestamp;
        var v: i64 = 0;
        for (c.s[c.i .. c.i + n]) |ch| {
            if (!std.ascii.isDigit(ch)) return error.InvalidTimestamp;
            v = v * 10 + (ch - '0');
        }
        c.i += n;
        return v;
    }
};

pub fn format(ts: Timestamp, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const f = fields(ts);
    const y: u64 = @intCast(std.math.clamp(f.year, 0, 9999));
    try w.print("{d:0>4}", .{y});
    switch (ts.precision) {
        .year => return w.writeAll("T"),
        .month => return w.print("-{d:0>2}T", .{f.month}),
        .day => return w.print("-{d:0>2}-{d:0>2}T", .{ f.month, f.day }),
        else => {},
    }
    try w.print("-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}", .{ f.month, f.day, f.hour, f.minute });
    if (ts.precision == .second or ts.precision == .frac) try w.print(":{d:0>2}", .{f.second});
    if (ts.precision == .frac and ts.frac_digits > 0) {
        var buf: [6]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{d:0>6}", .{f.micro}) catch unreachable;
        try w.print(".{s}", .{buf[0..@min(ts.frac_digits, 6)]});
    }
    if (ts.offset_min == 0) return w.writeAll("Z");
    const off: u32 = @abs(ts.offset_min);
    try w.print("{c}{d:0>2}:{d:0>2}", .{ @as(u8, if (ts.offset_min < 0) '-' else '+'), off / 60, off % 60 });
}

fn precisionOf(part: Part) Precision {
    return switch (part) {
        .year => .year,
        .month => .month,
        .day => .day,
        .hour, .minute => .minute,
        else => .second,
    };
}

fn addMonths(ts: Timestamp, months: i64) Error!Timestamp {
    var f = fields(ts);
    const total = std.math.add(i64, f.year * 12 + (f.month - 1), months) catch return error.Overflow;
    f.year = @divFloor(total, 12);
    if (f.year < min_year or f.year > max_year) return error.Overflow;
    f.month = @intCast(@mod(total, 12) + 1);
    f.day = @min(f.day, daysInMonth(f.year, f.month));
    var out = ts;
    out.micros = try fromFields(f, ts.offset_min);
    return out;
}

pub fn add(ts: Timestamp, part: Part, qty: i64) Error!Timestamp {
    var out = switch (part) {
        .year => try addMonths(ts, std.math.mul(i64, qty, 12) catch return error.Overflow),
        .month => try addMonths(ts, qty),
        else => blk: {
            const unit: i64 = switch (part) {
                .day => us_per_day,
                .hour => us_per_hour,
                .minute => us_per_min,
                .second => us_per_sec,
                else => return error.InvalidTimestamp,
            };
            const delta = std.math.mul(i64, qty, unit) catch return error.Overflow;
            var r = ts;
            r.micros = std.math.add(i64, ts.micros, delta) catch return error.Overflow;
            if (!inRange(r.micros)) return error.Overflow;
            break :blk r;
        },
    };
    const want = precisionOf(part);
    if (@intFromEnum(want) > @intFromEnum(out.precision)) out.precision = want;
    return out;
}

/// Number of whole `part` boundaries from a to b (b - a), truncated toward zero.
pub fn diff(part: Part, a: Timestamp, b: Timestamp) Error!i64 {
    switch (part) {
        .year, .month => {
            const fa = fields(.{ .micros = a.micros });
            const fb = fields(.{ .micros = b.micros });
            var months = (fb.year - fa.year) * 12 + (@as(i64, fb.month) - @as(i64, fa.month));
            const rest_a = a.micros - (daysFromCivil(fa.year, fa.month, 1) * us_per_day);
            const rest_b = b.micros - (daysFromCivil(fb.year, fb.month, 1) * us_per_day);
            if (months > 0 and rest_b < rest_a) months -= 1;
            if (months < 0 and rest_b > rest_a) months += 1;
            return if (part == .year) @divTrunc(months, 12) else months;
        },
        .day => return @divTrunc(b.micros - a.micros, us_per_day),
        .hour => return @divTrunc(b.micros - a.micros, us_per_hour),
        .minute => return @divTrunc(b.micros - a.micros, us_per_min),
        .second => return @divTrunc(b.micros - a.micros, us_per_sec),
        else => return error.InvalidTimestamp,
    }
}

pub fn extract(part: Part, ts: Timestamp) i64 {
    const f = fields(ts);
    return switch (part) {
        .year => f.year,
        .month => f.month,
        .day => f.day,
        .hour => f.hour,
        .minute => f.minute,
        .second => f.second,
        .timezone_hour => @divTrunc(@as(i64, ts.offset_min), 60),
        .timezone_minute => @rem(@as(i64, ts.offset_min), 60),
    };
}

pub fn partFromName(name: []const u8) ?Part {
    inline for (@typeInfo(Part).@"enum".fields) |fld| {
        if (std.ascii.eqlIgnoreCase(name, fld.name)) return @enumFromInt(fld.value);
    }
    return null;
}

fn roundTrip(s: []const u8) ![]const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    var w: std.Io.Writer = .fixed(&S.buf);
    try format(try parse(s), &w);
    return w.buffered();
}

test "civil round trip" {
    var d: i64 = -800000;
    while (d < 3000000) : (d += 997) {
        const c = civilFromDays(d);
        try std.testing.expectEqual(d, daysFromCivil(c.year, c.month, c.day));
    }
    try std.testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
}

test "parse and format precisions" {
    try std.testing.expectEqualStrings("2007T", try roundTrip("2007T"));
    try std.testing.expectEqualStrings("2007-02T", try roundTrip("2007-02T"));
    try std.testing.expectEqualStrings("2007-02-23T", try roundTrip("2007-02-23"));
    try std.testing.expectEqualStrings("2007-02-23T12:14Z", try roundTrip("2007-02-23T12:14Z"));
    try std.testing.expectEqualStrings("2007-02-23T12:14:33.079-08:00", try roundTrip("2007-02-23T12:14:33.079-08:00"));
    try std.testing.expectError(error.InvalidTimestamp, parse("2007-13-01"));
    try std.testing.expectError(error.InvalidTimestamp, parse("2007-02-30T"));
    try std.testing.expectError(error.InvalidTimestamp, parse("garbage"));
    try std.testing.expectError(error.InvalidTimestamp, parse("2007-02-23T12:14:33Zjunk"));
}

test "add diff extract" {
    const t = try parse("2020-01-31T10:00:00Z");
    const t2 = try add(t, .month, 1);
    try std.testing.expectEqual(@as(i64, 29), extract(.day, t2));
    try std.testing.expectEqual(@as(i64, 0), try diff(.month, t, t2));
    try std.testing.expectEqual(@as(i64, 2), try diff(.month, t, try add(t, .month, 2)));
    try std.testing.expectEqual(@as(i64, 0), try diff(.year, try parse("2020-06-01T"), try parse("2021-05-31T")));
    try std.testing.expectEqual(@as(i64, 1), try diff(.year, try parse("2020-06-01T"), try parse("2021-06-01T")));
    try std.testing.expectEqual(@as(i64, 36), try diff(.hour, try parse("2020-01-01T"), try parse("2020-01-02T12:00Z")));
    try std.testing.expectEqual(@as(i64, -8), extract(.timezone_hour, try parse("2007-02-23T12:14:33-08:00")));
    try std.testing.expectEqual(@as(i64, 12), extract(.hour, try parse("2007-02-23T12:14:33-08:00")));
    try std.testing.expectError(error.Overflow, add(t, .year, 1 << 60));
}
