//! Swift gateway helpers: URL decoding, query parameters, dates, escaping.
const std = @import("std");

pub const DecodeError = error{InvalidEncoding};

/// Percent-decodes `s` into `buf`; `plus_space` maps `+` to a space (query values).
pub fn percentDecode(buf: []u8, s: []const u8, plus_space: bool) DecodeError![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (n == buf.len) return error.InvalidEncoding;
        const c = s[i];
        if (c == '%') {
            if (i + 2 >= s.len) return error.InvalidEncoding;
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch return error.InvalidEncoding;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch return error.InvalidEncoding;
            buf[n] = hi * 16 + lo;
            i += 2;
        } else buf[n] = if (plus_space and c == '+') ' ' else c;
        n += 1;
    }
    return buf[0..n];
}

pub fn percentDecodeAlloc(a: std.mem.Allocator, s: []const u8, plus_space: bool) (DecodeError || error{OutOfMemory})![]const u8 {
    const buf = try a.alloc(u8, s.len);
    return percentDecode(buf, s, plus_space);
}

/// Writes `s` percent-encoded; `/` is kept when `keep_slash`.
pub fn percentEncode(w: *std.Io.Writer, s: []const u8, keep_slash: bool) std.Io.Writer.Error!void {
    for (s) |c| {
        const plain = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~' or (keep_slash and c == '/');
        if (plain) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

/// Value of query parameter `name` (raw, still encoded); "" for a bare flag.
pub fn queryRaw(qs: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, qs, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        const k = if (eq) |e| kv[0..e] else kv;
        if (std.mem.eql(u8, k, name)) return if (eq) |e| kv[e + 1 ..] else "";
    }
    return null;
}

/// Decoded query parameter, or null when absent or malformed.
pub fn query(a: std.mem.Allocator, q: []const u8, name: []const u8) ?[]const u8 {
    const raw = queryRaw(q, name) orelse return null;
    return percentDecodeAlloc(a, raw, true) catch null;
}

const days_in_month = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
pub fn daysFromCivil(y_in: i64, m: u32, d: u32) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = @intCast((m + 9) % 12);
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

pub const Civil = struct { year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32, wday: u32 };

pub fn civil(secs: i64) Civil {
    const s: u64 = @intCast(@max(secs, 0));
    const es: std.time.epoch.EpochSeconds = .{ .secs = s };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = @as(u32, md.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .min = ds.getMinutesIntoHour(),
        .sec = ds.getSecondsIntoMinute(),
        .wday = @intCast((ed.day + 4) % 7),
    };
}

const wday_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// IMF-fixdate, e.g. "Tue, 06 Oct 2026 12:00:00 GMT".
pub fn httpDate(buf: *[29]u8, secs: i64) []const u8 {
    const c = civil(secs);
    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        wday_names[c.wday], c.day, month_names[c.month - 1], c.year, c.hour, c.min, c.sec,
    }) catch buf[0..0];
}

/// Parses an IMF-fixdate into epoch seconds.
pub fn parseHttpDate(s: []const u8) ?i64 {
    var it = std.mem.tokenizeAny(u8, s, " ,:");
    _ = it.next() orelse return null;
    const d = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const mon = it.next() orelse return null;
    var m: u32 = 0;
    for (month_names, 1..) |n, i| if (std.ascii.eqlIgnoreCase(n, mon)) {
        m = @intCast(i);
    };
    if (m == 0) return null;
    const y = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const hh = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const mm = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    const ss = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    if (d == 0 or d > 31 or hh > 23 or mm > 59 or ss > 60) return null;
    return daysFromCivil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss;
}

/// Parses "YYYY-MM-DDTHH:MM:SS[.frac][Z|+00:00]" (UTC) into epoch seconds.
pub fn parseIso8601(s: []const u8) ?i64 {
    if (s.len < 19 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != ' ') or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const m = std.fmt.parseInt(u32, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u32, s[8..10], 10) catch return null;
    const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mm = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (m == 0 or m > 12 or d == 0 or d > days_in_month[m - 1] + @as(u32, if (m == 2) 1 else 0)) return null;
    if (hh > 23 or mm > 59 or ss > 60) return null;
    var rest = s[19..];
    if (rest.len > 0 and rest[0] == '.') {
        var i: usize = 1;
        while (i < rest.len and std.ascii.isDigit(rest[i])) i += 1;
        rest = rest[i..];
    }
    if (!(rest.len == 0 or std.mem.eql(u8, rest, "Z") or std.mem.eql(u8, rest, "+00:00") or std.mem.eql(u8, rest, "+0000"))) return null;
    return daysFromCivil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss;
}

/// Listing timestamp "2026-10-06T12:00:00.000000".
pub fn isoListing(buf: *[26]u8, ns: i128) []const u8 {
    const secs: i64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const micros: u64 = @intCast(@divFloor(@mod(ns, std.time.ns_per_s), 1000));
    const c = civil(secs);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{
        c.year, c.month, c.day, c.hour, c.min, c.sec, micros,
    }) catch buf[0..0];
}

/// X-Timestamp form "1700000000.12345".
pub fn timestamp(buf: *[32]u8, ns: i128) []const u8 {
    const secs: i64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const frac: u64 = @intCast(@divFloor(@mod(ns, std.time.ns_per_s), 10_000));
    return std.fmt.bufPrint(buf, "{d}.{d:0>5}", .{ secs, frac }) catch buf[0..0];
}

/// Bucket for a Swift container name: `_` becomes `-` so clients' default
/// `<name>_segments` containers satisfy bucket naming rules.
pub fn bucketName(a: std.mem.Allocator, name: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.indexOfScalar(u8, name, '_') == null) return name;
    const out = try a.dupe(u8, name);
    std.mem.replaceScalar(u8, out, '_', '-');
    return out;
}

pub fn xmlEscape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&apos;"),
        else => if (c < 0x20 and c != '\t' and c != '\n' and c != '\r') try w.print("&#x{X};", .{c}) else try w.writeByte(c),
    };
}

/// A JSON string literal, quotes included.
pub fn jsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try std.json.Stringify.encodeJsonString(s, .{}, w);
}

/// "content-type" -> "Content-Type" into `buf`.
pub fn titleCase(buf: []u8, name: []const u8) []const u8 {
    const n = @min(buf.len, name.len);
    var up = true;
    for (name[0..n], 0..) |c, i| {
        buf[i] = if (up) std.ascii.toUpper(c) else std.ascii.toLower(c);
        up = c == '-';
    }
    return buf[0..n];
}

/// True for header values safe to echo (no CR, LF, or NUL).
pub fn safeValue(v: []const u8) bool {
    for (v) |c| if (c == '\r' or c == '\n' or c == 0) return false;
    return true;
}

/// Parses 32 hex digits (optionally quoted) into an MD5.
pub fn parseMd5Hex(s_in: []const u8) ?[16]u8 {
    const s = std.mem.trim(u8, s_in, "\" ");
    if (s.len != 32) return null;
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

test "percent decode and encode" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("a b/c", try percentDecode(&buf, "a%20b%2fc", false));
    try std.testing.expectEqualStrings("a b", try percentDecode(&buf, "a+b", true));
    try std.testing.expectError(error.InvalidEncoding, percentDecode(&buf, "a%2", false));
    try std.testing.expectError(error.InvalidEncoding, percentDecode(&buf, "%zz", false));
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try percentEncode(&w, "a b/é", true);
    try std.testing.expectEqualStrings("a%20b/%C3%A9", w.buffered());
}

test "query params" {
    try std.testing.expectEqualStrings("10", queryRaw("format=json&limit=10", "limit").?);
    try std.testing.expectEqualStrings("", queryRaw("multipart-manifest&x=1", "multipart-manifest").?);
    try std.testing.expect(queryRaw("limitx=1", "limit") == null);
}

test "dates" {
    var b: [29]u8 = undefined;
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", httpDate(&b, 0));
    try std.testing.expectEqualStrings("Tue, 06 Oct 2026 12:30:05 GMT", httpDate(&b, 1791289805));
    try std.testing.expectEqual(@as(?i64, 1791289805), parseHttpDate("Tue, 06 Oct 2026 12:30:05 GMT"));
    try std.testing.expectEqual(@as(?i64, 1791289805), parseIso8601("2026-10-06T12:30:05.000000Z"));
    try std.testing.expectEqual(@as(?i64, 1791289805), parseIso8601("2026-10-06T12:30:05Z"));
    try std.testing.expect(parseIso8601("2026-13-06T12:30:05Z") == null);
    var l: [26]u8 = undefined;
    try std.testing.expectEqualStrings("2026-10-06T12:30:05.250000", isoListing(&l, 1791289805 * std.time.ns_per_s + 250 * std.time.ns_per_ms));
    var t: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1791289805.25000", timestamp(&t, 1791289805 * std.time.ns_per_s + 250 * std.time.ns_per_ms));
}

test "escaping and names" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try xmlEscape(&w, "a<b>&\"'\x01");
    try std.testing.expectEqualStrings("a&lt;b&gt;&amp;&quot;&apos;&#x1;", w.buffered());
    var tb: [32]u8 = undefined;
    try std.testing.expectEqualStrings("X-Object-Meta-Color", titleCase(&tb, "x-object-meta-color"));
    try std.testing.expect(parseMd5Hex("\"d41d8cd98f00b204e9800998ecf8427e\"") != null);
    try std.testing.expect(parseMd5Hex("zz") == null);
}
