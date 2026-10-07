//! FTP wire helpers: command parsing, passive replies, listing lines, timestamps.
//! Pure functions so they can be unit tested without sockets.
const std = @import("std");
const fs = @import("fs.zig");

/// Longest accepted command line, CRLF included.
pub const max_line = 4096;

pub const Verb = enum {
    USER,
    PASS,
    ACCT,
    SYST,
    FEAT,
    OPTS,
    PWD,
    XPWD,
    CWD,
    XCWD,
    CDUP,
    XCUP,
    TYPE,
    MODE,
    STRU,
    PASV,
    EPSV,
    PORT,
    EPRT,
    LIST,
    NLST,
    MLSD,
    MLST,
    RETR,
    REST,
    STOR,
    APPE,
    STOU,
    DELE,
    MKD,
    XMKD,
    RMD,
    XRMD,
    RNFR,
    RNTO,
    SIZE,
    MDTM,
    NOOP,
    QUIT,
    ABOR,
    STAT,
    HELP,
    AUTH,
    PBSZ,
    PROT,
    CCC,
    ALLO,
    REIN,
    SITE,
};

pub const Command = struct {
    verb: ?Verb,
    /// The verb as sent, for "unknown command" replies (bounded).
    raw: []const u8,
    arg: []const u8,
};

pub const ParseError = error{ Empty, BadChars };

/// Splits "VERB arg" (line without CRLF). Verbs are case-insensitive.
pub fn parse(line: []const u8) ParseError!Command {
    if (std.mem.indexOfAny(u8, line, "\r\n\x00") != null) return error.BadChars;
    const sp = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
    const raw = line[0..sp];
    if (raw.len == 0) return error.Empty;
    const arg = if (sp < line.len) line[sp + 1 ..] else "";
    var up: [8]u8 = undefined;
    if (raw.len > up.len) return .{ .verb = null, .raw = raw[0..up.len], .arg = arg };
    for (raw, 0..) |c, i| up[i] = std.ascii.toUpper(c);
    return .{ .verb = std.meta.stringToEnum(Verb, up[0..raw.len]), .raw = raw, .arg = arg };
}

/// Drops leading `-flags` words (as in "LIST -la dir").
pub fn listArg(arg: []const u8) []const u8 {
    var rest = std.mem.trim(u8, arg, " ");
    while (rest.len > 0 and rest[0] == '-') {
        const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return "";
        rest = std.mem.trimLeft(u8, rest[sp + 1 ..], " ");
    }
    return rest;
}

/// "A-B" with 1024 <= A <= B.
pub fn parsePortRange(s: []const u8) error{BadRange}![2]u16 {
    const dash = std.mem.indexOfScalar(u8, s, '-') orelse return error.BadRange;
    const lo = std.fmt.parseInt(u16, s[0..dash], 10) catch return error.BadRange;
    const hi = std.fmt.parseInt(u16, s[dash + 1 ..], 10) catch return error.BadRange;
    if (lo < 1024 or hi < lo) return error.BadRange;
    return .{ lo, hi };
}

pub fn pasvReply(buf: []u8, ip: [4]u8, port: u16) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "227 Entering Passive Mode ({d},{d},{d},{d},{d},{d}).", .{ ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xff });
}

pub fn epsvReply(buf: []u8, port: u16) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(buf, "229 Entering Extended Passive Mode (|||{d}|)", .{port});
}

/// IPv4 bytes of an address, if it is IPv4 (or IPv4-mapped IPv6).
pub fn ip4Of(a: std.net.Address) ?[4]u8 {
    switch (a.any.family) {
        std.posix.AF.INET => return @bitCast(a.in.sa.addr),
        std.posix.AF.INET6 => {
            const b = a.in6.sa.addr;
            if (std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff) return b[12..16].*;
            return null;
        },
        else => return null,
    }
}

/// Same host, ports ignored; IPv4-mapped IPv6 equals its IPv4 form.
pub fn sameHost(a: std.net.Address, b: std.net.Address) bool {
    if (ip4Of(a)) |x| return if (ip4Of(b)) |y| std.mem.eql(u8, &x, &y) else false;
    if (a.any.family != std.posix.AF.INET6 or b.any.family != std.posix.AF.INET6) return false;
    return std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr);
}

pub const Civil = struct { year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8 };

pub fn civil(secs: i64) Civil {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(std.math.clamp(secs, 0, 253402300799)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = md.day_index + 1,
        .hour = ds.getHoursIntoDay(),
        .min = ds.getMinutesIntoHour(),
        .sec = ds.getSecondsIntoMinute(),
    };
}

pub fn secsOf(ns: i128) i64 {
    return @intCast(@divFloor(@max(ns, 0), std.time.ns_per_s));
}

/// MDTM / MLSD "modify" fact: YYYYMMDDHHMMSS (UTC).
pub fn fmtStamp(buf: *[14]u8, secs: i64) []const u8 {
    const c = civil(secs);
    _ = std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}", .{ c.year, c.month, c.day, c.hour, c.min, c.sec }) catch unreachable;
    return buf;
}

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn isDir(k: fs.Kind) bool {
    return k != .file;
}

/// Writes a name, replacing CR/LF so a key cannot forge listing lines.
fn writeName(w: *std.Io.Writer, name: []const u8) std.Io.Writer.Error!void {
    for (name) |c| try w.writeByte(if (c == '\r' or c == '\n') '?' else c);
}

/// One `ls -l` style line (CRLF terminated), the format most clients parse.
pub fn writeListLine(w: *std.Io.Writer, name: []const u8, kind: fs.Kind, size: u64, mtime_ns: i128, now_s: i64) std.Io.Writer.Error!void {
    const t = secsOf(mtime_ns);
    const c = civil(t);
    const mode = if (isDir(kind)) "drwxr-xr-x" else "-rw-r--r--";
    try w.print("{s} 1 owner group {d:>12} {s} {d:>2} ", .{ mode, size, months[c.month - 1], c.day });
    const half_year = 182 * 86400;
    if (t > now_s - half_year and t <= now_s + 3600) {
        try w.print("{d:0>2}:{d:0>2} ", .{ c.hour, c.min });
    } else {
        try w.print(" {d:0>4} ", .{c.year});
    }
    try writeName(w, name);
    try w.writeAll("\r\n");
}

/// RFC 3659 facts followed by a space and the name, CRLF terminated.
pub fn writeMlsxLine(w: *std.Io.Writer, name: []const u8, kind: fs.Kind, size: u64, mtime_ns: i128, type_override: ?[]const u8) std.Io.Writer.Error!void {
    var stamp: [14]u8 = undefined;
    const ty = type_override orelse if (isDir(kind)) "dir" else "file";
    if (isDir(kind)) {
        try w.print("type={s};modify={s};perm=cdeflmp; ", .{ ty, fmtStamp(&stamp, secsOf(mtime_ns)) });
    } else {
        try w.print("type={s};size={d};modify={s};perm=adfrw; ", .{ ty, size, fmtStamp(&stamp, secsOf(mtime_ns)) });
    }
    try writeName(w, name);
    try w.writeAll("\r\n");
}

/// Writes `s` as a quoted pathname for 257 replies ("" escapes a quote).
pub fn writeQuoted(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeByte('"');
    for (s) |c| {
        if (c == '"') try w.writeByte('"');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

pub const feat_lines = [_][]const u8{
    "UTF8",                            "EPSV", "PASV", "SIZE", "MDTM", "REST STREAM",
    "MLST type*;size*;modify*;perm*;", "TVFS",
};
pub const feat_tls_lines = [_][]const u8{ "AUTH TLS", "PBSZ", "PROT" };

test "parse commands" {
    const c = try parse("retr a b.txt");
    try std.testing.expectEqual(Verb.RETR, c.verb.?);
    try std.testing.expectEqualStrings("a b.txt", c.arg);
    try std.testing.expectEqual(Verb.PWD, (try parse("PWD")).verb.?);
    try std.testing.expectEqual(@as(?Verb, null), (try parse("WHATEVER x")).verb);
    try std.testing.expectEqual(@as(?Verb, null), (try parse("XYZ")).verb);
    try std.testing.expectError(error.Empty, parse(""));
    try std.testing.expectError(error.Empty, parse(" x"));
    try std.testing.expectError(error.BadChars, parse("DELE a\rb"));
    try std.testing.expectEqualStrings("dir", listArg("-la dir"));
    try std.testing.expectEqualStrings("", listArg("-a"));
    try std.testing.expectEqualStrings("x y", listArg("x y"));
}

test "port range" {
    try std.testing.expectEqual([2]u16{ 30000, 30010 }, try parsePortRange("30000-30010"));
    try std.testing.expectError(error.BadRange, parsePortRange("10-20"));
    try std.testing.expectError(error.BadRange, parsePortRange("3000-2000"));
    try std.testing.expectError(error.BadRange, parsePortRange("x"));
}

test "passive replies" {
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("227 Entering Passive Mode (127,0,0,1,117,49).", try pasvReply(&buf, .{ 127, 0, 0, 1 }, 30001));
    try std.testing.expectEqualStrings("229 Entering Extended Passive Mode (|||30001|)", try epsvReply(&buf, 30001));
}

test "hosts" {
    const a = try std.net.Address.parseIp("127.0.0.1", 1);
    const b = try std.net.Address.parseIp("127.0.0.1", 2);
    const c = try std.net.Address.parseIp("10.0.0.1", 1);
    const m = try std.net.Address.parseIp("::ffff:127.0.0.1", 3);
    const six = try std.net.Address.parseIp("::1", 3);
    try std.testing.expect(sameHost(a, b));
    try std.testing.expect(!sameHost(a, c));
    try std.testing.expect(sameHost(a, m));
    try std.testing.expect(!sameHost(a, six));
    try std.testing.expect(sameHost(six, six));
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, ip4Of(m).?);
}

test "listing lines" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const t: i128 = 1700000000 * std.time.ns_per_s; // 2023-11-14 22:13:20 UTC
    try writeListLine(&w, "a.txt", .file, 42, t, 1700000100);
    try writeListLine(&w, "old\ndir", .dir, 0, t, 1800000000);
    try std.testing.expectEqualStrings(
        "-rw-r--r-- 1 owner group           42 Nov 14 22:13 a.txt\r\n" ++
            "drwxr-xr-x 1 owner group            0 Nov 14  2023 old?dir\r\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try writeMlsxLine(&w, "a.txt", .file, 42, t, null);
    try writeMlsxLine(&w, "d", .dir, 0, t, "cdir");
    try std.testing.expectEqualStrings(
        "type=file;size=42;modify=20231114221320;perm=adfrw; a.txt\r\n" ++
            "type=cdir;modify=20231114221320;perm=cdeflmp; d\r\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try writeQuoted(&w, "/a\"b");
    try std.testing.expectEqualStrings("\"/a\"\"b\"", w.buffered());
    var st: [14]u8 = undefined;
    try std.testing.expectEqualStrings("19700101000000", fmtStamp(&st, 0));
}
