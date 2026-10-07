//! Legacy Signature Version 2: `Authorization: AWS ak:sig` and presigned
//! `?AWSAccessKeyId=&Expires=&Signature=` queries, HMAC-SHA1 over the
//! canonical string botocore's HmacV1Auth builds.
const std = @import("std");
const router = @import("router.zig");

const Header = std.http.Header;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const b64 = std.base64.standard;

pub const max_skew_s = 15 * 60;

pub const Parsed = struct {
    access_key: []const u8,
    signature: []const u8,
    presigned: bool,
    expires_s: ?i64,
};

pub const ParseResult = union(enum) {
    /// Not a V2 request (anonymous or another scheme).
    none,
    /// V2 shape but unusable credentials: InvalidArgument.
    malformed,
    parsed: Parsed,
};

/// Query parameters that belong to the canonical resource (botocore's list).
const sub_resources = [_][]const u8{
    "accelerate",                   "acl",                       "analytics",
    "cors",                         "defaultObjectAcl",          "delete",
    "inventory",                    "lifecycle",                 "location",
    "logging",                      "metrics",                   "notification",
    "object-lock",                  "partNumber",                "policy",
    "replication",                  "requestPayment",            "response-cache-control",
    "response-content-disposition", "response-content-encoding", "response-content-language",
    "response-content-type",        "response-expires",          "restore",
    "select",                       "select-type",               "storageClass",
    "tagging",                      "torrent",                   "uploadId",
    "uploads",                      "versionId",                 "versioning",
    "versions",                     "website",
};

fn header(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

fn splitTarget(target: []const u8) struct { path: []const u8, query: []const u8 } {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return .{ .path = target, .query = "" };
    return .{ .path = target[0..q], .query = target[q + 1 ..] };
}

fn queryValue(arena: std.mem.Allocator, query: []const u8, name: []const u8) error{OutOfMemory}!?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        if (!std.mem.eql(u8, pair[0 .. eq orelse pair.len], name)) continue;
        return if (eq) |i| try unquote(arena, pair[i + 1 ..]) else "";
    }
    return null;
}

/// Percent-decoding like Python's unquote: `+` stays, bad escapes pass through.
fn unquote(arena: std.mem.Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    return router.percentDecode(arena, s, false) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUri => {
            var out: std.ArrayList(u8) = .empty;
            var i: usize = 0;
            while (i < s.len) : (i += 1) {
                if (s[i] == '%' and i + 2 < s.len) {
                    if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                        try out.append(arena, b);
                        i += 2;
                        continue;
                    } else |_| {}
                }
                try out.append(arena, s[i]);
            }
            return out.items;
        },
    };
}

pub fn parse(arena: std.mem.Allocator, method: []const u8, target: []const u8, headers: []const Header) error{OutOfMemory}!ParseResult {
    _ = method;
    if (header(headers, "authorization")) |auth| {
        if (auth.len < 4 or !std.mem.eql(u8, auth[0..4], "AWS ")) return .none;
        const cred = std.mem.trim(u8, auth[4..], " ");
        const colon = std.mem.lastIndexOfScalar(u8, cred, ':') orelse return .malformed;
        if (colon == 0 or colon + 1 == cred.len) return .malformed;
        return .{ .parsed = .{ .access_key = cred[0..colon], .signature = cred[colon + 1 ..], .presigned = false, .expires_s = null } };
    }
    const query = splitTarget(target).query;
    const ak = try queryValue(arena, query, "AWSAccessKeyId");
    const sig = try queryValue(arena, query, "Signature");
    if (ak == null and sig == null) return .none;
    const exp = try queryValue(arena, query, "Expires");
    if (ak == null or sig == null or exp == null) return .malformed;
    if (ak.?.len == 0 or sig.?.len == 0) return .malformed;
    const expires = std.fmt.parseInt(i64, exp.?, 10) catch return .malformed;
    return .{ .parsed = .{ .access_key = ak.?, .signature = sig.?, .presigned = true, .expires_s = expires } };
}

const Amz = struct { name: []const u8, value: []const u8 };

fn amzLess(_: void, a: Amz, b: Amz) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Trims and collapses folded (CR/LF + whitespace) runs to one space.
fn normValue(arena: std.mem.Allocator, v: []const u8) error{OutOfMemory}![]const u8 {
    const s = std.mem.trim(u8, v, " \t\r\n");
    if (std.mem.indexOfAny(u8, s, "\r\n") == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '\r' or s[i] == '\n') {
            while (i < s.len and std.mem.indexOfScalar(u8, " \t\r\n", s[i]) != null) i += 1;
            while (out.items.len > 0 and (out.getLast() == ' ' or out.getLast() == '\t')) _ = out.pop();
            try out.append(arena, ' ');
            continue;
        }
        try out.append(arena, s[i]);
        i += 1;
    }
    return out.items;
}

/// Canonical string. Date line is `presigned_expires`, else the Date header as
/// sent (empty when absent; clients sign Date even alongside x-amz-date).
/// Presigned x-amz-*/Content-* query parameters stand in for headers.
pub fn stringToSign(
    arena: std.mem.Allocator,
    method: []const u8,
    target: []const u8,
    headers: []const Header,
    presigned_expires: ?[]const u8,
    bucket_from_host: ?[]const u8,
) error{OutOfMemory}![]const u8 {
    const parts = splitTarget(target);
    var out: std.ArrayList(u8) = .empty;
    for (method) |c| try out.append(arena, std.ascii.toUpper(c));
    try out.append(arena, '\n');
    for ([_][]const u8{ "content-md5", "content-type" }) |n| {
        var v = header(headers, n);
        if (v == null and presigned_expires != null) v = try queryValue(arena, parts.query, n);
        try out.appendSlice(arena, std.mem.trim(u8, v orelse "", " \t"));
        try out.append(arena, '\n');
    }
    const date = presigned_expires orelse std.mem.trim(u8, header(headers, "date") orelse "", " \t");
    try out.appendSlice(arena, date);
    try out.append(arena, '\n');

    var amz: std.ArrayList(Amz) = .empty;
    for (headers) |h| {
        if (h.name.len < 6 or !std.ascii.eqlIgnoreCase(h.name[0..6], "x-amz-")) continue;
        try amz.append(arena, .{ .name = try std.ascii.allocLowerString(arena, h.name), .value = try normValue(arena, h.value) });
    }
    if (presigned_expires != null) {
        var it = std.mem.splitScalar(u8, parts.query, '&');
        while (it.next()) |pair| {
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
            const name = try unquote(arena, pair[0..eq]);
            if (name.len < 6 or !std.ascii.eqlIgnoreCase(name[0..6], "x-amz-")) continue;
            const v = if (eq < pair.len) try unquote(arena, pair[eq + 1 ..]) else "";
            try amz.append(arena, .{ .name = try std.ascii.allocLowerString(arena, name), .value = try normValue(arena, v) });
        }
    }
    std.mem.sort(Amz, amz.items, {}, amzLess);
    var i: usize = 0;
    while (i < amz.items.len) {
        const name = amz.items[i].name;
        try out.appendSlice(arena, name);
        try out.append(arena, ':');
        var first = true;
        while (i < amz.items.len and std.mem.eql(u8, amz.items[i].name, name)) : (i += 1) {
            if (!first) try out.append(arena, ',');
            try out.appendSlice(arena, amz.items[i].value);
            first = false;
        }
        try out.append(arena, '\n');
    }

    if (bucket_from_host) |b| {
        try out.append(arena, '/');
        try out.appendSlice(arena, b);
    }
    try out.appendSlice(arena, parts.path);
    try appendSubResources(arena, &out, parts.query);
    return out.items;
}

const Sub = struct { key: []const u8, value: ?[]const u8 };

fn subLess(_: void, a: Sub, b: Sub) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}

fn appendSubResources(arena: std.mem.Allocator, out: *std.ArrayList(u8), query: []const u8) error{OutOfMemory}!void {
    if (query.len == 0) return;
    var subs: std.ArrayList(Sub) = .empty;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const key = pair[0 .. eq orelse pair.len];
        for (sub_resources) |s| if (std.mem.eql(u8, s, key)) {
            try subs.append(arena, .{ .key = key, .value = if (eq) |e| try unquote(arena, pair[e + 1 ..]) else null });
            break;
        };
    }
    if (subs.items.len == 0) return;
    std.mem.sort(Sub, subs.items, {}, subLess);
    for (subs.items, 0..) |s, n| {
        try out.append(arena, if (n == 0) '?' else '&');
        try out.appendSlice(arena, s.key);
        if (s.value) |v| {
            try out.append(arena, '=');
            try out.appendSlice(arena, v);
        }
    }
}

pub fn sign(secret: []const u8, string_to_sign: []const u8) [28]u8 {
    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, string_to_sign, secret);
    var out: [28]u8 = undefined;
    _ = b64.Encoder.encode(&out, &mac);
    return out;
}

/// Constant-time comparison of the computed signature with the presented one.
pub fn verifySignature(expected_b64: [28]u8, got: []const u8) bool {
    if (got.len != 28) return false;
    return std.crypto.timing_safe.eql([28]u8, expected_b64, got[0..28].*);
}

pub const TimeCheck = enum {
    ok,
    /// AccessDenied "Request has expired".
    expired,
    /// RequestTimeTooSkewed.
    skewed,
    /// AccessDenied: no parseable Date/x-amz-date (including pre-1970 dates).
    missing_date,
};

/// Header form: x-amz-date wins over Date; an invalid x-amz-date does not fall back.
pub fn requestTime(headers: []const Header) ?i64 {
    if (header(headers, "x-amz-date")) |v| return parseHttpDate(v);
    return parseHttpDate(header(headers, "date") orelse return null);
}

pub fn checkTime(headers: []const Header, presigned_expires_s: ?i64, now_s: i64) TimeCheck {
    if (presigned_expires_s) |exp| return if (now_s > exp) .expired else .ok;
    const at = requestTime(headers) orelse return .missing_date;
    const d = if (at > now_s) at - now_s else now_s - at;
    return if (d > max_skew_s) .skewed else .ok;
}

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// RFC 1123 date (`Sun, 06 Nov 1994 08:49:37 GMT`, zone GMT/UTC/Z/+0000);
/// null for anything else or before the epoch.
pub fn parseHttpDate(raw: []const u8) ?i64 {
    var s = std.mem.trim(u8, raw, " \t");
    if (std.mem.indexOfScalar(u8, s, ',')) |c| s = std.mem.trimLeft(u8, s[c + 1 ..], " ");
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    const day_s = it.next() orelse return null;
    const mon_s = it.next() orelse return null;
    const year_s = it.next() orelse return null;
    const time_s = it.next() orelse return null;
    const zone = it.next() orelse return null;
    if (it.next() != null) return null;
    if (!(std.mem.eql(u8, zone, "GMT") or std.mem.eql(u8, zone, "UTC") or std.mem.eql(u8, zone, "Z") or std.mem.eql(u8, zone, "+0000"))) return null;
    const day = num(day_s, 1, 2) orelse return null;
    const year = num(year_s, 4, 4) orelse return null;
    var month: ?u32 = null;
    for (months, 1..) |m, n| if (std.ascii.eqlIgnoreCase(m, mon_s)) {
        month = @intCast(n);
    };
    if (time_s.len != 8 or time_s[2] != ':' or time_s[5] != ':') return null;
    const hh = num(time_s[0..2], 2, 2) orelse return null;
    const mm = num(time_s[3..5], 2, 2) orelse return null;
    const ss = num(time_s[6..8], 2, 2) orelse return null;
    if (year < 1970 or day < 1 or day > 31 or hh > 23 or mm > 59 or ss > 60) return null;
    const days = daysFromCivil(year, month orelse return null, day);
    return days * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + ss;
}

fn num(s: []const u8, min: usize, max: usize) ?u32 {
    if (s.len < min or s.len > max) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}

fn daysFromCivil(year: u32, month: u32, day: u32) i64 {
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ---- tests ----

const t = std.testing;
const example_ak = "AKIAIOSFODNN7EXAMPLE";
const example_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

test "classic GET example" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const hs = [_]Header{
        .{ .name = "Host", .value = "johnsmith.s3.example.com" },
        .{ .name = "Date", .value = "Tue, 27 Mar 2007 19:36:42 +0000" },
        .{ .name = "Authorization", .value = "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=" },
    };
    const sts = try stringToSign(arena.allocator(), "GET", "/photos/puppy.jpg", &hs, null, "johnsmith");
    try t.expectEqualStrings("GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg", sts);
    const sig = sign(example_secret, sts);
    try t.expectEqualStrings("bWq2s1WEIj+Ydj0vQ697zp+IXMU=", &sig);
    const p = (try parse(arena.allocator(), "GET", "/photos/puppy.jpg", &hs)).parsed;
    try t.expectEqualStrings(example_ak, p.access_key);
    try t.expect(verifySignature(sig, p.signature));
    try t.expect(!verifySignature(sig, "bWq2s1WEIj+Ydj0vQ697zp+IXMU"));
    try t.expect(!p.presigned);
}

test "PUT with content headers and amz headers" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const hs = [_]Header{
        .{ .name = "Content-MD5", .value = "4gJE4saaMU4BqNR0kLY+lw==" },
        .{ .name = "Content-Type", .value = "application/x-download" },
        .{ .name = "Date", .value = "Tue, 27 Mar 2007 21:06:08 +0000" },
        .{ .name = "x-amz-acl", .value = "public-read" },
        .{ .name = "X-Amz-Meta-ReviewedBy", .value = "joe@johnsmith.net" },
        .{ .name = "x-amz-meta-reviewedby", .value = "jane@johnsmith.net" },
        .{ .name = "X-Amz-Meta-FileChecksum", .value = "0x02661779" },
        .{ .name = "X-Amz-Meta-ChecksumAlgorithm", .value = "crc32" },
    };
    const sts = try stringToSign(arena.allocator(), "PUT", "/db-backup.dat.gz", &hs, null, "static.johnsmith.net");
    try t.expectEqualStrings("PUT\n4gJE4saaMU4BqNR0kLY+lw==\napplication/x-download\nTue, 27 Mar 2007 21:06:08 +0000\n" ++
        "x-amz-acl:public-read\nx-amz-meta-checksumalgorithm:crc32\nx-amz-meta-filechecksum:0x02661779\n" ++
        "x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n/static.johnsmith.net/db-backup.dat.gz", sts);
    // Independently computed with Python hmac/sha1.
    try t.expectEqualStrings("ilyl83RwaSoYIEdixDQcA4OnAnc=", &sign(example_secret, sts));
}

test "presigned query" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const target = "/photos/puppy.jpg?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=NpgCjnDzrM%2BWFzoENXmpNDUsSn8%3D&Expires=1175139620";
    const p = (try parse(a, "GET", target, &.{})).parsed;
    try t.expect(p.presigned);
    try t.expectEqual(@as(?i64, 1175139620), p.expires_s);
    const sts = try stringToSign(a, "GET", target, &.{}, "1175139620", "johnsmith");
    try t.expectEqualStrings("GET\n\n\n1175139620\n/johnsmith/photos/puppy.jpg", sts);
    try t.expect(verifySignature(sign(example_secret, sts), p.signature));
    try t.expectEqual(TimeCheck.ok, checkTime(&.{}, p.expires_s, 1175139620));
    try t.expectEqual(TimeCheck.expired, checkTime(&.{}, p.expires_s, 1175139621));
    try t.expectEqual(ParseResult.malformed, try parse(a, "GET", "/x?AWSAccessKeyId=a&Signature=b", &.{}));
    try t.expectEqual(ParseResult.none, try parse(a, "GET", "/x?X-Amz-Signature=b", &.{}));
}

test "presigned amz query params are signed as headers" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const sts = try stringToSign(arena.allocator(), "PUT", "/b/k?x-amz-acl=public-read&content-type=text%2Fplain&Expires=5", &.{}, "5", null);
    try t.expectEqualStrings("PUT\n\ntext/plain\n5\nx-amz-acl:public-read\n/b/k", sts);
}

test "authorization header shapes" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v4 = [_]Header{.{ .name = "Authorization", .value = "AWS4-HMAC-SHA256 Credential=x" }};
    try t.expectEqual(ParseResult.none, try parse(a, "GET", "/", &v4));
    const bad = [_]Header{.{ .name = "Authorization", .value = "AWS HAHAHA" }};
    try t.expectEqual(ParseResult.malformed, try parse(a, "GET", "/", &bad));
    const empty_sig = [_]Header{.{ .name = "Authorization", .value = "AWS ak:" }};
    try t.expectEqual(ParseResult.malformed, try parse(a, "GET", "/", &empty_sig));
    try t.expectEqual(ParseResult.none, try parse(a, "GET", "/", &.{}));
}

test "sub-resources sorted, decoded, others dropped; botocore cross-check" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    // Generated with botocore HmacV1Auth for key "dir/my file+plus ü.txt".
    const hs = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "x-amz-meta-B", .value = "  two " },
        .{ .name = "X-Amz-Meta-a", .value = "one" },
        .{ .name = "Date", .value = "Tue, 27 Mar 2007 19:36:42 +0000" },
    };
    const target = "/bkt/dir/my%20file%2Bplus%20%C3%BC.txt?versionId=a%2Bb%20c&uploadId=xyz&foo=bar&acl";
    const sts = try stringToSign(arena.allocator(), "put", target, &hs, null, null);
    try t.expectEqualStrings("PUT\n\ntext/plain\nTue, 27 Mar 2007 19:36:42 +0000\nx-amz-meta-a:one\nx-amz-meta-b:two\n" ++
        "/bkt/dir/my%20file%2Bplus%20%C3%BC.txt?acl&uploadId=xyz&versionId=a+b c", sts);
    try t.expectEqualStrings("aey0oPlM8+XkqjHDrN9rUA3aLnQ=", &sign(example_secret, sts));
}

test "vhost root and folded amz values" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const hs = [_]Header{.{ .name = "x-amz-meta-x", .value = "a\r\n   b" }};
    const sts = try stringToSign(arena.allocator(), "GET", "/?acl", &hs, null, "bkt");
    try t.expectEqualStrings("GET\n\n\n\nx-amz-meta-x:a b\n/bkt/?acl", sts);
}

test "time checks" {
    const now: i64 = 784111777; // Sun, 06 Nov 1994 08:49:37 GMT
    try t.expectEqual(@as(?i64, now), parseHttpDate("Sun, 06 Nov 1994 08:49:37 GMT"));
    try t.expectEqual(@as(?i64, 1175024202), parseHttpDate("Tue, 27 Mar 2007 19:36:42 +0000"));
    try t.expectEqual(@as(?i64, null), parseHttpDate("Bad Date"));
    try t.expectEqual(@as(?i64, null), parseHttpDate(""));
    try t.expectEqual(@as(?i64, null), parseHttpDate("Tue, 07 Jul 1950 21:53:04 GMT"));
    const date_ok = [_]Header{.{ .name = "Date", .value = "Sun, 06 Nov 1994 08:49:37 GMT" }};
    try t.expectEqual(TimeCheck.ok, checkTime(&date_ok, null, now + 60));
    try t.expectEqual(TimeCheck.skewed, checkTime(&date_ok, null, now + max_skew_s + 1));
    try t.expectEqual(TimeCheck.missing_date, checkTime(&.{}, null, now));
    const amz_bad = [_]Header{ date_ok[0], .{ .name = "x-amz-date", .value = "" } };
    try t.expectEqual(TimeCheck.missing_date, checkTime(&amz_bad, null, now));
    const future = [_]Header{.{ .name = "x-amz-date", .value = "Tue, 07 Jul 9999 21:53:04 GMT" }};
    try t.expectEqual(TimeCheck.skewed, checkTime(&future, null, now));
}
