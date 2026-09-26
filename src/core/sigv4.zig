//! Signature Version 4 primitives: pure functions shared by request
//! verification (s3/) and any future outbound S3 client.
const std = @import("std");
const Writer = std.Io.Writer;

pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const algorithm = "AWS4-HMAC-SHA256";
pub const chunk_algorithm = "AWS4-HMAC-SHA256-PAYLOAD";
pub const terminator = "aws4_request";
pub const unsigned_payload = "UNSIGNED-PAYLOAD";
pub const streaming_payload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const streaming_unsigned_trailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
pub const empty_sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub const Hex = [64]u8;

pub fn hmac(key: []const u8, msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, msg, key);
    return out;
}

pub fn sha256Hex(data: []const u8) Hex {
    var d: [32]u8 = undefined;
    Sha256.hash(data, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

/// kSigning = HMAC chain over "AWS4"+secret, date (YYYYMMDD), region, service, "aws4_request".
pub fn signingKey(secret: []const u8, date: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var k_date: [32]u8 = undefined;
    // HMAC hashes keys longer than a block, so long secrets need no buffer.
    if (secret.len > 64) {
        var h = Sha256.init(.{});
        h.update("AWS4");
        h.update(secret);
        const kd = h.finalResult();
        k_date = hmac(&kd, date);
    } else {
        var kb: [68]u8 = undefined;
        @memcpy(kb[0..4], "AWS4");
        @memcpy(kb[4..][0..secret.len], secret);
        k_date = hmac(kb[0 .. 4 + secret.len], date);
    }
    const k_region = hmac(&k_date, region);
    const k_service = hmac(&k_region, service);
    return hmac(&k_service, terminator);
}

pub fn sign(key: [32]u8, string_to_sign: []const u8) Hex {
    return std.fmt.bytesToHex(hmac(&key, string_to_sign), .lower);
}

fn unreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

/// SigV4 URI encoding: everything but unreserved bytes becomes %XX (upper hex).
pub fn uriEncode(w: *Writer, s: []const u8, keep_slash: bool) Writer.Error!void {
    for (s) |c| {
        if (unreserved(c) or (keep_slash and c == '/')) {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

/// Header value as canonicalized: outer whitespace trimmed, inner runs collapsed.
pub fn writeHeaderValue(w: *Writer, v: []const u8) Writer.Error!void {
    const t = std.mem.trim(u8, v, " \t");
    var space = false;
    for (t) |c| {
        if (c == ' ' or c == '\t') {
            space = true;
            continue;
        }
        if (space) try w.writeByte(' ');
        space = false;
        try w.writeByte(c);
    }
}

pub const Param = struct { name: []const u8, value: []const u8 };

/// Writes decoded query params encoded and sorted by encoded name, then value.
pub fn writeCanonicalQuery(arena: std.mem.Allocator, w: *Writer, params: []const Param) (Writer.Error || error{OutOfMemory})!void {
    const enc = try arena.alloc(Param, params.len);
    for (params, enc) |p, *e| e.* = .{ .name = try encodeAlloc(arena, p.name), .value = try encodeAlloc(arena, p.value) };
    std.mem.sort(Param, enc, {}, struct {
        fn lt(_: void, a: Param, b: Param) bool {
            return switch (std.mem.order(u8, a.name, b.name)) {
                .lt => true,
                .gt => false,
                .eq => std.mem.lessThan(u8, a.value, b.value),
            };
        }
    }.lt);
    for (enc, 0..) |p, i| {
        if (i > 0) try w.writeByte('&');
        try w.print("{s}={s}", .{ p.name, p.value });
    }
}

fn encodeAlloc(arena: std.mem.Allocator, s: []const u8) error{OutOfMemory}![]const u8 {
    var a: Writer.Allocating = .init(arena);
    uriEncode(&a.writer, s, false) catch return error.OutOfMemory;
    return a.written();
}

/// Credential scope: `date/region/service/aws4_request`.
pub const Scope = struct {
    date: []const u8,
    region: []const u8,
    service: []const u8,

    pub fn format(s: Scope, w: *Writer) Writer.Error!void {
        try w.print("{s}/{s}/{s}/" ++ terminator, .{ s.date, s.region, s.service });
    }
};

pub fn writeStringToSign(w: *Writer, amz_date: []const u8, scope: Scope, canonical_request: []const u8) Writer.Error!void {
    try w.print(algorithm ++ "\n{s}\n{f}\n{s}", .{ amz_date, scope, &sha256Hex(canonical_request) });
}

/// String to sign for one aws-chunked chunk, chained on the previous signature.
pub fn writeChunkStringToSign(w: *Writer, amz_date: []const u8, scope: Scope, prev_signature: []const u8, chunk_sha256_hex: []const u8) Writer.Error!void {
    try w.print(chunk_algorithm ++ "\n{s}\n{f}\n{s}\n" ++ empty_sha256_hex ++ "\n{s}", .{ amz_date, scope, prev_signature, chunk_sha256_hex });
}

/// Parses `YYYYMMDDTHHMMSSZ` into Unix seconds.
pub fn parseAmzDate(s: []const u8) error{InvalidDate}!i64 {
    if (s.len != 16 or s[8] != 'T' or s[15] != 'Z') return error.InvalidDate;
    const num = struct {
        fn f(d: []const u8) error{InvalidDate}!i64 {
            for (d) |c| if (!std.ascii.isDigit(c)) return error.InvalidDate;
            return std.fmt.parseInt(i64, d, 10) catch error.InvalidDate;
        }
    }.f;
    const y = try num(s[0..4]);
    const m = try num(s[4..6]);
    const d = try num(s[6..8]);
    const hh = try num(s[9..11]);
    const mm = try num(s[11..13]);
    const ss = try num(s[13..15]);
    if (m < 1 or m > 12 or d < 1 or d > 31 or hh > 23 or mm > 59 or ss > 60) return error.InvalidDate;
    // Days from civil (Howard Hinnant).
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = @mod(m + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + hh * 3600 + mm * 60 + ss;
}

test "uri encode" {
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try uriEncode(&w, "a b/c~d+*", true);
    try std.testing.expectEqualStrings("a%20b/c~d%2B%2A", w.buffered());
    w = .fixed(&buf);
    try uriEncode(&w, "a/b", false);
    try std.testing.expectEqualStrings("a%2Fb", w.buffered());
}

test "amz date" {
    try std.testing.expectEqual(@as(i64, 1440938160), try parseAmzDate("20150830T123600Z"));
    try std.testing.expectEqual(@as(i64, 0), try parseAmzDate("19700101T000000Z"));
    try std.testing.expectError(error.InvalidDate, parseAmzDate("20150830T1236Z"));
    try std.testing.expectError(error.InvalidDate, parseAmzDate("2015083xT123600Z"));
}

test "canonical query sorts encoded params" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var a: Writer.Allocating = .init(arena.allocator());
    try writeCanonicalQuery(arena.allocator(), &a.writer, &.{
        .{ .name = "prefix", .value = "a b/" },
        .{ .name = "list-type", .value = "2" },
        .{ .name = "acl", .value = "" },
    });
    try std.testing.expectEqualStrings("acl=&list-type=2&prefix=a%20b%2F", a.written());
}

// SigV4 reference vector "get-vanilla".
test "reference vector get-vanilla" {
    const creq = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n" ++ empty_sha256_hex;
    try std.testing.expectEqualStrings("bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63", &sha256Hex(creq));
    const scope: Scope = .{ .date = "20150830", .region = "us-east-1", .service = "service" };
    var buf: [256]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writeStringToSign(&w, "20150830T123600Z", scope, creq);
    const key = signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "service");
    try std.testing.expectEqualStrings("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", &sign(key, w.buffered()));
}

test "signing key for long secret matches direct hmac" {
    const secret = "x" ** 100;
    const key = signingKey(secret, "20150830", "r", "s");
    const k_date = hmac("AWS4" ++ secret, "20150830");
    const want = hmac(&hmac(&hmac(&k_date, "r"), "s"), terminator);
    try std.testing.expectEqualSlices(u8, &want, &key);
}
