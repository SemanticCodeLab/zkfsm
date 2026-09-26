//! Client-side AWS SigV4 header signing for the remote S3 backend.
//! Self-contained (std only); can be deduplicated with a shared core signer later.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Writer = std.Io.Writer;

pub const unsigned_payload = "UNSIGNED-PAYLOAD";
pub const empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    session_token: ?[]const u8 = null,
};

/// Lowercase name; `headers` passed to `authorization` must be sorted by name.
pub const Header = struct { name: []const u8, value: []const u8 };
pub const Param = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    method: []const u8,
    /// Already URI-encoded path.
    canonical_uri: []const u8,
    /// Output of `canonicalQuery`.
    canonical_query: []const u8,
    headers: []const Header,
    payload_hash: []const u8,
    /// YYYYMMDDTHHMMSSZ
    amz_date: []const u8,
};

pub const SignError = error{NoSpaceLeft};

/// RFC 3986 unreserved characters pass; everything else is %XX (uppercase).
pub fn uriEncode(w: *Writer, s: []const u8, encode_slash: bool) Writer.Error!void {
    for (s) |c| {
        const keep = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~' or
            (c == '/' and !encode_slash);
        if (keep) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

/// Sorted, encoded `a=b&c=d`. At most 16 params.
pub fn canonicalQuery(w: *Writer, params: []const Param) (Writer.Error || error{TooManyParams})!void {
    var sorted: [16]Param = undefined;
    if (params.len > sorted.len) return error.TooManyParams;
    @memcpy(sorted[0..params.len], params);
    std.mem.sort(Param, sorted[0..params.len], {}, struct {
        fn lt(_: void, a: Param, b: Param) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    for (sorted[0..params.len], 0..) |p, i| {
        if (i != 0) try w.writeByte('&');
        try uriEncode(w, p.name, true);
        try w.writeByte('=');
        try uriEncode(w, p.value, true);
    }
}

pub fn amzDate(ns: i128) [16]u8 {
    const secs: u64 = std.math.cast(u64, @divFloor(ns, std.time.ns_per_s)) orelse 0;
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var out: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable; // fixed width
    return out;
}

pub fn signingKey(secret: []const u8, date: []const u8, region: []const u8, service: []const u8) [32]u8 {
    var k = hmacPrefixed("AWS4", secret, date);
    k = hmac(&k, region);
    k = hmac(&k, service);
    return hmac(&k, "aws4_request");
}

fn hmac(key: []const u8, msg: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Hmac.create(&out, msg, key);
    return out;
}

fn hmacPrefixed(prefix: []const u8, secret: []const u8, msg: []const u8) [32]u8 {
    var key: [256]u8 = undefined;
    const n = @min(secret.len, key.len - prefix.len);
    @memcpy(key[0..prefix.len], prefix);
    @memcpy(key[prefix.len..][0..n], secret[0..n]);
    return hmac(key[0 .. prefix.len + n], msg);
}

pub fn hashHex(data: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(data, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

/// Returns the full Authorization header value written into `out`.
pub fn authorization(
    creds: Credentials,
    region: []const u8,
    service: []const u8,
    req: Request,
    out: []u8,
) SignError![]const u8 {
    if (req.amz_date.len != 16) return error.NoSpaceLeft;
    const date = req.amz_date[0..8];

    var hbuf: [256]u8 = undefined;
    var hw: Writer.Hashing(Sha256) = .init(&hbuf);
    writeCanonical(&hw.writer, req) catch return error.NoSpaceLeft;
    hw.writer.flush() catch return error.NoSpaceLeft;
    var creq: [32]u8 = undefined;
    hw.hasher.final(&creq);
    const creq_hex = std.fmt.bytesToHex(creq, .lower);

    var sts_buf: [256]u8 = undefined;
    const sts = std.fmt.bufPrint(&sts_buf, "AWS4-HMAC-SHA256\n{s}\n{s}/{s}/{s}/aws4_request\n{s}", .{
        req.amz_date, date, region, service, &creq_hex,
    }) catch return error.NoSpaceLeft;
    const key = signingKey(creds.secret_key, date, region, service);
    const sig = std.fmt.bytesToHex(hmac(&key, sts), .lower);

    var w: Writer = .fixed(out);
    w.print("AWS4-HMAC-SHA256 Credential={s}/{s}/{s}/{s}/aws4_request, SignedHeaders=", .{
        creds.access_key, date, region, service,
    }) catch return error.NoSpaceLeft;
    writeSignedHeaders(&w, req.headers) catch return error.NoSpaceLeft;
    w.print(", Signature={s}", .{&sig}) catch return error.NoSpaceLeft;
    return w.buffered();
}

fn writeSignedHeaders(w: *Writer, headers: []const Header) Writer.Error!void {
    for (headers, 0..) |hd, i| {
        if (i != 0) try w.writeByte(';');
        try w.writeAll(hd.name);
    }
}

fn writeCanonical(w: *Writer, req: Request) Writer.Error!void {
    try w.print("{s}\n{s}\n{s}\n", .{ req.method, req.canonical_uri, req.canonical_query });
    for (req.headers) |hd| try w.print("{s}:{s}\n", .{ hd.name, std.mem.trim(u8, hd.value, " \t") });
    try w.writeByte('\n');
    try writeSignedHeaders(w, req.headers);
    try w.print("\n{s}", .{req.payload_hash});
}

const test_creds: Credentials = .{
    .access_key = "AKIAIOSFODNN7EXAMPLE",
    .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
};

fn expectSig(req: Request, want: []const u8) !void {
    var out: [512]u8 = undefined;
    const auth = try authorization(test_creds, "us-east-1", "s3", req, &out);
    const idx = std.mem.indexOf(u8, auth, "Signature=") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(want, auth[idx + 10 ..]);
}

// Examples from the AWS S3 "Signature Calculations for the Authorization Header" docs.
test "sigv4 aws doc example: GET object with range" {
    try expectSig(.{
        .method = "GET",
        .canonical_uri = "/test.txt",
        .canonical_query = "",
        .headers = &.{
            .{ .name = "host", .value = "examplebucket.s3.amazonaws.com" },
            .{ .name = "range", .value = "bytes=0-9" },
            .{ .name = "x-amz-content-sha256", .value = empty_sha256 },
            .{ .name = "x-amz-date", .value = "20130524T000000Z" },
        },
        .payload_hash = empty_sha256,
        .amz_date = "20130524T000000Z",
    }, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
}

test "sigv4 aws doc example: PUT object" {
    var ub: [64]u8 = undefined;
    var uw: Writer = .fixed(&ub);
    try uw.writeByte('/');
    try uriEncode(&uw, "test$file.text", false);
    try std.testing.expectEqualStrings("/test%24file.text", uw.buffered());
    const payload = hashHex("Welcome to Amazon S3.");
    try expectSig(.{
        .method = "PUT",
        .canonical_uri = uw.buffered(),
        .canonical_query = "",
        .headers = &.{
            .{ .name = "date", .value = "Fri, 24 May 2013 00:00:00 GMT" },
            .{ .name = "host", .value = "examplebucket.s3.amazonaws.com" },
            .{ .name = "x-amz-content-sha256", .value = &payload },
            .{ .name = "x-amz-date", .value = "20130524T000000Z" },
            .{ .name = "x-amz-storage-class", .value = "REDUCED_REDUNDANCY" },
        },
        .payload_hash = &payload,
        .amz_date = "20130524T000000Z",
    }, "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd");
}

test "sigv4 aws doc example: list objects" {
    var qb: [64]u8 = undefined;
    var qw: Writer = .fixed(&qb);
    try canonicalQuery(&qw, &.{ .{ .name = "prefix", .value = "J" }, .{ .name = "max-keys", .value = "2" } });
    try std.testing.expectEqualStrings("max-keys=2&prefix=J", qw.buffered());
    try expectSig(.{
        .method = "GET",
        .canonical_uri = "/",
        .canonical_query = qw.buffered(),
        .headers = &.{
            .{ .name = "host", .value = "examplebucket.s3.amazonaws.com" },
            .{ .name = "x-amz-content-sha256", .value = empty_sha256 },
            .{ .name = "x-amz-date", .value = "20130524T000000Z" },
        },
        .payload_hash = empty_sha256,
        .amz_date = "20130524T000000Z",
    }, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7");
}

test "amz date format" {
    try std.testing.expectEqualStrings("19941106T084937Z", &amzDate(784111777 * std.time.ns_per_s));
}
