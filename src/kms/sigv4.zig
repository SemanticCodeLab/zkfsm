//! Signature Version 4 (AWS4-HMAC-SHA256) for single-shot requests with a fully buffered
//! payload (enough for the KMS JSON 1.1 API).
const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Allocator = std.mem.Allocator;

pub const Credentials = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8 = null,
};

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    method: []const u8,
    /// Absolute path, already URI-encoded.
    path: []const u8 = "/",
    /// Canonical query string (sorted, encoded) or "".
    query: []const u8 = "",
    /// Headers to sign; names lowercase, must include `host`.
    headers: []const Header,
    payload: []const u8,
};

/// "YYYYMMDDTHHMMSSZ" for a unix timestamp.
pub fn amzDate(buf: *[16]u8, unix: i64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(unix, 0)) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

fn hexLower(out: []u8, in: []const u8) []const u8 {
    const cs = "0123456789abcdef";
    for (in, 0..) |b, i| {
        out[2 * i] = cs[b >> 4];
        out[2 * i + 1] = cs[b & 15];
    }
    return out[0 .. 2 * in.len];
}

fn lessHeader(_: void, a: Header, b: Header) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

/// Returns the `Authorization` header value. `amz_date` must match the
/// signed `x-amz-date` header.
pub fn sign(gpa: Allocator, creds: Credentials, region: []const u8, service: []const u8, amz_date: []const u8, req: Request) error{ OutOfMemory, InvalidArgument }![]u8 {
    if (amz_date.len != 16) return error.InvalidArgument;
    const hs = try gpa.dupe(Header, req.headers);
    defer gpa.free(hs);
    std.mem.sort(Header, hs, {}, lessHeader);

    var canon: std.ArrayList(u8) = .empty;
    defer canon.deinit(gpa);
    var signed: std.ArrayList(u8) = .empty;
    defer signed.deinit(gpa);
    try canon.print(gpa, "{s}\n{s}\n{s}\n", .{ req.method, req.path, req.query });
    for (hs, 0..) |h, i| {
        for (h.name) |ch| if (std.ascii.isUpper(ch)) return error.InvalidArgument;
        try canon.print(gpa, "{s}:{s}\n", .{ h.name, std.mem.trim(u8, h.value, " \t") });
        if (i != 0) try signed.append(gpa, ';');
        try signed.appendSlice(gpa, h.name);
    }
    var ph: [32]u8 = undefined;
    Sha256.hash(req.payload, &ph, .{});
    var phx: [64]u8 = undefined;
    try canon.print(gpa, "\n{s}\n{s}", .{ signed.items, hexLower(&phx, &ph) });

    var ch: [32]u8 = undefined;
    Sha256.hash(canon.items, &ch, .{});
    var chx: [64]u8 = undefined;
    const date = amz_date[0..8];
    const sts = try std.fmt.allocPrint(gpa, "AWS4-HMAC-SHA256\n{s}\n{s}/{s}/{s}/aws4_request\n{s}", .{ amz_date, date, region, service, hexLower(&chx, &ch) });
    defer gpa.free(sts);

    const kinit = try std.mem.concat(gpa, u8, &.{ "AWS4", creds.secret_access_key });
    defer {
        std.crypto.secureZero(u8, kinit);
        gpa.free(kinit);
    }
    var k: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &k);
    Hmac.create(&k, date, kinit);
    Hmac.create(&k, region, &k);
    Hmac.create(&k, service, &k);
    Hmac.create(&k, "aws4_request", &k);
    var sig: [32]u8 = undefined;
    Hmac.create(&sig, sts, &k);
    var sigx: [64]u8 = undefined;
    return std.fmt.allocPrint(gpa, "AWS4-HMAC-SHA256 Credential={s}/{s}/{s}/{s}/aws4_request, SignedHeaders={s}, Signature={s}", .{
        creds.access_key_id, date, region, service, signed.items, hexLower(&sigx, &sig),
    });
}

test "sigv4 test suite: get-vanilla" {
    const gpa = std.testing.allocator;
    const creds: Credentials = .{ .access_key_id = "AKIDEXAMPLE", .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
    const auth = try sign(gpa, creds, "us-east-1", "service", "20150830T123600Z", .{
        .method = "GET",
        .headers = &.{ .{ .name = "x-amz-date", .value = "20150830T123600Z" }, .{ .name = "host", .value = "example.amazonaws.com" } },
        .payload = "",
    });
    defer gpa.free(auth);
    try std.testing.expectEqualStrings("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", auth);
}

test "sigv4 test suite: post-x-www-form-urlencoded" {
    const gpa = std.testing.allocator;
    const creds: Credentials = .{ .access_key_id = "AKIDEXAMPLE", .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" };
    const auth = try sign(gpa, creds, "us-east-1", "service", "20150830T123600Z", .{
        .method = "POST",
        .headers = &.{
            .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "host", .value = "example.amazonaws.com" },
            .{ .name = "x-amz-date", .value = "20150830T123600Z" },
        },
        .payload = "Param1=value1",
    });
    defer gpa.free(auth);
    try std.testing.expect(std.mem.endsWith(u8, auth, "SignedHeaders=content-type;host;x-amz-date, Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"));
}

test "amz date formatting" {
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("20150830T123600Z", amzDate(&b, 1440938160));
}
