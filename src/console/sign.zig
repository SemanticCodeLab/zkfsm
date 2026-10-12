//! Client-side SigV4: signs proxied requests with session credentials and builds
//! presigned GET URLs. Paths and query parameters arrive decoded.
const std = @import("std");
const core = @import("../core/root.zig");

const sv = core.sigv4;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    session_token: []const u8 = "",
};

pub const Header = std.http.Header;
pub const Param = sv.Param;

pub const Error = error{OutOfMemory};

/// Amz date `YYYYMMDDTHHMMSSZ` for a Unix time.
pub fn amzDate(now_s: i64, buf: *[16]u8) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(now_s, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// Canonical (encoded) path: each byte outside the unreserved set is %XX, '/' kept.
pub fn encodePath(a: Allocator, path: []const u8) Error![]const u8 {
    var out: Writer.Allocating = .init(a);
    sv.uriEncode(&out.writer, path, true) catch return error.OutOfMemory;
    return out.written();
}

/// Encodes one path segment ('/' escaped too).
pub fn encodePathTo(w: *Writer, s: []const u8) Writer.Error!void {
    return sv.uriEncode(w, s, false);
}

pub fn encodeQuery(a: Allocator, params: []const Param) Error![]const u8 {
    var out: Writer.Allocating = .init(a);
    sv.writeCanonicalQuery(a, &out.writer, params) catch return error.OutOfMemory;
    return out.written();
}

pub const Request = struct {
    method: []const u8,
    host: []const u8,
    /// Decoded path, starting with '/'.
    path: []const u8,
    params: []const Param = &.{},
    /// Extra headers to sign and send (lowercase names); host and x-amz-date are added.
    headers: []const Header = &.{},
    payload_sha256_hex: []const u8 = sv.unsigned_payload,
    region: []const u8 = "us-east-1",
    service: []const u8 = "s3",
};

pub const Signed = struct {
    /// Encoded path and query, ready for the request line.
    target: []const u8,
    /// Headers to send, including Authorization (host excluded; the client adds it).
    headers: []const Header,
};

pub fn sign(a: Allocator, creds: Credentials, req: Request, now_s: i64) Error!Signed {
    var date_buf: [16]u8 = undefined;
    const amz_date = try a.dupe(u8, amzDate(now_s, &date_buf));
    var hs: std.ArrayList(Header) = .empty;
    try hs.append(a, .{ .name = "host", .value = req.host });
    try hs.append(a, .{ .name = "x-amz-date", .value = amz_date });
    try hs.append(a, .{ .name = "x-amz-content-sha256", .value = req.payload_sha256_hex });
    if (creds.session_token.len > 0) try hs.append(a, .{ .name = "x-amz-security-token", .value = creds.session_token });
    for (req.headers) |h| try hs.append(a, .{ .name = try std.ascii.allocLowerString(a, h.name), .value = h.value });
    std.mem.sort(Header, hs.items, {}, struct {
        fn lt(_: void, x: Header, y: Header) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);

    const path = try encodePath(a, req.path);
    const query = try encodeQuery(a, req.params);
    var creq: Writer.Allocating = .init(a);
    var signed_names: Writer.Allocating = .init(a);
    {
        const w = &creq.writer;
        w.print("{s}\n{s}\n{s}\n", .{ req.method, path, query }) catch return error.OutOfMemory;
        for (hs.items, 0..) |h, i| {
            w.print("{s}:", .{h.name}) catch return error.OutOfMemory;
            sv.writeHeaderValue(w, h.value) catch return error.OutOfMemory;
            w.writeByte('\n') catch return error.OutOfMemory;
            if (i > 0) signed_names.writer.writeByte(';') catch return error.OutOfMemory;
            signed_names.writer.writeAll(h.name) catch return error.OutOfMemory;
        }
        w.print("\n{s}\n{s}", .{ signed_names.written(), req.payload_sha256_hex }) catch return error.OutOfMemory;
    }
    const scope: sv.Scope = .{ .date = amz_date[0..8], .region = req.region, .service = req.service };
    var sts: Writer.Allocating = .init(a);
    sv.writeStringToSign(&sts.writer, amz_date, scope, creq.written()) catch return error.OutOfMemory;
    const sig = sv.sign(sv.signingKey(creds.secret_key, scope.date, scope.region, scope.service), sts.written());
    const auth = std.fmt.allocPrint(a, sv.algorithm ++ " Credential={s}/{f}, SignedHeaders={s}, Signature={s}", .{ creds.access_key, scope, signed_names.written(), &sig }) catch return error.OutOfMemory;

    var out: std.ArrayList(Header) = .empty;
    for (hs.items) |h| if (!std.mem.eql(u8, h.name, "host")) try out.append(a, h);
    try out.append(a, .{ .name = "authorization", .value = auth });
    const target = if (query.len == 0) path else try std.fmt.allocPrint(a, "{s}?{s}", .{ path, query });
    return .{ .target = target, .headers = out.items };
}

/// Query-string presigned GET URL `base` + path (base like `http://host:9000`).
pub fn presign(a: Allocator, creds: Credentials, base: []const u8, host: []const u8, path: []const u8, extra: []const Param, expires_s: u32, region: []const u8, now_s: i64) Error![]const u8 {
    var date_buf: [16]u8 = undefined;
    const amz_date = amzDate(now_s, &date_buf);
    var cred_buf: [256]u8 = undefined;
    const credential = std.fmt.bufPrint(&cred_buf, "{s}/{s}/{s}/s3/" ++ sv.terminator, .{ creds.access_key, amz_date[0..8], region }) catch return error.OutOfMemory;
    var exp_buf: [12]u8 = undefined;
    var params: std.ArrayList(Param) = .empty;
    try params.appendSlice(a, extra);
    try params.append(a, .{ .name = "X-Amz-Algorithm", .value = sv.algorithm });
    try params.append(a, .{ .name = "X-Amz-Credential", .value = try a.dupe(u8, credential) });
    try params.append(a, .{ .name = "X-Amz-Date", .value = try a.dupe(u8, amz_date) });
    try params.append(a, .{ .name = "X-Amz-Expires", .value = try a.dupe(u8, std.fmt.bufPrint(&exp_buf, "{d}", .{expires_s}) catch unreachable) });
    try params.append(a, .{ .name = "X-Amz-SignedHeaders", .value = "host" });
    if (creds.session_token.len > 0) try params.append(a, .{ .name = "X-Amz-Security-Token", .value = creds.session_token });
    const enc_path = try encodePath(a, path);
    const query = try encodeQuery(a, params.items);
    const creq = std.fmt.allocPrint(a, "GET\n{s}\n{s}\nhost:{s}\n\nhost\n" ++ sv.unsigned_payload, .{ enc_path, query, host }) catch return error.OutOfMemory;
    const scope: sv.Scope = .{ .date = amz_date[0..8], .region = region, .service = "s3" };
    var sts: Writer.Allocating = .init(a);
    sv.writeStringToSign(&sts.writer, amz_date, scope, creq) catch return error.OutOfMemory;
    const sig = sv.sign(sv.signingKey(creds.secret_key, scope.date, region, "s3"), sts.written());
    return std.fmt.allocPrint(a, "{s}{s}?{s}&X-Amz-Signature={s}", .{ base, enc_path, query, &sig }) catch return error.OutOfMemory;
}

/// Percent-decodes `s` ('+' kept as is, as S3 paths require).
pub fn decode(a: Allocator, s: []const u8, plus_is_space: bool) Error![]const u8 {
    if (std.mem.indexOfAny(u8, s, if (plus_is_space) "%+" else "%") == null) return s;
    const out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                out[n] = b;
                n += 1;
                i += 2;
                continue;
            } else |_| {}
        }
        out[n] = if (plus_is_space and s[i] == '+') ' ' else s[i];
        n += 1;
    }
    return out[0..n];
}

/// Splits a raw query string into decoded params; '+' stays literal.
pub fn parseQuery(a: Allocator, raw: []const u8) Error![]Param {
    var out: std.ArrayList(Param) = .empty;
    var it = std.mem.tokenizeScalar(u8, raw, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        const k = kv[0 .. eq orelse kv.len];
        const v = if (eq) |e| kv[e + 1 ..] else "";
        try out.append(a, .{ .name = try decode(a, k, false), .value = try decode(a, v, false) });
    }
    return out.items;
}

const testing = std.testing;

test "amz date" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("20130524T000000Z", amzDate(1369353600, &b));
}

test "sign matches the published GET object example" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const creds: Credentials = .{ .access_key = "AKIAIOSFODNN7EXAMPLE", .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
    const s = try sign(a, creds, .{
        .method = "GET",
        .host = "examplebucket.s3.amazonaws.com",
        .path = "/test.txt",
        .headers = &.{.{ .name = "range", .value = "bytes=0-9" }},
        .payload_sha256_hex = sv.empty_sha256_hex,
    }, 1369353600);
    const auth = s.headers[s.headers.len - 1].value;
    try testing.expect(std.mem.endsWith(u8, auth, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"));
    try testing.expectEqualStrings("/test.txt", s.target);
}

test "presign matches the published example" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const creds: Credentials = .{ .access_key = "AKIAIOSFODNN7EXAMPLE", .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
    const url = try presign(a, creds, "https://examplebucket.s3.amazonaws.com", "examplebucket.s3.amazonaws.com", "/test.txt", &.{}, 86400, "us-east-1", 1369353600);
    try testing.expect(std.mem.endsWith(u8, url, "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"));
}

test "query parsing decodes names and values" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ps = try parseQuery(arena.allocator(), "prefix=a%2Fb%20c&versioning&list-type=2");
    try testing.expectEqual(@as(usize, 3), ps.len);
    try testing.expectEqualStrings("a/b c", ps[0].value);
    try testing.expectEqualStrings("versioning", ps[1].name);
    try testing.expectEqualStrings("", ps[1].value);
    try testing.expectEqualStrings("/a%20b/%2B", try encodePath(arena.allocator(), "/a b/+"));
}
