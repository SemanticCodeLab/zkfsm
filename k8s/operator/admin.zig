//! Calls into a zkfsm cluster: health, IAM bootstrap, buckets and pool
//! decommission through the MinIO-compatible admin API, signed with SigV4.
const std = @import("std");
const sio = @import("sio");

const A = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Creds = struct { access: []const u8, secret: []const u8 };

pub const Result = struct {
    status: u16,
    body: []const u8,

    pub fn ok(r: Result) bool {
        return r.status >= 200 and r.status < 300;
    }
};

pub const Client = struct {
    http: std.http.Client,
    creds: Creds,
    region: []const u8 = "us-east-1",

    /// `ca_file` trusts the cluster CA for https endpoints.
    pub fn init(gpa: A, creds: Creds, ca_file: ?[]const u8) !Client {
        var c: Client = .{ .http = .{ .allocator = gpa }, .creds = creds };
        if (ca_file) |f| {
            try c.http.ca_bundle.addCertsFromFilePathAbsolute(gpa, f);
            c.http.next_https_rescan_certs = false;
        }
        return c;
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// `base` is scheme://host:port; `query` must already be canonical (sorted, encoded).
    pub fn call(c: *Client, a: A, method: std.http.Method, base: []const u8, path: []const u8, qs: []const u8, body: []const u8, extra: []const std.http.Header) !Result {
        const uri = try std.Uri.parse(base);
        const host = try std.fmt.allocPrint(a, "{s}:{d}", .{ uri.host.?.percent_encoded, uri.port.? });
        const now = std.time.timestamp();
        const signed = try sign(a, c.creds, c.region, method, host, path, qs, body, now);
        var headers: std.ArrayList(std.http.Header) = .empty;
        try headers.appendSlice(a, &.{
            .{ .name = "x-amz-date", .value = signed.date },
            .{ .name = "x-amz-content-sha256", .value = signed.payload_hash },
            .{ .name = "authorization", .value = signed.authorization },
        });
        try headers.appendSlice(a, extra);
        const url = if (qs.len > 0) try std.fmt.allocPrint(a, "{s}{s}?{s}", .{ base, path, qs }) else try std.fmt.allocPrint(a, "{s}{s}", .{ base, path });
        var out: std.Io.Writer.Allocating = .init(a);
        const res = try c.http.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = if (method == .GET or method == .HEAD) null else body,
            .extra_headers = headers.items,
            .response_writer = &out.writer,
            .keep_alive = false,
        });
        return .{ .status = @intFromEnum(res.status), .body = out.written() };
    }

    pub fn ready(c: *Client, a: A, base: []const u8) bool {
        const url = std.fmt.allocPrint(a, "{s}/health/ready", .{base}) catch return false;
        const res = c.http.fetch(.{ .location = .{ .url = url }, .method = .GET, .keep_alive = false }) catch return false;
        return res.status == .ok;
    }

    pub fn addPolicy(c: *Client, a: A, base: []const u8, name: []const u8, doc: []const u8) !Result {
        return c.call(a, .PUT, base, "/minio/admin/v3/add-canned-policy", try query(a, &.{.{ "name", name }}), doc, &.{});
    }

    pub fn addUser(c: *Client, a: A, base: []const u8, access: []const u8, secret: []const u8) !Result {
        const plain = try std.json.Stringify.valueAlloc(a, .{ .secretKey = secret, .status = "enabled" }, .{});
        const body = try sio.encrypt(a, c.creds.secret, plain);
        return c.call(a, .PUT, base, "/minio/admin/v3/add-user", try query(a, &.{.{ "accessKey", access }}), body, &.{});
    }

    pub fn setPolicies(c: *Client, a: A, base: []const u8, user: []const u8, policies: []const []const u8) !Result {
        const names = try std.mem.join(a, ",", policies);
        return c.call(a, .PUT, base, "/minio/admin/v3/set-user-or-group-policy", try query(a, &.{ .{ "isGroup", "false" }, .{ "policyName", names }, .{ "userOrGroup", user } }), "", &.{});
    }

    /// Creates the bucket; an existing bucket owned by root counts as success.
    pub fn makeBucket(c: *Client, a: A, base: []const u8, name: []const u8, object_lock: bool) !Result {
        const path = try std.fmt.allocPrint(a, "/{s}", .{name});
        const extra: []const std.http.Header = if (object_lock) &.{.{ .name = "x-amz-bucket-object-lock-enabled", .value = "true" }} else &.{};
        var r = try c.call(a, .PUT, base, path, "", "", extra);
        if (r.status == 409 and std.mem.indexOf(u8, r.body, "BucketAlreadyOwnedByYou") != null) r.status = 200;
        return r;
    }

    pub fn decommission(c: *Client, a: A, base: []const u8, pool: []const u8) !Result {
        return c.call(a, .POST, base, "/minio/admin/v3/pools/decommission", try query(a, &.{.{ "pool", pool }}), "", &.{});
    }

    pub fn poolStatus(c: *Client, a: A, base: []const u8, pool: []const u8) !Result {
        return c.call(a, .GET, base, "/minio/admin/v3/pools/status", try query(a, &.{.{ "pool", pool }}), "", &.{});
    }
};

/// Canonical query string from pairs already sorted by key.
pub fn query(a: A, pairs: []const [2][]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (pairs, 0..) |p, i| {
        if (i > 0) try out.append(a, '&');
        try uriEncode(a, &out, p[0], true);
        try out.append(a, '=');
        try uriEncode(a, &out, p[1], true);
    }
    return out.items;
}

fn uriEncode(a: A, out: *std.ArrayList(u8), s: []const u8, slash: bool) !void {
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~' or (ch == '/' and !slash)) {
            try out.append(a, ch);
        } else try out.print(a, "%{X:0>2}", .{ch});
    }
}

pub const Signed = struct { date: []const u8, payload_hash: []const u8, authorization: []const u8 };

fn hex(a: A, bytes: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{x}", .{bytes});
}

pub fn sign(a: A, creds: Creds, region: []const u8, method: std.http.Method, host: []const u8, path: []const u8, canonical_query: []const u8, body: []const u8, now: i64) !Signed {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(now) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    const day = try std.fmt.allocPrint(a, "{d:0>4}{d:0>2}{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 });
    const date = try std.fmt.allocPrint(a, "{s}T{d:0>2}{d:0>2}{d:0>2}Z", .{ day, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
    var ph: [32]u8 = undefined;
    Sha256.hash(body, &ph, .{});
    const payload_hash = try hex(a, &ph);

    var enc_path: std.ArrayList(u8) = .empty;
    try uriEncode(a, &enc_path, path, false);
    const creq = try std.fmt.allocPrint(a, "{s}\n{s}\n{s}\nhost:{s}\nx-amz-content-sha256:{s}\nx-amz-date:{s}\n\nhost;x-amz-content-sha256;x-amz-date\n{s}", .{
        @tagName(method), enc_path.items, canonical_query, host, payload_hash, date, payload_hash,
    });
    var ch: [32]u8 = undefined;
    Sha256.hash(creq, &ch, .{});
    const scope = try std.fmt.allocPrint(a, "{s}/{s}/s3/aws4_request", .{ day, region });
    const sts = try std.fmt.allocPrint(a, "AWS4-HMAC-SHA256\n{s}\n{s}\n{s}", .{ date, scope, try hex(a, &ch) });

    var k: [32]u8 = undefined;
    const k0 = try std.fmt.allocPrint(a, "AWS4{s}", .{creds.secret});
    Hmac.create(&k, day, k0);
    Hmac.create(&k, region, &k);
    Hmac.create(&k, "s3", &k);
    Hmac.create(&k, "aws4_request", &k);
    var sig: [32]u8 = undefined;
    Hmac.create(&sig, sts, &k);
    return .{
        .date = date,
        .payload_hash = payload_hash,
        .authorization = try std.fmt.allocPrint(a, "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={s}", .{ creds.access, scope, try hex(a, &sig) }),
    };
}

/// Parsed decommission progress from /pools/status.
pub const DecomProgress = struct { complete: bool, failed: bool, canceled: bool };

pub fn parseDecom(a: A, body: []const u8) ?DecomProgress {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return null;
    if (v != .object) return null;
    const d = v.object.get("decommissionInfo") orelse return null;
    if (d != .object) return null;
    const f = struct {
        fn b(o: std.json.ObjectMap, k: []const u8) bool {
            const x = o.get(k) orelse return false;
            return x == .bool and x.bool;
        }
    };
    return .{ .complete = f.b(d.object, "complete"), .failed = f.b(d.object, "failed"), .canceled = f.b(d.object, "canceled") };
}

test "sigv4 signature" {
    // Expected value computed independently (Python hmac/hashlib).
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try sign(a, .{ .access = "AKIAIOSFODNN7EXAMPLE", .secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }, "us-east-1", .GET, "examplebucket.s3.example.test", "/test.txt", "", "", 1369353600);
    try std.testing.expectEqualStrings("20130524T000000Z", s.date);
    try std.testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", s.payload_hash);
    try std.testing.expectEqualStrings("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=010fd9672f6bffee9fa227e04938ba9301fc2ca28a3cfd4166a9adef54fb6914", s.authorization);
}

test "query encoding and decom parsing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("pool=http%3A%2F%2Fh-%7B0...3%7D%3A9000%2Fd", try query(a, &.{.{ "pool", "http://h-{0...3}:9000/d" }}));
    const p = parseDecom(a, "{\"id\":1,\"decommissionInfo\":{\"complete\":true}}").?;
    try std.testing.expect(p.complete and !p.failed);
    try std.testing.expect(parseDecom(a, "nope") == null);
}
