//! Remote replication targets (the madmin BucketTarget model): parsing the admin
//! request, persisting per bucket, and rendering list-remote-targets responses.
const std = @import("std");
const client = @import("client.zig");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;

/// Persisted form; field names are this store's own.
pub const Target = struct {
    arn: []const u8,
    source_bucket: []const u8,
    target_bucket: []const u8,
    endpoint: []const u8,
    secure: bool = false,
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8 = "",
    path: []const u8 = "auto",
    api: []const u8 = "s3v4",
    bandwidth: i64 = 0,
    sync: bool = false,
    storage_class: []const u8 = "",
    health_check_ns: i64 = 0,
    disable_proxy: bool = false,
    deployment_id: []const u8 = "",
    reset_id: []const u8 = "",

    pub fn remote(t: Target) client.Remote {
        return .{
            .endpoint = t.endpoint,
            .secure = t.secure,
            .access_key = t.access_key,
            .secret_key = t.secret_key,
            .region = if (t.region.len > 0) t.region else "us-east-1",
            .bandwidth = if (t.bandwidth > 0) @intCast(t.bandwidth) else 0,
        };
    }
};

pub const ParseError = error{ Malformed, OutOfMemory };

fn str(o: std.json.ObjectMap, k: []const u8) []const u8 {
    const v = o.get(k) orelse return "";
    return if (v == .string) v.string else "";
}

fn boolean(o: std.json.ObjectMap, k: []const u8) bool {
    const v = o.get(k) orelse return false;
    return v == .bool and v.bool;
}

fn int(o: std.json.ObjectMap, k: []const u8) i64 {
    const v = o.get(k) orelse return 0;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => 0,
    };
}

/// A madmin BucketTarget JSON document (the decrypted set-remote-target body).
pub fn parseRequest(a: Allocator, doc: []const u8) ParseError!Target {
    const v = std.json.parseFromSliceLeaky(Value, a, doc, .{}) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Malformed;
    if (v != .object) return error.Malformed;
    const o = v.object;
    var t: Target = .{
        .arn = str(o, "arn"),
        .source_bucket = str(o, "sourcebucket"),
        .target_bucket = str(o, "targetbucket"),
        .endpoint = str(o, "endpoint"),
        .secure = boolean(o, "secure"),
        .access_key = "",
        .secret_key = "",
        .region = str(o, "region"),
        .path = str(o, "path"),
        .api = str(o, "api"),
        .bandwidth = int(o, "bandwidthlimit"),
        .sync = boolean(o, "replicationSync"),
        .storage_class = str(o, "storageclass"),
        .health_check_ns = int(o, "healthCheckDuration"),
        .disable_proxy = boolean(o, "disableProxy"),
        .deployment_id = str(o, "deploymentID"),
        .reset_id = str(o, "resetID"),
    };
    if (o.get("credentials")) |c| if (c == .object) {
        t.access_key = str(c.object, "accessKey");
        t.secret_key = str(c.object, "secretKey");
    };
    const ty = str(o, "type");
    if (ty.len > 0 and !std.mem.eql(u8, ty, "replication")) return error.Malformed;
    if (t.endpoint.len == 0 or t.target_bucket.len == 0) return error.Malformed;
    return t;
}

pub const Health = struct { online: bool = false, last_online_ns: i128 = 0, offline_count: u64 = 0, downtime_ns: i128 = 0, latency_ns: u64 = 0 };

/// Writes one madmin BucketTarget; credentials carry no secret.
pub fn writeJson(w: *std.json.Stringify, t: Target, h: Health) std.Io.Writer.Error!void {
    var tb: [32]u8 = undefined;
    try w.beginObject();
    const fields = .{
        .{ "sourcebucket", t.source_bucket },
        .{ "endpoint", t.endpoint },
        .{ "targetbucket", t.target_bucket },
        .{ "path", t.path },
        .{ "api", t.api },
        .{ "arn", t.arn },
        .{ "type", "replication" },
        .{ "region", t.region },
        .{ "storageclass", t.storage_class },
        .{ "deploymentID", t.deployment_id },
        .{ "resetID", t.reset_id },
    };
    inline for (fields) |f| {
        try w.objectField(f[0]);
        try w.write(f[1]);
    }
    try w.objectField("credentials");
    try w.write(.{ .accessKey = t.access_key });
    try w.objectField("secure");
    try w.write(t.secure);
    try w.objectField("bandwidthlimit");
    try w.write(t.bandwidth);
    try w.objectField("replicationSync");
    try w.write(t.sync);
    try w.objectField("healthCheckDuration");
    try w.write(t.health_check_ns);
    try w.objectField("disableProxy");
    try w.write(t.disable_proxy);
    try w.objectField("isOnline");
    try w.write(h.online);
    try w.objectField("lastOnline");
    try w.write(rfc3339(h.last_online_ns, &tb));
    try w.objectField("totalDowntime");
    try w.write(@as(i64, @intCast(@min(h.downtime_ns, std.math.maxInt(i64)))));
    try w.objectField("offlineCount");
    try w.write(h.offline_count);
    try w.objectField("latency");
    try w.write(.{ .curr = h.latency_ns, .avg = h.latency_ns, .max = h.latency_ns });
    try w.objectField("edge");
    try w.write(false);
    try w.objectField("edgeSyncBeforeExpiry");
    try w.write(false);
    try w.endObject();
}

/// RFC 3339 UTC with nanoseconds; Go's zero time for 0.
pub fn rfc3339(ns: i128, buf: *[32]u8) []const u8 {
    if (ns <= 0) return "0001-01-01T00:00:00Z";
    const secs: u64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const frac: u64 = @intCast(@mod(ns, std.time.ns_per_s));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}Z", .{
        yd.year,              md.month.numeric(),      @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        frac,
    }) catch unreachable; // fixed width
}

/// Parses RFC 3339 (`2006-01-02T15:04:05[.frac](Z|±hh:mm)`) to ns since epoch.
pub fn parseRfc3339(s: []const u8) ?i128 {
    if (s.len < 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(u16, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const h = std.fmt.parseInt(u8, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(u8, s[14..16], 10) catch return null;
    const se = std.fmt.parseInt(u8, s[17..19], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31 or y < 1970) return null;
    var i: usize = 19;
    var frac: i128 = 0;
    if (i < s.len and s[i] == '.') {
        i += 1;
        var digits: u32 = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
            if (digits < 9) {
                frac = frac * 10 + (s[i] - '0');
                digits += 1;
            }
        }
        while (digits < 9) : (digits += 1) frac *= 10;
    }
    var offset_s: i64 = 0;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) {
        if (s.len < i + 6) return null;
        const oh = std.fmt.parseInt(i64, s[i + 1 .. i + 3], 10) catch return null;
        const om = std.fmt.parseInt(i64, s[i + 4 .. i + 6], 10) catch return null;
        offset_s = (oh * 3600 + om * 60) * @as(i64, if (s[i] == '-') -1 else 1);
    } else if (i >= s.len or s[i] != 'Z') return null;
    var days: i64 = 0;
    var yy: u16 = 1970;
    while (yy < y) : (yy += 1) days += if (std.time.epoch.isLeapYear(yy)) 366 else 365;
    var mm: u4 = 1;
    while (mm < mo) : (mm += 1) days += std.time.epoch.getDaysInMonth(y, @enumFromInt(mm));
    days += d - 1;
    const secs = days * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + se - offset_s;
    return @as(i128, secs) * std.time.ns_per_s + frac;
}

/// A fresh ARN for a target bucket.
pub fn newArn(a: Allocator, region: []const u8, target_bucket: []const u8) Allocator.Error![]const u8 {
    var b: [16]u8 = undefined;
    std.crypto.random.bytes(&b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = std.fmt.bytesToHex(b, .lower);
    return std.fmt.allocPrint(a, "arn:minio:replication:{s}:{s}-{s}-{s}-{s}-{s}:{s}", .{ region, h[0..8], h[8..12], h[12..16], h[16..20], h[20..32], target_bucket });
}

test "parse a madmin target and render it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"sourcebucket":"src","endpoint":"127.0.0.1:9002","credentials":{"accessKey":"ak","secretKey":"sk12345678","expiration":"0001-01-01T00:00:00Z"},
        \\"targetbucket":"dst","secure":false,"path":"auto","api":"s3v4","type":"replication","bandwidthlimit":1048576,"replicationSync":false,
        \\"healthCheckDuration":0,"disableProxy":false,"resetBeforeDate":"0001-01-01T00:00:00Z","totalDowntime":0,"lastOnline":"0001-01-01T00:00:00Z",
        \\"isOnline":false,"latency":{"curr":0,"avg":0,"max":0},"edge":false,"edgeSyncBeforeExpiry":false,"offlineCount":0}
    ;
    var t = try parseRequest(a, doc);
    try std.testing.expectEqualStrings("sk12345678", t.secret_key);
    try std.testing.expectEqual(@as(i64, 1048576), t.bandwidth);
    t.arn = try newArn(a, "", "dst");
    try std.testing.expect(std.mem.startsWith(u8, t.arn, "arn:minio:replication::"));
    var out: std.Io.Writer.Allocating = .init(a);
    var jw: std.json.Stringify = .{ .writer = &out.writer };
    try writeJson(&jw, t, .{});
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "sk12345678") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"targetbucket\":\"dst\"") != null);
    try std.testing.expectError(error.Malformed, parseRequest(a, "{\"type\":\"ilm\",\"endpoint\":\"x\",\"targetbucket\":\"y\"}"));
}

test "rfc3339 roundtrip" {
    var b: [32]u8 = undefined;
    const ns: i128 = 1_700_000_000_123_456_789;
    try std.testing.expectEqual(ns, parseRfc3339(rfc3339(ns, &b)).?);
    try std.testing.expectEqual(@as(i128, 3600 * std.time.ns_per_s), parseRfc3339("1970-01-01T02:00:00+01:00").?);
    try std.testing.expect(parseRfc3339("nope") == null);
}
