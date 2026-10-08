//! Typed batch job definitions (replicate, keyrotate, expire) decoded from the
//! YAML document `mc batch start` sends, with the filter and unit parsers they use.
const std = @import("std");
const yaml = @import("yaml.zig");

const Allocator = std.mem.Allocator;
const Node = yaml.Node;

pub const Error = error{ OutOfMemory, InvalidJob };

pub const max_kv_filters = 64;
pub const max_rules = 64;
pub const max_text = 1024;

pub const Kind = enum {
    replicate,
    keyrotate,
    expire,

    pub fn text(k: Kind) []const u8 {
        return @tagName(k);
    }
    pub fn parse(s: []const u8) ?Kind {
        return std.meta.stringToEnum(Kind, s);
    }
};

pub const KeyValue = struct { key: []const u8, value: []const u8 };

/// Object filters shared by replicate and keyrotate (times in ns since epoch).
pub const Filter = struct {
    newer_than_ns: ?i128 = null,
    older_than_ns: ?i128 = null,
    created_after_ns: ?i128 = null,
    created_before_ns: ?i128 = null,
    tags: []const KeyValue = &.{},
    metadata: []const KeyValue = &.{},
    /// keyrotate only: match objects sealed under this KMS key.
    kms_key: []const u8 = "",
};

pub const Notify = struct { endpoint: []const u8 = "", token: []const u8 = "" };

pub const Retry = struct {
    attempts: u32 = 3,
    delay_ns: u64 = 250 * std.time.ns_per_ms,
};

pub const Location = struct {
    bucket: []const u8,
    prefix: []const u8 = "",
    /// `host[:port]`; empty means this deployment.
    endpoint: []const u8 = "",
    secure: bool = false,
    access_key: []const u8 = "",
    secret_key: []const u8 = "",
    session_token: []const u8 = "",

    pub fn isLocal(l: Location) bool {
        return l.endpoint.len == 0;
    }
};

pub const Replicate = struct {
    source: Location,
    target: Location,
    filter: Filter = .{},
};

pub const Encryption = enum { sse_s3, sse_kms };

pub const KeyRotate = struct {
    bucket: []const u8,
    prefix: []const u8 = "",
    encryption: Encryption,
    key: []const u8 = "",
    /// Encryption context as canonical pairs (`k=v,k2=v2` or a JSON object).
    context: []const KeyValue = &.{},
    filter: Filter = .{},
};

pub const RuleType = enum { object, deleted };

pub const Rule = struct {
    type: RuleType,
    name: []const u8 = "",
    older_than_ns: ?u64 = null,
    created_before_ns: ?i128 = null,
    tags: []const KeyValue = &.{},
    metadata: []const KeyValue = &.{},
    size_lt: ?u64 = null,
    size_gt: ?u64 = null,
    retain_versions: u32 = 0,
};

pub const Expire = struct {
    bucket: []const u8,
    prefix: []const u8 = "",
    rules: []const Rule,
};

pub const Job = struct {
    kind: Kind,
    body: union(Kind) { replicate: Replicate, keyrotate: KeyRotate, expire: Expire },
    notify: Notify = .{},
    retry: Retry = .{},
};

/// Decodes a job document; times relative to `now_ns` (newerThan/olderThan) are resolved here.
pub fn parse(a: Allocator, doc: []const u8, now_ns: i128) Error!Job {
    const root = yaml.parse(a, doc) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidJob;
    if (root != .map or root.map.len != 1) return error.InvalidJob;
    const kind = Kind.parse(root.map[0].key) orelse return error.InvalidJob;
    const j = root.map[0].value;
    if (j != .map) return error.InvalidJob;
    if (j.getStr("apiVersion")) |v| if (!std.mem.eql(u8, v, "v1")) return error.InvalidJob;
    var out: Job = switch (kind) {
        .replicate => .{ .kind = kind, .body = .{ .replicate = try parseReplicate(a, j, now_ns) } },
        .keyrotate => .{ .kind = kind, .body = .{ .keyrotate = try parseKeyRotate(a, j, now_ns) } },
        .expire => .{ .kind = kind, .body = .{ .expire = try parseExpire(a, j) } },
    };
    // Expire keeps notify/retry at the top level, the others under flags.
    const holder = if (kind == .expire) j else (j.get("flags") orelse Node.null);
    if (holder.get("notify")) |n| out.notify = .{ .endpoint = try text(n.getStr("endpoint")), .token = try text(n.getStr("token")) };
    if (out.notify.endpoint.len > 0 and !std.mem.startsWith(u8, out.notify.endpoint, "http://") and !std.mem.startsWith(u8, out.notify.endpoint, "https://"))
        return error.InvalidJob;
    if (holder.get("retry")) |r| {
        if (r.getStr("attempts")) |s| out.retry.attempts = std.fmt.parseInt(u32, s, 10) catch return error.InvalidJob;
        if (out.retry.attempts > 100) return error.InvalidJob;
        if (r.getStr("delay")) |s| out.retry.delay_ns = try duration(s);
        if (out.retry.delay_ns > 3600 * std.time.ns_per_s) return error.InvalidJob;
    }
    return out;
}

fn text(s: ?[]const u8) Error![]const u8 {
    const v = s orelse return "";
    if (v.len > max_text) return error.InvalidJob;
    return v;
}

fn required(n: Node, key: []const u8) Error![]const u8 {
    const v = try text(n.getStr(key));
    if (v.len == 0) return error.InvalidJob;
    return v;
}

fn location(n: Node) Error!Location {
    if (n != .map) return error.InvalidJob;
    var l: Location = .{ .bucket = try required(n, "bucket"), .prefix = try text(n.getStr("prefix")) };
    if (n.getStr("type")) |t| if (!std.mem.eql(u8, t, "s3") and !std.mem.eql(u8, t, "minio")) return error.InvalidJob;
    const ep = try text(n.getStr("endpoint"));
    if (ep.len > 0) {
        l.secure = std.ascii.startsWithIgnoreCase(ep, "https://");
        if (!l.secure and !std.ascii.startsWithIgnoreCase(ep, "http://")) return error.InvalidJob;
        const rest = ep[if (l.secure) 8 else 7..];
        const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
        if (end == 0) return error.InvalidJob;
        l.endpoint = rest[0..end];
        const c = n.get("credentials") orelse return error.InvalidJob;
        l.access_key = try required(c, "accessKey");
        l.secret_key = try required(c, "secretKey");
        l.session_token = try text(c.getStr("sessionToken"));
    }
    return l;
}

fn parseReplicate(a: Allocator, j: Node, now_ns: i128) Error!Replicate {
    const r: Replicate = .{
        .source = try location(j.get("source") orelse return error.InvalidJob),
        .target = try location(j.get("target") orelse return error.InvalidJob),
        .filter = try filter(a, j.get("flags") orelse Node.null, now_ns),
    };
    // One side must be this deployment.
    if (!r.source.isLocal() and !r.target.isLocal()) return error.InvalidJob;
    if (r.source.isLocal() and r.target.isLocal() and std.mem.eql(u8, r.source.bucket, r.target.bucket)) return error.InvalidJob;
    return r;
}

fn parseKeyRotate(a: Allocator, j: Node, now_ns: i128) Error!KeyRotate {
    const enc = j.get("encryption") orelse return error.InvalidJob;
    const t = try required(enc, "type");
    var k: KeyRotate = .{
        .bucket = try required(j, "bucket"),
        .prefix = try text(j.getStr("prefix")),
        .encryption = if (std.ascii.eqlIgnoreCase(t, "sse-s3")) .sse_s3 else if (std.ascii.eqlIgnoreCase(t, "sse-kms")) .sse_kms else return error.InvalidJob,
        .key = try text(enc.getStr("key")),
        .filter = try filter(a, j.get("flags") orelse Node.null, now_ns),
    };
    if (k.encryption == .sse_kms and k.key.len == 0) return error.InvalidJob;
    if (k.encryption == .sse_s3 and k.key.len > 0) return error.InvalidJob;
    k.context = try contextPairs(a, try text(enc.getStr("context")));
    return k;
}

/// `k1=v1,k2=v2` or a flat JSON object.
fn contextPairs(a: Allocator, s: []const u8) Error![]const KeyValue {
    if (s.len == 0) return &.{};
    var out: std.ArrayList(KeyValue) = .empty;
    if (s[0] == '{') {
        const v = std.json.parseFromSliceLeaky(std.json.Value, a, s, .{}) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidJob;
        if (v != .object or v.object.count() > max_kv_filters) return error.InvalidJob;
        for (v.object.keys(), v.object.values()) |k, val| {
            if (val != .string) return error.InvalidJob;
            try out.append(a, .{ .key = k, .value = val.string });
        }
        return out.items;
    }
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| {
        const eq = std.mem.indexOfScalar(u8, p, '=') orelse return error.InvalidJob;
        if (out.items.len >= max_kv_filters or eq == 0) return error.InvalidJob;
        try out.append(a, .{ .key = std.mem.trim(u8, p[0..eq], " "), .value = std.mem.trim(u8, p[eq + 1 ..], " ") });
    }
    return out.items;
}

fn filter(a: Allocator, flags: Node, now_ns: i128) Error!Filter {
    const f = flags.get("filter") orelse return .{};
    var out: Filter = .{
        .tags = try kvList(a, f.get("tags")),
        .metadata = try kvList(a, f.get("metadata")),
        .kms_key = try text(f.getStr("kmskey")),
    };
    if (f.getStr("newerThan")) |s| out.newer_than_ns = now_ns - @as(i128, try duration(s));
    if (f.getStr("olderThan")) |s| out.older_than_ns = now_ns - @as(i128, try duration(s));
    if (f.getStr("createdAfter")) |s| out.created_after_ns = try date(s);
    if (f.getStr("createdBefore")) |s| out.created_before_ns = try date(s);
    return out;
}

fn kvList(a: Allocator, n: ?Node) Error![]const KeyValue {
    const v = n orelse return &.{};
    if (v == .null) return &.{};
    if (v != .seq or v.seq.len > max_kv_filters) return error.InvalidJob;
    const out = try a.alloc(KeyValue, v.seq.len);
    for (v.seq, out) |item, *o| o.* = .{ .key = try required(item, "key"), .value = try text(item.getStr("value")) };
    return out;
}

fn parseExpire(a: Allocator, j: Node) Error!Expire {
    const rules_n = j.get("rules") orelse return error.InvalidJob;
    if (rules_n != .seq or rules_n.seq.len == 0 or rules_n.seq.len > max_rules) return error.InvalidJob;
    const rules = try a.alloc(Rule, rules_n.seq.len);
    for (rules_n.seq, rules) |r, *o| {
        const t = try required(r, "type");
        o.* = .{
            .type = if (std.mem.eql(u8, t, "object")) .object else if (std.mem.eql(u8, t, "deleted")) .deleted else return error.InvalidJob,
            .name = try text(r.getStr("name")),
            .tags = try kvList(a, r.get("tags")),
            .metadata = try kvList(a, r.get("metadata")),
        };
        if (r.getStr("olderThan")) |s| o.older_than_ns = try duration(s);
        if (r.getStr("createdBefore")) |s| o.created_before_ns = try date(s);
        if (r.get("size")) |s| {
            if (s.getStr("lessThan")) |v| o.size_lt = try size(v);
            if (s.getStr("greaterThan")) |v| o.size_gt = try size(v);
        }
        if (r.get("purge")) |p| if (p.getStr("retainVersions")) |v| {
            o.retain_versions = std.fmt.parseInt(u32, v, 10) catch return error.InvalidJob;
        };
        // Tag, metadata and size filters need object data; delete markers have none.
        if (o.type == .deleted and (o.tags.len > 0 or o.metadata.len > 0 or o.size_lt != null or o.size_gt != null)) return error.InvalidJob;
    }
    return .{ .bucket = try required(j, "bucket"), .prefix = try text(j.getStr("prefix")), .rules = rules };
}

/// Durations like `7d10h31s`, `500ms`, `1.5h`; units ns, us, ms, s, m, h, d.
pub fn duration(s0: []const u8) Error!u64 {
    const s = std.mem.trim(u8, s0, " ");
    if (s.len == 0 or s.len > 64) return error.InvalidJob;
    if (std.mem.eql(u8, s, "0")) return 0;
    var total: f64 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const start = i;
        while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '.')) i += 1;
        if (i == start) return error.InvalidJob;
        const num = std.fmt.parseFloat(f64, s[start..i]) catch return error.InvalidJob;
        const ustart = i;
        while (i < s.len and std.ascii.isAlphabetic(s[i])) i += 1;
        const unit: f64 = blk: {
            const u = s[ustart..i];
            const units = .{ .{ "ns", 1 }, .{ "us", 1e3 }, .{ "ms", 1e6 }, .{ "s", 1e9 }, .{ "m", 60e9 }, .{ "h", 3600e9 }, .{ "d", 86400e9 } };
            inline for (units) |x| if (std.mem.eql(u8, u, x[0])) break :blk x[1];
            return error.InvalidJob;
        };
        total += num * unit;
    }
    if (!(total >= 0) or total > 1e19) return error.InvalidJob;
    return @intFromFloat(total);
}

/// Sizes like `10MiB`, `1MB`, `256KiB`, `42`.
pub fn size(s0: []const u8) Error!u64 {
    const s = std.mem.trim(u8, s0, " ");
    var i: usize = 0;
    while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
    if (i == 0 or i > 20) return error.InvalidJob;
    const n = std.fmt.parseInt(u64, s[0..i], 10) catch return error.InvalidJob;
    const u = std.mem.trim(u8, s[i..], " ");
    const units = .{
        .{ "", 1 },                        .{ "B", 1 },
        .{ "KB", 1000 },                   .{ "KiB", 1 << 10 },
        .{ "MB", 1000 * 1000 },            .{ "MiB", 1 << 20 },
        .{ "GB", 1000 * 1000 * 1000 },     .{ "GiB", 1 << 30 },
        .{ "TB", 1000 * 1000 * 1000 * 1000 }, .{ "TiB", 1 << 40 },
    };
    inline for (units) |x| if (std.ascii.eqlIgnoreCase(u, x[0])) return std.math.mul(u64, n, x[1]) catch error.InvalidJob;
    return error.InvalidJob;
}

/// RFC 3339 date-time, or a bare `YYYY-MM-DD` at midnight UTC.
pub fn date(s: []const u8) Error!i128 {
    var buf: [40]u8 = undefined;
    const full = if (s.len == 10) std.fmt.bufPrint(&buf, "{s}T00:00:00Z", .{s}) catch return error.InvalidJob else s;
    return parseRfc3339(full) orelse error.InvalidJob;
}

fn parseRfc3339(s: []const u8) ?i128 {
    if (s.len < 20 or s.len > 40 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't') or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(u16, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const h = std.fmt.parseInt(u8, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(u8, s[14..16], 10) catch return null;
    const se = std.fmt.parseInt(u8, s[17..19], 10) catch return null;
    if (y < 1970 or mo < 1 or mo > 12 or d < 1 or d > std.time.epoch.getDaysInMonth(y, @enumFromInt(mo)) or h > 23 or mi > 59 or se > 60) return null;
    var i: usize = 19;
    var frac: i128 = 0;
    if (s[i] == '.') {
        i += 1;
        var digits: u32 = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
            if (digits < 9) {
                frac = frac * 10 + (s[i] - '0');
                digits += 1;
            }
        }
        if (digits == 0) return null;
        while (digits < 9) : (digits += 1) frac *= 10;
    }
    var off: i64 = 0;
    if (i < s.len and (s[i] == '+' or s[i] == '-')) {
        if (s.len != i + 6 or s[i + 3] != ':') return null;
        const oh = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 10) catch return null;
        const om = std.fmt.parseInt(u8, s[i + 4 .. i + 6], 10) catch return null;
        off = (@as(i64, oh) * 3600 + @as(i64, om) * 60) * @as(i64, if (s[i] == '-') -1 else 1);
    } else if (i + 1 != s.len or (s[i] != 'Z' and s[i] != 'z')) return null;
    var days: i64 = 0;
    var yy: u16 = 1970;
    while (yy < y) : (yy += 1) days += if (std.time.epoch.isLeapYear(yy)) 366 else 365;
    var mm: u8 = 1;
    while (mm < mo) : (mm += 1) days += std.time.epoch.getDaysInMonth(y, @enumFromInt(mm));
    days += d - 1;
    const secs = days * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + se - off;
    return @as(i128, secs) * std.time.ns_per_s + frac;
}

/// Wildcard match: `*` any run, `?` one byte; linear-time backtracking.
pub fn glob(pattern: []const u8, s: []const u8) bool {
    var p: usize = 0;
    var i: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (i < s.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == s[i])) {
            p += 1;
            i += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            mark = i;
        } else if (star) |st| {
            p = st + 1;
            mark += 1;
            i = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const testing = std.testing;

test "units" {
    try testing.expectEqual(@as(u64, (7 * 86400 + 10 * 3600 + 31 * 60 + 5) * std.time.ns_per_s), try duration("7d10h31m5s"));
    try testing.expectEqual(@as(u64, 500 * std.time.ns_per_ms), try duration("500ms"));
    try testing.expectEqual(@as(u64, 90 * 60 * std.time.ns_per_s), try duration("1.5h"));
    for ([_][]const u8{ "", "h", "5x", "1e400h", "-1s", "5 s" }) |b| try testing.expectError(error.InvalidJob, duration(b));
    try testing.expectEqual(@as(u64, 10 << 20), try size("10MiB"));
    try testing.expectEqual(@as(u64, 1000), try size("1KB"));
    try testing.expectEqual(@as(u64, 42), try size("42"));
    for ([_][]const u8{ "", "MiB", "99999999999999999999999", "18446744073709551615TiB", "1XB" }) |b| try testing.expectError(error.InvalidJob, size(b));
    try testing.expectEqual(@as(i128, 1136214245) * std.time.ns_per_s, try date("2006-01-02T15:04:05.00Z"));
    try testing.expectEqual(@as(i128, 86400) * std.time.ns_per_s, try date("1970-01-02"));
    for ([_][]const u8{ "2006-02-30T00:00:00Z", "2006-01-02T15:04:05", "2006-01-02T15:04:05.Z", "x" }) |b| try testing.expectError(error.InvalidJob, date(b));
}

test "glob" {
    try testing.expect(glob("pick*", "pickle"));
    try testing.expect(glob("image/*", "image/png"));
    try testing.expect(glob("a?c", "abc"));
    try testing.expect(glob("*", ""));
    try testing.expect(!glob("a*b", "acd"));
    try testing.expect(glob("*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaab"));
    try testing.expect(!glob("*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

test "parse the three job kinds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const now: i128 = 1000 * std.time.ns_per_s * 86400;
    const rep = try parse(a,
        \\replicate:
        \\  apiVersion: v1
        \\  source:
        \\    type: minio
        \\    bucket: src
        \\    prefix: p/
        \\  target:
        \\    type: minio
        \\    bucket: dst
        \\    endpoint: "http://127.0.0.1:9001"
        \\    credentials:
        \\      accessKey: ak
        \\      secretKey: sk
        \\  flags:
        \\    filter:
        \\      newerThan: "1d"
        \\      tags:
        \\        - key: "name"
        \\          value: "pick*"
        \\    retry:
        \\      attempts: 2
        \\      delay: "10ms"
    , now);
    try testing.expectEqual(Kind.replicate, rep.kind);
    const r = rep.body.replicate;
    try testing.expectEqualStrings("127.0.0.1:9001", r.target.endpoint);
    try testing.expect(r.source.isLocal());
    try testing.expectEqual(now - 86400 * std.time.ns_per_s, r.filter.newer_than_ns.?);
    try testing.expectEqualStrings("pick*", r.filter.tags[0].value);
    try testing.expectEqual(@as(u32, 2), rep.retry.attempts);

    const kr = try parse(a,
        \\keyrotate:
        \\  apiVersion: v1
        \\  bucket: b
        \\  encryption:
        \\    type: sse-kms
        \\    key: newkey
        \\    context: "a=1,b=2"
    , now);
    try testing.expectEqualStrings("newkey", kr.body.keyrotate.key);
    try testing.expectEqual(@as(usize, 2), kr.body.keyrotate.context.len);

    const ex = try parse(a,
        \\expire:
        \\  apiVersion: v1
        \\  bucket: b
        \\  rules:
        \\    - type: object
        \\      name: "*.log"
        \\      olderThan: 1h
        \\      size:
        \\        lessThan: 10MiB
        \\      purge:
        \\        retainVersions: 2
        \\    - type: deleted
        \\  notify:
        \\    endpoint: http://h/x
    , now);
    const e = ex.body.expire;
    try testing.expectEqual(@as(usize, 2), e.rules.len);
    try testing.expectEqual(@as(u32, 2), e.rules[0].retain_versions);
    try testing.expectEqual(@as(u64, 10 << 20), e.rules[0].size_lt.?);
    try testing.expectEqualStrings("http://h/x", ex.notify.endpoint);

    const bad = [_][]const u8{
        "replicate:\n  source:\n    bucket: a\n  target:\n    bucket: a",
        "replicate:\n  source:\n    bucket: a\n    endpoint: http://x\n  target:\n    bucket: b",
        "keyrotate:\n  bucket: b\n  encryption:\n    type: sse-kms",
        "keyrotate:\n  bucket: b\n  encryption:\n    type: rot13",
        "expire:\n  bucket: b\n  rules: []",
        "expire:\n  bucket: b\n  rules:\n    - type: deleted\n      size:\n        lessThan: 1",
        "expire:\n  apiVersion: v9\n  bucket: b\n  rules:\n    - type: object",
        "catalog:\n  bucket: b",
        "a: 1\nb: 2",
        "expire:\n  bucket: b\n  rules:\n    - type: object\n  retry:\n    attempts: 100000",
        "expire:\n  bucket: b\n  rules:\n    - type: object\n  notify:\n    endpoint: file:///etc/passwd",
    };
    for (bad) |b| try testing.expectError(error.InvalidJob, parse(a, b, now));
}
