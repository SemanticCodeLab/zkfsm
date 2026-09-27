//! Routing: path-style `/`, `/{bucket}`, `/{bucket}/{key}` under an optional base path,
//! virtual-host-style `{bucket}.{domain}`, plus query parsing.
const std = @import("std");

pub const Error = error{ InvalidUri, OutOfMemory };

pub const Target = struct {
    bucket: []const u8,
    key: []const u8,
    query: []const u8,
};

/// Deployment addressing: base path and virtual-host domains.
pub const Routing = struct {
    /// Base path the S3 API is served under (e.g. `/s3`); empty for the root.
    path_prefix: []const u8 = "",
    /// Hosts `{bucket}.{domain}` address `bucket`.
    domains: []const []const u8 = &.{},
};

pub const ResolveError = Error || error{OutsidePrefix};

/// Routes a request target (origin-form) arriving with `host`.
pub fn resolve(arena: std.mem.Allocator, cfg: Routing, host: ?[]const u8, target: []const u8) ResolveError!Target {
    var rest = stripPrefix(cfg.path_prefix, target) orelse return error.OutsidePrefix;
    if (rest.len == 0 or rest[0] == '?') rest = try std.fmt.allocPrint(arena, "/{s}", .{rest});
    const bucket = if (host) |h| vhostBucket(cfg.domains, h) else null;
    const b = bucket orelse return parse(arena, rest);
    var t = try parse(arena, rest);
    // The whole path is the key; the bucket came from the host.
    const q = std.mem.indexOfScalar(u8, rest, '?') orelse rest.len;
    t.key = try percentDecode(arena, rest[1..q], false);
    t.bucket = b;
    return t;
}

/// `target` after `prefix` (empty, or starting with `/` or `?`), or null when outside it.
pub fn stripPrefix(prefix: []const u8, target: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    const rest = target[prefix.len..];
    if (rest.len > 0 and rest[0] != '/' and rest[0] != '?') return null;
    return rest;
}

/// The bucket named by a `{bucket}.{domain}[:port]` host, or null.
pub fn vhostBucket(domains: []const []const u8, host_header: []const u8) ?[]const u8 {
    var host = host_header;
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |i| {
        if (std.mem.indexOfScalar(u8, host, ']') == null) host = host[0..i];
    }
    for (domains) |d| {
        if (host.len <= d.len + 1 or host[host.len - d.len - 1] != '.') continue;
        if (!std.ascii.eqlIgnoreCase(host[host.len - d.len ..], d)) continue;
        return host[0 .. host.len - d.len - 1];
    }
    return null;
}

/// Startup check for configured base paths: leading `/`, no trailing `/`, no `?`, `#`, `%` or `..`.
pub fn validBasePath(p: []const u8) bool {
    if (p.len < 2 or p[0] != '/' or p[p.len - 1] == '/') return false;
    if (std.mem.indexOfAny(u8, p, "?#% \\") != null or std.mem.indexOf(u8, p, "..") != null) return false;
    return std.mem.indexOf(u8, p, "//") == null;
}

/// Decoded strings are allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, target: []const u8) Error!Target {
    if (target.len == 0 or target[0] != '/') return error.InvalidUri;
    const q = std.mem.indexOfScalar(u8, target, '?');
    const path = target[1 .. q orelse target.len];
    const query = if (q) |i| target[i + 1 ..] else "";
    const slash = std.mem.indexOfScalar(u8, path, '/');
    const raw_bucket = path[0 .. slash orelse path.len];
    const raw_key = if (slash) |i| path[i + 1 ..] else "";
    return .{
        .bucket = try percentDecode(arena, raw_bucket, false),
        .key = try percentDecode(arena, raw_key, false),
        .query = query,
    };
}

/// Returns the decoded value of `name`; "" for a bare flag, null if absent.
pub fn queryParam(arena: std.mem.Allocator, query: []const u8, name: []const u8) Error!?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const k = try percentDecode(arena, pair[0 .. eq orelse pair.len], true);
        if (!std.mem.eql(u8, k, name)) continue;
        return if (eq) |i| try percentDecode(arena, pair[i + 1 ..], true) else "";
    }
    return null;
}

pub fn percentDecode(arena: std.mem.Allocator, s: []const u8, plus_is_space: bool) Error![]const u8 {
    if (std.mem.indexOfAny(u8, s, "%+") == null) return s;
    const out = try arena.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '%') {
            if (s.len - i < 3) return error.InvalidUri;
            out[n] = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.InvalidUri;
            i += 2;
        } else if (c == '+' and plus_is_space) {
            out[n] = ' ';
        } else out[n] = c;
        n += 1;
    }
    return out[0..n];
}

test "route parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const t = try parse(a, "/bkt/dir/my%20file.txt?list-type=2&prefix=a%2Fb+c");
    try std.testing.expectEqualStrings("bkt", t.bucket);
    try std.testing.expectEqualStrings("dir/my file.txt", t.key);
    try std.testing.expectEqualStrings("a/b c", (try queryParam(a, t.query, "prefix")).?);
    try std.testing.expectEqualStrings("2", (try queryParam(a, t.query, "list-type")).?);
    try std.testing.expect((try queryParam(a, t.query, "delimiter")) == null);
    const root = try parse(a, "/");
    try std.testing.expectEqualStrings("", root.bucket);
    const b = try parse(a, "/bkt?location");
    try std.testing.expectEqualStrings("", (try queryParam(a, b.query, "location")).?);
    try std.testing.expectError(error.InvalidUri, parse(a, "/b/%zz"));
    try std.testing.expectError(error.InvalidUri, parse(a, "/b/%2"));
    try std.testing.expectError(error.InvalidUri, parse(a, "nope"));
}

test "base path, virtual hosts, and path validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg: Routing = .{ .path_prefix = "/s3", .domains = &.{ "s3.local", "example.com" } };
    const t = try resolve(a, cfg, "localhost:9000", "/s3/bkt/a%20b?acl");
    try std.testing.expectEqualStrings("bkt", t.bucket);
    try std.testing.expectEqualStrings("a b", t.key);
    try std.testing.expectEqualStrings("acl", t.query);
    try std.testing.expectEqualStrings("", (try resolve(a, cfg, null, "/s3")).bucket);
    try std.testing.expectEqualStrings("x", (try resolve(a, cfg, null, "/s3?x")).query);
    try std.testing.expectError(error.OutsidePrefix, resolve(a, cfg, null, "/bkt/k"));
    try std.testing.expectError(error.OutsidePrefix, resolve(a, cfg, null, "/s3x/k"));
    const v = try resolve(a, cfg, "Photos.S3.Local:9000", "/s3/dir/k.jpg?versionId=1");
    try std.testing.expectEqualStrings("Photos", v.bucket);
    try std.testing.expectEqualStrings("dir/k.jpg", v.key);
    const root = try resolve(a, .{ .domains = &.{"example.com"} }, "my.bucket.example.com", "/");
    try std.testing.expectEqualStrings("my.bucket", root.bucket);
    try std.testing.expectEqualStrings("", root.key);
    try std.testing.expectEqualStrings("", (try resolve(a, .{ .domains = &.{"example.com"} }, "example.com", "/")).bucket);
    try std.testing.expect(vhostBucket(&.{"example.com"}, "[::1]:9000") == null);
    try std.testing.expect(validBasePath("/s3"));
    try std.testing.expect(validBasePath("/api/s3"));
    for ([_][]const u8{ "", "/", "s3", "/s3/", "/a?b", "/a/../b", "/a//b", "/a%2f" }) |bad| try std.testing.expect(!validBasePath(bad));
}
