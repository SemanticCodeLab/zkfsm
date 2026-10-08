//! Source-neutral description of what gets migrated: one object version (or delete
//! marker) with its metadata, and a bucket's configuration documents.
const std = @import("std");
const object = @import("../object/root.zig");
const core = @import("../core/root.zig");

pub const Header = object.Header;
pub const Tag = object.Tag;
pub const Mode = object.lock.Mode;

pub const VersionInfo = struct {
    /// All zeros is the null version.
    id: [16]u8 = @splat(0),
    /// Version id as the source spells it (online sources address versions by it).
    src_id: []const u8 = "",
    mtime_ns: i128 = 0,
    delete_marker: bool = false,
    size: u64 = 0,
    /// Hex ETag without quotes; multipart ETags end in `-<parts>`.
    etag: []const u8 = "",
    content_type: []const u8 = "",
    user: []const Header = &.{},
    system: object.SystemHeaders = .{},
    tags: []const Tag = &.{},
    mode: Mode = .none,
    until_ns: i128 = 0,
    legal_hold: bool = false,
    /// Set when the version cannot be copied (encrypted, compressed, ...).
    skip_reason: ?[]const u8 = null,

    pub fn isNull(v: VersionInfo) bool {
        return std.mem.allEqual(u8, &v.id, 0);
    }
};

/// Raw configuration documents as the source stores or serves them.
pub const BucketConfigs = struct {
    versioning: ?[]const u8 = null,
    object_lock: ?[]const u8 = null,
    lock_enabled: bool = false,
    policy: ?[]const u8 = null,
    tagging: ?[]const u8 = null,
    lifecycle: ?[]const u8 = null,
    encryption: ?[]const u8 = null,
    notification: ?[]const u8 = null,
    cors: ?[]const u8 = null,
    quota: ?[]const u8 = null,
    replication: ?[]const u8 = null,
};

/// Versions of one key, oldest first.
pub fn sortOldestFirst(vs: []VersionInfo) void {
    std.mem.sort(VersionInfo, vs, {}, struct {
        fn lt(_: void, a: VersionInfo, b: VersionInfo) bool {
            return a.mtime_ns < b.mtime_ns;
        }
    }.lt);
}

pub const ApplyError = error{OutOfMemory};

/// Fills `v` from source metadata pairs (stored user metadata or GET response
/// headers). Unknown and internal names are dropped.
pub fn applyMeta(arena: std.mem.Allocator, v: *VersionInfo, pairs: []const Header) ApplyError!void {
    var user: std.ArrayList(Header) = .empty;
    for (pairs) |p| {
        const n = p.name;
        if (std.ascii.startsWithIgnoreCase(n, "x-amz-meta-")) {
            const name = try std.ascii.allocLowerString(arena, n["x-amz-meta-".len..]);
            try user.append(arena, .{ .name = name, .value = p.value });
        } else if (std.ascii.eqlIgnoreCase(n, "content-type")) {
            v.content_type = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "etag")) {
            v.etag = std.mem.trim(u8, p.value, "\"");
        } else if (std.ascii.eqlIgnoreCase(n, "cache-control")) {
            v.system.cache_control = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "content-disposition")) {
            v.system.content_disposition = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "content-encoding")) {
            v.system.content_encoding = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "content-language")) {
            v.system.content_language = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "expires")) {
            v.system.expires = p.value;
        } else if (std.ascii.eqlIgnoreCase(n, "x-amz-tagging")) {
            v.tags = try parseTagQuery(arena, p.value);
        } else if (std.ascii.eqlIgnoreCase(n, "x-amz-object-lock-mode")) {
            v.mode = parseMode(p.value);
        } else if (std.ascii.eqlIgnoreCase(n, "x-amz-object-lock-retain-until-date")) {
            v.until_ns = core.time.parseIso8601(p.value) catch 0;
        } else if (std.ascii.eqlIgnoreCase(n, "x-amz-object-lock-legal-hold")) {
            v.legal_hold = std.ascii.eqlIgnoreCase(p.value, "ON");
        } else if (std.ascii.startsWithIgnoreCase(n, "x-amz-server-side-encryption") or
            std.ascii.startsWithIgnoreCase(n, "x-minio-internal-server-side-encryption") or
            std.ascii.startsWithIgnoreCase(n, "x-minio-internal-encrypted"))
        {
            v.skip_reason = "encrypted object";
        } else if (std.ascii.eqlIgnoreCase(n, "x-minio-internal-compression")) {
            v.skip_reason = "compressed object";
        } else if (std.ascii.startsWithIgnoreCase(n, "x-minio-internal-transition")) {
            v.skip_reason = "transitioned to a remote tier";
        }
    }
    v.user = user.items;
}

pub fn parseMode(s: []const u8) Mode {
    if (std.ascii.eqlIgnoreCase(s, "GOVERNANCE")) return .governance;
    if (std.ascii.eqlIgnoreCase(s, "COMPLIANCE")) return .compliance;
    return .none;
}

/// `k1=v1&k2=v2` with percent-encoding, as stored for object tags.
pub fn parseTagQuery(arena: std.mem.Allocator, q: []const u8) ApplyError![]Tag {
    var out: std.ArrayList(Tag) = .empty;
    var it = std.mem.splitScalar(u8, q, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const k = try unescape(arena, pair[0..eq]);
        const val = if (eq < pair.len) try unescape(arena, pair[eq + 1 ..]) else "";
        try out.append(arena, .{ .key = k, .value = val });
    }
    return out.items;
}

fn unescape(arena: std.mem.Allocator, s: []const u8) ApplyError![]const u8 {
    const out = try arena.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '+') {
            out[n] = ' ';
        } else if (s[i] == '%' and i + 3 <= s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                out[n] = b;
                i += 2;
            } else |_| out[n] = '%';
        } else out[n] = s[i];
        n += 1;
    }
    return out[0..n];
}

test "metadata pairs map to fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var v: VersionInfo = .{};
    try applyMeta(arena.allocator(), &v, &.{
        .{ .name = "X-Amz-Meta-Color", .value = "blue" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "etag", .value = "\"abc-2\"" },
        .{ .name = "X-Amz-Tagging", .value = "k1=v1&a%20b=c+d" },
        .{ .name = "X-Amz-Object-Lock-Mode", .value = "GOVERNANCE" },
        .{ .name = "X-Amz-Object-Lock-Retain-Until-Date", .value = "2030-01-02T03:04:05.123Z" },
        .{ .name = "X-Amz-Object-Lock-Legal-Hold", .value = "ON" },
    });
    try std.testing.expectEqualStrings("color", v.user[0].name);
    try std.testing.expectEqualStrings("abc-2", v.etag);
    try std.testing.expectEqualStrings("a b", v.tags[1].key);
    try std.testing.expectEqualStrings("c d", v.tags[1].value);
    try std.testing.expectEqual(Mode.governance, v.mode);
    try std.testing.expect(v.until_ns > 0 and v.legal_hold);
    try std.testing.expect(v.skip_reason == null);
}
