//! Conditional requests (If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since).
const std = @import("std");

pub const Conditions = struct {
    if_match: ?[]const u8 = null,
    if_none_match: ?[]const u8 = null,
    if_modified_since_ns: ?i128 = null,
    if_unmodified_since_ns: ?i128 = null,

    pub fn any(c: Conditions) bool {
        return c.if_match != null or c.if_none_match != null or c.if_modified_since_ns != null or c.if_unmodified_since_ns != null;
    }
};

pub const Outcome = enum { proceed, not_modified, precondition_failed };

/// True if `header` (a `*` or comma-separated entity-tag list) names `etag`.
pub fn etagMatches(header: []const u8, etag: []const u8) bool {
    const want = std.mem.trim(u8, etag, "\"");
    var it = std.mem.splitScalar(u8, header, ',');
    while (it.next()) |raw| {
        var t = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, t, "*")) return true;
        if (std.mem.startsWith(u8, t, "W/")) t = t[2..];
        if (std.mem.eql(u8, std.mem.trim(u8, t, "\""), want)) return true;
    }
    return false;
}

fn secs(ns: i128) i128 {
    return @divFloor(ns, std.time.ns_per_s);
}

/// GET/HEAD evaluation, RFC 9110 13.2.2 order; a passing If-Match skips If-Unmodified-Since.
pub fn evalRead(c: Conditions, etag: []const u8, mtime_ns: i128) Outcome {
    if (c.if_match) |h| {
        if (!etagMatches(h, etag)) return .precondition_failed;
    } else if (c.if_unmodified_since_ns) |t| {
        if (secs(mtime_ns) > secs(t)) return .precondition_failed;
    }
    if (c.if_none_match) |h| {
        if (etagMatches(h, etag)) return .not_modified;
    } else if (c.if_modified_since_ns) |t| {
        if (secs(mtime_ns) <= secs(t)) return .not_modified;
    }
    return .proceed;
}

pub const WriteError = error{ PreconditionFailed, NoSuchKey };

/// PUT evaluation against the current live object (null if absent or a delete marker).
pub fn evalWrite(c: Conditions, current_etag: ?[]const u8) WriteError!void {
    if (c.if_none_match) |h| if (current_etag) |e| {
        if (etagMatches(h, e)) return error.PreconditionFailed;
    };
    if (c.if_match) |h| {
        const e = current_etag orelse return error.NoSuchKey;
        if (!etagMatches(h, e)) return error.PreconditionFailed;
    }
}

test "etag list matching" {
    try std.testing.expect(etagMatches("\"abc\"", "\"abc\""));
    try std.testing.expect(etagMatches("\"x\", W/\"abc\"", "\"abc\""));
    try std.testing.expect(etagMatches("*", "\"abc\""));
    try std.testing.expect(etagMatches("abc", "\"abc\""));
    try std.testing.expect(!etagMatches("\"abd\"", "\"abc\""));
}

test "read preconditions" {
    const s = std.time.ns_per_s;
    const e = "\"abc\"";
    try std.testing.expectEqual(Outcome.proceed, evalRead(.{}, e, 10 * s));
    try std.testing.expectEqual(Outcome.precondition_failed, evalRead(.{ .if_match = "\"no\"" }, e, 10 * s));
    try std.testing.expectEqual(Outcome.not_modified, evalRead(.{ .if_none_match = e }, e, 10 * s));
    try std.testing.expectEqual(Outcome.not_modified, evalRead(.{ .if_modified_since_ns = 10 * s }, e, 10 * s + 5));
    try std.testing.expectEqual(Outcome.proceed, evalRead(.{ .if_modified_since_ns = 9 * s }, e, 10 * s));
    try std.testing.expectEqual(Outcome.precondition_failed, evalRead(.{ .if_unmodified_since_ns = 9 * s }, e, 10 * s));
    // If-Match true wins over If-Unmodified-Since false; If-None-Match false wins over IMS.
    try std.testing.expectEqual(Outcome.proceed, evalRead(.{ .if_match = e, .if_unmodified_since_ns = 9 * s }, e, 10 * s));
    try std.testing.expectEqual(Outcome.not_modified, evalRead(.{ .if_none_match = e, .if_modified_since_ns = 9 * s }, e, 10 * s));
}

test "write preconditions" {
    try evalWrite(.{ .if_none_match = "*" }, null);
    try std.testing.expectError(error.PreconditionFailed, evalWrite(.{ .if_none_match = "*" }, "\"a\""));
    try std.testing.expectError(error.NoSuchKey, evalWrite(.{ .if_match = "\"a\"" }, null));
    try std.testing.expectError(error.PreconditionFailed, evalWrite(.{ .if_match = "\"b\"" }, "\"a\""));
    try evalWrite(.{ .if_match = "\"a\"" }, "\"a\"");
}
