//! Header lists (user and internal metadata) and standard system headers:
//! validation, bounds, and a compact encoding (u16 count, then u16-length name/value pairs).
const std = @import("std");
const codec = @import("codec.zig");

pub const Header = struct { name: []const u8, value: []const u8 };

/// S3 limit: user metadata names (without `x-amz-meta-`) plus values.
pub const user_limit = 2 * 1024;
/// Reserved namespace for embedding builds; never accepted from or shown to clients.
pub const internal_prefix = "x-zkfsm-internal-";
pub const internal_limit = 4 * 1024;
/// Bound on the five system headers together.
pub const system_limit = 8 * 1024;

pub const Kind = enum { user, internal };

pub const Error = error{ MetadataTooLarge, InvalidMetadata, OutOfMemory };

pub fn limit(kind: Kind) usize {
    return switch (kind) {
        .user => user_limit,
        .internal => internal_limit,
    };
}

/// Standard headers persisted with the object and returned on GET/HEAD.
pub const System = struct {
    cache_control: []const u8 = "",
    content_disposition: []const u8 = "",
    content_encoding: []const u8 = "",
    content_language: []const u8 = "",
    expires: []const u8 = "",

    /// Field name and HTTP header name, in encoding order.
    pub const fields = .{
        .{ "cache_control", "cache-control" },
        .{ "content_disposition", "content-disposition" },
        .{ "content_encoding", "content-encoding" },
        .{ "content_language", "content-language" },
        .{ "expires", "expires" },
    };

    pub fn validate(s: System) Error!void {
        var total: usize = 0;
        inline for (fields) |f| {
            const v = @field(s, f[0]);
            total += v.len;
            if (!validValue(v)) return error.InvalidMetadata;
        }
        if (total > system_limit) return error.MetadataTooLarge;
    }
};

fn validValue(v: []const u8) bool {
    for (v) |c| if (c == '\r' or c == '\n' or c == 0) return false;
    return true;
}

fn validName(n: []const u8) bool {
    if (n.len == 0) return false;
    for (n) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null)) return false;
    return true;
}

/// Names must be lowercase HTTP tokens and unique; internal names carry `internal_prefix`, user names must not.
pub fn validate(hs: []const Header, kind: Kind) Error!void {
    var total: usize = 0;
    for (hs, 0..) |h, i| {
        if (!validName(h.name) or !validValue(h.value)) return error.InvalidMetadata;
        const reserved = std.mem.startsWith(u8, h.name, internal_prefix);
        if (reserved != (kind == .internal)) return error.InvalidMetadata;
        for (hs[0..i]) |p| if (std.mem.eql(u8, p.name, h.name)) return error.InvalidMetadata;
        total += h.name.len + h.value.len;
    }
    if (total > limit(kind)) return error.MetadataTooLarge;
}

/// Empty lists encode as "".
pub fn encode(gpa: std.mem.Allocator, hs: []const Header, kind: Kind) Error![]u8 {
    try validate(hs, kind);
    if (hs.len == 0) return gpa.alloc(u8, 0);
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    writeList(&a.writer, hs) catch return error.OutOfMemory;
    return a.toOwnedSlice() catch error.OutOfMemory;
}

fn writeList(w: *std.Io.Writer, hs: []const Header) std.Io.Writer.Error!void {
    try codec.putInt(w, u16, @intCast(hs.len));
    for (hs) |h| {
        try codec.putInt(w, u16, @intCast(h.name.len));
        try w.writeAll(h.name);
        try codec.putInt(w, u16, @intCast(h.value.len));
        try w.writeAll(h.value);
    }
}

/// Writes an encoded list ("" means empty) as it appears inside a record.
pub fn put(w: *std.Io.Writer, encoded: []const u8) std.Io.Writer.Error!void {
    if (encoded.len == 0) return codec.putInt(w, u16, 0);
    try w.writeAll(encoded);
}

/// Consumes one encoded list from `c`, checking its bounds; returns the raw bytes ("" when empty).
pub fn take(c: *codec.Cursor, kind: Kind) codec.DecodeError![]const u8 {
    const start = c.pos;
    const n = try c.int(u16);
    var total: usize = 0;
    for (0..n) |_| {
        const name = try c.take(try c.int(u16));
        const value = try c.take(try c.int(u16));
        if (name.len == 0) return error.Corrupt;
        total += name.len + value.len;
        if (total > limit(kind)) return error.Corrupt;
    }
    return if (n == 0) "" else c.bytes[start..c.pos];
}

/// Decodes into `arena`; strings borrow from `bytes`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8) (codec.DecodeError || error{OutOfMemory})![]Header {
    if (bytes.len == 0) return &.{};
    var c: codec.Cursor = .{ .bytes = bytes };
    const out = try arena.alloc(Header, try c.int(u16));
    for (out) |*h| {
        h.name = try c.take(try c.int(u16));
        h.value = try c.take(try c.int(u16));
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return out;
}

pub fn putSystem(w: *std.Io.Writer, s: System) std.Io.Writer.Error!void {
    inline for (System.fields) |f| {
        const v = @field(s, f[0]);
        try codec.putInt(w, u16, @intCast(v.len));
        try w.writeAll(v);
    }
}

pub fn takeSystem(c: *codec.Cursor) codec.DecodeError!System {
    var s: System = .{};
    var total: usize = 0;
    inline for (System.fields) |f| {
        @field(s, f[0]) = try c.take(try c.int(u16));
        total += @field(s, f[0]).len;
    }
    if (total > system_limit) return error.Corrupt;
    return s;
}

test "header lists roundtrip, bounds, and namespaces" {
    const gpa = std.testing.allocator;
    const hs = [_]Header{ .{ .name = "k", .value = "v" }, .{ .name = "color", .value = "" } };
    const b = try encode(gpa, &hs, .user);
    defer gpa.free(b);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const d = try decode(arena.allocator(), b);
    try std.testing.expectEqual(@as(usize, 2), d.len);
    try std.testing.expectEqualStrings("color", d[1].name);
    var c: codec.Cursor = .{ .bytes = b };
    try std.testing.expectEqualStrings(b, try take(&c, .user));
    for (0..b.len) |n| {
        var t: codec.Cursor = .{ .bytes = b[0..n] };
        try std.testing.expectError(error.Corrupt, take(&t, .user));
    }

    const big = "x" ** (user_limit);
    try std.testing.expectError(error.MetadataTooLarge, validate(&.{.{ .name = "a", .value = big }}, .user));
    try validate(&.{.{ .name = "a", .value = big[1..] }}, .user);
    try std.testing.expectError(error.InvalidMetadata, validate(&.{.{ .name = "Upper", .value = "" }}, .user));
    try std.testing.expectError(error.InvalidMetadata, validate(&.{.{ .name = "a", .value = "x\r\n" }}, .user));
    try std.testing.expectError(error.InvalidMetadata, validate(&.{ .{ .name = "a", .value = "" }, .{ .name = "a", .value = "" } }, .user));
    try std.testing.expectError(error.InvalidMetadata, validate(&.{.{ .name = internal_prefix ++ "k", .value = "" }}, .user));
    try std.testing.expectError(error.InvalidMetadata, validate(&.{.{ .name = "k", .value = "" }}, .internal));
    try validate(&.{.{ .name = internal_prefix ++ "k", .value = big }}, .internal);
    try std.testing.expectError(error.MetadataTooLarge, validate(&.{.{ .name = internal_prefix ++ "k", .value = big ** 2 }}, .internal));
    try std.testing.expectError(error.MetadataTooLarge, (System{ .expires = "x" ** (system_limit + 1) }).validate());
}
