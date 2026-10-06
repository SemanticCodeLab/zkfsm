//! Replication hooks: durable change notifications for the replication engine, the
//! per-version replication status, and the origin of an incoming replica write.
const std = @import("std");
const core = @import("../core/root.zig");
const metadata = @import("../metadata/root.zig");

/// Internal header holding the version's replication status.
pub const status_header = metadata.headers.internal_prefix ++ "replication-status";

pub const Status = enum {
    pending,
    completed,
    failed,
    replica,

    pub fn text(s: Status) []const u8 {
        return switch (s) {
            .pending => "PENDING",
            .completed => "COMPLETED",
            .failed => "FAILED",
            .replica => "REPLICA",
        };
    }

    pub fn parse(s: []const u8) ?Status {
        inline for (@typeInfo(Status).@"enum".fields) |f| {
            const v: Status = @enumFromInt(f.value);
            if (std.mem.eql(u8, s, v.text())) return v;
        }
        return null;
    }
};

/// Source identity of a replica write; set by the replication receiver for the
/// duration of one request. Writes made under an origin never notify the sink.
pub const Origin = struct {
    version: ?core.VersionId = null,
    created_ns: ?i128 = null,
    delete_marker: bool = false,
};

pub threadlocal var origin: ?Origin = null;

pub const Kind = enum(u8) { put, delete_marker, delete_version, metadata };

pub const Event = struct {
    bucket: []const u8,
    key: []const u8,
    version: core.VersionId,
    kind: Kind,
};

/// Implemented by the replication engine.
pub const Sink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Whether a new version replicates. Called with the service mutex held; must not take it.
        wants: *const fn (ctx: *anyopaque, bid: core.BucketId, bucket: []const u8, key: []const u8, tags: []const u8) bool,
        /// Records the change durably. Called with no service lock held.
        notify: *const fn (ctx: *anyopaque, ev: Event) void,
    };
};

/// Status recorded in an encoded internal header list, if any.
pub fn statusOf(internal: []const metadata.headers.Header) ?Status {
    for (internal) |h| if (std.mem.eql(u8, h.name, status_header)) return Status.parse(h.value);
    return null;
}

/// Re-encodes `internal` (encoded header list) with the status replaced; result in `a`.
pub fn withStatus(a: std.mem.Allocator, internal: []const u8, status: Status) error{ OutOfMemory, Corrupt, MetadataTooLarge }![]const u8 {
    const hs = metadata.headers.decode(a, internal) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    var out: std.ArrayList(metadata.headers.Header) = .empty;
    for (hs) |h| if (!std.mem.eql(u8, h.name, status_header)) try out.append(a, h);
    try out.append(a, .{ .name = status_header, .value = status.text() });
    return metadata.headers.encode(a, out.items, .internal) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MetadataTooLarge => error.MetadataTooLarge,
        error.InvalidMetadata => error.Corrupt,
    };
}

test "status header roundtrip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const enc = try metadata.headers.encode(a, &.{.{ .name = metadata.headers.internal_prefix ++ "x", .value = "1" }}, .internal);
    const s1 = try withStatus(a, enc, .pending);
    const s2 = try withStatus(a, s1, .completed);
    const hs = try metadata.headers.decode(a, s2);
    try std.testing.expectEqual(@as(usize, 2), hs.len);
    try std.testing.expectEqual(Status.completed, statusOf(hs).?);
    try std.testing.expectEqual(Status.replica, Status.parse("REPLICA").?);
}
