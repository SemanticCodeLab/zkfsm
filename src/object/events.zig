//! Event hooks: committed object changes handed to the notification subsystem,
//! and the background cause (lifecycle, tiering) of changes made off-request.
const std = @import("std");
const core = @import("../core/root.zig");

pub const Kind = enum {
    created,
    deleted,
    delete_marker,
    tags_put,
    tags_deleted,
    retention_put,
    legal_hold_put,
    transitioned,
    transition_failed,
    restore_completed,
    replication_completed,
    replication_failed,
};

/// What drove a change made on this thread.
pub const Cause = enum { request, lifecycle };

pub threadlocal var cause: Cause = .request;

pub const Change = struct {
    bucket: []const u8,
    key: []const u8,
    version: ?core.VersionId = null,
    kind: Kind,
    size: u64 = 0,
    /// Unquoted hex ETag; empty when unknown.
    etag: []const u8 = "",
    content_type: []const u8 = "",
};

/// Implemented by the notification subsystem; called with no service lock held.
pub const Sink = struct {
    ctx: *anyopaque,
    notify: *const fn (ctx: *anyopaque, ch: Change) void,
};

/// Unquoted ETag text of `e` in `buf`.
pub fn etagText(e: core.ETag, buf: *[core.ETag.quoted_max]u8) []const u8 {
    const q = e.quoted(buf);
    return std.mem.trim(u8, q, "\"");
}
