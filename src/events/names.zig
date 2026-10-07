//! Event names (the s3:* wire identifiers) and wildcard expansion.
const std = @import("std");

pub const Name = enum {
    object_accessed_get,
    object_accessed_head,
    object_accessed_get_retention,
    object_accessed_get_legal_hold,
    object_accessed_attributes,
    object_created_put,
    object_created_post,
    object_created_copy,
    object_created_complete_multipart_upload,
    object_created_put_retention,
    object_created_put_legal_hold,
    object_created_put_tagging,
    object_created_delete_tagging,
    object_removed_delete,
    object_removed_delete_marker_created,
    object_removed_delete_all_versions,
    object_removed_no_op,
    bucket_created,
    bucket_removed,
    object_restore_post,
    object_restore_completed,
    object_transition_complete,
    object_transition_failed,
    lifecycle_expiration_delete,
    lifecycle_expiration_delete_marker_created,
    lifecycle_transition,
    replication_failed,
    replication_complete,
    replication_missed_threshold,
    replication_after_threshold,
    replication_not_tracked,
    scanner_many_versions,
    scanner_large_versions,
    scanner_big_prefix,

    pub fn text(n: Name) []const u8 {
        return switch (n) {
            .object_accessed_get => "s3:ObjectAccessed:Get",
            .object_accessed_head => "s3:ObjectAccessed:Head",
            .object_accessed_get_retention => "s3:ObjectAccessed:GetRetention",
            .object_accessed_get_legal_hold => "s3:ObjectAccessed:GetLegalHold",
            .object_accessed_attributes => "s3:ObjectAccessed:Attributes",
            .object_created_put => "s3:ObjectCreated:Put",
            .object_created_post => "s3:ObjectCreated:Post",
            .object_created_copy => "s3:ObjectCreated:Copy",
            .object_created_complete_multipart_upload => "s3:ObjectCreated:CompleteMultipartUpload",
            .object_created_put_retention => "s3:ObjectCreated:PutRetention",
            .object_created_put_legal_hold => "s3:ObjectCreated:PutLegalHold",
            .object_created_put_tagging => "s3:ObjectCreated:PutTagging",
            .object_created_delete_tagging => "s3:ObjectCreated:DeleteTagging",
            .object_removed_delete => "s3:ObjectRemoved:Delete",
            .object_removed_delete_marker_created => "s3:ObjectRemoved:DeleteMarkerCreated",
            .object_removed_delete_all_versions => "s3:ObjectRemoved:DeleteAllVersions",
            .object_removed_no_op => "s3:ObjectRemoved:NoOP",
            .bucket_created => "s3:BucketCreated",
            .bucket_removed => "s3:BucketRemoved",
            .object_restore_post => "s3:ObjectRestore:Post",
            .object_restore_completed => "s3:ObjectRestore:Completed",
            .object_transition_complete => "s3:ObjectTransition:Complete",
            .object_transition_failed => "s3:ObjectTransition:Failed",
            .lifecycle_expiration_delete => "s3:LifecycleExpiration:Delete",
            .lifecycle_expiration_delete_marker_created => "s3:LifecycleExpiration:DeleteMarkerCreated",
            .lifecycle_transition => "s3:LifecycleTransition",
            .replication_failed => "s3:Replication:OperationFailedReplication",
            .replication_complete => "s3:Replication:OperationCompletedReplication",
            .replication_missed_threshold => "s3:Replication:OperationMissedThreshold",
            .replication_after_threshold => "s3:Replication:OperationReplicatedAfterThreshold",
            .replication_not_tracked => "s3:Replication:OperationNotTracked",
            .scanner_many_versions => "s3:Scanner:ManyVersions",
            .scanner_large_versions => "s3:Scanner:LargeVersions",
            .scanner_big_prefix => "s3:Scanner:BigPrefix",
        };
    }
};

pub const count = @typeInfo(Name).@"enum".fields.len;

/// A set of event names; a configured `s3:ObjectCreated:*` becomes every created name.
pub const Mask = std.StaticBitSet(count);

const Group = struct { pattern: []const u8, prefix: []const u8 };

/// Wildcards; each matches the names starting with `prefix`.
const groups = [_]Group{
    .{ .pattern = "s3:ObjectAccessed:*", .prefix = "s3:ObjectAccessed:" },
    .{ .pattern = "s3:ObjectCreated:*", .prefix = "s3:ObjectCreated:" },
    .{ .pattern = "s3:ObjectRemoved:*", .prefix = "s3:ObjectRemoved:" },
    .{ .pattern = "s3:ObjectRestore:*", .prefix = "s3:ObjectRestore:" },
    .{ .pattern = "s3:ObjectTransition:*", .prefix = "s3:ObjectTransition:" },
    .{ .pattern = "s3:LifecycleExpiration:*", .prefix = "s3:LifecycleExpiration:" },
    .{ .pattern = "s3:Replication:*", .prefix = "s3:Replication:" },
    .{ .pattern = "s3:Scanner:*", .prefix = "s3:Scanner:" },
    // Older clients spell restore as one word.
    .{ .pattern = "s3:ObjectRestore:Post", .prefix = "s3:ObjectRestore:Post" },
};

/// Names matched by one configured event string; null when unknown.
pub fn parse(s: []const u8) ?Mask {
    var m = Mask.initEmpty();
    for (groups) |g| if (std.mem.eql(u8, s, g.pattern)) {
        inline for (@typeInfo(Name).@"enum".fields) |f| {
            const n: Name = @enumFromInt(f.value);
            if (std.mem.startsWith(u8, n.text(), g.prefix)) m.set(f.value);
        }
        return m;
    };
    inline for (@typeInfo(Name).@"enum".fields) |f| {
        const n: Name = @enumFromInt(f.value);
        if (std.mem.eql(u8, s, n.text())) {
            m.set(f.value);
            return m;
        }
    }
    return null;
}

pub fn has(m: Mask, n: Name) bool {
    return m.isSet(@intFromEnum(n));
}

test "wildcards expand to their group" {
    const m = parse("s3:ObjectCreated:*").?;
    try std.testing.expect(has(m, .object_created_put));
    try std.testing.expect(has(m, .object_created_complete_multipart_upload));
    try std.testing.expect(has(m, .object_created_put_tagging));
    try std.testing.expect(!has(m, .object_removed_delete));
    const r = parse("s3:ObjectRemoved:*").?;
    try std.testing.expect(has(r, .object_removed_delete_marker_created));
    try std.testing.expect(!has(r, .lifecycle_expiration_delete));
    try std.testing.expect(has(parse("s3:ObjectAccessed:Head").?, .object_accessed_head));
    try std.testing.expect(parse("s3:Bogus:*") == null);
    try std.testing.expect(has(parse("s3:Replication:*").?, .replication_failed));
}
