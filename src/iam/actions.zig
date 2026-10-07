//! S3 API operations mapped to IAM actions and the ARN they are authorized against.
const std = @import("std");

pub const Target = enum {
    /// `arn:aws:s3:::*` (account-level operations such as ListBuckets); matched by `*` too.
    service,
    /// `arn:aws:s3:::bucket`
    bucket,
    /// `arn:aws:s3:::bucket/key`
    object,
};

pub const Op = enum {
    list_buckets,
    create_bucket,
    delete_bucket,
    head_bucket,
    get_bucket_location,
    list_objects,
    list_objects_v2,
    list_object_versions,
    list_multipart_uploads,
    get_bucket_policy,
    put_bucket_policy,
    delete_bucket_policy,
    get_bucket_policy_status,
    get_bucket_versioning,
    put_bucket_versioning,
    get_bucket_acl,
    put_bucket_acl,
    get_bucket_cors,
    put_bucket_cors,
    delete_bucket_cors,
    get_bucket_tagging,
    put_bucket_tagging,
    delete_bucket_tagging,
    get_bucket_lifecycle,
    put_bucket_lifecycle,
    delete_bucket_lifecycle,
    get_bucket_encryption,
    put_bucket_encryption,
    delete_bucket_encryption,
    get_bucket_notification,
    put_bucket_notification,
    listen_bucket_notification,
    listen_notification,
    get_bucket_replication,
    put_bucket_replication,
    delete_bucket_replication,
    get_object_lock_configuration,
    put_object_lock_configuration,
    get_object,
    get_object_version,
    head_object,
    put_object,
    copy_object,
    delete_object,
    delete_object_version,
    delete_objects,
    get_object_acl,
    put_object_acl,
    get_object_tagging,
    get_object_version_tagging,
    put_object_tagging,
    delete_object_tagging,
    get_object_retention,
    put_object_retention,
    get_object_legal_hold,
    put_object_legal_hold,
    get_object_attributes,
    restore_object,
    select_object_content,
    create_multipart_upload,
    upload_part,
    upload_part_copy,
    complete_multipart_upload,
    abort_multipart_upload,
    list_parts,
};

pub const Mapping = struct { action: []const u8, target: Target };

/// Copy operations also need s3:GetObject on the source; the caller checks that separately.
pub fn mapping(op: Op) Mapping {
    return table[@intFromEnum(op)];
}

const table = blk: {
    const n = @typeInfo(Op).@"enum".fields.len;
    var t: [n]Mapping = undefined;
    var seen = [_]bool{false} ** n;
    for (entries) |e| {
        const i = @intFromEnum(e[0]);
        if (seen[i]) @compileError("duplicate mapping for " ++ @tagName(e[0]));
        seen[i] = true;
        t[i] = .{ .action = e[1], .target = e[2] };
    }
    for (seen, 0..) |s, i| if (!s) @compileError("missing mapping for " ++ @typeInfo(Op).@"enum".fields[i].name);
    break :blk t;
};

const entries = [_]struct { Op, []const u8, Target }{
    .{ .list_buckets, "s3:ListAllMyBuckets", .service },
    .{ .create_bucket, "s3:CreateBucket", .bucket },
    .{ .delete_bucket, "s3:DeleteBucket", .bucket },
    .{ .head_bucket, "s3:ListBucket", .bucket },
    .{ .get_bucket_location, "s3:GetBucketLocation", .bucket },
    .{ .list_objects, "s3:ListBucket", .bucket },
    .{ .list_objects_v2, "s3:ListBucket", .bucket },
    .{ .list_object_versions, "s3:ListBucketVersions", .bucket },
    .{ .list_multipart_uploads, "s3:ListBucketMultipartUploads", .bucket },
    .{ .get_bucket_policy, "s3:GetBucketPolicy", .bucket },
    .{ .put_bucket_policy, "s3:PutBucketPolicy", .bucket },
    .{ .delete_bucket_policy, "s3:DeleteBucketPolicy", .bucket },
    .{ .get_bucket_policy_status, "s3:GetBucketPolicyStatus", .bucket },
    .{ .get_bucket_versioning, "s3:GetBucketVersioning", .bucket },
    .{ .put_bucket_versioning, "s3:PutBucketVersioning", .bucket },
    .{ .get_bucket_acl, "s3:GetBucketAcl", .bucket },
    .{ .put_bucket_acl, "s3:PutBucketAcl", .bucket },
    .{ .get_bucket_cors, "s3:GetBucketCORS", .bucket },
    .{ .put_bucket_cors, "s3:PutBucketCORS", .bucket },
    .{ .delete_bucket_cors, "s3:PutBucketCORS", .bucket },
    .{ .get_bucket_tagging, "s3:GetBucketTagging", .bucket },
    .{ .put_bucket_tagging, "s3:PutBucketTagging", .bucket },
    .{ .delete_bucket_tagging, "s3:PutBucketTagging", .bucket },
    .{ .get_bucket_lifecycle, "s3:GetLifecycleConfiguration", .bucket },
    .{ .put_bucket_lifecycle, "s3:PutLifecycleConfiguration", .bucket },
    .{ .delete_bucket_lifecycle, "s3:PutLifecycleConfiguration", .bucket },
    .{ .get_bucket_encryption, "s3:GetEncryptionConfiguration", .bucket },
    .{ .put_bucket_encryption, "s3:PutEncryptionConfiguration", .bucket },
    .{ .delete_bucket_encryption, "s3:PutEncryptionConfiguration", .bucket },
    .{ .get_bucket_notification, "s3:GetBucketNotification", .bucket },
    .{ .put_bucket_notification, "s3:PutBucketNotification", .bucket },
    .{ .listen_bucket_notification, "s3:ListenBucketNotification", .bucket },
    .{ .listen_notification, "s3:ListenNotification", .service },
    .{ .get_bucket_replication, "s3:GetReplicationConfiguration", .bucket },
    .{ .put_bucket_replication, "s3:PutReplicationConfiguration", .bucket },
    .{ .delete_bucket_replication, "s3:PutReplicationConfiguration", .bucket },
    .{ .get_object_lock_configuration, "s3:GetBucketObjectLockConfiguration", .bucket },
    .{ .put_object_lock_configuration, "s3:PutBucketObjectLockConfiguration", .bucket },
    .{ .get_object, "s3:GetObject", .object },
    .{ .get_object_version, "s3:GetObjectVersion", .object },
    .{ .head_object, "s3:GetObject", .object },
    .{ .put_object, "s3:PutObject", .object },
    .{ .copy_object, "s3:PutObject", .object },
    .{ .delete_object, "s3:DeleteObject", .object },
    .{ .delete_object_version, "s3:DeleteObjectVersion", .object },
    .{ .delete_objects, "s3:DeleteObject", .object },
    .{ .get_object_acl, "s3:GetObjectAcl", .object },
    .{ .put_object_acl, "s3:PutObjectAcl", .object },
    .{ .get_object_tagging, "s3:GetObjectTagging", .object },
    .{ .get_object_version_tagging, "s3:GetObjectVersionTagging", .object },
    .{ .put_object_tagging, "s3:PutObjectTagging", .object },
    .{ .delete_object_tagging, "s3:DeleteObjectTagging", .object },
    .{ .get_object_retention, "s3:GetObjectRetention", .object },
    .{ .put_object_retention, "s3:PutObjectRetention", .object },
    .{ .get_object_legal_hold, "s3:GetObjectLegalHold", .object },
    .{ .put_object_legal_hold, "s3:PutObjectLegalHold", .object },
    .{ .get_object_attributes, "s3:GetObjectAttributes", .object },
    .{ .restore_object, "s3:RestoreObject", .object },
    .{ .select_object_content, "s3:GetObject", .object },
    .{ .create_multipart_upload, "s3:PutObject", .object },
    .{ .upload_part, "s3:PutObject", .object },
    .{ .upload_part_copy, "s3:PutObject", .object },
    .{ .complete_multipart_upload, "s3:PutObject", .object },
    .{ .abort_multipart_upload, "s3:AbortMultipartUpload", .object },
    .{ .list_parts, "s3:ListMultipartUploadParts", .object },
};

/// Admin API operations and their MinIO-compatible `admin:` actions.
pub const AdminOp = enum {
    create_user,
    delete_user,
    list_users,
    get_user,
    enable_user,
    disable_user,
    create_policy,
    delete_policy,
    get_policy,
    list_policies,
    attach_policy,
    add_user_to_group,
    remove_user_from_group,
    get_group,
    list_groups,
    enable_group,
    disable_group,
    create_service_account,
    update_service_account,
    remove_service_account,
    list_service_accounts,
    server_info,
    set_tier,
    list_tier,

    pub fn action(op: AdminOp) []const u8 {
        return admin_table[@intFromEnum(op)];
    }
};

/// Resource admin actions are evaluated against; MinIO admin statements carry none.
pub const admin_resource = "arn:aws:s3:::*";

const admin_table = blk: {
    const n = @typeInfo(AdminOp).@"enum".fields.len;
    var t: [n][]const u8 = undefined;
    var seen = [_]bool{false} ** n;
    for (admin_entries) |e| {
        const i = @intFromEnum(e[0]);
        if (seen[i]) @compileError("duplicate admin mapping for " ++ @tagName(e[0]));
        seen[i] = true;
        t[i] = e[1];
    }
    for (seen, 0..) |s, i| if (!s) @compileError("missing admin mapping for " ++ @typeInfo(AdminOp).@"enum".fields[i].name);
    break :blk t;
};

const admin_entries = [_]struct { AdminOp, []const u8 }{
    .{ .create_user, "admin:CreateUser" },
    .{ .delete_user, "admin:DeleteUser" },
    .{ .list_users, "admin:ListUsers" },
    .{ .get_user, "admin:GetUser" },
    .{ .enable_user, "admin:EnableUser" },
    .{ .disable_user, "admin:DisableUser" },
    .{ .create_policy, "admin:CreatePolicy" },
    .{ .delete_policy, "admin:DeletePolicy" },
    .{ .get_policy, "admin:GetPolicy" },
    .{ .list_policies, "admin:ListUserPolicies" },
    .{ .attach_policy, "admin:AttachUserOrGroupPolicy" },
    .{ .add_user_to_group, "admin:AddUserToGroup" },
    .{ .remove_user_from_group, "admin:RemoveUserFromGroup" },
    .{ .get_group, "admin:GetGroup" },
    .{ .list_groups, "admin:ListGroups" },
    .{ .enable_group, "admin:EnableGroup" },
    .{ .disable_group, "admin:DisableGroup" },
    .{ .create_service_account, "admin:CreateServiceAccount" },
    .{ .update_service_account, "admin:UpdateServiceAccount" },
    .{ .remove_service_account, "admin:RemoveServiceAccount" },
    .{ .list_service_accounts, "admin:ListServiceAccounts" },
    .{ .server_info, "admin:ServerInfo" },
    .{ .set_tier, "admin:SetTier" },
    .{ .list_tier, "admin:ListTier" },
};

pub const ArnError = error{ArnTooLong};

/// Writes the resource ARN for `op` into `buf`. `key` is ignored for bucket targets.
pub fn resourceArn(buf: []u8, op: Op, bucket: []const u8, key: []const u8) ArnError![]const u8 {
    return switch (mapping(op).target) {
        .service => "arn:aws:s3:::*",
        .bucket => std.fmt.bufPrint(buf, "arn:aws:s3:::{s}", .{bucket}) catch error.ArnTooLong,
        .object => std.fmt.bufPrint(buf, "arn:aws:s3:::{s}/{s}", .{ bucket, key }) catch error.ArnTooLong,
    };
}

test "mapping table" {
    const Case = struct { op: Op, action: []const u8, arn: []const u8 };
    const cases = [_]Case{
        .{ .op = .list_buckets, .action = "s3:ListAllMyBuckets", .arn = "arn:aws:s3:::*" },
        .{ .op = .list_objects_v2, .action = "s3:ListBucket", .arn = "arn:aws:s3:::photos" },
        .{ .op = .head_object, .action = "s3:GetObject", .arn = "arn:aws:s3:::photos/a/b.jpg" },
        .{ .op = .upload_part, .action = "s3:PutObject", .arn = "arn:aws:s3:::photos/a/b.jpg" },
        .{ .op = .list_parts, .action = "s3:ListMultipartUploadParts", .arn = "arn:aws:s3:::photos/a/b.jpg" },
        .{ .op = .delete_bucket_lifecycle, .action = "s3:PutLifecycleConfiguration", .arn = "arn:aws:s3:::photos" },
    };
    var buf: [256]u8 = undefined;
    for (cases) |c| {
        try std.testing.expectEqualStrings(c.action, mapping(c.op).action);
        try std.testing.expectEqualStrings(c.arn, try resourceArn(&buf, c.op, "photos", "a/b.jpg"));
    }
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.ArnTooLong, resourceArn(&tiny, .get_object, "photos", "k"));
}
