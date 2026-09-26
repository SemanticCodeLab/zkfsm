//! Google Cloud Storage via its S3-interoperable XML API: HMAC keys, SigV4 with
//! region "auto", ListObjectsV2 and XML multipart uploads. Reuses the S3 provider.
const std = @import("std");
const s3 = @import("s3.zig");

pub const default_endpoint = "https://storage.googleapis.com";

pub const Config = struct {
    bucket: []const u8,
    /// HMAC key pair from a service account (interoperability settings).
    credentials: s3.Credentials,
    prefix: []const u8 = "",
    endpoint: []const u8 = default_endpoint,
    part_size: usize = 16 * s3.MiB,
    retry: s3.RetryPolicy = .{},
};

/// GCS rejects `If-None-Match: *` (it uses x-goog-if-generation-match), so no conditional_write.
pub fn s3Config(c: Config) s3.Config {
    return .{
        .endpoint = c.endpoint,
        .region = "auto",
        .bucket = c.bucket,
        .prefix = c.prefix,
        .credentials = c.credentials,
        .addressing = .path,
        .part_size = c.part_size,
        .conditional_write = false,
        .retry = c.retry,
    };
}

pub const GcsBackend = s3.S3Backend;

test "gcs preset maps onto the s3 provider" {
    const cfg = s3Config(.{ .bucket = "my-bucket", .credentials = .{ .access_key = "GOOGEXAMPLEACCESSID", .secret_key = "example-secret" } });
    var c = try s3.S3Client.init(std.testing.allocator, cfg);
    defer c.deinit();
    try std.testing.expect(!c.capabilities().conditional_write);
    try std.testing.expect(c.capabilities().multipart_native);
    var b: s3.S3Client.Built = .{};
    try c.build(.{ .method = .GET, .key = "obj" }, 784111777 * std.time.ns_per_s, &b);
    try std.testing.expectEqualStrings("storage.googleapis.com", b.host);
    try std.testing.expectEqualStrings("/my-bucket/obj", b.path);
    try std.testing.expect(std.mem.indexOf(u8, b.auth, "/19941106/auto/s3/aws4_request") != null);
}

// Live test; needs a real GCS bucket and HMAC keys. Skipped without env.
test "remote live gcs backend" {
    const gpa = std.testing.allocator;
    const ak = std.process.getEnvVarOwned(gpa, "ZKFSM_GCS_ACCESS_KEY") catch return error.SkipZigTest;
    defer gpa.free(ak);
    const sk = std.process.getEnvVarOwned(gpa, "ZKFSM_GCS_SECRET_KEY") catch return error.SkipZigTest;
    defer gpa.free(sk);
    const bucket = std.process.getEnvVarOwned(gpa, "ZKFSM_GCS_BUCKET") catch return error.SkipZigTest;
    defer gpa.free(bucket);
    var cfg = s3Config(.{ .bucket = bucket, .credentials = .{ .access_key = ak, .secret_key = sk }, .prefix = "zkfsm-live/", .part_size = s3.min_part_size });
    cfg.list_page_size = 3;
    var gb: GcsBackend = undefined;
    try gb.init(gpa, cfg);
    defer gb.deinit();
    try s3.runLiveSuite(gpa, &gb.remote, 20);
}
