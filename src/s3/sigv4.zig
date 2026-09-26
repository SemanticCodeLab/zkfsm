//! SigV4 authentication. 0.1 slice: anonymous, every request allowed.
//! Header and presigned-query auth, HMAC-SHA256 and aws-chunked payloads slot in here.
const std = @import("std");

pub const Credentials = struct { access_key: []const u8, secret_key: []const u8 };

/// Returns whether the request may proceed. Anonymous until step 8.
pub fn authorize(req: *const std.http.Server.Request) bool {
    _ = req;
    return true;
}
