//! Bucket and tenant request-rate / bandwidth limits (503 SlowDown when exceeded).
const std = @import("std");
const iam = @import("../iam/root.zig");
const handler = @import("handler.zig");

const Ctx = handler.Ctx;
const rl = iam.ratelimit;

fn tenantOf(c: *const Ctx) []const u8 {
    return if (c.bucket_tenant.len > 0) c.bucket_tenant else c.tenant;
}

/// Takes a request token (and the declared upload bytes) from bucket and tenant.
pub fn admit(c: *Ctx) bool {
    const st = c.env.auth.iam orelse return true;
    const now = std.time.nanoTimestamp();
    const bytes = c.req.head.content_length orelse 0;
    if (c.route.bucket.len > 0) {
        if (!rl.global.admit(.bucket, c.route.bucket, rl.get(st, .bucket, c.route.bucket), bytes, now)) return false;
    }
    const t = tenantOf(c);
    if (t.len > 0) {
        if (!rl.global.admit(.tenant, t, rl.get(st, .tenant, t), bytes, now)) return false;
    }
    return true;
}

/// Charges bytes sent in the response; later requests wait out the debt.
pub fn charge(c: *Ctx) void {
    if (c.sent_bytes == 0) return;
    const st = c.env.auth.iam orelse return;
    const now = std.time.nanoTimestamp();
    if (c.route.bucket.len > 0) rl.global.charge(.bucket, c.route.bucket, rl.get(st, .bucket, c.route.bucket), c.sent_bytes, now);
    const t = tenantOf(c);
    if (t.len > 0) rl.global.charge(.tenant, t, rl.get(st, .tenant, t), c.sent_bytes, now);
}
