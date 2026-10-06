//! Serves the admin API on the S3 listener: requests under the admin prefix are
//! authenticated by SigV4, then handed to `admin.api` before S3 authorization.
const std = @import("std");
const s3 = @import("s3/root.zig");
const admin = @import("admin/root.zig");
const iam = @import("iam/root.zig");
const object = @import("object/root.zig");
const metrics = @import("metrics/root.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;

pub const Bridge = struct {
    prefix: []const u8 = admin.api.default_prefix,
    auth: s3.sigv4.Config,
    svc: *object.ObjectService,
    started_s: i64,

    pub fn extension(self: *Bridge) s3.Extension {
        return .{ .name = "admin", .ctx = self, .route = route, .before_authz = true };
    }

    fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *Bridge = @ptrCast(@alignCast(ptr));
        const target = admin.api.match(self.prefix, c.target) orelse return false;
        const store = self.auth.iam orelse {
            try respond(c, try admin.api.fail(c.arena, .not_implemented, "NotImplemented", "The admin API requires authenticated mode."));
            return true;
        };
        if ((c.req.head.content_length orelse 0) > admin.api.max_body) {
            try respond(c, try admin.api.fail(c.arena, .payload_too_large, "EntityTooLarge", "Request body is too large."));
            return true;
        }
        const empty = c.req.head.transfer_encoding == .none and c.req.head.content_length == 0;
        const body = if (empty) "" else try readBody(c) orelse return true;
        const now_s = std.time.timestamp();
        const ak = c.auth.access_key;
        var sbuf: iam.Store.SecretBuf = undefined;
        var tbuf: s3.tenancy.NameBuf = undefined;
        var sts_secret: [iam.sts.secret_key_len]u8 = undefined;
        const secret: []const u8 = if (!std.mem.eql(u8, ak, c.auth.principal)) blk: {
            const issuer = self.auth.sts orelse return denied(c);
            sts_secret = issuer.secretFor(ak);
            break :blk &sts_secret;
        } else store.secretFor(ak, now_s, &sbuf) orelse return denied(c);
        const res = try admin.api.handle(c.arena, .{ .store = store, .svc = self.svc, .started_s = self.started_s, .idp_env = if (self.auth.federation) |f| f.env else .{} }, .{
            .method = c.method,
            .target = target,
            .body = body,
            .caller = .{
                .access_key = ak,
                .secret = try c.arena.dupe(u8, secret),
                .principal = c.auth.principal,
                .session_policy = c.auth.session_policy,
                .federated_policies = c.auth.federated_policies,
                .tenant = try c.arena.dupe(u8, s3.tenancy.callerTenant(self.auth, c.auth, &tbuf) orelse ""),
            },
            .now_s = now_s,
        });
        try respond(c, res);
        return true;
    }
};

/// Reads exactly the declared body and checks its signed hash; null when an
/// error response was already sent. Admin clients send plain, not chunk-signed, bodies.
fn readBody(c: *Ctx) ConnError!?[]const u8 {
    if (c.auth.mode != .sha256 and c.auth.mode != .unchecked) {
        try s3.handler.fail(c, .NotImplemented);
        return null;
    }
    var buf: [s3.handler.io_buf_len]u8 = undefined;
    const r = try c.req.readerExpectContinue(&buf);
    const body = if (c.req.head.content_length) |len|
        r.readAlloc(c.arena, @intCast(len)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.EndOfStream => {
                try s3.handler.fail(c, .IncompleteBody);
                return null;
            },
            error.ReadFailed => return error.ReadFailed,
        }
    else
        r.allocRemaining(c.arena, .limited(admin.api.max_body)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => {
                try respond(c, try admin.api.fail(c.arena, .payload_too_large, "EntityTooLarge", "Request body is too large."));
                return null;
            },
            error.ReadFailed => return error.ReadFailed,
        };
    if (c.auth.mode == .sha256) {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
        if (!std.mem.eql(u8, &digest, &c.auth.sha256)) {
            try s3.handler.fail(c, .XAmzContentSHA256Mismatch);
            return null;
        }
    }
    return body;
}

fn denied(c: *Ctx) ConnError!bool {
    try respond(c, try admin.api.fail(c.arena, .forbidden, "AccessDenied", "Access Denied."));
    return true;
}

fn respond(c: *Ctx, res: admin.api.Response) ConnError!void {
    metrics.global.last_status = @intFromEnum(res.status);
    const hs = [_]std.http.Header{
        .{ .name = "content-type", .value = res.content_type },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
        .{ .name = "x-minio-config-applied", .value = "true" },
    };
    try c.req.respond(res.body, .{ .status = res.status, .extra_headers = hs[0..if (res.config_applied) 3 else 2] });
}
