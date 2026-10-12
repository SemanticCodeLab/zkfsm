//! Entry point: a raw route that claims Iceberg REST paths and requests signed
//! for the s3tables service, authenticates them (SigV4 over the buffered body),
//! and dispatches. Also an S3 extension that hides the reserved catalog keys.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const core = @import("../core/root.zig");
const http = @import("http.zig");
const catalog = @import("catalog.zig");
const store_mod = @import("store.zig");
const iceberg = @import("iceberg.zig");
const control = @import("control.zig");

const Request = std.http.Server.Request;
const RawError = s3.server.RawError;
const Req = http.Req;

/// Largest request body (commit/create JSON) accepted.
pub const max_body = 8 * 1024 * 1024;

pub const iceberg_prefixes = [_][]const u8{ "/iceberg/v1", "/_iceberg/v1" };

pub const Tables = struct {
    svc: *object.ObjectService,
    auth: s3.sigv4.Config,
    region: []const u8 = "us-east-1",
    account: []const u8 = "000000000000",
    store: store_mod.Store,

    pub fn init(svc: *object.ObjectService, auth: s3.sigv4.Config) Tables {
        var region: []const u8 = "us-east-1";
        if (std.posix.getenv("ZKFSM_REGION")) |r| if (r.len > 0 and r.len <= 64) {
            region = r;
        };
        return .{ .svc = svc, .auth = auth, .region = region, .store = .{ .svc = svc } };
    }

    pub fn catalogOf(self: *Tables) catalog.Catalog {
        return .{ .store = &self.store };
    }

    /// `self` must not move once the route is installed.
    pub fn route(self: *Tables) s3.server.RawRoute {
        return .{ .prefix = "", .ctx = self, .serve = serve, .accept = accept };
    }

    pub fn guard(self: *Tables) s3.Extension {
        return .{ .name = "tables-guard", .ctx = self, .route = guardRoute };
    }

    pub fn bucketArn(self: *Tables, arena: std.mem.Allocator, bucket: []const u8) error{OutOfMemory}![]const u8 {
        return std.fmt.allocPrint(arena, "arn:aws:s3tables:{s}:{s}:bucket/{s}", .{ self.region, self.account, bucket });
    }

    pub fn tableArn(self: *Tables, arena: std.mem.Allocator, bucket: []const u8, uuid: []const u8) error{OutOfMemory}![]const u8 {
        return std.fmt.allocPrint(arena, "arn:aws:s3tables:{s}:{s}:bucket/{s}/table/{s}", .{ self.region, self.account, bucket, uuid });
    }

    /// IAM decision for an s3tables action; the table bucket policy is the resource policy.
    pub fn allowed(self: *Tables, r: *Req, action: []const u8, bucket: ?[]const u8, table_uuid: ?[]const u8) RawError!bool {
        const st = self.auth.iam orelse return true;
        const a = r.arena;
        const arn = if (bucket) |b|
            (if (table_uuid) |u| try self.tableArn(a, b, u) else try self.bucketArn(a, b))
        else
            try std.fmt.allocPrint(a, "arn:aws:s3tables:{s}:{s}:bucket/*", .{ self.region, self.account });
        var rp: ?iam.Policy = null;
        if (bucket) |b| {
            const doc = self.store.read(a, b, catalog.policy_key, catalog.max_doc) catch null;
            if (doc) |d| rp = iam.policy.parse(a, d.body) catch null;
        }
        const ctx: iam.Context = .{ .now_s = std.time.timestamp(), .resource_policy = if (rp) |*p| p else null };
        if (r.auth.anonymous) {
            const nobody: iam.Principal = .{};
            return iam.authorize(&nobody, action, arn, &ctx).allowed();
        }
        var session: ?iam.Policy = null;
        if (r.auth.session_policy) |doc| session = iam.policy.parse(a, doc) catch return false;
        const who: iam.Identity = .{ .access_key = r.auth.principal, .session_policy = if (session) |*p| p else null, .federated_policies = r.auth.federated_policies };
        return st.authorize(who, action, arn, &ctx).allowed();
    }
};

fn icebergRest(target: []const u8) ?[]const u8 {
    for (iceberg_prefixes) |p| {
        if (!std.mem.startsWith(u8, target, p)) continue;
        const rest = target[p.len..];
        if (rest.len == 0 or rest[0] == '/' or rest[0] == '?') return rest;
    }
    return null;
}

fn signedForTables(req: *const Request) bool {
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) return std.mem.indexOf(u8, h.value, "/s3tables/aws4_request") != null;
    }
    return std.mem.indexOf(u8, req.head.target, "%2Fs3tables%2Faws4_request") != null;
}

fn accept(_: *anyopaque, req: *const Request) bool {
    return icebergRest(req.head.target) != null or signedForTables(req);
}

fn reject(req: *Request, status: std.http.Status, msg: []const u8) RawError!void {
    req.respond(msg, .{ .status = status, .keep_alive = false, .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }} }) catch return error.WriteFailed;
}

fn serve(ctx: *anyopaque, req: *Request, arena: std.mem.Allocator) RawError!void {
    const self: *Tables = @ptrCast(@alignCast(ctx));
    if (req.head.transfer_encoding == .none and req.head.content_length == null) req.head.content_length = 0;
    var in = try s3.sigv4.Input.fromRequest(arena, req);
    const method = req.head.method;
    if (req.head.content_length) |n| if (n > max_body) return reject(req, .payload_too_large, "request body too large\n");
    var buf: [16 * 1024]u8 = undefined;
    const reader = try req.readerExpectContinue(&buf);
    const body = reader.allocRemaining(arena, .limited(max_body)) catch |e| switch (e) {
        error.StreamTooLong => return reject(req, .payload_too_large, "request body too large\n"),
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => return error.ReadFailed,
    };

    // Non-S3 signers omit x-amz-content-sha256 but sign the body hash.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (in.header("x-amz-content-sha256")) |p| {
        if (std.mem.startsWith(u8, p, "STREAMING-")) return reject(req, .bad_request, "streaming payloads are not supported\n");
        if (p.len == 64 and !std.ascii.eqlIgnoreCase(p, &hex)) return reject(req, .bad_request, "x-amz-content-sha256 does not match the body\n");
    } else {
        const hs = try arena.alloc(std.http.Header, in.headers.len + 1);
        @memcpy(hs[0..in.headers.len], in.headers);
        hs[in.headers.len] = .{ .name = "x-amz-content-sha256", .value = try arena.dupe(u8, &hex) };
        in.headers = hs;
    }
    const now_s = std.time.timestamp();
    var outcome = try s3.sigv4.verify(arena, self.auth, in, now_s);
    // Encoded paths: clients differ on double-encoding the canonical URI.
    const q = std.mem.indexOfScalar(u8, in.target, '?');
    const path = in.target[0 .. q orelse in.target.len];
    if (outcome == .denied and outcome.denied == .SignatureDoesNotMatch and std.mem.indexOfScalar(u8, path, '%') != null) {
        for ([_]bool{ true, false }) |dbl| {
            in.double_encode = dbl;
            outcome = try s3.sigv4.verify(arena, self.auth, in, now_s);
            if (outcome == .ok) break;
        }
    }
    var r: Req = .{
        .raw = req,
        .arena = arena,
        .method = method,
        .path = path,
        .query = if (q) |i| in.target[i + 1 ..] else "",
        .body = body,
        .auth = .{},
        .request_id = std.fmt.bytesToHex(core.ObjectId.random().bytes[0..8].*, .upper),
    };
    const ice = icebergRest(in.target);
    switch (outcome) {
        .ok => |a| r.auth = a,
        .denied => |code| {
            const msg = @tagName(code);
            return if (ice != null) r.iceberg(.forbidden, "NotAuthorizedException", msg) else r.tables(.forbidden, "AccessDeniedException", msg);
        },
    }
    const svc_name = r.auth.scope.service;
    if (svc_name.len > 0 and !std.mem.eql(u8, svc_name, "s3") and !std.mem.eql(u8, svc_name, "s3tables"))
        return r.tables(.forbidden, "AccessDeniedException", "credential scope service not accepted");
    if (ice) |rest| {
        const rq = std.mem.indexOfScalar(u8, rest, '?');
        return iceberg.handle(self, &r, rest[0 .. rq orelse rest.len]);
    }
    return control.handle(self, &r);
}

/// Denies reserved keys as targets (objects, multipart) and as copy sources.
fn guardRoute(_: *anyopaque, c: *s3.handler.Ctx) s3.handler.ConnError!bool {
    var hit = object.list.isReserved(c.route.key);
    for (c.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-amz-copy-source")) {
        hit = hit or copySourceReserved(c.arena, h.value);
    };
    if (!hit) return false;
    try s3.handler.fail(c, .AccessDenied);
    return true;
}

/// `[/]bucket/key[?versionId=..]`, percent-encoded; undecodable counts as reserved.
fn copySourceReserved(arena: std.mem.Allocator, raw: []const u8) bool {
    const path = raw[0 .. std.mem.indexOfScalar(u8, raw, '?') orelse raw.len];
    const dec = s3.router.percentDecode(arena, path, false) catch return true;
    const p = std.mem.trimLeft(u8, dec, "/");
    const slash = std.mem.indexOfScalar(u8, p, '/') orelse return false;
    return object.list.isReserved(p[slash + 1 ..]);
}

test "copy source guard" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    try std.testing.expect(copySourceReserved(a.allocator(), "/b/.zkfsm-tables/bucket"));
    try std.testing.expect(copySourceReserved(a.allocator(), "b/%2Ezkfsm-tables%2Fns%2Fx?versionId=1"));
    try std.testing.expect(!copySourceReserved(a.allocator(), "/b/data/x"));
    try std.testing.expect(copySourceReserved(a.allocator(), "/b/%zz"));
}

test "route matching" {
    try std.testing.expectEqualStrings("/config", icebergRest("/iceberg/v1/config").?);
    try std.testing.expectEqualStrings("?x", icebergRest("/_iceberg/v1?x").?);
    try std.testing.expect(icebergRest("/iceberg/v10/x") == null);
    try std.testing.expect(icebergRest("/icebergs/v1") == null);
}
