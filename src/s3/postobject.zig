//! Browser-form POST object uploads (`POST /bucket` with multipart/form-data): the
//! form's POST policy is authenticated (SigV4 or SigV2) and checked, then the file
//! part streams into the object. Without a policy the upload is anonymous.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const postform = @import("postform.zig");
const authz = @import("authz.zig");
const sigv4 = @import("sigv4.zig");
const iam = @import("../iam/root.zig");
const s3v = @import("versioning.zig");
const acl = @import("acl.zig");
const checksums = @import("checksums.zig");
const errors = @import("errors.zig");

const Ctx = handler.Ctx;
const ConnError = handler.ConnError;
const Header = std.http.Header;
const Code = errors.Code;
const sv = core.sigv4;

const max_field = 64 * 1024;
const max_fields = 64;

/// Handles form uploads; false when the request is not one.
pub fn handle(c: *Ctx) ConnError!bool {
    if (c.method != .POST or c.route.bucket.len == 0 or c.route.key.len != 0) return false;
    const boundary = postform.boundaryFrom(c.content_type) orelse return false;
    run(c, boundary) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => |oe| try handler.fail(c, errors.fromObject(oe)),
    };
    return true;
}

fn failForm(c: *Ctx, e: postform.AnyError) ConnError!void {
    const st = postform.s3Status(e);
    try handler.fail(c, codeOf(st.code));
}

fn codeOf(name: []const u8) Code {
    return std.meta.stringToEnum(Code, name) orelse .InvalidRequest;
}

const Limited = struct {
    in: *std.Io.Reader,
    policy: ?*const postform.Policy,
    size: u64 = 0,
    failure: ?Code = null,
    done: bool = false,
    reader: std.Io.Reader,

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Limited = @alignCast(@fieldParentPtr("reader", r));
        if (self.done) return if (self.failure != null) error.ReadFailed else error.EndOfStream;
        const n = self.in.stream(w, limit) catch |e| switch (e) {
            error.EndOfStream => {
                self.done = true;
                if (self.policy) |p| p.checkLength(self.size, true) catch |le| return self.fail(le);
                return error.EndOfStream;
            },
            else => return e,
        };
        self.size += n;
        if (self.policy) |p| p.checkLength(self.size, false) catch |le| return self.fail(le);
        return n;
    }

    fn fail(self: *Limited, e: postform.LengthError) std.Io.Reader.StreamError {
        self.done = true;
        self.failure = codeOf(postform.s3Status(e).code);
        return error.ReadFailed;
    }
};

fn run(c: *Ctx, boundary: []const u8) handler.DispatchError!void {
    var in_buf: [16 * 1024]u8 = undefined;
    const body = try c.req.readerExpectContinue(&in_buf);
    var part_buf: [handler.io_buf_len]u8 = undefined;
    var fr = postform.FormReader.init(body, boundary, &part_buf) catch return handler.fail(c, .MalformedPOSTRequest);
    var fields: std.ArrayList(postform.Field) = .empty;
    var file: ?postform.Part = null;
    while (fr.nextPart(c.arena) catch |e| return failForm(c, e)) |part| {
        if (std.ascii.eqlIgnoreCase(part.name, "file")) {
            file = part;
            break;
        }
        if (fields.items.len >= max_fields) return handler.fail(c, .MalformedPOSTRequest);
        const v = fr.reader.allocRemaining(c.arena, .limited(max_field)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return handler.fail(c, .MalformedPOSTRequest),
            error.ReadFailed => return failForm(c, fr.failure orelse error.ReadFailed),
        };
        // The bucket comes from the URL; a form `bucket` field is matched against it.
        if (std.ascii.eqlIgnoreCase(part.name, "bucket")) continue;
        try fields.append(c.arena, .{ .name = part.name, .value = v });
    }
    const f = file orelse return handler.fail(c, .InvalidArgument);
    const raw_key = postform.fieldValue(fields.items, "key") orelse return handler.fail(c, .InvalidArgument);
    const key = try postform.substituteFilename(c.arena, raw_key, f.filename orelse "");
    if (key.len == 0) return handler.fail(c, .InvalidArgument);
    for (fields.items) |*fld| if (std.ascii.eqlIgnoreCase(fld.name, "key")) {
        fld.value = key;
    };
    try fields.append(c.arena, .{ .name = "bucket", .value = c.route.bucket });

    const now_s = std.time.timestamp();
    var policy: ?postform.Policy = null;
    if (postform.fieldValue(fields.items, "policy")) |pb64| {
        if (!try authenticate(c, fields.items, pb64, now_s)) return;
        policy = postform.Policy.parse(c.arena, pb64) catch |e| return failForm(c, e);
        policy.?.check(fields.items, now_s) catch |e| return failForm(c, e);
    } else c.auth = .{ .anonymous = c.env.auth.iam != null };

    c.route.key = key;
    if (!try handler.authorize(c, .{ .method = .PUT, .bucket = c.route.bucket, .key = key, .query = "" }, now_s)) return;

    var in: object.PutInput = .{ .content_type = postform.fieldValue(fields.items, "content-type") orelse f.content_type };
    try applyFields(c, fields.items, &in) orelse return;
    var lim: Limited = .{ .in = &fr.reader, .policy = if (policy) |*p| p else null, .reader = .{ .vtable = &.{ .stream = Limited.stream }, .buffer = &.{}, .seek = 0, .end = 0 } };
    var ck_buf: [handler.io_buf_len]u8 = undefined;
    var ver = checksums.Verifier.init(c.ext.checksum, &lim.reader, null, &ck_buf);
    const source = if (ver) |*v| &v.reader else &lim.reader;
    const info = c.svc.put(c.route.bucket, key, source, in) catch |e| {
        if (lim.failure) |code| return handler.fail(c, code);
        if (ver) |v| if (v.failure) |code| return handler.fail(c, code);
        if (fr.failure) |fe| return failForm(c, fe);
        return e;
    };
    // Fields after the file are ignored; drain them so the connection can be reused.
    while (fr.nextPart(c.arena) catch null) |_| {}
    try respond(c, fields.items, key, info);
}

/// Checks the policy signature (SigV4 or SigV2) and sets the caller; false after answering.
fn authenticate(c: *Ctx, fields: []const postform.Field, pb64: []const u8, now_s: i64) ConnError!bool {
    const store = c.env.auth.iam orelse {
        c.auth = .{};
        return true;
    };
    var sbuf: iam.Store.SecretBuf = undefined;
    if (postform.fieldValue(fields, "x-amz-signature")) |sig| {
        const cred = postform.fieldValue(fields, "x-amz-credential") orelse return deny(c, .InvalidArgument);
        const date = postform.fieldValue(fields, "x-amz-date") orelse return deny(c, .InvalidArgument);
        var it = std.mem.splitScalar(u8, cred, '/');
        const ak = it.next() orelse return deny(c, .InvalidArgument);
        const scope: sv.Scope = .{
            .date = it.next() orelse return deny(c, .InvalidArgument),
            .region = it.next() orelse return deny(c, .InvalidArgument),
            .service = it.next() orelse return deny(c, .InvalidArgument),
        };
        if (date.len < 8 or !std.mem.eql(u8, date[0..8], scope.date)) return deny(c, .AuthorizationHeaderMalformed);
        const secret = try secretFor(c, store, ak, fields, now_s, &sbuf) orelse return deny(c, .InvalidAccessKeyId);
        const want = sv.sign(sv.signingKey(secret, scope.date, scope.region, scope.service), pb64);
        if (sig.len != want.len or !std.crypto.timing_safe.eql(sv.Hex, want, sig[0..64].*)) return deny(c, .SignatureDoesNotMatch);
        return true;
    }
    const sig = postform.fieldValue(fields, "signature") orelse return deny(c, .InvalidArgument);
    const ak = postform.fieldValue(fields, "awsaccesskeyid") orelse return deny(c, .InvalidArgument);
    const secret = try secretFor(c, store, ak, fields, now_s, &sbuf) orelse return deny(c, .AccessDenied);
    const want = postform.signV2(secret, pb64);
    if (sig.len != want.len or !std.crypto.timing_safe.eql([28]u8, want, sig[0..28].*)) return deny(c, .SignatureDoesNotMatch);
    return true;
}

/// Secret of `ak` (an STS session when the form carries a security token); sets `c.auth`.
fn secretFor(c: *Ctx, store: *iam.Store, ak: []const u8, fields: []const postform.Field, now_s: i64, sbuf: *iam.Store.SecretBuf) error{OutOfMemory}!?[]const u8 {
    c.auth = .{ .principal = ak, .access_key = ak };
    if (postform.fieldValue(fields, "x-amz-security-token")) |t| {
        const issuer = c.env.auth.sts orelse return null;
        var dbuf: iam.sts.DecodeBuffer = undefined;
        const claims = issuer.verify(ak, t, now_s, &dbuf) catch return null;
        c.auth.principal = try c.arena.dupe(u8, claims.parent);
        c.auth.session_policy = if (claims.session_policy) |sp| try c.arena.dupe(u8, sp) else null;
        c.auth.federated_policies = if (claims.federated_policies) |fp| try c.arena.dupe(u8, fp) else null;
        c.auth.tenant = try c.arena.dupe(u8, claims.tenant);
        const s = issuer.secretFor(ak);
        @memcpy(sbuf[0..s.len], &s);
        return sbuf[0..s.len];
    }
    return store.secretFor(ak, now_s, sbuf);
}

fn deny(c: *Ctx, code: Code) ConnError!bool {
    try handler.fail(c, code);
    return false;
}

/// Metadata, tags, ACL, checksum, and standard headers from form fields; null after answering.
fn applyFields(c: *Ctx, fields: []const postform.Field, in: *object.PutInput) handler.DispatchError!?void {
    var meta: std.ArrayList(object.Header) = .empty;
    for (fields) |fld| {
        const h: Header = .{ .name = fld.name, .value = fld.value };
        if (std.ascii.startsWithIgnoreCase(fld.name, "x-amz-meta-") or std.ascii.eqlIgnoreCase(fld.name, "acl") or
            std.ascii.startsWithIgnoreCase(fld.name, "x-amz-checksum-") or std.ascii.eqlIgnoreCase(fld.name, "cache-control") or
            std.ascii.eqlIgnoreCase(fld.name, "content-disposition") or std.ascii.eqlIgnoreCase(fld.name, "content-encoding") or
            std.ascii.eqlIgnoreCase(fld.name, "expires"))
        {
            try c.ext.capture(c.arena, if (std.ascii.eqlIgnoreCase(fld.name, "acl")) .{ .name = "x-amz-acl", .value = fld.value } else h);
        }
    }
    _ = &meta;
    if (postform.fieldValue(fields, "tagging")) |t| {
        const tags = s3v.parseTagSet(c.arena, t) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Malformed => {
                try handler.fail(c, .MalformedXML);
                return null;
            },
        };
        in.tags = try object.versioning.encodeObjectTags(c.arena, tags);
    }
    const saved_tags = in.tags;
    if (!try s3v.putExtras(c, in)) return null;
    if (saved_tags.len > 0) in.tags = saved_tags;
    if (!try checksums.checkHeaders(c)) return null;
}

fn respond(c: *Ctx, fields: []const postform.Field, key: []const u8, info: object.ObjectInfo) ConnError!void {
    var eb: [core.ETag.quoted_max]u8 = undefined;
    const etag = info.etag.quoted(&eb);
    const scheme = "http";
    const location = try std.fmt.allocPrint(c.arena, "{s}://{s}/{s}/{s}", .{ scheme, c.host orelse "localhost", c.route.bucket, key });
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.append(c.arena, .{ .name = "etag", .value = etag });
    try s3v.putResponseHeaders(c, info, &hdrs);
    const redirect = postform.fieldValue(fields, "success_action_redirect") orelse postform.fieldValue(fields, "redirect");
    if (redirect) |url| if (url.len > 0) {
        const to = try postform.redirectUrl(c.arena, url, c.route.bucket, key, etag[1 .. etag.len - 1]);
        try hdrs.append(c.arena, .{ .name = "location", .value = to });
        return handler.respondEmpty(c, .see_other, hdrs.items);
    };
    try hdrs.append(c.arena, .{ .name = "location", .value = location });
    switch (postform.successStatus(postform.fieldValue(fields, "success_action_status"))) {
        200 => try handler.respondEmpty(c, .ok, hdrs.items),
        201 => {
            var a: std.Io.Writer.Allocating = .init(c.arena);
            postform.writePostResponse(&a.writer, location, c.route.bucket, key, etag) catch return error.OutOfMemory;
            try handler.respondXmlWith(c, .created, a.written(), hdrs.items);
        },
        else => try handler.respondEmpty(c, .no_content, hdrs.items),
    }
}
