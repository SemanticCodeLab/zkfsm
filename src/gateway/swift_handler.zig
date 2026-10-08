//! Swift v1 request handling: routing, authentication (tempauth, Keystone, temp
//! URLs), account and container operations. Objects live in swift_object.zig.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const access_mod = @import("access.zig");
const util = @import("swift_util.zig");
const listing = @import("swift_listing.zig");
const auth = @import("swift_auth.zig");
const meta = @import("swift_meta.zig");
const keystone = @import("keystone.zig");
const objects = @import("swift_object.zig");

const Request = std.http.Server.Request;
const Header = std.http.Header;
const Status = std.http.Status;
const Op = access_mod.Op;

pub const max_headers = 200;
pub const max_path = 8 * 1024;
/// Objects scanned per request when computing account/container usage.
pub const usage_budget = 100_000;
pub const max_account = 64;

pub const State = struct {
    gpa: std.mem.Allocator,
    access: access_mod.Access,
    prefix: []const u8 = "",
    tempauth: bool = true,
    token_ttl_s: u32 = 86400,
    secret: [32]u8,
    ks: ?*keystone.Keystone = null,
    accounts: meta.AccountStore,
    /// Bound HOST:PORT, used in X-Storage-Url when the request has no usable Host.
    host: []const u8 = "127.0.0.1",
};

pub const ConnError = error{ WriteFailed, ReadFailed, OutOfMemory, HttpExpectationFailed, StreamAborted };

pub const Ctx = struct {
    st: *State,
    req: *Request,
    a: std.mem.Allocator,
    peer: std.net.Address,
    secure: bool,
    method: std.http.Method,
    path: []const u8 = "",
    query: []const u8 = "",
    headers: []const Header = &.{},
    account: []const u8 = "",
    container: []const u8 = "",
    object: []const u8 = "",
    who: access_mod.Principal = .{},
    trans: [18]u8 = undefined,
    /// Set for temp URL requests: GET adds Content-Disposition.
    tempurl: bool = false,
    /// The request method was COPY (parsed as TRACE).
    is_copy: bool = false,
    /// PUT/POST without Content-Length or chunked encoding.
    length_missing: bool = false,

    pub fn svc(c: *const Ctx) *object.ObjectService {
        return c.st.access.svc;
    }

    pub fn header(c: *const Ctx, name: []const u8) ?[]const u8 {
        for (c.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    pub fn q(c: *const Ctx, name: []const u8) ?[]const u8 {
        return util.query(c.a, c.query, name);
    }

    pub fn allowed(c: *const Ctx, op: Op, bucket: []const u8, key: []const u8) bool {
        return c.st.access.allowed(&c.who, op, bucket, key, c.peer, c.secure);
    }

    /// Full response; adds the transaction id, date, and content type.
    pub fn send(c: *Ctx, status: Status, body: []const u8, ctype: ?[]const u8, extra: []const Header) ConnError!void {
        const hs = try c.baseHeaders(extra, ctype orelse "text/plain; charset=utf-8");
        try c.req.respond(body, .{ .status = status, .extra_headers = hs, .keep_alive = !c.length_missing });
    }

    pub fn baseHeaders(c: *Ctx, extra: []const Header, ctype: []const u8) ConnError![]Header {
        const hs = try c.a.alloc(Header, extra.len + 4);
        @memcpy(hs[0..extra.len], extra);
        const date = try c.a.create([29]u8);
        hs[extra.len] = .{ .name = "Content-Type", .value = ctype };
        hs[extra.len + 1] = .{ .name = "X-Trans-Id", .value = &c.trans };
        hs[extra.len + 2] = .{ .name = "X-Openstack-Request-Id", .value = &c.trans };
        hs[extra.len + 3] = .{ .name = "Date", .value = util.httpDate(date, std.time.timestamp()) };
        return hs;
    }

    pub fn fail(c: *Ctx, status: Status, msg: []const u8) ConnError!void {
        const body = if (c.method == .HEAD) "" else try std.fmt.allocPrint(c.a, "<html><h1>{s}</h1><p>{s}</p></html>", .{ status.phrase() orelse "Error", msg });
        return c.send(status, body, "text/html; charset=UTF-8", &.{});
    }

    pub fn failObj(c: *Ctx, e: object.Error) ConnError!void {
        return switch (e) {
            error.NoSuchBucket, error.NoSuchKey, error.NoSuchVersion => c.fail(.not_found, "The resource could not be found."),
            error.BucketNotEmpty => c.fail(.conflict, "There was a conflict when trying to complete your request."),
            error.BucketAlreadyExists => c.fail(.accepted, "Container exists."),
            error.InvalidBucketName => c.fail(.bad_request, "Invalid container name (S3 bucket naming rules apply)."),
            error.KeyTooLong, error.InvalidKey => c.fail(.bad_request, "Invalid object name."),
            error.MetadataTooLarge, error.InvalidMetadata, error.InvalidTag => c.fail(.bad_request, "Invalid or oversized metadata."),
            error.BadDigest => c.fail(.unprocessable_entity, "Etag does not match the body."),
            error.PreconditionFailed => c.fail(.precondition_failed, "A precondition failed."),
            error.IncompleteBody => c.fail(.request_timeout, "The body was shorter than declared."),
            error.ObjectLocked => c.fail(.forbidden, "The object is locked."),
            error.NoSpace => c.fail(.insufficient_storage, "Out of space."),
            error.QuotaExceeded => c.fail(.payload_too_large, "Bucket quota exceeded."),
            error.TierUnavailable, error.RestoreInProgress => c.fail(.service_unavailable, "Object data is not available yet."),
            error.InvalidObjectState, error.InvalidStorageClass => c.fail(.bad_request, "Invalid object state."),
            error.WriteQuorum, error.ReadQuorum, error.LockTimeout => c.fail(.service_unavailable, "Storage is unavailable."),
            error.InvalidRequest, error.InvalidVersionId, error.InvalidBucketState, error.MethodNotAllowed, error.NoSuchTagSet => c.fail(.bad_request, "Invalid request."),
            error.OutOfMemory => error.OutOfMemory,
            error.ReadFailed => error.ReadFailed,
            error.WriteFailed => error.WriteFailed,
            error.StorageFailed, error.Corrupt => c.fail(.internal_server_error, "Storage error."),
        };
    }

    pub fn denied(c: *Ctx) ConnError!void {
        return c.fail(.forbidden, "Access was denied to this resource.");
    }
};

/// Serves one request; errors mean the connection must close.
pub fn handle(st: *State, req: *Request, a: std.mem.Allocator, peer: std.net.Address, secure: bool, is_copy: bool) ConnError!void {
    var c: Ctx = .{ .st = st, .req = req, .a = a, .peer = peer, .secure = secure, .method = req.head.method, .is_copy = is_copy };
    var tp: ?[]const u8 = null;
    var hit = req.iterateHeaders();
    while (hit.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "traceparent")) {
        tp = a.dupe(u8, h.value) catch null;
    };
    var sp = core.trace.root("swift.request", .server, .gateway, .{ .traceparent = tp });
    defer sp.end();
    sp.str("http.request.method", @tagName(req.head.method));
    sp.str("path", a.dupe(u8, req.head.target) catch "");
    var rnd: [8]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    _ = std.fmt.bufPrint(&c.trans, "tx{x}", .{&rnd}) catch {};
    // A body-carrying method without a length cannot be framed; answer and close.
    if (req.head.method.requestHasBody() and req.head.content_length == null and req.head.transfer_encoding == .none) {
        req.head.content_length = 0;
        c.length_missing = true;
    }
    if (req.head.expect) |e| if (!std.ascii.eqlIgnoreCase(e, "100-continue")) {
        req.head.expect = null;
        c.length_missing = true;
        return c.fail(.expectation_failed, "Unsupported Expect header.");
    };

    var hs: std.ArrayList(Header) = .empty;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (hs.items.len == max_headers) return c.fail(.bad_request, "Too many headers.");
        try hs.append(a, .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) });
    }
    c.headers = hs.items;

    const target = try a.dupe(u8, req.head.target);
    const qpos = std.mem.indexOfScalar(u8, target, '?');
    const raw_path = if (qpos) |i| target[0..i] else target;
    c.query = if (qpos) |i| target[i + 1 ..] else "";
    if (raw_path.len > max_path) return c.fail(.bad_request, "Path too long.");
    var path = util.percentDecodeAlloc(a, raw_path, false) catch return c.fail(.bad_request, "Invalid path encoding.");
    if (std.mem.indexOfScalar(u8, path, 0) != null) return c.fail(.bad_request, "Invalid path.");
    if (st.prefix.len > 0) {
        if (!std.mem.startsWith(u8, path, st.prefix) or (path.len > st.prefix.len and path[st.prefix.len] != '/'))
            return c.fail(.not_found, "The resource could not be found.");
        path = path[st.prefix.len..];
    }
    c.path = path;

    if (std.mem.eql(u8, path, "/info")) return info(&c);
    if (std.mem.eql(u8, path, "/auth/v1.0") or std.mem.eql(u8, path, "/auth/v1") or std.mem.eql(u8, path, "/v1.0"))
        return tempauthLogin(&c);
    if (!std.mem.startsWith(u8, path, "/v1/")) return c.fail(.not_found, "The resource could not be found.");
    const rest = path[4..];
    const s1 = std.mem.indexOfScalar(u8, rest, '/');
    c.account = if (s1) |i| rest[0..i] else rest;
    if (s1) |i| {
        const r2 = rest[i + 1 ..];
        const s2 = std.mem.indexOfScalar(u8, r2, '/');
        c.container = try util.bucketName(a, if (s2) |j| r2[0..j] else r2);
        if (s2) |j| c.object = r2[j + 1 ..];
    }
    if (c.account.len == 0 or c.account.len > max_account + 5) return c.fail(.bad_request, "Invalid account.");

    if (util.queryRaw(c.query, "temp_url_sig") != null) return objects.tempUrl(&c);
    if (!try authenticate(&c)) return;

    if (c.container.len == 0) return switch (c.method) {
        .GET, .HEAD => accountGet(&c),
        .POST => accountPost(&c),
        else => c.fail(.method_not_allowed, "Method not allowed on an account."),
    };
    if (c.object.len == 0) return switch (c.method) {
        .GET, .HEAD => containerGet(&c),
        .PUT => containerPut(&c),
        .POST => containerPost(&c),
        .DELETE => containerDelete(&c),
        else => c.fail(.method_not_allowed, "Method not allowed on a container."),
    };
    return objects.dispatch(&c);
}

fn now() i64 {
    return std.time.timestamp();
}

/// Resolves X-Auth-Token to a principal bound to the URL's account; responds on failure.
fn authenticate(c: *Ctx) ConnError!bool {
    const tok = c.header("x-auth-token") orelse c.header("x-storage-token") orelse {
        try c.fail(.unauthorized, "This server could not verify that you are authorized to access the document you requested.");
        return false;
    };
    if (std.mem.startsWith(u8, tok, auth.token_prefix)) {
        var buf: [8 + 2 + 2 * auth.max_name]u8 = undefined;
        const claims = (if (c.st.tempauth) auth.verifyToken(&buf, &c.st.secret, tok, now()) else null) orelse {
            try c.fail(.unauthorized, "Invalid or expired token.");
            return false;
        };
        if (!std.mem.startsWith(u8, c.account, "AUTH_") or !std.mem.eql(u8, c.account[5..], claims.account)) {
            try c.denied();
            return false;
        }
        c.who = c.st.access.known(claims.access_key) orelse {
            try c.fail(.unauthorized, "Unknown identity.");
            return false;
        };
        return true;
    }
    const ks = c.st.ks orelse {
        try c.fail(.unauthorized, "Invalid token.");
        return false;
    };
    const info_opt = ks.validate(tok, now()) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unavailable => {
            try c.fail(.service_unavailable, "Identity service unavailable.");
            return false;
        },
    };
    const ki = info_opt orelse {
        try c.fail(.unauthorized, "Invalid token.");
        return false;
    };
    if (!std.mem.startsWith(u8, c.account, "AUTH_") or !std.mem.eql(u8, c.account[5..], ki.projectId())) {
        try c.denied();
        return false;
    }
    const ak = ks.cfg.mapped(ki.projectId(), ki.projectName()) orelse {
        try c.denied();
        return false;
    };
    c.who = c.st.access.known(ak) orelse {
        try c.denied();
        return false;
    };
    return true;
}

fn validAccountLabel(s: []const u8) bool {
    if (s.len == 0 or s.len > max_account) return false;
    for (s) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.')) return false;
    return true;
}

/// GET /auth/v1.0: X-Auth-User `account:user` or `user` (IAM access key), X-Auth-Key secret.
fn tempauthLogin(c: *Ctx) ConnError!void {
    if (!c.st.tempauth) return c.fail(.not_found, "tempauth is disabled.");
    if (c.method != .GET and c.method != .HEAD) return c.fail(.method_not_allowed, "Use GET.");
    const user_hdr = c.header("x-auth-user") orelse c.header("x-storage-user") orelse return c.fail(.unauthorized, "Missing X-Auth-User.");
    const key = c.header("x-auth-key") orelse c.header("x-storage-pass") orelse return c.fail(.unauthorized, "Missing X-Auth-Key.");
    var account = user_hdr;
    var user = user_hdr;
    if (std.mem.indexOfScalar(u8, user_hdr, ':')) |i| {
        account = user_hdr[0..i];
        user = user_hdr[i + 1 ..];
    }
    if (!validAccountLabel(account) or user.len == 0 or user.len > auth.max_name) return c.fail(.unauthorized, "Invalid user.");
    const who = c.st.access.login(user, key) orelse return c.fail(.unauthorized, "Invalid credentials.");
    const exp = now() + c.st.token_ttl_s;
    const tbuf = try c.a.alloc(u8, auth.max_token);
    const token = auth.mintToken(tbuf, &c.st.secret, account, who.accessKey(), exp) catch return c.fail(.unauthorized, "Invalid user.");
    const url = try storageUrl(c, account);
    const ttl = try std.fmt.allocPrint(c.a, "{d}", .{c.st.token_ttl_s});
    return c.send(.ok, "", null, &.{
        .{ .name = "X-Auth-Token", .value = token },
        .{ .name = "X-Storage-Token", .value = token },
        .{ .name = "X-Storage-Url", .value = url },
        .{ .name = "X-Auth-Token-Expires", .value = ttl },
    });
}

fn storageUrl(c: *Ctx, account: []const u8) ConnError![]const u8 {
    var host = c.header("host") orelse "";
    if (host.len == 0 or host.len > 255 or !util.safeValue(host) or std.mem.indexOfAny(u8, host, "/ \t@") != null)
        host = c.st.host;
    return std.fmt.allocPrint(c.a, "{s}://{s}{s}/v1/AUTH_{s}", .{ if (c.secure) "https" else "http", host, c.st.prefix, account });
}

fn info(c: *Ctx) ConnError!void {
    if (c.method != .GET and c.method != .HEAD) return c.fail(.method_not_allowed, "Use GET.");
    const body = try std.fmt.allocPrint(c.a,
        \\{{"swift": {{"version": "2.33.0", "max_file_size": 5368709122, "max_meta_name_length": 128,
        \\ "max_meta_value_length": 256, "max_meta_count": 90, "max_meta_overall_size": 4096,
        \\ "account_listing_limit": 10000, "container_listing_limit": 10000, "max_account_name_length": 69,
        \\ "max_container_name_length": 63, "max_object_name_length": 1024, "strict_cors_mode": true,
        \\ "allow_account_management": false, "account_autocreate": true}},
        \\ "slo": {{"max_manifest_segments": {d}, "max_manifest_size": {d}, "min_segment_size": 1, "yield_frequency": 10}},
        \\ "dlo": {{"max_segments": {d}}},
        \\ "tempurl": {{"methods": ["GET", "HEAD", "PUT"], "allowed_digests": ["sha1", "sha256", "sha512"],
        \\ "incoming_remove_headers": ["x-timestamp"], "outgoing_remove_headers": ["x-object-meta-*"]}},
        \\ "tempauth": {{"enabled": {}}}, "keystoneauth": {{"enabled": {}}}}}
    , .{ @import("swift_slo.zig").max_segments, @import("swift_slo.zig").max_manifest_bytes, objects.max_dlo_segments, c.st.tempauth, c.st.ks != null });
    return c.send(.ok, if (c.method == .HEAD) "" else body, "application/json; charset=utf-8", &.{});
}

// ---- account ----

pub const Usage = struct { count: u64 = 0, bytes: u64 = 0 };

/// Object count and bytes of `bucket`, scanning at most `budget` entries.
pub fn usage(c: *Ctx, bucket: []const u8, budget: *usize) Usage {
    var u: Usage = .{};
    var cursor: std.ArrayList(u8) = .empty;
    defer cursor.deinit(c.st.gpa);
    while (budget.* > 0) {
        var arena = std.heap.ArenaAllocator.init(c.st.gpa);
        defer arena.deinit();
        const page = @min(budget.*, 1000);
        const r = c.svc().list(arena.allocator(), bucket, .{ .start_after = cursor.items, .max_keys = page }) catch return u;
        for (r.contents) |e| {
            u.count += 1;
            u.bytes += e.size;
        }
        budget.* -|= r.contents.len;
        if (!r.is_truncated or r.contents.len == 0) break;
        cursor.clearRetainingCapacity();
        cursor.appendSlice(c.st.gpa, r.contents[r.contents.len - 1].key) catch return u;
    }
    return u;
}

fn visibleBuckets(c: *Ctx) ConnError!?[]object.BucketInfo {
    const all = c.st.access.visibleBuckets(c.a, &c.who) catch |e| {
        try c.failObj(e);
        return null;
    };
    std.mem.sort(object.BucketInfo, all, {}, struct {
        fn lt(_: void, x: object.BucketInfo, y: object.BucketInfo) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    if (c.allowed(.list_buckets, "", "")) return all;
    var out: std.ArrayList(object.BucketInfo) = .empty;
    for (all) |b| if (c.allowed(.list_objects_v2, b.name, "")) try out.append(c.a, b);
    return out.items;
}

fn metaHeaders(c: *Ctx, list: *std.ArrayList(Header), prefix: []const u8, items: []const meta.Meta) ConnError!void {
    for (items) |m| {
        var tb: [meta.max_name]u8 = undefined;
        const name = try std.fmt.allocPrint(c.a, "{s}{s}", .{ prefix, util.titleCase(&tb, m.name) });
        if (util.safeValue(m.value)) try list.append(c.a, .{ .name = name, .value = m.value });
    }
}

fn accountGet(c: *Ctx) ConnError!void {
    const buckets = (try visibleBuckets(c)) orelse return;
    const acct = c.st.accounts.get(c.a, c.account) catch return c.fail(.internal_server_error, "Account metadata unavailable.");
    var budget: usize = usage_budget;
    const fmt = listing.pickFormat(c.q("format"), c.header("accept"));
    const limit = listing.parseLimit(c.q("limit")) catch return c.fail(.precondition_failed, "Maximum limit is 10000");
    const marker = c.q("marker") orelse "";
    const end_marker = c.q("end_marker") orelse "";
    const prefix = c.q("prefix") orelse "";
    const delimiter = c.q("delimiter") orelse "";

    var total: Usage = .{};
    var rows: std.ArrayList(listing.ContainerRow) = .empty;
    for (buckets) |b| {
        const u = usage(c, b.name, &budget);
        total.count += u.count;
        total.bytes += u.bytes;
        if (c.method == .HEAD or rows.items.len >= limit) continue;
        if (!std.mem.startsWith(u8, b.name, prefix)) continue;
        if (marker.len > 0 and !std.mem.lessThan(u8, marker, b.name)) continue;
        if (end_marker.len > 0 and !std.mem.lessThan(u8, b.name, end_marker)) continue;
        if (delimiter.len > 0) if (std.mem.indexOf(u8, b.name[prefix.len..], delimiter)) |i| {
            const sd = b.name[0 .. prefix.len + i + delimiter.len];
            if (rows.items.len > 0 and std.mem.eql(u8, rows.items[rows.items.len - 1].name, sd)) continue;
            try rows.append(c.a, .{ .name = sd, .subdir = true });
            continue;
        };
        try rows.append(c.a, .{ .name = b.name, .count = u.count, .bytes = u.bytes, .mtime_ns = b.created_ns });
    }
    var hs: std.ArrayList(Header) = .empty;
    try hs.append(c.a, .{ .name = "X-Account-Container-Count", .value = try std.fmt.allocPrint(c.a, "{d}", .{buckets.len}) });
    try hs.append(c.a, .{ .name = "X-Account-Object-Count", .value = try std.fmt.allocPrint(c.a, "{d}", .{total.count}) });
    try hs.append(c.a, .{ .name = "X-Account-Bytes-Used", .value = try std.fmt.allocPrint(c.a, "{d}", .{total.bytes}) });
    try hs.append(c.a, .{ .name = "X-Timestamp", .value = "0000000000.00000" });
    try metaHeaders(c, &hs, "X-Account-Meta-", acct.meta);
    if (c.method == .HEAD) return c.send(.no_content, "", fmt.contentType(), hs.items);
    var body: std.Io.Writer.Allocating = .init(c.a);
    listing.renderAccount(&body.writer, fmt, c.account, rows.items) catch return error.OutOfMemory;
    if (rows.items.len == 0 and fmt == .plain) return c.send(.no_content, "", fmt.contentType(), hs.items);
    return c.send(.ok, body.written(), fmt.contentType(), hs.items);
}

fn accountPost(c: *Ctx) ConnError!void {
    if (!c.allowed(.list_buckets, "", "")) return c.denied();
    const changes = meta.fromHeaders(c.a, c.headers, "x-account-meta-", meta.max_name) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => c.fail(.bad_request, "Invalid account metadata."),
    };
    c.st.accounts.update(c.account, changes, c.who.accessKey()) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Storage => c.fail(.internal_server_error, "Cannot store account metadata."),
        else => c.fail(.bad_request, "Invalid or too much account metadata."),
    };
    return c.send(.no_content, "", null, &.{});
}

// ---- container ----

fn containerMetaChanges(c: *Ctx) ConnError!?[]meta.Meta {
    return meta.fromHeaders(c.a, c.headers, "x-container-meta-", meta.max_container_name) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try c.fail(.bad_request, "Invalid container metadata.");
            return null;
        },
    };
}

fn applyContainerMeta(c: *Ctx, changes: []const meta.Meta) ConnError!bool {
    if (changes.len == 0) return true;
    var owner: ?[]const u8 = null;
    for (changes) |m| if (std.mem.startsWith(u8, m.name, "temp-url-key")) {
        owner = c.who.accessKey();
    };
    meta.updateContainer(c.svc(), c.a, c.container, changes, owner) catch |e| {
        switch (e) {
            error.BadMetadata, error.TooMuchMetadata => try c.fail(.bad_request, "Invalid or too much container metadata."),
            error.Storage => try c.fail(.internal_server_error, "Storage error."),
            else => |x| try c.failObj(x),
        }
        return false;
    };
    return true;
}

fn containerPut(c: *Ctx) ConnError!void {
    if (!c.allowed(.create_bucket, c.container, "")) return c.denied();
    const changes = (try containerMetaChanges(c)) orelse return;
    var status: Status = .created;
    c.st.access.createBucket(&c.who, c.container) catch |e| switch (e) {
        error.BucketAlreadyExists => status = .accepted,
        else => return c.failObj(e),
    };
    if (!try applyContainerMeta(c, changes)) return;
    return c.send(status, "", null, &.{});
}

fn containerPost(c: *Ctx) ConnError!void {
    if (!c.allowed(.put_bucket_tagging, c.container, "")) return c.denied();
    c.svc().headBucket(c.container) catch |e| return c.failObj(e);
    const changes = (try containerMetaChanges(c)) orelse return;
    if (!try applyContainerMeta(c, changes)) return;
    return c.send(.no_content, "", null, &.{});
}

fn containerDelete(c: *Ctx) ConnError!void {
    if (!c.allowed(.delete_bucket, c.container, "")) return c.denied();
    c.svc().deleteBucket(c.container) catch |e| return c.failObj(e);
    return c.send(.no_content, "", null, &.{});
}

fn containerGet(c: *Ctx) ConnError!void {
    const op: Op = if (c.method == .HEAD) .head_bucket else .list_objects_v2;
    if (!c.allowed(op, c.container, "")) return c.denied();
    c.svc().headBucket(c.container) catch |e| return c.failObj(e);
    const cm = meta.getContainer(c.svc(), c.a, c.container) catch |e| return c.failObj(e);
    var budget: usize = usage_budget;
    const u = usage(c, c.container, &budget);
    var hs: std.ArrayList(Header) = .empty;
    try hs.append(c.a, .{ .name = "X-Container-Object-Count", .value = try std.fmt.allocPrint(c.a, "{d}", .{u.count}) });
    try hs.append(c.a, .{ .name = "X-Container-Bytes-Used", .value = try std.fmt.allocPrint(c.a, "{d}", .{u.bytes}) });
    try hs.append(c.a, .{ .name = "X-Storage-Policy", .value = "default" });
    try metaHeaders(c, &hs, "X-Container-Meta-", cm.meta);
    const fmt = listing.pickFormat(c.q("format"), c.header("accept"));
    if (c.method == .HEAD) return c.send(.no_content, "", fmt.contentType(), hs.items);

    const limit = listing.parseLimit(c.q("limit")) catch return c.fail(.precondition_failed, "Maximum limit is 10000");
    var prefix = c.q("prefix") orelse "";
    var delimiter = c.q("delimiter") orelse "";
    if (c.q("path")) |p| {
        prefix = if (p.len == 0 or std.mem.endsWith(u8, p, "/")) p else try std.fmt.allocPrint(c.a, "{s}/", .{p});
        delimiter = "/";
    }
    if (delimiter.len > 1) return c.fail(.precondition_failed, "Bad delimiter");
    const marker = c.q("marker") orelse "";
    const end_marker = c.q("end_marker") orelse "";
    const r = c.svc().list(c.a, c.container, .{ .prefix = prefix, .delimiter = delimiter, .start_after = marker, .max_keys = limit }) catch |e| return c.failObj(e);

    var rows: std.ArrayList(listing.Row) = .empty;
    var i: usize = 0;
    var j: usize = 0;
    while (i < r.contents.len or j < r.common_prefixes.len) {
        const take_obj = j >= r.common_prefixes.len or (i < r.contents.len and std.mem.lessThan(u8, r.contents[i].key, r.common_prefixes[j]));
        const name = if (take_obj) r.contents[i].key else r.common_prefixes[j];
        if (end_marker.len > 0 and !std.mem.lessThan(u8, name, end_marker)) break;
        if (take_obj) {
            try rows.append(c.a, .{ .object = try objects.listingRow(c, r.contents[i]) });
            i += 1;
        } else {
            try rows.append(c.a, .{ .subdir = name });
            j += 1;
        }
    }
    if (rows.items.len == 0 and fmt == .plain) return c.send(.no_content, "", fmt.contentType(), hs.items);
    var body: std.Io.Writer.Allocating = .init(c.a);
    listing.renderContainer(&body.writer, fmt, c.container, rows.items) catch return error.OutOfMemory;
    return c.send(.ok, body.written(), fmt.contentType(), hs.items);
}

test "account label validation" {
    try std.testing.expect(validAccountLabel("test_1.a-b"));
    try std.testing.expect(!validAccountLabel(""));
    try std.testing.expect(!validAccountLabel("a/b"));
    try std.testing.expect(!validAccountLabel("a" ** 65));
}
