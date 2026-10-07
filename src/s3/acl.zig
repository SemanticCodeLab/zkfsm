//! Bucket and object ACLs: canned ACLs, grant headers, and AccessControlPolicy bodies.
//! IAM and bucket policies decide first; ACL grants are consulted only when they deny,
//! so ACLs can open access (public-read, grants to users) but never narrow IAM.
const std = @import("std");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");
const s3v = @import("versioning.zig");
const sigv4 = @import("sigv4.zig");
const tenancy = @import("tenancy.zig");
const errors = @import("errors.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const Code = errors.Code;

/// Canonical id of the deployment root, the owner of everything root creates.
pub const owner_id = "zkfsm";
pub const all_users = "http://acs.amazonaws.com/groups/global/AllUsers";
pub const authenticated_users = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
pub const log_delivery = "http://acs.amazonaws.com/groups/s3/LogDelivery";
/// Object ACL and owner, kept with the version (dropped by copies).
pub const object_header = object.internal_prefix ++ "obj-acl";

pub const Perm = enum {
    READ,
    WRITE,
    READ_ACP,
    WRITE_ACP,
    FULL_CONTROL,

    fn parse(s: []const u8) ?Perm {
        return std.meta.stringToEnum(Perm, s);
    }

    fn covers(have: Perm, want: Perm) bool {
        return have == .FULL_CONTROL or have == want;
    }
};

pub const Kind = enum { id, group, email };

pub const Grant = struct { kind: Kind, value: []const u8, perm: Perm };

pub const Acl = struct {
    owner: []const u8,
    grants: []const Grant,

    pub fn private(owner: []const u8) Acl {
        return .{ .owner = owner, .grants = &.{} };
    }

    /// Grants including the owner's implicit FULL_CONTROL unless revoked explicitly.
    pub fn isPublic(a: Acl) bool {
        for (a.grants) |g| if (g.kind == .group and (std.mem.eql(u8, g.value, all_users) or std.mem.eql(u8, g.value, authenticated_users))) return true;
        return false;
    }
};

/// Who asks: "" for anonymous callers.
pub const Caller = struct { id: []const u8, anonymous: bool };

pub const ParseError = error{ OutOfMemory, MalformedACLError, InvalidArgument, UnresolvableGrantByEmailAddress };

/// Request headers that set an ACL, captured before the body is read.
pub const RequestAcl = struct {
    canned: ?[]const u8 = null,
    grant: [5]?[]const u8 = @splat(null),

    const grant_headers = [_]struct { []const u8, Perm }{
        .{ "x-amz-grant-read", .READ },
        .{ "x-amz-grant-write", .WRITE },
        .{ "x-amz-grant-read-acp", .READ_ACP },
        .{ "x-amz-grant-write-acp", .WRITE_ACP },
        .{ "x-amz-grant-full-control", .FULL_CONTROL },
    };

    pub fn capture(self: *RequestAcl, arena: std.mem.Allocator, h: std.http.Header) error{OutOfMemory}!void {
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-acl")) self.canned = try arena.dupe(u8, std.mem.trim(u8, h.value, " "));
        for (grant_headers, 0..) |g, i| if (std.ascii.eqlIgnoreCase(h.name, g[0])) {
            self.grant[i] = try arena.dupe(u8, h.value);
        };
    }

    pub fn present(self: RequestAcl) bool {
        if (self.canned != null) return true;
        for (self.grant) |g| if (g != null) return true;
        return false;
    }

    /// The ACL these headers describe for a resource owned by `owner`; null when none were sent.
    pub fn resolve(self: RequestAcl, arena: std.mem.Allocator, owner: []const u8, bucket_owner: []const u8) ParseError!?Acl {
        if (self.canned) |name| {
            for (self.grant) |g| if (g != null) return error.InvalidArgument;
            return try canned(arena, name, owner, bucket_owner);
        }
        var list: std.ArrayList(Grant) = .empty;
        for (self.grant, grant_headers) |hv, gh| {
            const v = hv orelse continue;
            var it = std.mem.splitScalar(u8, v, ',');
            while (it.next()) |raw| {
                const item = std.mem.trim(u8, raw, " \t");
                if (item.len == 0) continue;
                const eq = std.mem.indexOfScalar(u8, item, '=') orelse return error.InvalidArgument;
                const k = std.mem.trim(u8, item[0..eq], " ");
                const val = std.mem.trim(u8, std.mem.trim(u8, item[eq + 1 ..], " "), "\"");
                const kind: Kind = if (std.ascii.eqlIgnoreCase(k, "id")) .id else if (std.ascii.eqlIgnoreCase(k, "uri")) .group else if (std.ascii.eqlIgnoreCase(k, "emailAddress")) .email else return error.InvalidArgument;
                try list.append(arena, .{ .kind = kind, .value = try arena.dupe(u8, val), .perm = gh[1] });
            }
        }
        if (list.items.len == 0) return null;
        return .{ .owner = owner, .grants = list.items };
    }
};

/// The canned `private` ACL: the owner's FULL_CONTROL.
pub fn privateAcl(arena: std.mem.Allocator, owner: []const u8) error{OutOfMemory}!Acl {
    const g = try arena.alloc(Grant, 1);
    g[0] = .{ .kind = .id, .value = owner, .perm = .FULL_CONTROL };
    return .{ .owner = owner, .grants = g };
}

/// Expands a canned ACL; error.InvalidArgument for unknown names.
/// Group and bucket-owner grants come first, the owner's FULL_CONTROL last.
pub fn canned(arena: std.mem.Allocator, name: []const u8, owner: []const u8, bucket_owner: []const u8) ParseError!Acl {
    var g: std.ArrayList(Grant) = .empty;
    if (std.mem.eql(u8, name, "private")) {} else if (std.mem.eql(u8, name, "public-read")) {
        try g.append(arena, .{ .kind = .group, .value = all_users, .perm = .READ });
    } else if (std.mem.eql(u8, name, "public-read-write")) {
        try g.append(arena, .{ .kind = .group, .value = all_users, .perm = .READ });
        try g.append(arena, .{ .kind = .group, .value = all_users, .perm = .WRITE });
    } else if (std.mem.eql(u8, name, "authenticated-read")) {
        try g.append(arena, .{ .kind = .group, .value = authenticated_users, .perm = .READ });
    } else if (std.mem.eql(u8, name, "bucket-owner-read")) {
        if (!std.mem.eql(u8, owner, bucket_owner)) try g.append(arena, .{ .kind = .id, .value = bucket_owner, .perm = .READ });
    } else if (std.mem.eql(u8, name, "bucket-owner-full-control")) {
        if (!std.mem.eql(u8, owner, bucket_owner)) try g.append(arena, .{ .kind = .id, .value = bucket_owner, .perm = .FULL_CONTROL });
    } else if (std.mem.eql(u8, name, "log-delivery-write")) {
        try g.append(arena, .{ .kind = .group, .value = log_delivery, .perm = .WRITE });
        try g.append(arena, .{ .kind = .group, .value = log_delivery, .perm = .READ_ACP });
    } else if (std.mem.eql(u8, name, "aws-exec-read")) {
        // Read access for an exec service has no counterpart here; owner only.
    } else return error.InvalidArgument;
    try g.append(arena, .{ .kind = .id, .value = owner, .perm = .FULL_CONTROL });
    return .{ .owner = owner, .grants = g.items };
}

// ---- storage encoding: `owner|K:PERM:value|...` (no CR/LF, so it fits a header value) ----

pub fn encode(arena: std.mem.Allocator, a: Acl) error{ OutOfMemory, InvalidArgument }![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    if (!safe(a.owner)) return error.InvalidArgument;
    w.writeAll(a.owner) catch return error.OutOfMemory;
    for (a.grants) |g| {
        if (!safe(g.value)) return error.InvalidArgument;
        const k: u8 = switch (g.kind) {
            .id => 'i',
            .group => 'g',
            .email => 'e',
        };
        w.print("|{c}:{t}:{s}", .{ k, g.perm, g.value }) catch return error.OutOfMemory;
    }
    return out.written();
}

fn safe(s: []const u8) bool {
    return std.mem.indexOfAny(u8, s, "|\r\n\x00") == null;
}

/// Grants are given implicit owner FULL_CONTROL only by `canned`; stored lists are taken verbatim.
pub fn decode(arena: std.mem.Allocator, s: []const u8) error{OutOfMemory}!?Acl {
    var it = std.mem.splitScalar(u8, s, '|');
    const owner = it.next() orelse return null;
    var g: std.ArrayList(Grant) = .empty;
    while (it.next()) |item| {
        if (item.len < 4 or item[1] != ':') return null;
        const rest = item[2..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        const kind: Kind = switch (item[0]) {
            'i' => .id,
            'g' => .group,
            'e' => .email,
            else => return null,
        };
        const perm = Perm.parse(rest[0..colon]) orelse return null;
        try g.append(arena, .{ .kind = kind, .value = rest[colon + 1 ..], .perm = perm });
    }
    return .{ .owner = owner, .grants = g.items };
}

// ---- XML ----

pub fn writeXml(w: *std.Io.Writer, a: Acl) std.Io.Writer.Error!void {
    try xml.openRoot(w, "AccessControlPolicy");
    try w.writeAll("<Owner>");
    try xml.elem(w, "ID", a.owner);
    try xml.elem(w, "DisplayName", a.owner);
    try w.writeAll("</Owner><AccessControlList>");
    for (a.grants) |g| {
        try w.writeAll("<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"");
        switch (g.kind) {
            .id => {
                try w.writeAll("CanonicalUser\">");
                try xml.elem(w, "ID", g.value);
                try xml.elem(w, "DisplayName", g.value);
            },
            .group => {
                try w.writeAll("Group\">");
                try xml.elem(w, "URI", g.value);
            },
            .email => {
                try w.writeAll("AmazonCustomerByEmail\">");
                try xml.elem(w, "EmailAddress", g.value);
            },
        }
        try w.writeAll("</Grantee>");
        try xml.elem(w, "Permission", @tagName(g.perm));
        try w.writeAll("</Grant>");
    }
    try w.writeAll("</AccessControlList>");
    try xml.close(w, "AccessControlPolicy");
}

pub fn parseXml(arena: std.mem.Allocator, body: []const u8, owner: []const u8) ParseError!Acl {
    var top: xml_read.Scanner = .{ .s = body };
    const acp = (top.next("AccessControlPolicy") catch return error.MalformedACLError) orelse return error.MalformedACLError;
    var ls: xml_read.Scanner = .{ .s = acp };
    const list = (ls.next("AccessControlList") catch return error.MalformedACLError) orelse return error.MalformedACLError;
    var sc: xml_read.Scanner = .{ .s = list };
    var g: std.ArrayList(Grant) = .empty;
    while (sc.next("Grant") catch return error.MalformedACLError) |grant| {
        const perm_s = try field(arena, grant, "Permission") orelse return error.MalformedACLError;
        const perm = Perm.parse(perm_s) orelse return error.MalformedACLError;
        if (try field(arena, grant, "ID")) |id| {
            try g.append(arena, .{ .kind = .id, .value = id, .perm = perm });
        } else if (try field(arena, grant, "URI")) |uri| {
            try g.append(arena, .{ .kind = .group, .value = uri, .perm = perm });
        } else if (try field(arena, grant, "EmailAddress")) |e| {
            try g.append(arena, .{ .kind = .email, .value = e, .perm = perm });
        } else return error.MalformedACLError;
    }
    return .{ .owner = owner, .grants = g.items };
}

fn field(arena: std.mem.Allocator, doc: []const u8, name: []const u8) ParseError!?[]const u8 {
    var sc: xml_read.Scanner = .{ .s = doc };
    const raw = (sc.next(name) catch return error.MalformedACLError) orelse return null;
    return xml_read.unescape(arena, std.mem.trim(u8, raw, " \t\r\n")) catch error.MalformedACLError;
}

/// Grantees must be known: canonical ids are the root id or IAM users and service
/// accounts; groups are the three predefined ones; email grants cannot be resolved.
pub fn validate(store: ?*iam.Store, a: Acl) ParseError!void {
    for (a.grants) |g| switch (g.kind) {
        .email => return error.UnresolvableGrantByEmailAddress,
        .group => if (!std.mem.eql(u8, g.value, all_users) and !std.mem.eql(u8, g.value, authenticated_users) and !std.mem.eql(u8, g.value, log_delivery))
            return error.InvalidArgument,
        .id => if (!knownId(store, g.value)) return error.InvalidArgument,
    };
}

fn knownId(store: ?*iam.Store, id: []const u8) bool {
    if (std.mem.eql(u8, id, owner_id)) return true;
    const st = store orelse return true;
    const v = st.view();
    defer v.release();
    return v.isRoot(id) or v.user(id) != null or v.serviceAccount(id) != null;
}

// ---- evaluation ----

pub fn allows(a: Acl, who: Caller, want: Perm) bool {
    if (!who.anonymous and std.mem.eql(u8, who.id, a.owner) and (want == .READ_ACP or want == .WRITE_ACP)) return true;
    for (a.grants) |g| {
        if (!g.perm.covers(want)) continue;
        const match = switch (g.kind) {
            .id => !who.anonymous and std.mem.eql(u8, g.value, who.id),
            .group => std.mem.eql(u8, g.value, all_users) or (!who.anonymous and std.mem.eql(u8, g.value, authenticated_users)),
            .email => false,
        };
        if (match) return true;
    }
    return false;
}

/// Canonical id of the caller: the root id for root (and anonymous mode), else its IAM name.
pub fn callerOf(cfg: sigv4.Config, auth: sigv4.Auth) Caller {
    if (cfg.iam == null) return .{ .id = owner_id, .anonymous = false };
    if (auth.anonymous) return .{ .id = "", .anonymous = true };
    if (tenancy.isRoot(cfg, auth)) return .{ .id = owner_id, .anonymous = false };
    return .{ .id = auth.principal, .anonymous = false };
}

pub fn bucketAcl(svc: *object.ObjectService, arena: std.mem.Allocator, bucket: []const u8) object.Error!Acl {
    const doc = try object.bucket_meta.get(svc, arena, bucket, .acl) orelse return Acl.private(owner_id);
    return try decode(arena, doc) orelse Acl.private(owner_id);
}

pub fn objectAcl(arena: std.mem.Allocator, info: object.ObjectInfo) error{OutOfMemory}!Acl {
    for (info.internal) |h| if (std.mem.eql(u8, h.name, object_header)) {
        if (try decode(arena, h.value)) |a| return a;
    };
    return Acl.private(owner_id);
}

/// Internal header recording the ACL of a new object written by `who`; null for the default.
pub fn newObjectHeader(c: *Ctx, who: Caller) DispatchError!?object.Header {
    const req = c.ext.acl;
    if (!req.present() and std.mem.eql(u8, who.id, owner_id)) return null;
    const mode = try @import("bucket_extras.zig").ownership(c);
    const bucket_owner = (try bucketAcl(c.svc, c.arena, c.route.bucket)).owner;
    var owner = if (who.anonymous) bucket_owner else who.id;
    var a: Acl = undefined;
    if (mode == .BucketOwnerEnforced) {
        owner = bucket_owner;
        a = try privateAcl(c.arena, owner);
    } else {
        if (mode == .BucketOwnerPreferred and req.canned != null and std.mem.eql(u8, req.canned.?, "bucket-owner-full-control")) owner = bucket_owner;
        a = (req.resolve(c.arena, owner, bucket_owner) catch |e| return mapParse(e)) orelse try privateAcl(c.arena, owner);
    }
    if (std.mem.eql(u8, owner, owner_id) and a.grants.len == 1 and a.grants[0].kind == .id and a.grants[0].perm == .FULL_CONTROL and std.mem.eql(u8, a.grants[0].value, owner_id)) return null;
    return .{ .name = object_header, .value = encode(c.arena, a) catch |e| return mapParse(e) };
}

fn mapParse(e: error{ OutOfMemory, InvalidArgument, MalformedACLError, UnresolvableGrantByEmailAddress }) DispatchError {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRequest,
    };
}

/// Validates ACL headers of an object write; false after answering with an error.
pub fn checkWriteHeaders(c: *Ctx) DispatchError!bool {
    const req = c.ext.acl;
    if (!req.present()) return true;
    const a = (req.resolve(c.arena, owner_id, owner_id) catch |e| return failParse(c, e)) orelse return true;
    validate(c.env.auth.iam, a) catch |e| return failParse(c, e);
    if (try ownershipEnforced(c) and !cannedAllowedWhenEnforced(req.canned)) {
        try handler.fail(c, .AccessControlListNotSupported);
        return false;
    }
    if (a.isPublic() and (try @import("bucket_extras.zig").publicAccess(c)).block_public_acls) {
        try handler.fail(c, .AccessDenied);
        return false;
    }
    return true;
}

fn cannedAllowedWhenEnforced(name: ?[]const u8) bool {
    const n = name orelse return false;
    return std.mem.eql(u8, n, "bucket-owner-full-control");
}

fn ownershipEnforced(c: *Ctx) DispatchError!bool {
    return (try @import("bucket_extras.zig").ownership(c)) == .BucketOwnerEnforced;
}

fn failParse(c: *Ctx, e: ParseError) DispatchError!bool {
    try handler.fail(c, switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MalformedACLError => .MalformedACLError,
        error.InvalidArgument => .InvalidArgument,
        error.UnresolvableGrantByEmailAddress => .UnresolvableGrantByEmailAddress,
    });
    return false;
}

/// Records the owner and any requested ACL of a bucket just created by `who`.
pub fn onBucketCreated(c: *Ctx, who: Caller) DispatchError!void {
    const req = c.ext.acl;
    if (!req.present() and std.mem.eql(u8, who.id, owner_id)) return;
    const a = (req.resolve(c.arena, who.id, who.id) catch return) orelse try privateAcl(c.arena, who.id);
    try object.bucket_meta.set(c.svc, c.route.bucket, .acl, encode(c.arena, a) catch return);
}

/// Validates ACL headers of CreateBucket before the bucket exists; false after answering.
pub fn checkCreateHeaders(c: *Ctx) DispatchError!bool {
    const req = c.ext.acl;
    if (!req.present()) return true;
    const a = (req.resolve(c.arena, owner_id, owner_id) catch |e| return failParse(c, e)) orelse return true;
    validate(c.env.auth.iam, a) catch |e| return failParse(c, e);
    return true;
}

/// Handles `?acl` on buckets and objects; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if ((try handler.param(c, "acl")) == null) return false;
    const r = c.route;
    const who = callerOf(c.env.auth, c.auth);
    var info: ?object.ObjectInfo = null;
    if (r.key.len == 0) {
        try c.svc.headBucket(r.bucket);
    } else {
        const i = try object.versioning.headVersion(c.svc, c.arena, r.bucket, r.key, try s3v.versionParam(c));
        if (i.delete_marker) {
            try handler.fail(c, .MethodNotAllowed);
            return true;
        }
        info = i;
    }
    const current = if (info) |i| try objectAcl(c.arena, i) else try bucketAcl(c.svc, c.arena, r.bucket);
    switch (c.method) {
        .GET => {
            var shown = current;
            if (shown.grants.len == 0 and !std.mem.eql(u8, shown.owner, "") and !try storedExplicit(c, info)) {
                shown = try privateAcl(c.arena, current.owner);
            }
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try writeXml(&a.writer, shown);
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => try putAcl(c, info, current, who),
        else => try handler.fail(c, .MethodNotAllowed),
    }
    return true;
}

/// Whether the resource has a stored ACL (an explicit empty grant list stays empty).
fn storedExplicit(c: *Ctx, info: ?object.ObjectInfo) DispatchError!bool {
    if (info) |i| {
        for (i.internal) |h| if (std.mem.eql(u8, h.name, object_header)) return true;
        return false;
    }
    return (try object.bucket_meta.get(c.svc, c.arena, c.route.bucket, .acl)) != null;
}

fn putAcl(c: *Ctx, info: ?object.ObjectInfo, current: Acl, who: Caller) DispatchError!void {
    _ = who;
    const bucket_owner = if (info == null) current.owner else (try bucketAcl(c.svc, c.arena, c.route.bucket)).owner;
    const req = c.ext.acl;
    var next: Acl = undefined;
    if (req.present()) {
        next = (req.resolve(c.arena, current.owner, bucket_owner) catch |e| {
            _ = try failParse(c, e);
            return;
        }).?;
    } else {
        const body = try s3v.readBodyMax(c, 64 * 1024) orelse return;
        next = parseXml(c.arena, body, current.owner) catch |e| {
            _ = try failParse(c, e);
            return;
        };
    }
    validate(c.env.auth.iam, next) catch |e| {
        _ = try failParse(c, e);
        return;
    };
    const extras = @import("bucket_extras.zig");
    if (try ownershipEnforced(c)) return handler.fail(c, .AccessControlListNotSupported);
    if (next.isPublic() and (try extras.publicAccess(c)).block_public_acls) return handler.fail(c, .AccessDenied);
    const enc = encode(c.arena, next) catch |e| return mapParse(e);
    if (info) |i| {
        _ = try object.objmeta.setInternalHeader(c.svc, c.route.bucket, c.route.key, i.version_id, object_header, enc);
    } else try object.bucket_meta.set(c.svc, c.route.bucket, .acl, enc);
    try handler.respondEmpty(c, .ok, &.{});
}

test "canned ACLs, grant headers, encoding, and evaluation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pr = try canned(a, "public-read", "alice", "alice");
    try std.testing.expect(pr.isPublic());
    try std.testing.expect(allows(pr, .{ .id = "", .anonymous = true }, .READ));
    try std.testing.expect(!allows(pr, .{ .id = "", .anonymous = true }, .WRITE));
    try std.testing.expect(allows(pr, .{ .id = "alice", .anonymous = false }, .WRITE));
    const ar = try canned(a, "authenticated-read", "alice", "alice");
    try std.testing.expect(!allows(ar, .{ .id = "", .anonymous = true }, .READ));
    try std.testing.expect(allows(ar, .{ .id = "bob", .anonymous = false }, .READ));
    try std.testing.expectError(error.InvalidArgument, canned(a, "public-everything", "a", "a"));

    const enc = try encode(a, pr);
    const back = (try decode(a, enc)).?;
    try std.testing.expectEqualStrings("alice", back.owner);
    try std.testing.expectEqual(@as(usize, 2), back.grants.len);
    try std.testing.expectEqualStrings(all_users, back.grants[0].value);

    var req: RequestAcl = .{};
    try req.capture(a, .{ .name = "x-amz-grant-read", .value = "id=\"bob\", uri=\"" ++ all_users ++ "\"" });
    try req.capture(a, .{ .name = "X-Amz-Grant-Write-Acp", .value = "id=carol" });
    const h = (try req.resolve(a, "alice", "alice")).?;
    try std.testing.expectEqual(@as(usize, 3), h.grants.len);
    try std.testing.expect(allows(h, .{ .id = "bob", .anonymous = false }, .READ));
    try std.testing.expect(allows(h, .{ .id = "carol", .anonymous = false }, .WRITE_ACP));
    try std.testing.expect(!allows(h, .{ .id = "carol", .anonymous = false }, .WRITE));

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeXml(&w, h);
    const parsed = try parseXml(a, w.buffered(), "alice");
    try std.testing.expectEqual(@as(usize, 3), parsed.grants.len);
    try std.testing.expectEqual(Kind.group, parsed.grants[1].kind);
    try std.testing.expectError(error.MalformedACLError, parseXml(a, "<Nope/>", "x"));
    try std.testing.expectError(error.UnresolvableGrantByEmailAddress, validate(null, .{ .owner = "x", .grants = &.{.{ .kind = .email, .value = "a@b", .perm = .READ }} }));
}
