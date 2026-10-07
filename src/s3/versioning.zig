//! S3 versioning, object lock, tagging, and conditional-request plumbing.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const sigv4 = @import("sigv4.zig");
const router = @import("router.zig");
const xml = @import("xml.zig");

const ov = object.versioning;
const Ctx = handler.Ctx;
const Header = std.http.Header;
const DispatchError = handler.DispatchError;
const max_xml_body = 64 * 1024;

/// Request headers this module cares about, copied out of the request head.
pub const Headers = struct {
    if_match: ?[]const u8 = null,
    if_none_match: ?[]const u8 = null,
    if_modified_since: ?[]const u8 = null,
    if_unmodified_since: ?[]const u8 = null,
    tagging: ?[]const u8 = null,
    lock_mode: ?[]const u8 = null,
    lock_until: ?[]const u8 = null,
    legal_hold: ?[]const u8 = null,
    content_md5: ?[]const u8 = null,
    bypass_governance: bool = false,
    bucket_lock: bool = false,
    acl: @import("acl.zig").RequestAcl = .{},
    object_ownership: ?[]const u8 = null,
    checksum: @import("checksums.zig").RequestChecksums = .{},
    /// x-amz-meta-* with the prefix stripped and names lowercased; repeats joined by ",".
    meta: std.ArrayList(object.Header) = .empty,
    system: object.SystemHeaders = .{},

    pub fn capture(self: *Headers, arena: std.mem.Allocator, h: Header) error{OutOfMemory}!void {
        try self.captureMeta(arena, h);
        try self.acl.capture(arena, h);
        try self.checksum.capture(arena, h);
        const fields = .{
            .{ "if-match", "if_match" },
            .{ "if-none-match", "if_none_match" },
            .{ "if-modified-since", "if_modified_since" },
            .{ "if-unmodified-since", "if_unmodified_since" },
            .{ "x-amz-tagging", "tagging" },
            .{ "x-amz-object-lock-mode", "lock_mode" },
            .{ "x-amz-object-lock-retain-until-date", "lock_until" },
            .{ "x-amz-object-lock-legal-hold", "legal_hold" },
            .{ "content-md5", "content_md5" },
            .{ "x-amz-object-ownership", "object_ownership" },
        };
        inline for (fields) |f| if (std.ascii.eqlIgnoreCase(h.name, f[0])) {
            @field(self, f[1]) = try arena.dupe(u8, h.value);
        };
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-bypass-governance-retention"))
            self.bypass_governance = std.ascii.eqlIgnoreCase(std.mem.trim(u8, h.value, " "), "true");
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-bucket-object-lock-enabled"))
            self.bucket_lock = std.ascii.eqlIgnoreCase(std.mem.trim(u8, h.value, " "), "true");
    }

    fn captureMeta(self: *Headers, arena: std.mem.Allocator, h: Header) error{OutOfMemory}!void {
        inline for (object.SystemHeaders.fields) |f| if (std.ascii.eqlIgnoreCase(h.name, f[1])) {
            @field(self.system, f[0]) = try arena.dupe(u8, h.value);
        };
        // aws-chunked describes the upload framing, not the stored object.
        if (std.ascii.eqlIgnoreCase(h.name, "content-encoding")) self.system.content_encoding = try withoutAwsChunked(arena, h.value);
        const prefix = "x-amz-meta-";
        if (h.name.len <= prefix.len or !std.ascii.startsWithIgnoreCase(h.name, prefix)) return;
        const name = try std.ascii.allocLowerString(arena, h.name[prefix.len..]);
        // The internal namespace is never accepted from clients.
        if (std.mem.startsWith(u8, name, object.internal_prefix)) return;
        for (self.meta.items) |*m| if (std.mem.eql(u8, m.name, name)) {
            m.value = try std.fmt.allocPrint(arena, "{s},{s}", .{ m.value, h.value });
            return;
        };
        try self.meta.append(arena, .{ .name = name, .value = try arena.dupe(u8, h.value) });
    }

    /// Unparseable dates are ignored, as HTTP requires.
    pub fn conditions(self: Headers) object.conditional.Conditions {
        return .{
            .if_match = self.if_match,
            .if_none_match = self.if_none_match,
            .if_modified_since_ns = if (self.if_modified_since) |d| core.time.parseHttpDate(d) catch null else null,
            .if_unmodified_since_ns = if (self.if_unmodified_since) |d| core.time.parseHttpDate(d) catch null else null,
        };
    }
};

pub fn withoutAwsChunked(arena: std.mem.Allocator, v: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, v, ',');
    while (it.next()) |tok| {
        const t = std.mem.trim(u8, tok, " ");
        if (t.len == 0 or std.ascii.eqlIgnoreCase(t, "aws-chunked")) continue;
        if (out.items.len > 0) try out.append(arena, ',');
        try out.appendSlice(arena, t);
    }
    return out.items;
}

fn has(c: *Ctx, name: []const u8) error{OutOfMemory}!bool {
    return (try handler.param(c, name)) != null;
}

/// Handles versioning/lock/tagging subresources; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    const r = c.route;
    if (r.key.len == 0) {
        if (c.method == .PUT and c.ext.bucket_lock and !try has(c, "object-lock") and !try has(c, "tagging") and !try has(c, "versioning")) {
            try ov.createLockedBucket(c.svc, r.bucket);
            if (c.tenant.len > 0) object.tenancy.setTenant(c.svc, r.bucket, c.tenant) catch |e| {
                c.svc.deleteBucket(r.bucket) catch {};
                return e;
            };
            try handler.respondEmpty(c, .ok, &.{.{ .name = "location", .value = c.target }});
            return true;
        }
        if (try has(c, "versioning")) {
            try switch (c.method) {
                .GET => getBucketVersioning(c),
                .PUT => putBucketVersioning(c),
                else => handler.fail(c, .MethodNotAllowed),
            };
        } else if (try has(c, "object-lock")) {
            try switch (c.method) {
                .GET => getLockConfig(c),
                .PUT => putLockConfig(c),
                else => handler.fail(c, .MethodNotAllowed),
            };
        } else if (try has(c, "tagging")) {
            try switch (c.method) {
                .GET => writeTagging(c, try ov.getBucketTags(c.svc, c.arena, r.bucket), null),
                .PUT => {
                    const tags = try readTagging(c) orelse return true;
                    try ov.setBucketTags(c.svc, r.bucket, tags);
                    try handler.respondEmpty(c, .no_content, &.{});
                },
                .DELETE => {
                    try ov.setBucketTags(c.svc, r.bucket, null);
                    try handler.respondEmpty(c, .no_content, &.{});
                },
                else => handler.fail(c, .MethodNotAllowed),
            };
        } else if (try has(c, "versions")) {
            try switch (c.method) {
                .GET => listVersions(c),
                else => handler.fail(c, .MethodNotAllowed),
            };
        } else return false;
        return true;
    }
    if (try has(c, "tagging")) {
        try objectTagging(c);
    } else if (try has(c, "retention")) {
        try switch (c.method) {
            .GET => getRetention(c),
            .PUT => putRetention(c),
            else => handler.fail(c, .MethodNotAllowed),
        };
    } else if (try has(c, "legal-hold")) {
        try switch (c.method) {
            .GET => getLegalHold(c),
            .PUT => putLegalHold(c),
            else => handler.fail(c, .MethodNotAllowed),
        };
    } else if (c.method == .DELETE) {
        try deleteObject(c);
    } else return false;
    return true;
}

/// The `versionId` query parameter; null when absent.
pub fn versionParam(c: *Ctx) DispatchError!?core.VersionId {
    const s = try handler.param(c, "versionId") orelse return null;
    return try ov.parseVersionId(s);
}

fn versionHeader(c: *Ctx, v: core.VersionId) error{OutOfMemory}!Header {
    const buf = try c.arena.create([32]u8);
    return .{ .name = "x-amz-version-id", .value = ov.formatVersionId(v, buf) };
}

// ---- object PUT/GET/DELETE extensions ----

/// Extra PutInput fields from x-amz-tagging, object-lock headers, and preconditions.
/// Returns null after answering the request with an error.
pub fn putExtras(c: *Ctx, in: *object.PutInput) DispatchError!bool {
    const h = c.ext;
    in.conditions = h.conditions();
    in.metadata = h.meta.items;
    in.system = h.system;
    if (h.tagging) |t| {
        const tags = parseTagQuery(c.arena, t) catch {
            try handler.fail(c, .InvalidTag);
            return false;
        };
        in.tags = try ov.encodeObjectTags(c.arena, tags);
    }
    if (h.lock_mode != null or h.lock_until != null) {
        const mode = parseMode(h.lock_mode orelse "") orelse {
            try handler.fail(c, .InvalidArgument);
            return false;
        };
        const until = core.time.parseIso8601(h.lock_until orelse "") catch {
            try handler.fail(c, .InvalidArgument);
            return false;
        };
        in.retention = .{ .mode = mode, .until_ns = until };
    }
    if (h.legal_hold) |l| in.legal_hold = std.ascii.eqlIgnoreCase(l, "ON");
    if (h.content_md5) |b64| {
        var md5: [16]u8 = undefined;
        const dec = std.base64.standard.Decoder;
        const ok = if (dec.calcSizeForSlice(b64)) |n| n == 16 and if (dec.decode(&md5, b64)) |_| true else |_| false else |_| false;
        if (!ok) {
            try handler.fail(c, .InvalidDigest);
            return false;
        }
        in.content_md5 = md5;
    }
    const acl = @import("acl.zig");
    if (!try acl.checkWriteHeaders(c)) return false;
    if (try acl.newObjectHeader(c, acl.callerOf(c.env.auth, c.auth))) |hdr| {
        var list: std.ArrayList(object.Header) = .empty;
        try list.appendSlice(c.arena, in.internal);
        try list.append(c.arena, hdr);
        in.internal = list.items;
    }
    return true;
}

pub fn putResponseHeaders(c: *Ctx, info: object.ObjectInfo, out: *std.ArrayList(Header)) error{OutOfMemory}!void {
    if (!info.version_id.eql(ov.null_version_id)) try out.append(c.arena, try versionHeader(c, info.version_id));
}

/// Headers describing a version on GET/HEAD.
pub fn objectHeaders(c: *Ctx, info: object.ObjectInfo, asked_version: bool, out: *std.ArrayList(Header)) error{OutOfMemory}!void {
    if (info.tier.len > 0) try out.append(c.arena, .{ .name = "x-amz-storage-class", .value = info.tier });
    if (try object.transition.restoreHeader(c.svc, c.arena, info)) |v| try out.append(c.arena, .{ .name = "x-amz-restore", .value = v });
    if (asked_version or !info.version_id.eql(ov.null_version_id)) try out.append(c.arena, try versionHeader(c, info.version_id));
    if (info.retention_mode != .none) {
        const tb = try c.arena.create([24]u8);
        try out.appendSlice(c.arena, &.{
            .{ .name = "x-amz-object-lock-mode", .value = modeName(info.retention_mode) },
            .{ .name = "x-amz-object-lock-retain-until-date", .value = core.time.iso8601(info.retain_until_ns, tb) },
        });
    }
    if (info.legal_hold) try out.append(c.arena, .{ .name = "x-amz-object-lock-legal-hold", .value = "ON" });
    if (object.replica.statusOf(info.internal)) |st| try out.append(c.arena, .{ .name = "x-amz-replication-status", .value = st.text() });
    for (info.metadata) |m| try out.append(c.arena, .{ .name = try std.fmt.allocPrint(c.arena, "x-amz-meta-{s}", .{m.name}), .value = m.value });
    inline for (object.SystemHeaders.fields) |f| {
        const v = @field(info.system, f[0]);
        if (v.len > 0) try out.append(c.arena, .{ .name = f[1], .value = v });
    }
    if (info.tags.len > 0) {
        const tags = object.decodeTags(c.arena, info.tags) catch return;
        try out.append(c.arena, .{ .name = "x-amz-tagging-count", .value = try std.fmt.allocPrint(c.arena, "{d}", .{tags.len}) });
    }
}

/// GET `response-*` query parameters replace the matching response headers.
pub fn applyResponseOverrides(c: *Ctx, out: *std.ArrayList(Header)) error{OutOfMemory}!void {
    const names = [_][]const u8{ "content-type", "content-language", "expires", "cache-control", "content-disposition", "content-encoding" };
    inline for (names) |n| if (try handler.param(c, "response-" ++ n)) |v| {
        var i: usize = 0;
        while (i < out.items.len) {
            if (std.ascii.eqlIgnoreCase(out.items[i].name, n)) _ = out.orderedRemove(i) else i += 1;
        }
        try out.append(c.arena, .{ .name = n, .value = v });
    };
}

fn versionClass(c: *Ctx, e: ov.VersionEntry) []const u8 {
    const info = ov.headVersion(c.svc, c.arena, c.route.bucket, e.key, e.version) catch return "STANDARD";
    return if (info.tier.len > 0) info.tier else "STANDARD";
}

/// Looks up the version to serve; answers delete markers itself (returns null).
pub fn lookupForRead(c: *Ctx) DispatchError!?object.ObjectInfo {
    const v = try versionParam(c);
    const info = ov.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, v) catch |e| {
        if (e != error.NoSuchKey) return e;
        try handler.failWith(c, .NoSuchKey, &.{.{ .name = "x-amz-delete-marker", .value = "false" }});
        return null;
    };
    if (!info.delete_marker) return info;
    const hdrs = [_]Header{ .{ .name = "x-amz-delete-marker", .value = "true" }, try versionHeader(c, info.version_id) };
    try handler.failWith(c, if (v != null) .MethodNotAllowed else .NoSuchKey, &hdrs);
    return null;
}

/// Applies read preconditions; returns false after answering 304 or 412.
pub fn checkRead(c: *Ctx, info: object.ObjectInfo, etag: []const u8, extra: []const Header) DispatchError!bool {
    switch (object.conditional.evalRead(c.ext.conditions(), etag, info.created_ns)) {
        .proceed => return true,
        .precondition_failed => try handler.fail(c, .PreconditionFailed),
        .not_modified => try handler.respondEmpty(c, .not_modified, extra),
    }
    return false;
}

fn deleteObject(c: *Ctx) DispatchError!void {
    const res = try ov.deleteObject(c.svc, c.route.bucket, c.route.key, .{
        .version = try versionParam(c),
        .bypass_governance = c.ext.bypass_governance,
    });
    var hdrs: std.ArrayList(Header) = .empty;
    if (res.version) |v| try hdrs.append(c.arena, try versionHeader(c, v));
    if (res.delete_marker) try hdrs.append(c.arena, .{ .name = "x-amz-delete-marker", .value = "true" });
    try handler.respondEmpty(c, .no_content, hdrs.items);
}

// ---- bucket versioning and lock configuration ----

fn getBucketVersioning(c: *Ctx) DispatchError!void {
    const cfg = try ov.getConfig(c.svc, c.arena, c.route.bucket);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "VersioningConfiguration");
    switch (cfg.versioning) {
        .unset => {},
        .enabled => try xml.elem(w, "Status", "Enabled"),
        .suspended => try xml.elem(w, "Status", "Suspended"),
    }
    try xml.close(w, "VersioningConfiguration");
    try handler.respondXml(c, .ok, a.written());
}

fn putBucketVersioning(c: *Ctx) DispatchError!void {
    const body = try readBody(c) orelse return;
    const status = elemText(body, "Status") orelse "";
    const state: ov.Versioning = if (std.mem.eql(u8, status, "Enabled"))
        .enabled
    else if (std.mem.eql(u8, status, "Suspended"))
        .suspended
    else
        return handler.fail(c, .MalformedXML);
    try ov.setVersioning(c.svc, c.route.bucket, state);
    try handler.respondEmpty(c, .ok, &.{});
}

fn getLockConfig(c: *Ctx) DispatchError!void {
    const cfg = try ov.getConfig(c.svc, c.arena, c.route.bucket);
    if (!cfg.lock_enabled) return handler.fail(c, .ObjectLockConfigurationNotFoundError);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "ObjectLockConfiguration");
    try xml.elem(w, "ObjectLockEnabled", "Enabled");
    if (cfg.default_mode != .none) {
        try w.writeAll("<Rule><DefaultRetention>");
        try xml.elem(w, "Mode", modeName(cfg.default_mode));
        if (cfg.default_days > 0) try xml.elemInt(w, "Days", cfg.default_days);
        if (cfg.default_years > 0) try xml.elemInt(w, "Years", cfg.default_years);
        try w.writeAll("</DefaultRetention></Rule>");
    }
    try xml.close(w, "ObjectLockConfiguration");
    try handler.respondXml(c, .ok, a.written());
}

fn putLockConfig(c: *Ctx) DispatchError!void {
    const body = try readBody(c) orelse return;
    const enabled = elemText(body, "ObjectLockEnabled") orelse "";
    if (!std.mem.eql(u8, enabled, "Enabled")) return handler.fail(c, .MalformedXML);
    var d: ov.LockDefault = .{};
    if (elemText(body, "DefaultRetention")) |dr| {
        d.mode = parseMode(elemText(dr, "Mode") orelse "") orelse return handler.fail(c, .MalformedXML);
        if (elemText(dr, "Days")) |s| d.days = std.fmt.parseInt(u32, s, 10) catch return handler.fail(c, .MalformedXML);
        if (elemText(dr, "Years")) |s| d.years = std.fmt.parseInt(u32, s, 10) catch return handler.fail(c, .MalformedXML);
    }
    try ov.setLockConfig(c.svc, c.route.bucket, d);
    try handler.respondEmpty(c, .ok, &.{});
}

// ---- object retention, legal hold, tagging ----

fn getRetention(c: *Ctx) DispatchError!void {
    const info = try ov.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, try versionParam(c));
    if (info.delete_marker) return handler.fail(c, .MethodNotAllowed);
    if (info.retention_mode == .none) return handler.fail(c, .NoSuchObjectLockConfiguration);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var tb: [24]u8 = undefined;
    try xml.openRoot(w, "Retention");
    try xml.elem(w, "Mode", modeName(info.retention_mode));
    try xml.elem(w, "RetainUntilDate", core.time.iso8601(info.retain_until_ns, &tb));
    try xml.close(w, "Retention");
    try handler.respondXml(c, .ok, a.written());
}

fn putRetention(c: *Ctx) DispatchError!void {
    const body = try readBody(c) orelse return;
    var ret: object.lock.Retention = .{};
    if (elemText(body, "Mode")) |m| {
        ret.mode = parseMode(m) orelse return handler.fail(c, .MalformedXML);
        ret.until_ns = core.time.parseIso8601(elemText(body, "RetainUntilDate") orelse "") catch return handler.fail(c, .MalformedXML);
    }
    const v = try ov.setRetention(c.svc, c.route.bucket, c.route.key, try versionParam(c), .{
        .retention = ret,
        .bypass_governance = c.ext.bypass_governance,
    });
    try handler.respondEmpty(c, .ok, &.{try versionHeader(c, v)});
}

fn getLegalHold(c: *Ctx) DispatchError!void {
    const info = try ov.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, try versionParam(c));
    if (info.delete_marker) return handler.fail(c, .MethodNotAllowed);
    const cfg = try ov.getConfig(c.svc, c.arena, c.route.bucket);
    if (!cfg.lock_enabled) return handler.fail(c, .InvalidRequest);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    try xml.openRoot(&a.writer, "LegalHold");
    try xml.elem(&a.writer, "Status", if (info.legal_hold) "ON" else "OFF");
    try xml.close(&a.writer, "LegalHold");
    try handler.respondXml(c, .ok, a.written());
}

fn putLegalHold(c: *Ctx) DispatchError!void {
    const body = try readBody(c) orelse return;
    const s = elemText(body, "Status") orelse return handler.fail(c, .MalformedXML);
    const on = if (std.mem.eql(u8, s, "ON")) true else if (std.mem.eql(u8, s, "OFF")) false else return handler.fail(c, .MalformedXML);
    const v = try ov.setLegalHold(c.svc, c.route.bucket, c.route.key, try versionParam(c), on);
    try handler.respondEmpty(c, .ok, &.{try versionHeader(c, v)});
}

fn objectTagging(c: *Ctx) DispatchError!void {
    const v = try versionParam(c);
    switch (c.method) {
        .GET => {
            const info = try ov.headVersion(c.svc, c.arena, c.route.bucket, c.route.key, v);
            if (info.delete_marker) return handler.fail(c, .MethodNotAllowed);
            try writeTagging(c, try object.decodeTags(c.arena, info.tags), info.version_id);
        },
        .PUT => {
            const tags = try readTagging(c) orelse return;
            const nv = try ov.setObjectTags(c.svc, c.route.bucket, c.route.key, v, tags);
            try handler.respondEmpty(c, .ok, &.{try versionHeader(c, nv)});
        },
        .DELETE => {
            const nv = try ov.setObjectTags(c.svc, c.route.bucket, c.route.key, v, null);
            try handler.respondEmpty(c, .no_content, &.{try versionHeader(c, nv)});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
}

fn writeTagging(c: *Ctx, tags: []const object.Tag, version: ?core.VersionId) DispatchError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    try xml.openRoot(w, "Tagging");
    try w.writeAll("<TagSet>");
    for (tags) |t| {
        try w.writeAll("<Tag>");
        try xml.elem(w, "Key", t.key);
        try xml.elem(w, "Value", t.value);
        try w.writeAll("</Tag>");
    }
    try w.writeAll("</TagSet>");
    try xml.close(w, "Tagging");
    if (version) |v| {
        try c.req.respond(a.written(), .{ .status = .ok, .extra_headers = &.{
            .{ .name = "content-type", .value = "application/xml" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
            try versionHeader(c, v),
        } });
    } else try handler.respondXml(c, .ok, a.written());
}

fn readTagging(c: *Ctx) DispatchError!?[]object.Tag {
    const body = try readBody(c) orelse return null;
    const tags = parseTagSet(c.arena, body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => {
            try handler.fail(c, .MalformedXML);
            return null;
        },
    };
    return tags;
}

// ---- ListObjectVersions ----

fn listVersions(c: *Ctx) DispatchError!void {
    var p: ov.VersionListParams = .{
        .prefix = (try handler.param(c, "prefix")) orelse "",
        .delimiter = (try handler.param(c, "delimiter")) orelse "",
        .key_marker = (try handler.param(c, "key-marker")) orelse "",
    };
    if (try handler.param(c, "max-keys")) |mk| {
        const n = std.fmt.parseInt(usize, mk, 10) catch return handler.fail(c, .InvalidArgument);
        p.max_keys = @min(n, 1000);
    }
    const vm = try handler.param(c, "version-id-marker");
    if (vm) |s| if (s.len > 0) {
        if (p.key_marker.len == 0) return handler.fail(c, .InvalidArgument);
        p.version_id_marker = try ov.parseVersionId(s);
    };
    const res = try ov.listVersions(c.svc, c.arena, c.route.bucket, p);

    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    var vb: [32]u8 = undefined;
    try xml.openRoot(w, "ListVersionsResult");
    try xml.elem(w, "Name", c.route.bucket);
    try xml.elem(w, "Prefix", p.prefix);
    try xml.elem(w, "KeyMarker", p.key_marker);
    try xml.elem(w, "VersionIdMarker", vm orelse "");
    if (res.next_key_marker) |k| try xml.elem(w, "NextKeyMarker", k);
    if (res.next_version_id_marker) |v| try xml.elem(w, "NextVersionIdMarker", ov.formatVersionId(v, &vb));
    try xml.elemInt(w, "MaxKeys", p.max_keys);
    if (p.delimiter.len > 0) try xml.elem(w, "Delimiter", p.delimiter);
    try xml.elemBool(w, "IsTruncated", res.is_truncated);
    for (res.entries) |e| {
        var tb: [24]u8 = undefined;
        const tag = if (e.delete_marker) "DeleteMarker" else "Version";
        try xml.open(w, tag);
        try xml.elem(w, "Key", e.key);
        try xml.elem(w, "VersionId", ov.formatVersionId(e.version, &vb));
        try xml.elemBool(w, "IsLatest", e.is_latest);
        try xml.elem(w, "LastModified", core.time.iso8601(e.mtime_ns, &tb));
        if (!e.delete_marker) {
            var eb: [core.ETag.quoted_max]u8 = undefined;
            try xml.elem(w, "ETag", e.etag.quoted(&eb));
            try xml.elemInt(w, "Size", e.size);
            try xml.elem(w, "StorageClass", if (e.tiered) versionClass(c, e) else "STANDARD");
        }
        try w.writeAll("<Owner><ID>zkfsm</ID><DisplayName>zkfsm</DisplayName></Owner>");
        try xml.close(w, tag);
    }
    for (res.common_prefixes) |cp| {
        try w.writeAll("<CommonPrefixes>");
        try xml.elem(w, "Prefix", cp);
        try w.writeAll("</CommonPrefixes>");
    }
    try xml.close(w, "ListVersionsResult");
    try handler.respondXml(c, .ok, a.written());
}

// ---- small parsers ----

fn readBody(c: *Ctx) DispatchError!?[]const u8 {
    return readBodyMax(c, max_xml_body);
}

/// Reads a small request body; null after answering with an error.
pub fn readBodyMax(c: *Ctx, max: usize) DispatchError!?[]const u8 {
    var buf: [4096]u8 = undefined;
    var check_buf: [4096]u8 = undefined;
    var br: sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&buf), &check_buf);
    br.limitTo(c.req.head.content_length);
    return br.body().allocRemaining(c.arena, .limited(max)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed => {
            try handler.fail(c, br.failure orelse return error.ReadFailed);
            return null;
        },
        error.StreamTooLong => {
            try handler.fail(c, .MalformedXML);
            return null;
        },
    };
}

fn modeName(m: object.lock.Mode) []const u8 {
    return switch (m) {
        .governance => "GOVERNANCE",
        .compliance => "COMPLIANCE",
        .none => "",
    };
}

fn parseMode(s: []const u8) ?object.lock.Mode {
    if (std.mem.eql(u8, s, "GOVERNANCE")) return .governance;
    if (std.mem.eql(u8, s, "COMPLIANCE")) return .compliance;
    return null;
}

/// Raw inner text of the first `<name>` element (attributes allowed), not unescaped.
pub fn elemText(doc: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, doc, pos, "<")) |lt| {
        pos = lt + 1;
        const rest = doc[pos..];
        if (!std.mem.startsWith(u8, rest, name) or rest.len == name.len) continue;
        const after = rest[name.len];
        if (after != '>' and after != ' ' and after != '/') continue;
        const gt = std.mem.indexOfScalarPos(u8, doc, pos, '>') orelse return null;
        if (doc[gt - 1] == '/') return "";
        var close_buf: [64]u8 = undefined;
        const close_tag = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return null;
        const end = std.mem.indexOfPos(u8, doc, gt + 1, close_tag) orelse return null;
        return std.mem.trim(u8, doc[gt + 1 .. end], " \t\r\n");
    }
    return null;
}

fn unescape(arena: std.mem.Allocator, s: []const u8) error{ OutOfMemory, Malformed }![]const u8 {
    if (std.mem.indexOfScalar(u8, s, '&') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] != '&') {
            try out.append(arena, s[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, s, i, ';') orelse return error.Malformed;
        const ent = s[i + 1 .. semi];
        const ch: u8 = if (std.mem.eql(u8, ent, "amp")) '&' else if (std.mem.eql(u8, ent, "lt")) '<' else if (std.mem.eql(u8, ent, "gt")) '>' else if (std.mem.eql(u8, ent, "quot")) '"' else if (std.mem.eql(u8, ent, "apos")) '\'' else return error.Malformed;
        try out.append(arena, ch);
        i = semi + 1;
    }
    return out.items;
}

pub fn parseTagSet(arena: std.mem.Allocator, doc: []const u8) error{ OutOfMemory, Malformed }![]object.Tag {
    const set = elemText(doc, "TagSet") orelse return error.Malformed;
    var tags: std.ArrayList(object.Tag) = .empty;
    var rest = set;
    while (elemText(rest, "Tag")) |t| {
        const key = elemText(t, "Key") orelse return error.Malformed;
        const value = elemText(t, "Value") orelse "";
        try tags.append(arena, .{ .key = try unescape(arena, key), .value = try unescape(arena, value) });
        const end = std.mem.indexOf(u8, rest, "</Tag>") orelse break;
        rest = rest[end + "</Tag>".len ..];
    }
    return tags.items;
}

/// Parses `k1=v1&k2=v2` (URL-encoded) as sent in x-amz-tagging.
pub fn parseTagQuery(arena: std.mem.Allocator, s: []const u8) error{ OutOfMemory, InvalidUri }![]object.Tag {
    var tags: std.ArrayList(object.Tag) = .empty;
    var it = std.mem.splitScalar(u8, s, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        try tags.append(arena, .{
            .key = try router.percentDecode(arena, pair[0 .. eq orelse pair.len], true),
            .value = if (eq) |i| try router.percentDecode(arena, pair[i + 1 ..], true) else "",
        });
    }
    return tags.items;
}

test "xml element extraction" {
    const doc = "<?xml version=\"1.0\"?><VersioningConfiguration xmlns=\"x\"><Status>Enabled</Status></VersioningConfiguration>";
    try std.testing.expectEqualStrings("Enabled", elemText(doc, "Status").?);
    try std.testing.expect(elemText(doc, "Stat") == null);
    try std.testing.expect(elemText("<Status>open", "Status") == null);
    try std.testing.expectEqualStrings("", elemText("<A><Status/></A>", "Status").?);
}

test "tag set and tag query parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = "<Tagging><TagSet><Tag><Key>a&amp;b</Key><Value>1</Value></Tag><Tag><Key>c</Key><Value></Value></Tag></TagSet></Tagging>";
    const t = try parseTagSet(a, doc);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expectEqualStrings("a&b", t[0].key);
    try std.testing.expectEqualStrings("", t[1].value);
    try std.testing.expectError(error.Malformed, parseTagSet(a, "<Tagging></Tagging>"));
    try std.testing.expectEqual(@as(usize, 0), (try parseTagSet(a, "<Tagging><TagSet></TagSet></Tagging>")).len);
    const q = try parseTagQuery(a, "env=prod&team=a%20b&flag");
    try std.testing.expectEqual(@as(usize, 3), q.len);
    try std.testing.expectEqualStrings("a b", q[1].value);
    try std.testing.expectEqualStrings("", q[2].value);
}
