//! Static website hosting: Get/Put/DeleteBucketWebsite, and anonymous GET/HEAD on
//! the website endpoint (`{bucket}.{website-domain}`) with index and error documents,
//! redirects, and routing rules. Objects must be publicly readable (policy or ACL).
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const cfgmod = @import("website_config.zig");
const s3v = @import("versioning.zig");
const xml = @import("xml.zig");
const errors = @import("errors.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;

fn load(c: *Ctx) DispatchError!?cfgmod.Config {
    const doc = try object.bucket_meta.get(c.svc, c.arena, c.route.bucket, .website) orelse return null;
    return cfgmod.parse(c.arena, doc) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

/// Handles `?website` on a bucket (API endpoint); false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len != 0 or (try handler.param(c, "website")) == null) return false;
    switch (c.method) {
        .GET => {
            const doc = try object.bucket_meta.get(c.svc, c.arena, c.route.bucket, .website) orelse {
                try handler.fail(c, .NoSuchWebsiteConfiguration);
                return true;
            };
            const cfg = cfgmod.parse(c.arena, doc) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    try handler.fail(c, .NoSuchWebsiteConfiguration);
                    return true;
                },
            };
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try cfgmod.write(&a.writer, cfg);
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, object.bucket_meta.max_doc_bytes) orelse return true;
            _ = cfgmod.parse(c.arena, body) catch |e| {
                try handler.fail(c, switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.MalformedXML => .MalformedXML,
                    error.InvalidRequest => .InvalidArgument,
                });
                return true;
            };
            try object.bucket_meta.set(c.svc, c.route.bucket, .website, body);
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try object.bucket_meta.set(c.svc, c.route.bucket, .website, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
    return true;
}

/// Serves a request that arrived on the website endpoint. Always answers.
pub fn serve(c: *Ctx) handler.ConnError!void {
    serveInner(c) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        error.NoSuchBucket => return page(c, .not_found, "NoSuchBucket", "The specified bucket does not exist"),
        else => return page(c, .internal_server_error, "InternalError", "We encountered an internal error. Please try again."),
    };
}

fn serveInner(c: *Ctx) DispatchError!void {
    if (c.method != .GET and c.method != .HEAD) return page(c, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
    try c.svc.headBucket(c.route.bucket);
    const cfg = try load(c) orelse return page(c, .not_found, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration");
    const host = c.host orelse "";
    const key = c.route.key;
    switch (try mapCfg(cfgmod.resolve(c.arena, cfg, host, key))) {
        .redirect => |r| return redirect(c, r),
        .serve => |k| {
            if (try tryServe(c, k, .ok)) return;
            const status: u16 = if (try readable(c, k)) 404 else 403;
            // A directory without the trailing slash: redirect when its index exists.
            if (status == 404 and key.len > 0 and key[key.len - 1] != '/') if (indexOf(cfg)) |suffix| {
                const dir_index = try std.fmt.allocPrint(c.arena, "{s}/{s}", .{ key, suffix });
                if (try exists(c, dir_index)) return redirect(c, try mapCfg(cfgmod.directoryRedirect(c.arena, key)));
            };
            if (try mapCfg(cfgmod.onError(c.arena, cfg, host, key, status))) |r| return redirect(c, r);
            if (cfgmod.errorDocument(cfg)) |ek| if (try tryServe(c, ek, if (status == 404) .not_found else .forbidden)) return;
            if (status == 404) return page(c, .not_found, "NoSuchKey", "The specified key does not exist.");
            return page(c, .forbidden, "AccessDenied", "Access Denied");
        },
    }
}

fn mapCfg(v: anytype) DispatchError!@typeInfo(@TypeOf(v)).error_union.payload {
    return v catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidRequest,
    };
}

fn indexOf(cfg: cfgmod.Config) ?[]const u8 {
    return switch (cfg) {
        .site => |s| s.index_suffix,
        .redirect_all => null,
    };
}

/// Anonymous read allowed (policy or ACL) for `key`.
fn readable(c: *Ctx, key: []const u8) DispatchError!bool {
    return handler.anonymousMayRead(c, key);
}

fn exists(c: *Ctx, key: []const u8) DispatchError!bool {
    const info = object.versioning.headVersion(c.svc, c.arena, c.route.bucket, key, null) catch |e| return switch (e) {
        error.NoSuchKey, error.NoSuchVersion, error.KeyTooLong, error.InvalidKey => false,
        else => e,
    };
    return !info.delete_marker;
}

/// Streams `key` with `status` when it exists and is publicly readable.
fn tryServe(c: *Ctx, key: []const u8, status: std.http.Status) DispatchError!bool {
    if (!try exists(c, key)) return false;
    if (!try readable(c, key)) return false;
    c.route.key = key;
    c.route.query = "";
    c.status_override = if (status == .ok) null else status;
    try handler.serveObject(c);
    return true;
}

fn redirect(c: *Ctx, r: cfgmod.Redirect) DispatchError!void {
    const status: std.http.Status = @enumFromInt(r.code);
    try handler.respondEmpty(c, status, &.{.{ .name = "location", .value = r.location }});
}

/// Website endpoints answer errors with HTML, not XML.
fn page(c: *Ctx, status: std.http.Status, code: []const u8, msg: []const u8) handler.ConnError!void {
    var a: std.Io.Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    w.writeAll("<html><head><title>") catch return error.OutOfMemory;
    w.print("{d} {s}</title></head><body><h1>{d} {s}</h1><ul><li>Code: ", .{ @intFromEnum(status), status.phrase() orelse "", @intFromEnum(status), status.phrase() orelse "" }) catch return error.OutOfMemory;
    xml.escape(w, code) catch return error.OutOfMemory;
    w.writeAll("</li><li>Message: ") catch return error.OutOfMemory;
    xml.escape(w, msg) catch return error.OutOfMemory;
    w.writeAll("</li></ul></body></html>") catch return error.OutOfMemory;
    try handler.respondBody(c, status, if (c.method == .HEAD) "" else a.written(), "text/html; charset=utf-8", &.{});
}
