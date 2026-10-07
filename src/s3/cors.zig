//! Bucket CORS: Get/Put/DeleteBucketCors, unauthenticated OPTIONS preflight, and the
//! access-control headers added to every response of a request carrying `Origin`.
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const cfgmod = @import("cors_config.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;

fn load(c: *Ctx) DispatchError!?cfgmod.Config {
    const doc = try object.bucket_meta.get(c.svc, c.arena, c.route.bucket, .cors) orelse return null;
    // Stored documents were validated on PUT; one that no longer parses allows nothing.
    return cfgmod.parse(c.arena, doc) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

/// Answers OPTIONS requests (before authentication); false when the method is not OPTIONS.
pub fn preflight(c: *Ctx) handler.ConnError!bool {
    if (c.method != .OPTIONS) return false;
    if (c.route.bucket.len == 0) {
        try handler.fail(c, .BadRequest);
        return true;
    }
    const cfg = load(c) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| return ce,
        else => null,
    };
    const res = cfgmod.preflight(cfg, c.origin, c.acr_method, c.acr_headers, c.arena) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try handler.fail(c, .BadRequest);
            return true;
        },
    };
    switch (res) {
        .ok => |hs| try handler.respondEmpty(c, .ok, hs),
        .fail => |f| try handler.fail(c, if (f.status == 403) .AccessForbidden else .BadRequest),
    }
    return true;
}

/// Computes the CORS response headers for a request with `Origin` to an existing bucket.
pub fn prepare(c: *Ctx) handler.ConnError!void {
    const origin = c.origin orelse return;
    if (c.route.bucket.len == 0) return;
    const cfg = load(c) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return,
    } orelse return;
    c.extra = cfgmod.simpleHeaders(c.arena, cfg, origin, @tagName(c.method), c.acr_method) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => &.{},
    };
}

/// Handles `?cors` on a bucket; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len != 0 or (try handler.param(c, "cors")) == null) return false;
    switch (c.method) {
        .GET => {
            const cfg = try load(c) orelse {
                try c.svc.headBucket(c.route.bucket);
                try handler.fail(c, .NoSuchCORSConfiguration);
                return true;
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
                    error.InvalidRequest => .InvalidRequest,
                });
                return true;
            };
            try object.bucket_meta.set(c.svc, c.route.bucket, .cors, body);
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try object.bucket_meta.set(c.svc, c.route.bucket, .cors, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
    return true;
}
