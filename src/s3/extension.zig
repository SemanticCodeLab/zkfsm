//! Extension point for builds that add S3 operations. Extensions run after
//! authentication and authorization, before built-in dispatch.
const handler = @import("handler.zig");

pub const Extension = struct {
    name: []const u8,
    ctx: *anyopaque,
    /// Return true when the request was fully handled (response written).
    route: *const fn (ctx: *anyopaque, c: *handler.Ctx) handler.ConnError!bool,
    /// Run after authentication but before S3 authorization; the extension authorizes itself.
    before_authz: bool = false,
};

/// Sees every S3 request: `begin` once the request is parsed, `end` after the
/// response (or connection error) with the final status. Must not respond.
pub const Observer = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque, c: *handler.Ctx) void,
    end: *const fn (ctx: *anyopaque, c: *handler.Ctx, status: u16) void,
};
