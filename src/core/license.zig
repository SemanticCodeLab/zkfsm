//! Provider-neutral entitlement contract. The open core enforces nothing:
//! with no provider installed, every entitlement check reports Unlicensed.
const std = @import("std");

pub const LicenseError = error{ Unlicensed, Expired, Denied, Unavailable };

pub const Status = enum { uninitialized, valid, missing, invalid, expired, unavailable };

/// Implementations must never put raw license material in errors or status.
pub const Provider = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        initialize: *const fn (ctx: *anyopaque, raw: ?[]const u8) LicenseError!void,
        check: *const fn (ctx: *anyopaque, entitlement: []const u8) LicenseError!void,
        status: *const fn (ctx: *anyopaque) Status,
    };
};

pub const Registry = struct {
    provider: ?Provider = null,

    pub fn check(r: *const Registry, entitlement: []const u8) LicenseError!void {
        const p = r.provider orelse return error.Unlicensed;
        return p.vtable.check(p.ctx, entitlement);
    }

    pub fn status(r: *const Registry) Status {
        const p = r.provider orelse return .missing;
        return p.vtable.status(p.ctx);
    }
};

test "no provider means unlicensed" {
    const r: Registry = .{};
    try std.testing.expectError(error.Unlicensed, r.check("zkfsm.server"));
    try std.testing.expectEqual(Status.missing, r.status());
}

test "installed provider decides" {
    const Allow = struct {
        fn init(_: *anyopaque, _: ?[]const u8) LicenseError!void {}
        fn check(_: *anyopaque, e: []const u8) LicenseError!void {
            if (!std.mem.eql(u8, e, "zkfsm.kms")) return error.Denied;
        }
        fn status(_: *anyopaque) Status {
            return .valid;
        }
    };
    var dummy: u8 = 0;
    const vt: Provider.VTable = .{ .initialize = Allow.init, .check = Allow.check, .status = Allow.status };
    const r: Registry = .{ .provider = .{ .ctx = &dummy, .vtable = &vt } };
    try r.check("zkfsm.kms");
    try std.testing.expectError(error.Denied, r.check("zkfsm.tiering"));
    try std.testing.expectEqual(Status.valid, r.status());
}
