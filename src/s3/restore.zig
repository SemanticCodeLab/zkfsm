//! RestoreObject (POST /bucket/key?restore): brings a temporary local copy of tiered
//! data back for `Days`. 202 when a copy was made, 200 when an existing copy's expiry moved.
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml_read = @import("xml_read.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const max_body = 64 * 1024;

pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len == 0 or c.method != .POST or (try handler.param(c, "restore")) == null) return false;
    const version = try s3v.versionParam(c);
    const body = try s3v.readBodyMax(c, max_body) orelse return true;
    const days = parseDays(body) catch |e| {
        try handler.fail(c, switch (e) {
            error.MalformedXML => .MalformedXML,
            error.InvalidArgument => .InvalidArgument,
            error.NotImplemented => .NotImplemented,
        });
        return true;
    };
    const res = try object.transition.restore(c.svc, c.route.bucket, c.route.key, version, days);
    try handler.respondEmpty(c, if (res == .accepted) .accepted else .ok, &.{});
    return true;
}

const ParseError = error{ MalformedXML, InvalidArgument, NotImplemented };

/// `<RestoreRequest><Days>N</Days>...</RestoreRequest>`; select requests are not supported.
fn parseDays(doc: []const u8) ParseError!u32 {
    var top: xml_read.Scanner = .{ .s = doc };
    const root = (top.next("RestoreRequest") catch return error.MalformedXML) orelse return error.MalformedXML;
    var sc: xml_read.Scanner = .{ .s = root };
    if ((sc.next("SelectParameters") catch return error.MalformedXML) != null) return error.NotImplemented;
    sc = .{ .s = root };
    const raw = (sc.next("Days") catch return error.MalformedXML) orelse return error.MalformedXML;
    const n = std.fmt.parseInt(u32, std.mem.trim(u8, raw, " \t\r\n"), 10) catch return error.InvalidArgument;
    if (n == 0) return error.InvalidArgument;
    return n;
}

test "restore request parsing" {
    try std.testing.expectEqual(@as(u32, 3), try parseDays("<RestoreRequest xmlns=\"x\"><Days>3</Days><GlacierJobParameters><Tier>Standard</Tier></GlacierJobParameters></RestoreRequest>"));
    try std.testing.expectError(error.MalformedXML, parseDays("<RestoreRequest></RestoreRequest>"));
    try std.testing.expectError(error.InvalidArgument, parseDays("<RestoreRequest><Days>0</Days></RestoreRequest>"));
    try std.testing.expectError(error.InvalidArgument, parseDays("<RestoreRequest><Days>x</Days></RestoreRequest>"));
    try std.testing.expectError(error.NotImplemented, parseDays("<RestoreRequest><Days>1</Days><SelectParameters/></RestoreRequest>"));
    try std.testing.expectError(error.MalformedXML, parseDays("junk"));
}
