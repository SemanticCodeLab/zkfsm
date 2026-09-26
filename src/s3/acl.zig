//! Bucket and object ACLs. Access is governed by IAM and bucket policies, so every
//! resource reports the canned `private` ACL; PUT accepts only that ACL.
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;

pub const owner_id = "zkfsm";

/// Handles `?acl` on buckets and objects; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if ((try handler.param(c, "acl")) == null) return false;
    const r = c.route;
    // Header checks come first: reading the body invalidates the request head.
    var verdict: Verdict = .empty;
    if (c.method == .PUT) verdict = headerVerdict(c);
    if (r.key.len == 0) {
        try c.svc.headBucket(r.bucket);
    } else {
        const info = try object.versioning.headVersion(c.svc, c.arena, r.bucket, r.key, try s3v.versionParam(c));
        if (info.delete_marker) {
            try handler.fail(c, .MethodNotAllowed);
            return true;
        }
    }
    switch (c.method) {
        .GET => {
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try writePrivate(&a.writer);
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            if (verdict == .empty) {
                const body = try s3v.readBodyMax(c, 64 * 1024) orelse return true;
                verdict = bodyVerdict(body) catch .malformed;
            }
            switch (verdict) {
                .private => try handler.respondEmpty(c, .ok, &.{}),
                .unsupported => try handler.fail(c, .NotImplemented),
                .malformed, .empty => try handler.fail(c, .MalformedXML),
            }
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
    return true;
}

const Verdict = enum { empty, private, unsupported, malformed };

fn headerVerdict(c: *Ctx) Verdict {
    var v: Verdict = .empty;
    var it = c.req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.startsWithIgnoreCase(h.name, "x-amz-grant-")) return .unsupported;
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-acl"))
            v = if (std.mem.eql(u8, std.mem.trim(u8, h.value, " "), "private")) .private else return .unsupported;
    }
    return v;
}

/// An AccessControlPolicy body is accepted when it only grants the owner FULL_CONTROL.
fn bodyVerdict(body: []const u8) xml_read.Error!Verdict {
    var top: xml_read.Scanner = .{ .s = body };
    const acp = try top.next("AccessControlPolicy") orelse return .malformed;
    var grants: xml_read.Scanner = .{ .s = acp };
    const list = try grants.next("AccessControlList") orelse return .malformed;
    var sc: xml_read.Scanner = .{ .s = list };
    while (try sc.next("Grant")) |g| {
        var gs: xml_read.Scanner = .{ .s = g };
        const perm = try gs.next("Permission") orelse return .malformed;
        if (!std.mem.eql(u8, std.mem.trim(u8, perm, " \r\n\t"), "FULL_CONTROL")) return .unsupported;
        var ids: xml_read.Scanner = .{ .s = g };
        const id = try ids.next("ID") orelse return .unsupported;
        if (!std.mem.eql(u8, std.mem.trim(u8, id, " \r\n\t"), owner_id)) return .unsupported;
    }
    return .private;
}

pub fn writePrivate(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const owner = "<Owner><ID>" ++ owner_id ++ "</ID><DisplayName>" ++ owner_id ++ "</DisplayName></Owner>";
    try xml.openRoot(w, "AccessControlPolicy");
    try w.writeAll(owner ++ "<AccessControlList><Grant>" ++
        "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">" ++
        "<ID>" ++ owner_id ++ "</ID><DisplayName>" ++ owner_id ++ "</DisplayName></Grantee>" ++
        "<Permission>FULL_CONTROL</Permission></Grant></AccessControlList>");
    try xml.close(w, "AccessControlPolicy");
}

test "acl bodies" {
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writePrivate(&w);
    try std.testing.expectEqual(Verdict.private, try bodyVerdict(w.buffered()));
    const public =
        \\<AccessControlPolicy><Owner><ID>zkfsm</ID></Owner><AccessControlList><Grant><Grantee xsi:type="Group">
        \\<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>
    ;
    try std.testing.expectEqual(Verdict.unsupported, try bodyVerdict(public));
    try std.testing.expectEqual(Verdict.malformed, try bodyVerdict("<Nope/>"));
}
