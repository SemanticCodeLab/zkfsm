//! Bucket subresources stored as small documents: ownership controls, public access
//! block, logging configuration (stored, not delivered), and the accelerate and
//! request-payment stubs.
const std = @import("std");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");
const s3v = @import("versioning.zig");
const acl = @import("acl.zig");
const errors = @import("errors.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const Code = errors.Code;
const meta = object.bucket_meta;

pub const Ownership = enum { none, BucketOwnerEnforced, BucketOwnerPreferred, ObjectWriter };

pub const PublicAccess = struct {
    block_public_acls: bool = false,
    ignore_public_acls: bool = false,
    block_public_policy: bool = false,
    restrict_public_buckets: bool = false,

    const names = .{
        .{ "block_public_acls", "BlockPublicAcls" },
        .{ "ignore_public_acls", "IgnorePublicAcls" },
        .{ "block_public_policy", "BlockPublicPolicy" },
        .{ "restrict_public_buckets", "RestrictPublicBuckets" },
    };

    fn encode(p: PublicAccess) [4]u8 {
        var out: [4]u8 = undefined;
        inline for (names, 0..) |n, i| out[i] = if (@field(p, n[0])) '1' else '0';
        return out;
    }

    fn decode(s: []const u8) PublicAccess {
        var p: PublicAccess = .{};
        if (s.len != 4) return p;
        inline for (names, 0..) |n, i| @field(p, n[0]) = s[i] == '1';
        return p;
    }
};

pub fn ownership(c: *Ctx) DispatchError!Ownership {
    const doc = try meta.get(c.svc, c.arena, c.route.bucket, .ownership) orelse return .none;
    return std.meta.stringToEnum(Ownership, doc) orelse .none;
}

pub fn publicAccess(c: *Ctx) DispatchError!PublicAccess {
    return publicAccessOf(c.svc, c.arena, c.route.bucket);
}

pub fn publicAccessOf(svc: *object.ObjectService, arena: std.mem.Allocator, bucket: []const u8) object.Error!PublicAccess {
    const doc = try meta.get(svc, arena, bucket, .public_access_block) orelse return .{};
    return PublicAccess.decode(doc);
}

fn has(c: *Ctx, name: []const u8) error{OutOfMemory}!bool {
    return (try handler.param(c, name)) != null;
}

fn failed(c: *Ctx, code: Code) DispatchError!bool {
    try handler.fail(c, code);
    return true;
}

/// Handles the bucket subresources of this file; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len != 0) return false;
    if (try has(c, "ownershipControls")) return ownershipRoute(c);
    if (try has(c, "publicAccessBlock")) return publicAccessRoute(c);
    if (try has(c, "logging")) return loggingRoute(c);
    if (try has(c, "accelerate")) return stub(c, "AccelerateConfiguration", "");
    if (try has(c, "requestPayment")) return stub(c, "RequestPaymentConfiguration", "<Payer>BucketOwner</Payer>");
    return false;
}

fn stub(c: *Ctx, root: []const u8, inner: []const u8) DispatchError!bool {
    try c.svc.headBucket(c.route.bucket);
    if (c.method != .GET) return failed(c, .NotImplemented);
    var a: std.Io.Writer.Allocating = .init(c.arena);
    try xml.openRoot(&a.writer, root);
    try a.writer.writeAll(inner);
    try xml.close(&a.writer, root);
    try handler.respondXml(c, .ok, a.written());
    return true;
}

fn ownershipRoute(c: *Ctx) DispatchError!bool {
    switch (c.method) {
        .GET => {
            const o = try ownership(c);
            if (o == .none) return failed(c, .OwnershipControlsNotFoundError);
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try xml.openRoot(&a.writer, "OwnershipControls");
            try a.writer.writeAll("<Rule>");
            try xml.elem(&a.writer, "ObjectOwnership", @tagName(o));
            try a.writer.writeAll("</Rule>");
            try xml.close(&a.writer, "OwnershipControls");
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, 4096) orelse return true;
            const o = parseOwnership(body) orelse return failed(c, .MalformedXML);
            try setOwnership(c, o) orelse return true;
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try meta.set(c.svc, c.route.bucket, .ownership, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => return failed(c, .MethodNotAllowed),
    }
    return true;
}

fn parseOwnership(body: []const u8) ?Ownership {
    var sc: xml_read.Scanner = .{ .s = body };
    const v = (sc.next("ObjectOwnership") catch return null) orelse return null;
    const o = std.meta.stringToEnum(Ownership, std.mem.trim(u8, v, " \t\r\n")) orelse return null;
    return if (o == .none) null else o;
}

/// Enforced ownership requires a non-public bucket ACL; null after answering with an error.
fn setOwnership(c: *Ctx, o: Ownership) DispatchError!?void {
    if (o == .BucketOwnerEnforced) {
        const cur = try acl.bucketAcl(c.svc, c.arena, c.route.bucket);
        if (cur.grants.len > 1 or cur.isPublic()) {
            try handler.fail(c, .InvalidBucketAclWithObjectOwnership);
            return null;
        }
    }
    try meta.set(c.svc, c.route.bucket, .ownership, @tagName(o));
}

/// `x-amz-object-ownership` on CreateBucket; call after the bucket exists.
pub fn applyCreateOwnership(c: *Ctx, value: ?[]const u8) DispatchError!void {
    const v = value orelse return;
    const o = std.meta.stringToEnum(Ownership, std.mem.trim(u8, v, " ")) orelse return;
    if (o == .none) return;
    try meta.set(c.svc, c.route.bucket, .ownership, @tagName(o));
}

fn publicAccessRoute(c: *Ctx) DispatchError!bool {
    switch (c.method) {
        .GET => {
            const doc = try meta.get(c.svc, c.arena, c.route.bucket, .public_access_block) orelse return failed(c, .NoSuchPublicAccessBlockConfiguration);
            const p = PublicAccess.decode(doc);
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try xml.openRoot(&a.writer, "PublicAccessBlockConfiguration");
            inline for (PublicAccess.names) |n| try xml.elemBool(&a.writer, n[1], @field(p, n[0]));
            try xml.close(&a.writer, "PublicAccessBlockConfiguration");
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, 4096) orelse return true;
            var p: PublicAccess = .{};
            if (std.mem.indexOf(u8, body, "PublicAccessBlockConfiguration") == null) return failed(c, .MalformedXML);
            inline for (PublicAccess.names) |n| if (s3v.elemText(body, n[1])) |v| {
                @field(p, n[0]) = if (std.ascii.eqlIgnoreCase(v, "true")) true else if (std.ascii.eqlIgnoreCase(v, "false")) false else return failed(c, .MalformedXML);
            };
            const enc = p.encode();
            try meta.set(c.svc, c.route.bucket, .public_access_block, &enc);
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try meta.set(c.svc, c.route.bucket, .public_access_block, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => return failed(c, .MethodNotAllowed),
    }
    return true;
}

fn loggingRoute(c: *Ctx) DispatchError!bool {
    switch (c.method) {
        .GET => {
            const doc = try meta.get(c.svc, c.arena, c.route.bucket, .logging) orelse "";
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try xml.openRoot(&a.writer, "BucketLoggingStatus");
            try a.writer.writeAll(doc);
            try xml.close(&a.writer, "BucketLoggingStatus");
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, meta.max_doc_bytes) orelse return true;
            var sc: xml_read.Scanner = .{ .s = body };
            _ = (sc.next("BucketLoggingStatus") catch return failed(c, .MalformedXML)) orelse return failed(c, .MalformedXML);
            var ls: xml_read.Scanner = .{ .s = body };
            const enabled = ls.next("LoggingEnabled") catch return failed(c, .MalformedXML);
            const doc: ?[]const u8 = if (enabled) |inner| blk: {
                const target = s3v.elemText(inner, "TargetBucket") orelse return failed(c, .MalformedXML);
                c.svc.headBucket(target) catch return failed(c, .InvalidTargetBucketForLogging);
                const fmt = if (std.mem.indexOf(u8, inner, "<TargetObjectKeyFormat") == null) "<TargetObjectKeyFormat><SimplePrefix></SimplePrefix></TargetObjectKeyFormat>" else "";
                break :blk try std.fmt.allocPrint(c.arena, "<LoggingEnabled>{s}{s}</LoggingEnabled>", .{ inner, fmt });
            } else null;
            try c.svc.headBucket(c.route.bucket);
            try meta.set(c.svc, c.route.bucket, .logging, doc);
            try handler.respondEmpty(c, .ok, &.{});
        },
        else => return failed(c, .MethodNotAllowed),
    }
    return true;
}

test "public access block encoding" {
    const p: PublicAccess = .{ .block_public_acls = true, .restrict_public_buckets = true };
    const e = p.encode();
    try std.testing.expectEqualStrings("1001", &e);
    const d = PublicAccess.decode(&e);
    try std.testing.expect(d.block_public_acls and !d.ignore_public_acls and d.restrict_public_buckets);
    try std.testing.expectEqual(Ownership.ObjectWriter, parseOwnership("<OwnershipControls><Rule><ObjectOwnership>ObjectWriter</ObjectOwnership></Rule></OwnershipControls>").?);
    try std.testing.expect(parseOwnership("<OwnershipControls/>") == null);
}
