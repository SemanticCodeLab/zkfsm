//! Opaque per-bucket subresource documents (CORS, website, ACL, ownership, logging,
//! public access block, ...). One system record per (bucket id, kind); the protocol
//! layer owns the encoding. Keyed by bucket id, so a recreated bucket starts empty.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const service = @import("service.zig");

const Svc = service.ObjectService;
const Error = service.Error;

pub const Kind = enum(u8) {
    cors = 1,
    website = 2,
    logging = 3,
    ownership = 4,
    acl = 5,
    public_access_block = 6,
    accelerate = 7,
    request_payment = 8,
    location = 9,
    lifecycle_legacy = 10,
    /// WebDAV gateway lock table (gateway-encoded).
    webdav_locks = 11,
};

pub const max_doc_bytes = 64 * 1024;
const magic_hex = "5a42";

/// `5a42<kind><26 hex of sha256(bucket id)>` in the system space.
pub fn key(bid: core.BucketId, kind: Kind) backend.PhysicalKey {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bid.bytes, &d, .{});
    const hex = std.fmt.bytesToHex(d, .lower);
    var k: backend.PhysicalKey = .{ .space = .system, .hex = undefined };
    @memcpy(k.hex[0..4], magic_hex);
    const kh = std.fmt.bytesToHex([1]u8{@intFromEnum(kind)}, .lower);
    @memcpy(k.hex[4..6], &kh);
    @memcpy(k.hex[6..], hex[0..26]);
    return k;
}

/// The stored document in `arena`, or null when none is set.
pub fn get(svc: *Svc, arena: std.mem.Allocator, bucket: []const u8, kind: Kind) Error!?[]const u8 {
    const bid = try svc.bucketId(bucket);
    return getById(svc, arena, bid, kind);
}

pub fn getById(svc: *Svc, arena: std.mem.Allocator, bid: core.BucketId, kind: Kind) Error!?[]const u8 {
    const bytes = svc.store.getRecord(key(bid, kind), arena) catch |e| return switch (e) {
        error.NotFound => null,
        else => service.mapBackend(e),
    };
    return if (bytes.len == 0) null else bytes;
}

/// `doc` null (or empty) deletes the document.
pub fn set(svc: *Svc, bucket: []const u8, kind: Kind, doc: ?[]const u8) Error!void {
    const d = doc orelse "";
    if (d.len > max_doc_bytes) return error.InvalidRequest;
    const bid = try svc.bucketId(bucket);
    const held = try svc.clusterLock("bucketmeta", bucket, @tagName(kind));
    defer svc.clusterUnlock(held);
    const k = key(bid, kind);
    if (d.len == 0) {
        svc.store.deleteRecord(k) catch |e| switch (e) {
            error.NotFound => {},
            else => return service.mapBackend(e),
        };
        return;
    }
    svc.store.putRecord(k, d) catch |e| return service.mapBackend(e);
}

/// `5a43<28 hex of sha256(name)>`: a deployment-wide document not tied to a bucket.
fn namedKey(name: []const u8) backend.PhysicalKey {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &d, .{});
    const hex = std.fmt.bytesToHex(d, .lower);
    var k: backend.PhysicalKey = .{ .space = .system, .hex = undefined };
    @memcpy(k.hex[0..4], "5a43");
    @memcpy(k.hex[4..], hex[0..28]);
    return k;
}

/// Named document (gateway state shared by every node), or null when none is set.
pub fn getNamed(svc: *Svc, arena: std.mem.Allocator, name: []const u8) Error!?[]const u8 {
    const bytes = svc.store.getRecord(namedKey(name), arena) catch |e| return switch (e) {
        error.NotFound => null,
        else => service.mapBackend(e),
    };
    return if (bytes.len == 0) null else bytes;
}

/// Stores a named document; an empty `doc` deletes it.
pub fn setNamed(svc: *Svc, name: []const u8, doc: []const u8) Error!void {
    if (doc.len > max_doc_bytes) return error.InvalidRequest;
    const held = try svc.clusterLock("nameddoc", name, "");
    defer svc.clusterUnlock(held);
    const k = namedKey(name);
    if (doc.len == 0) {
        svc.store.deleteRecord(k) catch |e| switch (e) {
            error.NotFound => {},
            else => return service.mapBackend(e),
        };
        return;
    }
    svc.store.putRecord(k, doc) catch |e| return service.mapBackend(e);
}

/// Stores `doc` unless the name already has one; returns the stored document in `arena`.
pub fn initNamed(svc: *Svc, arena: std.mem.Allocator, name: []const u8, doc: []const u8) Error![]const u8 {
    if (doc.len == 0 or doc.len > max_doc_bytes) return error.InvalidRequest;
    const held = try svc.clusterLock("nameddoc", name, "");
    defer svc.clusterUnlock(held);
    const k = namedKey(name);
    if (svc.store.getRecord(k, arena)) |cur| {
        if (cur.len > 0) return cur;
    } else |e| switch (e) {
        error.NotFound => {},
        else => return service.mapBackend(e),
    }
    svc.store.putRecord(k, doc) catch |e| return service.mapBackend(e);
    return doc;
}

/// Removes every document of a deleted bucket; best effort.
pub fn dropAll(svc: *Svc, bid: core.BucketId) void {
    inline for (@typeInfo(Kind).@"enum".fields) |f| svc.store.deleteRecord(key(bid, @enumFromInt(f.value))) catch {};
}

test "bucket documents set, get, delete, and per-bucket-id isolation" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try Svc.init(gpa, lb.backend());
    defer svc.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    try svc.createBucket("bmeta");
    try std.testing.expect((try get(&svc, a, "bmeta", .cors)) == null);
    try set(&svc, "bmeta", .cors, "<CORSConfiguration/>");
    try set(&svc, "bmeta", .website, "w");
    try std.testing.expectEqualStrings("<CORSConfiguration/>", (try get(&svc, a, "bmeta", .cors)).?);
    try set(&svc, "bmeta", .cors, null);
    try std.testing.expect((try get(&svc, a, "bmeta", .cors)) == null);
    try std.testing.expectEqualStrings("w", (try get(&svc, a, "bmeta", .website)).?);
    const bid = try svc.bucketId("bmeta");
    try svc.deleteBucket("bmeta");
    dropAll(&svc, bid);
    try svc.createBucket("bmeta");
    try std.testing.expect((try get(&svc, a, "bmeta", .website)) == null);
    try std.testing.expectError(error.NoSuchBucket, get(&svc, a, "nope", .cors));
    try std.testing.expect(!std.mem.eql(u8, &key(bid, .cors).hex, &key(bid, .acl).hex));
}
