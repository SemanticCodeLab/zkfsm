//! Durable replication work items. Each pending operation is one system record, so a
//! crash between commit and delivery loses nothing; retries back off per entry.
const std = @import("std");
const store = @import("store.zig");

const Allocator = std.mem.Allocator;

pub const Op = enum {
    /// A new object version.
    put,
    delete_marker,
    delete_version,
    /// Tags, retention, or legal hold of an existing version.
    metadata,
    /// Existing-object replication or resync of one version.
    existing,
    /// Site replication: push one bucket's existence and configuration to a peer.
    bucket,
    /// Site replication: replay one IAM change on a peer.
    iam,
};

pub const Entry = struct {
    op: Op,
    bucket: []const u8 = "",
    key: []const u8 = "",
    /// Version id as hex, or "null".
    version: []const u8 = "",
    /// Object ops: target ARN. Site ops: peer deployment id.
    arn: []const u8 = "",
    attempts: u32 = 0,
    next_ns: i64 = 0,
    enq_ns: i64 = 0,
    resync_id: []const u8 = "",
    /// IAM replay: method, admin op path with query, sio-sealed body (base64).
    method: []const u8 = "",
    path: []const u8 = "",
    payload: []const u8 = "",
    sealed: bool = false,
    /// Distinguishes otherwise identical IAM entries.
    id: []const u8 = "",
    deleted: bool = false,

    /// Record identity; re-enqueueing the same change overwrites its entry.
    pub fn name(e: Entry, a: Allocator) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(a, "{t}\x00{s}\x00{s}\x00{s}\x00{s}\x00{s}", .{ e.op, e.bucket, e.key, e.version, e.arn, e.id });
    }

    pub fn recordKey(e: Entry, a: Allocator) Allocator.Error!store.PhysicalKey {
        return store.key(.queue, try e.name(a));
    }

    pub fn isSite(e: Entry) bool {
        return e.op == .bucket or e.op == .iam;
    }
};

/// Delay before attempt `n + 1`: 1 s doubling up to 30 s.
pub fn backoffNs(attempts: u32) i64 {
    const shift: u6 = @intCast(@min(attempts, 5));
    return @min(@as(i64, std.time.ns_per_s) << shift, 30 * std.time.ns_per_s);
}

pub fn lessEnqueued(_: void, x: Entry, y: Entry) bool {
    return x.enq_ns < y.enq_ns;
}

test "entry names and backoff" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const e: Entry = .{ .op = .put, .bucket = "b", .key = "k", .version = "v", .arn = "x" };
    var f = e;
    f.attempts = 3;
    try std.testing.expectEqualSlices(u8, &(try e.recordKey(a)).hex, &(try f.recordKey(a)).hex);
    f.op = .metadata;
    try std.testing.expect(!std.mem.eql(u8, &(try e.recordKey(a)).hex, &(try f.recordKey(a)).hex));
    try std.testing.expectEqual(@as(i64, std.time.ns_per_s), backoffNs(0));
    try std.testing.expectEqual(@as(i64, 30 * std.time.ns_per_s), backoffNs(9));
    const bytes = try std.json.Stringify.valueAlloc(a, e, .{});
    const back = try std.json.parseFromSliceLeaky(Entry, a, bytes, .{ .ignore_unknown_fields = true });
    try std.testing.expectEqual(Op.put, back.op);
    try std.testing.expectEqualStrings("k", back.key);
}
