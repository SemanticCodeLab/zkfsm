//! Byte-level persistence for catalog documents: small JSON objects in the
//! table bucket, written with If-Match / If-None-Match for compare-and-swap.
const std = @import("std");
const object = @import("../object/root.zig");

pub const Error = error{ OutOfMemory, NoSuchBucket, NotFound, AlreadyExists, PreconditionFailed, TooLarge, Storage, KeyTooLong };

/// Hex MD5 of the stored bytes; the CAS token.
pub const Tag = [32]u8;

pub const Doc = struct { body: []const u8, tag: Tag };

pub const Cond = union(enum) { none, create, match: []const u8 };

pub const Page = struct { keys: []const []const u8, truncated: bool };

pub const Store = struct {
    svc: *object.ObjectService,
    /// Serializes structural changes (create/drop/rename) within this process.
    mutex: std.Thread.Mutex = .{},

    pub fn read(self: *Store, arena: std.mem.Allocator, bucket: []const u8, key: []const u8, max: usize) Error!?Doc {
        const info = self.svc.head(arena, bucket, key) catch |e| return switch (e) {
            error.NoSuchKey => null,
            else => mapErr(e),
        };
        if (info.size > max) return error.TooLarge;
        var out: std.Io.Writer.Allocating = .init(arena);
        self.svc.read(info, null, &out.writer) catch |e| return switch (e) {
            error.NoSuchKey => null,
            else => mapErr(e),
        };
        return .{ .body = out.written(), .tag = std.fmt.bytesToHex(info.etag.md5, .lower) };
    }

    pub fn write(self: *Store, bucket: []const u8, key: []const u8, body: []const u8, cond: Cond) Error!Tag {
        var r: std.Io.Reader = .fixed(body);
        const conditions: object.conditional.Conditions = switch (cond) {
            .none => .{},
            .create => .{ .if_none_match = "*" },
            .match => |t| .{ .if_match = t },
        };
        const info = self.svc.put(bucket, key, &r, .{
            .content_type = "application/json",
            .content_length = body.len,
            .conditions = conditions,
        }) catch |e| return switch (e) {
            error.PreconditionFailed => if (cond == .create) error.AlreadyExists else error.PreconditionFailed,
            error.NoSuchKey => error.PreconditionFailed,
            else => mapErr(e),
        };
        return std.fmt.bytesToHex(info.etag.md5, .lower);
    }

    pub fn remove(self: *Store, bucket: []const u8, key: []const u8) Error!void {
        self.svc.delete(bucket, key) catch |e| return mapErr(e);
    }

    /// Keys under `prefix` after `after`, in order.
    pub fn list(self: *Store, arena: std.mem.Allocator, bucket: []const u8, prefix: []const u8, after: []const u8, max: usize) Error!Page {
        const res = self.svc.list(arena, bucket, .{ .include_reserved = true, .prefix = prefix, .start_after = after, .max_keys = max }) catch |e| return mapErr(e);
        const keys = try arena.alloc([]const u8, res.contents.len);
        for (res.contents, keys) |c, *k| k.* = c.key;
        return .{ .keys = keys, .truncated = res.is_truncated };
    }

    pub fn bucketExists(self: *Store, bucket: []const u8) Error!bool {
        self.svc.headBucket(bucket) catch |e| return switch (e) {
            error.NoSuchBucket, error.InvalidBucketName => false,
            else => mapErr(e),
        };
        return true;
    }

    /// Holds the process mutex and the cluster lock for one bucket's catalog.
    pub fn lock(self: *Store, bucket: []const u8) Error!Held {
        self.mutex.lock();
        errdefer self.mutex.unlock();
        const h = self.svc.clusterLock("tables", bucket, "catalog") catch |e| return mapErr(e);
        return .{ .store = self, .held = h };
    }
};

pub const Held = struct {
    store: *Store,
    held: object.service.Held,

    pub fn release(h: Held) void {
        h.store.svc.clusterUnlock(h.held);
        h.store.mutex.unlock();
    }
};

fn mapErr(e: object.Error) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.NoSuchBucket, error.InvalidBucketName => error.NoSuchBucket,
        error.NoSuchKey => error.NotFound,
        error.KeyTooLong, error.InvalidKey => error.KeyTooLong,
        error.PreconditionFailed => error.PreconditionFailed,
        else => {
            std.log.warn("tables: storage error {t}", .{e});
            return error.Storage;
        },
    };
}

/// Key-safe form of a name: [A-Za-z0-9._-] kept, other bytes as %XX.
pub fn encodeName(w: *std.Io.Writer, name: []const u8) std.Io.Writer.Error!void {
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.') {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

pub fn decodeName(arena: std.mem.Allocator, enc: []const u8) error{ OutOfMemory, Invalid }![]const u8 {
    const out = try arena.alloc(u8, enc.len);
    var n: usize = 0;
    var k: usize = 0;
    while (k < enc.len) {
        if (enc[k] == '%') {
            if (k + 3 > enc.len) return error.Invalid;
            out[n] = std.fmt.parseInt(u8, enc[k + 1 .. k + 3], 16) catch return error.Invalid;
            k += 3;
        } else {
            out[n] = enc[k];
            k += 1;
        }
        n += 1;
    }
    return out[0..n];
}

test "name encoding round-trips and keeps order of plain names" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    var w: std.Io.Writer.Allocating = .init(a.allocator());
    try encodeName(&w.writer, "a/b\x1fc %");
    try std.testing.expectEqualStrings("a%2Fb%1Fc%20%25", w.written());
    try std.testing.expectEqualStrings("a/b\x1fc %", try decodeName(a.allocator(), w.written()));
    try std.testing.expectError(error.Invalid, decodeName(a.allocator(), "%2"));
    try std.testing.expectError(error.Invalid, decodeName(a.allocator(), "%zz"));
}
