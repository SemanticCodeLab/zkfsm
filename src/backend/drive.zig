//! Drive handles: the per-drive operations protection stores use. A drive is either a
//! local directory or an external implementation (a remote drive reached over RPC).
const std = @import("std");
const iface = @import("root.zig");
const local = @import("local.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const LocalBackend = local.LocalBackend;

pub const Stat = struct { size: u64, mtime_ns: i128 };

/// Keys returned per scan page, and the bound a server enforces.
pub const scan_page_max = 1000;

/// An open stored blob for positional reads.
pub const ShardFile = union(enum) {
    local: std.fs.File,
    ext: ExtFile,

    /// Reads until `buf` is full or the blob ends; returns the byte count.
    pub fn preadAll(f: *ShardFile, buf: []u8, off: u64) Error!usize {
        return switch (f.*) {
            .local => |file| file.preadAll(buf, off) catch error.IoFailed,
            .ext => |x| x.vtable.pread(x.ctx, buf, off),
        };
    }

    pub fn stat(f: *ShardFile) Error!Stat {
        return switch (f.*) {
            .local => |file| {
                const st = file.stat() catch return error.IoFailed;
                return .{ .size = st.size, .mtime_ns = st.mtime };
            },
            .ext => |x| x.vtable.stat(x.ctx),
        };
    }

    pub fn close(f: *ShardFile) void {
        switch (f.*) {
            .local => |file| file.close(),
            .ext => |x| x.vtable.close(x.ctx),
        }
    }
};

pub const ExtFile = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        pread: *const fn (ctx: *anyopaque, buf: []u8, off: u64) Error!usize,
        stat: *const fn (ctx: *anyopaque) Error!Stat,
        close: *const fn (ctx: *anyopaque) void,
    };
};

/// An uncommitted blob; `commit` publishes it under a key atomically, `abort` drops it.
pub const Pending = union(enum) {
    local: LocalBackend.PendingWrite,
    ext: ExtPending,

    pub fn writeAll(p: *Pending, bytes: []const u8) Error!void {
        return switch (p.*) {
            .local => |*w| w.writeAll(bytes),
            .ext => |x| x.vtable.writeAll(x.ctx, bytes),
        };
    }

    /// Overwrites bytes already written (headers patched once the size is known).
    pub fn pwrite(p: *Pending, bytes: []const u8, off: u64) Error!void {
        return switch (p.*) {
            .local => |*w| w.file.pwriteAll(bytes, off) catch error.IoFailed,
            .ext => |x| x.vtable.pwrite(x.ctx, bytes, off),
        };
    }

    /// Consumes the pending write, success or not.
    pub fn commit(p: *Pending, key: PhysicalKey) Error!void {
        return switch (p.*) {
            .local => |*w| w.commit(key),
            .ext => |x| x.vtable.commit(x.ctx, key),
        };
    }

    pub fn abort(p: *Pending) void {
        switch (p.*) {
            .local => |*w| w.abort(),
            .ext => |x| x.vtable.abort(x.ctx),
        }
    }
};

pub const ExtPending = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writeAll: *const fn (ctx: *anyopaque, bytes: []const u8) Error!void,
        pwrite: *const fn (ctx: *anyopaque, bytes: []const u8, off: u64) Error!void,
        commit: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!void,
        abort: *const fn (ctx: *anyopaque) void,
    };
};

/// One page of a key scan in ascending hex order; `more` says a later page exists.
pub const ScanPage = struct {
    keys: std.ArrayList(PhysicalKey) = .empty,
    more: bool = false,

    pub fn deinit(p: *ScanPage, gpa: std.mem.Allocator) void {
        p.keys.deinit(gpa);
    }
};

/// External drive implementation (remote drives).
pub const Ext = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        store: *const fn (ctx: *anyopaque) iface.StorageBackend,
        begin: *const fn (ctx: *anyopaque) Error!ExtPending,
        openRead: *const fn (ctx: *anyopaque, key: PhysicalKey) Error!ExtFile,
        /// Raw format file bytes into `buf`; NotFound when unformatted.
        readFormat: *const fn (ctx: *anyopaque, buf: []u8) Error![]u8,
        /// Keys of `space` strictly after `after` (null: from the start).
        scan: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator, space: iface.KeySpace, after: ?[32]u8, out: *ScanPage) Error!void,
        /// False while the owning node is unreachable.
        online: *const fn (ctx: *anyopaque) bool,
        /// Deletes a stamped cluster record only if it still carries `stamp`.
        deleteRecordIf: *const fn (ctx: *anyopaque, key: PhysicalKey, stamp: u64) Error!void,
    };
};

/// A drive the caller holds; see `placement.DriveSet.acquire`.
pub const Handle = union(enum) {
    local: *LocalBackend,
    ext: Ext,

    pub fn store(h: Handle) iface.StorageBackend {
        return switch (h) {
            .local => |lb| lb.backend(),
            .ext => |x| x.vtable.store(x.ctx),
        };
    }

    pub fn begin(h: Handle) Error!Pending {
        return switch (h) {
            .local => |lb| .{ .local = try lb.begin() },
            .ext => |x| .{ .ext = try x.vtable.begin(x.ctx) },
        };
    }

    pub fn openRead(h: Handle, key: PhysicalKey) Error!ShardFile {
        return switch (h) {
            .local => |lb| .{ .local = try lb.openRead(key) },
            .ext => |x| .{ .ext = try x.vtable.openRead(x.ctx, key) },
        };
    }

    /// Stale temp files are swept by the drive's owner only.
    pub fn removeTemp(h: Handle, name: []const u8) Error!void {
        return switch (h) {
            .local => |lb| lb.removeTemp(name),
            .ext => error.InvalidKey,
        };
    }

    pub fn isLocal(h: Handle) bool {
        return h == .local;
    }
};

test "local handle pending write and shard file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    const h: Handle = .{ .local = &lb };
    const key: PhysicalKey = .{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* };
    var p = try h.begin();
    try p.writeAll("xxcdef");
    try p.pwrite("ab", 0);
    try p.commit(key);
    var f = try h.openRead(key);
    defer f.close();
    var b: [8]u8 = undefined;
    const n = try f.preadAll(&b, 0);
    try std.testing.expectEqualStrings("abcdef", b[0..n]);
    try std.testing.expectEqual(@as(u64, 6), (try f.stat()).size);
}
