//! Per-target persistent event queue: one file per entry, written to a temp name,
//! synced, then renamed, so a crash never leaves a partial entry. Bounded by count.
const std = @import("std");
const target = @import("target.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ QueueFull, StorageFailed, OutOfMemory };

/// Largest stored entry; bigger messages are refused.
pub const max_entry_len = 4 * 1024 * 1024;
const ext = ".event";
const name_len = 20 + ext.len;

pub const Item = struct {
    seq: u64,
    msg: target.Message,
};

pub const Queue = struct {
    gpa: Allocator,
    dir: std.fs.Dir,
    limit: u32,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    /// Sequence numbers on disk, oldest first.
    seqs: std.ArrayList(u64) = .empty,
    next_seq: u64 = 1,
    closed: bool = false,

    /// Opens (creating) `path` and loads the entries left by a previous run.
    pub fn open(gpa: Allocator, path: []const u8, limit: u32) Error!*Queue {
        const dir = std.fs.cwd().makeOpenPath(path, .{ .iterate = true }) catch return error.StorageFailed;
        const q = gpa.create(Queue) catch return error.OutOfMemory;
        q.* = .{ .gpa = gpa, .dir = dir, .limit = @max(1, limit) };
        errdefer q.close();
        var it = q.dir.iterate();
        while (it.next() catch return error.StorageFailed) |e| {
            if (e.kind != .file) continue;
            if (std.mem.startsWith(u8, e.name, ".tmp-")) {
                q.dir.deleteFile(e.name) catch {};
                continue;
            }
            if (e.name.len != name_len or !std.mem.endsWith(u8, e.name, ext)) continue;
            const seq = std.fmt.parseInt(u64, e.name[0..20], 10) catch continue;
            try q.seqs.append(gpa, seq);
            q.next_seq = @max(q.next_seq, seq + 1);
        }
        std.mem.sort(u64, q.seqs.items, {}, std.sort.asc(u64));
        return q;
    }

    pub fn close(q: *Queue) void {
        q.seqs.deinit(q.gpa);
        q.dir.close();
        q.gpa.destroy(q);
    }

    pub fn len(q: *Queue) usize {
        q.mutex.lock();
        defer q.mutex.unlock();
        return q.seqs.items.len;
    }

    /// Durably appends one message.
    pub fn put(q: *Queue, msg: *const target.Message) Error!void {
        var arena = std.heap.ArenaAllocator.init(q.gpa);
        defer arena.deinit();
        const bytes = try encode(arena.allocator(), msg);
        if (bytes.len > max_entry_len) return error.StorageFailed;
        q.mutex.lock();
        defer q.mutex.unlock();
        if (q.seqs.items.len >= q.limit) return error.QueueFull;
        const seq = q.next_seq;
        var nb: [name_len]u8 = undefined;
        var tb: [name_len + 5]u8 = undefined;
        const name = fileName(seq, &nb);
        const tmp = std.fmt.bufPrint(&tb, ".tmp-{s}", .{name}) catch unreachable; // sized for it
        {
            var f = q.dir.createFile(tmp, .{ .exclusive = false }) catch return error.StorageFailed;
            defer f.close();
            f.writeAll(bytes) catch return error.StorageFailed;
            f.sync() catch return error.StorageFailed;
        }
        q.dir.rename(tmp, name) catch return error.StorageFailed;
        syncDir(q.dir);
        try q.seqs.append(q.gpa, seq);
        q.next_seq = seq + 1;
        q.cond.signal();
    }

    /// Oldest entry, read into `a`; waits up to `timeout_ns` for one to arrive.
    /// Unreadable entries are dropped and counted in `corrupt`.
    pub fn peek(q: *Queue, a: Allocator, timeout_ns: u64, corrupt: *u64) error{OutOfMemory}!?Item {
        q.mutex.lock();
        defer q.mutex.unlock();
        if (q.seqs.items.len == 0 and !q.closed) q.cond.timedWait(&q.mutex, timeout_ns) catch {};
        while (q.seqs.items.len > 0) {
            const seq = q.seqs.items[0];
            var nb: [name_len]u8 = undefined;
            const name = fileName(seq, &nb);
            const bytes = q.dir.readFileAlloc(a, name, max_entry_len) catch |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                corrupt.* += 1;
                _ = q.seqs.orderedRemove(0);
                q.dir.deleteFile(name) catch {};
                continue;
            };
            const msg = decode(a, bytes) catch |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                corrupt.* += 1;
                _ = q.seqs.orderedRemove(0);
                q.dir.deleteFile(name) catch {};
                continue;
            };
            return .{ .seq = seq, .msg = msg };
        }
        return null;
    }

    /// Removes a delivered entry.
    pub fn remove(q: *Queue, seq: u64) void {
        q.mutex.lock();
        defer q.mutex.unlock();
        for (q.seqs.items, 0..) |s, i| if (s == seq) {
            _ = q.seqs.orderedRemove(i);
            break;
        };
        var nb: [name_len]u8 = undefined;
        q.dir.deleteFile(fileName(seq, &nb)) catch {};
    }

    /// Wakes a waiting `peek`; used at shutdown.
    pub fn wake(q: *Queue) void {
        q.mutex.lock();
        defer q.mutex.unlock();
        q.closed = true;
        q.cond.broadcast();
    }
};

fn fileName(seq: u64, buf: *[name_len]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d:0>20}" ++ ext, .{seq}) catch unreachable; // fixed width
}

fn syncDir(dir: std.fs.Dir) void {
    std.posix.fsync(dir.fd) catch {};
}

const Stored = struct {
    key: []const u8 = "",
    event_name: []const u8 = "",
    body: []const u8 = "",
    record: []const u8 = "",
    event_time: []const u8 = "",
    removed: bool = false,
};

fn encode(a: Allocator, m: *const target.Message) error{OutOfMemory}![]const u8 {
    const s: Stored = .{ .key = m.key, .event_name = m.event_name, .body = m.body, .record = m.record, .event_time = m.event_time, .removed = m.removed };
    return std.json.Stringify.valueAlloc(a, s, .{});
}

fn decode(a: Allocator, bytes: []const u8) error{ OutOfMemory, Corrupt }!target.Message {
    const s = std.json.parseFromSliceLeaky(Stored, a, bytes, .{ .ignore_unknown_fields = true }) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Corrupt;
    if (s.body.len == 0) return error.Corrupt;
    return .{ .key = s.key, .event_name = s.event_name, .body = s.body, .record = s.record, .event_time = s.event_time, .removed = s.removed };
}

test "entries survive reopen, stay ordered, and the queue is bounded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corrupt: u64 = 0;
    {
        const q = try Queue.open(std.testing.allocator, path, 2);
        defer q.close();
        try q.put(&.{ .key = "b/1", .body = "{\"n\":1}" });
        try q.put(&.{ .key = "b/2", .body = "{\"n\":2}", .removed = true });
        try std.testing.expectError(error.QueueFull, q.put(&.{ .body = "x" }));
    }
    try tmp.dir.writeFile(.{ .sub_path = "00000000000000000000.event", .data = "garbage" });
    try tmp.dir.writeFile(.{ .sub_path = ".tmp-00000000000000000009.event", .data = "half" });
    const q = try Queue.open(std.testing.allocator, path, 10);
    defer q.close();
    try std.testing.expectEqual(@as(usize, 3), q.len());
    const first = (try q.peek(arena.allocator(), 0, &corrupt)).?;
    try std.testing.expectEqual(@as(u64, 1), corrupt);
    try std.testing.expectEqualStrings("b/1", first.msg.key);
    q.remove(first.seq);
    const second = (try q.peek(arena.allocator(), 0, &corrupt)).?;
    try std.testing.expect(second.msg.removed);
    q.remove(second.seq);
    try std.testing.expect((try q.peek(arena.allocator(), 1000, &corrupt)) == null);
    try q.put(&.{ .body = "{}" });
    try std.testing.expectEqual(@as(u64, 3), (try q.peek(arena.allocator(), 0, &corrupt)).?.seq);
}
