//! Read leases: blobs a peer is streaming stay open here, so a delete (an overwrite's
//! garbage) unlinks the name but the reader keeps the bytes it started on. A lease
//! idle past `lease_ms` is closed; ids are random so a stale one never aliases.
const std = @import("std");

pub const lease_ms: i64 = 30_000;
pub const max_open = 4096;

pub const Error = error{ Busy, OutOfMemory };

const Entry = struct {
    file: std.fs.File,
    last_ms: i64,
    /// Reads in progress; a busy entry is never closed under them.
    busy: u32 = 0,
    closing: bool = false,
};

pub const Table = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged(u64, Entry) = .empty,

    pub fn deinit(t: *Table) void {
        var it = t.map.valueIterator();
        while (it.next()) |e| e.file.close();
        t.map.deinit(t.gpa);
    }

    /// Takes ownership of `file` (closed on error too).
    pub fn open(t: *Table, file: std.fs.File, now_ms: i64) Error!u64 {
        t.mutex.lock();
        defer t.mutex.unlock();
        if (t.map.count() >= max_open) {
            file.close();
            return error.Busy;
        }
        var id: u64 = 0;
        while (id == 0 or t.map.contains(id)) id = std.crypto.random.int(u64);
        t.map.put(t.gpa, id, .{ .file = file, .last_ms = now_ms }) catch {
            file.close();
            return error.OutOfMemory;
        };
        return id;
    }

    /// Pins the lease for one read; pair with `release`.
    pub fn acquire(t: *Table, id: u64, now_ms: i64) ?std.fs.File {
        t.mutex.lock();
        defer t.mutex.unlock();
        const e = t.map.getPtr(id) orelse return null;
        if (e.closing) return null;
        e.busy += 1;
        e.last_ms = now_ms;
        return e.file;
    }

    pub fn release(t: *Table, id: u64, now_ms: i64) void {
        t.mutex.lock();
        defer t.mutex.unlock();
        const e = t.map.getPtr(id) orelse return;
        e.busy -= 1;
        e.last_ms = now_ms;
        if (e.busy == 0 and e.closing) t.drop(id);
    }

    pub fn close(t: *Table, id: u64) void {
        t.mutex.lock();
        defer t.mutex.unlock();
        const e = t.map.getPtr(id) orelse return;
        if (e.busy > 0) e.closing = true else t.drop(id);
    }

    fn drop(t: *Table, id: u64) void {
        const kv = t.map.fetchRemove(id) orelse return;
        kv.value.file.close();
    }

    /// Closes idle leases; returns how many.
    pub fn sweep(t: *Table, now_ms: i64) usize {
        t.mutex.lock();
        defer t.mutex.unlock();
        var n: usize = 0;
        while (true) {
            var victims: [64]u64 = undefined;
            var k: usize = 0;
            var it = t.map.iterator();
            while (it.next()) |kv| if (kv.value_ptr.busy == 0 and now_ms - kv.value_ptr.last_ms > lease_ms) {
                victims[k] = kv.key_ptr.*;
                k += 1;
                if (k == victims.len) break;
            };
            for (victims[0..k]) |v| t.drop(v);
            n += k;
            if (k < victims.len) return n;
        }
    }

    pub fn count(t: *Table) usize {
        t.mutex.lock();
        defer t.mutex.unlock();
        return t.map.count();
    }
};

test "leases survive unlink, expire when idle, and close after the last reader" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "blob", .data = "old-bytes" });
    var t: Table = .{ .gpa = gpa };
    defer t.deinit();
    const id = try t.open(try tmp.dir.openFile("blob", .{}), 0);
    try tmp.dir.deleteFile("blob");
    try tmp.dir.writeFile(.{ .sub_path = "blob", .data = "new" });
    var buf: [16]u8 = undefined;
    const f = t.acquire(id, 1).?;
    try std.testing.expectEqualStrings("old-bytes", buf[0..try f.preadAll(&buf, 0)]);
    t.close(id);
    try std.testing.expect(t.acquire(id, 2) == null);
    try std.testing.expectEqual(@as(usize, 1), t.count());
    t.release(id, 2);
    try std.testing.expectEqual(@as(usize, 0), t.count());

    const id2 = try t.open(try tmp.dir.openFile("blob", .{}), 0);
    try std.testing.expectEqual(@as(usize, 0), t.sweep(lease_ms));
    try std.testing.expectEqual(@as(usize, 1), t.sweep(lease_ms + 1));
    try std.testing.expect(t.acquire(id2, lease_ms + 2) == null);
}
