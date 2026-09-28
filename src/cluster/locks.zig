//! Namespace locks across nodes: every node keeps a lease table; a lock is held once a
//! majority of nodes granted it. Holders refresh leases; unlocks are retried; leases of
//! crashed holders expire.
const std = @import("std");
const rpc_mod = @import("rpc.zig");

pub const max_resource = 1400;
pub const lease_ms: i64 = 30 * std.time.ms_per_s;
const refresh_every_ns = 10 * std.time.ns_per_s;
const acquire_timeout_ms: i64 = 30 * std.time.ms_per_s;
const call_timeout_ms = 3000;

pub const Error = error{ LockTimeout, NoQuorum, OutOfMemory };

/// Per-node lease table, served to peers over RPC and used directly for this node.
pub const Table = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    entries: std.StringHashMapUnmanaged(Entry) = .empty,

    const Entry = struct { uid: u64, expires_ms: i64 };

    pub fn deinit(t: *Table) void {
        var it = t.entries.keyIterator();
        while (it.next()) |k| t.gpa.free(k.*);
        t.entries.deinit(t.gpa);
    }

    /// Grants when free, expired, or already held by `uid` (then it renews).
    pub fn lock(t: *Table, resource: []const u8, uid: u64, now_ms: i64) error{OutOfMemory}!bool {
        t.mutex.lock();
        defer t.mutex.unlock();
        if (t.entries.getPtr(resource)) |e| {
            if (e.uid != uid and e.expires_ms > now_ms) return false;
            e.* = .{ .uid = uid, .expires_ms = now_ms + lease_ms };
            return true;
        }
        const k = try t.gpa.dupe(u8, resource);
        errdefer t.gpa.free(k);
        try t.entries.put(t.gpa, k, .{ .uid = uid, .expires_ms = now_ms + lease_ms });
        if (t.entries.count() % 1024 == 0) t.expire(now_ms);
        return true;
    }

    /// Extends a lease still held by `uid`; false when it was lost.
    pub fn refresh(t: *Table, resource: []const u8, uid: u64, now_ms: i64) bool {
        t.mutex.lock();
        defer t.mutex.unlock();
        const e = t.entries.getPtr(resource) orelse return false;
        if (e.uid != uid) return false;
        e.expires_ms = now_ms + lease_ms;
        return true;
    }

    pub fn unlock(t: *Table, resource: []const u8, uid: u64) void {
        t.mutex.lock();
        defer t.mutex.unlock();
        const e = t.entries.getEntry(resource) orelse return;
        if (e.value_ptr.uid != uid) return;
        const k = e.key_ptr.*;
        t.entries.removeByPtr(e.key_ptr);
        t.gpa.free(k);
    }

    fn expire(t: *Table, now_ms: i64) void {
        var dead: [64][]const u8 = undefined;
        var n: usize = 0;
        var it = t.entries.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.expires_ms > now_ms) continue;
            dead[n] = e.key_ptr.*;
            n += 1;
            if (n == dead.len) break;
        }
        for (dead[0..n]) |k| {
            _ = t.entries.remove(k);
            t.gpa.free(k);
        }
    }
};

/// Body of lock, refresh, and unlock calls: `<uid hex>\n<resource>`.
pub fn encodeBody(buf: []u8, resource: []const u8, uid: u64) error{NoSpaceLeft}![]u8 {
    return std.fmt.bufPrint(buf, "{x:0>16}\n{s}", .{ uid, resource });
}

pub fn decodeBody(body: []const u8) ?struct { uid: u64, resource: []const u8 } {
    if (body.len < 18 or body[16] != '\n') return null;
    const uid = std.fmt.parseInt(u64, body[0..16], 16) catch return null;
    const res = body[17..];
    if (res.len == 0 or res.len > max_resource) return null;
    return .{ .uid = uid, .resource = res };
}

/// Client side: acquires majorities, keeps leases alive, retries unlocks.
pub const Manager = struct {
    gpa: std.mem.Allocator,
    rpc: *rpc_mod.Rpc,
    table: *Table,
    mutex: std.Thread.Mutex = .{},
    held: std.AutoHashMapUnmanaged(u64, Held) = .empty,
    stop_ev: std.Thread.ResetEvent = .{},
    thread: ?std.Thread = null,

    const Held = struct { resource: []u8, granted: u256 };

    pub fn deinit(m: *Manager) void {
        m.stop_ev.set();
        if (m.thread) |t| t.join();
        var it = m.held.valueIterator();
        while (it.next()) |h| m.gpa.free(h.resource);
        m.held.deinit(m.gpa);
    }

    pub fn start(m: *Manager) void {
        m.thread = std.Thread.spawn(.{}, refreshLoop, .{m}) catch null;
    }

    fn nodes(m: *const Manager) usize {
        return m.rpc.peers.len;
    }

    fn quorum(m: *const Manager) usize {
        return m.nodes() / 2 + 1;
    }

    /// True while enough nodes are reachable to ever win a lock.
    pub fn haveQuorum(m: *Manager) bool {
        var up: usize = 0;
        for (0..m.nodes()) |i| up += @intFromBool(m.rpc.isOnline(@intCast(i)));
        return up >= m.quorum();
    }

    /// Returns the lock uid; the caller passes it to `unlock`.
    pub fn lock(m: *Manager, resource: []const u8) Error!u64 {
        if (resource.len > max_resource) return error.OutOfMemory;
        const uid = std.crypto.random.int(u64) | 1;
        const deadline = std.time.milliTimestamp() + acquire_timeout_ms;
        var backoff_ms: u64 = 5;
        while (true) {
            if (!m.haveQuorum()) return error.NoQuorum;
            const granted = m.ask(resource, uid, "lock");
            if (@popCount(granted) >= m.quorum()) {
                const copy = try m.gpa.dupe(u8, resource);
                m.mutex.lock();
                defer m.mutex.unlock();
                m.held.put(m.gpa, uid, .{ .resource = copy, .granted = granted }) catch {
                    m.gpa.free(copy);
                    m.release(resource, uid, granted);
                    return error.OutOfMemory;
                };
                return uid;
            }
            m.release(resource, uid, granted);
            if (std.time.milliTimestamp() > deadline) return error.LockTimeout;
            std.Thread.sleep((backoff_ms + std.crypto.random.uintLessThan(u64, backoff_ms)) * std.time.ns_per_ms);
            backoff_ms = @min(backoff_ms * 2, 250);
        }
    }

    pub fn unlock(m: *Manager, uid: u64) void {
        const h = blk: {
            m.mutex.lock();
            defer m.mutex.unlock();
            const kv = m.held.fetchRemove(uid) orelse return;
            break :blk kv.value;
        };
        defer m.gpa.free(h.resource);
        m.release(h.resource, uid, h.granted);
    }

    /// Sends `op` to every reachable node; returns the bitmask of nodes that said yes.
    fn ask(m: *Manager, resource: []const u8, uid: u64, op: []const u8) u256 {
        var granted: u256 = 0;
        var bb: [max_resource + 32]u8 = undefined;
        const body = encodeBody(&bb, resource, uid) catch return 0;
        const now = std.time.milliTimestamp();
        for (0..m.nodes()) |i| {
            const node: u16 = @intCast(i);
            const yes = if (node == m.rpc.self_node) blk: {
                if (std.mem.eql(u8, op, "lock")) break :blk m.table.lock(resource, uid, now) catch false;
                break :blk m.table.refresh(resource, uid, now);
            } else blk: {
                var c = m.rpc.call(node, op, "", .{ .bytes = body }, .{ .timeout_ms = call_timeout_ms }) catch break :blk false;
                defer c.deinit();
                break :blk c.ok();
            };
            if (yes) granted |= @as(u256, 1) << @intCast(node);
        }
        return granted;
    }

    /// Unlocks on `granted` nodes; failed calls are retried a few times, then left to expire.
    fn release(m: *Manager, resource: []const u8, uid: u64, granted: u256) void {
        var bb: [max_resource + 32]u8 = undefined;
        const body = encodeBody(&bb, resource, uid) catch return;
        for (0..m.nodes()) |i| {
            if (granted & (@as(u256, 1) << @intCast(i)) == 0) continue;
            const node: u16 = @intCast(i);
            if (node == m.rpc.self_node) {
                m.table.unlock(resource, uid);
                continue;
            }
            var attempt: u8 = 0;
            while (attempt < 3) : (attempt += 1) {
                if (m.rpc.call(node, "unlock", "", .{ .bytes = body }, .{ .timeout_ms = call_timeout_ms })) |c| {
                    var cc = c;
                    cc.deinit();
                    break;
                } else |e| {
                    if (e == error.NodeOffline) break;
                    std.Thread.sleep(20 * std.time.ns_per_ms);
                }
            }
        }
    }

    fn refreshLoop(m: *Manager) void {
        while (true) {
            m.stop_ev.timedWait(refresh_every_ns) catch {};
            if (m.stop_ev.isSet()) return;
            var todo: std.ArrayList(struct { uid: u64, resource: []u8 }) = .empty;
            defer {
                for (todo.items) |t| m.gpa.free(t.resource);
                todo.deinit(m.gpa);
            }
            {
                m.mutex.lock();
                defer m.mutex.unlock();
                var it = m.held.iterator();
                while (it.next()) |e| {
                    const copy = m.gpa.dupe(u8, e.value_ptr.resource) catch continue;
                    todo.append(m.gpa, .{ .uid = e.key_ptr.*, .resource = copy }) catch m.gpa.free(copy);
                }
            }
            for (todo.items) |t| {
                const ok = m.ask(t.resource, t.uid, "refresh");
                if (@popCount(ok) < m.quorum()) std.log.warn("lock {s}: lease refresh lost its majority", .{t.resource});
            }
        }
    }
};

test "lease table grants, renews, expires, and unlocks by uid" {
    var t: Table = .{ .gpa = std.testing.allocator };
    defer t.deinit();
    try std.testing.expect(try t.lock("obj/b/k", 1, 0));
    try std.testing.expect(!try t.lock("obj/b/k", 2, 10));
    try std.testing.expect(try t.lock("obj/b/k", 1, 10));
    try std.testing.expect(t.refresh("obj/b/k", 1, 20));
    try std.testing.expect(!t.refresh("obj/b/k", 2, 20));
    // An expired lease can be taken over.
    try std.testing.expect(try t.lock("obj/b/k", 2, 20 + lease_ms + 1));
    t.unlock("obj/b/k", 1);
    try std.testing.expect(!try t.lock("obj/b/k", 3, 30 + lease_ms));
    t.unlock("obj/b/k", 2);
    try std.testing.expect(try t.lock("obj/b/k", 3, 40 + lease_ms));

    var bb: [64]u8 = undefined;
    const body = try encodeBody(&bb, "obj/b/k", 0xabc);
    const d = decodeBody(body).?;
    try std.testing.expectEqual(@as(u64, 0xabc), d.uid);
    try std.testing.expectEqualStrings("obj/b/k", d.resource);
    try std.testing.expect(decodeBody("zz") == null);
}
