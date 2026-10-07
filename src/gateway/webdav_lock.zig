//! In-memory WebDAV write locks: bounded table, expiry, opaquelocktoken UUIDs.
//! Locks live only in this process; a restart drops them (clients re-lock).
const std = @import("std");

pub const max_locks = 1024;
pub const max_path = 1024;
pub const max_owner = 256;
pub const default_timeout_s: u32 = 3600;
pub const max_timeout_s: u32 = 86400;
pub const token_len = "opaquelocktoken:".len + 36;

pub const Scope = enum { exclusive, shared };

pub const Lock = struct {
    token: [token_len]u8 = undefined,
    path_buf: [max_path]u8 = undefined,
    path_len: u16 = 0,
    infinite: bool = true,
    scope: Scope = .exclusive,
    owner_buf: [max_owner]u8 = undefined,
    owner_len: u16 = 0,
    owner_href: bool = false,
    timeout_s: u32 = default_timeout_s,
    expires_s: i64 = 0,
    used: bool = false,

    pub fn path(l: *const Lock) []const u8 {
        return l.path_buf[0..l.path_len];
    }
    pub fn owner(l: *const Lock) []const u8 {
        return l.owner_buf[0..l.owner_len];
    }
};

pub const Request = struct {
    path: []const u8,
    infinite: bool = true,
    scope: Scope = .exclusive,
    owner: []const u8 = "",
    owner_href: bool = false,
    timeout_s: u32 = default_timeout_s,
};

pub const Error = error{ Locked, Full, TooLong, NoMatch };

/// True when `p` is `root` or lies below it.
pub fn within(root: []const u8, p: []const u8) bool {
    if (!std.mem.startsWith(u8, p, root)) return false;
    if (p.len == root.len) return true;
    return std.mem.eql(u8, root, "/") or p[root.len] == '/';
}

fn covers(l: *const Lock, p: []const u8) bool {
    if (l.infinite) return within(l.path(), p);
    return std.mem.eql(u8, l.path(), p);
}

/// Whether lock `l` restricts writes to `p` (and, if `recursive`, to its members).
fn affects(l: *const Lock, p: []const u8, recursive: bool) bool {
    return covers(l, p) or (recursive and within(p, l.path()));
}

fn has(tokens: []const []const u8, t: []const u8) bool {
    for (tokens) |x| if (std.mem.eql(u8, x, t)) return true;
    return false;
}

pub const Table = struct {
    mu: std.Thread.Mutex = .{},
    locks: [max_locks]Lock = [_]Lock{.{}} ** max_locks,

    fn expire(t: *Table, now: i64) void {
        for (&t.locks) |*l| if (l.used and l.expires_s <= now) {
            l.used = false;
        };
    }

    /// Grants a new lock or fails with Locked on conflict.
    pub fn acquire(t: *Table, r: Request, now: i64) Error!Lock {
        if (r.path.len > max_path) return error.TooLong;
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        var free: ?*Lock = null;
        for (&t.locks) |*l| {
            if (!l.used) {
                if (free == null) free = l;
                continue;
            }
            const overlap = covers(l, r.path) or (r.infinite and within(r.path, l.path()));
            if (overlap and (l.scope == .exclusive or r.scope == .exclusive)) return error.Locked;
        }
        const l = free orelse return error.Full;
        l.* = .{ .used = true, .infinite = r.infinite, .scope = r.scope, .owner_href = r.owner_href };
        @memcpy(l.path_buf[0..r.path.len], r.path);
        l.path_len = @intCast(r.path.len);
        const on = @min(r.owner.len, max_owner);
        @memcpy(l.owner_buf[0..on], r.owner[0..on]);
        l.owner_len = @intCast(on);
        l.timeout_s = @min(r.timeout_s, max_timeout_s);
        l.expires_s = now + l.timeout_s;
        newToken(&l.token);
        return l.*;
    }

    /// Extends a lock on `p` whose token was submitted.
    pub fn refresh(t: *Table, p: []const u8, tokens: []const []const u8, timeout_s: u32, now: i64) Error!Lock {
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        for (&t.locks) |*l| if (l.used and covers(l, p) and has(tokens, &l.token)) {
            l.timeout_s = @min(timeout_s, max_timeout_s);
            l.expires_s = now + l.timeout_s;
            return l.*;
        };
        return error.NoMatch;
    }

    pub fn release(t: *Table, p: []const u8, token: []const u8, now: i64) Error!void {
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        for (&t.locks) |*l| if (l.used and covers(l, p) and std.mem.eql(u8, &l.token, token)) {
            l.used = false;
            return;
        };
        return error.NoMatch;
    }

    /// Path of a lock that blocks writing `p` without the submitted tokens, else null.
    /// Holding any shared lock on the resource satisfies the other shared locks.
    pub fn blocker(t: *Table, p: []const u8, recursive: bool, tokens: []const []const u8, now: i64, buf: []u8) ?[]const u8 {
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        var shared_ok = false;
        for (&t.locks) |*l| if (l.used and l.scope == .shared and covers(l, p) and has(tokens, &l.token)) {
            shared_ok = true;
        };
        for (&t.locks) |*l| {
            if (!l.used or !affects(l, p, recursive) or has(tokens, &l.token)) continue;
            if (l.scope == .shared and shared_ok and covers(l, p)) continue;
            const n = @min(buf.len, l.path_len);
            @memcpy(buf[0..n], l.path_buf[0..n]);
            return buf[0..n];
        }
        return null;
    }

    /// True when `token` names a live lock covering `p`.
    pub fn valid(t: *Table, p: []const u8, token: []const u8, now: i64) bool {
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        for (&t.locks) |*l| if (l.used and covers(l, p) and std.mem.eql(u8, &l.token, token)) return true;
        return false;
    }

    /// Copies the live locks covering `p` into `out`; returns how many.
    pub fn discover(t: *Table, p: []const u8, now: i64, out: []Lock) usize {
        t.mu.lock();
        defer t.mu.unlock();
        t.expire(now);
        var n: usize = 0;
        for (&t.locks) |*l| if (l.used and covers(l, p) and n < out.len) {
            out[n] = l.*;
            n += 1;
        };
        return n;
    }

    /// Drops every lock rooted at or below `p` (after DELETE or MOVE).
    pub fn dropUnder(t: *Table, p: []const u8) void {
        t.mu.lock();
        defer t.mu.unlock();
        for (&t.locks) |*l| if (l.used and within(p, l.path())) {
            l.used = false;
        };
    }
};

fn newToken(out: *[token_len]u8) void {
    var b: [16]u8 = undefined;
    std.crypto.random.bytes(&b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = std.fmt.bytesToHex(b, .lower);
    _ = std.fmt.bufPrint(out, "opaquelocktoken:{s}-{s}-{s}-{s}-{s}", .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] }) catch {};
}

/// Parses a Timeout header ("Second-N", "Infinite", comma-separated); default when absent.
pub fn parseTimeout(h: ?[]const u8) u32 {
    const v = h orelse return default_timeout_s;
    var it = std.mem.tokenizeAny(u8, v, ", ");
    while (it.next()) |t| {
        if (std.ascii.eqlIgnoreCase(t, "Infinite")) return max_timeout_s;
        if (t.len > 7 and std.ascii.eqlIgnoreCase(t[0..7], "Second-")) {
            const n = std.fmt.parseInt(u64, t[7..], 10) catch continue;
            return @intCast(@max(1, @min(n, max_timeout_s)));
        }
    }
    return default_timeout_s;
}

test "lock conflicts, tokens, expiry" {
    const t = try std.testing.allocator.create(Table);
    defer std.testing.allocator.destroy(t);
    t.* = .{};
    var buf: [max_path]u8 = undefined;
    const a = try t.acquire(.{ .path = "/b/dir", .timeout_s = 10 }, 100);
    try std.testing.expect(std.mem.startsWith(u8, &a.token, "opaquelocktoken:"));
    try std.testing.expectEqual(@as(u8, '4'), a.token[16 + 14]);
    try std.testing.expectError(error.Locked, t.acquire(.{ .path = "/b/dir/x", .scope = .shared }, 101));
    try std.testing.expectError(error.Locked, t.acquire(.{ .path = "/b" }, 101));
    _ = try t.acquire(.{ .path = "/b/other", .infinite = false }, 101);
    try std.testing.expectEqualStrings("/b/dir", t.blocker("/b/dir/f", false, &.{}, 102, &buf).?);
    try std.testing.expect(t.blocker("/b/dir/f", false, &.{&a.token}, 102, &buf) == null);
    try std.testing.expect(t.blocker("/b/dirx", false, &.{}, 102, &buf) == null);
    try std.testing.expectEqualStrings("/b/dir", t.blocker("/b", true, &.{}, 102, &buf).?);
    try std.testing.expect(t.blocker("/b/other/new", false, &.{}, 102, &buf) == null);
    var found: [2]Lock = undefined;
    try std.testing.expectEqual(@as(usize, 1), t.discover("/b/dir/f", 102, &found));
    _ = try t.refresh("/b/dir/f", &.{&a.token}, 100, 105);
    try std.testing.expect(t.valid("/b/dir", &a.token, 150));
    try std.testing.expectError(error.NoMatch, t.release("/b/elsewhere", &a.token, 150));
    try t.release("/b/dir", &a.token, 150);
    try std.testing.expect(!t.valid("/b/dir", &a.token, 150));
    const s = try t.acquire(.{ .path = "/b/s", .scope = .shared, .timeout_s = 5 }, 200);
    const s2 = try t.acquire(.{ .path = "/b/s", .scope = .shared, .timeout_s = 5 }, 200);
    try std.testing.expect(t.blocker("/b/s", false, &.{&s2.token}, 201, &buf) == null);
    try std.testing.expect(t.blocker("/b/s", false, &.{}, 201, &buf) != null);
    try std.testing.expect(t.blocker("/b/s", false, &.{}, 205, &buf) == null);
    _ = s;
    t.dropUnder("/b");
    try std.testing.expect(t.blocker("/b/other", false, &.{}, 205, &buf) == null);
}

test "lock table is bounded" {
    const t = try std.testing.allocator.create(Table);
    defer std.testing.allocator.destroy(t);
    t.* = .{};
    var pb: [32]u8 = undefined;
    for (0..max_locks) |i| _ = try t.acquire(.{ .path = try std.fmt.bufPrint(&pb, "/b/{d}", .{i}) }, 0);
    try std.testing.expectError(error.Full, t.acquire(.{ .path = "/b/x" }, 0));
    _ = try t.acquire(.{ .path = "/b/x" }, default_timeout_s + 1);
}

test "timeout header" {
    try std.testing.expectEqual(default_timeout_s, parseTimeout(null));
    try std.testing.expectEqual(@as(u32, 60), parseTimeout("Second-60"));
    try std.testing.expectEqual(max_timeout_s, parseTimeout("Infinite, Second-4100000000"));
    try std.testing.expectEqual(max_timeout_s, parseTimeout("Second-999999999999"));
    try std.testing.expectEqual(@as(u32, 30), parseTimeout("bogus, Second-30"));
}
