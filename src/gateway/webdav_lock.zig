//! WebDAV write locks: bounded tables, expiry, opaquelocktoken UUIDs. `Store`
//! keeps each bucket's locks in a bucket document of the object layer, so every
//! node of a cluster (and a restarted server) sees the same locks.
const std = @import("std");
const object = @import("../object/root.zig");

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

pub const Error = error{ Locked, Full, TooLong, NoMatch, Storage };

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

/// Lock operations over a slice of slots (`used` marks live ones).
const Slots = struct {
    fn expire(ls: []Lock, now: i64) void {
        for (ls) |*l| if (l.used and l.expires_s <= now) {
            l.used = false;
        };
    }

    fn acquire(ls: []Lock, r: Request, now: i64) Error!Lock {
        if (r.path.len > max_path) return error.TooLong;
        expire(ls, now);
        var free: ?*Lock = null;
        for (ls) |*l| {
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

    fn refresh(ls: []Lock, p: []const u8, tokens: []const []const u8, timeout_s: u32, now: i64) Error!Lock {
        expire(ls, now);
        for (ls) |*l| if (l.used and covers(l, p) and has(tokens, &l.token)) {
            l.timeout_s = @min(timeout_s, max_timeout_s);
            l.expires_s = now + l.timeout_s;
            return l.*;
        };
        return error.NoMatch;
    }

    fn release(ls: []Lock, p: []const u8, token: []const u8, now: i64) Error!void {
        expire(ls, now);
        for (ls) |*l| if (l.used and covers(l, p) and std.mem.eql(u8, &l.token, token)) {
            l.used = false;
            return;
        };
        return error.NoMatch;
    }

    fn blocker(ls: []Lock, p: []const u8, recursive: bool, tokens: []const []const u8, now: i64, buf: []u8) ?[]const u8 {
        expire(ls, now);
        var shared_ok = false;
        for (ls) |*l| if (l.used and l.scope == .shared and covers(l, p) and has(tokens, &l.token)) {
            shared_ok = true;
        };
        for (ls) |*l| {
            if (!l.used or !affects(l, p, recursive) or has(tokens, &l.token)) continue;
            if (l.scope == .shared and shared_ok and covers(l, p)) continue;
            const n = @min(buf.len, l.path_len);
            @memcpy(buf[0..n], l.path_buf[0..n]);
            return buf[0..n];
        }
        return null;
    }

    fn valid(ls: []Lock, p: []const u8, token: []const u8, now: i64) bool {
        expire(ls, now);
        for (ls) |*l| if (l.used and covers(l, p) and std.mem.eql(u8, &l.token, token)) return true;
        return false;
    }

    fn discover(ls: []Lock, p: []const u8, now: i64, out: []Lock) usize {
        expire(ls, now);
        var n: usize = 0;
        for (ls) |*l| if (l.used and covers(l, p) and n < out.len) {
            out[n] = l.*;
            n += 1;
        };
        return n;
    }

    /// True when any lock was dropped.
    fn dropUnder(ls: []Lock, p: []const u8) bool {
        var any = false;
        for (ls) |*l| if (l.used and within(p, l.path())) {
            l.used = false;
            any = true;
        };
        return any;
    }
};

/// One process-local table.
pub const Table = struct {
    mu: std.Thread.Mutex = .{},
    locks: [max_locks]Lock = [_]Lock{.{}} ** max_locks,

    /// Grants a new lock or fails with Locked on conflict.
    pub fn acquire(t: *Table, r: Request, now: i64) Error!Lock {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.acquire(&t.locks, r, now);
    }

    /// Extends a lock on `p` whose token was submitted.
    pub fn refresh(t: *Table, p: []const u8, tokens: []const []const u8, timeout_s: u32, now: i64) Error!Lock {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.refresh(&t.locks, p, tokens, timeout_s, now);
    }

    pub fn release(t: *Table, p: []const u8, token: []const u8, now: i64) Error!void {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.release(&t.locks, p, token, now);
    }

    /// Path of a lock that blocks writing `p` without the submitted tokens, else null.
    /// Holding any shared lock on the resource satisfies the other shared locks.
    pub fn blocker(t: *Table, p: []const u8, recursive: bool, tokens: []const []const u8, now: i64, buf: []u8) ?[]const u8 {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.blocker(&t.locks, p, recursive, tokens, now, buf);
    }

    /// True when `token` names a live lock covering `p`.
    pub fn valid(t: *Table, p: []const u8, token: []const u8, now: i64) bool {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.valid(&t.locks, p, token, now);
    }

    /// Copies the live locks covering `p` into `out`; returns how many.
    pub fn discover(t: *Table, p: []const u8, now: i64, out: []Lock) usize {
        t.mu.lock();
        defer t.mu.unlock();
        return Slots.discover(&t.locks, p, now, out);
    }

    /// Drops every lock rooted at or below `p` (after DELETE or MOVE).
    pub fn dropUnder(t: *Table, p: []const u8) void {
        t.mu.lock();
        defer t.mu.unlock();
        _ = Slots.dropUnder(&t.locks, p);
    }
};

/// Shared locks: per bucket, a document in the object layer guarded by a
/// cluster lock. Locks on "/" itself stay in the local table.
pub const Store = struct {
    gpa: std.mem.Allocator,
    svc: *object.ObjectService,
    local: Table = .{},

    const kind = object.bucket_meta.Kind.webdav_locks;

    fn bucketOf(p: []const u8) ?[]const u8 {
        const t = std.mem.trimLeft(u8, p, "/");
        if (t.len == 0) return null;
        return t[0 .. std.mem.indexOfScalar(u8, t, '/') orelse t.len];
    }

    /// Live locks of `bucket` plus `spare` free slots, in `arena`.
    fn load(s: *Store, arena: std.mem.Allocator, bucket: []const u8, now: i64, spare: usize) Error![]Lock {
        const doc = object.bucket_meta.get(s.svc, arena, bucket, kind) catch |e| switch (e) {
            error.NoSuchBucket, error.InvalidBucketName => null,
            error.OutOfMemory => return error.Full,
            else => return error.Storage,
        };
        return decode(arena, doc orelse "", now, spare) catch error.Storage;
    }

    fn save(s: *Store, arena: std.mem.Allocator, bucket: []const u8, ls: []const Lock) Error!void {
        const doc = encode(arena, ls) catch return error.Full;
        object.bucket_meta.set(s.svc, bucket, kind, doc) catch return error.Storage;
    }

    /// Runs `op` on the bucket's locks under the cluster lock and stores the result.
    fn mutate(s: *Store, bucket: []const u8, now: i64, spare: usize, ctx: anytype, comptime op: anytype) @TypeOf(op(ctx, @as([]Lock, &.{}))) {
        s.local.mu.lock();
        defer s.local.mu.unlock();
        const held = s.svc.clusterLock("davlock", bucket, "") catch return error.Storage;
        defer s.svc.clusterUnlock(held);
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const ls = try s.load(arena.allocator(), bucket, now, spare);
        const out = try op(ctx, ls);
        try s.save(arena.allocator(), bucket, ls);
        return out;
    }

    pub fn acquire(s: *Store, r: Request, now: i64) Error!Lock {
        const b = bucketOf(r.path) orelse return s.local.acquire(r, now);
        const C = struct {
            r: Request,
            now: i64,
            fn f(c: @This(), ls: []Lock) Error!Lock {
                return Slots.acquire(ls, c.r, c.now);
            }
        };
        return s.mutate(b, now, 1, C{ .r = r, .now = now }, C.f);
    }

    pub fn refresh(s: *Store, p: []const u8, tokens: []const []const u8, timeout_s: u32, now: i64) Error!Lock {
        const b = bucketOf(p) orelse return s.local.refresh(p, tokens, timeout_s, now);
        const C = struct {
            p: []const u8,
            tokens: []const []const u8,
            t: u32,
            now: i64,
            fn f(c: @This(), ls: []Lock) Error!Lock {
                return Slots.refresh(ls, c.p, c.tokens, c.t, c.now);
            }
        };
        return s.mutate(b, now, 0, C{ .p = p, .tokens = tokens, .t = timeout_s, .now = now }, C.f);
    }

    pub fn release(s: *Store, p: []const u8, token: []const u8, now: i64) Error!void {
        const b = bucketOf(p) orelse return s.local.release(p, token, now);
        const C = struct {
            p: []const u8,
            token: []const u8,
            now: i64,
            fn f(c: @This(), ls: []Lock) Error!void {
                return Slots.release(ls, c.p, c.token, c.now);
            }
        };
        return s.mutate(b, now, 0, C{ .p = p, .token = token, .now = now }, C.f);
    }

    /// As `Table.blocker`; an unreadable lock document blocks (fails closed).
    pub fn blocker(s: *Store, p: []const u8, recursive: bool, tokens: []const []const u8, now: i64, buf: []u8) ?[]const u8 {
        if (s.local.blocker(p, recursive, tokens, now, buf)) |l| return l;
        const b = bucketOf(p) orelse return null;
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const ls = s.load(arena.allocator(), b, now, 0) catch {
            const n = @min(buf.len, p.len);
            @memcpy(buf[0..n], p[0..n]);
            return buf[0..n];
        };
        return Slots.blocker(ls, p, recursive, tokens, now, buf);
    }

    pub fn valid(s: *Store, p: []const u8, token: []const u8, now: i64) bool {
        if (s.local.valid(p, token, now)) return true;
        const b = bucketOf(p) orelse return false;
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const ls = s.load(arena.allocator(), b, now, 0) catch return false;
        return Slots.valid(ls, p, token, now);
    }

    pub fn discover(s: *Store, p: []const u8, now: i64, out: []Lock) usize {
        const n = s.local.discover(p, now, out);
        const b = bucketOf(p) orelse return n;
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const ls = s.load(arena.allocator(), b, now, 0) catch return n;
        return n + Slots.discover(ls, p, now, out[n..]);
    }

    /// Drops every lock rooted at or below `p` (after DELETE or MOVE); best effort.
    pub fn dropUnder(s: *Store, p: []const u8) void {
        s.local.dropUnder(p);
        const b = bucketOf(p) orelse return;
        const C = struct {
            p: []const u8,
            fn f(c: @This(), ls: []Lock) Error!void {
                if (!Slots.dropUnder(ls, c.p)) return error.NoMatch;
            }
        };
        s.mutate(b, std.time.timestamp(), 0, C{ .p = p }, C.f) catch {};
    }
};

const doc_version: u8 = 1;

/// Live locks as a compact binary document.
fn encode(arena: std.mem.Allocator, ls: []const Lock) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, doc_version);
    for (ls) |*l| if (l.used) {
        try out.appendSlice(arena, &l.token);
        var hdr: [2 + 1 + 2 + 4 + 8]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], l.path_len, .little);
        hdr[2] = @as(u8, @intFromBool(l.infinite)) | @as(u8, @intFromBool(l.scope == .shared)) << 1 | @as(u8, @intFromBool(l.owner_href)) << 2;
        std.mem.writeInt(u16, hdr[3..5], l.owner_len, .little);
        std.mem.writeInt(u32, hdr[5..9], l.timeout_s, .little);
        std.mem.writeInt(i64, hdr[9..17], l.expires_s, .little);
        try out.appendSlice(arena, &hdr);
        try out.appendSlice(arena, l.path());
        try out.appendSlice(arena, l.owner());
    };
    return if (out.items.len == 1) "" else out.items;
}

/// Unexpired locks of a document plus `spare` free slots (bounded by max_locks).
fn decode(arena: std.mem.Allocator, doc: []const u8, now: i64, spare: usize) error{ OutOfMemory, Corrupt }![]Lock {
    var list: std.ArrayList(Lock) = .empty;
    if (doc.len > 0) {
        if (doc[0] != doc_version) return error.Corrupt;
        var i: usize = 1;
        while (i < doc.len) {
            if (doc.len - i < token_len + 17) return error.Corrupt;
            var l: Lock = .{ .used = true };
            @memcpy(&l.token, doc[i..][0..token_len]);
            const h = doc[i + token_len ..][0..17];
            const pl = std.mem.readInt(u16, h[0..2], .little);
            const ol = std.mem.readInt(u16, h[3..5], .little);
            if (pl > max_path or ol > max_owner) return error.Corrupt;
            l.infinite = h[2] & 1 != 0;
            l.scope = if (h[2] & 2 != 0) .shared else .exclusive;
            l.owner_href = h[2] & 4 != 0;
            l.timeout_s = std.mem.readInt(u32, h[5..9], .little);
            l.expires_s = std.mem.readInt(i64, h[9..17], .little);
            i += token_len + 17;
            if (doc.len - i < @as(usize, pl) + ol) return error.Corrupt;
            @memcpy(l.path_buf[0..pl], doc[i..][0..pl]);
            l.path_len = pl;
            @memcpy(l.owner_buf[0..ol], doc[i + pl ..][0..ol]);
            l.owner_len = ol;
            i += @as(usize, pl) + ol;
            if (l.expires_s > now and list.items.len < max_locks) try list.append(arena, l);
        }
    }
    const room = @min(spare, max_locks -| list.items.len);
    try list.appendNTimes(arena, .{}, room);
    return list.items;
}

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

test "lock documents round trip and drop expired" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ls = try decode(a, "", 0, 3);
    const x = try Slots.acquire(ls, .{ .path = "/b/x", .owner = "me", .owner_href = true, .timeout_s = 10 }, 100);
    _ = try Slots.acquire(ls, .{ .path = "/b/y", .scope = .shared, .infinite = false, .timeout_s = 1000 }, 100);
    const doc = try encode(a, ls);
    const back = try decode(a, doc, 105, 0);
    try std.testing.expectEqual(@as(usize, 2), back.len);
    try std.testing.expectEqualSlices(u8, &x.token, &back[0].token);
    try std.testing.expectEqualStrings("me", back[0].owner());
    try std.testing.expect(back[0].owner_href and back[0].infinite and back[1].scope == .shared and !back[1].infinite);
    try std.testing.expectEqual(@as(usize, 1), (try decode(a, doc, 200, 0)).len);
    try std.testing.expectError(error.Corrupt, decode(a, doc[0 .. doc.len - 1], 0, 0));
    try std.testing.expectError(error.Corrupt, decode(a, "\x09", 0, 0));
}

test "timeout header" {
    try std.testing.expectEqual(default_timeout_s, parseTimeout(null));
    try std.testing.expectEqual(@as(u32, 60), parseTimeout("Second-60"));
    try std.testing.expectEqual(max_timeout_s, parseTimeout("Infinite, Second-4100000000"));
    try std.testing.expectEqual(max_timeout_s, parseTimeout("Second-999999999999"));
    try std.testing.expectEqual(@as(u32, 30), parseTimeout("bogus, Second-30"));
}
