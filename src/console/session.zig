//! In-memory console sessions keyed by a random cookie id. Each holds temporary
//! credentials from STS, never the user's long-term secret.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const id_len = 43; // 32 random bytes, url-safe base64 without padding
pub const Id = [id_len]u8;

pub const limits = struct {
    pub const max_sessions = 4096;
    pub const max_pending = 256;
    pub const pending_ttl_s = 600;
};

pub const Session = struct {
    user: []const u8,
    access_key: []const u8,
    secret_key: []const u8,
    session_token: []const u8,
    provider: []const u8,
    expires_s: i64,
};

/// OpenID login in flight: the `state` value maps back to its provider.
pub const Pending = struct {
    provider: []const u8,
    redirect_uri: []const u8,
    created_s: i64,
};

pub const Error = error{ OutOfMemory, TooManySessions };

pub const Store = struct {
    gpa: Allocator,
    mutex: std.Thread.Mutex = .{},
    sessions: std.StringHashMapUnmanaged(Session) = .empty,
    pending: std.StringHashMapUnmanaged(Pending) = .empty,

    pub fn deinit(s: *Store) void {
        var it = s.sessions.iterator();
        while (it.next()) |e| freeSession(s.gpa, e.key_ptr.*, e.value_ptr.*);
        s.sessions.deinit(s.gpa);
        var pit = s.pending.iterator();
        while (pit.next()) |e| freePending(s.gpa, e.key_ptr.*, e.value_ptr.*);
        s.pending.deinit(s.gpa);
    }

    pub fn newId() Id {
        var raw: [32]u8 = undefined;
        std.crypto.random.bytes(&raw);
        var id: Id = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&id, &raw);
        return id;
    }

    /// Stores a copy of `v` under a fresh id.
    pub fn create(s: *Store, v: Session, now_s: i64) Error!Id {
        const id = newId();
        s.mutex.lock();
        defer s.mutex.unlock();
        s.sweepLocked(now_s);
        if (s.sessions.count() >= limits.max_sessions) return error.TooManySessions;
        const key = try s.gpa.dupe(u8, &id);
        errdefer s.gpa.free(key);
        const copy = try dupeSession(s.gpa, v);
        errdefer freeSession(s.gpa, "", copy);
        try s.sessions.put(s.gpa, key, copy);
        return id;
    }

    /// Copies the live session for `id` into `a`; null when unknown or expired.
    pub fn get(s: *Store, a: Allocator, id: []const u8, now_s: i64) error{OutOfMemory}!?Session {
        s.mutex.lock();
        defer s.mutex.unlock();
        const v = s.sessions.get(id) orelse return null;
        if (v.expires_s <= now_s) {
            s.removeLocked(id);
            return null;
        }
        return try dupeSession(a, v);
    }

    pub fn remove(s: *Store, id: []const u8) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        s.removeLocked(id);
    }

    fn removeLocked(s: *Store, id: []const u8) void {
        if (s.sessions.fetchRemove(id)) |kv| freeSession(s.gpa, kv.key, kv.value);
    }

    fn sweepLocked(s: *Store, now_s: i64) void {
        var dead: [64][]const u8 = undefined;
        var n: usize = 0;
        var it = s.sessions.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.expires_s <= now_s and n < dead.len) {
                dead[n] = e.key_ptr.*;
                n += 1;
            }
        }
        for (dead[0..n]) |k| s.removeLocked(k);
    }

    pub fn putPending(s: *Store, state: []const u8, p: Pending) Error!void {
        s.mutex.lock();
        defer s.mutex.unlock();
        var dead: [16][]const u8 = undefined;
        var n: usize = 0;
        var it = s.pending.iterator();
        while (it.next()) |e| if (p.created_s - e.value_ptr.created_s > limits.pending_ttl_s and n < dead.len) {
            dead[n] = e.key_ptr.*;
            n += 1;
        };
        for (dead[0..n]) |k| if (s.pending.fetchRemove(k)) |kv| freePending(s.gpa, kv.key, kv.value);
        if (s.pending.count() >= limits.max_pending) return error.TooManySessions;
        const key = try s.gpa.dupe(u8, state);
        errdefer s.gpa.free(key);
        const prov = try s.gpa.dupe(u8, p.provider);
        errdefer s.gpa.free(prov);
        const redir = try s.gpa.dupe(u8, p.redirect_uri);
        errdefer s.gpa.free(redir);
        try s.pending.put(s.gpa, key, .{ .provider = prov, .redirect_uri = redir, .created_s = p.created_s });
    }

    /// Removes and returns the pending login (copied into `a`) if it is fresh.
    pub fn takePending(s: *Store, a: Allocator, state: []const u8, now_s: i64) error{OutOfMemory}!?Pending {
        s.mutex.lock();
        defer s.mutex.unlock();
        const kv = s.pending.fetchRemove(state) orelse return null;
        defer freePending(s.gpa, kv.key, kv.value);
        if (now_s - kv.value.created_s > limits.pending_ttl_s) return null;
        return .{ .provider = try a.dupe(u8, kv.value.provider), .redirect_uri = try a.dupe(u8, kv.value.redirect_uri), .created_s = kv.value.created_s };
    }
};

fn dupeSession(a: Allocator, v: Session) error{OutOfMemory}!Session {
    var out: Session = v;
    inline for (.{ "user", "access_key", "secret_key", "session_token", "provider" }) |f| @field(out, f) = &.{};
    errdefer freeSession(a, "", out);
    inline for (.{ "user", "access_key", "secret_key", "session_token", "provider" }) |f| @field(out, f) = try a.dupe(u8, @field(v, f));
    return out;
}

fn freeSession(a: Allocator, key: []const u8, v: Session) void {
    if (key.len > 0) a.free(key);
    std.crypto.secureZero(u8, @constCast(v.secret_key));
    inline for (.{ "user", "access_key", "secret_key", "session_token", "provider" }) |f| a.free(@field(v, f));
}

fn freePending(a: Allocator, key: []const u8, p: Pending) void {
    a.free(key);
    a.free(p.provider);
    a.free(p.redirect_uri);
}

test "sessions expire and are removed" {
    var st: Store = .{ .gpa = std.testing.allocator };
    defer st.deinit();
    const id = try st.create(.{ .user = "u", .access_key = "AK", .secret_key = "SK", .session_token = "T", .provider = "password", .expires_s = 100 }, 0);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const s = (try st.get(arena.allocator(), &id, 50)).?;
    try std.testing.expectEqualStrings("SK", s.secret_key);
    try std.testing.expect(try st.get(arena.allocator(), &id, 100) == null);
    try std.testing.expect(try st.get(arena.allocator(), "nope", 0) == null);
    const id2 = try st.create(.{ .user = "u", .access_key = "AK", .secret_key = "SK", .session_token = "", .provider = "password", .expires_s = 100 }, 0);
    st.remove(&id2);
    try std.testing.expect(try st.get(arena.allocator(), &id2, 0) == null);
    try st.putPending("state1", .{ .provider = "p", .redirect_uri = "r", .created_s = 0 });
    try std.testing.expect((try st.takePending(arena.allocator(), "state1", 10)) != null);
    try std.testing.expect((try st.takePending(arena.allocator(), "state1", 10)) == null);
}
