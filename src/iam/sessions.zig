//! STS session bookkeeping: a bounded registry of issued sessions (for access-key
//! listings) and per-user revocation cut-offs checked on every token use.
const std = @import("std");
const store_mod = @import("store.zig");
const sts = @import("sts.zig");

const Allocator = std.mem.Allocator;
const Store = store_mod.Store;
const Snapshot = store_mod.Snapshot;
const Session = store_mod.Session;
const Revocation = store_mod.Revocation;

pub const max_sessions = 4096;
pub const max_revocations = 4096;

pub const VerifyError = sts.ValidateError || error{Revoked};

/// Validates the token for `access_key`, then rejects it when revoked.
pub fn verify(issuer: *const sts.Issuer, st: *Store, access_key: []const u8, token: []const u8, now_s: i64, buf: *sts.DecodeBuffer) VerifyError!sts.Claims {
    const c = try issuer.verify(access_key, token, now_s, buf);
    if (revoked(st, c)) return error.Revoked;
    return c;
}

pub fn revoked(st: *Store, c: sts.Claims) bool {
    const v = st.view();
    defer v.release();
    for (v.snap.revocations) |r| if (covers(r, c.parent, @tagName(c.provider), c.token_type) and c.issued_ms <= r.before_ms) return true;
    return false;
}

fn covers(r: Revocation, user: []const u8, provider: []const u8, token_type: []const u8) bool {
    if (!std.mem.eql(u8, r.user, user)) return false;
    if (r.provider.len > 0 and !std.mem.eql(u8, r.provider, provider)) return false;
    return r.token_type.len == 0 or std.mem.eql(u8, r.token_type, token_type);
}

const RecordCtx = struct { s: Session, now_s: i64 };

/// Adds an issued session; expired entries are pruned and the oldest dropped at the cap.
pub fn record(st: *Store, s: Session, now_s: i64) store_mod.StoreError!void {
    try st.mutate(RecordCtx{ .s = s, .now_s = now_s }, struct {
        fn f(c: RecordCtx, a: Allocator, next: *Snapshot) store_mod.StoreError!void {
            var keep: std.ArrayList(Session) = .empty;
            const live = next.sessions;
            const skip = (countLive(live, c.now_s) + 1) -| max_sessions;
            var dropped: usize = 0;
            for (live) |x| {
                if (x.expires_s <= c.now_s) continue;
                if (dropped < skip) {
                    dropped += 1;
                    continue;
                }
                try keep.append(a, x);
            }
            try keep.append(a, c.s);
            next.sessions = keep.items;
        }
    }.f);
}

fn countLive(xs: []const Session, now_s: i64) usize {
    var n: usize = 0;
    for (xs) |x| n += @intFromBool(x.expires_s > now_s);
    return n;
}

pub const RevokeError = store_mod.StoreError || error{TooManyRevocations};

const RevokeCtx = struct { r: Revocation, now_ms: i64, removed: *usize, err: *?RevokeError };

/// Revokes sessions of `user` issued up to `now_ms`; returns how many listed sessions it removed.
pub fn revoke(st: *Store, user: []const u8, provider: []const u8, token_type: []const u8, now_ms: i64) RevokeError!usize {
    var removed: usize = 0;
    var err: ?RevokeError = null;
    const ctx: RevokeCtx = .{ .r = .{ .user = user, .provider = provider, .token_type = token_type, .before_ms = now_ms }, .now_ms = now_ms, .removed = &removed, .err = &err };
    st.mutate(ctx, struct {
        fn f(c: RevokeCtx, a: Allocator, next: *Snapshot) store_mod.StoreError!void {
            // Cut-offs older than the longest session lifetime cover nothing still valid.
            const horizon = c.now_ms - sts.limits.max_duration_s * 1000;
            var rs: std.ArrayList(Revocation) = .empty;
            for (next.revocations) |r| {
                if (r.before_ms < horizon) continue;
                if (std.mem.eql(u8, r.user, c.r.user) and std.mem.eql(u8, r.provider, c.r.provider) and std.mem.eql(u8, r.token_type, c.r.token_type)) continue;
                try rs.append(a, r);
            }
            if (rs.items.len >= max_revocations) {
                c.err.* = error.TooManyRevocations;
                return error.LimitExceeded;
            }
            try rs.append(a, c.r);
            next.revocations = rs.items;
            var ss: std.ArrayList(Session) = .empty;
            for (next.sessions) |s| {
                if (covers(c.r, s.parent, s.provider, s.token_type) and s.issued_ms <= c.r.before_ms) {
                    c.removed.* += 1;
                    continue;
                }
                try ss.append(a, s);
            }
            next.sessions = ss.items;
        }
    }.f) catch |e| return err orelse e;
    return removed;
}

/// Live sessions from `provider`, optionally only those of `users`, copied into `a`.
pub fn list(a: Allocator, st: *Store, provider: []const u8, users: []const []const u8, now_s: i64) error{OutOfMemory}![]const Session {
    const v = st.view();
    defer v.release();
    var out: std.ArrayList(Session) = .empty;
    for (v.snap.sessions) |s| {
        if (s.expires_s <= now_s or !std.mem.eql(u8, s.provider, provider)) continue;
        if (users.len > 0) {
            const hit = for (users) |u| {
                if (std.mem.eql(u8, u, s.parent)) break true;
            } else false;
            if (!hit) continue;
        }
        try out.append(a, .{
            .access_key = try a.dupe(u8, s.access_key),
            .parent = try a.dupe(u8, s.parent),
            .provider = try a.dupe(u8, s.provider),
            .token_type = try a.dupe(u8, s.token_type),
            .issued_ms = s.issued_ms,
            .expires_s = s.expires_s,
        });
    }
    return out.items;
}

test "revocation cut-off, provider and type filters, registry" {
    const a = std.testing.allocator;
    var mem: store_mod.MemoryPersistence = .{ .gpa = a };
    defer mem.deinit();
    var st: Store = undefined;
    try st.open(a, mem.persistence(), .{ .root_access_key = "root" });
    defer st.deinit();
    const issuer: sts.Issuer = .{ .key = @splat(3) };
    var prng = std.Random.DefaultPrng.init(5);
    var c1 = try issuer.issue(a, .{ .parent = "dn1", .provider = .ldap, .token_type = "ci", .issued_ms = 1000_000 }, 1000, prng.random());
    defer c1.deinit(a);
    var c2 = try issuer.issue(a, .{ .parent = "dn1", .provider = .ldap, .issued_ms = 1000_000 }, 1000, prng.random());
    defer c2.deinit(a);
    try record(&st, .{ .access_key = &c1.access_key, .parent = "dn1", .provider = "ldap", .token_type = "ci", .issued_ms = 1000_000, .expires_s = c1.expires_s }, 1000);
    try record(&st, .{ .access_key = &c2.access_key, .parent = "dn1", .provider = "ldap", .issued_ms = 1000_000, .expires_s = c2.expires_s }, 1000);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    try std.testing.expectEqual(@as(usize, 2), (try list(arena.allocator(), &st, "ldap", &.{"dn1"}, 1000)).len);
    try std.testing.expectEqual(@as(usize, 0), (try list(arena.allocator(), &st, "openid", &.{}, 1000)).len);
    var buf: sts.DecodeBuffer = undefined;
    _ = try verify(&issuer, &st, &c1.access_key, c1.session_token, 1001, &buf);
    try std.testing.expectEqual(@as(usize, 0), try revoke(&st, "dn1", "openid", "", 1001_000));
    _ = try verify(&issuer, &st, &c1.access_key, c1.session_token, 1001, &buf);
    try std.testing.expectEqual(@as(usize, 1), try revoke(&st, "dn1", "ldap", "ci", 1001_000));
    try std.testing.expectError(error.Revoked, verify(&issuer, &st, &c1.access_key, c1.session_token, 1001, &buf));
    _ = try verify(&issuer, &st, &c2.access_key, c2.session_token, 1001, &buf);
    try std.testing.expectEqual(@as(usize, 1), try revoke(&st, "dn1", "", "", 1001_000));
    try std.testing.expectError(error.Revoked, verify(&issuer, &st, &c2.access_key, c2.session_token, 1001, &buf));
    var c3 = try issuer.issue(a, .{ .parent = "dn1", .provider = .ldap, .issued_ms = 1002_000 }, 1002, prng.random());
    defer c3.deinit(a);
    _ = try verify(&issuer, &st, &c3.access_key, c3.session_token, 1002, &buf);
}
