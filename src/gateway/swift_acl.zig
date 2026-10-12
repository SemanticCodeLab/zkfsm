//! Swift container ACLs (X-Container-Read / X-Container-Write): referrer grants
//! (`.r:*`, `.r:host`, `.r:-host`, `.rlistings`) and user grants (`account`,
//! `account:user`, `*:user`, `*:*`).
const std = @import("std");

pub const max_len = 256;

/// The authenticated caller as ACLs see it; null fields never match.
pub const Who = struct { account: []const u8, user: []const u8 };

const Elem = union(enum) {
    referrer: struct { host: []const u8, deny: bool },
    listings,
    user: struct { account: []const u8, user: []const u8 },
};

const Iter = struct {
    it: std.mem.TokenIterator(u8, .scalar),

    fn next(i: *Iter) ?Elem {
        while (i.it.next()) |raw| {
            const e = std.mem.trim(u8, raw, " \t");
            if (e.len == 0) continue;
            if (std.mem.eql(u8, e, ".rlistings")) return .listings;
            if (cutPrefix(e, ".r:") orelse cutPrefix(e, ".ref:") orelse cutPrefix(e, ".referer:") orelse cutPrefix(e, ".referrer:")) |h| {
                const host = std.mem.trim(u8, h, " \t");
                if (host.len > 0 and host[0] == '-') return .{ .referrer = .{ .host = host[1..], .deny = true } };
                return .{ .referrer = .{ .host = host, .deny = false } };
            }
            if (std.mem.indexOfScalar(u8, e, ':')) |c| return .{ .user = .{ .account = e[0..c], .user = e[c + 1 ..] } };
            return .{ .user = .{ .account = e, .user = "*" } };
        }
        return null;
    }
};

fn cutPrefix(s: []const u8, p: []const u8) ?[]const u8 {
    return if (std.mem.startsWith(u8, s, p)) s[p.len..] else null;
}

fn iter(acl: []const u8) Iter {
    return .{ .it = std.mem.tokenizeScalar(u8, acl, ',') };
}

/// Well-formed and storable; a write ACL may not name referrers.
pub fn valid(acl: []const u8, write: bool) bool {
    if (acl.len > max_len) return false;
    for (acl) |c| if (c < 0x20 or c == 0x7f) return false;
    var it = iter(acl);
    while (it.next()) |e| switch (e) {
        .referrer => |r| if (write or r.host.len == 0) return false,
        .listings => if (write) return false,
        .user => |u| if (u.account.len == 0 or u.user.len == 0 or u.account[0] == '.') return false,
    };
    return true;
}

/// Host of a Referer URL, without port or credentials.
fn refererHost(referer: []const u8) []const u8 {
    var s = referer;
    if (std.mem.indexOf(u8, s, "://")) |i| s = s[i + 3 ..];
    if (std.mem.indexOfAny(u8, s, "/?#")) |i| s = s[0..i];
    if (std.mem.lastIndexOfScalar(u8, s, '@')) |i| s = s[i + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |i| s = s[0..i];
    return s;
}

fn hostMatches(pattern: []const u8, host: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    if (pattern.len > 0 and pattern[0] == '.') return host.len >= pattern.len and std.ascii.eqlIgnoreCase(host[host.len - pattern.len ..], pattern);
    return std.ascii.eqlIgnoreCase(pattern, host);
}

/// Referrer rules in order; the last matching one decides.
fn referrerAllowed(acl: []const u8, referer: ?[]const u8) bool {
    const host = refererHost(referer orelse "");
    var ok = false;
    var it = iter(acl);
    while (it.next()) |e| switch (e) {
        .referrer => |r| if (hostMatches(r.host, host)) {
            ok = !r.deny;
        },
        else => {},
    };
    return ok;
}

fn userAllowed(acl: []const u8, who: ?Who) bool {
    const w = who orelse return false;
    var it = iter(acl);
    while (it.next()) |e| switch (e) {
        .user => |u| {
            const acct_ok = std.mem.eql(u8, u.account, "*") or std.mem.eql(u8, u.account, w.account);
            const user_ok = std.mem.eql(u8, u.user, "*") or std.mem.eql(u8, u.user, w.user);
            if (acct_ok and user_ok) return true;
        },
        else => {},
    };
    return false;
}

fn hasListings(acl: []const u8) bool {
    var it = iter(acl);
    while (it.next()) |e| if (e == .listings) return true;
    return false;
}

/// Object GET/HEAD under the read ACL.
pub fn mayRead(acl: []const u8, who: ?Who, referer: ?[]const u8) bool {
    return userAllowed(acl, who) or referrerAllowed(acl, referer);
}

/// Container listing: user grants, or referrer grants together with `.rlistings`.
pub fn mayList(acl: []const u8, who: ?Who, referer: ?[]const u8) bool {
    return userAllowed(acl, who) or (hasListings(acl) and referrerAllowed(acl, referer));
}

/// Object PUT/POST/DELETE under the write ACL.
pub fn mayWrite(acl: []const u8, who: ?Who) bool {
    return userAllowed(acl, who);
}

test "referrer grants" {
    try std.testing.expect(mayRead(".r:*", null, null));
    try std.testing.expect(!mayList(".r:*", null, null));
    try std.testing.expect(mayList(".r:*,.rlistings", null, null));
    try std.testing.expect(mayRead(".r:.example.com", null, "http://www.example.com/page"));
    try std.testing.expect(!mayRead(".r:.example.com", null, "http://example.org/"));
    try std.testing.expect(!mayRead(".r:*,.r:-bad.example.com", null, "https://bad.example.com:8443/x"));
    try std.testing.expect(mayRead(".r:*,.r:-bad.example.com", null, "https://ok.example.com/x"));
    try std.testing.expect(!mayRead(".r:example.com", null, null));
    try std.testing.expect(!mayRead("", null, "http://example.com"));
}

test "user grants" {
    const alice: Who = .{ .account = "test", .user = "alice" };
    try std.testing.expect(mayRead("test:alice", alice, null));
    try std.testing.expect(mayRead("other:bob, test", alice, null));
    try std.testing.expect(mayRead("*:alice", alice, null));
    try std.testing.expect(mayWrite("*:*", alice));
    try std.testing.expect(!mayWrite("test:bob,other:alice", alice));
    try std.testing.expect(!mayWrite("*:*", null));
    try std.testing.expect(mayList("test:alice", alice, null));
}

test "validation" {
    try std.testing.expect(valid(".r:*,.rlistings,test:alice", false));
    try std.testing.expect(!valid(".r:*", true));
    try std.testing.expect(!valid(".rlistings", true));
    try std.testing.expect(!valid(".r:", false));
    try std.testing.expect(!valid(":alice", false));
    try std.testing.expect(!valid(".bogus", false));
    try std.testing.expect(valid("test:alice,*:bob", true));
    try std.testing.expect(!valid("a" ** 300, false));
}
