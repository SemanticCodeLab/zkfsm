//! Login and authorization shared by the gateways: credentials come from the IAM
//! store, decisions from the IAM evaluator plus the target bucket's policy.
const std = @import("std");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");

pub const Op = iam.actions.Op;

/// An authenticated caller. `key` is a copy owned by the session.
pub const Principal = struct {
    key_buf: [iam.store.limits.max_name]u8 = undefined,
    key_len: u8 = 0,
    /// Anonymous mode (no IAM store): everything is allowed.
    open: bool = false,

    pub fn accessKey(p: *const Principal) []const u8 {
        return p.key_buf[0..p.key_len];
    }

    pub fn of(access_key: []const u8) error{NameTooLong}!Principal {
        var p: Principal = .{};
        if (access_key.len > p.key_buf.len) return error.NameTooLong;
        @memcpy(p.key_buf[0..access_key.len], access_key);
        p.key_len = @intCast(access_key.len);
        return p;
    }
};

pub const Access = struct {
    svc: *object.ObjectService,
    /// Null: anonymous server, any login is accepted and everything is allowed.
    iam: ?*iam.Store = null,

    /// Password login: the IAM access key and its secret, compared in constant time.
    pub fn login(a: Access, user: []const u8, password: []const u8) ?Principal {
        const st = a.iam orelse {
            var p = Principal.of(user) catch Principal{};
            p.open = true;
            return p;
        };
        var buf: iam.Store.SecretBuf = undefined;
        const secret = st.secretFor(user, std.time.timestamp(), &buf) orelse return null;
        if (!ctEql(secret, password)) return null;
        return Principal.of(user) catch null;
    }

    /// Principal for a key proven by other means (public key, token); null if unusable.
    pub fn known(a: Access, access_key: []const u8) ?Principal {
        const st = a.iam orelse {
            var p = Principal.of(access_key) catch Principal{};
            p.open = true;
            return p;
        };
        var buf: iam.Store.SecretBuf = undefined;
        _ = st.secretFor(access_key, std.time.timestamp(), &buf) orelse return null;
        return Principal.of(access_key) catch null;
    }

    /// Root (or a service account of root) reaches every tenant's buckets.
    pub fn isRoot(a: Access, who: *const Principal) bool {
        if (who.open) return true;
        const st = a.iam orelse return true;
        const v = st.view();
        defer v.release();
        if (v.isRoot(who.accessKey())) return true;
        const sa = v.serviceAccount(who.accessKey()) orelse return false;
        return v.isRoot(sa.parent);
    }

    /// The caller's tenant ("" = global); null when its tenant is removed or disabled.
    pub fn tenant(a: Access, who: *const Principal, buf: *[iam.store.limits.max_name]u8) ?[]const u8 {
        const st = a.iam orelse return "";
        if (who.open) return "";
        const t = st.tenantOf(who.accessKey(), buf) orelse return "";
        return if (iam.federation.tenantUsable(st, t)) t else null;
    }

    /// Tenant boundary: non-root callers reach only buckets of their own tenant.
    pub fn mayReach(a: Access, who: *const Principal, bucket: []const u8) bool {
        if (a.iam == null or who.open or a.isRoot(who)) return true;
        var buf: [iam.store.limits.max_name]u8 = undefined;
        const t = a.tenant(who, &buf) orelse return false;
        var sfa = std.heap.stackFallback(1024, a.svc.gpa);
        var arena = std.heap.ArenaAllocator.init(sfa.get());
        defer arena.deinit();
        const owner = object.tenancy.tenantOf(a.svc, arena.allocator(), bucket) catch |e| return e == error.NoSuchBucket;
        return std.mem.eql(u8, owner, t);
    }

    /// Buckets visible to `who`: all for root, else its tenant's (or the global ones).
    pub fn visibleBuckets(a: Access, arena: std.mem.Allocator, who: *const Principal) object.Error![]object.BucketInfo {
        if (a.iam == null or a.isRoot(who)) return a.svc.listBuckets(arena);
        var buf: [iam.store.limits.max_name]u8 = undefined;
        const t = a.tenant(who, &buf) orelse return &.{};
        return object.tenancy.listOwned(a.svc, arena, t);
    }

    /// Creates a bucket owned by the caller's tenant.
    pub fn createBucket(a: Access, who: *const Principal, name: []const u8) object.Error!void {
        var buf: [iam.store.limits.max_name]u8 = undefined;
        const t = (if (a.isRoot(who)) "" else a.tenant(who, &buf)) orelse return error.InvalidRequest;
        return object.tenancy.createOwned(a.svc, name, t);
    }

    /// True when `who` may perform `op` on bucket/key. `peer` feeds aws:SourceIp.
    pub fn allowed(a: Access, who: *const Principal, op: Op, bucket: []const u8, key: []const u8, peer: ?std.net.Address, secure: bool) bool {
        if (who.open) return true;
        const st = a.iam orelse return true;
        if (bucket.len > 0 and !a.mayReach(who, bucket)) return false;
        if (bucket.len == 0) {
            var tb: [iam.store.limits.max_name]u8 = undefined;
            if (a.tenant(who, &tb) == null) return false;
        }
        var sfa = std.heap.stackFallback(16 * 1024, a.svc.gpa);
        var arena_state = std.heap.ArenaAllocator.init(sfa.get());
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var bucket_policy: ?iam.Policy = null;
        if (bucket.len > 0) {
            if (object.policy.get(a.svc, arena, bucket) catch null) |doc| {
                bucket_policy = iam.policy.parse(arena, doc) catch null;
            }
        }
        var arn_buf: [2048]u8 = undefined;
        const arn = iam.actions.resourceArn(&arn_buf, op, bucket, key) catch return false;
        var entries: [3]iam.context.Entry = undefined;
        var n: usize = 0;
        var ip_buf: [64]u8 = undefined;
        var ip_val: [1][]const u8 = undefined;
        if (peer) |addr| if (hostOf(addr, &ip_buf)) |h| {
            ip_val[0] = h;
            entries[n] = .{ .key = "aws:SourceIp", .values = &ip_val };
            n += 1;
        };
        const tls_val: [1][]const u8 = .{if (secure) "true" else "false"};
        entries[n] = .{ .key = "aws:SecureTransport", .values = &tls_val };
        n += 1;
        const now = std.time.timestamp();
        const ctx: iam.Context = .{
            .entries = entries[0..n],
            .now_s = now,
            .resource_policy = if (bucket_policy) |*p| p else null,
        };
        return st.authorize(.{ .access_key = who.accessKey() }, iam.actions.mapping(op).action, arn, &ctx).allowed();
    }
};

fn hostOf(addr: std.net.Address, buf: []u8) ?[]const u8 {
    const s = std.fmt.bufPrint(buf, "{f}", .{addr}) catch return null;
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse s.len;
    return std.mem.trim(u8, s[0..colon], "[]");
}

/// Constant-time equality; the length is not secret.
pub fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var d: u8 = 0;
    for (a, b) |x, y| d |= x ^ y;
    return d == 0;
}

test "ctEql" {
    try std.testing.expect(ctEql("abc", "abc"));
    try std.testing.expect(!ctEql("abc", "abd"));
    try std.testing.expect(!ctEql("abc", "ab"));
}
