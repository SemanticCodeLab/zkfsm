//! Federated identities for STS: OpenID Connect tokens (discovery + cached JWKS with
//! rotation on unknown key ids) and LDAP bind-search logins, each mapped to policies
//! and an optional tenant.
const std = @import("std");
const store_mod = @import("store.zig");
const idp = @import("idp.zig");
const jwt = @import("jwt.zig");
const ldap = @import("ldap.zig");

const Allocator = std.mem.Allocator;
const Store = store_mod.Store;

pub const limits = struct {
    pub const max_discovery_bytes = 64 * 1024;
    pub const max_policies = 32;
};

pub const FetchError = error{ OutOfMemory, FetchFailed, TooLarge };

/// HTTP GET used for discovery and JWKS documents; swappable for tests.
pub const Fetcher = struct {
    ctx: ?*anyopaque = null,
    get: *const fn (ctx: ?*anyopaque, a: Allocator, url: []const u8, max: usize) FetchError![]u8 = httpGet,
};

fn httpGet(_: ?*anyopaque, a: Allocator, url: []const u8, max: usize) FetchError![]u8 {
    var client: std.http.Client = .{ .allocator = std.heap.page_allocator };
    defer client.deinit();
    const buf = try a.alloc(u8, max);
    var w: std.Io.Writer = .fixed(buf);
    const res = client.fetch(.{ .location = .{ .url = url }, .response_writer = &w, .keep_alive = false }) catch |e| return switch (e) {
        error.WriteFailed => error.TooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => error.FetchFailed,
    };
    if (res.status != .ok) return error.FetchFailed;
    return w.buffered();
}

pub const WebIdentity = struct {
    subject: []const u8,
    /// Comma-joined policy names.
    policies: []const u8,
    tenant: []const u8,
    provider: []const u8,
    /// Token expiry, when it carried one.
    expires_s: ?i64,
    issuer: []const u8,
    audience: []const u8,
};

pub const Error = error{ OutOfMemory, NoProvider, ProviderUnavailable, InvalidToken, ExpiredToken, NoPolicy, InvalidTenant };

pub const LdapIdentity = struct {
    user_dn: []const u8,
    groups: []const []const u8,
    policies: []const u8,
    tenant: []const u8,
};

pub const LdapError = error{ OutOfMemory, NotConfigured, InvalidCredentials, DirectoryUnavailable, NoPolicy, InvalidTenant };

const Cached = struct {
    config_url: []u8,
    issuer: []u8,
    keys: jwt.KeySet,
    fetched_s: i64,
    /// Last refetch attempt (successful or not); bounds refetch storms.
    tried_s: i64,

    fn destroy(c: *Cached, gpa: Allocator) void {
        gpa.free(c.config_url);
        gpa.free(c.issuer);
        c.keys.deinit();
        gpa.destroy(c);
    }
};

pub const Federation = struct {
    gpa: Allocator,
    store: *Store,
    env: idp.EnvConfig = .{},
    fetcher: Fetcher = .{},
    /// JWKS older than this are refetched before use.
    ttl_s: i64 = 3600,
    /// An unknown key id triggers a refetch at most this often per provider.
    min_refresh_s: i64 = 10,
    mutex: std.Thread.Mutex = .{},
    cache: std.StringHashMapUnmanaged(*Cached) = .empty,
    /// Providers whose first fetch failed, by name: the time of the failure.
    failed: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn deinit(self: *Federation) void {
        var fit = self.failed.keyIterator();
        while (fit.next()) |k| self.gpa.free(k.*);
        self.failed.deinit(self.gpa);
        var it = self.cache.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            e.value_ptr.*.destroy(self.gpa);
        }
        self.cache.deinit(self.gpa);
    }

    /// Validates an OpenID token and maps it to policies. `role_arn` selects a
    /// role-policy provider; otherwise claim-based providers are tried in order.
    pub fn webIdentity(self: *Federation, a: Allocator, token: []const u8, role_arn: ?[]const u8, now_s: i64) Error!WebIdentity {
        const entries = try idp.effective(a, self.store, self.env, .openid);
        var last: Error = error.NoProvider;
        for (entries) |e| {
            const p = idp.OpenId.from(e.name, e.settings);
            if (!p.enabled) continue;
            var arn_buf: [128]u8 = undefined;
            if (role_arn) |want| {
                if (!std.mem.eql(u8, p.roleArn(&arn_buf), want)) continue;
            } else if (p.role_policy.len > 0) continue;
            return self.tryProvider(a, p, token, now_s) catch |err| {
                last = moreSpecific(last, err);
                continue;
            };
        }
        return last;
    }

    fn tryProvider(self: *Federation, a: Allocator, p: idp.OpenId, token: []const u8, now_s: i64) Error!WebIdentity {
        const claims = try self.verifyWith(a, p, token, now_s);
        const subject = claims.string(p.user_claim) orelse return error.InvalidToken;
        if (subject.len == 0) return error.InvalidToken;
        var names: std.ArrayList([]const u8) = .empty;
        if (p.role_policy.len > 0) {
            var it = std.mem.tokenizeScalar(u8, p.role_policy, ',');
            while (it.next()) |n| try names.append(a, std.mem.trim(u8, n, " "));
        } else {
            const claim = try std.fmt.allocPrint(a, "{s}{s}", .{ p.claim_prefix, p.claim_name });
            const list = try claims.stringList(a, claim) orelse return error.NoPolicy;
            for (list) |n| if (names.items.len < limits.max_policies) try names.append(a, n);
        }
        const policies = try existingPolicies(a, self.store, names.items);
        if (policies.len == 0) return error.NoPolicy;
        var tenant = p.tenant;
        if (p.tenant_claim.len > 0) tenant = claims.string(p.tenant_claim) orelse return error.InvalidTenant;
        if (tenant.len > 0 and !tenantUsable(self.store, tenant)) return error.InvalidTenant;
        return .{
            .subject = subject,
            .policies = policies,
            .tenant = tenant,
            .provider = p.name,
            .expires_s = claims.int("exp"),
            .issuer = claims.string("iss") orelse "",
            .audience = p.client_id,
        };
    }

    /// Verifies against cached keys; refetches on expiry or an unknown key id.
    fn verifyWith(self: *Federation, a: Allocator, p: idp.OpenId, token: []const u8, now_s: i64) Error!jwt.Claims {
        self.mutex.lock();
        defer self.mutex.unlock();
        var c = try self.cached(p, now_s, false);
        const opts: jwt.Options = .{ .issuer = c.issuer, .audiences = &.{p.client_id} };
        return jwt.verify(a, token, &c.keys, now_s, opts) catch |e| switch (e) {
            error.UnknownKey => {
                if (now_s - c.tried_s < self.min_refresh_s) return error.InvalidToken;
                c = try self.cached(p, now_s, true);
                return jwt.verify(a, token, &c.keys, now_s, .{ .issuer = c.issuer, .audiences = &.{p.client_id} }) catch |e2| mapJwt(e2);
            },
            else => mapJwt(e),
        };
    }

    /// Caller holds `mutex`.
    fn cached(self: *Federation, p: idp.OpenId, now_s: i64, force: bool) Error!*Cached {
        if (self.cache.get(p.name)) |c| {
            const same = std.mem.eql(u8, c.config_url, p.config_url);
            if (same and !force and now_s - c.fetched_s < self.ttl_s) return c;
            if (same and now_s - c.tried_s < self.min_refresh_s) return c;
            c.tried_s = now_s;
        } else if (self.failed.get(p.name)) |t| if (now_s - t < self.min_refresh_s) return error.ProviderUnavailable;
        const fresh = self.fetch(p.config_url, now_s) catch |e| {
            // Keep serving the previous keys when a refresh fails.
            if (self.cache.get(p.name)) |c| if (std.mem.eql(u8, c.config_url, p.config_url)) return c;
            try self.noteFailure(p.name, now_s);
            return e;
        };
        const gop = self.cache.getOrPut(self.gpa, p.name) catch {
            fresh.destroy(self.gpa);
            return error.OutOfMemory;
        };
        if (gop.found_existing) {
            gop.value_ptr.*.destroy(self.gpa);
        } else {
            gop.key_ptr.* = self.gpa.dupe(u8, p.name) catch {
                self.cache.removeByPtr(gop.key_ptr);
                fresh.destroy(self.gpa);
                return error.OutOfMemory;
            };
        }
        gop.value_ptr.* = fresh;
        return fresh;
    }

    fn noteFailure(self: *Federation, name: []const u8, now_s: i64) error{OutOfMemory}!void {
        const gop = try self.failed.getOrPut(self.gpa, name);
        if (!gop.found_existing) gop.key_ptr.* = self.gpa.dupe(u8, name) catch |e| {
            self.failed.removeByPtr(gop.key_ptr);
            return e;
        };
        gop.value_ptr.* = now_s;
    }

    fn fetch(self: *Federation, config_url: []const u8, now_s: i64) Error!*Cached {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const doc = self.fetcher.get(self.fetcher.ctx, a, config_url, limits.max_discovery_bytes) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ProviderUnavailable,
        };
        const Discovery = struct { issuer: []const u8, jwks_uri: []const u8 };
        const d = std.json.parseFromSliceLeaky(Discovery, a, doc, .{ .ignore_unknown_fields = true }) catch return error.ProviderUnavailable;
        if (!std.mem.startsWith(u8, d.jwks_uri, "http://") and !std.mem.startsWith(u8, d.jwks_uri, "https://")) return error.ProviderUnavailable;
        const jwks = self.fetcher.get(self.fetcher.ctx, a, d.jwks_uri, jwt.limits.max_jwks_bytes) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ProviderUnavailable,
        };
        var keys = jwt.KeySet.parse(self.gpa, jwks) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ProviderUnavailable,
        };
        errdefer keys.deinit();
        const c = try self.gpa.create(Cached);
        errdefer self.gpa.destroy(c);
        const url = try self.gpa.dupe(u8, config_url);
        errdefer self.gpa.free(url);
        c.* = .{ .config_url = url, .issuer = try self.gpa.dupe(u8, d.issuer), .keys = keys, .fetched_s = now_s, .tried_s = now_s };
        return c;
    }

    /// LDAP bind-search login; policies come from DN mappings of the user and its groups.
    pub fn ldapIdentity(self: *Federation, a: Allocator, username: []const u8, password: []const u8) LdapError!LdapIdentity {
        const entries = try idp.effective(a, self.store, self.env, .ldap);
        const e = for (entries) |x| {
            if (std.mem.eql(u8, x.name, idp.default_name)) break x;
        } else return error.NotConfigured;
        const cfg = idp.Ldap.from(e.settings);
        if (!cfg.enabled or cfg.server_addr.len == 0) return error.NotConfigured;
        if (username.len == 0 or password.len == 0) return error.InvalidCredentials;
        const res = ldap.authenticate(a, .{
            .server_addr = cfg.server_addr,
            .tls = if (cfg.server_insecure) .none else if (cfg.server_starttls) .starttls else .ldaps,
            .tls_skip_verify = cfg.tls_skip_verify,
            .ca_file = if (cfg.tls_ca_file.len > 0) cfg.tls_ca_file else null,
            .client_cert_file = cfg.tls_client_cert,
            .client_key_file = cfg.tls_client_key,
            .lookup_bind_dn = cfg.lookup_bind_dn,
            .lookup_bind_password = cfg.lookup_bind_password,
            .user_dn_search_base = cfg.user_dn_search_base_dn,
            .user_dn_search_filter = cfg.user_dn_search_filter,
            .group_search_base = cfg.group_search_base_dn,
            .group_search_filter = cfg.group_search_filter,
        }, username, password) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidCredentials, error.UserNotFound, error.AmbiguousUser => error.InvalidCredentials,
            else => error.DirectoryUnavailable,
        };
        const mapped = try idp.ldapPolicies(a, self.store, res.user_dn, res.groups);
        var names: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, mapped, ',');
        while (it.next()) |n| try names.append(a, n);
        const policies = try existingPolicies(a, self.store, names.items);
        if (policies.len == 0) return error.NoPolicy;
        if (cfg.tenant.len > 0 and !tenantUsable(self.store, cfg.tenant)) return error.InvalidTenant;
        return .{ .user_dn = res.user_dn, .groups = res.groups, .policies = policies, .tenant = cfg.tenant };
    }
};

fn mapJwt(e: jwt.VerifyError) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Expired => error.ExpiredToken,
        else => error.InvalidToken,
    };
}

/// Prefers errors that say more about the token than "no provider".
fn moreSpecific(prev: Error, next: Error) Error {
    const rank = struct {
        fn of(e: Error) u8 {
            return switch (e) {
                error.NoProvider => 0,
                error.ProviderUnavailable => 1,
                error.InvalidToken => 2,
                error.ExpiredToken, error.NoPolicy, error.InvalidTenant => 3,
                error.OutOfMemory => 4,
            };
        }
    };
    return if (rank.of(next) >= rank.of(prev)) next else prev;
}

fn existingPolicies(a: Allocator, st: *Store, names: []const []const u8) error{OutOfMemory}![]const u8 {
    var keep: std.ArrayList([]const u8) = .empty;
    for (names) |n| {
        if (n.len == 0 or std.mem.indexOfScalar(u8, n, ',') != null or !st.policyExists(n)) continue;
        for (keep.items) |k| {
            if (std.mem.eql(u8, k, n)) break;
        } else try keep.append(a, n);
    }
    return std.mem.join(a, ",", keep.items);
}

pub fn tenantUsable(st: *Store, name: []const u8) bool {
    const v = st.view();
    defer v.release();
    for (v.snap.tenants) |t| if (std.mem.eql(u8, t.name, name)) return t.enabled;
    return false;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// Serves canned documents by URL and counts fetches.
const FakeWeb = struct {
    discovery: []const u8,
    jwks: []const u8,
    fetches: usize = 0,

    fn fetcher(self: *FakeWeb) Fetcher {
        return .{ .ctx = self, .get = get };
    }

    fn get(ctx: ?*anyopaque, a: Allocator, url: []const u8, max: usize) FetchError![]u8 {
        const self: *FakeWeb = @ptrCast(@alignCast(ctx.?));
        self.fetches += 1;
        const body = if (std.mem.endsWith(u8, url, "openid-configuration")) self.discovery else if (std.mem.endsWith(u8, url, "/jwks")) self.jwks else return error.FetchFailed;
        if (body.len > max) return error.TooLarge;
        return a.dupe(u8, body);
    }
};

test "provider selection, policy claims, and fetch failures" {
    var mem: store_mod.MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var st: Store = undefined;
    try st.open(testing.allocator, mem.persistence(), .{ .root_access_key = "root" });
    defer st.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var web: FakeWeb = .{ .discovery = "{\"issuer\":\"http://idp\",\"jwks_uri\":\"http://idp/jwks\"}", .jwks = "{\"keys\":[]}" };
    var fed: Federation = .{ .gpa = testing.allocator, .store = &st, .fetcher = web.fetcher() };
    defer fed.deinit();
    try testing.expectError(error.NoProvider, fed.webIdentity(a, "x.y.z", null, 1000));
    try idp.upsert(&st, .openid, "_", try idp.parseSettings(a, .openid, "config_url=http://idp/.well-known/openid-configuration client_id=zk"), false);
    // A JWKS without usable keys makes the provider unavailable; the refetch is rate-limited.
    try testing.expectError(error.ProviderUnavailable, fed.webIdentity(a, "x.y.z", null, 1000));
    const n = web.fetches;
    try testing.expectError(error.ProviderUnavailable, fed.webIdentity(a, "x.y.z", null, 1001));
    try testing.expectEqual(n, web.fetches);
    try testing.expectError(error.ProviderUnavailable, fed.webIdentity(a, "x.y.z", null, 1000 + fed.min_refresh_s));
    try testing.expect(web.fetches > n);
    try testing.expectError(error.NoProvider, fed.webIdentity(a, "x.y.z", "arn:zkfsm:iam:::role/none", 1000));

    try testing.expectEqualStrings("readwrite,readonly", try existingPolicies(a, &st, &.{ "readwrite", "ghost", "readonly", "readwrite", "a,b" }));
    try testing.expect(!tenantUsable(&st, "acme"));
}
