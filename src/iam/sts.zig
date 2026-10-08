//! AssumeRole-style temporary credentials. The session token is self-contained and
//! HMAC-signed: it carries the access key, parent identity, expiry, and session policy.
const std = @import("std");
const policy = @import("policy.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.url_safe_no_pad;

pub const limits = struct {
    pub const min_duration_s = 900;
    pub const max_duration_s = 43_200;
    pub const max_policy_bytes = 2048;
    pub const max_parent_bytes = 512;
    pub const max_roles_bytes = 1024;
    pub const max_tenant_bytes = 64;
    pub const max_token_type_bytes = 64;
    pub const max_payload = 2 + 1 + access_key_len + 2 + max_parent_bytes + 8 + 2 + max_policy_bytes + 2 + max_roles_bytes + 1 + max_tenant_bytes + 8 + 1 + 1 + max_token_type_bytes;
    pub const max_token_bytes = b64.Encoder.calcSize(max_payload + Hmac.mac_length);
};

pub const access_key_len = 20;
pub const secret_key_len = 40;
const magic_v1 = [2]u8{ 'Z', '1' };
/// v2 adds federated policy names and a tenant, and widens the parent length.
const magic_v2 = [2]u8{ 'Z', '2' };
/// v3 adds issue time, identity provider, and token revoke type (for revocation).
const magic = [2]u8{ 'Z', '3' };

/// Identity provider that vouched for the session; names match MinIO's userProvider.
pub const Provider = enum(u8) {
    builtin = 0,
    openid = 1,
    ldap = 2,
    tls = 3,
};

pub const IssueError = error{ OutOfMemory, InvalidDuration, InvalidParent, SessionPolicyTooLarge, InvalidSessionPolicy, InvalidRoles, InvalidTenant, InvalidTokenType };
pub const ValidateError = error{ MalformedToken, BadSignature, Expired, AccessKeyMismatch };

pub const Request = struct {
    /// Access key of the user or service account that assumes the session.
    parent: []const u8,
    duration_s: i64 = 3600,
    /// Optional policy JSON; the session gets the intersection with the parent's rights.
    session_policy: ?[]const u8 = null,
    /// Federated sessions: comma-separated policy names that replace the parent lookup.
    federated_policies: ?[]const u8 = null,
    tenant: []const u8 = "",
    provider: Provider = .builtin,
    /// Free-form label a later revocation can target (MinIO `TokenRevokeType`).
    token_type: []const u8 = "",
    /// Issue time in ms; 0 takes `now_s`.
    issued_ms: i64 = 0,
};

pub const Credentials = struct {
    access_key: [access_key_len]u8,
    secret_key: [secret_key_len]u8,
    session_token: []u8,
    expires_s: i64,

    pub fn deinit(self: *Credentials, gpa: std.mem.Allocator) void {
        gpa.free(self.session_token);
    }
};

/// Slices point into the caller's decode buffer.
pub const Claims = struct {
    access_key: []const u8,
    parent: []const u8,
    expires_s: i64,
    session_policy: ?[]const u8,
    federated_policies: ?[]const u8 = null,
    tenant: []const u8 = "",
    /// 0 for tokens older than v3, so any revocation covers them.
    issued_ms: i64 = 0,
    provider: Provider = .builtin,
    token_type: []const u8 = "",
};

pub const DecodeBuffer = [limits.max_payload + Hmac.mac_length]u8;

pub const Issuer = struct {
    key: [32]u8,

    pub fn issue(self: *const Issuer, gpa: std.mem.Allocator, req: Request, now_s: i64, rand: std.Random) IssueError!Credentials {
        if (req.duration_s < limits.min_duration_s or req.duration_s > limits.max_duration_s) return error.InvalidDuration;
        if (req.parent.len == 0 or req.parent.len > limits.max_parent_bytes) return error.InvalidParent;
        if (req.session_policy) |doc| {
            if (doc.len > limits.max_policy_bytes) return error.SessionPolicyTooLarge;
            var p = policy.parse(gpa, doc) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidSessionPolicy,
            };
            p.deinit();
        }
        if (req.federated_policies) |r| if (r.len > limits.max_roles_bytes) return error.InvalidRoles;
        if (req.tenant.len > limits.max_tenant_bytes) return error.InvalidTenant;
        if (req.token_type.len > limits.max_token_type_bytes) return error.InvalidTokenType;
        var creds: Credentials = .{
            .access_key = undefined,
            .secret_key = undefined,
            .session_token = undefined,
            .expires_s = now_s + req.duration_s,
        };
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        @memcpy(creds.access_key[0..4], "ASIA");
        for (creds.access_key[4..]) |*c| c.* = alphabet[rand.int(u5)];
        creds.secret_key = self.secretFor(&creds.access_key);

        var raw: DecodeBuffer = undefined;
        var w: std.Io.Writer = .fixed(&raw);
        const pol = req.session_policy orelse "";
        w.writeAll(&magic) catch unreachable; // sizes bounded above
        w.writeByte(access_key_len) catch unreachable;
        w.writeAll(&creds.access_key) catch unreachable;
        w.writeInt(u16, @intCast(req.parent.len), .little) catch unreachable;
        w.writeAll(req.parent) catch unreachable;
        w.writeInt(i64, creds.expires_s, .little) catch unreachable;
        w.writeInt(u16, @intCast(pol.len), .little) catch unreachable;
        w.writeAll(pol) catch unreachable;
        // Length 0xffff marks "not federated" so an empty policy list stays distinct.
        if (req.federated_policies) |r| {
            w.writeInt(u16, @intCast(r.len), .little) catch unreachable;
            w.writeAll(r) catch unreachable;
        } else w.writeInt(u16, 0xffff, .little) catch unreachable;
        w.writeByte(@intCast(req.tenant.len)) catch unreachable;
        w.writeAll(req.tenant) catch unreachable;
        w.writeInt(i64, if (req.issued_ms != 0) req.issued_ms else now_s * 1000, .little) catch unreachable;
        w.writeByte(@intFromEnum(req.provider)) catch unreachable;
        w.writeByte(@intCast(req.token_type.len)) catch unreachable;
        w.writeAll(req.token_type) catch unreachable;
        const payload_len = w.end;
        self.mac(raw[0..payload_len], raw[payload_len..][0..Hmac.mac_length]);
        const signed = raw[0 .. payload_len + Hmac.mac_length];
        creds.session_token = try gpa.alloc(u8, b64.Encoder.calcSize(signed.len));
        _ = b64.Encoder.encode(creds.session_token, signed);
        return creds;
    }

    /// Checks signature and expiry. Token input is untrusted and fully bounds-checked.
    pub fn validate(self: *const Issuer, token: []const u8, now_s: i64, buf: *DecodeBuffer) ValidateError!Claims {
        if (token.len > limits.max_token_bytes) return error.MalformedToken;
        const n = b64.Decoder.calcSizeForSlice(token) catch return error.MalformedToken;
        if (n < Hmac.mac_length + magic.len or n > buf.len) return error.MalformedToken;
        b64.Decoder.decode(buf[0..n], token) catch return error.MalformedToken;
        const payload = buf[0 .. n - Hmac.mac_length];
        var want: [Hmac.mac_length]u8 = undefined;
        self.mac(payload, &want);
        if (!std.crypto.timing_safe.eql([Hmac.mac_length]u8, want, buf[n - Hmac.mac_length ..][0..Hmac.mac_length].*))
            return error.BadSignature;
        var r: std.Io.Reader = .fixed(payload);
        const m = r.takeArray(2) catch return error.MalformedToken;
        const v3 = std.mem.eql(u8, m, &magic);
        const v2 = v3 or std.mem.eql(u8, m, &magic_v2);
        if (!v2 and !std.mem.eql(u8, m, &magic_v1)) return error.MalformedToken;
        const ak_len = r.takeByte() catch return error.MalformedToken;
        const ak = r.take(ak_len) catch return error.MalformedToken;
        const parent_len: usize = if (v2) r.takeInt(u16, .little) catch return error.MalformedToken else r.takeByte() catch return error.MalformedToken;
        const parent = r.take(parent_len) catch return error.MalformedToken;
        const exp = r.takeInt(i64, .little) catch return error.MalformedToken;
        const pol_len = r.takeInt(u16, .little) catch return error.MalformedToken;
        const pol = r.take(pol_len) catch return error.MalformedToken;
        var roles: ?[]const u8 = null;
        var tenant: []const u8 = "";
        if (v2) {
            const roles_len = r.takeInt(u16, .little) catch return error.MalformedToken;
            if (roles_len != 0xffff) roles = r.take(roles_len) catch return error.MalformedToken;
            const tenant_len = r.takeByte() catch return error.MalformedToken;
            tenant = r.take(tenant_len) catch return error.MalformedToken;
        }
        var issued_ms: i64 = 0;
        var provider: Provider = .builtin;
        var token_type: []const u8 = "";
        if (v3) {
            issued_ms = r.takeInt(i64, .little) catch return error.MalformedToken;
            const pb = r.takeByte() catch return error.MalformedToken;
            provider = std.meta.intToEnum(Provider, pb) catch return error.MalformedToken;
            const tl = r.takeByte() catch return error.MalformedToken;
            token_type = r.take(tl) catch return error.MalformedToken;
        }
        if (r.seek != payload.len) return error.MalformedToken;
        if (now_s >= exp) return error.Expired;
        return .{
            .access_key = ak,
            .parent = parent,
            .expires_s = exp,
            .session_policy = if (pol.len == 0) null else pol,
            .federated_policies = roles,
            .tenant = tenant,
            .issued_ms = issued_ms,
            .provider = provider,
            .token_type = token_type,
        };
    }

    /// Validates the token and that it was issued for `access_key`.
    pub fn verify(self: *const Issuer, access_key: []const u8, token: []const u8, now_s: i64, buf: *DecodeBuffer) ValidateError!Claims {
        const c = try self.validate(token, now_s, buf);
        if (!std.mem.eql(u8, c.access_key, access_key)) return error.AccessKeyMismatch;
        return c;
    }

    /// Temporary secrets are derived, so no server-side session state is needed.
    pub fn secretFor(self: *const Issuer, access_key: []const u8) [secret_key_len]u8 {
        var h = Hmac.init(&self.key);
        h.update("zkfsm-sts-secret\x00");
        h.update(access_key);
        var d: [Hmac.mac_length]u8 = undefined;
        h.final(&d);
        var enc: [std.base64.standard.Encoder.calcSize(Hmac.mac_length)]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&enc, &d);
        return enc[0..secret_key_len].*;
    }

    fn mac(self: *const Issuer, payload: []const u8, out: *[Hmac.mac_length]u8) void {
        var h = Hmac.init(&self.key);
        h.update("zkfsm-sts-token\x00");
        h.update(payload);
        h.final(out);
    }
};

const test_issuer: Issuer = .{ .key = @splat(7) };

test "issue and validate round trip" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1);
    const pol =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
    ;
    var c = try test_issuer.issue(a, .{ .parent = "alice", .duration_s = 900, .session_policy = pol }, 1000, prng.random());
    defer c.deinit(a);
    try std.testing.expect(std.mem.startsWith(u8, &c.access_key, "ASIA"));
    try std.testing.expectEqual(@as(i64, 1900), c.expires_s);
    var buf: DecodeBuffer = undefined;
    const cl = try test_issuer.verify(&c.access_key, c.session_token, 1899, &buf);
    try std.testing.expectEqualStrings("alice", cl.parent);
    try std.testing.expectEqualStrings(pol, cl.session_policy.?);
    try std.testing.expectEqualSlices(u8, &c.secret_key, &test_issuer.secretFor(cl.access_key));
    try std.testing.expectError(error.Expired, test_issuer.validate(c.session_token, 1900, &buf));
    try std.testing.expectError(error.AccessKeyMismatch, test_issuer.verify("ASIAOTHER", c.session_token, 1000, &buf));
    const other: Issuer = .{ .key = @splat(8) };
    try std.testing.expectError(error.BadSignature, other.validate(c.session_token, 1000, &buf));
}

test "tampered and malformed tokens" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(2);
    var c = try test_issuer.issue(a, .{ .parent = "svc1" }, 0, prng.random());
    defer c.deinit(a);
    var buf: DecodeBuffer = undefined;
    const t = try a.dupe(u8, c.session_token);
    defer a.free(t);
    t[5] = if (t[5] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, test_issuer.validate(t, 0, &buf));
    try std.testing.expectError(error.MalformedToken, test_issuer.validate("", 0, &buf));
    try std.testing.expectError(error.MalformedToken, test_issuer.validate("!!!!", 0, &buf));
    const huge = try a.alloc(u8, limits.max_token_bytes + 4);
    defer a.free(huge);
    @memset(huge, 'A');
    try std.testing.expectError(error.MalformedToken, test_issuer.validate(huge, 0, &buf));
}

test "issue rejects bad requests" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    try std.testing.expectError(error.InvalidDuration, test_issuer.issue(a, .{ .parent = "x", .duration_s = 60 }, 0, r));
    try std.testing.expectError(error.InvalidDuration, test_issuer.issue(a, .{ .parent = "x", .duration_s = 100_000 }, 0, r));
    try std.testing.expectError(error.InvalidParent, test_issuer.issue(a, .{ .parent = "" }, 0, r));
    try std.testing.expectError(error.InvalidTenant, test_issuer.issue(a, .{ .parent = "x", .tenant = "t" ** 65 }, 0, r));
    try std.testing.expectError(error.InvalidSessionPolicy, test_issuer.issue(a, .{ .parent = "x", .session_policy = "{}" }, 0, r));
    const big = try a.alloc(u8, limits.max_policy_bytes + 1);
    defer a.free(big);
    @memset(big, ' ');
    try std.testing.expectError(error.SessionPolicyTooLarge, test_issuer.issue(a, .{ .parent = "x", .session_policy = big }, 0, r));
}

test "federated session carries policies and tenant" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(4);
    const dn = "uid=alice,ou=people,dc=example,dc=org" ** 4;
    var c = try test_issuer.issue(a, .{ .parent = dn, .federated_policies = "readwrite,diag", .tenant = "acme" }, 0, prng.random());
    defer c.deinit(a);
    var buf: DecodeBuffer = undefined;
    const cl = try test_issuer.validate(c.session_token, 0, &buf);
    try std.testing.expectEqualStrings(dn, cl.parent);
    try std.testing.expectEqualStrings("readwrite,diag", cl.federated_policies.?);
    try std.testing.expectEqualStrings("acme", cl.tenant);
    var t = try test_issuer.issue(a, .{ .parent = "carol", .provider = .ldap, .token_type = "batch", .issued_ms = 1234 }, 0, prng.random());
    defer t.deinit(a);
    const tc = try test_issuer.validate(t.session_token, 0, &buf);
    try std.testing.expectEqual(Provider.ldap, tc.provider);
    try std.testing.expectEqualStrings("batch", tc.token_type);
    try std.testing.expectEqual(@as(i64, 1234), tc.issued_ms);
    try std.testing.expectError(error.InvalidTokenType, test_issuer.issue(a, .{ .parent = "x", .token_type = "t" ** 65 }, 0, prng.random()));
    var e = try test_issuer.issue(a, .{ .parent = "bob", .federated_policies = "" }, 0, prng.random());
    defer e.deinit(a);
    try std.testing.expectEqualStrings("", (try test_issuer.validate(e.session_token, 0, &buf)).federated_policies.?);
    var l = try test_issuer.issue(a, .{ .parent = "bob" }, 0, prng.random());
    defer l.deinit(a);
    try std.testing.expect((try test_issuer.validate(l.session_token, 0, &buf)).federated_policies == null);
}
