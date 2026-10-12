//! Short-lived remote credentials: OAuth2 bearer tokens (service-account JWT bearer
//! grant, client-credentials grant) and temporary signing keys (web-identity role
//! exchange, metadata credential endpoint), cached and refreshed before expiry.
const std = @import("std");
const core = @import("../core/root.zig");
const rhttp = @import("remote/http.zig");
const xml = @import("remote/xml.zig");
const sign = @import("s3/sign.zig");

const log = std.log.scoped(.remote_creds);
const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, CredentialsUnavailable };
pub const InitError = error{ OutOfMemory, InvalidConfig };

pub const ServiceAccount = struct {
    email: []const u8,
    /// PEM, PKCS#8 or PKCS#1 RSA private key.
    private_key_pem: []const u8,
    token_uri: []const u8,
    scope: []const u8 = "https://www.googleapis.com/auth/devstorage.read_write",
};

pub const ClientSecret = struct {
    /// e.g. https://login.microsoftonline.com; the token URL is <authority>/<tenant>/oauth2/v2.0/token.
    authority: []const u8,
    tenant: []const u8,
    client_id: []const u8,
    secret: []const u8,
    scope: []const u8 = "https://storage.azure.com/.default",
};

pub const WebIdentity = struct {
    /// Security token service endpoint (AssumeRoleWithWebIdentity).
    sts_endpoint: []const u8,
    role_arn: []const u8,
    token_file: []const u8,
    session_name: []const u8 = "zkfsm-tier",
    duration_s: u32 = 3600,
};

pub const Metadata = struct {
    /// Container-style endpoint returning the credentials document directly.
    full_uri: []const u8 = "",
    /// Sent as Authorization to `full_uri` when set.
    auth_token: []const u8 = "",
    /// Instance-metadata base URL (session-token flow) when `full_uri` is empty.
    base: []const u8 = "http://169.254.169.254",
};

pub const Kind = union(enum) {
    service_account: ServiceAccount,
    client_secret: ClientSecret,
    web_identity: WebIdentity,
    metadata: Metadata,
};

/// Signing keys copied into a caller buffer.
pub const Signing = sign.Credentials;

pub const Source = struct {
    gpa: Allocator,
    /// Strings borrowed; must outlive the source.
    kind: Kind,
    mutex: std.Thread.Mutex = .{},
    http: std.http.Client,
    rsa: ?RsaKey = null,
    /// Bearer: "Bearer <token>". Signing: access key, secret, session token back to back.
    cached: std.ArrayListUnmanaged(u8) = .empty,
    ak_len: usize = 0,
    sk_len: usize = 0,
    expires_ns: i128 = 0,
    fetched_ns: i128 = 0,
    /// Completed fetches (tests, metrics).
    fetches: std.atomic.Value(u32) = .init(0),

    /// Initializes in place.
    pub fn init(self: *Source, gpa: Allocator, kind: Kind) InitError!void {
        self.* = .{ .gpa = gpa, .kind = kind, .http = .{ .allocator = gpa } };
        rhttp.applyCaFile(&self.http);
        errdefer self.http.deinit();
        if (kind == .service_account) {
            self.rsa = RsaKey.fromPem(gpa, kind.service_account.private_key_pem) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidConfig,
            };
            if (kind.service_account.email.len == 0 or kind.service_account.token_uri.len == 0) return error.InvalidConfig;
        }
    }

    pub fn deinit(self: *Source) void {
        self.cached.deinit(self.gpa);
        self.http.deinit();
    }

    pub fn isBearer(self: *const Source) bool {
        return switch (self.kind) {
            .service_account, .client_secret => true,
            .web_identity, .metadata => false,
        };
    }

    /// Drops the cached credentials (e.g. after the remote rejected them).
    pub fn invalidate(self: *Source) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expires_ns = 0;
    }

    /// "Bearer <token>" copied into `buf`.
    pub fn authorization(self: *Source, buf: []u8) Error![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.ensureLocked();
        if (self.cached.items.len > buf.len) return error.CredentialsUnavailable;
        @memcpy(buf[0..self.cached.items.len], self.cached.items);
        return buf[0..self.cached.items.len];
    }

    /// Temporary signing keys copied into `buf`.
    pub fn signing(self: *Source, buf: []u8) Error!Signing {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.ensureLocked();
        const c = self.cached.items;
        if (c.len > buf.len) return error.CredentialsUnavailable;
        @memcpy(buf[0..c.len], c);
        const st = buf[self.ak_len + self.sk_len .. c.len];
        return .{
            .access_key = buf[0..self.ak_len],
            .secret_key = buf[self.ak_len..][0..self.sk_len],
            .session_token = if (st.len > 0) st else null,
        };
    }

    fn ensureLocked(self: *Source) Error!void {
        const now = std.time.nanoTimestamp();
        const life = self.expires_ns - self.fetched_ns;
        const margin = @min(5 * std.time.ns_per_min, @divFloor(life, 2));
        if (self.expires_ns != 0 and now < self.expires_ns - margin) return;
        self.refreshLocked(now) catch |e| {
            if (self.expires_ns > now) return; // keep using the still-valid cached value
            log.warn("remote credentials unavailable: {t}", .{e});
            return error.CredentialsUnavailable;
        };
        _ = self.fetches.fetchAdd(1, .monotonic);
    }

    const FetchError = error{ OutOfMemory, Http, Rejected, BadResponse, TokenFile, Signing };

    fn refreshLocked(self: *Source, now: i128) FetchError!void {
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        switch (self.kind) {
            .service_account => |sa| {
                const jwt = try self.assertion(a, sa, now);
                const body = try form(a, &.{ .{ "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" }, .{ "assertion", jwt } });
                try self.storeBearer(a, try self.request(a, .POST, sa.token_uri, body, &.{}), now);
            },
            .client_secret => |cs| {
                const url = try std.fmt.allocPrint(a, "{s}/{s}/oauth2/v2.0/token", .{ std.mem.trimRight(u8, cs.authority, "/"), cs.tenant });
                const body = try form(a, &.{ .{ "grant_type", "client_credentials" }, .{ "client_id", cs.client_id }, .{ "client_secret", cs.secret }, .{ "scope", cs.scope } });
                try self.storeBearer(a, try self.request(a, .POST, url, body, &.{}), now);
            },
            .web_identity => |wi| {
                const raw = std.fs.cwd().readFileAlloc(a, wi.token_file, 64 * 1024) catch return error.TokenFile;
                const token = std.mem.trim(u8, raw, " \t\r\n");
                var dur: [12]u8 = undefined;
                const body = try form(a, &.{
                    .{ "Action", "AssumeRoleWithWebIdentity" },
                    .{ "Version", "2011-06-15" },
                    .{ "RoleArn", wi.role_arn },
                    .{ "RoleSessionName", wi.session_name },
                    .{ "DurationSeconds", std.fmt.bufPrint(&dur, "{d}", .{wi.duration_s}) catch unreachable }, // u32 fits
                    .{ "WebIdentityToken", token },
                });
                const doc = try self.request(a, .POST, wi.sts_endpoint, body, &.{});
                var b1: [256]u8 = undefined;
                var b2: [256]u8 = undefined;
                var b3: [8192]u8 = undefined;
                const ak = xml.unescape(xml.find(doc, "AccessKeyId") orelse return error.BadResponse, &b1) catch return error.BadResponse;
                const sk = xml.unescape(xml.find(doc, "SecretAccessKey") orelse return error.BadResponse, &b2) catch return error.BadResponse;
                const st = xml.unescape(xml.find(doc, "SessionToken") orelse "", &b3) catch return error.BadResponse;
                const exp = core.time.parseIso8601(xml.find(doc, "Expiration") orelse return error.BadResponse) catch return error.BadResponse;
                try self.storeSigning(ak, sk, st, exp, now);
            },
            .metadata => |md| try self.fromMetadata(a, md, now),
        }
    }

    fn fromMetadata(self: *Source, a: Allocator, md: Metadata, now: i128) FetchError!void {
        const doc = if (md.full_uri.len > 0) blk: {
            const hs: []const std.http.Header = if (md.auth_token.len > 0) &.{.{ .name = "authorization", .value = md.auth_token }} else &.{};
            break :blk try self.request(a, .GET, md.full_uri, null, hs);
        } else blk: {
            const base = std.mem.trimRight(u8, md.base, "/");
            const tok = try self.request(a, .PUT, try std.fmt.allocPrint(a, "{s}/latest/api/token", .{base}), "", &.{
                .{ .name = "x-aws-ec2-metadata-token-ttl-seconds", .value = "21600" },
            });
            const th = [_]std.http.Header{.{ .name = "x-aws-ec2-metadata-token", .value = std.mem.trim(u8, tok, " \r\n") }};
            const list_url = try std.fmt.allocPrint(a, "{s}/latest/meta-data/iam/security-credentials/", .{base});
            const roles = try self.request(a, .GET, list_url, null, &th);
            var it = std.mem.tokenizeAny(u8, roles, "\r\n ");
            const role = it.next() orelse return error.BadResponse;
            break :blk try self.request(a, .GET, try std.fmt.allocPrint(a, "{s}{s}", .{ list_url, role }), null, &th);
        };
        const v = std.json.parseFromSliceLeaky(std.json.Value, a, doc, .{}) catch return error.BadResponse;
        if (v != .object) return error.BadResponse;
        const ak = jsonStr(v.object, "AccessKeyId") orelse return error.BadResponse;
        const sk = jsonStr(v.object, "SecretAccessKey") orelse return error.BadResponse;
        const st = jsonStr(v.object, "Token") orelse "";
        const exp = core.time.parseIso8601(jsonStr(v.object, "Expiration") orelse return error.BadResponse) catch return error.BadResponse;
        try self.storeSigning(ak, sk, st, exp, now);
    }

    fn storeSigning(self: *Source, ak: []const u8, sk: []const u8, st: []const u8, exp: i128, now: i128) FetchError!void {
        if (ak.len == 0 or sk.len == 0 or exp <= now) return error.BadResponse;
        self.cached.clearRetainingCapacity();
        try self.cached.appendSlice(self.gpa, ak);
        try self.cached.appendSlice(self.gpa, sk);
        try self.cached.appendSlice(self.gpa, st);
        self.ak_len = ak.len;
        self.sk_len = sk.len;
        self.fetched_ns = now;
        self.expires_ns = exp;
    }

    /// OAuth2 token response: {"access_token": ..., "expires_in": seconds}.
    fn storeBearer(self: *Source, a: Allocator, doc: []const u8, now: i128) FetchError!void {
        const v = std.json.parseFromSliceLeaky(std.json.Value, a, doc, .{}) catch return error.BadResponse;
        if (v != .object) return error.BadResponse;
        const tok = jsonStr(v.object, "access_token") orelse return error.BadResponse;
        if (tok.len == 0) return error.BadResponse;
        const secs: i64 = switch (v.object.get("expires_in") orelse std.json.Value{ .integer = 3600 }) {
            .integer => |i| i,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch return error.BadResponse,
            else => return error.BadResponse,
        };
        if (secs <= 0 or secs > 30 * 24 * 3600) return error.BadResponse;
        self.cached.clearRetainingCapacity();
        try self.cached.appendSlice(self.gpa, "Bearer ");
        try self.cached.appendSlice(self.gpa, tok);
        self.fetched_ns = now;
        self.expires_ns = now + @as(i128, secs) * std.time.ns_per_s;
    }

    /// RS256-signed JWT for the service-account bearer grant.
    fn assertion(self: *Source, a: Allocator, sa: ServiceAccount, now: i128) FetchError![]const u8 {
        const enc = std.base64.url_safe_no_pad.Encoder;
        const iat = @divFloor(now, std.time.ns_per_s);
        const header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
        const claims = std.json.Stringify.valueAlloc(a, .{
            .iss = sa.email,
            .scope = sa.scope,
            .aud = sa.token_uri,
            .iat = @as(i64, @intCast(iat)),
            .exp = @as(i64, @intCast(iat + 3600)),
        }, .{}) catch return error.OutOfMemory;
        var out: std.Io.Writer.Allocating = .init(a);
        const w = &out.writer;
        enc.encodeWriter(w, header) catch return error.OutOfMemory;
        w.writeByte('.') catch return error.OutOfMemory;
        enc.encodeWriter(w, claims) catch return error.OutOfMemory;
        var sig: [max_bytes]u8 = undefined;
        const s = self.rsa.?.signSha256(out.written(), &sig) catch return error.Signing;
        w.writeByte('.') catch return error.OutOfMemory;
        enc.encodeWriter(w, s) catch return error.OutOfMemory;
        return out.written();
    }

    fn request(self: *Source, a: Allocator, method: std.http.Method, url: []const u8, body: ?[]const u8, extra: []const std.http.Header) FetchError![]const u8 {
        var out: std.Io.Writer.Allocating = .init(a);
        const res = self.http.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = body,
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{
                .content_type = if (body != null and body.?.len > 0) .{ .override = "application/x-www-form-urlencoded" } else .default,
                .user_agent = .{ .override = "zkfsm" },
                .accept_encoding = .omit,
            },
            .extra_headers = extra,
            .response_writer = &out.writer,
        }) catch |e| {
            log.warn("credential request to {s} failed: {t}", .{ url, e });
            return error.Http;
        };
        if (res.status != .ok) {
            log.warn("credential request to {s}: HTTP {d}", .{ url, @intFromEnum(res.status) });
            return error.Rejected;
        }
        return out.written();
    }
};

fn jsonStr(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

/// application/x-www-form-urlencoded body.
fn form(a: Allocator, pairs: []const [2][]const u8) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    for (pairs, 0..) |p, i| {
        if (i > 0) out.writer.writeByte('&') catch return error.OutOfMemory;
        sign.uriEncode(&out.writer, p[0], true) catch return error.OutOfMemory;
        out.writer.writeByte('=') catch return error.OutOfMemory;
        sign.uriEncode(&out.writer, p[1], true) catch return error.OutOfMemory;
    }
    return out.written();
}

// ---- RSA (RS256 signing) ----

const max_bits = 4096;
const max_bytes = max_bits / 8;
const Modulus = std.crypto.ff.Modulus(max_bits);

pub const KeyError = error{ OutOfMemory, InvalidKey };

pub const RsaKey = struct {
    n: Modulus,
    n_len: usize,
    d: [max_bytes]u8,
    d_len: usize,

    /// PEM "PRIVATE KEY" (PKCS#8) or "RSA PRIVATE KEY" (PKCS#1).
    pub fn fromPem(gpa: Allocator, pem: []const u8) KeyError!RsaKey {
        const der = try pemDer(gpa, pem);
        defer gpa.free(der);
        return fromDer(der);
    }

    pub fn fromDer(der: []const u8) KeyError!RsaKey {
        const top = try elem(der, 0, 0x30);
        const ver = try elem(der, top.start, 0x02);
        const next = try anyElem(der, ver.end);
        if (der[ver.end] == 0x30) { // PKCS#8: AlgorithmIdentifier, then OCTET STRING
            const inner = try elem(der, next.end, 0x04);
            return fromDer(der[inner.start..inner.end]);
        }
        const n = try elem(der, ver.end, 0x02);
        const e = try elem(der, n.end, 0x02);
        const d = try elem(der, e.end, 0x02);
        const nb = std.mem.trimLeft(u8, der[n.start..n.end], &.{0});
        const db = std.mem.trimLeft(u8, der[d.start..d.end], &.{0});
        if (nb.len < 64 or nb.len > max_bytes or db.len == 0 or db.len > nb.len) return error.InvalidKey;
        var k: RsaKey = .{ .n = Modulus.fromBytes(nb, .big) catch return error.InvalidKey, .n_len = nb.len, .d = undefined, .d_len = db.len };
        @memcpy(k.d[0..db.len], db);
        return k;
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256; the signature is `n_len` bytes of `out`.
    pub fn signSha256(k: *const RsaKey, msg: []const u8, out: *[max_bytes]u8) error{InvalidKey}![]const u8 {
        const prefix = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
        const t_len = prefix.len + 32;
        if (k.n_len < t_len + 11) return error.InvalidKey;
        var em: [max_bytes]u8 = undefined;
        const e = em[0..k.n_len];
        e[0] = 0;
        e[1] = 1;
        @memset(e[2 .. k.n_len - t_len - 1], 0xff);
        e[k.n_len - t_len - 1] = 0;
        @memcpy(e[k.n_len - t_len ..][0..prefix.len], &prefix);
        std.crypto.hash.sha2.Sha256.hash(msg, e[k.n_len - 32 ..][0..32], .{});
        const m = Modulus.Fe.fromBytes(k.n, e, .big) catch return error.InvalidKey;
        const s = k.n.powWithEncodedExponent(m, k.d[0..k.d_len], .big) catch return error.InvalidKey;
        s.toBytes(out[0..k.n_len], .big) catch return error.InvalidKey;
        return out[0..k.n_len];
    }
};

fn pemDer(gpa: Allocator, pem: []const u8) KeyError![]u8 {
    const begin = std.mem.indexOf(u8, pem, "-----BEGIN ") orelse return error.InvalidKey;
    const body_start = (std.mem.indexOfPos(u8, pem, begin + 11, "-----") orelse return error.InvalidKey) + 5;
    const end = std.mem.indexOfPos(u8, pem, body_start, "-----END ") orelse return error.InvalidKey;
    const clean = try gpa.alloc(u8, end - body_start);
    defer gpa.free(clean);
    var n: usize = 0;
    for (pem[body_start..end]) |c| if (!std.ascii.isWhitespace(c)) {
        clean[n] = c;
        n += 1;
    };
    const dec = std.base64.standard.Decoder;
    const size = dec.calcSizeForSlice(clean[0..n]) catch return error.InvalidKey;
    const der = try gpa.alloc(u8, size);
    errdefer gpa.free(der);
    dec.decode(der, clean[0..n]) catch return error.InvalidKey;
    return der;
}

const Span = struct { start: usize, end: usize };

fn anyElem(b: []const u8, i: usize) KeyError!Span {
    if (i + 2 > b.len) return error.InvalidKey;
    var p = i + 1;
    var len: usize = b[p];
    p += 1;
    if (len & 0x80 != 0) {
        const nb = len & 0x7f;
        if (nb == 0 or nb > 4 or p + nb > b.len) return error.InvalidKey;
        len = 0;
        for (b[p .. p + nb]) |x| len = len << 8 | x;
        p += nb;
    }
    if (len > b.len - p) return error.InvalidKey;
    return .{ .start = p, .end = p + len };
}

fn elem(b: []const u8, i: usize, tag: u8) KeyError!Span {
    if (i >= b.len or b[i] != tag) return error.InvalidKey;
    return anyElem(b, i);
}

const test_key =
    \\-----BEGIN PRIVATE KEY-----
    \\MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALunnAyWIKmiL03R
    \\BxRA1H/1IIKnblgGM9syYwty22wCYL7iCOc0PkPFpbbmHrsB79DEdA+NZnBO8puK
    \\Cx/MICvEbiYkPkpzZOoQQ4GreqIShbjjb0SPSOe5q6JOFZvYgTfjTaXPmVS1lPrw
    \\ofeGsKdGcd3cy3mv0eBRN+rMU4S7AgMBAAECgYAKq/J86MC8xONpynxbk4BCMp+B
    \\rqHg0aF7Urc9PG/sCYqU8GfPNjJgSkotR5Lx0Z9gwPtUsxbjRioX3FbbnRErMxJB
    \\+HDPGhGhtgKCsLj2trvO74QZcY1qqBqdR0xmZTNbX2nrl0eFps2tqrSg3He8uWKf
    \\KUC8FVlSDPG2JcIIgQJBAORi6ZbOLAtGtVm4Lm1eQ/9OvEHhImEwnqd4f/UGJeWS
    \\LnAU6MWf0ODpc4P1VtFjv5djxWoghhADSp5nC2erInsCQQDSV/VGbgVYEDVssIGF
    \\tRl6AToVoqyKoIxH5SWmoZS/pA8ZJs+Al0vCTsSZXrJauoSPBdC/DlHtU/MG+Zkp
    \\b7LBAkADEtm179xj4nW6WWI2kpgzrWmXMWJ3EGJyOoruT0DfUBJT69QeJMJ45Gtr
    \\kTez5bXEYdFcVke3m3O7ogNjR8hVAkEAxTaeyygAbq7TyFI9PiWr+04HLZ3V9CvP
    \\GuFnybGZi4zAcy6GQuSXrVi4z6uPwa069/XV4CwG+GNLavC+f7EwgQJBAL53vJpX
    \\C3oNZwqMJi8XWZe+FRh6VSMn+QzkL8+tXsuLrqs1RUy6rBjxF/Hcka+cBAB910QJ
    \\VQxEWRpS4eurNkA=
    \\-----END PRIVATE KEY-----
;

test "rs256 signature verifies with the public key" {
    const k = try RsaKey.fromPem(std.testing.allocator, test_key);
    try std.testing.expectEqual(@as(usize, 128), k.n_len);
    var out: [max_bytes]u8 = undefined;
    const s = try k.signSha256("header.claims", &out);
    var nb: [128]u8 = undefined;
    try k.n.toBytes(&nb, .big);
    const rsa = std.crypto.Certificate.rsa;
    const pk = try rsa.PublicKey.fromBytes(&.{ 1, 0, 1 }, &nb);
    try rsa.PKCS1v1_5Signature.verify(128, s[0..128].*, "header.claims", pk, std.crypto.hash.sha2.Sha256);
    try std.testing.expectError(error.InvalidSignature, rsa.PKCS1v1_5Signature.verify(128, s[0..128].*, "other", pk, std.crypto.hash.sha2.Sha256));
    try std.testing.expectError(error.InvalidKey, RsaKey.fromPem(std.testing.allocator, "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"));
    const der = try pemDer(std.testing.allocator, test_key);
    defer std.testing.allocator.free(der);
    for (0..300) |cut| try std.testing.expectError(error.InvalidKey, RsaKey.fromDer(der[0..cut]));
}

test "form encoding and bearer storage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("a=x%3Ay&b=1%202", try form(a, &.{ .{ "a", "x:y" }, .{ "b", "1 2" } }));
    var s: Source = undefined;
    try s.init(std.testing.allocator, .{ .client_secret = .{ .authority = "http://127.0.0.1:1", .tenant = "t", .client_id = "c", .secret = "s" } });
    defer s.deinit();
    try s.storeBearer(a, "{\"access_token\":\"abc\",\"expires_in\":3599,\"token_type\":\"Bearer\"}", 1000);
    try std.testing.expectEqualStrings("Bearer abc", s.cached.items);
    try std.testing.expectError(error.BadResponse, s.storeBearer(a, "{\"expires_in\":5}", 1000));
    try s.storeSigning("AK", "SK", "TOK", 2000, 1000);
    s.expires_ns = std.time.nanoTimestamp() + std.time.ns_per_hour;
    s.fetched_ns = std.time.nanoTimestamp();
    var buf: [64]u8 = undefined;
    const c = try s.signing(&buf);
    try std.testing.expectEqualStrings("SK", c.secret_key);
    try std.testing.expectEqualStrings("TOK", c.session_token.?);
}
