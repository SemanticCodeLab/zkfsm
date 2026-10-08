//! OpenID Connect authorization-code login (with PKCE and nonce) for consoles.
//! The flow state is sealed with a server key and travels in `state`, so any node
//! can finish the login; a cookie binds it to the browser that started it.
const std = @import("std");
const federation = @import("federation.zig");
const idp = @import("idp.zig");

const Allocator = std.mem.Allocator;
const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.url_safe_no_pad;

pub const max_state_age_s = 600;
pub const max_redirect_bytes = 512;
const max_state_bytes = 4096;
const max_token_response = 64 * 1024;

pub const Error = federation.Error || error{ InvalidState, InvalidRedirect, ExchangeFailed };

pub const Begin = struct {
    /// IdP authorization URL to redirect the browser to.
    url: []const u8,
    /// Cookie value binding the flow to this browser.
    binding: []const u8,
};

pub const Finish = struct {
    id: federation.WebIdentity,
    redirect_after: []const u8,
};

const Sealed = struct {
    p: []const u8,
    v: []const u8,
    n: []const u8,
    b: []const u8,
    r: []const u8,
    a: []const u8,
    t: i64,
};

/// Safe post-login targets are absolute paths on this server.
pub fn safeRedirect(path: []const u8) bool {
    if (path.len == 0) return true;
    if (path.len > max_redirect_bytes or path[0] != '/') return false;
    if (path.len > 1 and (path[1] == '/' or path[1] == '\\')) return false;
    for (path) |c| if (c < 0x21 or c > 0x7e or c == '\\') return false;
    return true;
}

const Endpoints = struct { authorization_endpoint: []const u8 = "", token_endpoint: []const u8 = "" };

fn endpoints(fed: *federation.Federation, a: Allocator, p: idp.OpenId) Error!Endpoints {
    const doc = fed.fetcher.get(fed.fetcher.ctx, a, p.config_url, federation.limits.max_discovery_bytes) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ProviderUnavailable,
    };
    const d = std.json.parseFromSliceLeaky(Endpoints, a, doc, .{ .ignore_unknown_fields = true }) catch return error.ProviderUnavailable;
    if (!isHttp(d.authorization_endpoint) or !isHttp(d.token_endpoint)) return error.ProviderUnavailable;
    return d;
}

fn isHttp(u: []const u8) bool {
    return std.mem.startsWith(u8, u, "http://") or std.mem.startsWith(u8, u, "https://");
}

fn randomText(a: Allocator, comptime n: usize, rand: std.Random) Error![]const u8 {
    var raw: [n]u8 = undefined;
    rand.bytes(&raw);
    const out = try a.alloc(u8, b64.Encoder.calcSize(n));
    return b64.Encoder.encode(out, &raw);
}

fn sealKey(key: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    Hmac.create(&out, "zkfsm-oidc-state", &key);
    return out;
}

/// Starts a login at provider `name`; `callback` is used unless the provider sets redirect_uri.
pub fn begin(fed: *federation.Federation, a: Allocator, key: [32]u8, name: []const u8, callback: []const u8, redirect_after: []const u8, now_s: i64, rand: std.Random) Error!Begin {
    if (!safeRedirect(redirect_after)) return error.InvalidRedirect;
    const p = try fed.provider(a, name);
    const ep = try endpoints(fed, a, p);
    const redirect_uri = if (p.redirect_uri.len > 0) p.redirect_uri else callback;
    const verifier = try randomText(a, 32, rand);
    const nonce = try randomText(a, 16, rand);
    const binding = try randomText(a, 16, rand);
    var digest: [32]u8 = undefined;
    Sha256.hash(verifier, &digest, .{});
    var chal: [b64.Encoder.calcSize(32)]u8 = undefined;
    _ = b64.Encoder.encode(&chal, &digest);

    const plain = try std.json.Stringify.valueAlloc(a, Sealed{ .p = p.name, .v = verifier, .n = nonce, .b = binding, .r = redirect_uri, .a = redirect_after, .t = now_s }, .{});
    var iv: [Aead.nonce_length]u8 = undefined;
    rand.bytes(&iv);
    const box = try a.alloc(u8, iv.len + plain.len + Aead.tag_length);
    @memcpy(box[0..iv.len], &iv);
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(box[iv.len..][0..plain.len], &tag, plain, "", iv, sealKey(key));
    @memcpy(box[iv.len + plain.len ..], &tag);
    const state = try a.alloc(u8, b64.Encoder.calcSize(box.len));
    _ = b64.Encoder.encode(state, box);

    var scopes: std.ArrayList(u8) = .empty;
    try scopes.appendSlice(a, "openid");
    var it = std.mem.tokenizeAny(u8, p.scopes, ", ");
    while (it.next()) |s| if (!std.mem.eql(u8, s, "openid")) {
        try scopes.append(a, ' ');
        try scopes.appendSlice(a, s);
    };
    var url: std.Io.Writer.Allocating = .init(a);
    const w = &url.writer;
    const sep: u8 = if (std.mem.indexOfScalar(u8, ep.authorization_endpoint, '?') != null) '&' else '?';
    w.print("{s}{c}response_type=code&client_id=", .{ ep.authorization_endpoint, sep }) catch return error.OutOfMemory;
    const params = [_]struct { []const u8, []const u8 }{
        .{ "", p.client_id },
        .{ "&redirect_uri=", redirect_uri },
        .{ "&scope=", scopes.items },
        .{ "&state=", state },
        .{ "&nonce=", nonce },
        .{ "&code_challenge=", &chal },
    };
    for (params) |kv| {
        w.writeAll(kv[0]) catch return error.OutOfMemory;
        formEscape(w, kv[1]) catch return error.OutOfMemory;
    }
    w.writeAll("&code_challenge_method=S256") catch return error.OutOfMemory;
    return .{ .url = url.written(), .binding = binding };
}

/// Unseals `state`, exchanges `code`, and validates the returned id_token.
pub fn finish(fed: *federation.Federation, a: Allocator, key: [32]u8, name: []const u8, code: []const u8, state: []const u8, binding: []const u8, now_s: i64) Error!Finish {
    const s = try unseal(a, key, state);
    if (!std.mem.eql(u8, s.p, name)) return error.InvalidState;
    if (now_s - s.t > max_state_age_s or s.t > now_s + 60) return error.InvalidState;
    if (s.b.len != binding.len or !std.crypto.timing_safe.eql([22]u8, toFixed(s.b), toFixed(binding))) return error.InvalidState;
    if (code.len == 0 or code.len > 4096) return error.InvalidState;
    const p = try fed.provider(a, name);
    const ep = try endpoints(fed, a, p);

    var form: std.Io.Writer.Allocating = .init(a);
    const w = &form.writer;
    const fields = [_]struct { []const u8, []const u8 }{
        .{ "grant_type=authorization_code&code=", code },
        .{ "&redirect_uri=", s.r },
        .{ "&client_id=", p.client_id },
        .{ "&code_verifier=", s.v },
    };
    for (fields) |kv| {
        w.writeAll(kv[0]) catch return error.OutOfMemory;
        formEscape(w, kv[1]) catch return error.OutOfMemory;
    }
    var basic: []const u8 = "";
    if (p.client_secret.len > 0) {
        var cred: std.Io.Writer.Allocating = .init(a);
        formEscape(&cred.writer, p.client_id) catch return error.OutOfMemory;
        cred.writer.writeByte(':') catch return error.OutOfMemory;
        formEscape(&cred.writer, p.client_secret) catch return error.OutOfMemory;
        const raw = cred.written();
        const enc = try a.alloc(u8, std.base64.standard.Encoder.calcSize(raw.len));
        basic = std.base64.standard.Encoder.encode(enc, raw);
    }
    const body = fed.fetcher.post(fed.fetcher.ctx, a, ep.token_endpoint, form.written(), basic, max_token_response) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ExchangeFailed,
    };
    const TokenResponse = struct { id_token: []const u8 = "" };
    const tr = std.json.parseFromSliceLeaky(TokenResponse, a, body, .{ .ignore_unknown_fields = true }) catch return error.ExchangeFailed;
    if (tr.id_token.len == 0) return error.ExchangeFailed;
    const id = try fed.identityFrom(a, p, tr.id_token, now_s);
    const got = id.nonce orelse return error.InvalidToken;
    if (!std.mem.eql(u8, got, s.n)) return error.InvalidToken;
    return .{ .id = id, .redirect_after = s.a };
}

fn toFixed(s: []const u8) [22]u8 {
    var out: [22]u8 = @splat(0);
    const n = @min(s.len, out.len);
    @memcpy(out[0..n], s[0..n]);
    return out;
}

fn unseal(a: Allocator, key: [32]u8, state: []const u8) Error!Sealed {
    if (state.len > max_state_bytes) return error.InvalidState;
    const n = b64.Decoder.calcSizeForSlice(state) catch return error.InvalidState;
    if (n < Aead.nonce_length + Aead.tag_length) return error.InvalidState;
    const box = try a.alloc(u8, n);
    b64.Decoder.decode(box, state) catch return error.InvalidState;
    const iv = box[0..Aead.nonce_length].*;
    const ct = box[Aead.nonce_length .. n - Aead.tag_length];
    const tag = box[n - Aead.tag_length ..][0..Aead.tag_length].*;
    const plain = try a.alloc(u8, ct.len);
    Aead.decrypt(plain, ct, tag, "", iv, sealKey(key)) catch return error.InvalidState;
    return std.json.parseFromSliceLeaky(Sealed, a, plain, .{}) catch error.InvalidState;
}

/// application/x-www-form-urlencoded escaping (unreserved characters pass).
pub fn formEscape(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try w.writeByte(c);
        } else try w.print("%{X:0>2}", .{c});
    }
}

const testing = std.testing;

test "redirect targets" {
    try testing.expect(safeRedirect(""));
    try testing.expect(safeRedirect("/browser?x=1"));
    try testing.expect(!safeRedirect("//evil.example"));
    try testing.expect(!safeRedirect("https://evil.example"));
    try testing.expect(!safeRedirect("/\\evil"));
    try testing.expect(!safeRedirect("/a b"));
}

test "sealed state round trip and tamper" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key: [32]u8 = @splat(9);
    const plain = try std.json.Stringify.valueAlloc(a, Sealed{ .p = "corp", .v = "v", .n = "n", .b = "b", .r = "r", .a = "", .t = 5 }, .{});
    var iv: [Aead.nonce_length]u8 = @splat(1);
    const box = try a.alloc(u8, iv.len + plain.len + Aead.tag_length);
    @memcpy(box[0..iv.len], &iv);
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(box[iv.len..][0..plain.len], &tag, plain, "", iv, sealKey(key));
    @memcpy(box[iv.len + plain.len ..], &tag);
    const state = try a.alloc(u8, b64.Encoder.calcSize(box.len));
    _ = b64.Encoder.encode(state, box);
    try testing.expectEqualStrings("corp", (try unseal(a, key, state)).p);
    try testing.expectError(error.InvalidState, unseal(a, @splat(8), state));
    state[3] = if (state[3] == 'A') 'B' else 'A';
    try testing.expectError(error.InvalidState, unseal(a, key, state));
    try testing.expectError(error.InvalidState, unseal(a, key, "!!"));
}
