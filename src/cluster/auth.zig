//! Node-to-node request authentication: HMAC-SHA256 over the request line, sender,
//! timestamp, nonce, and body digest, with a replay window of seen nonces.
const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Secret = [32]u8;

/// Requests older or newer than this (clock skew included) are refused.
pub const window_ms: i64 = 60 * std.time.ms_per_s;
/// Nonces kept at most; beyond it, requests are refused until old ones expire.
pub const max_nonces = 1 << 20;

pub const header_node = "x-zkfsm-node";
pub const header_time = "x-zkfsm-time";
pub const header_nonce = "x-zkfsm-nonce";
pub const header_body = "x-zkfsm-body";
pub const header_sig = "x-zkfsm-sig";
/// Body tag for streamed bodies whose integrity rests on shard checksums (and TLS).
pub const body_stream = "stream";

/// The cluster secret from root credentials; every node with the same root derives it.
pub fn fromRoot(access_key: []const u8, secret_key: []const u8) Secret {
    var out: Secret = undefined;
    var h = HmacSha256.init("zkfsm-cluster-secret-v1");
    h.update(access_key);
    h.update(":");
    h.update(secret_key);
    h.final(&out);
    return out;
}

pub fn fromString(s: []const u8) Secret {
    var out: Secret = undefined;
    HmacSha256.create(&out, "zkfsm-cluster-secret-v1/explicit", s);
    return out;
}

/// Proof of the root credentials that only secret holders can compare.
pub fn rootFingerprint(secret: Secret, access_key: []const u8, secret_key: []const u8) [16]u8 {
    var d: [32]u8 = undefined;
    var h = HmacSha256.init(&secret);
    h.update("root:");
    h.update(access_key);
    h.update(":");
    h.update(secret_key);
    h.final(&d);
    return d[0..16].*;
}

pub fn bodyDigest(body: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

pub const Fields = struct {
    method: []const u8,
    target: []const u8,
    node: []const u8,
    time: []const u8,
    nonce: []const u8,
    body: []const u8,
};

pub fn sign(secret: Secret, f: Fields) [64]u8 {
    var mac: [32]u8 = undefined;
    var h = HmacSha256.init(&secret);
    for ([_][]const u8{ f.method, f.target, f.node, f.time, f.nonce, f.body }) |part| {
        h.update(part);
        h.update("\n");
    }
    h.final(&mac);
    return std.fmt.bytesToHex(mac, .lower);
}

pub const VerifyError = error{ BadSignature, Expired, Replayed, Busy };

/// Remembers nonces for twice the window so each signed request is accepted once.
pub const ReplayGuard = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    seen: std.AutoHashMapUnmanaged([16]u8, i64) = .empty,
    inserts: usize = 0,

    pub fn deinit(g: *ReplayGuard) void {
        g.seen.deinit(g.gpa);
    }

    pub fn verify(g: *ReplayGuard, secret: Secret, f: Fields, sig: []const u8, now_ms: i64) VerifyError!void {
        const want = sign(secret, f);
        if (sig.len != want.len or !std.crypto.timing_safe.eql([64]u8, want, sig[0..64].*)) return error.BadSignature;
        const t = std.fmt.parseInt(i64, f.time, 10) catch return error.BadSignature;
        if (@abs(now_ms - t) > window_ms) return error.Expired;
        if (f.nonce.len != 32) return error.BadSignature;
        var n: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&n, f.nonce) catch return error.BadSignature;
        g.mutex.lock();
        defer g.mutex.unlock();
        g.inserts += 1;
        if (g.inserts % 4096 == 0 or g.seen.count() >= max_nonces) g.prune(now_ms);
        if (g.seen.count() >= max_nonces) return error.Busy;
        const gop = g.seen.getOrPut(g.gpa, n) catch return error.Busy;
        if (gop.found_existing) return error.Replayed;
        gop.value_ptr.* = now_ms + 2 * window_ms;
    }

    fn prune(g: *ReplayGuard, now_ms: i64) void {
        var it = g.seen.iterator();
        var dead: [256][16]u8 = undefined;
        while (true) {
            var n: usize = 0;
            it = g.seen.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* > now_ms) continue;
                dead[n] = e.key_ptr.*;
                n += 1;
                if (n == dead.len) break;
            }
            for (dead[0..n]) |k| _ = g.seen.remove(k);
            if (n < dead.len) return;
        }
    }
};

pub fn newNonce() [32]u8 {
    var b: [16]u8 = undefined;
    std.crypto.random.bytes(&b);
    return std.fmt.bytesToHex(b, .lower);
}

test "sign and verify with replay window" {
    const secret = fromRoot("root", "rootsecret");
    try std.testing.expect(!std.mem.eql(u8, &secret, &fromRoot("root", "other")));
    var g: ReplayGuard = .{ .gpa = std.testing.allocator };
    defer g.deinit();
    const nonce = newNonce();
    var tb: [24]u8 = undefined;
    const now: i64 = 1_700_000_000_000;
    const f: Fields = .{ .method = "POST", .target = "/zkfsm/rpc/v1/stat?d=0", .node = "1", .time = try std.fmt.bufPrint(&tb, "{d}", .{now}), .nonce = &nonce, .body = body_stream };
    const sig = sign(secret, f);
    try g.verify(secret, f, &sig, now + 10);
    try std.testing.expectError(error.Replayed, g.verify(secret, f, &sig, now + 20));
    var f2 = f;
    const n2 = newNonce();
    f2.nonce = &n2;
    try std.testing.expectError(error.BadSignature, g.verify(secret, f2, &sig, now));
    const sig2 = sign(secret, f2);
    try std.testing.expectError(error.Expired, g.verify(secret, f2, &sig2, now + window_ms + 1));
    try std.testing.expectError(error.BadSignature, g.verify(fromString("x"), f2, &sig2, now));
    var f3 = f2;
    f3.target = "/zkfsm/rpc/v1/delete?d=0";
    try std.testing.expectError(error.BadSignature, g.verify(secret, f3, &sig2, now));
}
