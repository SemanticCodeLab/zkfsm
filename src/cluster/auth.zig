//! Node-to-node request authentication: HMAC-SHA256 over the request line, sender,
//! timestamp, nonce, and body digest, with a replay window of seen nonces.
const std = @import("std");

const HmacSha256 = @import("../core/hwhash.zig").HmacSha256;

pub const Secret = [32]u8;

/// Requests older or newer than this (clock skew included) are refused; the same
/// 15 minutes S3 signatures allow.
pub const window_ms: i64 = 15 * 60 * std.time.ms_per_s;

/// Added to this node's clock for signing and checking node-to-node requests.
/// Set from ZKFSM_TEST_CLOCK_SKEW_S at start, for tests of skewed clocks only.
pub var clock_offset_ms: i64 = 0;

pub fn nowMs() i64 {
    return std.time.milliTimestamp() + clock_offset_ms;
}

/// How far `time` (a request's timestamp header) is from `now_ms`, in seconds.
pub fn skewSeconds(time: []const u8, now_ms: i64) ?u64 {
    const t = std.fmt.parseInt(i64, time, 10) catch return null;
    return @abs(now_ms - t) / std.time.ms_per_s;
}
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
    @import("../core/hwhash.zig").Sha256.hash(body, &d, .{});
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

/// Accepts each signed request once. A sender numbers its requests within a random
/// epoch (the nonce is epoch and sequence number), so the guard keeps one sliding
/// bitmap per sender epoch instead of every nonce: constant memory at any call rate.
/// Random nonces of older senders are remembered one by one, as before.
pub const ReplayGuard = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    epochs: std.AutoHashMapUnmanaged(EpochKey, *Window) = .empty,
    seen: std.AutoHashMapUnmanaged([16]u8, i64) = .empty,
    inserts: usize = 0,
    last_prune_ms: i64 = 0,

    const EpochKey = struct { node: u32, epoch: u64 };
    /// Sequence numbers remembered behind the newest one. A request this far behind
    /// would have to be overtaken by a million others within the time window.
    const window_bits = 1 << 20;
    /// Sender epochs kept at once (a sender starts one per process start).
    const max_epochs = 1024;

    const Window = struct {
        max: u64 = 0,
        used_ms: i64 = 0,
        bits: [window_bits / 64]u64 = @splat(0),

        fn accept(w: *Window, seq: u64) bool {
            if (seq > w.max) {
                // Forget the numbers that slide out of the window.
                if (seq - w.max >= window_bits) {
                    @memset(&w.bits, 0);
                } else {
                    var q = w.max + 1;
                    while (q < seq) : (q += 1) w.clear(q);
                }
                w.max = seq;
                w.set(seq);
                return true;
            }
            if (w.max - seq >= window_bits) return false;
            if (w.get(seq)) return false;
            w.set(seq);
            return true;
        }

        fn get(w: *const Window, q: u64) bool {
            return w.bits[(q % window_bits) / 64] & (@as(u64, 1) << @intCast(q % 64)) != 0;
        }
        fn set(w: *Window, q: u64) void {
            w.bits[(q % window_bits) / 64] |= @as(u64, 1) << @intCast(q % 64);
        }
        fn clear(w: *Window, q: u64) void {
            w.bits[(q % window_bits) / 64] &= ~(@as(u64, 1) << @intCast(q % 64));
        }
    };

    pub fn deinit(g: *ReplayGuard) void {
        var it = g.epochs.valueIterator();
        while (it.next()) |w| g.gpa.destroy(w.*);
        g.epochs.deinit(g.gpa);
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
        const epoch = std.mem.readInt(u64, n[0..8], .big);
        const seq = std.mem.readInt(u64, n[8..16], .big);
        g.mutex.lock();
        defer g.mutex.unlock();
        // Numbered senders stay below `seq_limit`; a random nonce almost never does.
        if (seq == 0 or seq >= seq_limit) return g.verifyRandom(n, now_ms);
        const node = std.fmt.parseInt(u32, f.node, 10) catch std.math.maxInt(u32);
        const key: EpochKey = .{ .node = node, .epoch = epoch };
        const w = g.epochs.get(key) orelse blk: {
            // Epochs idle for longer than the time window cannot be replayed any more.
            g.dropIdleEpochs(now_ms);
            if (g.epochs.count() >= max_epochs) return error.Busy;
            const new = g.gpa.create(Window) catch return error.Busy;
            new.* = .{};
            g.epochs.put(g.gpa, key, new) catch {
                g.gpa.destroy(new);
                return error.Busy;
            };
            break :blk new;
        };
        w.used_ms = now_ms;
        if (!w.accept(seq)) return error.Replayed;
    }

    fn dropIdleEpochs(g: *ReplayGuard, now_ms: i64) void {
        var dead: [64]EpochKey = undefined;
        while (true) {
            var n: usize = 0;
            var it = g.epochs.iterator();
            while (it.next()) |e| {
                if (now_ms - e.value_ptr.*.used_ms <= 2 * window_ms) continue;
                dead[n] = e.key_ptr.*;
                n += 1;
                if (n == dead.len) break;
            }
            for (dead[0..n]) |k| if (g.epochs.fetchRemove(k)) |kv| g.gpa.destroy(kv.value);
            if (n < dead.len) return;
        }
    }

    fn verifyRandom(g: *ReplayGuard, n: [16]u8, now_ms: i64) VerifyError!void {
        g.inserts += 1;
        const full = g.seen.count() >= max_nonces;
        // A full table is swept at most once a second, not on every request.
        if (g.inserts % 4096 == 0 or (full and now_ms - g.last_prune_ms >= 1000)) {
            g.last_prune_ms = now_ms;
            g.prune(now_ms);
        }
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

/// Sequence numbers stay below this; the sender starts a new epoch long before.
const seq_limit: u64 = 1 << 32;

const Numbering = struct {
    mutex: std.Thread.Mutex = .{},
    epoch: u64 = 0,
    seq: u64 = 0,
};
var numbering: Numbering = .{};

/// A nonce no request of this process used before: its random epoch, then a counter.
pub fn newNonce() [32]u8 {
    var b: [16]u8 = undefined;
    {
        numbering.mutex.lock();
        defer numbering.mutex.unlock();
        if (numbering.epoch == 0 or numbering.seq >= seq_limit / 2) {
            numbering.epoch = std.crypto.random.int(u64) | 1;
            numbering.seq = 0;
        }
        numbering.seq += 1;
        std.mem.writeInt(u64, b[0..8], numbering.epoch, .big);
        std.mem.writeInt(u64, b[8..16], numbering.seq, .big);
    }
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

    // Numbered requests arrive out of order across connections: each is accepted once.
    var nonces: [300][32]u8 = undefined;
    for (&nonces) |*x| x.* = newNonce();
    var order: [300]usize = undefined;
    for (&order, 0..) |*o, i| o.* = i;
    var prng = std.Random.DefaultPrng.init(4);
    prng.random().shuffle(usize, &order);
    for (order) |i| {
        var fi = f;
        fi.nonce = &nonces[i];
        const si = sign(secret, fi);
        try g.verify(secret, fi, &si, now);
        try std.testing.expectError(error.Replayed, g.verify(secret, fi, &si, now + 1));
    }
    // The same numbers from another node are another sender.
    var fo = f;
    fo.node = "2";
    fo.nonce = &nonces[7];
    const so = sign(secret, fo);
    try g.verify(secret, fo, &so, now);
    // A random nonce (an older sender) is remembered on its own.
    var fr = f;
    fr.nonce = "0123456789abcdeffedcba9876543210";
    const sr = sign(secret, fr);
    try g.verify(secret, fr, &sr, now);
    try std.testing.expectError(error.Replayed, g.verify(secret, fr, &sr, now));
}

test "replay window slides and forgets idle epochs" {
    var w: ReplayGuard.Window = .{};
    try std.testing.expect(w.accept(5));
    try std.testing.expect(!w.accept(5));
    try std.testing.expect(w.accept(3));
    try std.testing.expect(w.accept(5 + ReplayGuard.window_bits));
    // 5 slid out: too old to tell apart from a replay.
    try std.testing.expect(!w.accept(5));
    try std.testing.expect(w.accept(6));
    try std.testing.expect(!w.accept(6));
    try std.testing.expect(w.accept(6 + 3 * ReplayGuard.window_bits));
    try std.testing.expect(w.accept(7 + 2 * ReplayGuard.window_bits));
}
