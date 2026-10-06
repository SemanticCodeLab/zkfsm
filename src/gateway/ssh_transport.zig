//! SSH transport layer, server side (RFC 4253): version exchange, binary packets,
//! key exchange and re-exchange, strict kex, ext-info, keepalives. One thread
//! drives a connection; key exchanges run inline when either side starts one.
const std = @import("std");
const posix = std.posix;
const wire = @import("ssh_wire.zig");
const cipher = @import("ssh_cipher.zig");
const kex = @import("ssh_kex.zig");
const keys = @import("ssh_keys.zig");

pub const msg_disconnect: u8 = 1;
pub const msg_ignore: u8 = 2;
pub const msg_unimplemented: u8 = 3;
pub const msg_debug: u8 = 4;
pub const msg_service_request: u8 = 5;
pub const msg_service_accept: u8 = 6;
pub const msg_ext_info: u8 = 7;
pub const msg_global_request: u8 = 80;
pub const msg_request_success: u8 = 81;
pub const msg_request_failure: u8 = 82;

pub const reason_protocol_error: u32 = 2;
pub const reason_kex_failed: u32 = 3;
pub const reason_mac_error: u32 = 5;
pub const reason_no_more_auth: u32 = 14;
pub const reason_by_application: u32 = 11;

pub const version = "SSH-2.0-zkfsm_1.0";

pub const Error = error{
    /// The peer closed the connection or sent DISCONNECT.
    Closed,
    Io,
    Timeout,
    Protocol,
    BadMac,
    NoCommonAlgorithm,
    OutOfMemory,
};

pub const Options = struct {
    host_keys: []const keys.HostKey,
    /// Start a new key exchange after this many bytes in either direction.
    rekey_bytes: u64 = 1 << 30,
    /// Idle seconds before a keepalive probe; three unanswered probes end the session.
    keepalive_s: u32 = 60,
};

/// Bound on non-kex messages queued while a server-started re-exchange waits.
const max_pending_bytes = 4 * 1024 * 1024;
const rbuf_len = 64 * 1024;
const pkt_buf_len = 4 + cipher.max_packet + cipher.tag_len;

pub const Transport = struct {
    gpa: std.mem.Allocator,
    fd: posix.socket_t,
    opts: Options,

    rbuf: []u8,
    rstart: usize = 0,
    rend: usize = 0,
    in: []u8,
    out: []u8,

    rx: cipher.Cipher = .none,
    tx: cipher.Cipher = .none,
    rx_seq: u32 = 0,
    tx_seq: u32 = 0,
    /// Sequence number of the last packet returned by `read`.
    last_seq: u32 = 0,

    v_c: [255]u8 = undefined,
    v_c_len: usize = 0,
    session_id: ?[32]u8 = null,
    strict: bool = false,
    bytes_since_kex: u64 = 0,
    /// Our KEXINIT payload while an exchange is open.
    our_kexinit: [1024]u8 = undefined,
    our_kexinit_len: usize = 0,
    kexinit_sent: bool = false,

    pending: std.ArrayList([]u8) = .empty,
    pending_bytes: usize = 0,
    pending_head: usize = 0,
    probes: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, fd: posix.socket_t, opts: Options) Error!Transport {
        const rbuf = try gpa.alloc(u8, rbuf_len);
        errdefer gpa.free(rbuf);
        const in = try gpa.alloc(u8, pkt_buf_len);
        errdefer gpa.free(in);
        const out = try gpa.alloc(u8, pkt_buf_len + 64);
        return .{ .gpa = gpa, .fd = fd, .opts = opts, .rbuf = rbuf, .in = in, .out = out };
    }

    pub fn deinit(t: *Transport) void {
        t.rx.wipe();
        t.tx.wipe();
        for (t.pending.items[t.pending_head..]) |p| t.gpa.free(p);
        t.pending.deinit(t.gpa);
        t.gpa.free(t.rbuf);
        t.gpa.free(t.in);
        t.gpa.free(t.out);
    }

    pub fn sessionId(t: *const Transport) [32]u8 {
        return t.session_id orelse [_]u8{0} ** 32;
    }

    // ---- socket ----

    fn sendRaw(t: *Transport, data: []const u8) Error!void {
        var off: usize = 0;
        while (off < data.len) {
            const n = posix.send(t.fd, data[off..], posix.MSG.NOSIGNAL) catch |e| return switch (e) {
                error.WouldBlock => error.Timeout,
                else => error.Io,
            };
            if (n == 0) return error.Io;
            off += n;
        }
    }

    fn fill(t: *Transport) Error!void {
        if (t.rstart == t.rend) {
            t.rstart = 0;
            t.rend = 0;
        } else if (t.rend == t.rbuf.len) {
            std.mem.copyForwards(u8, t.rbuf, t.rbuf[t.rstart..t.rend]);
            t.rend -= t.rstart;
            t.rstart = 0;
        }
        const n = posix.read(t.fd, t.rbuf[t.rend..]) catch |e| return switch (e) {
            error.WouldBlock => error.Timeout,
            error.ConnectionResetByPeer => error.Closed,
            else => error.Io,
        };
        if (n == 0) return error.Closed;
        t.rend += n;
    }

    fn take(t: *Transport, dst: []u8) Error!void {
        var off: usize = 0;
        while (off < dst.len) {
            if (t.rstart == t.rend) try t.fill();
            const n = @min(dst.len - off, t.rend - t.rstart);
            @memcpy(dst[off..][0..n], t.rbuf[t.rstart..][0..n]);
            t.rstart += n;
            off += n;
        }
    }

    /// Waits for input; false after `ms` without any.
    fn waitReadable(t: *Transport, ms: i32) Error!bool {
        if (t.rstart != t.rend) return true;
        var fds = [_]posix.pollfd{.{ .fd = t.fd, .events = posix.POLL.IN, .revents = 0 }};
        const n = posix.poll(&fds, ms) catch return error.Io;
        return n > 0;
    }

    // ---- packets ----

    fn readPacket(t: *Transport) Error![]u8 {
        var first: [4]u8 = undefined;
        try t.take(&first);
        const len = t.rx.openLength(t.rx_seq, first) catch return error.Protocol;
        const rest = t.rx.restLen(len);
        @memcpy(t.in[0..4], &first);
        try t.take(t.in[4..][0..rest]);
        const payload = t.rx.open(t.rx_seq, t.in[0 .. 4 + rest]) catch |e| return switch (e) {
            error.BadMac => error.BadMac,
            error.BadPacket => error.Protocol,
        };
        t.last_seq = t.rx_seq;
        t.rx_seq +%= 1;
        if (t.rx_seq == 0 and t.session_id == null) return error.Protocol;
        t.bytes_since_kex += 4 + rest;
        if (payload.len == 0) return error.Protocol;
        return payload;
    }

    fn writePacket(t: *Transport, payload: []const u8) Error!void {
        const pkt = t.tx.seal(t.tx_seq, payload, t.out) catch return error.Protocol;
        t.tx_seq +%= 1;
        t.bytes_since_kex += pkt.len;
        try t.sendRaw(pkt);
    }

    // ---- public message API ----

    /// Sends a message, first finishing any re-exchange that is due.
    pub fn write(t: *Transport, payload: []const u8) Error!void {
        if (t.session_id != null and (t.kexinit_sent or t.bytes_since_kex >= t.opts.rekey_bytes)) try t.serverRekey();
        try t.writePacket(payload);
    }

    /// Next message for the layers above; transport messages are handled here.
    /// The slice is valid until the next call.
    pub fn read(t: *Transport) Error![]const u8 {
        while (true) {
            if (t.pending_head < t.pending.items.len) {
                const p = t.pending.items[t.pending_head];
                t.pending_head += 1;
                t.pending_bytes -= p.len;
                @memcpy(t.in[0..p.len], p);
                t.gpa.free(p);
                if (t.pending_head == t.pending.items.len) {
                    t.pending.clearRetainingCapacity();
                    t.pending_head = 0;
                }
                return t.in[0..p.len];
            }
            if (t.bytes_since_kex >= t.opts.rekey_bytes and !t.kexinit_sent) {
                try t.serverRekey();
                continue;
            }
            if (!try t.waitReadable(@intCast(@as(u64, t.opts.keepalive_s) * 1000))) {
                if (t.probes >= 3) return error.Timeout;
                t.probes += 1;
                var buf: [64]u8 = undefined;
                var w = wire.Writer.init(&buf);
                w.byte(msg_global_request) catch return error.Protocol;
                w.string("keepalive@openssh.com") catch return error.Protocol;
                w.boolean(true) catch return error.Protocol;
                try t.write(w.written());
                continue;
            }
            const p = try t.readPacket();
            t.probes = 0;
            switch (p[0]) {
                msg_disconnect => return error.Closed,
                msg_ignore, msg_debug, msg_unimplemented => continue,
                msg_request_success, msg_request_failure => continue,
                kex.msg_kexinit => {
                    try t.runKex(p);
                    continue;
                },
                kex.msg_newkeys, kex.msg_kex_ecdh_init, kex.msg_kex_ecdh_reply => return error.Protocol,
                else => return p,
            }
        }
    }

    /// Version exchange and the first key exchange.
    pub fn handshake(t: *Transport) Error!void {
        try t.sendRaw(version ++ "\r\n");
        try t.readVersion();
        try t.sendKexInit();
        const p = try t.readPacket();
        // Strict kex or not, the first packet must be KEXINIT.
        if (p[0] != kex.msg_kexinit) return error.Protocol;
        try t.runKex(p);
    }

    fn readVersion(t: *Transport) Error!void {
        var lines: usize = 0;
        while (lines < 32) : (lines += 1) {
            var line: [256]u8 = undefined;
            var n: usize = 0;
            while (true) {
                var b: [1]u8 = undefined;
                try t.take(&b);
                if (b[0] == '\n') break;
                if (n == line.len) return error.Protocol;
                line[n] = b[0];
                n += 1;
            }
            const l = std.mem.trimRight(u8, line[0..n], "\r");
            if (!std.mem.startsWith(u8, l, "SSH-")) continue;
            if (!std.mem.startsWith(u8, l, "SSH-2.0-") and !std.mem.startsWith(u8, l, "SSH-1.99-")) return error.Protocol;
            @memcpy(t.v_c[0..l.len], l);
            t.v_c_len = l.len;
            return;
        }
        return error.Protocol;
    }

    fn hasEd(t: *const Transport) bool {
        for (t.opts.host_keys) |*k| if (k.* == .ed25519) return true;
        return false;
    }

    fn hasRsa(t: *const Transport) bool {
        for (t.opts.host_keys) |*k| if (k.* == .rsa) return true;
        return false;
    }

    fn sendKexInit(t: *Transport) Error!void {
        var w = wire.Writer.init(&t.our_kexinit);
        kex.writeKexInit(&w, t.hasEd(), t.hasRsa(), t.session_id == null) catch return error.Protocol;
        t.our_kexinit_len = w.len;
        t.kexinit_sent = true;
        try t.writePacket(w.written());
    }

    /// Server-started re-exchange: queue whatever arrives before the client's KEXINIT.
    fn serverRekey(t: *Transport) Error!void {
        if (!t.kexinit_sent) try t.sendKexInit();
        while (true) {
            const p = try t.readPacket();
            switch (p[0]) {
                kex.msg_kexinit => return t.runKex(p),
                msg_disconnect => return error.Closed,
                msg_ignore, msg_debug, msg_unimplemented, msg_request_success, msg_request_failure => {},
                kex.msg_newkeys, kex.msg_kex_ecdh_init => return error.Protocol,
                else => {
                    if (t.pending_bytes + p.len > max_pending_bytes) return error.Protocol;
                    const copy = try t.gpa.dupe(u8, p);
                    errdefer t.gpa.free(copy);
                    try t.pending.append(t.gpa, copy);
                    t.pending_bytes += p.len;
                },
            }
        }
    }

    /// Reads the next kex-phase packet, skipping what the rules allow.
    fn readKexPacket(t: *Transport, initial_strict: bool) Error![]u8 {
        while (true) {
            const p = try t.readPacket();
            switch (p[0]) {
                msg_disconnect => return error.Closed,
                msg_ignore, msg_debug => if (initial_strict) return error.Protocol else continue,
                else => return p,
            }
        }
    }

    fn runKex(t: *Transport, client_kexinit: []const u8) Error!void {
        const first = t.session_id == null;
        if (client_kexinit.len > 64 * 1024) return error.Protocol;
        const i_c = try t.gpa.dupe(u8, client_kexinit);
        defer t.gpa.free(i_c);
        if (!t.kexinit_sent) try t.sendKexInit();
        const n = kex.negotiate(i_c, t.hasEd(), t.hasRsa(), first) catch |e| return switch (e) {
            error.NoCommonAlgorithm => error.NoCommonAlgorithm,
            error.BadMessage => error.Protocol,
        };
        if (first) t.strict = n.strict;
        const initial_strict = first and t.strict;

        var p = try t.readKexPacket(initial_strict);
        if (n.skip_guess) p = try t.readKexPacket(initial_strict);
        if (p[0] != kex.msg_kex_ecdh_init) return error.Protocol;
        var r = wire.Reader.init(p[1..]);
        const q_c_view = r.stringMax(4096) catch return error.Protocol;
        if (!r.done()) return error.Protocol;
        var q_c_buf: [4096]u8 = undefined;
        const q_c = q_c_buf[0..q_c_view.len];
        @memcpy(q_c, q_c_view);

        var q_s: [kex.max_reply]u8 = undefined;
        var q_s_len: usize = 0;
        var secret = kex.serverExchange(n.kex, q_c, &q_s, &q_s_len) catch return error.Protocol;
        defer secret.wipe();

        const hk = for (t.opts.host_keys) |*k| {
            if (k.supports(n.host)) break k;
        } else return error.NoCommonAlgorithm;
        var ks_buf: [keys.max_pub_blob]u8 = undefined;
        var ks = wire.Writer.init(&ks_buf);
        hk.writeBlob(&ks) catch return error.Protocol;

        const h = kex.exchangeHash(t.v_c[0..t.v_c_len], version, i_c, t.our_kexinit[0..t.our_kexinit_len], ks.written(), q_c, q_s[0..q_s_len], &secret);
        if (first) t.session_id = h;

        var reply_buf: [kex.max_reply + keys.max_pub_blob + keys.max_sig_blob + 64]u8 = undefined;
        var w = wire.Writer.init(&reply_buf);
        w.byte(kex.msg_kex_ecdh_reply) catch return error.Protocol;
        w.string(ks.written()) catch return error.Protocol;
        w.string(q_s[0..q_s_len]) catch return error.Protocol;
        const sig_start = w.beginString() catch return error.Protocol;
        hk.sign(n.host, &h, &w) catch return error.Protocol;
        w.endString(sig_start);
        try t.writePacket(w.written());
        try t.writePacket(&.{kex.msg_newkeys});

        var c = kex.makeCiphers(n, &secret, h, t.session_id.?);
        t.tx.wipe();
        t.tx = c.sc;
        if (t.strict) t.tx_seq = 0;
        if (first and n.ext_info) try t.sendExtInfo();

        const nk = try t.readKexPacket(initial_strict);
        if (nk[0] != kex.msg_newkeys or nk.len != 1) return error.Protocol;
        t.rx.wipe();
        t.rx = c.cs;
        std.crypto.secureZero(u8, std.mem.asBytes(&c));
        if (t.strict) t.rx_seq = 0;
        t.kexinit_sent = false;
        t.bytes_since_kex = 0;
    }

    fn sendExtInfo(t: *Transport) Error!void {
        var buf: [128]u8 = undefined;
        var w = wire.Writer.init(&buf);
        w.byte(msg_ext_info) catch return error.Protocol;
        w.u32be(1) catch return error.Protocol;
        w.string("server-sig-algs") catch return error.Protocol;
        w.string(keys.user_sig_algs) catch return error.Protocol;
        try t.writePacket(w.written());
    }

    /// Replies UNIMPLEMENTED to the last message returned by `read`.
    pub fn unimplemented(t: *Transport) Error!void {
        var buf: [5]u8 = undefined;
        buf[0] = msg_unimplemented;
        std.mem.writeInt(u32, buf[1..5], t.last_seq, .big);
        try t.write(&buf);
    }

    /// Best-effort DISCONNECT.
    pub fn disconnect(t: *Transport, reason: u32, text: []const u8) void {
        var buf: [256]u8 = undefined;
        var w = wire.Writer.init(&buf);
        w.byte(msg_disconnect) catch return;
        w.u32be(reason) catch return;
        w.string(text[0..@min(text.len, 200)]) catch return;
        w.string("") catch return;
        t.writePacket(w.written()) catch {};
    }
};

test "transport handshake against an in-process client" {
    // Exercises version exchange, kex and packets over a socketpair with a scripted client.
    const a = std.testing.allocator;
    var fds: [2]i32 = undefined;
    if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds) != 0) return error.SkipZigTest;
    defer posix.close(fds[1]);
    const host = [_]keys.HostKey{.{ .ed25519 = std.crypto.sign.Ed25519.KeyPair.generate() }};
    var t = try Transport.init(a, fds[0], .{ .host_keys = &host });
    defer {
        posix.close(fds[0]);
        t.deinit();
    }
    const th = try std.Thread.spawn(.{}, testClient, .{fds[1]});
    try t.handshake();
    const m = try t.read();
    try std.testing.expectEqualStrings(&.{ msg_service_request, 'x' }, m);
    try t.write("\x06ok");
    th.join();
}

fn testClient(fd: posix.socket_t) void {
    testClientRun(fd) catch |e| std.debug.panic("client: {t}", .{e});
}

fn testClientRun(fd: posix.socket_t) !void {
    const X25519 = std.crypto.dh.X25519;
    _ = try posix.write(fd, "SSH-2.0-test\r\n");
    var rb: [65536]u8 = undefined;
    var have: usize = 0;
    // Server version line.
    while (std.mem.indexOf(u8, rb[0..have], "\r\n") == null) have += try posix.read(fd, rb[have..]);
    const eol = std.mem.indexOf(u8, rb[0..have], "\r\n").? + 2;
    std.mem.copyForwards(u8, &rb, rb[eol..have]);
    have -= eol;
    const v_s = version;
    var rx: cipher.Cipher = .none;
    var tx: cipher.Cipher = .none;
    var rseq: u32 = 0;
    var tseq: u32 = 0;
    const Io = struct {
        fn recv(f: posix.socket_t, buf: *[65536]u8, n: *usize, c: *cipher.Cipher, seq: *u32, out: []u8) ![]u8 {
            while (n.* < 4) n.* += try posix.read(f, buf[n.*..]);
            const len = try c.openLength(seq.*, buf[0..4].*);
            const total = 4 + c.restLen(len);
            while (n.* < total) n.* += try posix.read(f, buf[n.*..]);
            @memcpy(out[0..total], buf[0..total]);
            std.mem.copyForwards(u8, buf, buf[total..n.*]);
            n.* -= total;
            const p = try c.open(seq.*, out[0..total]);
            seq.* +%= 1;
            return p;
        }
        fn send(f: posix.socket_t, c: *cipher.Cipher, seq: *u32, payload: []const u8) !void {
            var o: [2048]u8 = undefined;
            const pkt = try c.seal(seq.*, payload, &o);
            seq.* +%= 1;
            _ = try posix.write(f, pkt);
        }
    };
    var pbuf: [65536]u8 = undefined;
    const i_s_view = try Io.recv(fd, &rb, &have, &rx, &rseq, &pbuf);
    var i_s_buf: [1024]u8 = undefined;
    const i_s = i_s_buf[0..i_s_view.len];
    @memcpy(i_s, i_s_view);
    var ki_buf: [512]u8 = undefined;
    var w = wire.Writer.init(&ki_buf);
    try w.byte(kex.msg_kexinit);
    try w.bytes(&([_]u8{1} ** 16));
    for ([_][]const u8{ "curve25519-sha256," ++ kex.strict_c, "ssh-ed25519", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "" }) |s| try w.string(s);
    try w.boolean(false);
    try w.u32be(0);
    const i_c = w.written();
    try Io.send(fd, &tx, &tseq, i_c);
    const eph = X25519.KeyPair.generate();
    var ib: [64]u8 = undefined;
    var iw = wire.Writer.init(&ib);
    try iw.byte(kex.msg_kex_ecdh_init);
    try iw.string(&eph.public_key);
    try Io.send(fd, &tx, &tseq, iw.written());
    const reply = try Io.recv(fd, &rb, &have, &rx, &rseq, &pbuf);
    var r = wire.Reader.init(reply[1..]);
    const k_s = try r.string();
    const q_s = try r.string();
    const sig = try r.string();
    const shared = try X25519.scalarmult(eph.secret_key, q_s[0..32].*);
    var k: kex.Secret = .{};
    var kw = wire.Writer.init(&k.buf);
    try kw.mpint(&shared);
    k.len = kw.len;
    const h = kex.exchangeHash("SSH-2.0-test", v_s, i_c, i_s, k_s, &eph.public_key, q_s, &k);
    if (!keys.verify("ssh-ed25519", k_s, sig, &h)) return error.BadHostSignature;
    const nk = try Io.recv(fd, &rb, &have, &rx, &rseq, &pbuf);
    if (nk[0] != kex.msg_newkeys) return error.NoNewKeys;
    try Io.send(fd, &tx, &tseq, &.{kex.msg_newkeys});
    const n: kex.Negotiated = .{ .kex = .curve25519_sha256, .host = .ssh_ed25519, .enc_cs = .aes256_gcm, .enc_sc = .chacha20_poly1305, .skip_guess = false, .strict = true, .ext_info = false };
    const c = kex.makeCiphers(n, &k, h, h);
    tx = c.cs;
    rx = c.sc;
    // Strict kex: sequence numbers restart after NEWKEYS.
    tseq = 0;
    rseq = 0;
    try Io.send(fd, &tx, &tseq, &.{ msg_ignore, 0, 0, 0, 0 });
    try Io.send(fd, &tx, &tseq, &.{ msg_service_request, 'x' });
    const ok = try Io.recv(fd, &rb, &have, &rx, &rseq, &pbuf);
    if (!std.mem.eql(u8, ok, "\x06ok")) return error.BadReply;
}
