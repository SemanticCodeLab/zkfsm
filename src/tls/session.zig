//! Server side of one TLS 1.3 connection: handshake, then std.Io.Reader/Writer
//! over protected records. No PSK, no 0-RTT; optional client certificates.
const std = @import("std");
const tls = std.crypto.tls;
const hs = @import("handshake.zig");
const sched = @import("schedule.zig");
const config = @import("config.zig");
const keys = @import("keys.zig");
const peer_cert = @import("peer.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const X25519 = std.crypto.dh.X25519;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    PeerAlert,
    ConnectionClosed,
    Truncated,
    HandshakeFailure,
    ProtocolVersion,
    DecodeError,
    IllegalParameter,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    DecryptError,
    NoApplicationProtocol,
    MissingExtension,
    BadCertificate,
    CertificateExpired,
    UnknownCa,
    InternalError,
    OutOfMemory,
};

const max_handshake_msg = 1 << 16;
const max_flight = 1 << 17;
const max_early_skip = 1 << 16;
/// Rekey well before the AES-GCM per-key record limit (RFC 8446 5.5).
const rekey_after: u64 = 1 << 22;
const alpn_http11 = "http/1.1";

fn Pair(comptime S: type) type {
    return struct { read: S.Traffic, write: S.Traffic };
}

const Keys = union(enum) {
    none,
    aes128: Pair(sched.Aes128),
    aes256: Pair(sched.Aes256),
    chacha: Pair(sched.Chacha),
};

/// Verified client certificate subject; `common_name` lives inside the Session.
pub const PeerIdentity = struct { common_name: []const u8, not_before_s: i64, not_after_s: i64 };

const suite_fields = .{ .{ sched.Aes128, "aes128" }, .{ sched.Aes256, "aes256" }, .{ sched.Chacha, "chacha" } };

pub const Session = struct {
    gpa: std.mem.Allocator,
    input: *Reader,
    output: *Writer,
    reader: Reader,
    writer: Writer,
    keys: Keys = .none,
    read_protected: bool = false,
    write_protected: bool = false,
    received_close: bool = false,
    sent_close: bool = false,
    failed: ?Error = null,
    ccs_seen: u8 = 0,
    early_skip: usize = 0,
    sni_buf: [255]u8 = undefined,
    sni_len: u8 = 0,
    alpn: bool = false,
    peer_cn_buf: [peer_cert.max_common_name]u8 = undefined,
    peer_cn_len: u8 = 0,
    peer_not_before: i64 = 0,
    peer_not_after: i64 = 0,
    pend: []u8 = &.{},
    // Handshake reassembly, only allocated during the handshake.
    hs_buf: []u8 = &.{},
    hs_start: usize = 0,
    hs_end: usize = 0,
    rbuf: [32 * 1024]u8 = undefined,
    wbuf: [sched.max_plaintext]u8 = undefined,
    rec: [sched.header_len + sched.max_ciphertext]u8 = undefined,
    plain: [sched.max_ciphertext]u8 = undefined,
    scratch: [sched.max_plaintext + 1]u8 = undefined,
    out: [sched.header_len + sched.max_ciphertext]u8 = undefined,

    /// Runs the server handshake over `input`/`output`. On error an alert has been sent.
    pub fn accept(gpa: std.mem.Allocator, ctx: *config.Context, input: *Reader, output: *Writer) Error!*Session {
        const s = try gpa.create(Session);
        s.* = .{
            .gpa = gpa,
            .input = input,
            .output = output,
            .reader = .{ .buffer = &.{}, .vtable = &.{ .stream = stream, .readVec = readVec }, .seek = 0, .end = 0 },
            .writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain, .flush = flush } },
        };
        s.reader.buffer = &s.rbuf;
        s.writer.buffer = &s.wbuf;
        const creds = ctx.acquire();
        defer creds.release();
        s.handshake(creds, ctx.client_cas) catch |e| {
            s.sendAlertFor(e);
            s.destroy();
            return e;
        };
        return s;
    }

    /// Server name the client asked for, if any.
    pub fn serverName(s: *const Session) ?[]const u8 {
        return if (s.sni_len > 0) s.sni_buf[0..s.sni_len] else null;
    }

    /// Verified client certificate identity, if the client presented one with a usable CN.
    pub fn peerIdentity(s: *const Session) ?PeerIdentity {
        if (s.peer_cn_len == 0) return null;
        return .{ .common_name = s.peer_cn_buf[0..s.peer_cn_len], .not_before_s = s.peer_not_before, .not_after_s = s.peer_not_after };
    }

    pub fn negotiatedHttp11(s: *const Session) bool {
        return s.alpn;
    }

    /// Flushes, sends close_notify, and frees the session.
    pub fn close(s: *Session) void {
        if (s.failed == null and !s.sent_close) {
            flush(&s.writer) catch {};
            s.sendAlert(.close_notify);
        }
        s.destroy();
    }

    fn destroy(s: *Session) void {
        s.freeHandshake();
        switch (s.keys) {
            .none => {},
            inline else => |*p| {
                p.read.wipe();
                p.write.wipe();
            },
        }
        std.crypto.secureZero(u8, &s.plain);
        std.crypto.secureZero(u8, &s.rbuf);
        std.crypto.secureZero(u8, &s.wbuf);
        s.gpa.destroy(s);
    }

    fn freeHandshake(s: *Session) void {
        if (s.hs_buf.len == 0) return;
        std.crypto.secureZero(u8, s.hs_buf);
        s.gpa.free(s.hs_buf);
        s.hs_buf = &.{};
    }

    // ---- handshake ----

    fn handshake(s: *Session, creds: *config.Credentials, cas: []const []const u8) Error!void {
        s.hs_buf = try s.gpa.alloc(u8, max_handshake_msg + 4);
        defer s.freeHandshake();
        const flight = try s.gpa.alloc(u8, max_flight);
        defer {
            std.crypto.secureZero(u8, flight);
            s.gpa.free(flight);
        }
        const msg = try s.readHandshake();
        if (msg[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.UnexpectedMessage;
        const ch = try parseHello(msg);
        inline for (suite_fields) |sf| {
            if (ch.offersSuite(sf[0].suite_id)) return s.run(sf[0], sf[1], creds, cas, msg, ch, flight);
        }
        return error.HandshakeFailure;
    }

    const Negotiated = struct { scheme: keys.SignatureScheme, alpn: bool };

    fn negotiate(ch: hs.ClientHello, creds: *config.Credentials) Error!Negotiated {
        const algs = ch.sig_algs orelse return error.MissingExtension;
        const scheme = creds.key.chooseScheme(algs) orelse return error.HandshakeFailure;
        var alpn = false;
        if (ch.alpn != null) {
            if (!ch.offersAlpn(alpn_http11)) return error.NoApplicationProtocol;
            alpn = true;
        }
        if (ch.key_shares != null and ch.groups == null) return error.MissingExtension;
        return .{ .scheme = scheme, .alpn = alpn };
    }

    fn run(s: *Session, comptime S: type, comptime field: []const u8, creds: *config.Credentials, cas: []const []const u8, msg1: []const u8, ch1: hs.ClientHello, flight: []u8) Error!void {
        var ch = ch1;
        var neg = try negotiate(ch, creds);
        const groups = ch.groups orelse return error.MissingExtension;
        const group: u16, const retry = if (ch.keyShare(hs.group_x25519) != null)
            .{ hs.group_x25519, false }
        else if (ch.keyShare(hs.group_secp256r1) != null)
            .{ hs.group_secp256r1, false }
        else if (hs.containsU16(groups, hs.group_x25519))
            .{ hs.group_x25519, true }
        else if (hs.containsU16(groups, hs.group_secp256r1))
            .{ hs.group_secp256r1, true }
        else
            return error.HandshakeFailure;

        var sid_buf: [32]u8 = undefined;
        const sid = sid_buf[0..ch.session_id.len];
        @memcpy(sid, ch.session_id);
        var sent_ccs = false;
        var transcript = S.Hash.init(.{});
        var msg = msg1;
        s.early_skip = if (ch.early_data) max_early_skip else 0;

        if (retry) {
            var h1: [S.hash_len]u8 = undefined;
            S.Hash.hash(msg1, &h1, .{});
            transcript.update(&.{ @intFromEnum(tls.HandshakeType.message_hash), 0, 0, S.hash_len });
            transcript.update(&h1);
            var b: hs.Builder = .{ .buf = flight };
            hs.helloRetryRequest(&b, sid, S.suite_id, group) catch return error.InternalError;
            transcript.update(b.written());
            try s.sendPlain(.handshake, b.written());
            if (sid.len > 0) {
                try s.sendPlain(.change_cipher_spec, &.{1});
                sent_ccs = true;
            }
            s.output.flush() catch return error.ConnectionClosed;
            msg = try s.readHandshake();
            if (msg[0] != @intFromEnum(tls.HandshakeType.client_hello)) return error.UnexpectedMessage;
            ch = try parseHello(msg);
            if (!std.mem.eql(u8, ch.session_id, sid) or !ch.offersSuite(S.suite_id) or ch.early_data or
                ch.keyShareCount() != 1 or ch.keyShare(group) == null) return error.IllegalParameter;
            neg = try negotiate(ch, creds);
            s.early_skip = 0;
        }
        transcript.update(msg);
        if (ch.sni) |name| {
            @memcpy(s.sni_buf[0..name.len], name);
            s.sni_len = @intCast(name.len);
        }
        s.alpn = neg.alpn;

        // Key exchange.
        var shared: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &shared);
        var pub_buf: [65]u8 = undefined;
        const peer = ch.keyShare(group).?;
        const our_pub: []const u8 = switch (group) {
            hs.group_x25519 => blk: {
                if (peer.len != X25519.public_length) return error.IllegalParameter;
                var kp = X25519.KeyPair.generate();
                defer std.crypto.secureZero(u8, &kp.secret_key);
                shared = X25519.scalarmult(kp.secret_key, peer[0..32].*) catch return error.IllegalParameter;
                pub_buf[0..32].* = kp.public_key;
                break :blk pub_buf[0..32];
            },
            else => blk: {
                if (peer.len != 65 or peer[0] != 4) return error.IllegalParameter;
                const pk = P256.PublicKey.fromSec1(peer) catch return error.IllegalParameter;
                var kp = P256.KeyPair.generate();
                defer std.crypto.secureZero(u8, std.mem.asBytes(&kp.secret_key));
                const point = pk.p.mul(kp.secret_key.bytes, .big) catch return error.IllegalParameter;
                shared = point.affineCoordinates().x.toBytes(.big);
                pub_buf = kp.public_key.toUncompressedSec1();
                break :blk &pub_buf;
            },
        };

        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);
        {
            var b: hs.Builder = .{ .buf = flight };
            hs.serverHello(&b, random, sid, S.suite_id, group, our_pub) catch return error.InternalError;
            transcript.update(b.written());
            try s.sendPlain(.handshake, b.written());
        }
        if (sid.len > 0 and !sent_ccs) try s.sendPlain(.change_cipher_spec, &.{1});

        var ks = S.Schedule.init(&shared);
        defer ks.wipe();
        var c_hs = S.derive(ks.handshake, "c hs traffic", &peek(S, transcript));
        defer std.crypto.secureZero(u8, &c_hs);
        var s_hs = S.derive(ks.handshake, "s hs traffic", &peek(S, transcript));
        defer std.crypto.secureZero(u8, &s_hs);
        s.keys = @unionInit(Keys, field, .{ .read = S.Traffic.init(c_hs), .write = S.Traffic.init(s_hs) });
        const pair = &@field(s.keys, field);
        s.read_protected = true;
        s.write_protected = true;

        // EncryptedExtensions, Certificate, CertificateVerify, Finished.
        var b: hs.Builder = .{ .buf = flight };
        var mark = b.len;
        hs.encryptedExtensions(&b, if (neg.alpn) alpn_http11 else null, ch.sni != null) catch return error.InternalError;
        if (cas.len > 0) hs.certificateRequest(&b, &peer_cert.schemes) catch return error.InternalError;
        hs.certificate(&b, creds.chain) catch return error.InternalError;
        transcript.update(b.buf[mark..b.len]);
        {
            var content_buf: [200]u8 = undefined;
            const content = hs.verifyContent(&content_buf, &peek(S, transcript));
            var sig_buf: [keys.max_signature_len]u8 = undefined;
            const sig = creds.key.sign(neg.scheme, content, &sig_buf) catch return error.InternalError;
            mark = b.len;
            hs.certificateVerify(&b, @intFromEnum(neg.scheme), sig) catch return error.InternalError;
            transcript.update(b.buf[mark..b.len]);
        }
        var s_fin = S.finishedData(s_hs, &peek(S, transcript));
        mark = b.len;
        hs.finished(&b, &s_fin) catch return error.InternalError;
        transcript.update(b.buf[mark..b.len]);
        try s.sendProtected(.handshake, b.written());
        s.output.flush() catch return error.ConnectionClosed;

        const th = peek(S, transcript);
        var c_ap = S.derive(ks.master, "c ap traffic", &th);
        defer std.crypto.secureZero(u8, &c_ap);
        var s_ap = S.derive(ks.master, "s ap traffic", &th);
        defer std.crypto.secureZero(u8, &s_ap);
        pair.write.wipe();
        pair.write = S.Traffic.init(s_ap);

        // Client auth messages extend the transcript for Finished only (RFC 8446 7.1).
        if (cas.len > 0) try s.clientAuth(S, &transcript, cas);
        var expected = S.finishedData(c_hs, &peek(S, transcript));
        defer std.crypto.secureZero(u8, &expected);
        const fin = try s.readHandshake();
        if (fin[0] != @intFromEnum(tls.HandshakeType.finished)) return error.UnexpectedMessage;
        if (fin.len != 4 + S.hash_len) return error.DecodeError;
        if (!std.crypto.timing_safe.eql([S.hash_len]u8, fin[4..][0..S.hash_len].*, expected)) return error.DecryptError;
        if (s.hs_end != s.hs_start) return error.UnexpectedMessage;
        pair.read.wipe();
        pair.read = S.Traffic.init(c_ap);
        s.early_skip = 0;
    }

    fn clientAuth(s: *Session, comptime S: type, transcript: *S.Hash, cas: []const []const u8) Error!void {
        const m = try s.readHandshake();
        if (m[0] != @intFromEnum(tls.HandshakeType.certificate)) return error.UnexpectedMessage;
        // Later reads compact hs_buf, so keep our own copy of the chain.
        const msg = try s.gpa.dupe(u8, m);
        defer s.gpa.free(msg);
        transcript.update(msg);
        var list: [hs.max_peer_chain][]const u8 = undefined;
        const chain = try hs.parseCertificate(msg[4..], &list);
        if (chain.len == 0) return;
        const leaf = try peer_cert.verifyChain(chain, cas, std.time.timestamp());

        const cv = try s.readHandshake();
        if (cv[0] != @intFromEnum(tls.HandshakeType.certificate_verify)) return error.UnexpectedMessage;
        var c: hs.Cursor = .{ .b = cv[4..] };
        const scheme = try c.int(u16);
        const sig = try c.vec(u16);
        if (c.left() != 0) return error.DecodeError;
        var content_buf: [200]u8 = undefined;
        const content = hs.verifyContentFor(&content_buf, hs.client_verify_context, &peek(S, transcript.*));
        try peer_cert.verifySignature(leaf, scheme, sig, content);
        transcript.update(cv);
        if (peer_cert.commonName(leaf)) |cn| {
            @memcpy(s.peer_cn_buf[0..cn.len], cn);
            s.peer_cn_len = @intCast(cn.len);
            s.peer_not_before = @intCast(leaf.validity.not_before);
            s.peer_not_after = @intCast(leaf.validity.not_after);
        }
    }

    fn peek(comptime S: type, t: S.Hash) [S.hash_len]u8 {
        var c = t;
        var out: [S.hash_len]u8 = undefined;
        c.final(&out);
        return out;
    }

    fn parseHello(msg: []const u8) Error!hs.ClientHello {
        return hs.ClientHello.parse(msg[4..]) catch |e| switch (e) {
            error.DecodeError => error.DecodeError,
            error.IllegalParameter => error.IllegalParameter,
            error.ProtocolVersion => error.ProtocolVersion,
        };
    }

    /// Returns the next complete handshake message (header included).
    fn readHandshake(s: *Session) Error![]const u8 {
        if (s.hs_start > 0) {
            const n = s.hs_end - s.hs_start;
            std.mem.copyForwards(u8, s.hs_buf[0..n], s.hs_buf[s.hs_start..s.hs_end]);
            s.hs_start = 0;
            s.hs_end = n;
        }
        while (true) {
            const have = s.hs_end - s.hs_start;
            if (have >= 4) {
                const len = std.mem.readInt(u24, s.hs_buf[s.hs_start + 1 ..][0..3], .big);
                if (len > max_handshake_msg) return error.DecodeError;
                if (have >= 4 + len) {
                    const m = s.hs_buf[s.hs_start..][0 .. 4 + len];
                    s.hs_start += 4 + len;
                    return m;
                }
            }
            const rec = try s.nextRecord();
            switch (rec.ct) {
                .handshake => {
                    if (rec.data.len == 0) return error.UnexpectedMessage;
                    if (s.hs_buf.len - s.hs_end < rec.data.len) return error.DecodeError;
                    @memcpy(s.hs_buf[s.hs_end..][0..rec.data.len], rec.data);
                    s.hs_end += rec.data.len;
                },
                .change_cipher_spec => {
                    s.ccs_seen += 1;
                    if (rec.data.len != 1 or rec.data[0] != 1 or s.ccs_seen > 1) return error.UnexpectedMessage;
                },
                .alert => return peerAlert(rec.data),
                else => return error.UnexpectedMessage,
            }
        }
    }

    const Record = struct { ct: tls.ContentType, data: []u8 };

    /// Reads one record and removes protection; skips rejected 0-RTT data.
    fn nextRecord(s: *Session) Error!Record {
        while (true) {
            const n = s.input.readSliceShort(s.rec[0..sched.header_len]) catch return error.ConnectionClosed;
            if (n == 0) return error.ConnectionClosed;
            if (n < sched.header_len) return error.Truncated;
            const hdr = s.rec[0..sched.header_len];
            const ct: tls.ContentType = @enumFromInt(hdr[0]);
            const len = std.mem.readInt(u16, hdr[3..5], .big);
            if (hdr[1] != 3) return error.DecodeError;
            if (len > sched.max_ciphertext) return error.RecordOverflow;
            const body = s.rec[sched.header_len..][0..len];
            s.input.readSliceAll(body) catch return error.Truncated;
            switch (ct) {
                .change_cipher_spec => return .{ .ct = ct, .data = body },
                .handshake, .alert => {
                    if (s.read_protected) return error.UnexpectedMessage;
                    if (len > sched.max_plaintext) return error.RecordOverflow;
                    return .{ .ct = ct, .data = body };
                },
                .application_data => {
                    if (!s.read_protected) return error.UnexpectedMessage;
                    const opened = switch (s.keys) {
                        .none => return error.InternalError,
                        inline else => |*p| p.read.open(hdr, body, &s.plain),
                    } catch |e| switch (e) {
                        error.BadRecordMac => {
                            if (s.early_skip >= body.len) {
                                s.early_skip -= body.len;
                                continue;
                            }
                            return error.BadRecordMac;
                        },
                        else => |x| return x,
                    };
                    s.early_skip = 0;
                    return .{ .ct = opened[0], .data = opened[1] };
                },
                else => return error.UnexpectedMessage,
            }
        }
    }

    fn peerAlert(data: []const u8) Error {
        if (data.len != 2) return error.DecodeError;
        if (data[1] == @intFromEnum(tls.Alert.Description.close_notify)) return error.ConnectionClosed;
        std.log.debug("tls: peer alert {d}", .{data[1]});
        return error.PeerAlert;
    }

    fn sendPlain(s: *Session, ct: tls.ContentType, data: []const u8) Error!void {
        var rest = data;
        while (true) {
            const n = @min(rest.len, sched.max_plaintext);
            const hdr = [_]u8{ @intFromEnum(ct), 3, 3, @intCast(n >> 8), @truncate(n) };
            s.output.writeAll(&hdr) catch return error.ConnectionClosed;
            s.output.writeAll(rest[0..n]) catch return error.ConnectionClosed;
            rest = rest[n..];
            if (rest.len == 0) return;
        }
    }

    fn sendProtected(s: *Session, ct: tls.ContentType, data: []const u8) Error!void {
        var rest = data;
        while (true) {
            const n = @min(rest.len, sched.max_plaintext);
            const len = switch (s.keys) {
                .none => return error.InternalError,
                inline else => |*p| p.write.seal(ct, rest[0..n], &s.scratch, &s.out),
            };
            s.output.writeAll(s.out[0..len]) catch return error.ConnectionClosed;
            rest = rest[n..];
            if (rest.len == 0) return;
        }
    }

    fn sendAlert(s: *Session, desc: tls.Alert.Description) void {
        const level: u8 = if (desc == .close_notify) 1 else 2;
        const body = [_]u8{ level, @intFromEnum(desc) };
        const r = if (s.write_protected) s.sendProtected(.alert, &body) else s.sendPlain(.alert, &body);
        r catch return;
        s.output.flush() catch {};
        s.sent_close = true;
    }

    fn sendAlertFor(s: *Session, e: Error) void {
        const desc: tls.Alert.Description = switch (e) {
            error.PeerAlert, error.ConnectionClosed, error.Truncated => return,
            error.HandshakeFailure => .handshake_failure,
            error.ProtocolVersion => .protocol_version,
            error.DecodeError => .decode_error,
            error.IllegalParameter => .illegal_parameter,
            error.UnexpectedMessage => .unexpected_message,
            error.BadRecordMac => .bad_record_mac,
            error.RecordOverflow => .record_overflow,
            error.DecryptError => .decrypt_error,
            error.NoApplicationProtocol => .no_application_protocol,
            error.MissingExtension => .missing_extension,
            error.BadCertificate => .bad_certificate,
            error.CertificateExpired => .certificate_expired,
            error.UnknownCa => .unknown_ca,
            error.InternalError, error.OutOfMemory => .internal_error,
        };
        s.sendAlert(desc);
    }

    fn fail(s: *Session, e: Error) void {
        if (s.failed != null) return;
        s.failed = e;
        s.sendAlertFor(e);
    }

    // ---- application data ----

    /// Makes plaintext available in `reader.buffer`; returns 0 like std's TLS client.
    fn fill(s: *Session) Reader.Error!usize {
        if (s.failed != null) return error.ReadFailed;
        while (s.pend.len == 0) {
            if (s.received_close) return error.EndOfStream;
            const rec = s.nextRecord() catch |e| switch (e) {
                error.ConnectionClosed => {
                    s.received_close = true;
                    return error.EndOfStream;
                },
                else => {
                    s.fail(e);
                    return error.ReadFailed;
                },
            };
            switch (rec.ct) {
                .application_data => s.pend = rec.data,
                .alert => {
                    const e = peerAlert(rec.data);
                    if (e == error.ConnectionClosed) {
                        s.received_close = true;
                        return error.EndOfStream;
                    }
                    s.fail(e);
                    return error.ReadFailed;
                },
                .handshake => s.postHandshake(rec.data) catch |e| {
                    s.fail(e);
                    return error.ReadFailed;
                },
                else => {
                    s.fail(error.UnexpectedMessage);
                    return error.ReadFailed;
                },
            }
        }
        const r = &s.reader;
        if (r.buffer.len - r.end < s.pend.len and r.seek > 0) {
            const live = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = live;
        }
        const n = @min(r.buffer.len - r.end, s.pend.len);
        @memcpy(r.buffer[r.end..][0..n], s.pend[0..n]);
        r.end += n;
        s.pend = s.pend[n..];
        return 0;
    }

    /// Post-handshake messages must arrive whole; only KeyUpdate is accepted.
    fn postHandshake(s: *Session, data: []const u8) Error!void {
        var c: hs.Cursor = .{ .b = data };
        while (c.left() > 0) {
            const typ = c.int(u8) catch return error.DecodeError;
            const body = c.vec(u24) catch return error.UnexpectedMessage;
            if (typ != @intFromEnum(tls.HandshakeType.key_update)) return error.UnexpectedMessage;
            if (body.len != 1) return error.DecodeError;
            if (c.left() != 0) return error.UnexpectedMessage;
            const requested = switch (body[0]) {
                0 => false,
                1 => true,
                else => return error.IllegalParameter,
            };
            switch (s.keys) {
                .none => return error.InternalError,
                inline else => |*p| p.read.update(),
            }
            if (requested and !s.sent_close) try s.sendKeyUpdate();
        }
    }

    fn sendKeyUpdate(s: *Session) Error!void {
        const msg = [_]u8{ @intFromEnum(tls.HandshakeType.key_update), 0, 0, 1, 0 };
        try s.sendProtected(.handshake, &msg);
        switch (s.keys) {
            .none => return error.InternalError,
            inline else => |*p| p.write.update(),
        }
    }

    fn sealApp(s: *Session, data: []const u8) Writer.Error!void {
        const seq = switch (s.keys) {
            .none => return error.WriteFailed,
            inline else => |*p| p.write.seq,
        };
        if (seq >= rekey_after) s.sendKeyUpdate() catch return error.WriteFailed;
        s.sendProtected(.application_data, data) catch return error.WriteFailed;
    }

    fn sealAll(s: *Session, data: []const u8) Writer.Error!void {
        var rest = data;
        while (rest.len > 0) {
            const n = @min(rest.len, sched.max_plaintext);
            try s.sealApp(rest[0..n]);
            rest = rest[n..];
        }
    }
};

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    _ = w;
    _ = limit;
    const s: *Session = @alignCast(@fieldParentPtr("reader", r));
    return s.fill();
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    _ = data;
    const s: *Session = @alignCast(@fieldParentPtr("reader", r));
    return s.fill();
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const s: *Session = @alignCast(@fieldParentPtr("writer", w));
    if (s.failed != null or s.sent_close) return error.WriteFailed;
    try s.sealAll(w.buffered());
    w.end = 0;
    var total: usize = 0;
    for (data[0 .. data.len - 1]) |d| {
        try s.sealAll(d);
        total += d.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| {
        try s.sealAll(last);
        total += last.len;
    }
    return total;
}

fn flush(w: *Writer) Writer.Error!void {
    const s: *Session = @alignCast(@fieldParentPtr("writer", w));
    if (s.failed != null or s.sent_close) return error.WriteFailed;
    try s.sealAll(w.buffered());
    w.end = 0;
    s.output.flush() catch return error.WriteFailed;
}
