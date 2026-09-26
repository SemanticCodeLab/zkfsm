//! TLS 1.3 key schedule and record protection per cipher suite (RFC 8446 7.1, 5.2).
const std = @import("std");
const tls = std.crypto.tls;
const aead = std.crypto.aead;
const sha2 = std.crypto.hash.sha2;

pub const max_plaintext = 1 << 14;
pub const max_ciphertext = max_plaintext + 256;
pub const header_len = 5;

pub const OpenError = error{ BadRecordMac, RecordOverflow, UnexpectedMessage, DecodeError };

pub fn Suite(comptime Aead: type, comptime H: type, comptime id: u16) type {
    return struct {
        pub const suite_id = id;
        pub const Hash = H;
        pub const Hmac = std.crypto.auth.hmac.Hmac(H);
        pub const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
        pub const hash_len = H.digest_length;
        pub const tag_len = Aead.tag_length;
        pub const Secret = [hash_len]u8;

        pub fn expand(secret: Secret, label: []const u8, ctx: []const u8, comptime len: usize) [len]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret, label, ctx, len);
        }

        pub fn derive(secret: Secret, label: []const u8, transcript: []const u8) Secret {
            return expand(secret, label, transcript, hash_len);
        }

        /// Early, handshake and master secrets from an (EC)DHE shared secret, no PSK.
        pub const Schedule = struct {
            handshake: Secret,
            master: Secret,

            pub fn init(shared: []const u8) Schedule {
                const zeros = [_]u8{0} ** hash_len;
                const empty = tls.emptyHash(H);
                const early = Hkdf.extract(&zeros, &zeros);
                const hs = Hkdf.extract(&derive(early, "derived", &empty), shared);
                return .{ .handshake = hs, .master = Hkdf.extract(&derive(hs, "derived", &empty), &zeros) };
            }

            pub fn wipe(s: *Schedule) void {
                std.crypto.secureZero(u8, &s.handshake);
                std.crypto.secureZero(u8, &s.master);
            }
        };

        pub fn finishedData(base: Secret, transcript: []const u8) Secret {
            var key = expand(base, "finished", "", Hmac.key_length);
            defer std.crypto.secureZero(u8, &key);
            var out: Secret = undefined;
            Hmac.create(&out, transcript, &key);
            return out;
        }

        /// One direction of record protection.
        pub const Traffic = struct {
            secret: Secret,
            key: [Aead.key_length]u8,
            iv: [Aead.nonce_length]u8,
            seq: u64 = 0,

            pub fn init(secret: Secret) Traffic {
                return .{
                    .secret = secret,
                    .key = expand(secret, "key", "", Aead.key_length),
                    .iv = expand(secret, "iv", "", Aead.nonce_length),
                };
            }

            /// KeyUpdate: next generation of this direction's secret.
            pub fn update(t: *Traffic) void {
                const next = init(expand(t.secret, "traffic upd", "", hash_len));
                t.wipe();
                t.* = next;
            }

            pub fn wipe(t: *Traffic) void {
                std.crypto.secureZero(u8, std.mem.asBytes(t));
            }

            fn nonce(t: Traffic) [Aead.nonce_length]u8 {
                var n = t.iv;
                var seq: [8]u8 = undefined;
                std.mem.writeInt(u64, &seq, t.seq, .big);
                for (n[n.len - 8 ..], seq) |*a, b| a.* ^= b;
                return n;
            }

            /// Encrypts `data` with inner type `ct` into `out` as one record; returns its length.
            pub fn seal(t: *Traffic, ct: tls.ContentType, data: []const u8, scratch: []u8, out: []u8) usize {
                std.debug.assert(data.len <= max_plaintext);
                const inner = scratch[0 .. data.len + 1];
                @memcpy(inner[0..data.len], data);
                inner[data.len] = @intFromEnum(ct);
                const body_len = inner.len + tag_len;
                const hdr = out[0..header_len];
                hdr.* = .{ @intFromEnum(tls.ContentType.application_data), 3, 3, @intCast(body_len >> 8), @truncate(body_len) };
                Aead.encrypt(out[header_len..][0..inner.len], out[header_len + inner.len ..][0..tag_len], inner, hdr, t.nonce(), t.key);
                std.crypto.secureZero(u8, inner);
                t.seq += 1;
                return header_len + body_len;
            }

            /// Decrypts one record body into `out`; returns the content and its inner type.
            pub fn open(t: *Traffic, hdr: *const [header_len]u8, body: []const u8, out: []u8) OpenError!struct { tls.ContentType, []u8 } {
                if (body.len > max_ciphertext) return error.RecordOverflow;
                if (body.len < tag_len + 1) return error.BadRecordMac;
                const clen = body.len - tag_len;
                const plain = out[0..clen];
                Aead.decrypt(plain, body[0..clen], body[clen..][0..tag_len].*, hdr, t.nonce(), t.key) catch return error.BadRecordMac;
                t.seq += 1;
                var n = clen;
                while (n > 0 and plain[n - 1] == 0) n -= 1;
                if (n == 0) return error.UnexpectedMessage;
                if (n - 1 > max_plaintext) return error.RecordOverflow;
                return .{ @enumFromInt(plain[n - 1]), plain[0 .. n - 1] };
            }
        };
    };
}

pub const Aes128 = Suite(aead.aes_gcm.Aes128Gcm, sha2.Sha256, 0x1301);
pub const Aes256 = Suite(aead.aes_gcm.Aes256Gcm, sha2.Sha384, 0x1302);
pub const Chacha = Suite(aead.chacha_poly.ChaCha20Poly1305, sha2.Sha256, 0x1303);

/// Server preference order.
pub const suites = .{ Aes128, Aes256, Chacha };
