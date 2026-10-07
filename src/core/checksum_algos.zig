//! S3 additional checksums: CRC32, CRC32C, CRC64NVME, SHA1, SHA256.
//! Streaming: call `Hasher.update` on every body chunk, then `final`.
//! Multipart: `composite` (hash of part digests, "-N") or `combineParts` (full-object CRC).

const std = @import("std");

const b64 = std.base64.standard;

pub const Error = error{ InvalidChecksum, UnsupportedChecksumType };

/// Largest raw digest (SHA256).
pub const max_digest_len = 32;
/// Room for base64(32 bytes) + "-" + part count.
pub const max_text_len = 64;

pub const Algorithm = enum {
    crc32,
    crc32c,
    crc64nvme,
    sha1,
    sha256,

    pub fn parse(name: []const u8) ?Algorithm {
        inline for (std.meta.fields(Algorithm)) |f| {
            if (std.ascii.eqlIgnoreCase(name, f.name)) return @enumFromInt(f.value);
        }
        return null;
    }

    pub fn wireName(self: Algorithm) []const u8 {
        return switch (self) {
            .crc32 => "CRC32",
            .crc32c => "CRC32C",
            .crc64nvme => "CRC64NVME",
            .sha1 => "SHA1",
            .sha256 => "SHA256",
        };
    }

    pub fn headerName(self: Algorithm) []const u8 {
        return switch (self) {
            .crc32 => "x-amz-checksum-crc32",
            .crc32c => "x-amz-checksum-crc32c",
            .crc64nvme => "x-amz-checksum-crc64nvme",
            .sha1 => "x-amz-checksum-sha1",
            .sha256 => "x-amz-checksum-sha256",
        };
    }

    pub fn fromHeaderName(name: []const u8) ?Algorithm {
        const prefix = "x-amz-checksum-";
        if (name.len <= prefix.len) return null;
        if (!std.ascii.eqlIgnoreCase(name[0..prefix.len], prefix)) return null;
        return parse(name[prefix.len..]);
    }

    pub fn digestLen(self: Algorithm) usize {
        return switch (self) {
            .crc32, .crc32c => 4,
            .crc64nvme => 8,
            .sha1 => 20,
            .sha256 => 32,
        };
    }

    pub fn isCrc(self: Algorithm) bool {
        return switch (self) {
            .crc32, .crc32c, .crc64nvme => true,
            .sha1, .sha256 => false,
        };
    }

    /// Length of the base64 text of a single (non-composite) digest.
    pub fn base64Len(self: Algorithm) usize {
        return b64.Encoder.calcSize(self.digestLen());
    }
};

pub const ChecksumType = enum {
    composite,
    full_object,

    pub fn wireName(self: ChecksumType) []const u8 {
        return switch (self) {
            .composite => "COMPOSITE",
            .full_object => "FULL_OBJECT",
        };
    }

    pub fn parse(name: []const u8) ?ChecksumType {
        if (std.ascii.eqlIgnoreCase(name, "COMPOSITE")) return .composite;
        if (std.ascii.eqlIgnoreCase(name, "FULL_OBJECT")) return .full_object;
        return null;
    }

    /// Multipart default when the client names only the algorithm.
    pub fn defaultFor(alg: Algorithm) ChecksumType {
        return if (alg == .crc64nvme) .full_object else .composite;
    }

    /// SHA digests cannot be combined, so they only allow COMPOSITE.
    pub fn supports(self: ChecksumType, alg: Algorithm) bool {
        return switch (self) {
            .composite => alg != .crc64nvme,
            .full_object => alg.isCrc(),
        };
    }
};

/// Reflected (LSB-first) CRC with init = xorout = all ones, slicing-by-8.
fn ReflectedCrc(comptime T: type, comptime poly_normal: T) type {
    return struct {
        const Self = @This();
        pub const poly: T = @bitReverse(poly_normal);
        const tables: [8][256]T = blk: {
            @setEvalBranchQuota(100_000);
            var t: [8][256]T = undefined;
            for (0..256) |i| {
                var c: T = @intCast(i);
                for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ poly else c >> 1;
                t[0][i] = c;
            }
            for (0..256) |i| {
                for (1..8) |k| t[k][i] = (t[k - 1][i] >> 8) ^ t[0][@as(u8, @truncate(t[k - 1][i]))];
            }
            break :blk t;
        };

        crc: T = ~@as(T, 0),

        pub fn update(self: *Self, bytes: []const u8) void {
            var c = self.crc;
            var i: usize = 0;
            while (i + 8 <= bytes.len) : (i += 8) {
                const w = std.mem.readInt(u64, bytes[i..][0..8], .little);
                if (T == u64) {
                    const x = c ^ w;
                    c = tables[7][@as(u8, @truncate(x))] ^ tables[6][@as(u8, @truncate(x >> 8))] ^
                        tables[5][@as(u8, @truncate(x >> 16))] ^ tables[4][@as(u8, @truncate(x >> 24))] ^
                        tables[3][@as(u8, @truncate(x >> 32))] ^ tables[2][@as(u8, @truncate(x >> 40))] ^
                        tables[1][@as(u8, @truncate(x >> 48))] ^ tables[0][@as(u8, @truncate(x >> 56))];
                } else {
                    const lo: u32 = c ^ @as(u32, @truncate(w));
                    const hi: u32 = @truncate(w >> 32);
                    c = tables[7][@as(u8, @truncate(lo))] ^ tables[6][@as(u8, @truncate(lo >> 8))] ^
                        tables[5][@as(u8, @truncate(lo >> 16))] ^ tables[4][@as(u8, @truncate(lo >> 24))] ^
                        tables[3][@as(u8, @truncate(hi))] ^ tables[2][@as(u8, @truncate(hi >> 8))] ^
                        tables[1][@as(u8, @truncate(hi >> 16))] ^ tables[0][@as(u8, @truncate(hi >> 24))];
                }
            }
            for (bytes[i..]) |b| c = (c >> 8) ^ tables[0][@as(u8, @truncate(c)) ^ b];
            self.crc = c;
        }

        pub fn final(self: Self) T {
            return ~self.crc;
        }

        pub fn hash(bytes: []const u8) T {
            var s: Self = .{};
            s.update(bytes);
            return s.final();
        }

        // GF(2) product mod poly in reflected form (zlib multmodp).
        fn mulMod(a: T, b_in: T) T {
            const top: T = @as(T, 1) << (@bitSizeOf(T) - 1);
            var m = top;
            var p: T = 0;
            var b = b_in;
            while (true) {
                if (a & m != 0) {
                    p ^= b;
                    if (a & (m - 1) == 0) break;
                }
                m >>= 1;
                if (m == 0) break;
                b = if (b & 1 != 0) (b >> 1) ^ poly else b >> 1;
            }
            return p;
        }

        // pow2[k] = x^(2^k) mod poly; k up to 66 covers 8 * maxInt(u64) bits.
        const pow2: [67]T = blk: {
            @setEvalBranchQuota(1_000_000);
            var t: [67]T = undefined;
            t[0] = @as(T, 1) << (@bitSizeOf(T) - 2);
            for (1..67) |k| t[k] = mulMod(t[k - 1], t[k - 1]);
            break :blk t;
        };

        /// CRC of A||B from crc(A), crc(B) and len(B).
        pub fn combine(crc_a: T, crc_b: T, len_b: u64) T {
            var p: T = @as(T, 1) << (@bitSizeOf(T) - 1);
            var n = len_b;
            var k: usize = 3; // bytes -> bits
            while (n != 0) : ({
                n >>= 1;
                k += 1;
            }) {
                if (n & 1 != 0) p = mulMod(pow2[k], p);
            }
            return mulMod(p, crc_a) ^ crc_b;
        }
    };
}

pub const Crc32 = ReflectedCrc(u32, 0x04C11DB7);
pub const Crc32c = ReflectedCrc(u32, 0x1EDC6F41);
pub const Crc64Nvme = ReflectedCrc(u64, 0xAD93D23594C93659);

pub const Hasher = union(Algorithm) {
    crc32: Crc32,
    crc32c: Crc32c,
    crc64nvme: Crc64Nvme,
    sha1: std.crypto.hash.Sha1,
    sha256: std.crypto.hash.sha2.Sha256,

    pub fn init(alg: Algorithm) Hasher {
        return switch (alg) {
            .crc32 => .{ .crc32 = .{} },
            .crc32c => .{ .crc32c = .{} },
            .crc64nvme => .{ .crc64nvme = .{} },
            .sha1 => .{ .sha1 = std.crypto.hash.Sha1.init(.{}) },
            .sha256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
        };
    }

    pub fn update(self: *Hasher, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    /// Raw digest; CRCs are big-endian.
    pub fn final(self: *Hasher, out: *[max_digest_len]u8) []const u8 {
        switch (self.*) {
            .crc32 => |h| std.mem.writeInt(u32, out[0..4], h.final(), .big),
            .crc32c => |h| std.mem.writeInt(u32, out[0..4], h.final(), .big),
            .crc64nvme => |h| std.mem.writeInt(u64, out[0..8], h.final(), .big),
            .sha1 => |*h| h.final(out[0..20]),
            .sha256 => |*h| h.final(out[0..32]),
        }
        return out[0..std.meta.activeTag(self.*).digestLen()];
    }

    pub fn finalBase64(self: *Hasher, buf: *[max_text_len]u8) []const u8 {
        var raw: [max_digest_len]u8 = undefined;
        return b64.Encoder.encode(buf, self.final(&raw));
    }

    pub fn algorithm(self: Hasher) Algorithm {
        return std.meta.activeTag(self);
    }
};

/// One-shot raw digest.
pub fn digest(alg: Algorithm, bytes: []const u8, out: *[max_digest_len]u8) []const u8 {
    var h = Hasher.init(alg);
    h.update(bytes);
    return h.final(out);
}

/// Decode a single-digest base64 value, enforcing the algorithm's length.
pub fn decodeBase64(alg: Algorithm, text: []const u8, out: *[max_digest_len]u8) error{InvalidChecksum}![]const u8 {
    if (text.len != alg.base64Len()) return error.InvalidChecksum;
    const n = b64.Decoder.calcSizeForSlice(text) catch return error.InvalidChecksum;
    if (n != alg.digestLen()) return error.InvalidChecksum;
    b64.Decoder.decode(out[0..n], text) catch return error.InvalidChecksum;
    return out[0..n];
}

pub fn encodeBase64(raw: []const u8, buf: *[max_text_len]u8) error{InvalidChecksum}![]const u8 {
    if (raw.len > max_digest_len) return error.InvalidChecksum;
    return b64.Encoder.encode(buf, raw);
}

/// COMPOSITE: base64(hash(digest_1 || ... || digest_N)) ++ "-N".
pub fn composite(alg: Algorithm, part_digests: []const []const u8, out: *[max_text_len]u8) error{InvalidChecksum}![]const u8 {
    if (part_digests.len == 0) return error.InvalidChecksum;
    var h = Hasher.init(alg);
    for (part_digests) |d| {
        if (d.len != alg.digestLen()) return error.InvalidChecksum;
        h.update(d);
    }
    var raw: [max_digest_len]u8 = undefined;
    const enc = b64.Encoder.encode(out, h.final(&raw));
    const suffix = std.fmt.bufPrint(out[enc.len..], "-{d}", .{part_digests.len}) catch return error.InvalidChecksum;
    return out[0 .. enc.len + suffix.len];
}

/// CRC of A||B from crc(A), crc(B) and len(B); values are zero-extended CRCs.
pub fn combine(alg: Algorithm, crc_a: u64, crc_b: u64, len_b: u64) Error!u64 {
    return switch (alg) {
        .crc32 => Crc32.combine(@truncate(crc_a), @truncate(crc_b), len_b),
        .crc32c => Crc32c.combine(@truncate(crc_a), @truncate(crc_b), len_b),
        .crc64nvme => Crc64Nvme.combine(crc_a, crc_b, len_b),
        .sha1, .sha256 => error.UnsupportedChecksumType,
    };
}

pub const Part = struct { digest: []const u8, len: u64 };

/// FULL_OBJECT: whole-object CRC (big-endian raw bytes) from per-part CRCs and sizes.
pub fn combineParts(alg: Algorithm, parts: []const Part, out: *[max_digest_len]u8) Error![]const u8 {
    if (!alg.isCrc()) return error.UnsupportedChecksumType;
    if (parts.len == 0) return error.InvalidChecksum;
    const n = alg.digestLen();
    var acc: u64 = 0;
    for (parts, 0..) |p, i| {
        if (p.digest.len != n) return error.InvalidChecksum;
        const v: u64 = if (n == 4) std.mem.readInt(u32, p.digest[0..4], .big) else std.mem.readInt(u64, p.digest[0..8], .big);
        acc = if (i == 0) v else try combine(alg, acc, v, p.len);
    }
    if (n == 4) std.mem.writeInt(u32, out[0..4], @truncate(acc), .big) else std.mem.writeInt(u64, out[0..8], acc, .big);
    return out[0..n];
}

// ---- tests ----

const testing = std.testing;

test "check values" {
    const s = "123456789";
    try testing.expectEqual(@as(u32, 0xCBF43926), Crc32.hash(s));
    try testing.expectEqual(@as(u32, 0xE3069283), Crc32c.hash(s));
    try testing.expectEqual(@as(u64, 0xAE8B14860A799888), Crc64Nvme.hash(s));
    try testing.expectEqual(std.hash.Crc32.hash(s), Crc32.hash(s));
    try testing.expectEqual(std.hash.crc.Crc32Iscsi.hash(s), Crc32c.hash(s));
}

test "names" {
    try testing.expectEqual(Algorithm.crc64nvme, Algorithm.parse("CRC64NVME").?);
    try testing.expectEqual(Algorithm.crc32c, Algorithm.parse("crc32c").?);
    try testing.expect(Algorithm.parse("md5") == null);
    try testing.expectEqual(Algorithm.sha256, Algorithm.fromHeaderName("X-Amz-Checksum-SHA256").?);
    try testing.expect(Algorithm.fromHeaderName("x-amz-checksum-") == null);
    try testing.expect(Algorithm.fromHeaderName("x-amz-checksum-type") == null);
    inline for (std.meta.fields(Algorithm)) |f| {
        const a: Algorithm = @enumFromInt(f.value);
        try testing.expectEqual(a, Algorithm.parse(a.wireName()).?);
        try testing.expectEqual(a, Algorithm.fromHeaderName(a.headerName()).?);
    }
    try testing.expectEqual(ChecksumType.full_object, ChecksumType.defaultFor(.crc64nvme));
    try testing.expectEqual(ChecksumType.composite, ChecksumType.defaultFor(.sha256));
}

test "streaming in odd chunks equals one-shot" {
    var prng = std.Random.DefaultPrng.init(42);
    var data: [5000]u8 = undefined;
    prng.random().bytes(&data);
    inline for (std.meta.fields(Algorithm)) |f| {
        const a: Algorithm = @enumFromInt(f.value);
        var one: [max_digest_len]u8 = undefined;
        const want = digest(a, &data, &one);
        for ([_]usize{ 1, 3, 7, 13, 64, 1021 }) |step| {
            var h = Hasher.init(a);
            var i: usize = 0;
            while (i < data.len) : (i += step) h.update(data[i..@min(i + step, data.len)]);
            var got: [max_digest_len]u8 = undefined;
            try testing.expectEqualSlices(u8, want, h.final(&got));
        }
    }
}

test "combine equals crc of concatenation" {
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var data: [4096]u8 = undefined;
    r.bytes(&data);
    for (0..50) |_| {
        const cut = r.uintAtMost(usize, data.len);
        const a = data[0..cut];
        const b = data[cut..];
        try testing.expectEqual(@as(u64, Crc32.hash(&data)), try combine(.crc32, Crc32.hash(a), Crc32.hash(b), b.len));
        try testing.expectEqual(@as(u64, Crc32c.hash(&data)), try combine(.crc32c, Crc32c.hash(a), Crc32c.hash(b), b.len));
        try testing.expectEqual(Crc64Nvme.hash(&data), try combine(.crc64nvme, Crc64Nvme.hash(a), Crc64Nvme.hash(b), b.len));
    }
    try testing.expectError(error.UnsupportedChecksumType, combine(.sha1, 0, 0, 1));
}

test "base64 decode validates length" {
    var out: [max_digest_len]u8 = undefined;
    const raw = try decodeBase64(.crc32, "WgDhBQ==", &out);
    try testing.expectEqualSlices(u8, &.{ 0x5a, 0x00, 0xe1, 0x05 }, raw);
    try testing.expectError(error.InvalidChecksum, decodeBase64(.crc32, "bad", &out));
    try testing.expectError(error.InvalidChecksum, decodeBase64(.crc64nvme, "WgDhBQ==", &out));
    try testing.expectError(error.InvalidChecksum, decodeBase64(.crc32, "WgDh!Q==", &out));
    try testing.expectError(error.InvalidChecksum, decodeBase64(.sha256, "", &out));
}

// Vectors from s3-tests test_multipart_use_cksum_helper_*: 3 parts of 5 MiB 'A','B','C'.
test "s3-tests multipart vectors" {
    const size = 5 * 1024 * 1024;
    const body = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(body);
    const Case = struct { alg: Algorithm, parts: [3][]const u8, whole: []const u8 };
    const cases = [_]Case{
        .{ .alg = .sha256, .parts = .{ "275VF5loJr1YYawit0XSHREhkFXYkkPKGuoK0x9VKxI=", "mrHwOfjTL5Zwfj74F05HOQGLdUb7E5szdCbxgUSq6NM=", "Vw7oB/nKQ5xWb3hNgbyfkvDiivl+U+/Dft48nfJfDow=" }, .whole = "uWBwpe1dxI4Vw8Gf0X9ynOdw/SS6VBzfWm9giiv1sf4=-3" },
        .{ .alg = .sha1, .parts = .{ "iIaTCGbm+vdVjNqIMF2S0T7ibMk=", "LS/TJ32bAVKEwRu+sE3X7awh/lk=", "6DDwovUaHwrKNXDMzOGbuvj9kxI=" }, .whole = "sizjvY4eud3MrcHdZM3cQ/ol39o=-3" },
        .{ .alg = .crc64nvme, .parts = .{ "L/E4WYn8v98=", "xW1l19VobYM=", "cK5MnNaWrW4=" }, .whole = "i+6LR0y3eFo=" },
        .{ .alg = .crc32, .parts = .{ "JRTCyQ==", "QoZTGg==", "YAgjqw==" }, .whole = "WgDhBQ==" },
        .{ .alg = .crc32c, .parts = .{ "MDaLrw==", "TH4EZg==", "Z7mBIQ==" }, .whole = "xU+Krw==" },
    };
    for (cases) |c| {
        var raws: [3][max_digest_len]u8 = undefined;
        var slices: [3][]const u8 = undefined;
        var parts: [3]Part = undefined;
        for ("ABC", 0..) |ch, i| {
            @memset(body, ch);
            var h = Hasher.init(c.alg);
            h.update(body);
            var txt: [max_text_len]u8 = undefined;
            try testing.expectEqualStrings(c.parts[i], h.finalBase64(&txt));
            slices[i] = try decodeBase64(c.alg, c.parts[i], &raws[i]);
            parts[i] = .{ .digest = slices[i], .len = size };
        }
        var txt: [max_text_len]u8 = undefined;
        if (c.alg.isCrc()) {
            var raw: [max_digest_len]u8 = undefined;
            const whole = try combineParts(c.alg, &parts, &raw);
            try testing.expectEqualStrings(c.whole, try encodeBase64(whole, &txt));
        } else {
            try testing.expectEqualStrings(c.whole, try composite(c.alg, &slices, &txt));
            try testing.expectError(error.UnsupportedChecksumType, combineParts(c.alg, &parts, &raws[0]));
        }
    }
}

test "composite rejects bad input" {
    var txt: [max_text_len]u8 = undefined;
    try testing.expectError(error.InvalidChecksum, composite(.sha256, &.{}, &txt));
    try testing.expectError(error.InvalidChecksum, composite(.crc32, &.{"abc"}, &txt));
    // CRC32 COMPOSITE: crc32 over the 4-byte part CRCs, "-N".
    const got = try composite(.crc32, &.{ "\x01\x02\x03\x04", "\x05\x06\x07\x08" }, &txt);
    try testing.expectEqualStrings("P8qIxQ==-2", got); // python zlib.crc32
}
