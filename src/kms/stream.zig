//! DARE-style AES-256-GCM object stream: header `"ZKS1" || nonce[12]`, then 64 KiB
//! packages `hdr[8] || ct || tag[16]` with a sequence-XORed nonce and an
//! authenticated final flag, so truncation and reordering are detected.
const std = @import("std");

const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;

pub const package_size = 64 * 1024;
pub const tag_len = Aes.tag_length;
pub const stream_header_len = 16;
pub const package_header_len = 8;
pub const package_overhead = package_header_len + tag_len;
const magic = "ZKS1";
const pkg_version: u8 = 1;
const flag_final: u8 = 1;

pub const DecryptError = error{ Truncated, AuthenticationFailed, Malformed, TrailingData, SequenceOverflow, ReadFailed };
pub const EncryptError = error{ SequenceOverflow, WriteFailed, AlreadyFinished };

/// Ciphertext size for a plaintext of `n` bytes.
pub fn encryptedSize(n: u64) u64 {
    const pkgs = @max(1, std.math.divCeil(u64, n, package_size) catch unreachable);
    return stream_header_len + pkgs * package_overhead + n;
}

/// Byte offset of package `idx` within the ciphertext (for range reads).
pub fn packageOffset(idx: u64) u64 {
    return stream_header_len + idx * (package_size + package_overhead);
}

fn nonceFor(base: [12]u8, seq: u32) [12]u8 {
    var n = base;
    const tail = std.mem.readInt(u32, n[8..12], .big) ^ seq;
    std.mem.writeInt(u32, n[8..12], tail, .big);
    return n;
}

const aad_prefix_len = stream_header_len + package_header_len;

/// Encrypting std.Io.Writer. Call `finish` after the last write; a stream
/// without `finish` fails to decrypt (no final package).
pub const Encryptor = struct {
    out: *Writer,
    key: [32]u8,
    aad: []const u8,
    head: [stream_header_len]u8,
    seq: u32 = 0,
    started: bool = false,
    finished: bool = false,
    err: ?EncryptError = null,
    /// One spare byte: a full package is emitted only once more data follows, so
    /// the final package is never empty and `encryptedSize` always holds.
    buf: [package_size + 1]u8 = undefined,
    ct: [package_size]u8 = undefined,
    interface: Writer,

    /// `self` must not move after init. `aad` must outlive the encryptor.
    pub fn init(self: *Encryptor, out: *Writer, key: *const [32]u8, aad: []const u8) void {
        self.* = .{ .out = out, .key = key.*, .aad = aad, .head = undefined, .interface = .{
            .buffer = &self.buf,
            .end = 0,
            .vtable = &.{ .drain = drain, .flush = flush },
        } };
        self.head[0..4].* = magic.*;
        std.crypto.random.bytes(self.head[4..16]);
    }

    pub fn deinit(self: *Encryptor) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.buf);
        std.crypto.secureZero(u8, &self.ct);
    }

    pub fn writer(self: *Encryptor) *Writer {
        return &self.interface;
    }

    /// Emits the final package and flushes the underlying writer.
    pub fn finish(self: *Encryptor) EncryptError!void {
        if (self.finished) return error.AlreadyFinished;
        if (self.err) |e| return e;
        if (self.interface.end > package_size) try self.emitFull();
        try self.emit(self.interface.end, true);
        self.interface.end = 0;
        self.finished = true;
        self.out.flush() catch return error.WriteFailed;
    }

    fn emit(self: *Encryptor, len: usize, final: bool) EncryptError!void {
        if (!self.started) {
            self.out.writeAll(&self.head) catch return error.WriteFailed;
            self.started = true;
        }
        if (self.seq == std.math.maxInt(u32)) return error.SequenceOverflow;
        var hdr = [package_header_len]u8{ pkg_version, if (final) flag_final else 0, 0, 0, 0, 0, 0, 0 };
        std.mem.writeInt(u32, hdr[4..8], @intCast(len), .little);
        const ad_prefix: [aad_prefix_len]u8 = self.head ++ hdr;
        var tag: [tag_len]u8 = undefined;
        encryptWithAad(self.ct[0..len], &tag, self.buf[0..len], &ad_prefix, self.aad, nonceFor(self.head[4..16].*, self.seq), self.key);
        self.out.writeAll(&hdr) catch return error.WriteFailed;
        self.out.writeAll(self.ct[0..len]) catch return error.WriteFailed;
        self.out.writeAll(&tag) catch return error.WriteFailed;
        self.seq += 1;
    }

    fn emitFull(self: *Encryptor) EncryptError!void {
        try self.emit(package_size, false);
        self.buf[0] = self.buf[package_size];
        self.interface.end = 1;
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *Encryptor = @fieldParentPtr("interface", w);
        if (self.finished) {
            self.err = error.AlreadyFinished;
            return error.WriteFailed;
        }
        if (w.end == w.buffer.len) self.emitFull() catch |e| {
            self.err = e;
            return error.WriteFailed;
        };
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            const k = copyIn(w, d);
            n += k;
            if (k < d.len) return n;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            const k = copyIn(w, last);
            n += k;
            if (k < last.len) return n;
        }
        return n;
    }

    fn copyIn(w: *Writer, d: []const u8) usize {
        const k = @min(d.len, w.buffer.len - w.end);
        @memcpy(w.buffer[w.end..][0..k], d[0..k]);
        w.end += k;
        return k;
    }

    fn flush(w: *Writer) Writer.Error!void {
        // Partial packages cannot be emitted before finish; only push lower layer.
        const self: *Encryptor = @fieldParentPtr("interface", w);
        try self.out.flush();
    }
};

// AES-GCM takes one AAD slice; join the fixed prefix and caller AAD.
fn encryptWithAad(c: []u8, tag: *[tag_len]u8, m: []const u8, prefix: []const u8, aad: []const u8, nonce: [12]u8, key: [32]u8) void {
    var small: [aad_prefix_len + 256]u8 = undefined;
    if (aad.len <= 256) {
        @memcpy(small[0..prefix.len], prefix);
        @memcpy(small[prefix.len..][0..aad.len], aad);
        Aes.encrypt(c, tag, m, small[0 .. prefix.len + aad.len], nonce, key);
    } else {
        // Long AAD: bind its SHA-256 instead.
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(aad, &h, .{});
        @memcpy(small[0..prefix.len], prefix);
        @memcpy(small[prefix.len..][0..32], &h);
        Aes.encrypt(c, tag, m, small[0 .. prefix.len + 32], nonce, key);
    }
}

fn decryptWithAad(m: []u8, c: []const u8, tag: [tag_len]u8, prefix: []const u8, aad: []const u8, nonce: [12]u8, key: [32]u8) error{AuthenticationFailed}!void {
    var small: [aad_prefix_len + 256]u8 = undefined;
    @memcpy(small[0..prefix.len], prefix);
    var ad_len = prefix.len;
    if (aad.len <= 256) {
        @memcpy(small[prefix.len..][0..aad.len], aad);
        ad_len += aad.len;
    } else {
        std.crypto.hash.sha2.Sha256.hash(aad, small[prefix.len..][0..32], .{});
        ad_len += 32;
    }
    Aes.decrypt(m, c, tag, small[0..ad_len], nonce, key) catch return error.AuthenticationFailed;
}

/// Decrypting std.Io.Reader. Reports `error.ReadFailed`; see `err` for cause.
pub const Decryptor = struct {
    in: *Reader,
    key: [32]u8,
    aad: []const u8,
    head: ?[stream_header_len]u8 = null,
    seq: u32 = 0,
    done: bool = false,
    err: ?DecryptError = null,
    buf: [2 * package_size]u8 = undefined,
    ct: [package_size + tag_len]u8 = undefined,
    interface: Reader,

    /// `self` must not move after init. `in` is positioned at stream start.
    pub fn init(self: *Decryptor, in: *Reader, key: *const [32]u8, aad: []const u8) void {
        self.* = .{ .in = in, .key = key.*, .aad = aad, .interface = .{
            .buffer = &self.buf,
            .seek = 0,
            .end = 0,
            .vtable = &.{ .stream = stream, .discard = discard },
        } };
    }

    /// Range read: `in` positioned at `packageOffset(first_package)`; the
    /// caller supplies the stream header it read from offset 0.
    pub fn initAt(self: *Decryptor, in: *Reader, key: *const [32]u8, aad: []const u8, head: [stream_header_len]u8, first_package: u32) void {
        self.init(in, key, aad);
        self.head = head;
        self.seq = first_package;
    }

    pub fn deinit(self: *Decryptor) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.buf);
    }

    pub fn reader(self: *Decryptor) *Reader {
        return &self.interface;
    }

    fn fail(self: *Decryptor, e: DecryptError) Reader.StreamError {
        self.err = e;
        return error.ReadFailed;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const self: *Decryptor = @fieldParentPtr("interface", r);
        if (self.err != null) return error.ReadFailed;
        if (self.done) return error.EndOfStream;
        if (r.buffer.len - r.end < package_size) {
            const live = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = live;
        }
        const head = self.head orelse blk: {
            const h = self.in.takeArray(stream_header_len) catch |e| return self.fail(mapRead(e));
            if (!std.mem.eql(u8, h[0..4], magic)) return self.fail(error.Malformed);
            self.head = h.*;
            break :blk h.*;
        };
        const hdr = (self.in.takeArray(package_header_len) catch |e| return self.fail(mapRead(e))).*;
        const len = std.mem.readInt(u32, hdr[4..8], .little);
        const final = hdr[1] == flag_final;
        if (hdr[0] != pkg_version or hdr[1] & ~flag_final != 0 or hdr[2] != 0 or hdr[3] != 0 or len > package_size)
            return self.fail(error.Malformed);
        if (!final and len != package_size) return self.fail(error.Malformed);
        self.in.readSliceAll(self.ct[0 .. len + tag_len]) catch |e| return self.fail(mapRead(e));
        const prefix: [aad_prefix_len]u8 = head ++ hdr;
        decryptWithAad(r.buffer[r.end..][0..len], self.ct[0..len], self.ct[len..][0..tag_len].*, &prefix, self.aad, nonceFor(head[4..16].*, self.seq), self.key) catch
            return self.fail(error.AuthenticationFailed);
        if (self.seq == std.math.maxInt(u32)) return self.fail(error.SequenceOverflow);
        self.seq += 1;
        r.end += len;
        if (final) {
            self.done = true;
            if (self.in.peekByte()) |_| {
                r.end -= len;
                return self.fail(error.TrailingData);
            } else |e| switch (e) {
                error.EndOfStream => {},
                error.ReadFailed => return self.fail(error.ReadFailed),
            }
        }
        return 0;
    }

    // Packages land in `buffer`, so the default discard (which lends the
    // buffer out as a sink) cannot be used.
    fn discard(r: *Reader, limit: std.Io.Limit) Reader.Error!usize {
        var sink: Writer.Discarding = .init(&.{});
        _ = stream(r, &sink.writer, limit) catch |e| switch (e) {
            error.WriteFailed => unreachable, // stream never writes to the sink
            else => |re| return re,
        };
        const n = limit.minInt(r.end - r.seek);
        r.seek += n;
        return n;
    }

    fn mapRead(e: Reader.Error) DecryptError {
        return switch (e) {
            error.EndOfStream => error.Truncated,
            error.ReadFailed => error.ReadFailed,
        };
    }
};

/// Whole-buffer helpers (tests, small objects).
pub fn encryptAlloc(gpa: std.mem.Allocator, key: *const [32]u8, aad: []const u8, plain: []const u8) (EncryptError || error{OutOfMemory})![]u8 {
    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const enc = try gpa.create(Encryptor);
    defer gpa.destroy(enc);
    enc.init(&out.writer, key, aad);
    defer enc.deinit();
    enc.writer().writeAll(plain) catch return enc.err orelse error.WriteFailed;
    try enc.finish();
    return out.toOwnedSlice();
}

pub fn decryptAlloc(gpa: std.mem.Allocator, key: *const [32]u8, aad: []const u8, cipher: []const u8) (DecryptError || error{OutOfMemory})![]u8 {
    var in: Reader = .fixed(cipher);
    const dec = try gpa.create(Decryptor);
    defer gpa.destroy(dec);
    dec.init(&in, key, aad);
    defer dec.deinit();
    return dec.reader().allocRemaining(gpa, .unlimited) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed => dec.err orelse error.ReadFailed,
        error.StreamTooLong => unreachable,
    };
}

const testing = std.testing;

fn testKey() [32]u8 {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @intCast(i * 7 + 3);
    return k;
}

test "round trip at many sizes" {
    const gpa = testing.allocator;
    const key = testKey();
    const sizes = [_]usize{ 0, 1, 15, 16, 17, 4095, 65535, 65536, 65537, 131071, 131072, 131073, 3 * 65536 + 123, 1 << 20 };
    const src = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(src);
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(src);
    for (sizes) |n| {
        const ct = try encryptAlloc(gpa, &key, "bucket/object", src[0..n]);
        defer gpa.free(ct);
        try testing.expectEqual(encryptedSize(n), ct.len);
        const pt = try decryptAlloc(gpa, &key, "bucket/object", ct);
        defer gpa.free(pt);
        try testing.expectEqualSlices(u8, src[0..n], pt);
    }
}

test "odd write sizes through the writer adapter" {
    const gpa = testing.allocator;
    const key = testKey();
    const src = try gpa.alloc(u8, 300_001);
    defer gpa.free(src);
    for (src, 0..) |*b, i| b.* = @truncate(i *% 31);
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    const enc = try gpa.create(Encryptor);
    defer gpa.destroy(enc);
    enc.init(&out.writer, &key, "");
    var off: usize = 0;
    var step: usize = 1;
    while (off < src.len) : (step = step * 3 + 1) {
        const k = @min(step % 70_000 + 1, src.len - off);
        try enc.writer().writeAll(src[off..][0..k]);
        try enc.writer().flush();
        off += k;
    }
    try enc.writer().splatByteAll('z', 10);
    try enc.finish();
    enc.deinit();
    const pt = try decryptAlloc(gpa, &key, "", out.written());
    defer gpa.free(pt);
    try testing.expectEqualSlices(u8, src, pt[0..src.len]);
    try testing.expectEqualSlices(u8, "zzzzzzzzzz", pt[src.len..]);
}

test "exact package multiples never end in an empty package" {
    const gpa = testing.allocator;
    const key = testKey();
    for ([_]usize{ package_size, 2 * package_size, 2 * package_size + 1 }) |n| {
        const src = try gpa.alloc(u8, n);
        defer gpa.free(src);
        @memset(src, 0x5A);
        var out: Writer.Allocating = .init(gpa);
        defer out.deinit();
        const enc = try gpa.create(Encryptor);
        defer gpa.destroy(enc);
        enc.init(&out.writer, &key, "");
        defer enc.deinit();
        try enc.writer().writeAll(src);
        // Readers may ask for room after the last byte (std.http bodies do).
        _ = try enc.writer().writableSliceGreedy(1);
        try enc.finish();
        try testing.expectEqual(encryptedSize(n), out.written().len);
        const pt = try decryptAlloc(gpa, &key, "", out.written());
        defer gpa.free(pt);
        try testing.expectEqualSlices(u8, src, pt);
    }
}

test "truncation, reorder, tamper, aad and key mismatch are detected" {
    const gpa = testing.allocator;
    const key = testKey();
    const n = 3 * package_size + 500;
    const src = try gpa.alloc(u8, n);
    defer gpa.free(src);
    @memset(src, 0xAB);
    const ct = try encryptAlloc(gpa, &key, "aad", src);
    defer gpa.free(ct);
    const pkg = package_size + package_overhead;

    // Truncation at a package boundary: missing final package.
    try testing.expectError(error.Truncated, decryptAlloc(gpa, &key, "aad", ct[0 .. stream_header_len + 2 * pkg]));
    // Truncation mid-package and empty input.
    try testing.expectError(error.Truncated, decryptAlloc(gpa, &key, "aad", ct[0 .. ct.len - 1]));
    try testing.expectError(error.Truncated, decryptAlloc(gpa, &key, "aad", ""));
    try testing.expectError(error.Truncated, decryptAlloc(gpa, &key, "aad", ct[0..stream_header_len]));

    // Reorder packages 0 and 1.
    const swapped = try gpa.dupe(u8, ct);
    defer gpa.free(swapped);
    @memcpy(swapped[stream_header_len..][0..pkg], ct[stream_header_len + pkg ..][0..pkg]);
    @memcpy(swapped[stream_header_len + pkg ..][0..pkg], ct[stream_header_len..][0..pkg]);
    try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &key, "aad", swapped));

    // Bit flips in header nonce, payload, tag.
    for ([_]usize{ 5, stream_header_len + 100, stream_header_len + pkg - 1, ct.len - 1 }) |pos| {
        const t = try gpa.dupe(u8, ct);
        defer gpa.free(t);
        t[pos] ^= 0x01;
        try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &key, "aad", t));
    }
    // Forging the final flag on a middle package.
    {
        const t = try gpa.dupe(u8, ct[0 .. stream_header_len + pkg]);
        defer gpa.free(t);
        t[stream_header_len + 1] = flag_final;
        try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &key, "aad", t));
    }
    // Trailing data after final package.
    {
        const t = try std.mem.concat(gpa, u8, &.{ ct, "x" });
        defer gpa.free(t);
        try testing.expectError(error.TrailingData, decryptAlloc(gpa, &key, "aad", t));
    }
    try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &key, "other", ct));
    var bad = key;
    bad[0] ^= 1;
    try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &bad, "aad", ct));
    // Long AAD path.
    const long = [_]u8{'q'} ** 1000;
    const ct2 = try encryptAlloc(gpa, &key, &long, "hi");
    defer gpa.free(ct2);
    const pt2 = try decryptAlloc(gpa, &key, &long, ct2);
    defer gpa.free(pt2);
    try testing.expectEqualStrings("hi", pt2);
    try testing.expectError(error.AuthenticationFailed, decryptAlloc(gpa, &key, long[0..999], ct2));
}

test "range read from a package offset" {
    const gpa = testing.allocator;
    const key = testKey();
    const src = try gpa.alloc(u8, 4 * package_size + 10);
    defer gpa.free(src);
    for (src, 0..) |*b, i| b.* = @truncate(i >> 8);
    const ct = try encryptAlloc(gpa, &key, "", src);
    defer gpa.free(ct);
    var in: Reader = .fixed(ct[@intCast(packageOffset(2))..]);
    const dec = try gpa.create(Decryptor);
    defer gpa.destroy(dec);
    dec.initAt(&in, &key, "", ct[0..stream_header_len].*, 2);
    const pt = try dec.reader().allocRemaining(gpa, .unlimited);
    defer gpa.free(pt);
    try testing.expectEqualSlices(u8, src[2 * package_size ..], pt);
    // Wrong starting index fails authentication.
    var in2: Reader = .fixed(ct[@intCast(packageOffset(2))..]);
    dec.initAt(&in2, &key, "", ct[0..stream_header_len].*, 1);
    try testing.expectError(error.ReadFailed, dec.reader().allocRemaining(gpa, .unlimited));
    try testing.expectEqual(DecryptError.AuthenticationFailed, dec.err.?);
}

test "decryptor supports discard" {
    const gpa = std.testing.allocator;
    const key = [_]u8{9} ** 32;
    const plain = try gpa.alloc(u8, 2 * package_size + 10);
    defer gpa.free(plain);
    for (plain, 0..) |*b, i| b.* = @truncate(i);
    const ct = try encryptAlloc(gpa, &key, "ad", plain);
    defer gpa.free(ct);
    var in: Reader = .fixed(ct);
    const dec = try gpa.create(Decryptor);
    defer gpa.destroy(dec);
    dec.init(&in, &key, "ad");
    defer dec.deinit();
    try dec.reader().discardAll(package_size + 5);
    var got: [7]u8 = undefined;
    try dec.reader().readSliceAll(&got);
    try std.testing.expectEqualSlices(u8, plain[package_size + 5 ..][0..7], &got);
}
