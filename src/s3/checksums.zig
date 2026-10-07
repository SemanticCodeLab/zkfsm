//! Additional checksums (x-amz-checksum-*): verified while the body streams, from a
//! header or a trailer, stored with the version, and returned on request.
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const sigv4 = @import("sigv4.zig");
const errors = @import("errors.zig");

const ca = core.checksum_algos;
pub const Algorithm = ca.Algorithm;
pub const ChecksumType = ca.ChecksumType;
const Ctx = handler.Ctx;
const Header = std.http.Header;
const Code = errors.Code;

/// `ALG:TYPE:base64` of the object (composite values carry "-N").
pub const stored_header = object.internal_prefix ++ "cksum";
/// Multipart: comma-separated base64 part checksums (kept only while they fit).
pub const parts_header = object.internal_prefix ++ "obj-cksum-parts";
/// Upload marker on completed multipart objects, for idempotent CompleteMultipartUpload retries.
pub const upload_header = object.internal_prefix ++ "obj-upload";
const parts_limit = 2048;

/// Checksum request headers, captured before the body is read.
pub const RequestChecksums = struct {
    value_alg: ?Algorithm = null,
    value: []const u8 = "",
    /// x-amz-sdk-checksum-algorithm / x-amz-checksum-algorithm.
    algorithm: ?Algorithm = null,
    bad_algorithm: bool = false,
    trailer: ?Algorithm = null,
    ctype: ?ChecksumType = null,
    bad_type: bool = false,
    mode_enabled: bool = false,
    multiple: bool = false,

    pub fn capture(self: *RequestChecksums, arena: std.mem.Allocator, h: Header) error{OutOfMemory}!void {
        if (Algorithm.fromHeaderName(h.name)) |alg| {
            if (self.value_alg != null and self.value_alg.? != alg) self.multiple = true;
            self.value_alg = alg;
            self.value = try arena.dupe(u8, std.mem.trim(u8, h.value, " "));
            return;
        }
        if (std.ascii.eqlIgnoreCase(h.name, "x-amz-sdk-checksum-algorithm") or std.ascii.eqlIgnoreCase(h.name, "x-amz-checksum-algorithm")) {
            self.algorithm = Algorithm.parse(std.mem.trim(u8, h.value, " "));
            self.bad_algorithm = self.algorithm == null;
        } else if (std.ascii.eqlIgnoreCase(h.name, "x-amz-trailer")) {
            self.trailer = Algorithm.fromHeaderName(std.mem.trim(u8, h.value, " "));
        } else if (std.ascii.eqlIgnoreCase(h.name, "x-amz-checksum-type")) {
            self.ctype = ChecksumType.parse(std.mem.trim(u8, h.value, " "));
            self.bad_type = self.ctype == null;
        } else if (std.ascii.eqlIgnoreCase(h.name, "x-amz-checksum-mode")) {
            self.mode_enabled = std.ascii.eqlIgnoreCase(std.mem.trim(u8, h.value, " "), "ENABLED");
        }
    }

    /// The algorithm the body is checked with, if any.
    pub fn bodyAlgorithm(self: RequestChecksums) ?Algorithm {
        return self.value_alg orelse self.trailer orelse self.algorithm;
    }
};

/// Validates checksum headers; false after answering with an error.
pub fn checkHeaders(c: *Ctx) handler.ConnError!bool {
    const r = c.ext.checksum;
    if (r.bad_algorithm or r.bad_type or r.multiple) {
        try handler.fail(c, .InvalidRequest);
        return false;
    }
    if (r.value_alg) |alg| {
        var raw: [ca.max_digest_len]u8 = undefined;
        _ = ca.decodeBase64(alg, r.value, &raw) catch {
            try handler.fail(c, .InvalidRequest);
            return false;
        };
        if (r.algorithm) |a| if (a != alg) {
            try handler.fail(c, .InvalidRequest);
            return false;
        };
    }
    return true;
}

/// Hashes a body as it streams and checks it against the header or trailer at the end.
pub const Verifier = struct {
    in: *std.Io.Reader,
    alg: Algorithm,
    hasher: ca.Hasher,
    expected: []const u8,
    body: ?*const sigv4.BodyReader,
    failure: ?Code = null,
    size: u64 = 0,
    done: bool = false,
    digest_buf: [ca.max_digest_len]u8 = undefined,
    digest_len: u8 = 0,
    text_buf: [ca.max_text_len]u8 = undefined,
    text_len: u8 = 0,
    /// Stored-header value whose tail receives the checksum text at the end of the body.
    slot: []u8 = &.{},
    reader: std.Io.Reader,

    /// Null when the request asks for no checksum.
    pub fn init(r: RequestChecksums, in: *std.Io.Reader, body: ?*const sigv4.BodyReader, buffer: []u8) ?Verifier {
        const alg = r.bodyAlgorithm() orelse return null;
        return .{
            .in = in,
            .alg = alg,
            .hasher = .init(alg),
            .expected = if (r.value_alg != null) r.value else "",
            .body = body,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub fn digest(self: *const Verifier) []const u8 {
        return self.digest_buf[0..self.digest_len];
    }

    /// Base64 of the body's checksum; valid once the body was read to the end.
    pub fn text(self: *const Verifier) []const u8 {
        return self.text_buf[0..self.text_len];
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Verifier = @alignCast(@fieldParentPtr("reader", r));
        if (self.done) return if (self.failure != null) error.ReadFailed else error.EndOfStream;
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (dest.len == 0) return 0;
        const n = self.in.readSliceShort(dest) catch |e| return e;
        self.hasher.update(dest[0..n]);
        self.size += n;
        w.advance(n);
        if (n < dest.len) {
            try self.finish();
            if (n == 0) return error.EndOfStream;
        }
        return n;
    }

    fn finish(self: *Verifier) std.Io.Reader.StreamError!void {
        self.done = true;
        const d = self.hasher.final(&self.digest_buf);
        self.digest_len = @intCast(d.len);
        const t = ca.encodeBase64(d, &self.text_buf) catch unreachable; // digest fits
        self.text_len = @intCast(t.len);
        if (self.slot.len >= t.len) @memcpy(self.slot[self.slot.len - t.len ..], t);
        var want = self.expected;
        if (want.len == 0) if (self.body) |b| if (b.trailer()) |tr| {
            if (Algorithm.fromHeaderName(tr.name) == self.alg) want = tr.value;
        };
        if (want.len > 0 and !std.mem.eql(u8, want, t)) {
            self.failure = .BadDigest;
            return error.ReadFailed;
        }
    }
};

/// `ALG:TYPE:value` for the stored header.
pub fn encodeStored(arena: std.mem.Allocator, alg: Algorithm, ctype: ChecksumType, value: []const u8) error{OutOfMemory}![]const u8 {
    return std.fmt.allocPrint(arena, "{s}:{s}:{s}", .{ alg.wireName(), ctype.wireName(), value });
}

pub const Stored = struct { alg: Algorithm, ctype: ChecksumType, value: []const u8 };

pub fn stored(info: object.ObjectInfo) ?Stored {
    for (info.internal) |h| if (std.mem.eql(u8, h.name, stored_header)) return parseStored(h.value);
    return null;
}

pub fn parseStored(v: []const u8) ?Stored {
    var it = std.mem.splitScalar(u8, v, ':');
    const alg = Algorithm.parse(it.next() orelse return null) orelse return null;
    const ctype = ChecksumType.parse(it.next() orelse return null) orelse return null;
    return .{ .alg = alg, .ctype = ctype, .value = it.rest() };
}

pub fn partValues(info: object.ObjectInfo) ?[]const u8 {
    for (info.internal) |h| if (std.mem.eql(u8, h.name, parts_header)) return h.value;
    return null;
}

/// The `n`th (1-based) stored part checksum.
pub fn partValue(info: object.ObjectInfo, n: usize) ?[]const u8 {
    const all = partValues(info) orelse return null;
    var it = std.mem.splitScalar(u8, all, ',');
    var i: usize = 1;
    while (it.next()) |v| : (i += 1) if (i == n) return v;
    return null;
}

pub fn partsFit(total_len: usize) bool {
    return total_len <= parts_limit;
}

/// Response headers naming the stored checksum (whole-object reads with checksum mode).
pub fn responseHeaders(c: *Ctx, info: object.ObjectInfo, part: ?u16, out: *std.ArrayList(Header)) error{OutOfMemory}!void {
    const s = stored(info) orelse return;
    if (part) |n| {
        if (s.ctype != .composite) return;
        const v = partValue(info, n) orelse return;
        try out.append(c.arena, .{ .name = s.alg.headerName(), .value = v });
        try out.append(c.arena, .{ .name = "x-amz-checksum-type", .value = ChecksumType.composite.wireName() });
        return;
    }
    try out.append(c.arena, .{ .name = s.alg.headerName(), .value = s.value });
    try out.append(c.arena, .{ .name = "x-amz-checksum-type", .value = s.ctype.wireName() });
}

test "stored checksum encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const v = try encodeStored(arena.allocator(), .sha256, .composite, "abc=-3");
    const s = parseStored(v).?;
    try std.testing.expectEqual(Algorithm.sha256, s.alg);
    try std.testing.expectEqual(ChecksumType.composite, s.ctype);
    try std.testing.expectEqualStrings("abc=-3", s.value);
    try std.testing.expect(parseStored("nope") == null);
}

test "verifier checks header and trailer values" {
    var src: std.Io.Reader = .fixed("hello");
    var buf: [64]u8 = undefined;
    var v = Verifier.init(.{ .value_alg = .crc32, .value = "NhCmhg==" }, &src, null, &buf).?;
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try v.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualStrings("hello", out.written());
    try std.testing.expectEqualStrings("NhCmhg==", v.text());

    var src2: std.Io.Reader = .fixed("hellx");
    var v2 = Verifier.init(.{ .value_alg = .crc32, .value = "NhCmhg==" }, &src2, null, &buf).?;
    var out2: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out2.deinit();
    try std.testing.expectError(error.ReadFailed, v2.reader.streamRemaining(&out2.writer));
    try std.testing.expectEqual(Code.BadDigest, v2.failure.?);
    try std.testing.expect(Verifier.init(.{}, &src, null, &buf) == null);
}
