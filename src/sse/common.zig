//! Shared helpers for the SSE and Select routes: custom-code errors, bounded
//! body reads, and std.Io.Reader adapters over stored objects.
const std = @import("std");
const object = @import("../object/root.zig");
const s3 = @import("../s3/root.zig");
const kstream = @import("../kms/stream.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Header = std.http.Header;

/// S3 error response with a code outside the core `Code` enum.
pub fn failCustom(c: *Ctx, status: std.http.Status, code: []const u8, message: []const u8) ConnError!void {
    var a: Writer.Allocating = .init(c.arena);
    const w = &a.writer;
    const resource = std.mem.sliceTo(c.target, '?');
    writeError(w, code, message, resource, &c.request_id) catch return error.OutOfMemory;
    const hdrs = [_]Header{
        .{ .name = "content-type", .value = "application/xml" },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    };
    const keep = c.req.server.reader.state == .ready or c.req.server.reader.state == .received_head;
    try c.req.respond(a.written(), .{ .status = status, .extra_headers = &hdrs, .keep_alive = keep });
}

fn writeError(w: *Writer, code: []const u8, message: []const u8, resource: []const u8, rid: []const u8) Writer.Error!void {
    try w.writeAll(s3.xml.declaration ++ "<Error>");
    try s3.xml.elem(w, "Code", code);
    try s3.xml.elem(w, "Message", message);
    try s3.xml.elem(w, "Resource", resource);
    try s3.xml.elem(w, "RequestId", rid);
    try w.writeAll("</Error>");
}

/// Maps ObjectService failures onto S3 errors; connection errors propagate.
pub fn failObject(c: *Ctx, e: s3.handler.DispatchError) ConnError!void {
    return switch (e) {
        error.OutOfMemory, error.WriteFailed, error.ReadFailed, error.HttpExpectationFailed, error.StreamAborted => |ce| ce,
        else => |oe| s3.handler.fail(c, s3.errors.fromObject(oe)),
    };
}

/// First request header named `name` (case-insensitive), copied into the arena.
/// Only valid before the body is read.
pub fn header(c: *Ctx, name: []const u8) error{OutOfMemory}!?[]const u8 {
    var it = c.req.iterateHeaders();
    while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return try c.arena.dupe(u8, h.value);
    return null;
}

pub fn hasParam(c: *Ctx, name: []const u8) error{OutOfMemory}!bool {
    return (try s3.handler.param(c, name)) != null;
}

pub const BodyError = error{ TooLarge, Rejected } || ConnError;

/// Reads a whole (SigV4-checked) request body up to `max` bytes. On
/// `Rejected` or `TooLarge` the caller still owns the error response.
pub fn readBody(c: *Ctx, max: usize, rejected: *?s3.errors.Code) BodyError![]u8 {
    var body_buf: [s3.handler.io_buf_len]u8 = undefined;
    var check_buf: [s3.handler.io_buf_len]u8 = undefined;
    var br: s3.sigv4.BodyReader = .init(c.auth, try c.req.readerExpectContinue(&body_buf), &check_buf);
    return br.body().allocRemaining(c.arena, .limited(max)) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.TooLarge,
        error.ReadFailed => {
            rejected.* = br.failure;
            return if (br.failure != null) error.Rejected else error.ReadFailed;
        },
    };
}

/// Reader over a byte range of a stored object, fetched in buffer-sized reads.
pub const ObjectReader = struct {
    svc: *object.ObjectService,
    info: object.ObjectInfo,
    pos: u64,
    end: u64,
    err: ?object.Error = null,
    interface: Reader,

    /// `self` must not move after init.
    pub fn init(self: *ObjectReader, svc: *object.ObjectService, info: object.ObjectInfo, offset: u64, len: u64, buffer: []u8) void {
        self.* = .{ .svc = svc, .info = info, .pos = offset, .end = offset + len, .interface = .{
            .vtable = &.{ .stream = stream, .discard = discard },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        } };
    }

    fn discard(r: *Reader, limit: std.Io.Limit) Reader.Error!usize {
        const self: *ObjectReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.err != null) return error.ReadFailed;
        if (self.pos >= self.end) return error.EndOfStream;
        const n: usize = @intCast(@min(self.end - self.pos, @intFromEnum(limit)));
        self.pos += n;
        return n;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const self: *ObjectReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.err != null) return error.ReadFailed;
        if (self.pos >= self.end) return error.EndOfStream;
        if (r.seek > 0) {
            const live = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = live;
        }
        const n: usize = @intCast(@min(r.buffer.len - r.end, self.end - self.pos));
        if (n == 0) return 0;
        var fw: Writer = .fixed(r.buffer[r.end..][0..n]);
        self.svc.read(self.info, .{ .offset = self.pos, .length = n }, &fw) catch |e| {
            self.err = e;
            return error.ReadFailed;
        };
        if (fw.end != n) {
            self.err = error.Corrupt;
            return error.ReadFailed;
        }
        r.end += n;
        self.pos += n;
        return 0;
    }
};

/// Pulls plaintext from `src` and yields the DARE ciphertext stream.
pub const EncryptReader = struct {
    src: *Reader,
    enc: kstream.Encryptor,
    sink: Writer,
    done: bool = false,
    err: ?kstream.EncryptError = null,
    interface: Reader,

    pub const min_buffer = 4 * kstream.package_size;

    /// `self` must not move after init; `buffer.len >= min_buffer`.
    pub fn init(self: *EncryptReader, src: *Reader, key: *const [32]u8, aad: []const u8, buffer: []u8) void {
        std.debug.assert(buffer.len >= min_buffer);
        self.src = src;
        self.done = false;
        self.err = null;
        self.sink = .fixed(buffer[0..0]);
        self.interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 };
        self.enc.init(&self.sink, key, aad);
    }

    pub fn deinit(self: *EncryptReader) void {
        self.enc.deinit();
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        _ = w;
        _ = limit;
        const self: *EncryptReader = @alignCast(@fieldParentPtr("interface", r));
        if (self.err != null) return error.ReadFailed;
        if (self.done) return error.EndOfStream;
        if (r.seek > 0) {
            const live = r.end - r.seek;
            std.mem.copyForwards(u8, r.buffer[0..live], r.buffer[r.seek..r.end]);
            r.seek = 0;
            r.end = live;
        }
        // One call emits at most the stream header and two packages (full + final).
        if (r.buffer.len - r.end < 2 * (kstream.package_size + kstream.package_overhead) + kstream.stream_header_len) return 0;
        self.sink = .fixed(r.buffer[r.end..]);
        const ew = self.enc.writer();
        _ = self.src.stream(ew, .limited(kstream.package_size)) catch |e| switch (e) {
            error.EndOfStream => {
                self.enc.finish() catch |fe| {
                    self.err = fe;
                    return error.ReadFailed;
                };
                self.done = true;
            },
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => {
                self.err = self.enc.err orelse error.WriteFailed;
                return error.ReadFailed;
            },
        };
        r.end += self.sink.end;
        return 0;
    }
};

/// Plaintext length of a DARE stream of `n` ciphertext bytes.
pub fn plainSize(n: u64) error{Malformed}!u64 {
    const unit = kstream.package_size + kstream.package_overhead;
    if (n < kstream.stream_header_len + kstream.package_overhead) return error.Malformed;
    const body = n - kstream.stream_header_len;
    const full = body / unit;
    const rem = body % unit;
    if (rem == 0) return full * kstream.package_size;
    if (rem < kstream.package_overhead) return error.Malformed;
    return full * kstream.package_size + rem - kstream.package_overhead;
}

test "plainSize inverts encryptedSize" {
    for ([_]u64{ 0, 1, 100, 65535, 65536, 65537, 3 * 65536, 3 * 65536 + 7 }) |n|
        try std.testing.expectEqual(n, try plainSize(kstream.encryptedSize(n)));
    try std.testing.expectError(error.Malformed, plainSize(10));
}

test "encrypt reader round trips through decryptor" {
    const gpa = std.testing.allocator;
    const plain = try gpa.alloc(u8, 3 * kstream.package_size + 123);
    defer gpa.free(plain);
    for (plain, 0..) |*b, i| b.* = @truncate(i * 7);
    var src: Reader = .fixed(plain);
    const buf = try gpa.alloc(u8, EncryptReader.min_buffer);
    defer gpa.free(buf);
    const er = try gpa.create(EncryptReader);
    defer gpa.destroy(er);
    const key = [_]u8{3} ** 32;
    er.init(&src, &key, "b/k", buf);
    defer er.deinit();
    const ct = try er.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(ct);
    try std.testing.expectEqual(kstream.encryptedSize(plain.len), ct.len);
    const back = try kstream.decryptAlloc(gpa, &key, "b/k", ct);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
