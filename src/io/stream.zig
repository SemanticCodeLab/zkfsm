//! Streaming helpers: a pass-through reader that hashes and counts bytes.
const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

pub fn HashingReader(comptime Hasher: type) type {
    return struct {
        in: *Reader,
        hasher: Hasher,
        count: u64 = 0,
        /// Latched at end of input; some readers (std.http bodies) panic if read past EOF.
        eof: bool = false,
        reader: Reader,

        const Self = @This();

        pub fn init(in: *Reader, hasher: Hasher, buffer: []u8) Self {
            return .{
                .in = in,
                .hasher = hasher,
                .reader = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
            const self: *Self = @alignCast(@fieldParentPtr("reader", r));
            if (self.eof) return error.EndOfStream;
            const dest = limit.slice(try w.writableSliceGreedy(1));
            const n = try self.in.readSliceShort(dest);
            if (n < dest.len) self.eof = true;
            if (n == 0) return error.EndOfStream;
            self.hasher.update(dest[0..n]);
            self.count += n;
            w.advance(n);
            return n;
        }
    };
}

test "hashing reader md5 and count" {
    const Md5 = std.crypto.hash.Md5;
    var src: Reader = .fixed("hello world");
    var buf: [4]u8 = undefined;
    var hr = HashingReader(Md5).init(&src, Md5.init(.{}), &buf);
    var out: Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try hr.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualStrings("hello world", out.written());
    var d: [16]u8 = undefined;
    hr.hasher.final(&d);
    var want: [16]u8 = undefined;
    Md5.hash("hello world", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &d);
    try std.testing.expectEqual(@as(u64, 11), hr.count);
}
