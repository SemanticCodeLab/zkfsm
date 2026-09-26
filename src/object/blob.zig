//! BlobReader: a std.Io.Reader over byte ranges of stored blobs, read in order.
//! Used to stream existing data into a new blob (copy, multipart complete).
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const placement = @import("../placement/root.zig");

pub const Segment = struct {
    blob: core.ObjectId,
    offset: u64,
    length: u64,
};

pub const BlobReader = struct {
    store: backend.StorageBackend,
    segs: []const Segment,
    i: usize = 0,
    /// Bytes consumed from segs[i].
    pos: u64 = 0,
    /// Set when a backend read failed; the reader then reports ReadFailed.
    err: ?backend.Error = null,
    reader: std.Io.Reader,

    pub fn init(store: backend.StorageBackend, segs: []const Segment, buffer: []u8) BlobReader {
        return .{
            .store = store,
            .segs = segs,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    pub fn totalLen(segs: []const Segment) u64 {
        var n: u64 = 0;
        for (segs) |s| n += s.length;
        return n;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *BlobReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.err != null) return error.ReadFailed;
        while (self.i < self.segs.len and self.pos == self.segs[self.i].length) {
            self.i += 1;
            self.pos = 0;
        }
        if (self.i == self.segs.len) return error.EndOfStream;
        const seg = self.segs[self.i];
        // Bound each read by the writer's free space so the backend never over-writes.
        const room = (try w.writableSliceGreedy(1)).len;
        const n = limit.minInt64(@min(seg.length - self.pos, room));
        if (n == 0) return 0;
        const range: core.Range = .{ .offset = seg.offset + self.pos, .length = n };
        _ = self.store.get(placement.dataKey(seg.blob), range, w) catch |e| switch (e) {
            error.WriteFailed => return error.WriteFailed,
            else => {
                self.err = e;
                return error.ReadFailed;
            },
        };
        self.pos += n;
        return n;
    }
};

test "blob reader concatenates ranges" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    const store = lb.backend();
    const a = core.ObjectId.random();
    const b = core.ObjectId.random();
    var sa: std.Io.Reader = .fixed("0123456789");
    _ = try store.put(placement.dataKey(a), &sa, .{});
    var sb: std.Io.Reader = .fixed("abcdef");
    _ = try store.put(placement.dataKey(b), &sb, .{});

    const segs = [_]Segment{
        .{ .blob = a, .offset = 2, .length = 5 },
        .{ .blob = b, .offset = 0, .length = 0 },
        .{ .blob = b, .offset = 0, .length = 6 },
    };
    var buf: [3]u8 = undefined; // tiny buffer forces many chunked reads
    var br = BlobReader.init(store, &segs, &buf);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try br.reader.streamRemaining(&out.writer);
    try std.testing.expectEqualStrings("23456abcdef", out.written());
    try std.testing.expectEqual(@as(u64, 11), BlobReader.totalLen(&segs));

    const missing = [_]Segment{.{ .blob = core.ObjectId.random(), .offset = 0, .length = 1 }};
    var br2 = BlobReader.init(store, &missing, &buf);
    try std.testing.expectError(error.ReadFailed, br2.reader.streamRemaining(&out.writer));
    try std.testing.expectEqual(backend.Error.NotFound, br2.err.?);
}
