//! Byte ranges: the parsed request form and the resolved absolute form.
const std = @import("std");

pub const RangeError = error{ InvalidRange, Unsatisfiable };

/// Absolute half-open byte range [offset, offset+length).
pub const Range = struct {
    offset: u64,
    length: u64,

    pub fn last(self: Range) u64 {
        return self.offset + self.length - 1;
    }
};

pub const RangeSpec = union(enum) {
    from_to: struct { first: u64, last: u64 },
    from: u64,
    suffix: u64,

    /// Parses a single `bytes=` range; multi-range is rejected.
    pub fn parse(header: []const u8) RangeError!RangeSpec {
        const p = "bytes=";
        if (!std.mem.startsWith(u8, header, p)) return error.InvalidRange;
        const spec = std.mem.trim(u8, header[p.len..], " ");
        if (std.mem.indexOfScalar(u8, spec, ',') != null) return error.InvalidRange;
        const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return error.InvalidRange;
        const a = spec[0..dash];
        const b = spec[dash + 1 ..];
        if (a.len == 0) {
            const n = std.fmt.parseInt(u64, b, 10) catch return error.InvalidRange;
            return .{ .suffix = n };
        }
        const first = std.fmt.parseInt(u64, a, 10) catch return error.InvalidRange;
        if (b.len == 0) return .{ .from = first };
        const lst = std.fmt.parseInt(u64, b, 10) catch return error.InvalidRange;
        if (lst < first) return error.InvalidRange;
        return .{ .from_to = .{ .first = first, .last = lst } };
    }

    pub fn resolve(self: RangeSpec, size: u64) RangeError!Range {
        switch (self) {
            .from_to => |r| {
                if (r.first >= size) return error.Unsatisfiable;
                const lst = @min(r.last, size - 1);
                return .{ .offset = r.first, .length = lst - r.first + 1 };
            },
            .from => |f| {
                if (f >= size) return error.Unsatisfiable;
                return .{ .offset = f, .length = size - f };
            },
            .suffix => |n| {
                if (n == 0 or size == 0) return error.Unsatisfiable;
                const len = @min(n, size);
                return .{ .offset = size - len, .length = len };
            },
        }
    }
};

test "range parse and resolve" {
    const t = std.testing;
    try t.expectEqual(Range{ .offset = 0, .length = 5 }, try (try RangeSpec.parse("bytes=0-4")).resolve(10));
    try t.expectEqual(Range{ .offset = 7, .length = 3 }, try (try RangeSpec.parse("bytes=7-")).resolve(10));
    try t.expectEqual(Range{ .offset = 6, .length = 4 }, try (try RangeSpec.parse("bytes=-4")).resolve(10));
    try t.expectEqual(Range{ .offset = 8, .length = 2 }, try (try RangeSpec.parse("bytes=8-100")).resolve(10));
    try t.expectError(error.Unsatisfiable, (try RangeSpec.parse("bytes=10-")).resolve(10));
    try t.expectError(error.InvalidRange, RangeSpec.parse("bytes=5-1"));
    try t.expectError(error.InvalidRange, RangeSpec.parse("items=1-2"));
    try t.expectError(error.InvalidRange, RangeSpec.parse("bytes=0-1,3-4"));
}
