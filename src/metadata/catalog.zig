//! Bucket catalog: the set of buckets, persisted as one record under the data root.
const std = @import("std");
const core = @import("../core/root.zig");
const codec = @import("codec.zig");

pub const magic = "ZKBC";
pub const format_version: u16 = 1;

pub const Bucket = struct {
    name: []const u8,
    id: core.BucketId,
    created_ns: i128,
};

pub const Error = error{ OutOfMemory, Corrupt };

/// In-memory catalog; owns bucket name strings.
pub const Catalog = struct {
    gpa: std.mem.Allocator,
    buckets: std.ArrayList(Bucket) = .empty,

    pub fn init(gpa: std.mem.Allocator) Catalog {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Catalog) void {
        for (self.buckets.items) |b| self.gpa.free(b.name);
        self.buckets.deinit(self.gpa);
    }

    pub fn find(self: *const Catalog, name: []const u8) ?Bucket {
        for (self.buckets.items) |b| if (std.mem.eql(u8, b.name, name)) return b;
        return null;
    }

    /// Inserts keeping name order.
    pub fn add(self: *Catalog, b: Bucket) error{OutOfMemory}!void {
        const name = try self.gpa.dupe(u8, b.name);
        errdefer self.gpa.free(name);
        var i: usize = 0;
        while (i < self.buckets.items.len and std.mem.lessThan(u8, self.buckets.items[i].name, name)) i += 1;
        try self.buckets.insert(self.gpa, i, .{ .name = name, .id = b.id, .created_ns = b.created_ns });
    }

    pub fn remove(self: *Catalog, name: []const u8) bool {
        for (self.buckets.items, 0..) |b, i| if (std.mem.eql(u8, b.name, name)) {
            self.gpa.free(b.name);
            _ = self.buckets.orderedRemove(i);
            return true;
        };
        return false;
    }

    pub fn encode(self: *const Catalog, gpa: std.mem.Allocator) error{OutOfMemory}![]u8 {
        var a: std.Io.Writer.Allocating = .init(gpa);
        defer a.deinit();
        self.encodeTo(&a.writer) catch return error.OutOfMemory;
        return a.toOwnedSlice() catch error.OutOfMemory;
    }

    fn encodeTo(self: *const Catalog, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(magic);
        try codec.putInt(w, u16, format_version);
        try codec.putInt(w, u32, @intCast(self.buckets.items.len));
        for (self.buckets.items) |b| {
            try w.writeByte(@intCast(b.name.len));
            try w.writeAll(b.name);
            try w.writeAll(&b.id.bytes);
            try codec.putInt(w, i128, b.created_ns);
        }
    }

    pub fn decode(gpa: std.mem.Allocator, bytes: []const u8) Error!Catalog {
        var cat = Catalog.init(gpa);
        errdefer cat.deinit();
        var c: codec.Cursor = .{ .bytes = bytes };
        if (!std.mem.eql(u8, try c.take(4), magic)) return error.Corrupt;
        if (try c.int(u16) != format_version) return error.Corrupt;
        const n = try c.int(u32);
        for (0..n) |_| {
            const name = try c.take((try c.take(1))[0]);
            const id: core.BucketId = .{ .bytes = try c.fixed(16) };
            const created = try c.int(i128);
            try cat.add(.{ .name = name, .id = id, .created_ns = created });
        }
        return cat;
    }
};

test "catalog roundtrip and ordering" {
    const gpa = std.testing.allocator;
    var cat = Catalog.init(gpa);
    defer cat.deinit();
    try cat.add(.{ .name = "zeta", .id = core.BucketId.random(), .created_ns = 1 });
    try cat.add(.{ .name = "alpha", .id = core.BucketId.random(), .created_ns = 2 });
    const bytes = try cat.encode(gpa);
    defer gpa.free(bytes);
    var back = try Catalog.decode(gpa, bytes);
    defer back.deinit();
    try std.testing.expectEqualStrings("alpha", back.buckets.items[0].name);
    try std.testing.expectEqualStrings("zeta", back.buckets.items[1].name);
    try std.testing.expect(back.remove("alpha"));
    try std.testing.expect(back.find("alpha") == null);
    try std.testing.expectError(error.Corrupt, Catalog.decode(gpa, bytes[0 .. bytes.len - 1]));
}
