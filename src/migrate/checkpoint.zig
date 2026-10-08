//! Resume state of one migration: an append-only file in the destination's
//! `.zkfsm` directory listing finished objects ("O bucket\tkey") and buckets ("B bucket").
const std = @import("std");

pub const Error = error{ OutOfMemory, CheckpointFailed };

const sync_every = 256;

pub const Checkpoint = struct {
    gpa: std.mem.Allocator,
    file: std.fs.File,
    dir: std.fs.Dir,
    done: std.StringHashMapUnmanaged(void) = .empty,
    pending: usize = 0,

    /// One file per source (named by a hash of its location), so separate migrations
    /// into the same destination do not share progress.
    pub fn open(gpa: std.mem.Allocator, dir: std.fs.Dir, source: []const []const u8, restart: bool) Error!Checkpoint {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (source) |s| {
            h.update(s);
            h.update("\x00");
        }
        var d: [32]u8 = undefined;
        h.final(&d);
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "migrate-{s}.ckpt", .{std.fmt.bytesToHex(d[0..8].*, .lower)}) catch unreachable; // fits
        var c: Checkpoint = .{ .gpa = gpa, .file = undefined, .dir = dir };
        errdefer c.deinitMap();
        var torn = false;
        if (!restart) {
            if (dir.readFileAlloc(gpa, name, 1 << 34)) |bytes| {
                defer gpa.free(bytes);
                torn = bytes.len > 0 and bytes[bytes.len - 1] != '\n';
                var it = std.mem.splitScalar(u8, bytes, '\n');
                while (it.next()) |line| {
                    // A torn final line (crash mid-append) has no newline and is dropped.
                    if (it.index == null) break;
                    if (line.len < 2) continue;
                    try c.add(line);
                }
            } else |e| if (e != error.FileNotFound) return error.CheckpointFailed;
        }
        c.file = dir.createFile(name, .{ .truncate = restart, .read = false }) catch return error.CheckpointFailed;
        c.file.seekFromEnd(0) catch return error.CheckpointFailed;
        if (torn) c.file.writeAll("\n") catch return error.CheckpointFailed;
        return c;
    }

    fn deinitMap(c: *Checkpoint) void {
        var it = c.done.keyIterator();
        while (it.next()) |k| c.gpa.free(k.*);
        c.done.deinit(c.gpa);
    }

    pub fn deinit(c: *Checkpoint) void {
        c.file.sync() catch {};
        c.file.close();
        c.dir.close();
        c.deinitMap();
    }

    fn add(c: *Checkpoint, line: []const u8) error{OutOfMemory}!void {
        const gop = try c.done.getOrPut(c.gpa, line);
        if (!gop.found_existing) gop.key_ptr.* = try c.gpa.dupe(u8, line);
    }

    fn has(c: *Checkpoint, kind: u8, bucket: []const u8, key: ?[]const u8) bool {
        var buf: [2048]u8 = undefined;
        const line = format(&buf, kind, bucket, key) orelse return false;
        return c.done.contains(line);
    }

    fn format(buf: []u8, kind: u8, bucket: []const u8, key: ?[]const u8) ?[]const u8 {
        return if (key) |k|
            std.fmt.bufPrint(buf, "{c} {s}\t{s}", .{ kind, bucket, k }) catch null
        else
            std.fmt.bufPrint(buf, "{c} {s}", .{ kind, bucket }) catch null;
    }

    fn mark(c: *Checkpoint, kind: u8, bucket: []const u8, key: ?[]const u8) Error!void {
        // Keys with newlines cannot be recorded; they are simply redone on resume.
        if (key) |k| if (std.mem.indexOfScalar(u8, k, '\n') != null) return;
        var buf: [2048]u8 = undefined;
        const line = format(&buf, kind, bucket, key) orelse return;
        try c.add(line);
        var w = c.file.writer(&.{});
        w.interface.print("{s}\n", .{line}) catch return error.CheckpointFailed;
        c.pending += 1;
        if (kind == 'B' or c.pending >= sync_every) {
            c.file.sync() catch return error.CheckpointFailed;
            c.pending = 0;
        }
    }

    pub fn objectDone(c: *Checkpoint, bucket: []const u8, key: []const u8) bool {
        return c.has('O', bucket, key);
    }

    pub fn bucketDone(c: *Checkpoint, bucket: []const u8) bool {
        return c.has('B', bucket, null);
    }

    pub fn markObject(c: *Checkpoint, bucket: []const u8, key: []const u8) Error!void {
        return c.mark('O', bucket, key);
    }

    pub fn markBucket(c: *Checkpoint, bucket: []const u8) Error!void {
        return c.mark('B', bucket, null);
    }
};

test "marks survive reopen and torn lines are dropped" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const src = &[_][]const u8{"/src"};
    {
        var c = try Checkpoint.open(std.testing.allocator, try tmp.dir.openDir(".", .{}), src, false);
        defer c.deinit();
        try c.markObject("b", "k1");
        try c.markBucket("b");
        try c.file.writeAll("O b\tpartial");
    }
    var c = try Checkpoint.open(std.testing.allocator, try tmp.dir.openDir(".", .{}), src, false);
    defer c.deinit();
    try std.testing.expect(c.objectDone("b", "k1"));
    try std.testing.expect(c.bucketDone("b"));
    try std.testing.expect(!c.objectDone("b", "partial"));
    try std.testing.expect(!c.objectDone("b", "k2"));
    try c.markObject("b", "k3");
    var again = try Checkpoint.open(std.testing.allocator, try tmp.dir.openDir(".", .{}), src, false);
    defer again.deinit();
    try std.testing.expect(again.objectDone("b", "k3"));
}
