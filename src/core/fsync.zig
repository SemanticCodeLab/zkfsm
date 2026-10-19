//! Directory fsync: makes created, renamed or removed entries durable.
const std = @import("std");

/// Fsyncs `dir` itself; a fresh readable handle, since fsync on O_PATH is EBADF.
pub fn syncDir(dir: std.fs.Dir) !void {
    var d = try dir.openDir(".", .{ .iterate = true });
    defer d.close();
    try std.posix.fsync(d.fd);
}

/// `parent.makeOpenPath(sub)`, then fsyncs `parent` so the new entry survives a power cut.
pub fn makeOpenPathSynced(parent: std.fs.Dir, sub: []const u8) !std.fs.Dir {
    const d = try parent.makeOpenPath(sub, .{});
    errdefer @constCast(&d).close();
    try syncDir(parent);
    return d;
}

test "sync a directory after a rename" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var d = try makeOpenPathSynced(tmp.dir, "a");
    defer d.close();
    try d.writeFile(.{ .sub_path = "x.tmp", .data = "1" });
    try d.rename("x.tmp", "x");
    try syncDir(d);
}
