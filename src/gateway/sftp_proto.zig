//! SFTP version 3 wire format (draft-ietf-secsh-filexfer-02): packet types,
//! status codes, attributes, and `ls -l` style long names.
const std = @import("std");
const wire = @import("ssh_wire.zig");
const fs = @import("fs.zig");

pub const version: u32 = 3;
/// Largest SFTP packet accepted (length field excluded).
pub const max_packet = 256 * 1024;
/// Largest READ reply payload and WRITE we advertise.
pub const max_io = 128 * 1024;
/// Largest handle string we hand out or accept.
pub const max_handle = 16;

pub const Type = struct {
    pub const init: u8 = 1;
    pub const version: u8 = 2;
    pub const open: u8 = 3;
    pub const close: u8 = 4;
    pub const read: u8 = 5;
    pub const write: u8 = 6;
    pub const lstat: u8 = 7;
    pub const fstat: u8 = 8;
    pub const setstat: u8 = 9;
    pub const fsetstat: u8 = 10;
    pub const opendir: u8 = 11;
    pub const readdir: u8 = 12;
    pub const remove: u8 = 13;
    pub const mkdir: u8 = 14;
    pub const rmdir: u8 = 15;
    pub const realpath: u8 = 16;
    pub const stat: u8 = 17;
    pub const rename: u8 = 18;
    pub const readlink: u8 = 19;
    pub const symlink: u8 = 20;
    pub const status: u8 = 101;
    pub const handle: u8 = 102;
    pub const data: u8 = 103;
    pub const name: u8 = 104;
    pub const attrs: u8 = 105;
    pub const extended: u8 = 200;
    pub const extended_reply: u8 = 201;
};

pub const Status = enum(u32) {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,

    pub fn text(s: Status) []const u8 {
        return switch (s) {
            .ok => "Success",
            .eof => "End of file",
            .no_such_file => "No such file",
            .permission_denied => "Permission denied",
            .failure => "Failure",
            .bad_message => "Bad message",
            .no_connection => "No connection",
            .connection_lost => "Connection lost",
            .op_unsupported => "Operation unsupported",
        };
    }
};

pub const Open = struct {
    pub const read: u32 = 0x01;
    pub const write: u32 = 0x02;
    pub const append: u32 = 0x04;
    pub const creat: u32 = 0x08;
    pub const trunc: u32 = 0x10;
    pub const excl: u32 = 0x20;
};

pub const Flag = struct {
    pub const size: u32 = 0x01;
    pub const uidgid: u32 = 0x02;
    pub const permissions: u32 = 0x04;
    pub const acmodtime: u32 = 0x08;
    pub const extended: u32 = 0x80000000;
};

/// File status codes for gateway file system errors.
pub fn statusOf(e: fs.Error) struct { Status, []const u8 } {
    return switch (e) {
        error.NotFound => .{ .no_such_file, "No such file or directory" },
        error.Denied => .{ .permission_denied, "Permission denied" },
        error.Exists => .{ .failure, "File exists" },
        error.NotEmpty => .{ .failure, "Directory not empty" },
        error.IsDir => .{ .failure, "Is a directory" },
        error.NotDir => .{ .failure, "Not a directory" },
        error.InvalidPath => .{ .failure, "Invalid path" },
        error.TooLarge => .{ .failure, "Too large" },
        error.OutOfMemory => .{ .failure, "Out of memory" },
        error.Storage, error.ReadFailed, error.WriteFailed => .{ .failure, "Storage error" },
    };
}

pub const Attrs = struct {
    size: ?u64 = null,
    uid: u32 = 0,
    gid: u32 = 0,
    has_ids: bool = false,
    perms: ?u32 = null,
    atime: u32 = 0,
    mtime: u32 = 0,
    has_times: bool = false,

    pub const max_extended = 64;

    pub fn decode(r: *wire.Reader) wire.DecodeError!Attrs {
        var a: Attrs = .{};
        const flags = try r.u32be();
        if (flags & Flag.size != 0) a.size = try r.u64be();
        if (flags & Flag.uidgid != 0) {
            a.uid = try r.u32be();
            a.gid = try r.u32be();
            a.has_ids = true;
        }
        if (flags & Flag.permissions != 0) a.perms = try r.u32be();
        if (flags & Flag.acmodtime != 0) {
            a.atime = try r.u32be();
            a.mtime = try r.u32be();
            a.has_times = true;
        }
        if (flags & Flag.extended != 0) {
            const n = try r.u32be();
            if (n > max_extended) return error.BadMessage;
            for (0..n) |_| {
                _ = try r.string();
                _ = try r.string();
            }
        }
        return a;
    }

    pub fn encode(a: Attrs, w: *wire.Writer) wire.EncodeError!void {
        var flags: u32 = 0;
        if (a.size != null) flags |= Flag.size;
        if (a.has_ids) flags |= Flag.uidgid;
        if (a.perms != null) flags |= Flag.permissions;
        if (a.has_times) flags |= Flag.acmodtime;
        try w.u32be(flags);
        if (a.size) |s| try w.u64be(s);
        if (a.has_ids) {
            try w.u32be(a.uid);
            try w.u32be(a.gid);
        }
        if (a.perms) |p| try w.u32be(p);
        if (a.has_times) {
            try w.u32be(a.atime);
            try w.u32be(a.mtime);
        }
    }

    pub fn of(kind: fs.Kind, size: u64, mtime_ns: i128) Attrs {
        const secs = @divFloor(mtime_ns, std.time.ns_per_s);
        const t: u32 = @intCast(std.math.clamp(secs, 0, std.math.maxInt(u32)));
        const dir = kind != .file;
        return .{
            .size = if (dir) 0 else size,
            .has_ids = true,
            .perms = if (dir) 0o040755 else 0o100644,
            .atime = t,
            .mtime = t,
            .has_times = true,
        };
    }
};

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// `ls -l` line: recent files show the time, older ones the year.
pub fn longName(buf: []u8, name: []const u8, a: Attrs, now_s: i64) wire.EncodeError![]const u8 {
    const dir = (a.perms orelse 0) & 0o170000 == 0o040000;
    const mode = if (dir) "drwxr-xr-x" else "-rw-r--r--";
    const es: std.time.epoch.EpochSeconds = .{ .secs = a.mtime };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    var when_buf: [16]u8 = undefined;
    const recent = @abs(now_s - @as(i64, a.mtime)) < 180 * 24 * 3600;
    const when = (if (recent)
        std.fmt.bufPrint(&when_buf, "{s} {d:>2} {d:0>2}:{d:0>2}", .{ months[md.month.numeric() - 1], md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour() })
    else
        std.fmt.bufPrint(&when_buf, "{s} {d:>2}  {d}", .{ months[md.month.numeric() - 1], md.day_index + 1, day.year })) catch return error.NoSpace;
    return std.fmt.bufPrint(buf, "{s}    1 zkfsm    zkfsm    {d:>12} {s} {s}", .{ mode, a.size orelse 0, when, name }) catch error.NoSpace;
}

test "attrs round trip and bounds" {
    var buf: [64]u8 = undefined;
    var w = wire.Writer.init(&buf);
    const a = Attrs.of(.file, 1234, 1_700_000_000 * std.time.ns_per_s);
    try a.encode(&w);
    var r = wire.Reader.init(w.written());
    const b = try Attrs.decode(&r);
    try std.testing.expectEqual(@as(?u64, 1234), b.size);
    try std.testing.expectEqual(@as(?u32, 0o100644), b.perms);
    try std.testing.expectEqual(@as(u32, 1_700_000_000), b.mtime);
    try std.testing.expect(r.done());
    r = wire.Reader.init(&.{ 0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff });
    try std.testing.expectError(error.BadMessage, Attrs.decode(&r));
    r = wire.Reader.init(&.{ 0, 0, 0, 1, 0, 0 });
    try std.testing.expectError(error.BadMessage, Attrs.decode(&r));
}

test "long names" {
    var buf: [256]u8 = undefined;
    const t: i64 = 1_700_000_000;
    const f = try longName(&buf, "a.txt", Attrs.of(.file, 42, @as(i128, t) * std.time.ns_per_s), t);
    try std.testing.expectEqualStrings("-rw-r--r--    1 zkfsm    zkfsm              42 Nov 14 22:13 a.txt", f);
    const d = try longName(&buf, "dir", Attrs.of(.dir, 0, 0), t);
    try std.testing.expectEqualStrings("drwxr-xr-x    1 zkfsm    zkfsm               0 Jan  1  1970 dir", d);
}

test "status mapping" {
    try std.testing.expectEqual(Status.no_such_file, statusOf(error.NotFound)[0]);
    try std.testing.expectEqual(Status.permission_denied, statusOf(error.Denied)[0]);
    try std.testing.expectEqual(Status.failure, statusOf(error.NotEmpty)[0]);
}
