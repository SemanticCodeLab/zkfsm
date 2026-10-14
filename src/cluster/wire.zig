//! Wire encodings shared by the RPC client and server: key addresses, write frames,
//! and change notifications. Every decoder bounds lengths and rejects malformed input.
const std = @import("std");
const backend = @import("../backend/root.zig");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");

const PhysicalKey = backend.PhysicalKey;

pub fn spaceChar(s: backend.KeySpace) u8 {
    return switch (s) {
        .data => 'd',
        .record => 'r',
        .system => 's',
    };
}

pub fn parseSpace(c: u8) ?backend.KeySpace {
    return switch (c) {
        'd' => .data,
        'r' => .record,
        's' => .system,
        else => null,
    };
}

pub fn isHex(s: []const u8) bool {
    for (s) |c| if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    return true;
}

/// `<space char><32 hex>`
pub fn parseKey(s: []const u8) ?PhysicalKey {
    if (s.len != 33 or !isHex(s[1..])) return null;
    return .{ .space = parseSpace(s[0]) orelse return null, .hex = s[1..33].* };
}

/// Drives addressed by one batched record call.
pub const max_batch = 16;

// ---- write frames: D len data | P off len data | C key | A ----

pub const data_header_len = 5;
pub const patch_header_len = 13;
pub const max_patch = 4096;
pub const max_data = 1024 * 1024;
pub const commit_frame_len = 34;

pub fn dataHeader(out: []u8, len: u32) void {
    out[0] = 'D';
    std.mem.writeInt(u32, out[1..5], len, .little);
}

pub fn patchFrame(buf: []u8, bytes: []const u8, off: u64) []u8 {
    buf[0] = 'P';
    std.mem.writeInt(u64, buf[1..9], off, .little);
    std.mem.writeInt(u32, buf[9..13], @intCast(bytes.len), .little);
    @memcpy(buf[13..][0..bytes.len], bytes);
    return buf[0 .. 13 + bytes.len];
}

pub fn commitFrame(buf: *[commit_frame_len]u8, key: PhysicalKey) []u8 {
    buf[0] = 'C';
    buf[1] = spaceChar(key.space);
    buf[2..34].* = key.hex;
    return buf;
}

pub const Frame = union(enum) {
    data: u32,
    patch: struct { off: u64, len: u32 },
    commit: PhysicalKey,
    abort,
};

pub const FrameError = error{ BadFrame, EndOfStream, ReadFailed };

/// Reads one frame header; for data and patch frames the payload follows in `r`.
pub fn readFrame(r: *std.Io.Reader) FrameError!Frame {
    const t = r.takeByte() catch |e| return if (e == error.EndOfStream) error.EndOfStream else error.ReadFailed;
    switch (t) {
        'D' => {
            const n = r.takeInt(u32, .little) catch return error.BadFrame;
            if (n > max_data) return error.BadFrame;
            return .{ .data = n };
        },
        'P' => {
            const off = r.takeInt(u64, .little) catch return error.BadFrame;
            const n = r.takeInt(u32, .little) catch return error.BadFrame;
            if (n > max_patch) return error.BadFrame;
            return .{ .patch = .{ .off = off, .len = n } };
        },
        'C' => {
            const b = r.takeArray(33) catch return error.BadFrame;
            return .{ .commit = parseKey(b) orelse return error.BadFrame };
        },
        'A' => return .abort,
        else => return error.BadFrame,
    }
}

// ---- change notifications: repeated (u32 len, entry) ----

pub const max_notify = 4 * 1024 * 1024;

pub const Note = union(enum) {
    change: object.service.Change,
    iam,
    /// Pool decommission/rebalance state changed: reload it.
    pools,
    /// The next change is entry `seq` of the sender's journal epoch `epoch`.
    mark: Mark,
    /// A blob the sender will delete after its grace; delete it later if it cannot.
    garbage: [16]u8,
    /// The sender releases its namespace lock (after the notes before it apply).
    unlock: object.service.LockRef,
};

/// Longest lock resource name (see cluster/locks.zig).
pub const max_resource = 1400;

pub const Mark = struct { epoch: u64, seq: u64 };

const Version = object.index.Version;
/// id, size, md5, parts, mtime, flags.
const stored_len = 16 + 8 + 16 + 4 + 16 + 1;

pub fn encodeNotes(gpa: std.mem.Allocator, notes: []const Note) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    for (notes) |n| {
        var eb: std.Io.Writer.Allocating = .init(gpa);
        defer eb.deinit();
        encodeNote(&eb.writer, n) catch return error.OutOfMemory;
        w.writeInt(u32, @intCast(eb.written().len), .little) catch return error.OutOfMemory;
        w.writeAll(eb.written()) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice();
}

pub fn encodeNote(w: *std.Io.Writer, n: Note) std.Io.Writer.Error!void {
    switch (n) {
        .iam => try w.writeByte('i'),
        .pools => try w.writeByte('p'),
        .garbage => |id| {
            try w.writeByte('g');
            try w.writeAll(&id);
        },
        .unlock => |u| {
            try w.writeByte('k');
            try w.writeInt(u64, u.uid, .little);
            try w.writeAll(u.resource);
        },
        .mark => |m| {
            try w.writeByte('j');
            try w.writeInt(u64, m.epoch, .little);
            try w.writeInt(u64, m.seq, .little);
        },
        .change => |c| switch (c) {
            .catalog => try w.writeByte('c'),
            .resync => try w.writeByte('x'),
            .upload => |id| {
                try w.writeByte('u');
                try w.writeAll(&id.bytes);
            },
            .record => |r| {
                try w.writeByte(if (r.stored != null) 'R' else 'r');
                try w.writeByte(spaceChar(r.pk.space));
                try w.writeAll(&r.pk.hex);
                try w.writeAll(&r.bid.bytes);
                if (r.version) |v| {
                    try w.writeByte(1);
                    try w.writeAll(&v.bytes);
                } else try w.writeByte(0);
                if (r.stored) |v| {
                    try w.writeAll(&v.id.bytes);
                    try w.writeInt(u64, v.size, .little);
                    try w.writeAll(&v.etag.md5);
                    try w.writeInt(u32, v.etag.parts, .little);
                    try w.writeInt(i128, v.mtime_ns, .little);
                    try w.writeByte(@as(u8, @intFromBool(v.delete_marker)) | @as(u8, @intFromBool(v.tiered)) << 1);
                    const l = r.lock orelse object.service.LockRef{ .uid = 0, .resource = "" };
                    try w.writeInt(u64, l.uid, .little);
                    try w.writeInt(u16, @intCast(l.resource.len), .little);
                    try w.writeAll(l.resource);
                }
                try w.writeAll(r.key);
            },
        },
    }
}

/// Decodes entries in place; record keys borrow from `bytes`.
pub const NoteIter = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn next(it: *NoteIter) error{BadNote}!?Note {
        if (it.pos == it.bytes.len) return null;
        if (it.bytes.len - it.pos < 4) return error.BadNote;
        const n = std.mem.readInt(u32, it.bytes[it.pos..][0..4], .little);
        it.pos += 4;
        if (n == 0 or n > it.bytes.len - it.pos) return error.BadNote;
        const e = it.bytes[it.pos..][0..n];
        it.pos += n;
        return try decodeNote(e);
    }
};

pub fn decodeNote(e: []const u8) error{BadNote}!Note {
    if (e.len == 0) return error.BadNote;
    switch (e[0]) {
        'i' => return .iam,
        'p' => return .pools,
        'g' => {
            if (e.len != 17) return error.BadNote;
            return .{ .garbage = e[1..17].* };
        },
        'j' => {
            if (e.len != 17) return error.BadNote;
            return .{ .mark = .{ .epoch = std.mem.readInt(u64, e[1..9], .little), .seq = std.mem.readInt(u64, e[9..17], .little) } };
        },
        'k' => {
            if (e.len < 10 or e.len > 9 + max_resource) return error.BadNote;
            return .{ .unlock = .{ .uid = std.mem.readInt(u64, e[1..9], .little), .resource = e[9..] } };
        },
        'c' => return .{ .change = .catalog },
        'x' => return .{ .change = .resync },
        'u' => {
            if (e.len != 17) return error.BadNote;
            return .{ .change = .{ .upload = .{ .bytes = e[1..17].* } } };
        },
        'r', 'R' => {
            if (e.len < 1 + 33 + 16 + 1) return error.BadNote;
            const pk = parseKey(e[1..34]) orelse return error.BadNote;
            const bid: core.BucketId = .{ .bytes = e[34..50].* };
            var pos: usize = 51;
            var version: ?core.VersionId = null;
            switch (e[50]) {
                0 => {},
                1 => {
                    if (e.len < 67) return error.BadNote;
                    version = .{ .bytes = e[51..67].* };
                    pos = 67;
                },
                else => return error.BadNote,
            }
            var stored: ?Version = null;
            var lock: ?object.service.LockRef = null;
            if (e[0] == 'R') {
                if (e.len < pos + stored_len) return error.BadNote;
                const b = e[pos..][0..stored_len];
                if (b[60] > 3) return error.BadNote;
                stored = .{
                    .id = .{ .bytes = b[0..16].* },
                    .size = std.mem.readInt(u64, b[16..24], .little),
                    .etag = .{ .md5 = b[24..40].*, .parts = std.mem.readInt(u32, b[40..44], .little) },
                    .mtime_ns = std.mem.readInt(i128, b[44..60], .little),
                    .delete_marker = b[60] & 1 != 0,
                    .tiered = b[60] & 2 != 0,
                };
                pos += stored_len;
                if (e.len < pos + 10) return error.BadNote;
                const uid = std.mem.readInt(u64, e[pos..][0..8], .little);
                const rl = std.mem.readInt(u16, e[pos + 8 ..][0..2], .little);
                pos += 10;
                if (rl > max_resource or e.len < pos + rl) return error.BadNote;
                if (uid != 0) lock = .{ .uid = uid, .resource = e[pos..][0..rl] };
                pos += rl;
            }
            const key = e[pos..];
            if (key.len == 0 or key.len > 1024) return error.BadNote;
            return .{ .change = .{ .record = .{ .pk = pk, .bid = bid, .key = key, .version = version, .stored = stored, .lock = lock } } };
        },
        else => return error.BadNote,
    }
}

test "frames and notes roundtrip; garbage is rejected" {
    var buf: [64]u8 = undefined;
    const key: PhysicalKey = .{ .space = .record, .hex = "0123456789abcdef0123456789abcdef".* };
    var cf: [commit_frame_len]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    var dh: [data_header_len]u8 = undefined;
    dataHeader(&dh, 3);
    try stream.writeAll(&dh);
    try stream.writeAll("abc");
    try stream.writeAll(commitFrame(&cf, key));
    var r: std.Io.Reader = .fixed(stream.buffered());
    try std.testing.expectEqual(@as(u32, 3), (try readFrame(&r)).data);
    _ = try r.take(3);
    try std.testing.expect(std.mem.eql(u8, &(try readFrame(&r)).commit.hex, &key.hex));
    try std.testing.expectError(error.EndOfStream, readFrame(&r));
    var bad: std.Io.Reader = .fixed("D\xff\xff\xff\xff");
    try std.testing.expectError(error.BadFrame, readFrame(&bad));

    const notes = [_]Note{
        .iam,
        .{ .change = .{ .record = .{ .pk = key, .bid = .{ .bytes = @splat(3) }, .key = "a/b", .version = .{ .bytes = @splat(4) } } } },
        .{ .change = .catalog },
        .{ .change = .{ .record = .{ .pk = key, .bid = .{ .bytes = @splat(5) }, .key = "k", .version = null, .stored = .{ .id = .{ .bytes = @splat(6) }, .size = 77, .etag = .{ .md5 = @splat(8), .parts = 2 }, .mtime_ns = -5, .delete_marker = false, .tiered = true }, .lock = .{ .uid = 9, .resource = "obj/b/k" } } } },
        .{ .unlock = .{ .uid = 9, .resource = "obj/b/k" } },
    };
    const enc = try encodeNotes(std.testing.allocator, &notes);
    defer std.testing.allocator.free(enc);
    var it: NoteIter = .{ .bytes = enc };
    try std.testing.expect((try it.next()).? == .iam);
    const rec = (try it.next()).?.change.record;
    try std.testing.expectEqualStrings("a/b", rec.key);
    try std.testing.expectEqual(@as(u8, 4), rec.version.?.bytes[0]);
    try std.testing.expect((try it.next()).?.change == .catalog);
    const st = (try it.next()).?.change.record;
    try std.testing.expectEqualStrings("k", st.key);
    try std.testing.expectEqual(@as(u64, 77), st.stored.?.size);
    try std.testing.expectEqual(@as(i128, -5), st.stored.?.mtime_ns);
    try std.testing.expect(st.stored.?.tiered and !st.stored.?.delete_marker);
    try std.testing.expectEqualStrings("obj/b/k", st.lock.?.resource);
    try std.testing.expectEqual(@as(u64, 9), (try it.next()).?.unlock.uid);
    try std.testing.expect((try it.next()) == null);
    var junk: NoteIter = .{ .bytes = "\x05\x00\x00\x00r" };
    try std.testing.expectError(error.BadNote, junk.next());
    try std.testing.expect(parseKey("q0123456789abcdef0123456789abcdef") == null);
}
