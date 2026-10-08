//! Change journal: every index change this node makes gets a sequence number and
//! is appended (before the record is written) to a node-local file. An entry turns
//! stable once its operation published; peers that missed notes pull stable
//! entries past their watermark instead of rebuilding their key index.
//! The epoch changes when the file is lost or a reboot may have cut its tail.
const std = @import("std");
const wire = @import("wire.zig");

pub const Error = error{ OutOfMemory, IoFailed };

const file_magic = "ZKJ1";
const header_len = 4 + 8 + 16 + 1;
const entry_head = 8 + 4;
/// Entries kept in memory and served to peers; older ones need a full rebuild.
pub const max_entries = 100_000;
pub const max_bytes = 32 * 1024 * 1024;
const max_note = 4096;

const Entry = struct { seq: u64, bytes: []u8, done: bool, born_ms: i64 = 0 };
/// An entry whose operation never published (it failed oddly) stops holding back
/// the stable point after this long.
const stuck_ms: i64 = 60_000;

pub const Journal = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    file: ?std.fs.File = null,
    dir: ?std.fs.Dir = null,
    epoch: u64 = 0,
    /// Next sequence number to hand out.
    next: u64 = 1,
    /// All entries up to here finished; peers may read them.
    stable: u64 = 0,
    /// Entries in seq order, the oldest first.
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    bytes: usize = 0,
    file_len: u64 = header_len,

    pub const name = "journal";

    /// Opens (or starts) the journal in `dir`; never fails hard: without a usable
    /// file the journal lives in memory under a fresh epoch.
    pub fn open(gpa: std.mem.Allocator, dir: ?std.fs.Dir) Journal {
        var j: Journal = .{ .gpa = gpa, .dir = dir };
        j.load() catch |e| {
            if (e == error.FileNotFound) std.log.info("change journal: new", .{}) else std.log.warn("change journal: starting a new epoch ({t})", .{e});
            j.reset();
        };
        return j;
    }

    pub fn deinit(j: *Journal) void {
        for (j.entries.items) |e| j.gpa.free(e.bytes);
        j.entries.deinit(j.gpa);
        if (j.file) |f| f.close();
    }

    fn reset(j: *Journal) void {
        for (j.entries.items) |e| j.gpa.free(e.bytes);
        j.entries.clearRetainingCapacity();
        j.bytes = 0;
        j.epoch = std.crypto.random.int(u64) | 1;
        j.next = 1;
        j.stable = 0;
        if (j.file) |f| f.close();
        j.file = null;
        j.rewrite() catch |e| std.log.warn("change journal: kept in memory only ({t})", .{e});
    }

    fn load(j: *Journal) !void {
        const d = j.dir orelse return error.NoDirectory;
        var f = try d.openFile(name, .{ .mode = .read_write });
        errdefer f.close();
        var hb: [header_len]u8 = undefined;
        if (try f.preadAll(&hb, 0) != header_len or !std.mem.eql(u8, hb[0..4], file_magic)) return error.BadHeader;
        const epoch = std.mem.readInt(u64, hb[4..12], .little);
        const clean = hb[28] == 1;
        // Same boot: a crash cannot lose written bytes. Another boot: only a clean close counts.
        if (!clean and !std.mem.eql(u8, hb[12..28], &bootId())) return error.UncleanReboot;
        const size = (try f.stat()).size;
        const all = try j.gpa.alloc(u8, @intCast(size - header_len));
        defer j.gpa.free(all);
        if (try f.preadAll(all, header_len) != all.len) return error.ShortRead;
        var pos: usize = 0;
        var last: u64 = 0;
        while (all.len - pos >= entry_head) {
            const seq = std.mem.readInt(u64, all[pos..][0..8], .little);
            const len = std.mem.readInt(u32, all[pos + 8 ..][0..4], .little);
            if (len == 0 or len > max_note or all.len - pos - entry_head < len or seq <= last) break;
            const body = all[pos + entry_head ..][0..len];
            _ = wire.decodeNote(body) catch break;
            try j.keep(seq, body, true);
            last = seq;
            pos += entry_head + len;
        }
        j.epoch = epoch;
        j.next = last + 1;
        j.stable = last;
        j.file = f;
        // A torn tail is cut so new entries follow the last good one.
        j.file_len = header_len + pos;
        try f.setEndPos(j.file_len);
        try j.writeHeader(false);
    }

    fn writeHeader(j: *Journal, clean: bool) !void {
        const f = j.file orelse return;
        var hb: [header_len]u8 = undefined;
        @memcpy(hb[0..4], file_magic);
        std.mem.writeInt(u64, hb[4..12], j.epoch, .little);
        hb[12..28].* = bootId();
        hb[28] = @intFromBool(clean);
        try f.pwriteAll(&hb, 0);
    }

    /// Writes the file anew from the entries in memory (compaction, new epoch).
    fn rewrite(j: *Journal) !void {
        const d = j.dir orelse return;
        const tmp = name ++ ".tmp";
        const f = try d.createFile(tmp, .{ .read = true, .truncate = true });
        if (j.file) |old| old.close();
        j.file = f;
        errdefer {
            f.close();
            j.file = null;
        }
        try j.writeHeader(false);
        var w_buf: [64 * 1024]u8 = undefined;
        var fw = f.writer(&w_buf);
        try fw.seekTo(header_len);
        var len: u64 = header_len;
        for (j.entries.items) |e| {
            try writeEntry(&fw.interface, e.seq, e.bytes);
            len += entry_head + e.bytes.len;
        }
        try fw.interface.flush();
        try f.sync();
        try d.rename(tmp, name);
        j.file_len = len;
    }

    fn writeEntry(w: *std.Io.Writer, seq: u64, bytes: []const u8) !void {
        try w.writeInt(u64, seq, .little);
        try w.writeInt(u32, @intCast(bytes.len), .little);
        try w.writeAll(bytes);
    }

    fn keep(j: *Journal, seq: u64, bytes: []const u8, done: bool) error{OutOfMemory}!void {
        const copy = try j.gpa.dupe(u8, bytes);
        errdefer j.gpa.free(copy);
        try j.entries.append(j.gpa, .{ .seq = seq, .bytes = copy, .done = done, .born_ms = std.time.milliTimestamp() });
        j.bytes += copy.len;
        if (j.entries.items.len <= max_entries and j.bytes <= max_bytes) return;
        // Drop the oldest eighth at once so trimming stays cheap.
        const drop = @max(1, j.entries.items.len / 8);
        for (j.entries.items[0..drop]) |e| {
            j.bytes -= e.bytes.len;
            j.gpa.free(e.bytes);
        }
        j.entries.replaceRangeAssumeCapacity(0, drop, &.{});
    }

    /// Records a change; returns its sequence number (0 when it could not be kept,
    /// which makes peers fall back to a rebuild for this epoch).
    pub fn append(j: *Journal, note: wire.Note) u64 {
        var buf: [max_note + 4]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        wire.encodeNote(&w, note) catch return j.lost();
        const bytes = w.buffered();
        j.mutex.lock();
        defer j.mutex.unlock();
        const seq = j.next;
        j.keep(seq, bytes, false) catch return j.lostLocked();
        j.next += 1;
        if (j.file) |f| {
            var eb: [entry_head]u8 = undefined;
            std.mem.writeInt(u64, eb[0..8], seq, .little);
            std.mem.writeInt(u32, eb[8..12], @intCast(bytes.len), .little);
            const ok = blk: {
                f.pwriteAll(&eb, j.file_len) catch break :blk false;
                f.pwriteAll(bytes, j.file_len + entry_head) catch break :blk false;
                break :blk true;
            };
            if (!ok) return j.lostLocked();
            j.file_len += entry_head + bytes.len;
            if (j.file_len > 2 * max_bytes + header_len) j.rewrite() catch {};
        }
        return seq;
    }

    fn lost(j: *Journal) u64 {
        j.mutex.lock();
        defer j.mutex.unlock();
        return j.lostLocked();
    }

    /// An entry that cannot be kept breaks the sequence: start a new epoch.
    fn lostLocked(j: *Journal) u64 {
        std.log.warn("change journal: entry lost; starting a new epoch", .{});
        j.reset();
        return 0;
    }

    /// Marks entries whose operation published; advances the stable point.
    pub fn finish(j: *Journal, seqs: []const u64) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        for (seqs) |s| if (j.find(s)) |i| {
            j.entries.items[i].done = true;
        };
        const items = j.entries.items;
        var i: usize = if (items.len > 0 and j.stable >= items[0].seq) @intCast(j.stable - items[0].seq + 1) else 0;
        while (i < items.len and items[i].done) : (i += 1) j.stable = items[i].seq;
    }

    /// Lets entries stuck unfinished past `stuck_ms` turn stable.
    pub fn expireStuck(j: *Journal, now_ms: i64) void {
        var stuck: [16]u64 = undefined;
        var n: usize = 0;
        {
            j.mutex.lock();
            defer j.mutex.unlock();
            for (j.entries.items) |e| {
                if (e.seq <= j.stable or e.done) continue;
                if (now_ms - e.born_ms < stuck_ms or n == stuck.len) break;
                stuck[n] = e.seq;
                n += 1;
            }
        }
        if (n > 0) j.finish(stuck[0..n]);
    }

    fn find(j: *Journal, seq: u64) ?usize {
        const items = j.entries.items;
        if (items.len == 0 or seq < items[0].seq) return null;
        const i: usize = @intCast(seq - items[0].seq);
        return if (i < items.len and items[i].seq == seq) i else null;
    }

    pub const Head = struct { epoch: u64, stable: u64 };

    pub fn head(j: *Journal) Head {
        j.mutex.lock();
        defer j.mutex.unlock();
        return .{ .epoch = j.epoch, .stable = j.stable };
    }

    /// The last entry handed out (finished or not).
    pub fn lastAppended(j: *Journal) Head {
        j.mutex.lock();
        defer j.mutex.unlock();
        return .{ .epoch = j.epoch, .stable = j.next - 1 };
    }

    pub const ReadError = error{ OutOfMemory, Gone };
    pub const Page = struct { bytes: []u8, more: bool };

    /// Stable entries after `after` (at most `limit` bytes), framed as `u64 seq,
    /// u32 len, note`. Gone: another epoch, or entries already dropped.
    pub fn read(j: *Journal, gpa: std.mem.Allocator, epoch: u64, after: u64, limit: usize) ReadError!Page {
        j.mutex.lock();
        defer j.mutex.unlock();
        if (epoch != j.epoch or after >= j.next) return error.Gone;
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        // A reader ahead of the stable point got those entries as notes.
        if (after >= j.stable) return .{ .bytes = try out.toOwnedSlice(), .more = false };
        const first = j.find(after + 1) orelse return error.Gone;
        var last = after;
        for (j.entries.items[first..]) |e| {
            if (e.seq > j.stable or out.written().len + entry_head + e.bytes.len > limit) break;
            writeEntry(&out.writer, e.seq, e.bytes) catch return error.OutOfMemory;
            last = e.seq;
        }
        return .{ .bytes = try out.toOwnedSlice(), .more = last < j.stable };
    }

    /// Flushes the file; `clean` marks a deliberate shutdown (survives a reboot).
    pub fn sync(j: *Journal, clean: bool) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        const f = j.file orelse return;
        if (clean) j.writeHeader(true) catch {};
        f.sync() catch {};
    }
};

/// Entries of a `Journal.read` page.
pub const PageIter = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub const Item = struct { seq: u64, note: wire.Note };

    pub fn next(it: *PageIter) error{BadPage}!?Item {
        if (it.pos == it.bytes.len) return null;
        if (it.bytes.len - it.pos < entry_head) return error.BadPage;
        const seq = std.mem.readInt(u64, it.bytes[it.pos..][0..8], .little);
        const len = std.mem.readInt(u32, it.bytes[it.pos + 8 ..][0..4], .little);
        it.pos += entry_head;
        if (len == 0 or len > it.bytes.len - it.pos) return error.BadPage;
        const body = it.bytes[it.pos..][0..len];
        it.pos += len;
        return .{ .seq = seq, .note = wire.decodeNote(body) catch return error.BadPage };
    }
};

/// The kernel's id of this boot; zeros when unknown.
fn bootId() [16]u8 {
    var out: [16]u8 = @splat(0);
    var buf: [64]u8 = undefined;
    const text = std.fs.cwd().readFile("/proc/sys/kernel/random/boot_id", &buf) catch return out;
    var hex: [32]u8 = undefined;
    var n: usize = 0;
    for (text) |c| if (std.ascii.isHex(c) and n < hex.len) {
        hex[n] = c;
        n += 1;
    };
    if (n == hex.len) _ = std.fmt.hexToBytes(&out, &hex) catch {};
    return out;
}

test "journal: sequence, stable point, reads, reload, and epochs" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const n1: wire.Note = .{ .change = .catalog };
    const n2: wire.Note = .{ .change = .{ .upload = .{ .bytes = @splat(7) } } };
    var epoch: u64 = 0;
    {
        var j = Journal.open(gpa, tmp.dir);
        defer j.deinit();
        epoch = j.epoch;
        try std.testing.expectEqual(@as(u64, 1), j.append(n1));
        try std.testing.expectEqual(@as(u64, 2), j.append(n2));
        try std.testing.expectEqual(@as(u64, 3), j.append(n1));
        // Entry 2 finished first: nothing is stable until 1 is.
        j.finish(&.{2});
        try std.testing.expectEqual(@as(u64, 0), j.head().stable);
        j.finish(&.{1});
        try std.testing.expectEqual(@as(u64, 2), j.head().stable);
        const page = try j.read(gpa, epoch, 0, 1 << 20);
        defer gpa.free(page.bytes);
        try std.testing.expect(!page.more);
        var it: PageIter = .{ .bytes = page.bytes };
        try std.testing.expectEqual(@as(u64, 1), (try it.next()).?.seq);
        const second = (try it.next()).?;
        try std.testing.expectEqual(@as(u64, 2), second.seq);
        try std.testing.expectEqual(@as(u8, 7), second.note.change.upload.bytes[0]);
        try std.testing.expect((try it.next()) == null);
        try std.testing.expectError(error.Gone, j.read(gpa, epoch +% 1, 0, 1 << 20));
        try std.testing.expectError(error.Gone, j.read(gpa, epoch, 4, 1 << 20));
        const ahead = try j.read(gpa, epoch, 3, 1 << 20);
        try std.testing.expectEqual(@as(usize, 0), ahead.bytes.len);
        gpa.free(ahead.bytes);
    }
    {
        // Reopened in the same boot: same epoch, everything stable, numbering continues.
        var j = Journal.open(gpa, tmp.dir);
        defer j.deinit();
        try std.testing.expectEqual(epoch, j.epoch);
        try std.testing.expectEqual(@as(u64, 3), j.head().stable);
        try std.testing.expectEqual(@as(u64, 4), j.append(n2));
        j.sync(true);
    }
    {
        // After a clean close too.
        var j = Journal.open(gpa, tmp.dir);
        defer j.deinit();
        try std.testing.expectEqual(epoch, j.epoch);
        try std.testing.expectEqual(@as(u64, 4), j.head().stable);
    }
    // A torn tail is cut, not fatal.
    {
        var f = try tmp.dir.openFile(Journal.name, .{ .mode = .read_write });
        defer f.close();
        try f.pwriteAll("\x09\x00\x00", (try f.stat()).size);
    }
    {
        var j = Journal.open(gpa, tmp.dir);
        defer j.deinit();
        try std.testing.expectEqual(epoch, j.epoch);
        try std.testing.expectEqual(@as(u64, 5), j.append(n1));
    }
    // A lost file means a new epoch.
    try tmp.dir.deleteFile(Journal.name);
    var j = Journal.open(gpa, tmp.dir);
    defer j.deinit();
    try std.testing.expect(j.epoch != epoch);
    try std.testing.expectEqual(@as(u64, 1), j.append(n1));
}
