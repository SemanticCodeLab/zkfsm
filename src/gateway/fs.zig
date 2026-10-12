//! A POSIX-like view of the object namespace for file protocols: buckets are
//! top-level directories, `/`-separated keys form the tree below them. Empty
//! directories are zero-byte `dir/` marker objects. Every call is authorized.
const std = @import("std");
const object = @import("../object/root.zig");
const core = @import("../core/root.zig");
const access_mod = @import("access.zig");

const Access = access_mod.Access;
const Principal = access_mod.Principal;
const Op = access_mod.Op;

pub const max_path = 1024;
/// Upper bound on objects touched by one directory rename.
pub const max_rename_objects = 10_000;

pub const Error = error{
    NotFound,
    Exists,
    NotEmpty,
    Denied,
    InvalidPath,
    IsDir,
    NotDir,
    TooLarge,
    /// The bucket's hard quota would be exceeded.
    QuotaExceeded,
    Storage,
    OutOfMemory,
    /// The caller's source or sink failed.
    ReadFailed,
    WriteFailed,
};

pub const Kind = enum { root, bucket, dir, file };

pub const Stat = struct {
    kind: Kind,
    size: u64 = 0,
    mtime_ns: i128 = 0,
    etag: ?core.ETag = null,
};

pub const Entry = struct {
    name: []const u8,
    kind: Kind,
    size: u64 = 0,
    mtime_ns: i128 = 0,
    etag: ?core.ETag = null,
};

/// A path split into bucket and key; key ends without `/` (dir keys are prefixes).
pub const Loc = struct {
    bucket: []const u8,
    key: []const u8,

    pub fn kindHint(l: Loc) Kind {
        if (l.bucket.len == 0) return .root;
        if (l.key.len == 0) return .bucket;
        return .file;
    }
};

/// Resolves `input` against `cwd` (both `/`-separated) into `buf`, collapsing `.`,
/// `..`, and repeated slashes. The result is absolute without a trailing slash.
pub fn normalize(buf: []u8, cwd: []const u8, input: []const u8) Error![]const u8 {
    var segs: [256][]const u8 = undefined;
    var n: usize = 0;
    const parts = [_][]const u8{ if (input.len > 0 and input[0] == '/') "" else cwd, input };
    for (parts) |part| {
        var it = std.mem.tokenizeScalar(u8, part, '/');
        while (it.next()) |s| {
            if (std.mem.eql(u8, s, ".")) continue;
            if (std.mem.eql(u8, s, "..")) {
                n -|= 1;
                continue;
            }
            if (std.mem.indexOfScalar(u8, s, 0) != null) return error.InvalidPath;
            if (n == segs.len) return error.InvalidPath;
            segs[n] = s;
            n += 1;
        }
    }
    var w: usize = 0;
    if (n == 0) {
        if (buf.len < 1) return error.InvalidPath;
        buf[0] = '/';
        return buf[0..1];
    }
    for (segs[0..n]) |s| {
        if (w + 1 + s.len > buf.len or w + 1 + s.len > max_path) return error.InvalidPath;
        buf[w] = '/';
        @memcpy(buf[w + 1 ..][0..s.len], s);
        w += 1 + s.len;
    }
    return buf[0..w];
}

/// Splits a normalized absolute path.
pub fn split(path: []const u8) Loc {
    const p = std.mem.trim(u8, path, "/");
    const slash = std.mem.indexOfScalar(u8, p, '/') orelse return .{ .bucket = p, .key = "" };
    return .{ .bucket = p[0..slash], .key = p[slash + 1 ..] };
}

/// Last path component (empty for the root).
pub fn baseName(path: []const u8) []const u8 {
    const p = std.mem.trimRight(u8, path, "/");
    const i = std.mem.lastIndexOfScalar(u8, p, '/') orelse return p;
    return p[i + 1 ..];
}

fn mapErr(e: object.Error) Error {
    return switch (e) {
        error.NoSuchBucket, error.NoSuchKey, error.NoSuchVersion => error.NotFound,
        error.BucketAlreadyExists => error.Exists,
        error.BucketNotEmpty => error.NotEmpty,
        error.InvalidBucketName, error.KeyTooLong, error.InvalidKey => error.InvalidPath,
        error.OutOfMemory => error.OutOfMemory,
        error.ReadFailed => error.ReadFailed,
        error.WriteFailed => error.WriteFailed,
        error.MetadataTooLarge => error.TooLarge,
        error.ObjectLocked, error.MethodNotAllowed => error.Denied,
        error.QuotaExceeded => error.QuotaExceeded,
        else => error.Storage,
    };
}

/// One logged-in session's view. Cheap to copy.
pub const Fs = struct {
    access: Access,
    who: Principal,
    peer: ?std.net.Address = null,
    secure: bool = false,

    fn check(f: *const Fs, op: Op, bucket: []const u8, key: []const u8) Error!void {
        if (!f.access.allowed(&f.who, op, bucket, key, f.peer, f.secure)) return error.Denied;
    }

    fn svc(f: *const Fs) *object.ObjectService {
        return f.access.svc;
    }

    /// Kind and attributes of a normalized path.
    pub fn stat(f: *const Fs, arena: std.mem.Allocator, path: []const u8) Error!Stat {
        const l = split(path);
        switch (l.kindHint()) {
            .root => return .{ .kind = .root },
            .bucket => {
                try f.check(.head_bucket, l.bucket, "");
                f.svc().headBucket(l.bucket) catch |e| return mapErr(e);
                const created = for (f.svc().listBuckets(arena) catch |e| return mapErr(e)) |b| {
                    if (std.mem.eql(u8, b.name, l.bucket)) break b.created_ns;
                } else 0;
                return .{ .kind = .bucket, .mtime_ns = created };
            },
            else => {},
        }
        try f.check(.head_object, l.bucket, l.key);
        if (f.svc().head(arena, l.bucket, l.key)) |info| {
            return .{ .kind = .file, .size = info.size, .mtime_ns = info.created_ns, .etag = info.etag };
        } else |e| switch (e) {
            error.NoSuchKey, error.InvalidKey => {},
            else => return mapErr(e),
        }
        const prefix = try std.fmt.allocPrint(arena, "{s}/", .{l.key});
        const r = f.svc().list(arena, l.bucket, .{ .prefix = prefix, .max_keys = 1 }) catch |e| return mapErr(e);
        if (r.contents.len == 0 and r.common_prefixes.len == 0) return error.NotFound;
        const mtime = if (r.contents.len > 0 and r.contents[0].key.len == prefix.len) r.contents[0].mtime_ns else 0;
        return .{ .kind = .dir, .mtime_ns = mtime };
    }

    /// Object metadata for reading a file; strings live in `arena`.
    pub fn openRead(f: *const Fs, arena: std.mem.Allocator, path: []const u8) Error!object.ObjectInfo {
        const l = split(path);
        if (l.key.len == 0) return error.IsDir;
        try f.check(.get_object, l.bucket, l.key);
        return f.svc().head(arena, l.bucket, l.key) catch |e| switch (e) {
            error.NoSuchKey => if (f.stat(arena, path)) |_| error.IsDir else |_| error.NotFound,
            else => mapErr(e),
        };
    }

    /// Streams `range` (or all) of an object opened with `openRead`.
    pub fn read(f: *const Fs, info: object.ObjectInfo, range: ?core.Range, sink: *std.Io.Writer) Error!void {
        f.svc().read(info, range, sink) catch |e| return mapErr(e);
    }

    /// Stores `source` as the file at `path`, replacing any existing object.
    pub fn write(f: *const Fs, path: []const u8, source: *std.Io.Reader, len: ?u64, content_type: []const u8) Error!object.ObjectInfo {
        const l = split(path);
        if (l.key.len == 0) return error.IsDir;
        try f.check(.put_object, l.bucket, l.key);
        return f.svc().put(l.bucket, l.key, source, .{ .content_length = len, .content_type = content_type }) catch |e| mapErr(e);
    }

    pub fn remove(f: *const Fs, arena: std.mem.Allocator, path: []const u8) Error!void {
        const l = split(path);
        if (l.key.len == 0) return error.IsDir;
        try f.check(.delete_object, l.bucket, l.key);
        _ = f.svc().head(arena, l.bucket, l.key) catch |e| return mapErr(e);
        f.svc().delete(l.bucket, l.key) catch |e| return mapErr(e);
    }

    /// A bucket at the top level, else a `dir/` marker object.
    pub fn mkdir(f: *const Fs, arena: std.mem.Allocator, path: []const u8) Error!void {
        const l = split(path);
        switch (l.kindHint()) {
            .root => return error.Exists,
            .bucket => {
                try f.check(.create_bucket, l.bucket, "");
                return f.access.createBucket(&f.who, l.bucket) catch |e| mapErr(e);
            },
            else => {},
        }
        if (f.stat(arena, path)) |_| return error.Exists else |e| if (e != error.NotFound) return e;
        const marker = try std.fmt.allocPrint(arena, "{s}/", .{l.key});
        try f.check(.put_object, l.bucket, marker);
        var empty: std.Io.Reader = .fixed("");
        _ = f.svc().put(l.bucket, marker, &empty, .{ .content_length = 0 }) catch |e| return mapErr(e);
    }

    /// Removes an empty directory (its marker) or an empty bucket.
    pub fn rmdir(f: *const Fs, arena: std.mem.Allocator, path: []const u8) Error!void {
        const l = split(path);
        switch (l.kindHint()) {
            .root => return error.Denied,
            .bucket => {
                try f.check(.delete_bucket, l.bucket, "");
                return f.svc().deleteBucket(l.bucket) catch |e| mapErr(e);
            },
            else => {},
        }
        const st = try f.stat(arena, path);
        if (st.kind != .dir) return error.NotDir;
        const prefix = try std.fmt.allocPrint(arena, "{s}/", .{l.key});
        const r = f.svc().list(arena, l.bucket, .{ .prefix = prefix, .max_keys = 2 }) catch |e| return mapErr(e);
        for (r.contents) |c| if (c.key.len != prefix.len) return error.NotEmpty;
        if (r.common_prefixes.len > 0) return error.NotEmpty;
        try f.check(.delete_object, l.bucket, prefix);
        f.svc().delete(l.bucket, prefix) catch |e| return mapErr(e);
    }

    /// Server-side copy of one file.
    pub fn copyFile(f: *const Fs, src: []const u8, dst: []const u8) Error!void {
        const s = split(src);
        const d = split(dst);
        if (s.key.len == 0 or d.key.len == 0) return error.IsDir;
        try f.check(.get_object, s.bucket, s.key);
        try f.check(.put_object, d.bucket, d.key);
        _ = object.copy.copyObject(f.svc(), .{ .bucket = s.bucket, .key = s.key }, d.bucket, d.key, .{}) catch |e| return mapErr(e);
    }

    /// Rename: copy then delete. Directories move every object under them (bounded).
    pub fn rename(f: *const Fs, arena: std.mem.Allocator, src: []const u8, dst: []const u8) Error!void {
        const st = try f.stat(arena, src);
        switch (st.kind) {
            .root, .bucket => return error.Denied,
            .file => {
                try f.copyFile(src, dst);
                return f.remove(arena, src);
            },
            .dir => {},
        }
        const s = split(src);
        const d = split(dst);
        if (d.key.len == 0) return error.Denied;
        const sp = try std.fmt.allocPrint(arena, "{s}/", .{s.key});
        const dp = try std.fmt.allocPrint(arena, "{s}/", .{d.key});
        if (std.mem.eql(u8, s.bucket, d.bucket) and std.mem.startsWith(u8, dp, sp)) return error.InvalidPath;
        var keys: std.ArrayList([]const u8) = .empty;
        var after: []const u8 = "";
        while (true) {
            const r = f.svc().list(arena, s.bucket, .{ .prefix = sp, .start_after = after, .max_keys = 1000 }) catch |e| return mapErr(e);
            for (r.contents) |c| try keys.append(arena, c.key);
            if (keys.items.len > max_rename_objects) return error.TooLarge;
            if (!r.is_truncated) break;
            after = r.next_marker orelse break;
        }
        for (keys.items) |k| {
            const nk = try std.fmt.allocPrint(arena, "{s}{s}", .{ dp, k[sp.len..] });
            try f.check(.get_object, s.bucket, k);
            try f.check(.put_object, d.bucket, nk);
            try f.check(.delete_object, s.bucket, k);
            _ = object.copy.copyObject(f.svc(), .{ .bucket = s.bucket, .key = k }, d.bucket, nk, .{}) catch |e| return mapErr(e);
            f.svc().delete(s.bucket, k) catch |e| return mapErr(e);
        }
    }

    /// Directory listing, paged. Strings live in `arena`. Pass the returned
    /// cursor back to continue; null cursor means the listing is complete.
    pub fn list(f: *const Fs, arena: std.mem.Allocator, path: []const u8, cursor: []const u8, max: usize) Error!Page {
        const l = split(path);
        var out: std.ArrayList(Entry) = .empty;
        if (l.bucket.len == 0) {
            try f.check(.list_buckets, "", "");
            const bs = f.access.visibleBuckets(arena, &f.who) catch |e| return mapErr(e);
            for (bs) |b| try out.append(arena, .{ .name = b.name, .kind = .bucket, .mtime_ns = b.created_ns });
            return .{ .entries = out.items, .next = null };
        }
        try f.check(.list_objects, l.bucket, "");
        const prefix = if (l.key.len == 0) "" else try std.fmt.allocPrint(arena, "{s}/", .{l.key});
        const r = f.svc().list(arena, l.bucket, .{ .prefix = prefix, .delimiter = "/", .start_after = cursor, .max_keys = @max(1, max) }) catch |e| return mapErr(e);
        if (l.key.len > 0 and cursor.len == 0 and r.contents.len == 0 and r.common_prefixes.len == 0) {
            if (f.svc().head(arena, l.bucket, l.key)) |_| return error.NotDir else |_| return error.NotFound;
        }
        for (r.common_prefixes) |cp| {
            const name = std.mem.trimRight(u8, cp[prefix.len..], "/");
            if (name.len > 0) try out.append(arena, .{ .name = name, .kind = .dir });
        }
        for (r.contents) |c| {
            if (c.key.len == prefix.len) continue; // this directory's own marker
            try out.append(arena, .{ .name = c.key[prefix.len..], .kind = .file, .size = c.size, .mtime_ns = c.mtime_ns, .etag = c.etag });
        }
        return .{ .entries = out.items, .next = if (r.is_truncated) r.next_marker else null };
    }
};

pub const Page = struct { entries: []Entry, next: ?[]const u8 };

fn mapMp(e: object.multipart.Error) Error {
    return switch (e) {
        error.NoSuchUpload, error.InvalidPart, error.InvalidPartOrder, error.EntityTooSmall, error.InvalidPartNumber, error.InvalidRange => error.Storage,
        else => |se| mapErr(se),
    };
}

/// Streaming write of one file: bytes buffer up to `part_size`, then go out as
/// multipart parts. A file that never fills a part is stored with one plain put.
pub const Upload = struct {
    f: Fs,
    gpa: std.mem.Allocator,
    bucket: []u8,
    key: []u8,
    id: ?object.multipart.UploadId = null,
    refs: std.ArrayList(object.multipart.PartRef) = .empty,
    buf: std.ArrayList(u8) = .empty,
    /// Bytes already sent as parts; writes below this offset are refused.
    flushed: u64 = 0,

    pub const part_size: usize = 8 * 1024 * 1024;
    pub const WriteError = Error || error{Unordered};

    pub fn begin(f: Fs, gpa: std.mem.Allocator, path: []const u8) Error!Upload {
        const l = split(path);
        if (l.key.len == 0) return error.IsDir;
        try f.check(.put_object, l.bucket, l.key);
        f.svc().headBucket(l.bucket) catch |e| return mapErr(e);
        const b = try gpa.dupe(u8, l.bucket);
        errdefer gpa.free(b);
        return .{ .f = f, .gpa = gpa, .bucket = b, .key = try gpa.dupe(u8, l.key) };
    }

    pub fn size(u: *const Upload) u64 {
        return u.flushed + u.buf.items.len;
    }

    /// Writes `data` at `off`; gaps read as zeros. Offsets below the sent parts fail.
    pub fn writeAt(u: *Upload, off: u64, data: []const u8) WriteError!void {
        if (off < u.flushed) return error.Unordered;
        while (u.size() < off) {
            const room = part_size -| u.buf.items.len;
            const n: usize = @intCast(@min(off - u.size(), @max(room, 1)));
            try u.buf.appendNTimes(u.gpa, 0, n);
            try u.maybeFlush();
        }
        const rel: usize = @intCast(off - u.flushed);
        const over = @min(data.len, u.buf.items.len - rel);
        @memcpy(u.buf.items[rel..][0..over], data[0..over]);
        var rest = data[over..];
        while (rest.len > 0) {
            const n = @min(rest.len, @max(part_size -| u.buf.items.len, 1));
            try u.buf.appendSlice(u.gpa, rest[0..n]);
            rest = rest[n..];
            try u.maybeFlush();
        }
    }

    /// Sequential append from a stream until it ends.
    pub fn pump(u: *Upload, src: *std.Io.Reader) Error!void {
        while (true) {
            try u.buf.ensureTotalCapacity(u.gpa, part_size);
            const dst = u.buf.allocatedSlice()[u.buf.items.len..part_size];
            const n = src.readSliceShort(dst) catch return error.ReadFailed;
            u.buf.items.len += n;
            if (u.buf.items.len >= part_size) try u.flushPart();
            if (n < dst.len) return;
        }
    }

    /// Seeds the file with the first `len` bytes of the object now at the path.
    pub fn copyPrefix(u: *Upload, arena: std.mem.Allocator, len: u64) Error!void {
        if (len == 0) return;
        try u.f.check(.get_object, u.bucket, u.key);
        if (len >= object.multipart.min_part_size) {
            try u.startMp();
            const src: object.copy.Source = .{ .bucket = u.bucket, .key = u.key };
            const et = object.multipart.uploadPartCopy(u.f.svc(), u.bucket, u.key, u.id.?, 1, src, .{ .first = 0, .last = len - 1 }) catch |e| return mapMp(e);
            try u.refs.append(u.gpa, .{ .number = 1, .md5 = et.md5 });
            u.flushed = len;
            return;
        }
        const info = u.f.svc().head(arena, u.bucket, u.key) catch |e| return mapErr(e);
        if (len > info.size) return error.InvalidPath;
        var aw: std.Io.Writer.Allocating = .fromArrayList(u.gpa, &u.buf);
        defer u.buf = aw.toArrayList();
        u.f.svc().read(info, .{ .offset = 0, .length = len }, &aw.writer) catch |e| return mapErr(e);
    }

    fn startMp(u: *Upload) Error!void {
        if (u.id != null) return;
        u.id = object.multipart.create(u.f.svc(), u.bucket, u.key, .{ .content_type = "application/octet-stream" }) catch |e| return mapMp(e);
    }

    fn maybeFlush(u: *Upload) Error!void {
        if (u.buf.items.len >= part_size) try u.flushPart();
    }

    fn flushPart(u: *Upload) Error!void {
        try u.startMp();
        const n: u16 = @intCast(u.refs.items.len + 1);
        if (n > object.multipart.max_part_number) return error.TooLarge;
        var r: std.Io.Reader = .fixed(u.buf.items);
        const et = object.multipart.uploadPart(u.f.svc(), u.bucket, u.key, u.id.?, n, &r, u.buf.items.len) catch |e| return mapMp(e);
        try u.refs.append(u.gpa, .{ .number = n, .md5 = et.md5 });
        u.flushed += u.buf.items.len;
        u.buf.clearRetainingCapacity();
    }

    /// Commits the file. The Upload must still be released with `deinit`.
    pub fn finish(u: *Upload) Error!void {
        if (u.id == null) {
            var r: std.Io.Reader = .fixed(u.buf.items);
            _ = u.f.svc().put(u.bucket, u.key, &r, .{ .content_length = u.buf.items.len, .content_type = "application/octet-stream" }) catch |e| return mapErr(e);
            return;
        }
        if (u.buf.items.len > 0) try u.flushPart();
        _ = object.multipart.complete(u.f.svc(), u.bucket, u.key, u.id.?, u.refs.items) catch |e| return mapMp(e);
        u.id = null;
    }

    /// Drops any started multipart upload and frees memory.
    pub fn deinit(u: *Upload) void {
        if (u.id) |id| object.multipart.abort(u.f.svc(), u.bucket, u.key, id) catch {};
        u.refs.deinit(u.gpa);
        u.buf.deinit(u.gpa);
        u.gpa.free(u.bucket);
        u.gpa.free(u.key);
        u.* = undefined;
    }
};

test "normalize and split" {
    var buf: [max_path]u8 = undefined;
    try std.testing.expectEqualStrings("/", try normalize(&buf, "/", ""));
    try std.testing.expectEqualStrings("/b/x", try normalize(&buf, "/b", "x"));
    try std.testing.expectEqualStrings("/c", try normalize(&buf, "/b/x", "/c/./"));
    try std.testing.expectEqualStrings("/", try normalize(&buf, "/b", "../../.."));
    try std.testing.expectEqualStrings("/b/y", try normalize(&buf, "/b/x", "../y"));
    const l = split("/bkt/a/b.txt");
    try std.testing.expectEqualStrings("bkt", l.bucket);
    try std.testing.expectEqualStrings("a/b.txt", l.key);
    try std.testing.expectEqual(Kind.root, split("/").kindHint());
    try std.testing.expectEqual(Kind.bucket, split("/bkt").kindHint());
    try std.testing.expectEqualStrings("b.txt", baseName("/bkt/a/b.txt"));
}
