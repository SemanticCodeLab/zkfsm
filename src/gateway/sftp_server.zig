//! SFTP v3 request handling over the gateway file view. Reads are ranged object
//! reads behind a small read-ahead cache; writes spool to an unlinked temp file
//! at their offsets and become one object on CLOSE.
const std = @import("std");
const wire = @import("ssh_wire.zig");
const proto = @import("sftp_proto.zig");
const fs_mod = @import("fs.zig");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");

const Fs = fs_mod.Fs;
const T = proto.Type;
const Status = proto.Status;

pub const Limits = struct {
    /// Largest file accepted for writing (the spool bound).
    max_file: u64 = 5 * 1024 * 1024 * 1024,
    max_handles: usize = 64,
};

const read_ahead = 1024 * 1024;
const readdir_batch = 64;
const out_len = proto.max_packet + 4096;

const File = struct {
    path_buf: [fs_mod.max_path]u8 = undefined,
    path_len: usize = 0,
    /// Read mode: the object being read (strings in `arena`).
    info: ?object.ObjectInfo = null,
    arena: std.heap.ArenaAllocator,
    cache: []u8 = &.{},
    cache_off: u64 = 0,
    cache_len: usize = 0,
    /// Write mode: unlinked spool file holding the whole new content.
    spool: ?std.fs.File = null,
    size: u64 = 0,
    dirty: bool = false,
    append: bool = false,

    fn path(f: *const File) []const u8 {
        return f.path_buf[0..f.path_len];
    }
};

const Dir = struct {
    path_buf: [fs_mod.max_path]u8 = undefined,
    path_len: usize = 0,
    cursor_buf: [2048]u8 = undefined,
    cursor_len: usize = 0,
    done: bool = false,

    fn path(d: *const Dir) []const u8 {
        return d.path_buf[0..d.path_len];
    }
};

const Handle = union(enum) { file: File, dir: Dir };

pub const Session = struct {
    gpa: std.mem.Allocator,
    fs: Fs,
    spool_dir: std.fs.Dir,
    limits: Limits,
    handles: [64]?*Handle = @splat(null),
    gens: [64]u32 = @splat(0),
    out: []u8,
    arena: std.heap.ArenaAllocator,
    inited: bool = false,

    pub fn init(gpa: std.mem.Allocator, fs: Fs, spool_dir: std.fs.Dir, limits: Limits) error{OutOfMemory}!Session {
        return .{
            .gpa = gpa,
            .fs = fs,
            .spool_dir = spool_dir,
            .limits = .{ .max_file = limits.max_file, .max_handles = @min(limits.max_handles, 64) },
            .out = try gpa.alloc(u8, out_len),
            .arena = .init(gpa),
        };
    }

    /// Drops every handle; unfinished uploads are discarded.
    pub fn deinit(s: *Session) void {
        for (&s.handles) |*h| if (h.*) |p| {
            s.freeHandle(p);
            h.* = null;
        };
        s.arena.deinit();
        s.gpa.free(s.out);
    }

    fn freeHandle(s: *Session, h: *Handle) void {
        switch (h.*) {
            .file => |*f| {
                if (f.spool) |sp| sp.close();
                if (f.cache.len > 0) s.gpa.free(f.cache);
                f.arena.deinit();
            },
            .dir => {},
        }
        s.gpa.destroy(h);
    }

    /// Handles one request (without its length prefix); returns the framed reply.
    pub fn handle(s: *Session, req: []const u8) []const u8 {
        _ = s.arena.reset(.retain_capacity);
        var r = wire.Reader.init(req);
        const ty = r.byte() catch return s.status(0, .bad_message, "empty packet");
        if (ty == T.init) {
            s.inited = true;
            return s.versionReply() catch s.status(0, .failure, "reply too large");
        }
        const id = r.u32be() catch return s.status(0, .bad_message, "missing id");
        if (!s.inited) return s.status(id, .failure, "INIT expected");
        return s.dispatch(ty, id, &r) catch |e| switch (e) {
            error.BadMessage => s.status(id, .bad_message, "malformed request"),
            error.NoSpace => s.status(id, .failure, "reply too large"),
        };
    }

    const ReqError = wire.DecodeError || wire.EncodeError;

    fn dispatch(s: *Session, ty: u8, id: u32, r: *wire.Reader) ReqError![]const u8 {
        return switch (ty) {
            T.open => s.open(id, r),
            T.close => s.close(id, r),
            T.read => s.read(id, r),
            T.write => s.write(id, r),
            T.lstat, T.stat => s.stat(id, r),
            T.fstat => s.fstat(id, r),
            T.setstat => blk: {
                _ = try r.stringMax(4096);
                _ = try proto.Attrs.decode(r);
                break :blk s.status(id, .ok, "");
            },
            T.fsetstat => s.fsetstat(id, r),
            T.opendir => s.opendir(id, r),
            T.readdir => s.readdir(id, r),
            T.remove => s.simple(id, r, .remove),
            T.mkdir => s.simple(id, r, .mkdir),
            T.rmdir => s.simple(id, r, .rmdir),
            T.realpath => s.realpath(id, r),
            T.rename => s.rename(id, r, false),
            T.extended => s.extended(id, r),
            else => s.status(id, .op_unsupported, "operation not supported"),
        };
    }

    // ---- replies ----

    fn begin(s: *Session, ty: u8, id: u32) wire.EncodeError!wire.Writer {
        var w = wire.Writer.init(s.out);
        _ = try w.reserve(4);
        try w.byte(ty);
        try w.u32be(id);
        return w;
    }

    fn finish(w: *wire.Writer) []const u8 {
        std.mem.writeInt(u32, w.buf[0..4], @intCast(w.len - 4), .big);
        return w.written();
    }

    fn status(s: *Session, id: u32, code: Status, msg: []const u8) []const u8 {
        var w = s.begin(T.status, id) catch unreachable;
        // Fits: out is far larger than any status line.
        w.u32be(@intFromEnum(code)) catch unreachable;
        w.string(if (msg.len == 0) code.text() else msg[0..@min(msg.len, 256)]) catch unreachable;
        w.string("en") catch unreachable;
        return finish(&w);
    }

    fn fsStatus(s: *Session, id: u32, e: fs_mod.Error) []const u8 {
        const m = proto.statusOf(e);
        return s.status(id, m[0], m[1]);
    }

    fn versionReply(s: *Session) wire.EncodeError![]const u8 {
        var w = wire.Writer.init(s.out);
        _ = try w.reserve(4);
        try w.byte(T.version);
        try w.u32be(proto.version);
        for ([_][2][]const u8{
            .{ "posix-rename@openssh.com", "1" },
            .{ "statvfs@openssh.com", "2" },
            .{ "limits@openssh.com", "1" },
        }) |ext| {
            try w.string(ext[0]);
            try w.string(ext[1]);
        }
        return finish(&w);
    }

    fn pathArg(s: *Session, r: *wire.Reader, buf: *[fs_mod.max_path]u8) (wire.DecodeError || fs_mod.Error)![]const u8 {
        _ = s;
        const raw = try r.stringMax(4096);
        return fs_mod.normalize(buf, "/", raw);
    }

    // ---- handles ----

    fn newHandle(s: *Session, h: Handle) error{ OutOfMemory, TooMany }!struct { *Handle, [8]u8 } {
        const idx = for (s.handles[0..s.limits.max_handles], 0..) |slot, i| {
            if (slot == null) break i;
        } else return error.TooMany;
        const p = try s.gpa.create(Handle);
        p.* = h;
        s.handles[idx] = p;
        s.gens[idx] +%= 1;
        var id: [8]u8 = undefined;
        std.mem.writeInt(u32, id[0..4], @intCast(idx), .big);
        std.mem.writeInt(u32, id[4..8], s.gens[idx], .big);
        return .{ p, id };
    }

    fn lookup(s: *Session, r: *wire.Reader) wire.DecodeError!?struct { *Handle, usize } {
        const id = try r.stringMax(proto.max_handle);
        if (id.len != 8) return null;
        const idx = std.mem.readInt(u32, id[0..4], .big);
        if (idx >= s.handles.len) return null;
        const h = s.handles[idx] orelse return null;
        if (s.gens[idx] != std.mem.readInt(u32, id[4..8], .big)) return null;
        return .{ h, idx };
    }

    fn handleReply(s: *Session, id: u32, hid: [8]u8) wire.EncodeError![]const u8 {
        var w = try s.begin(T.handle, id);
        try w.string(&hid);
        return finish(&w);
    }

    // ---- files ----

    fn open(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        var pb: [fs_mod.max_path]u8 = undefined;
        const path = s.pathArg(r, &pb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        const flags = try r.u32be();
        _ = try proto.Attrs.decode(r);
        const arena = s.arena.allocator();
        var f: File = .{ .arena = .init(s.gpa) };
        var keep = false;
        defer if (!keep) {
            if (f.spool) |sp| sp.close();
            f.arena.deinit();
        };
        @memcpy(f.path_buf[0..path.len], path);
        f.path_len = path.len;

        if (flags & (proto.Open.write | proto.Open.append) == 0) {
            const info = s.fs.openRead(f.arena.allocator(), path) catch |e| return s.fsStatus(id, e);
            f.info = info;
        } else {
            var exists = false;
            if (s.fs.stat(arena, path)) |st| {
                if (st.kind != .file) return s.fsStatus(id, error.IsDir);
                exists = true;
            } else |e| if (e != error.NotFound) return s.fsStatus(id, e);
            if (exists and flags & proto.Open.creat != 0 and flags & proto.Open.excl != 0) return s.fsStatus(id, error.Exists);
            if (!exists and flags & proto.Open.creat == 0) return s.fsStatus(id, error.NotFound);
            f.spool = s.makeSpool() catch return s.status(id, .failure, "cannot create spool file");
            f.append = flags & proto.Open.append != 0;
            f.dirty = !exists or flags & proto.Open.trunc != 0;
            if (exists and flags & proto.Open.trunc == 0) {
                if (s.preload(&f)) |_| {} else |e| return s.fsStatus(id, e);
            }
        }
        const made = s.newHandle(.{ .file = f }) catch |e| return switch (e) {
            error.TooMany => s.status(id, .failure, "too many open handles"),
            error.OutOfMemory => s.status(id, .failure, "out of memory"),
        };
        keep = true;
        return s.handleReply(id, made[1]);
    }

    fn makeSpool(s: *Session) !std.fs.File {
        var rnd: [8]u8 = undefined;
        std.crypto.random.bytes(&rnd);
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "zkfsm-sftp-{x}.spool", .{rnd}) catch unreachable;
        const file = try s.spool_dir.createFile(name, .{ .read = true, .exclusive = true, .mode = 0o600 });
        s.spool_dir.deleteFile(name) catch {};
        return file;
    }

    /// Copies the existing object into the spool so partial rewrites keep the rest.
    fn preload(s: *Session, f: *File) fs_mod.Error!void {
        const info = try s.fs.openRead(f.arena.allocator(), f.path());
        if (info.size > s.limits.max_file) return error.TooLarge;
        const buf = try s.gpa.alloc(u8, 64 * 1024);
        defer s.gpa.free(buf);
        var fw = f.spool.?.writer(buf);
        try s.fs.read(info, null, &fw.interface);
        fw.interface.flush() catch return error.WriteFailed;
        f.size = info.size;
    }

    fn fileOf(s: *Session, r: *wire.Reader) wire.DecodeError!?*File {
        const h = (try s.lookup(r)) orelse return null;
        return if (h[0].* == .file) &h[0].file else null;
    }

    fn read(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const f = (try s.fileOf(r)) orelse return s.status(id, .failure, "invalid handle");
        const off = try r.u64be();
        const want = @min(try r.u32be(), proto.max_io);
        const size = if (f.info) |i| i.size else f.size;
        if (off >= size or want == 0) return s.status(id, .eof, "");
        const n: usize = @intCast(@min(want, size - off));
        var w = try s.begin(T.data, id);
        try w.u32be(@intCast(n));
        const dst = try w.reserve(n);
        if (f.spool) |sp| {
            const got = sp.preadAll(dst, off) catch return s.status(id, .failure, "spool read failed");
            if (got != n) return s.status(id, .failure, "short spool read");
            return finish(&w);
        }
        if (!(off >= f.cache_off and off + n <= f.cache_off + f.cache_len)) {
            if (f.cache.len == 0) f.cache = s.gpa.alloc(u8, read_ahead) catch return s.status(id, .failure, "out of memory");
            const chunk: usize = @intCast(@min(read_ahead, size - off));
            var fw: std.Io.Writer = .fixed(f.cache[0..chunk]);
            f.cache_len = 0;
            s.fs.read(f.info.?, core.Range{ .offset = off, .length = chunk }, &fw) catch |e| return s.fsStatus(id, e);
            if (fw.end != chunk) return s.status(id, .failure, "short read");
            f.cache_off = off;
            f.cache_len = chunk;
        }
        const start: usize = @intCast(off - f.cache_off);
        @memcpy(dst, f.cache[start..][0..n]);
        return finish(&w);
    }

    fn write(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const f = (try s.fileOf(r)) orelse return s.status(id, .failure, "invalid handle");
        var off = try r.u64be();
        const data = try r.string();
        const sp = f.spool orelse return s.status(id, .permission_denied, "handle not open for writing");
        if (f.append) off = f.size;
        if (off > s.limits.max_file or data.len > s.limits.max_file - off) return s.status(id, .failure, "file too large");
        sp.pwriteAll(data, off) catch return s.status(id, .failure, "spool write failed");
        f.size = @max(f.size, off + data.len);
        f.dirty = true;
        return s.status(id, .ok, "");
    }

    fn close(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const h = (try s.lookup(r)) orelse return s.status(id, .failure, "invalid handle");
        s.handles[h[1]] = null;
        defer s.freeHandle(h[0]);
        if (h[0].* == .file) {
            const f = &h[0].file;
            if (f.spool != null and f.dirty) {
                if (s.commit(f)) |_| {} else |e| return s.fsStatus(id, e);
            }
        }
        return s.status(id, .ok, "");
    }

    fn commit(s: *Session, f: *File) fs_mod.Error!void {
        const buf = try s.gpa.alloc(u8, 64 * 1024);
        defer s.gpa.free(buf);
        var fr = f.spool.?.reader(buf);
        _ = try s.fs.write(f.path(), &fr.interface, f.size, "application/octet-stream");
    }

    fn attrReply(s: *Session, id: u32, a: proto.Attrs) wire.EncodeError![]const u8 {
        var w = try s.begin(T.attrs, id);
        try a.encode(&w);
        return finish(&w);
    }

    fn stat(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        var pb: [fs_mod.max_path]u8 = undefined;
        const path = s.pathArg(r, &pb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        const st = s.fs.stat(s.arena.allocator(), path) catch |e| return s.fsStatus(id, e);
        return s.attrReply(id, proto.Attrs.of(st.kind, st.size, st.mtime_ns));
    }

    fn fstat(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const h = (try s.lookup(r)) orelse return s.status(id, .failure, "invalid handle");
        switch (h[0].*) {
            .file => |*f| {
                if (f.info) |i| return s.attrReply(id, proto.Attrs.of(.file, i.size, i.created_ns));
                return s.attrReply(id, proto.Attrs.of(.file, f.size, std.time.nanoTimestamp()));
            },
            .dir => |*d| {
                const st = s.fs.stat(s.arena.allocator(), d.path()) catch |e| return s.fsStatus(id, e);
                return s.attrReply(id, proto.Attrs.of(st.kind, 0, st.mtime_ns));
            },
        }
    }

    fn fsetstat(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const h = (try s.lookup(r)) orelse return s.status(id, .failure, "invalid handle");
        const a = try proto.Attrs.decode(r);
        if (h[0].* == .file) if (h[0].file.spool) |sp| if (a.size) |size| {
            const f = &h[0].file;
            if (size > s.limits.max_file) return s.status(id, .failure, "file too large");
            sp.setEndPos(size) catch return s.status(id, .failure, "truncate failed");
            f.size = size;
            f.dirty = true;
        };
        return s.status(id, .ok, "");
    }

    // ---- directories ----

    fn opendir(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        var pb: [fs_mod.max_path]u8 = undefined;
        const path = s.pathArg(r, &pb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        const st = s.fs.stat(s.arena.allocator(), path) catch |e| return s.fsStatus(id, e);
        if (st.kind == .file) return s.fsStatus(id, error.NotDir);
        var d: Dir = .{};
        @memcpy(d.path_buf[0..path.len], path);
        d.path_len = path.len;
        const made = s.newHandle(.{ .dir = d }) catch |e| return switch (e) {
            error.TooMany => s.status(id, .failure, "too many open handles"),
            error.OutOfMemory => s.status(id, .failure, "out of memory"),
        };
        return s.handleReply(id, made[1]);
    }

    fn readdir(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const h = (try s.lookup(r)) orelse return s.status(id, .failure, "invalid handle");
        if (h[0].* != .dir) return s.status(id, .failure, "not a directory handle");
        const d = &h[0].dir;
        const arena = s.arena.allocator();
        var tries: usize = 0;
        while (!d.done and tries < 16) : (tries += 1) {
            const page = s.fs.list(arena, d.path(), d.cursor_buf[0..d.cursor_len], readdir_batch) catch |e| return s.fsStatus(id, e);
            if (page.next) |n| {
                if (n.len > d.cursor_buf.len) return s.status(id, .failure, "listing cursor too long");
                @memcpy(d.cursor_buf[0..n.len], n);
                d.cursor_len = n.len;
            } else d.done = true;
            if (page.entries.len == 0) continue;
            var w = try s.begin(T.name, id);
            try w.u32be(@intCast(page.entries.len));
            const now = std.time.timestamp();
            for (page.entries) |e| {
                const a = proto.Attrs.of(e.kind, e.size, e.mtime_ns);
                var lb: [fs_mod.max_path + 128]u8 = undefined;
                try w.string(e.name);
                try w.string(try proto.longName(&lb, e.name, a, now));
                try a.encode(&w);
            }
            return finish(&w);
        }
        if (!d.done) return s.status(id, .failure, "listing made no progress");
        return s.status(id, .eof, "");
    }

    // ---- namespace ----

    const Op = enum { remove, mkdir, rmdir };

    fn simple(s: *Session, id: u32, r: *wire.Reader, op: Op) ReqError![]const u8 {
        var pb: [fs_mod.max_path]u8 = undefined;
        const path = s.pathArg(r, &pb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        if (op == .mkdir) _ = try proto.Attrs.decode(r);
        const arena = s.arena.allocator();
        const res = switch (op) {
            .remove => s.fs.remove(arena, path),
            .mkdir => s.fs.mkdir(arena, path),
            .rmdir => s.fs.rmdir(arena, path),
        };
        res catch |e| return s.fsStatus(id, e);
        return s.status(id, .ok, "");
    }

    fn rename(s: *Session, id: u32, r: *wire.Reader, overwrite: bool) ReqError![]const u8 {
        var ab: [fs_mod.max_path]u8 = undefined;
        var bb: [fs_mod.max_path]u8 = undefined;
        const src = s.pathArg(r, &ab) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        const dst = s.pathArg(r, &bb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        const arena = s.arena.allocator();
        if (s.fs.stat(arena, dst)) |st| {
            // v3 RENAME never replaces; posix-rename replaces files only.
            if (!overwrite or st.kind != .file) return s.fsStatus(id, error.Exists);
        } else |e| if (e != error.NotFound) return s.fsStatus(id, e);
        if (std.mem.eql(u8, src, dst)) return s.status(id, .ok, "");
        s.fs.rename(arena, src, dst) catch |e| return s.fsStatus(id, e);
        return s.status(id, .ok, "");
    }

    fn realpath(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        var pb: [fs_mod.max_path]u8 = undefined;
        const path = s.pathArg(r, &pb) catch |e| return switch (e) {
            error.BadMessage => error.BadMessage,
            else => |x| s.fsStatus(id, x),
        };
        var w = try s.begin(T.name, id);
        try w.u32be(1);
        try w.string(path);
        try w.string(path);
        try w.u32be(0);
        return finish(&w);
    }

    fn extended(s: *Session, id: u32, r: *wire.Reader) ReqError![]const u8 {
        const name = try r.stringMax(256);
        if (std.mem.eql(u8, name, "posix-rename@openssh.com")) return s.rename(id, r, true);
        if (std.mem.eql(u8, name, "limits@openssh.com")) {
            var w = try s.begin(T.extended_reply, id);
            try w.u64be(proto.max_packet);
            try w.u64be(proto.max_io);
            try w.u64be(proto.max_io);
            try w.u64be(s.limits.max_handles);
            return finish(&w);
        }
        if (std.mem.eql(u8, name, "statvfs@openssh.com")) {
            var pb: [fs_mod.max_path]u8 = undefined;
            const path = s.pathArg(r, &pb) catch |e| return switch (e) {
                error.BadMessage => error.BadMessage,
                else => |x| s.fsStatus(id, x),
            };
            _ = s.fs.stat(s.arena.allocator(), path) catch |e| return s.fsStatus(id, e);
            // Object storage has no fixed capacity here; report a large free volume.
            var w = try s.begin(T.extended_reply, id);
            const blocks: u64 = 1 << 40;
            for ([_]u64{ 4096, 4096, blocks, blocks, blocks, 1 << 32, 1 << 32, 1 << 32, 0, 0, 1024 }) |v| try w.u64be(v);
            return finish(&w);
        }
        return s.status(id, .op_unsupported, "extension not supported");
    }
};

test "handles, framing and bounds without storage" {
    // Requests that never reach storage: init, unknown ops, bad handles, malformed input.
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var s = try Session.init(a, undefined, tmp.dir, .{});
    defer s.deinit();
    var rb: [64]u8 = undefined;

    var w = wire.Writer.init(&rb);
    try w.byte(T.read);
    try w.u32be(5);
    const early = s.handle(w.written());
    try std.testing.expectEqual(T.status, early[4]);

    w = wire.Writer.init(&rb);
    try w.byte(T.init);
    try w.u32be(3);
    const v = s.handle(w.written());
    try std.testing.expectEqual(T.version, v[4]);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, v[5..9], .big));
    try std.testing.expect(std.mem.indexOf(u8, v, "posix-rename@openssh.com") != null);

    w = wire.Writer.init(&rb);
    try w.byte(T.read);
    try w.u32be(9);
    try w.string("bogus-handle");
    try w.u64be(0);
    try w.u32be(10);
    const bad = s.handle(w.written());
    try std.testing.expectEqual(T.status, bad[4]);
    try std.testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, bad[5..9], .big));
    try std.testing.expectEqual(@as(u32, @intFromEnum(Status.failure)), std.mem.readInt(u32, bad[9..13], .big));

    w = wire.Writer.init(&rb);
    try w.byte(T.symlink);
    try w.u32be(10);
    try std.testing.expectEqual(@as(u32, 8), std.mem.readInt(u32, s.handle(w.written())[9..13], .big));

    w = wire.Writer.init(&rb);
    try w.byte(T.close);
    try w.u32be(11);
    try w.u32be(1 << 30);
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, s.handle(w.written())[9..13], .big));

    w = wire.Writer.init(&rb);
    try w.byte(T.realpath);
    try w.u32be(12);
    try w.string("a/../b//c/.");
    const rp = s.handle(w.written());
    try std.testing.expectEqual(T.name, rp[4]);
    try std.testing.expect(std.mem.indexOf(u8, rp, "/b/c") != null);

    try std.testing.expectEqual(T.status, s.handle("")[4]);
}
