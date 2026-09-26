//! NAS backend profile (NFS, SMB, CephFS, ...): the local on-disk layout with NAS tuning.
//! No O_DIRECT; puts are made durable by a group-commit thread (one syncfs per batch);
//! stats are served from a TTL cache; per-key fcntl byte-range locks serialize writers.
const std = @import("std");
const iface = @import("root.zig");
const local = @import("local.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const ObjectMeta = iface.ObjectMeta;
const posix = std.posix;

const io_buf_len = 256 * 1024; // larger writes amortize NAS round trips
const lock_slots = 1 << 16;
const mutex_stripes = 256;

pub const LockMode = enum {
    /// In-process striped mutexes only (single writer host).
    none,
    /// Byte-range fcntl locks on `locks/keys.lock`, honoured by NFS (NLM/v4) and SMB clients.
    fcntl,
};

pub const Profile = struct {
    /// How long the committer waits for more writers before syncing a batch.
    group_commit_window_us: u32 = 500,
    stat_ttl_ms: u32 = 1000,
    stat_cache_max: u32 = 16 * 1024,
    lock_mode: LockMode = .fcntl,
};

pub const OpenError = error{ OpenFailed, AccessDenied, OutOfMemory, ThreadFailed };

pub const PutError = Error || error{PreconditionFailed};

pub const NasBackend = struct {
    gpa: std.mem.Allocator,
    profile: Profile,
    lb: local.LocalBackend,
    lock_file: ?std.fs.File,
    stripes: [mutex_stripes]std.Thread.Mutex = @splat(.{}),

    // Group commit queue.
    mu: std.Thread.Mutex = .{},
    work: std.Thread.Condition = .{},
    done: std.Thread.Condition = .{},
    queue: ?*Commit = null,
    stopping: bool = false,
    thread: ?std.Thread = null,
    batches: u64 = 0,
    commits: u64 = 0,

    // Stat cache.
    cache_mu: std.Thread.Mutex = .{},
    cache: std.AutoHashMapUnmanaged(PhysicalKey, CacheEntry) = .empty,

    const CacheEntry = struct { meta: ObjectMeta, expires_ns: i128 };

    const Commit = struct {
        tmp: []const u8,
        final: []const u8,
        next: ?*Commit = null,
        finished: bool = false,
        err: ?Error = null,
    };

    /// Opens in place and starts the committer; `self` must not move afterwards.
    pub fn open(self: *NasBackend, gpa: std.mem.Allocator, path: []const u8, profile: Profile) OpenError!void {
        self.* = .{ .gpa = gpa, .profile = profile, .lb = try local.LocalBackend.open(path), .lock_file = null };
        errdefer self.lb.close();
        if (profile.lock_mode == .fcntl) {
            self.lb.root.makePath("locks") catch return error.OpenFailed;
            self.lock_file = self.lb.root.createFile("locks/keys.lock", .{ .read = true, .truncate = false }) catch return error.OpenFailed;
        }
        errdefer if (self.lock_file) |f| f.close();
        self.thread = std.Thread.spawn(.{}, committer, .{self}) catch return error.ThreadFailed;
    }

    pub fn close(self: *NasBackend) void {
        self.mu.lock();
        self.stopping = true;
        self.work.signal();
        self.mu.unlock();
        if (self.thread) |t| t.join();
        if (self.lock_file) |f| f.close();
        self.cache.deinit(self.gpa);
        self.lb.close();
    }

    pub fn capabilities(self: *const NasBackend) iface.Capabilities {
        return .{
            .atomic_rename = true,
            .durable_sync = true,
            .range_read = true,
            .conditional_write = self.profile.lock_mode == .fcntl,
        };
    }

    pub fn backend(self: *NasBackend) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = self.capabilities(), .vtable = &vtable };
    }

    const vtable: iface.StorageBackend.VTable = .{
        .put = put,
        .get = get,
        .stat = stat,
        .delete = delete,
        .list = list,
        .putRecord = putRecord,
        .getRecord = getRecord,
        .deleteRecord = deleteRecord,
        .sync = sync,
    };

    fn self_(ctx: *anyopaque) *NasBackend {
        return @ptrCast(@alignCast(ctx));
    }

    fn localBackend(self: *NasBackend) iface.StorageBackend {
        return self.lb.backend();
    }

    // ---- locking ----

    pub const KeyLock = struct {
        nas: *NasBackend,
        slot: u32,

        pub fn release(l: KeyLock) void {
            if (l.nas.lock_file) |f| fcntlLock(f, l.slot, posix.F.UNLCK) catch {};
            l.nas.stripes[l.slot % mutex_stripes].unlock();
        }
    };

    fn slotOf(key: PhysicalKey) u32 {
        var h = std.hash.Wyhash.init(@intFromEnum(key.space));
        h.update(&key.hex);
        return @intCast(h.final() % lock_slots);
    }

    /// Exclusive per-key lock: an in-process stripe, then a 1-byte fcntl range lock.
    pub fn lockKey(self: *NasBackend, key: PhysicalKey) Error!KeyLock {
        const slot = slotOf(key);
        self.stripes[slot % mutex_stripes].lock();
        if (self.lock_file) |f| fcntlLock(f, slot, posix.F.WRLCK) catch {
            self.stripes[slot % mutex_stripes].unlock();
            return error.IoFailed;
        };
        return .{ .nas = self, .slot = slot };
    }

    fn fcntlLock(f: std.fs.File, slot: u32, kind: i16) posix.FcntlError!void {
        var fl = std.mem.zeroes(posix.Flock);
        fl.type = kind;
        fl.whence = posix.SEEK.SET;
        fl.start = slot;
        fl.len = 1;
        _ = try posix.fcntl(f.handle, posix.F.SETLKW, @intFromPtr(&fl));
    }

    // ---- stat cache ----

    fn cacheGet(self: *NasBackend, key: PhysicalKey) ?ObjectMeta {
        self.cache_mu.lock();
        defer self.cache_mu.unlock();
        const e = self.cache.get(key) orelse return null;
        if (std.time.nanoTimestamp() >= e.expires_ns) {
            _ = self.cache.remove(key);
            return null;
        }
        return e.meta;
    }

    fn cachePut(self: *NasBackend, key: PhysicalKey, meta: ObjectMeta) void {
        if (self.profile.stat_ttl_ms == 0) return;
        self.cache_mu.lock();
        defer self.cache_mu.unlock();
        if (self.cache.count() >= self.profile.stat_cache_max) self.cache.clearRetainingCapacity();
        const exp = std.time.nanoTimestamp() + @as(i128, self.profile.stat_ttl_ms) * std.time.ns_per_ms;
        self.cache.put(self.gpa, key, .{ .meta = meta, .expires_ns = exp }) catch {}; // cache is best-effort
    }

    fn cacheDrop(self: *NasBackend, key: PhysicalKey) void {
        self.cache_mu.lock();
        defer self.cache_mu.unlock();
        _ = self.cache.remove(key);
    }

    // ---- group commit ----

    fn committer(self: *NasBackend) void {
        while (true) {
            self.mu.lock();
            while (self.queue == null and !self.stopping) self.work.wait(&self.mu);
            if (self.queue == null and self.stopping) {
                self.mu.unlock();
                return;
            }
            if (self.profile.group_commit_window_us > 0 and !self.stopping) {
                self.mu.unlock();
                std.Thread.sleep(@as(u64, self.profile.group_commit_window_us) * std.time.ns_per_us);
                self.mu.lock();
            }
            var batch = self.queue;
            self.queue = null;
            self.mu.unlock();

            // Data durable before names become visible, and names durable before ack.
            const data_err = self.syncRoot();
            var n: u64 = 0;
            var it = batch;
            while (it) |c| : (it = c.next) {
                n += 1;
                c.err = data_err orelse self.rename(c.tmp, c.final);
            }
            const meta_err = self.syncRoot();

            self.mu.lock();
            self.batches += 1;
            self.commits += n;
            while (batch) |c| {
                batch = c.next;
                if (c.err == null) c.err = meta_err;
                c.finished = true;
            }
            self.done.broadcast();
            self.mu.unlock();
        }
    }

    fn syncRoot(self: *NasBackend) ?Error {
        posix.syncfs(self.lb.root.fd) catch return error.IoFailed;
        return null;
    }

    fn rename(self: *NasBackend, tmp: []const u8, final: []const u8) ?Error {
        const dir = std.fs.path.dirname(final) orelse ".";
        self.lb.root.makePath(dir) catch |e| return mapFs(e);
        self.lb.root.rename(tmp, final) catch |e| return mapFs(e);
        return null;
    }

    fn submit(self: *NasBackend, tmp: []const u8, final: []const u8) Error!void {
        var c: Commit = .{ .tmp = tmp, .final = final };
        self.mu.lock();
        defer self.mu.unlock();
        c.next = self.queue;
        self.queue = &c;
        self.work.signal();
        while (!c.finished) self.done.wait(&self.mu);
        if (c.err) |e| return e;
    }

    pub const Stats = struct { batches: u64, commits: u64 };

    pub fn stats(self: *NasBackend) Stats {
        self.mu.lock();
        defer self.mu.unlock();
        return .{ .batches = self.batches, .commits = self.commits };
    }

    // ---- operations ----

    /// Writes to tmp without fsync, then commits through the group-commit thread.
    fn write(self: *NasBackend, key: PhysicalKey, source: *std.Io.Reader, if_absent: bool) PutError!ObjectMeta {
        var path_buf: [64]u8 = undefined;
        const final = try local.keyPath(key, &path_buf);
        var tmp_buf: [48]u8 = undefined;
        const tmp = tempPath(&tmp_buf);
        var file = self.lb.root.createFile(tmp, .{ .exclusive = true }) catch |e| return mapFs(e);
        var committed = false;
        defer if (!committed) self.lb.root.deleteFile(tmp) catch {};
        {
            defer file.close();
            const wbuf = try self.gpa.alloc(u8, io_buf_len);
            defer self.gpa.free(wbuf);
            var fw = file.writer(wbuf);
            _ = source.streamRemaining(&fw.interface) catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
                error.WriteFailed => return mapFs(fw.err orelse error.Unexpected),
            };
            fw.interface.flush() catch return mapFs(fw.err orelse error.Unexpected);
        }
        const lock = try self.lockKey(key);
        defer lock.release();
        if (if_absent) {
            if (self.lb.root.statFile(final)) |_| return error.PreconditionFailed else |e| switch (e) {
                error.FileNotFound => {},
                else => return mapFs(e),
            }
        }
        try self.submit(tmp, final);
        committed = true;
        const st = self.lb.root.statFile(final) catch |e| return mapFs(e);
        const meta: ObjectMeta = .{ .size = st.size, .mtime_ns = st.mtime };
        self.cachePut(key, meta);
        return meta;
    }

    /// Create-only put; needs `lock_mode = .fcntl` to hold across NAS clients.
    pub fn putIfAbsent(self: *NasBackend, key: PhysicalKey, source: *std.Io.Reader) PutError!ObjectMeta {
        return self.write(key, source, true);
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!ObjectMeta {
        _ = opts;
        return self_(ctx).write(key, source, false) catch |e| switch (e) {
            error.PreconditionFailed => error.IoFailed, // not requested
            else => |x| x,
        };
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?iface.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const self = self_(ctx);
        const m = try self.localBackend().get(key, range, sink);
        self.cachePut(key, m);
        return m;
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta {
        const self = self_(ctx);
        if (self.cacheGet(key)) |m| return m;
        const m = try self.localBackend().stat(key);
        self.cachePut(key, m);
        return m;
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        const self = self_(ctx);
        const lock = try self.lockKey(key);
        defer lock.release();
        self.cacheDrop(key);
        return self.localBackend().delete(key);
    }

    fn list(ctx: *anyopaque, space: iface.KeySpace, cb: iface.ListCallback) Error!void {
        return self_(ctx).localBackend().list(space, cb);
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        if (key.space == .data) return error.InvalidKey;
        var src: std.Io.Reader = .fixed(bytes);
        _ = try put(ctx, key, &src, .{});
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        return self_(ctx).localBackend().getRecord(key, gpa);
    }

    fn deleteRecord(ctx: *anyopaque, key: PhysicalKey) Error!void {
        if (key.space == .data) return error.InvalidKey;
        return delete(ctx, key);
    }

    fn sync(ctx: *anyopaque) Error!void {
        if (self_(ctx).syncRoot()) |e| return e;
    }
};

fn tempPath(buf: *[48]u8) []const u8 {
    var r: [16]u8 = undefined;
    std.crypto.random.bytes(&r);
    return std.fmt.bufPrint(buf, "tmp/{s}.tmp", .{std.fmt.bytesToHex(r, .lower)}) catch unreachable; // fixed width
}

fn mapFs(e: anyerror) Error {
    return switch (e) {
        error.FileNotFound, error.NotDir => error.NotFound,
        error.NoSpaceLeft, error.DiskQuota => error.NoSpace,
        error.OutOfMemory => error.OutOfMemory,
        else => error.IoFailed,
    };
}

fn openTmp(tmp: *std.testing.TmpDir, nas: *NasBackend, profile: Profile) !void {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &pbuf);
    try nas.open(std.testing.allocator, root, profile);
}

test "nas backend put, get, stat cache, list, delete" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var nas: NasBackend = undefined;
    try openTmp(&tmp, &nas, .{ .stat_ttl_ms = 60_000 });
    defer nas.close();
    const b = nas.backend();
    try std.testing.expect(!b.capabilities.direct_io);
    try std.testing.expect(b.capabilities.conditional_write);

    const key: PhysicalKey = .{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* };
    var src: std.Io.Reader = .fixed("0123456789");
    try std.testing.expectEqual(@as(u64, 10), (try b.put(key, &src, .{})).size);
    try std.testing.expect(nas.stats().commits == 1);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try b.get(key, .{ .offset = 3, .length = 4 }, &out.writer);
    try std.testing.expectEqualStrings("3456", out.written());

    // Served from cache even after an out-of-band change (as another NAS client might make).
    try tmp.dir.writeFile(.{ .sub_path = "data/00/11/00112233445566778899aabbccddeeff", .data = "xy" });
    try std.testing.expectEqual(@as(u64, 10), (try b.stat(key)).size);
    nas.cacheDrop(key);
    try std.testing.expectEqual(@as(u64, 2), (try b.stat(key)).size);

    var again: std.Io.Reader = .fixed("z");
    try std.testing.expectError(error.PreconditionFailed, nas.putIfAbsent(key, &again));

    const Counter = struct {
        n: usize = 0,
        fn f(ctx: *anyopaque, _: PhysicalKey) Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.n += 1;
        }
    };
    var c: Counter = .{};
    try b.list(.data, .{ .ctx = &c, .func = Counter.f });
    try std.testing.expectEqual(@as(usize, 1), c.n);

    try b.delete(key);
    try std.testing.expectError(error.NotFound, b.stat(key));

    const rk: PhysicalKey = .{ .space = .record, .hex = key.hex };
    try b.putRecord(rk, "rec");
    const got = try b.getRecord(rk, std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("rec", got);
    try b.deleteRecord(rk);
    try b.sync();
}

test "stat cache entries expire after the TTL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var nas: NasBackend = undefined;
    try openTmp(&tmp, &nas, .{ .stat_ttl_ms = 20 });
    defer nas.close();
    const b = nas.backend();
    const key: PhysicalKey = .{ .space = .data, .hex = "ffeeddccbbaa99887766554433221100".* };
    var src: std.Io.Reader = .fixed("abc");
    _ = try b.put(key, &src, .{});
    try tmp.dir.writeFile(.{ .sub_path = "data/ff/ee/ffeeddccbbaa99887766554433221100", .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 3), (try b.stat(key)).size);
    std.Thread.sleep(40 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u64, 6), (try b.stat(key)).size);
}

test "concurrent puts are group-committed in batches" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var nas: NasBackend = undefined;
    try openTmp(&tmp, &nas, .{ .group_commit_window_us = 5000 });
    defer nas.close();
    const n_threads = 16;
    const Worker = struct {
        fn run(n: *NasBackend, i: usize, fail: *std.atomic.Value(bool)) void {
            var key: PhysicalKey = .{ .space = .data, .hex = "a0000000000000000000000000000000".* };
            key.hex[30] = "0123456789abcdef"[i / 16];
            key.hex[31] = "0123456789abcdef"[i % 16];
            var src: std.Io.Reader = .fixed("payload");
            _ = n.backend().put(key, &src, .{}) catch fail.store(true, .monotonic);
        }
    };
    var fail: std.atomic.Value(bool) = .init(false);
    var threads: [n_threads]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &nas, i, &fail });
    for (threads) |t| t.join();
    try std.testing.expect(!fail.load(.monotonic));
    const s = nas.stats();
    try std.testing.expectEqual(@as(u64, n_threads), s.commits);
    try std.testing.expect(s.batches < n_threads);
}

test "fcntl key locks exclude other processes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var nas: NasBackend = undefined;
    try openTmp(&tmp, &nas, .{});
    defer nas.close();
    const key: PhysicalKey = .{ .space = .data, .hex = "0123456789abcdef0123456789abcdef".* };
    const lock = try nas.lockKey(key);
    // A second open file description in another process conflicts; F_GETLK reports it.
    const pid = try posix.fork();
    if (pid == 0) {
        const f = tmp.dir.openFile("locks/keys.lock", .{ .mode = .read_write }) catch posix.exit(2);
        var fl = std.mem.zeroes(posix.Flock);
        fl.type = posix.F.WRLCK;
        fl.whence = posix.SEEK.SET;
        fl.start = NasBackend.slotOf(key);
        fl.len = 1;
        _ = posix.fcntl(f.handle, posix.F.SETLK, @intFromPtr(&fl)) catch |e| posix.exit(if (e == error.Locked) 0 else 3);
        posix.exit(1);
    }
    const res = posix.waitpid(pid, 0);
    lock.release();
    try std.testing.expectEqual(@as(u32, 0), posix.W.EXITSTATUS(res.status));
}
