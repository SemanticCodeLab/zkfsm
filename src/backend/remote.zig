//! Provider-neutral RemoteObjectBackend: maps PhysicalKeys onto object names and
//! implements StorageBackend over any Provider (S3, GCS interop, Azure Blob).
const std = @import("std");
const iface = @import("root.zig");
const local = @import("local.zig");

const Error = iface.Error;
const PhysicalKey = iface.PhysicalKey;
const ObjectMeta = iface.ObjectMeta;

pub const max_record_len = 16 * 1024 * 1024;

pub const PutObjectOptions = struct {
    size_hint: ?u64 = null,
    /// Fail with PreconditionFailed if the object already exists.
    if_absent: bool = false,
};

pub const PutError = Error || error{PreconditionFailed};

pub const NameCallback = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, name: []const u8) Error!void,
};

/// One remote object store. Names are full object keys (backend prefix included).
pub const Provider = struct {
    ctx: *anyopaque,
    capabilities: iface.Capabilities,
    vtable: *const VTable,

    pub const VTable = struct {
        put: *const fn (ctx: *anyopaque, name: []const u8, source: *std.Io.Reader, opts: PutObjectOptions) PutError!ObjectMeta,
        get: *const fn (ctx: *anyopaque, name: []const u8, range: ?iface.Range, sink: *std.Io.Writer) Error!ObjectMeta,
        head: *const fn (ctx: *anyopaque, name: []const u8) Error!ObjectMeta,
        delete: *const fn (ctx: *anyopaque, name: []const u8) Error!void,
        /// Every name starting with `prefix`; pagination is the provider's job.
        list: *const fn (ctx: *anyopaque, prefix: []const u8, cb: NameCallback) Error!void,
    };
};

pub const RemoteObjectBackend = struct {
    provider: Provider,
    /// Borrowed; either empty or ending in '/'.
    prefix: []const u8,

    pub fn init(provider: Provider, prefix: []const u8) RemoteObjectBackend {
        return .{ .provider = provider, .prefix = prefix };
    }

    pub fn backend(self: *RemoteObjectBackend) iface.StorageBackend {
        return .{ .ctx = self, .capabilities = self.provider.capabilities, .vtable = &vtable };
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

    const name_max = 1024 + 64;

    fn name(self: *const RemoteObjectBackend, key: PhysicalKey, buf: *[name_max]u8) Error![]const u8 {
        var kb: [64]u8 = undefined;
        const rel = try local.keyPath(key, &kb);
        return std.fmt.bufPrint(buf, "{s}{s}", .{ self.prefix, rel }) catch error.InvalidKey;
    }

    fn self_(ctx: *anyopaque) *RemoteObjectBackend {
        return @ptrCast(@alignCast(ctx));
    }

    /// Create-only put; needs `capabilities.conditional_write`.
    pub fn putIfAbsent(self: *RemoteObjectBackend, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) PutError!ObjectMeta {
        var nb: [name_max]u8 = undefined;
        const n = try self.name(key, &nb);
        return self.provider.vtable.put(self.provider.ctx, n, source, .{ .size_hint = opts.size_hint, .if_absent = true });
    }

    fn put(ctx: *anyopaque, key: PhysicalKey, source: *std.Io.Reader, opts: iface.PutOptions) Error!ObjectMeta {
        const self = self_(ctx);
        var nb: [name_max]u8 = undefined;
        const n = try self.name(key, &nb);
        return self.provider.vtable.put(self.provider.ctx, n, source, .{ .size_hint = opts.size_hint }) catch |e| switch (e) {
            error.PreconditionFailed => error.IoFailed, // not requested; server misbehaved
            else => |x| x,
        };
    }

    fn get(ctx: *anyopaque, key: PhysicalKey, range: ?iface.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const self = self_(ctx);
        var nb: [name_max]u8 = undefined;
        return self.provider.vtable.get(self.provider.ctx, try self.name(key, &nb), range, sink);
    }

    fn stat(ctx: *anyopaque, key: PhysicalKey) Error!ObjectMeta {
        const self = self_(ctx);
        var nb: [name_max]u8 = undefined;
        return self.provider.vtable.head(self.provider.ctx, try self.name(key, &nb));
    }

    fn delete(ctx: *anyopaque, key: PhysicalKey) Error!void {
        const self = self_(ctx);
        var nb: [name_max]u8 = undefined;
        return self.provider.vtable.delete(self.provider.ctx, try self.name(key, &nb));
    }

    const ListCtx = struct {
        prefix_len: usize,
        space: iface.KeySpace,
        cb: iface.ListCallback,

        fn onName(ctx: *anyopaque, full: []const u8) Error!void {
            const lc: *ListCtx = @ptrCast(@alignCast(ctx));
            if (full.len < lc.prefix_len) return;
            const key = parseRel(full[lc.prefix_len..], lc.space) orelse return;
            try lc.cb.func(lc.cb.ctx, key);
        }
    };

    fn list(ctx: *anyopaque, space: iface.KeySpace, cb: iface.ListCallback) Error!void {
        const self = self_(ctx);
        var pb: [name_max]u8 = undefined;
        const p = std.fmt.bufPrint(&pb, "{s}{s}/", .{ self.prefix, @tagName(space) }) catch return error.InvalidKey;
        var lc: ListCtx = .{ .prefix_len = self.prefix.len, .space = space, .cb = cb };
        return self.provider.vtable.list(self.provider.ctx, p, .{ .ctx = &lc, .func = ListCtx.onName });
    }

    fn putRecord(ctx: *anyopaque, key: PhysicalKey, bytes: []const u8) Error!void {
        if (key.space == .data) return error.InvalidKey;
        var src: std.Io.Reader = .fixed(bytes);
        _ = try put(ctx, key, &src, .{ .size_hint = bytes.len });
    }

    fn getRecord(ctx: *anyopaque, key: PhysicalKey, gpa: std.mem.Allocator) Error![]u8 {
        if (key.space == .data) return error.InvalidKey;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        var lim_buf: [256]u8 = undefined;
        var lim = LimitWriter.init(&out.writer, max_record_len, &lim_buf);
        _ = get(ctx, key, null, &lim.writer) catch |e| switch (e) {
            error.WriteFailed => return if (lim.overflow) error.TooLarge else error.OutOfMemory,
            else => |x| return x,
        };
        lim.writer.flush() catch return if (lim.overflow) error.TooLarge else error.OutOfMemory;
        return out.toOwnedSlice() catch error.OutOfMemory;
    }

    fn deleteRecord(ctx: *anyopaque, key: PhysicalKey) Error!void {
        if (key.space == .data) return error.InvalidKey;
        return delete(ctx, key);
    }

    /// Acknowledged remote writes are already durable.
    fn sync(_: *anyopaque) Error!void {}
};

/// Inverse of `local.keyPath`; rejects anything that does not round-trip.
pub fn parseRel(rel: []const u8, space: iface.KeySpace) ?PhysicalKey {
    const hex_start: usize = switch (space) {
        .data, .record => @tagName(space).len + 7, // "<space>/ab/cd/"
        .system => "system/".len,
    };
    if (rel.len < hex_start + 32) return null;
    const key: PhysicalKey = .{ .space = space, .hex = rel[hex_start..][0..32].* };
    var buf: [64]u8 = undefined;
    const want = local.keyPath(key, &buf) catch return null;
    return if (std.mem.eql(u8, want, rel)) key else null;
}

/// Forwards at most `limit` bytes, then fails with WriteFailed and sets `overflow`.
const LimitWriter = struct {
    out: *std.Io.Writer,
    left: usize,
    overflow: bool = false,
    writer: std.Io.Writer,

    fn init(out: *std.Io.Writer, limit: usize, buf: []u8) LimitWriter {
        return .{ .out = out, .left = limit, .writer = .{ .buffer = buf, .vtable = &.{ .drain = drain } } };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *LimitWriter = @alignCast(@fieldParentPtr("writer", w));
        try self.pass(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.pass(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.pass(last);
        return n + last.len * splat;
    }

    fn pass(self: *LimitWriter, bytes: []const u8) std.Io.Writer.Error!void {
        if (bytes.len > self.left) {
            self.overflow = true;
            return error.WriteFailed;
        }
        self.left -= bytes.len;
        try self.out.writeAll(bytes);
    }
};

/// In-memory Provider used to test the key mapping without a network.
const MemProvider = struct {
    gpa: std.mem.Allocator,
    objects: std.StringHashMapUnmanaged([]u8) = .empty,

    fn deinit(m: *MemProvider) void {
        var it = m.objects.iterator();
        while (it.next()) |e| {
            m.gpa.free(e.key_ptr.*);
            m.gpa.free(e.value_ptr.*);
        }
        m.objects.deinit(m.gpa);
    }

    fn provider(m: *MemProvider) Provider {
        return .{ .ctx = m, .capabilities = .{ .range_read = true, .conditional_write = true }, .vtable = &.{
            .put = mput,
            .get = mget,
            .head = mhead,
            .delete = mdelete,
            .list = mlist,
        } };
    }

    fn from(ctx: *anyopaque) *MemProvider {
        return @ptrCast(@alignCast(ctx));
    }

    fn mput(ctx: *anyopaque, n: []const u8, src: *std.Io.Reader, opts: PutObjectOptions) PutError!ObjectMeta {
        const m = from(ctx);
        if (opts.if_absent and m.objects.contains(n)) return error.PreconditionFailed;
        const data = src.allocRemaining(m.gpa, .unlimited) catch return error.ReadFailed;
        const gop = m.objects.getOrPut(m.gpa, n) catch return error.OutOfMemory;
        if (gop.found_existing) m.gpa.free(gop.value_ptr.*) else gop.key_ptr.* = m.gpa.dupe(u8, n) catch return error.OutOfMemory;
        gop.value_ptr.* = data;
        return .{ .size = data.len, .mtime_ns = 0 };
    }

    fn mget(ctx: *anyopaque, n: []const u8, range: ?iface.Range, sink: *std.Io.Writer) Error!ObjectMeta {
        const d = from(ctx).objects.get(n) orelse return error.NotFound;
        const r = range orelse iface.Range{ .offset = 0, .length = d.len };
        if (r.offset + r.length > d.len) return error.IoFailed;
        sink.writeAll(d[r.offset..][0..r.length]) catch return error.WriteFailed;
        return .{ .size = d.len, .mtime_ns = 0 };
    }

    fn mhead(ctx: *anyopaque, n: []const u8) Error!ObjectMeta {
        const d = from(ctx).objects.get(n) orelse return error.NotFound;
        return .{ .size = d.len, .mtime_ns = 0 };
    }

    fn mdelete(ctx: *anyopaque, n: []const u8) Error!void {
        const m = from(ctx);
        const kv = m.objects.fetchRemove(n) orelse return error.NotFound;
        m.gpa.free(kv.key);
        m.gpa.free(kv.value);
    }

    fn mlist(ctx: *anyopaque, prefix: []const u8, cb: NameCallback) Error!void {
        var it = from(ctx).objects.keyIterator();
        while (it.next()) |k| if (std.mem.startsWith(u8, k.*, prefix)) try cb.func(cb.ctx, k.*);
    }
};

test "remote backend maps keys under prefix and round-trips list" {
    var mem: MemProvider = .{ .gpa = std.testing.allocator };
    defer mem.deinit();
    var rb = RemoteObjectBackend.init(mem.provider(), "tenant/");
    const b = rb.backend();
    const key: PhysicalKey = .{ .space = .data, .hex = "00112233445566778899aabbccddeeff".* };
    var src: std.Io.Reader = .fixed("0123456789");
    _ = try b.put(key, &src, .{});
    try std.testing.expect(mem.objects.contains("tenant/data/00/11/00112233445566778899aabbccddeeff"));

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    _ = try b.get(key, .{ .offset = 2, .length = 3 }, &out.writer);
    try std.testing.expectEqualStrings("234", out.written());

    const rk: PhysicalKey = .{ .space = .system, .hex = key.hex };
    try b.putRecord(rk, "sys");
    const got = try b.getRecord(rk, std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("sys", got);

    const Counter = struct {
        n: usize = 0,
        fn f(ctx: *anyopaque, k: PhysicalKey) Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (k.space == .data) c.n += 1;
        }
    };
    var c: Counter = .{};
    try b.list(.data, .{ .ctx = &c, .func = Counter.f });
    try std.testing.expectEqual(@as(usize, 1), c.n);

    var again: std.Io.Reader = .fixed("x");
    try std.testing.expectError(error.PreconditionFailed, rb.putIfAbsent(key, &again, .{}));
    try b.delete(key);
    try std.testing.expectError(error.NotFound, b.stat(key));
    try std.testing.expectError(error.InvalidKey, b.putRecord(key, "x"));
}

test "parseRel rejects foreign names" {
    try std.testing.expect(parseRel("data/00/11/00112233445566778899aabbccddeeff", .data) != null);
    try std.testing.expect(parseRel("data/ff/11/00112233445566778899aabbccddeeff", .data) == null);
    try std.testing.expect(parseRel("record/00/11/00112233445566778899aabbccddeeff.meta", .record) != null);
    try std.testing.expect(parseRel("system/00112233445566778899aabbccddeeff.meta", .system) != null);
    try std.testing.expect(parseRel("junk", .system) == null);
}
