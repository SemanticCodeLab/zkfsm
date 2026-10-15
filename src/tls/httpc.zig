//! Streaming HTTP/1.1 client over `dial.zig`: keep-alive pool, bounded heads,
//! Content-Length and chunked bodies both ways. A failed exchange closes its connection.
const std = @import("std");
const dial = @import("dial.zig");

pub const Method = std.http.Method;
pub const Header = std.http.Header;

pub const Error = error{ OutOfMemory, InvalidArgument, ConnectFailed, TlsFailed, InvalidResponse, ResponseTooLarge, SourceFailed };

pub const max_head = 16 << 10;
pub const max_headers = 100;
/// Unread response bytes drained so a connection can be reused; more closes it.
const drain_budget = 256 << 10;

/// Where a request goes: dial host (no brackets), port, and TLS settings when https.
pub const Target = struct {
    host: []const u8,
    port: u16,
    tls: ?dial.TlsOptions = null,
};

pub const Options = struct {
    connect_timeout_ms: u32 = 5000,
    io_timeout_ms: u32 = 60_000,
    max_idle: u16 = 32,
    idle_timeout_ms: u32 = 30_000,
};

/// Writes an upload body: exactly `len` bytes, or a chunked body when `len` is null.
pub const Stream = struct {
    len: ?u64,
    ctx: *anyopaque,
    write: *const fn (ctx: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void,
};

pub const Body = union(enum) { none, bytes: []const u8, stream: Stream };

pub const Request = struct {
    method: Method,
    /// Origin-form target ("/path?query"), already percent-encoded.
    target: []const u8,
    /// Host header value.
    host: []const u8,
    headers: []const Header = &.{},
    body: Body = .none,
    user_agent: []const u8 = "zkfsm",
};

/// Keep-alive connections keyed by host, port and TLS settings. Thread-safe.
pub const Pool = struct {
    gpa: std.mem.Allocator,
    opts: Options = .{},
    mutex: std.Thread.Mutex = .{},
    idle: std.ArrayList(Idle) = .empty,

    const Idle = struct { key: []u8, conn: *dial.Conn, since_ms: i64 };

    pub fn init(gpa: std.mem.Allocator, opts: Options) Pool {
        return .{ .gpa = gpa, .opts = opts };
    }

    pub fn deinit(p: *Pool) void {
        for (p.idle.items) |it| {
            it.conn.close();
            p.gpa.free(it.key);
        }
        p.idle.deinit(p.gpa);
        p.* = undefined;
    }

    fn keyOf(gpa: std.mem.Allocator, t: Target) error{OutOfMemory}![]u8 {
        const o = t.tls orelse return std.fmt.allocPrint(gpa, "h\x00{s}\x00{d}", .{ t.host, t.port });
        return std.fmt.allocPrint(gpa, "s\x00{s}\x00{d}\x00{d}\x00{s}\x00{s}\x00{s}\x00{s}\x00{t}", .{
            t.host, t.port, @intFromBool(o.skip_verify), o.ca_file, o.server_name, o.client_cert_file, o.client_key_file, o.min_version,
        });
    }

    /// An idle live connection for `key`, else null.
    fn take(p: *Pool, key: []const u8) ?*dial.Conn {
        const now = std.time.milliTimestamp();
        p.mutex.lock();
        defer p.mutex.unlock();
        var i = p.idle.items.len;
        while (i > 0) {
            i -= 1;
            const it = p.idle.items[i];
            const stale = now - it.since_ms > p.opts.idle_timeout_ms;
            if (!stale and !std.mem.eql(u8, it.key, key)) continue;
            _ = p.idle.orderedRemove(i);
            p.gpa.free(it.key);
            if (stale or !alive(it.conn)) {
                it.conn.close();
                continue;
            }
            return it.conn;
        }
        return null;
    }

    fn put(p: *Pool, key: []const u8, c: *dial.Conn) void {
        const k = p.gpa.dupe(u8, key) catch return c.close();
        p.mutex.lock();
        defer p.mutex.unlock();
        if (p.idle.items.len >= p.opts.max_idle) {
            const old = p.idle.orderedRemove(0);
            old.conn.close();
            p.gpa.free(old.key);
        }
        p.idle.append(p.gpa, .{ .key = k, .conn = c, .since_ms = std.time.milliTimestamp() }) catch {
            p.gpa.free(k);
            c.close();
        };
    }
};

/// An idle connection is reusable only if nothing (data, EOF, error) is pending on it.
fn alive(c: *dial.Conn) bool {
    if (c.reader().bufferedLen() > 0) return false;
    var pfd = [_]std.posix.pollfd{.{ .fd = c.stream.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&pfd, 0) catch return false;
    return n == 0;
}

const Framing = enum { none, length, chunked, eof };
const ChunkState = enum { size, data, crlf, done };

/// One request/response. Must stay at a stable address between `start` and `deinit`.
pub const Exchange = struct {
    pool: *Pool,
    conn: ?*dial.Conn = null,
    key: []u8 = &.{},
    status: u16 = 0,
    content_length: ?u64 = null,
    keep_alive: bool = true,
    failed: bool = false,
    framing: Framing = .none,
    remaining: u64 = 0,
    chunk: ChunkState = .size,
    head_buf: [max_head]u8 = undefined,
    head_len: usize = 0,
    hdrs: [max_headers]Header = undefined,
    n_hdrs: usize = 0,
    reader: std.Io.Reader = undefined,

    /// Sends the request and reads the response head. On success call `deinit`.
    /// A reused connection that turns out dead is replaced once when the request is replayable.
    pub fn start(x: *Exchange, pool: *Pool, t: Target, r: Request) Error!void {
        x.* = .{ .pool = pool };
        try validate(r);
        x.key = try Pool.keyOf(pool.gpa, t);
        errdefer pool.gpa.free(x.key);
        const replayable = r.body != .stream and r.method.idempotent();
        var fresh_only = false;
        while (true) {
            var reused = false;
            const c = blk: {
                if (!fresh_only) if (pool.take(x.key)) |c| {
                    reused = true;
                    break :blk c;
                };
                break :blk dial.dial(pool.gpa, t.host, t.port, .{
                    .connect_timeout_ms = pool.opts.connect_timeout_ms,
                    .io_timeout_ms = pool.opts.io_timeout_ms,
                    .tls = t.tls,
                }) catch |e| return switch (e) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.TlsFailed => error.TlsFailed,
                    error.ConnectFailed => error.ConnectFailed,
                };
            };
            x.conn = c;
            x.exchange(c, r) catch |e| {
                x.conn = null;
                c.close();
                if (reused and replayable and e == error.ConnectFailed) {
                    fresh_only = true;
                    continue;
                }
                return e;
            };
            x.reader = .{ .vtable = &body_vtable, .buffer = &.{}, .seek = 0, .end = 0 };
            return;
        }
    }

    fn validate(r: Request) Error!void {
        if (std.mem.indexOfAny(u8, r.target, "\r\n ") != null or r.target.len == 0) return error.InvalidArgument;
        if (std.mem.indexOfAny(u8, r.host, "\r\n ") != null) return error.InvalidArgument;
        for (r.headers) |h| {
            if (std.mem.indexOfAny(u8, h.value, "\r\n") != null or h.name.len == 0 or std.mem.indexOfAny(u8, h.name, "\r\n: ") != null) return error.InvalidArgument;
        }
    }

    fn exchange(x: *Exchange, c: *dial.Conn, r: Request) Error!void {
        const w = c.writer();
        writeHead(w, r) catch return error.ConnectFailed;
        switch (r.body) {
            .none => {},
            .bytes => |b| w.writeAll(b) catch return error.ConnectFailed,
            .stream => |s| try sendStream(w, s),
        }
        c.flush() catch return error.ConnectFailed;
        try x.readHead(c.reader(), r.method);
    }

    fn sendStream(w: *std.Io.Writer, s: Stream) Error!void {
        if (s.len) |len| {
            var cw: Counting = .{ .inner = w, .left = len };
            s.write(s.ctx, &cw.writer) catch |e| return if (e == error.SourceFailed or cw.over) error.SourceFailed else error.ConnectFailed;
            if (cw.left != 0) return error.SourceFailed;
            return;
        }
        var buf: [32 << 10]u8 = undefined;
        var cw: Chunked = .{ .inner = w, .writer = .{ .buffer = &buf, .vtable = &.{ .drain = Chunked.drain } } };
        s.write(s.ctx, &cw.writer) catch |e| return if (e == error.SourceFailed) error.SourceFailed else error.ConnectFailed;
        cw.writer.flush() catch return error.ConnectFailed;
        w.writeAll("0\r\n\r\n") catch return error.ConnectFailed;
    }

    fn line(x: *Exchange, rd: *std.Io.Reader) Error![]const u8 {
        const l = rd.takeDelimiterInclusive('\n') catch |e| return switch (e) {
            error.StreamTooLong => error.ResponseTooLarge,
            error.ReadFailed, error.EndOfStream => error.ConnectFailed,
        };
        const v = std.mem.trimRight(u8, l, "\r\n");
        if (v.len > max_head - x.head_len) return error.ResponseTooLarge;
        const dst = x.head_buf[x.head_len..][0..v.len];
        @memcpy(dst, v);
        x.head_len += v.len;
        return dst;
    }

    fn readHead(x: *Exchange, rd: *std.Io.Reader, method: Method) Error!void {
        while (true) {
            x.head_len = 0;
            x.n_hdrs = 0;
            x.content_length = null;
            x.keep_alive = true;
            var chunked = false;
            const sl = try x.line(rd);
            if (sl.len < 12 or !std.mem.startsWith(u8, sl, "HTTP/1.") or sl[8] != ' ') return error.InvalidResponse;
            if (sl[7] == '0') x.keep_alive = false;
            x.status = std.fmt.parseInt(u16, sl[9..12], 10) catch return error.InvalidResponse;
            if (x.status < 100 or x.status > 999) return error.InvalidResponse;
            while (true) {
                const h = try x.line(rd);
                if (h.len == 0) break;
                if (x.n_hdrs == max_headers) return error.ResponseTooLarge;
                const colon = std.mem.indexOfScalar(u8, h, ':') orelse return error.InvalidResponse;
                const name = h[0..colon];
                const value = std.mem.trim(u8, h[colon + 1 ..], " \t");
                x.hdrs[x.n_hdrs] = .{ .name = name, .value = value };
                x.n_hdrs += 1;
                if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                    const v = std.fmt.parseInt(u64, value, 10) catch return error.InvalidResponse;
                    if (x.content_length != null and x.content_length.? != v) return error.InvalidResponse;
                    x.content_length = v;
                } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                    if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.InvalidResponse;
                    chunked = true;
                } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                    if (std.ascii.indexOfIgnoreCase(value, "close") != null) x.keep_alive = false;
                }
            }
            if (x.status < 200) continue;
            const bodiless = method == .HEAD or x.status == 204 or x.status == 304;
            if (bodiless) {
                x.framing = .none;
            } else if (chunked) {
                x.framing = .chunked;
                x.content_length = null;
            } else if (x.content_length) |n| {
                x.framing = .length;
                x.remaining = n;
            } else {
                x.framing = .eof;
                x.keep_alive = false;
            }
            return;
        }
    }

    pub fn headers(x: *const Exchange) []const Header {
        return x.hdrs[0..x.n_hdrs];
    }

    pub fn header(x: *const Exchange, name: []const u8) ?[]const u8 {
        for (x.headers()) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    /// Body stream over `transfer_buf` (may be empty); call at most once.
    pub fn body(x: *Exchange, transfer_buf: []u8) *std.Io.Reader {
        x.reader.buffer = transfer_buf;
        return &x.reader;
    }

    /// Reads a small body into memory.
    pub fn readAll(x: *Exchange, gpa: std.mem.Allocator, limit: usize) error{ Transient, OutOfMemory, TooLarge }![]u8 {
        var buf: [4096]u8 = undefined;
        return x.body(&buf).allocRemaining(gpa, .limited(limit)) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => error.TooLarge,
            error.ReadFailed => error.Transient,
        };
    }

    fn complete(x: *const Exchange) bool {
        return switch (x.framing) {
            .none => true,
            .length => x.remaining == 0,
            .chunked => x.chunk == .done,
            .eof => false,
        };
    }

    /// Returns the connection to the pool when its response was fully read, else closes it.
    pub fn deinit(x: *Exchange) void {
        const gpa = x.pool.gpa;
        defer gpa.free(x.key);
        const c = x.conn orelse return;
        if (!x.failed and x.keep_alive and !x.complete() and x.framing != .eof) {
            var sink_buf: [4096]u8 = undefined;
            var d: std.Io.Writer.Discarding = .init(&sink_buf);
            var budget: usize = drain_budget;
            while (!x.complete() and !x.failed and budget > 0) {
                const n = x.pull(&d.writer, .limited(budget)) catch break;
                budget -|= n;
                _ = d.writer.consumeAll();
            }
        }
        x.conn = null;
        if (!x.failed and x.keep_alive and x.complete()) return x.pool.put(x.key, c);
        c.close();
    }

    const body_vtable: std.Io.Reader.VTable = .{ .stream = bodyStream };

    fn bodyStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const x: *Exchange = @alignCast(@fieldParentPtr("reader", r));
        return x.pull(w, limit);
    }

    fn fail(x: *Exchange) error{ReadFailed} {
        x.failed = true;
        return error.ReadFailed;
    }

    fn pull(x: *Exchange, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const c = x.conn orelse return error.EndOfStream;
        const in = c.reader();
        switch (x.framing) {
            .none => return error.EndOfStream,
            .eof => return in.stream(w, limit) catch |e| switch (e) {
                error.EndOfStream => error.EndOfStream,
                error.WriteFailed => error.WriteFailed,
                error.ReadFailed => x.fail(),
            },
            .length => {
                if (x.remaining == 0) return error.EndOfStream;
                const n = in.stream(w, limit.min(.limited64(x.remaining))) catch |e| return switch (e) {
                    error.WriteFailed => error.WriteFailed,
                    error.ReadFailed, error.EndOfStream => x.fail(),
                };
                x.remaining -= n;
                return n;
            },
            .chunked => while (true) switch (x.chunk) {
                .done => return error.EndOfStream,
                .crlf => {
                    const l = in.takeDelimiterInclusive('\n') catch return x.fail();
                    if (std.mem.trimRight(u8, l, "\r\n").len != 0) return x.fail();
                    x.chunk = .size;
                },
                .size => {
                    const l = in.takeDelimiterInclusive('\n') catch return x.fail();
                    const s = std.mem.trimRight(u8, l, "\r\n");
                    const hex = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, s, ';')) |i| s[0..i] else s, " \t");
                    if (hex.len == 0 or hex.len > 15) return x.fail();
                    x.remaining = std.fmt.parseInt(u64, hex, 16) catch return x.fail();
                    if (x.remaining == 0) {
                        var n: usize = 0;
                        while (true) : (n += 1) {
                            if (n > max_headers) return x.fail();
                            const t = in.takeDelimiterInclusive('\n') catch return x.fail();
                            if (std.mem.trimRight(u8, t, "\r\n").len == 0) break;
                        }
                        x.chunk = .done;
                    } else x.chunk = .data;
                },
                .data => {
                    const n = in.stream(w, limit.min(.limited64(x.remaining))) catch |e| return switch (e) {
                        error.WriteFailed => error.WriteFailed,
                        error.ReadFailed, error.EndOfStream => x.fail(),
                    };
                    x.remaining -= n;
                    if (x.remaining == 0) x.chunk = .crlf;
                    return n;
                },
            },
        }
    }
};

fn writeHead(w: *std.Io.Writer, r: Request) std.Io.Writer.Error!void {
    try w.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: {s}\r\n", .{ @tagName(r.method), r.target, r.host, r.user_agent });
    switch (r.body) {
        .none => if (r.method.requestHasBody()) try w.writeAll("Content-Length: 0\r\n"),
        .bytes => |b| try w.print("Content-Length: {d}\r\n", .{b.len}),
        .stream => |s| if (s.len) |n| try w.print("Content-Length: {d}\r\n", .{n}) else try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    for (r.headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    try w.writeAll("\r\n");
}

/// Passes at most `left` bytes through; more is a source error.
const Counting = struct {
    inner: *std.Io.Writer,
    left: u64,
    over: bool = false,
    writer: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } },

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Counting = @alignCast(@fieldParentPtr("writer", w));
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.put(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.put(last);
        return n + last.len * splat;
    }

    fn put(self: *Counting, d: []const u8) std.Io.Writer.Error!void {
        if (d.len > self.left) {
            self.over = true;
            return error.WriteFailed;
        }
        try self.inner.writeAll(d);
        self.left -= d.len;
    }
};

/// Frames everything written as HTTP chunks; the caller writes the last chunk.
const Chunked = struct {
    inner: *std.Io.Writer,
    writer: std.Io.Writer,

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Chunked = @alignCast(@fieldParentPtr("writer", w));
        const last = data[data.len - 1];
        var total: usize = w.end + last.len * splat;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        if (total == 0) return 0;
        try self.inner.print("{x}\r\n", .{total});
        try self.inner.writeAll(w.buffered());
        for (data[0 .. data.len - 1]) |d| try self.inner.writeAll(d);
        for (0..splat) |_| try self.inner.writeAll(last);
        try self.inner.writeAll("\r\n");
        return w.consume(total);
    }
};

const testing = std.testing;

fn testExchange(pool: *Pool, raw: []const u8, method: Method) !*Exchange {
    const x = try testing.allocator.create(Exchange);
    errdefer testing.allocator.destroy(x);
    x.* = .{ .pool = pool };
    var rd: std.Io.Reader = .fixed(raw);
    try x.readHead(&rd, method);
    return x;
}

test "head parsing: interim, length, chunked, bounds" {
    var pool = Pool.init(testing.allocator, .{});
    defer pool.deinit();
    {
        const x = try testExchange(&pool, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 206 Partial\r\nContent-Length: 2\r\nETag: \"e\"\r\n\r\n", .GET);
        defer testing.allocator.destroy(x);
        try testing.expectEqual(@as(u16, 206), x.status);
        try testing.expectEqual(Framing.length, x.framing);
        try testing.expectEqualStrings("\"e\"", x.header("etag").?);
    }
    {
        const x = try testExchange(&pool, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n", .GET);
        defer testing.allocator.destroy(x);
        try testing.expectEqual(Framing.chunked, x.framing);
        try testing.expect(!x.keep_alive);
    }
    try testing.expectError(error.InvalidResponse, testExchange(&pool, "garbage\r\n\r\n", .GET));
    try testing.expectError(error.InvalidResponse, testExchange(&pool, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", .GET));
    try testing.expectError(error.ConnectFailed, testExchange(&pool, "HTTP/1.1 200 OK\r\n", .GET));
    var many: std.Io.Writer.Allocating = .init(testing.allocator);
    defer many.deinit();
    try many.writer.writeAll("HTTP/1.1 200 OK\r\n");
    for (0..max_headers + 1) |i| try many.writer.print("X-{d}: v\r\n", .{i});
    try many.writer.writeAll("\r\n");
    try testing.expectError(error.ResponseTooLarge, testExchange(&pool, many.written(), .GET));
}

test "chunked writer frames and request head" {
    var out: [256]u8 = undefined;
    var inner: std.Io.Writer = .fixed(&out);
    var buf: [4]u8 = undefined;
    var cw: Chunked = .{ .inner = &inner, .writer = .{ .buffer = &buf, .vtable = &.{ .drain = Chunked.drain } } };
    try cw.writer.writeAll("hello world");
    try cw.writer.flush();
    var rd: std.Io.Reader = .fixed(inner.buffered());
    var got: std.Io.Writer.Allocating = .init(testing.allocator);
    defer got.deinit();
    while (true) {
        const l = std.mem.trimRight(u8, rd.takeDelimiterInclusive('\n') catch break, "\r\n");
        const n = try std.fmt.parseInt(usize, l, 16);
        try got.writer.writeAll(try rd.take(n));
        _ = try rd.take(2);
    }
    try testing.expectEqualStrings("hello world", got.written());

    var hw: std.Io.Writer = .fixed(&out);
    try writeHead(&hw, .{ .method = .PUT, .target = "/b/k", .host = "h:1", .body = .{ .bytes = "abc" } });
    try testing.expect(std.mem.indexOf(u8, hw.buffered(), "Content-Length: 3\r\n") != null);
    try testing.expectError(error.InvalidArgument, Exchange.validate(.{ .method = .GET, .target = "/a b", .host = "h" }));
    try testing.expectError(error.InvalidArgument, Exchange.validate(.{ .method = .GET, .target = "/", .host = "h", .headers = &.{.{ .name = "x", .value = "a\r\nb" }} }));
}

/// Serves `responses` one per request on one connection, recording what it read.
const TestServer = struct {
    server: std.net.Server,
    responses: []const []const u8,
    accepts: std.atomic.Value(u32) = .init(0),

    fn run(s: *TestServer) void {
        var i: usize = 0;
        while (i < s.responses.len) {
            const conn = s.server.accept() catch return;
            _ = s.accepts.fetchAdd(1, .monotonic);
            defer conn.stream.close();
            var rb: [8192]u8 = undefined;
            var sr = conn.stream.reader(&rb);
            const rd = sr.interface();
            while (i < s.responses.len) : (i += 1) {
                var len: usize = 0;
                var chunked = false;
                while (true) {
                    const l = std.mem.trimRight(u8, rd.takeDelimiterInclusive('\n') catch return, "\r\n");
                    if (l.len == 0) break;
                    if (std.ascii.startsWithIgnoreCase(l, "content-length: ")) len = std.fmt.parseInt(usize, l[16..], 10) catch 0;
                    if (std.ascii.startsWithIgnoreCase(l, "transfer-encoding: chunked")) chunked = true;
                }
                if (chunked) {
                    while (true) {
                        const l = std.mem.trimRight(u8, rd.takeDelimiterInclusive('\n') catch return, "\r\n");
                        const n = std.fmt.parseInt(usize, l, 16) catch return;
                        rd.discardAll(n + 2) catch return;
                        if (n == 0) break;
                    }
                } else rd.discardAll(len) catch return;
                const resp = s.responses[i];
                if (resp.len == 0) { // drop the connection without answering
                    i += 1;
                    break;
                }
                conn.stream.writeAll(resp) catch return;
            }
        }
    }
};

test "pooled exchanges reuse, stream bodies, and survive a dropped connection" {
    const gpa = testing.allocator;
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var ts: TestServer = .{ .server = try addr.listen(.{ .reuse_address = true }), .responses = &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "",
        "HTTP/1.1 204 No Content\r\n\r\n",
    } };
    defer ts.server.deinit();
    const th = try std.Thread.spawn(.{}, TestServer.run, .{&ts});
    defer th.join();
    var pool = Pool.init(gpa, .{});
    defer pool.deinit();
    const t: Target = .{ .host = "127.0.0.1", .port = ts.server.listen_address.getPort() };
    var x: Exchange = undefined;
    {
        try x.start(&pool, t, .{ .method = .GET, .target = "/a", .host = "h" });
        defer x.deinit();
        const b = try x.readAll(gpa, 64);
        defer gpa.free(b);
        try testing.expectEqualStrings("hello", b);
    }
    {
        const Src = struct {
            fn write(_: *anyopaque, w: *std.Io.Writer) error{ WriteFailed, SourceFailed }!void {
                try w.writeAll("streamed body");
            }
        };
        var dummy: u8 = 0;
        try x.start(&pool, t, .{ .method = .PUT, .target = "/b", .host = "h", .body = .{ .stream = .{ .len = null, .ctx = &dummy, .write = Src.write } } });
        defer x.deinit();
        const b = try x.readAll(gpa, 64);
        defer gpa.free(b);
        try testing.expectEqualStrings("abc", b);
    }
    // The server drops the third request; an idempotent DELETE is replayed on a new connection.
    try x.start(&pool, t, .{ .method = .DELETE, .target = "/c", .host = "h" });
    try testing.expectEqual(@as(u16, 204), x.status);
    x.deinit();
    try testing.expectEqual(@as(u32, 2), ts.accepts.load(.monotonic));
}
