//! Minimal HTTP/2 (prior-knowledge h2c) server and client carrying unary gRPC.
//! One thread per connection; requests are dispatched synchronously.
const std = @import("std");
const hpack = @import("hpack.zig");
const posix = std.posix;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FrameType = enum(u8) {
    data = 0,
    headers = 1,
    priority = 2,
    rst_stream = 3,
    settings = 4,
    push_promise = 5,
    ping = 6,
    goaway = 7,
    window_update = 8,
    continuation = 9,
    _,
};

pub const flag_end_stream: u8 = 0x1;
pub const flag_ack: u8 = 0x1;
pub const flag_end_headers: u8 = 0x4;
pub const flag_padded: u8 = 0x8;
pub const flag_priority: u8 = 0x20;

const max_frame: u32 = 16384;
const max_body: usize = 8 << 20;
const max_header_block: usize = 256 << 10;

pub const Response = struct {
    status: u32 = 0,
    message: []const u8 = "",
    body: []const u8 = "",
};

pub const Handler = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, arena: Allocator, path: []const u8, req: []const u8) Response,
};

pub const FrameHeader = struct { len: u32, typ: FrameType, flags: u8, stream: u31 };

fn readExact(fd: posix.fd_t, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try posix.read(fd, buf[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

fn writeAll(fd: posix.fd_t, buf: []const u8) !void {
    var off: usize = 0;
    while (off < buf.len) off += try posix.write(fd, buf[off..]);
}

pub fn readFrameHeader(fd: posix.fd_t) !FrameHeader {
    var h: [9]u8 = undefined;
    try readExact(fd, &h);
    return .{
        .len = std.mem.readInt(u24, h[0..3], .big),
        .typ = @enumFromInt(h[3]),
        .flags = h[4],
        .stream = @intCast(std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff),
    };
}

pub fn writeFrame(fd: posix.fd_t, typ: FrameType, flags: u8, stream: u31, payload: []const u8) !void {
    var h: [9]u8 = undefined;
    std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
    h[3] = @intFromEnum(typ);
    h[4] = flags;
    std.mem.writeInt(u32, h[5..9], stream, .big);
    try writeAll(fd, &h);
    if (payload.len > 0) try writeAll(fd, payload);
}

fn writeWindowUpdate(fd: posix.fd_t, stream: u31, inc: u32) !void {
    var p: [4]u8 = undefined;
    std.mem.writeInt(u32, &p, inc, .big);
    try writeFrame(fd, .window_update, 0, stream, &p);
}

fn writeGoaway(fd: posix.fd_t, last: u31, code: u32) void {
    var p: [8]u8 = undefined;
    std.mem.writeInt(u32, p[0..4], last, .big);
    std.mem.writeInt(u32, p[4..8], code, .big);
    writeFrame(fd, .goaway, 0, 0, &p) catch {};
}

/// Header block split into HEADERS + CONTINUATION frames as needed.
fn writeHeaderBlock(fd: posix.fd_t, stream: u31, block: []const u8, end_stream: bool) !void {
    var rest = block;
    var first = true;
    while (true) {
        const n = @min(rest.len, max_frame);
        const last = n == rest.len;
        var flags: u8 = if (last) flag_end_headers else 0;
        if (first and end_stream) flags |= flag_end_stream;
        try writeFrame(fd, if (first) .headers else .continuation, flags, stream, rest[0..n]);
        rest = rest[n..];
        first = false;
        if (last) return;
    }
}

fn writeData(fd: posix.fd_t, stream: u31, data: []const u8, end_stream: bool) !void {
    var rest = data;
    while (true) {
        const n = @min(rest.len, max_frame);
        const last = n == rest.len;
        try writeFrame(fd, .data, if (last and end_stream) flag_end_stream else 0, stream, rest[0..n]);
        rest = rest[n..];
        if (last) return;
    }
}

/// Strips padding and priority fields from a HEADERS/DATA payload.
fn unpad(payload: []const u8, flags: u8, is_headers: bool) ![]const u8 {
    var p = payload;
    var pad: usize = 0;
    if (flags & flag_padded != 0) {
        if (p.len < 1) return error.ProtocolError;
        pad = p[0];
        p = p[1..];
    }
    if (is_headers and flags & flag_priority != 0) {
        if (p.len < 5) return error.ProtocolError;
        p = p[5..];
    }
    if (pad > p.len) return error.ProtocolError;
    return p[0 .. p.len - pad];
}

pub fn grpcFrame(gpa: Allocator, msg: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, msg.len + 5);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg.len), .big);
    @memcpy(out[5..], msg);
    return out;
}

/// Extracts the single message of a unary gRPC body (empty body = empty message).
pub fn grpcUnframe(body: []const u8) ![]const u8 {
    if (body.len == 0) return body;
    if (body.len < 5) return error.GrpcInvalid;
    if (body[0] != 0) return error.GrpcCompressed;
    const n = std.mem.readInt(u32, body[1..5], .big);
    if (n != body.len - 5) return error.GrpcInvalid;
    return body[5..];
}

fn percentEncode(arena: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (s) |c| {
        if (c >= 0x20 and c <= 0x7e and c != '%') {
            try out.append(arena, c);
        } else {
            try out.print(arena, "%{X:0>2}", .{c});
        }
    }
    return out.items;
}

pub fn percentDecode(arena: Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            const v = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch {
                try out.append(arena, s[i]);
                continue;
            };
            try out.append(arena, v);
            i += 2;
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

const Stream = struct {
    path: []const u8 = "",
    body: std.ArrayList(u8) = .empty,
    arena: std.heap.ArenaAllocator,
};

const Conn = struct {
    gpa: Allocator,
    fd: posix.fd_t,
    handler: Handler,
    dec: hpack.Decoder,
    streams: std.AutoHashMapUnmanaged(u31, *Stream) = .empty,
    last_stream: u31 = 0,
    // header block being assembled across CONTINUATION frames
    block: std.ArrayList(u8) = .empty,
    block_stream: u31 = 0,
    block_end_stream: bool = false,

    fn deinit(self: *Conn) void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| self.freeStream(s.*);
        self.streams.deinit(self.gpa);
        self.block.deinit(self.gpa);
        self.dec.deinit();
    }

    fn freeStream(self: *Conn, s: *Stream) void {
        s.arena.deinit();
        self.gpa.destroy(s);
    }

    fn dropStream(self: *Conn, id: u31) void {
        if (self.streams.fetchRemove(id)) |kv| self.freeStream(kv.value);
    }

    fn rst(self: *Conn, id: u31, code: u32) !void {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, code, .big);
        try writeFrame(self.fd, .rst_stream, 0, id, &p);
        self.dropStream(id);
    }

    fn run(self: *Conn) !void {
        var pre: [preface.len]u8 = undefined;
        try readExact(self.fd, &pre);
        if (!std.mem.eql(u8, &pre, preface)) return error.BadPreface;
        // SETTINGS: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=1 MiB
        var s: [12]u8 = undefined;
        std.mem.writeInt(u16, s[0..2], 0x3, .big);
        std.mem.writeInt(u32, s[2..6], 100, .big);
        std.mem.writeInt(u16, s[6..8], 0x4, .big);
        std.mem.writeInt(u32, s[8..12], 1 << 20, .big);
        try writeFrame(self.fd, .settings, 0, 0, &s);
        try writeWindowUpdate(self.fd, 0, (1 << 30) - 65535);

        var payload_buf: [max_frame]u8 = undefined;
        while (true) {
            const fh = try readFrameHeader(self.fd);
            if (fh.len > max_frame) {
                writeGoaway(self.fd, self.last_stream, 0x6);
                return error.FrameTooLarge;
            }
            const payload = payload_buf[0..fh.len];
            try readExact(self.fd, payload);
            if (self.block_stream != 0 and fh.typ != .continuation) {
                writeGoaway(self.fd, self.last_stream, 0x1);
                return error.ProtocolError;
            }
            switch (fh.typ) {
                .settings => {
                    if (fh.flags & flag_ack == 0) {
                        if (fh.len % 6 != 0) return error.ProtocolError;
                        try writeFrame(self.fd, .settings, flag_ack, 0, "");
                    }
                },
                .ping => {
                    if (fh.flags & flag_ack == 0 and fh.len == 8) try writeFrame(self.fd, .ping, flag_ack, 0, payload);
                },
                .goaway => return,
                .headers => {
                    if (fh.stream == 0) return error.ProtocolError;
                    const frag = try unpad(payload, fh.flags, true);
                    self.block.clearRetainingCapacity();
                    try self.block.appendSlice(self.gpa, frag);
                    self.block_stream = fh.stream;
                    self.block_end_stream = fh.flags & flag_end_stream != 0;
                    if (fh.flags & flag_end_headers != 0) try self.endHeaders();
                },
                .continuation => {
                    if (fh.stream != self.block_stream or self.block_stream == 0) return error.ProtocolError;
                    if (self.block.items.len + payload.len > max_header_block) return error.HeaderBlockTooLarge;
                    try self.block.appendSlice(self.gpa, payload);
                    if (fh.flags & flag_end_headers != 0) try self.endHeaders();
                },
                .data => {
                    if (fh.len > 0) {
                        try writeWindowUpdate(self.fd, 0, fh.len);
                        if (fh.flags & flag_end_stream == 0) try writeWindowUpdate(self.fd, fh.stream, fh.len);
                    }
                    const data = try unpad(payload, fh.flags, false);
                    const st = self.streams.get(fh.stream) orelse continue;
                    if (st.body.items.len + data.len > max_body) {
                        try self.rst(fh.stream, 0xb);
                        continue;
                    }
                    try st.body.appendSlice(st.arena.allocator(), data);
                    if (fh.flags & flag_end_stream != 0) try self.dispatch(fh.stream);
                },
                .rst_stream => self.dropStream(fh.stream),
                else => {}, // PRIORITY, WINDOW_UPDATE, unknown: ignored
            }
        }
    }

    fn endHeaders(self: *Conn) !void {
        const id = self.block_stream;
        self.block_stream = 0;
        if (self.streams.get(id)) |st| {
            // trailers from the client; decode to keep HPACK state in sync
            var hdrs: std.ArrayList(hpack.Header) = .empty;
            try self.dec.decode(st.arena.allocator(), self.block.items, &hdrs);
            if (self.block_end_stream) try self.dispatch(id);
            return;
        }
        const st = try self.gpa.create(Stream);
        st.* = .{ .arena = std.heap.ArenaAllocator.init(self.gpa) };
        errdefer self.freeStream(st);
        var hdrs: std.ArrayList(hpack.Header) = .empty;
        try self.dec.decode(st.arena.allocator(), self.block.items, &hdrs);
        for (hdrs.items) |h| {
            if (std.mem.eql(u8, h.name, ":path")) st.path = h.value;
        }
        if (id > self.last_stream) self.last_stream = id;
        try self.streams.put(self.gpa, id, st);
        if (self.block_end_stream) try self.dispatch(id);
    }

    fn dispatch(self: *Conn, id: u31) !void {
        const st = self.streams.get(id) orelse return;
        defer self.dropStream(id);
        const arena = st.arena.allocator();
        var resp: Response = undefined;
        if (grpcUnframe(st.body.items)) |msg| {
            resp = self.handler.call(self.handler.ctx, arena, st.path, msg);
        } else |e| {
            resp = .{ .status = if (e == error.GrpcCompressed) 12 else 13, .message = "malformed grpc request" };
        }
        try sendResponse(self.fd, arena, id, resp);
    }
};

fn sendResponse(fd: posix.fd_t, arena: Allocator, id: u31, resp: Response) !void {
    var hb: std.ArrayList(u8) = .empty;
    try hb.append(arena, 0x88); // indexed :status 200
    try hpack.encodeLiteral(arena, &hb, "content-type", "application/grpc");
    var status_buf: [10]u8 = undefined;
    const status = std.fmt.bufPrint(&status_buf, "{d}", .{resp.status}) catch unreachable;
    if (resp.status != 0) {
        // trailers-only response
        try hpack.encodeLiteral(arena, &hb, "grpc-status", status);
        try hpack.encodeLiteral(arena, &hb, "grpc-message", try percentEncode(arena, resp.message));
        return writeHeaderBlock(fd, id, hb.items, true);
    }
    try writeHeaderBlock(fd, id, hb.items, false);
    try writeData(fd, id, try grpcFrame(arena, resp.body), false);
    var tb: std.ArrayList(u8) = .empty;
    try hpack.encodeLiteral(arena, &tb, "grpc-status", "0");
    try writeHeaderBlock(fd, id, tb.items, true);
}

/// Serves one connection until EOF or GOAWAY, then closes `fd`.
pub fn serveConn(gpa: Allocator, fd: posix.fd_t, handler: Handler) void {
    defer posix.close(fd);
    var c: Conn = .{ .gpa = gpa, .fd = fd, .handler = handler, .dec = hpack.Decoder.init(gpa) };
    defer c.deinit();
    c.run() catch |e| switch (e) {
        error.EndOfStream, error.ConnectionResetByPeer => {},
        else => std.log.debug("h2 connection closed: {s}", .{@errorName(e)}),
    };
}

pub fn listenUnix(path: []const u8) !posix.socket_t {
    std.fs.deleteFileAbsolute(path) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    };
    const addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    try posix.listen(fd, 128);
    return fd;
}

pub fn serve(gpa: Allocator, listen_fd: posix.socket_t, handler: Handler) !void {
    while (true) {
        const fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch |e| switch (e) {
            error.ConnectionAborted => continue,
            else => return e,
        };
        const t = std.Thread.spawn(.{}, serveConn, .{ gpa, fd, handler }) catch |e| {
            std.log.err("spawn connection thread: {s}", .{@errorName(e)});
            posix.close(fd);
            continue;
        };
        t.detach();
    }
}

pub fn connectUnix(path: []const u8) !posix.socket_t {
    const addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &addr.any, addr.getOsSockLen());
    return fd;
}

pub const CallResult = struct { status: u32, message: []const u8, body: []const u8 };

/// Tiny h2c client: one unary gRPC call on stream 1 (tests and `zkfsm-csi call`).
pub fn unaryCall(arena: Allocator, fd: posix.fd_t, path: []const u8, msg: []const u8) !CallResult {
    try writeAll(fd, preface);
    try writeFrame(fd, .settings, 0, 0, "");
    var hb: std.ArrayList(u8) = .empty;
    try hb.appendSlice(arena, &.{ 0x83, 0x86 }); // :method POST, :scheme http
    try hpack.encodeLiteral(arena, &hb, ":path", path);
    try hpack.encodeLiteral(arena, &hb, ":authority", "localhost");
    try hpack.encodeLiteral(arena, &hb, "content-type", "application/grpc");
    try hpack.encodeLiteral(arena, &hb, "te", "trailers");
    try writeHeaderBlock(fd, 1, hb.items, false);
    try writeData(fd, 1, try grpcFrame(arena, msg), true);

    var dec = hpack.Decoder.init(arena);
    var body: std.ArrayList(u8) = .empty;
    var block: std.ArrayList(u8) = .empty;
    var status: ?u32 = null;
    var message: []const u8 = "";
    var end = false;
    const payload_buf = try arena.alloc(u8, 1 << 24);
    while (true) {
        const fh = try readFrameHeader(fd);
        const payload = payload_buf[0..fh.len];
        try readExact(fd, payload);
        switch (fh.typ) {
            .settings => if (fh.flags & flag_ack == 0) try writeFrame(fd, .settings, flag_ack, 0, ""),
            .ping => if (fh.flags & flag_ack == 0) try writeFrame(fd, .ping, flag_ack, 0, payload),
            .goaway => return error.GoAway,
            .rst_stream => return error.StreamReset,
            .data => if (fh.stream == 1) {
                try body.appendSlice(arena, try unpad(payload, fh.flags, false));
                if (fh.flags & flag_end_stream != 0) break;
            },
            .headers, .continuation => if (fh.stream == 1) {
                if (fh.typ == .headers) {
                    block.clearRetainingCapacity();
                    try block.appendSlice(arena, try unpad(payload, fh.flags, true));
                    if (fh.flags & flag_end_stream != 0) end = true;
                } else try block.appendSlice(arena, payload);
                if (fh.flags & flag_end_headers != 0) {
                    var hdrs: std.ArrayList(hpack.Header) = .empty;
                    try dec.decode(arena, block.items, &hdrs);
                    for (hdrs.items) |h| {
                        if (std.mem.eql(u8, h.name, "grpc-status")) status = try std.fmt.parseInt(u32, h.value, 10);
                        if (std.mem.eql(u8, h.name, "grpc-message")) message = try percentDecode(arena, h.value);
                    }
                    if (end) break;
                }
            },
            else => {},
        }
    }
    return .{ .status = status orelse return error.NoGrpcStatus, .message = message, .body = try grpcUnframe(body.items) };
}

const testing = std.testing;

const Echo = struct {
    fn call(_: *anyopaque, arena: Allocator, path: []const u8, req: []const u8) Response {
        if (std.mem.eql(u8, path, "/test.Echo/Echo")) return .{ .body = req };
        return .{ .status = 12, .message = std.fmt.allocPrint(arena, "unknown method {s}\n100%", .{path}) catch "oom" };
    }
};

fn socketPair() ![2]posix.fd_t {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketPair;
    return fds;
}

pub fn testCall(handler: Handler, arena: Allocator, path: []const u8, msg: []const u8) !CallResult {
    const fds = try socketPair();
    const t = try std.Thread.spawn(.{}, serveConn, .{ testing.allocator, fds[0], handler });
    defer {
        posix.close(fds[1]);
        t.join();
    }
    return unaryCall(arena, fds[1], path, msg);
}

test "h2 unary echo with large body and unknown method" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var dummy: u8 = 0;
    const h: Handler = .{ .ctx = &dummy, .call = Echo.call };
    const big = try arena.alloc(u8, 100_000);
    for (big, 0..) |*b, i| b.* = @truncate(i);
    const r = try testCall(h, arena, "/test.Echo/Echo", big);
    try testing.expectEqual(@as(u32, 0), r.status);
    try testing.expectEqualSlices(u8, big, r.body);
    const u = try testCall(h, arena, "/test.Echo/Nope", "");
    try testing.expectEqual(@as(u32, 12), u.status);
    try testing.expectEqualStrings("unknown method /test.Echo/Nope\n100%", u.message);
}

test "h2 rejects bad preface" {
    const fds = try socketPair();
    var dummy: u8 = 0;
    const t = try std.Thread.spawn(.{}, serveConn, .{ testing.allocator, fds[0], Handler{ .ctx = &dummy, .call = Echo.call } });
    try writeAll(fds[1], "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    t.join();
    var buf: [16]u8 = undefined;
    // closed with unread data: EOF or reset, never a SETTINGS frame
    const n = posix.read(fds[1], &buf) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
    posix.close(fds[1]);
}
