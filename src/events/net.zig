//! Client connections for notification targets: TCP with connect and I/O
//! deadlines, optional TLS (std client), and a mid-stream TLS upgrade.
const std = @import("std");
const posix = std.posix;

pub const Error = error{ ConnectFailed, TlsFailed, OutOfMemory };

pub const TlsOptions = struct {
    /// Skip certificate and host checks (self-signed brokers in tests).
    skip_verify: bool = false,
    /// PEM bundle file; empty uses the system roots.
    ca_file: []const u8 = "",
    /// Host name to verify; empty uses the dialed host.
    server_name: []const u8 = "",
};

pub const Options = struct {
    connect_timeout_ms: u32 = 5000,
    io_timeout_ms: u32 = 10000,
    tls: ?TlsOptions = null,
};

const buf_len = std.crypto.tls.Client.min_buffer_len;

/// One heap-pinned connection; reader/writer pointers stay valid until `close`.
pub const Conn = struct {
    gpa: std.mem.Allocator,
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    sw: std.net.Stream.Writer,
    tls: ?std.crypto.tls.Client = null,
    bundle: ?std.crypto.Certificate.Bundle = null,
    rbuf: [buf_len]u8 = undefined,
    wbuf: [buf_len]u8 = undefined,
    tls_rbuf: [buf_len]u8 = undefined,
    tls_wbuf: [buf_len]u8 = undefined,

    pub fn reader(c: *Conn) *std.Io.Reader {
        if (c.tls) |*t| return &t.reader;
        return c.sr.interface();
    }

    pub fn writer(c: *Conn) *std.Io.Writer {
        if (c.tls) |*t| return &t.writer;
        return &c.sw.interface;
    }

    /// Pushes buffered bytes through TLS and the socket.
    pub fn flush(c: *Conn) error{WriteFailed}!void {
        if (c.tls) |*t| try t.writer.flush();
        try c.sw.interface.flush();
    }

    /// Starts TLS on an open plaintext connection (e.g. after a STARTTLS exchange).
    pub fn startTls(c: *Conn, host: []const u8, o: TlsOptions) Error!void {
        const name = if (o.server_name.len > 0) o.server_name else host;
        var opts: std.crypto.tls.Client.Options = .{
            .host = if (o.skip_verify) .no_verification else .{ .explicit = name },
            .ca = .no_verification,
            .read_buffer = &c.tls_rbuf,
            .write_buffer = &c.tls_wbuf,
        };
        if (!o.skip_verify) {
            var b: std.crypto.Certificate.Bundle = .{};
            if (o.ca_file.len > 0) {
                b.addCertsFromFilePath(c.gpa, std.fs.cwd(), o.ca_file) catch return error.TlsFailed;
            } else b.rescan(c.gpa) catch return error.TlsFailed;
            c.bundle = b;
            opts.ca = .{ .bundle = b };
        }
        c.tls = std.crypto.tls.Client.init(c.sr.interface(), &c.sw.interface, opts) catch return error.TlsFailed;
    }

    pub fn close(c: *Conn) void {
        if (c.tls) |*t| {
            t.end() catch {};
            c.sw.interface.flush() catch {};
        }
        if (c.bundle) |*b| b.deinit(c.gpa);
        c.stream.close();
        c.gpa.destroy(c);
    }
};

/// Dials `host:port` (first address that answers within the deadline).
pub fn dial(gpa: std.mem.Allocator, host: []const u8, port: u16, o: Options) Error!*Conn {
    const list = std.net.getAddressList(gpa, host, port) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.ConnectFailed;
    defer list.deinit();
    for (list.addrs) |addr| {
        const s = connectAddr(addr, o) catch continue;
        const c = gpa.create(Conn) catch {
            s.close();
            return error.OutOfMemory;
        };
        c.* = .{ .gpa = gpa, .stream = s, .sr = undefined, .sw = undefined };
        c.sr = s.reader(&c.rbuf);
        c.sw = s.writer(&c.wbuf);
        if (o.tls) |t| c.startTls(host, t) catch |e| {
            s.close();
            gpa.destroy(c);
            return e;
        };
        return c;
    }
    return error.ConnectFailed;
}

fn connectAddr(addr: std.net.Address, o: Options) error{ConnectFailed}!std.net.Stream {
    const fd = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.TCP) catch return error.ConnectFailed;
    errdefer posix.close(fd);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |e| switch (e) {
        error.WouldBlock, error.ConnectionPending => {
            var pfd = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
            const n = posix.poll(&pfd, @intCast(o.connect_timeout_ms)) catch return error.ConnectFailed;
            if (n == 0) return error.ConnectFailed;
            posix.getsockoptError(fd) catch return error.ConnectFailed;
        },
        else => return error.ConnectFailed,
    };
    const fl = posix.fcntl(fd, posix.F.GETFL, 0) catch return error.ConnectFailed;
    _ = posix.fcntl(fd, posix.F.SETFL, fl & ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"))) catch return error.ConnectFailed;
    const tv = posix.timeval{ .sec = @intCast(o.io_timeout_ms / 1000), .usec = @intCast((o.io_timeout_ms % 1000) * 1000) };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1))) catch {};
    return .{ .handle = fd };
}

/// Splits `host:port` (IPv6 in brackets) with a default port.
pub fn splitHostPort(s: []const u8, default_port: u16) error{InvalidAddress}!struct { []const u8, u16 } {
    if (s.len == 0) return error.InvalidAddress;
    if (s[0] == '[') {
        const end = std.mem.indexOfScalar(u8, s, ']') orelse return error.InvalidAddress;
        const rest = s[end + 1 ..];
        if (rest.len == 0) return .{ s[1..end], default_port };
        if (rest[0] != ':') return error.InvalidAddress;
        return .{ s[1..end], std.fmt.parseInt(u16, rest[1..], 10) catch return error.InvalidAddress };
    }
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return .{ s, default_port };
    if (std.mem.indexOfScalar(u8, s[0..colon], ':') != null) return .{ s, default_port };
    return .{ s[0..colon], std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.InvalidAddress };
}

test "splitHostPort" {
    const a = try splitHostPort("broker:9093", 9092);
    try std.testing.expectEqualStrings("broker", a[0]);
    try std.testing.expectEqual(@as(u16, 9093), a[1]);
    try std.testing.expectEqual(@as(u16, 9092), (try splitHostPort("broker", 9092))[1]);
    try std.testing.expectEqualStrings("::1", (try splitHostPort("[::1]:5", 1))[0]);
    try std.testing.expectError(error.InvalidAddress, splitHostPort("h:x", 1));
}

test "dial refuses a closed port quickly" {
    try std.testing.expectError(error.ConnectFailed, dial(std.testing.allocator, "127.0.0.1", 1, .{ .connect_timeout_ms = 500 }));
}

test "dial and echo through a local listener" {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{});
    defer srv.deinit();
    const port = srv.listen_address.getPort();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.net.Server) void {
            const conn = s.accept() catch return;
            defer conn.stream.close();
            var b: [4]u8 = undefined;
            const n = conn.stream.read(&b) catch return;
            _ = conn.stream.write(b[0..n]) catch {};
        }
    }.run, .{&srv});
    defer t.join();
    const c = try dial(std.testing.allocator, "127.0.0.1", port, .{});
    defer c.close();
    try c.writer().writeAll("ping");
    try c.flush();
    var got: [4]u8 = undefined;
    try c.reader().readSliceAll(&got);
    try std.testing.expectEqualStrings("ping", &got);
}
