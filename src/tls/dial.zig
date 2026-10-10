//! Outbound connections: TCP with connect and I/O deadlines, optional TLS through
//! the mutual-TLS client, and a mid-stream TLS upgrade (STARTTLS-style).
const std = @import("std");
const posix = std.posix;
const Client = @import("client.zig");
const ClientAuth = @import("client_auth.zig").ClientAuth;

pub const Error = error{ ConnectFailed, TlsFailed, OutOfMemory };
pub const ConfigError = error{ InvalidConfig, OutOfMemory };

pub const MinVersion = enum { tls_1_2, tls_1_3 };

/// TLS settings shared by every outbound client (targets, KMS, LDAP).
pub const TlsOptions = struct {
    /// Skip certificate and host checks (self-signed peers in tests).
    skip_verify: bool = false,
    /// PEM bundle file; empty uses $SSL_CERT_FILE, then the system roots.
    ca_file: []const u8 = "",
    /// Host name to verify and send as SNI; empty uses the dialed host.
    server_name: []const u8 = "",
    /// PEM certificate chain and key presented when the server asks for one.
    client_cert_file: []const u8 = "",
    client_key_file: []const u8 = "",
    min_version: MinVersion = .tls_1_2,

    pub fn hasClientCert(o: TlsOptions) bool {
        return o.client_cert_file.len > 0;
    }

    /// Loads every configured file once so bad settings fail at configuration time.
    pub fn check(o: TlsOptions, gpa: std.mem.Allocator) ConfigError!void {
        if ((o.client_cert_file.len > 0) != (o.client_key_file.len > 0)) return error.InvalidConfig;
        if (o.hasClientCert()) {
            var a = ClientAuth.fromFiles(gpa, o.client_cert_file, o.client_key_file) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidConfig;
            a.deinit();
        }
        if (o.ca_file.len > 0 and !o.skip_verify) {
            var b: std.crypto.Certificate.Bundle = .{};
            defer b.deinit(gpa);
            b.addCertsFromFilePath(gpa, std.fs.cwd(), o.ca_file) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidConfig;
            if (b.map.count() == 0) return error.InvalidConfig;
        }
    }
};

/// Parses "1.2"/"1.3" (also "tls1.2", "TLSv1.3"); empty means the default.
pub fn parseMinVersion(s: []const u8) ?MinVersion {
    if (s.len == 0) return .tls_1_2;
    var v = s;
    for ([_][]const u8{ "tlsv", "tls" }) |p| {
        if (std.ascii.startsWithIgnoreCase(v, p)) {
            v = v[p.len..];
            break;
        }
    }
    if (std.mem.eql(u8, v, "1.2")) return .tls_1_2;
    if (std.mem.eql(u8, v, "1.3")) return .tls_1_3;
    return null;
}

pub const buf_len = Client.min_buffer_len;

/// TLS state layered over an existing reader/writer; must not move after `start`.
pub const Secure = struct {
    client: Client = undefined,
    bundle: ?std.crypto.Certificate.Bundle = null,
    auth: ?ClientAuth = null,
    alert: std.crypto.tls.Alert = undefined,
    rbuf: [buf_len]u8 = undefined,
    wbuf: [buf_len]u8 = undefined,

    /// Runs the handshake; on error everything acquired is released.
    pub fn start(s: *Secure, gpa: std.mem.Allocator, input: *std.Io.Reader, output: *std.Io.Writer, host: []const u8, o: TlsOptions) Error!void {
        s.* = .{};
        errdefer s.release(gpa);
        const name = if (o.server_name.len > 0) o.server_name else host;
        var opts: Client.Options = .{
            .host = if (o.skip_verify) .no_verification else .{ .explicit = name },
            .ca = .no_verification,
            .read_buffer = &s.rbuf,
            .write_buffer = &s.wbuf,
            .alert = &s.alert,
            .min_version = if (o.min_version == .tls_1_3) .tls_1_3 else .tls_1_2,
        };
        if (!o.skip_verify) {
            s.bundle = .{};
            const env_ca = posix.getenv("SSL_CERT_FILE") orelse "";
            const ca = if (o.ca_file.len > 0) o.ca_file else env_ca;
            if (ca.len > 0) {
                s.bundle.?.addCertsFromFilePath(gpa, std.fs.cwd(), ca) catch |e| return mapLoad(e);
            } else s.bundle.?.rescan(gpa) catch |e| return mapLoad(e);
            opts.ca = .{ .bundle = s.bundle.? };
        }
        if (o.hasClientCert()) {
            s.auth = ClientAuth.fromFiles(gpa, o.client_cert_file, o.client_key_file) catch |e| return mapLoad(e);
            opts.client_auth = &s.auth.?;
        }
        s.client = Client.init(input, output, opts) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.TlsFailed;
    }

    /// Sends close_notify into the underlying writer (caller flushes it).
    pub fn end(s: *Secure) void {
        s.client.end() catch {};
    }

    pub fn release(s: *Secure, gpa: std.mem.Allocator) void {
        if (s.bundle) |*b| b.deinit(gpa);
        if (s.auth) |*a| a.deinit();
        s.bundle = null;
        s.auth = null;
    }
};

fn mapLoad(e: anytype) Error {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.TlsFailed;
}

pub const Options = struct {
    connect_timeout_ms: u32 = 5000,
    io_timeout_ms: u32 = 10000,
    tls: ?TlsOptions = null,
};

/// One heap-pinned connection; reader/writer pointers stay valid until `close`.
pub const Conn = struct {
    gpa: std.mem.Allocator,
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    sw: std.net.Stream.Writer,
    secure: ?*Secure = null,
    rbuf: [buf_len]u8 = undefined,
    wbuf: [buf_len]u8 = undefined,

    pub fn reader(c: *Conn) *std.Io.Reader {
        if (c.secure) |s| return &s.client.reader;
        return c.sr.interface();
    }

    pub fn writer(c: *Conn) *std.Io.Writer {
        if (c.secure) |s| return &s.client.writer;
        return &c.sw.interface;
    }

    /// Pushes buffered bytes through TLS and the socket.
    pub fn flush(c: *Conn) error{WriteFailed}!void {
        if (c.secure) |s| try s.client.writer.flush();
        try c.sw.interface.flush();
    }

    /// Starts TLS on an open plaintext connection (e.g. after a STARTTLS exchange).
    pub fn startTls(c: *Conn, host: []const u8, o: TlsOptions) Error!void {
        if (c.secure != null) return error.TlsFailed;
        const s = try c.gpa.create(Secure);
        s.start(c.gpa, c.sr.interface(), &c.sw.interface, host, o) catch |e| {
            c.gpa.destroy(s);
            return e;
        };
        c.secure = s;
    }

    pub fn close(c: *Conn) void {
        if (c.secure) |s| {
            s.end();
            c.sw.interface.flush() catch {};
            s.release(c.gpa);
            c.gpa.destroy(s);
        }
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

test "min version parsing" {
    try std.testing.expectEqual(MinVersion.tls_1_2, parseMinVersion("").?);
    try std.testing.expectEqual(MinVersion.tls_1_3, parseMinVersion("TLSv1.3").?);
    try std.testing.expectEqual(MinVersion.tls_1_2, parseMinVersion("1.2").?);
    try std.testing.expect(parseMinVersion("1.1") == null);
}

test "tls options check rejects half-configured client certificates" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidConfig, (TlsOptions{ .client_cert_file = "x" }).check(gpa));
    try std.testing.expectError(error.InvalidConfig, (TlsOptions{ .client_cert_file = "/nonexistent", .client_key_file = "/nonexistent" }).check(gpa));
    try std.testing.expectError(error.InvalidConfig, (TlsOptions{ .ca_file = "/nonexistent" }).check(gpa));
}
