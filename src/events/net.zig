//! Client connections for notification targets: TCP with deadlines, optional TLS
//! (with client certificates) and STARTTLS upgrade, provided by the tls layer.
const std = @import("std");
const tls = @import("../tls/root.zig");
const target = @import("target.zig");

pub const Error = tls.dial.Error;
pub const TlsOptions = tls.TlsOptions;
pub const Options = tls.dial.Options;
pub const Conn = tls.dial.Conn;
pub const dial = tls.dial.dial;
pub const parseMinVersion = tls.dial.parseMinVersion;

/// Target keys holding the client certificate, key and CA file (MinIO names differ per target).
pub const TlsKeys = struct { cert: []const u8 = "client_cert", key: []const u8 = "client_key", ca: []const u8 = "tls_ca_file" };

/// TLS options from target settings, strings copied into `a`; files are loaded once to validate.
pub fn tlsOptions(a: std.mem.Allocator, s: target.Settings, k: TlsKeys) target.InitError!TlsOptions {
    const o: TlsOptions = .{
        .skip_verify = s.flag("tls_skip_verify"),
        .ca_file = try a.dupe(u8, s.get(k.ca)),
        .server_name = try a.dupe(u8, s.get("tls_server_name")),
        .client_cert_file = try a.dupe(u8, s.get(k.cert)),
        .client_key_file = try a.dupe(u8, s.get(k.key)),
        .min_version = parseMinVersion(s.get("tls_min_version")) orelse return error.InvalidConfig,
    };
    try o.check(a);
    return o;
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
