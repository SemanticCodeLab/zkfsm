//! Loopback tests: the outbound client against our own server with client CAs
//! (TLS 1.3), and against `openssl s_server -tls1_2` when openssl is installed.
const std = @import("std");
const config = @import("config.zig");
const session = @import("session.zig");
const dial = @import("dial.zig");

const testing = std.testing;

const files = [_][]const u8{
    "mtls_ca.pem",             "mtls_server.pem",         "mtls_server.key",
    "mtls_client_p256.pem",    "mtls_client_p256.key",    "mtls_client_p384.pem",
    "mtls_client_p384.key",    "mtls_client_rsa.pem",     "mtls_client_rsa.key",
    "mtls_client_ed25519.pem", "mtls_client_ed25519.key", "ca.pem",
};

const Fixture = struct {
    tmp: testing.TmpDir,
    dir: []u8,

    fn init() !Fixture {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        inline for (files) |f| try tmp.dir.writeFile(.{ .sub_path = f, .data = @embedFile("testdata/" ++ f) });
        const dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
        return .{ .tmp = tmp, .dir = dir };
    }

    fn path(f: *const Fixture, buf: []u8, name: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ f.dir, name }) catch unreachable;
    }

    fn deinit(f: *Fixture) void {
        testing.allocator.free(f.dir);
        f.tmp.cleanup();
    }
};

const ServerResult = struct { ok: bool = false, cn: [64]u8 = undefined, cn_len: usize = 0 };

fn serveOnce(srv: *std.net.Server, ctx: *config.Context, out: *ServerResult) void {
    const conn = srv.accept() catch return;
    defer conn.stream.close();
    var rb: [16 * 1024]u8 = undefined;
    var wb: [16 * 1024]u8 = undefined;
    var sr = conn.stream.reader(&rb);
    var sw = conn.stream.writer(&wb);
    const s = session.Session.accept(testing.allocator, ctx, sr.interface(), &sw.interface) catch return;
    defer s.close();
    if (s.peerIdentity()) |p| {
        out.cn_len = @min(p.common_name.len, out.cn.len);
        @memcpy(out.cn[0..out.cn_len], p.common_name[0..out.cn_len]);
    }
    var got: [4]u8 = undefined;
    s.reader.readSliceAll(&got) catch return;
    if (!std.mem.eql(u8, &got, "ping")) return;
    s.writer.writeAll("pong") catch return;
    s.writer.flush() catch return;
    sw.interface.flush() catch return;
    out.ok = true;
}

/// One client connection against our server; returns the CN the server saw.
fn roundTrip(f: *const Fixture, ctx: *config.Context, o: dial.TlsOptions, cn_out: []u8) !usize {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{ .reuse_address = true });
    defer srv.deinit();
    var res: ServerResult = .{};
    const t = try std.Thread.spawn(.{}, serveOnce, .{ &srv, ctx, &res });
    defer t.join();
    _ = f;
    const c = dial.dial(testing.allocator, "127.0.0.1", srv.listen_address.getPort(), .{ .tls = o, .io_timeout_ms = 5000 }) catch |e| {
        // Unblock the server thread if it is still waiting.
        if (std.net.tcpConnectToAddress(srv.listen_address)) |s| s.close() else |_| {}
        return e;
    };
    defer c.close();
    try c.writer().writeAll("ping");
    try c.flush();
    var got: [4]u8 = undefined;
    try c.reader().readSliceAll(&got);
    try testing.expectEqualStrings("pong", &got);
    @memcpy(cn_out[0..res.cn_len], res.cn[0..res.cn_len]);
    return res.cn_len;
}

test "mutual TLS 1.3 against our server with every client key type" {
    var f = try Fixture.init();
    defer f.deinit();
    var b: [4][512]u8 = undefined;
    var ctx = try config.Context.init(testing.allocator, f.path(&b[0], "mtls_server.pem"), f.path(&b[1], "mtls_server.key"));
    defer ctx.deinit();
    try ctx.setClientCa(f.path(&b[2], "mtls_ca.pem"));
    var ca_buf: [512]u8 = undefined;
    const ca = f.path(&ca_buf, "mtls_ca.pem");

    inline for (.{ "p256", "p384", "rsa", "ed25519" }) |kind| {
        var cb: [512]u8 = undefined;
        var kb: [512]u8 = undefined;
        var cn: [64]u8 = undefined;
        const n = try roundTrip(&f, &ctx, .{
            .ca_file = ca,
            .server_name = "localhost",
            .client_cert_file = f.path(&cb, "mtls_client_" ++ kind ++ ".pem"),
            .client_key_file = f.path(&kb, "mtls_client_" ++ kind ++ ".key"),
            .min_version = .tls_1_3,
        }, &cn);
        try testing.expectEqualStrings("client-" ++ kind, cn[0..n]);
    }

    // No client certificate: the request is answered with an empty Certificate.
    var cn: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try roundTrip(&f, &ctx, .{ .ca_file = ca, .server_name = "localhost" }, &cn));
    // Server certificate from an unknown CA, and a host name mismatch.
    var other: [512]u8 = undefined;
    try testing.expectError(error.TlsFailed, roundTrip(&f, &ctx, .{ .ca_file = f.path(&other, "ca.pem"), .server_name = "localhost" }, &cn));
    try testing.expectError(error.TlsFailed, roundTrip(&f, &ctx, .{ .ca_file = ca, .server_name = "wrong.example" }, &cn));
    // Skip-verify still presents the client certificate.
    var cb: [512]u8 = undefined;
    var kb: [512]u8 = undefined;
    const n = try roundTrip(&f, &ctx, .{ .skip_verify = true, .client_cert_file = f.path(&cb, "mtls_client_p256.pem"), .client_key_file = f.path(&kb, "mtls_client_p256.key") }, &cn);
    try testing.expectEqualStrings("client-p256", cn[0..n]);
}

fn haveOpenssl() bool {
    const r = std.process.Child.run(.{ .allocator = testing.allocator, .argv = &.{ "openssl", "version" } }) catch return false;
    testing.allocator.free(r.stdout);
    testing.allocator.free(r.stderr);
    return r.term == .Exited and r.term.Exited == 0;
}

fn freePort() !u16 {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{ .reuse_address = true });
    defer srv.deinit();
    return srv.listen_address.getPort();
}

/// GET against `openssl s_server -www`; returns whether the page reports our certificate.
fn opensslGet(port: u16, o: dial.TlsOptions) !bool {
    var tries: usize = 0;
    const c = while (true) : (tries += 1) {
        if (dial.dial(testing.allocator, "127.0.0.1", port, .{ .tls = o, .io_timeout_ms = 5000 })) |c| break c else |e| {
            if (e != error.ConnectFailed or tries > 50) return e;
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    };
    defer c.close();
    try c.writer().writeAll("GET / HTTP/1.0\r\n\r\n");
    try c.flush();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    _ = c.reader().streamRemaining(&out.writer) catch {};
    const page = out.written();
    if (std.mem.indexOf(u8, page, "TLSv1.2") == null) return error.TestUnexpectedResult;
    return std.mem.indexOf(u8, page, "client-") != null;
}

test "mutual TLS 1.2 against openssl s_server" {
    if (!haveOpenssl()) return error.SkipZigTest;
    var f = try Fixture.init();
    defer f.deinit();
    var b: [6][512]u8 = undefined;
    const ca = f.path(&b[0], "mtls_ca.pem");
    const cases = .{ .{ "p256", "" }, .{ "rsa", "" }, .{ "rsa", "RSA+SHA256" }, .{ "p384", "" }, .{ "ed25519", "" } };
    inline for (cases) |cs| {
        const port = try freePort();
        var pb: [8]u8 = undefined;
        const ps = try std.fmt.bufPrint(&pb, "{d}", .{port});
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(testing.allocator);
        try argv.appendSlice(testing.allocator, &.{ "openssl", "s_server", "-quiet", "-tls1_2", "-www", "-naccept", "1", "-accept", ps, "-Verify", "2", "-verify_return_error", "-CAfile", ca, "-cert", f.path(&b[1], "mtls_server.pem"), "-key", f.path(&b[2], "mtls_server.key") });
        if (cs[1].len > 0) try argv.appendSlice(testing.allocator, &.{ "-client_sigalgs", cs[1] });
        var child = std.process.Child.init(argv.items, testing.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        try child.spawn();
        defer _ = child.kill() catch {};
        const ok = try opensslGet(port, .{
            .ca_file = ca,
            .server_name = "localhost",
            .client_cert_file = f.path(&b[3], "mtls_client_" ++ cs[0] ++ ".pem"),
            .client_key_file = f.path(&b[4], "mtls_client_" ++ cs[0] ++ ".key"),
        });
        try testing.expect(ok);
    }
    // Without a client certificate the server refuses the handshake.
    const port = try freePort();
    var pb: [8]u8 = undefined;
    const ps = try std.fmt.bufPrint(&pb, "{d}", .{port});
    var child = std.process.Child.init(&.{ "openssl", "s_server", "-quiet", "-tls1_2", "-www", "-naccept", "1", "-accept", ps, "-Verify", "2", "-verify_return_error", "-CAfile", ca, "-cert", f.path(&b[1], "mtls_server.pem"), "-key", f.path(&b[2], "mtls_server.key") }, testing.allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    defer _ = child.kill() catch {};
    try testing.expectError(error.TlsFailed, opensslGet(port, .{ .ca_file = ca, .server_name = "localhost" }));
}
