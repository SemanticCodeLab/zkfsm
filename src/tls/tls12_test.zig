//! TLS 1.2 server state machine driven in-process: negotiation outcomes and a
//! seeded mutation loop over ClientHellos and client flights.
const std = @import("std");
const config = @import("config.zig");
const session = @import("session.zig");
const t12 = @import("tls12.zig");

const gpa = std.testing.allocator;

const HelloOpts = struct {
    ems: bool = true,
    fallback: bool = false,
    reneg: []const u8 = &.{},
    suite: u16 = 0xc02b,
};

fn clientHello(buf: []u8, o: HelloOpts) []u8 {
    var exts: [64]u8 = undefined;
    var e: usize = 0;
    const fixed = [_]u8{ 0, 10, 0, 6, 0, 4, 0, 0x1d, 0, 0x17, 0, 13, 0, 4, 0, 2, 4, 3 };
    @memcpy(exts[0..fixed.len], &fixed);
    e = fixed.len;
    if (o.ems) {
        exts[e..][0..4].* = .{ 0, 23, 0, 0 };
        e += 4;
    }
    exts[e..][0..5].* = .{ 0xff, 1, 0, @intCast(o.reneg.len + 1), @intCast(o.reneg.len) };
    e += 5;
    @memcpy(exts[e..][0..o.reneg.len], o.reneg);
    e += o.reneg.len;

    var suites: [6]u8 = undefined;
    std.mem.writeInt(u16, suites[0..2], o.suite, .big);
    suites[2..4].* = .{ 0xcc, 0xa9 };
    suites[4..6].* = if (o.fallback) .{ 0x56, 0 } else .{ 0xcc, 0xa8 };
    var body: [256]u8 = undefined;
    var n: usize = 0;
    body[0..2].* = .{ 3, 3 };
    @memset(body[2..34], 0x42);
    n = 34;
    body[n] = 0;
    body[n + 1 ..][0..2].* = .{ 0, 6 };
    @memcpy(body[n + 3 ..][0..6], &suites);
    n += 9;
    body[n..][0..2].* = .{ 1, 0 };
    n += 2;
    std.mem.writeInt(u16, body[n..][0..2], @intCast(e), .big);
    @memcpy(body[n + 2 ..][0..e], exts[0..e]);
    n += 2 + e;

    const total = 4 + n;
    buf[0..5].* = .{ 22, 3, 1, @intCast(total >> 8), @truncate(total) };
    buf[5..9].* = .{ 1, 0, @intCast(n >> 8), @truncate(n) };
    @memcpy(buf[9..][0..n], body[0..n]);
    return buf[0 .. 9 + n];
}

const Fixture = struct {
    ctx: config.Context,

    fn init() !Fixture {
        const creds = try config.Credentials.fromPem(gpa, @embedFile("testdata/server12.pem"), @embedFile("testdata/server12.key"));
        return .{ .ctx = .{ .gpa = gpa, .cert_path = "", .key_path = "", .current = creds } };
    }

    fn deinit(f: *Fixture) void {
        f.ctx.current.release();
    }

    fn run(f: *Fixture, input: []const u8, out: []u8) struct { session.Error!void, []u8 } {
        var r: std.Io.Reader = .fixed(input);
        var w: std.Io.Writer = .fixed(out);
        const res: session.Error!void = if (session.Session.accept(gpa, &f.ctx, &r, &w)) |s| s.close() else |e| e;
        return .{ res, w.buffered() };
    }
};

test "tls 1.2 server hello: suite, EMS, downgrade sentinel" {
    var f = try Fixture.init();
    defer f.deinit();
    var hb: [512]u8 = undefined;
    var out: [8192]u8 = undefined;
    const res, const w = f.run(clientHello(&hb, .{}), &out);
    try std.testing.expectError(error.ConnectionClosed, res);
    // Record header, handshake header, then version and random.
    try std.testing.expectEqual(22, w[0]);
    try std.testing.expectEqual(2, w[5]);
    try std.testing.expectEqualSlices(u8, &.{ 3, 3 }, w[9..11]);
    try std.testing.expectEqualSlices(u8, &t12.downgrade_sentinel, w[35..43]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0xc0, 0x2b, 0 }, w[43..47]);
    try std.testing.expect(std.mem.indexOf(u8, w[0..100], &.{ 0, 23, 0, 0 }) != null);
    try std.testing.expect(std.mem.indexOf(u8, w[0..100], &.{ 0xff, 1, 0, 1, 0 }) != null);
}

test "tls 1.2 refusals send the right alert" {
    var f = try Fixture.init();
    defer f.deinit();
    var hb: [512]u8 = undefined;
    var out: [8192]u8 = undefined;
    const Case = struct { o: HelloOpts, err: session.Error, alert: u8 };
    const cases = [_]Case{
        .{ .o = .{ .ems = false }, .err = error.HandshakeFailure, .alert = 40 },
        .{ .o = .{ .reneg = "abc" }, .err = error.HandshakeFailure, .alert = 40 },
        .{ .o = .{ .fallback = true }, .err = error.InappropriateFallback, .alert = 86 },
        .{ .o = .{ .suite = 0xc02f }, .err = error.HandshakeFailure, .alert = 40 },
    };
    for (cases) |c| {
        // 0xc02f alone is RSA-only; drop the ChaCha ECDSA fallback by offering CBC.
        var h = clientHello(&hb, c.o);
        if (c.o.suite == 0xc02f) h[9 + 39 ..][0..4].* = .{ 0xc0, 0x09, 0xc0, 0x13 };
        const res, const w = f.run(h, &out);
        try std.testing.expectError(c.err, res);
        try std.testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, c.alert }, w);
    }
    f.ctx.min_version = .tls13;
    const res, const w = f.run(clientHello(&hb, .{}), &out);
    try std.testing.expectError(error.ProtocolVersion, res);
    try std.testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 70 }, w);
}

test "fuzz: mutated 1.2 hellos and client flights only yield typed errors" {
    var f = try Fixture.init();
    defer f.deinit();
    var hb: [512]u8 = undefined;
    const hello = clientHello(&hb, .{});
    // ClientKeyExchange, ChangeCipherSpec, and a bogus encrypted Finished.
    var base: [1024]u8 = undefined;
    var n = hello.len;
    @memcpy(base[0..n], hello);
    const point = std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{7} ** 32) catch unreachable;
    base[n..][0..9].* = .{ 22, 3, 3, 0, 37, 16, 0, 0, 33 };
    base[n + 9] = 32;
    base[n + 10 ..][0..32].* = point.public_key;
    n += 42;
    base[n..][0..6].* = .{ 20, 3, 3, 0, 1, 1 };
    n += 6;
    base[n..][0..5].* = .{ 22, 3, 3, 0, 40 };
    @memset(base[n + 5 ..][0..40], 0x5a);
    n += 45;
    const seed = base[0..n];

    var prng = std.Random.DefaultPrng.init(0x7e5712);
    const rnd = prng.random();
    var buf: [2048]u8 = undefined;
    var out: [16384]u8 = undefined;
    // Each surviving hello costs a key generation and a signature (Debug: ~0.1 s).
    const iterations = 300;
    var flight_errors: usize = 0;
    for (0..iterations) |_| {
        var len = seed.len;
        @memcpy(buf[0..len], seed);
        switch (rnd.uintLessThan(u8, 4)) {
            0 => len = rnd.uintLessThan(usize, seed.len), // truncation
            1 => { // random bytes after a valid hello
                len = hello.len + rnd.uintLessThan(usize, 600);
                rnd.bytes(buf[hello.len..len]);
            },
            2 => { // pure noise, sometimes with a plausible record header
                len = rnd.uintLessThan(usize, 600) + 5;
                rnd.bytes(buf[0..len]);
                if (rnd.boolean()) buf[0..3].* = .{ 22, 3, 3 };
            },
            else => for (0..rnd.intRangeAtMost(usize, 1, 8)) |_| {
                const j = rnd.uintLessThan(usize, len);
                switch (rnd.uintLessThan(u8, 4)) {
                    0 => buf[j] = rnd.int(u8),
                    1 => buf[j] ^= @as(u8, 1) << rnd.int(u3),
                    2 => { // delete
                        const k = @min(len - j, rnd.intRangeAtMost(usize, 1, 16));
                        std.mem.copyForwards(u8, buf[j .. len - k], buf[j + k .. len]);
                        len -= k;
                    },
                    else => { // insert
                        const k = rnd.intRangeAtMost(usize, 1, 16);
                        std.mem.copyBackwards(u8, buf[j + k .. len + k], buf[j..len]);
                        rnd.bytes(buf[j..][0..k]);
                        len += k;
                    },
                }
                if (len == 0) break;
            },
        }
        const res, _ = f.run(buf[0..len], &out);
        if (res) |_| return error.TestUnexpectedResult else |e| {
            if (e != error.DecodeError and e != error.ConnectionClosed) flight_errors += 1;
        }
    }
    // The loop must reach past the hello, not only bounce off the parser.
    try std.testing.expect(flight_errors > iterations / 10);
}
