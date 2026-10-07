//! FTP and FTPS gateway (RFC 959, 2389, 2428, 3659, 4217): plain FTP with
//! explicit AUTH TLS on --ftp, implicit TLS on --ftps. Passive mode only.
const std = @import("std");
const root = @import("root.zig");
const listener = @import("listener.zig");
const proto = @import("ftp_proto.zig");
const session = @import("ftp_session.zig");

pub const Config = struct {
    listen: ?std.net.Address = null,
    /// Implicit FTPS (TLS from the first byte).
    implicit: ?std.net.Address = null,
    passive_lo: u16 = 0,
    passive_hi: u16 = 0,
    public_ip: ?[4]u8 = null,
    require_tls: bool = false,

    pub fn enabled(c: Config) bool {
        return c.listen != null or c.implicit != null;
    }
};

pub const usage =
    \\ftp gateway:
    \\  --ftp HOST:PORT  serve FTP (explicit FTPS via AUTH TLS when --tls-cert is set)
    \\  --ftps HOST:PORT serve implicit FTPS (needs --tls-cert)
    \\  --ftp-passive-ports A-B  passive data port range (default: any free port)
    \\  --ftp-public-ip IP  IPv4 address announced in PASV replies (default: local address)
    \\  --ftp-require-tls on|off  refuse login and data without TLS (default: off)
    \\
;

/// Consumes `flag value` when it belongs to this gateway.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) root.FlagError!bool {
    if (std.mem.eql(u8, flag, "--ftp")) {
        cfg.listen = listener.parseAddr(value) catch return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--ftps")) {
        cfg.implicit = listener.parseAddr(value) catch return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--ftp-passive-ports")) {
        const r = proto.parsePortRange(value) catch return error.BadArgs;
        cfg.passive_lo = r[0];
        cfg.passive_hi = r[1];
    } else if (std.mem.eql(u8, flag, "--ftp-public-ip")) {
        const a = std.net.Address.parseIp4(value, 0) catch return error.BadArgs;
        cfg.public_ip = proto.ip4Of(a) orelse return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--ftp-require-tls")) {
        if (std.mem.eql(u8, value, "on")) cfg.require_tls = true else if (std.mem.eql(u8, value, "off")) cfg.require_tls = false else return error.BadArgs;
    } else return false;
    return true;
}

pub const Server = struct {
    env: session.Env,
    next_port: std.atomic.Value(u32) = .init(0),
    plain: listener.Listener,
    secure: listener.Listener,
    plain_on: bool = false,
    secure_on: bool = false,

    pub fn start(deps: root.Deps, cfg: Config) root.StartError!*Server {
        if ((cfg.implicit != null or cfg.require_tls) and deps.tls == null) {
            std.log.err("ftp: --ftps and --ftp-require-tls need --tls-cert/--tls-key", .{});
            return error.BadConfig;
        }
        const self = try deps.gpa.create(Server);
        errdefer deps.gpa.destroy(self);
        self.* = .{
            .env = .{
                .deps = deps,
                .passive_lo = cfg.passive_lo,
                .passive_hi = cfg.passive_hi,
                .public_ip = cfg.public_ip,
                .require_tls = cfg.require_tls,
                .next_port = undefined,
            },
            .plain = .{ .name = "ftp", .handler = .{ .ctx = undefined, .serve = servePlain } },
            .secure = .{ .name = "ftps", .handler = .{ .ctx = undefined, .serve = serveImplicit } },
        };
        self.env.next_port = &self.next_port;
        self.env.idle_timeout_s = self.plain.idle_timeout_s;
        self.plain.handler.ctx = self;
        self.secure.handler.ctx = self;
        if (cfg.listen) |a| {
            try self.plain.start(a);
            self.plain_on = true;
        }
        errdefer if (self.plain_on) self.plain.stop(0);
        if (cfg.implicit) |a| {
            try self.secure.start(a);
            self.secure_on = true;
        }
        return self;
    }

    pub fn stop(self: *Server) void {
        if (self.plain_on) self.plain.stop(5);
        if (self.secure_on) self.secure.stop(5);
        // Sessions still running after the drain keep using `self`; leak it then.
        if (self.plain.active.load(.seq_cst) == 0 and self.secure.active.load(.seq_cst) == 0)
            self.env.deps.gpa.destroy(self);
    }

    fn servePlain(ctx: *anyopaque, conn: std.net.Server.Connection) void {
        const self: *Server = @ptrCast(@alignCast(ctx));
        session.Session.run(&self.env, conn, false);
    }

    fn serveImplicit(ctx: *anyopaque, conn: std.net.Server.Connection) void {
        const self: *Server = @ptrCast(@alignCast(ctx));
        session.Session.run(&self.env, conn, true);
    }
};

test "flags" {
    var c: Config = .{};
    try std.testing.expect(!c.enabled());
    try std.testing.expect(try parseFlag(&c, "--ftp", "127.0.0.1:2121"));
    try std.testing.expect(try parseFlag(&c, "--ftp-passive-ports", "30000-30100"));
    try std.testing.expect(try parseFlag(&c, "--ftp-public-ip", "10.1.2.3"));
    try std.testing.expect(try parseFlag(&c, "--ftp-require-tls", "on"));
    try std.testing.expect(!try parseFlag(&c, "--sftp", "x"));
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--ftp-require-tls", "maybe"));
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--ftp-public-ip", "::1"));
    try std.testing.expect(c.enabled() and c.require_tls);
    try std.testing.expectEqual([4]u8{ 10, 1, 2, 3 }, c.public_ip.?);
    try std.testing.expectEqual(@as(u16, 30100), c.passive_hi);
}

test {
    _ = proto;
    _ = session;
}
