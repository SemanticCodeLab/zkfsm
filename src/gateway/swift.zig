//! OpenStack Swift v1 gateway: the account is the identity's view of all buckets,
//! containers are buckets, objects are keys. Auth is tempauth (IAM access keys),
//! Keystone v3 tokens, or temp URLs; HTTPS when the server has a certificate.
const std = @import("std");
const root = @import("root.zig");
const tls = @import("../tls/root.zig");
const listener_mod = @import("listener.zig");
const handler = @import("swift_handler.zig");
const keystone = @import("keystone.zig");
const meta = @import("swift_meta.zig");

pub const Config = struct {
    listen: ?std.net.Address = null,
    tempauth: bool = true,
    /// URL path prefix the API is mounted under, e.g. "/swift".
    prefix: []const u8 = "",
    /// Serve plain HTTP even when the server has a TLS certificate.
    insecure: bool = false,
    token_ttl_s: u32 = 86400,
    keystone: keystone.Config = .{},

    pub fn enabled(c: Config) bool {
        return c.listen != null;
    }
};

pub const usage =
    \\  --swift HOST:PORT                OpenStack Swift API (HTTPS when --tls-cert is set)
    \\  --swift-tempauth on|off          tempauth at /auth/v1.0 with IAM keys (default on)
    \\  --swift-prefix /PATH             mount the Swift API under PATH
    \\  --swift-insecure on|off          plain HTTP even with a certificate (default off)
    \\  --swift-token-ttl SECONDS        tempauth token lifetime (default 86400)
    \\  --swift-keystone URL             validate X-Auth-Token with Keystone v3 at URL
    \\  --swift-keystone-user NAME       service user for token validation
    \\  --swift-keystone-password PW     service user password
    \\  --swift-keystone-project NAME    service user project
    \\  --swift-keystone-domain NAME     user and project domain (default Default)
    \\  --swift-keystone-admin-token T   fixed service token instead of user/password
    \\  --swift-keystone-map P=KEY       map Keystone project (id or name) to an IAM access key (repeatable)
    \\
;

fn onOff(v: []const u8) root.FlagError!bool {
    if (std.mem.eql(u8, v, "on")) return true;
    if (std.mem.eql(u8, v, "off")) return false;
    return error.BadArgs;
}

/// Consumes `flag value` when it belongs to this gateway.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) root.FlagError!bool {
    const eql = std.mem.eql;
    if (eql(u8, flag, "--swift")) {
        cfg.listen = listener_mod.parseAddr(value) catch return error.BadArgs;
    } else if (eql(u8, flag, "--swift-tempauth")) {
        cfg.tempauth = try onOff(value);
    } else if (eql(u8, flag, "--swift-insecure")) {
        cfg.insecure = try onOff(value);
    } else if (eql(u8, flag, "--swift-prefix")) {
        const p = std.mem.trimRight(u8, value, "/");
        if (p.len > 0 and p[0] != '/') return error.BadArgs;
        if (p.len > 256) return error.BadArgs;
        cfg.prefix = p;
    } else if (eql(u8, flag, "--swift-token-ttl")) {
        cfg.token_ttl_s = std.fmt.parseInt(u32, value, 10) catch return error.BadArgs;
        if (cfg.token_ttl_s == 0) return error.BadArgs;
    } else if (eql(u8, flag, "--swift-keystone")) {
        cfg.keystone.url = value;
    } else if (eql(u8, flag, "--swift-keystone-user")) {
        cfg.keystone.user = value;
    } else if (eql(u8, flag, "--swift-keystone-password")) {
        cfg.keystone.password = value;
    } else if (eql(u8, flag, "--swift-keystone-project")) {
        cfg.keystone.project = value;
    } else if (eql(u8, flag, "--swift-keystone-domain")) {
        cfg.keystone.domain = value;
    } else if (eql(u8, flag, "--swift-keystone-admin-token")) {
        cfg.keystone.admin_token = value;
    } else if (eql(u8, flag, "--swift-keystone-map")) {
        try cfg.keystone.addMap(value);
    } else return false;
    return true;
}

pub const Server = struct {
    gpa: std.mem.Allocator,
    tls: ?*tls.Context,
    state: handler.State,
    listener: listener_mod.Listener,
    host_buf: [64]u8 = undefined,

    pub fn start(deps: root.Deps, cfg: Config) root.StartError!*Server {
        const addr = cfg.listen orelse return error.BadConfig;
        if (!cfg.keystone.valid()) {
            std.log.err("swift: --swift-keystone needs --swift-keystone-admin-token or user, password and project", .{});
            return error.BadConfig;
        }
        if (!cfg.tempauth and cfg.keystone.url == null) std.log.warn("swift: no auth method enabled; only temp URLs work", .{});
        const self = try deps.gpa.create(Server);
        errdefer deps.gpa.destroy(self);
        const ks: ?*keystone.Keystone = if (cfg.keystone.url != null) try keystone.Keystone.create(deps.gpa, cfg.keystone) else null;
        errdefer if (ks) |k| k.destroy();
        var accounts = try meta.AccountStore.init(deps.gpa, deps.state_dir);
        errdefer accounts.deinit();
        const use_tls = deps.tls != null and !cfg.insecure;
        self.* = .{
            .gpa = deps.gpa,
            .tls = if (use_tls) deps.tls else null,
            .state = .{
                .gpa = deps.gpa,
                .access = deps.access,
                .prefix = cfg.prefix,
                .tempauth = cfg.tempauth,
                .token_ttl_s = cfg.token_ttl_s,
                .secret = tokenSecret(deps.state_dir),
                .ks = ks,
                .accounts = accounts,
            },
            .listener = .{ .name = "swift", .handler = .{ .ctx = self, .serve = serve } },
        };
        try self.listener.start(addr);
        self.state.host = std.fmt.bufPrint(&self.host_buf, "{f}", .{self.listener.bound}) catch "127.0.0.1";
        return self;
    }

    pub fn stop(self: *Server) void {
        self.listener.stop(5);
        if (self.state.ks) |k| k.destroy();
        self.state.accounts.deinit();
        self.gpa.destroy(self);
    }

    /// Bound address (useful with port 0).
    pub fn address(self: *const Server) std.net.Address {
        return self.listener.bound;
    }

    fn serve(ctx: *anyopaque, conn: std.net.Server.Connection) void {
        const self: *Server = @ptrCast(@alignCast(ctx));
        defer conn.stream.close();
        var rbuf: [16 * 1024]u8 = undefined;
        var wbuf: [16 * 1024]u8 = undefined;
        var sr = conn.stream.reader(&rbuf);
        var sw = conn.stream.writer(&wbuf);
        var in: *std.Io.Reader = sr.interface();
        var out: *std.Io.Writer = &sw.interface;
        const sess: ?*tls.Session = if (self.tls) |t| tls.Session.accept(self.gpa, t, in, out) catch return else null;
        defer if (sess) |s| s.close();
        if (sess) |s| {
            in = &s.reader;
            out = &s.writer;
        }
        var http = std.http.Server.init(in, out);
        while (!self.listener.isStopping()) {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            const a = arena.allocator();
            const raw = http.reader.receiveHead() catch |e| {
                if (e == error.HttpHeadersOversize) {
                    out.writeAll("HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                }
                return;
            };
            // std.http knows no COPY; parse it as TRACE (bodiless) and flag it.
            const is_copy = std.mem.startsWith(u8, raw, "COPY ");
            const hb = if (is_copy) std.mem.concat(a, u8, &.{ "TRACE", raw[4..] }) catch return else a.dupe(u8, raw) catch return;
            var req: std.http.Server.Request = .{
                .server = &http,
                .head_buffer = hb,
                .head = std.http.Server.Request.Head.parse(hb) catch {
                    out.writeAll("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                    out.flush() catch {};
                    return;
                },
            };
            const keep = req.head.keep_alive and !is_copy;
            handler.handle(&self.state, &req, a, conn.address, sess != null, is_copy) catch |e| {
                std.log.debug("swift: connection closed: {t}", .{e});
                return;
            };
            if (!keep or !bodyDone(&http.reader)) return;
        }
    }
};

/// True when the request body was consumed, so the next request can follow.
fn bodyDone(r: *std.http.Reader) bool {
    switch (r.state) {
        .ready => return true,
        .body_remaining_content_length => |n| if (n == 0) {
            r.state = .ready;
            return true;
        },
        else => {},
    }
    return false;
}

/// Tempauth signing key: persisted under the state dir so tokens survive restarts.
fn tokenSecret(state_dir: ?[]const u8) [32]u8 {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    const dir = state_dir orelse return key;
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&pbuf, "{s}/swift/token.key", .{dir}) catch return key;
    var existing: [32]u8 = undefined;
    if (std.fs.cwd().openFile(path, .{})) |f| {
        defer f.close();
        if ((f.readAll(&existing) catch 0) == 32) return existing;
    } else |_| {}
    const f = std.fs.cwd().createFile(path, .{ .mode = 0o600 }) catch return key;
    defer f.close();
    f.writeAll(&key) catch {};
    return key;
}

test "flags" {
    var c: Config = .{};
    try std.testing.expect(try parseFlag(&c, "--swift", "127.0.0.1:8080"));
    try std.testing.expect(c.enabled());
    try std.testing.expect(try parseFlag(&c, "--swift-tempauth", "off"));
    try std.testing.expect(!c.tempauth);
    try std.testing.expect(try parseFlag(&c, "--swift-prefix", "/swift/"));
    try std.testing.expectEqualStrings("/swift", c.prefix);
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--swift-prefix", "swift"));
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--swift-insecure", "maybe"));
    try std.testing.expect(try parseFlag(&c, "--swift-keystone-map", "p1=alice"));
    try std.testing.expect(try parseFlag(&c, "--swift-keystone", "http://k:5000/v3"));
    try std.testing.expect(!c.keystone.valid());
    try std.testing.expect(try parseFlag(&c, "--swift-keystone-admin-token", "tok"));
    try std.testing.expect(c.keystone.valid());
    try std.testing.expect(!try parseFlag(&c, "--ftp", "x"));
}

test {
    _ = handler;
    _ = keystone;
    _ = meta;
    _ = @import("swift_util.zig");
    _ = @import("swift_auth.zig");
    _ = @import("swift_listing.zig");
    _ = @import("swift_slo.zig");
    _ = @import("swift_object.zig");
}
