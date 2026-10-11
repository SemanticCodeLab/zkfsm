//! Webhook target: POSTs each payload as JSON to an HTTP(S) endpoint.
//! Also the transport of the audit webhook logger.
const std = @import("std");
const target = @import("target.zig");
const net = @import("net.zig");

pub const keys = [_][]const u8{ "endpoint", "auth_token", "queue_dir", "queue_limit", "client_cert", "client_key", "tls_skip_verify", "tls_ca_file", "tls_server_name", "tls_min_version", "comment" };

const max_status_line = 512;

const Webhook = struct {
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    path: []const u8,
    host_header: []const u8,
    secure: bool,
    tls: net.TlsOptions = .{},
    arena: std.heap.ArenaAllocator,
    auth: []const u8,
    owned: std.ArrayList([]u8) = .empty,

    fn send(ctx: *anyopaque, msg: *const target.Message) target.SendError!void {
        const self: *Webhook = @ptrCast(@alignCast(ctx));
        const c = net.dial(self.gpa, self.host, self.port, .{ .tls = if (self.secure) self.tls else null }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unreachable,
        };
        defer c.close();
        const w = c.writer();
        w.print("POST {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: zkfsm\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n", .{ self.path, self.host_header, msg.body.len }) catch return error.Unreachable;
        if (self.auth.len > 0) w.print("Authorization: {s}\r\n", .{self.auth}) catch return error.Unreachable;
        w.writeAll("\r\n") catch return error.Unreachable;
        w.writeAll(msg.body) catch return error.Unreachable;
        c.flush() catch return error.Unreachable;
        const status = readStatus(c.reader()) catch return error.Unreachable;
        if (status < 200 or status > 299) return error.Rejected;
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *Webhook = @ptrCast(@alignCast(ctx));
        for (self.owned.items) |s| self.gpa.free(s);
        self.owned.deinit(self.gpa);
        self.arena.deinit();
        self.gpa.destroy(self);
    }

    fn own(self: *Webhook, s: []const u8) error{OutOfMemory}![]const u8 {
        const d = try self.gpa.dupe(u8, s);
        self.owned.append(self.gpa, d) catch {
            self.gpa.free(d);
            return error.OutOfMemory;
        };
        return d;
    }
};

/// Status code of `HTTP/1.x NNN ...`.
fn readStatus(r: *std.Io.Reader) error{ ReadFailed, BadResponse }!u16 {
    const line = r.takeDelimiterExclusive('\n') catch |e| return switch (e) {
        error.ReadFailed => error.ReadFailed,
        else => error.BadResponse,
    };
    if (line.len > max_status_line or line.len < 12 or !std.mem.startsWith(u8, line, "HTTP/1.")) return error.BadResponse;
    return std.fmt.parseInt(u16, line[9..12], 10) catch error.BadResponse;
}

const vtable: target.Client.VTable = .{ .send = Webhook.send, .deinit = Webhook.deinit };

pub fn create(gpa: std.mem.Allocator, s: target.Settings) target.InitError!target.Client {
    const endpoint = s.get("endpoint");
    const uri = std.Uri.parse(endpoint) catch return error.InvalidConfig;
    const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) true else if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) false else return error.InvalidConfig;
    var hb: [std.Uri.host_name_max]u8 = undefined;
    const host = uri.getHost(&hb) catch return error.InvalidConfig;
    const self = try gpa.create(Webhook);
    self.* = .{ .gpa = gpa, .host = "", .port = uri.port orelse if (secure) 443 else 80, .path = "/", .host_header = "", .secure = secure, .auth = "", .arena = .init(gpa) };
    errdefer Webhook.deinit(self);
    if (secure) self.tls = try net.tlsOptions(self.arena.allocator(), s, .{});
    self.host = try self.own(host);
    const hh = try hostHeader(gpa, host, uri.port);
    defer gpa.free(hh);
    self.host_header = try self.own(hh);
    var pb: std.Io.Writer.Allocating = .init(gpa);
    defer pb.deinit();
    uri.path.formatPath(&pb.writer) catch return error.OutOfMemory;
    if (uri.query) |q| {
        pb.writer.writeByte('?') catch return error.OutOfMemory;
        q.formatQuery(&pb.writer) catch return error.OutOfMemory;
    }
    if (pb.written().len > 0) self.path = try self.own(pb.written());
    const token = s.get("auth_token");
    if (token.len > 0) {
        // A bare token becomes a bearer credential; "Scheme value" is sent as is.
        const v = if (std.mem.indexOfScalar(u8, token, ' ') == null) try std.fmt.allocPrint(gpa, "Bearer {s}", .{token}) else try gpa.dupe(u8, token);
        defer gpa.free(v);
        self.auth = try self.own(v);
    }
    if (std.mem.indexOfAny(u8, self.auth, "\r\n") != null or std.mem.indexOfAny(u8, self.path, "\r\n ") != null) return error.InvalidConfig;
    return .{ .ctx = self, .vtable = &vtable };
}

fn hostHeader(gpa: std.mem.Allocator, host: []const u8, port: ?u16) error{OutOfMemory}![]u8 {
    const v6 = std.mem.indexOfScalar(u8, host, ':') != null;
    if (port) |p| return if (v6) std.fmt.allocPrint(gpa, "[{s}]:{d}", .{ host, p }) else std.fmt.allocPrint(gpa, "{s}:{d}", .{ host, p });
    return if (v6) std.fmt.allocPrint(gpa, "[{s}]", .{host}) else gpa.dupe(u8, host);
}

test "settings validation" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidConfig, create(a, .{ .kvs = &.{.{ .key = "endpoint", .value = "ftp://x" }} }));
    try std.testing.expectError(error.InvalidConfig, create(a, .{}));
    const c = try create(a, .{ .kvs = &.{ .{ .key = "endpoint", .value = "http://127.0.0.1:1/hook?x=1" }, .{ .key = "auth_token", .value = "tok" } } });
    defer c.deinit();
    const w: *Webhook = @ptrCast(@alignCast(c.ctx));
    try std.testing.expectEqualStrings("/hook?x=1", w.path);
    try std.testing.expectEqualStrings("Bearer tok", w.auth);
    try std.testing.expectEqualStrings("127.0.0.1:1", w.host_header);
    try std.testing.expectError(error.Unreachable, c.send(&.{ .body = "{}" }));
}

test "posts to a local receiver" {
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{});
    defer srv.deinit();
    var got: [512]u8 = undefined;
    var got_len: usize = 0;
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.net.Server, buf: []u8, n: *usize) void {
            const conn = s.accept() catch return;
            defer conn.stream.close();
            while (n.* < buf.len) {
                const k = conn.stream.read(buf[n.*..]) catch return;
                if (k == 0) break;
                n.* += k;
                if (std.mem.indexOf(u8, buf[0..n.*], "{\"a\":1}") != null) break;
            }
            _ = conn.stream.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") catch {};
        }
    }.run, .{ &srv, &got, &got_len });
    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/in", .{srv.listen_address.getPort()});
    defer std.testing.allocator.free(url);
    const c = try create(std.testing.allocator, .{ .kvs = &.{.{ .key = "endpoint", .value = url }} });
    defer c.deinit();
    try c.send(&.{ .body = "{\"a\":1}" });
    t.join();
    try std.testing.expect(std.mem.startsWith(u8, got[0..got_len], "POST /in HTTP/1.1\r\n"));
}
