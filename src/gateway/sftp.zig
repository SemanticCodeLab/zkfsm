//! SFTP gateway: an SSH-2 server (transport, user authentication, session
//! channels) whose only subsystem is SFTP v3 over the gateway file view.
const std = @import("std");
const posix = std.posix;
const root = @import("root.zig");
const listener_mod = @import("listener.zig");
const fs_mod = @import("fs.zig");
const wire = @import("ssh_wire.zig");
const keys = @import("ssh_keys.zig");
const transport = @import("ssh_transport.zig");
const proto = @import("sftp_proto.zig");
const server = @import("sftp_server.zig");

const Transport = transport.Transport;

pub const max_host_keys = 4;

pub const Config = struct {
    listen: ?std.net.Address = null,
    host_key_files: [max_host_keys][]const u8 = undefined,
    host_key_count: usize = 0,
    authorized_keys: ?[]const u8 = null,
    rekey_bytes: u64 = 1 << 30,
    max_file: u64 = 5 * 1024 * 1024 * 1024,

    pub fn enabled(c: Config) bool {
        return c.listen != null;
    }
};

pub const usage =
    \\  --sftp HOST:PORT SFTP gateway (SSH-2 with the sftp subsystem; password = secret key)
    \\  --sftp-host-key FILE  host key: openssh ed25519 or PEM RSA; repeatable (default:
    \\                   generated ed25519 kept in the first drive's .zkfsm)
    \\  --sftp-authorized-keys FILE  public keys, one per line: ACCESS-KEY TYPE BASE64 [COMMENT]
    \\  --sftp-rekey-bytes N  re-exchange keys after N bytes (default: 1 GiB)
    \\  --sftp-max-file N  largest file accepted for upload (default: 5 GiB)
    \\
;

/// Consumes `flag value` when it belongs to this gateway.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) root.FlagError!bool {
    if (std.mem.eql(u8, flag, "--sftp")) {
        cfg.listen = listener_mod.parseAddr(value) catch return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--sftp-host-key")) {
        if (cfg.host_key_count == max_host_keys or value.len == 0) return error.BadArgs;
        cfg.host_key_files[cfg.host_key_count] = value;
        cfg.host_key_count += 1;
    } else if (std.mem.eql(u8, flag, "--sftp-authorized-keys")) {
        if (value.len == 0) return error.BadArgs;
        cfg.authorized_keys = value;
    } else if (std.mem.eql(u8, flag, "--sftp-rekey-bytes")) {
        cfg.rekey_bytes = std.fmt.parseInt(u64, value, 10) catch return error.BadArgs;
        if (cfg.rekey_bytes < 64 * 1024) return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--sftp-max-file")) {
        cfg.max_file = std.fmt.parseInt(u64, value, 10) catch return error.BadArgs;
    } else return false;
    return true;
}

const host_key_name = "sftp_host_ed25519_key";
const max_auth_failures = 6;
const max_user = 128;
const max_channels = 4;
const window_size: u32 = 2 * 1024 * 1024;
const channel_max_packet: u32 = 64 * 1024;

pub const Server = struct {
    gpa: std.mem.Allocator,
    deps: root.Deps,
    cfg: Config,
    host_keys: [max_host_keys]keys.HostKey = undefined,
    host_key_count: usize = 0,
    spool_dir: std.fs.Dir,
    listener: listener_mod.Listener,

    pub fn start(deps: root.Deps, cfg: Config) root.StartError!*Server {
        const gpa = deps.gpa;
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .deps = deps, .cfg = cfg, .spool_dir = undefined, .listener = .{
            .name = "sftp",
            .handler = .{ .ctx = s, .serve = serve },
            .idle_timeout_s = 600,
        } };
        errdefer for (s.host_keys[0..s.host_key_count]) |*k| k.deinit(gpa);
        try s.loadHostKeys();
        s.spool_dir = openSpoolDir(gpa, deps.state_dir) catch {
            std.log.err("sftp: cannot open a spool directory", .{});
            return error.BadConfig;
        };
        errdefer s.spool_dir.close();
        for (s.host_keys[0..s.host_key_count]) |*k| {
            var fp: [64]u8 = undefined;
            std.log.info("sftp host key {s} {s}", .{ @tagName(k.*), k.fingerprint(&fp) });
        }
        try s.listener.start(cfg.listen orelse return error.BadConfig);
        return s;
    }

    pub fn stop(self: *Server) void {
        self.listener.stop(5);
        self.spool_dir.close();
        for (self.host_keys[0..self.host_key_count]) |*k| k.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    fn loadHostKeys(s: *Server) root.StartError!void {
        const gpa = s.gpa;
        for (s.cfg.host_key_files[0..s.cfg.host_key_count]) |path| {
            const text = std.fs.cwd().readFileAlloc(gpa, path, 64 * 1024) catch |e| {
                std.log.err("sftp: cannot read host key {s}: {t}", .{ path, e });
                return error.BadConfig;
            };
            defer {
                std.crypto.secureZero(u8, text);
                gpa.free(text);
            }
            s.host_keys[s.host_key_count] = keys.loadHostKey(gpa, text) catch |e| {
                std.log.err("sftp: unusable host key {s}: {t} (ed25519 in OpenSSH format or RSA in PEM)", .{ path, e });
                return error.BadConfig;
            };
            s.host_key_count += 1;
        }
        if (s.host_key_count > 0) return;
        s.host_keys[0] = .{ .ed25519 = try persistentEd25519(gpa, s.deps.state_dir) };
        s.host_key_count = 1;
    }
};

fn persistentEd25519(gpa: std.mem.Allocator, state_dir: ?[]const u8) root.StartError!std.crypto.sign.Ed25519.KeyPair {
    const Ed = std.crypto.sign.Ed25519;
    const dir_path = state_dir orelse {
        std.log.warn("sftp: no state directory; using an ephemeral host key (clients will see it change)", .{});
        return Ed.KeyPair.generate();
    };
    var dir = std.fs.cwd().makeOpenPath(dir_path, .{}) catch {
        std.log.err("sftp: cannot open state directory {s}", .{dir_path});
        return error.BadConfig;
    };
    defer dir.close();
    if (dir.readFileAlloc(gpa, host_key_name, 64 * 1024)) |text| {
        defer {
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }
        var k = keys.loadHostKey(gpa, text) catch {
            std.log.err("sftp: corrupt host key {s}/{s}", .{ dir_path, host_key_name });
            return error.BadConfig;
        };
        if (k != .ed25519) {
            k.deinit(gpa);
            return error.BadConfig;
        }
        return k.ed25519;
    } else |e| if (e != error.FileNotFound) {
        std.log.err("sftp: cannot read host key in {s}: {t}", .{ dir_path, e });
        return error.BadConfig;
    }
    const kp = Ed.KeyPair.generate();
    var buf: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const text = keys.encodeOpenSsh(kp, &buf) catch return error.BadConfig;
    const f = dir.createFile(host_key_name, .{ .exclusive = true, .mode = 0o600 }) catch {
        std.log.err("sftp: cannot create host key in {s}", .{dir_path});
        return error.BadConfig;
    };
    defer f.close();
    f.writeAll(text) catch return error.BadConfig;
    std.log.info("sftp: generated host key {s}/{s}", .{ dir_path, host_key_name });
    return kp;
}

fn openSpoolDir(gpa: std.mem.Allocator, state_dir: ?[]const u8) !std.fs.Dir {
    if (state_dir) |d| {
        const p = try std.fs.path.join(gpa, &.{ d, "sftp-spool" });
        defer gpa.free(p);
        return std.fs.cwd().makeOpenPath(p, .{});
    }
    const tmp = posix.getenv("TMPDIR") orelse "/tmp";
    return std.fs.cwd().openDir(tmp, .{});
}

fn serve(ctx: *anyopaque, conn: std.net.Server.Connection) void {
    const s: *Server = @ptrCast(@alignCast(ctx));
    defer conn.stream.close();
    var t = Transport.init(s.gpa, conn.stream.handle, .{
        .host_keys = s.host_keys[0..s.host_key_count],
        .rekey_bytes = s.cfg.rekey_bytes,
    }) catch return;
    defer t.deinit();
    const c = s.gpa.create(Conn) catch return;
    defer s.gpa.destroy(c);
    c.* = .{ .srv = s, .t = &t, .peer = conn.address };
    defer c.deinit();
    c.run() catch |e| {
        switch (e) {
            error.Protocol => t.disconnect(transport.reason_protocol_error, "protocol error"),
            error.BadMac => t.disconnect(transport.reason_mac_error, "bad packet authentication"),
            error.NoCommonAlgorithm => t.disconnect(transport.reason_kex_failed, "no common algorithm"),
            error.TooManyFailures => t.disconnect(transport.reason_no_more_auth, "too many authentication failures"),
            else => {},
        }
        std.log.debug("sftp: {f}: session ended: {t}", .{ conn.address, e });
    };
}

const msg = struct {
    const userauth_request: u8 = 50;
    const userauth_failure: u8 = 51;
    const userauth_success: u8 = 52;
    const userauth_pk_ok: u8 = 60;
    const channel_open: u8 = 90;
    const channel_open_confirmation: u8 = 91;
    const channel_open_failure: u8 = 92;
    const channel_window_adjust: u8 = 93;
    const channel_data: u8 = 94;
    const channel_extended_data: u8 = 95;
    const channel_eof: u8 = 96;
    const channel_close: u8 = 97;
    const channel_request: u8 = 98;
    const channel_success: u8 = 99;
    const channel_failure: u8 = 100;
};

const Channel = struct {
    peer: u32 = 0,
    remote_window: u64 = 0,
    remote_max: u32 = 0,
    local_window: u32 = window_size,
    consumed: u32 = 0,
    in: std.ArrayList(u8) = .empty,
    in_start: usize = 0,
    sftp: ?*server.Session = null,
    eof_sent: bool = false,
    close_recv: bool = false,
    close_sent: bool = false,
};

const ConnError = transport.Error || error{TooManyFailures};

const Conn = struct {
    srv: *Server,
    t: *Transport,
    peer: std.net.Address,
    fs: ?fs_mod.Fs = null,
    channels: [max_channels]?*Channel = @splat(null),
    scratch: [channel_max_packet + 64]u8 = undefined,

    fn deinit(c: *Conn) void {
        for (&c.channels) |*slot| if (slot.*) |ch| {
            c.freeChannel(ch);
            slot.* = null;
        };
    }

    fn freeChannel(c: *Conn, ch: *Channel) void {
        if (ch.sftp) |ss| {
            ss.deinit();
            c.srv.gpa.destroy(ss);
        }
        ch.in.deinit(c.srv.gpa);
        c.srv.gpa.destroy(ch);
    }

    fn run(c: *Conn) ConnError!void {
        try c.t.handshake();
        try c.authenticate();
        while (true) {
            const m = try c.t.read();
            try c.dispatch(m);
            for (&c.channels) |*slot| if (slot.*) |ch| {
                if (!ch.close_recv) c.process(ch) catch |e| switch (e) {
                    error.ChannelGone => {},
                    else => |x| return x,
                };
                if (ch.close_recv) {
                    c.freeChannel(ch);
                    slot.* = null;
                }
            };
        }
    }

    // ---- authentication ----

    fn authenticate(c: *Conn) ConnError!void {
        const first = try c.t.read();
        var r = wire.Reader.init(first);
        if ((r.byte() catch 0) != transport.msg_service_request) return error.Protocol;
        const svc = r.stringMax(64) catch return error.Protocol;
        if (!std.mem.eql(u8, svc, "ssh-userauth")) return error.Protocol;
        var ab: [32]u8 = undefined;
        var aw = wire.Writer.init(&ab);
        aw.byte(transport.msg_service_accept) catch return error.Protocol;
        aw.string("ssh-userauth") catch return error.Protocol;
        try c.t.write(aw.written());

        var failures: u32 = 0;
        while (true) {
            const m = try c.t.read();
            if (m[0] != msg.userauth_request) {
                try c.t.unimplemented();
                continue;
            }
            switch (try c.authAttempt(m)) {
                .success => {
                    try c.t.write(&.{msg.userauth_success});
                    return;
                },
                .pk_ok => {},
                .failure => |counted| {
                    if (counted) {
                        failures += 1;
                        if (failures >= max_auth_failures) return error.TooManyFailures;
                    }
                    try c.authFailure();
                },
            }
        }
    }

    fn authFailure(c: *Conn) ConnError!void {
        var b: [64]u8 = undefined;
        var w = wire.Writer.init(&b);
        w.byte(msg.userauth_failure) catch return error.Protocol;
        w.string(if (c.srv.cfg.authorized_keys != null) "publickey,password" else "password") catch return error.Protocol;
        w.boolean(false) catch return error.Protocol;
        try c.t.write(w.written());
    }

    const AuthResult = union(enum) { success, pk_ok, failure: bool };

    fn authAttempt(c: *Conn, m: []const u8) ConnError!AuthResult {
        var r = wire.Reader.init(m[1..]);
        const user = r.stringMax(max_user) catch return error.Protocol;
        const service = r.stringMax(64) catch return error.Protocol;
        const method = r.stringMax(64) catch return error.Protocol;
        if (!std.mem.eql(u8, service, "ssh-connection")) return .{ .failure = true };
        const acc = c.srv.deps.access;
        if (std.mem.eql(u8, method, "password")) {
            const change = r.boolean() catch return error.Protocol;
            const pw = r.stringMax(1024) catch return error.Protocol;
            if (change) return .{ .failure = true };
            if (acc.login(user, pw)) |p| {
                c.fs = .{ .access = acc, .who = p, .peer = c.peer, .secure = true };
                return .success;
            }
            std.log.info("sftp: {f}: password login failed for {s}", .{ c.peer, user });
            std.Thread.sleep(200 * std.time.ns_per_ms);
            return .{ .failure = true };
        }
        if (std.mem.eql(u8, method, "publickey")) return c.publicKey(user, &r);
        return .{ .failure = false };
    }

    fn publicKey(c: *Conn, user: []const u8, r: *wire.Reader) ConnError!AuthResult {
        const has_sig = r.boolean() catch return error.Protocol;
        const alg_name = r.stringMax(64) catch return error.Protocol;
        const blob = r.stringMax(8192) catch return error.Protocol;
        const path = c.srv.cfg.authorized_keys orelse return .{ .failure = true };
        const alg = keys.SigAlg.parse(alg_name) orelse return .{ .failure = true };
        const kt = keys.blobType(blob) orelse return .{ .failure = true };
        const want_kt = if (alg == .ssh_ed25519) "ssh-ed25519" else "ssh-rsa";
        if (!std.mem.eql(u8, kt, want_kt)) return .{ .failure = true };
        const gpa = c.srv.gpa;
        const text = std.fs.cwd().readFileAlloc(gpa, path, keys.max_authorized_file) catch {
            std.log.warn("sftp: cannot read authorized keys {s}", .{path});
            return .{ .failure = true };
        };
        defer gpa.free(text);
        if (!keys.authorized(text, user, blob)) return .{ .failure = true };
        const who = c.srv.deps.access.known(user) orelse return .{ .failure = true };
        if (!has_sig) {
            var b: [8192 + 128]u8 = undefined;
            var w = wire.Writer.init(&b);
            w.byte(msg.userauth_pk_ok) catch return error.Protocol;
            w.string(alg_name) catch return error.Protocol;
            w.string(blob) catch return error.Protocol;
            try c.t.write(w.written());
            return .pk_ok;
        }
        const sig = r.stringMax(keys.max_sig_blob) catch return error.Protocol;
        // RFC 4252 section 7: the signed data.
        var sb: [8192 + 512]u8 = undefined;
        var w = wire.Writer.init(&sb);
        const sid = c.t.sessionId();
        w.string(&sid) catch return error.Protocol;
        w.byte(msg.userauth_request) catch return error.Protocol;
        w.string(user) catch return error.Protocol;
        w.string("ssh-connection") catch return error.Protocol;
        w.string("publickey") catch return error.Protocol;
        w.boolean(true) catch return error.Protocol;
        w.string(alg_name) catch return error.Protocol;
        w.string(blob) catch return error.Protocol;
        if (!keys.verify(alg_name, blob, sig, w.written())) {
            std.log.info("sftp: {f}: bad public key signature for {s}", .{ c.peer, user });
            return .{ .failure = true };
        }
        c.fs = .{ .access = c.srv.deps.access, .who = who, .peer = c.peer, .secure = true };
        return .success;
    }

    // ---- connection protocol ----

    fn channelOf(c: *Conn, id: u32) ?*Channel {
        if (id >= max_channels) return null;
        const ch = c.channels[id] orelse return null;
        return if (ch.close_recv) null else ch;
    }

    fn dispatch(c: *Conn, m: []const u8) ConnError!void {
        var r = wire.Reader.init(m[1..]);
        switch (m[0]) {
            transport.msg_global_request => {
                _ = r.stringMax(256) catch return error.Protocol;
                const want = r.boolean() catch return error.Protocol;
                if (want) try c.t.write(&.{transport.msg_request_failure});
            },
            msg.userauth_request => {}, // RFC 4252 5.1: ignored after success
            msg.channel_open => try c.open(&r),
            msg.channel_request => try c.request(&r),
            msg.channel_window_adjust => {
                const id = r.u32be() catch return error.Protocol;
                const n = r.u32be() catch return error.Protocol;
                if (c.channelOf(id)) |ch| ch.remote_window = @min(ch.remote_window + n, std.math.maxInt(u32));
            },
            msg.channel_data, msg.channel_extended_data => {
                const id = r.u32be() catch return error.Protocol;
                if (m[0] == msg.channel_extended_data) _ = r.u32be() catch return error.Protocol;
                const data = r.string() catch return error.Protocol;
                const ch = c.channelOf(id) orelse return;
                if (data.len > ch.local_window or data.len > channel_max_packet) return error.Protocol;
                ch.local_window -= @intCast(data.len);
                if (m[0] == msg.channel_extended_data or ch.sftp == null) {
                    ch.consumed += @intCast(data.len);
                    return;
                }
                try ch.in.appendSlice(c.srv.gpa, data);
            },
            msg.channel_eof => {
                const id = r.u32be() catch return error.Protocol;
                if (c.channelOf(id)) |ch| try c.closeChannel(ch);
            },
            msg.channel_close => {
                const id = r.u32be() catch return error.Protocol;
                if (c.channelOf(id)) |ch| {
                    try c.closeChannel(ch);
                    ch.close_recv = true;
                }
            },
            msg.channel_success, msg.channel_failure, msg.channel_open_confirmation, msg.channel_open_failure => {},
            else => try c.t.unimplemented(),
        }
    }

    fn open(c: *Conn, r: *wire.Reader) ConnError!void {
        const kind = r.stringMax(64) catch return error.Protocol;
        const sender = r.u32be() catch return error.Protocol;
        const win = r.u32be() catch return error.Protocol;
        const maxp = r.u32be() catch return error.Protocol;
        var b: [128]u8 = undefined;
        var w = wire.Writer.init(&b);
        const slot: ?usize = for (c.channels, 0..) |ch, i| {
            if (ch == null) break i;
        } else null;
        if (!std.mem.eql(u8, kind, "session") or slot == null) {
            w.byte(msg.channel_open_failure) catch return error.Protocol;
            w.u32be(sender) catch return error.Protocol;
            w.u32be(if (slot == null) 4 else 3) catch return error.Protocol;
            w.string(if (slot == null) "too many channels" else "only session channels") catch return error.Protocol;
            w.string("") catch return error.Protocol;
            return c.t.write(w.written());
        }
        const ch = try c.srv.gpa.create(Channel);
        ch.* = .{ .peer = sender, .remote_window = win, .remote_max = @max(maxp, 1) };
        c.channels[slot.?] = ch;
        w.byte(msg.channel_open_confirmation) catch return error.Protocol;
        w.u32be(sender) catch return error.Protocol;
        w.u32be(@intCast(slot.?)) catch return error.Protocol;
        w.u32be(window_size) catch return error.Protocol;
        w.u32be(channel_max_packet) catch return error.Protocol;
        try c.t.write(w.written());
    }

    fn request(c: *Conn, r: *wire.Reader) ConnError!void {
        const id = r.u32be() catch return error.Protocol;
        const kind = r.stringMax(64) catch return error.Protocol;
        const want = r.boolean() catch return error.Protocol;
        const ch = c.channelOf(id) orelse return;
        var ok = false;
        if (std.mem.eql(u8, kind, "subsystem")) {
            const name = r.stringMax(64) catch return error.Protocol;
            if (std.mem.eql(u8, name, "sftp") and ch.sftp == null) {
                const ss = try c.srv.gpa.create(server.Session);
                errdefer c.srv.gpa.destroy(ss);
                ss.* = try server.Session.init(c.srv.gpa, c.fs.?, c.srv.spool_dir, .{ .max_file = c.srv.cfg.max_file, .max_handles = 32 });
                ch.sftp = ss;
                ok = true;
            }
        }
        if (!want) return;
        var b: [8]u8 = undefined;
        b[0] = if (ok) msg.channel_success else msg.channel_failure;
        std.mem.writeInt(u32, b[1..5], ch.peer, .big);
        try c.t.write(b[0..5]);
    }

    fn closeChannel(c: *Conn, ch: *Channel) ConnError!void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u32, b[1..5], ch.peer, .big);
        if (!ch.eof_sent) {
            b[0] = msg.channel_eof;
            try c.t.write(b[0..5]);
            ch.eof_sent = true;
        }
        if (!ch.close_sent) {
            b[0] = msg.channel_close;
            try c.t.write(b[0..5]);
            ch.close_sent = true;
        }
    }

    const ProcessError = ConnError || error{ChannelGone};

    /// Runs every complete SFTP request buffered on `ch`.
    fn process(c: *Conn, ch: *Channel) ProcessError!void {
        const ss = ch.sftp orelse return c.adjust(ch);
        while (!ch.close_sent) {
            const avail = ch.in.items[ch.in_start..];
            if (avail.len < 4) break;
            const len = std.mem.readInt(u32, avail[0..4], .big);
            if (len == 0 or len > proto.max_packet) {
                try c.closeChannel(ch);
                break;
            }
            if (avail.len < 4 + len) break;
            const reply = ss.handle(avail[4..][0..len]);
            ch.in_start += 4 + len;
            ch.consumed += 4 + len;
            try c.sendData(ch, reply);
        }
        if (ch.in_start > 0) {
            const rest = ch.in.items.len - ch.in_start;
            std.mem.copyForwards(u8, ch.in.items[0..rest], ch.in.items[ch.in_start..]);
            ch.in.shrinkRetainingCapacity(rest);
            ch.in_start = 0;
        }
        try c.adjust(ch);
    }

    fn adjust(c: *Conn, ch: *Channel) ConnError!void {
        if (ch.consumed < window_size / 2 or ch.close_sent) return;
        var b: [9]u8 = undefined;
        b[0] = msg.channel_window_adjust;
        std.mem.writeInt(u32, b[1..5], ch.peer, .big);
        std.mem.writeInt(u32, b[5..9], ch.consumed, .big);
        ch.local_window += ch.consumed;
        ch.consumed = 0;
        try c.t.write(&b);
    }

    /// Sends `data` within the peer's window, reading (not processing) input while blocked.
    fn sendData(c: *Conn, ch: *Channel, data: []const u8) ProcessError!void {
        var off: usize = 0;
        while (off < data.len) {
            while (ch.remote_window == 0) {
                if (ch.close_recv or ch.close_sent) return error.ChannelGone;
                const m = try c.t.read();
                try c.dispatch(m);
            }
            if (ch.close_recv or ch.close_sent) return error.ChannelGone;
            const n: usize = @intCast(@min(data.len - off, ch.remote_window, ch.remote_max, channel_max_packet));
            var w = wire.Writer.init(&c.scratch);
            w.byte(msg.channel_data) catch return error.Protocol;
            w.u32be(ch.peer) catch return error.Protocol;
            w.string(data[off..][0..n]) catch return error.Protocol;
            try c.t.write(w.written());
            ch.remote_window -= n;
            off += n;
        }
    }
};

test "flags" {
    var cfg: Config = .{};
    try std.testing.expect(try parseFlag(&cfg, "--sftp", "127.0.0.1:2222"));
    try std.testing.expect(cfg.enabled());
    try std.testing.expect(try parseFlag(&cfg, "--sftp-host-key", "/k1"));
    try std.testing.expect(try parseFlag(&cfg, "--sftp-host-key", "/k2"));
    try std.testing.expectEqual(@as(usize, 2), cfg.host_key_count);
    try std.testing.expect(try parseFlag(&cfg, "--sftp-authorized-keys", "/ak"));
    try std.testing.expect(!try parseFlag(&cfg, "--ftp", "x"));
    try std.testing.expectError(error.BadArgs, parseFlag(&cfg, "--sftp", "nope"));
    try std.testing.expectError(error.BadArgs, parseFlag(&cfg, "--sftp-rekey-bytes", "10"));
}

test {
    _ = @import("ssh_wire.zig");
    _ = @import("ssh_cipher.zig");
    _ = @import("ssh_keys.zig");
    _ = @import("ssh_kex.zig");
    _ = @import("ssh_transport.zig");
    _ = @import("sftp_proto.zig");
    _ = @import("sftp_server.zig");
}
