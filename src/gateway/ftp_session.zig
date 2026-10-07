//! One FTP control connection: login, path state, passive data channels, and
//! the command loop. Objects are reached only through the gateway Fs view.
const std = @import("std");
const posix = std.posix;
const tls = @import("../tls/root.zig");
const root = @import("root.zig");
const fs = @import("fs.zig");
const listener = @import("listener.zig");
const proto = @import("ftp_proto.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Settings a session needs from the server.
pub const Env = struct {
    deps: root.Deps,
    passive_lo: u16 = 0,
    passive_hi: u16 = 0,
    public_ip: ?[4]u8 = null,
    require_tls: bool = false,
    idle_timeout_s: u32 = 300,
    /// Rotates the start of the passive port search.
    next_port: *std.atomic.Value(u32),
};

const data_accept_ms = 20_000;
const max_list_entries = 200_000;
const list_page = 1000;
const max_stat_entries = 1000;
/// APPE rewrites the object, so old + new bytes are spooled in memory up to this.
pub const max_append_spool = 64 * 1024 * 1024;
const max_login_failures = 3;
const max_user = 256;

/// Passive data socket plus its stream buffers; heap allocated (stable addresses).
const Data = struct {
    gpa: std.mem.Allocator,
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    sw: std.net.Stream.Writer,
    secure: ?*tls.Session = null,
    rbuf: [16 * 1024]u8,
    wbuf: [64 * 1024]u8,

    fn reader(d: *Data) *Reader {
        return if (d.secure) |t| &t.reader else d.sr.interface();
    }

    fn writer(d: *Data) *Writer {
        return if (d.secure) |t| &t.writer else &d.sw.interface;
    }

    /// Flushes (unless `ok` is false), sends close_notify under TLS, closes.
    fn finish(d: *Data, ok: bool) void {
        if (d.secure) |t| t.close();
        if (ok) d.sw.interface.flush() catch {};
        d.stream.close();
        d.gpa.destroy(d);
    }
};

const DataError = error{ NoPassive, Timeout, Failed, TlsFailed, OutOfMemory };

pub const Session = struct {
    env: *const Env,
    gpa: std.mem.Allocator,
    stream: std.net.Stream,
    peer: std.net.Address,
    local: std.net.Address,
    raw_r: std.net.Stream.Reader,
    raw_w: std.net.Stream.Writer,
    in: *Reader,
    out: *Writer,
    ctl_tls: ?*tls.Session = null,
    prot_p: bool = false,
    pbsz: bool = false,

    user_buf: [max_user]u8 = undefined,
    user_len: usize = 0,
    who: ?root.Principal = null,
    failures: u8 = 0,
    cwd_buf: [fs.max_path]u8 = undefined,
    cwd_len: usize = 1,
    rest: u64 = 0,
    rnfr_buf: [fs.max_path]u8 = undefined,
    rnfr_len: ?usize = null,
    pasv: ?std.net.Server = null,
    quit: bool = false,

    fn cwd(s: *const Session) []const u8 {
        return s.cwd_buf[0..s.cwd_len];
    }

    fn view(s: *const Session) fs.Fs {
        return .{ .access = s.env.deps.access, .who = s.who.?, .peer = s.peer, .secure = s.ctl_tls != null };
    }

    // ---- replies ----

    fn reply(s: *Session, code: u16, msg: []const u8) void {
        s.out.print("{d} {s}\r\n", .{ code, msg }) catch {};
        s.out.flush() catch {};
    }

    fn replyFmt(s: *Session, code: u16, comptime f: []const u8, args: anytype) void {
        s.out.print("{d} ", .{code}) catch {};
        s.out.print(f, args) catch {};
        s.out.writeAll("\r\n") catch {};
        s.out.flush() catch {};
    }

    fn replyFs(s: *Session, e: fs.Error) void {
        switch (e) {
            error.NotFound => s.reply(550, "No such file or directory."),
            error.Exists => s.reply(550, "File exists."),
            error.NotEmpty => s.reply(550, "Directory not empty."),
            error.Denied => s.reply(550, "Permission denied."),
            error.InvalidPath => s.reply(553, "Invalid file name."),
            error.IsDir => s.reply(550, "Is a directory."),
            error.NotDir => s.reply(550, "Not a directory."),
            error.TooLarge => s.reply(552, "Too large."),
            error.QuotaExceeded => s.reply(552, "Quota exceeded."),
            error.ReadFailed, error.WriteFailed => s.reply(426, "Connection closed; transfer aborted."),
            error.Storage, error.OutOfMemory => s.reply(451, "Local error in processing."),
        }
    }

    // ---- entry ----

    pub fn run(env: *const Env, conn: std.net.Server.Connection, implicit: bool) void {
        const gpa = env.deps.gpa;
        var rbuf: [proto.max_line]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var s: Session = .{
            .env = env,
            .gpa = gpa,
            .stream = conn.stream,
            .peer = conn.address,
            .local = localAddr(conn.stream) orelse conn.address,
            .raw_r = conn.stream.reader(&rbuf),
            .raw_w = conn.stream.writer(&wbuf),
            .in = undefined,
            .out = undefined,
        };
        s.in = s.raw_r.interface();
        s.out = &s.raw_w.interface;
        s.cwd_buf[0] = '/';
        defer s.close();
        if (implicit) {
            const ctx = env.deps.tls orelse return;
            if (!s.startTls(ctx)) return;
            s.prot_p = true;
            s.pbsz = true;
        }
        s.reply(220, "zkfsm FTP server ready.");
        s.loop();
    }

    fn close(s: *Session) void {
        s.dropPassive();
        if (s.ctl_tls) |t| t.close();
        s.raw_w.interface.flush() catch {};
        s.stream.close();
    }

    fn startTls(s: *Session, ctx: *tls.Context) bool {
        const t = tls.Session.accept(s.gpa, ctx, s.raw_r.interface(), &s.raw_w.interface) catch |e| {
            std.log.debug("ftp: tls handshake failed: {t}", .{e});
            return false;
        };
        s.ctl_tls = t;
        s.in = &t.reader;
        s.out = &t.writer;
        return true;
    }

    fn loop(s: *Session) void {
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        while (!s.quit) {
            const raw = s.in.takeDelimiterInclusive('\n') catch |e| switch (e) {
                error.StreamTooLong => {
                    s.reply(500, "Command line too long.");
                    return;
                },
                error.EndOfStream, error.ReadFailed => return,
            };
            if (raw.len > proto.max_line) {
                s.reply(500, "Command line too long.");
                return;
            }
            const line = std.mem.trimRight(u8, raw, "\r\n");
            const cmd = proto.parse(line) catch {
                s.reply(500, "Syntax error.");
                continue;
            };
            _ = arena_state.reset(.retain_capacity);
            const keep_rest = cmd.verb == .REST;
            const keep_rnfr = cmd.verb == .RNFR;
            s.dispatch(arena_state.allocator(), cmd);
            if (!keep_rest) s.rest = 0;
            if (!keep_rnfr) s.rnfr_len = null;
        }
    }

    fn dispatch(s: *Session, arena: std.mem.Allocator, cmd: proto.Command) void {
        const verb = cmd.verb orelse {
            s.replyFmt(500, "Unknown command '{s}'.", .{cmd.raw});
            return;
        };
        switch (verb) {
            .USER, .PASS, .AUTH, .PBSZ, .PROT, .FEAT, .SYST, .QUIT, .NOOP, .HELP, .OPTS, .CCC, .ACCT => {},
            else => if (s.who == null) {
                s.reply(530, "Please login with USER and PASS.");
                return;
            },
        }
        switch (verb) {
            .USER => s.cmdUser(cmd.arg),
            .PASS => s.cmdPass(cmd.arg),
            .ACCT => s.reply(202, "ACCT not needed."),
            .SYST => s.reply(215, "UNIX Type: L8"),
            .FEAT => s.cmdFeat(),
            .OPTS => s.cmdOpts(cmd.arg),
            .PWD, .XPWD => {
                s.out.writeAll("257 ") catch {};
                proto.writeQuoted(s.out, s.cwd()) catch {};
                s.out.writeAll(" is the current directory.\r\n") catch {};
                s.out.flush() catch {};
            },
            .CWD, .XCWD => s.cmdCwd(arena, cmd.arg),
            .CDUP, .XCUP => s.cmdCwd(arena, ".."),
            .TYPE => {
                const t = std.mem.trim(u8, cmd.arg, " ");
                if (t.len > 0 and (std.ascii.toUpper(t[0]) == 'I' or std.ascii.toUpper(t[0]) == 'A' or std.ascii.toUpper(t[0]) == 'L')) {
                    s.reply(200, "Type set.");
                } else s.reply(504, "Type not supported.");
            },
            .MODE => if (std.ascii.eqlIgnoreCase(cmd.arg, "S")) s.reply(200, "Mode set to S.") else s.reply(504, "Only stream mode is supported."),
            .STRU => if (std.ascii.eqlIgnoreCase(cmd.arg, "F")) s.reply(200, "Structure set to F.") else s.reply(504, "Only file structure is supported."),
            .PASV => s.cmdPasv(false, cmd.arg),
            .EPSV => s.cmdPasv(true, cmd.arg),
            .PORT, .EPRT => s.reply(502, "Active mode is not supported; use PASV or EPSV."),
            .LIST => s.cmdList(arena, cmd.arg, .list),
            .NLST => s.cmdList(arena, cmd.arg, .nlst),
            .MLSD => s.cmdList(arena, cmd.arg, .mlsd),
            .MLST => s.cmdMlst(arena, cmd.arg),
            .RETR => s.cmdRetr(arena, cmd.arg),
            .REST => {
                s.rest = std.fmt.parseInt(u64, std.mem.trim(u8, cmd.arg, " "), 10) catch {
                    s.reply(501, "Invalid restart offset.");
                    return;
                };
                s.replyFmt(350, "Restarting at {d}. Send RETR to resume.", .{s.rest});
            },
            .STOR => s.cmdStor(arena, cmd.arg, false),
            .APPE => s.cmdStor(arena, cmd.arg, true),
            .STOU => s.reply(502, "STOU not supported."),
            .DELE => s.cmdSimple(arena, cmd.arg, .dele),
            .MKD, .XMKD => s.cmdSimple(arena, cmd.arg, .mkd),
            .RMD, .XRMD => s.cmdSimple(arena, cmd.arg, .rmd),
            .RNFR => s.cmdRnfr(arena, cmd.arg),
            .RNTO => s.cmdRnto(arena, cmd.arg),
            .SIZE => s.cmdSizeMdtm(arena, cmd.arg, true),
            .MDTM => s.cmdSizeMdtm(arena, cmd.arg, false),
            .NOOP => s.reply(200, "NOOP ok."),
            .QUIT => {
                s.reply(221, "Goodbye.");
                s.quit = true;
            },
            .ABOR => {
                s.dropPassive();
                s.reply(225, "No transfer to abort.");
            },
            .STAT => s.cmdStat(arena, cmd.arg),
            .HELP => {
                s.out.writeAll("214-Commands recognized:\r\n" ++
                    " USER PASS SYST FEAT OPTS PWD CWD CDUP TYPE MODE STRU PASV EPSV\r\n" ++
                    " LIST NLST MLSD MLST RETR REST STOR APPE DELE MKD RMD RNFR RNTO\r\n" ++
                    " SIZE MDTM NOOP QUIT ABOR STAT HELP AUTH PBSZ PROT\r\n" ++
                    "214 Help OK.\r\n") catch {};
                s.out.flush() catch {};
            },
            .AUTH => s.cmdAuth(cmd.arg),
            .PBSZ => {
                if (s.ctl_tls == null) return s.reply(503, "PBSZ requires AUTH first.");
                s.pbsz = true;
                s.reply(200, "PBSZ=0");
            },
            .PROT => s.cmdProt(cmd.arg),
            .CCC => s.reply(534, "CCC not allowed."),
            .ALLO => s.reply(202, "ALLO not needed."),
            .REIN => s.reply(502, "REIN not supported."),
            .SITE => s.reply(502, "SITE not supported."),
        }
    }

    // ---- login and security ----

    fn tlsRequired(s: *const Session) bool {
        return s.env.require_tls and s.ctl_tls == null;
    }

    fn cmdUser(s: *Session, arg: []const u8) void {
        if (s.tlsRequired()) return s.reply(530, "TLS required; send AUTH TLS first.");
        if (arg.len == 0 or arg.len > max_user) return s.reply(501, "Invalid user name.");
        @memcpy(s.user_buf[0..arg.len], arg);
        s.user_len = arg.len;
        s.who = null;
        s.reply(331, "Password required.");
    }

    fn cmdPass(s: *Session, arg: []const u8) void {
        if (s.tlsRequired()) return s.reply(530, "TLS required; send AUTH TLS first.");
        if (s.who != null) return s.reply(230, "Already logged in.");
        if (s.user_len == 0) return s.reply(503, "Send USER first.");
        if (s.env.deps.access.login(s.user_buf[0..s.user_len], arg)) |p| {
            s.who = p;
            s.failures = 0;
            s.cwd_len = 1;
            return s.reply(230, "Login successful.");
        }
        s.failures += 1;
        s.user_len = 0;
        std.Thread.sleep(200 * std.time.ns_per_ms);
        s.reply(530, "Login incorrect.");
        if (s.failures >= max_login_failures) s.quit = true;
    }

    fn cmdFeat(s: *Session) void {
        s.out.writeAll("211-Features:\r\n") catch {};
        for (proto.feat_lines) |l| s.out.print(" {s}\r\n", .{l}) catch {};
        if (s.env.deps.tls != null) for (proto.feat_tls_lines) |l| s.out.print(" {s}\r\n", .{l}) catch {};
        s.out.writeAll("211 End\r\n") catch {};
        s.out.flush() catch {};
    }

    fn cmdOpts(s: *Session, arg: []const u8) void {
        var it = std.mem.tokenizeScalar(u8, arg, ' ');
        const name = it.next() orelse return s.reply(501, "Missing option.");
        if (std.ascii.eqlIgnoreCase(name, "UTF8")) {
            const v = it.next() orelse "ON";
            if (std.ascii.eqlIgnoreCase(v, "ON")) return s.reply(200, "UTF8 mode enabled.");
            return s.reply(504, "UTF8 is always on.");
        }
        if (std.ascii.eqlIgnoreCase(name, "MLST")) return s.reply(200, "MLST OPTS type;size;modify;perm;");
        s.reply(501, "Option not understood.");
    }

    fn cmdAuth(s: *Session, arg: []const u8) void {
        if (!std.ascii.eqlIgnoreCase(arg, "TLS") and !std.ascii.eqlIgnoreCase(arg, "SSL") and !std.ascii.eqlIgnoreCase(arg, "TLS-C"))
            return s.reply(504, "Only AUTH TLS is supported.");
        if (s.ctl_tls != null) return s.reply(503, "TLS already active.");
        const ctx = s.env.deps.tls orelse return s.reply(502, "TLS not configured.");
        s.reply(234, "AUTH TLS successful.");
        if (!s.startTls(ctx)) {
            s.quit = true;
            return;
        }
        // RFC 4217: the security exchange resets the login state.
        s.who = null;
        s.user_len = 0;
    }

    fn cmdProt(s: *Session, arg: []const u8) void {
        if (s.ctl_tls == null) return s.reply(503, "PROT requires AUTH first.");
        if (!s.pbsz) return s.reply(503, "PROT requires PBSZ first.");
        if (std.ascii.eqlIgnoreCase(arg, "P")) {
            s.prot_p = true;
            return s.reply(200, "PROT now Private.");
        }
        if (std.ascii.eqlIgnoreCase(arg, "C")) {
            if (s.env.require_tls) return s.reply(534, "Policy requires PROT P.");
            s.prot_p = false;
            return s.reply(200, "PROT now Clear.");
        }
        s.reply(504, "PROT level not supported.");
    }

    // ---- paths ----

    fn resolve(s: *Session, arena: std.mem.Allocator, arg: []const u8) ?[]const u8 {
        const buf = arena.alloc(u8, fs.max_path) catch {
            s.reply(451, "Out of memory.");
            return null;
        };
        return fs.normalize(buf, s.cwd(), arg) catch {
            s.reply(553, "Invalid path.");
            return null;
        };
    }

    fn cmdCwd(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        const path = s.resolve(arena, if (arg.len == 0) "/" else arg) orelse return;
        const f = s.view();
        const st = f.stat(arena, path) catch |e| return s.replyFs(e);
        if (st.kind == .file) return s.reply(550, "Not a directory.");
        @memcpy(s.cwd_buf[0..path.len], path);
        s.cwd_len = path.len;
        s.reply(250, "Directory changed.");
    }

    const Simple = enum { dele, mkd, rmd };

    fn cmdSimple(s: *Session, arena: std.mem.Allocator, arg: []const u8, op: Simple) void {
        if (arg.len == 0) return s.reply(501, "Missing path.");
        const path = s.resolve(arena, arg) orelse return;
        const f = s.view();
        switch (op) {
            .dele => {
                f.remove(arena, path) catch |e| return s.replyFs(e);
                s.reply(250, "File deleted.");
            },
            .mkd => {
                f.mkdir(arena, path) catch |e| return s.replyFs(e);
                s.out.writeAll("257 ") catch {};
                proto.writeQuoted(s.out, path) catch {};
                s.out.writeAll(" created.\r\n") catch {};
                s.out.flush() catch {};
            },
            .rmd => {
                f.rmdir(arena, path) catch |e| return s.replyFs(e);
                s.reply(250, "Directory removed.");
            },
        }
    }

    fn cmdRnfr(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        if (arg.len == 0) return s.reply(501, "Missing path.");
        const path = s.resolve(arena, arg) orelse return;
        const f = s.view();
        _ = f.stat(arena, path) catch |e| return s.replyFs(e);
        @memcpy(s.rnfr_buf[0..path.len], path);
        s.rnfr_len = path.len;
        s.reply(350, "Ready for RNTO.");
    }

    fn cmdRnto(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        const n = s.rnfr_len orelse return s.reply(503, "Send RNFR first.");
        if (arg.len == 0) return s.reply(501, "Missing path.");
        const src = arena.dupe(u8, s.rnfr_buf[0..n]) catch return s.reply(451, "Out of memory.");
        const dst = s.resolve(arena, arg) orelse return;
        const f = s.view();
        if (f.stat(arena, dst)) |st| {
            if (st.kind != .file) return s.reply(550, "Target exists.");
        } else |e| if (e != error.NotFound) return s.replyFs(e);
        f.rename(arena, src, dst) catch |e| return s.replyFs(e);
        s.reply(250, "Rename successful.");
    }

    fn cmdSizeMdtm(s: *Session, arena: std.mem.Allocator, arg: []const u8, size: bool) void {
        if (arg.len == 0) return s.reply(501, "Missing path.");
        const path = s.resolve(arena, arg) orelse return;
        const f = s.view();
        const st = f.stat(arena, path) catch |e| return s.replyFs(e);
        if (st.kind != .file) return s.reply(550, "Not a plain file.");
        if (size) return s.replyFmt(213, "{d}", .{st.size});
        var stamp: [14]u8 = undefined;
        s.replyFmt(213, "{s}", .{proto.fmtStamp(&stamp, proto.secsOf(st.mtime_ns))});
    }

    // ---- passive data channel ----

    fn dropPassive(s: *Session) void {
        if (s.pasv) |*p| p.deinit();
        s.pasv = null;
    }

    fn cmdPasv(s: *Session, extended: bool, arg: []const u8) void {
        if (extended and std.ascii.eqlIgnoreCase(arg, "ALL")) return s.reply(200, "EPSV ALL ok.");
        s.dropPassive();
        var ip4: [4]u8 = undefined;
        if (!extended) {
            ip4 = s.env.public_ip orelse proto.ip4Of(s.local) orelse
                return s.reply(522, "PASV needs IPv4; use EPSV.");
        }
        const srv = s.listenPassive() orelse return s.reply(425, "Cannot open passive connection.");
        s.pasv = srv;
        var buf: [96]u8 = undefined;
        const port = srv.listen_address.getPort();
        const text = (if (extended) proto.epsvReply(&buf, port) else proto.pasvReply(&buf, ip4, port)) catch return s.reply(451, "Local error.");
        s.out.writeAll(text) catch {};
        s.out.writeAll("\r\n") catch {};
        s.out.flush() catch {};
    }

    fn listenPassive(s: *Session) ?std.net.Server {
        var addr = s.local;
        const lo = s.env.passive_lo;
        const hi = s.env.passive_hi;
        if (lo == 0) {
            addr.setPort(0);
            return addr.listen(.{ .reuse_address = true, .kernel_backlog = 4 }) catch null;
        }
        const span: u32 = @as(u32, hi - lo) + 1;
        const start = s.env.next_port.fetchAdd(1, .monotonic);
        var i: u32 = 0;
        while (i < @min(span, 512)) : (i += 1) {
            addr.setPort(@intCast(lo + (start +% i) % span));
            if (addr.listen(.{ .reuse_address = true, .kernel_backlog = 4 })) |srv| return srv else |_| {}
        }
        return null;
    }

    /// Accepts the client's data connection (only from the control peer's host).
    fn openData(s: *Session) DataError!*Data {
        var srv = s.pasv orelse return error.NoPassive;
        s.pasv = null;
        defer srv.deinit();
        const deadline = std.time.milliTimestamp() + data_accept_ms;
        const conn = while (true) {
            const left = deadline - std.time.milliTimestamp();
            if (left <= 0) return error.Timeout;
            var fds = [_]posix.pollfd{.{ .fd = srv.stream.handle, .events = posix.POLL.IN, .revents = 0 }};
            const n = posix.poll(&fds, @intCast(left)) catch return error.Failed;
            if (n == 0) return error.Timeout;
            const c = srv.accept() catch return error.Failed;
            if (proto.sameHost(c.address, s.peer)) break c;
            std.log.warn("ftp: rejected data connection from {f} (control peer {f})", .{ c.address, s.peer });
            c.stream.close();
        };
        listener.setTimeouts(conn.stream.handle, s.env.idle_timeout_s);
        const d = s.gpa.create(Data) catch {
            conn.stream.close();
            return error.OutOfMemory;
        };
        d.gpa = s.gpa;
        d.stream = conn.stream;
        d.secure = null;
        d.sr = conn.stream.reader(&d.rbuf);
        d.sw = conn.stream.writer(&d.wbuf);
        if (s.prot_p) {
            const ctx = s.env.deps.tls orelse {
                d.finish(false);
                return error.TlsFailed;
            };
            d.secure = tls.Session.accept(s.gpa, ctx, d.sr.interface(), &d.sw.interface) catch {
                d.finish(false);
                return error.TlsFailed;
            };
        }
        return d;
    }

    /// Checks protection policy and passive state, sends 150, opens the channel.
    fn beginTransfer(s: *Session) ?*Data {
        if (s.env.require_tls and !s.prot_p) {
            s.reply(521, "Data protection required (PROT P).");
            return null;
        }
        if (s.pasv == null) {
            s.reply(425, "Use PASV or EPSV first.");
            return null;
        }
        s.replyFmt(150, "Opening {s} data connection.", .{if (s.prot_p) "TLS" else "BINARY"});
        return s.openData() catch |e| {
            s.replyFmt(425, "Cannot open data connection ({t}).", .{e});
            return null;
        };
    }

    // ---- transfers ----

    fn cmdRetr(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        if (arg.len == 0) return s.reply(501, "Missing path.");
        const path = s.resolve(arena, arg) orelse return;
        const f = s.view();
        const info = f.openRead(arena, path) catch |e| return s.replyFs(e);
        if (s.rest > info.size) return s.reply(554, "Restart offset beyond end of file.");
        const d = s.beginTransfer() orelse return;
        const len = info.size - s.rest;
        var ok = true;
        if (len > 0) {
            const range: ?@import("../core/root.zig").Range = if (s.rest > 0) .{ .offset = s.rest, .length = len } else null;
            f.read(info, range, d.writer()) catch |e| {
                d.finish(false);
                return s.replyFs(e);
            };
            d.writer().flush() catch {
                ok = false;
            };
        }
        d.finish(ok);
        if (!ok) return s.reply(426, "Connection closed; transfer aborted.");
        s.reply(226, "Transfer complete.");
    }

    fn cmdStor(s: *Session, arena: std.mem.Allocator, arg: []const u8, append: bool) void {
        if (arg.len == 0) return s.reply(501, "Missing path.");
        if (s.rest != 0) return s.reply(504, "REST with STOR is not supported; use APPE.");
        const path = s.resolve(arena, arg) orelse return;
        const f = s.view();
        var spool: std.ArrayList(u8) = .empty;
        defer spool.deinit(s.gpa);
        if (append) {
            if (f.stat(arena, path)) |st| {
                if (st.kind != .file) return s.reply(550, "Is a directory.");
                if (st.size > max_append_spool) return s.reply(504, "APPE is limited to files up to 64 MiB.");
                const info = f.openRead(arena, path) catch |e| return s.replyFs(e);
                var aw: Writer.Allocating = .fromArrayList(s.gpa, &spool);
                f.read(info, null, &aw.writer) catch |e| {
                    spool = aw.toArrayList();
                    return s.replyFs(e);
                };
                spool = aw.toArrayList();
            } else |e| if (e != error.NotFound) return s.replyFs(e);
        }
        const d = s.beginTransfer() orelse return;
        if (append) {
            d.reader().appendRemaining(s.gpa, &spool, .limited(max_append_spool - spool.items.len + 1)) catch |e| {
                d.finish(false);
                return switch (e) {
                    error.StreamTooLong => s.reply(552, "APPE result exceeds 64 MiB."),
                    error.OutOfMemory => s.reply(451, "Out of memory."),
                    error.ReadFailed => s.reply(426, "Connection closed; transfer aborted."),
                };
            };
            if (spool.items.len > max_append_spool) {
                d.finish(false);
                return s.reply(552, "APPE result exceeds 64 MiB.");
            }
            d.finish(true);
            var src: Reader = .fixed(spool.items);
            _ = f.write(path, &src, spool.items.len, "application/octet-stream") catch |e| return s.replyFs(e);
            return s.reply(226, "Transfer complete.");
        }
        _ = f.write(path, d.reader(), null, "application/octet-stream") catch |e| {
            d.finish(false);
            return s.replyFs(e);
        };
        d.finish(true);
        s.reply(226, "Transfer complete.");
    }

    // ---- listings ----

    const ListKind = enum { list, nlst, mlsd };

    fn cmdList(s: *Session, arena: std.mem.Allocator, arg: []const u8, kind: ListKind) void {
        const a = if (kind == .mlsd) std.mem.trim(u8, arg, " ") else proto.listArg(arg);
        const path = s.resolve(arena, a) orelse return;
        const f = s.view();
        const st = f.stat(arena, path) catch |e| return s.replyFs(e);
        if (st.kind == .file and kind == .mlsd) return s.reply(501, "Not a directory.");
        // Fail before 150 when the directory itself is unreadable.
        if (st.kind != .file) _ = f.list(arena, path, "", 1) catch |e| return s.replyFs(e);
        const d = s.beginTransfer() orelse return;
        const w = d.writer();
        const now_s = std.time.timestamp();
        if (st.kind == .file) {
            writeEntry(w, kind, fs.baseName(path), .file, st.size, st.mtime_ns, now_s) catch {
                d.finish(false);
                return s.reply(426, "Connection closed; transfer aborted.");
            };
        } else {
            const err = listDir(s.gpa, f, w, path, kind, now_s, max_list_entries);
            if (err) |e| {
                d.finish(false);
                return s.replyFs(e);
            }
        }
        w.flush() catch {
            d.finish(false);
            return s.reply(426, "Connection closed; transfer aborted.");
        };
        d.finish(true);
        s.reply(226, "Transfer complete.");
    }

    fn cmdMlst(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        const path = s.resolve(arena, std.mem.trim(u8, arg, " ")) orelse return;
        const f = s.view();
        const st = f.stat(arena, path) catch |e| return s.replyFs(e);
        s.out.writeAll("250-Listing\r\n ") catch {};
        proto.writeMlsxLine(s.out, path, st.kind, st.size, st.mtime_ns, null) catch {};
        s.out.writeAll("250 End\r\n") catch {};
        s.out.flush() catch {};
    }

    fn cmdStat(s: *Session, arena: std.mem.Allocator, arg: []const u8) void {
        if (arg.len == 0) {
            s.out.print("211-zkfsm FTP status\r\n Connected from {f}\r\n Logged in as {s}\r\n TYPE: BINARY, STRU: File, MODE: Stream\r\n Data protection: {s}\r\n211 End of status\r\n", .{
                s.peer, s.who.?.accessKey(), if (s.prot_p) "private" else "clear",
            }) catch {};
            s.out.flush() catch {};
            return;
        }
        const path = s.resolve(arena, proto.listArg(arg)) orelse return;
        const f = s.view();
        const st = f.stat(arena, path) catch |e| return s.replyFs(e);
        const now_s = std.time.timestamp();
        s.out.writeAll("213-Status follows:\r\n") catch {};
        if (st.kind == .file) {
            writeEntry(s.out, .list, fs.baseName(path), .file, st.size, st.mtime_ns, now_s) catch {};
        } else if (listDir(s.gpa, f, s.out, path, .list, now_s, max_stat_entries)) |e| {
            return s.replyFs(e);
        }
        s.out.writeAll("213 End of status\r\n") catch {};
        s.out.flush() catch {};
    }
};

fn writeEntry(w: *Writer, kind: Session.ListKind, name: []const u8, k: fs.Kind, size: u64, mtime_ns: i128, now_s: i64) Writer.Error!void {
    switch (kind) {
        .list => try proto.writeListLine(w, name, k, size, mtime_ns, now_s),
        .nlst => {
            try w.writeAll(name);
            try w.writeAll("\r\n");
        },
        .mlsd => try proto.writeMlsxLine(w, name, k, size, mtime_ns, null),
    }
}

/// Streams a directory page by page; returns the error to report, if any.
fn listDir(gpa: std.mem.Allocator, f: fs.Fs, w: *Writer, path: []const u8, kind: Session.ListKind, now_s: i64, limit: usize) ?fs.Error {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var cursor_buf: [fs.max_path + 16]u8 = undefined;
    var cursor: []const u8 = "";
    var sent: usize = 0;
    while (sent < limit) {
        _ = arena_state.reset(.retain_capacity);
        const page = f.list(arena_state.allocator(), path, cursor, list_page) catch |e| return e;
        for (page.entries) |e| {
            if (sent >= limit) break;
            if (std.mem.indexOfAny(u8, e.name, "\r\n") != null and kind == .nlst) continue;
            writeEntry(w, kind, e.name, e.kind, e.size, e.mtime_ns, now_s) catch return error.WriteFailed;
            sent += 1;
        }
        const next = page.next orelse break;
        if (next.len > cursor_buf.len or next.len == 0) break;
        @memcpy(cursor_buf[0..next.len], next);
        cursor = cursor_buf[0..next.len];
    }
    return null;
}

fn localAddr(stream: std.net.Stream) ?std.net.Address {
    var addr: std.net.Address = undefined;
    var len: posix.socklen_t = @sizeOf(std.net.Address);
    posix.getsockname(stream.handle, &addr.any, &len) catch return null;
    return addr;
}
