//! Minimal LDAPv3 client for STS AssumeRoleWithLDAPIdentity: lookup-bind, search the
//! user, bind as the user, collect group DNs. Plain, StartTLS, or LDAPS. Every server
//! response is treated as hostile: message size, entry count, and nesting are bounded.
const std = @import("std");
const tls = @import("../tls/root.zig");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const limits = struct {
    pub const max_message = 1 << 20;
    pub const max_groups = 1000;
    pub const max_references = 1000;
    pub const max_filter_depth = 16;
    pub const max_filter_len = 8192;
    pub const max_dn = 4096;
};

pub const TlsMode = enum { none, starttls, ldaps };

pub const Config = struct {
    /// host:port
    server_addr: []const u8,
    tls: TlsMode = .none,
    tls_skip_verify: bool = false,
    /// PEM CA bundle file; null = system roots.
    ca_file: ?[]const u8 = null,
    /// PEM client certificate and key for servers that demand one.
    client_cert_file: []const u8 = "",
    client_key_file: []const u8 = "",
    lookup_bind_dn: []const u8,
    lookup_bind_password: []const u8,
    user_dn_search_base: []const u8,
    /// e.g. "(uid=%s)"; %s is replaced by the RFC 4515-escaped username.
    user_dn_search_filter: []const u8,
    /// Optional; empty disables group lookup.
    group_search_base: []const u8 = "",
    /// e.g. "(&(objectclass=groupOfNames)(member=%d))"; %d = escaped user DN, %s = escaped username.
    group_search_filter: []const u8 = "",
    timeout_ms: u32 = 5000,
};

/// Allocated in the caller's arena.
pub const Result = struct { user_dn: []const u8, groups: []const []const u8 };

pub const Error = error{
    OutOfMemory,
    ConnectFailed,
    TlsFailed,
    Timeout,
    ProtocolError,
    ResponseTooLarge,
    LookupBindFailed,
    InvalidCredentials,
    UserNotFound,
    AmbiguousUser,
    InvalidFilter,
    SearchFailed,
};

pub const FilterError = error{ OutOfMemory, InvalidFilter };

const tag = struct {
    const integer = 0x02;
    const octets = 0x04;
    const enumerated = 0x0a;
    const boolean = 0x01;
    const sequence = 0x30;
    const bind_request = 0x60;
    const bind_response = 0x61;
    const unbind_request = 0x42;
    const search_request = 0x63;
    const search_entry = 0x64;
    const search_done = 0x65;
    const search_reference = 0x73;
    const extended_request = 0x77;
    const extended_response = 0x78;
};

const rc_success = 0;
const rc_size_limit_exceeded = 4;
const starttls_oid = "1.3.6.1.4.1.1466.20037";

// ---------------------------------------------------------------- BER

const Tlv = struct { tag: u8, body: []const u8 };

/// Definite-length BER reader over a bounded buffer.
const Ber = struct {
    buf: []const u8,
    pos: usize = 0,

    fn done(p: *const Ber) bool {
        return p.pos >= p.buf.len;
    }

    fn next(p: *Ber) error{ProtocolError}!Tlv {
        const rest = p.buf[p.pos..];
        if (rest.len < 2) return error.ProtocolError;
        const t = rest[0];
        if (t & 0x1f == 0x1f) return error.ProtocolError;
        const l = try parseLength(rest[1..]);
        const start = 1 + l.header;
        if (l.len > rest.len - start) return error.ProtocolError;
        p.pos += start + l.len;
        return .{ .tag = t, .body = rest[start..][0..l.len] };
    }

    fn expect(p: *Ber, t: u8) error{ProtocolError}![]const u8 {
        const v = try p.next();
        if (v.tag != t) return error.ProtocolError;
        return v.body;
    }
};

const Length = struct { len: usize, header: usize };

fn parseLength(b: []const u8) error{ProtocolError}!Length {
    if (b.len == 0) return error.ProtocolError;
    if (b[0] < 0x80) return .{ .len = b[0], .header = 1 };
    const n = b[0] & 0x7f;
    // 0x80 is the indefinite form; longer than 4 bytes is never legitimate here.
    if (n == 0 or n > 4 or b.len < 1 + n) return error.ProtocolError;
    var len: u32 = 0;
    for (b[1..][0..n]) |x| len = (len << 8) | x;
    return .{ .len = len, .header = 1 + n };
}

fn decodeInt(body: []const u8) error{ProtocolError}!i32 {
    if (body.len == 0 or body.len > 4) return error.ProtocolError;
    var v: i32 = if (body[0] & 0x80 != 0) -1 else 0;
    for (body) |x| v = (v << 8) | @as(i32, x);
    return v;
}

/// BER writer; constructed values reserve one length byte and widen it on `end`.
const Enc = struct {
    gpa: Allocator,
    list: std.ArrayList(u8) = .empty,

    fn begin(e: *Enc, t: u8) Allocator.Error!usize {
        try e.list.appendSlice(e.gpa, &.{ t, 0 });
        return e.list.items.len;
    }

    fn end(e: *Enc, start: usize) Allocator.Error!void {
        const n = e.list.items.len - start;
        if (n < 0x80) {
            e.list.items[start - 1] = @intCast(n);
            return;
        }
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, @intCast(n), .big);
        var skip: usize = 0;
        while (be[skip] == 0) skip += 1;
        e.list.items[start - 1] = @intCast(0x80 | (4 - skip));
        try e.list.insertSlice(e.gpa, start, be[skip..]);
    }

    fn prim(e: *Enc, t: u8, body: []const u8) Allocator.Error!void {
        const s = try e.begin(t);
        try e.list.appendSlice(e.gpa, body);
        try e.end(s);
    }

    fn int(e: *Enc, t: u8, v: i32) Allocator.Error!void {
        var be: [4]u8 = undefined;
        std.mem.writeInt(i32, &be, v, .big);
        var skip: usize = 0;
        while (skip < 3 and ((be[skip] == 0 and be[skip + 1] & 0x80 == 0) or
            (be[skip] == 0xff and be[skip + 1] & 0x80 != 0))) skip += 1;
        try e.prim(t, be[skip..]);
    }
};

// ---------------------------------------------------------------- filters

/// RFC 4515 value escaping: specials, NUL, and non-printable/non-ASCII bytes become \xx.
pub fn escapeFilterValue(arena: Allocator, value: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, value.len);
    const hex = "0123456789abcdef";
    for (value) |c| {
        const special = c == '*' or c == '(' or c == ')' or c == '\\' or c < 0x20 or c >= 0x7f;
        if (special) {
            try out.appendSlice(arena, &.{ '\\', hex[c >> 4], hex[c & 0xf] });
        } else try out.append(arena, c);
    }
    return out.items;
}

/// Compiles an RFC 4515 filter string into BER, appended to `e`.
fn compileFilter(e: *Enc, s: []const u8) FilterError!void {
    if (s.len > limits.max_filter_len) return error.InvalidFilter;
    var p: FilterParser = .{ .s = s, .e = e };
    try p.filter(0);
    if (p.i != s.len) return error.InvalidFilter;
}

const FilterParser = struct {
    s: []const u8,
    i: usize = 0,
    e: *Enc,

    fn peek(p: *const FilterParser) ?u8 {
        return if (p.i < p.s.len) p.s[p.i] else null;
    }

    fn filter(p: *FilterParser, depth: usize) FilterError!void {
        if (depth >= limits.max_filter_depth) return error.InvalidFilter;
        if (p.peek() != '(') return error.InvalidFilter;
        p.i += 1;
        switch (p.peek() orelse return error.InvalidFilter) {
            '&' => try p.set(0xa0, depth),
            '|' => try p.set(0xa1, depth),
            '!' => {
                p.i += 1;
                const st = try p.e.begin(0xa2);
                try p.filter(depth + 1);
                try p.e.end(st);
            },
            else => try p.item(),
        }
        if (p.peek() != ')') return error.InvalidFilter;
        p.i += 1;
    }

    fn set(p: *FilterParser, t: u8, depth: usize) FilterError!void {
        p.i += 1;
        const st = try p.e.begin(t);
        var n: usize = 0;
        while (p.peek() == '(') : (n += 1) try p.filter(depth + 1);
        if (n == 0) return error.InvalidFilter;
        try p.e.end(st);
    }

    fn item(p: *FilterParser) FilterError!void {
        const a = p.i;
        while (p.peek()) |c| : (p.i += 1) {
            if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == ';')) break;
        }
        const attr = p.s[a..p.i];
        if (attr.len == 0) return error.InvalidFilter;
        const op: u8 = switch (p.peek() orelse return error.InvalidFilter) {
            '=' => 0xa3,
            '>' => 0xa5,
            '<' => 0xa6,
            '~' => 0xa8,
            else => return error.InvalidFilter,
        };
        p.i += 1;
        if (op != 0xa3) {
            if (p.peek() != '=') return error.InvalidFilter;
            p.i += 1;
        }
        const v = p.i;
        while (p.peek()) |c| : (p.i += 1) {
            if (c == ')') break;
            if (c == '(') return error.InvalidFilter;
        }
        const raw = p.s[v..p.i];
        const has_star = std.mem.indexOfScalar(u8, raw, '*') != null;
        if (op == 0xa3 and std.mem.eql(u8, raw, "*")) return p.e.prim(0x87, attr);
        if (op == 0xa3 and has_star) return p.substrings(attr, raw);
        if (has_star) return error.InvalidFilter;
        const st = try p.e.begin(op);
        try p.e.prim(tag.octets, attr);
        try p.value(tag.octets, raw);
        try p.e.end(st);
    }

    fn substrings(p: *FilterParser, attr: []const u8, raw: []const u8) FilterError!void {
        const st = try p.e.begin(0xa4);
        try p.e.prim(tag.octets, attr);
        const seq = try p.e.begin(tag.sequence);
        const n = std.mem.count(u8, raw, "*") + 1;
        var it = std.mem.splitScalar(u8, raw, '*');
        var idx: usize = 0;
        while (it.next()) |part| : (idx += 1) {
            if (idx == 0) {
                if (part.len > 0) try p.value(0x80, part);
            } else if (idx == n - 1) {
                if (part.len > 0) try p.value(0x82, part);
            } else {
                if (part.len == 0) return error.InvalidFilter;
                try p.value(0x81, part);
            }
        }
        try p.e.end(seq);
        try p.e.end(st);
    }

    fn value(p: *FilterParser, t: u8, raw: []const u8) FilterError!void {
        const st = try p.e.begin(t);
        var k: usize = 0;
        while (k < raw.len) : (k += 1) {
            if (raw[k] != '\\') {
                try p.e.list.append(p.e.gpa, raw[k]);
                continue;
            }
            if (raw.len - k < 3) return error.InvalidFilter;
            const b = std.fmt.parseInt(u8, raw[k + 1 .. k + 3], 16) catch return error.InvalidFilter;
            try p.e.list.append(p.e.gpa, b);
            k += 2;
        }
        try p.e.end(st);
    }
};

/// Substitutes %s (username) and %d (user DN); both already escaped.
fn expandFilter(arena: Allocator, tmpl: []const u8, s_val: []const u8, d_val: []const u8) FilterError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var k: usize = 0;
    while (k < tmpl.len) : (k += 1) {
        if (tmpl[k] == '%' and k + 1 < tmpl.len and (tmpl[k + 1] == 's' or tmpl[k + 1] == 'd')) {
            try out.appendSlice(arena, if (tmpl[k + 1] == 's') s_val else d_val);
            k += 1;
        } else try out.append(arena, tmpl[k]);
        if (out.items.len > limits.max_filter_len) return error.InvalidFilter;
    }
    return out.items;
}

// ---------------------------------------------------------------- connection

/// Reads one LDAPMessage header; returns its content length (bounded).
fn readFrameLen(in: *std.Io.Reader) (std.Io.Reader.Error || error{ ProtocolError, ResponseTooLarge })!usize {
    if (try in.takeByte() != tag.sequence) return error.ProtocolError;
    var hdr: [5]u8 = undefined;
    hdr[0] = try in.takeByte();
    const n: usize = if (hdr[0] < 0x80) 0 else hdr[0] & 0x7f;
    if (n > 4) return error.ProtocolError;
    try in.readSliceAll(hdr[1..][0..n]);
    const l = try parseLength(hdr[0 .. 1 + n]);
    if (l.len > limits.max_message) return error.ResponseTooLarge;
    return l.len;
}

const Msg = struct { id: i32, op: Tlv };

const Conn = struct {
    arena: Allocator,
    stream: std.net.Stream,
    sr: std.net.Stream.Reader,
    sw: std.net.Stream.Writer,
    sec: ?*tls.dial.Secure = null,
    msg_id: i32 = 0,
    buf: []u8 = &.{},

    fn reader(c: *Conn) *std.Io.Reader {
        return if (c.sec) |t| &t.client.reader else c.sr.interface();
    }

    fn writer(c: *Conn) *std.Io.Writer {
        return if (c.sec) |t| &t.client.writer else &c.sw.interface;
    }

    fn readErr(c: *Conn, e: std.Io.Reader.Error) Error {
        if (e == error.EndOfStream) return error.ProtocolError;
        if (c.sr.getError()) |se| return if (se == error.WouldBlock) error.Timeout else error.ConnectFailed;
        return if (c.sec != null) error.TlsFailed else error.ConnectFailed;
    }

    fn writeErr(c: *Conn) Error {
        if (c.sw.err) |se| return if (se == error.WouldBlock) error.Timeout else error.ConnectFailed;
        return if (c.sec != null) error.TlsFailed else error.ConnectFailed;
    }

    fn send(c: *Conn, op: []const u8) Error!void {
        c.msg_id += 1;
        var e: Enc = .{ .gpa = c.arena };
        const st = try e.begin(tag.sequence);
        try e.int(tag.integer, c.msg_id);
        try e.list.appendSlice(c.arena, op);
        try e.end(st);
        const w = c.writer();
        w.writeAll(e.list.items) catch return c.writeErr();
        w.flush() catch return c.writeErr();
        if (c.sec != null) c.sw.interface.flush() catch return c.writeErr();
    }

    /// Returned slices are valid until the next `recv`.
    fn recv(c: *Conn) Error!Msg {
        const in = c.reader();
        const len = readFrameLen(in) catch |e| return switch (e) {
            error.ProtocolError, error.ResponseTooLarge => |x| x,
            error.ReadFailed, error.EndOfStream => |x| c.readErr(x),
        };
        if (c.buf.len < len) c.buf = try c.arena.alloc(u8, @max(len, 2 * c.buf.len, 512));
        in.readSliceAll(c.buf[0..len]) catch |e| return c.readErr(e);
        var p: Ber = .{ .buf = c.buf[0..len] };
        const id = try decodeInt(try p.expect(tag.integer));
        const op = try p.next();
        // id 0 is unsolicited (e.g. Notice of Disconnection); nothing else is expected.
        if (id != c.msg_id) return error.ProtocolError;
        return .{ .id = id, .op = op };
    }

    fn bind(c: *Conn, dn: []const u8, password: []const u8) Error!i32 {
        var e: Enc = .{ .gpa = c.arena };
        const st = try e.begin(tag.bind_request);
        try e.int(tag.integer, 3);
        try e.prim(tag.octets, dn);
        try e.prim(0x80, password);
        try e.end(st);
        try c.send(e.list.items);
        const m = try c.recv();
        if (m.op.tag != tag.bind_response) return error.ProtocolError;
        return resultCode(m.op.body);
    }

    const SearchOutcome = struct { code: i32, overflow: bool };

    /// Collects entry DNs into `out`; stops early (overflow) once more than `cap` arrive.
    fn search(c: *Conn, base: []const u8, filter: []const u8, cap: usize, time_s: i32, out: *std.ArrayList([]const u8)) Error!SearchOutcome {
        var e: Enc = .{ .gpa = c.arena };
        const st = try e.begin(tag.search_request);
        try e.prim(tag.octets, base);
        try e.int(tag.enumerated, 2); // wholeSubtree
        try e.int(tag.enumerated, 0); // neverDerefAliases
        try e.int(tag.integer, @intCast(cap + 1));
        try e.int(tag.integer, time_s);
        try e.prim(tag.boolean, &.{0});
        try compileFilter(&e, filter);
        const attrs = try e.begin(tag.sequence);
        try e.prim(tag.octets, "1.1");
        try e.end(attrs);
        try e.end(st);
        try c.send(e.list.items);

        var refs: usize = 0;
        while (true) {
            const m = try c.recv();
            switch (m.op.tag) {
                tag.search_entry => {
                    if (out.items.len >= cap) return .{ .code = rc_success, .overflow = true };
                    var p: Ber = .{ .buf = m.op.body };
                    const dn = try p.expect(tag.octets);
                    if (dn.len == 0) return error.ProtocolError;
                    if (dn.len > limits.max_dn) return error.ResponseTooLarge;
                    try out.append(c.arena, try c.arena.dupe(u8, dn));
                },
                tag.search_reference => {
                    refs += 1;
                    if (refs > limits.max_references) return error.ProtocolError;
                },
                tag.search_done => return .{ .code = try resultCode(m.op.body), .overflow = false },
                else => return error.ProtocolError,
            }
        }
    }

    fn startTls(c: *Conn, cfg: Config, host: []const u8) Error!void {
        const s = try c.arena.create(tls.dial.Secure);
        s.start(c.arena, c.sr.interface(), &c.sw.interface, host, .{
            .skip_verify = cfg.tls_skip_verify,
            .ca_file = cfg.ca_file orelse "",
            .client_cert_file = cfg.client_cert_file,
            .client_key_file = cfg.client_key_file,
        }) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            if (c.sr.getError()) |se| if (se == error.WouldBlock) return error.Timeout;
            return error.TlsFailed;
        };
        c.sec = s;
    }

    fn extendedStartTls(c: *Conn) Error!void {
        var e: Enc = .{ .gpa = c.arena };
        const st = try e.begin(tag.extended_request);
        try e.prim(0x80, starttls_oid);
        try e.end(st);
        try c.send(e.list.items);
        const m = try c.recv();
        if (m.op.tag != tag.extended_response) return error.ProtocolError;
        if (try resultCode(m.op.body) != rc_success) return error.TlsFailed;
        // Bytes buffered past the response would bypass TLS.
        if (c.sr.interface().bufferedLen() != 0) return error.ProtocolError;
    }

    fn unbindAndClose(c: *Conn) void {
        c.msg_id += 1;
        var e: Enc = .{ .gpa = c.arena };
        if (e.begin(tag.sequence)) |st| {
            e.int(tag.integer, c.msg_id) catch {};
            e.list.appendSlice(c.arena, &.{ tag.unbind_request, 0 }) catch {};
            e.end(st) catch {};
            const w = c.writer();
            w.writeAll(e.list.items) catch {};
            w.flush() catch {};
        } else |_| {}
        if (c.sec) |t| {
            t.end();
            t.release(c.arena);
        }
        c.sw.interface.flush() catch {};
        c.stream.close();
    }
};

fn resultCode(body: []const u8) error{ProtocolError}!i32 {
    var p: Ber = .{ .buf = body };
    return decodeInt(try p.expect(tag.enumerated));
}

const HostPort = struct { host: []const u8, port: u16 };

fn splitHostPort(addr: []const u8) error{ConnectFailed}!HostPort {
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.ConnectFailed;
    var host = addr[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    if (host.len == 0) return error.ConnectFailed;
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.ConnectFailed;
    return .{ .host = host, .port = port };
}

fn setTimeouts(fd: posix.socket_t, ms: u32) posix.SetSockOptError!void {
    const tv: posix.timeval = .{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
}

fn connect(arena: Allocator, cfg: Config) Error!*Conn {
    const hp = try splitHostPort(cfg.server_addr);
    const list = std.net.getAddressList(arena, hp.host, hp.port) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ConnectFailed,
    };
    defer list.deinit();
    var last: Error = error.ConnectFailed;
    const fd: posix.socket_t = for (list.addrs) |addr| {
        const s = posix.socket(addr.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP) catch continue;
        setTimeouts(s, @max(cfg.timeout_ms, 1)) catch {
            posix.close(s);
            continue;
        };
        posix.connect(s, &addr.any, addr.getOsSockLen()) catch |e| {
            posix.close(s);
            last = if (e == error.WouldBlock or e == error.ConnectionTimedOut) error.Timeout else error.ConnectFailed;
            continue;
        };
        break s;
    } else return last;
    const stream: std.net.Stream = .{ .handle = fd };
    errdefer stream.close();

    const n = tls.Client.min_buffer_len;
    const bufs = try arena.alloc(u8, 2 * n);
    const c = try arena.create(Conn);
    c.* = .{
        .arena = arena,
        .stream = stream,
        .sr = stream.reader(bufs[0..n]),
        .sw = stream.writer(bufs[n .. 2 * n]),
    };
    switch (cfg.tls) {
        .none => {},
        .ldaps => try c.startTls(cfg, hp.host),
        .starttls => {
            try c.extendedStartTls();
            try c.startTls(cfg, hp.host);
        },
    }
    return c;
}

/// Bind-search-bind: lookup bind, find exactly one user entry, bind as it with
/// `password`, re-bind as lookup and collect group DNs. Unbinds and closes.
pub fn authenticate(arena: Allocator, cfg: Config, username: []const u8, password: []const u8) Error!Result {
    // An empty password is an unauthenticated bind that servers report as success.
    if (password.len == 0 or username.len == 0) return error.InvalidCredentials;
    const esc_user = try escapeFilterValue(arena, username);
    const user_filter = try expandFilter(arena, cfg.user_dn_search_filter, esc_user, "");
    const time_s: i32 = @intCast(@max(1, cfg.timeout_ms / 1000));

    const c = try connect(arena, cfg);
    defer c.unbindAndClose();

    if (try c.bind(cfg.lookup_bind_dn, cfg.lookup_bind_password) != rc_success) return error.LookupBindFailed;

    var users: std.ArrayList([]const u8) = .empty;
    const us = try c.search(cfg.user_dn_search_base, user_filter, 1, time_s, &users);
    if (us.overflow or us.code == rc_size_limit_exceeded) return error.AmbiguousUser;
    if (us.code != rc_success) return error.SearchFailed;
    if (users.items.len == 0) return error.UserNotFound;
    const user_dn = users.items[0];

    if (try c.bind(user_dn, password) != rc_success) return error.InvalidCredentials;

    var groups: std.ArrayList([]const u8) = .empty;
    if (cfg.group_search_base.len != 0 and cfg.group_search_filter.len != 0) {
        const esc_dn = try escapeFilterValue(arena, user_dn);
        const gf = try expandFilter(arena, cfg.group_search_filter, esc_user, esc_dn);
        if (try c.bind(cfg.lookup_bind_dn, cfg.lookup_bind_password) != rc_success) return error.LookupBindFailed;
        const gs = try c.search(cfg.group_search_base, gf, limits.max_groups, time_s, &groups);
        if (gs.overflow or gs.code == rc_size_limit_exceeded) return error.ResponseTooLarge;
        if (gs.code != rc_success) return error.SearchFailed;
    }
    return .{ .user_dn = user_dn, .groups = groups.items };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn compileForTest(a: Allocator, s: []const u8) FilterError![]const u8 {
    var e: Enc = .{ .gpa = a };
    try compileFilter(&e, s);
    return e.list.items;
}

test "ber integer and length round trips" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]i32{ 0, 1, 127, 128, 255, 256, -1, -128, -129, 65535, std.math.maxInt(i32), std.math.minInt(i32) }) |v| {
        var e: Enc = .{ .gpa = a };
        try e.int(tag.integer, v);
        var p: Ber = .{ .buf = e.list.items };
        try testing.expectEqual(v, try decodeInt(try p.expect(tag.integer)));
        try testing.expect(p.done());
    }
    for ([_]usize{ 0, 1, 127, 128, 255, 256, 70000 }) |n| {
        var e: Enc = .{ .gpa = a };
        const outer = try e.begin(tag.sequence);
        const body = try a.alloc(u8, n);
        @memset(body, 'x');
        try e.prim(tag.octets, body);
        try e.end(outer);
        var p: Ber = .{ .buf = e.list.items };
        var inner: Ber = .{ .buf = try p.expect(tag.sequence) };
        try testing.expectEqualSlices(u8, body, try inner.expect(tag.octets));
    }
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x80 }, blk: {
        var e: Enc = .{ .gpa = a };
        try e.int(tag.integer, -128);
        break :blk e.list.items;
    });
}

test "ber rejects indefinite, oversized, and truncated lengths" {
    var p: Ber = .{ .buf = &.{ 0x30, 0x80, 0x00, 0x00 } };
    try testing.expectError(error.ProtocolError, p.next());
    p = .{ .buf = &.{ 0x30, 0x85, 1, 0, 0, 0, 0 } };
    try testing.expectError(error.ProtocolError, p.next());
    p = .{ .buf = &.{ 0x04, 0x05, 'a' } };
    try testing.expectError(error.ProtocolError, p.next());
    p = .{ .buf = &.{ 0x04, 0x84, 0xff, 0xff, 0xff, 0xff } };
    try testing.expectError(error.ProtocolError, p.next());
    p = .{ .buf = &.{ 0x1f, 0x01, 0x00 } };
    try testing.expectError(error.ProtocolError, p.next());
    try testing.expectError(error.ProtocolError, decodeInt(&.{}));
    try testing.expectError(error.ProtocolError, decodeInt(&.{ 1, 2, 3, 4, 5 }));
}

test "filter compiler" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualSlices(u8, &.{ 0xa3, 0x0a, 0x04, 0x03, 'u', 'i', 'd', 0x04, 0x03, 'b', 'o', 'b' }, try compileForTest(a, "(uid=bob)"));
    try testing.expectEqualSlices(u8, &.{ 0x87, 0x02, 'c', 'n' }, try compileForTest(a, "(cn=*)"));
    try testing.expectEqualSlices(u8, &.{ 0xa3, 0x06, 0x04, 0x01, 'a', 0x04, 0x01, '*' }, try compileForTest(a, "(a=\\2a)"));
    try testing.expectEqualSlices(u8, &.{
        0xa4, 0x0f, 0x04, 0x02, 'c', 'n', 0x30, 0x09, 0x80, 0x01, 'a', 0x81, 0x01, 'b', 0x82, 0x01, 'c',
    }, try compileForTest(a, "(cn=a*b*c)"));
    try testing.expectEqualSlices(u8, &.{ 0xa4, 0x09, 0x04, 0x02, 'c', 'n', 0x30, 0x03, 0x81, 0x01, 'x' }, try compileForTest(a, "(cn=*x*)"));
    try testing.expectEqualSlices(u8, &.{ 0xa2, 0x08, 0xa5, 0x06, 0x04, 0x01, 'n', 0x04, 0x01, '5' }, try compileForTest(a, "(!(n>=5))"));
    const complex = try compileForTest(a, "(&(objectClass=groupOfNames)(|(member=uid=a,dc=x)(cn<=z)(cn~=q)))");
    try testing.expectEqual(@as(u8, 0xa0), complex[0]);
    var p: Ber = .{ .buf = complex };
    var and_set: Ber = .{ .buf = try p.expect(0xa0) };
    _ = try and_set.expect(0xa3);
    var or_set: Ber = .{ .buf = try and_set.expect(0xa1) };
    _ = try or_set.expect(0xa3);
    _ = try or_set.expect(0xa6);
    _ = try or_set.expect(0xa8);
    try testing.expect(or_set.done() and and_set.done() and p.done());

    const bad = [_][]const u8{
        "",          "uid=bob",    "(uid=bob", "(uid=bob))", "(=bob)",   "(uid~bob)", "(&)",
        "(uid=\\4)", "(uid=\\zz)", "(a=b(c)",  "(cn:=x)",    "(cn>=a*)", "(cn=a**b)", "(!(a=b)(c=d))",
        "(|(a=b)x)", "((a=b))",
    };
    for (bad) |s| try testing.expectError(error.InvalidFilter, compileForTest(a, s));
    const deep = "(!" ** 20 ++ "(a=b)" ++ ")" ** 20;
    try testing.expectError(error.InvalidFilter, compileForTest(a, deep));
    const ok_depth = "(!" ** 14 ++ "(a=b)" ++ ")" ** 14;
    _ = try compileForTest(a, ok_depth);
}

test "escapeFilterValue" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("alice", try escapeFilterValue(a, "alice"));
    try testing.expectEqualStrings("\\2a\\28x\\29\\5c\\00", try escapeFilterValue(a, "*(x)\\\x00"));
    try testing.expectEqualStrings("\\c3\\a9\\0a~", try escapeFilterValue(a, "\xc3\xa9\n~"));
    // Escaped values compile back to the original bytes.
    const raw = "a*(b)\\c\x00\xff";
    const f = try std.fmt.allocPrint(a, "(x={s})", .{try escapeFilterValue(a, raw)});
    var p: Ber = .{ .buf = try compileForTest(a, f) };
    var eq: Ber = .{ .buf = try p.expect(0xa3) };
    _ = try eq.expect(tag.octets);
    try testing.expectEqualSlices(u8, raw, try eq.expect(tag.octets));
}

test "expandFilter" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("(&(m=D)(u=S)%x)", try expandFilter(arena.allocator(), "(&(m=%d)(u=%s)%x)", "S", "D"));
}

const fake = struct {
    const lookup_dn = "cn=admin,dc=example,dc=org";
    const lookup_pw = "adminpw";
    const alice_dn = "uid=alice,ou=people,dc=example,dc=org";
    const alice_pw = "alicepw";
    const people = "ou=people,dc=example,dc=org";
    const groups = "ou=groups,dc=example,dc=org";
    const group_dns = [_][]const u8{ "cn=devs,ou=groups,dc=example,dc=org", "cn=ops,ou=groups,dc=example,dc=org" };

    const Server = struct {
        server: std.net.Server,
        conns: usize,
        huge: bool = false,

        fn run(s: *Server) void {
            for (0..s.conns) |_| {
                const conn = s.server.accept() catch return;
                serve(conn.stream, s.huge) catch {};
                conn.stream.close();
            }
        }
    };

    fn reply(w: *std.Io.Writer, a: Allocator, id: i32, op: []const u8) !void {
        var e: Enc = .{ .gpa = a };
        const st = try e.begin(tag.sequence);
        try e.int(tag.integer, id);
        try e.list.appendSlice(a, op);
        try e.end(st);
        try w.writeAll(e.list.items);
        try w.flush();
    }

    fn result(a: Allocator, t: u8, code: i32) ![]const u8 {
        var e: Enc = .{ .gpa = a };
        const st = try e.begin(t);
        try e.int(tag.enumerated, code);
        try e.prim(tag.octets, "");
        try e.prim(tag.octets, "");
        try e.end(st);
        return e.list.items;
    }

    fn entry(a: Allocator, dn: []const u8) ![]const u8 {
        var e: Enc = .{ .gpa = a };
        const st = try e.begin(tag.search_entry);
        try e.prim(tag.octets, dn);
        try e.prim(tag.sequence, "");
        try e.end(st);
        return e.list.items;
    }

    fn serve(stream: std.net.Stream, huge: bool) !void {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var rb: [4096]u8 = undefined;
        var wb: [4096]u8 = undefined;
        var sr = stream.reader(&rb);
        var sw = stream.writer(&wb);
        const in = sr.interface();
        const w = &sw.interface;
        while (true) {
            const len = try readFrameLen(in);
            if (huge) {
                try w.writeAll(&.{ 0x30, 0x84, 0x7f, 0xff, 0xff, 0xff });
                try w.flush();
                return;
            }
            const body = try a.alloc(u8, len);
            try in.readSliceAll(body);
            var p: Ber = .{ .buf = body };
            const id = try decodeInt(try p.expect(tag.integer));
            const op = try p.next();
            switch (op.tag) {
                tag.bind_request => {
                    var b: Ber = .{ .buf = op.body };
                    _ = try b.expect(tag.integer);
                    const name = try b.expect(tag.octets);
                    const pw = try b.expect(0x80);
                    const ok = (std.mem.eql(u8, name, lookup_dn) and std.mem.eql(u8, pw, lookup_pw)) or
                        (std.mem.eql(u8, name, alice_dn) and std.mem.eql(u8, pw, alice_pw));
                    try reply(w, a, id, try result(a, tag.bind_response, if (ok) 0 else 49));
                },
                tag.search_request => {
                    var b: Ber = .{ .buf = op.body };
                    const base = try b.expect(tag.octets);
                    if (std.mem.eql(u8, base, people)) {
                        if (std.mem.indexOf(u8, op.body, "alice") != null)
                            try reply(w, a, id, try entry(a, alice_dn));
                    } else if (std.mem.eql(u8, base, groups)) {
                        if (std.mem.indexOf(u8, op.body, alice_dn) != null) {
                            for (group_dns) |g| try reply(w, a, id, try entry(a, g));
                        }
                    }
                    try reply(w, a, id, try result(a, tag.search_done, 0));
                },
                tag.unbind_request => return,
                else => return error.ProtocolError,
            }
        }
    }

    fn start(conns: usize, huge: bool) !struct { srv: *Server, thread: std.Thread, port: u16 } {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const srv = try testing.allocator.create(Server);
        srv.* = .{ .server = try addr.listen(.{ .reuse_address = true }), .conns = conns, .huge = huge };
        const th = try std.Thread.spawn(.{}, Server.run, .{srv});
        return .{ .srv = srv, .thread = th, .port = srv.server.listen_address.getPort() };
    }

    fn stop(srv: *Server, th: std.Thread) void {
        th.join();
        srv.server.deinit();
        testing.allocator.destroy(srv);
    }

    fn config(addr_buf: []u8, port: u16) Config {
        return .{
            .server_addr = std.fmt.bufPrint(addr_buf, "127.0.0.1:{d}", .{port}) catch "",
            .lookup_bind_dn = lookup_dn,
            .lookup_bind_password = lookup_pw,
            .user_dn_search_base = people,
            .user_dn_search_filter = "(uid=%s)",
            .group_search_base = groups,
            .group_search_filter = "(&(objectclass=groupOfNames)(member=%d))",
            .timeout_ms = 3000,
        };
    }
};

test "authenticate against in-process fake server" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try fake.start(3, false);
    defer fake.stop(s.srv, s.thread);
    var addr_buf: [32]u8 = undefined;
    const cfg = fake.config(&addr_buf, s.port);

    const r = try authenticate(a, cfg, "alice", fake.alice_pw);
    try testing.expectEqualStrings(fake.alice_dn, r.user_dn);
    try testing.expectEqual(@as(usize, 2), r.groups.len);
    try testing.expectEqualStrings(fake.group_dns[0], r.groups[0]);
    try testing.expectEqualStrings(fake.group_dns[1], r.groups[1]);

    try testing.expectError(error.InvalidCredentials, authenticate(a, cfg, "alice", "wrong"));
    try testing.expectError(error.UserNotFound, authenticate(a, cfg, "mallory", "x"));
    // Rejected before connecting; the server only expects three connections.
    try testing.expectError(error.InvalidCredentials, authenticate(a, cfg, "alice", ""));
}

test "huge length prefix is rejected without allocating" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const s = try fake.start(1, true);
    defer fake.stop(s.srv, s.thread);
    var addr_buf: [32]u8 = undefined;
    const cfg = fake.config(&addr_buf, s.port);
    try testing.expectError(error.ResponseTooLarge, authenticate(arena.allocator(), cfg, "alice", fake.alice_pw));
}

test "tls modes compile and fail cleanly on a closed port" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var srv = try addr.listen(.{ .reuse_address = true });
    const port = srv.listen_address.getPort();
    srv.deinit();
    var addr_buf: [32]u8 = undefined;
    var cfg = fake.config(&addr_buf, port);
    for ([_]TlsMode{ .ldaps, .starttls }) |mode| {
        cfg.tls = mode;
        try testing.expectError(error.ConnectFailed, authenticate(arena.allocator(), cfg, "alice", "pw"));
    }
    cfg.tls = .ldaps;
    cfg.tls_skip_verify = true;
    try testing.expectError(error.ConnectFailed, authenticate(arena.allocator(), cfg, "alice", "pw"));
    try testing.expectError(error.ConnectFailed, splitHostPort("nohost"));
    try testing.expectError(error.ConnectFailed, splitHostPort(":389"));
    const hp = try splitHostPort("[::1]:636");
    try testing.expectEqualStrings("::1", hp.host);
}
