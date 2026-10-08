//! WebDAV gateway (RFC 4918 classes 1 and 2) over the object namespace: buckets
//! are top-level collections, `dir/` markers make empty collections, locks are
//! in-memory. HTTPS when the server has a certificate; Basic auth via IAM.
const std = @import("std");
const root = @import("root.zig");
const core = @import("../core/root.zig");
const fsm = @import("fs.zig");
const listener = @import("listener.zig");
const http = @import("webdav_http.zig");
const proto = @import("webdav_proto.zig");
const xml = @import("webdav_xml.zig");
const lockm = @import("webdav_lock.zig");

const Status = std.http.Status;
const Header = std.http.Header;
const Writer = std.Io.Writer;
const Error = http.Error;

pub const max_prefix = 128;
/// Bound on resources one DELETE/COPY/MOVE of a collection touches.
pub const max_tree = fsm.max_rename_objects;
/// Bound on members listed by one Depth: 1 PROPFIND.
pub const max_listing = 100_000;
const list_page = 1000;
const drain_max = 16 * 1024 * 1024;
const xml_type = "application/xml; charset=utf-8";
const allow = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

pub const Config = struct {
    listen: ?std.net.Address = null,
    /// URL path prefix ("" or "/x"), no trailing slash.
    prefix: []const u8 = "",
    /// Allow Basic auth over plain HTTP when no certificate is configured.
    insecure: bool = false,

    pub fn enabled(c: Config) bool {
        return c.listen != null;
    }
};

pub const usage =
    \\  --webdav HOST:PORT        serve WebDAV (HTTPS when --tls-cert is set)
    \\  --webdav-prefix PATH      URL path prefix for WebDAV (default /)
    \\  --webdav-insecure on|off  allow Basic auth over plain HTTP (default off)
    \\
;

/// Consumes `flag value` when it belongs to this gateway.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) root.FlagError!bool {
    if (std.mem.eql(u8, flag, "--webdav")) {
        cfg.listen = listener.parseAddr(value) catch return error.BadArgs;
    } else if (std.mem.eql(u8, flag, "--webdav-prefix")) {
        cfg.prefix = try parsePrefix(value);
    } else if (std.mem.eql(u8, flag, "--webdav-insecure")) {
        if (std.mem.eql(u8, value, "on")) cfg.insecure = true else if (std.mem.eql(u8, value, "off")) cfg.insecure = false else return error.BadArgs;
    } else return false;
    return true;
}

fn parsePrefix(v: []const u8) root.FlagError![]const u8 {
    const p = std.mem.trimRight(u8, v, "/");
    if (v.len == 0 or v[0] != '/' or p.len > max_prefix) return error.BadArgs;
    var it = std.mem.splitScalar(u8, p, '/');
    _ = it.next();
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return error.BadArgs;
        for (seg) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '~') return error.BadArgs;
    }
    return p;
}

pub const Server = struct {
    deps: root.Deps,
    cfg: Config,
    lis: listener.Listener,
    locks: lockm.Table,

    pub fn start(deps: root.Deps, cfg: Config) root.StartError!*Server {
        if (deps.tls == null and !cfg.insecure and deps.access.iam != null) {
            std.log.err("webdav: Basic auth over plain HTTP needs --webdav-insecure on (or --tls-cert)", .{});
            return error.BadConfig;
        }
        const addr = cfg.listen orelse return error.BadConfig;
        const s = try deps.gpa.create(Server);
        errdefer deps.gpa.destroy(s);
        s.deps = deps;
        s.cfg = cfg;
        s.lis = .{ .name = if (deps.tls != null) "webdav (https)" else "webdav (http)", .handler = .{ .ctx = s, .serve = serveConn }, .max_conns = 128, .idle_timeout_s = 120 };
        s.locks.mu = .{};
        for (&s.locks.locks) |*l| l.used = false;
        try s.lis.start(addr);
        return s;
    }

    pub fn stop(self: *Server) void {
        self.lis.stop(5);
        // A session still running would touch freed memory; leak instead.
        if (self.lis.active.load(.seq_cst) == 0) self.deps.gpa.destroy(self);
    }

    fn serveConn(ctx: *anyopaque, conn: std.net.Server.Connection) void {
        const s: *Server = @ptrCast(@alignCast(ctx));
        http.serve(.{
            .gpa = s.deps.gpa,
            .tls = s.deps.tls,
            .handler = .{ .ctx = s, .handle = handle },
            .stopping = &s.lis.stopping,
        }, conn);
    }

    fn authenticate(s: *Server, x: *http.Exchange) ?root.Principal {
        if (s.deps.access.iam == null) return .{ .open = true };
        const h = x.header("authorization") orelse return null;
        if (h.len < 6 or !std.ascii.eqlIgnoreCase(h[0..6], "Basic ")) return null;
        const enc = std.mem.trim(u8, h[6..], " \t");
        var buf: [768]u8 = undefined;
        const d = std.base64.standard.Decoder;
        const n = d.calcSizeForSlice(enc) catch return null;
        if (n > buf.len) return null;
        d.decode(buf[0..n], enc) catch return null;
        const colon = std.mem.indexOfScalar(u8, buf[0..n], ':') orelse return null;
        return s.deps.access.login(buf[0..colon], buf[colon + 1 .. n]);
    }
};

// ---- request plumbing ----

const Req = struct {
    s: *Server,
    x: *http.Exchange,
    fs: fsm.Fs,
    path: []const u8,
    now: i64,

    fn arena(r: *Req) std.mem.Allocator {
        return r.x.arena;
    }
    fn prefix(r: *Req) []const u8 {
        return r.s.cfg.prefix;
    }
};

fn send(x: *http.Exchange, status: Status, body: []const u8, extra: []const Header) Error!void {
    const unread = x.req.server.reader.state == .received_head and x.hasBody();
    // Unread uploads up to drain_max are drained so the client sees the status;
    // larger ones are not invited (no 100-continue) and the connection closes.
    const big = unread and (x.req.head.expect != null or (x.req.head.content_length orelse std.math.maxInt(u64)) > drain_max);
    if (big) x.req.head.expect = null;
    return x.req.respond(body, .{ .status = status, .keep_alive = !big, .extra_headers = extra });
}

fn sendXml(x: *http.Exchange, status: Status, body: []const u8, extra: []const Header) Error!void {
    var hs: [4]Header = undefined;
    hs[0] = .{ .name = "content-type", .value = xml_type };
    const n = @min(extra.len, hs.len - 1);
    @memcpy(hs[1..][0..n], extra[0..n]);
    return send(x, status, body, hs[0 .. n + 1]);
}

fn davError(x: *http.Exchange, status: Status, cond: []const u8) Error!void {
    const body = try std.fmt.allocPrint(x.arena, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\">{s}</D:error>\n", .{cond});
    return sendXml(x, status, body, &.{});
}

fn fsStatus(e: fsm.Error) Status {
    return switch (e) {
        error.NotFound => .not_found,
        error.Exists, error.IsDir => .method_not_allowed,
        error.NotEmpty, error.NotDir => .conflict,
        error.Denied => .forbidden,
        error.InvalidPath => .bad_request,
        error.TooLarge, error.QuotaExceeded => .insufficient_storage,
        error.Storage, error.OutOfMemory, error.ReadFailed, error.WriteFailed => .internal_server_error,
    };
}

fn fail(x: *http.Exchange, e: fsm.Error) Error!void {
    if (e == error.ReadFailed) return error.ReadFailed;
    return send(x, fsStatus(e), "", &.{});
}

/// Decodes and normalizes an encoded path below the prefix.
fn resolve(arena: std.mem.Allocator, encoded: []const u8) (error{InvalidPath} || std.mem.Allocator.Error)![]const u8 {
    if (encoded.len > fsm.max_path * 3) return error.InvalidPath;
    const dec = try arena.alloc(u8, encoded.len);
    const p = try proto.percentDecode(dec, encoded);
    const out = try arena.alloc(u8, fsm.max_path);
    return fsm.normalize(out, "/", p) catch error.InvalidPath;
}

fn parentOf(path: []const u8) []const u8 {
    const i = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "/";
    return if (i == 0) "/" else path[0..i];
}

fn join(arena: std.mem.Allocator, dir: []const u8, name: []const u8) error{OutOfMemory}![]const u8 {
    if (std.mem.eql(u8, dir, "/")) return std.fmt.allocPrint(arena, "/{s}", .{name});
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

fn isCollection(k: fsm.Kind) bool {
    return k != .file;
}

fn handle(ctx: *anyopaque, x: *http.Exchange) Error!void {
    const s: *Server = @ptrCast(@alignCast(ctx));
    var sp = core.trace.root("webdav.request", .server, .gateway, .{});
    defer sp.end();
    sp.str("http.request.method", x.method);
    sp.str("path", x.target);
    const enc = proto.stripPrefix(s.cfg.prefix, proto.uriPath(x.target)) orelse return send(x, .not_found, "", &.{});
    const path = resolve(x.arena, enc) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidPath => return send(x, .bad_request, "", &.{}),
    };
    const m = x.method;
    if (std.mem.eql(u8, m, "OPTIONS")) return send(x, .ok, "", &.{
        .{ .name = "dav", .value = "1, 2" },
        .{ .name = "allow", .value = allow },
        .{ .name = "ms-author-via", .value = "DAV" },
    });
    const who = s.authenticate(x) orelse return send(x, .unauthorized, "", &.{
        .{ .name = "www-authenticate", .value = "Basic realm=\"zkfsm\", charset=\"UTF-8\"" },
    });
    var r: Req = .{
        .s = s,
        .x = x,
        .fs = .{ .access = s.deps.access, .who = who, .peer = x.peer, .secure = x.secure },
        .path = path,
        .now = std.time.timestamp(),
    };
    const eq = std.mem.eql;
    if (eq(u8, m, "GET") or eq(u8, m, "HEAD")) return get(&r);
    if (eq(u8, m, "PUT")) return put(&r);
    if (eq(u8, m, "DELETE")) return delete(&r);
    if (eq(u8, m, "MKCOL")) return mkcol(&r);
    if (eq(u8, m, "PROPFIND")) return propfind(&r);
    if (eq(u8, m, "PROPPATCH")) return proppatch(&r);
    if (eq(u8, m, "COPY")) return copyMove(&r, false);
    if (eq(u8, m, "MOVE")) return copyMove(&r, true);
    if (eq(u8, m, "LOCK")) return lockRes(&r);
    if (eq(u8, m, "UNLOCK")) return unlockRes(&r);
    return send(x, .method_not_allowed, "", &.{.{ .name = "allow", .value = allow }});
}

// ---- preconditions: If header and locks ----

/// Lock tokens the client submitted in If.
fn submitted(r: *Req) Error!?[]const []const u8 {
    const h = r.x.header("if") orelse return &.{};
    const lists = proto.parseIf(r.arena(), h) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadIf => return null,
    };
    return try proto.ifTokens(r.arena(), lists);
}

/// Evaluates If (RFC 4918 10.4): true when any list holds.
fn ifHolds(r: *Req, lists: []const proto.List) Error!bool {
    for (lists) |l| {
        const target = if (l.tag) |t| blk: {
            const enc = proto.stripPrefix(r.prefix(), proto.uriPath(t)) orelse continue;
            break :blk resolve(r.arena(), enc) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidPath => continue,
            };
        } else r.path;
        const ok = for (l.conds) |c| {
            var v = if (c.etag) blk: {
                const st = r.fs.stat(r.arena(), target) catch break :blk false;
                const e = st.etag orelse break :blk false;
                var b: [core.ETag.quoted_max]u8 = undefined;
                break :blk std.mem.eql(u8, e.quoted(&b), c.value);
            } else r.s.locks.valid(target, c.value, r.now);
            if (c.not) v = !v;
            if (!v) break false;
        } else true;
        if (ok) return true;
    }
    return false;
}

/// Sends 400/412/423 and returns false when the write to `path` may not proceed.
fn precheck(r: *Req, path: []const u8, recursive: bool) Error!bool {
    var tokens: []const []const u8 = &.{};
    if (r.x.header("if")) |h| {
        const lists = proto.parseIf(r.arena(), h) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadIf => {
                try send(r.x, .bad_request, "", &.{});
                return false;
            },
        };
        if (!try ifHolds(r, lists)) {
            try send(r.x, .precondition_failed, "", &.{});
            return false;
        }
        tokens = try proto.ifTokens(r.arena(), lists);
    }
    var buf: [lockm.max_path]u8 = undefined;
    if (r.s.locks.blocker(path, recursive, tokens, r.now, &buf)) |held| {
        var a: Writer.Allocating = .init(r.arena());
        a.writer.writeAll("<D:lock-token-submitted><D:href>") catch return error.OutOfMemory;
        proto.writeHref(&a.writer, r.prefix(), held, false) catch return error.OutOfMemory;
        a.writer.writeAll("</D:href></D:lock-token-submitted>") catch return error.OutOfMemory;
        try davError(r.x, .locked, a.written());
        return false;
    }
    return true;
}

/// Sends 409 and returns false when the parent of `path` is not a collection.
fn parentExists(r: *Req, path: []const u8) Error!bool {
    const st = r.fs.stat(r.arena(), parentOf(path)) catch |e| {
        if (e == error.NotFound) {
            try send(r.x, .conflict, "", &.{});
        } else try fail(r.x, e);
        return false;
    };
    if (st.kind == .file) {
        try send(r.x, .conflict, "", &.{});
        return false;
    }
    return true;
}

// ---- tree walks ----

const Item = struct { rel: []const u8, kind: fsm.Kind };

/// Every member below collection `path`, parents before children (bounded).
fn collect(r: *Req, path: []const u8) fsm.Error![]Item {
    const a = r.arena();
    var items: std.ArrayList(Item) = .empty;
    var next: usize = 0;
    var dir: []const u8 = "";
    while (true) {
        const abs = if (dir.len == 0) path else join(a, path, dir) catch return error.OutOfMemory;
        var cursor: []const u8 = "";
        while (true) {
            const page = try r.fs.list(a, abs, cursor, list_page);
            for (page.entries) |e| {
                if (items.items.len >= max_tree) return error.TooLarge;
                const rel = if (dir.len == 0) e.name else try std.fmt.allocPrint(a, "{s}/{s}", .{ dir, e.name });
                try items.append(a, .{ .rel = rel, .kind = if (e.kind == .file) .file else .dir });
            }
            cursor = page.next orelse break;
        }
        while (next < items.items.len and items.items[next].kind == .file) next += 1;
        if (next == items.items.len) break;
        dir = items.items[next].rel;
        next += 1;
    }
    return items.items;
}

fn deleteTree(r: *Req, path: []const u8, kind: fsm.Kind) fsm.Error!void {
    const a = r.arena();
    if (kind == .file) return r.fs.remove(a, path);
    const items = try collect(r, path);
    for (items) |it| if (it.kind == .file) try r.fs.remove(a, try join(a, path, it.rel));
    var i = items.len;
    while (i > 0) {
        i -= 1;
        if (items[i].kind == .file) continue;
        r.fs.rmdir(a, try join(a, path, items[i].rel)) catch |e| if (e != error.NotFound) return e;
    }
    r.fs.rmdir(a, path) catch |e| if (e != error.NotFound or kind == .bucket) return e;
}

fn mkdirOk(r: *Req, path: []const u8) fsm.Error!void {
    r.fs.mkdir(r.arena(), path) catch |e| if (e != error.Exists) return e;
}

fn copyTree(r: *Req, src: []const u8, dst: []const u8, deep: bool) fsm.Error!void {
    const a = r.arena();
    try mkdirOk(r, dst);
    if (!deep) return;
    for (try collect(r, src)) |it| {
        const d = try join(a, dst, it.rel);
        if (it.kind == .file) try r.fs.copyFile(try join(a, src, it.rel), d) else try mkdirOk(r, d);
    }
}

// ---- methods ----

fn get(r: *Req) Error!void {
    const x = r.x;
    const head = std.mem.eql(u8, x.method, "HEAD");
    const st = r.fs.stat(r.arena(), r.path) catch |e| return fail(x, e);
    if (isCollection(st.kind)) return listingPage(r, head);
    const info = r.fs.openRead(r.arena(), r.path) catch |e| return fail(x, e);
    var eb: [core.ETag.quoted_max]u8 = undefined;
    const etag = info.etag.quoted(&eb);
    var db: [29]u8 = undefined;
    const ctype = if (info.content_type.len > 0) info.content_type else proto.guessType(r.path);
    var hs: [6]Header = undefined;
    var nh: usize = 0;
    hs[nh] = .{ .name = "etag", .value = etag };
    nh += 1;
    hs[nh] = .{ .name = "last-modified", .value = core.time.httpDate(info.created_ns, &db) };
    nh += 1;
    hs[nh] = .{ .name = "content-type", .value = if (std.mem.indexOfAny(u8, ctype, "\r\n") == null) ctype else "application/octet-stream" };
    nh += 1;
    hs[nh] = .{ .name = "accept-ranges", .value = "bytes" };
    nh += 1;
    if (x.header("if-none-match")) |inm| {
        if (std.mem.eql(u8, std.mem.trim(u8, inm, " "), etag) or std.mem.eql(u8, std.mem.trim(u8, inm, " "), "*"))
            return send(x, .not_modified, "", hs[0..2]);
    }
    var range: ?core.Range = null;
    var crb: [80]u8 = undefined;
    if (x.header("range")) |rh| if (info.size > 0) {
        if (core.RangeSpec.parse(rh)) |spec| {
            range = spec.resolve(info.size) catch {
                const cr = std.fmt.bufPrint(&crb, "bytes */{d}", .{info.size}) catch unreachable;
                return send(x, .range_not_satisfiable, "", &.{.{ .name = "content-range", .value = cr }});
            };
            hs[nh] = .{ .name = "content-range", .value = std.fmt.bufPrint(&crb, "bytes {d}-{d}/{d}", .{ range.?.offset, range.?.last(), info.size }) catch unreachable };
            nh += 1;
        } else |_| {}
    };
    const len = if (range) |g| g.length else info.size;
    const buf = try r.arena().alloc(u8, 64 * 1024);
    var bw = try x.req.respondStreaming(buf, .{
        .content_length = len,
        .respond_options = .{ .status = if (range != null) .partial_content else .ok, .extra_headers = hs[0..nh] },
    });
    if (head) return bw.flush();
    r.fs.read(info, range, &bw.writer) catch return error.WriteFailed;
    try bw.writer.flush();
    if (bw.state != .content_length or bw.state.content_length != 0) return error.WriteFailed;
    try bw.end();
}

/// Minimal HTML index for GET on a collection (first page only).
fn listingPage(r: *Req, head: bool) Error!void {
    const page = r.fs.list(r.arena(), r.path, "", list_page) catch |e| return fail(r.x, e);
    var a: Writer.Allocating = .init(r.arena());
    const w = &a.writer;
    if (!head) {
        render: {
            w.writeAll("<!DOCTYPE html>\n<html><body><ul>\n") catch break :render;
            for (page.entries) |e| {
                const p = try join(r.arena(), r.path, e.name);
                w.writeAll("<li><a href=\"") catch break :render;
                proto.writeHref(w, r.prefix(), p, e.kind != .file) catch break :render;
                w.writeAll("\">") catch break :render;
                xml.escape(w, e.name) catch break :render;
                w.writeAll(if (e.kind != .file) "/</a></li>\n" else "</a></li>\n") catch break :render;
            }
            w.writeAll("</ul></body></html>\n") catch break :render;
        }
    }
    return send(r.x, .ok, a.written(), &.{.{ .name = "content-type", .value = "text/html; charset=utf-8" }});
}

fn put(r: *Req) Error!void {
    const x = r.x;
    const l = fsm.split(r.path);
    if (l.key.len == 0) return send(x, .method_not_allowed, "", &.{});
    var existed = false;
    if (r.fs.stat(r.arena(), r.path)) |st| {
        if (st.kind != .file) return send(x, .method_not_allowed, "", &.{});
        existed = true;
    } else |e| if (e != error.NotFound) return fail(x, e);
    if (!existed and !try parentExists(r, r.path)) return;
    if (!try precheck(r, r.path, false)) return;
    const ct_h = x.header("content-type");
    const ctype = try r.arena().dupe(u8, if (ct_h) |c| c else proto.guessType(r.path));
    const len: ?u64 = if (x.req.head.transfer_encoding == .chunked) null else x.req.head.content_length;
    const buf = try r.arena().alloc(u8, 64 * 1024);
    const body = try x.bodyReader(buf);
    const info = r.fs.write(r.path, body, len, ctype) catch |e| {
        // Drain a modest rest so the client reads the status instead of a reset.
        if (e != error.ReadFailed and (len orelse drain_max + 1) <= drain_max) _ = body.discardRemaining() catch {};
        return fail(x, e);
    };
    var eb: [core.ETag.quoted_max]u8 = undefined;
    return send(x, if (existed) .no_content else .created, "", &.{.{ .name = "etag", .value = info.etag.quoted(&eb) }});
}

fn delete(r: *Req) Error!void {
    const st = r.fs.stat(r.arena(), r.path) catch |e| return fail(r.x, e);
    if (st.kind == .root) return send(r.x, .forbidden, "", &.{});
    if (!try precheck(r, r.path, true)) return;
    deleteTree(r, r.path, st.kind) catch |e| return fail(r.x, e);
    r.s.locks.dropUnder(r.path);
    return send(r.x, .no_content, "", &.{});
}

fn mkcol(r: *Req) Error!void {
    const x = r.x;
    if (x.hasBody()) return send(x, .unsupported_media_type, "", &.{});
    if (r.fs.stat(r.arena(), r.path)) |_| {
        return send(x, .method_not_allowed, "", &.{});
    } else |e| if (e != error.NotFound) return fail(x, e);
    if (fsm.split(r.path).key.len > 0 and !try parentExists(r, r.path)) return;
    if (!try precheck(r, r.path, false)) return;
    r.fs.mkdir(r.arena(), r.path) catch |e| return fail(x, e);
    return send(x, .created, "", &.{});
}

fn copyMove(r: *Req, move: bool) Error!void {
    const x = r.x;
    const dh = x.header("destination") orelse return send(x, .bad_request, "", &.{});
    const denc = proto.stripPrefix(r.prefix(), proto.uriPath(dh)) orelse return send(x, .bad_gateway, "", &.{});
    const dst = resolve(r.arena(), denc) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidPath => return send(x, .bad_request, "", &.{}),
    };
    const overwrite = proto.parseOverwrite(x.header("overwrite")) orelse return send(x, .bad_request, "", &.{});
    const depth = proto.parseDepth(x.header("depth"), .infinity) orelse return send(x, .bad_request, "", &.{});
    if (depth == .one or (move and depth != .infinity)) return send(x, .bad_request, "", &.{});
    const st = r.fs.stat(r.arena(), r.path) catch |e| return fail(x, e);
    if (st.kind == .root or std.mem.eql(u8, dst, "/")) return send(x, .forbidden, "", &.{});
    if (std.mem.eql(u8, r.path, dst) or lockm.within(r.path, dst) or (move and lockm.within(dst, r.path)))
        return send(x, .forbidden, "", &.{});
    if (st.kind == .file and fsm.split(dst).key.len == 0) return send(x, .conflict, "", &.{});
    if (move and !try precheck(r, r.path, true)) return;
    if (!try precheck(r, dst, true)) return;
    var existed = false;
    if (r.fs.stat(r.arena(), dst)) |dst_st| {
        if (!overwrite) return send(x, .precondition_failed, "", &.{});
        existed = true;
        deleteTree(r, dst, dst_st.kind) catch |e| return fail(x, e);
        r.s.locks.dropUnder(dst);
    } else |e| if (e != error.NotFound) return fail(x, e);
    if (fsm.split(dst).key.len > 0 and !try parentExists(r, dst)) return;
    const res: fsm.Error!void = switch (st.kind) {
        .file => if (move) r.fs.rename(r.arena(), r.path, dst) else r.fs.copyFile(r.path, dst),
        else => if (move and st.kind == .dir and fsm.split(dst).key.len > 0)
            r.fs.rename(r.arena(), r.path, dst)
        else blk: {
            copyTree(r, r.path, dst, depth == .infinity) catch |e| break :blk e;
            if (move) deleteTree(r, r.path, st.kind) catch |e| break :blk e;
        },
    };
    res catch |e| return fail(x, e);
    if (move) r.s.locks.dropUnder(r.path);
    return send(x, if (existed) .no_content else .created, "", &.{});
}

fn readBody(r: *Req) Error!?[]const u8 {
    return r.x.readSmallBody(xml.max_input) catch |e| switch (e) {
        error.BodyTooLarge => {
            try send(r.x, .payload_too_large, "", &.{});
            return null;
        },
        else => return e,
    };
}

fn resourceOf(r: *Req, path: []const u8, kind: fsm.Kind, size: u64, mtime: i128, etag: ?core.ETag, ctype: []const u8, lbuf: []lockm.Lock) proto.Resource {
    const n = r.s.locks.discover(path, r.now, lbuf);
    return .{
        .path = path,
        .collection = isCollection(kind),
        .size = size,
        .mtime_ns = mtime,
        .etag = etag,
        .content_type = if (kind == .file) (if (ctype.len > 0) ctype else proto.guessType(path)) else "",
        .locks = lbuf[0..n],
        .now_s = r.now,
    };
}

fn propfind(r: *Req) Error!void {
    const x = r.x;
    const depth = proto.parseDepth(x.header("depth"), .infinity) orelse return send(x, .bad_request, "", &.{});
    if (depth == .infinity) return davError(x, .forbidden, "<D:propfind-finite-depth/>");
    const body = try readBody(r) orelse return;
    const pf = proto.parsePropfind(r.arena(), body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadBody => return send(x, .bad_request, "", &.{}),
    };
    const st = r.fs.stat(r.arena(), r.path) catch |e| return fail(x, e);
    var ctype: []const u8 = "";
    if (st.kind == .file) {
        if (r.fs.openRead(r.arena(), r.path)) |info| ctype = info.content_type else |_| {}
    }
    var first: ?fsm.Page = null;
    if (depth == .one and isCollection(st.kind)) first = r.fs.list(r.arena(), r.path, "", list_page) catch |e| return fail(x, e);

    const buf = try r.arena().alloc(u8, 32 * 1024);
    var bw = try x.req.respondStreaming(buf, .{ .respond_options = .{
        .status = .multi_status,
        .extra_headers = &.{.{ .name = "content-type", .value = xml_type }},
    } });
    const w = &bw.writer;
    var lbuf: [8]lockm.Lock = undefined;
    try w.writeAll(proto.multistatus_open);
    try proto.writeResponse(w, r.prefix(), resourceOf(r, r.path, st.kind, st.size, st.mtime_ns, st.etag, ctype, &lbuf), pf);
    if (first) |p0| {
        var page = p0;
        var page_arena = std.heap.ArenaAllocator.init(r.s.deps.gpa);
        defer page_arena.deinit();
        var total: usize = 0;
        while (true) {
            for (page.entries) |e| {
                const child = try join(page_arena.allocator(), r.path, e.name);
                try proto.writeResponse(w, r.prefix(), resourceOf(r, child, e.kind, e.size, e.mtime_ns, e.etag, "", &lbuf), pf);
            }
            total += page.entries.len;
            const cur = page.next orelse break;
            if (total >= max_listing) break;
            var cbuf: [fsm.max_path + 1]u8 = undefined;
            if (cur.len > cbuf.len) break;
            @memcpy(cbuf[0..cur.len], cur);
            _ = page_arena.reset(.retain_capacity);
            page = r.fs.list(page_arena.allocator(), r.path, cbuf[0..cur.len], list_page) catch return error.WriteFailed;
        }
    }
    try w.writeAll(proto.multistatus_close);
    try bw.end();
}

fn proppatch(r: *Req) Error!void {
    const x = r.x;
    const body = try readBody(r) orelse return;
    const props = proto.parseProppatch(r.arena(), body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.BadBody => return send(x, .bad_request, "", &.{}),
    };
    const st = r.fs.stat(r.arena(), r.path) catch |e| return fail(x, e);
    if (!try precheck(r, r.path, false)) return;
    var a: Writer.Allocating = .init(r.arena());
    const w = &a.writer;
    w.writeAll(proto.multistatus_open) catch return error.OutOfMemory;
    proto.writePatchResponse(w, r.prefix(), r.path, isCollection(st.kind), props, 403) catch return error.OutOfMemory;
    w.writeAll(proto.multistatus_close) catch return error.OutOfMemory;
    return sendXml(x, .multi_status, a.written(), &.{});
}

fn lockRes(r: *Req) Error!void {
    const x = r.x;
    const body = try readBody(r) orelse return;
    const timeout = lockm.parseTimeout(x.header("timeout"));
    var created = false;
    const granted: lockm.Lock = if (std.mem.trim(u8, body, " \t\r\n").len == 0) blk: {
        const tokens = try submitted(r) orelse return send(x, .bad_request, "", &.{});
        if (tokens.len == 0) return send(x, .bad_request, "", &.{});
        break :blk r.s.locks.refresh(r.path, tokens, timeout, r.now) catch return send(x, .precondition_failed, "", &.{});
    } else blk: {
        const li = proto.parseLockinfo(r.arena(), body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadBody => return send(x, .bad_request, "", &.{}),
        };
        const depth = proto.parseDepth(x.header("depth"), .infinity) orelse return send(x, .bad_request, "", &.{});
        if (depth == .one) return send(x, .bad_request, "", &.{});
        var exists = true;
        _ = r.fs.stat(r.arena(), r.path) catch |e| {
            if (e != error.NotFound) return fail(x, e);
            exists = false;
        };
        if (!exists) {
            if (fsm.split(r.path).key.len == 0) return send(x, .not_found, "", &.{});
            if (!try parentExists(r, r.path)) return;
        }
        if (x.header("if")) |h| {
            const lists = proto.parseIf(r.arena(), h) catch return send(x, .bad_request, "", &.{});
            if (!try ifHolds(r, lists)) return send(x, .precondition_failed, "", &.{});
        }
        const l = r.s.locks.acquire(.{
            .path = r.path,
            .infinite = depth == .infinity,
            .scope = li.scope,
            .owner = li.owner,
            .owner_href = li.owner_href,
            .timeout_s = timeout,
        }, r.now) catch |e| switch (e) {
            error.Locked => return davError(x, .locked, "<D:no-conflicting-lock/>"),
            error.Full => return send(x, .service_unavailable, "", &.{}),
            error.TooLong, error.NoMatch => return send(x, .bad_request, "", &.{}),
        };
        if (!exists) {
            var empty: std.Io.Reader = .fixed("");
            _ = r.fs.write(r.path, &empty, 0, proto.guessType(r.path)) catch |e| {
                r.s.locks.release(r.path, &l.token, r.now) catch {};
                return fail(x, e);
            };
            created = true;
        }
        break :blk l;
    };
    var a: Writer.Allocating = .init(r.arena());
    const w = &a.writer;
    render: {
        w.writeAll("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>") catch break :render;
        proto.writeActiveLock(w, r.prefix(), &granted, r.now) catch break :render;
        w.writeAll("</D:lockdiscovery></D:prop>\n") catch break :render;
    }
    const lt = try std.fmt.allocPrint(r.arena(), "<{s}>", .{&granted.token});
    return sendXml(x, if (created) .created else .ok, a.written(), &.{.{ .name = "lock-token", .value = lt }});
}

fn unlockRes(r: *Req) Error!void {
    const tok = proto.parseLockToken(r.x.header("lock-token")) orelse return send(r.x, .bad_request, "", &.{});
    r.s.locks.release(r.path, tok, r.now) catch return davError(r.x, .conflict, "<D:lock-token-matches-request-uri/>");
    return send(r.x, .no_content, "", &.{});
}

test "flags" {
    var c: Config = .{};
    try std.testing.expect(try parseFlag(&c, "--webdav", "127.0.0.1:8080"));
    try std.testing.expect(c.enabled());
    try std.testing.expect(try parseFlag(&c, "--webdav-prefix", "/dav/"));
    try std.testing.expectEqualStrings("/dav", c.prefix);
    try std.testing.expect(try parseFlag(&c, "--webdav-prefix", "/"));
    try std.testing.expectEqualStrings("", c.prefix);
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--webdav-prefix", "dav"));
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--webdav-prefix", "/a/../b"));
    try std.testing.expect(try parseFlag(&c, "--webdav-insecure", "on"));
    try std.testing.expect(c.insecure);
    try std.testing.expectError(error.BadArgs, parseFlag(&c, "--webdav-insecure", "yes"));
    try std.testing.expect(!try parseFlag(&c, "--ftp", "x"));
}

test "paths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("/b/a b", try resolve(a, "/b/./x/../a%20b/"));
    try std.testing.expectEqualStrings("/", try resolve(a, "/%2e%2e/.."));
    try std.testing.expectError(error.InvalidPath, resolve(a, "/b/%00"));
    try std.testing.expectEqualStrings("/b", parentOf("/b/x"));
    try std.testing.expectEqualStrings("/", parentOf("/b"));
}

test {
    _ = http;
    _ = proto;
    _ = xml;
    _ = lockm;
}
