//! observe: OpenTelemetry export (traces, logs, metrics over OTLP/HTTP), metrics v3,
//! `mc admin trace` / `mc admin logs` streams, and server access log delivery.
//! Wired from main: the S3 observer and admin extension, raw metric routes, the span sink.
const std = @import("std");
const core = @import("../core/root.zig");
const s3 = @import("../s3/root.zig");
const admin = @import("../admin/root.zig");
const iam = @import("../iam/root.zig");
const object = @import("../object/root.zig");
const metrics = @import("../metrics/root.zig");

pub const proto = @import("proto.zig");
pub const otlp = @import("otlp.zig");
pub const hub = @import("hub.zig");
pub const logs = @import("logs.zig");
pub const apistats = @import("apistats.zig");
pub const metrics_v3 = @import("metrics_v3.zig");
pub const sysinfo = @import("sysinfo.zig");
pub const accesslog = @import("accesslog.zig");
pub const traceinfo = @import("traceinfo.zig");
pub const config = @import("config.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const trace = core.trace;
const Allocator = std.mem.Allocator;

/// Peer access for cluster-wide trace and log streams.
pub const Peers = struct {
    ctx: *anyopaque,
    count: usize,
    call: *const fn (ctx: *anyopaque, peer: usize, a: Allocator, body: []const u8) ?[]const u8,
};

pub const Options = struct {
    settings: config.Settings = .{},
    node: []const u8,
    deployment_id: []const u8,
    admin_prefix: []const u8 = admin.api.default_prefix,
    store: ?*iam.Store = null,
    /// Journal directory for access logs (a local drive).
    state_dir: []const u8,
};

pub const Observe = struct {
    gpa: Allocator,
    opts: Options,
    hub: hub.Hub,
    logs: logs.Logs,
    stats: apistats.Stats,
    exporter: ?*otlp.Exporter = null,
    delivery: ?*accesslog.Delivery = null,
    sources: metrics_v3.Sources = undefined,
    metrics_route: metrics_v3.Route = undefined,
    peers: ?Peers = null,

    /// Heap-pinned: the span sink, log hook, and routes point at it.
    pub fn create(gpa: Allocator, svc: *object.ObjectService, opts: Options) error{OutOfMemory}!*Observe {
        const o = try gpa.create(Observe);
        o.* = .{ .gpa = gpa, .opts = opts, .hub = .init(gpa), .logs = undefined, .stats = .{ .gpa = gpa } };
        o.logs = .{ .gpa = gpa, .hub = &o.hub, .deployment_id = opts.deployment_id, .node = opts.node };
        o.sources = .{ .svc = svc, .stats = &o.stats, .server = opts.node, .started_ns = std.time.nanoTimestamp() };
        o.metrics_route = .{ .src = &o.sources, .store = opts.store, .auth = if (opts.settings.prometheus_public) .public else .jwt };
        trace.setRatio(opts.settings.ratio);
        if (opts.settings.otlp) |cfg| {
            const e = try gpa.create(otlp.Exporter);
            e.* = .init(gpa, cfg);
            e.metrics = .{ .ctx = o, .func = renderAll };
            e.start() catch |err| {
                std.log.warn("otel: exporter not started: {t}", .{err});
                gpa.destroy(e);
                return o.finish();
            };
            o.exporter = e;
            o.sources.exporter = e;
            o.logs.exporter = e;
            trace.state.exporting.store(cfg.traces_url != null, .release);
            std.log.info("otel: exporting to {s} (sample ratio {d})", .{ cfg.traces_url orelse cfg.metrics_url orelse cfg.logs_url orelse "", opts.settings.ratio });
        }
        return o.finish();
    }

    fn finish(o: *Observe) *Observe {
        trace.state.sink = .{ .ctx = o, .finish = onSpan };
        logs.global = &o.logs;
        const dir = std.fs.path.join(o.gpa, &.{ o.opts.state_dir, "accesslog" }) catch return o;
        defer o.gpa.free(dir);
        if (accesslog.Delivery.init(o.gpa, o.sources.svc, .{
            .dir = dir,
            .node_id = o.opts.node,
            .interval_s = o.opts.settings.access_log_interval_s,
        })) |d| {
            d.start() catch {};
            o.delivery = d;
            o.sources.access_log = accesslog.Delivery.render;
            o.sources.access_log_ctx = d;
        } else |e| std.log.warn("access log: journal {s} unavailable ({t}); delivery disabled", .{ dir, e });
        return o;
    }

    /// Flushes exporters and pending access logs.
    pub fn destroy(o: *Observe) void {
        logs.global = null;
        trace.state.sink = null;
        trace.state.exporting.store(false, .release);
        if (o.delivery) |d| {
            d.deliverAll();
            d.deinit();
        }
        if (o.exporter) |e| {
            if (e.stop()) o.gpa.destroy(e);
        }
        o.logs.deinit();
        o.stats.deinit();
        o.hub.deinit();
        o.gpa.destroy(o);
    }

    pub fn observer(o: *Observe) s3.Observer {
        return .{ .ctx = o, .begin = begin, .end = end };
    }

    pub fn extension(o: *Observe) s3.Extension {
        return .{ .name = "observe", .ctx = o, .route = route, .before_authz = true };
    }

    pub fn rawRoute(o: *Observe) s3.server.RawRoute {
        return o.metrics_route.raw();
    }

    fn renderAll(ctx: *anyopaque, gpa: Allocator) error{OutOfMemory}![]u8 {
        const o: *Observe = @ptrCast(@alignCast(ctx));
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        _ = metrics_v3.render(&o.sources, arena.allocator(), &out.writer, "") catch return error.OutOfMemory;
        return out.toOwnedSlice();
    }

    // ------------------------------------------------------------ spans

    fn onSpan(ctx: *anyopaque, sp: *const trace.Span) void {
        const o: *Observe = @ptrCast(@alignCast(ctx));
        if (sp.exported()) if (o.exporter) |e| e.pushSpan(sp);
        if (sp.typ == .s3 or sp.typ == .admin) return;
        const bit = hub.bitOf(sp.typ);
        if (!o.hub.wantsTrace(bit)) return;
        const line = traceinfo.spanEntry(o.gpa, o.opts.node, sp) catch return;
        defer o.gpa.free(line);
        o.hub.publishTrace(bit, sp.err != null, @intCast(@max(0, sp.end_ns - sp.start_ns)), line);
    }

    // ------------------------------------------------------------ S3 observer

    const Req = struct { span: trace.Span = .{} };
    threadlocal var req_state: Req = .{};

    fn header(c: *const Ctx, name: []const u8) ?[]const u8 {
        for (c.req_headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    fn begin(_: *anyopaque, c: *Ctx) void {
        req_state = .{};
        req_state.span = trace.root("s3", .server, .s3, .{ .traceparent = header(c, "traceparent") });
    }

    fn end(ptr: *anyopaque, c: *Ctx, status: u16) void {
        const o: *Observe = @ptrCast(@alignCast(ptr));
        const end_ns = std.time.nanoTimestamp();
        const dur: u64 = @intCast(@max(0, end_ns - c.start_ns));
        const tx = metrics.global.txBody();
        const rx: u64 = c.auth.decoded_length orelse c.req.head.content_length orelse 0;
        const admin_op = admin.api.match(o.opts.admin_prefix, c.target);
        const idx: usize = if (admin_op != null)
            apistats.admin_index
        else if (s3.authz.classify(c.method, c.route.bucket, c.route.key, c.route.query, c.copy_source)) |op|
            @intFromEnum(op)
        else
            apistats.unknown_index;
        o.stats.record(.{
            .index = idx,
            .bucket = if (admin_op != null) "" else c.route.bucket,
            .status = status,
            .dur_ns = dur,
            .rx = rx,
            .tx = tx,
            .auth_rejected = status == 403 and c.auth.access_key.len == 0 and !c.auth.anonymous,
        });
        if (idx == @intFromEnum(iam.actions.Op.delete_bucket) and status == 204) o.stats.dropBucket(c.route.bucket);

        var fb: [96]u8 = undefined;
        const funcname: []const u8 = if (admin_op) |t|
            std.fmt.bufPrint(&fb, "admin{s}", .{t.op}) catch "admin"
        else
            std.fmt.bufPrint(&fb, "s3.{s}", .{apistats.names[idx]}) catch "s3";
        for (fb[0..funcname.len]) |*ch| if (ch.* == '/') {
            ch.* = '.';
        };
        const sp = &req_state.span;
        if (sp.recording) {
            sp.name = c.arena.dupe(u8, funcname) catch "s3";
            if (admin_op != null) sp.typ = .admin;
            sp.str("http.request.method", @tagName(c.method));
            sp.str("url.path", c.target[0 .. std.mem.indexOfScalar(u8, c.target, '?') orelse c.target.len]);
            if (c.route.query.len > 0) sp.str("url.query", c.route.query);
            sp.int("http.response.status_code", status);
            if (c.route.bucket.len > 0) sp.str("aws.s3.bucket", c.route.bucket);
            if (c.route.key.len > 0) sp.str("aws.s3.key", c.route.key);
            sp.str("aws.request_id", &c.request_id);
            sp.int("http.request.body.size", @intCast(@min(rx, std.math.maxInt(i63))));
            sp.int("http.response.body.size", @intCast(@min(tx, std.math.maxInt(i63))));
            if (header(c, "user-agent")) |ua| sp.str("user_agent.original", ua);
            if (c.auth.access_key.len > 0) sp.str("enduser.id", c.auth.access_key);
            if (c.peer) |p| if (std.fmt.allocPrint(c.arena, "{f}", .{p})) |s| sp.str("client.address", s) else |_| {};
            if (c.err_code.len > 0) sp.str("aws.s3.error_code", c.err_code);
            if (status >= 500) sp.fail(if (c.err_code.len > 0) c.err_code else "server error");
        }
        sp.end();
        if (o.hub.wantsTrace(hub.tt.s3)) {
            const client = if (c.peer) |p| std.fmt.allocPrint(c.arena, "{f}", .{p}) catch "" else "";
            if (traceinfo.s3Entry(c.arena, c, .{ .node = o.opts.node, .funcname = funcname, .start_ns = c.start_ns, .end_ns = end_ns, .status = status, .rx = rx, .tx = tx, .client = client })) |line|
                o.hub.publishTrace(hub.tt.s3, status >= 400, dur, line)
            else |_| {}
        }
        if (admin_op == null) if (o.delivery) |d| {
            d.record(c, status, tx, dur);
            if (idx == @intFromEnum(iam.actions.Op.put_bucket_logging) or idx == @intFromEnum(iam.actions.Op.delete_bucket)) d.invalidate(c.route.bucket);
        };
    }

    // ------------------------------------------------------------ admin streams

    fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
        const o: *Observe = @ptrCast(@alignCast(ptr));
        const t = admin.api.match(o.opts.admin_prefix, c.target) orelse return false;
        const stream: hub.Stream = if (std.mem.eql(u8, t.op, "/trace")) .trace else if (std.mem.eql(u8, t.op, "/log")) .log else return false;
        if (c.method != .GET) return false;
        const store = o.opts.store orelse {
            try fail(c, .not_implemented, "NotImplemented", "The admin API requires authenticated mode.");
            return true;
        };
        if (!try o.allowed(c, store, if (stream == .trace) "admin:ServerTrace" else "admin:ConsoleLog")) {
            try fail(c, .forbidden, "AccessDenied", "Access Denied.");
            return true;
        }
        const q = t.query;
        switch (stream) {
            .trace => {
                const f = traceFilter(c.arena, q) catch {
                    try fail(c, .bad_request, "XMinioAdminInvalidArgument", "Invalid trace parameters.");
                    return true;
                };
                try o.streamTrace(c, f);
            },
            .log => {
                const node = (admin.api.queryParam(c.arena, q, "node") catch null) orelse "";
                const limit_s = (admin.api.queryParam(c.arena, q, "limit") catch null) orelse "0";
                const limit = std.fmt.parseInt(usize, limit_s, 10) catch 0;
                try o.streamLogs(c, node, limit);
            },
        }
        return true;
    }

    fn allowed(o: *Observe, c: *Ctx, store: *iam.Store, action: []const u8) ConnError!bool {
        _ = o;
        var tbuf: s3.tenancy.NameBuf = undefined;
        const ac: admin.api.Ctx = .{ .a = c.arena, .env = .{ .store = store }, .req = .{
            .method = c.method,
            .target = .{ .op = "", .query = "" },
            .body = "",
            .caller = .{
                .access_key = c.auth.access_key,
                .secret = "",
                .principal = c.auth.principal,
                .session_policy = c.auth.session_policy,
                .federated_policies = c.auth.federated_policies,
                .tenant = try c.arena.dupe(u8, s3.tenancy.callerTenant(c.env.auth, c.auth, &tbuf) orelse ""),
            },
            .now_s = std.time.timestamp(),
        } };
        return ac.canAction(action);
    }

    fn fail(c: *Ctx, status: std.http.Status, code: []const u8, msg: []const u8) ConnError!void {
        const res = try admin.api.fail(c.arena, status, code, msg);
        metrics.global.last_status = @intFromEnum(status);
        c.err_code = code;
        try c.req.respond(res.body, .{ .status = status, .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
        } });
    }

    fn openStream(c: *Ctx, buf: []u8) ConnError!std.http.BodyWriter {
        metrics.global.last_status = 200;
        return c.req.respondStreaming(buf, .{ .respond_options = .{ .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
        } } }) catch return error.WriteFailed;
    }

    /// Sends what is buffered to the client now.
    fn push(bw: *std.http.BodyWriter) ConnError!void {
        bw.writer.flush() catch return error.WriteFailed;
        bw.flush() catch return error.WriteFailed;
    }

    fn streamTrace(o: *Observe, c: *Ctx, f: hub.Filter) ConnError!void {
        const sub = try o.hub.subscribe(.trace, f);
        defer o.hub.unsubscribe(sub);
        var id: [16]u8 = undefined;
        std.crypto.random.bytes(&id);
        const peer_id = std.fmt.bytesToHex(id, .lower);
        var buf: [16 * 1024]u8 = undefined;
        var bw = try openStream(c, &buf);
        try push(&bw);
        try o.pump(&bw, sub, .trace, &peer_id, f, "");
    }

    fn streamLogs(o: *Observe, c: *Ctx, node: []const u8, limit: usize) ConnError!void {
        const sub = try o.hub.subscribe(.log, .{});
        defer o.hub.unsubscribe(sub);
        var buf: [16 * 1024]u8 = undefined;
        var bw = try openStream(c, &buf);
        if (node.len == 0 or std.mem.eql(u8, node, o.opts.node)) {
            for (try o.logs.recent(c.arena, limit)) |line| {
                bw.writer.writeAll(line) catch return error.WriteFailed;
                bw.writer.writeByte('\n') catch return error.WriteFailed;
            }
        }
        try push(&bw);
        var id: [16]u8 = undefined;
        std.crypto.random.bytes(&id);
        const peer_id = std.fmt.bytesToHex(id, .lower);
        try o.pump(&bw, sub, .log, &peer_id, .{}, node);
    }

    /// Writes local and peer entries until the client goes away.
    fn pump(o: *Observe, bw: *std.http.BodyWriter, sub: *hub.Subscriber, stream: hub.Stream, peer_id: []const u8, f: hub.Filter, node: []const u8) ConnError!void {
        var idle_ms: u64 = 0;
        var tick: u64 = 0;
        const local = node.len == 0 or std.mem.eql(u8, node, o.opts.node);
        while (true) : (tick += 1) {
            const lines = try sub.take(o.gpa, 250 * std.time.ns_per_ms);
            defer {
                for (lines) |l| o.gpa.free(l);
                o.gpa.free(lines);
            }
            var wrote = false;
            if (local) for (lines) |l| {
                bw.writer.writeAll(l) catch return error.WriteFailed;
                bw.writer.writeByte('\n') catch return error.WriteFailed;
                wrote = true;
            };
            if (o.peers != null and tick % 2 == 0) wrote = (try o.pollPeers(bw, stream, peer_id, f, node)) or wrote;
            idle_ms = if (wrote) 0 else idle_ms + 250;
            // Whitespace between JSON values keeps the connection observed alive.
            if (idle_ms >= 1000) {
                bw.writer.writeByte(' ') catch return error.WriteFailed;
                wrote = true;
                idle_ms = 0;
            }
            if (wrote) try push(bw);
        }
    }

    fn pollPeers(o: *Observe, bw: *std.http.BodyWriter, stream: hub.Stream, peer_id: []const u8, f: hub.Filter, node: []const u8) ConnError!bool {
        const p = o.peers.?;
        var arena = std.heap.ArenaAllocator.init(o.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const body = try std.fmt.allocPrint(a, "{s}{{\"id\":\"{s}\",\"stream\":\"{t}\",\"mask\":{d},\"err\":{},\"thr\":{d},\"node\":\"{s}\"}}", .{ peer_magic, peer_id, stream, f.mask, f.only_errors, f.threshold_ns, node });
        var wrote = false;
        for (0..p.count) |i| {
            const res = p.call(p.ctx, i, a, body) orelse continue;
            if (res.len == 0) continue;
            bw.writer.writeAll(res) catch return error.WriteFailed;
            if (res[res.len - 1] != '\n') bw.writer.writeByte('\n') catch return error.WriteFailed;
            wrote = true;
        }
        return wrote;
    }

    pub const peer_magic = "obs1";

    /// Peer side of cluster streams: a remote subscriber per stream id, polled.
    pub fn handlePeer(o: *Observe, a: Allocator, body: []const u8) error{OutOfMemory}![]const u8 {
        const P = struct { id: []const u8, stream: []const u8, mask: u64 = 0, err: bool = false, thr: u64 = 0, node: []const u8 = "" };
        const req = std.json.parseFromSliceLeaky(P, a, body[peer_magic.len..], .{ .ignore_unknown_fields = true }) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            return "";
        };
        if (req.id.len == 0 or req.id.len > 32) return "";
        const stream = std.meta.stringToEnum(hub.Stream, req.stream) orelse return "";
        if (stream == .log and req.node.len > 0 and !std.mem.eql(u8, req.node, o.opts.node)) return "";
        o.hub.expire(10 * std.time.ns_per_s);
        o.hub.mutex.lock();
        var found: ?*hub.Subscriber = null;
        for (o.hub.subs.items) |s| if (std.mem.eql(u8, std.mem.sliceTo(&s.id, 0), req.id)) {
            found = s;
        };
        if (found) |s| {
            s.last_poll_ns = std.time.nanoTimestamp();
            const lines = s.take(o.gpa, 0) catch {
                o.hub.mutex.unlock();
                return error.OutOfMemory;
            };
            o.hub.mutex.unlock();
            defer {
                for (lines) |l| o.gpa.free(l);
                o.gpa.free(lines);
            }
            var out: std.ArrayList(u8) = .empty;
            for (lines) |l| {
                try out.appendSlice(a, l);
                try out.append(a, '\n');
            }
            return out.items;
        }
        o.hub.mutex.unlock();
        const s = try o.hub.subscribe(stream, .{ .mask = req.mask, .only_errors = req.err, .threshold_ns = req.thr });
        @memcpy(s.id[0..req.id.len], req.id);
        return "";
    }
};

/// Stable hooks for the listener that forward once the Observe instance exists
/// (cluster nodes serve raw routes before storage is up).
pub const Late = struct {
    ptr: std.atomic.Value(?*Observe) = .init(null),

    pub fn set(l: *Late, o: *Observe) void {
        l.ptr.store(o, .release);
    }

    fn get(l: *Late) ?*Observe {
        return l.ptr.load(.acquire);
    }

    pub fn observer(l: *Late) s3.Observer {
        return .{ .ctx = l, .begin = lBegin, .end = lEnd };
    }

    pub fn extension(l: *Late) s3.Extension {
        return .{ .name = "observe", .ctx = l, .route = lRoute, .before_authz = true };
    }

    pub fn rawRoute(l: *Late) s3.server.RawRoute {
        return .{ .prefix = metrics_v3.root_path, .ctx = l, .serve = lServe };
    }

    fn lBegin(ctx: *anyopaque, c: *Ctx) void {
        const l: *Late = @ptrCast(@alignCast(ctx));
        if (l.get()) |o| Observe.begin(o, c);
    }

    fn lEnd(ctx: *anyopaque, c: *Ctx, status: u16) void {
        const l: *Late = @ptrCast(@alignCast(ctx));
        if (l.get()) |o| Observe.end(o, c, status);
    }

    fn lRoute(ctx: *anyopaque, c: *Ctx) ConnError!bool {
        const l: *Late = @ptrCast(@alignCast(ctx));
        const o = l.get() orelse return false;
        return Observe.route(o, c);
    }

    fn lServe(ctx: *anyopaque, req: *std.http.Server.Request, arena: Allocator) s3.server.RawError!void {
        const l: *Late = @ptrCast(@alignCast(ctx));
        const o = l.get() orelse return req.respond("starting\n", .{ .status = .service_unavailable });
        const r = o.metrics_route.raw();
        return r.serve(r.ctx, req, arena);
    }

    /// Cluster ext-RPC multiplexer: observe polls first, everything else to `next`.
    pub fn peerHandle(l: *Late, a: Allocator, body: []const u8) error{OutOfMemory}!?[]const u8 {
        if (!std.mem.startsWith(u8, body, Observe.peer_magic)) return null;
        const o = l.get() orelse return "";
        return try o.handlePeer(a, body);
    }
};

fn traceFilter(a: Allocator, q: []const u8) error{ OutOfMemory, Invalid }!hub.Filter {
    var f: hub.Filter = .{ .mask = 0 };
    const tt = hub.tt;
    const flags = .{
        .{ "s3", tt.s3 },           .{ "internal", tt.internal },                     .{ "storage", tt.storage }, .{ "os", tt.os },
        .{ "scanner", tt.scanner }, .{ "healing", tt.healing },                       .{ "ftp", tt.ftp },         .{ "ilm", tt.ilm },
        .{ "kms", tt.kms },         .{ "replication-resync", tt.replication_resync },
    };
    inline for (flags) |fl| if (try admin.api.queryParam(a, q, fl[0])) |v| {
        if (std.mem.eql(u8, v, "true")) f.mask |= fl[1];
    };
    // Old clients send no type flags: S3 only.
    if (f.mask == 0) f.mask = tt.s3;
    if (try admin.api.queryParam(a, q, "err")) |v| f.only_errors = std.mem.eql(u8, v, "true");
    if (try admin.api.queryParam(a, q, "threshold")) |v| f.threshold_ns = hub.parseDuration(v) orelse return error.Invalid;
    return f;
}

test {
    _ = proto;
    _ = otlp;
    _ = hub;
    _ = logs;
    _ = apistats;
    _ = metrics_v3;
    _ = sysinfo;
    _ = accesslog;
    _ = traceinfo;
    _ = config;
}

test "trace filter from query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const f = try traceFilter(arena.allocator(), "err=true&threshold=100ms&s3=true&storage=true&internal=false");
    try std.testing.expect(f.only_errors);
    try std.testing.expectEqual(@as(u64, 100_000_000), f.threshold_ns);
    try std.testing.expectEqual(hub.tt.s3 | hub.tt.storage, f.mask);
    try std.testing.expectEqual(hub.tt.s3, (try traceFilter(arena.allocator(), "")).mask);
}
