//! OTLP/HTTP protobuf export of spans, logs, and metrics: bounded queues drained by
//! one background thread that POSTs to `<endpoint>/v1/{traces,logs,metrics}`.
const std = @import("std");
const core = @import("../core/root.zig");
const proto = @import("proto.zig");

const trace = core.trace;
const Allocator = std.mem.Allocator;

pub const Signal = enum { traces, logs, metrics };

pub const Config = struct {
    /// Per-signal full URLs; null disables the signal.
    traces_url: ?[]const u8 = null,
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,
    headers: []const std.http.Header = &.{},
    /// Resource attributes; service.name first.
    resource: []const [2][]const u8 = &.{},
    schedule_delay_ms: u32 = 5000,
    max_queue: u32 = 2048,
    max_batch: u32 = 512,
    metrics_interval_ms: u32 = 60000,
    timeout_ms: u32 = 10000,
};

/// A finished span copied out of the request's memory.
pub const SpanRec = struct {
    trace_id: [16]u8,
    span_id: [8]u8,
    parent: ?[8]u8,
    sampled: bool,
    kind: trace.Kind,
    name: []const u8,
    start_ns: u64,
    end_ns: u64,
    err: ?[]const u8,
    attrs: []trace.Attr,
    /// One allocation holding the strings and the attribute array.
    mem: []u8,

    pub fn copy(gpa: Allocator, s: *const trace.Span) error{OutOfMemory}!*SpanRec {
        var need: usize = s.name.len + (if (s.err) |e| e.len else 0);
        for (s.attributes()) |a| {
            need += a.key.len;
            if (a.value == .str) need += a.value.str.len;
        }
        const r = try gpa.create(SpanRec);
        errdefer gpa.destroy(r);
        const mem = try gpa.alloc(u8, need);
        errdefer gpa.free(mem);
        const attrs = try gpa.alloc(trace.Attr, s.n_attrs);
        var off: usize = 0;
        const dup = struct {
            fn f(m: []u8, o: *usize, v: []const u8) []const u8 {
                @memcpy(m[o.*..][0..v.len], v);
                defer o.* += v.len;
                return m[o.*..][0..v.len];
            }
        }.f;
        for (s.attributes(), attrs) |a, *d| {
            d.key = dup(mem, &off, a.key);
            d.value = switch (a.value) {
                .str => |v| .{ .str = dup(mem, &off, v) },
                .int => |v| .{ .int = v },
            };
        }
        r.* = .{
            .trace_id = s.ctx.trace_id,
            .span_id = s.ctx.span_id,
            .parent = s.parent,
            .sampled = s.ctx.sampled,
            .kind = s.kind,
            .name = dup(mem, &off, s.name),
            .start_ns = nanos(s.start_ns),
            .end_ns = nanos(s.end_ns),
            .err = if (s.err) |e| dup(mem, &off, e) else null,
            .attrs = attrs,
            .mem = mem,
        };
        return r;
    }

    pub fn destroy(r: *SpanRec, gpa: Allocator) void {
        gpa.free(r.attrs);
        gpa.free(r.mem);
        gpa.destroy(r);
    }
};

pub const Level = enum { debug, info, warn, err };

pub const LogRec = struct {
    time_ns: u64,
    level: Level,
    scope: []const u8,
    msg: []const u8,
    trace_id: ?[16]u8 = null,
    span_id: ?[8]u8 = null,
};

fn nanos(t: i128) u64 {
    return if (t <= 0) 0 else @intCast(@min(t, std.math.maxInt(u64)));
}

// ---------------------------------------------------------------- encoding

fn keyValue(w: *proto.Writer, field: u32, k: []const u8, v: trace.Value) proto.Error!void {
    try w.begin(field);
    try w.str(1, k);
    try w.begin(2);
    switch (v) {
        .str => |s| {
            // An empty string must still select the string_value arm.
            if (s.len == 0) {
                try w.buf.appendSlice(w.gpa, &.{ 0x0a, 0x00 });
            } else try w.str(1, s);
        },
        .int => |n| {
            try w.buf.append(w.gpa, 0x18);
            var u: u64 = @bitCast(n);
            while (u >= 0x80) : (u >>= 7) try w.buf.append(w.gpa, @as(u8, @truncate(u)) | 0x80);
            try w.buf.append(w.gpa, @truncate(u));
        },
    }
    try w.end();
    try w.end();
}

fn resource(w: *proto.Writer, res: []const [2][]const u8) proto.Error!void {
    try w.begin(1);
    for (res) |kv| try keyValue(w, 1, kv[0], .{ .str = kv[1] });
    try w.end();
}

fn scope(w: *proto.Writer) proto.Error!void {
    try w.begin(1);
    try w.str(1, "zkfsm");
    try w.str(2, "0.1.0");
    try w.end();
}

pub fn encodeSpans(gpa: Allocator, res: []const [2][]const u8, spans: []const *SpanRec) proto.Error![]u8 {
    var w: proto.Writer = .init(gpa);
    errdefer w.deinit();
    try w.begin(1); // ResourceSpans
    try resource(&w, res);
    try w.begin(2); // ScopeSpans
    try scope(&w);
    for (spans) |s| {
        try w.begin(2);
        try w.str(1, &s.trace_id);
        try w.str(2, &s.span_id);
        if (s.parent) |p| try w.str(4, &p);
        try w.str(5, s.name);
        try w.uint(6, @intFromEnum(s.kind));
        try w.fixed64(7, s.start_ns);
        try w.fixed64(8, s.end_ns);
        for (s.attrs) |a| try keyValue(&w, 9, a.key, a.value);
        try w.begin(15); // Status
        if (s.err) |e| try w.str(2, e);
        try w.uint(3, if (s.err != null) 2 else 0);
        try w.end();
        try w.fixed32(16, if (s.sampled) 0x101 else 0x100);
        try w.end();
    }
    try w.end();
    try w.end();
    return w.buf.toOwnedSlice(gpa);
}

pub fn encodeLogs(gpa: Allocator, res: []const [2][]const u8, logs: []const LogRec) proto.Error![]u8 {
    var w: proto.Writer = .init(gpa);
    errdefer w.deinit();
    try w.begin(1); // ResourceLogs
    try resource(&w, res);
    try w.begin(2); // ScopeLogs
    try scope(&w);
    for (logs) |l| {
        try w.begin(2);
        try w.fixed64(1, l.time_ns);
        const sev: struct { u64, []const u8 } = switch (l.level) {
            .debug => .{ 5, "DEBUG" },
            .info => .{ 9, "INFO" },
            .warn => .{ 13, "WARN" },
            .err => .{ 17, "ERROR" },
        };
        try w.uint(2, sev[0]);
        try w.str(3, sev[1]);
        try w.begin(5);
        try w.str(1, l.msg);
        try w.end();
        if (l.scope.len > 0) try keyValue(&w, 6, "log.scope", .{ .str = l.scope });
        if (l.trace_id) |t| try w.str(9, &t);
        if (l.span_id) |s| try w.str(10, &s);
        try w.fixed64(11, l.time_ns);
        try w.end();
    }
    try w.end();
    try w.end();
    return w.buf.toOwnedSlice(gpa);
}

/// Converts Prometheus text exposition (as rendered by this server) to OTLP metrics:
/// counters become monotonic cumulative sums, gauges gauges, histograms histograms.
pub fn encodeMetrics(gpa: Allocator, res: []const [2][]const u8, text: []const u8, start_ns: u64, now_ns: u64) error{OutOfMemory}![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fams = try parseExposition(a, text);
    var w: proto.Writer = .init(gpa);
    errdefer w.deinit();
    try w.begin(1); // ResourceMetrics
    try resource(&w, res);
    try w.begin(2); // ScopeMetrics
    try scope(&w);
    for (fams) |f| {
        if (f.samples.items.len == 0) continue;
        try w.begin(2);
        try w.str(1, f.name);
        try w.str(2, f.help);
        switch (f.kind) {
            .counter, .gauge, .untyped => {
                const sum = f.kind == .counter;
                try w.begin(if (sum) 7 else 5);
                for (f.samples.items) |s| {
                    try w.begin(1);
                    for (s.labels) |l| try keyValue(&w, 7, l[0], .{ .str = l[1] });
                    if (sum) try w.fixed64(2, start_ns);
                    try w.fixed64(3, now_ns);
                    try w.double(4, s.value);
                    try w.end();
                }
                if (sum) {
                    try w.uint(2, 2); // cumulative
                    try w.boolean(3, true);
                }
                try w.end();
            },
            .histogram => {
                try w.begin(9);
                for (try groupHistogram(a, f)) |h| {
                    try w.begin(1);
                    for (h.labels) |l| try keyValue(&w, 9, l[0], .{ .str = l[1] });
                    try w.fixed64(2, start_ns);
                    try w.fixed64(3, now_ns);
                    try w.fixed64(4, h.count);
                    try w.double(5, h.sum);
                    try w.packedFixed64(6, h.counts);
                    try w.packedDouble(7, h.bounds);
                    try w.end();
                }
                try w.uint(2, 2);
                try w.end();
            },
        }
        try w.end();
    }
    try w.end();
    try w.end();
    return w.buf.toOwnedSlice(gpa);
}

const FamKind = enum { counter, gauge, histogram, untyped };
const Sample = struct { suffix: []const u8, labels: []const [2][]const u8, value: f64 };
const Family = struct { name: []const u8, help: []const u8 = "", kind: FamKind, samples: std.ArrayList(Sample) = .empty };

fn parseExposition(a: Allocator, text: []const u8) error{OutOfMemory}![]Family {
    var fams: std.ArrayList(Family) = .empty;
    var helps: std.StringHashMapUnmanaged([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line0| {
        const line = std.mem.trim(u8, line0, " \r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "# HELP ")) {
            const rest = line[7..];
            const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
            try helps.put(a, rest[0..sp], rest[sp + 1 ..]);
            continue;
        }
        if (std.mem.startsWith(u8, line, "# TYPE ")) {
            var p = std.mem.tokenizeScalar(u8, line[7..], ' ');
            const name = p.next() orelse continue;
            const t = p.next() orelse "untyped";
            const kind: FamKind = if (std.mem.eql(u8, t, "counter")) .counter else if (std.mem.eql(u8, t, "gauge")) .gauge else if (std.mem.eql(u8, t, "histogram")) .histogram else .untyped;
            try fams.append(a, .{ .name = name, .help = helps.get(name) orelse "", .kind = kind });
            continue;
        }
        if (line[0] == '#') continue;
        const s = parseSample(a, line) orelse continue;
        // Attach to the family whose name prefixes the sample name.
        var target: ?*Family = null;
        var i = fams.items.len;
        while (i > 0) {
            i -= 1;
            const f = &fams.items[i];
            if (std.mem.eql(u8, f.name, s.name) or (f.kind == .histogram and std.mem.startsWith(u8, s.name, f.name) and isHistSuffix(s.name[f.name.len..]))) {
                target = f;
                break;
            }
        }
        if (target == null) {
            try fams.append(a, .{ .name = s.name, .kind = .untyped });
            target = &fams.items[fams.items.len - 1];
        }
        const f = target.?;
        try f.samples.append(a, .{ .suffix = s.name[f.name.len..], .labels = s.labels, .value = s.value });
    }
    return fams.items;
}

fn isHistSuffix(s: []const u8) bool {
    return std.mem.eql(u8, s, "_bucket") or std.mem.eql(u8, s, "_sum") or std.mem.eql(u8, s, "_count");
}

const Parsed = struct { name: []const u8, labels: []const [2][]const u8, value: f64 };

fn parseSample(a: Allocator, line: []const u8) ?Parsed {
    var labels: std.ArrayList([2][]const u8) = .empty;
    var i: usize = 0;
    while (i < line.len and line[i] != '{' and line[i] != ' ') i += 1;
    const name = line[0..i];
    if (i < line.len and line[i] == '{') {
        i += 1;
        while (i < line.len and line[i] != '}') {
            const eq = std.mem.indexOfScalarPos(u8, line, i, '=') orelse return null;
            const key = std.mem.trim(u8, line[i..eq], " ,");
            if (eq + 1 >= line.len or line[eq + 1] != '"') return null;
            var j = eq + 2;
            var val: std.ArrayList(u8) = .empty;
            while (j < line.len and line[j] != '"') : (j += 1) {
                var ch = line[j];
                if (ch == '\\' and j + 1 < line.len) {
                    j += 1;
                    ch = if (line[j] == 'n') '\n' else line[j];
                }
                val.append(a, ch) catch return null;
            }
            labels.append(a, .{ key, val.items }) catch return null;
            i = j + 1;
            while (i < line.len and (line[i] == ',' or line[i] == ' ')) i += 1;
        }
        i += 1;
    }
    const rest = std.mem.trim(u8, line[@min(i, line.len)..], " ");
    const vtxt = rest[0 .. std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len];
    const v = if (std.mem.eql(u8, vtxt, "+Inf")) std.math.inf(f64) else std.fmt.parseFloat(f64, vtxt) catch return null;
    return .{ .name = name, .labels = labels.items, .value = v };
}

const Hist = struct { labels: []const [2][]const u8, counts: []u64, bounds: []f64, count: u64, sum: f64 };

fn sameLabels(x: []const [2][]const u8, y: []const [2][]const u8) bool {
    var nx: usize = 0;
    for (x) |l| {
        if (std.mem.eql(u8, l[0], "le")) continue;
        nx += 1;
        const found = for (y) |m| {
            if (std.mem.eql(u8, l[0], m[0]) and std.mem.eql(u8, l[1], m[1])) break true;
        } else false;
        if (!found) return false;
    }
    var ny: usize = 0;
    for (y) |l| ny += @intFromBool(!std.mem.eql(u8, l[0], "le"));
    return nx == ny;
}

/// Prometheus buckets are cumulative; OTLP wants per-bucket counts.
fn groupHistogram(a: Allocator, f: Family) error{OutOfMemory}![]Hist {
    var out: std.ArrayList(Hist) = .empty;
    var done = try a.alloc(bool, f.samples.items.len);
    @memset(done, false);
    for (f.samples.items, 0..) |s, i| {
        if (done[i] or !std.mem.eql(u8, s.suffix, "_bucket")) continue;
        var bounds: std.ArrayList(f64) = .empty;
        var cum: std.ArrayList(u64) = .empty;
        var labels: std.ArrayList([2][]const u8) = .empty;
        for (s.labels) |l| if (!std.mem.eql(u8, l[0], "le")) try labels.append(a, l);
        var h: Hist = .{ .labels = labels.items, .counts = &.{}, .bounds = &.{}, .count = 0, .sum = 0 };
        for (f.samples.items[i..], i..) |t, j| {
            if (!sameLabels(t.labels, s.labels)) continue;
            done[j] = true;
            if (std.mem.eql(u8, t.suffix, "_bucket")) {
                const le = for (t.labels) |l| {
                    if (std.mem.eql(u8, l[0], "le")) break l[1];
                } else "+Inf";
                if (!std.mem.eql(u8, le, "+Inf")) try bounds.append(a, std.fmt.parseFloat(f64, le) catch continue);
                try cum.append(a, @intFromFloat(@max(0, t.value)));
            } else if (std.mem.eql(u8, t.suffix, "_sum")) {
                h.sum = t.value;
            } else if (std.mem.eql(u8, t.suffix, "_count")) {
                h.count = @intFromFloat(@max(0, t.value));
            }
        }
        if (cum.items.len == bounds.items.len) try cum.append(a, h.count);
        const counts = try a.alloc(u64, cum.items.len);
        var prev: u64 = 0;
        for (cum.items, counts) |c, *d| {
            d.* = c -| prev;
            prev = @max(prev, c);
        }
        h.counts = counts;
        h.bounds = bounds.items;
        try out.append(a, h);
    }
    return out.items;
}

// ---------------------------------------------------------------- exporter

pub const Renderer = struct {
    ctx: *anyopaque,
    func: *const fn (ctx: *anyopaque, gpa: Allocator) error{OutOfMemory}![]u8,
};

pub const Stats = struct {
    exported: [3]std.atomic.Value(u64) = .{ .init(0), .init(0), .init(0) },
    failed: [3]std.atomic.Value(u64) = .{ .init(0), .init(0), .init(0) },
    dropped: [3]std.atomic.Value(u64) = .{ .init(0), .init(0), .init(0) },
};

pub const Exporter = struct {
    gpa: Allocator,
    cfg: Config,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    spans: std.ArrayList(*SpanRec) = .empty,
    logs: std.ArrayList(LogRec) = .empty,
    stopping: bool = false,
    thread: ?std.Thread = null,
    metrics: ?Renderer = null,
    stats: Stats = .{},
    started_ns: u64 = 0,
    done: std.Thread.ResetEvent = .{},

    pub fn init(gpa: Allocator, cfg: Config) Exporter {
        return .{ .gpa = gpa, .cfg = cfg, .started_ns = nanos(std.time.nanoTimestamp()) };
    }

    pub fn start(e: *Exporter) std.Thread.SpawnError!void {
        e.thread = try std.Thread.spawn(.{}, loop, .{e});
    }

    /// Flushes what is queued, then joins the worker. Returns false (and leaves the
    /// exporter allocated) when a hung collector keeps the worker past the timeout.
    pub fn stop(e: *Exporter) bool {
        {
            e.mutex.lock();
            defer e.mutex.unlock();
            e.stopping = true;
            e.cond.signal();
        }
        if (e.thread) |t| {
            e.done.timedWait(@as(u64, e.cfg.timeout_ms) * std.time.ns_per_ms + 2 * std.time.ns_per_s) catch {
                std.log.scoped(.otlp).warn("otel: exporter still busy at shutdown; abandoning queued data", .{});
                t.detach();
                return false;
            };
            t.join();
        }
        e.thread = null;
        for (e.spans.items) |s| s.destroy(e.gpa);
        e.spans.deinit(e.gpa);
        for (e.logs.items) |l| e.gpa.free(l.msg);
        e.logs.deinit(e.gpa);
        return true;
    }

    pub fn pushSpan(e: *Exporter, s: *const trace.Span) void {
        if (e.cfg.traces_url == null) return;
        const rec = SpanRec.copy(e.gpa, s) catch {
            _ = e.stats.dropped[0].fetchAdd(1, .monotonic);
            return;
        };
        e.mutex.lock();
        defer e.mutex.unlock();
        if (e.spans.items.len >= e.cfg.max_queue or e.stopping) {
            _ = e.stats.dropped[0].fetchAdd(1, .monotonic);
            rec.destroy(e.gpa);
            return;
        }
        e.spans.append(e.gpa, rec) catch {
            rec.destroy(e.gpa);
            return;
        };
        if (e.spans.items.len >= e.cfg.max_batch) e.cond.signal();
    }

    /// `msg` is copied.
    pub fn pushLog(e: *Exporter, l: LogRec) void {
        if (e.cfg.logs_url == null) return;
        var rec = l;
        rec.msg = e.gpa.dupe(u8, l.msg) catch return;
        e.mutex.lock();
        defer e.mutex.unlock();
        if (e.logs.items.len >= e.cfg.max_queue or e.stopping) {
            _ = e.stats.dropped[1].fetchAdd(1, .monotonic);
            e.gpa.free(rec.msg);
            return;
        }
        e.logs.append(e.gpa, rec) catch e.gpa.free(rec.msg);
    }

    fn loop(e: *Exporter) void {
        defer e.done.set();
        var client: std.http.Client = .{ .allocator = e.gpa };
        defer client.deinit();
        var next_metrics: i128 = std.time.nanoTimestamp() + @as(i128, e.cfg.metrics_interval_ms) * std.time.ns_per_ms;
        while (true) {
            var spans: []*SpanRec = &.{};
            var logs: []LogRec = &.{};
            var stopping = false;
            {
                e.mutex.lock();
                defer e.mutex.unlock();
                if (!e.stopping and e.spans.items.len < e.cfg.max_batch)
                    e.cond.timedWait(&e.mutex, @as(u64, e.cfg.schedule_delay_ms) * std.time.ns_per_ms) catch {};
                stopping = e.stopping;
                const ns = @min(e.spans.items.len, e.cfg.max_batch);
                if (ns > 0) {
                    spans = e.gpa.dupe(*SpanRec, e.spans.items[0..ns]) catch &.{};
                    if (spans.len > 0) e.spans.replaceRangeAssumeCapacity(0, ns, &.{});
                }
                const nl = @min(e.logs.items.len, e.cfg.max_batch);
                if (nl > 0) {
                    logs = e.gpa.dupe(LogRec, e.logs.items[0..nl]) catch &.{};
                    if (logs.len > 0) e.logs.replaceRangeAssumeCapacity(0, nl, &.{});
                }
            }
            if (spans.len > 0) {
                e.sendSpans(&client, spans);
                for (spans) |s| s.destroy(e.gpa);
                e.gpa.free(spans);
            }
            if (logs.len > 0) {
                e.sendLogs(&client, logs);
                for (logs) |l| e.gpa.free(l.msg);
                e.gpa.free(logs);
            }
            const now = std.time.nanoTimestamp();
            if (e.metrics != null and e.cfg.metrics_url != null and (now >= next_metrics or stopping)) {
                next_metrics = now + @as(i128, e.cfg.metrics_interval_ms) * std.time.ns_per_ms;
                e.sendMetrics(&client);
            }
            if (stopping) {
                e.mutex.lock();
                const empty = e.spans.items.len == 0 and e.logs.items.len == 0;
                e.mutex.unlock();
                if (empty) return;
            }
        }
    }

    fn sendSpans(e: *Exporter, client: *std.http.Client, spans: []const *SpanRec) void {
        const body = encodeSpans(e.gpa, e.cfg.resource, spans) catch return;
        defer e.gpa.free(body);
        e.post(client, .traces, e.cfg.traces_url.?, body, spans.len);
    }

    fn sendLogs(e: *Exporter, client: *std.http.Client, logs: []const LogRec) void {
        const body = encodeLogs(e.gpa, e.cfg.resource, logs) catch return;
        defer e.gpa.free(body);
        e.post(client, .logs, e.cfg.logs_url.?, body, logs.len);
    }

    fn sendMetrics(e: *Exporter, client: *std.http.Client) void {
        const r = e.metrics.?;
        const text = r.func(r.ctx, e.gpa) catch return;
        defer e.gpa.free(text);
        const body = encodeMetrics(e.gpa, e.cfg.resource, text, e.started_ns, nanos(std.time.nanoTimestamp())) catch return;
        defer e.gpa.free(body);
        e.post(client, .metrics, e.cfg.metrics_url.?, body, 1);
    }

    fn post(e: *Exporter, client: *std.http.Client, sig: Signal, url: []const u8, body: []const u8, n: usize) void {
        const i = @intFromEnum(sig);
        const res = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .keep_alive = true,
            .headers = .{ .content_type = .{ .override = "application/x-protobuf" } },
            .extra_headers = e.cfg.headers,
        }) catch |err| {
            _ = e.stats.failed[i].fetchAdd(n, .monotonic);
            std.log.scoped(.otlp).debug("export {t} to {s} failed: {t}", .{ sig, url, err });
            return;
        };
        if (@intFromEnum(res.status) / 100 == 2) {
            _ = e.stats.exported[i].fetchAdd(n, .monotonic);
        } else {
            _ = e.stats.failed[i].fetchAdd(n, .monotonic);
            std.log.scoped(.otlp).debug("export {t} to {s}: HTTP {d}", .{ sig, url, @intFromEnum(res.status) });
        }
    }
};

test "span request encodes trace ids and attributes" {
    const gpa = std.testing.allocator;
    var s: trace.Span = .{ .recording = true, .name = "s3.GetObject", .kind = .server, .ctx = .{ .trace_id = @splat(1), .span_id = @splat(2), .sampled = true }, .start_ns = 10, .end_ns = 20 };
    s.str("http.request.method", "GET");
    s.int("http.response.status_code", 200);
    s.recording = true;
    const rec = try SpanRec.copy(gpa, &s);
    defer rec.destroy(gpa);
    const body = try encodeSpans(gpa, &.{.{ "service.name", "zkfsm" }}, &.{rec});
    defer gpa.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "s3.GetObject") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "http.request.method") != null);
    // ResourceSpans -> ScopeSpans -> Span -> trace_id.
    var r: proto.Reader = .{ .s = body };
    var rs: proto.Reader = .{ .s = r.next().?.data };
    _ = rs.next(); // resource
    var ss: proto.Reader = .{ .s = rs.next().?.data };
    _ = ss.next(); // scope
    var sp: proto.Reader = .{ .s = ss.next().?.data };
    const tid = sp.next().?;
    try std.testing.expectEqual(@as(u32, 1), tid.num);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(1)), tid.data);
}

test "metrics conversion: counters, gauges, histograms" {
    const gpa = std.testing.allocator;
    const text =
        \\# HELP a_total requests
        \\# TYPE a_total counter
        \\a_total{name="GetObject",type="s3"} 3
        \\# TYPE g gauge
        \\g 1.5
        \\# TYPE h histogram
        \\h_bucket{api="x",le="0.1"} 1
        \\h_bucket{api="x",le="1"} 3
        \\h_bucket{api="x",le="+Inf"} 4
        \\h_sum{api="x"} 2.5
        \\h_count{api="x"} 4
        \\
    ;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const fams = try parseExposition(arena.allocator(), text);
    try std.testing.expectEqual(@as(usize, 3), fams.len);
    const hs = try groupHistogram(arena.allocator(), fams[2]);
    try std.testing.expectEqual(@as(usize, 1), hs.len);
    try std.testing.expectEqualSlices(u64, &.{ 1, 2, 1 }, hs[0].counts);
    try std.testing.expectEqual(@as(u64, 4), hs[0].count);
    const body = try encodeMetrics(gpa, &.{}, text, 1, 2);
    defer gpa.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "a_total") != null);
}
