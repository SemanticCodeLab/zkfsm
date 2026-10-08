//! Request tracing: span ids, W3C traceparent, and the thread's current span.
//! Finished recording spans go to one process-wide sink (OTLP export, live trace).
const std = @import("std");

/// What a span covers; live trace subscribers filter on it.
pub const Type = enum(u5) { s3, admin, gateway, storage, internal, kms, ilm, replication, scanner, healing, os };
/// OTLP SpanKind numbering.
pub const Kind = enum(u3) { internal = 1, server = 2, client = 3, producer = 4, consumer = 5 };

pub const Context = struct {
    trace_id: [16]u8,
    span_id: [8]u8,
    sampled: bool,
};

pub const Value = union(enum) { str: []const u8, int: i64 };
pub const Attr = struct { key: []const u8, value: Value };
pub const max_attrs = 20;

pub const Span = struct {
    recording: bool = false,
    ctx: Context = undefined,
    parent: ?[8]u8 = null,
    name: []const u8 = "",
    kind: Kind = .internal,
    typ: Type = .s3,
    start_ns: i128 = 0,
    end_ns: i128 = 0,
    err: ?[]const u8 = null,
    attrs: [max_attrs]Attr = undefined,
    n_attrs: u8 = 0,
    /// Set when this span became the thread's current one; restored by `end`.
    prev: ?Context = null,
    restores: bool = false,

    pub fn str(s: *Span, key: []const u8, v: []const u8) void {
        s.put(key, .{ .str = v });
    }

    pub fn int(s: *Span, key: []const u8, v: i64) void {
        s.put(key, .{ .int = v });
    }

    fn put(s: *Span, key: []const u8, v: Value) void {
        if (!s.recording) return;
        for (s.attrs[0..s.n_attrs]) |*a| if (std.mem.eql(u8, a.key, key)) {
            a.value = v;
            return;
        };
        if (s.n_attrs == max_attrs) return;
        s.attrs[s.n_attrs] = .{ .key = key, .value = v };
        s.n_attrs += 1;
    }

    /// Marks the span failed; `msg` must outlive `end`.
    pub fn fail(s: *Span, msg: []const u8) void {
        if (s.recording) s.err = msg;
    }

    pub fn attributes(s: *const Span) []const Attr {
        return s.attrs[0..s.n_attrs];
    }

    pub fn end(s: *Span) void {
        if (s.restores) current = s.prev;
        s.restores = false;
        if (!s.recording) return;
        s.recording = false;
        s.end_ns = std.time.nanoTimestamp();
        if (state.sink) |k| k.finish(k.ctx, s);
    }

    /// True when the span goes to the OTLP exporter (not only to live trace).
    pub fn exported(s: *const Span) bool {
        return s.ctx.sampled and state.exporting.load(.monotonic);
    }
};

pub const Sink = struct {
    ctx: *anyopaque,
    finish: *const fn (ctx: *anyopaque, s: *const Span) void,
};

pub const state = struct {
    /// Set once at startup, before serving.
    pub var sink: ?Sink = null;
    pub var exporting: std.atomic.Value(bool) = .init(false);
    /// Root sampling threshold over the low 8 trace-id bytes; maxInt = always.
    pub var threshold: std.atomic.Value(u64) = .init(std.math.maxInt(u64));
    /// Bit per `Type` with at least one live subscriber.
    pub var live: std.atomic.Value(u32) = .init(0);
};

threadlocal var current: ?Context = null;

pub fn setRatio(r: f64) void {
    const t: u64 = if (r >= 1.0) std.math.maxInt(u64) else if (r <= 0) 0 else @intFromFloat(r * 18446744073709551615.0);
    state.threshold.store(t, .monotonic);
}

fn liveFor(t: Type) bool {
    return state.live.load(.monotonic) & (@as(u32, 1) << @intFromEnum(t)) != 0;
}

fn active() bool {
    return state.exporting.load(.monotonic) or state.live.load(.monotonic) != 0;
}

pub fn currentContext() ?Context {
    return current;
}

pub const RootOptions = struct {
    /// Incoming `traceparent` header value.
    traceparent: ?[]const u8 = null,
    /// Without a parent, start a new (ratio-sampled) trace; else export nothing.
    fresh: bool = true,
};

/// Starts the span of an incoming request or a background task; it becomes current.
pub fn root(name: []const u8, kind: Kind, typ: Type, o: RootOptions) Span {
    if (!active()) return .{};
    const remote: ?Context = if (o.traceparent) |h| parse(h) else null;
    var ctx: Context = .{ .trace_id = undefined, .span_id = undefined, .sampled = false };
    if (remote) |r| {
        ctx.trace_id = r.trace_id;
        ctx.sampled = r.sampled;
    } else {
        std.crypto.random.bytes(&ctx.trace_id);
        const low = std.mem.readInt(u64, ctx.trace_id[8..16], .big);
        ctx.sampled = o.fresh and low <= state.threshold.load(.monotonic) and state.threshold.load(.monotonic) != 0;
    }
    std.crypto.random.bytes(&ctx.span_id);
    var s: Span = .{ .name = name, .kind = kind, .typ = typ, .ctx = ctx, .parent = if (remote) |r| r.span_id else null };
    s.recording = (ctx.sampled and state.exporting.load(.monotonic)) or liveFor(typ);
    s.prev = current;
    s.restores = true;
    current = ctx;
    if (s.recording) s.start_ns = std.time.nanoTimestamp();
    return s;
}

/// A child of the current span that becomes current until `end`.
pub fn child(name: []const u8, kind: Kind, typ: Type) Span {
    return start(name, kind, typ, true);
}

/// A child that never becomes current (client calls, storage operations).
pub fn leaf(name: []const u8, kind: Kind, typ: Type) Span {
    return start(name, kind, typ, false);
}

fn start(name: []const u8, kind: Kind, typ: Type, nest: bool) Span {
    if (!active()) return .{};
    const parent = current;
    const sampled = if (parent) |p| p.sampled else false;
    const rec = (sampled and state.exporting.load(.monotonic)) or liveFor(typ);
    if (!rec) return .{};
    var ctx: Context = .{ .trace_id = undefined, .span_id = undefined, .sampled = sampled };
    if (parent) |p| ctx.trace_id = p.trace_id else std.crypto.random.bytes(&ctx.trace_id);
    std.crypto.random.bytes(&ctx.span_id);
    var s: Span = .{ .recording = true, .name = name, .kind = kind, .typ = typ, .ctx = ctx, .parent = if (parent) |p| p.span_id else null };
    if (nest) {
        s.prev = current;
        s.restores = true;
        current = ctx;
    }
    s.start_ns = std.time.nanoTimestamp();
    return s;
}

pub const header_len = 55;

/// `traceparent` value for an outgoing call made under the current span.
pub fn outgoing(buf: *[header_len]u8) ?[]const u8 {
    const c = current orelse return null;
    return format(c, buf);
}

pub fn format(c: Context, buf: *[header_len]u8) []const u8 {
    return std.fmt.bufPrint(buf, "00-{x}-{x}-{s}", .{ &c.trace_id, &c.span_id, if (c.sampled) "01" else "00" }) catch unreachable;
}

/// W3C trace-context `traceparent`; null when malformed or all-zero ids.
pub fn parse(h: []const u8) ?Context {
    const v = std.mem.trim(u8, h, " \t");
    if (v.len < header_len) return null;
    if (v[2] != '-' or v[35] != '-' or v[52] != '-') return null;
    if (std.mem.eql(u8, v[0..2], "ff")) return null;
    // Version 00 is exactly 55 characters; later versions may append fields.
    if (std.mem.eql(u8, v[0..2], "00") and v.len != header_len) return null;
    if (v.len > header_len and v[header_len] != '-') return null;
    var c: Context = .{ .trace_id = undefined, .span_id = undefined, .sampled = false };
    _ = std.fmt.hexToBytes(&c.trace_id, v[3..35]) catch return null;
    _ = std.fmt.hexToBytes(&c.span_id, v[36..52]) catch return null;
    for (v[0..55]) |ch| if (std.ascii.isUpper(ch)) return null;
    var flags: [1]u8 = undefined;
    _ = std.fmt.hexToBytes(&flags, v[53..55]) catch return null;
    if (std.mem.allEqual(u8, &c.trace_id, 0) or std.mem.allEqual(u8, &c.span_id, 0)) return null;
    c.sampled = flags[0] & 1 == 1;
    return c;
}

test "traceparent round trip and rejects" {
    const h = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const c = parse(h).?;
    try std.testing.expect(c.sampled);
    var buf: [header_len]u8 = undefined;
    try std.testing.expectEqualStrings(h, format(c, &buf));
    try std.testing.expect(parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01") == null);
    try std.testing.expect(parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01") == null);
    try std.testing.expect(parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") == null);
    try std.testing.expect(parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01") == null);
    try std.testing.expect(parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0") == null);
    try std.testing.expect(parse("garbage") == null);
    try std.testing.expect(!parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00-extra").?.sampled);
}

test "spans nest, sample, and reach the sink" {
    const Rec = struct {
        var n: usize = 0;
        var last_parent: ?[8]u8 = null;
        fn finish(_: *anyopaque, s: *const Span) void {
            n += 1;
            last_parent = s.parent;
        }
    };
    var dummy: u8 = 0;
    state.sink = .{ .ctx = &dummy, .finish = Rec.finish };
    defer state.sink = null;
    state.exporting.store(true, .monotonic);
    defer state.exporting.store(false, .monotonic);
    var r = root("req", .server, .s3, .{ .traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" });
    try std.testing.expect(r.recording);
    var ch = child("storage", .internal, .storage);
    try std.testing.expectEqualSlices(u8, &r.ctx.span_id, &ch.parent.?);
    var buf: [header_len]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, outgoing(&buf).?, "4bf92f3577b34da6a3ce929d0e0e4736") != null);
    ch.end();
    try std.testing.expectEqualSlices(u8, &r.ctx.span_id, &currentContext().?.span_id);
    r.end();
    try std.testing.expect(currentContext() == null);
    try std.testing.expectEqual(@as(usize, 2), Rec.n);
    // Unsampled parent: nothing records without live subscribers.
    var u = root("req", .server, .s3, .{ .traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00" });
    try std.testing.expect(!u.recording);
    var c2 = leaf("x", .client, .internal);
    try std.testing.expect(!c2.recording);
    c2.end();
    u.end();
    setRatio(0);
    var z = root("req", .server, .s3, .{});
    try std.testing.expect(!z.recording);
    z.end();
    setRatio(1);
    try std.testing.expectEqual(@as(usize, 2), Rec.n);
}
