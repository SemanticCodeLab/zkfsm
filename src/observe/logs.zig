//! Server log capture: every std.log line still goes to stderr, and info and
//! above are kept in a ring for `mc admin logs`, streamed live, and exported over OTLP.
const std = @import("std");
const core = @import("../core/root.zig");
const hub_mod = @import("hub.zig");
const otlp = @import("otlp.zig");

pub const ring_len = 1024;

pub const Logs = struct {
    gpa: std.mem.Allocator,
    hub: *hub_mod.Hub,
    exporter: ?*otlp.Exporter = null,
    deployment_id: []const u8 = "",
    node: []const u8 = "",
    mutex: std.Thread.Mutex = .{},
    ring: [ring_len]?[]u8 = @splat(null),
    next: usize = 0,

    pub fn deinit(l: *Logs) void {
        for (&l.ring) |*e| if (e.*) |x| {
            l.gpa.free(x);
            e.* = null;
        };
    }

    fn record(l: *Logs, level: std.log.Level, scope: []const u8, msg: []const u8) void {
        const now = std.time.nanoTimestamp();
        var tb: [40]u8 = undefined;
        const line = entryJson(l.gpa, l.deployment_id, l.node, level, now, msg, &tb) catch return;
        {
            l.mutex.lock();
            defer l.mutex.unlock();
            if (l.ring[l.next]) |old| l.gpa.free(old);
            l.ring[l.next] = line;
            l.next = (l.next + 1) % ring_len;
        }
        if (l.hub.wantsLogs()) l.hub.publishLog(line);
        if (l.exporter) |e| {
            const ctx = core.trace.currentContext();
            e.pushLog(.{
                .time_ns = @intCast(@max(now, 0)),
                .level = switch (level) {
                    .err => .err,
                    .warn => .warn,
                    .info => .info,
                    .debug => .debug,
                },
                .scope = scope,
                .msg = msg,
                .trace_id = if (ctx) |c| c.trace_id else null,
                .span_id = if (ctx) |c| c.span_id else null,
            });
        }
    }

    /// The newest `limit` entries (0 = all kept), oldest first; caller frees the slice only.
    pub fn recent(l: *Logs, a: std.mem.Allocator, limit: usize) error{OutOfMemory}![]const []const u8 {
        l.mutex.lock();
        defer l.mutex.unlock();
        var out: std.ArrayList([]const u8) = .empty;
        for (0..ring_len) |i| if (l.ring[(l.next + i) % ring_len]) |e| try out.append(a, try a.dupe(u8, e));
        const n = if (limit == 0) out.items.len else @min(limit, out.items.len);
        return out.items[out.items.len - n ..];
    }
};

/// Installed once at startup; the log function is process-wide.
pub var global: ?*Logs = null;
threadlocal var in_log: bool = false;

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    std.log.defaultLog(level, scope, format, args);
    if (level == .debug or scope == .otlp) return;
    const l = global orelse return;
    if (in_log) return;
    in_log = true;
    defer in_log = false;
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, format, args) catch buf[0..];
    l.record(level, @tagName(scope), msg);
}

/// RFC 3339 with nanoseconds, UTC.
pub fn rfc3339Nano(ns: i128, buf: *[40]u8) []const u8 {
    const t: u128 = @intCast(@max(ns, 0));
    const secs: u64 = @intCast(t / std.time.ns_per_s);
    const frac: u64 = @intCast(t % std.time.ns_per_s);
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}Z", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), frac,
    }) catch unreachable;
}

/// One madmin LogInfo object.
fn entryJson(gpa: std.mem.Allocator, deployment: []const u8, node: []const u8, level: std.log.Level, now: i128, msg: []const u8, tb: *[40]u8) error{OutOfMemory}![]u8 {
    const lv = switch (level) {
        .err => "ERROR",
        .warn => "WARNING",
        .info => "INFO",
        .debug => "DEBUG",
    };
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var s: std.json.Stringify = .{ .writer = &out.writer };
    write(&s, deployment, node, lv, rfc3339Nano(now, tb), msg, level == .err) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

fn write(s: *std.json.Stringify, deployment: []const u8, node: []const u8, lv: []const u8, time: []const u8, msg: []const u8, is_err: bool) std.Io.Writer.Error!void {
    try s.beginObject();
    try s.objectField("deploymentid");
    try s.write(deployment);
    try s.objectField("level");
    try s.write(lv);
    try s.objectField("errKind");
    try s.write("MINIO");
    try s.objectField("time");
    try s.write(time);
    try s.objectField("message");
    try s.write(msg);
    if (is_err) {
        try s.objectField("error");
        try s.beginObject();
        try s.objectField("message");
        try s.write(msg);
        try s.endObject();
    }
    try s.objectField("node");
    try s.write(node);
    try s.endObject();
}

test "ring keeps the newest entries and renders LogInfo" {
    const gpa = std.testing.allocator;
    var h: hub_mod.Hub = .init(gpa);
    defer h.deinit();
    var l: Logs = .{ .gpa = gpa, .hub = &h, .deployment_id = "dep", .node = "n1" };
    defer l.deinit();
    for (0..ring_len + 5) |i| {
        var b: [16]u8 = undefined;
        l.record(.info, "default", std.fmt.bufPrint(&b, "m{d}", .{i}) catch unreachable);
    }
    l.record(.err, "default", "boom");
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const r = try l.recent(arena.allocator(), 2);
    try std.testing.expectEqual(@as(usize, 2), r.len);
    try std.testing.expect(std.mem.indexOf(u8, r[1], "\"error\":{\"message\":\"boom\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, r[0], "\"deploymentid\":\"dep\"") != null);
    var tb: [40]u8 = undefined;
    try std.testing.expectEqualStrings("1970-01-01T00:00:01.000000005Z", rfc3339Nano(std.time.ns_per_s + 5, &tb));
}
