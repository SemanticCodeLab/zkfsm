//! Live streams for `mc admin trace` and `mc admin logs`: subscribers own a bounded
//! queue of rendered JSON lines; slow subscribers drop entries instead of blocking.
const std = @import("std");
const core = @import("../core/root.zig");

const Allocator = std.mem.Allocator;

pub const Stream = enum { trace, log };

/// madmin trace type bits (TraceType).
pub const tt = struct {
    pub const os: u64 = 1 << 0;
    pub const storage: u64 = 1 << 1;
    pub const s3: u64 = 1 << 2;
    pub const internal: u64 = 1 << 3;
    pub const scanner: u64 = 1 << 4;
    pub const healing: u64 = 1 << 6;
    pub const replication_resync: u64 = 1 << 11;
    pub const ftp: u64 = 1 << 13;
    pub const ilm: u64 = 1 << 14;
    pub const kms: u64 = 1 << 15;
};

/// The madmin trace bit a span type is reported under.
pub fn bitOf(t: core.trace.Type) u64 {
    return switch (t) {
        .s3, .admin => tt.s3,
        .gateway => tt.ftp,
        .storage => tt.storage,
        .internal => tt.internal,
        .kms => tt.kms,
        .ilm => tt.ilm,
        .replication => tt.replication_resync,
        .scanner => tt.scanner,
        .healing => tt.healing,
        .os => tt.os,
    };
}

pub const Filter = struct {
    /// madmin TraceType mask (trace) or ignored (log).
    mask: u64 = tt.s3,
    only_errors: bool = false,
    threshold_ns: u64 = 0,
};

pub const Subscriber = struct {
    stream: Stream,
    filter: Filter,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    lines: std.ArrayList([]u8) = .empty,
    dropped: u64 = 0,
    closed: bool = false,
    /// Remote (peer-polled) subscribers expire when not polled.
    last_poll_ns: i128 = 0,
    id: [32]u8 = @splat(0),

    const max_lines = 4096;

    fn push(s: *Subscriber, gpa: Allocator, line: []const u8) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        if (s.lines.items.len >= max_lines) {
            s.dropped += 1;
            return;
        }
        const copy = gpa.dupe(u8, line) catch return;
        s.lines.append(gpa, copy) catch {
            gpa.free(copy);
            return;
        };
        s.cond.signal();
    }

    /// Takes queued lines (caller frees each and the slice), waiting up to `wait_ns`.
    pub fn take(s: *Subscriber, gpa: Allocator, wait_ns: u64) error{OutOfMemory}![][]u8 {
        s.mutex.lock();
        defer s.mutex.unlock();
        if (s.lines.items.len == 0 and !s.closed and wait_ns > 0) s.cond.timedWait(&s.mutex, wait_ns) catch {};
        const out = try s.lines.toOwnedSlice(gpa);
        return out;
    }
};

pub const Hub = struct {
    gpa: Allocator,
    mutex: std.Thread.Mutex = .{},
    subs: std.ArrayList(*Subscriber) = .empty,
    /// Union of trace masks, for cheap "anyone listening" checks.
    trace_mask: std.atomic.Value(u64) = .init(0),
    log_subs: std.atomic.Value(u32) = .init(0),

    pub fn init(gpa: Allocator) Hub {
        return .{ .gpa = gpa };
    }

    pub fn deinit(h: *Hub) void {
        for (h.subs.items) |s| h.destroy(s);
        h.subs.deinit(h.gpa);
    }

    fn destroy(h: *Hub, s: *Subscriber) void {
        for (s.lines.items) |l| h.gpa.free(l);
        s.lines.deinit(h.gpa);
        h.gpa.destroy(s);
    }

    pub fn subscribe(h: *Hub, stream: Stream, f: Filter) error{OutOfMemory}!*Subscriber {
        const s = try h.gpa.create(Subscriber);
        s.* = .{ .stream = stream, .filter = f, .last_poll_ns = std.time.nanoTimestamp() };
        h.mutex.lock();
        defer h.mutex.unlock();
        h.subs.append(h.gpa, s) catch {
            h.gpa.destroy(s);
            return error.OutOfMemory;
        };
        h.recompute();
        return s;
    }

    pub fn unsubscribe(h: *Hub, s: *Subscriber) void {
        h.mutex.lock();
        defer h.mutex.unlock();
        for (h.subs.items, 0..) |x, i| if (x == s) {
            _ = h.subs.swapRemove(i);
            break;
        };
        h.recompute();
        h.destroy(s);
    }

    /// Finds a remote subscriber by id (peer polling).
    pub fn byId(h: *Hub, id: []const u8) ?*Subscriber {
        h.mutex.lock();
        defer h.mutex.unlock();
        for (h.subs.items) |s| if (std.mem.eql(u8, std.mem.sliceTo(&s.id, 0), id)) return s;
        return null;
    }

    /// Drops remote subscribers not polled within `ttl_ns`.
    pub fn expire(h: *Hub, ttl_ns: i128) void {
        const now = std.time.nanoTimestamp();
        h.mutex.lock();
        defer h.mutex.unlock();
        var i: usize = 0;
        while (i < h.subs.items.len) {
            const s = h.subs.items[i];
            if (s.id[0] != 0 and now - s.last_poll_ns > ttl_ns) {
                _ = h.subs.swapRemove(i);
                h.destroy(s);
                continue;
            }
            i += 1;
        }
        h.recompute();
    }

    fn recompute(h: *Hub) void {
        var mask: u64 = 0;
        var logs: u32 = 0;
        for (h.subs.items) |s| switch (s.stream) {
            .trace => mask |= s.filter.mask,
            .log => logs += 1,
        };
        h.trace_mask.store(mask, .release);
        h.log_subs.store(logs, .release);
        // Span types the tracer must record for live subscribers (S3 comes from the observer).
        var live: u32 = 0;
        inline for (@typeInfo(core.trace.Type).@"enum".fields) |f| {
            const t: core.trace.Type = @enumFromInt(f.value);
            if (t != .s3 and t != .admin and mask & bitOf(t) != 0) live |= @as(u32, 1) << f.value;
        }
        core.trace.state.live.store(live, .release);
    }

    pub fn wantsTrace(h: *const Hub, bit: u64) bool {
        return h.trace_mask.load(.acquire) & bit != 0;
    }

    pub fn wantsLogs(h: *const Hub) bool {
        return h.log_subs.load(.acquire) > 0;
    }

    /// Delivers one rendered trace entry to the subscribers whose filter matches.
    pub fn publishTrace(h: *Hub, bit: u64, failed: bool, dur_ns: u64, line: []const u8) void {
        h.mutex.lock();
        defer h.mutex.unlock();
        for (h.subs.items) |s| {
            if (s.stream != .trace or s.filter.mask & bit == 0) continue;
            if (s.filter.only_errors and !failed) continue;
            if (dur_ns < s.filter.threshold_ns) continue;
            s.push(h.gpa, line);
        }
    }

    pub fn publishLog(h: *Hub, line: []const u8) void {
        h.mutex.lock();
        defer h.mutex.unlock();
        for (h.subs.items) |s| if (s.stream == .log) s.push(h.gpa, line);
    }
};

/// Go `time.ParseDuration` subset: "0s", "100ms", "1.5s", "2m", "1h30m".
pub fn parseDuration(s: []const u8) ?u64 {
    if (s.len == 0) return 0;
    var i: usize = 0;
    var total: f64 = 0;
    while (i < s.len) {
        const num_start = i;
        while (i < s.len and (std.ascii.isDigit(s[i]) or s[i] == '.')) i += 1;
        if (i == num_start) return null;
        const v = std.fmt.parseFloat(f64, s[num_start..i]) catch return null;
        const unit_start = i;
        while (i < s.len and !std.ascii.isDigit(s[i]) and s[i] != '.') i += 1;
        const u = s[unit_start..i];
        const mult: f64 = if (std.mem.eql(u8, u, "ns")) 1 else if (std.mem.eql(u8, u, "us") or std.mem.eql(u8, u, "µs")) 1e3 else if (std.mem.eql(u8, u, "ms")) 1e6 else if (std.mem.eql(u8, u, "s")) 1e9 else if (std.mem.eql(u8, u, "m")) 60e9 else if (std.mem.eql(u8, u, "h")) 3600e9 else if (u.len == 0 and v == 0) 0 else return null;
        total += v * mult;
    }
    return @intFromFloat(@min(total, 1.8e19));
}

test "hub routes by mask, errors, and threshold" {
    const gpa = std.testing.allocator;
    var h: Hub = .init(gpa);
    defer h.deinit();
    const a = try h.subscribe(.trace, .{ .mask = tt.s3 });
    const b = try h.subscribe(.trace, .{ .mask = tt.storage | tt.s3, .only_errors = true });
    try std.testing.expect(h.wantsTrace(tt.storage));
    try std.testing.expect(core.trace.state.live.load(.monotonic) & (1 << @intFromEnum(core.trace.Type.storage)) != 0);
    h.publishTrace(tt.s3, false, 10, "ok");
    h.publishTrace(tt.s3, true, 10, "bad");
    h.publishTrace(tt.storage, true, 10, "disk");
    const la = try a.take(gpa, 0);
    defer {
        for (la) |l| gpa.free(l);
        gpa.free(la);
    }
    const lb = try b.take(gpa, 0);
    defer {
        for (lb) |l| gpa.free(l);
        gpa.free(lb);
    }
    try std.testing.expectEqual(@as(usize, 2), la.len);
    try std.testing.expectEqual(@as(usize, 2), lb.len);
    try std.testing.expectEqualStrings("bad", lb[0]);
    h.unsubscribe(b);
    h.unsubscribe(a);
    try std.testing.expectEqual(@as(u32, 0), core.trace.state.live.load(.monotonic));
    try std.testing.expectEqual(@as(?u64, 1_500_000_000), parseDuration("1.5s"));
    try std.testing.expectEqual(@as(?u64, 0), parseDuration("0s"));
    try std.testing.expectEqual(@as(?u64, 5_400_000_000_000), parseDuration("1h30m"));
    try std.testing.expect(parseDuration("x") == null);
}
