//! Replication counters per target and Prometheus exposition.
const std = @import("std");

pub const Target = struct {
    bucket: []const u8,
    arn: []const u8,
    sent_count: u64 = 0,
    sent_bytes: u64 = 0,
    failed_count: u64 = 0,
    failed_bytes: u64 = 0,
    pending_count: u64 = 0,
    online: bool = true,
    last_online_ns: i128 = 0,
    offline_since_ns: i128 = 0,
    downtime_ns: i128 = 0,
    offline_count: u64 = 0,
    latency_ns: u64 = 0,
};

pub const Stats = struct {
    gpa: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    targets: std.StringArrayHashMapUnmanaged(*Target) = .empty,
    received_count: u64 = 0,
    received_bytes: u64 = 0,
    queued: u64 = 0,
    retries: u64 = 0,
    started_ns: i128 = 0,

    pub fn deinit(s: *Stats) void {
        for (s.targets.values()) |t| {
            s.gpa.free(t.bucket);
            s.gpa.free(t.arn);
            s.gpa.destroy(t);
        }
        s.targets.deinit(s.gpa);
    }

    /// Caller holds `mutex`; null only when out of memory.
    pub fn targetLocked(s: *Stats, bucket: []const u8, arn: []const u8) ?*Target {
        if (s.targets.get(arn)) |t| return t;
        const t = s.gpa.create(Target) catch return null;
        t.* = .{
            .bucket = s.gpa.dupe(u8, bucket) catch {
                s.gpa.destroy(t);
                return null;
            },
            .arn = s.gpa.dupe(u8, arn) catch {
                s.gpa.free(t.bucket);
                s.gpa.destroy(t);
                return null;
            },
        };
        s.targets.put(s.gpa, t.arn, t) catch {
            s.gpa.free(t.bucket);
            s.gpa.free(t.arn);
            s.gpa.destroy(t);
            return null;
        };
        return t;
    }

    pub fn sent(s: *Stats, bucket: []const u8, arn: []const u8, bytes: u64) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        const t = s.targetLocked(bucket, arn) orelse return;
        t.sent_count += 1;
        t.sent_bytes += bytes;
    }

    pub fn failed(s: *Stats, bucket: []const u8, arn: []const u8, bytes: u64) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        s.retries += 1;
        const t = s.targetLocked(bucket, arn) orelse return;
        t.failed_count += 1;
        t.failed_bytes += bytes;
    }

    pub fn received(s: *Stats, bytes: u64) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        s.received_count += 1;
        s.received_bytes += bytes;
    }

    /// Records a reachability observation for a target.
    pub fn health(s: *Stats, bucket: []const u8, arn: []const u8, online: bool, latency_ns: u64) void {
        s.mutex.lock();
        defer s.mutex.unlock();
        const t = s.targetLocked(bucket, arn) orelse return;
        const now = std.time.nanoTimestamp();
        if (online) {
            if (!t.online and t.offline_since_ns > 0) t.downtime_ns += now - t.offline_since_ns;
            t.online = true;
            t.last_online_ns = now;
            t.offline_since_ns = 0;
            t.latency_ns = latency_ns;
        } else if (t.online) {
            t.online = false;
            t.offline_since_ns = now;
            t.offline_count += 1;
        }
    }

    pub fn snapshot(s: *Stats, arn: []const u8) ?Target {
        s.mutex.lock();
        defer s.mutex.unlock();
        const t = s.targets.get(arn) orelse return null;
        return t.*;
    }

    pub fn render(ctx: *anyopaque, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const s: *Stats = @ptrCast(@alignCast(ctx));
        s.mutex.lock();
        defer s.mutex.unlock();
        const families = [_][3][]const u8{
            .{ "zkfsm_replication_sent_objects_total", "counter", "sent_count" },
            .{ "zkfsm_replication_sent_bytes_total", "counter", "sent_bytes" },
            .{ "zkfsm_replication_failed_total", "counter", "failed_count" },
            .{ "zkfsm_replication_failed_bytes_total", "counter", "failed_bytes" },
            .{ "zkfsm_replication_pending_operations", "gauge", "pending_count" },
            .{ "zkfsm_replication_target_offline_total", "counter", "offline_count" },
        };
        inline for (families) |f| {
            try w.print("# TYPE {s} {s}\n", .{ f[0], f[1] });
            for (s.targets.values()) |t| try w.print("{s}{{bucket=\"{s}\",target=\"{s}\"}} {d}\n", .{ f[0], t.bucket, t.arn, @field(t, f[2]) });
        }
        try w.writeAll("# TYPE zkfsm_replication_target_online gauge\n");
        for (s.targets.values()) |t| try w.print("zkfsm_replication_target_online{{bucket=\"{s}\",target=\"{s}\"}} {d}\n", .{ t.bucket, t.arn, @intFromBool(t.online) });
        try w.writeAll("# TYPE zkfsm_replication_target_latency_seconds gauge\n");
        for (s.targets.values()) |t| try w.print("zkfsm_replication_target_latency_seconds{{bucket=\"{s}\",target=\"{s}\"}} {d}.{d:0>9}\n", .{ t.bucket, t.arn, t.latency_ns / std.time.ns_per_s, t.latency_ns % std.time.ns_per_s });
        try w.print("# TYPE zkfsm_replication_received_objects_total counter\nzkfsm_replication_received_objects_total {d}\n", .{s.received_count});
        try w.print("# TYPE zkfsm_replication_received_bytes_total counter\nzkfsm_replication_received_bytes_total {d}\n", .{s.received_bytes});
        try w.print("# TYPE zkfsm_replication_queue_length gauge\nzkfsm_replication_queue_length {d}\n", .{s.queued});
        try w.print("# TYPE zkfsm_replication_retries_total counter\nzkfsm_replication_retries_total {d}\n", .{s.retries});
    }
};

test "stats render" {
    var s: Stats = .{ .gpa = std.testing.allocator };
    defer s.deinit();
    s.sent("b", "arn:x", 10);
    s.failed("b", "arn:x", 3);
    s.health("b", "arn:x", false, 0);
    s.received(5);
    var buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try Stats.render(&s, &w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_replication_sent_bytes_total{bucket=\"b\",target=\"arn:x\"} 10") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_replication_target_online{bucket=\"b\",target=\"arn:x\"} 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_replication_received_bytes_total 5") != null);
}
