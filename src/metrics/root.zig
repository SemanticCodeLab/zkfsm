//! metrics: process-wide atomic counters, Prometheus text exposition, and
//! the health endpoints. Handlers record; the server serves.
const std = @import("std");
const object = @import("../object/root.zig");

pub const Status = enum(u3) { s2xx, s3xx, s4xx, s5xx, other };

const bucket_bounds_ms = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 };

pub const Counters = struct {
    started_ns: i128 = 0,
    requests: [5]std.atomic.Value(u64) = [_]std.atomic.Value(u64){.init(0)} ** 5,
    inflight: std.atomic.Value(i64) = .init(0),
    latency_buckets: [bucket_bounds_ms.len]std.atomic.Value(u64) = [_]std.atomic.Value(u64){.init(0)} ** bucket_bounds_ms.len,
    latency_sum_us: std.atomic.Value(u64) = .init(0),
    conn_errors: std.atomic.Value(u64) = .init(0),

    pub fn begin(c: *Counters) i128 {
        _ = c.inflight.fetchAdd(1, .monotonic);
        return std.time.nanoTimestamp();
    }

    pub fn end(c: *Counters, start_ns: i128, status: u10) void {
        _ = c.inflight.fetchSub(1, .monotonic);
        const cls: Status = switch (status) {
            200...299 => .s2xx,
            300...399 => .s3xx,
            400...499 => .s4xx,
            500...599 => .s5xx,
            else => .other,
        };
        _ = c.requests[@intFromEnum(cls)].fetchAdd(1, .monotonic);
        const elapsed = std.time.nanoTimestamp() - start_ns;
        const us: u64 = if (elapsed <= 0) 0 else std.math.cast(u64, @divTrunc(elapsed, 1000)) orelse std.math.maxInt(u64);
        _ = c.latency_sum_us.fetchAdd(us, .monotonic);
        for (bucket_bounds_ms, 0..) |b, i| {
            if (us <= b * 1000) _ = c.latency_buckets[i].fetchAdd(1, .monotonic);
        }
    }

    pub fn render(c: *const Counters, w: *std.Io.Writer) std.Io.Writer.Error!void {
        const names = [_][]const u8{ "2xx", "3xx", "4xx", "5xx", "other" };
        try w.writeAll("# TYPE zkfsm_requests_total counter\n");
        var total: u64 = 0;
        for (names, 0..) |n, i| {
            const v = c.requests[i].load(.monotonic);
            total += v;
            try w.print("zkfsm_requests_total{{code=\"{s}\"}} {d}\n", .{ n, v });
        }
        try w.print("# TYPE zkfsm_requests_inflight gauge\nzkfsm_requests_inflight {d}\n", .{c.inflight.load(.monotonic)});
        try w.writeAll("# TYPE zkfsm_request_duration_seconds histogram\n");
        for (bucket_bounds_ms, 0..) |b, i| {
            try w.print("zkfsm_request_duration_seconds_bucket{{le=\"{d}.{d:0>3}\"}} {d}\n", .{ b / 1000, b % 1000, c.latency_buckets[i].load(.monotonic) });
        }
        try w.print("zkfsm_request_duration_seconds_bucket{{le=\"+Inf\"}} {d}\n", .{total});
        const sum_us = c.latency_sum_us.load(.monotonic);
        try w.print("zkfsm_request_duration_seconds_sum {d}.{d:0>6}\n", .{ sum_us / 1_000_000, sum_us % 1_000_000 });
        try w.print("zkfsm_request_duration_seconds_count {d}\n", .{total});
        try w.print("# TYPE zkfsm_connection_errors_total counter\nzkfsm_connection_errors_total {d}\n", .{c.conn_errors.load(.monotonic)});
        const up_ns = std.time.nanoTimestamp() - c.started_ns;
        try w.print("# TYPE zkfsm_uptime_seconds gauge\nzkfsm_uptime_seconds {d}\n", .{@divTrunc(@max(up_ns, 0), std.time.ns_per_s)});
        try w.writeAll("# TYPE zkfsm_build_info gauge\nzkfsm_build_info{version=\"0.1.0\"} 1\n");
    }
};

pub const global = struct {
    pub var counters: Counters = .{};
    /// Status of the response being written on this thread.
    pub threadlocal var last_status: u10 = 200;
};

pub const Endpoint = enum { live, ready, metrics };

/// Where the operational endpoints live.
pub const Paths = struct {
    /// `{health_prefix}/live` and `{health_prefix}/ready`.
    health_prefix: []const u8 = "/health",
    metrics_path: []const u8 = "/metrics",
    /// Also serve `/minio/health/*` and `/minio/v2/metrics/cluster`.
    minio_compat: bool = true,
};

/// Operational paths are served before S3 routing and need no auth.
pub fn match(target: []const u8) ?Endpoint {
    return matchPaths(.{}, target);
}

pub fn matchPaths(p: Paths, target: []const u8) ?Endpoint {
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    const eql = std.mem.eql;
    if (eql(u8, path, p.metrics_path) or (p.minio_compat and eql(u8, path, "/minio/v2/metrics/cluster"))) return .metrics;
    if (p.minio_compat and std.mem.startsWith(u8, path, "/minio/health/")) {
        if (eql(u8, path, "/minio/health/live")) return .live;
        if (eql(u8, path, "/minio/health/ready")) return .ready;
    }
    if (!std.mem.startsWith(u8, path, p.health_prefix)) return null;
    const rest = path[p.health_prefix.len..];
    if (eql(u8, rest, "/live")) return .live;
    if (eql(u8, rest, "/ready")) return .ready;
    return null;
}

pub fn isReady(svc: *object.ObjectService) bool {
    svc.store.sync() catch return false;
    return true;
}

test "endpoint matching" {
    try std.testing.expectEqual(Endpoint.live, match("/health/live").?);
    try std.testing.expectEqual(Endpoint.ready, match("/minio/health/ready?x=1").?);
    try std.testing.expectEqual(Endpoint.metrics, match("/metrics").?);
    try std.testing.expect(match("/healthz") == null);
    try std.testing.expect(match("/bucket/health/live") == null);
    const p: Paths = .{ .health_prefix = "/ops/h", .metrics_path = "/ops/m", .minio_compat = false };
    try std.testing.expectEqual(Endpoint.live, matchPaths(p, "/ops/h/live").?);
    try std.testing.expectEqual(Endpoint.metrics, matchPaths(p, "/ops/m?x").?);
    try std.testing.expect(matchPaths(p, "/health/live") == null);
    try std.testing.expect(matchPaths(p, "/minio/health/live") == null);
    try std.testing.expect(matchPaths(p, "/metrics") == null);
}

test "render includes counts" {
    var c: Counters = .{ .started_ns = std.time.nanoTimestamp() };
    const t = c.begin();
    c.end(t, 200);
    c.end(c.begin(), 404);
    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try c.render(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_requests_total{code=\"2xx\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_requests_total{code=\"4xx\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zkfsm_request_duration_seconds_count 2") != null);
}
