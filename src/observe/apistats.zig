//! Per-API and per-bucket request statistics behind the v3 `api` and `bucket/api`
//! metric groups: counts, error classes, traffic, and latency distributions.
const std = @import("std");
const iam = @import("../iam/root.zig");

const Op = iam.actions.Op;
const Atomic = std.atomic.Value;

pub const n_ops = @typeInfo(Op).@"enum".fields.len;
/// Index of admin API calls, after the S3 operations.
pub const admin_index = n_ops;
pub const unknown_index = n_ops + 1;
pub const n_names = n_ops + 2;

/// Upper bounds (seconds) of the latency distribution; +Inf is implied.
pub const bounds = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 };
const bound_ns = blk: {
    var out: [bounds.len]u64 = undefined;
    for (bounds, &out) |b, *o| o.* = @intFromFloat(b * 1e9);
    break :blk out;
};

/// `put_object` -> `PutObject`, at compile time.
pub const names: [n_names][]const u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [n_names][]const u8 = undefined;
    for (@typeInfo(Op).@"enum".fields, 0..) |f, i| {
        var buf: [f.name.len]u8 = undefined;
        var n: usize = 0;
        var up = true;
        for (f.name) |ch| {
            if (ch == '_') {
                up = true;
                continue;
            }
            buf[n] = if (up) std.ascii.toUpper(ch) else ch;
            n += 1;
            up = false;
        }
        const final = buf[0..n].*;
        out[i] = &final;
    }
    out[admin_index] = "Admin";
    out[unknown_index] = "Unknown";
    break :blk out;
};

pub const Counters = struct {
    total: Atomic(u64) = .init(0),
    err4: Atomic(u64) = .init(0),
    err5: Atomic(u64) = .init(0),
    canceled: Atomic(u64) = .init(0),
    rx: Atomic(u64) = .init(0),
    tx: Atomic(u64) = .init(0),
    dur_ns: Atomic(u64) = .init(0),
    /// Non-cumulative; index bounds.len is the overflow bucket.
    hist: [bounds.len + 1]Atomic(u64) = @splat(.init(0)),

    fn add(c: *Counters, status: u16, dur: u64, rx: u64, tx: u64, canceled: bool) void {
        _ = c.total.fetchAdd(1, .monotonic);
        if (status >= 400 and status < 500) _ = c.err4.fetchAdd(1, .monotonic);
        if (status >= 500) _ = c.err5.fetchAdd(1, .monotonic);
        if (canceled) _ = c.canceled.fetchAdd(1, .monotonic);
        _ = c.rx.fetchAdd(rx, .monotonic);
        _ = c.tx.fetchAdd(tx, .monotonic);
        _ = c.dur_ns.fetchAdd(dur, .monotonic);
        var i: usize = 0;
        while (i < bound_ns.len and dur > bound_ns[i]) i += 1;
        _ = c.hist[i].fetchAdd(1, .monotonic);
    }
};

pub const max_buckets = 1024;

pub const Stats = struct {
    gpa: std.mem.Allocator,
    api: [n_names]Counters = @splat(.{}),
    inflight: Atomic(i64) = .init(0),
    rejected_auth: Atomic(u64) = .init(0),
    rejected_invalid: Atomic(u64) = .init(0),
    lock: std.Thread.RwLock = .{},
    buckets: std.StringArrayHashMapUnmanaged(*[n_names]Counters) = .empty,

    pub fn deinit(s: *Stats) void {
        for (s.buckets.keys(), s.buckets.values()) |k, v| {
            s.gpa.free(k);
            s.gpa.destroy(v);
        }
        s.buckets.deinit(s.gpa);
    }

    pub const Done = struct {
        index: usize,
        bucket: []const u8,
        status: u16,
        dur_ns: u64,
        rx: u64,
        tx: u64,
        canceled: bool = false,
        /// Signature/credential failure (403 before dispatch).
        auth_rejected: bool = false,
    };

    pub fn record(s: *Stats, d: Done) void {
        s.api[d.index].add(d.status, d.dur_ns, d.rx, d.tx, d.canceled);
        if (d.auth_rejected) _ = s.rejected_auth.fetchAdd(1, .monotonic);
        if (d.status == 400) _ = s.rejected_invalid.fetchAdd(1, .monotonic);
        if (d.bucket.len == 0 or d.index == admin_index) return;
        const per = s.bucketCounters(d.bucket) orelse return;
        per[d.index].add(d.status, d.dur_ns, d.rx, d.tx, d.canceled);
    }

    fn bucketCounters(s: *Stats, bucket: []const u8) ?*[n_names]Counters {
        {
            s.lock.lockShared();
            defer s.lock.unlockShared();
            if (s.buckets.get(bucket)) |c| return c;
        }
        s.lock.lock();
        defer s.lock.unlock();
        if (s.buckets.get(bucket)) |c| return c;
        if (s.buckets.count() >= max_buckets) return null;
        const c = s.gpa.create([n_names]Counters) catch return null;
        c.* = @splat(.{});
        const k = s.gpa.dupe(u8, bucket) catch {
            s.gpa.destroy(c);
            return null;
        };
        s.buckets.put(s.gpa, k, c) catch {
            s.gpa.free(k);
            s.gpa.destroy(c);
            return null;
        };
        return c;
    }

    /// Forgets a deleted bucket's series.
    /// Zeroes a deleted bucket's series; the slot stays, since requests in flight may hold it.
    pub fn dropBucket(s: *Stats, bucket: []const u8) void {
        s.lock.lockShared();
        defer s.lock.unlockShared();
        const per = s.buckets.get(bucket) orelse return;
        for (per) |*c| {
            inline for (.{ "total", "err4", "err5", "canceled", "rx", "tx", "dur_ns" }) |f| @field(c, f).store(0, .monotonic);
            for (&c.hist) |*h| h.store(0, .monotonic);
        }
    }

    pub fn bucketNames(s: *Stats, a: std.mem.Allocator) error{OutOfMemory}![]const []const u8 {
        s.lock.lockShared();
        defer s.lock.unlockShared();
        const out = try a.alloc([]const u8, s.buckets.count());
        for (s.buckets.keys(), out) |k, *o| o.* = try a.dupe(u8, k);
        return out;
    }

    fn typeOf(i: usize) []const u8 {
        return if (i == admin_index) "admin" else "s3";
    }

    /// `/api/requests` group (MinIO v3 names).
    pub fn renderApi(s: *Stats, w: *std.Io.Writer, server: []const u8) std.Io.Writer.Error!void {
        try w.print("# HELP minio_api_requests_inflight_total Number of requests currently in flight\n# TYPE minio_api_requests_inflight_total gauge\nminio_api_requests_inflight_total{{type=\"s3\",server=\"{s}\"}} {d}\n", .{ server, @max(0, s.inflight.load(.monotonic)) });
        try w.print("# HELP minio_api_requests_rejected_auth_total Requests rejected for invalid credentials or signatures\n# TYPE minio_api_requests_rejected_auth_total counter\nminio_api_requests_rejected_auth_total{{type=\"s3\",server=\"{s}\"}} {d}\n", .{ server, s.rejected_auth.load(.monotonic) });
        try w.print("# HELP minio_api_requests_rejected_invalid_total Requests rejected as invalid\n# TYPE minio_api_requests_rejected_invalid_total counter\nminio_api_requests_rejected_invalid_total{{type=\"s3\",server=\"{s}\"}} {d}\n", .{ server, s.rejected_invalid.load(.monotonic) });
        const fams = .{
            .{ "minio_api_requests_total", "Total number of requests", "total" },
            .{ "minio_api_requests_errors_total", "Requests with 4xx or 5xx status", "" },
            .{ "minio_api_requests_4xx_errors_total", "Requests with 4xx status", "err4" },
            .{ "minio_api_requests_5xx_errors_total", "Requests with 5xx status", "err5" },
            .{ "minio_api_requests_canceled_total", "Requests canceled by the client", "canceled" },
        };
        inline for (fams) |f| {
            try w.print("# HELP {s} {s}\n# TYPE {s} counter\n", .{ f[0], f[1], f[0] });
            for (&s.api, 0..) |*c, i| {
                const v = if (f[2].len == 0) c.err4.load(.monotonic) + c.err5.load(.monotonic) else @field(c, f[2]).load(.monotonic);
                if (c.total.load(.monotonic) == 0) continue;
                try w.print("{s}{{name=\"{s}\",type=\"{s}\",server=\"{s}\"}} {d}\n", .{ f[0], names[i], typeOf(i), server, v });
            }
        }
        try distribution(w, "minio_api_requests_ttfb_seconds_distribution", "Distribution of request time to first byte", &s.api, null, server);
        try histogram(w, "minio_api_requests_duration_seconds", "Request latency histogram", &s.api, null, server);
        inline for (.{ .{ "minio_api_requests_traffic_sent_bytes", "tx" }, .{ "minio_api_requests_traffic_received_bytes", "rx" } }) |f| {
            var sum: u64 = 0;
            for (&s.api) |*c| sum += @field(c, f[1]).load(.monotonic);
            try w.print("# TYPE {s} counter\n{s}{{type=\"s3\",server=\"{s}\"}} {d}\n", .{ f[0], f[0], server, sum });
        }
    }

    /// `/bucket/api/{bucket}` group.
    pub fn renderBucket(s: *Stats, w: *std.Io.Writer, bucket: []const u8, server: []const u8) std.Io.Writer.Error!void {
        s.lock.lockShared();
        const per = s.buckets.get(bucket);
        s.lock.unlockShared();
        inline for (.{ .{ "minio_bucket_api_traffic_received_bytes", "rx" }, .{ "minio_bucket_api_traffic_sent_bytes", "tx" } }) |f| {
            var sum: u64 = 0;
            if (per) |p| for (p) |*c| {
                sum += @field(c, f[1]).load(.monotonic);
            };
            try w.print("# TYPE {s} counter\n{s}{{bucket=\"{s}\",type=\"s3\",server=\"{s}\"}} {d}\n", .{ f[0], f[0], bucket, server, sum });
        }
        const p = per orelse return;
        const fams = .{
            .{ "minio_bucket_api_total", "total" },
            .{ "minio_bucket_api_4xx_errors_total", "err4" },
            .{ "minio_bucket_api_5xx_errors_total", "err5" },
            .{ "minio_bucket_api_canceled_total", "canceled" },
        };
        inline for (fams) |f| {
            try w.print("# TYPE {s} counter\n", .{f[0]});
            for (p, 0..) |*c, i| {
                if (c.total.load(.monotonic) == 0) continue;
                try w.print("{s}{{bucket=\"{s}\",name=\"{s}\",type=\"s3\",server=\"{s}\"}} {d}\n", .{ f[0], bucket, names[i], server, @field(c, f[1]).load(.monotonic) });
            }
        }
        try distribution(w, "minio_bucket_api_ttfb_seconds_distribution", "Distribution of time to first byte per bucket and API", p, bucket, server);
        try histogram(w, "minio_bucket_api_duration_seconds", "Request latency histogram per bucket and API", p, bucket, server);
    }
};

fn labelsPrefix(w: *std.Io.Writer, bucket: ?[]const u8) std.Io.Writer.Error!void {
    if (bucket) |b| try w.print("bucket=\"{s}\",", .{b});
}

fn boundText(i: usize, buf: *[16]u8) []const u8 {
    if (i == bounds.len) return "+Inf";
    return std.fmt.bufPrint(buf, "{d}", .{bounds[i]}) catch "+Inf";
}

/// MinIO's `*_ttfb_seconds_distribution`: a counter per `le` bucket (non-cumulative).
fn distribution(w: *std.Io.Writer, name: []const u8, help: []const u8, cs: []Counters, bucket: ?[]const u8, server: []const u8) std.Io.Writer.Error!void {
    try w.print("# HELP {s} {s}\n# TYPE {s} counter\n", .{ name, help, name });
    for (cs, 0..) |*c, i| {
        if (c.total.load(.monotonic) == 0) continue;
        for (&c.hist, 0..) |*h, j| {
            var bb: [16]u8 = undefined;
            try w.print("{s}{{", .{name});
            try labelsPrefix(w, bucket);
            try w.print("name=\"{s}\",type=\"{s}\",le=\"{s}\",server=\"{s}\"}} {d}\n", .{ names[i], Stats.typeOf(i), boundText(j, &bb), server, h.load(.monotonic) });
        }
    }
}

/// A standard cumulative Prometheus histogram.
fn histogram(w: *std.Io.Writer, name: []const u8, help: []const u8, cs: []Counters, bucket: ?[]const u8, server: []const u8) std.Io.Writer.Error!void {
    try w.print("# HELP {s} {s}\n# TYPE {s} histogram\n", .{ name, help, name });
    for (cs, 0..) |*c, i| {
        const total = c.total.load(.monotonic);
        if (total == 0) continue;
        var cum: u64 = 0;
        for (&c.hist, 0..) |*h, j| {
            cum += h.load(.monotonic);
            var bb: [16]u8 = undefined;
            try w.print("{s}_bucket{{", .{name});
            try labelsPrefix(w, bucket);
            try w.print("name=\"{s}\",type=\"{s}\",server=\"{s}\",le=\"{s}\"}} {d}\n", .{ names[i], Stats.typeOf(i), server, boundText(j, &bb), cum });
        }
        const ns = c.dur_ns.load(.monotonic);
        try w.print("{s}_sum{{", .{name});
        try labelsPrefix(w, bucket);
        try w.print("name=\"{s}\",type=\"{s}\",server=\"{s}\"}} {d}.{d:0>9}\n", .{ names[i], Stats.typeOf(i), server, ns / std.time.ns_per_s, ns % std.time.ns_per_s });
        try w.print("{s}_count{{", .{name});
        try labelsPrefix(w, bucket);
        try w.print("name=\"{s}\",type=\"{s}\",server=\"{s}\"}} {d}\n", .{ names[i], Stats.typeOf(i), server, cum });
    }
}

test "api names and recording" {
    try std.testing.expectEqualStrings("PutObject", names[@intFromEnum(Op.put_object)]);
    try std.testing.expectEqualStrings("ListObjectsV2", names[@intFromEnum(Op.list_objects_v2)]);
    var s: Stats = .{ .gpa = std.testing.allocator };
    defer s.deinit();
    s.record(.{ .index = @intFromEnum(Op.get_object), .bucket = "b1", .status = 200, .dur_ns = 3_000_000, .rx = 0, .tx = 10 });
    s.record(.{ .index = @intFromEnum(Op.get_object), .bucket = "b1", .status = 404, .dur_ns = 30_000_000_000, .rx = 0, .tx = 0 });
    var buf: [64 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try s.renderApi(&w, "n1");
    try s.renderBucket(&w, "b1", "n1");
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "minio_api_requests_total{name=\"GetObject\",type=\"s3\",server=\"n1\"} 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "minio_api_requests_4xx_errors_total{name=\"GetObject\",type=\"s3\",server=\"n1\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "minio_bucket_api_traffic_sent_bytes{bucket=\"b1\",type=\"s3\",server=\"n1\"} 10") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "minio_api_requests_duration_seconds_bucket{name=\"GetObject\",type=\"s3\",server=\"n1\",le=\"+Inf\"} 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "minio_api_requests_duration_seconds_bucket{name=\"GetObject\",type=\"s3\",server=\"n1\",le=\"0.005\"} 1") != null);
}
