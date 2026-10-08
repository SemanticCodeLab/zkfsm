//! Wire forms of job state: madmin JobMetric, BatchJobResult, and the
//! realtime-metrics packet `mc batch status` streams.
const std = @import("std");
const job = @import("job.zig");
const spec = @import("spec.zig");

const Stringify = std.json.Stringify;
const Record = job.Record;
const W = std.Io.Writer.Error;

/// RFC 3339 UTC with nanoseconds.
pub fn rfc3339(ns: i128, buf: *[40]u8) []const u8 {
    const t: i128 = @max(ns, 0);
    const secs: u64 = @intCast(@divFloor(t, std.time.ns_per_s));
    const frac: u64 = @intCast(@mod(t, std.time.ns_per_s));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}Z", .{
        yd.year,              md.month.numeric(),      @as(u8, md.day_index) + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        frac,
    }) catch unreachable; // fixed width
}

fn field(w: *Stringify, name: []const u8, v: anytype) W!void {
    try w.objectField(name);
    try w.write(v);
}

/// madmin JobMetric.
pub fn metric(w: *Stringify, r: Record) W!void {
    var b1: [40]u8 = undefined;
    var b2: [40]u8 = undefined;
    const st = std.meta.stringToEnum(job.State, r.state) orelse .failed;
    try w.beginObject();
    try field(w, "jobID", r.id);
    try field(w, "jobType", r.kind);
    try field(w, "startTime", rfc3339(r.started_ns, &b1));
    try field(w, "lastUpdate", rfc3339(r.updated_ns, &b2));
    try field(w, "retryAttempts", r.retry_attempts);
    try field(w, "complete", st == .complete);
    try field(w, "failed", st == .failed or st == .canceled);
    const c = r.counters;
    const kind = spec.Kind.parse(r.kind) orelse .replicate;
    try w.objectField(switch (kind) {
        .replicate => "replicate",
        .keyrotate => "rotation",
        .expire => "expired",
    });
    try w.beginObject();
    try field(w, "lastBucket", r.last_bucket);
    try field(w, "lastObject", r.last_object);
    try field(w, "objects", c.objects);
    try field(w, "objectsFailed", c.objects_failed);
    if (kind != .keyrotate) {
        try field(w, "deleteMarkers", c.delete_markers);
        try field(w, "deleteMarkersFailed", c.delete_markers_failed);
    }
    if (kind == .replicate) {
        try field(w, "bytesTransferred", c.bytes);
        try field(w, "bytesFailed", c.bytes_failed);
    }
    try w.endObject();
    // Not part of the madmin shape; clients ignore it.
    try field(w, "status", r.state);
    if (r.message.len > 0) try field(w, "message", r.message);
    try w.endObject();
}

/// madmin BatchJobResult.
pub fn result(w: *Stringify, r: Record, with_elapsed: bool) W!void {
    var b: [40]u8 = undefined;
    try w.beginObject();
    try field(w, "id", r.id);
    try field(w, "type", r.kind);
    if (r.user.len > 0) try field(w, "user", r.user);
    try field(w, "started", rfc3339(r.started_ns, &b));
    if (with_elapsed and r.updated_ns > r.started_ns) try field(w, "elapsed", r.updated_ns - r.started_ns);
    try w.endObject();
}

/// One madmin RealtimeMetrics packet holding a single job.
pub fn realtime(w: *Stringify, r: Record, host: []const u8, now_ns: i128, final: bool) W!void {
    var b: [40]u8 = undefined;
    try w.beginObject();
    try w.objectField("hosts");
    try w.beginArray();
    try w.write(host);
    try w.endArray();
    try w.objectField("aggregated");
    try w.beginObject();
    try w.objectField("batchJobs");
    try w.beginObject();
    try field(w, "collected", rfc3339(now_ns, &b));
    try w.objectField("Jobs");
    try w.beginObject();
    try w.objectField(r.id);
    try metric(w, r);
    try w.endObject();
    try w.endObject();
    try w.endObject();
    try field(w, "final", final);
    try w.endObject();
}

test "metric shape" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var w: Stringify = .{ .writer = &out.writer };
    try metric(&w, .{ .id = "J", .kind = "expire", .started_ns = 0, .state = "complete", .spec = "", .counters = .{ .objects = 2 } });
    const s = out.written();
    try std.testing.expect(std.mem.indexOf(u8, s, "\"expired\":{\"lastBucket\":\"\",\"lastObject\":\"\",\"objects\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "\"complete\":true,\"failed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "1970-01-01T00:00:00.000000000Z") != null);
}
