//! Per-operation request, error and latency counters around any Kms backend,
//! rendered as Prometheus text. Stats outlive backend swaps.
const std = @import("std");
const types = @import("types.zig");

const Error = types.Error;
const Allocator = std.mem.Allocator;
const Counter = std.atomic.Value(u64);

pub const Op = enum { create_key, generate_data_key, decrypt_data_key, seal_data_key, list_keys, key_status, rotate_key, set_key_state, delete_key, key_tags, set_key_tags };

pub const bucket_bounds_us = [_]u64{ 100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000 };

pub const OpStats = struct {
    requests: Counter = .init(0),
    errors: Counter = .init(0),
    latency_sum_us: Counter = .init(0),
    buckets: [bucket_bounds_us.len]Counter = @splat(.init(0)),
};

pub const Stats = struct {
    ops: [std.meta.fields(Op).len]OpStats = @splat(.{}),
    active: std.atomic.Value(i64) = .init(0),
    /// Key counts by state as of the last listing; -1 until known.
    keys_enabled: std.atomic.Value(i64) = .init(-1),
    keys_disabled: std.atomic.Value(i64) = .init(-1),
    reconfigs: Counter = .init(0),
    reconfig_failures: Counter = .init(0),
    rekeyed_objects: Counter = .init(0),
    started_s: i64 = 0,

    pub fn record(s: *Stats, op: Op, start_ns: i128, failed: bool) void {
        const o = &s.ops[@intFromEnum(op)];
        _ = o.requests.fetchAdd(1, .monotonic);
        if (failed) _ = o.errors.fetchAdd(1, .monotonic);
        const el = std.time.nanoTimestamp() - start_ns;
        const us: u64 = if (el <= 0) 0 else std.math.cast(u64, @divTrunc(el, 1000)) orelse std.math.maxInt(u64);
        _ = o.latency_sum_us.fetchAdd(us, .monotonic);
        for (bucket_bounds_us, &o.buckets) |b, *c| {
            if (us <= b) _ = c.fetchAdd(1, .monotonic);
        }
    }

    pub fn noteKeys(s: *Stats, list: []const types.KeyInfo) void {
        var en: i64 = 0;
        var dis: i64 = 0;
        for (list) |k| switch (k.state) {
            .enabled => en += 1,
            else => dis += 1,
        };
        s.keys_enabled.store(en, .monotonic);
        s.keys_disabled.store(dis, .monotonic);
    }

    pub fn totals(s: *const Stats) struct { ok: u64, err: u64 } {
        var ok: u64 = 0;
        var err: u64 = 0;
        for (&s.ops) |*o| {
            const r = o.requests.load(.monotonic);
            const e = o.errors.load(.monotonic);
            ok += r - @min(r, e);
            err += e;
        }
        return .{ .ok = ok, .err = err };
    }

    pub fn render(s: *const Stats, backend: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll("# HELP zkfsm_kms_requests_total KMS backend calls by operation\n# TYPE zkfsm_kms_requests_total counter\n");
        for (&s.ops, 0..) |*o, i| try w.print("zkfsm_kms_requests_total{{op=\"{t}\"}} {d}\n", .{ @as(Op, @enumFromInt(i)), o.requests.load(.monotonic) });
        try w.writeAll("# HELP zkfsm_kms_errors_total KMS backend calls that failed\n# TYPE zkfsm_kms_errors_total counter\n");
        for (&s.ops, 0..) |*o, i| try w.print("zkfsm_kms_errors_total{{op=\"{t}\"}} {d}\n", .{ @as(Op, @enumFromInt(i)), o.errors.load(.monotonic) });
        try w.writeAll("# HELP zkfsm_kms_request_duration_seconds KMS backend call latency\n# TYPE zkfsm_kms_request_duration_seconds histogram\n");
        for (&s.ops, 0..) |*o, i| {
            const op: Op = @enumFromInt(i);
            for (bucket_bounds_us, &o.buckets) |b, *c| try w.print("zkfsm_kms_request_duration_seconds_bucket{{op=\"{t}\",le=\"{d}.{d:0>6}\"}} {d}\n", .{ op, b / 1_000_000, b % 1_000_000, c.load(.monotonic) });
            const n = o.requests.load(.monotonic);
            const sum = o.latency_sum_us.load(.monotonic);
            try w.print("zkfsm_kms_request_duration_seconds_bucket{{op=\"{t}\",le=\"+Inf\"}} {d}\n", .{ op, n });
            try w.print("zkfsm_kms_request_duration_seconds_sum{{op=\"{t}\"}} {d}.{d:0>6}\n", .{ op, sum / 1_000_000, sum % 1_000_000 });
            try w.print("zkfsm_kms_request_duration_seconds_count{{op=\"{t}\"}} {d}\n", .{ op, n });
        }
        try w.print("# HELP zkfsm_kms_requests_active KMS backend calls in flight\n# TYPE zkfsm_kms_requests_active gauge\nzkfsm_kms_requests_active {d}\n", .{s.active.load(.monotonic)});
        try w.writeAll("# HELP zkfsm_kms_keys Master keys by state (last listing)\n# TYPE zkfsm_kms_keys gauge\n");
        try w.print("zkfsm_kms_keys{{state=\"enabled\"}} {d}\nzkfsm_kms_keys{{state=\"disabled\"}} {d}\n", .{ @max(0, s.keys_enabled.load(.monotonic)), @max(0, s.keys_disabled.load(.monotonic)) });
        try w.print("# HELP zkfsm_kms_backend_info Active KMS backend\n# TYPE zkfsm_kms_backend_info gauge\nzkfsm_kms_backend_info{{backend=\"{s}\"}} 1\n", .{backend});
        try w.print("# HELP zkfsm_kms_reconfigurations_total Runtime KMS reconfigurations applied\n# TYPE zkfsm_kms_reconfigurations_total counter\nzkfsm_kms_reconfigurations_total {d}\n", .{s.reconfigs.load(.monotonic)});
        try w.print("# HELP zkfsm_kms_reconfiguration_failures_total Runtime KMS reconfigurations rejected\n# TYPE zkfsm_kms_reconfiguration_failures_total counter\nzkfsm_kms_reconfiguration_failures_total {d}\n", .{s.reconfig_failures.load(.monotonic)});
        try w.print("# HELP zkfsm_kms_rekeyed_objects_total Object keys re-wrapped by rekey\n# TYPE zkfsm_kms_rekeyed_objects_total counter\nzkfsm_kms_rekeyed_objects_total {d}\n", .{s.rekeyed_objects.load(.monotonic)});
    }
};

/// Counting wrapper; `inner` and `stats` must outlive it.
pub const Metered = struct {
    inner: types.Kms,
    stats: *Stats,
    vt: types.Kms.VTable = undefined,

    pub fn kms(m: *Metered) types.Kms {
        const iv = m.inner.vtable;
        m.vt = .{
            .kind = iv.kind,
            .createKey = createKey,
            .generateDataKey = generateDataKey,
            .decryptDataKey = decryptDataKey,
            .listKeys = listKeys,
            .keyStatus = keyStatus,
            .rotateKey = rotateKey,
            .setKeyState = if (iv.setKeyState != null) setKeyState else null,
            .deleteKey = if (iv.deleteKey != null) deleteKey else null,
            .keyTags = if (iv.keyTags != null) keyTags else null,
            .setKeyTags = if (iv.setKeyTags != null) setKeyTags else null,
            .sealDataKey = if (iv.sealDataKey != null) sealDataKey else null,
        };
        return .{ .ptr = m, .vtable = &m.vt };
    }

    fn cast(p: *anyopaque) *Metered {
        return @ptrCast(@alignCast(p));
    }

    fn begin(m: *Metered) i128 {
        _ = m.stats.active.fetchAdd(1, .monotonic);
        return std.time.nanoTimestamp();
    }

    fn end(m: *Metered, op: Op, t: i128, failed: bool) void {
        _ = m.stats.active.fetchSub(1, .monotonic);
        m.stats.record(op, t, failed);
    }

    /// Records the outcome of an inner call under `op`.
    fn run(m: *Metered, comptime op: Op, comptime T: type, r: Error!T, t: i128) Error!T {
        m.end(op, t, if (r) |_| false else |_| true);
        return r;
    }

    fn createKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const m = cast(p);
        const t = m.begin();
        return m.run(.create_key, types.KeyInfo, m.inner.createKey(gpa, id), t);
    }
    fn generateDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, ctx: types.Context) Error!types.DataKey {
        const m = cast(p);
        const t = m.begin();
        return m.run(.generate_data_key, types.DataKey, m.inner.generateDataKey(gpa, id, ctx), t);
    }
    fn decryptDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, sealed: []const u8, ctx: types.Context) Error![types.dek_len]u8 {
        const m = cast(p);
        const t = m.begin();
        return m.run(.decrypt_data_key, [types.dek_len]u8, m.inner.decryptDataKey(gpa, id, sealed, ctx), t);
    }
    fn sealDataKey(p: *anyopaque, gpa: Allocator, id: []const u8, dek: *const [types.dek_len]u8, ctx: types.Context) Error!types.DataKey {
        const m = cast(p);
        const t = m.begin();
        return m.run(.seal_data_key, types.DataKey, m.inner.sealDataKey(gpa, id, dek, ctx), t);
    }
    fn listKeys(p: *anyopaque, gpa: Allocator) Error![]types.KeyInfo {
        const m = cast(p);
        const t = m.begin();
        const r = m.run(.list_keys, []types.KeyInfo, m.inner.listKeys(gpa), t);
        if (r) |l| m.stats.noteKeys(l) else |_| {}
        return r;
    }
    fn keyStatus(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const m = cast(p);
        const t = m.begin();
        return m.run(.key_status, types.KeyInfo, m.inner.keyStatus(gpa, id), t);
    }
    fn rotateKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!types.KeyInfo {
        const m = cast(p);
        const t = m.begin();
        return m.run(.rotate_key, types.KeyInfo, m.inner.rotateKey(gpa, id), t);
    }
    fn setKeyState(p: *anyopaque, gpa: Allocator, id: []const u8, st: types.KeyState) Error!void {
        const m = cast(p);
        const t = m.begin();
        return m.run(.set_key_state, void, m.inner.setKeyState(gpa, id, st), t);
    }
    fn deleteKey(p: *anyopaque, gpa: Allocator, id: []const u8) Error!void {
        const m = cast(p);
        const t = m.begin();
        return m.run(.delete_key, void, m.inner.deleteKey(gpa, id), t);
    }
    fn keyTags(p: *anyopaque, gpa: Allocator, id: []const u8) Error![]types.Tag {
        const m = cast(p);
        const t = m.begin();
        return m.run(.key_tags, []types.Tag, m.inner.keyTags(gpa, id), t);
    }
    fn setKeyTags(p: *anyopaque, gpa: Allocator, id: []const u8, tags: []const types.Tag) Error!void {
        const m = cast(p);
        const t = m.begin();
        return m.run(.set_key_tags, void, m.inner.setKeyTags(gpa, id, tags), t);
    }
};

test "metered wrapper counts calls and errors" {
    const keyring = @import("keyring.zig");
    const gpa = std.testing.allocator;
    var mem: keyring.MemoryStore = .{ .gpa = gpa };
    defer mem.deinit();
    var kr: keyring.KeyringKms = .{ .store = mem.keyStore(), .kind = .local };
    var stats: Stats = .{};
    var m: Metered = .{ .inner = kr.kms(), .stats = &stats };
    const k = m.kms();
    var ki = try k.createKey(gpa, "a");
    ki.deinit(gpa);
    try std.testing.expectError(error.KeyExists, k.createKey(gpa, "a"));
    const l = try k.listKeys(gpa);
    types.freeKeyInfos(gpa, l);
    try std.testing.expectEqual(@as(u64, 2), stats.ops[@intFromEnum(Op.create_key)].requests.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), stats.ops[@intFromEnum(Op.create_key)].errors.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 1), stats.keys_enabled.load(.monotonic));
    var buf: [16 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try stats.render("local", &w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "zkfsm_kms_requests_total{op=\"create_key\"} 2") != null);
}
