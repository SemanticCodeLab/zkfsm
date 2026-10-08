//! Observability settings: `--otel-*` / `--access-log-*` flags over the standard
//! OTEL_* environment, then ZKFSM_* fallbacks.
const std = @import("std");
const otlp = @import("otlp.zig");

pub const usage =
    \\observability (OpenTelemetry over OTLP/HTTP protobuf; standard OTEL_* variables apply):
    \\  --otel-endpoint URL     collector base URL; /v1/traces, /v1/logs, /v1/metrics are appended
    \\                          (or $OTEL_EXPORTER_OTLP_ENDPOINT; per-signal OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT)
    \\  --otel-sample-ratio R   root span sampling ratio 0..1 (default: 1, or $OTEL_TRACES_SAMPLER[_ARG]);
    \\                          an incoming traceparent's sampled flag wins
    \\  --otel-headers K=V,...  extra export headers (or $OTEL_EXPORTER_OTLP_HEADERS)
    \\  --otel-signals LIST     traces,logs,metrics subset to export (default: all;
    \\                          $OTEL_{TRACES,LOGS,METRICS}_EXPORTER=none disables one)
    \\  --otel-service-name N   service.name (default: $OTEL_SERVICE_NAME, else zkfsm)
    \\  --access-log-interval S seconds between server access log deliveries (default: 300,
    \\                          or $ZKFSM_ACCESS_LOG_INTERVAL)
    \\  metrics v3 at /minio/metrics/v3 need a bearer JWT (mc admin prometheus generate)
    \\  unless $MINIO_PROMETHEUS_AUTH_TYPE / $ZKFSM_PROMETHEUS_AUTH_TYPE=public
    \\
;

pub const Flags = struct {
    endpoint: ?[]const u8 = null,
    ratio: ?f64 = null,
    headers: ?[]const u8 = null,
    signals: ?[]const u8 = null,
    service_name: ?[]const u8 = null,
    access_log_interval_s: ?u32 = null,

    pub fn isFlag(flag: []const u8) bool {
        return std.mem.startsWith(u8, flag, "--otel-") or std.mem.startsWith(u8, flag, "--access-log-");
    }

    pub fn set(f: *Flags, flag: []const u8, value: []const u8) bool {
        if (std.mem.eql(u8, flag, "--otel-endpoint")) {
            if (!validUrl(value)) return false;
            f.endpoint = value;
        } else if (std.mem.eql(u8, flag, "--otel-sample-ratio")) {
            const r = std.fmt.parseFloat(f64, value) catch return false;
            if (!(r >= 0 and r <= 1)) return false;
            f.ratio = r;
        } else if (std.mem.eql(u8, flag, "--otel-headers")) {
            f.headers = value;
        } else if (std.mem.eql(u8, flag, "--otel-signals")) {
            var it = std.mem.tokenizeScalar(u8, value, ',');
            while (it.next()) |s| if (std.meta.stringToEnum(otlp.Signal, s) == null) return false;
            f.signals = value;
        } else if (std.mem.eql(u8, flag, "--otel-service-name")) {
            if (value.len == 0) return false;
            f.service_name = value;
        } else if (std.mem.eql(u8, flag, "--access-log-interval")) {
            const v = std.fmt.parseInt(u32, value, 10) catch return false;
            if (v == 0) return false;
            f.access_log_interval_s = v;
        } else return false;
        return true;
    }
};

fn validUrl(u: []const u8) bool {
    return std.mem.startsWith(u8, u, "http://") or std.mem.startsWith(u8, u, "https://");
}

pub const Settings = struct {
    otlp: ?otlp.Config = null,
    ratio: f64 = 1,
    access_log_interval_s: u32 = 300,
    prometheus_public: bool = false,
};

pub const Error = error{ BadConfig, OutOfMemory };

/// Resolves flags and environment. `instance` becomes service.instance.id.
pub fn resolve(a: std.mem.Allocator, f: Flags, env: *const std.process.EnvMap, instance: []const u8) Error!Settings {
    var s: Settings = .{};
    if (f.access_log_interval_s) |v| s.access_log_interval_s = v else if (env.get("ZKFSM_ACCESS_LOG_INTERVAL")) |v| {
        s.access_log_interval_s = std.fmt.parseInt(u32, v, 10) catch return error.BadConfig;
        if (s.access_log_interval_s == 0) return error.BadConfig;
    }
    const pa = env.get("ZKFSM_PROMETHEUS_AUTH_TYPE") orelse env.get("MINIO_PROMETHEUS_AUTH_TYPE") orelse "jwt";
    s.prometheus_public = std.ascii.eqlIgnoreCase(pa, "public");

    s.ratio = if (f.ratio) |r| r else try samplerRatio(env);
    if (isTrue(env.get("OTEL_SDK_DISABLED"))) return s;
    const base = f.endpoint orelse env.get("OTEL_EXPORTER_OTLP_ENDPOINT") orelse env.get("ZKFSM_OTEL_ENDPOINT");
    if (base) |b| if (!validUrl(b)) return error.BadConfig;
    const proto = env.get("OTEL_EXPORTER_OTLP_PROTOCOL") orelse "http/protobuf";
    if (!std.mem.eql(u8, proto, "http/protobuf")) {
        std.log.warn("otel: OTEL_EXPORTER_OTLP_PROTOCOL={s} is not supported; exporting http/protobuf", .{proto});
    }
    var cfg: otlp.Config = .{};
    var any = false;
    inline for (.{ .{ "traces", "TRACES" }, .{ "logs", "LOGS" }, .{ "metrics", "METRICS" } }) |sig| {
        const on = signalOn(f.signals, sig[0]) and !std.mem.eql(u8, env.get("OTEL_" ++ sig[1] ++ "_EXPORTER") orelse "otlp", "none");
        const url: ?[]const u8 = if (!on) null else if (env.get("OTEL_EXPORTER_OTLP_" ++ sig[1] ++ "_ENDPOINT")) |u| blk: {
            if (!validUrl(u)) return error.BadConfig;
            break :blk u;
        } else if (base) |b| try std.fmt.allocPrint(a, "{s}/v1/{s}", .{ std.mem.trimRight(u8, b, "/"), sig[0] }) else null;
        @field(cfg, sig[0] ++ "_url") = url;
        any = any or url != null;
    }
    if (!any) return s;
    cfg.headers = try parseHeaders(a, f.headers orelse env.get("OTEL_EXPORTER_OTLP_HEADERS") orelse "");
    var res: std.ArrayList([2][]const u8) = .empty;
    try res.append(a, .{ "service.name", f.service_name orelse env.get("OTEL_SERVICE_NAME") orelse "zkfsm" });
    try res.append(a, .{ "service.version", "0.1.0" });
    try res.append(a, .{ "service.instance.id", instance });
    try res.append(a, .{ "telemetry.sdk.name", "zkfsm" });
    try res.append(a, .{ "telemetry.sdk.language", "zig" });
    var ra = std.mem.tokenizeScalar(u8, env.get("OTEL_RESOURCE_ATTRIBUTES") orelse "", ',');
    while (ra.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        try res.append(a, .{ std.mem.trim(u8, kv[0..eq], " "), std.mem.trim(u8, kv[eq + 1 ..], " ") });
    }
    cfg.resource = res.items;
    inline for (.{ .{ "OTEL_BSP_SCHEDULE_DELAY", "schedule_delay_ms" }, .{ "OTEL_BSP_MAX_QUEUE_SIZE", "max_queue" }, .{ "OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "max_batch" }, .{ "OTEL_METRIC_EXPORT_INTERVAL", "metrics_interval_ms" }, .{ "OTEL_EXPORTER_OTLP_TIMEOUT", "timeout_ms" } }) |e| {
        if (env.get(e[0])) |v| {
            const n = std.fmt.parseInt(u32, v, 10) catch return error.BadConfig;
            if (n == 0) return error.BadConfig;
            @field(cfg, e[1]) = n;
        }
    }
    s.otlp = cfg;
    return s;
}

fn isTrue(v: ?[]const u8) bool {
    const x = v orelse return false;
    return std.ascii.eqlIgnoreCase(x, "true") or std.mem.eql(u8, x, "1");
}

fn signalOn(list: ?[]const u8, name: []const u8) bool {
    const l = list orelse return true;
    var it = std.mem.tokenizeScalar(u8, l, ',');
    while (it.next()) |s| if (std.mem.eql(u8, s, name)) return true;
    return false;
}

/// OTEL_TRACES_SAMPLER: always_on, always_off, traceidratio and their parentbased_ forms.
fn samplerRatio(env: *const std.process.EnvMap) Error!f64 {
    const s = env.get("OTEL_TRACES_SAMPLER") orelse return 1;
    const name = if (std.mem.startsWith(u8, s, "parentbased_")) s["parentbased_".len..] else s;
    if (std.mem.eql(u8, name, "always_on")) return 1;
    if (std.mem.eql(u8, name, "always_off")) return 0;
    if (std.mem.eql(u8, name, "traceidratio")) {
        const r = std.fmt.parseFloat(f64, env.get("OTEL_TRACES_SAMPLER_ARG") orelse "1") catch return error.BadConfig;
        if (!(r >= 0 and r <= 1)) return error.BadConfig;
        return r;
    }
    return error.BadConfig;
}

/// `k=v,k2=v2` with percent-encoded values (W3C baggage style).
pub fn parseHeaders(a: std.mem.Allocator, s: []const u8) Error![]const std.http.Header {
    var out: std.ArrayList(std.http.Header) = .empty;
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.BadConfig;
        const k = std.mem.trim(u8, kv[0..eq], " ");
        if (k.len == 0) return error.BadConfig;
        const raw = std.mem.trim(u8, kv[eq + 1 ..], " ");
        var v: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (i < raw.len) : (i += 1) {
            if (raw[i] == '%' and i + 2 < raw.len) if (std.fmt.parseInt(u8, raw[i + 1 .. i + 3], 16)) |b| {
                try v.append(a, b);
                i += 2;
                continue;
            } else |_| {};
            try v.append(a, raw[i]);
        }
        for (v.items) |ch| if (ch == '\r' or ch == '\n') return error.BadConfig;
        try out.append(a, .{ .name = k, .value = v.items });
    }
    return out.items;
}

test "settings from flags and environment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.EnvMap.init(a);
    try env.put("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4318/");
    try env.put("OTEL_LOGS_EXPORTER", "none");
    try env.put("OTEL_EXPORTER_OTLP_HEADERS", "x-a=1,authorization=Bearer%20t");
    try env.put("OTEL_TRACES_SAMPLER", "parentbased_traceidratio");
    try env.put("OTEL_TRACES_SAMPLER_ARG", "0.25");
    const s = try resolve(a, .{}, &env, "n1");
    try std.testing.expectEqualStrings("http://c:4318/v1/traces", s.otlp.?.traces_url.?);
    try std.testing.expect(s.otlp.?.logs_url == null);
    try std.testing.expectEqualStrings("Bearer t", s.otlp.?.headers[1].value);
    try std.testing.expectEqual(@as(f64, 0.25), s.ratio);
    var f: Flags = .{};
    try std.testing.expect(f.set("--otel-sample-ratio", "0.5"));
    try std.testing.expect(!f.set("--otel-sample-ratio", "2"));
    try std.testing.expect(f.set("--otel-signals", "traces,metrics"));
    try std.testing.expect(!f.set("--otel-signals", "traces,bogus"));
    try std.testing.expect(!f.set("--otel-endpoint", "c:4318"));
    try std.testing.expectEqual(@as(f64, 0.5), (try resolve(a, f, &env, "n1")).ratio);
    var empty = std.process.EnvMap.init(a);
    try std.testing.expect((try resolve(a, .{}, &empty, "n")).otlp == null);
}
