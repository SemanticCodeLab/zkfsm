//! zkfsm entry point: config parsing and wiring. The only file that sees every layer.
const std = @import("std");
const backend = @import("backend/root.zig");
const placement = @import("placement/root.zig");
const protection = @import("protection/root.zig");
const heal = @import("heal/root.zig");
const object = @import("object/root.zig");
const s3 = @import("s3/root.zig");
const metrics = @import("metrics/root.zig");
const iam = @import("iam/root.zig");
const admin = @import("admin/root.zig");
const admin_http = @import("admin_http.zig");
const tls = @import("tls/root.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm [heal] [--data DIR...] [--listen HOST:PORT] [--protection P] [--scan-interval S] [--anonymous]
    \\  heal             run one scan/heal pass over the drives and exit
    \\  --data           one or more drives; /data{1...4} expands (default: $ZKFSM_DATA, else ./data)
    \\  --listen         listen address (default: 0.0.0.0:9000)
    \\  --protection     single | replica:2 | replica:3 | EC:4+2 | EC:8+4 | EC:12+4
    \\                   default: stored in the drive format, else replica:2 with 2+ drives
    \\  --scan-interval  seconds between background heal passes, 0 disables (default: 600)
    \\  --anonymous      serve without authentication when no credentials are set
    \\  --admin-prefix   admin API path prefix (default: $ZKFSM_ADMIN_PREFIX, else /minio/admin);
    \\                   /zkfsm/admin is always accepted too. Path-style keys under
    \\                   <prefix>/v3/ (bucket = first segment) are shadowed by the admin API
    \\  --tls-cert FILE  PEM certificate chain, leaf first (or $ZKFSM_TLS_CERT); enables HTTPS
    \\  --tls-key FILE   PEM private key: EC P-256 or RSA 2048-4096 (or $ZKFSM_TLS_KEY)
    \\  --certs-dir DIR  directory holding public.crt and private.key (or $ZKFSM_CERTS_DIR)
    \\                   SIGHUP reloads the certificate and key
    \\  --max-conns      open connections before new ones get 503 (default: 1024)
    \\  --workers        connections served concurrently (default: 256)
    \\  --idle-timeout   seconds a connection may idle or a socket op may stall (default: 30)
    \\  --header-timeout seconds to receive a request head once it starts (default: 10)
    \\  --shutdown-timeout seconds SIGINT/SIGTERM waits for in-flight requests (default: 30)
    \\credentials: ZKFSM_ACCESS_KEY / ZKFSM_SECRET_KEY (or MINIO_ROOT_USER / MINIO_ROOT_PASSWORD)
    \\
;

const Config = struct {
    heal_only: bool = false,
    data: []const []const u8,
    host: []const u8 = "0.0.0.0",
    port: u16 = 9000,
    protection: ?placement.Profile = null,
    scan_interval_s: u64 = 600,
    anonymous: bool = false,
    admin_prefix: ?[]const u8 = null,
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    certs_dir: ?[]const u8 = null,
    limits: s3.server.Limits = .{},
};

/// Hooks for builds that embed zkfsm (see lib.zig `app`).
pub const Options = struct {
    extensions: []const s3.Extension = &.{},
    /// Consumes an unknown `--flag value` pair; return false to reject it.
    extra_flag: ?*const fn (ctx: ?*anyopaque, flag: []const u8, value: []const u8) bool = null,
    extra_ctx: ?*anyopaque = null,
    extra_usage: []const u8 = "",
};

const ConfigError = error{ BadArgs, HelpRequested, OutOfMemory };

fn isFlag(a: []const u8) bool {
    return std.mem.startsWith(u8, a, "-");
}

const limit_flags = [_][2][]const u8{
    .{ "--max-conns", "max_conns" },
    .{ "--workers", "workers" },
    .{ "--idle-timeout", "idle_timeout_s" },
    .{ "--header-timeout", "header_timeout_s" },
    .{ "--shutdown-timeout", "shutdown_timeout_s" },
};

fn limitField(flag: []const u8) ?[]const u8 {
    for (limit_flags) |lf| if (std.mem.eql(u8, flag, lf[0])) return lf[1];
    return null;
}

/// Strings in the result point into `args`, `env_data`, or `arena`.
fn parseArgs(arena: std.mem.Allocator, args: []const []const u8, env_data: ?[]const u8, opts: Options) ConfigError!Config {
    var cfg: Config = .{ .data = &.{} };
    var specs: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    if (args.len > 1 and std.mem.eql(u8, args[1], "heal")) {
        cfg.heal_only = true;
        i = 2;
    }
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) return error.HelpRequested;
        if (std.mem.eql(u8, a, "--anonymous")) {
            cfg.anonymous = true;
            continue;
        }
        if (i + 1 >= args.len) return error.BadArgs;
        i += 1;
        if (std.mem.eql(u8, a, "--data")) {
            try specs.append(arena, args[i]);
            while (i + 1 < args.len and !isFlag(args[i + 1])) : (i += 1) try specs.append(arena, args[i + 1]);
        } else if (std.mem.eql(u8, a, "--listen")) {
            const colon = std.mem.lastIndexOfScalar(u8, args[i], ':') orelse return error.BadArgs;
            cfg.host = args[i][0..colon];
            cfg.port = std.fmt.parseInt(u16, args[i][colon + 1 ..], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--protection")) {
            cfg.protection = placement.Profile.parse(args[i]) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--admin-prefix")) {
            admin.api.validatePrefix(args[i]) catch return error.BadArgs;
            cfg.admin_prefix = args[i];
        } else if (std.mem.eql(u8, a, "--tls-cert")) {
            cfg.tls_cert = args[i];
        } else if (std.mem.eql(u8, a, "--tls-key")) {
            cfg.tls_key = args[i];
        } else if (std.mem.eql(u8, a, "--certs-dir")) {
            cfg.certs_dir = args[i];
        } else if (limitField(a)) |field| {
            const v = std.fmt.parseInt(u32, args[i], 10) catch return error.BadArgs;
            if (v == 0) return error.BadArgs;
            inline for (limit_flags) |lf| if (std.mem.eql(u8, field, lf[1])) {
                @field(cfg.limits, lf[1]) = v;
            };
        } else if (std.mem.eql(u8, a, "--scan-interval")) {
            cfg.scan_interval_s = std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs;
        } else if (opts.extra_flag) |f| {
            if (!f(opts.extra_ctx, a, args[i])) return error.BadArgs;
        } else return error.BadArgs;
    }
    if (specs.items.len == 0) {
        var it = std.mem.tokenizeScalar(u8, env_data orelse "./data", ' ');
        while (it.next()) |d| try specs.append(arena, d);
    }
    var paths: std.ArrayList([]const u8) = .empty;
    for (specs.items) |sp| placement.ellipsis.expand(arena, sp, &paths) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadArgs,
    };
    cfg.data = paths.items;
    return cfg;
}

pub fn main() u8 {
    return run(.{});
}

pub fn run(opts: Options) u8 {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = std.process.argsAlloc(arena) catch return 1;
    const env_data = std.process.getEnvVarOwned(arena, "ZKFSM_DATA") catch null;

    const cfg = parseArgs(arena, args, env_data, opts) catch |e| {
        std.debug.print("{s}{s}", .{ usage, opts.extra_usage });
        return if (e == error.HelpRequested) 0 else 2;
    };
    const creds = loadCredentials(gpa) catch |e| {
        std.log.err("{s}", .{switch (e) {
            error.Incomplete => "access key and secret key must be set together",
            error.OutOfMemory => "out of memory",
        }});
        return 2;
    };
    if (creds == null and !cfg.anonymous and !cfg.heal_only) {
        std.log.err("no credentials: set ZKFSM_ACCESS_KEY and ZKFSM_SECRET_KEY, or pass --anonymous", .{});
        return 2;
    }
    if (creds) |c| if (c.access_key.len < 3 or c.secret_key.len < iam.store.limits.min_secret or c.secret_key.len > iam.store.limits.max_secret) {
        std.log.err("access key needs at least 3 characters and secret key 8 to 40", .{});
        return 2;
    };
    if (creds == null and !cfg.heal_only) std.log.warn("anonymous mode: requests are not authenticated", .{});
    const addr = std.net.Address.parseIp(cfg.host, cfg.port) catch {
        std.log.err("invalid listen address {s}", .{cfg.host});
        return 2;
    };
    var drives = placement.DriveSet.open(gpa, cfg.data, cfg.protection) catch |e| {
        std.log.err("cannot open drives: {t}", .{e});
        return 1;
    };
    defer drives.deinit();
    var stores: protection.Stores = .{};
    const strategy = protection.Strategy.init(gpa, &drives, &stores) catch {
        std.log.err("protection {s} is not supported", .{drives.profile.name()});
        return 1;
    };
    const be = strategy.backend();
    var healer = heal.Healer.init(gpa, &drives, strategy, .{});
    std.log.info("{d} drive(s), protection {s}", .{ drives.count(), drives.profile.name() });

    if (cfg.heal_only) {
        const r = healer.runOnce() catch |e| {
            std.log.err("heal failed: {t}", .{e});
            return 1;
        };
        heal.logReport(r);
        return if (r.fullyRedundant()) 0 else 3;
    }

    var svc = object.ObjectService.init(gpa, be) catch |e| {
        std.log.err("cannot load catalog: {t}", .{e});
        return 1;
    };
    defer svc.deinit();
    if (cfg.scan_interval_s > 0) {
        healer.start(cfg.scan_interval_s * std.time.ns_per_s) catch {
            std.log.err("cannot start healer", .{});
            return 1;
        };
    }
    defer if (cfg.scan_interval_s > 0) healer.stop();
    if (std.Thread.spawn(.{}, sweepLoop, .{&svc})) |t| t.detach() else |e| std.log.warn("upload sweeper not started: {t}", .{e});
    var auth: s3.sigv4.Config = .{};
    var iam_dir: ?std.fs.Dir = null;
    defer if (iam_dir) |*d| d.close();
    var iam_file: iam.store.FilePersistence = undefined;
    var iam_store: iam.Store = undefined;
    if (creds) |c| {
        iam_dir = openIamDir(cfg.data[0]) catch |e| {
            std.log.err("cannot open {s}/.zkfsm: {t}", .{ cfg.data[0], e });
            return 1;
        };
        iam_file = .{ .dir = iam_dir.? };
        iam_store.open(gpa, iam_file.persistence(), .{ .root_access_key = c.access_key, .root_secret = c.secret_key }) catch |e| {
            std.log.err("cannot load IAM store: {t}", .{e});
            return 1;
        };
        auth = .{ .iam = &iam_store, .sts = .{ .key = s3.sigv4.stsIssuerKey(c.secret_key) } };
    }
    defer if (auth.iam) |st| st.deinit();
    const admin_prefix = cfg.admin_prefix orelse std.process.getEnvVarOwned(arena, "ZKFSM_ADMIN_PREFIX") catch admin.api.default_prefix;
    admin.api.validatePrefix(admin_prefix) catch {
        std.log.err("invalid admin prefix {s}: need /seg[/seg...], no trailing slash, '?', '..' or '//'", .{admin_prefix});
        return 2;
    };
    warnShadowedBucket(&svc, arena, admin_prefix);
    var bridge: admin_http.Bridge = .{ .prefix = admin_prefix, .auth = auth, .svc = &svc, .started_s = std.time.timestamp() };
    const extensions = std.mem.concat(arena, s3.Extension, &.{ &.{bridge.extension()}, opts.extensions }) catch return 1;
    var tls_ctx: tls.Context = undefined;
    const tls_paths = tlsPaths(arena, cfg) catch {
        std.log.err("--tls-cert and --tls-key must be set together", .{});
        return 2;
    };
    if (tls_paths) |tp| {
        tls_ctx = tls.Context.init(gpa, tp[0], tp[1]) catch |e| {
            std.log.err("cannot load TLS certificate {s} / key {s}: {t}", .{ tp[0], tp[1], e });
            return 2;
        };
        tls_ctx.watchSighup() catch std.log.warn("tls: SIGHUP reload unavailable", .{});
        std.log.info("tls enabled ({s})", .{tp[0]});
    }
    defer if (tls_paths != null) tls_ctx.deinit();
    var server: s3.Server = .{ .gpa = gpa, .svc = &svc, .auth = auth, .extensions = extensions, .tls = if (tls_paths != null) &tls_ctx else null, .limits = cfg.limits };
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    active_server = &server;
    installStopSignals();
    server.run(addr) catch |e| {
        std.log.err("server failed: {t}", .{e});
        return 1;
    };
    svc.flush() catch |e| std.log.warn("key index not saved ({t}); it is rebuilt on next start", .{e});
    be.sync() catch |e| std.log.warn("final sync failed: {t}", .{e});
    std.log.info("stopped", .{});
    return 0;
}

/// The admin prefix takes precedence over path-style S3 keys that share it.
fn warnShadowedBucket(svc: *object.ObjectService, arena: std.mem.Allocator, prefix: []const u8) void {
    const buckets = svc.listBuckets(arena) catch return;
    for ([_][]const u8{ prefix, admin.api.native_prefix }) |p| {
        const name = admin.api.shadowedBucket(p);
        for (buckets) |b| if (std.mem.eql(u8, b.name, name))
            std.log.warn("bucket {s}: path-style keys under {s}/v3/ are served by the admin API", .{ name, p });
    }
}

/// Certificate and key paths from flags, else environment; null when TLS is off.
fn tlsPaths(arena: std.mem.Allocator, cfg: Config) error{ Incomplete, OutOfMemory }!?[2][]const u8 {
    const env = struct {
        fn get(a: std.mem.Allocator, name: []const u8) ?[]const u8 {
            const v = std.process.getEnvVarOwned(a, name) catch return null;
            return if (v.len == 0) null else v;
        }
    };
    var cert = cfg.tls_cert orelse env.get(arena, "ZKFSM_TLS_CERT");
    var key = cfg.tls_key orelse env.get(arena, "ZKFSM_TLS_KEY");
    if (cert == null and key == null) {
        const dir = cfg.certs_dir orelse env.get(arena, "ZKFSM_CERTS_DIR") orelse return null;
        cert = try std.fs.path.join(arena, &.{ dir, "public.crt" });
        key = try std.fs.path.join(arena, &.{ dir, "private.key" });
    }
    return .{ cert orelse return error.Incomplete, key orelse return error.Incomplete };
}

var active_server: ?*s3.Server = null;

fn onStopSignal(_: i32) callconv(.c) void {
    const s = active_server orelse return;
    // A second signal skips the drain.
    if (!s.requestStop()) std.posix.exit(1);
}

fn installStopSignals() void {
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onStopSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Aborts multipart uploads older than a week; runs at start, then hourly.
fn sweepLoop(svc: *object.ObjectService) void {
    const max_age: i128 = 7 * std.time.ns_per_day;
    while (true) {
        const n = object.multipart.sweepStale(svc, std.time.nanoTimestamp(), max_age) catch |e| blk: {
            std.log.warn("upload sweep failed: {t}", .{e});
            break :blk 0;
        };
        if (n > 0) std.log.info("aborted {d} stale multipart uploads", .{n});
        std.Thread.sleep(std.time.ns_per_hour);
    }
}

fn openIamDir(data: []const u8) error{CannotOpen}!std.fs.Dir {
    var root = std.fs.cwd().openDir(data, .{}) catch return error.CannotOpen;
    defer root.close();
    return root.makeOpenPath(".zkfsm", .{}) catch error.CannotOpen;
}

/// Root credentials from the environment; process-lifetime, never freed.
fn loadCredentials(gpa: std.mem.Allocator) error{ Incomplete, OutOfMemory }!?s3.sigv4.Credentials {
    const pairs = [_][2][]const u8{
        .{ "ZKFSM_ACCESS_KEY", "ZKFSM_SECRET_KEY" },
        .{ "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD" },
    };
    for (pairs) |p| {
        const ak = envVar(gpa, p[0]) catch return error.OutOfMemory;
        const sk = envVar(gpa, p[1]) catch return error.OutOfMemory;
        if (ak == null and sk == null) continue;
        return .{ .access_key = ak orelse return error.Incomplete, .secret_key = sk orelse return error.Incomplete };
    }
    return null;
}

fn envVar(gpa: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]const u8 {
    const v = std.process.getEnvVarOwned(gpa, name) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
    if (v.len == 0) return null;
    return v;
}

test "arg parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const c = try parseArgs(a, &.{ "zkfsm", "--data", "/tmp/x", "--listen", "127.0.0.1:9100" }, null, .{});
    try std.testing.expectEqualStrings("/tmp/x", c.data[0]);
    try std.testing.expectEqual(@as(u16, 9100), c.port);
    try std.testing.expectEqualStrings("env", (try parseArgs(a, &.{"zkfsm"}, "env", .{})).data[0]);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--listen", "nope" }, null, .{}));

    const m = try parseArgs(a, &.{ "zkfsm", "heal", "--data", "/d{1...3}", "/e", "--protection", "replica:3", "--scan-interval", "5" }, null, .{});
    try std.testing.expect(m.heal_only);
    try std.testing.expectEqual(@as(usize, 4), m.data.len);
    try std.testing.expectEqualStrings("/d3", m.data[2]);
    try std.testing.expectEqualStrings("/e", m.data[3]);
    try std.testing.expect(m.protection.?.eql(.{ .replica = 3 }));
    try std.testing.expectEqual(@as(u64, 5), m.scan_interval_s);
    try std.testing.expectEqual(@as(usize, 2), (try parseArgs(a, &.{"zkfsm"}, "/a /b", .{})).data.len);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--protection", "replica:5" }, null, .{}));
    try std.testing.expect((try parseArgs(a, &.{ "zkfsm", "--anonymous", "--data", "d" }, null, .{})).anonymous);
    try std.testing.expectEqualStrings("/ops/admin", (try parseArgs(a, &.{ "zkfsm", "--admin-prefix", "/ops/admin" }, null, .{})).admin_prefix.?);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--admin-prefix", "/ops/" }, null, .{}));
    const l = try parseArgs(a, &.{ "zkfsm", "--max-conns", "8", "--idle-timeout", "3", "--workers", "2" }, null, .{});
    try std.testing.expectEqual(@as(u32, 8), l.limits.max_conns);
    try std.testing.expectEqual(@as(u32, 3), l.limits.idle_timeout_s);
    try std.testing.expectEqual(@as(u32, 2), l.limits.workers);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--workers", "0" }, null, .{}));
}

test {
    _ = @import("core/root.zig");
    _ = @import("io/root.zig");
    _ = @import("device/root.zig");
    _ = @import("metadata/root.zig");
    _ = backend;
    _ = placement;
    _ = protection;
    _ = heal;
    _ = object;
    _ = @import("metrics/root.zig");
    _ = s3;
    _ = iam;
    _ = admin;
    _ = tls;
}
