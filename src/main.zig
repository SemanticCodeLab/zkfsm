//! zkfsm entry point: config parsing and wiring. The only file that sees every layer.
const std = @import("std");
const backend = @import("backend/root.zig");
const object = @import("object/root.zig");
const s3 = @import("s3/root.zig");
const metrics = @import("metrics/root.zig");
const iam = @import("iam/root.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm [--data DIR] [--listen HOST:PORT] [--anonymous]
    \\  --data       data root (default: $ZKFSM_DATA, else ./data)
    \\  --listen     listen address (default: 0.0.0.0:9000)
    \\  --anonymous  serve without authentication when no credentials are set
    \\credentials: ZKFSM_ACCESS_KEY / ZKFSM_SECRET_KEY
    \\             (or MINIO_ROOT_USER / MINIO_ROOT_PASSWORD)
    \\
;

const Config = struct { data: []const u8, host: []const u8, port: u16, anonymous: bool = false };

/// Hooks for builds that embed zkfsm (see lib.zig `app`).
pub const Options = struct {
    extensions: []const s3.Extension = &.{},
    /// Consumes an unknown `--flag value` pair; return false to reject it.
    extra_flag: ?*const fn (ctx: ?*anyopaque, flag: []const u8, value: []const u8) bool = null,
    extra_ctx: ?*anyopaque = null,
    extra_usage: []const u8 = "",
};

const ConfigError = error{ BadArgs, HelpRequested };

fn parseArgs(args: []const []const u8, env_data: ?[]const u8, opts: Options) ConfigError!Config {
    var cfg: Config = .{ .data = env_data orelse "./data", .host = "0.0.0.0", .port = 9000 };
    var i: usize = 1;
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
            cfg.data = args[i];
        } else if (std.mem.eql(u8, a, "--listen")) {
            const colon = std.mem.lastIndexOfScalar(u8, args[i], ':') orelse return error.BadArgs;
            cfg.host = args[i][0..colon];
            cfg.port = std.fmt.parseInt(u16, args[i][colon + 1 ..], 10) catch return error.BadArgs;
        } else if (opts.extra_flag) |f| {
            if (!f(opts.extra_ctx, a, args[i])) return error.BadArgs;
        } else return error.BadArgs;
    }
    return cfg;
}

pub fn main() u8 {
    return run(.{});
}

pub fn run(opts: Options) u8 {
    const gpa = std.heap.smp_allocator;
    const args = std.process.argsAlloc(gpa) catch return 1;
    defer std.process.argsFree(gpa, args);
    const env_data = std.process.getEnvVarOwned(gpa, "ZKFSM_DATA") catch null;
    defer if (env_data) |d| gpa.free(d);

    const cfg = parseArgs(args, env_data, opts) catch |e| {
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
    if (creds == null and !cfg.anonymous) {
        std.log.err("no credentials: set ZKFSM_ACCESS_KEY and ZKFSM_SECRET_KEY, or pass --anonymous", .{});
        return 2;
    }
    if (creds) |c| if (c.access_key.len < 3 or c.secret_key.len < iam.store.limits.min_secret or c.secret_key.len > iam.store.limits.max_secret) {
        std.log.err("access key needs at least 3 characters and secret key 8 to 40", .{});
        return 2;
    };
    if (creds == null) std.log.warn("anonymous mode: requests are not authenticated", .{});
    const addr = std.net.Address.parseIp(cfg.host, cfg.port) catch {
        std.log.err("invalid listen address {s}", .{cfg.host});
        return 2;
    };
    var local = backend.local.LocalBackend.open(cfg.data) catch |e| {
        std.log.err("cannot open data root {s}: {t}", .{ cfg.data, e });
        return 1;
    };
    defer local.close();
    var svc = object.ObjectService.init(gpa, local.backend()) catch |e| {
        std.log.err("cannot load catalog: {t}", .{e});
        return 1;
    };
    defer svc.deinit();
    std.log.info("data root {s}", .{cfg.data});
    if (std.Thread.spawn(.{}, sweepLoop, .{&svc})) |t| t.detach() else |e| std.log.warn("upload sweeper not started: {t}", .{e});
    var auth: s3.sigv4.Config = .{};
    var iam_dir: ?std.fs.Dir = null;
    defer if (iam_dir) |*d| d.close();
    var iam_file: iam.store.FilePersistence = undefined;
    var iam_store: iam.Store = undefined;
    if (creds) |c| {
        iam_dir = openIamDir(cfg.data) catch |e| {
            std.log.err("cannot open {s}/.zkfsm: {t}", .{ cfg.data, e });
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
    var server: s3.Server = .{ .gpa = gpa, .svc = &svc, .auth = auth, .extensions = opts.extensions };
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    server.run(addr) catch |e| {
        std.log.err("server failed: {t}", .{e});
        return 1;
    };
    return 0;
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
    const c = try parseArgs(&.{ "zkfsm", "--data", "/tmp/x", "--listen", "127.0.0.1:9100" }, null, .{});
    try std.testing.expectEqualStrings("/tmp/x", c.data);
    try std.testing.expectEqual(@as(u16, 9100), c.port);
    try std.testing.expectEqualStrings("env", (try parseArgs(&.{"zkfsm"}, "env", .{})).data);
    try std.testing.expectError(error.BadArgs, parseArgs(&.{ "zkfsm", "--listen", "nope" }, null, .{}));
    try std.testing.expect((try parseArgs(&.{ "zkfsm", "--anonymous", "--data", "d" }, null, .{})).anonymous);
}

test {
    _ = @import("core/root.zig");
    _ = @import("io/root.zig");
    _ = @import("device/root.zig");
    _ = @import("metadata/root.zig");
    _ = backend;
    _ = @import("placement/root.zig");
    _ = object;
    _ = @import("metrics/root.zig");
    _ = s3;
    _ = iam;
}
