//! zkfsm entry point: config parsing and wiring. The only file that sees every layer.
const std = @import("std");
const backend = @import("backend/root.zig");
const object = @import("object/root.zig");
const s3 = @import("s3/root.zig");
const metrics = @import("metrics/root.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm [--data DIR] [--listen HOST:PORT]
    \\  --data     data root (default: $ZKFSM_DATA, else ./data)
    \\  --listen   listen address (default: 0.0.0.0:9000)
    \\
;

const Config = struct { data: []const u8, host: []const u8, port: u16 };

const ConfigError = error{ BadArgs, HelpRequested };

fn parseArgs(args: []const []const u8, env_data: ?[]const u8) ConfigError!Config {
    var cfg: Config = .{ .data = env_data orelse "./data", .host = "0.0.0.0", .port = 9000 };
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) return error.HelpRequested;
        if (i + 1 >= args.len) return error.BadArgs;
        i += 1;
        if (std.mem.eql(u8, a, "--data")) {
            cfg.data = args[i];
        } else if (std.mem.eql(u8, a, "--listen")) {
            const colon = std.mem.lastIndexOfScalar(u8, args[i], ':') orelse return error.BadArgs;
            cfg.host = args[i][0..colon];
            cfg.port = std.fmt.parseInt(u16, args[i][colon + 1 ..], 10) catch return error.BadArgs;
        } else return error.BadArgs;
    }
    return cfg;
}

pub fn main() u8 {
    const gpa = std.heap.smp_allocator;
    const args = std.process.argsAlloc(gpa) catch return 1;
    defer std.process.argsFree(gpa, args);
    const env_data = std.process.getEnvVarOwned(gpa, "ZKFSM_DATA") catch null;
    defer if (env_data) |d| gpa.free(d);

    const cfg = parseArgs(args, env_data) catch |e| {
        std.debug.print("{s}", .{usage});
        return if (e == error.HelpRequested) 0 else 2;
    };
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
    var server: s3.Server = .{ .gpa = gpa, .svc = &svc };
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    server.run(addr) catch |e| {
        std.log.err("server failed: {t}", .{e});
        return 1;
    };
    return 0;
}

test "arg parsing" {
    const c = try parseArgs(&.{ "zkfsm", "--data", "/tmp/x", "--listen", "127.0.0.1:9100" }, null);
    try std.testing.expectEqualStrings("/tmp/x", c.data);
    try std.testing.expectEqual(@as(u16, 9100), c.port);
    try std.testing.expectEqualStrings("env", (try parseArgs(&.{"zkfsm"}, "env")).data);
    try std.testing.expectError(error.BadArgs, parseArgs(&.{ "zkfsm", "--listen", "nope" }, null));
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
}
