//! zkfsm entry point: config parsing and wiring. The only file that sees every layer.
const std = @import("std");
const backend = @import("backend/root.zig");
const placement = @import("placement/root.zig");
const protection = @import("protection/root.zig");
const heal = @import("heal/root.zig");
const object = @import("object/root.zig");
const s3 = @import("s3/root.zig");
const metrics = @import("metrics/root.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm [heal] [--data DIR...] [--listen HOST:PORT] [--protection P] [--scan-interval S]
    \\  heal             run one scan/heal pass over the drives and exit
    \\  --data           one or more drives; /data{1...4} expands (default: $ZKFSM_DATA, else ./data)
    \\  --listen         listen address (default: 0.0.0.0:9000)
    \\  --protection     single | replica:2 | replica:3 | EC:4+2 | EC:8+4 | EC:12+4
    \\                   default: stored in the drive format, else replica:2 with 2+ drives
    \\  --scan-interval  seconds between background heal passes, 0 disables (default: 600)
    \\
;

const Config = struct {
    heal_only: bool = false,
    data: []const []const u8,
    host: []const u8 = "0.0.0.0",
    port: u16 = 9000,
    protection: ?placement.Profile = null,
    scan_interval_s: u64 = 600,
};

const ConfigError = error{ BadArgs, HelpRequested, OutOfMemory };

fn isFlag(a: []const u8) bool {
    return std.mem.startsWith(u8, a, "-");
}

/// Strings in the result point into `args`, `env_data`, or `arena`.
fn parseArgs(arena: std.mem.Allocator, args: []const []const u8, env_data: ?[]const u8) ConfigError!Config {
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
        } else if (std.mem.eql(u8, a, "--scan-interval")) {
            cfg.scan_interval_s = std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs;
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
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = std.process.argsAlloc(arena) catch return 1;
    const env_data = std.process.getEnvVarOwned(arena, "ZKFSM_DATA") catch null;

    const cfg = parseArgs(arena, args, env_data) catch |e| {
        std.debug.print("{s}", .{usage});
        return if (e == error.HelpRequested) 0 else 2;
    };
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
    var server: s3.Server = .{ .gpa = gpa, .svc = &svc };
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    server.run(addr) catch |e| {
        std.log.err("server failed: {t}", .{e});
        return 1;
    };
    return 0;
}

test "arg parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const c = try parseArgs(a, &.{ "zkfsm", "--data", "/tmp/x", "--listen", "127.0.0.1:9100" }, null);
    try std.testing.expectEqualStrings("/tmp/x", c.data[0]);
    try std.testing.expectEqual(@as(u16, 9100), c.port);
    try std.testing.expectEqualStrings("env", (try parseArgs(a, &.{"zkfsm"}, "env")).data[0]);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--listen", "nope" }, null));

    const m = try parseArgs(a, &.{ "zkfsm", "heal", "--data", "/d{1...3}", "/e", "--protection", "replica:3", "--scan-interval", "5" }, null);
    try std.testing.expect(m.heal_only);
    try std.testing.expectEqual(@as(usize, 4), m.data.len);
    try std.testing.expectEqualStrings("/d3", m.data[2]);
    try std.testing.expectEqualStrings("/e", m.data[3]);
    try std.testing.expect(m.protection.?.eql(.{ .replica = 3 }));
    try std.testing.expectEqual(@as(u64, 5), m.scan_interval_s);
    try std.testing.expectEqual(@as(usize, 2), (try parseArgs(a, &.{"zkfsm"}, "/a /b")).data.len);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--protection", "replica:5" }, null));
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
}
