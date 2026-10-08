//! zkfsm-csi: DirectPV-style local-drive CSI driver (csi.zkfsm.io).
//! Subcommands: controller, node (also `node --gc`), call, version; see `usage`.
const std = @import("std");
const h2 = @import("h2.zig");
const csi = @import("csi.zig");
const drives = @import("drives.zig");
const node_mod = @import("node.zig");
const service = @import("service.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage:
    \\  zkfsm-csi controller --endpoint unix:///csi/csi.sock
    \\  zkfsm-csi node --endpoint unix:///csi/csi.sock --node-id NODE
    \\      [--drive-glob '/dev/loop*']... [--drive-dir PATH] [--state-dir /var/lib/zkfsm-csi]
    \\      [--sysfs /sys] [--dev-root /dev] [--mountinfo /proc/self/mountinfo]
    \\      [--min-drive-size BYTES] [--no-mkfs] [--rescan-seconds 60]
    \\  zkfsm-csi node --gc --volume NAME [--volume NAME]... [--state-dir ...] [--drive-dir ...]
    \\  zkfsm-csi call --endpoint unix:///csi/csi.sock /csi.v1.Identity/GetPluginInfo [HEX_BODY]
    \\
;

const Args = struct {
    cmd: []const u8 = "",
    endpoint: []const u8 = "unix:///csi/csi.sock",
    node_id: []const u8 = "",
    globs: std.ArrayList([]const u8) = .empty,
    drive_dir: ?[]const u8 = null,
    state_dir: []const u8 = "/var/lib/zkfsm-csi",
    sysfs: []const u8 = "/sys",
    dev_root: []const u8 = "/dev",
    mountinfo: []const u8 = "/proc/self/mountinfo",
    min_size: u64 = drives.default_min_size,
    mkfs: bool = true,
    rescan: u64 = 60,
    gc: bool = false,
    volumes: std.ArrayList([]const u8) = .empty,
    positional: std.ArrayList([]const u8) = .empty,
};

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(2);
}

fn parseArgs(arena: std.mem.Allocator, argv: []const []const u8) !Args {
    var a: Args = .{};
    if (argv.len < 1) fatal("{s}", .{usage});
    a.cmd = argv[0];
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        var name = arg;
        var inline_val: ?[]const u8 = null;
        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
                name = arg[0..eq];
                inline_val = arg[eq + 1 ..];
            }
        } else {
            try a.positional.append(arena, arg);
            continue;
        }
        const flags_no_val = [_][]const u8{ "--gc", "--no-mkfs", "--help", "-h" };
        var is_bool = false;
        for (flags_no_val) |f| is_bool = is_bool or std.mem.eql(u8, name, f);
        const val: []const u8 = if (is_bool) "" else inline_val orelse blk: {
            i += 1;
            if (i >= argv.len) fatal("{s} needs a value", .{name});
            break :blk argv[i];
        };
        const eql = std.mem.eql;
        if (eql(u8, name, "--endpoint")) a.endpoint = val //
        else if (eql(u8, name, "--node-id")) a.node_id = val //
        else if (eql(u8, name, "--drive-glob")) {
            var it = std.mem.tokenizeScalar(u8, val, ',');
            while (it.next()) |g| try a.globs.append(arena, g);
        } else if (eql(u8, name, "--drive-dir")) a.drive_dir = if (val.len == 0) null else val //
        else if (eql(u8, name, "--state-dir")) a.state_dir = val //
        else if (eql(u8, name, "--sysfs")) a.sysfs = val //
        else if (eql(u8, name, "--dev-root")) a.dev_root = val //
        else if (eql(u8, name, "--mountinfo")) a.mountinfo = val //
        else if (eql(u8, name, "--min-drive-size")) a.min_size = std.fmt.parseInt(u64, val, 10) catch fatal("bad --min-drive-size", .{}) //
        else if (eql(u8, name, "--rescan-seconds")) a.rescan = std.fmt.parseInt(u64, val, 10) catch fatal("bad --rescan-seconds", .{}) //
        else if (eql(u8, name, "--no-mkfs")) a.mkfs = false //
        else if (eql(u8, name, "--gc")) a.gc = true //
        else if (eql(u8, name, "--volume")) try a.volumes.append(arena, val) //
        else if (eql(u8, name, "--help") or eql(u8, name, "-h")) {
            std.fs.File.stdout().writeAll(usage) catch {};
            std.process.exit(0);
        } else fatal("unknown flag {s}\n{s}", .{ name, usage });
    }
    return a;
}

/// Accepts unix:///abs/path, unix:/abs/path, or a bare path.
pub fn socketPath(endpoint: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, endpoint, "unix://")) return endpoint["unix://".len..];
    if (std.mem.startsWith(u8, endpoint, "unix:")) return endpoint["unix:".len..];
    if (std.mem.indexOf(u8, endpoint, "://") != null) return error.UnsupportedEndpoint;
    return endpoint;
}

fn listen(endpoint: []const u8) !std.posix.socket_t {
    const path = try socketPath(endpoint);
    if (std.fs.path.dirname(path)) |dir| try std.fs.cwd().makePath(dir);
    const fd = try h2.listenUnix(path);
    std.log.info("listening on {s}", .{path});
    return fd;
}

fn rescanLoop(n: *node_mod.Node, seconds: u64) void {
    while (true) {
        std.Thread.sleep(seconds * std.time.ns_per_s);
        n.refresh() catch |e| std.log.warn("rescan: {s}", .{@errorName(e)});
    }
}

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const argv = try std.process.argsAlloc(arena);
    const a = try parseArgs(arena, if (argv.len > 1) argv[1..] else &.{"help"});

    if (std.mem.eql(u8, a.cmd, "controller")) {
        var svc: service.Service = .{ .mode = .controller };
        const fd = try listen(a.endpoint);
        std.log.info("{s} {s} controller ready", .{ csi.plugin_name, csi.plugin_version });
        return h2.serve(gpa, fd, svc.handler());
    }
    if (std.mem.eql(u8, a.cmd, "node")) return runNode(gpa, arena, a);
    if (std.mem.eql(u8, a.cmd, "call")) return runCall(arena, a);
    if (std.mem.eql(u8, a.cmd, "version")) {
        try std.fs.File.stdout().writeAll(csi.plugin_name ++ " " ++ csi.plugin_version ++ "\n");
        return;
    }
    fatal("{s}", .{usage});
}

fn runNode(gpa: std.mem.Allocator, arena: std.mem.Allocator, a: Args) !void {
    if (!a.gc and a.node_id.len == 0) fatal("--node-id is required", .{});
    const n = try node_mod.Node.init(gpa, .{
        .node_id = if (a.node_id.len > 0) a.node_id else "gc",
        .state_dir = a.state_dir,
        .drive_dir = a.drive_dir,
        .scan = .{ .sysfs = a.sysfs, .dev_root = a.dev_root, .mountinfo = a.mountinfo, .globs = a.globs.items, .min_size = a.min_size },
        .mounter = .{ .mountinfo = a.mountinfo },
        .mkfs = a.mkfs and !a.gc,
    });
    defer n.deinit();
    try n.refresh();
    if (a.gc) {
        if (a.volumes.items.len == 0) fatal("--gc needs at least one --volume NAME", .{});
        var failed = false;
        for (a.volumes.items) |name| {
            n.gcVolume(arena, name) catch |e| {
                std.log.err("gc {s}: {s}", .{ name, @errorName(e) });
                failed = true;
                continue;
            };
            std.log.info("gc {s}: data deleted, allocation released", .{name});
        }
        if (failed) std.process.exit(1);
        return;
    }
    var svc: service.Service = .{ .mode = .node, .node = n };
    const fd = try listen(a.endpoint);
    if (a.rescan > 0) (try std.Thread.spawn(.{}, rescanLoop, .{ n, a.rescan })).detach();
    std.log.info("{s} {s} node {s} ready with {d} drive(s)", .{ csi.plugin_name, csi.plugin_version, a.node_id, n.drives.len });
    return h2.serve(gpa, fd, svc.handler());
}

fn runCall(arena: std.mem.Allocator, a: Args) !void {
    if (a.positional.items.len < 1) fatal("call needs METHOD", .{});
    const method = a.positional.items[0];
    var body: []const u8 = "";
    if (a.positional.items.len > 1) {
        const hex = a.positional.items[1];
        const buf = try arena.alloc(u8, hex.len / 2);
        body = std.fmt.hexToBytes(buf, hex) catch fatal("bad hex body", .{});
    }
    const fd = try h2.connectUnix(try socketPath(a.endpoint));
    defer std.posix.close(fd);
    const r = try h2.unaryCall(arena, fd, method, body);
    const out = try std.fmt.allocPrint(arena, "grpc-status: {d}\ngrpc-message: {s}\nbody: {x}\n", .{ r.status, r.message, r.body });
    try std.fs.File.stdout().writeAll(out);
    if (r.status != 0) std.process.exit(1);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("hpack.zig");
    _ = @import("pb.zig");
    _ = @import("h2.zig");
    _ = @import("csi.zig");
    _ = @import("mount.zig");
    _ = @import("drives.zig");
    _ = @import("node.zig");
    _ = @import("service.zig");
}

test "endpoint parsing" {
    try std.testing.expectEqualStrings("/csi/csi.sock", try socketPath("unix:///csi/csi.sock"));
    try std.testing.expectEqualStrings("/a.sock", try socketPath("unix:/a.sock"));
    try std.testing.expectEqualStrings("/b.sock", try socketPath("/b.sock"));
    try std.testing.expectError(error.UnsupportedEndpoint, socketPath("tcp://1.2.3.4:5"));
}

test "argument parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = try parseArgs(arena_state.allocator(), &.{ "node", "--node-id", "w1", "--drive-glob=/dev/loop*,/dev/vd*", "--drive-glob", "/dev/nvme*", "--no-mkfs", "--state-dir", "/s" });
    try std.testing.expectEqualStrings("node", a.cmd);
    try std.testing.expectEqualStrings("w1", a.node_id);
    try std.testing.expectEqual(@as(usize, 3), a.globs.items.len);
    try std.testing.expect(!a.mkfs);
    try std.testing.expectEqualStrings("/s", a.state_dir);
}
