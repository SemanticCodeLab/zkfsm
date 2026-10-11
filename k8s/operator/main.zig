//! zkfsm-operator: reconciles zkfsm.io/v1 Cluster resources.
const std = @import("std");
const kube = @import("kube");
const controller = @import("controller.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm-operator [--namespace NS] [--interval SECONDS] [--once]
    \\  --namespace  watch one namespace (default: all; $WATCH_NAMESPACE)
    \\  --interval   seconds between reconcile passes (default: 5)
    \\  --once       run a single pass and exit
    \\API access: in-cluster service account, or $KUBE_API (e.g. http://127.0.0.1:8001 from kubectl proxy)
    \\
;

pub fn main() !u8 {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    const gpa = gpa_state.allocator();
    var opts: controller.Options = .{ .namespace = std.posix.getenv("WATCH_NAMESPACE") };
    var once = false;
    var it = std.process.args();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--namespace")) {
            opts.namespace = it.next() orelse return bad();
        } else if (std.mem.eql(u8, arg, "--interval")) {
            opts.interval_s = std.fmt.parseInt(u32, it.next() orelse return bad(), 10) catch return bad();
        } else if (std.mem.eql(u8, arg, "--once")) {
            once = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage});
            return 0;
        } else return bad();
    }
    if (opts.namespace) |n| if (n.len == 0) {
        opts.namespace = null;
    };
    const kc = kube.Client.fromEnv(gpa) catch |e| {
        std.log.err("kubernetes client: {t}", .{e});
        return 1;
    };
    defer kc.deinit();
    var ctl: controller.Controller = .{ .gpa = gpa, .kc = kc, .opts = opts };
    std.log.info("zkfsm-operator watching {s}, every {d}s", .{ opts.namespace orelse "all namespaces", opts.interval_s });
    if (once) {
        std.fs.cwd().makePath(opts.work_dir) catch {};
        ctl.pass();
        return 0;
    }
    ctl.run();
    return 0;
}

fn bad() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

test {
    _ = @import("controller.zig");
    _ = @import("render.zig");
    _ = @import("spec.zig");
    _ = @import("tlsgen.zig");
    _ = @import("admin.zig");
    _ = @import("jv.zig");
}
