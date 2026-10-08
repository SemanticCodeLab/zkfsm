//! Service control: restart or stop every node. A node answers first, then stops
//! serving (draining in-flight requests); a restart re-executes the same binary with
//! the same arguments and environment once the server has shut down.
const std = @import("std");
const admin = @import("../admin/root.zig");
const root = @import("root.zig");
const peer = @import("peer.zig");

const Ops = root.Ops;

pub const Action = enum {
    restart,
    stop,

    pub fn parse(s: []const u8) ?Action {
        return std.meta.stringToEnum(Action, s);
    }

    fn iamAction(a: Action) []const u8 {
        return switch (a) {
            .restart => "admin:ServiceRestart",
            .stop => "admin:ServiceStop",
        };
    }
};

const PeerResult = struct { host: []const u8, err: ?[]const u8 = null };

/// Delay between answering and stopping, so the response reaches the client.
const answer_grace_ns = 300 * std.time.ns_per_ms;

pub fn handle(o: *Ops, c: *const admin.api.Ctx) admin.api.Error!admin.api.Response {
    const name = try c.param("action") orelse return admin.api.badRequest(c.a, "action is required.");
    const action = Action.parse(name) orelse
        return admin.api.fail(c.a, .not_implemented, "NotImplemented", "Only restart and stop are supported.");
    if (!try c.canAction(action.iamAction())) return admin.api.denied(c.a);
    const dry = std.mem.eql(u8, try c.param("dry-run") orelse "false", "true");
    const v2 = std.mem.eql(u8, try c.param("type") orelse "", "2");
    var results: std.ArrayList(PeerResult) = .empty;
    for (0..o.nodeCount()) |i| {
        const host = o.nodeName(i);
        if (i == o.selfNode()) {
            try results.append(c.a, .{ .host = host });
            continue;
        }
        const err: ?[]const u8 = if (dry)
            (if (o.nodeOnline(i)) null else "node is offline")
        else
            peer.sendService(o, @intCast(i), action);
        try results.append(c.a, .{ .host = host, .err = err });
    }
    if (!dry) schedule(o, action);
    if (!v2) return .{};
    return c.json(.{ .action = name, .dryRun = dry, .results = results.items });
}

/// Stops this node's server in the background; a restart re-executes it afterwards.
pub fn schedule(o: *Ops, action: Action) void {
    if (action == .restart) o.restart.store(true, .release);
    std.log.warn("admin: service {t} requested", .{action});
    const t = std.Thread.spawn(.{}, stopLater, .{o}) catch {
        if (o.server) |s| _ = s.requestStop();
        return;
    };
    t.detach();
}

fn stopLater(o: *Ops) void {
    std.Thread.sleep(answer_grace_ns);
    if (o.server) |s| _ = s.requestStop();
}

/// Replaces the process with a fresh copy of itself; returns only on failure.
pub fn reexec() void {
    const a = std.heap.page_allocator;
    const argv = a.allocSentinel(?[*:0]const u8, std.os.argv.len, null) catch return;
    for (std.os.argv, 0..) |arg, i| argv[i] = arg;
    const envp = a.allocSentinel(?[*:0]const u8, std.os.environ.len, null) catch return;
    for (std.os.environ, 0..) |e, i| envp[i] = e;
    std.log.info("restarting", .{});
    const err = std.posix.execveZ("/proc/self/exe", argv.ptr, envp.ptr);
    std.log.err("restart failed: {t}", .{err});
}

test "actions" {
    try std.testing.expectEqual(Action.restart, Action.parse("restart").?);
    try std.testing.expect(Action.parse("freeze") == null);
}
