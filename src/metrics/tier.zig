//! Prometheus series for remote tiers: activity counters and per-tier usage.
const std = @import("std");
const object = @import("../object/root.zig");

pub fn render(svc: *object.ObjectService, w: *std.Io.Writer) std.Io.Writer.Error!void {
    const reg = svc.tiers orelse return;
    const c = &reg.counters;
    const counters = .{
        .{ "zkfsm_tier_transitions_total", "Objects moved to a remote tier", &c.transitions },
        .{ "zkfsm_tier_transitioned_bytes_total", "Bytes moved to remote tiers", &c.transitioned_bytes },
        .{ "zkfsm_tier_transition_failures_total", "Transitions that failed and will be retried", &c.transition_failures },
        .{ "zkfsm_tier_restores_total", "RestoreObject copies made", &c.restores },
        .{ "zkfsm_tier_restore_failures_total", "RestoreObject copies that failed", &c.restore_failures },
        .{ "zkfsm_tier_restores_expired_total", "Restored copies removed after expiry", &c.restores_expired },
        .{ "zkfsm_tier_remote_reads_total", "Reads served from a remote tier", &c.remote_reads },
        .{ "zkfsm_tier_remote_read_bytes_total", "Bytes read from remote tiers", &c.remote_read_bytes },
        .{ "zkfsm_tier_remote_read_failures_total", "Reads from a remote tier that failed", &c.remote_read_failures },
        .{ "zkfsm_tier_cleanup_deleted_total", "Remote blobs of removed versions deleted", &c.cleanup_deleted },
        .{ "zkfsm_tier_cleanup_failures_total", "Remote deletes that failed and will be retried", &c.cleanup_failures },
    };
    inline for (counters) |m| try w.print("# HELP {s} {s}\n# TYPE {s} counter\n{s} {d}\n", .{ m[0], m[1], m[0], m[0], m[2].load(.monotonic) });
    try w.print("# HELP zkfsm_tier_cleanup_pending Remote deletes waiting in the cleanup journal\n# TYPE zkfsm_tier_cleanup_pending gauge\nzkfsm_tier_cleanup_pending {d}\n", .{c.cleanup_pending.load(.monotonic)});

    var buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const view = reg.statsCopy(fba.allocator()) catch return;
    const gauges = .{
        .{ "zkfsm_tier_objects", "Current object versions stored in the tier", "objects" },
        .{ "zkfsm_tier_versions", "Object versions stored in the tier", "versions" },
        .{ "zkfsm_tier_bytes", "Bytes stored in the tier", "bytes" },
    };
    inline for (gauges) |g| {
        try w.print("# HELP {s} {s}\n# TYPE {s} gauge\n", .{ g[0], g[1], g[0] });
        try w.print("{s}{{tier=\"STANDARD\"}} {d}\n", .{ g[0], @field(view.hot, g[2]) });
        for (view.tiers) |t| try w.print("{s}{{tier=\"{s}\",type=\"{s}\"}} {d}\n", .{ g[0], t.name, t.kind, @field(t.usage, g[2]) });
    }
}
