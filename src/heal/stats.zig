//! Heal pass counters, read lock-free by observability endpoints.
const std = @import("std");

pub const ring_len = 16;

const A64 = std.atomic.Value(u64);
const I64 = std.atomic.Value(i64);

pub const Stats = struct {
    passes: A64 = .init(0),
    /// Start of the pass in progress (ms since epoch); 0 when idle.
    running_since_ms: I64 = .init(0),
    entries: A64 = .init(0),
    keys_checked: A64 = .init(0),
    repaired: A64 = .init(0),
    unrepaired: A64 = .init(0),
    /// Completion times of the last `ring_len` passes, oldest overwritten first.
    done_ms: [ring_len]I64 = [_]I64{.init(0)} ** ring_len,

    pub fn begin(s: *Stats) void {
        s.running_since_ms.store(std.time.milliTimestamp(), .release);
    }

    pub fn abort(s: *Stats) void {
        s.running_since_ms.store(0, .release);
    }

    pub fn end(s: *Stats, entries: u64, checked: u64, repaired: u64, unrepaired: u64) void {
        _ = s.entries.fetchAdd(entries, .monotonic);
        _ = s.keys_checked.fetchAdd(checked, .monotonic);
        _ = s.repaired.fetchAdd(repaired, .monotonic);
        _ = s.unrepaired.fetchAdd(unrepaired, .monotonic);
        const n = s.passes.fetchAdd(1, .acq_rel);
        s.done_ms[n % ring_len].store(std.time.milliTimestamp(), .release);
        s.running_since_ms.store(0, .release);
    }

    /// Completion times, oldest first, into `out`.
    pub fn completed(s: *const Stats, out: *[ring_len]i64) []i64 {
        const n = s.passes.load(.acquire);
        const k: usize = @intCast(@min(n, ring_len));
        for (0..k) |i| out[i] = s.done_ms[@intCast((n - k + i) % ring_len)].load(.acquire);
        return out[0..k];
    }
};

test "completion ring keeps the newest passes in order" {
    var s: Stats = .{};
    for (0..20) |_| {
        s.begin();
        s.end(3, 2, 1, 0);
    }
    var buf: [ring_len]i64 = undefined;
    const c = s.completed(&buf);
    try std.testing.expectEqual(@as(usize, ring_len), c.len);
    for (1..c.len) |i| try std.testing.expect(c[i - 1] <= c[i]);
    try std.testing.expectEqual(@as(u64, 60), s.entries.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 0), s.running_since_ms.load(.monotonic));
}
