//! Fan-out: one call per drive, run concurrently on a shared pool, so a quorum
//! operation costs about one round trip whatever the set size. The caller claims
//! indices too and only ever runs its own calls, so it never waits for a busy pool
//! or for unrelated work (that could hold locks it depends on).
const std = @import("std");

const pool_threads = 64;

var pool: std.Thread.Pool = undefined;
var pool_ok = false;
var once = std.once(initPool);

fn initPool() void {
    pool.init(.{ .allocator = std.heap.smp_allocator, .n_jobs = pool_threads }) catch return;
    pool_ok = true;
}

/// Shared by the caller and the pool tasks it spawned; freed by the last one out.
const Job = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, i: usize) void,
    n: usize,
    next: std.atomic.Value(usize) = .init(0),
    done: std.atomic.Value(usize) = .init(0),
    refs: std.atomic.Value(u32) = .init(1),
    finished: std.Thread.ResetEvent = .{},

    /// Runs unclaimed indices until none are left.
    fn work(j: *Job) void {
        while (true) {
            const i = j.next.fetchAdd(1, .acq_rel);
            if (i >= j.n) return;
            j.call(j.ctx, i);
            if (j.done.fetchAdd(1, .acq_rel) + 1 == j.n) j.finished.set();
        }
    }

    fn unref(j: *Job) void {
        if (j.refs.fetchSub(1, .acq_rel) == 1) std.heap.smp_allocator.destroy(j);
    }

    fn task(j: *Job) void {
        j.work();
        j.unref();
    }
};

/// Calls `f(ctx, i)` for every i in [0, n); concurrently when `parallel` is set.
/// `ctx` must be a pointer. Returns once all calls returned.
pub fn run(n: usize, parallel: bool, ctx: anytype, comptime f: fn (@TypeOf(ctx), usize) void) void {
    if (n == 0) return;
    if (parallel and n > 1) {
        once.call();
        if (pool_ok) if (std.heap.smp_allocator.create(Job)) |j| {
            const E = struct {
                fn call(p: *anyopaque, i: usize) void {
                    f(@ptrCast(@alignCast(p)), i);
                }
            };
            j.* = .{ .ctx = @ptrCast(@constCast(ctx)), .call = E.call, .n = n };
            for (1..n) |_| {
                _ = j.refs.fetchAdd(1, .acq_rel);
                pool.spawn(Job.task, .{j}) catch {
                    _ = j.refs.fetchSub(1, .acq_rel);
                    break;
                };
            }
            j.work();
            j.finished.wait();
            j.unref();
            return;
        } else |_| {};
    }
    for (0..n) |i| f(ctx, i);
}

test "fan-out runs every index once, in parallel or not" {
    const Ctx = struct {
        hits: [16]std.atomic.Value(u32) = @splat(.init(0)),
        fn f(c: *@This(), i: usize) void {
            _ = c.hits[i].fetchAdd(1, .monotonic);
        }
    };
    for ([_]bool{ false, true }) |par| {
        var c: Ctx = .{};
        run(16, par, &c, Ctx.f);
        for (&c.hits) |*h| try std.testing.expectEqual(@as(u32, 1), h.load(.monotonic));
    }
    // Nested fan-out from inside a call completes too.
    const Outer = struct {
        n: std.atomic.Value(u32) = .init(0),
        fn f(o: *@This(), _: usize) void {
            var c: Ctx = .{};
            run(8, true, &c, Ctx.f);
            _ = o.n.fetchAdd(1, .monotonic);
        }
    };
    var o: Outer = .{};
    run(200, true, &o, Outer.f);
    try std.testing.expectEqual(@as(u32, 200), o.n.load(.monotonic));
}
