//! Throughput of encode and reconstruct per EC profile. Run: zig build bench
const std = @import("std");
const erasure = @import("erasure");

const shard_len = 1 << 20;
const target_ns = 1_000_000_000;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    var prng = std.Random.DefaultPrng.init(42);

    std.debug.print("{s:<8} {s:>14} {s:>18} {s:>18}\n", .{ "profile", "shard", "encode MB/s", "reconstruct MB/s" });
    for (std.meta.tags(erasure.Profile)) |p| {
        const c = erasure.Codec.init(p);
        const n = p.totalShards();
        const k = p.dataShards();
        var bufs: [16][]u8 = undefined;
        for (0..n) |i| {
            bufs[i] = try a.alignedAlloc(u8, .@"64", shard_len);
            prng.random().bytes(bufs[i]);
        }
        defer for (0..n) |i| a.free(bufs[i]);
        var data: [16][]const u8 = undefined;
        for (0..k) |i| data[i] = bufs[i];

        const data_bytes: f64 = @floatFromInt(@as(usize, k) * shard_len);
        var timer = try std.time.Timer.start();
        var iters: usize = 0;
        while (timer.read() < target_ns) : (iters += 1) try c.encode(data[0..k], bufs[k..n]);
        const enc = data_bytes * @as(f64, @floatFromInt(iters)) / (@as(f64, @floatFromInt(timer.read())) / 1e9) / 1e6;

        // Worst case: lose the first m data shards.
        var present = [_]bool{true} ** 16;
        for (0..p.parityShards()) |i| present[i] = false;
        timer.reset();
        iters = 0;
        while (timer.read() < target_ns) : (iters += 1) try c.reconstruct(bufs[0..n], present[0..n]);
        const rec = data_bytes * @as(f64, @floatFromInt(iters)) / (@as(f64, @floatFromInt(timer.read())) / 1e9) / 1e6;
        if (!try c.verify(bufs[0..n])) return error.VerifyFailed;

        std.debug.print("{s:<8} {d:>11} KiB {d:>18.0} {d:>18.0}\n", .{ p.name(), shard_len / 1024, enc, rec });
    }
}
