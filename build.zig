const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.addModule("zkfsm", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{ .name = "zkfsm", .root_module = mod });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run the zkfsm server").dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = mod });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const erasure_src = b.path("src/protection/erasure.zig");
    const erasure_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = erasure_src,
        .target = target,
        .optimize = optimize,
    }) });
    test_step.dependOn(&b.addRunArtifact(erasure_tests).step);

    // Benchmarks always build ReleaseFast regardless of -Doptimize.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/erasure_bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("erasure", b.createModule(.{
        .root_source_file = erasure_src,
        .target = target,
        .optimize = .ReleaseFast,
    }));
    const bench = b.addExecutable(.{ .name = "erasure-bench", .root_module = bench_mod });
    b.step("bench", "Erasure codec throughput (ReleaseFast)").dependOn(&b.addRunArtifact(bench).step);
}
