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

    // The hardware hash paths need the LLVM backend, also in Debug.
    const hw_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/core/hwhash.zig"),
        .target = target,
        .optimize = optimize,
    }), .use_llvm = true });
    test_step.dependOn(&b.addRunArtifact(hw_tests).step);

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

    const s3load = b.addExecutable(.{ .name = "s3load", .root_module = b.createModule(.{
        .root_source_file = b.path("bench/s3load.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    }) });
    b.step("s3load", "Build the HTTP load generator").dependOn(&b.addInstallArtifact(s3load, .{}).step);

    // IAM tests as their own root (src/ so iam can import the tls layer).
    const iam_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/iam_tests.zig"),
        .target = target,
        .optimize = optimize,
    }) });
    test_step.dependOn(&b.addRunArtifact(iam_tests).step);

    // S3 Select over Parquet/CSV/JSON fixtures whose expected output came from DuckDB.
    const select_fx = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("tests/select_fixtures_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "select", .module = b.createModule(.{
            .root_source_file = b.path("src/select/root.zig"),
            .target = target,
            .optimize = optimize,
        }) }},
    }) });
    test_step.dependOn(&b.addRunArtifact(select_fx).step);

    // Live remote-backend tests; they skip unless ZKFSM_S3_* / ZKFSM_AZURE_* / ZKFSM_GCS_* are set.
    const live = b.addTest(.{ .root_module = mod, .filters = &.{"remote live"} });
    const live_run = b.addRunArtifact(live);
    live_run.has_side_effects = true;
    b.step("test-remote", "Run live remote backend tests").dependOn(&live_run.step);

    // Kubernetes operator (zkfsm.io/v1 Cluster); shares the admin-payload cipher with the server.
    const dial_mod = b.createModule(.{ .root_source_file = b.path("src/tls/dial.zig"), .target = target, .optimize = optimize });
    const kube_mod = b.createModule(.{
        .root_source_file = b.path("k8s/kube.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "tls_dial", .module = dial_mod }},
    });
    const sio_mod = b.createModule(.{ .root_source_file = b.path("src/admin/sio.zig"), .target = target, .optimize = optimize });
    const op_mod = b.createModule(.{
        .root_source_file = b.path("k8s/operator/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "kube", .module = kube_mod }, .{ .name = "sio", .module = sio_mod } },
    });
    const operator = b.addExecutable(.{ .name = "zkfsm-operator", .root_module = op_mod });
    b.installArtifact(operator);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = op_mod })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = kube_mod })).step);

    // CSI driver for local drives (csi.zkfsm.io): node plugin and controller.
    const csi_mod = b.createModule(.{ .root_source_file = b.path("k8s/csi/main.zig"), .target = target, .optimize = optimize });
    b.installArtifact(b.addExecutable(.{ .name = "zkfsm-csi", .root_module = csi_mod }));
    const csi_tests = b.addRunArtifact(b.addTest(.{ .root_module = csi_mod }));
    test_step.dependOn(&csi_tests.step);
    b.step("test-csi", "Run zkfsm-csi unit tests").dependOn(&csi_tests.step);
}
