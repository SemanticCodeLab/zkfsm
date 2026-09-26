const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
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
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);

    // Live remote-backend tests; they skip unless ZKFSM_S3_* / ZKFSM_AZURE_* / ZKFSM_GCS_* are set.
    const live = b.addTest(.{ .root_module = mod, .filters = &.{"remote live"} });
    const live_run = b.addRunArtifact(live);
    live_run.has_side_effects = true;
    b.step("test-remote", "Run live remote backend tests").dependOn(&live_run.step);
}
