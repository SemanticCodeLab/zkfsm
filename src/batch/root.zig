//! batch: MinIO-compatible batch jobs (replicate, keyrotate, expire) driven by
//! YAML job definitions over the admin API, run in the background and resumable.
pub const yaml = @import("yaml.zig");
pub const spec = @import("spec.zig");
pub const job = @import("job.zig");
pub const walk = @import("walk.zig");
pub const match = @import("match.zig");
pub const crypt = @import("crypt.zig");
pub const remote = @import("remote.zig");
pub const run = @import("run.zig");
pub const report = @import("report.zig");
pub const templates = @import("templates.zig");
pub const manager = @import("manager.zig");
pub const api = @import("api.zig");

pub const Manager = manager.Manager;
pub const Api = api.Api;

test {
    _ = yaml;
    _ = spec;
    _ = job;
    _ = walk;
    _ = match;
    _ = crypt;
    _ = remote;
    _ = run;
    _ = report;
    _ = templates;
    _ = manager;
    _ = api;
}
