//! Package root for embedding zkfsm (e.g. by extension builds). Re-exports
//! the layers; the binary entry point stays in main.zig.
pub const core = @import("core/root.zig");
pub const io = @import("io/root.zig");
pub const device = @import("device/root.zig");
pub const backend = @import("backend/root.zig");
pub const metadata = @import("metadata/root.zig");
pub const placement = @import("placement/root.zig");
pub const object = @import("object/root.zig");
pub const s3 = @import("s3/root.zig");
pub const metrics = @import("metrics/root.zig");
pub const license = core.license;

test {
    _ = core;
}
