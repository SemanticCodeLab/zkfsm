//! Server-side encryption, the KMS backend selection and S3 Select, served as
//! S3 routes ahead of the built-in dispatch.
pub const common = @import("common.zig");
pub const setup = @import("setup.zig");
pub const handler = @import("handler.zig");
pub const select_api = @import("select_api.zig");
pub const kms_admin = @import("kms_admin.zig");

pub const Sse = handler.SseExt;
pub const SelectApi = select_api.SelectExt;
pub const KmsAdmin = kms_admin.KmsAdmin;

test {
    _ = common;
    _ = setup;
    _ = handler;
    _ = select_api;
    _ = kms_admin;
}
