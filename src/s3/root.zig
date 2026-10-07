//! s3: the S3 protocol adapter. Talks to ObjectService only, never to backends.
pub const server = @import("server.zig");
pub const handler = @import("handler.zig");
pub const router = @import("router.zig");
pub const xml = @import("xml.zig");
pub const errors = @import("errors.zig");
pub const sigv4 = @import("sigv4.zig");
pub const authz = @import("authz.zig");
pub const multipart = @import("multipart.zig");
pub const versioning = @import("versioning.zig");
pub const xml_read = @import("xml_read.zig");
pub const extension = @import("extension.zig");
pub const lifecycle = @import("lifecycle.zig");
pub const policy = @import("policy.zig");
pub const acl = @import("acl.zig");
pub const list_v1 = @import("list_v1.zig");
pub const sts = @import("sts.zig");
pub const restore = @import("restore.zig");
pub const tenancy = @import("tenancy.zig");
pub const Extension = extension.Extension;

pub const Server = server.Server;

test {
    _ = server;
    _ = handler;
    _ = router;
    _ = xml;
    _ = errors;
    _ = sigv4;
    _ = authz;
    _ = multipart;
    _ = versioning;
    _ = xml_read;
    _ = extension;
    _ = lifecycle;
    _ = policy;
    _ = acl;
    _ = list_v1;
    _ = sts;
    _ = restore;
    _ = tenancy;
}
