//! s3: the S3 protocol adapter. Talks to ObjectService only, never to backends.
pub const server = @import("server.zig");
pub const handler = @import("handler.zig");
pub const router = @import("router.zig");
pub const xml = @import("xml.zig");
pub const errors = @import("errors.zig");
pub const sigv4 = @import("sigv4.zig");
pub const multipart = @import("multipart.zig");
pub const versioning = @import("versioning.zig");
pub const xml_read = @import("xml_read.zig");

pub const Server = server.Server;

test {
    _ = server;
    _ = handler;
    _ = router;
    _ = xml;
    _ = errors;
    _ = sigv4;
    _ = multipart;
    _ = versioning;
    _ = xml_read;
}
