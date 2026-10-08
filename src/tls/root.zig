//! tls: native TLS 1.3 and 1.2 server termination on std.crypto primitives.
pub const Session = @import("session.zig").Session;
pub const Error = @import("session.zig").Error;
pub const PeerIdentity = @import("session.zig").PeerIdentity;
pub const Context = @import("config.zig").Context;
pub const Version = @import("config.zig").Version;
pub const Credentials = @import("config.zig").Credentials;
pub const LoadError = @import("config.zig").LoadError;

test {
    _ = @import("der.zig");
    _ = @import("pem.zig");
    _ = @import("rsa.zig");
    _ = @import("peer.zig");
    _ = @import("keys.zig");
    _ = @import("handshake.zig");
    _ = @import("schedule.zig");
    _ = @import("tls12.zig");
    _ = @import("tls12_test.zig");
    _ = @import("config.zig");
    _ = @import("session.zig");
    _ = @import("rfc8448_test.zig");
}
