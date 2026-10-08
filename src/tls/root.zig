//! tls: native TLS 1.3 server termination on std.crypto primitives.
pub const Session = @import("session.zig").Session;
pub const Error = @import("session.zig").Error;
pub const PeerIdentity = @import("session.zig").PeerIdentity;
pub const Context = @import("config.zig").Context;
pub const Credentials = @import("config.zig").Credentials;
pub const LoadError = @import("config.zig").LoadError;
/// Outbound side: TLS 1.2/1.3 client with client certificates, dialing, HTTPS.
pub const Client = @import("client.zig");
pub const ClientAuth = @import("client_auth.zig").ClientAuth;
pub const dial = @import("dial.zig");
pub const TlsOptions = dial.TlsOptions;
pub const https = @import("https.zig");

test {
    _ = @import("der.zig");
    _ = @import("pem.zig");
    _ = @import("rsa.zig");
    _ = @import("peer.zig");
    _ = @import("keys.zig");
    _ = @import("handshake.zig");
    _ = @import("schedule.zig");
    _ = @import("config.zig");
    _ = @import("session.zig");
    _ = @import("rfc8448_test.zig");
    _ = @import("client_auth.zig");
    _ = @import("dial.zig");
    _ = @import("https.zig");
    _ = @import("client_test.zig");
}
