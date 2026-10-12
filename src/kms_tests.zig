//! Test root for KMS; sits in src/ so kms may import the tls layer.
test {
    _ = @import("kms/root.zig");
}
