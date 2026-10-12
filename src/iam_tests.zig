//! Test root for IAM; sits in src/ so iam may import sibling layers (tls).
test {
    _ = @import("iam/root.zig");
}
