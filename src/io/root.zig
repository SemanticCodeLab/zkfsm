//! io: streaming helpers; buffer pool and io_uring come later.
pub const stream = @import("stream.zig");
pub const HashingReader = stream.HashingReader;

test {
    _ = stream;
}
