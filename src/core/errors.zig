//! Shared error sets. Each layer defines its own set; these are the leaves.
pub const StreamError = error{ ReadFailed, WriteFailed };
pub const AllocError = error{OutOfMemory};
