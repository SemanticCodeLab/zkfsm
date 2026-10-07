//! events: bucket event notifications (configuration, MinIO-compatible records,
//! persistent per-target queues, broker clients, live listening) and audit logging.
pub const target = @import("target.zig");
pub const net = @import("net.zig");
pub const names = @import("names.zig");
pub const config = @import("config.zig");
pub const record = @import("record.zig");
pub const queue = @import("queue.zig");
pub const kinds = @import("kinds.zig");
pub const settings = @import("settings.zig");
pub const store = @import("store.zig");
pub const notifier = @import("notifier.zig");
pub const audit = @import("audit.zig");
pub const s3ext = @import("s3ext.zig");
pub const admin = @import("admin.zig");

pub const Notifier = notifier.Notifier;

test {
    _ = target;
    _ = net;
    _ = names;
    _ = config;
    _ = record;
    _ = queue;
    _ = kinds;
    _ = settings;
    _ = store;
    _ = notifier;
    _ = audit;
    _ = s3ext;
    _ = admin;
}
