//! device: physical substrates a backend sits on. Only LocalPath exists in 0.1.
pub const DeviceKind = enum { local_path, block_device, network_filesystem, object_backend, plugin };

pub const LocalPath = struct {
    path: []const u8,
    pub const kind: DeviceKind = .local_path;
};
