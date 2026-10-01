//! ftp gateway (stub; replaced by the implementation).
const std = @import("std");
const root = @import("root.zig");

pub const Config = struct {
    listen: ?std.net.Address = null,

    pub fn enabled(c: Config) bool {
        return c.listen != null;
    }
};

pub const usage = "";

/// Consumes `flag value` when it belongs to this gateway.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) root.FlagError!bool {
    _ = cfg;
    _ = flag;
    _ = value;
    return false;
}

pub const Server = struct {
    pub fn start(deps: root.Deps, cfg: Config) root.StartError!*Server {
        _ = deps;
        _ = cfg;
        return error.ListenFailed;
    }

    pub fn stop(self: *Server) void {
        _ = self;
    }
};
