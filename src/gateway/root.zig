//! gateway: non-S3 protocols (FTP/FTPS, SFTP, WebDAV, Swift) over the same
//! object namespace. Each talks to ObjectService and authorizes through IAM.
const std = @import("std");
const tls = @import("../tls/root.zig");
pub const access = @import("access.zig");
pub const fs = @import("fs.zig");
pub const listener = @import("listener.zig");
pub const ftp = @import("ftp.zig");
pub const sftp = @import("sftp.zig");
pub const webdav = @import("webdav.zig");
pub const swift = @import("swift.zig");

pub const Access = access.Access;
pub const Principal = access.Principal;
pub const FlagError = error{ BadArgs, OutOfMemory };
pub const StartError = error{ ListenFailed, ThreadFailed, OutOfMemory, BadConfig };

/// What every gateway gets from main.
pub const Deps = struct {
    gpa: std.mem.Allocator,
    access: Access,
    /// The server certificate (from --tls-cert); FTPS and HTTPS gateways need it.
    tls: ?*tls.Context = null,
    /// Directory for gateway state such as SSH host keys (first drive's .zkfsm).
    state_dir: ?[]const u8 = null,
};

pub const Config = struct {
    ftp: ftp.Config = .{},
    sftp: sftp.Config = .{},
    webdav: webdav.Config = .{},
    swift: swift.Config = .{},

    pub fn any(c: Config) bool {
        return c.ftp.enabled() or c.sftp.enabled() or c.webdav.enabled() or c.swift.enabled();
    }
};

pub const usage = ftp.usage ++ sftp.usage ++ webdav.usage ++ swift.usage;

/// Routes a `--flag value` pair to the gateway that owns it.
pub fn parseFlag(cfg: *Config, flag: []const u8, value: []const u8) FlagError!bool {
    if (try ftp.parseFlag(&cfg.ftp, flag, value)) return true;
    if (try sftp.parseFlag(&cfg.sftp, flag, value)) return true;
    if (try webdav.parseFlag(&cfg.webdav, flag, value)) return true;
    return swift.parseFlag(&cfg.swift, flag, value);
}

/// The enabled gateways; `stop` shuts them all down.
pub const Running = struct {
    ftp: ?*ftp.Server = null,
    sftp: ?*sftp.Server = null,
    webdav: ?*webdav.Server = null,
    swift: ?*swift.Server = null,

    pub fn start(deps: Deps, cfg: Config) StartError!Running {
        var r: Running = .{};
        errdefer r.stop();
        if (cfg.ftp.enabled()) r.ftp = try ftp.Server.start(deps, cfg.ftp);
        if (cfg.sftp.enabled()) r.sftp = try sftp.Server.start(deps, cfg.sftp);
        if (cfg.webdav.enabled()) r.webdav = try webdav.Server.start(deps, cfg.webdav);
        if (cfg.swift.enabled()) r.swift = try swift.Server.start(deps, cfg.swift);
        return r;
    }

    pub fn stop(r: *Running) void {
        if (r.ftp) |s| s.stop();
        if (r.sftp) |s| s.stop();
        if (r.webdav) |s| s.stop();
        if (r.swift) |s| s.stop();
        r.* = .{};
    }
};

test {
    _ = access;
    _ = fs;
    _ = listener;
    _ = ftp;
    _ = sftp;
    _ = webdav;
    _ = swift;
}
