//! The contract every notification/audit target client implements, and the
//! key=value settings they are configured from (admin config, env, flags).
const std = @import("std");

pub const Kv = struct { key: []const u8, value: []const u8 };

pub const Settings = struct {
    kvs: []const Kv = &.{},

    pub fn get(s: Settings, key: []const u8) []const u8 {
        for (s.kvs) |kv| if (std.mem.eql(u8, kv.key, key)) return kv.value;
        return "";
    }

    pub fn flag(s: Settings, key: []const u8) bool {
        const v = s.get(key);
        return std.ascii.eqlIgnoreCase(v, "on") or std.ascii.eqlIgnoreCase(v, "true") or std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "yes");
    }

    /// Integer value, `default` when unset; InvalidConfig when malformed.
    pub fn int(s: Settings, comptime T: type, key: []const u8, default: T) error{InvalidConfig}!T {
        const v = s.get(key);
        if (v.len == 0) return default;
        return std.fmt.parseInt(T, v, 10) catch error.InvalidConfig;
    }

    /// Duration like "10s", "500ms", "1m", or plain seconds; in milliseconds.
    pub fn durationMs(s: Settings, key: []const u8, default_ms: u64) error{InvalidConfig}!u64 {
        const v = s.get(key);
        if (v.len == 0) return default_ms;
        const units = [_]struct { []const u8, u64 }{ .{ "ms", 1 }, .{ "s", 1000 }, .{ "m", 60_000 }, .{ "h", 3_600_000 } };
        for (units) |u| if (std.mem.endsWith(u8, v, u[0])) {
            const n = std.fmt.parseInt(u64, v[0 .. v.len - u[0].len], 10) catch continue;
            return std.math.mul(u64, n, u[1]) catch error.InvalidConfig;
        };
        const n = std.fmt.parseInt(u64, v, 10) catch return error.InvalidConfig;
        return std.math.mul(u64, n, 1000) catch error.InvalidConfig;
    }
};

/// Row layout for database and key-value targets.
pub const Format = enum {
    /// One row/field per object key, updated in place, removed on delete.
    namespace,
    /// Append-only log of every event with its time.
    access,

    pub fn parse(s: []const u8) error{InvalidConfig}!Format {
        if (s.len == 0 or std.ascii.eqlIgnoreCase(s, "namespace")) return .namespace;
        if (std.ascii.eqlIgnoreCase(s, "access")) return .access;
        return error.InvalidConfig;
    }
};

/// One delivery. Slices are valid for the duration of `send` only.
pub const Message = struct {
    /// "bucket/object" (object unescaped); empty for audit entries.
    key: []const u8 = "",
    /// e.g. "s3:ObjectCreated:Put"; empty for audit entries.
    event_name: []const u8 = "",
    /// Full payload: `{"EventName":..,"Key":..,"Records":[..]}` or an audit entry.
    body: []const u8,
    /// The single event record object (namespace/access formats).
    record: []const u8 = "",
    /// RFC 3339 UTC event time.
    event_time: []const u8 = "",
    /// ObjectRemoved:* events delete the namespace row/field.
    removed: bool = false,
};

pub const SendError = error{
    /// Connection or transport failure; the entry stays queued and is retried.
    Unreachable,
    /// The peer answered with a failure; retried with backoff.
    Rejected,
    OutOfMemory,
};

pub const InitError = error{ InvalidConfig, OutOfMemory };

/// A live target client. `send` connects lazily and reconnects after failures;
/// it is called from one delivery thread at a time.
pub const Client = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ctx: *anyopaque, msg: *const Message) SendError!void,
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn send(c: Client, msg: *const Message) SendError!void {
        return c.vtable.send(c.ctx, msg);
    }

    pub fn deinit(c: Client) void {
        c.vtable.deinit(c.ctx);
    }
};

test "settings parsing" {
    const s: Settings = .{ .kvs = &.{ .{ .key = "tls", .value = "on" }, .{ .key = "n", .value = "7" }, .{ .key = "d", .value = "2m" } } };
    try std.testing.expect(s.flag("tls"));
    try std.testing.expect(!s.flag("x"));
    try std.testing.expectEqual(@as(u32, 7), try s.int(u32, "n", 1));
    try std.testing.expectEqual(@as(u32, 1), try s.int(u32, "none", 1));
    try std.testing.expectEqual(@as(u64, 120_000), try s.durationMs("d", 5));
    try std.testing.expectEqual(Format.access, try Format.parse("ACCESS"));
    try std.testing.expectError(error.InvalidConfig, Format.parse("x"));
}
