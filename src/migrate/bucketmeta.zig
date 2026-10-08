//! Decoder for the source's per-bucket `.metadata.bin`: a 4-byte header (format and
//! version, little-endian u16 each) then a msgpack map of configuration documents.
const std = @import("std");
const msgpack = @import("msgpack.zig");
const model = @import("model.zig");

pub const Error = msgpack.Error || error{ BadHeader, UnsupportedVersion };

pub const Parsed = struct {
    name: []const u8 = "",
    created_ns: i128 = 0,
    configs: model.BucketConfigs = .{},
};

fn doc(r: *msgpack.Reader) Error!?[]const u8 {
    if (try r.nil()) return null;
    const b = try r.bytes();
    return if (b.len == 0) null else b;
}

pub fn parse(bytes: []const u8) Error!Parsed {
    if (bytes.len < 4) return error.BadHeader;
    const format = std.mem.readInt(u16, bytes[0..2], .little);
    const version = std.mem.readInt(u16, bytes[2..4], .little);
    if (format != 1) return error.BadHeader;
    if (version != 1) return error.UnsupportedVersion;
    var r: msgpack.Reader = .{ .buf = bytes[4..] };
    var out: Parsed = .{};
    const c = &out.configs;
    const n = try r.mapLen();
    for (0..n) |_| {
        const k = try r.str();
        if (std.mem.eql(u8, k, "Name")) {
            out.name = try r.str();
        } else if (std.mem.eql(u8, k, "Created")) {
            out.created_ns = try r.time();
        } else if (std.mem.eql(u8, k, "LockEnabled")) {
            c.lock_enabled = try r.boolean();
        } else if (std.mem.eql(u8, k, "PolicyConfigJSON")) {
            c.policy = try doc(&r);
        } else if (std.mem.eql(u8, k, "NotificationConfigXML")) {
            c.notification = try doc(&r);
        } else if (std.mem.eql(u8, k, "LifecycleConfigXML")) {
            c.lifecycle = try doc(&r);
        } else if (std.mem.eql(u8, k, "ObjectLockConfigXML")) {
            c.object_lock = try doc(&r);
        } else if (std.mem.eql(u8, k, "VersioningConfigXML")) {
            c.versioning = try doc(&r);
        } else if (std.mem.eql(u8, k, "EncryptionConfigXML")) {
            c.encryption = try doc(&r);
        } else if (std.mem.eql(u8, k, "TaggingConfigXML")) {
            c.tagging = try doc(&r);
        } else if (std.mem.eql(u8, k, "QuotaConfigJSON")) {
            c.quota = try doc(&r);
        } else if (std.mem.eql(u8, k, "ReplicationConfigXML")) {
            c.replication = try doc(&r);
        } else if (std.mem.eql(u8, k, "CorsConfigXML") or std.mem.eql(u8, k, "BucketCorsConfigXML")) {
            c.cors = try doc(&r);
        } else try r.skip();
    }
    // A lock configuration document implies Object Lock even when the flag is absent.
    if (c.object_lock) |x| if (std.mem.indexOf(u8, x, "<ObjectLockEnabled>Enabled</ObjectLockEnabled>") != null) {
        c.lock_enabled = true;
    };
    return out;
}

test "parses a minimal blob and rejects hostile ones" {
    const blob = "\x01\x00\x01\x00" ++ "\x83" ++ "\xa4Name" ++ "\xa3abc" ++ "\xabLockEnabled" ++ "\xc3" ++
        "\xb3VersioningConfigXML" ++ "\xc4\x04<V/>";
    const p = try parse(blob);
    try std.testing.expectEqualStrings("abc", p.name);
    try std.testing.expect(p.configs.lock_enabled);
    try std.testing.expectEqualStrings("<V/>", p.configs.versioning.?);
    try std.testing.expectError(error.BadHeader, parse("\x02\x00\x01\x00"));
    try std.testing.expectError(error.UnsupportedVersion, parse("\x01\x00\x09\x00"));
    for (0..blob.len) |i| _ = parse(blob[0..i]) catch {};
}
