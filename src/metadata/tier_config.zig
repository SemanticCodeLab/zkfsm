//! Remote tier definitions and their binary encoding (the plaintext that is sealed
//! into system state). Pure; no I/O.
const std = @import("std");
const codec = @import("codec.zig");

pub const Kind = enum(u8) {
    s3 = 1,
    azure = 2,
    gcs = 3,
    minio = 4,

    pub fn parse(s: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |f| if (std.mem.eql(u8, s, f.name)) return @enumFromInt(f.value);
        return null;
    }
};

pub const max_tiers = 256;
pub const max_name = 64;
pub const max_field = 4096;

/// One tier. For azure `access_key`/`secret_key` are the account name and key; for
/// gcs they are the HMAC interoperability key pair.
pub const Config = struct {
    name: []const u8,
    kind: Kind,
    endpoint: []const u8 = "",
    access_key: []const u8 = "",
    secret_key: []const u8 = "",
    bucket: []const u8,
    prefix: []const u8 = "",
    region: []const u8 = "",
    storage_class: []const u8 = "",
    created_ns: i128 = 0,

    pub fn eql(a: Config, b: Config) bool {
        if (a.kind != b.kind or a.created_ns != b.created_ns) return false;
        inline for (string_fields) |f| if (!std.mem.eql(u8, @field(a, f), @field(b, f))) return false;
        return true;
    }
};

const string_fields = .{ "name", "endpoint", "access_key", "secret_key", "bucket", "prefix", "region", "storage_class" };

/// Tier names are upper-case letters, digits, '-' and '_' (S3 storage-class style),
/// and never STANDARD, which names the local hot tier.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name or std.mem.eql(u8, name, "STANDARD")) return false;
    for (name) |c| if (!(std.ascii.isUpper(c) or std.ascii.isDigit(c) or c == '-' or c == '_')) return false;
    return true;
}

pub const Error = error{ InvalidConfig, OutOfMemory };

pub fn encode(gpa: std.mem.Allocator, tiers: []const Config) Error![]u8 {
    if (tiers.len > max_tiers) return error.InvalidConfig;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    const w = &a.writer;
    codec.putInt(w, u16, @intCast(tiers.len)) catch return error.OutOfMemory;
    for (tiers) |t| {
        if (!validName(t.name)) return error.InvalidConfig;
        w.writeByte(@intFromEnum(t.kind)) catch return error.OutOfMemory;
        codec.putInt(w, i128, t.created_ns) catch return error.OutOfMemory;
        inline for (string_fields) |f| {
            const v: []const u8 = @field(t, f);
            if (v.len > max_field) return error.InvalidConfig;
            codec.putInt(w, u16, @intCast(v.len)) catch return error.OutOfMemory;
            w.writeAll(v) catch return error.OutOfMemory;
        }
    }
    return a.toOwnedSlice() catch error.OutOfMemory;
}

/// Strings borrow from `bytes`; the slice lives in `arena`.
pub fn decode(arena: std.mem.Allocator, bytes: []const u8) (codec.DecodeError || error{OutOfMemory})![]Config {
    var c: codec.Cursor = .{ .bytes = bytes };
    const n = try c.int(u16);
    if (n > max_tiers) return error.Corrupt;
    const out = try arena.alloc(Config, n);
    for (out) |*t| {
        t.* = .{ .name = "", .kind = .s3, .bucket = "" };
        t.kind = std.meta.intToEnum(Kind, (try c.take(1))[0]) catch return error.Corrupt;
        t.created_ns = try c.int(i128);
        inline for (string_fields) |f| @field(t, f) = try c.take(try c.int(u16));
        if (!validName(t.name)) return error.Corrupt;
    }
    if (c.pos != bytes.len) return error.Corrupt;
    return out;
}

test "tier config roundtrip and names" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const tiers = [_]Config{
        .{ .name = "WARM", .kind = .minio, .endpoint = "http://127.0.0.1:9000", .access_key = "ak", .secret_key = "sk", .bucket = "b", .prefix = "p/", .created_ns = 5 },
        .{ .name = "AZ_1", .kind = .azure, .access_key = "acct", .secret_key = "a2V5", .bucket = "cont" },
    };
    const b = try encode(gpa, &tiers);
    defer gpa.free(b);
    const d = try decode(arena.allocator(), b);
    try std.testing.expectEqual(@as(usize, 2), d.len);
    try std.testing.expect(d[0].eql(tiers[0]) and d[1].eql(tiers[1]) and !d[0].eql(tiers[1]));
    for (0..b.len) |n| try std.testing.expectError(error.Corrupt, decode(arena.allocator(), b[0..n]));
    try std.testing.expect(validName("WARM-TIER_2"));
    for ([_][]const u8{ "", "warm", "STANDARD", "A B", "X" ** 65 }) |bad| try std.testing.expect(!validName(bad));
    try std.testing.expectError(error.InvalidConfig, encode(gpa, &.{.{ .name = "lower", .kind = .s3, .bucket = "b" }}));
    try std.testing.expectEqual(Kind.gcs, Kind.parse("gcs").?);
    try std.testing.expect(Kind.parse("ftp") == null);
}
