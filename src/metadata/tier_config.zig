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

/// How a tier authenticates to its backend.
pub const Auth = enum(u8) {
    /// Static key pair (S3 keys, Azure account key, GCS HMAC key).
    keys = 0,
    /// Temporary keys from a web-identity role exchange or the metadata endpoint.
    role = 1,
    /// GCS service account: `access_key` is the client email, `secret_key` the PEM key.
    service_account = 2,
    /// Azure service principal: `secret_key` is the client secret.
    service_principal = 3,
};

/// One tier. For azure `access_key`/`secret_key` are the account name and key; for
/// gcs they are the HMAC interoperability key pair (see `Auth` for the other modes).
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
    auth: Auth = .keys,
    role_arn: []const u8 = "",
    /// Web-identity token file (role); empty uses the node's environment.
    token_file: []const u8 = "",
    /// OAuth token endpoint (service account) or authority (service principal).
    token_uri: []const u8 = "",
    tenant_id: []const u8 = "",
    client_id: []const u8 = "",
    /// TLS to the endpoint: PEM client certificate and key paths, CA bundle path,
    /// verified host name, and minimum version ("1.2"/"1.3"); all node-local.
    client_cert: []const u8 = "",
    client_key: []const u8 = "",
    ca_file: []const u8 = "",
    server_name: []const u8 = "",
    min_version: []const u8 = "",

    pub fn eql(a: Config, b: Config) bool {
        if (a.kind != b.kind or a.created_ns != b.created_ns or a.auth != b.auth) return false;
        inline for (string_fields) |f| if (!std.mem.eql(u8, @field(a, f), @field(b, f))) return false;
        return true;
    }
};

const v1_fields = .{ "name", "endpoint", "access_key", "secret_key", "bucket", "prefix", "region", "storage_class" };
const v2_fields = .{ "role_arn", "token_file", "token_uri", "tenant_id", "client_id" };
const v3_fields = .{ "client_cert", "client_key", "ca_file", "server_name", "min_version" };
pub const string_fields = v1_fields ++ v2_fields ++ v3_fields;
/// Leading u16 of the v2/v3 encodings (v1 starts with the tier count, at most 256).
const v2_marker: u16 = 0xffff;
const v3_marker: u16 = 0xfffe;

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
    codec.putInt(w, u16, v3_marker) catch return error.OutOfMemory;
    codec.putInt(w, u16, @intCast(tiers.len)) catch return error.OutOfMemory;
    for (tiers) |t| {
        if (!validName(t.name)) return error.InvalidConfig;
        w.writeByte(@intFromEnum(t.kind)) catch return error.OutOfMemory;
        codec.putInt(w, i128, t.created_ns) catch return error.OutOfMemory;
        w.writeByte(@intFromEnum(t.auth)) catch return error.OutOfMemory;
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
    var n = try c.int(u16);
    const v3 = n == v3_marker;
    const v2 = v3 or n == v2_marker;
    if (v2) n = try c.int(u16);
    if (n > max_tiers) return error.Corrupt;
    const out = try arena.alloc(Config, n);
    for (out) |*t| {
        t.* = .{ .name = "", .kind = .s3, .bucket = "" };
        t.kind = std.meta.intToEnum(Kind, (try c.take(1))[0]) catch return error.Corrupt;
        t.created_ns = try c.int(i128);
        if (v2) t.auth = std.meta.intToEnum(Auth, (try c.take(1))[0]) catch return error.Corrupt;
        inline for (v1_fields) |f| @field(t, f) = try c.take(try c.int(u16));
        if (v2) inline for (v2_fields) |f| {
            @field(t, f) = try c.take(try c.int(u16));
        };
        if (v3) inline for (v3_fields) |f| {
            @field(t, f) = try c.take(try c.int(u16));
        };
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
        .{ .name = "AZ_SP", .kind = .azure, .access_key = "acct", .secret_key = "cs", .bucket = "cont", .auth = .service_principal, .tenant_id = "t", .client_id = "c", .client_cert = "/c.pem", .client_key = "/k.pem", .min_version = "1.3" },
    };
    const b = try encode(gpa, &tiers);
    defer gpa.free(b);
    const d = try decode(arena.allocator(), b);
    try std.testing.expectEqual(@as(usize, 3), d.len);
    try std.testing.expect(d[0].eql(tiers[0]) and d[1].eql(tiers[1]) and !d[0].eql(tiers[1]) and d[2].eql(tiers[2]));
    try std.testing.expectEqualStrings("c", d[2].client_id);
    try std.testing.expectEqualStrings("/k.pem", d[2].client_key);
    // v1 encoding (no marker, no auth) still decodes.
    const v1 = [_]u8{ 1, 0, 1 } ++ [_]u8{0} ** 16 ++ [_]u8{ 1, 0, 'W' } ++ [_]u8{ 0, 0 } ** 3 ++ [_]u8{ 1, 0, 'b' } ++ [_]u8{ 0, 0 } ** 3;
    const old = try decode(arena.allocator(), &v1);
    try std.testing.expectEqualStrings("W", old[0].name);
    try std.testing.expectEqual(Auth.keys, old[0].auth);
    for (0..b.len) |n| try std.testing.expectError(error.Corrupt, decode(arena.allocator(), b[0..n]));
    try std.testing.expect(validName("WARM-TIER_2"));
    for ([_][]const u8{ "", "warm", "STANDARD", "A B", "X" ** 65 }) |bad| try std.testing.expect(!validName(bad));
    try std.testing.expectError(error.InvalidConfig, encode(gpa, &.{.{ .name = "lower", .kind = .s3, .bucket = "b" }}));
    try std.testing.expectEqual(Kind.gcs, Kind.parse("gcs").?);
    try std.testing.expect(Kind.parse("ftp") == null);
}
