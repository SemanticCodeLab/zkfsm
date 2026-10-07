//! Single fixed master key from configuration (`<name>:<base64 32 bytes>`), the
//! MINIO_KMS_SECRET_KEY format. Keys cannot be created or rotated.
const std = @import("std");
const types = @import("types.zig");
const keyring = @import("keyring.zig");

const Error = types.Error;
const Allocator = std.mem.Allocator;

pub const ParseError = error{ InvalidArgument, OutOfMemory };

pub const StaticKms = struct {
    name: []const u8,
    key: [32]u8,
    ring: keyring.KeyringKms,

    /// `spec` is borrowed and must outlive the backend; `self` must not move.
    pub fn init(self: *StaticKms, spec: []const u8) ParseError!void {
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.InvalidArgument;
        const name = spec[0..colon];
        if (!types.validKeyName(name)) return error.InvalidArgument;
        const b64 = std.base64.standard.Decoder;
        const n = b64.calcSizeForSlice(spec[colon + 1 ..]) catch return error.InvalidArgument;
        if (n != 32) return error.InvalidArgument;
        self.name = name;
        b64.decode(&self.key, spec[colon + 1 ..]) catch return error.InvalidArgument;
        self.ring = .{ .store = .{ .ptr = self, .vtable = &.{ .load = load, .store = store, .list = list } }, .kind = .local };
    }

    pub fn kms(self: *StaticKms) types.Kms {
        return self.ring.kms();
    }

    fn load(p: *anyopaque, gpa: Allocator, id: []const u8) Error!keyring.KeyRecord {
        const s: *StaticKms = @ptrCast(@alignCast(p));
        if (!std.mem.eql(u8, id, s.name)) return error.KeyNotFound;
        const vs = try gpa.alloc(keyring.Version, 1);
        errdefer gpa.free(vs);
        vs[0] = .{ .n = 1, .key = s.key };
        return .{ .id = try gpa.dupe(u8, id), .state = .enabled, .created_unix = 0, .current = 1, .versions = vs };
    }

    fn store(p: *anyopaque, gpa: Allocator, rec: keyring.KeyRecord, mode: keyring.KeyStore.Mode) Error!void {
        const s: *StaticKms = @ptrCast(@alignCast(p));
        _ = gpa;
        _ = mode;
        return if (std.mem.eql(u8, rec.id, s.name)) error.KeyExists else error.Unsupported;
    }

    fn list(p: *anyopaque, gpa: Allocator) Error![][]u8 {
        const s: *StaticKms = @ptrCast(@alignCast(p));
        const out = try gpa.alloc([]u8, 1);
        errdefer gpa.free(out);
        out[0] = try gpa.dupe(u8, s.name);
        return out;
    }
};

test "static key seals and refuses new keys" {
    const gpa = std.testing.allocator;
    var sk: StaticKms = undefined;
    try sk.init("my-key:" ++ "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    const k = sk.kms();
    var dk = try k.generateDataKey(gpa, "my-key", .{});
    defer dk.deinit(gpa);
    const back = try k.decryptDataKey(gpa, "my-key", dk.sealed, .{});
    try std.testing.expectEqualSlices(u8, &dk.plaintext, &back);
    try std.testing.expectError(error.KeyExists, k.createKey(gpa, "my-key"));
    try std.testing.expectError(error.Unsupported, k.createKey(gpa, "other"));
    try std.testing.expectError(error.KeyNotFound, k.generateDataKey(gpa, "other", .{}));
    const l = try k.listKeys(gpa);
    defer types.freeKeyInfos(gpa, l);
    try std.testing.expectEqual(@as(usize, 1), l.len);
    var bad: StaticKms = undefined;
    try std.testing.expectError(error.InvalidArgument, bad.init("nokey"));
    try std.testing.expectError(error.InvalidArgument, bad.init("k:AAAA"));
}
