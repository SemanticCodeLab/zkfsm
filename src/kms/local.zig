//! DEVELOPMENT ONLY. Master keys stored in plaintext JSON files (mode 0600)
//! in a directory. Offers no protection against anyone who can read the
//! disk. Never enable in production; `init` logs a warning every time.
const std = @import("std");
const types = @import("types.zig");
const keyring = @import("keyring.zig");

const Error = types.Error;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.kms_local);

pub const LocalFileStore = struct {
    dir: std.fs.Dir,

    /// Opens (creating if needed) `path` as the key directory.
    pub fn init(path: []const u8) Error!LocalFileStore {
        log.warn("INSECURE local file KMS backend in use at '{s}': development only", .{path});
        std.fs.cwd().makePath(path) catch return error.StorageFailed;
        const dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch return error.StorageFailed;
        return .{ .dir = dir };
    }

    pub fn deinit(s: *LocalFileStore) void {
        s.dir.close();
    }

    pub fn keyStore(s: *LocalFileStore) keyring.KeyStore {
        return .{ .ptr = s, .vtable = &.{ .load = load, .store = store, .list = list } };
    }

    fn fileName(buf: []u8, id: []const u8, suffix: []const u8) Error![]const u8 {
        if (!types.validKeyName(id)) return error.InvalidArgument;
        return std.fmt.bufPrint(buf, "{s}.key{s}", .{ id, suffix }) catch error.InvalidArgument;
    }

    fn load(p: *anyopaque, gpa: Allocator, id: []const u8) Error!keyring.KeyRecord {
        const s: *LocalFileStore = @ptrCast(@alignCast(p));
        var nb: [160]u8 = undefined;
        const name = try fileName(&nb, id, "");
        const bytes = s.dir.readFileAlloc(gpa, name, 1 << 20) catch |e| switch (e) {
            error.FileNotFound => return error.KeyNotFound,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.StorageFailed,
        };
        defer {
            std.crypto.secureZero(u8, bytes);
            gpa.free(bytes);
        }
        var rec = try keyring.KeyRecord.fromJson(gpa, bytes);
        if (!std.mem.eql(u8, rec.id, id)) {
            rec.deinit(gpa);
            return error.InvalidResponse;
        }
        return rec;
    }

    fn store(p: *anyopaque, gpa: Allocator, rec: keyring.KeyRecord, mode: keyring.KeyStore.Mode) Error!void {
        const s: *LocalFileStore = @ptrCast(@alignCast(p));
        var nb: [160]u8 = undefined;
        var tb: [160]u8 = undefined;
        const name = try fileName(&nb, rec.id, "");
        const tmp = try fileName(&tb, rec.id, ".tmp");
        if (mode == .create) {
            if (s.dir.access(name, .{})) |_| return error.KeyExists else |_| {}
        }
        const js = try rec.toJson(gpa);
        defer {
            std.crypto.secureZero(u8, js);
            gpa.free(js);
        }
        {
            var f = s.dir.createFile(tmp, .{ .mode = 0o600, .truncate = true }) catch return error.StorageFailed;
            defer f.close();
            f.writeAll(js) catch return error.StorageFailed;
            f.sync() catch return error.StorageFailed;
        }
        s.dir.rename(tmp, name) catch return error.StorageFailed;
    }

    fn list(p: *anyopaque, gpa: Allocator) Error![][]u8 {
        const s: *LocalFileStore = @ptrCast(@alignCast(p));
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |n| gpa.free(n);
            out.deinit(gpa);
        }
        var it = s.dir.iterate();
        while (it.next() catch return error.StorageFailed) |e| {
            if (e.kind != .file or !std.mem.endsWith(u8, e.name, ".key")) continue;
            const id = e.name[0 .. e.name.len - 4];
            if (!types.validKeyName(id)) continue;
            const d = try gpa.dupe(u8, id);
            out.append(gpa, d) catch {
                gpa.free(d);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(gpa);
    }
};

/// Convenience: a Kms over a dev key directory. Keep both alive together.
pub const LocalKms = struct {
    files: LocalFileStore,
    ring: keyring.KeyringKms,

    pub fn init(self: *LocalKms, path: []const u8) Error!void {
        self.files = try LocalFileStore.init(path);
        self.ring = .{ .store = self.files.keyStore(), .kind = .local };
    }

    pub fn deinit(self: *LocalKms) void {
        self.files.deinit();
    }

    pub fn kms(self: *LocalKms) types.Kms {
        return self.ring.kms();
    }
};

test "local file backend persists across reopen" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(gpa, ".");
    defer gpa.free(path);

    var lk: LocalKms = undefined;
    try lk.init(path);
    var ki = try lk.kms().createKey(gpa, "dev-key");
    ki.deinit(gpa);
    var dk = try lk.kms().generateDataKey(gpa, "dev-key", .{});
    defer dk.deinit(gpa);
    lk.deinit();

    var lk2: LocalKms = undefined;
    try lk2.init(path);
    defer lk2.deinit();
    const back = try lk2.kms().decryptDataKey(gpa, "dev-key", dk.sealed, .{});
    try std.testing.expectEqualSlices(u8, &dk.plaintext, &back);
    const st = try tmp.dir.statFile("dev-key.key");
    try std.testing.expectEqual(@as(std.fs.File.Mode, 0o600), st.mode & 0o777);
    const l = try lk2.kms().listKeys(gpa);
    defer types.freeKeyInfos(gpa, l);
    try std.testing.expectEqual(@as(usize, 1), l.len);
    try std.testing.expectError(error.KeyExists, lk2.kms().createKey(gpa, "dev-key"));
}
