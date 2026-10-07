//! Swift account and container metadata. Account metadata (incl. temp URL keys)
//! lives in one small file per account under `<state_dir>/swift` (memory only
//! without a state dir); container metadata is stored as reserved bucket tags.
const std = @import("std");
const object = @import("../object/root.zig");
const util = @import("swift_util.zig");

pub const max_count = 90;
pub const max_name = 128;
pub const max_value = 256;
pub const max_total = 4096;
/// Bucket tag keys are at most 128 bytes, so container names are shorter.
pub const tag_prefix = "swift-meta:";
pub const max_container_name = 128 - tag_prefix.len;
pub const owner_tag = "swift-owner";
const owner_name = "@owner";

pub const Meta = struct { name: []const u8, value: []const u8 };

pub const Error = error{ BadMetadata, TooMuchMetadata, Storage, OutOfMemory };

/// Collects `<prefix><name>: value` headers (set) and `X-Remove-<prefix><name>` (cleared).
/// Names are lowercased; an empty value removes the entry.
pub fn fromHeaders(a: std.mem.Allocator, headers: []const std.http.Header, prefix: []const u8, max_name_len: usize) Error![]Meta {
    var out: std.ArrayList(Meta) = .empty;
    for (headers) |h| {
        var name: []const u8 = undefined;
        var value = h.value;
        if (startsWithIgnoreCase(h.name, prefix)) {
            name = h.name[prefix.len..];
        } else if (startsWithIgnoreCase(h.name, "x-remove-") and startsWithIgnoreCase(h.name["x-remove-".len..], prefix[2..])) {
            name = h.name["x-remove-".len + prefix.len - 2 ..];
            value = "";
        } else continue;
        if (name.len == 0 or name.len > max_name_len or value.len > max_value or !util.safeValue(value)) return error.BadMetadata;
        const lower = try a.alloc(u8, name.len);
        for (name, lower) |c, *l| {
            l.* = std.ascii.toLower(c);
            if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null)) return error.BadMetadata;
        }
        if (out.items.len == max_count) return error.TooMuchMetadata;
        try out.append(a, .{ .name = lower, .value = std.mem.trim(u8, value, " \t") });
    }
    return out.items;
}

fn startsWithIgnoreCase(s: []const u8, p: []const u8) bool {
    return s.len >= p.len and std.ascii.eqlIgnoreCase(s[0..p.len], p);
}

/// Applies `changes` to `cur`; returns the merged list in `a`.
pub fn merge(a: std.mem.Allocator, cur: []const Meta, changes: []const Meta) Error![]Meta {
    var out: std.ArrayList(Meta) = .empty;
    for (cur) |m| {
        var replaced = false;
        for (changes) |c| if (std.mem.eql(u8, c.name, m.name)) {
            replaced = true;
        };
        if (!replaced) try out.append(a, m);
    }
    for (changes) |c| if (c.value.len > 0) try out.append(a, c);
    var total: usize = 0;
    for (out.items) |m| total += m.name.len + m.value.len;
    if (out.items.len > max_count or total > max_total) return error.TooMuchMetadata;
    return out.items;
}

pub fn find(list: []const Meta, name: []const u8) ?[]const u8 {
    for (list) |m| if (std.mem.eql(u8, m.name, name)) return m.value;
    return null;
}

// ---- accounts ----

pub const Account = struct { meta: []Meta, owner: ?[]const u8 };

pub const AccountStore = struct {
    gpa: std.mem.Allocator,
    /// `<state_dir>/swift`, or null for memory only.
    dir: ?[]const u8 = null,
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMapUnmanaged([]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, state_dir: ?[]const u8) error{OutOfMemory}!AccountStore {
        var s: AccountStore = .{ .gpa = gpa };
        if (state_dir) |d| {
            s.dir = try std.fs.path.join(gpa, &.{ d, "swift" });
            std.fs.cwd().makePath(s.dir.?) catch {};
        }
        return s;
    }

    pub fn deinit(s: *AccountStore) void {
        var it = s.map.iterator();
        while (it.next()) |e| {
            s.gpa.free(e.key_ptr.*);
            s.gpa.free(e.value_ptr.*);
        }
        s.map.deinit(s.gpa);
        if (s.dir) |d| s.gpa.free(d);
    }

    fn fileName(buf: []u8, account: []const u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.print("acct-{x}", .{account}) catch return "";
        return w.buffered();
    }

    /// Encoded record (copied into `a`), loading it from disk on first use.
    fn loadLocked(s: *AccountStore, a: std.mem.Allocator, account: []const u8) Error![]const u8 {
        if (s.map.get(account)) |v| return a.dupe(u8, v);
        const dir = s.dir orelse return "";
        var nb: [2 * util_max_account + 8]u8 = undefined;
        const name = fileName(&nb, account);
        var d = std.fs.cwd().openDir(dir, .{}) catch return error.Storage;
        defer d.close();
        const bytes = d.readFileAlloc(s.gpa, name, max_total * 3) catch |e| return switch (e) {
            error.FileNotFound => "",
            error.OutOfMemory => error.OutOfMemory,
            else => error.Storage,
        };
        errdefer s.gpa.free(bytes);
        const key = try s.gpa.dupe(u8, account);
        errdefer s.gpa.free(key);
        try s.map.put(s.gpa, key, bytes);
        return a.dupe(u8, bytes);
    }

    pub fn get(s: *AccountStore, a: std.mem.Allocator, account: []const u8) Error!Account {
        if (account.len > util_max_account) return .{ .meta = &.{}, .owner = null };
        s.mutex.lock();
        const bytes = s.loadLocked(a, account) catch |e| {
            s.mutex.unlock();
            return e;
        };
        s.mutex.unlock();
        return decode(a, bytes);
    }

    /// Merges `changes` and records `owner` (the identity temp URLs act as).
    pub fn update(s: *AccountStore, account: []const u8, changes: []const Meta, owner: []const u8) Error!void {
        if (account.len > util_max_account) return error.BadMetadata;
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        s.mutex.lock();
        defer s.mutex.unlock();
        const cur = try decode(a, try s.loadLocked(a, account));
        const merged = try merge(a, cur.meta, changes);
        var w: std.Io.Writer.Allocating = .init(a);
        encode(&w.writer, merged, owner) catch return error.OutOfMemory;
        const bytes = try s.gpa.dupe(u8, w.written());
        errdefer s.gpa.free(bytes);
        if (s.dir) |dir| {
            var nb: [2 * util_max_account + 8]u8 = undefined;
            var d = std.fs.cwd().openDir(dir, .{}) catch return error.Storage;
            defer d.close();
            d.writeFile(.{ .sub_path = fileName(&nb, account), .data = bytes }) catch return error.Storage;
        }
        if (s.map.getPtr(account)) |v| {
            s.gpa.free(v.*);
            v.* = bytes;
        } else {
            const key = try s.gpa.dupe(u8, account);
            errdefer s.gpa.free(key);
            try s.map.put(s.gpa, key, bytes);
        }
    }
};

pub const util_max_account = 128;

fn encode(w: *std.Io.Writer, list: []const Meta, owner: []const u8) std.Io.Writer.Error!void {
    if (owner.len > 0) try w.print("{s}\t{s}\n", .{ owner_name, owner });
    for (list) |m| try w.print("{s}\t{s}\n", .{ m.name, m.value });
}

fn decode(a: std.mem.Allocator, bytes: []const u8) Error!Account {
    var out: std.ArrayList(Meta) = .empty;
    var owner: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        const m: Meta = .{ .name = line[0..tab], .value = line[tab + 1 ..] };
        if (std.mem.eql(u8, m.name, owner_name)) owner = m.value else if (out.items.len < max_count) try out.append(a, m);
    }
    return .{ .meta = out.items, .owner = owner };
}

// ---- containers (bucket tags) ----

pub const Container = struct { meta: []Meta, owner: ?[]const u8, other: []object.Tag };

pub fn getContainer(svc: *object.ObjectService, a: std.mem.Allocator, bucket: []const u8) object.Error!Container {
    const tags = object.versioning.getBucketTags(svc, a, bucket) catch |e| switch (e) {
        error.NoSuchTagSet => &[_]object.Tag{},
        else => return e,
    };
    var meta: std.ArrayList(Meta) = .empty;
    var other: std.ArrayList(object.Tag) = .empty;
    var owner: ?[]const u8 = null;
    for (tags) |t| {
        if (std.mem.startsWith(u8, t.key, tag_prefix)) {
            try meta.append(a, .{ .name = t.key[tag_prefix.len..], .value = t.value });
        } else if (std.mem.eql(u8, t.key, owner_tag)) owner = t.value else try other.append(a, t);
    }
    return .{ .meta = meta.items, .owner = owner, .other = other.items };
}

/// Merges `changes` into the container's metadata, keeping foreign tags.
pub fn updateContainer(svc: *object.ObjectService, a: std.mem.Allocator, bucket: []const u8, changes: []const Meta, owner: ?[]const u8) (object.Error || Error)!void {
    const cur = try getContainer(svc, a, bucket);
    const merged = try merge(a, cur.meta, changes);
    var tags: std.ArrayList(object.Tag) = .empty;
    try tags.appendSlice(a, cur.other);
    for (merged) |m| try tags.append(a, .{ .key = try std.fmt.allocPrint(a, tag_prefix ++ "{s}", .{m.name}), .value = m.value });
    if (owner orelse cur.owner) |o| try tags.append(a, .{ .key = owner_tag, .value = o });
    if (tags.items.len > 50) return error.TooMuchMetadata;
    try object.versioning.setBucketTags(svc, bucket, if (tags.items.len == 0) null else tags.items);
}

test "metadata from headers and merge" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hs = [_]std.http.Header{
        .{ .name = "X-Container-Meta-Color", .value = " red " },
        .{ .name = "X-Remove-Container-Meta-Size", .value = "x" },
        .{ .name = "Content-Type", .value = "text/plain" },
    };
    const m = try fromHeaders(a, &hs, "x-container-meta-", 100);
    try std.testing.expectEqual(@as(usize, 2), m.len);
    try std.testing.expectEqualStrings("color", m[0].name);
    try std.testing.expectEqualStrings("red", m[0].value);
    try std.testing.expectEqualStrings("", m[1].value);
    const cur = [_]Meta{ .{ .name = "size", .value = "1" }, .{ .name = "keep", .value = "y" } };
    const merged = try merge(a, &cur, m);
    try std.testing.expectEqual(@as(usize, 2), merged.len);
    try std.testing.expectEqualStrings("y", find(merged, "keep").?);
    try std.testing.expectEqualStrings("red", find(merged, "color").?);
    try std.testing.expectError(error.BadMetadata, fromHeaders(a, &.{.{ .name = "X-Container-Meta-a b", .value = "v" }}, "x-container-meta-", 100));
    try std.testing.expectError(error.BadMetadata, fromHeaders(a, &.{.{ .name = "X-Container-Meta-a", .value = "v" ** 300 }}, "x-container-meta-", 100));
}

test "account store persists" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &pbuf);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    {
        var s = try AccountStore.init(std.testing.allocator, dir);
        defer s.deinit();
        try s.update("AUTH_t", &.{.{ .name = "temp-url-key", .value = "k1" }}, "alice");
        try s.update("AUTH_t", &.{.{ .name = "color", .value = "red" }}, "alice");
    }
    var s = try AccountStore.init(std.testing.allocator, dir);
    defer s.deinit();
    const acct = try s.get(arena.allocator(), "AUTH_t");
    try std.testing.expectEqualStrings("k1", find(acct.meta, "temp-url-key").?);
    try std.testing.expectEqualStrings("red", find(acct.meta, "color").?);
    try std.testing.expectEqualStrings("alice", acct.owner.?);
    const none = try s.get(arena.allocator(), "AUTH_none");
    try std.testing.expectEqual(@as(usize, 0), none.meta.len);
}
