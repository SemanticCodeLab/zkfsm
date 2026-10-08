//! Catalog records (table bucket marker, namespaces, table pointers) on top of
//! the document store. A table pointer names the current metadata file; commits
//! swap it with If-Match on the pointer's ETag, which is also the version token.
const std = @import("std");
const json = @import("json.zig");
const store_mod = @import("store.zig");

const Allocator = std.mem.Allocator;
const Store = store_mod.Store;
pub const Tag = store_mod.Tag;

pub const reserved_prefix = ".zkfsm-tables/";
const marker_key = reserved_prefix ++ "bucket";
pub const policy_key = reserved_prefix ++ "policy";
const ns_prefix = reserved_prefix ++ "ns/";
const tbl_prefix = reserved_prefix ++ "t/";

pub const max_doc = 1024 * 1024;
pub const max_metadata = 16 * 1024 * 1024;
pub const max_name = 255;
pub const max_levels = 16;
pub const max_page = 1000;
/// Listing pages scanned per request while filtering namespaces.
const max_scan_pages = 64;

pub const Error = store_mod.Error || error{ InvalidName, NotEmpty, Corrupt, NotTableBucket };

pub const Bucket = struct { name: []const u8, id: []const u8, created_ms: i64, owner: []const u8 };

pub const Namespace = struct {
    levels: []const []const u8,
    id: []const u8,
    created_ms: i64,
    created_by: []const u8,
    properties: json.ObjectMap,
    tag: Tag = undefined,
};

pub const Table = struct {
    levels: []const []const u8,
    name: []const u8,
    uuid: []const u8,
    metadata_location: ?[]const u8 = null,
    warehouse: []const u8,
    created_ms: i64,
    modified_ms: i64,
    created_by: []const u8,
    modified_by: []const u8,
    /// Metadata file sequence; the next file is gen + 1.
    gen: i64 = 0,
    tag: Tag = undefined,
};

/// Namespace level and table name rules: 1..255 bytes, no control characters.
pub fn validName(n: []const u8) bool {
    if (n.len == 0 or n.len > max_name) return false;
    for (n) |c| if (c < 0x20 or c == 0x7f) return false;
    return true;
}

pub fn validLevels(levels: []const []const u8) bool {
    if (levels.len == 0 or levels.len > max_levels) return false;
    for (levels) |l| if (!validName(l)) return false;
    return true;
}

fn joinLevels(w: *std.Io.Writer, levels: []const []const u8) std.Io.Writer.Error!void {
    for (levels, 0..) |l, k| {
        if (k > 0) try w.writeAll("%1F");
        try store_mod.encodeName(w, l);
    }
}

fn nsKey(arena: Allocator, levels: []const []const u8) error{OutOfMemory}![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    w.writer.writeAll(ns_prefix) catch return error.OutOfMemory;
    joinLevels(&w.writer, levels) catch return error.OutOfMemory;
    return w.written();
}

fn tablePrefix(arena: Allocator, levels: []const []const u8) error{OutOfMemory}![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    w.writer.writeAll(tbl_prefix) catch return error.OutOfMemory;
    joinLevels(&w.writer, levels) catch return error.OutOfMemory;
    w.writer.writeByte('/') catch return error.OutOfMemory;
    return w.written();
}

fn tableKey(arena: Allocator, levels: []const []const u8, name: []const u8) error{OutOfMemory}![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    w.writer.writeAll(try tablePrefix(arena, levels)) catch return error.OutOfMemory;
    store_mod.encodeName(&w.writer, name) catch return error.OutOfMemory;
    return w.written();
}

fn splitLevels(arena: Allocator, enc: []const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitSequence(u8, enc, "%1F");
    while (it.next()) |part| {
        if (out.items.len >= max_levels) return error.Corrupt;
        try out.append(arena, store_mod.decodeName(arena, part) catch return error.Corrupt);
    }
    return out.items;
}

pub fn nowMs() i64 {
    return std.time.milliTimestamp();
}

pub const Catalog = struct {
    store: *Store,

    // ---- table buckets ----

    pub fn getBucket(c: Catalog, arena: Allocator, bucket: []const u8) Error!?Bucket {
        const got = c.store.read(arena, bucket, marker_key, max_doc) catch |e| switch (e) {
            error.NoSuchBucket => return null,
            else => return e,
        };
        const doc = got orelse return null;
        const o = json.parseObject(arena, doc.body) catch return error.Corrupt;
        return .{
            .name = bucket,
            .id = json.str(o, "id") orelse "",
            .created_ms = json.int(o, "createdAt") orelse 0,
            .owner = json.str(o, "owner") orelse "",
        };
    }

    /// Marks an existing (empty or new) bucket as a table bucket.
    pub fn markBucket(c: Catalog, arena: Allocator, bucket: []const u8, owner: []const u8) Error!void {
        var o = json.newObject(arena);
        var ub: [36]u8 = undefined;
        try o.put("id", json.s(@import("metadata.zig").uuid4(&ub)));
        try o.put("createdAt", json.i(nowMs()));
        try o.put("owner", json.s(owner));
        _ = try c.store.write(bucket, marker_key, try json.stringify(arena, .{ .object = o }), .create);
    }

    /// Removes the marker; fails while namespaces remain.
    pub fn unmarkBucket(c: Catalog, arena: Allocator, bucket: []const u8) Error!void {
        const page = try c.store.list(arena, bucket, ns_prefix, "", 1);
        if (page.keys.len > 0) return error.NotEmpty;
        const tables = try c.store.list(arena, bucket, tbl_prefix, "", 1);
        if (tables.keys.len > 0) return error.NotEmpty;
        try c.store.remove(bucket, policy_key);
        try c.store.remove(bucket, marker_key);
    }

    pub fn requireBucket(c: Catalog, arena: Allocator, bucket: []const u8) Error!Bucket {
        return try c.getBucket(arena, bucket) orelse error.NotTableBucket;
    }

    // ---- namespaces ----

    pub fn getNamespace(c: Catalog, arena: Allocator, bucket: []const u8, levels: []const []const u8) Error!?Namespace {
        if (!validLevels(levels)) return error.InvalidName;
        const doc = try c.store.read(arena, bucket, try nsKey(arena, levels), max_doc) orelse return null;
        const o = json.parseObject(arena, doc.body) catch return error.Corrupt;
        return .{
            .levels = levels,
            .id = json.str(o, "id") orelse "",
            .created_ms = json.int(o, "createdAt") orelse 0,
            .created_by = json.str(o, "createdBy") orelse "",
            .properties = json.obj(o, "properties") orelse json.newObject(arena),
            .tag = doc.tag,
        };
    }

    fn nsDoc(arena: Allocator, ns: Namespace) Error![]const u8 {
        var o = json.newObject(arena);
        try o.put("namespace", try json.stringArray(arena, ns.levels));
        try o.put("id", json.s(ns.id));
        try o.put("createdAt", json.i(ns.created_ms));
        try o.put("createdBy", json.s(ns.created_by));
        try o.put("properties", .{ .object = ns.properties });
        return json.stringify(arena, .{ .object = o });
    }

    pub fn createNamespace(c: Catalog, arena: Allocator, bucket: []const u8, ns: Namespace) Error!void {
        if (!validLevels(ns.levels)) return error.InvalidName;
        _ = try c.store.write(bucket, try nsKey(arena, ns.levels), try nsDoc(arena, ns), .create);
    }

    /// Rewrites properties if the namespace still has `ns.tag`.
    pub fn updateNamespace(c: Catalog, arena: Allocator, bucket: []const u8, ns: Namespace) Error!void {
        var tag = ns.tag;
        _ = try c.store.write(bucket, try nsKey(arena, ns.levels), try nsDoc(arena, ns), .{ .match = &tag });
    }

    pub fn dropNamespace(c: Catalog, arena: Allocator, bucket: []const u8, levels: []const []const u8) Error!void {
        const h = try c.store.lock(bucket);
        defer h.release();
        _ = try c.getNamespace(arena, bucket, levels) orelse return error.NotFound;
        const tables = try c.store.list(arena, bucket, try tablePrefix(arena, levels), "", 1);
        if (tables.keys.len > 0) return error.NotEmpty;
        const child_prefix = try std.fmt.allocPrint(arena, "{s}%1F", .{try nsKey(arena, levels)});
        const children = try c.store.list(arena, bucket, child_prefix, "", 1);
        if (children.keys.len > 0) return error.NotEmpty;
        try c.store.remove(bucket, try nsKey(arena, levels));
    }

    pub const NsPage = struct { items: []const []const []const u8, next: ?[]const u8 };

    /// Direct children of `parent` (top level when empty); `after` is an opaque page token.
    pub fn listNamespaces(c: Catalog, arena: Allocator, bucket: []const u8, parent: []const []const u8, name_prefix: []const u8, after: []const u8, max: usize) Error!NsPage {
        const prefix = if (parent.len == 0) ns_prefix else try std.fmt.allocPrint(arena, "{s}%1F", .{try nsKey(arena, parent)});
        var out: std.ArrayList([]const []const u8) = .empty;
        var cursor = if (after.len > 0 and std.mem.startsWith(u8, after, prefix)) after else "";
        var pages: usize = 0;
        while (pages < max_scan_pages) : (pages += 1) {
            const page = try c.store.list(arena, bucket, prefix, cursor, max_page);
            for (page.keys) |k| {
                cursor = k;
                const levels = try splitLevels(arena, k[ns_prefix.len..]);
                if (levels.len != parent.len + 1) continue;
                if (!std.mem.startsWith(u8, levels[levels.len - 1], name_prefix)) continue;
                try out.append(arena, levels);
                if (out.items.len == max) return .{ .items = out.items, .next = if (page.truncated or !std.mem.eql(u8, k, page.keys[page.keys.len - 1])) k else null };
            }
            if (!page.truncated) return .{ .items = out.items, .next = null };
        }
        return .{ .items = out.items, .next = if (cursor.len > 0) cursor else null };
    }

    // ---- tables ----

    pub fn getTable(c: Catalog, arena: Allocator, bucket: []const u8, levels: []const []const u8, name: []const u8) Error!?Table {
        if (!validLevels(levels) or !validName(name)) return error.InvalidName;
        const doc = try c.store.read(arena, bucket, try tableKey(arena, levels, name), max_doc) orelse return null;
        const o = json.parseObject(arena, doc.body) catch return error.Corrupt;
        return .{
            .levels = levels,
            .name = name,
            .uuid = json.str(o, "uuid") orelse return error.Corrupt,
            .metadata_location = json.str(o, "metadataLocation"),
            .warehouse = json.str(o, "warehouseLocation") orelse "",
            .created_ms = json.int(o, "createdAt") orelse 0,
            .modified_ms = json.int(o, "modifiedAt") orelse 0,
            .created_by = json.str(o, "createdBy") orelse "",
            .modified_by = json.str(o, "modifiedBy") orelse "",
            .gen = json.int(o, "gen") orelse 0,
            .tag = doc.tag,
        };
    }

    fn tableDoc(arena: Allocator, t: Table) Error![]const u8 {
        var o = json.newObject(arena);
        try o.put("namespace", try json.stringArray(arena, t.levels));
        try o.put("name", json.s(t.name));
        try o.put("uuid", json.s(t.uuid));
        try o.put("metadataLocation", if (t.metadata_location) |l| json.s(l) else .null);
        try o.put("warehouseLocation", json.s(t.warehouse));
        try o.put("createdAt", json.i(t.created_ms));
        try o.put("modifiedAt", json.i(t.modified_ms));
        try o.put("createdBy", json.s(t.created_by));
        try o.put("modifiedBy", json.s(t.modified_by));
        try o.put("gen", json.i(t.gen));
        return json.stringify(arena, .{ .object = o });
    }

    /// Creates the pointer; the namespace must exist. Returns the version token.
    pub fn createTable(c: Catalog, arena: Allocator, bucket: []const u8, t: Table) Error!Tag {
        if (!validLevels(t.levels) or !validName(t.name)) return error.InvalidName;
        const h = try c.store.lock(bucket);
        defer h.release();
        _ = try c.getNamespace(arena, bucket, t.levels) orelse return error.NotFound;
        return c.store.write(bucket, try tableKey(arena, t.levels, t.name), try tableDoc(arena, t), .create);
    }

    /// Compare-and-swap of the pointer: succeeds only if it still has `t.tag`.
    pub fn swapTable(c: Catalog, arena: Allocator, bucket: []const u8, t: Table) Error!Tag {
        var tag = t.tag;
        return c.store.write(bucket, try tableKey(arena, t.levels, t.name), try tableDoc(arena, t), .{ .match = &tag });
    }

    /// Deletes the pointer, optionally only at version `want`.
    pub fn dropTable(c: Catalog, arena: Allocator, bucket: []const u8, levels: []const []const u8, name: []const u8, want: ?[]const u8) Error!Table {
        const h = try c.store.lock(bucket);
        defer h.release();
        const t = try c.getTable(arena, bucket, levels, name) orelse return error.NotFound;
        if (want) |w| if (!std.mem.eql(u8, w, &t.tag)) return error.PreconditionFailed;
        try c.store.remove(bucket, try tableKey(arena, levels, name));
        return t;
    }

    pub fn renameTable(c: Catalog, arena: Allocator, bucket: []const u8, from_levels: []const []const u8, from: []const u8, to_levels: []const []const u8, to: []const u8, want: ?[]const u8) Error!void {
        if (!validLevels(to_levels) or !validName(to)) return error.InvalidName;
        const h = try c.store.lock(bucket);
        defer h.release();
        var t = try c.getTable(arena, bucket, from_levels, from) orelse return error.NotFound;
        if (want) |w| if (!std.mem.eql(u8, w, &t.tag)) return error.PreconditionFailed;
        _ = try c.getNamespace(arena, bucket, to_levels) orelse return error.NotFound;
        t.levels = to_levels;
        t.name = to;
        t.modified_ms = nowMs();
        _ = try c.store.write(bucket, try tableKey(arena, to_levels, to), try tableDoc(arena, t), .create);
        try c.store.remove(bucket, try tableKey(arena, from_levels, from));
    }

    pub const TablePage = struct { items: []const Table, next: ?[]const u8 };

    /// Tables of one namespace (or all when `levels` is null) whose name starts with `name_prefix`.
    pub fn listTables(c: Catalog, arena: Allocator, bucket: []const u8, levels: ?[]const []const u8, name_prefix: []const u8, after: []const u8, max: usize) Error!TablePage {
        var w: std.Io.Writer.Allocating = .init(arena);
        if (levels) |l| {
            w.writer.writeAll(try tablePrefix(arena, l)) catch return error.OutOfMemory;
            store_mod.encodeName(&w.writer, name_prefix) catch return error.OutOfMemory;
        } else w.writer.writeAll(tbl_prefix) catch return error.OutOfMemory;
        const prefix = w.written();
        var out: std.ArrayList(Table) = .empty;
        var cursor = if (after.len > 0 and std.mem.startsWith(u8, after, prefix)) after else "";
        var pages: usize = 0;
        while (pages < max_scan_pages) : (pages += 1) {
            const page = try c.store.list(arena, bucket, prefix, cursor, @min(max, max_page));
            for (page.keys) |k| {
                cursor = k;
                const rest = k[tbl_prefix.len..];
                const slash = std.mem.indexOfScalar(u8, rest, '/') orelse continue;
                const lv = try splitLevels(arena, rest[0..slash]);
                const name = store_mod.decodeName(arena, rest[slash + 1 ..]) catch continue;
                if (levels == null and !std.mem.startsWith(u8, name, name_prefix)) continue;
                const t = try c.getTable(arena, bucket, lv, name) orelse continue;
                try out.append(arena, t);
                if (out.items.len == max) return .{ .items = out.items, .next = if (page.truncated or !std.mem.eql(u8, k, page.keys[page.keys.len - 1])) k else null };
            }
            if (!page.truncated) return .{ .items = out.items, .next = null };
        }
        return .{ .items = out.items, .next = if (cursor.len > 0) cursor else null };
    }

    pub fn hasTables(c: Catalog, arena: Allocator, bucket: []const u8) Error!bool {
        return (try c.store.list(arena, bucket, tbl_prefix, "", 1)).keys.len > 0;
    }
};

/// `s3://bucket/key` (also s3a/s3n) split into bucket and key.
pub const Location = struct { bucket: []const u8, key: []const u8 };

pub fn parseLocation(loc: []const u8) ?Location {
    const rest = for ([_][]const u8{ "s3://", "s3a://", "s3n://" }) |p| {
        if (std.mem.startsWith(u8, loc, p)) break loc[p.len..];
    } else return null;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return .{ .bucket = rest, .key = "" };
    return .{ .bucket = rest[0..slash], .key = rest[slash + 1 ..] };
}

test "locations" {
    const l = parseLocation("s3://b/x/y").?;
    try std.testing.expectEqualStrings("b", l.bucket);
    try std.testing.expectEqualStrings("x/y", l.key);
    try std.testing.expect(parseLocation("file:///x") == null);
    try std.testing.expectEqualStrings("", parseLocation("s3a://b").?.key);
}

test "names and levels" {
    try std.testing.expect(validName("a"));
    try std.testing.expect(!validName(""));
    try std.testing.expect(!validName("a\x1fb"));
    var long: [256]u8 = @splat('a');
    try std.testing.expect(!validName(&long));
    try std.testing.expect(!validLevels(&.{}));
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const k = try nsKey(a.allocator(), &.{ "a", "b c" });
    const lv = try splitLevels(a.allocator(), k[ns_prefix.len..]);
    try std.testing.expectEqual(@as(usize, 2), lv.len);
    try std.testing.expectEqualStrings("b c", lv[1]);
}
