//! Static large object manifests: the client's PUT form, the stored form, and the
//! Swift SLO ETag (MD5 over segment ETags, with ":range;" for ranged segments).
const std = @import("std");
const core = @import("../core/root.zig");
const util = @import("swift_util.zig");

pub const max_segments = 1000;
pub const max_manifest_bytes = 2 * 1024 * 1024;

pub const Error = error{ BadManifest, TooManySegments, ManifestTooLarge, OutOfMemory };

/// One segment as given on PUT (`path` is "/container/object").
pub const PutSegment = struct {
    container: []const u8,
    object: []const u8,
    etag: ?[]const u8 = null,
    size: ?u64 = null,
    range: ?[]const u8 = null,
};

/// One segment as stored and returned by multipart-manifest=get.
pub const Stored = struct {
    container: []const u8,
    object: []const u8,
    hash: []const u8,
    /// Bytes this segment contributes (after `range`).
    bytes: u64,
    content_type: []const u8 = "application/octet-stream",
    mtime_ns: i128 = 0,
    range: ?[]const u8 = null,
};

fn splitPath(p_in: []const u8) Error!struct { []const u8, []const u8 } {
    const p = if (p_in.len > 0 and p_in[0] == '/') p_in[1..] else p_in;
    const slash = std.mem.indexOfScalar(u8, p, '/') orelse return error.BadManifest;
    if (slash == 0 or slash + 1 >= p.len) return error.BadManifest;
    return .{ p[0..slash], p[slash + 1 ..] };
}

fn str(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn uint(v: std.json.Value) ?u64 {
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else null,
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

/// Parses and shape-checks a manifest PUT body; segment existence is checked later.
pub fn parsePut(arena: std.mem.Allocator, body: []const u8) Error![]PutSegment {
    if (body.len > max_manifest_bytes) return error.ManifestTooLarge;
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadManifest,
    };
    const arr = switch (root) {
        .array => |a| a.items,
        else => return error.BadManifest,
    };
    if (arr.len == 0) return error.BadManifest;
    if (arr.len > max_segments) return error.TooManySegments;
    const out = try arena.alloc(PutSegment, arr.len);
    for (arr, out) |item, *seg| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.BadManifest,
        };
        var it = obj.iterator();
        var path: ?[]const u8 = null;
        seg.* = .{ .container = "", .object = "" };
        while (it.next()) |kv| {
            const k = kv.key_ptr.*;
            const v = kv.value_ptr.*;
            if (std.mem.eql(u8, k, "path")) {
                path = str(v) orelse return error.BadManifest;
            } else if (std.mem.eql(u8, k, "etag")) {
                if (v != .null) seg.etag = str(v) orelse return error.BadManifest;
            } else if (std.mem.eql(u8, k, "size_bytes")) {
                if (v != .null) seg.size = uint(v) orelse return error.BadManifest;
            } else if (std.mem.eql(u8, k, "range")) {
                if (v != .null) seg.range = str(v) orelse return error.BadManifest;
            } else return error.BadManifest;
        }
        const parts = try splitPath(path orelse return error.BadManifest);
        seg.container = parts[0];
        seg.object = parts[1];
        if (seg.etag) |e| if (util.parseMd5Hex(e) == null) return error.BadManifest;
        if (seg.range) |r| _ = core.RangeSpec.parse(try rangeHeader(arena, r)) catch return error.BadManifest;
    }
    return out;
}

fn rangeHeader(arena: std.mem.Allocator, r: []const u8) Error![]const u8 {
    return std.fmt.allocPrint(arena, "bytes={s}", .{r});
}

/// Resolves a segment range against the segment's size.
pub fn resolveRange(arena: std.mem.Allocator, r: ?[]const u8, size: u64) Error!core.Range {
    const spec = r orelse return .{ .offset = 0, .length = size };
    const rs = core.RangeSpec.parse(try rangeHeader(arena, spec)) catch return error.BadManifest;
    return rs.resolve(size) catch error.BadManifest;
}

/// MD5 hex of the concatenated segment hashes, ranged ones suffixed ":<range>;".
pub fn etag(segs: []const Stored) [32]u8 {
    var h = std.crypto.hash.Md5.init(.{});
    for (segs) |s| {
        h.update(s.hash);
        if (s.range) |r| {
            h.update(":");
            h.update(r);
            h.update(";");
        }
    }
    var d: [16]u8 = undefined;
    h.final(&d);
    return std.fmt.bytesToHex(d, .lower);
}

pub fn totalBytes(segs: []const Stored) u64 {
    var n: u64 = 0;
    for (segs) |s| n +|= s.bytes;
    return n;
}

/// Stored JSON: [{"name":"/c/o","hash":..,"bytes":..,"content_type":..,"last_modified":..}].
pub fn renderStored(w: *std.Io.Writer, segs: []const Stored) std.Io.Writer.Error!void {
    try w.writeByte('[');
    for (segs, 0..) |s, i| {
        var lb: [26]u8 = undefined;
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("{\"name\": ");
        try writePath(w, s);
        try w.writeAll(", \"hash\": ");
        try util.jsonString(w, s.hash);
        try w.print(", \"bytes\": {d}, \"content_type\": ", .{s.bytes});
        try util.jsonString(w, s.content_type);
        try w.print(", \"last_modified\": \"{s}\"", .{util.isoListing(&lb, s.mtime_ns)});
        if (s.range) |r| {
            try w.writeAll(", \"range\": ");
            try util.jsonString(w, r);
        }
        try w.writeByte('}');
    }
    try w.writeByte(']');
}

/// The PUT form of a stored manifest (multipart-manifest=get&format=raw).
pub fn renderRaw(w: *std.Io.Writer, segs: []const Stored) std.Io.Writer.Error!void {
    try w.writeByte('[');
    for (segs, 0..) |s, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("{\"path\": ");
        try writePath(w, s);
        try w.writeAll(", \"etag\": ");
        try util.jsonString(w, s.hash);
        try w.print(", \"size_bytes\": {d}", .{s.bytes});
        if (s.range) |r| {
            try w.writeAll(", \"range\": ");
            try util.jsonString(w, r);
        }
        try w.writeByte('}');
    }
    try w.writeByte(']');
}

fn writePath(w: *std.Io.Writer, s: Stored) std.Io.Writer.Error!void {
    var buf: [2200]u8 = undefined;
    const p = std.fmt.bufPrint(&buf, "/{s}/{s}", .{ s.container, s.object }) catch return error.WriteFailed;
    try util.jsonString(w, p);
}

/// Parses the stored form back (bounded by `max_manifest_bytes`).
pub fn parseStored(arena: std.mem.Allocator, body: []const u8) Error![]Stored {
    if (body.len > max_manifest_bytes) return error.ManifestTooLarge;
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadManifest,
    };
    const arr = switch (root) {
        .array => |a| a.items,
        else => return error.BadManifest,
    };
    if (arr.len > max_segments) return error.TooManySegments;
    const out = try arena.alloc(Stored, arr.len);
    for (arr, out) |item, *s| {
        const o = switch (item) {
            .object => |x| x,
            else => return error.BadManifest,
        };
        const parts = try splitPath(str(o.get("name") orelse return error.BadManifest) orelse return error.BadManifest);
        s.* = .{
            .container = parts[0],
            .object = parts[1],
            .hash = str(o.get("hash") orelse return error.BadManifest) orelse return error.BadManifest,
            .bytes = uint(o.get("bytes") orelse return error.BadManifest) orelse return error.BadManifest,
        };
        if (o.get("content_type")) |v| s.content_type = str(v) orelse s.content_type;
        if (o.get("range")) |v| s.range = str(v);
        if (o.get("last_modified")) |v| if (str(v)) |lm| {
            if (util.parseIso8601(lm)) |secs| s.mtime_ns = @as(i128, secs) * std.time.ns_per_s;
        };
    }
    return out;
}

test "parse put manifest" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const segs = try parsePut(a,
        \\[{"path": "/segs/a", "etag": "d41d8cd98f00b204e9800998ecf8427e", "size_bytes": 5},
        \\ {"path": "/segs/b/c", "etag": null, "size_bytes": null, "range": "1-3"}]
    );
    try std.testing.expectEqual(@as(usize, 2), segs.len);
    try std.testing.expectEqualStrings("segs", segs[0].container);
    try std.testing.expectEqualStrings("a", segs[0].object);
    try std.testing.expectEqual(@as(?u64, 5), segs[0].size);
    try std.testing.expectEqualStrings("b/c", segs[1].object);
    try std.testing.expectEqualStrings("1-3", segs[1].range.?);
    try std.testing.expectError(error.BadManifest, parsePut(a, "[]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "{}"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "[{\"path\":\"nocontainer\"}]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "[{\"path\":\"/c/o\",\"bogus\":1}]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "[{\"path\":\"/c/o\",\"etag\":\"xyz\"}]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "[{\"path\":\"/c/o\",\"range\":\"5-1\"}]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "[{\"path\":\"/c/o\",\"size_bytes\":-1}]"));
    try std.testing.expectError(error.BadManifest, parsePut(a, "not json"));
    var big: std.ArrayList(u8) = .empty;
    try big.append(a, '[');
    for (0..max_segments + 1) |i| try big.appendSlice(a, if (i == 0) "{\"path\":\"/c/o\"}" else ",{\"path\":\"/c/o\"}");
    try big.append(a, ']');
    try std.testing.expectError(error.TooManySegments, parsePut(a, big.items));
    const r = try resolveRange(a, "1-3", 10);
    try std.testing.expectEqual(@as(u64, 1), r.offset);
    try std.testing.expectEqual(@as(u64, 3), r.length);
    try std.testing.expectError(error.BadManifest, resolveRange(a, "20-30", 10));
}

// Python: md5(b"aaaa..." + b"bbbb...").hexdigest(), and with ":1-3;" appended.
test "slo etag and stored round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h1 = "0cc175b9c0f1b6a831c399e269772661";
    const h2 = "92eb5ffee6ae2fec3ad71c777531578f";
    var segs = [_]Stored{
        .{ .container = "c", .object = "a", .hash = h1, .bytes = 1 },
        .{ .container = "c", .object = "b/x", .hash = h2, .bytes = 3, .range = "1-3" },
    };
    try std.testing.expectEqualStrings("6c2216e3ef5ac6ad40729828950d12df", &etag(&segs));
    segs[1].range = null;
    try std.testing.expectEqualStrings("3bc22fb7aaebe9c8c5d7de312b876bb8", &etag(&segs));
    segs[1].range = "1-3";
    var buf: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try renderStored(&w, &segs);
    const back = try parseStored(a, w.buffered());
    try std.testing.expectEqual(@as(usize, 2), back.len);
    try std.testing.expectEqualStrings("b/x", back[1].object);
    try std.testing.expectEqualStrings("1-3", back[1].range.?);
    try std.testing.expectEqual(@as(u64, 4), totalBytes(back));
    w = .fixed(&buf);
    try renderRaw(&w, &segs);
    const raw = try parsePut(a, w.buffered());
    try std.testing.expectEqualStrings(h2, raw[1].etag.?);
}
