//! Decoder for the source per-object metadata file (`xl.meta`, container "XL2 "
//! v1.0-1.3): versions, erasure geometry, parts, system/user metadata, inline data.
//! All lengths are bounded by the input; strings borrow from the input bytes.
const std = @import("std");
const msgpack = @import("msgpack.zig");

pub const Error = msgpack.Error || error{ BadMagic, UnsupportedVersion, BadChecksum, BadField, TooMany, OutOfMemory };

pub const max_versions = 10_000;
pub const max_parts = 10_000;
pub const max_meta_entries = 1024;

pub const Kind = enum { object, delete_marker };

pub const KV = struct { name: []const u8, value: []const u8 };

pub const Part = struct { number: u32, size: u64, actual_size: i64 };

pub const Version = struct {
    kind: Kind,
    /// All zeros is the null version.
    id: [16]u8 = @splat(0),
    mod_time_ns: i128 = 0,
    data_dir: [16]u8 = @splat(0),
    ec_m: u8 = 0,
    ec_n: u8 = 0,
    ec_block_size: u64 = 0,
    ec_index: u8 = 0,
    ec_dist: []const u8 = "",
    checksum_algo: u8 = 0,
    parts: []Part = &.{},
    size: i64 = 0,
    meta_sys: []KV = &.{},
    meta_usr: []KV = &.{},

    pub fn isNull(v: Version) bool {
        return std.mem.allEqual(u8, &v.id, 0);
    }

    pub fn usr(v: Version, name: []const u8) ?[]const u8 {
        for (v.meta_usr) |kv| if (std.ascii.eqlIgnoreCase(kv.name, name)) return kv.value;
        return null;
    }

    pub fn sys(v: Version, name: []const u8) ?[]const u8 {
        for (v.meta_sys) |kv| if (std.ascii.eqlIgnoreCase(kv.name, name)) return kv.value;
        return null;
    }

    pub fn isInline(v: Version) bool {
        const s = v.sys("x-minio-internal-inline-data") orelse return false;
        return std.mem.eql(u8, s, "true");
    }

    /// Version id as the source spells it: a dashed UUID, or "null".
    pub fn idText(v: Version, buf: *[36]u8) []const u8 {
        if (v.isNull()) return "null";
        return formatUuid(v.id, buf);
    }
};

pub const File = struct {
    versions: []Version,
    /// Raw inline-data block (after the checksum), possibly empty.
    inline_data: []const u8 = "",

    /// This drive's inline shard stream for one version, if stored inline.
    pub fn inlineFor(f: File, v: Version) Error!?[]const u8 {
        if (f.inline_data.len == 0) return null;
        if (f.inline_data[0] != 1) return error.UnsupportedVersion;
        var buf: [36]u8 = undefined;
        const want = v.idText(&buf);
        var r: msgpack.Reader = .{ .buf = f.inline_data[1..] };
        const n = try r.mapLen();
        for (0..n) |_| {
            const k = try r.str();
            const d = try r.bin();
            if (std.mem.eql(u8, k, want)) return d;
        }
        return null;
    }
};

pub fn formatUuid(id: [16]u8, buf: *[36]u8) []const u8 {
    const hex = std.fmt.bytesToHex(id, .lower);
    @memcpy(buf[0..8], hex[0..8]);
    buf[8] = '-';
    @memcpy(buf[9..13], hex[8..12]);
    buf[13] = '-';
    @memcpy(buf[14..18], hex[12..16]);
    buf[18] = '-';
    @memcpy(buf[19..23], hex[16..20]);
    buf[23] = '-';
    @memcpy(buf[24..36], hex[20..32]);
    return buf;
}

pub fn parseUuid(s: []const u8) ?[16]u8 {
    var hex: [32]u8 = undefined;
    var n: usize = 0;
    for (s) |c| {
        if (c == '-') continue;
        if (n == 32) return null;
        hex[n] = c;
        n += 1;
    }
    if (n != 32) return null;
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &hex) catch return null;
    return out;
}

pub fn parse(arena: std.mem.Allocator, bytes: []const u8) Error!File {
    if (bytes.len < 8 or !std.mem.eql(u8, bytes[0..4], "XL2 ")) return error.BadMagic;
    const major = std.mem.readInt(u16, bytes[4..6], .little);
    const minor = std.mem.readInt(u16, bytes[6..8], .little);
    if (major != 1 or minor > 3) return error.UnsupportedVersion;
    var r: msgpack.Reader = .{ .buf = bytes[8..] };
    if (minor == 0) {
        return .{ .versions = try legacyVersions(arena, &r) };
    }
    const body = try r.bin();
    const crc_val = try r.uint();
    if (crc_val > std.math.maxInt(u32)) return error.BadChecksum;
    const want: u32 = @truncate(std.hash.XxHash64.hash(0, body));
    if (want != crc_val) return error.BadChecksum;
    const rest = bytes[8 + r.pos ..];
    var br: msgpack.Reader = .{ .buf = body };
    const versions = if (minor < 3) try legacyVersions(arena, &br) else try indexedVersions(arena, &br);
    return .{ .versions = versions, .inline_data = if (minor >= 2) rest else "" };
}

/// v1.3: header version, meta version, count, then (header bin, meta bin) pairs.
fn indexedVersions(arena: std.mem.Allocator, r: *msgpack.Reader) Error![]Version {
    const header_ver = try r.uint();
    const meta_ver = try r.uint();
    if (header_ver > 3 or meta_ver > 3) return error.UnsupportedVersion;
    const n = try r.int();
    if (n < 0 or n > max_versions) return error.TooMany;
    const out = try arena.alloc(Version, @intCast(n));
    var kept: usize = 0;
    for (0..@intCast(n)) |_| {
        _ = try r.bin();
        var mr: msgpack.Reader = .{ .buf = try r.bin() };
        if (try versionMap(arena, &mr)) |v| {
            out[kept] = v;
            kept += 1;
        }
    }
    return out[0..kept];
}

/// v1.0-1.2: a map whose "Versions" entry is an array of version maps.
fn legacyVersions(arena: std.mem.Allocator, r: *msgpack.Reader) Error![]Version {
    const fields = try r.mapLen();
    var out: std.ArrayList(Version) = .empty;
    for (0..fields) |_| {
        const k = try r.str();
        if (!std.mem.eql(u8, k, "Versions")) {
            try r.skip();
            continue;
        }
        if (try r.nil()) continue;
        const n = try r.arrayLen();
        if (n > max_versions) return error.TooMany;
        for (0..n) |_| if (try versionMap(arena, r)) |v| try out.append(arena, v);
    }
    return out.items;
}

/// One version map; null for kinds the migrator does not read (legacy v1 objects).
fn versionMap(arena: std.mem.Allocator, r: *msgpack.Reader) Error!?Version {
    const fields = try r.mapLen();
    var typ: i64 = 0;
    var got: ?Version = null;
    for (0..fields) |_| {
        const k = try r.str();
        if (std.mem.eql(u8, k, "Type")) {
            typ = try r.int();
        } else if (std.mem.eql(u8, k, "V2Obj")) {
            if (try r.nil()) continue;
            got = try objectMap(arena, r);
        } else if (std.mem.eql(u8, k, "DelObj")) {
            if (try r.nil()) continue;
            got = try deleteMap(arena, r);
        } else try r.skip();
    }
    const v = got orelse return null;
    switch (typ) {
        1 => if (v.kind != .object) return error.BadField,
        2 => if (v.kind != .delete_marker) return error.BadField,
        else => return null,
    }
    return v;
}

fn uuidField(r: *msgpack.Reader) Error![16]u8 {
    if (try r.nil()) return @splat(0);
    const b = try r.bytes();
    if (b.len != 16) return error.BadField;
    return b[0..16].*;
}

fn smallUint(r: *msgpack.Reader, max: u64) Error!u64 {
    const v = try r.uint();
    if (v > max) return error.BadField;
    return v;
}

fn objectMap(arena: std.mem.Allocator, r: *msgpack.Reader) Error!Version {
    var v: Version = .{ .kind = .object };
    var nums: []u32 = &.{};
    var sizes: []u64 = &.{};
    var asizes: []i64 = &.{};
    const fields = try r.mapLen();
    for (0..fields) |_| {
        const k = try r.str();
        if (std.mem.eql(u8, k, "ID")) {
            v.id = try uuidField(r);
        } else if (std.mem.eql(u8, k, "DDir")) {
            v.data_dir = try uuidField(r);
        } else if (std.mem.eql(u8, k, "EcM")) {
            v.ec_m = @intCast(try smallUint(r, 16));
        } else if (std.mem.eql(u8, k, "EcN")) {
            v.ec_n = @intCast(try smallUint(r, 16));
        } else if (std.mem.eql(u8, k, "EcBSize")) {
            v.ec_block_size = try smallUint(r, 64 << 20);
        } else if (std.mem.eql(u8, k, "EcIndex")) {
            v.ec_index = @intCast(try smallUint(r, 32));
        } else if (std.mem.eql(u8, k, "EcDist")) {
            if (try r.nil()) continue;
            const n = try r.arrayLen();
            if (n > 32) return error.BadField;
            const d = try arena.alloc(u8, n);
            for (d) |*x| x.* = @intCast(try smallUint(r, 32));
            v.ec_dist = d;
        } else if (std.mem.eql(u8, k, "CSumAlgo")) {
            v.checksum_algo = @intCast(try smallUint(r, 255));
        } else if (std.mem.eql(u8, k, "PartNums")) {
            if (try r.nil()) continue;
            const n = try r.arrayLen();
            if (n > max_parts) return error.TooMany;
            nums = try arena.alloc(u32, n);
            for (nums) |*x| x.* = @intCast(try smallUint(r, 100_000));
        } else if (std.mem.eql(u8, k, "PartSizes")) {
            if (try r.nil()) continue;
            const n = try r.arrayLen();
            if (n > max_parts) return error.TooMany;
            sizes = try arena.alloc(u64, n);
            for (sizes) |*x| x.* = try smallUint(r, 1 << 50);
        } else if (std.mem.eql(u8, k, "PartASizes")) {
            if (try r.nil()) continue;
            const n = try r.arrayLen();
            if (n > max_parts) return error.TooMany;
            asizes = try arena.alloc(i64, n);
            for (asizes) |*x| x.* = try r.int();
        } else if (std.mem.eql(u8, k, "Size")) {
            v.size = try r.int();
        } else if (std.mem.eql(u8, k, "MTime")) {
            v.mod_time_ns = try r.int();
        } else if (std.mem.eql(u8, k, "MetaSys")) {
            v.meta_sys = try kvMap(arena, r);
        } else if (std.mem.eql(u8, k, "MetaUsr")) {
            v.meta_usr = try kvMap(arena, r);
        } else try r.skip();
    }
    if (nums.len != sizes.len) return error.BadField;
    const parts = try arena.alloc(Part, nums.len);
    for (parts, nums, sizes, 0..) |*p, n, s, i| p.* = .{ .number = n, .size = s, .actual_size = if (i < asizes.len) asizes[i] else @intCast(s) };
    v.parts = parts;
    if (v.size < 0) return error.BadField;
    return v;
}

fn deleteMap(arena: std.mem.Allocator, r: *msgpack.Reader) Error!Version {
    var v: Version = .{ .kind = .delete_marker };
    const fields = try r.mapLen();
    for (0..fields) |_| {
        const k = try r.str();
        if (std.mem.eql(u8, k, "ID")) {
            v.id = try uuidField(r);
        } else if (std.mem.eql(u8, k, "MTime")) {
            v.mod_time_ns = try r.int();
        } else if (std.mem.eql(u8, k, "MetaSys")) {
            v.meta_sys = try kvMap(arena, r);
        } else try r.skip();
    }
    return v;
}

fn kvMap(arena: std.mem.Allocator, r: *msgpack.Reader) Error![]KV {
    if (try r.nil()) return &.{};
    const n = try r.mapLen();
    if (n > max_meta_entries) return error.TooMany;
    const out = try arena.alloc(KV, n);
    for (out) |*kv| kv.* = .{ .name = try r.str(), .value = try r.bytes() };
    return out;
}

// ---- tests ----

const testing = std.testing;

/// Tiny msgpack writer for building fixtures.
const W = struct {
    list: std.ArrayList(u8) = .empty,
    a: std.mem.Allocator,
    fn raw(w: *W, b: []const u8) void {
        w.list.appendSlice(w.a, b) catch unreachable;
    }
    fn str(w: *W, s: []const u8) void {
        w.raw(&.{ 0xd9, @intCast(s.len) });
        w.raw(s);
    }
    fn bin(w: *W, s: []const u8) void {
        w.raw(&.{ 0xc6, 0, 0, 0, 0 });
        std.mem.writeInt(u32, w.list.items[w.list.items.len - 4 ..][0..4], @intCast(s.len), .big);
        w.raw(s);
    }
    fn int(w: *W, v: i64) void {
        w.raw(&.{0xd3});
        var b: [8]u8 = undefined;
        std.mem.writeInt(i64, &b, v, .big);
        w.raw(&b);
    }
    fn map(w: *W, n: u8) void {
        w.raw(&.{0x80 | n});
    }
    fn arr(w: *W, n: u8) void {
        w.raw(&.{0x90 | n});
    }
};

fn fixture(a: std.mem.Allocator) ![]u8 {
    var meta: W = .{ .a = a };
    meta.map(2);
    meta.str("Type");
    meta.int(1);
    meta.str("V2Obj");
    meta.map(9);
    meta.str("ID");
    meta.bin(&([_]u8{0xab} ** 16));
    meta.str("EcM");
    meta.int(2);
    meta.str("EcN");
    meta.int(2);
    meta.str("EcBSize");
    meta.int(1 << 20);
    meta.str("EcIndex");
    meta.int(3);
    meta.str("PartNums");
    meta.arr(1);
    meta.int(1);
    meta.str("PartSizes");
    meta.arr(1);
    meta.int(5);
    meta.str("Size");
    meta.int(5);
    meta.str("MetaUsr");
    meta.map(1);
    meta.str("etag");
    meta.str("abc");
    var body: W = .{ .a = a };
    body.raw(&.{ 3, 3, 1 });
    body.bin("hdr");
    body.bin(meta.list.items);
    var file: W = .{ .a = a };
    file.raw("XL2 \x01\x00\x03\x00");
    file.bin(body.list.items);
    const crc: u32 = @truncate(std.hash.XxHash64.hash(0, body.list.items));
    file.raw(&.{0xce});
    var cb: [4]u8 = undefined;
    std.mem.writeInt(u32, &cb, crc, .big);
    file.raw(&cb);
    return file.list.items;
}

test "parses a v1.3 file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try parse(a, try fixture(a));
    try testing.expectEqual(@as(usize, 1), f.versions.len);
    const v = f.versions[0];
    try testing.expectEqual(Kind.object, v.kind);
    try testing.expectEqual(@as(u8, 3), v.ec_index);
    try testing.expectEqual(@as(u64, 5), v.parts[0].size);
    try testing.expectEqualStrings("abc", v.usr("ETag").?);
    var buf: [36]u8 = undefined;
    try testing.expectEqualStrings("abababab-abab-abab-abab-abababababab", v.idText(&buf));
}

test "hostile files error without crashing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const good = try fixture(a);
    try testing.expectError(error.BadMagic, parse(a, "XL1 \x01\x00\x03\x00"));
    try testing.expectError(error.UnsupportedVersion, parse(a, "XL2 \x02\x00\x03\x00"));
    // Every truncation and every single-byte corruption must fail cleanly or parse.
    for (0..good.len) |n| _ = parse(a, good[0..n]) catch {};
    var prng = std.Random.DefaultPrng.init(7);
    const copy = try a.dupe(u8, good);
    for (0..5000) |_| {
        @memcpy(copy, good);
        const i = prng.random().uintLessThan(usize, copy.len);
        copy[i] = prng.random().int(u8);
        _ = parse(a, copy) catch {};
    }
    // Corrupt payload with a matching length is caught by the checksum.
    @memcpy(copy, good);
    copy[copy.len - 10] ^= 0xff;
    try testing.expectError(error.BadChecksum, parse(a, copy));
}

test "uuid round trip" {
    const id = parseUuid("6053e2b9-7941-4a38-b48f-d5262f2d75e8").?;
    var buf: [36]u8 = undefined;
    try testing.expectEqualStrings("6053e2b9-7941-4a38-b48f-d5262f2d75e8", formatUuid(id, &buf));
    try testing.expect(parseUuid("zz") == null);
}
