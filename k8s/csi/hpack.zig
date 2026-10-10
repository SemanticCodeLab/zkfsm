//! HPACK (RFC 7541): decoder with static/dynamic tables and Huffman, plus a
//! minimal encoder that emits literals without indexing.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Error = error{ HpackInvalid, OutOfMemory };

const static_table = [_]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

/// RFC 7541 Appendix B: (code, bit length) for symbols 0..256 (256 = EOS).
pub const huffman_table = [257][2]u32{
    .{ 0x1ff8, 13 },     .{ 0x7fffd8, 23 },   .{ 0xfffffe2, 28 },  .{ 0xfffffe3, 28 },
    .{ 0xfffffe4, 28 },  .{ 0xfffffe5, 28 },  .{ 0xfffffe6, 28 },  .{ 0xfffffe7, 28 },
    .{ 0xfffffe8, 28 },  .{ 0xffffea, 24 },   .{ 0x3ffffffc, 30 }, .{ 0xfffffe9, 28 },
    .{ 0xfffffea, 28 },  .{ 0x3ffffffd, 30 }, .{ 0xfffffeb, 28 },  .{ 0xfffffec, 28 },
    .{ 0xfffffed, 28 },  .{ 0xfffffee, 28 },  .{ 0xfffffef, 28 },  .{ 0xffffff0, 28 },
    .{ 0xffffff1, 28 },  .{ 0xffffff2, 28 },  .{ 0x3ffffffe, 30 }, .{ 0xffffff3, 28 },
    .{ 0xffffff4, 28 },  .{ 0xffffff5, 28 },  .{ 0xffffff6, 28 },  .{ 0xffffff7, 28 },
    .{ 0xffffff8, 28 },  .{ 0xffffff9, 28 },  .{ 0xffffffa, 28 },  .{ 0xffffffb, 28 },
    .{ 0x14, 6 },        .{ 0x3f8, 10 },      .{ 0x3f9, 10 },      .{ 0xffa, 12 },
    .{ 0x1ff9, 13 },     .{ 0x15, 6 },        .{ 0xf8, 8 },        .{ 0x7fa, 11 },
    .{ 0x3fa, 10 },      .{ 0x3fb, 10 },      .{ 0xf9, 8 },        .{ 0x7fb, 11 },
    .{ 0xfa, 8 },        .{ 0x16, 6 },        .{ 0x17, 6 },        .{ 0x18, 6 },
    .{ 0x0, 5 },         .{ 0x1, 5 },         .{ 0x2, 5 },         .{ 0x19, 6 },
    .{ 0x1a, 6 },        .{ 0x1b, 6 },        .{ 0x1c, 6 },        .{ 0x1d, 6 },
    .{ 0x1e, 6 },        .{ 0x1f, 6 },        .{ 0x5c, 7 },        .{ 0xfb, 8 },
    .{ 0x7ffc, 15 },     .{ 0x20, 6 },        .{ 0xffb, 12 },      .{ 0x3fc, 10 },
    .{ 0x1ffa, 13 },     .{ 0x21, 6 },        .{ 0x5d, 7 },        .{ 0x5e, 7 },
    .{ 0x5f, 7 },        .{ 0x60, 7 },        .{ 0x61, 7 },        .{ 0x62, 7 },
    .{ 0x63, 7 },        .{ 0x64, 7 },        .{ 0x65, 7 },        .{ 0x66, 7 },
    .{ 0x67, 7 },        .{ 0x68, 7 },        .{ 0x69, 7 },        .{ 0x6a, 7 },
    .{ 0x6b, 7 },        .{ 0x6c, 7 },        .{ 0x6d, 7 },        .{ 0x6e, 7 },
    .{ 0x6f, 7 },        .{ 0x70, 7 },        .{ 0x71, 7 },        .{ 0x72, 7 },
    .{ 0xfc, 8 },        .{ 0x73, 7 },        .{ 0xfd, 8 },        .{ 0x1ffb, 13 },
    .{ 0x7fff0, 19 },    .{ 0x1ffc, 13 },     .{ 0x3ffc, 14 },     .{ 0x22, 6 },
    .{ 0x7ffd, 15 },     .{ 0x3, 5 },         .{ 0x23, 6 },        .{ 0x4, 5 },
    .{ 0x24, 6 },        .{ 0x5, 5 },         .{ 0x25, 6 },        .{ 0x26, 6 },
    .{ 0x27, 6 },        .{ 0x6, 5 },         .{ 0x74, 7 },        .{ 0x75, 7 },
    .{ 0x28, 6 },        .{ 0x29, 6 },        .{ 0x2a, 6 },        .{ 0x7, 5 },
    .{ 0x2b, 6 },        .{ 0x76, 7 },        .{ 0x2c, 6 },        .{ 0x8, 5 },
    .{ 0x9, 5 },         .{ 0x2d, 6 },        .{ 0x77, 7 },        .{ 0x78, 7 },
    .{ 0x79, 7 },        .{ 0x7a, 7 },        .{ 0x7b, 7 },        .{ 0x7ffe, 15 },
    .{ 0x7fc, 11 },      .{ 0x3ffd, 14 },     .{ 0x1ffd, 13 },     .{ 0xffffffc, 28 },
    .{ 0xfffe6, 20 },    .{ 0x3fffd2, 22 },   .{ 0xfffe7, 20 },    .{ 0xfffe8, 20 },
    .{ 0x3fffd3, 22 },   .{ 0x3fffd4, 22 },   .{ 0x3fffd5, 22 },   .{ 0x7fffd9, 23 },
    .{ 0x3fffd6, 22 },   .{ 0x7fffda, 23 },   .{ 0x7fffdb, 23 },   .{ 0x7fffdc, 23 },
    .{ 0x7fffdd, 23 },   .{ 0x7fffde, 23 },   .{ 0xffffeb, 24 },   .{ 0x7fffdf, 23 },
    .{ 0xffffec, 24 },   .{ 0xffffed, 24 },   .{ 0x3fffd7, 22 },   .{ 0x7fffe0, 23 },
    .{ 0xffffee, 24 },   .{ 0x7fffe1, 23 },   .{ 0x7fffe2, 23 },   .{ 0x7fffe3, 23 },
    .{ 0x7fffe4, 23 },   .{ 0x1fffdc, 21 },   .{ 0x3fffd8, 22 },   .{ 0x7fffe5, 23 },
    .{ 0x3fffd9, 22 },   .{ 0x7fffe6, 23 },   .{ 0x7fffe7, 23 },   .{ 0xffffef, 24 },
    .{ 0x3fffda, 22 },   .{ 0x1fffdd, 21 },   .{ 0xfffe9, 20 },    .{ 0x3fffdb, 22 },
    .{ 0x3fffdc, 22 },   .{ 0x7fffe8, 23 },   .{ 0x7fffe9, 23 },   .{ 0x1fffde, 21 },
    .{ 0x7fffea, 23 },   .{ 0x3fffdd, 22 },   .{ 0x3fffde, 22 },   .{ 0xfffff0, 24 },
    .{ 0x1fffdf, 21 },   .{ 0x3fffdf, 22 },   .{ 0x7fffeb, 23 },   .{ 0x7fffec, 23 },
    .{ 0x1fffe0, 21 },   .{ 0x1fffe1, 21 },   .{ 0x3fffe0, 22 },   .{ 0x1fffe2, 21 },
    .{ 0x7fffed, 23 },   .{ 0x3fffe1, 22 },   .{ 0x7fffee, 23 },   .{ 0x7fffef, 23 },
    .{ 0xfffea, 20 },    .{ 0x3fffe2, 22 },   .{ 0x3fffe3, 22 },   .{ 0x3fffe4, 22 },
    .{ 0x7ffff0, 23 },   .{ 0x3fffe5, 22 },   .{ 0x3fffe6, 22 },   .{ 0x7ffff1, 23 },
    .{ 0x3ffffe0, 26 },  .{ 0x3ffffe1, 26 },  .{ 0xfffeb, 20 },    .{ 0x7fff1, 19 },
    .{ 0x3fffe7, 22 },   .{ 0x7ffff2, 23 },   .{ 0x3fffe8, 22 },   .{ 0x1ffffec, 25 },
    .{ 0x3ffffe2, 26 },  .{ 0x3ffffe3, 26 },  .{ 0x3ffffe4, 26 },  .{ 0x7ffffde, 27 },
    .{ 0x7ffffdf, 27 },  .{ 0x3ffffe5, 26 },  .{ 0xfffff1, 24 },   .{ 0x1ffffed, 25 },
    .{ 0x7fff2, 19 },    .{ 0x1fffe3, 21 },   .{ 0x3ffffe6, 26 },  .{ 0x7ffffe0, 27 },
    .{ 0x7ffffe1, 27 },  .{ 0x3ffffe7, 26 },  .{ 0x7ffffe2, 27 },  .{ 0xfffff2, 24 },
    .{ 0x1fffe4, 21 },   .{ 0x1fffe5, 21 },   .{ 0x3ffffe8, 26 },  .{ 0x3ffffe9, 26 },
    .{ 0xffffffd, 28 },  .{ 0x7ffffe3, 27 },  .{ 0x7ffffe4, 27 },  .{ 0x7ffffe5, 27 },
    .{ 0xfffec, 20 },    .{ 0xfffff3, 24 },   .{ 0xfffed, 20 },    .{ 0x1fffe6, 21 },
    .{ 0x3fffe9, 22 },   .{ 0x1fffe7, 21 },   .{ 0x1fffe8, 21 },   .{ 0x7ffff3, 23 },
    .{ 0x3fffea, 22 },   .{ 0x3fffeb, 22 },   .{ 0x1ffffee, 25 },  .{ 0x1ffffef, 25 },
    .{ 0xfffff4, 24 },   .{ 0xfffff5, 24 },   .{ 0x3ffffea, 26 },  .{ 0x7ffff4, 23 },
    .{ 0x3ffffeb, 26 },  .{ 0x7ffffe6, 27 },  .{ 0x3ffffec, 26 },  .{ 0x3ffffed, 26 },
    .{ 0x7ffffe7, 27 },  .{ 0x7ffffe8, 27 },  .{ 0x7ffffe9, 27 },  .{ 0x7ffffea, 27 },
    .{ 0x7ffffeb, 27 },  .{ 0xffffffe, 28 },  .{ 0x7ffffec, 27 },  .{ 0x7ffffed, 27 },
    .{ 0x7ffffee, 27 },  .{ 0x7ffffef, 27 },  .{ 0x7fffff0, 27 },  .{ 0x3ffffee, 26 },
    .{ 0x3fffffff, 30 },
};

/// Canonical decode tables: codes of one length are consecutive (verified in tests).
const Canon = struct {
    first: [31]u32,
    count: [31]u16,
    offset: [31]u16,
    syms: [257]u16,
};

const canon: Canon = blk: {
    @setEvalBranchQuota(400000);
    var c: Canon = .{ .first = @splat(0), .count = @splat(0), .offset = @splat(0), .syms = undefined };
    var n: usize = 0;
    for (1..31) |len| {
        c.offset[len] = n;
        const start = n;
        for (huffman_table, 0..) |e, sym| {
            if (e[1] != len) continue;
            // insertion sort by code within this length
            var i = n;
            while (i > start and huffman_table[c.syms[i - 1]][0] > e[0]) : (i -= 1) c.syms[i] = c.syms[i - 1];
            c.syms[i] = sym;
            n += 1;
        }
        c.count[len] = n - start;
        if (n > start) c.first[len] = huffman_table[c.syms[start]][0];
    }
    break :blk c;
};

pub fn huffmanDecode(gpa: Allocator, src: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var code: u32 = 0;
    var len: usize = 0;
    for (src) |byte| {
        var bit: u3 = 7;
        while (true) {
            code = (code << 1) | ((byte >> bit) & 1);
            len += 1;
            if (len > 30) return error.HpackInvalid;
            if (canon.count[len] > 0 and code >= canon.first[len] and code - canon.first[len] < canon.count[len]) {
                const sym = canon.syms[canon.offset[len] + code - canon.first[len]];
                if (sym == 256) return error.HpackInvalid;
                try out.append(gpa, @intCast(sym));
                code = 0;
                len = 0;
            }
            if (bit == 0) break;
            bit -= 1;
        }
    }
    // padding must be < 8 bits of the EOS prefix (all ones)
    if (len >= 8 or code != (@as(u32, 1) << @intCast(len)) - 1) return error.HpackInvalid;
    return out.toOwnedSlice(gpa);
}

pub fn huffmanEncode(gpa: Allocator, out: *std.ArrayList(u8), src: []const u8) !void {
    var acc: u64 = 0;
    var bits: u6 = 0;
    for (src) |b| {
        const e = huffman_table[b];
        acc = (acc << @intCast(e[1])) | e[0];
        bits += @intCast(e[1]);
        while (bits >= 8) {
            bits -= 8;
            try out.append(gpa, @truncate(acc >> bits));
        }
    }
    if (bits > 0) {
        const pad: u6 = 8 - bits;
        try out.append(gpa, @truncate((acc << pad) | ((@as(u64, 1) << pad) - 1)));
    }
}

fn readInt(buf: []const u8, pos: *usize, prefix: u4) Error!u64 {
    if (pos.* >= buf.len) return error.HpackInvalid;
    const max: u64 = (@as(u64, 1) << prefix) - 1;
    var v: u64 = buf[pos.*] & max;
    pos.* += 1;
    if (v < max) return v;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= buf.len or shift > 28) return error.HpackInvalid;
        const b = buf[pos.*];
        pos.* += 1;
        v += @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        shift += 7;
    }
}

pub fn writeInt(gpa: Allocator, out: *std.ArrayList(u8), flags: u8, prefix: u4, value: u64) !void {
    const max: u64 = (@as(u64, 1) << prefix) - 1;
    if (value < max) return out.append(gpa, flags | @as(u8, @intCast(value)));
    try out.append(gpa, flags | @as(u8, @intCast(max)));
    var v = value - max;
    while (v >= 128) : (v >>= 7) try out.append(gpa, @as(u8, @intCast(v & 0x7f)) | 0x80);
    try out.append(gpa, @intCast(v));
}

fn readString(arena: Allocator, buf: []const u8, pos: *usize) Error![]const u8 {
    if (pos.* >= buf.len) return error.HpackInvalid;
    const huff = buf[pos.*] & 0x80 != 0;
    const n = try readInt(buf, pos, 7);
    if (n > buf.len - pos.*) return error.HpackInvalid;
    const raw = buf[pos.*..][0..@intCast(n)];
    pos.* += @intCast(n);
    if (huff) return huffmanDecode(arena, raw);
    return arena.dupe(u8, raw);
}

pub const Decoder = struct {
    gpa: Allocator,
    /// index 0 is the newest entry; each buf holds name ++ value
    entries: std.ArrayList(Entry) = .empty,
    size: usize = 0,
    max_size: usize = 4096,
    limit: usize = 4096,

    const Entry = struct { buf: []u8, name_len: usize };

    pub fn init(gpa: Allocator) Decoder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Decoder) void {
        for (self.entries.items) |e| self.gpa.free(e.buf);
        self.entries.deinit(self.gpa);
    }

    fn evict(self: *Decoder, target: usize) void {
        while (self.size > target) {
            const e = self.entries.pop().?;
            self.size -= e.buf.len + 32;
            self.gpa.free(e.buf);
        }
    }

    fn add(self: *Decoder, name: []const u8, value: []const u8) !void {
        const sz = name.len + value.len + 32;
        if (sz > self.max_size) return self.evict(0);
        self.evict(self.max_size - sz);
        const buf = try self.gpa.alloc(u8, name.len + value.len);
        @memcpy(buf[0..name.len], name);
        @memcpy(buf[name.len..], value);
        try self.entries.insert(self.gpa, 0, .{ .buf = buf, .name_len = name.len });
        self.size += sz;
    }

    fn lookup(self: *Decoder, idx: u64) Error!Header {
        if (idx == 0) return error.HpackInvalid;
        if (idx <= static_table.len) return static_table[@intCast(idx - 1)];
        const d = idx - static_table.len - 1;
        if (d >= self.entries.items.len) return error.HpackInvalid;
        const e = self.entries.items[@intCast(d)];
        return .{ .name = e.buf[0..e.name_len], .value = e.buf[e.name_len..] };
    }

    /// Decodes one complete header block; strings are allocated in `arena`.
    pub fn decode(self: *Decoder, arena: Allocator, block: []const u8, out: *std.ArrayList(Header)) Error!void {
        var pos: usize = 0;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 0x80 != 0) {
                const h = try self.lookup(try readInt(block, &pos, 7));
                try out.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
            } else if (b & 0xe0 == 0x20) {
                const n = try readInt(block, &pos, 5);
                if (n > self.limit) return error.HpackInvalid;
                self.max_size = @intCast(n);
                self.evict(self.max_size);
            } else {
                const indexing = b & 0xc0 == 0x40;
                const idx = try readInt(block, &pos, if (indexing) 6 else 4);
                const name = if (idx == 0) try readString(arena, block, &pos) else try arena.dupe(u8, (try self.lookup(idx)).name);
                const value = try readString(arena, block, &pos);
                if (indexing) try self.add(name, value);
                try out.append(arena, .{ .name = name, .value = value });
            }
        }
    }
};

/// Literal header field without indexing, new name, no Huffman.
pub fn encodeLiteral(gpa: Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.append(gpa, 0x00);
    try writeInt(gpa, out, 0, 7, name.len);
    try out.appendSlice(gpa, name);
    try writeInt(gpa, out, 0, 7, value.len);
    try out.appendSlice(gpa, value);
}

const testing = std.testing;

fn unhex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectHeaders(got: []const Header, want: []const [2][]const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (got, want) |g, w| {
        try testing.expectEqualStrings(w[0], g.name);
        try testing.expectEqualStrings(w[1], g.value);
    }
}

fn runRfcRequests(blocks: [3][]const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Decoder.init(testing.allocator);
    defer d.deinit();

    var out: std.ArrayList(Header) = .empty;
    try d.decode(arena, blocks[0], &out);
    try expectHeaders(out.items, &.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" }, .{ ":authority", "www.example.com" } });
    try testing.expectEqual(@as(usize, 57), d.size);

    out = .empty;
    try d.decode(arena, blocks[1], &out);
    try expectHeaders(out.items, &.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" }, .{ ":authority", "www.example.com" }, .{ "cache-control", "no-cache" } });
    try testing.expectEqual(@as(usize, 110), d.size);

    out = .empty;
    try d.decode(arena, blocks[2], &out);
    try expectHeaders(out.items, &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/index.html" }, .{ ":authority", "www.example.com" }, .{ "custom-key", "custom-value" } });
    try testing.expectEqual(@as(usize, 164), d.size);
    try testing.expectEqualStrings("custom-key", (try d.lookup(62)).name);
    try testing.expectEqualStrings("cache-control", (try d.lookup(63)).name);
}

test "hpack RFC 7541 C.3 requests without Huffman" {
    try runRfcRequests(.{
        &unhex("828684410f7777772e6578616d706c652e636f6d"),
        &unhex("828684be58086e6f2d6361636865"),
        &unhex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"),
    });
}

test "hpack RFC 7541 C.4 requests with Huffman" {
    try runRfcRequests(.{
        &unhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
        &unhex("828684be5886a8eb10649cbf"),
        &unhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"),
    });
}

test "huffman table is canonical and complete" {
    // codes of each length are consecutive and the Kraft sum is exactly 1
    var kraft: u64 = 0;
    var prev_code: u64 = 0;
    var prev_len: u32 = 0;
    var first = true;
    for (1..31) |len| {
        const n = canon.count[len];
        for (0..n) |i| {
            const sym = canon.syms[canon.offset[len] + i];
            const code: u64 = huffman_table[sym][0];
            if (!first) try testing.expectEqual((prev_code + 1) << @intCast(len - prev_len), code);
            first = false;
            prev_code = code;
            prev_len = @intCast(len);
            kraft += @as(u64, 1) << @intCast(30 - len);
        }
    }
    try testing.expectEqual(@as(u64, 1) << 30, kraft);
}

test "huffman round trip all bytes" {
    var src: [256]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @intCast(i);
    var enc: std.ArrayList(u8) = .empty;
    defer enc.deinit(testing.allocator);
    try huffmanEncode(testing.allocator, &enc, &src);
    const dec = try huffmanDecode(testing.allocator, enc.items);
    defer testing.allocator.free(dec);
    try testing.expectEqualSlices(u8, &src, dec);
    try testing.expectError(error.HpackInvalid, huffmanDecode(testing.allocator, &.{0x00}));
}

test "literal encoder decodes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buf: std.ArrayList(u8) = .empty;
    const long = "x" ** 300;
    try encodeLiteral(arena, &buf, "grpc-message", long);
    var d = Decoder.init(testing.allocator);
    defer d.deinit();
    var out: std.ArrayList(Header) = .empty;
    try d.decode(arena, buf.items, &out);
    try expectHeaders(out.items, &.{.{ "grpc-message", long }});
}
