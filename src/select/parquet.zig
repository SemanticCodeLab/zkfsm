//! Parquet reader for flat schemas: footer via thrift compact protocol,
//! PLAIN / dictionary encodings, UNCOMPRESSED / SNAPPY / GZIP / ZSTD pages.
const std = @import("std");
const thrift = @import("thrift.zig");
const snappy = @import("snappy.zig");
const datetime = @import("datetime.zig");
const Value = @import("value.zig").Value;
const Allocator = std.mem.Allocator;

pub const Error = error{
    OutOfMemory,
    InvalidParquet,
    UnsupportedParquet,
    ParquetTooLarge,
} || thrift.Error || snappy.Error;

pub const Physical = enum(i32) { boolean = 0, int32 = 1, int64 = 2, int96 = 3, float = 4, double = 5, byte_array = 6, fixed_len_byte_array = 7, _ };
pub const Logical = enum { none, string, date, ts_millis, ts_micros, ts_nanos, decimal };

pub const Column = struct {
    name: []const u8,
    physical: Physical,
    type_length: usize = 0,
    optional: bool = false,
    logical: Logical = .none,
    scale: i32 = 0,
};

pub const Chunk = struct {
    codec: i32 = 0,
    num_values: i64 = 0,
    start: u64 = 0,
    size: u64 = 0,
};

pub const RowGroup = struct {
    num_rows: u64,
    chunks: []Chunk,

    pub fn startOffset(rg: RowGroup) u64 {
        return if (rg.chunks.len > 0) rg.chunks[0].start else 0;
    }
};

pub const Limits = struct {
    /// Cells (rows x columns) decoded at once for one row group.
    max_row_group_cells: u64 = 4 * 1024 * 1024,
    max_page_bytes: usize = 64 * 1024 * 1024,
    max_columns: usize = 4096,
};

pub const File = struct {
    data: []const u8,
    columns: []Column,
    row_groups: []RowGroup,
    limits: Limits,

    /// Parses the footer; metadata is allocated in `arena`, `data` is borrowed.
    pub fn open(arena: Allocator, data: []const u8, limits: Limits) Error!File {
        if (data.len < 12 or !std.mem.eql(u8, data[0..4], "PAR1") or !std.mem.eql(u8, data[data.len - 4 ..], "PAR1"))
            return error.InvalidParquet;
        const flen = std.mem.readInt(u32, data[data.len - 8 ..][0..4], .little);
        if (flen > data.len - 12) return error.InvalidParquet;
        const meta = data[data.len - 8 - flen .. data.len - 8];
        var f: File = .{ .data = data, .columns = &.{}, .row_groups = &.{}, .limits = limits };
        try f.readFileMeta(arena, meta);
        return f;
    }

    fn readFileMeta(f: *File, arena: Allocator, meta: []const u8) Error!void {
        var r: thrift.Reader = .{ .s = meta };
        var last: i16 = 0;
        var schema_seen = false;
        while (try r.fieldHeader(&last)) |h| {
            switch (h.id) {
                2 => {
                    if (h.type != .list) return error.InvalidParquet;
                    try f.readSchema(arena, &r);
                    schema_seen = true;
                },
                4 => {
                    if (h.type != .list) return error.InvalidParquet;
                    if (!schema_seen) return error.InvalidParquet;
                    const lh = try r.listHeader();
                    const groups = try arena.alloc(RowGroup, lh.len);
                    for (groups) |*g| g.* = try f.readRowGroup(arena, &r);
                    f.row_groups = groups;
                },
                else => try r.skip(h.type),
            }
        }
        if (!schema_seen) return error.InvalidParquet;
    }

    fn readSchema(f: *File, arena: Allocator, r: *thrift.Reader) Error!void {
        const lh = try r.listHeader();
        if (lh.len == 0 or lh.elem != .@"struct") return error.InvalidParquet;
        if (lh.len - 1 > f.limits.max_columns) return error.UnsupportedParquet;
        var cols: std.ArrayList(Column) = .empty;
        for (0..lh.len) |idx| {
            var c: Column = .{ .name = "", .physical = @enumFromInt(-1) };
            var has_type = false;
            var children: i32 = 0;
            var repetition: i32 = 0;
            var converted: i32 = -1;
            var last: i16 = 0;
            try r.enter();
            while (try r.fieldHeader(&last)) |h| {
                switch (h.id) {
                    1 => {
                        c.physical = @enumFromInt(try r.readI32());
                        has_type = true;
                    },
                    2 => c.type_length = std.math.cast(usize, try r.readI32()) orelse return error.InvalidParquet,
                    3 => repetition = try r.readI32(),
                    4 => c.name = try arena.dupe(u8, try r.readBinary()),
                    5 => children = try r.readI32(),
                    6 => converted = try r.readI32(),
                    7 => c.scale = try r.readI32(),
                    10 => try readLogical(r, &c),
                    else => try r.skip(h.type),
                }
            }
            r.leave();
            if (idx == 0) continue; // root
            if (children > 0 or !has_type) return error.UnsupportedParquet;
            if (repetition == 2) return error.UnsupportedParquet;
            c.optional = repetition == 1;
            if (c.logical == .none) c.logical = switch (converted) {
                0, 4, 19 => .string,
                5 => .decimal,
                6 => .date,
                9 => .ts_millis,
                10 => .ts_micros,
                else => .none,
            };
            switch (c.physical) {
                .boolean, .int32, .int64, .int96, .float, .double, .byte_array => {},
                .fixed_len_byte_array => if (c.type_length == 0 or c.type_length > 1 << 20) return error.InvalidParquet,
                _ => return error.UnsupportedParquet,
            }
            try cols.append(arena, c);
        }
        f.columns = cols.items;
    }

    fn readLogical(r: *thrift.Reader, c: *Column) Error!void {
        try r.enter();
        defer r.leave();
        var last: i16 = 0;
        while (try r.fieldHeader(&last)) |h| {
            switch (h.id) {
                1 => {
                    c.logical = .string;
                    try r.skip(h.type);
                },
                5 => {
                    c.logical = .decimal;
                    try r.enter();
                    var l2: i16 = 0;
                    while (try r.fieldHeader(&l2)) |h2| {
                        if (h2.id == 1) c.scale = try r.readI32() else try r.skip(h2.type);
                    }
                    r.leave();
                },
                6 => {
                    c.logical = .date;
                    try r.skip(h.type);
                },
                8 => {
                    try r.enter();
                    var l2: i16 = 0;
                    while (try r.fieldHeader(&l2)) |h2| {
                        if (h2.id == 2) {
                            try r.enter();
                            var l3: i16 = 0;
                            while (try r.fieldHeader(&l3)) |h3| {
                                c.logical = switch (h3.id) {
                                    1 => .ts_millis,
                                    2 => .ts_micros,
                                    3 => .ts_nanos,
                                    else => c.logical,
                                };
                                try r.skip(h3.type);
                            }
                            r.leave();
                        } else try r.skip(h2.type);
                    }
                    r.leave();
                },
                else => try r.skip(h.type),
            }
        }
    }

    fn readRowGroup(f: *File, arena: Allocator, r: *thrift.Reader) Error!RowGroup {
        try r.enter();
        defer r.leave();
        var rg: RowGroup = .{ .num_rows = 0, .chunks = &.{} };
        var last: i16 = 0;
        while (try r.fieldHeader(&last)) |h| {
            switch (h.id) {
                1 => {
                    const lh = try r.listHeader();
                    if (lh.len != f.columns.len) return error.InvalidParquet;
                    const chunks = try arena.alloc(Chunk, lh.len);
                    for (chunks) |*c| c.* = try readColumnChunk(r, f.data.len);
                    rg.chunks = chunks;
                },
                3 => rg.num_rows = std.math.cast(u64, try r.readI64()) orelse return error.InvalidParquet,
                else => try r.skip(h.type),
            }
        }
        if (rg.chunks.len != f.columns.len) return error.InvalidParquet;
        return rg;
    }

    fn readColumnChunk(r: *thrift.Reader, file_len: usize) Error!Chunk {
        try r.enter();
        defer r.leave();
        var c: Chunk = .{};
        var seen_meta = false;
        var last: i16 = 0;
        while (try r.fieldHeader(&last)) |h| {
            if (h.id == 1) return error.UnsupportedParquet; // external file_path
            if (h.id != 3) {
                try r.skip(h.type);
                continue;
            }
            seen_meta = true;
            try r.enter();
            var data_off: i64 = -1;
            var dict_off: i64 = -1;
            var l2: i16 = 0;
            while (try r.fieldHeader(&l2)) |m| {
                switch (m.id) {
                    4 => c.codec = try r.readI32(),
                    5 => c.num_values = try r.readI64(),
                    7 => c.size = std.math.cast(u64, try r.readI64()) orelse return error.InvalidParquet,
                    9 => data_off = try r.readI64(),
                    11 => dict_off = try r.readI64(),
                    else => try r.skip(m.type),
                }
            }
            r.leave();
            const start = if (dict_off > 0 and dict_off < data_off) dict_off else data_off;
            if (start < 4 or c.num_values < 0) return error.InvalidParquet;
            c.start = @intCast(start);
            if (c.start > file_len or c.size > file_len - c.start) return error.InvalidParquet;
        }
        if (!seen_meta) return error.InvalidParquet;
        return c;
    }

    /// Decodes all columns of row group `idx` into `arena`: result[col][row].
    pub fn readRowGroupValues(f: *const File, arena: Allocator, idx: usize) Error![][]Value {
        const rg = f.row_groups[idx];
        const cells = std.math.mul(u64, rg.num_rows, f.columns.len) catch return error.ParquetTooLarge;
        if (cells > f.limits.max_row_group_cells) return error.ParquetTooLarge;
        const out = try arena.alloc([]Value, f.columns.len);
        for (f.columns, rg.chunks, 0..) |col, chunk, i| {
            if (chunk.num_values != rg.num_rows) return error.InvalidParquet;
            out[i] = try f.readChunk(arena, col, chunk, @intCast(rg.num_rows));
        }
        return out;
    }

    fn readChunk(f: *const File, arena: Allocator, col: Column, chunk: Chunk, rows: usize) Error![]Value {
        const values = try arena.alloc(Value, rows);
        var filled: usize = 0;
        var dict: []const Value = &.{};
        const region = f.data[@intCast(chunk.start)..@intCast(chunk.start + chunk.size)];
        var pos: usize = 0;
        while (filled < rows) {
            if (pos >= region.len) return error.InvalidParquet;
            var r: thrift.Reader = .{ .s = region[pos..] };
            const ph = try readPageHeader(&r);
            pos += r.i;
            if (ph.compressed_size > region.len - pos) return error.InvalidParquet;
            const raw = region[pos .. pos + ph.compressed_size];
            pos += ph.compressed_size;
            if (ph.uncompressed_size > f.limits.max_page_bytes) return error.ParquetTooLarge;
            switch (ph.kind) {
                .dictionary => {
                    const page = try decompress(arena, chunk.codec, raw, ph.uncompressed_size);
                    if (ph.num_values > f.limits.max_row_group_cells) return error.ParquetTooLarge;
                    const d = try arena.alloc(Value, ph.num_values);
                    var dec: Plain = .{ .s = page };
                    for (d) |*v| v.* = try dec.next(col);
                    dict = d;
                },
                .data_v1, .data_v2 => {
                    const n = ph.num_values;
                    if (n > rows - filled) return error.InvalidParquet;
                    var def_bytes: []const u8 = &.{};
                    var body: []const u8 = undefined;
                    if (ph.kind == .data_v1) {
                        const page = try decompress(arena, chunk.codec, raw, ph.uncompressed_size);
                        body = page;
                        if (col.optional) {
                            if (page.len < 4) return error.InvalidParquet;
                            const dl = std.mem.readInt(u32, page[0..4], .little);
                            if (dl > page.len - 4) return error.InvalidParquet;
                            def_bytes = page[4 .. 4 + dl];
                            body = page[4 + dl ..];
                        }
                    } else {
                        const lv = std.math.add(usize, ph.rep_len, ph.def_len) catch return error.InvalidParquet;
                        if (ph.rep_len != 0 or lv > raw.len or lv > ph.uncompressed_size) return error.InvalidParquet;
                        def_bytes = raw[0..ph.def_len];
                        body = if (ph.v2_compressed)
                            try decompress(arena, chunk.codec, raw[lv..], ph.uncompressed_size - lv)
                        else
                            raw[lv..];
                    }
                    const dst = values[filled .. filled + n];
                    try decodeValues(arena, col, ph.encoding, def_bytes, body, dict, dst);
                    filled += n;
                },
                .other => {},
            }
        }
        return values;
    }
};

const PageKind = enum { data_v1, dictionary, data_v2, other };

const PageHeader = struct {
    kind: PageKind = .other,
    uncompressed_size: usize = 0,
    compressed_size: usize = 0,
    num_values: usize = 0,
    encoding: i32 = 0,
    def_len: usize = 0,
    rep_len: usize = 0,
    v2_compressed: bool = true,
};

fn nonNeg(v: i32) thrift.Error!usize {
    return std.math.cast(usize, v) orelse error.InvalidThrift;
}

fn readPageHeader(r: *thrift.Reader) Error!PageHeader {
    var ph: PageHeader = .{};
    var last: i16 = 0;
    while (try r.fieldHeader(&last)) |h| {
        switch (h.id) {
            1 => ph.kind = switch (try r.readI32()) {
                0 => .data_v1,
                2 => .dictionary,
                3 => .data_v2,
                else => .other,
            },
            2 => ph.uncompressed_size = try nonNeg(try r.readI32()),
            3 => ph.compressed_size = try nonNeg(try r.readI32()),
            5, 7, 8 => {
                try r.enter();
                var l2: i16 = 0;
                while (try r.fieldHeader(&l2)) |s| {
                    switch (s.id) {
                        1 => ph.num_values = try nonNeg(try r.readI32()),
                        2 => if (h.id == 8) try r.skip(s.type) else {
                            ph.encoding = try r.readI32();
                        },
                        4 => if (h.id == 8) {
                            ph.encoding = try r.readI32();
                        } else try r.skip(s.type),
                        5 => if (h.id == 8) {
                            ph.def_len = try nonNeg(try r.readI32());
                        } else try r.skip(s.type),
                        6 => if (h.id == 8) {
                            ph.rep_len = try nonNeg(try r.readI32());
                        } else try r.skip(s.type),
                        7 => if (h.id == 8) {
                            ph.v2_compressed = try thrift.Reader.fieldBool(s.type);
                        } else try r.skip(s.type),
                        else => try r.skip(s.type),
                    }
                }
                r.leave();
            },
            else => try r.skip(h.type),
        }
    }
    return ph;
}

fn decompress(arena: Allocator, codec: i32, raw: []const u8, size: usize) Error![]const u8 {
    switch (codec) {
        0 => {
            if (raw.len != size) return error.InvalidParquet;
            return raw;
        },
        1 => {
            const out = try snappy.decompress(arena, raw, size);
            if (out.len != size) return error.InvalidParquet;
            return out;
        },
        2 => {
            const out = try arena.alloc(u8, size);
            const window = try arena.alloc(u8, std.compress.flate.max_window_len);
            var in: std.Io.Reader = .fixed(raw);
            var dec: std.compress.flate.Decompress = .init(&in, .gzip, window);
            dec.reader.readSliceAll(out) catch return error.InvalidParquet;
            return out;
        },
        6 => {
            const zstd = std.compress.zstd;
            const out = try arena.alloc(u8, size);
            const window = try arena.alloc(u8, zstd.default_window_len + zstd.block_size_max);
            var in: std.Io.Reader = .fixed(raw);
            var dec: zstd.Decompress = .init(&in, window, .{});
            dec.reader.readSliceAll(out) catch return error.InvalidParquet;
            return out;
        },
        else => return error.UnsupportedParquet,
    }
}

/// RLE / bit-packed hybrid decoder.
const Rle = struct {
    s: []const u8,
    i: usize = 0,
    bw: u6,

    fn varint(d: *Rle) Error!u64 {
        var r: thrift.Reader = .{ .s = d.s[d.i..] };
        const v = try r.varint();
        d.i += r.i;
        return v;
    }

    fn fill(d: *Rle, out: []u32) Error!void {
        if (d.bw > 32) return error.InvalidParquet;
        var o: usize = 0;
        while (o < out.len) {
            const h = try d.varint();
            if (h & 1 == 1) {
                const groups = h >> 1;
                const count = std.math.mul(u64, groups, 8) catch return error.InvalidParquet;
                const nbytes = std.math.mul(u64, groups, d.bw) catch return error.InvalidParquet;
                if (nbytes > d.s.len - d.i) return error.InvalidParquet;
                const bytes = d.s[d.i .. d.i + @as(usize, @intCast(nbytes))];
                d.i += bytes.len;
                const take: usize = @intCast(@min(count, out.len - o));
                for (0..take) |k| {
                    var v: u64 = 0;
                    const bit = k * d.bw;
                    for (0..d.bw) |b| {
                        const p = bit + b;
                        v |= @as(u64, (bytes[p / 8] >> @intCast(p % 8)) & 1) << @intCast(b);
                    }
                    out[o + k] = @intCast(v);
                }
                o += take;
            } else {
                const count = h >> 1;
                if (count == 0) return error.InvalidParquet;
                const vb = (@as(usize, d.bw) + 7) / 8;
                if (vb > d.s.len - d.i) return error.InvalidParquet;
                var v: u32 = 0;
                for (0..vb) |k| v |= @as(u32, d.s[d.i + k]) << @intCast(8 * k);
                d.i += vb;
                const take: usize = @intCast(@min(count, out.len - o));
                @memset(out[o .. o + take], v);
                o += take;
            }
        }
    }
};

const Plain = struct {
    s: []const u8,
    i: usize = 0,
    bit: u3 = 0,

    fn bytes(d: *Plain, n: usize) Error![]const u8 {
        if (n > d.s.len - d.i) return error.InvalidParquet;
        const out = d.s[d.i .. d.i + n];
        d.i += n;
        return out;
    }

    fn next(d: *Plain, col: Column) Error!Value {
        switch (col.physical) {
            .boolean => {
                if (d.i >= d.s.len) return error.InvalidParquet;
                const b = (d.s[d.i] >> d.bit) & 1;
                if (d.bit == 7) {
                    d.bit = 0;
                    d.i += 1;
                } else d.bit += 1;
                return .{ .bool = b == 1 };
            },
            .int32 => return try convertInt(col, std.mem.readInt(i32, (try d.bytes(4))[0..4], .little)),
            .int64 => return try convertInt(col, std.mem.readInt(i64, (try d.bytes(8))[0..8], .little)),
            .int96 => {
                const b = try d.bytes(12);
                const nanos = std.mem.readInt(i64, b[0..8], .little);
                const jd = std.mem.readInt(i32, b[8..12], .little);
                const days = @as(i64, jd) - 2440588;
                const day_us = std.math.mul(i64, days, datetime.us_per_day) catch return error.InvalidParquet;
                return tsValue(std.math.add(i64, day_us, @divTrunc(nanos, 1000)) catch return error.InvalidParquet, .frac, 6);
            },
            .float => return .{ .float = @as(f32, @bitCast(std.mem.readInt(u32, (try d.bytes(4))[0..4], .little))) },
            .double => return .{ .float = @bitCast(std.mem.readInt(u64, (try d.bytes(8))[0..8], .little)) },
            .byte_array => {
                const n = std.mem.readInt(u32, (try d.bytes(4))[0..4], .little);
                return .{ .string = try d.bytes(n) };
            },
            .fixed_len_byte_array => {
                const b = try d.bytes(col.type_length);
                if (col.logical == .decimal) {
                    if (b.len > 16) return error.UnsupportedParquet;
                    var v: i128 = if (b[0] & 0x80 != 0) -1 else 0;
                    for (b) |x| v = (v << 8) | x;
                    return .{ .float = scaleDecimal(@floatFromInt(v), col.scale) };
                }
                return .{ .string = b };
            },
            _ => return error.UnsupportedParquet,
        }
    }
};

fn scaleDecimal(v: f64, scale: i32) f64 {
    return v / std.math.pow(f64, 10, @floatFromInt(std.math.clamp(scale, 0, 38)));
}

fn tsValue(micros: i64, precision: datetime.Precision, digits: u8) Error!Value {
    if (!datetime.inRange(micros)) return error.InvalidParquet;
    return .{ .timestamp = .{ .micros = micros, .precision = precision, .frac_digits = digits } };
}

fn convertInt(col: Column, v: i64) Error!Value {
    return switch (col.logical) {
        .date => tsValue(std.math.mul(i64, v, datetime.us_per_day) catch return error.InvalidParquet, .day, 0),
        .ts_millis => tsValue(std.math.mul(i64, v, 1000) catch return error.InvalidParquet, .frac, 3),
        .ts_micros => tsValue(v, .frac, 6),
        .ts_nanos => tsValue(@divFloor(v, 1000), .frac, 6),
        .decimal => .{ .float = scaleDecimal(@floatFromInt(v), col.scale) },
        else => .{ .int = v },
    };
}

fn decodeValues(arena: Allocator, col: Column, encoding: i32, def_bytes: []const u8, body: []const u8, dict: []const Value, dst: []Value) Error!void {
    const n = dst.len;
    const defs = try arena.alloc(u32, n);
    defer arena.free(defs);
    if (col.optional) {
        var rle: Rle = .{ .s = def_bytes, .bw = 1 };
        try rle.fill(defs);
    } else @memset(defs, 1);
    var present: usize = 0;
    for (defs) |d| {
        if (d > 1) return error.InvalidParquet;
        present += d;
    }
    switch (encoding) {
        0 => {
            var p: Plain = .{ .s = body };
            for (dst, defs) |*v, d| v.* = if (d == 1) try p.next(col) else .null;
        },
        2, 8 => {
            if (present == 0) {
                @memset(dst, .null);
                return;
            }
            if (body.len < 1) return error.InvalidParquet;
            const idx = try arena.alloc(u32, present);
            defer arena.free(idx);
            var rle: Rle = .{ .s = body[1..], .bw = std.math.cast(u6, body[0]) orelse return error.InvalidParquet };
            try rle.fill(idx);
            var k: usize = 0;
            for (dst, defs) |*v, d| {
                if (d == 0) {
                    v.* = .null;
                    continue;
                }
                const di = idx[k];
                k += 1;
                if (di >= dict.len) return error.InvalidParquet;
                v.* = dict[di];
            }
        },
        3 => {
            // RLE booleans (data page v2): 4-byte length then bit width 1 hybrid.
            if (col.physical != .boolean or body.len < 4) return error.UnsupportedParquet;
            const len = std.mem.readInt(u32, body[0..4], .little);
            if (len > body.len - 4) return error.InvalidParquet;
            const bits = try arena.alloc(u32, present);
            defer arena.free(bits);
            var rle: Rle = .{ .s = body[4 .. 4 + len], .bw = 1 };
            try rle.fill(bits);
            var k: usize = 0;
            for (dst, defs) |*v, d| {
                if (d == 0) {
                    v.* = .null;
                    continue;
                }
                v.* = .{ .bool = bits[k] == 1 };
                k += 1;
            }
        },
        else => return error.UnsupportedParquet,
    }
}

test "rle hybrid" {
    // run of 3 x value 5 (bw 3), then 1 bit-packed group: 0..7
    const bytes = [_]u8{ 0x06, 0x05, 0x03, 0x88, 0xC6, 0xFA };
    var d: Rle = .{ .s = &bytes, .bw = 3 };
    var out: [11]u32 = undefined;
    try d.fill(&out);
    try std.testing.expectEqualSlices(u32, &.{ 5, 5, 5, 0, 1, 2, 3, 4, 5, 6, 7 }, &out);
    var short: Rle = .{ .s = bytes[0..3], .bw = 3 };
    var out2: [5]u32 = undefined;
    try std.testing.expectError(error.InvalidParquet, short.fill(&out2));
}

test "hostile footers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.InvalidParquet, File.open(a, "PAR1PAR1", .{}));
    try std.testing.expectError(error.InvalidParquet, File.open(a, "PAR1\xff\xff\xff\xffPAR1", .{}));
    try std.testing.expectError(error.InvalidParquet, File.open(a, "PAR1\x00\x01\x00\x00\x00PAR1", .{}));
}
