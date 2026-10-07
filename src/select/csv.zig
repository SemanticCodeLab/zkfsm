//! Streaming CSV record reader following S3 Select InputSerialization.CSV.
const std = @import("std");
const request = @import("request.zig");
const value = @import("value.zig");
const Value = value.Value;
const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, ReadFailed, RecordTooLarge, TooManyFields };

pub const max_fields = 16 * 1024;

pub const Reader = struct {
    in: *std.Io.Reader,
    opts: request.CsvInput,
    gpa: Allocator,
    max_record: usize,
    /// Long-lived: header and generated `_N` names.
    names: std.heap.ArenaAllocator,
    header: []const []const u8 = &.{},
    generated: std.ArrayList([]const u8) = .empty,
    buf: std.ArrayList(u8) = .empty,
    ends: std.ArrayList(usize) = .empty,
    keys: std.ArrayList([]const u8) = .empty,
    vals: std.ArrayList(Value) = .empty,
    /// Bytes consumed from `in`.
    offset: u64 = 0,
    /// Inclusive scan-range end: records starting after it are not read.
    end_offset: ?u64 = null,
    started: bool = false,
    done: bool = false,

    pub fn init(gpa: Allocator, in: *std.Io.Reader, opts: request.CsvInput, max_record: usize) Reader {
        return .{ .in = in, .opts = opts, .gpa = gpa, .max_record = max_record, .names = .init(gpa) };
    }

    pub fn deinit(r: *Reader) void {
        r.names.deinit();
        r.generated.deinit(r.gpa);
        r.buf.deinit(r.gpa);
        r.ends.deinit(r.gpa);
        r.keys.deinit(r.gpa);
        r.vals.deinit(r.gpa);
    }

    fn take(r: *Reader) Error!?u8 {
        const b = r.in.takeByte() catch |e| switch (e) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
        r.offset += 1;
        return b;
    }

    fn peekByte(r: *Reader) Error!?u8 {
        return r.in.peekByte() catch |e| switch (e) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
    }

    /// True (and consumes the rest) if `first` starts delimiter `d`.
    fn matchDelim(r: *Reader, first: u8, d: []const u8) Error!bool {
        if (d.len == 0 or first != d[0]) return false;
        if (d.len == 1) return true;
        const rest = r.in.peek(d.len - 1) catch |e| switch (e) {
            error.EndOfStream => return false,
            error.ReadFailed => return error.ReadFailed,
        };
        if (!std.mem.eql(u8, rest, d[1..])) return false;
        r.in.toss(d.len - 1);
        r.offset += d.len - 1;
        return true;
    }

    fn append(r: *Reader, b: u8) Error!void {
        if (r.buf.items.len >= r.max_record) return error.RecordTooLarge;
        try r.buf.append(r.gpa, b);
    }

    fn endField(r: *Reader) Error!void {
        if (r.ends.items.len >= max_fields) return error.TooManyFields;
        try r.ends.append(r.gpa, r.buf.items.len);
    }

    /// Skips to just past the next record delimiter.
    fn skipRecord(r: *Reader) Error!void {
        while (try r.take()) |b| {
            if (try r.matchDelim(b, r.opts.record_delimiter)) return;
        }
    }

    /// Reads one physical record into buf/ends. Returns false at EOF.
    fn readRecord(r: *Reader) Error!bool {
        r.buf.clearRetainingCapacity();
        r.ends.clearRetainingCapacity();
        const o = r.opts;
        const strip_cr = std.mem.eql(u8, o.record_delimiter, "\n");
        var in_quotes = false;
        var field_start: usize = 0;
        var quoted_field = false;
        var any = false;
        while (true) {
            const b = (try r.take()) orelse {
                if (!any) return false;
                try r.endField();
                return true;
            };
            any = true;
            if (in_quotes) {
                if (b == o.quote_escape and o.quote_escape != o.quote) {
                    if ((try r.peekByte()) == o.quote) {
                        _ = try r.take();
                        try r.append(o.quote);
                    } else try r.append(b);
                } else if (b == o.quote) {
                    if (o.quote_escape == o.quote and (try r.peekByte()) == o.quote) {
                        _ = try r.take();
                        try r.append(o.quote);
                    } else in_quotes = false;
                } else try r.append(b);
                continue;
            }
            if (b == o.quote and r.buf.items.len == field_start) {
                in_quotes = true;
                quoted_field = true;
            } else if (try r.matchDelim(b, o.field_delimiter)) {
                try r.endField();
                field_start = r.buf.items.len;
                quoted_field = false;
            } else if (try r.matchDelim(b, o.record_delimiter)) {
                if (strip_cr and !quoted_field and r.buf.items.len > field_start and r.buf.items[r.buf.items.len - 1] == '\r')
                    r.buf.items.len -= 1;
                try r.endField();
                return true;
            } else try r.append(b);
        }
    }

    fn fieldSlices(r: *Reader, arena: Allocator) Error![]const []const u8 {
        const out = try arena.alloc([]const u8, r.ends.items.len);
        var start: usize = 0;
        for (r.ends.items, 0..) |e, i| {
            out[i] = r.buf.items[start..e];
            start = e;
        }
        return out;
    }

    fn positionalName(r: *Reader, i: usize) Error![]const u8 {
        while (r.generated.items.len <= i) {
            const n = try std.fmt.allocPrint(r.names.allocator(), "_{d}", .{r.generated.items.len + 1});
            try r.generated.append(r.gpa, n);
        }
        return r.generated.items[i];
    }

    /// Positions the stream for ScanRange: first record starting at or after `start`.
    pub fn seekScanRange(r: *Reader, start: u64, end: ?u64) Error!void {
        r.end_offset = end;
        if (start == 0) return;
        r.started = true; // no header line inside a range that skips byte 0
        const skip = start - 1;
        const n = r.in.discard(.limited64(skip)) catch |e| switch (e) {
            error.EndOfStream => 0,
            error.ReadFailed => return error.ReadFailed,
        };
        r.offset += n;
        if (n < skip) {
            // discard can return short; keep going until done or EOF.
            var left = skip - n;
            while (left > 0) {
                const m = r.in.discard(.limited64(left)) catch |e| switch (e) {
                    error.EndOfStream => {
                        r.done = true;
                        return;
                    },
                    error.ReadFailed => return error.ReadFailed,
                };
                if (m == 0) {
                    r.done = true;
                    return;
                }
                left -= m;
                r.offset += m;
            }
        }
        try r.skipRecord();
    }

    /// Next record as an object valid until the following call.
    pub fn next(r: *Reader, arena: Allocator) Error!?Value {
        while (!r.done) {
            if (r.end_offset) |e| if (r.offset > e) {
                r.done = true;
                return null;
            };
            if (r.opts.comments) |c| {
                if ((try r.peekByte()) == c) {
                    try r.skipRecord();
                    continue;
                }
            }
            if (!try r.readRecord()) {
                r.done = true;
                return null;
            }
            if (r.ends.items.len == 1 and r.ends.items[0] == 0) continue; // blank line
            if (!r.started) {
                r.started = true;
                switch (r.opts.file_header_info) {
                    .none => {},
                    .ignore => continue,
                    .use => {
                        const na = r.names.allocator();
                        const h = try na.alloc([]const u8, r.ends.items.len);
                        var start: usize = 0;
                        for (r.ends.items, 0..) |e, i| {
                            h[i] = try na.dupe(u8, r.buf.items[start..e]);
                            start = e;
                        }
                        r.header = h;
                        continue;
                    },
                }
            }
            const fields = try r.fieldSlices(arena);
            const keys = try arena.alloc([]const u8, fields.len);
            const vals = try arena.alloc(Value, fields.len);
            for (fields, 0..) |f, i| {
                keys[i] = if (i < r.header.len) r.header[i] else try r.positionalName(i);
                vals[i] = .{ .string = f };
            }
            return .{ .object = .{ .keys = keys, .values = vals, .positional = true } };
        }
        return null;
    }
};

fn collect(src: []const u8, opts: request.CsvInput, out: *std.ArrayList(u8), scan: ?request.ScanRange) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var in: std.Io.Reader = .fixed(src);
    var r = Reader.init(std.testing.allocator, &in, opts, 1024);
    defer r.deinit();
    if (scan) |s| try r.seekScanRange(s.start orelse 0, s.end);
    while (try r.next(arena.allocator())) |rec| {
        for (rec.object.keys, rec.object.values) |k, v| {
            try out.print(std.testing.allocator, "{s}={s};", .{ k, v.string });
        }
        try out.append(std.testing.allocator, '|');
    }
}

test "csv quoting header comments" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try collect("a,b\r\n# skip\n1,\"x,\"\"y\"\"\nz\"\n\n2,3", .{ .file_header_info = .use, .comments = '#' }, &out, null);
    try std.testing.expectEqualStrings("a=1;b=x,\"y\"\nz;|a=2;b=3;|", out.items);
}

test "csv custom delimiters and escape" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try collect("h1||h2;;'a\\'b'||c;;d", .{ .file_header_info = .ignore, .field_delimiter = "||", .record_delimiter = ";;", .quote = '\'', .quote_escape = '\\' }, &out, null);
    try std.testing.expectEqualStrings("_1=a'b;_2=c;|_1=d;|", out.items);
}

test "csv scan range" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    // Records start at 0, 4, 8, 12.
    try collect("aa1\nbb2\ncc3\ndd4\n", .{}, &out, .{ .start = 2, .end = 8 });
    try std.testing.expectEqualStrings("_1=bb2;|_1=cc3;|", out.items);
    out.clearRetainingCapacity();
    try collect("aa1\nbb2\ncc3\ndd4\n", .{}, &out, .{ .start = 4, .end = 4 });
    try std.testing.expectEqualStrings("_1=bb2;|", out.items);
}

test "csv record size limit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const big = "x" ** 2000;
    var in: std.Io.Reader = .fixed(big);
    var r = Reader.init(std.testing.allocator, &in, .{}, 1024);
    defer r.deinit();
    try std.testing.expectError(error.RecordTooLarge, r.next(arena.allocator()));
}
