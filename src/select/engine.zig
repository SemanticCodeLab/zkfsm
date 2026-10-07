//! SelectObjectContent execution: input decoding, SQL evaluation and the
//! event-stream response (Records, Progress, Cont, Stats, End).
const std = @import("std");
const request = @import("request.zig");
const ast = @import("ast.zig");
const parser = @import("parser.zig");
const eval = @import("eval.zig");
const value = @import("value.zig");
const datetime = @import("datetime.zig");
const csv = @import("csv.zig");
const json = @import("json.zig");
const parquet = @import("parquet.zig");
const output = @import("output.zig");
const eventstream = @import("eventstream.zig");
const Value = value.Value;
const Allocator = std.mem.Allocator;

pub const PrepareError = request.Error || parser.Error;

pub const RunError = error{ OutOfMemory, ReadFailed, WriteFailed, ObjectTooLarge, InvalidCompressedInput } ||
    eval.Error || csv.Error || json.Error || parquet.Error || eventstream.WriteError;

pub const Options = struct {
    max_record_bytes: usize = 1024 * 1024,
    /// Parquet needs random access, so the object is buffered up to this size.
    max_parquet_bytes: usize = 256 * 1024 * 1024,
    parquet_limits: parquet.Limits = .{},
    records_chunk_bytes: usize = 64 * 1024,
    /// Emit a Cont keep-alive after this many processed bytes without events.
    cont_interval_bytes: u64 = 8 * 1024 * 1024,
    /// Fixed clock for UTCNOW(); null uses the system clock.
    now_micros: ?i64 = null,
};

pub const Stats = struct {
    bytes_scanned: u64 = 0,
    bytes_processed: u64 = 0,
    bytes_returned: u64 = 0,
};

const Counter = struct {
    n: u64 = 0,
    pub fn update(c: *Counter, bytes: []const u8) void {
        c.n += bytes.len;
    }
};

const io_buffer_len = 64 * 1024;

pub const Select = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    req: request.Request,
    query: ast.Query,
    names: []const []const u8,
    opts: Options,

    /// Parses the XML body and SQL; errors here map to HTTP 400 before streaming.
    pub fn initXml(gpa: Allocator, body: []const u8, opts: Options) PrepareError!Select {
        var arena = std.heap.ArenaAllocator.init(gpa);
        const req = request.parse(arena.allocator(), body) catch |e| {
            arena.deinit();
            return e;
        };
        // `finish` owns the arena from here, including on error.
        return finish(gpa, arena, req, opts);
    }

    pub fn init(gpa: Allocator, req: request.Request, opts: Options) PrepareError!Select {
        return finish(gpa, std.heap.ArenaAllocator.init(gpa), req, opts);
    }

    fn finish(gpa: Allocator, arena_in: std.heap.ArenaAllocator, req: request.Request, opts: Options) PrepareError!Select {
        var arena = arena_in;
        errdefer arena.deinit();
        const a = arena.allocator();
        const q = try parser.parse(a, req.expression);
        var names: []const []const u8 = &.{};
        if (q.items) |items| {
            const ns = try a.alloc([]const u8, items.len);
            for (items, 0..) |it, i| ns[i] = try columnName(a, it, i);
            names = ns;
        }
        return .{ .gpa = gpa, .arena = arena, .req = req, .query = q, .names = names, .opts = opts };
    }

    pub fn deinit(s: *Select) void {
        s.arena.deinit();
    }

    /// Streams the response to `out`. On failure an error event is written
    /// (best effort) and the error is returned.
    pub fn run(s: *Select, input: *std.Io.Reader, out: *std.Io.Writer) RunError!Stats {
        var r: Run = .{ .sel = s, .out = out, .rec = .init(s.gpa), .row_arena = .init(s.gpa) };
        defer r.deinit();
        r.execute(input) catch |err| {
            eventstream.writeError(out, errorCode(err), @errorName(err)) catch {};
            out.flush() catch {};
            return err;
        };
        return r.stats();
    }
};

fn columnName(a: Allocator, it: ast.SelectItem, i: usize) Allocator.Error![]const u8 {
    if (it.alias) |al| return al;
    if (it.expr.* == .path) {
        const steps = it.expr.path.steps;
        if (steps.len > 0) switch (steps[steps.len - 1]) {
            .field => |f| return f.name,
            else => {},
        };
    }
    return std.fmt.allocPrint(a, "_{d}", .{i + 1});
}

pub fn errorCode(err: RunError) []const u8 {
    return switch (err) {
        error.DivisionByZero => "EvaluatorDivisionByZero",
        error.InvalidCast => "CastFailed",
        error.TypeMismatch, error.InvalidArgument => "EvaluatorInvalidArguments",
        error.InvalidTimestamp => "EvaluatorInvalidTimestampFormatPattern",
        error.Overflow => "IntegerOverflow",
        error.RecordTooLarge => "OverMaxRecordSize",
        error.TooManyFields => "CSVParsingError",
        error.InvalidJson, error.JsonTooDeep => "JSONParsingError",
        error.InvalidParquet, error.InvalidThrift, error.ThriftTooDeep, error.InvalidSnappy, error.SnappyTooLarge => "ParquetParsingError",
        error.UnsupportedParquet => "UnsupportedParquetType",
        error.ParquetTooLarge, error.ObjectTooLarge => "ObjectSerializationConflict",
        error.InvalidCompressedInput => "InvalidCompressionFormat",
        error.UnsupportedPath => "UnsupportedSyntax",
        else => "InternalError",
    };
}

const Run = struct {
    sel: *Select,
    out: *std.Io.Writer,
    rec: std.Io.Writer.Allocating,
    row_arena: std.heap.ArenaAllocator,
    aggs: []eval.AggState = &.{},
    scanned: ?*Counter = null,
    processed: ?*Counter = null,
    returned: u64 = 0,
    emitted: u64 = 0,
    last_event_at: u64 = 0,
    stop: bool = false,
    now: datetime.Timestamp = .{ .micros = 0 },
    steps: []const ast.Step = &.{},

    fn deinit(r: *Run) void {
        for (r.aggs) |*a| a.deinit(r.sel.gpa);
        r.sel.gpa.free(r.aggs);
        r.rec.deinit();
        r.row_arena.deinit();
    }

    fn stats(r: *const Run) Stats {
        return .{
            .bytes_scanned = if (r.scanned) |c| c.n else 0,
            .bytes_processed = if (r.processed) |c| c.n else 0,
            .bytes_returned = r.returned,
        };
    }

    fn execute(r: *Run, input: *std.Io.Reader) RunError!void {
        const s = r.sel;
        const gpa = s.gpa;
        const q = &s.query;
        const now_us = s.opts.now_micros orelse std.time.microTimestamp();
        r.now = .{ .micros = now_us, .precision = .frac, .frac_digits = 3 };
        r.steps = q.from_steps;
        r.aggs = try gpa.alloc(eval.AggState, q.aggregates.len);
        for (r.aggs) |*a| a.* = .{};

        const buf1 = try gpa.alloc(u8, io_buffer_len);
        defer gpa.free(buf1);
        const buf2 = try gpa.alloc(u8, io_buffer_len);
        defer gpa.free(buf2);
        var scan = input.hashed(Counter{}, buf1);
        r.scanned = &scan.hasher;
        var window: []u8 = &.{};
        defer gpa.free(window);
        var gz: std.compress.flate.Decompress = undefined;
        var src: *std.Io.Reader = &scan.reader;
        if (s.req.compression == .gzip) {
            window = try gpa.alloc(u8, std.compress.flate.max_window_len);
            gz = .init(&scan.reader, .gzip, window);
            src = &gz.reader;
        }
        var proc = src.hashed(Counter{}, buf2);
        r.processed = &proc.hasher;
        const in = &proc.reader;
        const range = s.req.scan_range;

        if (q.limit == null or q.limit.? > 0) switch (s.req.input) {
            .csv => |opts| {
                var cr = csv.Reader.init(gpa, in, opts, s.opts.max_record_bytes);
                defer cr.deinit();
                if (range) |sr| try cr.seekScanRange(sr.start orelse 0, sr.end);
                while (!r.stop) {
                    _ = r.row_arena.reset(.retain_capacity);
                    const doc = (try mapRead(csv.Error, cr.next(r.row_arena.allocator()), s.req.compression)) orelse break;
                    try r.expand(doc, r.steps, 0);
                    try r.tick();
                }
            },
            .json => |_| {
                var steps = r.steps;
                const unwrap = steps.len > 0 and steps[0] == .wildcard;
                if (unwrap) steps = steps[1..];
                var jr = json.Reader.init(gpa, in, s.opts.max_record_bytes, unwrap);
                defer jr.deinit();
                if (range) |sr| try jr.seekScanRange(sr.start orelse 0, sr.end);
                while (!r.stop) {
                    _ = r.row_arena.reset(.retain_capacity);
                    const doc = (try mapRead(json.Error, jr.next(r.row_arena.allocator()), s.req.compression)) orelse break;
                    try r.expand(doc, steps, 0);
                    try r.tick();
                }
            },
            .parquet => try r.runParquet(in, range),
        };
        if (!r.stop) {
            // Drain so Stats reflect the whole object (and gzip trailer is checked).
            _ = in.discardRemaining() catch |e| switch (e) {
                error.ReadFailed => return if (s.req.compression == .gzip) error.InvalidCompressedInput else error.ReadFailed,
            };
        }
        if (q.isAggregate() and (q.limit == null or q.limit.? > 0)) {
            const results = try r.row_arena.allocator().alloc(Value, r.aggs.len);
            for (q.aggregates, r.aggs, 0..) |node, *st, i| results[i] = st.result(node.aggregate.kind);
            const env: eval.Env = .{ .arena = r.row_arena.allocator(), .record = .null, .alias = q.alias, .now = r.now, .agg_results = results };
            try r.project(&env);
        }
        try r.flushRecords();
        if (s.req.request_progress) try r.progress("Progress");
        try r.progress("Stats");
        try eventstream.writeEvent(r.out, "End", null, "");
        try r.out.flush();
    }

    /// Gzip decode failures surface as ReadFailed from the decompressor.
    fn mapRead(comptime E: type, res: E!?Value, comp: request.Compression) RunError!?Value {
        return res catch |e| switch (e) {
            error.ReadFailed => if (comp == .gzip) error.InvalidCompressedInput else error.ReadFailed,
            else => |x| x,
        };
    }

    fn runParquet(r: *Run, in: *std.Io.Reader, range: ?request.ScanRange) RunError!void {
        const s = r.sel;
        const gpa = s.gpa;
        const data = in.allocRemaining(gpa, .limited(s.opts.max_parquet_bytes)) catch |e| switch (e) {
            error.StreamTooLong => return error.ObjectTooLarge,
            error.OutOfMemory => return error.OutOfMemory,
            error.ReadFailed => return error.ReadFailed,
        };
        defer gpa.free(data);
        var meta_arena = std.heap.ArenaAllocator.init(gpa);
        defer meta_arena.deinit();
        const file = try parquet.File.open(meta_arena.allocator(), data, s.opts.parquet_limits);
        const keys = try meta_arena.allocator().alloc([]const u8, file.columns.len);
        for (file.columns, 0..) |c, i| keys[i] = c.name;
        var rg_arena = std.heap.ArenaAllocator.init(gpa);
        defer rg_arena.deinit();
        for (file.row_groups, 0..) |rg, gi| {
            if (r.stop) break;
            if (range) |sr| {
                const off = rg.startOffset();
                if (off < (sr.start orelse 0)) continue;
                if (sr.end) |e| if (off > e) continue;
            }
            _ = rg_arena.reset(.retain_capacity);
            const cols = try file.readRowGroupValues(rg_arena.allocator(), gi);
            var row: usize = 0;
            while (row < rg.num_rows and !r.stop) : (row += 1) {
                _ = r.row_arena.reset(.retain_capacity);
                const vals = try r.row_arena.allocator().alloc(Value, cols.len);
                for (cols, 0..) |c, ci| vals[ci] = c[row];
                try r.expand(.{ .object = .{ .keys = keys, .values = vals } }, r.steps, 0);
                try r.tick();
            }
        }
    }

    fn expand(r: *Run, v: Value, steps: []const ast.Step, depth: usize) RunError!void {
        if (r.stop) return;
        if (steps.len == 0) return r.record(v);
        switch (steps[0]) {
            .wildcard => switch (v) {
                .list => |l| for (l) |item| try r.expand(item, steps[1..], depth + 1),
                else => try r.expand(v, steps[1..], depth + 1),
            },
            else => {
                const next = try eval.walk(v, steps[0..1]);
                if (next != .missing) try r.expand(next, steps[1..], depth + 1);
            },
        }
    }

    fn record(r: *Run, rec: Value) RunError!void {
        const q = &r.sel.query;
        const env: eval.Env = .{ .arena = r.row_arena.allocator(), .record = rec, .alias = q.alias, .now = r.now };
        if (q.where) |w| if (!try eval.isTrue(&env, w)) return;
        if (q.isAggregate()) {
            for (q.aggregates, r.aggs) |node, *st| try st.update(r.sel.gpa, &env, node);
            return;
        }
        try r.project(&env);
    }

    fn project(r: *Run, env: *const eval.Env) RunError!void {
        const s = r.sel;
        const q = &s.query;
        const a = env.arena;
        const w = &r.rec.writer;
        if (q.items) |items| {
            const vals = try a.alloc(Value, items.len);
            for (items, 0..) |it, i| vals[i] = try eval.eval(env, it.expr);
            try output.writeRow(s.req.output, w, a, s.names, vals);
        } else switch (env.record) {
            .object => |o| try output.writeRow(s.req.output, w, a, o.keys, o.values),
            else => try output.writeRow(s.req.output, w, a, &.{"_1"}, &.{env.record}),
        }
        r.emitted += 1;
        if (q.limit) |l| if (r.emitted >= l) {
            r.stop = true;
        };
        if (r.rec.written().len >= s.opts.records_chunk_bytes) try r.flushRecords();
    }

    fn flushRecords(r: *Run) RunError!void {
        const data = r.rec.written();
        if (data.len == 0) return;
        var off: usize = 0;
        while (off < data.len) {
            const n = @min(data.len - off, eventstream.max_message_len / 2);
            try eventstream.writeEvent(r.out, "Records", "application/octet-stream", data[off .. off + n]);
            off += n;
        }
        r.returned += data.len;
        r.rec.clearRetainingCapacity();
        r.last_event_at = r.processed.?.n;
        if (r.sel.req.request_progress) try r.progress("Progress");
    }

    /// Keep-alive for long scans that produce no records.
    fn tick(r: *Run) RunError!void {
        const p = r.processed.?.n;
        if (p - r.last_event_at < r.sel.opts.cont_interval_bytes) return;
        r.last_event_at = p;
        if (r.sel.req.request_progress) return r.progress("Progress");
        try eventstream.writeEvent(r.out, "Cont", null, "");
    }

    fn progress(r: *Run, kind: []const u8) RunError!void {
        const st = r.stats();
        var buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&buf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{s}><BytesScanned>{d}</BytesScanned><BytesProcessed>{d}</BytesProcessed><BytesReturned>{d}</BytesReturned></{s}>", .{ kind, st.bytes_scanned, st.bytes_processed, st.bytes_returned, kind }) catch unreachable;
        try eventstream.writeEvent(r.out, kind, "text/xml", body);
    }
};

/// Test helper: runs a request and returns concatenated Records payloads.
pub fn runCollect(gpa: Allocator, req: request.Request, data: []const u8, opts: Options) ![]u8 {
    var sel = try Select.init(gpa, req, opts);
    defer sel.deinit();
    var in: std.Io.Reader = .fixed(data);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    _ = try sel.run(&in, &aw.writer);
    return collectRecords(gpa, aw.written());
}

pub fn collectRecords(gpa: Allocator, stream: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var rest = stream;
    var saw_end = false;
    while (rest.len > 0) {
        const m = try eventstream.decode(rest);
        rest = rest[m.len..];
        const et = m.header(":event-type") orelse return error.MissingEventType;
        if (std.mem.eql(u8, et, "Records")) try out.appendSlice(gpa, m.payload);
        if (std.mem.eql(u8, et, "End")) saw_end = true;
    }
    if (!saw_end) return error.MissingEnd;
    return out.toOwnedSlice(gpa);
}

const t = std.testing;

fn expectQuery(input: request.InputFormat, out_fmt: request.OutputFormat, sql: []const u8, data: []const u8, want: []const u8) !void {
    const got = try runCollect(t.allocator, .{ .expression = sql, .input = input, .output = out_fmt }, data, .{ .now_micros = 0 });
    defer t.allocator.free(got);
    try t.expectEqualStrings(want, got);
}

const people_csv =
    \\name,age,city,joined
    \\Alice,34,Paris,2019-03-01T
    \\Bob,27,"New York, NY",2021-07-15T
    \\Carol,41,London,2015-11-30T
    \\Dan,,Paris,2020-01-01T
    \\
;
const csv_use: request.InputFormat = .{ .csv = .{ .file_header_info = .use } };
const csv_out: request.OutputFormat = .{ .csv = .{} };
const json_out: request.OutputFormat = .{ .json = "\n" };

test "csv select where limit" {
    try expectQuery(csv_use, csv_out, "SELECT s.name, s.city FROM S3Object s WHERE s.city = 'Paris'", people_csv, "Alice,Paris\nDan,Paris\n");
    try expectQuery(csv_use, csv_out, "SELECT * FROM S3Object LIMIT 2", people_csv, "Alice,34,Paris,2019-03-01T\nBob,27,\"New York, NY\",2021-07-15T\n");
    try expectQuery(csv_use, json_out, "SELECT s._1 AS n, CAST(s.age AS INT) + 1 AS next FROM S3Object s WHERE s.age <> '' AND CAST(s.age AS INT) > 30", people_csv, "{\"n\":\"Alice\",\"next\":35}\n{\"n\":\"Carol\",\"next\":42}\n");
    try expectQuery(csv_use, csv_out, "SELECT UPPER(name), CHAR_LENGTH(city) FROM S3Object WHERE city LIKE '%York%'", people_csv, "BOB,12\n");
    try expectQuery(csv_use, csv_out, "SELECT name FROM S3Object s WHERE s.age = ''", people_csv, "Dan\n");
    try expectQuery(csv_use, csv_out, "SELECT name FROM S3Object WHERE EXTRACT(YEAR FROM TO_TIMESTAMP(joined)) BETWEEN 2019 AND 2020", people_csv, "Alice\nDan\n");
    try expectQuery(csv_use, csv_out, "SELECT name FROM S3Object LIMIT 0", people_csv, "");
}

test "csv aggregates" {
    try expectQuery(csv_use, csv_out, "SELECT COUNT(*), SUM(CAST(age AS INT)), MIN(age), MAX(name), AVG(CAST(age AS FLOAT)) FROM S3Object WHERE age <> ''", people_csv, "3,102,27,Carol,34\n");
    try expectQuery(csv_use, json_out, "SELECT COUNT(*) AS c FROM S3Object s WHERE s.city = 'Nowhere'", people_csv, "{\"c\":0}\n");
    try expectQuery(csv_use, json_out, "SELECT SUM(CAST(age AS INT)) AS c FROM S3Object s WHERE s.city = 'Nowhere'", people_csv, "{\"c\":null}\n");
}

test "json document and lines" {
    const doc =
        \\{"id": 1, "user": {"name": "a", "tags": ["x", "y"]}, "score": 1.5}
        \\{"id": 2, "user": {"name": "b", "tags": []}, "score": null}
        \\{"id": 3, "user": {"name": "c"}}
    ;
    try expectQuery(.{ .json = .lines }, json_out, "SELECT s.id, s.user.name FROM S3Object s WHERE s.score IS NOT NULL", doc, "{\"id\":1,\"name\":\"a\"}\n");
    try expectQuery(.{ .json = .document }, csv_out, "SELECT s.user.tags[1] FROM S3Object[*] s", doc, "y\n\n\n");
    try expectQuery(.{ .json = .document }, json_out, "SELECT s.user.tags[1] AS t FROM S3Object[*] s", doc, "{\"t\":\"y\"}\n{}\n{}\n");
    try expectQuery(.{ .json = .document }, json_out, "SELECT * FROM S3Object[*].user.tags[*] s", doc, "{\"_1\":\"x\"}\n{\"_1\":\"y\"}\n");
    try expectQuery(.{ .json = .document }, json_out, "SELECT s.a FROM S3Object[*] s", "[{\"a\":1},{\"a\":2}]", "{\"a\":1}\n{\"a\":2}\n");
    try expectQuery(.{ .json = .document }, csv_out, "SELECT COUNT(*), SUM(s.id) FROM S3Object s", doc, "3,6\n");
    try expectQuery(.{ .json = .lines }, json_out, "SELECT s.user FROM S3Object s LIMIT 1", doc, "{\"user\":{\"name\":\"a\",\"tags\":[\"x\",\"y\"]}}\n");
}

test "gzip input and stats events" {
    // gzip of "a,b\n1,2\n3,4\n" produced by python gzip.compress(mtime=0).
    const gz = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4b, 0xd4, 0x49, 0xe2, 0x32, 0xd4, 0x31, 0xe2, 0x32, 0xd6, 0x31, 0xe1, 0x02, 0x00, 0xe5, 0xe9, 0xd6, 0xce, 0x0c, 0x00, 0x00, 0x00 };
    const req: request.Request = .{ .expression = "SELECT b FROM S3Object", .compression = .gzip, .input = csv_use, .output = csv_out, .request_progress = true };
    var sel = try Select.init(t.allocator, req, .{});
    defer sel.deinit();
    var in: std.Io.Reader = .fixed(&gz);
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();
    const st = try sel.run(&in, &aw.writer);
    try t.expectEqual(@as(u64, gz.len), st.bytes_scanned);
    try t.expectEqual(@as(u64, 12), st.bytes_processed);
    try t.expectEqual(@as(u64, 4), st.bytes_returned);
    var rest = aw.written();
    var kinds: std.ArrayList(u8) = .empty;
    defer kinds.deinit(t.allocator);
    while (rest.len > 0) {
        const m = try eventstream.decode(rest);
        rest = rest[m.len..];
        try kinds.append(t.allocator, m.header(":event-type").?[0]);
        if (std.mem.eql(u8, m.header(":event-type").?, "Records")) try t.expectEqualStrings("2\n4\n", m.payload);
        if (std.mem.eql(u8, m.header(":event-type").?, "Stats")) try t.expect(std.mem.indexOf(u8, m.payload, "<BytesReturned>4</BytesReturned>") != null);
    }
    try t.expectEqualStrings("RPPSE", kinds.items);
}

test "runtime error emits error event" {
    const req: request.Request = .{ .expression = "SELECT 1 / 0 FROM S3Object", .input = csv_use, .output = csv_out };
    var sel = try Select.init(t.allocator, req, .{});
    defer sel.deinit();
    var in: std.Io.Reader = .fixed(people_csv);
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();
    try t.expectError(error.DivisionByZero, sel.run(&in, &aw.writer));
    const m = try eventstream.decode(aw.written());
    try t.expectEqualStrings("error", m.header(":message-type").?);
    try t.expectEqualStrings("EvaluatorDivisionByZero", m.header(":error-code").?);
}

test "corrupt gzip reports compression error" {
    const req: request.Request = .{ .expression = "SELECT * FROM S3Object", .compression = .gzip, .input = csv_use, .output = csv_out };
    var sel = try Select.init(t.allocator, req, .{});
    defer sel.deinit();
    var in: std.Io.Reader = .fixed("\x1f\x8b\x08\x00garbagegarbagegarbage");
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();
    try t.expectError(error.InvalidCompressedInput, sel.run(&in, &aw.writer));
}

test "xml request end to end" {
    const body =
        \\<SelectObjectContentRequest><Expression>SELECT s._2 FROM S3Object s WHERE s._1 = 'k'</Expression>
        \\<ExpressionType>SQL</ExpressionType><InputSerialization><CSV><FieldDelimiter>|</FieldDelimiter></CSV></InputSerialization>
        \\<OutputSerialization><JSON/></OutputSerialization></SelectObjectContentRequest>
    ;
    var sel = try Select.initXml(t.allocator, body, .{});
    defer sel.deinit();
    var in: std.Io.Reader = .fixed("k|v1\nx|v2\nk|v3\n");
    var aw: std.Io.Writer.Allocating = .init(t.allocator);
    defer aw.deinit();
    _ = try sel.run(&in, &aw.writer);
    const recs = try collectRecords(t.allocator, aw.written());
    defer t.allocator.free(recs);
    try t.expectEqualStrings("{\"_2\":\"v1\"}\n{\"_2\":\"v3\"}\n", recs);
}

test "json lines scan range" {
    // Lines start at 0, 8, 16, 24.
    const data = "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n{\"a\":4}\n";
    const req: request.Request = .{ .expression = "SELECT s.a FROM S3Object s", .input = .{ .json = .lines }, .output = csv_out, .scan_range = .{ .start = 3, .end = 16 } };
    const got = try runCollect(t.allocator, req, data, .{});
    defer t.allocator.free(got);
    try t.expectEqualStrings("2\n3\n", got);
}
