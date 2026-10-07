//! S3 Select results over pyarrow-written Parquet and text fixtures,
//! compared with DuckDB output (see tests/select/gen_fixtures.py).
const std = @import("std");
const select = @import("select");
const fixtures = @import("select/cases.zig");
const request = select.request;

fn run(input: request.InputFormat, compression: request.Compression, sql: []const u8, data: []const u8) ![]u8 {
    const req: request.Request = .{ .expression = sql, .compression = compression, .input = input, .output = .{ .csv = .{} } };
    return select.engine.runCollect(std.testing.allocator, req, data, .{ .now_micros = 0 });
}

fn check(label: []const u8, case: fixtures.Case, got: []const u8) !void {
    if (!std.mem.eql(u8, case.expected, got)) {
        std.debug.print("\nmismatch: {s} / {s}\nsql: {s}\n--- expected\n{s}--- got\n{s}\n", .{ label, case.name, case.sql, case.expected, got });
        return error.TestUnexpectedResult;
    }
}

test "parquet fixtures match duckdb" {
    inline for (fixtures.parquet_files) |file| {
        const data = @embedFile("select/fixtures/" ++ file);
        for (fixtures.cases) |case| {
            const got = try run(.parquet, .none, case.sql, data);
            defer std.testing.allocator.free(got);
            try check(file, case, got);
        }
    }
}

test "gzip csv fixture matches duckdb" {
    const data = @embedFile("select/fixtures/rows.csv.gz");
    for (fixtures.cases) |case| {
        if (!case.text_ok) continue;
        const got = try run(.{ .csv = .{ .file_header_info = .use } }, .gzip, case.sql, data);
        defer std.testing.allocator.free(got);
        try check("rows.csv.gz", case, got);
    }
}

test "json lines fixture matches duckdb" {
    const data = @embedFile("select/fixtures/rows.jsonl");
    for (fixtures.cases) |case| {
        if (!case.text_ok) continue;
        const got = try run(.{ .json = .lines }, .none, case.sql, data);
        defer std.testing.allocator.free(got);
        try check("rows.jsonl", case, got);
    }
}

test "truncated and corrupted parquet never panics" {
    const data = @embedFile("select/fixtures/dict_snappy.parquet");
    var buf: [data.len]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for (0..1500) |i| {
        @memcpy(&buf, data);
        var slice: []const u8 = &buf;
        if (i % 3 == 0) {
            slice = buf[0..rnd.uintLessThan(usize, data.len)];
        } else {
            for (0..1 + i % 8) |_| buf[rnd.uintLessThan(usize, data.len)] = rnd.int(u8);
        }
        if (run(.parquet, .none, "SELECT * FROM S3Object", slice)) |got| {
            std.testing.allocator.free(got);
        } else |_| {}
    }
}

test "random sql, csv and json input never panic" {
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    const words = [_][]const u8{ "SELECT", "*", "s", "s._1", "s.a", "FROM", "S3Object", "S3Object[*]", "WHERE", "AND", "OR", "NOT", "(", ")", ",", "=", "<", "+", "-", "/", "%", "||", "1", "0", "-9223372036854775808", "1e308", "'x'", "'%'", "LIKE", "BETWEEN", "IN", "IS", "NULL", "MISSING", "CAST", "AS", "INT", "COUNT", "SUM", "MIN", "(*)", "LIMIT", "CASE", "WHEN", "THEN", "END", "TRIM", "SUBSTRING", "UPPER", "EXTRACT", "YEAR", "DATE_ADD", "DATE_DIFF", "day", "TO_TIMESTAMP", "'2020T'", "UTCNOW()", "[", "]", ".", "\"q\"" };
    const inputs = [_][]const u8{ "a,b\n1,2\n\"x\"\"y\",\n", "{\"a\":[1,{\"b\":null}],\"s\":\"t\"}\n{\"a\":2}", "{\"a\":", "\"unterminated,\n", "[1,2,[3]]", "" };
    var sql_buf: [512]u8 = undefined;
    for (0..4000) |_| {
        var w: std.Io.Writer = .fixed(&sql_buf);
        const n = 1 + rnd.uintLessThan(usize, 16);
        if (rnd.boolean()) w.writeAll("SELECT ") catch unreachable;
        for (0..n) |_| {
            w.writeAll(words[rnd.uintLessThan(usize, words.len)]) catch break;
            w.writeByte(' ') catch break;
        }
        const sql = w.buffered();
        const data = inputs[rnd.uintLessThan(usize, inputs.len)];
        const input: request.InputFormat = switch (rnd.uintLessThan(u8, 3)) {
            0 => .{ .csv = .{ .file_header_info = .use } },
            1 => .{ .json = .document },
            else => .{ .json = .lines },
        };
        if (run(input, .none, sql, data)) |got| {
            std.testing.allocator.free(got);
        } else |_| {}
    }
}

test "valid queries over hostile values never panic" {
    const sqls = [_][]const u8{
        "SELECT CAST(s.a AS INT) * 9223372036854775807, s.a / 0.0, -s.a FROM S3Object s",
        "SELECT DATE_ADD(year, s.a, TO_TIMESTAMP('9999-12-31T')) FROM S3Object s",
        "SELECT DATE_ADD(second, s.a, UTCNOW()) FROM S3Object s",
        "SELECT SUBSTRING(s.b, s.a, s.a) FROM S3Object s",
        "SELECT SUM(s.a), AVG(s.a), MIN(s.b), MAX(s.b) FROM S3Object s",
        "SELECT ABS(s.a), s.a % -1 FROM S3Object s",
        "SELECT CAST(s.c AS TIMESTAMP), TO_STRING(TO_TIMESTAMP(s.c), 'yyyy MMMM dd a XXX') FROM S3Object s",
    };
    const data = "{\"a\":-9223372036854775808,\"b\":\"\xff\xfe\",\"c\":\"0000-01-01T00:00Z\"}\n{\"a\":9223372036854775807,\"b\":\"\",\"c\":\"9999-12-31T23:59:59.999999-23:59\"}\n{\"a\":1e308}\n";
    for (sqls) |sql| {
        if (run(.{ .json = .lines }, .none, sql, data)) |got| {
            std.testing.allocator.free(got);
        } else |_| {}
    }
}
