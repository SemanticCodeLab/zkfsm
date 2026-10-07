//! SelectObjectContentRequest XML body decoding.
const std = @import("std");
const xml = @import("xml.zig");

pub const Error = xml.Error || error{
    MissingRequiredParameter,
    InvalidExpressionType,
    InvalidCompressionFormat,
    InvalidFileHeaderInfo,
    InvalidJsonType,
    InvalidQuoteFields,
    InvalidRequestParameter,
    InvalidDataSource,
    InvalidScanRange,
    UnsupportedScanRangeInput,
};

pub const Compression = enum { none, gzip };
pub const FileHeaderInfo = enum { none, ignore, use };
pub const JsonType = enum { document, lines };
pub const QuoteFields = enum { asneeded, always };

pub const CsvInput = struct {
    file_header_info: FileHeaderInfo = .none,
    comments: ?u8 = null,
    quote_escape: u8 = '"',
    record_delimiter: []const u8 = "\n",
    field_delimiter: []const u8 = ",",
    quote: u8 = '"',
    allow_quoted_record_delimiter: bool = false,
};

pub const CsvOutput = struct {
    quote_fields: QuoteFields = .asneeded,
    quote_escape: u8 = '"',
    record_delimiter: []const u8 = "\n",
    field_delimiter: []const u8 = ",",
    quote: u8 = '"',
};

pub const InputFormat = union(enum) {
    csv: CsvInput,
    json: JsonType,
    parquet,
};

pub const OutputFormat = union(enum) {
    csv: CsvOutput,
    /// Record delimiter.
    json: []const u8,
};

/// Inclusive byte range; either side may be open.
pub const ScanRange = struct { start: ?u64 = null, end: ?u64 = null };

pub const Request = struct {
    expression: []const u8,
    compression: Compression = .none,
    input: InputFormat,
    output: OutputFormat,
    scan_range: ?ScanRange = null,
    request_progress: bool = false,
};

const max_delimiter_len = 8;

fn eqlUpper(s: []const u8, lit: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, s, " \t\r\n"), lit);
}

fn delimiter(text: ?[]const u8, default: []const u8) Error![]const u8 {
    const t = text orelse return default;
    if (t.len == 0) return default;
    if (t.len > max_delimiter_len) return error.InvalidRequestParameter;
    return t;
}

fn singleChar(text: ?[]const u8, default: u8) Error!u8 {
    const t = text orelse return default;
    if (t.len == 0) return default;
    if (t.len != 1) return error.InvalidRequestParameter;
    return t[0];
}

fn parseBoolText(t: []const u8) Error!bool {
    if (eqlUpper(t, "TRUE")) return true;
    if (eqlUpper(t, "FALSE")) return false;
    return error.InvalidRequestParameter;
}

/// Decodes the request body. Returned slices live in `arena`.
pub fn parse(arena: std.mem.Allocator, body: []const u8) Error!Request {
    const root = try xml.parse(arena, body, .{});
    if (!std.mem.eql(u8, root.name, "SelectObjectContentRequest")) return error.InvalidRequestParameter;
    const expr = root.childText("Expression") orelse return error.MissingRequiredParameter;
    if (std.mem.trim(u8, expr, " \t\r\n").len == 0) return error.MissingRequiredParameter;
    const et = root.childText("ExpressionType") orelse return error.MissingRequiredParameter;
    if (!eqlUpper(et, "SQL")) return error.InvalidExpressionType;

    const in_node = root.child("InputSerialization") orelse return error.MissingRequiredParameter;
    const out_node = root.child("OutputSerialization") orelse return error.MissingRequiredParameter;

    var req: Request = .{ .expression = expr, .input = undefined, .output = undefined };
    if (in_node.childText("CompressionType")) |c| {
        if (eqlUpper(c, "NONE") or c.len == 0) {
            req.compression = .none;
        } else if (eqlUpper(c, "GZIP")) {
            req.compression = .gzip;
        } else return error.InvalidCompressionFormat;
    }

    var formats: usize = 0;
    if (in_node.child("CSV")) |n| {
        formats += 1;
        var c: CsvInput = .{};
        if (n.childText("FileHeaderInfo")) |h| {
            c.file_header_info = if (eqlUpper(h, "USE")) .use else if (eqlUpper(h, "IGNORE")) .ignore else if (eqlUpper(h, "NONE") or h.len == 0) .none else return error.InvalidFileHeaderInfo;
        }
        if (n.childText("Comments")) |cm| c.comments = try singleChar(cm, 0);
        if (c.comments == 0) c.comments = null;
        c.quote_escape = try singleChar(n.childText("QuoteEscapeCharacter"), '"');
        c.record_delimiter = try delimiter(n.childText("RecordDelimiter"), "\n");
        c.field_delimiter = try delimiter(n.childText("FieldDelimiter"), ",");
        c.quote = try singleChar(n.childText("QuoteCharacter"), '"');
        if (n.childText("AllowQuotedRecordDelimiter")) |a| c.allow_quoted_record_delimiter = try parseBoolText(a);
        req.input = .{ .csv = c };
    }
    if (in_node.child("JSON")) |n| {
        formats += 1;
        const t = n.childText("Type") orelse "DOCUMENT";
        req.input = .{ .json = if (eqlUpper(t, "DOCUMENT")) .document else if (eqlUpper(t, "LINES")) .lines else return error.InvalidJsonType };
    }
    if (in_node.child("Parquet")) |_| {
        formats += 1;
        req.input = .parquet;
    }
    if (formats != 1) return error.InvalidDataSource;
    if (req.input == .parquet and req.compression != .none) return error.InvalidCompressionFormat;

    var outs: usize = 0;
    if (out_node.child("CSV")) |n| {
        outs += 1;
        var c: CsvOutput = .{};
        if (n.childText("QuoteFields")) |q| {
            c.quote_fields = if (eqlUpper(q, "ALWAYS")) .always else if (eqlUpper(q, "ASNEEDED") or q.len == 0) .asneeded else return error.InvalidQuoteFields;
        }
        c.quote_escape = try singleChar(n.childText("QuoteEscapeCharacter"), '"');
        c.record_delimiter = try delimiter(n.childText("RecordDelimiter"), "\n");
        c.field_delimiter = try delimiter(n.childText("FieldDelimiter"), ",");
        c.quote = try singleChar(n.childText("QuoteCharacter"), '"');
        req.output = .{ .csv = c };
    }
    if (out_node.child("JSON")) |n| {
        outs += 1;
        req.output = .{ .json = try delimiter(n.childText("RecordDelimiter"), "\n") };
    }
    if (outs != 1) return error.InvalidRequestParameter;

    if (root.child("RequestProgress")) |rp| {
        if (rp.childText("Enabled")) |e| req.request_progress = try parseBoolText(e);
    }
    if (root.child("ScanRange")) |sr| {
        var r: ScanRange = .{};
        if (sr.childText("Start")) |s| r.start = std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch return error.InvalidScanRange;
        if (sr.childText("End")) |s| r.end = std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10) catch return error.InvalidScanRange;
        if (r.start != null and r.end != null and r.start.? > r.end.?) return error.InvalidScanRange;
        if (req.compression != .none) return error.UnsupportedScanRangeInput;
        switch (req.input) {
            .csv => |c| if (c.allow_quoted_record_delimiter) return error.UnsupportedScanRangeInput,
            .json => |j| if (j == .document) return error.UnsupportedScanRangeInput,
            .parquet => {},
        }
        req.scan_range = r;
    }
    return req;
}

test "parse full csv request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const body =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<SelectObjectContentRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Expression>SELECT s._1 FROM S3Object s WHERE s._2 &gt; 3</Expression>
        \\  <ExpressionType>SQL</ExpressionType>
        \\  <RequestProgress><Enabled>TRUE</Enabled></RequestProgress>
        \\  <InputSerialization>
        \\    <CompressionType>NONE</CompressionType>
        \\    <CSV><FileHeaderInfo>USE</FileHeaderInfo><Comments>#</Comments><FieldDelimiter>;</FieldDelimiter></CSV>
        \\  </InputSerialization>
        \\  <OutputSerialization><JSON><RecordDelimiter>,</RecordDelimiter></JSON></OutputSerialization>
        \\  <ScanRange><Start>10</Start><End>100</End></ScanRange>
        \\</SelectObjectContentRequest>
    ;
    const r = try parse(arena.allocator(), body);
    try std.testing.expectEqualStrings("SELECT s._1 FROM S3Object s WHERE s._2 > 3", r.expression);
    try std.testing.expect(r.request_progress);
    try std.testing.expectEqual(FileHeaderInfo.use, r.input.csv.file_header_info);
    try std.testing.expectEqual(@as(?u8, '#'), r.input.csv.comments);
    try std.testing.expectEqualStrings(";", r.input.csv.field_delimiter);
    try std.testing.expectEqualStrings(",", r.output.json);
    try std.testing.expectEqual(@as(?u64, 10), r.scan_range.?.start);
}

test "request validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const head = "<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType>";
    try std.testing.expectError(error.InvalidCompressionFormat, parse(a, head ++ "<InputSerialization><CompressionType>BZIP2</CompressionType><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>"));
    try std.testing.expectError(error.InvalidDataSource, parse(a, head ++ "<InputSerialization><CSV/><JSON/></InputSerialization><OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>"));
    try std.testing.expectError(error.UnsupportedScanRangeInput, parse(a, head ++ "<InputSerialization><JSON><Type>DOCUMENT</Type></JSON></InputSerialization><OutputSerialization><CSV/></OutputSerialization><ScanRange><Start>1</Start></ScanRange></SelectObjectContentRequest>"));
    const ok = try parse(a, head ++ "<InputSerialization><CompressionType>GZIP</CompressionType><JSON><Type>LINES</Type></JSON></InputSerialization><OutputSerialization><CSV><QuoteFields>ALWAYS</QuoteFields></CSV></OutputSerialization></SelectObjectContentRequest>");
    try std.testing.expectEqual(JsonType.lines, ok.input.json);
    try std.testing.expectEqual(Compression.gzip, ok.compression);
    try std.testing.expectEqual(QuoteFields.always, ok.output.csv.quote_fields);
}
