//! Browser-form POST object uploads: streaming multipart/form-data reader,
//! POST policy parse/check, and response helpers (status, XML body, redirect).
const std = @import("std");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const ascii = std.ascii;

// ---------------------------------------------------------------- multipart

/// Returns the boundary parameter of a `multipart/form-data` content type.
pub fn boundaryFrom(content_type: []const u8) ?[]const u8 {
    const semi = std.mem.indexOfScalar(u8, content_type, ';') orelse return null;
    const mt = std.mem.trim(u8, content_type[0..semi], " \t");
    if (!ascii.eqlIgnoreCase(mt, "multipart/form-data")) return null;
    var rest = content_type[semi + 1 ..];
    while (true) {
        rest = std.mem.trimLeft(u8, rest, " \t;");
        if (rest.len == 0) return null;
        const eq = std.mem.indexOfScalar(u8, rest, '=') orelse return null;
        const pname = std.mem.trim(u8, rest[0..eq], " \t");
        rest = std.mem.trimLeft(u8, rest[eq + 1 ..], " \t");
        var value: []const u8 = undefined;
        if (rest.len > 0 and rest[0] == '"') {
            const close = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return null;
            value = rest[1..close];
            rest = rest[close + 1 ..];
        } else {
            const end = std.mem.indexOfAny(u8, rest, "; \t") orelse rest.len;
            value = rest[0..end];
            rest = rest[end..];
        }
        if (ascii.eqlIgnoreCase(pname, "boundary")) {
            if (value.len == 0 or value.len > max_boundary) return null;
            return value;
        }
    }
}

pub const max_boundary = 70;
const max_part_headers = 16;

pub const Part = struct {
    name: []const u8,
    filename: ?[]const u8,
    /// Empty when the part carries no Content-Type header.
    content_type: []const u8,
};

pub const Error = error{ MalformedForm, ReadFailed, OutOfMemory };
pub const InitError = error{ InvalidBoundary, BufferTooSmall };

/// Streams parts of a multipart/form-data body. After `nextPart` returns a
/// part, read its bytes from `reader` until EndOfStream. On ReadFailed from
/// `reader`, `failure` says whether the input was malformed or failed.
pub const FormReader = struct {
    in: *Reader,
    delim_buf: [max_boundary + 4]u8,
    delim_len: usize,
    state: State,
    failure: ?Error = null,
    reader: Reader,

    const State = enum { preamble, body, after_delim, done };

    /// `in` must buffer at least 2*(boundary.len+4) bytes; `buffer` backs `reader`.
    pub fn init(in: *Reader, boundary: []const u8, buffer: []u8) InitError!FormReader {
        if (boundary.len == 0 or boundary.len > max_boundary) return error.InvalidBoundary;
        if (in.buffer.len < 2 * (boundary.len + 4) or buffer.len == 0) return error.BufferTooSmall;
        var fr: FormReader = .{
            .in = in,
            .delim_buf = undefined,
            .delim_len = boundary.len + 4,
            .state = .preamble,
            .reader = .{
                .vtable = &.{ .stream = bodyStream },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
        @memcpy(fr.delim_buf[0..4], "\r\n--");
        @memcpy(fr.delim_buf[4..fr.delim_len], boundary);
        return fr;
    }

    fn delim(self: *const FormReader) []const u8 {
        return self.delim_buf[0..self.delim_len];
    }

    /// Advances to the next part (skipping unread body bytes); null after the
    /// closing delimiter. Header strings are copied into `arena`.
    pub fn nextPart(self: *FormReader, arena: Allocator) Error!?Part {
        if (self.failure) |e| return e;
        switch (self.state) {
            .done => return null,
            .preamble => {
                const first = self.delim()[2..];
                const head = self.in.peek(first.len) catch |e| return self.fail(e);
                if (std.mem.eql(u8, head, first)) {
                    self.in.toss(first.len);
                    self.state = .after_delim;
                } else {
                    self.state = .body;
                    try self.drain();
                }
            },
            .body => try self.drain(),
            .after_delim => {},
        }
        self.reader.seek = 0;
        self.reader.end = 0;
        const two = self.in.peek(2) catch |e| return self.fail(e);
        if (std.mem.eql(u8, two, "--")) {
            self.in.toss(2);
            self.state = .done;
            return null;
        }
        while (true) {
            const b = self.in.peekByte() catch |e| return self.fail(e);
            if (b != ' ' and b != '\t') break;
            self.in.toss(1);
        }
        const crlf = self.in.take(2) catch |e| return self.fail(e);
        if (!std.mem.eql(u8, crlf, "\r\n")) return self.setFail(error.MalformedForm);
        const part = try self.readHeaders(arena);
        self.state = .body;
        return part;
    }

    fn readHeaders(self: *FormReader, arena: Allocator) Error!Part {
        var name: ?[]const u8 = null;
        var filename: ?[]const u8 = null;
        var ctype: []const u8 = "";
        var count: usize = 0;
        while (true) {
            const line = self.in.takeDelimiterInclusive('\n') catch |e| switch (e) {
                error.ReadFailed => return self.setFail(error.ReadFailed),
                error.EndOfStream, error.StreamTooLong => return self.setFail(error.MalformedForm),
            };
            if (line.len < 2 or line[line.len - 2] != '\r') return self.setFail(error.MalformedForm);
            const text = line[0 .. line.len - 2];
            if (text.len == 0) break;
            count += 1;
            if (count > max_part_headers) return self.setFail(error.MalformedForm);
            const colon = std.mem.indexOfScalar(u8, text, ':') orelse return self.setFail(error.MalformedForm);
            const hname = std.mem.trim(u8, text[0..colon], " \t");
            const hval = std.mem.trim(u8, text[colon + 1 ..], " \t");
            if (ascii.eqlIgnoreCase(hname, "content-disposition")) {
                const cd = parseDisposition(arena, hval) catch |e| return self.setFail(e);
                name = cd.name;
                filename = cd.filename;
            } else if (ascii.eqlIgnoreCase(hname, "content-type")) {
                ctype = arena.dupe(u8, hval) catch return self.setFail(error.OutOfMemory);
            }
        }
        return .{
            .name = name orelse return self.setFail(error.MalformedForm),
            .filename = filename,
            .content_type = ctype,
        };
    }

    fn drain(self: *FormReader) Error!void {
        while (try self.nextChunk()) |chunk| self.in.toss(chunk.len);
    }

    /// Next run of body bytes still buffered in `in` (caller tosses what it
    /// consumes); null once the delimiter is consumed.
    fn nextChunk(self: *FormReader) Error!?[]const u8 {
        if (self.failure) |e| return e;
        if (self.state != .body) return null;
        const d = self.delim();
        const in = self.in;
        while (true) {
            const buf = in.buffered();
            if (std.mem.indexOf(u8, buf, d)) |i| {
                if (i > 0) return buf[0..i];
                in.toss(d.len);
                self.state = .after_delim;
                return null;
            }
            const safe = buf.len -| (d.len - 1);
            if (safe > 0 and (safe >= in.buffer.len / 2 or buf.len == in.buffer.len)) return buf[0..safe];
            in.fillMore() catch |e| switch (e) {
                error.EndOfStream => {
                    if (safe > 0) return buf[0..safe];
                    return self.setFail(error.MalformedForm);
                },
                error.ReadFailed => return self.setFail(error.ReadFailed),
            };
        }
    }

    fn bodyStream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *FormReader = @alignCast(@fieldParentPtr("reader", r));
        const chunk = (self.nextChunk() catch return error.ReadFailed) orelse return error.EndOfStream;
        const n = try w.write(chunk[0..limit.minInt(chunk.len)]);
        self.in.toss(n);
        return n;
    }

    fn fail(self: *FormReader, e: Reader.Error) Error {
        return self.setFail(switch (e) {
            error.EndOfStream => error.MalformedForm,
            error.ReadFailed => error.ReadFailed,
        });
    }

    fn setFail(self: *FormReader, e: Error) Error {
        self.failure = e;
        return e;
    }
};

const Disposition = struct { name: ?[]const u8 = null, filename: ?[]const u8 = null };

fn parseDisposition(arena: Allocator, v: []const u8) Error!Disposition {
    var out: Disposition = .{};
    const semi = std.mem.indexOfScalar(u8, v, ';') orelse v.len;
    if (!ascii.eqlIgnoreCase(std.mem.trim(u8, v[0..semi], " \t"), "form-data")) return error.MalformedForm;
    var i = semi;
    while (i < v.len) {
        while (i < v.len and (v[i] == ';' or v[i] == ' ' or v[i] == '\t')) i += 1;
        if (i >= v.len) break;
        const eq = std.mem.indexOfScalarPos(u8, v, i, '=') orelse return error.MalformedForm;
        const key = std.mem.trim(u8, v[i..eq], " \t");
        i = eq + 1;
        var val: std.ArrayList(u8) = .empty;
        if (i < v.len and v[i] == '"') {
            i += 1;
            while (true) {
                if (i >= v.len) return error.MalformedForm;
                const c = v[i];
                i += 1;
                if (c == '"') break;
                if (c == '\\' and i < v.len) {
                    try val.append(arena, v[i]);
                    i += 1;
                } else try val.append(arena, c);
            }
        } else {
            const end = std.mem.indexOfScalarPos(u8, v, i, ';') orelse v.len;
            try val.appendSlice(arena, std.mem.trim(u8, v[i..end], " \t"));
            i = end;
        }
        if (ascii.eqlIgnoreCase(key, "name")) {
            out.name = val.items;
        } else if (ascii.eqlIgnoreCase(key, "filename")) {
            out.filename = val.items;
        }
    }
    return out;
}

// ---------------------------------------------------------------- policy

pub const Field = struct { name: []const u8, value: []const u8 };

pub const Condition = union(enum) {
    /// `field` is lowercase without the leading `$`.
    eq: struct { field: []const u8, value: []const u8 },
    starts_with: struct { field: []const u8, prefix: []const u8 },
    length_range: struct { min: u64, max: u64 },
};

pub const PolicyError = error{ MalformedPolicy, OutOfMemory };
pub const CheckError = error{ PolicyExpired, ConditionFailed };
pub const LengthError = error{ EntityTooLarge, EntityTooSmall };

pub const Policy = struct {
    expiration: i64,
    conditions: []const Condition,

    /// Decodes the base64 `policy` form field; allocations live in `arena`.
    pub fn parse(arena: Allocator, b64: []const u8) PolicyError!Policy {
        const dec = std.base64.standard.Decoder;
        const trimmed = std.mem.trim(u8, b64, " \t\r\n");
        const n = dec.calcSizeForSlice(trimmed) catch return error.MalformedPolicy;
        const raw = try arena.alloc(u8, n);
        dec.decode(raw, trimmed) catch return error.MalformedPolicy;
        const root = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedPolicy,
        };
        if (root != .object) return error.MalformedPolicy;
        // Top-level keys are case-sensitive.
        const exp_v = root.object.get("expiration") orelse return error.MalformedPolicy;
        if (exp_v != .string) return error.MalformedPolicy;
        const expiration = parseIso8601(exp_v.string) orelse return error.MalformedPolicy;
        const conds_v = root.object.get("conditions") orelse return error.MalformedPolicy;
        if (conds_v != .array) return error.MalformedPolicy;

        var list: std.ArrayList(Condition) = .empty;
        for (conds_v.array.items) |c| switch (c) {
            .object => |obj| {
                if (obj.count() == 0) return error.MalformedPolicy;
                var it = obj.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* != .string) return error.MalformedPolicy;
                    try list.append(arena, .{ .eq = .{
                        .field = try lowerField(arena, kv.key_ptr.*),
                        .value = kv.value_ptr.string,
                    } });
                }
            },
            .array => |arr| try list.append(arena, try parseArrayCond(arena, arr.items)),
            else => return error.MalformedPolicy,
        };
        return .{ .expiration = expiration, .conditions = list.items };
    }

    /// Checks expiry and every condition, and that each non-exempt field is
    /// covered by a condition. `fields` must include `bucket` and the final key.
    pub fn check(self: *const Policy, fields: []const Field, now_s: i64) CheckError!void {
        if (now_s >= self.expiration) return error.PolicyExpired;
        for (self.conditions) |c| switch (c) {
            .eq => |e| {
                const v = fieldValue(fields, e.field) orelse return error.ConditionFailed;
                if (!std.mem.eql(u8, v, e.value)) return error.ConditionFailed;
            },
            .starts_with => |s| {
                const v = fieldValue(fields, s.field) orelse return error.ConditionFailed;
                if (ascii.eqlIgnoreCase(s.field, "content-type")) {
                    var it = std.mem.splitScalar(u8, v, ',');
                    while (it.next()) |piece| {
                        const p = std.mem.trim(u8, piece, " \t");
                        if (!std.mem.startsWith(u8, p, s.prefix)) return error.ConditionFailed;
                    }
                } else if (!std.mem.startsWith(u8, v, s.prefix)) return error.ConditionFailed;
            },
            .length_range => {},
        };
        for (fields) |f| {
            if (isExempt(f.name)) continue;
            if (!self.covers(f.name)) return error.ConditionFailed;
        }
    }

    fn covers(self: *const Policy, name: []const u8) bool {
        for (self.conditions) |c| switch (c) {
            .eq => |e| if (ascii.eqlIgnoreCase(e.field, name)) return true,
            .starts_with => |s| if (ascii.eqlIgnoreCase(s.field, name)) return true,
            .length_range => {},
        };
        return false;
    }

    pub const Range = struct { min: u64, max: u64 };

    /// The tightest content-length-range, if any; enforce while streaming.
    pub fn contentLengthRange(self: *const Policy) ?Range {
        var out: ?Range = null;
        for (self.conditions) |c| switch (c) {
            .length_range => |r| {
                if (out) |*o| {
                    o.min = @max(o.min, r.min);
                    o.max = @min(o.max, r.max);
                } else out = .{ .min = r.min, .max = r.max };
            },
            else => {},
        };
        return out;
    }

    /// Checks a final (or running, with `final=false`) upload size.
    pub fn checkLength(self: *const Policy, size: u64, final: bool) LengthError!void {
        const r = self.contentLengthRange() orelse return;
        if (size > r.max) return error.EntityTooLarge;
        if (final and size < r.min) return error.EntityTooSmall;
    }
};

/// Form fields never subject to the coverage rule.
pub fn isExempt(name: []const u8) bool {
    const exact = [_][]const u8{ "policy", "signature", "x-amz-signature", "awsaccesskeyid", "file" };
    for (exact) |e| if (ascii.eqlIgnoreCase(name, e)) return true;
    return startsWithIgnoreCase(name, "x-ignore-") or startsWithIgnoreCase(name, "x-amz-checksum-");
}

/// Case-insensitive lookup of a form field.
pub fn fieldValue(fields: []const Field, name: []const u8) ?[]const u8 {
    for (fields) |f| if (ascii.eqlIgnoreCase(f.name, name)) return f.value;
    return null;
}

/// Replaces every `${filename}` in `key` with the file part's filename.
pub fn substituteFilename(arena: Allocator, key: []const u8, filename: []const u8) Allocator.Error![]const u8 {
    return std.mem.replaceOwned(u8, arena, key, "${filename}", filename);
}

fn startsWithIgnoreCase(s: []const u8, prefix: []const u8) bool {
    return s.len >= prefix.len and ascii.eqlIgnoreCase(s[0..prefix.len], prefix);
}

fn lowerField(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    return ascii.allocLowerString(arena, name);
}

fn parseArrayCond(arena: Allocator, items: []const std.json.Value) PolicyError!Condition {
    if (items.len == 0 or items[0] != .string) return error.MalformedPolicy;
    const op = items[0].string;
    if (ascii.eqlIgnoreCase(op, "content-length-range")) {
        if (items.len != 3) return error.MalformedPolicy;
        const min = jsonU64(items[1]) orelse return error.MalformedPolicy;
        const max = jsonU64(items[2]) orelse return error.MalformedPolicy;
        if (min > max) return error.MalformedPolicy;
        return .{ .length_range = .{ .min = min, .max = max } };
    }
    if (items.len != 3 or items[1] != .string or items[2] != .string) return error.MalformedPolicy;
    const f = items[1].string;
    if (f.len < 2 or f[0] != '$') return error.MalformedPolicy;
    const field = try lowerField(arena, f[1..]);
    if (ascii.eqlIgnoreCase(op, "eq")) return .{ .eq = .{ .field = field, .value = items[2].string } };
    if (ascii.eqlIgnoreCase(op, "starts-with")) return .{ .starts_with = .{ .field = field, .prefix = items[2].string } };
    return error.MalformedPolicy;
}

fn jsonU64(v: std.json.Value) ?u64 {
    return switch (v) {
        .integer => |i| if (i < 0) null else @intCast(i),
        .string, .number_string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff]Z` to unix seconds.
pub fn parseIso8601(s: []const u8) ?i64 {
    if (s.len < 20 or s[s.len - 1] != 'Z') return null;
    if (s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    const frac = s[19 .. s.len - 1];
    if (frac.len > 0) {
        if (frac.len < 2 or frac.len > 10 or frac[0] != '.') return null;
        for (frac[1..]) |c| if (!ascii.isDigit(c)) return null;
    }
    const y = digits(s[0..4]) orelse return null;
    const mo = digits(s[5..7]) orelse return null;
    const d = digits(s[8..10]) orelse return null;
    const h = digits(s[11..13]) orelse return null;
    const mi = digits(s[14..16]) orelse return null;
    const sec = digits(s[17..19]) orelse return null;
    if (mo < 1 or mo > 12 or d < 1 or h > 23 or mi > 59 or sec > 59) return null;
    const leap = (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
    const mdays = [_]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (d > mdays[@intCast(mo - 1)]) return null;
    // Days from civil (proleptic Gregorian).
    const yy = if (mo <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = if (mo > 2) mo - 3 else mo + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + h * 3600 + mi * 60 + sec;
}

fn digits(s: []const u8) ?i64 {
    var v: i64 = 0;
    for (s) |c| {
        if (!ascii.isDigit(c)) return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

// ---------------------------------------------------------------- responses

pub const Status = struct { status: u16, code: []const u8, message: []const u8 };

pub const AnyError = Error || PolicyError || CheckError || LengthError;

/// Maps this module's errors to S3 error responses.
pub fn s3Status(err: AnyError) Status {
    return switch (err) {
        error.PolicyExpired => .{ .status = 403, .code = "AccessDenied", .message = "Invalid according to Policy: Policy expired." },
        error.ConditionFailed => .{ .status = 403, .code = "AccessDenied", .message = "Invalid according to Policy: Policy Condition failed." },
        error.MalformedPolicy => .{ .status = 400, .code = "InvalidPolicyDocument", .message = "Invalid Policy: Invalid JSON." },
        error.EntityTooLarge => .{ .status = 400, .code = "EntityTooLarge", .message = "Your proposed upload exceeds the maximum allowed size." },
        error.EntityTooSmall => .{ .status = 400, .code = "EntityTooSmall", .message = "Your proposed upload is smaller than the minimum allowed size." },
        error.MalformedForm => .{ .status = 400, .code = "MalformedPOSTRequest", .message = "The body of your POST request is not well-formed multipart/form-data." },
        error.ReadFailed => .{ .status = 400, .code = "IncompleteBody", .message = "The request body could not be read." },
        error.OutOfMemory => .{ .status = 500, .code = "InternalError", .message = "We encountered an internal error. Please try again." },
    };
}

/// Base64 HMAC-SHA1 of the base64 policy (signature V2). For V4 the string
/// to sign is the base64 policy itself, signed with the SigV4 signing key.
pub fn signV2(secret: []const u8, policy_b64: []const u8) [28]u8 {
    const H = std.crypto.auth.hmac.HmacSha1;
    var mac: [H.mac_length]u8 = undefined;
    H.create(&mac, policy_b64, secret);
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &mac);
    return out;
}

/// success_action_status: 200/201/204, anything else -> 204.
pub fn successStatus(field: ?[]const u8) u16 {
    const v = field orelse return 204;
    if (std.mem.eql(u8, v, "200")) return 200;
    if (std.mem.eql(u8, v, "201")) return 201;
    return 204;
}

/// Writes the 201 `PostResponse` body; `etag` is written as given (quoted).
pub fn writePostResponse(w: *Writer, location: []const u8, bucket: []const u8, key: []const u8, etag: []const u8) Writer.Error!void {
    try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse><Location>");
    try xmlEscape(w, location);
    try w.writeAll("</Location><Bucket>");
    try xmlEscape(w, bucket);
    try w.writeAll("</Bucket><Key>");
    try xmlEscape(w, key);
    try w.writeAll("</Key><ETag>");
    try xmlEscape(w, etag);
    try w.writeAll("</ETag></PostResponse>");
}

fn xmlEscape(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&apos;"),
        else => try w.writeByte(c),
    };
}

/// success_action_redirect target: `url?bucket=..&key=..&etag="<etag>"`
/// (percent-encoded); `etag` is given without quotes.
pub fn redirectUrl(gpa: Allocator, url: []const u8, bucket: []const u8, key: []const u8, etag: []const u8) Allocator.Error![]u8 {
    var aw: Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;
    buildRedirect(w, url, bucket, key, etag) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

fn buildRedirect(w: *Writer, url: []const u8, bucket: []const u8, key: []const u8, etag: []const u8) Writer.Error!void {
    try w.writeAll(url);
    try w.writeByte(if (std.mem.indexOfScalar(u8, url, '?') == null) '?' else '&');
    try w.writeAll("bucket=");
    try urlEncode(w, bucket);
    try w.writeAll("&key=");
    try urlEncode(w, key);
    try w.writeAll("&etag=%22");
    try urlEncode(w, etag);
    try w.writeAll("%22");
}

fn urlEncode(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| {
        if (ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try w.writeByte(c);
        } else try w.print("%{X:0>2}", .{c});
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// Test reader yielding 1..7 bytes per underlying read.
const Trickle = struct {
    src: []const u8,
    pos: usize = 0,
    step: usize = 0,
    r: Reader,

    fn init(src: []const u8, buf: []u8) Trickle {
        return .{ .src = src, .r = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const t: *Trickle = @alignCast(@fieldParentPtr("r", r));
        if (t.pos >= t.src.len) return error.EndOfStream;
        t.step += 1;
        const want = 1 + (t.step * 5) % 7;
        const n = @min(want, t.src.len - t.pos);
        const k = try w.write(t.src[t.pos..][0..limit.minInt(n)]);
        t.pos += k;
        return k;
    }
};

const sample_body = "preamble junk\r\n" ++
    "--XyZ\r\n" ++
    "Content-Disposition: form-data; name=\"key\"\r\n\r\n" ++
    "foo.txt\r\n" ++
    "--XyZ\r\n" ++
    "content-disposition: form-data; name=\"tricky\"\r\n\r\n" ++
    "a\r\n--XyY\r\n--Xy\r\n-\r\n" ++
    "--XyZ \t\r\n" ++
    "CONTENT-DISPOSITION: form-data; name=\"file\"; filename=\"a \\\"b\\\".txt\"\r\n" ++
    "Content-Type: text/plain\r\n\r\n" ++
    "hello\r\nworld\r\n" ++
    "--XyZ--\r\nepilogue";

fn collect(arena: Allocator, fr: *FormReader) !std.ArrayList([2][]const u8) {
    var out: std.ArrayList([2][]const u8) = .empty;
    while (try fr.nextPart(arena)) |p| {
        const body = try fr.reader.allocRemaining(arena, .limited(1 << 20));
        try out.append(arena, .{ p.name, body });
    }
    return out;
}

test "form parse: trickle reader, split delimiters" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]usize{ 96, 97, 101, 128, 4096 }) |bufsz| {
        const inbuf = try arena.alloc(u8, bufsz);
        var t = Trickle.init(sample_body, inbuf);
        var rb: [3]u8 = undefined;
        var fr = try FormReader.init(&t.r, "XyZ", &rb);
        const parts = try collect(arena, &fr);
        try testing.expectEqual(@as(usize, 3), parts.items.len);
        try testing.expectEqualStrings("key", parts.items[0][0]);
        try testing.expectEqualStrings("foo.txt", parts.items[0][1]);
        try testing.expectEqualStrings("a\r\n--XyY\r\n--Xy\r\n-", parts.items[1][1]);
        try testing.expectEqualStrings("file", parts.items[2][0]);
        try testing.expectEqualStrings("hello\r\nworld", parts.items[2][1]);
        try testing.expectEqual(@as(?Part, null), try fr.nextPart(arena));
    }
}

test "form parse: filename, content type, skip unread body" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var inbuf: [100]u8 = undefined;
    var t = Trickle.init(sample_body, &inbuf);
    var rb: [8]u8 = undefined;
    var fr = try FormReader.init(&t.r, "XyZ", &rb);
    _ = (try fr.nextPart(arena)).?;
    _ = (try fr.nextPart(arena)).?;
    const f = (try fr.nextPart(arena)).?;
    try testing.expectEqualStrings("a \"b\".txt", f.filename.?);
    try testing.expectEqualStrings("text/plain", f.content_type);
    try testing.expect((try fr.nextPart(arena)) == null);
}

test "form parse: large streamed part with bounded buffers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const payload = try arena.alloc(u8, 100_000);
    for (payload, 0..) |*b, i| b.* = if (i % 97 == 0) '\r' else if (i % 89 == 0) '-' else 'x';
    const body = try std.mem.concat(arena, u8, &.{ "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n", payload, "\r\n--b--" });
    var inbuf: [64]u8 = undefined;
    var t = Trickle.init(body, &inbuf);
    var rb: [16]u8 = undefined;
    var fr = try FormReader.init(&t.r, "b", &rb);
    _ = (try fr.nextPart(arena)).?;
    var hasher = std.hash.Wyhash.init(0);
    var total: usize = 0;
    var chunk: [37]u8 = undefined;
    while (true) {
        const n = try fr.reader.readSliceShort(&chunk);
        hasher.update(chunk[0..n]);
        total += n;
        if (n < chunk.len) break;
    }
    try testing.expectEqual(payload.len, total);
    try testing.expectEqual(std.hash.Wyhash.hash(0, payload), hasher.final());
    try testing.expect((try fr.nextPart(arena)) == null);
}

test "form parse: malformed inputs" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_][]const u8{
        "",
        "--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nunterminated",
        "--b\r\nContent-Disposition: form-data\r\n\r\nv\r\n--b--",
        "--b\r\nNoColonHere\r\n\r\nv\r\n--b--",
        "--b\r\nContent-Disposition: attachment; name=\"x\"\r\n\r\nv\r\n--b--",
        "--bX\r\n",
        "--b\nContent-Disposition: form-data; name=x\n\nv\n--b--",
    };
    for (cases) |c| {
        var inbuf: [64]u8 = undefined;
        var t = Trickle.init(c, &inbuf);
        var rb: [4]u8 = undefined;
        var fr = try FormReader.init(&t.r, "b", &rb);
        const res = blk: {
            while (fr.nextPart(arena) catch |e| break :blk e) |_| {
                _ = fr.reader.discardRemaining() catch break :blk fr.failure.?;
            }
            break :blk error.NoError;
        };
        try testing.expectEqual(error.MalformedForm, res);
    }
    var small: [8]u8 = undefined;
    var t2 = Trickle.init("", &small);
    var rb2: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, FormReader.init(&t2.r, "boundary", &rb2));
    try testing.expectError(error.InvalidBoundary, FormReader.init(&t2.r, "", &rb2));
}

test "boundaryFrom" {
    try testing.expectEqualStrings("abc", boundaryFrom("multipart/form-data; boundary=abc").?);
    try testing.expectEqualStrings("a b;c", boundaryFrom("Multipart/Form-Data; charset=utf-8; BOUNDARY=\"a b;c\"").?);
    try testing.expectEqualStrings("x", boundaryFrom("multipart/form-data;boundary=x; foo=bar").?);
    try testing.expect(boundaryFrom("multipart/mixed; boundary=abc") == null);
    try testing.expect(boundaryFrom("multipart/form-data") == null);
    try testing.expect(boundaryFrom("multipart/form-data; boundary=") == null);
    try testing.expect(boundaryFrom("multipart/form-data; boundary=\"open") == null);
}

fn toB64(arena: Allocator, json: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(json.len));
    return enc.encode(out, json);
}

const good_policy =
    \\{"expiration": "2026-10-06T12:00:00Z", "conditions": [
    \\ {"bUcKeT": "bkt"}, ["StArTs-WiTh", "$KeY", "foo"], {"acl": "private"},
    \\ ["starts-with", "$Content-Type", "text/plain"], ["content-length-range", 0, "1024"],
    \\ ["eq", "$success_action_redirect", "http://x/y"]]}
;

const good_fields = [_]Field{
    .{ .name = "bucket", .value = "bkt" },
    .{ .name = "kEy", .value = "foo.txt" },
    .{ .name = "aCl", .value = "private" },
    .{ .name = "pOLICy", .value = "..." },
    .{ .name = "AWSAccessKeyId", .value = "AK" },
    .{ .name = "signature", .value = "sig" },
    .{ .name = "Content-Type", .value = "text/plain" },
    .{ .name = "success_action_redirect", .value = "http://x/y" },
    .{ .name = "x-ignore-foo", .value = "bar" },
    .{ .name = "x-amz-checksum-sha256", .value = "abc" },
};

test "policy parse and check" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = try Policy.parse(arena, try toB64(arena, good_policy));
    try testing.expectEqual(@as(i64, 1791288000), p.expiration);
    try testing.expectEqual(@as(usize, 6), p.conditions.len);
    const now: i64 = 1791288000 - 10;
    try p.check(&good_fields, now);
    try testing.expectError(error.PolicyExpired, p.check(&good_fields, now + 10));

    var f = good_fields;
    f[0].value = "other"; // wrong bucket
    try testing.expectError(error.ConditionFailed, p.check(&f, now));
    f = good_fields;
    f[1].value = "bar.txt";
    try testing.expectError(error.ConditionFailed, p.check(&f, now));
    // Uncovered field.
    const extra = good_fields ++ [_]Field{.{ .name = "x-amz-meta-foo", .value = "v" }};
    try testing.expectError(error.ConditionFailed, p.check(&extra, now));
    // Condition on a missing field.
    try testing.expectError(error.ConditionFailed, p.check(good_fields[0..6], now));

    const r = p.contentLengthRange().?;
    try testing.expectEqual(@as(u64, 1024), r.max);
    try p.checkLength(1024, true);
    try testing.expectError(error.EntityTooLarge, p.checkLength(1025, false));
}

test "policy content-length and content-type lists" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const p = try Policy.parse(arena, try toB64(arena,
        \\{"expiration":"2030-01-01T00:00:00.000Z","conditions":[["content-length-range",512,1000],
        \\["starts-with","$Content-Type","image/"],{"bucket":"b"}]}
    ));
    try testing.expectError(error.EntityTooSmall, p.checkLength(3, true));
    try p.checkLength(3, false);
    const ok = [_]Field{ .{ .name = "bucket", .value = "b" }, .{ .name = "content-type", .value = "image/png, image/gif" } };
    try p.check(&ok, 0);
    const bad = [_]Field{ .{ .name = "bucket", .value = "b" }, .{ .name = "content-type", .value = "image/png,text/x" } };
    try testing.expectError(error.ConditionFailed, p.check(&bad, 0));
}

test "policy malformed documents" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bad = [_][]const u8{
        \\{"EXPIRATION":"2030-01-01T00:00:00Z","conditions":[{"bucket":"b"}]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","CONDITIONS":[{"bucket":"b"}]}
        ,
        \\{"conditions":[{"bucket":"b"}]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z"}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[{}]}
        ,
        \\{"expiration":"2030-01-01 00:00:00.123456+00:00","conditions":[]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["content-length-range",0]]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["content-length-range",-1,0]]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["content-length-range",5,1]]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["matches","$key","x"]]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["eq","key","x"]]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[{"bucket":5}]}
        ,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[["eq","$key"]]}
        ,
        \\[1,2]
        ,
        \\{not json
    };
    for (bad) |doc| {
        try testing.expectError(error.MalformedPolicy, Policy.parse(arena, try toB64(arena, doc)));
    }
    try testing.expectError(error.MalformedPolicy, Policy.parse(arena, "!!!notbase64"));
    // Empty list parses; coverage then fails on bucket.
    const p = try Policy.parse(arena, try toB64(arena,
        \\{"expiration":"2030-01-01T00:00:00Z","conditions":[]}
    ));
    try testing.expectError(error.ConditionFailed, p.check(&.{.{ .name = "bucket", .value = "b" }}, 0));
}

test "parseIso8601" {
    try testing.expectEqual(@as(?i64, 0), parseIso8601("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 951782400), parseIso8601("2000-02-29T00:00:00.5Z"));
    try testing.expectEqual(@as(?i64, 1791288000), parseIso8601("2026-10-06T12:00:00.000Z"));
    try testing.expect(parseIso8601("2026-02-29T00:00:00Z") == null);
    try testing.expect(parseIso8601("2026-13-01T00:00:00Z") == null);
    try testing.expect(parseIso8601("2026-10-06T24:00:00Z") == null);
    try testing.expect(parseIso8601("2026-10-06T12:00:00") == null);
    try testing.expect(parseIso8601("2026-10-06T12:00:00.Z") == null);
    try testing.expect(parseIso8601("2026-10-06T12:00:00+00:00") == null);
}

test "signV2 and success helpers" {
    // RFC 2202 test case 2 for HMAC-SHA1.
    const sig = signV2("Jefe", "what do ya want for nothing?");
    try testing.expectEqualStrings("7/zfauXrL6LSdBbV8YTfnCWafHk=", &sig);
    try testing.expectEqual(@as(u16, 204), successStatus(null));
    try testing.expectEqual(@as(u16, 201), successStatus("201"));
    try testing.expectEqual(@as(u16, 200), successStatus("200"));
    try testing.expectEqual(@as(u16, 204), successStatus("404"));
    try testing.expectEqual(@as(u16, 403), s3Status(error.ConditionFailed).status);
    try testing.expectEqual(@as(u16, 400), s3Status(error.EntityTooLarge).status);

    const url = try redirectUrl(testing.allocator, "http://h/p", "bkt", "a b&c.txt", "abc");
    defer testing.allocator.free(url);
    try testing.expectEqualStrings("http://h/p?bucket=bkt&key=a%20b%26c.txt&etag=%22abc%22", url);
    const url2 = try redirectUrl(testing.allocator, "http://h/p?x=1", "b", "k", "e");
    defer testing.allocator.free(url2);
    try testing.expectEqualStrings("http://h/p?x=1&bucket=b&key=k&etag=%22e%22", url2);

    var buf: [512]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writePostResponse(&w, "http://h/b/k", "b", "a<b>&", "\"e\"");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "<Key>a&lt;b&gt;&amp;</Key><ETag>&quot;e&quot;</ETag>") != null);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("up/foo.txt", try substituteFilename(arena_state.allocator(), "up/${filename}", "foo.txt"));
}
