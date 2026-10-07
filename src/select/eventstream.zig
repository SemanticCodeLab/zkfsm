//! Event-stream framing (application/vnd.amazon.eventstream):
//! [total_len u32][headers_len u32][prelude_crc u32][headers][payload][msg_crc u32].
const std = @import("std");
const Crc32 = std.hash.Crc32;

pub const Header = struct { name: []const u8, value: []const u8 };

const header_string_type: u8 = 7;
pub const prelude_len = 12;
pub const max_message_len = 16 * 1024 * 1024;

pub const WriteError = std.Io.Writer.Error || error{MessageTooLarge};

fn headersLen(headers: []const Header) usize {
    var n: usize = 0;
    for (headers) |h| n += 1 + h.name.len + 1 + 2 + h.value.len;
    return n;
}

pub fn writeMessage(w: *std.Io.Writer, headers: []const Header, payload: []const u8) WriteError!void {
    const hl = headersLen(headers);
    const total = prelude_len + hl + payload.len + 4;
    if (total > max_message_len) return error.MessageTooLarge;
    for (headers) |h| if (h.name.len > 255 or h.value.len > std.math.maxInt(u16)) return error.MessageTooLarge;
    var prelude: [prelude_len]u8 = undefined;
    std.mem.writeInt(u32, prelude[0..4], @intCast(total), .big);
    std.mem.writeInt(u32, prelude[4..8], @intCast(hl), .big);
    std.mem.writeInt(u32, prelude[8..12], Crc32.hash(prelude[0..8]), .big);
    var crc = Crc32.init();
    crc.update(&prelude);
    try w.writeAll(&prelude);
    for (headers) |h| {
        var lens: [1]u8 = .{@intCast(h.name.len)};
        var tl: [3]u8 = undefined;
        tl[0] = header_string_type;
        std.mem.writeInt(u16, tl[1..3], @intCast(h.value.len), .big);
        crc.update(&lens);
        crc.update(h.name);
        crc.update(&tl);
        crc.update(h.value);
        try w.writeAll(&lens);
        try w.writeAll(h.name);
        try w.writeAll(&tl);
        try w.writeAll(h.value);
    }
    crc.update(payload);
    try w.writeAll(payload);
    var tail: [4]u8 = undefined;
    std.mem.writeInt(u32, &tail, crc.final(), .big);
    try w.writeAll(&tail);
}

pub fn writeEvent(w: *std.Io.Writer, event_type: []const u8, content_type: ?[]const u8, payload: []const u8) WriteError!void {
    if (content_type) |ct| {
        return writeMessage(w, &.{
            .{ .name = ":event-type", .value = event_type },
            .{ .name = ":content-type", .value = ct },
            .{ .name = ":message-type", .value = "event" },
        }, payload);
    }
    return writeMessage(w, &.{
        .{ .name = ":event-type", .value = event_type },
        .{ .name = ":message-type", .value = "event" },
    }, payload);
}

pub fn writeError(w: *std.Io.Writer, code: []const u8, message: []const u8) WriteError!void {
    return writeMessage(w, &.{
        .{ .name = ":error-code", .value = code },
        .{ .name = ":error-message", .value = message },
        .{ .name = ":message-type", .value = "error" },
    }, "");
}

pub const DecodeError = error{ Truncated, BadPreludeCrc, BadMessageCrc, BadLength, UnsupportedHeaderType, TooManyHeaders };

pub const max_headers = 16;

pub const Message = struct {
    headers_buf: [max_headers]Header = undefined,
    header_count: usize = 0,
    payload: []const u8 = "",
    /// Total bytes consumed from the input.
    len: usize = 0,

    pub fn headers(m: *const Message) []const Header {
        return m.headers_buf[0..m.header_count];
    }

    pub fn header(m: *const Message, name: []const u8) ?[]const u8 {
        for (m.headers()) |h| if (std.mem.eql(u8, h.name, name)) return h.value;
        return null;
    }
};

/// Decodes one message from the front of `buf` (string headers only).
pub fn decode(buf: []const u8) DecodeError!Message {
    if (buf.len < prelude_len + 4) return error.Truncated;
    const total = std.mem.readInt(u32, buf[0..4], .big);
    const hl = std.mem.readInt(u32, buf[4..8], .big);
    if (std.mem.readInt(u32, buf[8..12], .big) != Crc32.hash(buf[0..8])) return error.BadPreludeCrc;
    if (total < prelude_len + 4 or hl > total - prelude_len - 4) return error.BadLength;
    if (buf.len < total) return error.Truncated;
    if (std.mem.readInt(u32, buf[total - 4 ..][0..4], .big) != Crc32.hash(buf[0 .. total - 4])) return error.BadMessageCrc;
    var m: Message = .{ .len = total };
    var i: usize = prelude_len;
    const hend = prelude_len + hl;
    while (i < hend) {
        if (m.header_count >= max_headers) return error.TooManyHeaders;
        const nl = buf[i];
        i += 1;
        if (i + nl + 3 > hend) return error.BadLength;
        const name = buf[i .. i + nl];
        i += nl;
        if (buf[i] != header_string_type) return error.UnsupportedHeaderType;
        const vl = std.mem.readInt(u16, buf[i + 1 ..][0..2], .big);
        i += 3;
        if (i + vl > hend) return error.BadLength;
        m.headers_buf[m.header_count] = .{ .name = name, .value = buf[i .. i + vl] };
        m.header_count += 1;
        i += vl;
    }
    m.payload = buf[hend .. total - 4];
    return m;
}

test "round trip and corruption" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeEvent(&w, "Records", "application/octet-stream", "a,b\n");
    try writeEvent(&w, "End", null, "");
    const bytes = w.buffered();
    const m = try decode(bytes);
    try std.testing.expectEqualStrings("Records", m.header(":event-type").?);
    try std.testing.expectEqualStrings("a,b\n", m.payload);
    const m2 = try decode(bytes[m.len..]);
    try std.testing.expectEqualStrings("End", m2.header(":event-type").?);
    try std.testing.expectEqual(bytes.len, m.len + m2.len);
    var bad = buf;
    bad[20] ^= 1;
    try std.testing.expectError(error.BadMessageCrc, decode(&bad));
    bad = buf;
    bad[1] ^= 1;
    try std.testing.expectError(error.BadPreludeCrc, decode(&bad));
    try std.testing.expectError(error.Truncated, decode(bytes[0 .. m.len - 1]));
}

test "known end message bytes" {
    // Independent CRC check of a fixed End frame layout.
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeEvent(&w, "End", null, "");
    const b = w.buffered();
    try std.testing.expectEqual(@as(usize, 56), b.len);
    try std.testing.expectEqual(@as(u32, 56), std.mem.readInt(u32, b[0..4], .big));
    try std.testing.expectEqual(@as(u32, 40), std.mem.readInt(u32, b[4..8], .big));
}
