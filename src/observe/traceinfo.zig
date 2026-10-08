//! madmin TraceInfo JSON for `mc admin trace`: full HTTP detail for S3/admin
//! requests, and a compact form for internal spans (storage, RPC, KMS, ILM, ...).
const std = @import("std");
const core = @import("../core/root.zig");
const s3 = @import("../s3/root.zig");
const logs = @import("logs.zig");
const hub = @import("hub.zig");

const Stringify = std.json.Stringify;
const Header = std.http.Header;
const WError = std.Io.Writer.Error;

fn redacted(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or std.ascii.eqlIgnoreCase(name, "x-amz-security-token") or
        std.ascii.eqlIgnoreCase(name, "cookie") or std.ascii.eqlIgnoreCase(name, "x-amz-server-side-encryption-customer-key");
}

/// Go's http.Header: map of name to value list.
fn headers(s: *Stringify, hs: []const Header) WError!void {
    try s.beginObject();
    for (hs, 0..) |h, i| {
        const seen = for (hs[0..i]) |p| {
            if (std.ascii.eqlIgnoreCase(p.name, h.name)) break true;
        } else false;
        if (seen) continue;
        try s.objectField(h.name);
        try s.beginArray();
        for (hs[i..]) |x| if (std.ascii.eqlIgnoreCase(x.name, h.name)) try s.write(if (redacted(x.name)) "*REDACTED*" else x.value);
        try s.endArray();
    }
    try s.endObject();
}

pub const Http = struct {
    node: []const u8,
    funcname: []const u8,
    start_ns: i128,
    end_ns: i128,
    status: u16,
    rx: u64,
    tx: u64,
    client: []const u8,
};

pub fn s3Entry(a: std.mem.Allocator, c: *const s3.handler.Ctx, h: Http) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    var s: Stringify = .{ .writer = &out.writer };
    writeS3(&s, c, h) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

fn writeS3(s: *Stringify, c: *const s3.handler.Ctx, h: Http) WError!void {
    var t0: [40]u8 = undefined;
    var t1: [40]u8 = undefined;
    const dur: u64 = @intCast(@max(0, h.end_ns - h.start_ns));
    const path = c.target[0 .. std.mem.indexOfScalar(u8, c.target, '?') orelse c.target.len];
    const query = if (std.mem.indexOfScalar(u8, c.target, '?')) |q| c.target[q + 1 ..] else "";
    try s.beginObject();
    try s.objectField("type");
    try s.write(hub.tt.s3);
    try s.objectField("nodename");
    try s.write(h.node);
    try s.objectField("funcname");
    try s.write(h.funcname);
    try s.objectField("time");
    try s.write(logs.rfc3339Nano(h.start_ns, &t0));
    try s.objectField("path");
    try s.write(path);
    try s.objectField("dur");
    try s.write(dur);
    if (c.err_code.len > 0) {
        try s.objectField("error");
        try s.write(c.err_code);
    }
    try s.objectField("http");
    try s.beginObject();
    try s.objectField("request");
    try s.beginObject();
    try s.objectField("time");
    try s.write(logs.rfc3339Nano(h.start_ns, &t0));
    try s.objectField("proto");
    try s.write("HTTP/1.1");
    try s.objectField("method");
    try s.write(@tagName(c.method));
    try s.objectField("path");
    try s.write(path);
    try s.objectField("rawquery");
    try s.write(query);
    try s.objectField("headers");
    try headers(s, c.req_headers);
    try s.objectField("client");
    try s.write(h.client);
    try s.endObject();
    try s.objectField("response");
    try s.beginObject();
    try s.objectField("time");
    try s.write(logs.rfc3339Nano(h.end_ns, &t1));
    try s.objectField("headers");
    try headers(s, c.resp_headers);
    try s.objectField("statuscode");
    try s.write(h.status);
    try s.endObject();
    try s.objectField("stats");
    try s.beginObject();
    try s.objectField("inputbytes");
    try s.write(h.rx);
    try s.objectField("outputbytes");
    try s.write(h.tx);
    try s.objectField("latency");
    try s.write(dur);
    try s.objectField("timetofirstbyte");
    try s.write(dur);
    try s.endObject();
    try s.endObject();
    try s.endObject();
}

/// Internal span: path from a `path`, `key`, or `rpc.op` attribute; others go to `custom`.
pub fn spanEntry(a: std.mem.Allocator, node: []const u8, sp: *const core.trace.Span) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    var s: Stringify = .{ .writer = &out.writer };
    writeSpan(&s, node, sp) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

fn writeSpan(s: *Stringify, node: []const u8, sp: *const core.trace.Span) WError!void {
    var tb: [40]u8 = undefined;
    var path: []const u8 = "";
    var bytes: i64 = 0;
    for (sp.attributes()) |at| {
        if (at.value == .str and path.len == 0 and (std.mem.eql(u8, at.key, "path") or std.mem.eql(u8, at.key, "key") or std.mem.eql(u8, at.key, "rpc.op"))) path = at.value.str;
        if (at.value == .int and std.mem.eql(u8, at.key, "bytes")) bytes = at.value.int;
    }
    try s.beginObject();
    try s.objectField("type");
    try s.write(hub.bitOf(sp.typ));
    try s.objectField("nodename");
    try s.write(node);
    try s.objectField("funcname");
    try s.write(sp.name);
    try s.objectField("time");
    try s.write(logs.rfc3339Nano(sp.start_ns, &tb));
    try s.objectField("path");
    try s.write(if (path.len > 0) path else sp.name);
    try s.objectField("dur");
    try s.write(@as(u64, @intCast(@max(0, sp.end_ns - sp.start_ns))));
    if (bytes > 0) {
        try s.objectField("bytes");
        try s.write(bytes);
    }
    if (sp.err) |e| {
        try s.objectField("error");
        try s.write(e);
    }
    if (sp.n_attrs > 0) {
        try s.objectField("custom");
        try s.beginObject();
        var tid: [32]u8 = undefined;
        _ = std.fmt.bufPrint(&tid, "{x}", .{&sp.ctx.trace_id}) catch unreachable;
        try s.objectField("traceID");
        try s.write(&tid);
        for (sp.attributes()) |at| {
            try s.objectField(at.key);
            switch (at.value) {
                .str => |v| try s.write(v),
                .int => |v| try s.print("\"{d}\"", .{v}),
            }
        }
        try s.endObject();
    }
    try s.endObject();
}

test "span entry is valid JSON with the madmin fields" {
    const a = std.testing.allocator;
    var sp: core.trace.Span = .{ .recording = true, .name = "storage.put", .typ = .storage, .ctx = .{ .trace_id = @splat(0xab), .span_id = @splat(1), .sampled = false }, .start_ns = 1, .end_ns = 501 };
    sp.str("key", "data/ab");
    sp.int("bytes", 42);
    const j = try spanEntry(a, "n1:9000", &sp);
    defer a.free(j);
    const V = struct { type: u64, nodename: []const u8, funcname: []const u8, path: []const u8, dur: u64, bytes: i64 };
    const p = try std.json.parseFromSlice(V, a, j, .{ .ignore_unknown_fields = true });
    defer p.deinit();
    try std.testing.expectEqual(hub.tt.storage, p.value.type);
    try std.testing.expectEqualStrings("data/ab", p.value.path);
    try std.testing.expectEqual(@as(u64, 500), p.value.dur);
}
