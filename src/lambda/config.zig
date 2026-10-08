//! Object Lambda webhook targets: `lambda_webhook[:id] key=value ...` lines (admin
//! config API), MINIO_/ZKFSM_LAMBDA_WEBHOOK_<KEY>[_<ID>] env vars, endpoint parsing.
const std = @import("std");

const Allocator = std.mem.Allocator;

pub const subsys = "lambda_webhook";
/// Id of a target configured without one.
pub const default_id = "_";
pub const keys = [_][]const u8{ "enable", "endpoint", "auth_token", "client_cert", "client_key", "comment" };

const max_lines = 64;
const max_value = 4096;

pub const Kv = struct { key: []const u8, value: []const u8 };

pub const Target = struct {
    id: []const u8 = default_id,
    kvs: []const Kv = &.{},

    pub fn get(t: Target, key: []const u8) []const u8 {
        var v: []const u8 = "";
        for (t.kvs) |kv| if (std.mem.eql(u8, kv.key, key)) {
            v = kv.value;
        };
        return v;
    }

    /// Stored targets default to on; env targets need ENABLE=on (checked in fromEnv).
    pub fn enabled(t: Target) bool {
        const v = t.get("enable");
        return v.len == 0 or isOn(v);
    }
};

pub fn isOn(v: []const u8) bool {
    for ([_][]const u8{ "on", "true", "yes", "1", "enable", "enabled" }) |s| if (std.ascii.eqlIgnoreCase(v, s)) return true;
    return false;
}

pub const ParseError = error{ InvalidConfig, UnknownSubsys, UnknownKey, OutOfMemory };

pub fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.')) return false;
    return true;
}

fn knownKey(k: []const u8) bool {
    for (keys) |x| if (std.mem.eql(u8, x, k)) return true;
    return false;
}

/// Parses one `lambda_webhook[:id] k=v k="v w"` line; a bare head names a target.
pub fn parseLine(a: Allocator, line_raw: []const u8) ParseError!Target {
    const line = std.mem.trim(u8, line_raw, " \t\r");
    var i: usize = 0;
    while (i < line.len and line[i] != ' ' and line[i] != '\t') i += 1;
    const head = line[0..i];
    var t: Target = .{};
    var sub = head;
    if (std.mem.indexOfScalar(u8, head, ':')) |c| {
        sub = head[0..c];
        t.id = head[c + 1 ..];
        if (!validId(t.id)) return error.InvalidConfig;
    }
    if (!std.mem.eql(u8, sub, subsys)) return error.UnknownSubsys;
    var kvs: std.ArrayList(Kv) = .empty;
    var pos = i;
    while (true) {
        while (pos < line.len and (line[pos] == ' ' or line[pos] == '\t')) pos += 1;
        if (pos >= line.len) break;
        const eq = std.mem.indexOfScalarPos(u8, line, pos, '=') orelse return error.InvalidConfig;
        const key = line[pos..eq];
        if (!knownKey(key)) return error.UnknownKey;
        var vs = eq + 1;
        var value: []const u8 = undefined;
        if (vs < line.len and line[vs] == '"') {
            vs += 1;
            const end = std.mem.indexOfScalarPos(u8, line, vs, '"') orelse return error.InvalidConfig;
            value = line[vs..end];
            pos = end + 1;
        } else {
            var e = vs;
            while (e < line.len and line[e] != ' ' and line[e] != '\t') e += 1;
            value = line[vs..e];
            pos = e;
        }
        if (value.len > max_value or kvs.items.len >= keys.len * 2) return error.InvalidConfig;
        if (std.mem.indexOfAny(u8, value, "\r\n") != null) return error.InvalidConfig;
        try kvs.append(a, .{ .key = try a.dupe(u8, key), .value = try a.dupe(u8, value) });
    }
    t.id = try a.dupe(u8, t.id);
    t.kvs = kvs.items;
    return t;
}

/// Parses stored lines; blank and `#` lines are skipped.
pub fn parse(a: Allocator, text: []const u8) ParseError![]Target {
    var out: std.ArrayList(Target) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (out.items.len == max_lines) return error.InvalidConfig;
        try out.append(a, try parseLine(a, line));
    }
    return out.items;
}

/// Keys given in `upd` replace existing ones of the same target.
pub fn merge(a: Allocator, table: []const Target, upd: Target) error{OutOfMemory}![]Target {
    var out: std.ArrayList(Target) = .empty;
    var found = false;
    for (table) |t| {
        if (!std.mem.eql(u8, t.id, upd.id)) {
            try out.append(a, t);
            continue;
        }
        found = true;
        var kvs: std.ArrayList(Kv) = .empty;
        try kvs.appendSlice(a, t.kvs);
        for (upd.kvs) |kv| {
            const hit = for (kvs.items) |*x| {
                if (std.mem.eql(u8, x.key, kv.key)) break x;
            } else null;
            if (hit) |x| x.value = kv.value else try kvs.append(a, kv);
        }
        try out.append(a, .{ .id = t.id, .kvs = kvs.items });
    }
    if (!found) try out.append(a, upd);
    return out.items;
}

pub fn remove(a: Allocator, table: []const Target, id: ?[]const u8) error{OutOfMemory}![]Target {
    var out: std.ArrayList(Target) = .empty;
    if (id) |want| for (table) |t| if (!std.mem.eql(u8, t.id, want)) try out.append(a, t);
    return out.items;
}

/// Lines with every key; `redact` hides secrets.
pub fn render(a: Allocator, table: []const Target, redact: bool) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    for (table) |t| renderOne(w, t, redact) catch return error.OutOfMemory;
    return out.written();
}

fn renderOne(w: *std.Io.Writer, t: Target, redact: bool) std.Io.Writer.Error!void {
    try w.writeAll(subsys);
    if (!std.mem.eql(u8, t.id, default_id)) try w.print(":{s}", .{t.id});
    for (t.kvs) |kv| {
        const secret = std.mem.eql(u8, kv.key, "auth_token") or std.mem.eql(u8, kv.key, "client_key");
        const v = if (redact and secret and kv.value.len > 0) "*redacted*" else kv.value;
        if (v.len == 0 or std.mem.indexOfAny(u8, v, " \t") != null)
            try w.print(" {s}=\"{s}\"", .{ kv.key, v })
        else
            try w.print(" {s}={s}", .{ kv.key, v });
    }
    try w.writeByte('\n');
}

/// Targets from `MINIO_LAMBDA_WEBHOOK_<KEY>[_<ID>]` and `ZKFSM_...`; ZKFSM_ wins.
/// Only targets with ENABLE=on are returned, as in MinIO.
pub fn fromEnv(a: Allocator, env: *const std.process.EnvMap) error{OutOfMemory}![]Target {
    var table: []Target = &.{};
    for ([_][]const u8{ "MINIO_LAMBDA_WEBHOOK_", "ZKFSM_LAMBDA_WEBHOOK_" }) |prefix| {
        var it = env.iterator();
        while (it.next()) |kv| {
            const name = kv.key_ptr.*;
            if (!std.mem.startsWith(u8, name, prefix)) continue;
            const m = matchKey(name[prefix.len..]) orelse continue;
            if (!validId(m.id) or kv.value_ptr.len > max_value) continue;
            const kvs = try a.alloc(Kv, 1);
            kvs[0] = .{ .key = m.key, .value = kv.value_ptr.* };
            table = try merge(a, table, .{ .id = try a.dupe(u8, m.id), .kvs = kvs });
        }
    }
    var out: std.ArrayList(Target) = .empty;
    for (table) |t| if (isOn(t.get("enable"))) try out.append(a, t);
    return out.items;
}

const KeyMatch = struct { key: []const u8, id: []const u8 };

fn matchKey(s: []const u8) ?KeyMatch {
    var best: ?KeyMatch = null;
    for (keys) |key| {
        if (key.len > s.len or (best != null and key.len <= best.?.key.len)) continue;
        if (!upperEql(key, s[0..key.len])) continue;
        if (s.len == key.len) {
            best = .{ .key = key, .id = default_id };
        } else if (s[key.len] == '_' and s.len > key.len + 1) {
            best = .{ .key = key, .id = s[key.len + 1 ..] };
        }
    }
    return best;
}

fn upperEql(lower: []const u8, upper: []const u8) bool {
    for (lower, upper) |l, u| if (std.ascii.toUpper(l) != u) return false;
    return true;
}

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
    /// Path and query sent in the request line.
    path: []const u8,
    host_header: []const u8,
    secure: bool,
};

pub const EndpointError = error{ InvalidConfig, OutOfMemory };

/// Parses an http(s) endpoint; client certificates are not supported by the std TLS client.
pub fn endpoint(a: Allocator, t: Target) EndpointError!Endpoint {
    if (t.get("client_cert").len > 0 or t.get("client_key").len > 0) return error.InvalidConfig;
    const raw = t.get("endpoint");
    if (raw.len == 0) return error.InvalidConfig;
    const uri = std.Uri.parse(raw) catch return error.InvalidConfig;
    const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) true else if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) false else return error.InvalidConfig;
    var hb: [std.Uri.host_name_max]u8 = undefined;
    const host = try a.dupe(u8, uri.getHost(&hb) catch return error.InvalidConfig);
    var pb: std.Io.Writer.Allocating = .init(a);
    uri.path.formatPath(&pb.writer) catch return error.OutOfMemory;
    if (pb.written().len == 0) pb.writer.writeByte('/') catch return error.OutOfMemory;
    if (uri.query) |q| {
        pb.writer.writeByte('?') catch return error.OutOfMemory;
        q.formatQuery(&pb.writer) catch return error.OutOfMemory;
    }
    const path = pb.written();
    if (std.mem.indexOfAny(u8, path, "\r\n \t") != null) return error.InvalidConfig;
    const v6 = std.mem.indexOfScalar(u8, host, ':') != null;
    const hh = if (uri.port) |p|
        (if (v6) try std.fmt.allocPrint(a, "[{s}]:{d}", .{ host, p }) else try std.fmt.allocPrint(a, "{s}:{d}", .{ host, p }))
    else if (v6) try std.fmt.allocPrint(a, "[{s}]", .{host}) else host;
    return .{ .host = host, .port = uri.port orelse if (secure) 443 else 80, .path = path, .host_header = hh, .secure = secure };
}

/// `Authorization` value: a bare token becomes a bearer credential.
pub fn authHeader(a: Allocator, t: Target) error{ InvalidConfig, OutOfMemory }!?[]const u8 {
    const tok = t.get("auth_token");
    if (tok.len == 0) return null;
    if (std.mem.indexOfAny(u8, tok, "\r\n") != null) return error.InvalidConfig;
    if (std.mem.indexOfScalar(u8, tok, ' ') != null) return tok;
    return try std.fmt.allocPrint(a, "Bearer {s}", .{tok});
}

const tst = std.testing;

test "parse, merge, render" {
    var arena = std.heap.ArenaAllocator.init(tst.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ts = try parse(a, "lambda_webhook:fn1 endpoint=http://h:1/x auth_token=\"Bearer t\"\n# c\nlambda_webhook enable=off");
    try tst.expectEqual(@as(usize, 2), ts.len);
    try tst.expectEqualStrings("fn1", ts[0].id);
    try tst.expectEqualStrings("Bearer t", ts[0].get("auth_token"));
    try tst.expect(!ts[1].enabled());
    try tst.expectError(error.UnknownKey, parseLine(a, "lambda_webhook:1 nope=1"));
    try tst.expectError(error.UnknownSubsys, parseLine(a, "notify_webhook:1 endpoint=x"));
    try tst.expectError(error.InvalidConfig, parseLine(a, "lambda_webhook:a/b endpoint=x"));
    const m = try merge(a, ts, try parseLine(a, "lambda_webhook:fn1 comment=c"));
    try tst.expectEqualStrings("http://h:1/x", m[0].get("endpoint"));
    try tst.expectEqualStrings("lambda_webhook:fn1 endpoint=http://h:1/x auth_token=*redacted* comment=c\n", try render(a, m[0..1], true));
    try tst.expectEqual(@as(usize, 1), (try remove(a, m, "fn1")).len);
}

test "env targets" {
    var arena = std.heap.ArenaAllocator.init(tst.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.EnvMap.init(a);
    try env.put("MINIO_LAMBDA_WEBHOOK_ENABLE_fn1", "on");
    try env.put("MINIO_LAMBDA_WEBHOOK_ENDPOINT_fn1", "http://127.0.0.1:9/a");
    try env.put("MINIO_LAMBDA_WEBHOOK_AUTH_TOKEN_fn1", "tok");
    try env.put("ZKFSM_LAMBDA_WEBHOOK_ENDPOINT_fn1", "http://127.0.0.1:10/b");
    try env.put("MINIO_LAMBDA_WEBHOOK_ENDPOINT_off", "http://x/");
    const ts = try fromEnv(a, &env);
    try tst.expectEqual(@as(usize, 1), ts.len);
    try tst.expectEqualStrings("http://127.0.0.1:10/b", ts[0].get("endpoint"));
    try tst.expectEqualStrings("tok", ts[0].get("auth_token"));
    const ep = try endpoint(a, ts[0]);
    try tst.expectEqualStrings("/b", ep.path);
    try tst.expectEqualStrings("127.0.0.1:10", ep.host_header);
    try tst.expectEqualStrings("Bearer tok", (try authHeader(a, ts[0])).?);
    try tst.expectError(error.InvalidConfig, endpoint(a, .{ .kvs = &.{.{ .key = "endpoint", .value = "ftp://x" }} }));
    try tst.expectError(error.InvalidConfig, endpoint(a, .{ .kvs = &.{ .{ .key = "endpoint", .value = "https://x" }, .{ .key = "client_cert", .value = "/c" } } }));
}
