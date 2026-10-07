//! Target configuration in the `subsys[:id] key=value ...` line format used by the
//! admin config API, its persistence, and the MINIO_/ZKFSM_ NOTIFY|AUDIT env vars.
const std = @import("std");
const target = @import("target.zig");
const kinds = @import("kinds.zig");

const Allocator = std.mem.Allocator;
pub const Kv = target.Kv;

/// The id of a target configured without one.
pub const default_id = "_";

pub const Entry = struct {
    subsys: []const u8,
    id: []const u8 = default_id,
    kvs: []const Kv = &.{},

    pub fn settings(e: Entry) target.Settings {
        return .{ .kvs = e.kvs };
    }

    pub fn enabled(e: Entry) bool {
        const v = e.settings().get("enable");
        return v.len == 0 or e.settings().flag("enable");
    }

    pub fn sameTarget(e: Entry, o: Entry) bool {
        return std.mem.eql(u8, e.subsys, o.subsys) and std.mem.eql(u8, e.id, o.id);
    }
};

pub const ParseError = error{ InvalidConfig, UnknownSubsys, UnknownKey, OutOfMemory };

const max_lines = 256;
const max_kvs = 64;
const max_value = 4096;

/// Parses `subsys[:id] k=v k="v w" ...` lines; blank and `#` lines are skipped.
pub fn parse(a: Allocator, text: []const u8) ParseError![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (out.items.len == max_lines) return error.InvalidConfig;
        try out.append(a, try parseLine(a, line));
    }
    return out.items;
}

/// A bare `subsys[:id]` line (no keys) is valid: it names a target to delete or show.
pub fn parseLine(a: Allocator, line: []const u8) ParseError!Entry {
    var i: usize = 0;
    while (i < line.len and line[i] != ' ' and line[i] != '\t') i += 1;
    const head = line[0..i];
    var e: Entry = .{ .subsys = head };
    if (std.mem.indexOfScalar(u8, head, ':')) |c| {
        e.subsys = head[0..c];
        e.id = head[c + 1 ..];
        if (!validId(e.id)) return error.InvalidConfig;
    }
    const kind = kinds.bySubsys(e.subsys) orelse return error.UnknownSubsys;
    var kvs: std.ArrayList(Kv) = .empty;
    while (true) {
        while (i < line.len and (line[i] == ' ' or line[i] == '\t')) i += 1;
        if (i >= line.len) break;
        const ks = i;
        while (i < line.len and line[i] != '=' and line[i] != ' ') i += 1;
        if (i >= line.len or line[i] != '=') return error.InvalidConfig;
        const key = line[ks..i];
        i += 1;
        var value: []const u8 = "";
        if (i < line.len and line[i] == '"') {
            const end = std.mem.indexOfScalarPos(u8, line, i + 1, '"') orelse return error.InvalidConfig;
            value = line[i + 1 .. end];
            i = end + 1;
        } else {
            const vs = i;
            while (i < line.len and line[i] != ' ' and line[i] != '\t') i += 1;
            value = line[vs..i];
        }
        if (value.len > max_value or kvs.items.len == max_kvs) return error.InvalidConfig;
        if (!kinds.validKey(kind, key)) return error.UnknownKey;
        try kvs.append(a, .{ .key = try a.dupe(u8, key), .value = try a.dupe(u8, value) });
    }
    e.subsys = try a.dupe(u8, e.subsys);
    e.id = try a.dupe(u8, e.id);
    e.kvs = kvs.items;
    return e;
}

fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.')) return false;
    return true;
}

/// Renders entries as lines; `redact` blanks secrets.
pub fn render(a: Allocator, entries: []const Entry, redact: bool) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    for (entries) |e| renderEntry(w, e, redact) catch return error.OutOfMemory;
    return out.written();
}

fn renderEntry(w: *std.Io.Writer, e: Entry, redact: bool) std.Io.Writer.Error!void {
    try w.writeAll(e.subsys);
    if (!std.mem.eql(u8, e.id, default_id)) try w.print(":{s}", .{e.id});
    for (e.kvs) |kv| {
        const v = if (redact and isSecret(kv.key) and kv.value.len > 0) "*redacted*" else kv.value;
        if (v.len == 0 or std.mem.indexOfAny(u8, v, " \t") != null)
            try w.print(" {s}=\"{s}\"", .{ kv.key, v })
        else
            try w.print(" {s}={s}", .{ kv.key, v });
    }
    try w.writeByte('\n');
}

pub fn isSecret(key: []const u8) bool {
    const secrets = [_][]const u8{ "password", "sasl_password", "auth_token", "token", "client_key", "client_tls_key", "connection_string", "dsn_string", "url" };
    for (secrets) |s| if (std.mem.eql(u8, s, key)) return true;
    return false;
}

/// Applies `upd` to `table`: keys given replace existing ones, others are kept.
pub fn merge(a: Allocator, table: []const Entry, upd: Entry) error{OutOfMemory}![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    var found = false;
    for (table) |e| {
        if (!e.sameTarget(upd)) {
            try out.append(a, e);
            continue;
        }
        found = true;
        var kvs: std.ArrayList(Kv) = .empty;
        try kvs.appendSlice(a, e.kvs);
        for (upd.kvs) |kv| {
            const hit = for (kvs.items) |*x| {
                if (std.mem.eql(u8, x.key, kv.key)) break x;
            } else null;
            if (hit) |x| x.value = kv.value else try kvs.append(a, kv);
        }
        try out.append(a, .{ .subsys = e.subsys, .id = e.id, .kvs = kvs.items });
    }
    if (!found) try out.append(a, upd);
    return out.items;
}

/// Removes the target `del` names (or every target of its subsystem when `all`).
pub fn remove(a: Allocator, table: []const Entry, del: Entry, all: bool) error{OutOfMemory}![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    for (table) |e| {
        const hit = if (all) std.mem.eql(u8, e.subsys, del.subsys) else e.sameTarget(del);
        if (!hit) try out.append(a, e);
    }
    return out.items;
}

/// Targets from `MINIO_NOTIFY_<TYPE>_<KEY>[_<ID>]`, `ZKFSM_NOTIFY_...` and the
/// AUDIT equivalents. ZKFSM_ names win over MINIO_ ones.
pub fn fromEnv(a: Allocator, env: *const std.process.EnvMap) error{OutOfMemory}![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    for ([_][]const u8{ "MINIO_", "ZKFSM_" }) |brand| {
        var it = env.iterator();
        while (it.next()) |kv| {
            const name = kv.key_ptr.*;
            if (!std.mem.startsWith(u8, name, brand)) continue;
            const rest = name[brand.len..];
            for (&kinds.all) |*k| {
                const group = if (k.audit) "AUDIT_" else "NOTIFY_";
                if (!std.mem.startsWith(u8, rest, group) or !std.mem.startsWith(u8, rest[group.len..], k.env)) continue;
                const tail = rest[group.len + k.env.len ..];
                if (tail.len < 2 or tail[0] != '_') continue;
                const m = matchKey(k, tail[1..]) orelse continue;
                try setEnv(a, &out, k.subsys, m.id, m.key, kv.value_ptr.*);
            }
        }
    }
    // Env targets need ENABLE=on, as in MinIO.
    var enabled: std.ArrayList(Entry) = .empty;
    for (out.items) |e| if (e.settings().flag("enable")) try enabled.append(a, e);
    return enabled.items;
}

const KeyMatch = struct { key: []const u8, id: []const u8 };

/// Longest key whose upper-case form is `s` or a prefix of `s` followed by `_ID`.
fn matchKey(k: *const kinds.Kind, s: []const u8) ?KeyMatch {
    var best: ?KeyMatch = null;
    var best_len: usize = 0;
    const lists = [_][]const []const u8{ &kinds.common_keys, k.keys };
    for (lists) |list| for (list) |key| {
        if (key.len <= best_len or key.len > s.len) continue;
        if (!upperEql(key, s[0..key.len])) continue;
        if (s.len == key.len) {
            best = .{ .key = key, .id = default_id };
        } else if (s[key.len] == '_' and s.len > key.len + 1) {
            best = .{ .key = key, .id = s[key.len + 1 ..] };
        } else continue;
        best_len = key.len;
    };
    return best;
}

fn upperEql(lower: []const u8, upper: []const u8) bool {
    for (lower, upper) |l, u| if (std.ascii.toUpper(l) != u) return false;
    return true;
}

fn setEnv(a: Allocator, out: *std.ArrayList(Entry), subsys: []const u8, id_raw: []const u8, key: []const u8, value: []const u8) error{OutOfMemory}!void {
    const id = try a.dupe(u8, id_raw);
    const upd: Entry = .{ .subsys = subsys, .id = id, .kvs = try a.dupe(Kv, &.{.{ .key = key, .value = value }}) };
    const merged = try merge(a, out.items, upd);
    out.clearRetainingCapacity();
    try out.appendSlice(a, merged);
}

const t = std.testing;

test "parse, merge, render" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const es = try parse(a, "notify_webhook:1 endpoint=http://h:1/x auth_token=\"Bearer t\"\n# c\nnotify_redis address=r:6379 key=k");
    try t.expectEqual(@as(usize, 2), es.len);
    try t.expectEqualStrings("1", es[0].id);
    try t.expectEqualStrings("Bearer t", es[0].settings().get("auth_token"));
    try t.expectEqualStrings(default_id, es[1].id);
    try t.expectError(error.UnknownKey, parseLine(a, "notify_webhook:1 nope=1"));
    try t.expectError(error.UnknownSubsys, parseLine(a, "notify_bogus:1 a=b"));
    const m = try merge(a, es, try parseLine(a, "notify_webhook:1 queue_dir=/q"));
    try t.expectEqual(@as(usize, 2), m.len);
    try t.expectEqualStrings("/q", m[0].settings().get("queue_dir"));
    try t.expectEqualStrings("http://h:1/x", m[0].settings().get("endpoint"));
    const r = try render(a, m[0..1], true);
    try t.expectEqualStrings("notify_webhook:1 endpoint=http://h:1/x auth_token=*redacted* queue_dir=/q\n", r);
    try t.expectEqual(@as(usize, 1), (try remove(a, m, m[0], false)).len);
    try t.expect((try parseLine(a, "notify_webhook:1 enable=off")).enabled() == false);
}

test "env targets" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.EnvMap.init(a);
    try env.put("MINIO_NOTIFY_WEBHOOK_ENABLE_PRIMARY", "on");
    try env.put("MINIO_NOTIFY_WEBHOOK_ENDPOINT_PRIMARY", "http://a/");
    try env.put("ZKFSM_NOTIFY_KAFKA_ENABLE", "on");
    try env.put("ZKFSM_NOTIFY_KAFKA_BROKERS", "k:9092");
    try env.put("ZKFSM_NOTIFY_KAFKA_TLS_SKIP_VERIFY", "on");
    try env.put("MINIO_NOTIFY_REDIS_ADDRESS_X", "r:1");
    try env.put("MINIO_AUDIT_WEBHOOK_ENABLE_A", "on");
    try env.put("MINIO_AUDIT_WEBHOOK_ENDPOINT_A", "http://audit/");
    const es = try fromEnv(a, &env);
    try t.expectEqual(@as(usize, 3), es.len);
    var saw_kafka = false;
    for (es) |e| if (std.mem.eql(u8, e.subsys, "notify_kafka")) {
        saw_kafka = true;
        try t.expectEqualStrings(default_id, e.id);
        try t.expect(e.settings().flag("tls_skip_verify"));
    };
    try t.expect(saw_kafka);
}
