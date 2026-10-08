//! Iceberg table metadata (format v2): builds new metadata, checks commit
//! requirements, and applies table updates to the metadata JSON tree.
const std = @import("std");
const json = @import("json.zig");

const Value = json.Value;
const ObjectMap = json.ObjectMap;
const Allocator = std.mem.Allocator;

pub const Error = error{ OutOfMemory, BadRequest, CommitFailed, Unsupported };

/// Explains the last failure; points at static text or arena memory.
pub const Diag = struct {
    msg: []const u8 = "",

    pub fn fail(d: *Diag, comptime e: Error, msg: []const u8) Error {
        d.msg = msg;
        return e;
    }
};

pub const max_list_items = 100_000;
const default_spec_field_base = 1000;

pub fn uuid4(out: *[36]u8) []const u8 {
    var b: [16]u8 = undefined;
    std.crypto.random.bytes(&b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = std.fmt.bytesToHex(b, .lower);
    _ = std.fmt.bufPrint(out, "{s}-{s}-{s}-{s}-{s}", .{ h[0..8], h[8..12], h[12..16], h[16..20], h[20..32] }) catch unreachable; // 36 bytes
    return out;
}

/// Highest field id in a schema or nested type; bounded by json.max_depth.
pub fn maxFieldId(v: Value) i64 {
    var best: i64 = 0;
    switch (v) {
        .object => |o| {
            for ([_][]const u8{ "id", "element-id", "key-id", "value-id" }) |k| {
                if (json.int(o, k)) |n| best = @max(best, n);
            }
            if (json.arr(o, "fields")) |fs| for (fs) |f| {
                best = @max(best, maxFieldId(f));
            };
            for ([_][]const u8{ "type", "element", "key", "value" }) |k| {
                if (json.get(o, k)) |sub| best = @max(best, maxFieldId(sub));
            }
        },
        else => {},
    }
    return best;
}

fn validSchema(v: Value) ?ObjectMap {
    const o = switch (v) {
        .object => |o| o,
        else => return null,
    };
    const t = json.str(o, "type") orelse return null;
    if (!std.mem.eql(u8, t, "struct")) return null;
    const fs = json.arr(o, "fields") orelse return null;
    for (fs) |f| switch (f) {
        .object => |fo| {
            if (json.int(fo, "id") == null or json.str(fo, "name") == null or json.get(fo, "type") == null) return null;
        },
        else => return null,
    };
    return o;
}

fn idsOf(list: []const Value, key: []const u8) i64 {
    var best: i64 = -1;
    for (list) |e| switch (e) {
        .object => |o| if (json.int(o, key)) |n| {
            best = @max(best, n);
        },
        else => {},
    };
    return best;
}

fn findById(list: []const Value, key: []const u8, id: i64) ?usize {
    for (list, 0..) |e, idx| switch (e) {
        .object => |o| if (json.int(o, key)) |n| if (n == id) return idx,
        else => {},
    };
    return null;
}

/// Fields of a partition spec, with missing field ids assigned from 1000.
fn normalizeSpec(arena: Allocator, spec: ?ObjectMap, spec_id: i64, last_partition_id: *i64, d: *Diag) Error!Value {
    var out = json.newObject(arena);
    try out.put("spec-id", json.i(spec_id));
    var fields = json.newArray(arena);
    var next = @max(last_partition_id.*, default_spec_field_base - 1);
    if (spec) |so| if (json.get(so, "fields")) |fv| {
        const items = switch (fv) {
            .array => |a| a.items,
            else => return d.fail(error.BadRequest, "partition spec fields must be an array"),
        };
        for (items) |f| {
            var fo = switch (f) {
                .object => |m| try m.clone(),
                else => return d.fail(error.BadRequest, "partition field must be an object"),
            };
            if (json.int(fo, "source-id") == null or json.str(fo, "transform") == null or json.str(fo, "name") == null)
                return d.fail(error.BadRequest, "partition field needs source-id, transform and name");
            if (json.int(fo, "field-id")) |id| {
                next = @max(next, id);
            } else {
                next += 1;
                try fo.put("field-id", json.i(next));
            }
            try fields.append(.{ .object = fo });
        }
    };
    last_partition_id.* = @max(last_partition_id.*, next);
    try out.put("fields", .{ .array = fields });
    return .{ .object = out };
}

fn normalizeOrder(arena: Allocator, order: ?ObjectMap, d: *Diag) Error!Value {
    var out = json.newObject(arena);
    var fields = json.newArray(arena);
    if (order) |oo| if (json.get(oo, "fields")) |fv| switch (fv) {
        .array => |a| for (a.items) |f| switch (f) {
            .object => try fields.append(f),
            else => return d.fail(error.BadRequest, "sort field must be an object"),
        },
        else => return d.fail(error.BadRequest, "sort order fields must be an array"),
    };
    try out.put("order-id", json.i(if (fields.items.len == 0) 0 else 1));
    try out.put("fields", .{ .array = fields });
    return .{ .object = out };
}

pub const Create = struct {
    location: []const u8,
    schema: Value,
    spec: ?ObjectMap = null,
    order: ?ObjectMap = null,
    properties: ?ObjectMap = null,
    uuid: []const u8,
    now_ms: i64,
};

/// Fresh v2 metadata for a CreateTable request.
pub fn create(arena: Allocator, c: Create, d: *Diag) Error!ObjectMap {
    var schema = (validSchema(c.schema) orelse return d.fail(error.BadRequest, "schema must be a struct with fields")).clone() catch return error.OutOfMemory;
    try schema.put("schema-id", json.i(0));
    var props = json.newObject(arena);
    if (c.properties) |p| {
        var it = p.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* != .string) return d.fail(error.BadRequest, "property values must be strings");
            if (std.mem.eql(u8, e.key_ptr.*, "format-version")) {
                if (!std.mem.eql(u8, e.value_ptr.string, "2")) return d.fail(error.Unsupported, "only format-version 2 is supported");
                continue;
            }
            try props.put(e.key_ptr.*, e.value_ptr.*);
        }
    }
    var m = json.newObject(arena);
    var last_pid: i64 = default_spec_field_base - 1;
    const spec = try normalizeSpec(arena, c.spec, 0, &last_pid, d);
    try m.put("format-version", json.i(2));
    try m.put("table-uuid", json.s(c.uuid));
    try m.put("location", json.s(c.location));
    try m.put("last-sequence-number", json.i(0));
    try m.put("last-updated-ms", json.i(c.now_ms));
    try m.put("last-column-id", json.i(maxFieldId(.{ .object = schema })));
    try m.put("current-schema-id", json.i(0));
    try m.put("schemas", try single(arena, .{ .object = schema }));
    try m.put("default-spec-id", json.i(0));
    try m.put("partition-specs", try single(arena, spec));
    try m.put("last-partition-id", json.i(last_pid));
    const order = try normalizeOrder(arena, c.order, d);
    try m.put("default-sort-order-id", json.i(json.int(order.object, "order-id").?));
    try m.put("sort-orders", try single(arena, order));
    try m.put("properties", .{ .object = props });
    try m.put("current-snapshot-id", json.i(-1));
    try m.put("refs", .{ .object = json.newObject(arena) });
    try m.put("snapshots", .{ .array = json.newArray(arena) });
    try m.put("statistics", .{ .array = json.newArray(arena) });
    try m.put("partition-statistics", .{ .array = json.newArray(arena) });
    try m.put("snapshot-log", .{ .array = json.newArray(arena) });
    try m.put("metadata-log", .{ .array = json.newArray(arena) });
    return m;
}

/// Empty metadata that a staged create's updates fill in.
pub fn skeleton(arena: Allocator, uuid: []const u8, now_ms: i64) error{OutOfMemory}!ObjectMap {
    var m = json.newObject(arena);
    try m.put("format-version", json.i(2));
    try m.put("table-uuid", json.s(uuid));
    try m.put("location", json.s(""));
    try m.put("last-sequence-number", json.i(0));
    try m.put("last-updated-ms", json.i(now_ms));
    try m.put("last-column-id", json.i(0));
    try m.put("current-schema-id", json.i(-1));
    try m.put("schemas", .{ .array = json.newArray(arena) });
    try m.put("default-spec-id", json.i(-1));
    try m.put("partition-specs", .{ .array = json.newArray(arena) });
    try m.put("last-partition-id", json.i(default_spec_field_base - 1));
    try m.put("default-sort-order-id", json.i(-1));
    try m.put("sort-orders", .{ .array = json.newArray(arena) });
    try m.put("properties", .{ .object = json.newObject(arena) });
    try m.put("current-snapshot-id", json.i(-1));
    try m.put("refs", .{ .object = json.newObject(arena) });
    try m.put("snapshots", .{ .array = json.newArray(arena) });
    try m.put("statistics", .{ .array = json.newArray(arena) });
    try m.put("partition-statistics", .{ .array = json.newArray(arena) });
    try m.put("snapshot-log", .{ .array = json.newArray(arena) });
    try m.put("metadata-log", .{ .array = json.newArray(arena) });
    return m;
}

/// Fills defaults a staged create may leave out; fails if no schema was set.
pub fn completeStaged(arena: Allocator, m: *ObjectMap, default_location: []const u8, d: *Diag) Error!void {
    const schemas = json.arr(m.*, "schemas") orelse &.{};
    const cur = json.int(m.*, "current-schema-id") orelse -1;
    if (schemas.len == 0 or findById(schemas, "schema-id", cur) == null) return d.fail(error.BadRequest, "staged create needs a current schema");
    const specs = try listPtr(m, "partition-specs");
    if (specs.items.len == 0) {
        var pid = json.int(m.*, "last-partition-id") orelse default_spec_field_base - 1;
        try specs.append(try normalizeSpec(arena, null, 0, &pid, d));
        try m.put("default-spec-id", json.i(0));
    }
    const orders = try listPtr(m, "sort-orders");
    if (orders.items.len == 0) {
        try orders.append(try normalizeOrder(arena, null, d));
        try m.put("default-sort-order-id", json.i(0));
    }
    if ((json.str(m.*, "location") orelse "").len == 0) try m.put("location", json.s(default_location));
}

fn single(arena: Allocator, v: Value) error{OutOfMemory}!Value {
    var a = json.newArray(arena);
    try a.append(v);
    return .{ .array = a };
}

fn listPtr(m: *ObjectMap, key: []const u8) error{OutOfMemory}!*json.Array {
    if (json.arrPtr(m, key)) |a| return a;
    try m.put(key, .{ .array = json.newArray(m.allocator) });
    return json.arrPtr(m, key).?;
}

fn mapPtr(m: *ObjectMap, key: []const u8) error{OutOfMemory}!*ObjectMap {
    if (json.objPtr(m, key)) |o| return o;
    try m.put(key, .{ .object = json.newObject(m.allocator) });
    return json.objPtr(m, key).?;
}

/// Checks Iceberg update requirements; `meta` is null when the table does not exist.
pub fn checkRequirements(meta: ?ObjectMap, reqs: []const Value, d: *Diag) Error!void {
    for (reqs) |rv| {
        const r = switch (rv) {
            .object => |o| o,
            else => return d.fail(error.BadRequest, "requirement must be an object"),
        };
        const t = json.str(r, "type") orelse return d.fail(error.BadRequest, "requirement without type");
        if (std.mem.eql(u8, t, "assert-create")) {
            if (meta != null) return d.fail(error.CommitFailed, "Requirement failed: table already exists");
            continue;
        }
        const m = meta orelse return d.fail(error.CommitFailed, "Requirement failed: table does not exist");
        if (std.mem.eql(u8, t, "assert-table-uuid")) {
            const want = json.str(r, "uuid") orelse return d.fail(error.BadRequest, "assert-table-uuid needs uuid");
            if (!std.ascii.eqlIgnoreCase(want, json.str(m, "table-uuid") orelse "")) return d.fail(error.CommitFailed, "Requirement failed: table UUID does not match");
        } else if (std.mem.eql(u8, t, "assert-ref-snapshot-id")) {
            const ref = json.str(r, "ref") orelse return d.fail(error.BadRequest, "assert-ref-snapshot-id needs ref");
            const want = json.int(r, "snapshot-id");
            const have: ?i64 = if (json.obj(m, "refs")) |refs| (if (json.obj(refs, ref)) |ro| json.int(ro, "snapshot-id") else null) else null;
            if (want == null and have != null) return d.fail(error.CommitFailed, "Requirement failed: ref was created concurrently");
            if (want != null and (have == null or have.? != want.?)) return d.fail(error.CommitFailed, "Requirement failed: ref has changed");
        } else {
            const Pair = struct { req: []const u8, field: []const u8, meta: []const u8 };
            const pairs = [_]Pair{
                .{ .req = "assert-last-assigned-field-id", .field = "last-assigned-field-id", .meta = "last-column-id" },
                .{ .req = "assert-current-schema-id", .field = "current-schema-id", .meta = "current-schema-id" },
                .{ .req = "assert-last-assigned-partition-id", .field = "last-assigned-partition-id", .meta = "last-partition-id" },
                .{ .req = "assert-default-spec-id", .field = "default-spec-id", .meta = "default-spec-id" },
                .{ .req = "assert-default-sort-order-id", .field = "default-sort-order-id", .meta = "default-sort-order-id" },
            };
            const p = for (pairs) |p| {
                if (std.mem.eql(u8, t, p.req)) break p;
            } else return d.fail(error.BadRequest, "unknown requirement type");
            const want = json.int(r, p.field) orelse return d.fail(error.BadRequest, "requirement value missing");
            if (json.int(m, p.meta) != want) return d.fail(error.CommitFailed, "Requirement failed: table metadata has changed");
        }
    }
}

/// State carried across one commit's updates (ids of "last added" items).
const Applied = struct {
    last_schema: ?i64 = null,
    last_spec: ?i64 = null,
    last_order: ?i64 = null,
    added_snapshots: std.ArrayList(i64) = .empty,
};

/// Applies table updates in order; any malformed or unknown update fails the whole commit.
pub fn applyUpdates(arena: Allocator, m: *ObjectMap, updates: []const Value, now_ms: i64, d: *Diag) Error!void {
    var st: Applied = .{};
    for (updates) |uv| {
        const u = switch (uv) {
            .object => |o| o,
            else => return d.fail(error.BadRequest, "update must be an object"),
        };
        const action = json.str(u, "action") orelse return d.fail(error.BadRequest, "update without action");
        try applyOne(arena, m, u, action, &st, now_ms, d);
    }
    try m.put("last-updated-ms", json.i(@max(now_ms, (json.int(m.*, "last-updated-ms") orelse 0) + 1)));
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn applyOne(arena: Allocator, m: *ObjectMap, u: ObjectMap, action: []const u8, st: *Applied, now_ms: i64, d: *Diag) Error!void {
    if (eq(action, "assign-uuid")) {
        const id = json.str(u, "uuid") orelse return d.fail(error.BadRequest, "assign-uuid needs uuid");
        const cur = json.str(m.*, "table-uuid") orelse "";
        if (cur.len > 0 and !std.ascii.eqlIgnoreCase(cur, id) and json.arr(m.*, "schemas").?.len > 0)
            return d.fail(error.BadRequest, "cannot reassign table uuid");
        try m.put("table-uuid", json.s(id));
    } else if (eq(action, "upgrade-format-version")) {
        const v = json.int(u, "format-version") orelse return d.fail(error.BadRequest, "upgrade-format-version needs format-version");
        const cur = json.int(m.*, "format-version") orelse 2;
        if (v < cur) return d.fail(error.BadRequest, "cannot downgrade format version");
        if (v != 2) return d.fail(error.Unsupported, "only format-version 2 is supported");
    } else if (eq(action, "add-schema")) {
        const raw = json.get(u, "schema") orelse return d.fail(error.BadRequest, "add-schema needs schema");
        var schema = (validSchema(raw) orelse return d.fail(error.BadRequest, "schema must be a struct with fields")).clone() catch return error.OutOfMemory;
        const list = try listPtr(m, "schemas");
        if (list.items.len >= max_list_items) return d.fail(error.BadRequest, "too many schemas");
        const want = json.int(schema, "schema-id");
        const id = if (want != null and want.? >= 0 and findById(list.items, "schema-id", want.?) == null) want.? else idsOf(list.items, "schema-id") + 1;
        try schema.put("schema-id", json.i(id));
        try list.append(.{ .object = schema });
        var last = @max(json.int(m.*, "last-column-id") orelse 0, maxFieldId(.{ .object = schema }));
        if (json.int(u, "last-column-id")) |l| last = @max(last, l);
        try m.put("last-column-id", json.i(last));
        st.last_schema = id;
    } else if (eq(action, "set-current-schema")) {
        const id = try resolveLast(json.int(u, "schema-id"), st.last_schema, d);
        if (findById(json.arr(m.*, "schemas") orelse &.{}, "schema-id", id) == null) return d.fail(error.BadRequest, "unknown schema id");
        try m.put("current-schema-id", json.i(id));
    } else if (eq(action, "add-spec")) {
        const spec = json.obj(u, "spec") orelse return d.fail(error.BadRequest, "add-spec needs spec");
        const list = try listPtr(m, "partition-specs");
        if (list.items.len >= max_list_items) return d.fail(error.BadRequest, "too many partition specs");
        const want = json.int(spec, "spec-id");
        const id = if (want != null and want.? >= 0 and findById(list.items, "spec-id", want.?) == null) want.? else idsOf(list.items, "spec-id") + 1;
        var last = json.int(m.*, "last-partition-id") orelse default_spec_field_base - 1;
        try list.append(try normalizeSpec(arena, spec, id, &last, d));
        try m.put("last-partition-id", json.i(last));
        st.last_spec = id;
    } else if (eq(action, "set-default-spec")) {
        const id = try resolveLast(json.int(u, "spec-id"), st.last_spec, d);
        if (findById(json.arr(m.*, "partition-specs") orelse &.{}, "spec-id", id) == null) return d.fail(error.BadRequest, "unknown spec id");
        try m.put("default-spec-id", json.i(id));
    } else if (eq(action, "add-sort-order")) {
        var order = (json.obj(u, "sort-order") orelse return d.fail(error.BadRequest, "add-sort-order needs sort-order")).clone() catch return error.OutOfMemory;
        if (json.get(order, "fields") == null) try order.put("fields", .{ .array = json.newArray(arena) });
        if (json.arr(order, "fields") == null) return d.fail(error.BadRequest, "sort order fields must be an array");
        const list = try listPtr(m, "sort-orders");
        if (list.items.len >= max_list_items) return d.fail(error.BadRequest, "too many sort orders");
        const unsorted = json.arr(order, "fields").?.len == 0;
        const want = json.int(order, "order-id");
        const id: i64 = if (unsorted) 0 else if (want != null and want.? > 0 and findById(list.items, "order-id", want.?) == null) want.? else @max(1, idsOf(list.items, "order-id") + 1);
        try order.put("order-id", json.i(id));
        if (findById(list.items, "order-id", id) == null) try list.append(.{ .object = order });
        st.last_order = id;
    } else if (eq(action, "set-default-sort-order")) {
        const id = try resolveLast(json.int(u, "sort-order-id"), st.last_order, d);
        if (findById(json.arr(m.*, "sort-orders") orelse &.{}, "order-id", id) == null) return d.fail(error.BadRequest, "unknown sort order id");
        try m.put("default-sort-order-id", json.i(id));
    } else if (eq(action, "add-snapshot")) {
        const snap = json.obj(u, "snapshot") orelse return d.fail(error.BadRequest, "add-snapshot needs snapshot");
        const id = json.int(snap, "snapshot-id") orelse return d.fail(error.BadRequest, "snapshot needs snapshot-id");
        if (json.int(snap, "timestamp-ms") == null or json.str(snap, "manifest-list") == null) return d.fail(error.BadRequest, "snapshot needs timestamp-ms and manifest-list");
        const list = try listPtr(m, "snapshots");
        if (list.items.len >= max_list_items) return d.fail(error.BadRequest, "too many snapshots");
        if (findById(list.items, "snapshot-id", id) != null) return d.fail(error.BadRequest, "snapshot id already exists");
        const seq = json.int(snap, "sequence-number") orelse return d.fail(error.BadRequest, "snapshot needs sequence-number");
        const last_seq = json.int(m.*, "last-sequence-number") orelse 0;
        if (seq <= last_seq and last_seq > 0) return d.fail(error.BadRequest, "snapshot sequence number is not newer than the table's");
        if (json.int(snap, "parent-snapshot-id")) |p| if (findById(list.items, "snapshot-id", p) == null)
            return d.fail(error.BadRequest, "parent snapshot does not exist");
        try list.append(.{ .object = snap });
        try m.put("last-sequence-number", json.i(@max(seq, last_seq)));
        try st.added_snapshots.append(arena, id);
    } else if (eq(action, "set-snapshot-ref")) {
        try setRef(arena, m, u, st, now_ms, d);
    } else if (eq(action, "remove-snapshots")) {
        const ids = json.arr(u, "snapshot-ids") orelse return d.fail(error.BadRequest, "remove-snapshots needs snapshot-ids");
        for (ids) |iv| {
            const id = json.asInt(iv) orelse return d.fail(error.BadRequest, "snapshot ids must be integers");
            try removeSnapshot(m, id);
        }
    } else if (eq(action, "remove-snapshot-ref")) {
        const name = json.str(u, "ref-name") orelse return d.fail(error.BadRequest, "remove-snapshot-ref needs ref-name");
        const refs = try mapPtr(m, "refs");
        _ = refs.orderedRemove(name);
        if (eq(name, "main")) try m.put("current-snapshot-id", json.i(-1));
    } else if (eq(action, "set-location")) {
        const loc = json.str(u, "location") orelse return d.fail(error.BadRequest, "set-location needs location");
        try m.put("location", json.s(std.mem.trimRight(u8, loc, "/")));
    } else if (eq(action, "set-properties")) {
        const ups = json.obj(u, "updates") orelse return d.fail(error.BadRequest, "set-properties needs updates");
        const props = try mapPtr(m, "properties");
        var it = ups.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* != .string) return d.fail(error.BadRequest, "property values must be strings");
            try props.put(e.key_ptr.*, e.value_ptr.*);
        }
    } else if (eq(action, "remove-properties")) {
        const rm = json.arr(u, "removals") orelse return d.fail(error.BadRequest, "remove-properties needs removals");
        const props = try mapPtr(m, "properties");
        for (rm) |k| switch (k) {
            .string => |name| _ = props.orderedRemove(name),
            else => return d.fail(error.BadRequest, "removals must be strings"),
        };
    } else if (eq(action, "set-statistics")) {
        const stats = json.obj(u, "statistics") orelse return d.fail(error.BadRequest, "set-statistics needs statistics");
        const id = json.int(stats, "snapshot-id") orelse return d.fail(error.BadRequest, "statistics need snapshot-id");
        try replaceBySnapshot(m, "statistics", id, .{ .object = stats });
    } else if (eq(action, "remove-statistics")) {
        const id = json.int(u, "snapshot-id") orelse return d.fail(error.BadRequest, "remove-statistics needs snapshot-id");
        try replaceBySnapshot(m, "statistics", id, null);
    } else if (eq(action, "set-partition-statistics")) {
        const stats = json.obj(u, "partition-statistics") orelse return d.fail(error.BadRequest, "set-partition-statistics needs partition-statistics");
        const id = json.int(stats, "snapshot-id") orelse return d.fail(error.BadRequest, "partition statistics need snapshot-id");
        try replaceBySnapshot(m, "partition-statistics", id, .{ .object = stats });
    } else if (eq(action, "remove-partition-statistics")) {
        const id = json.int(u, "snapshot-id") orelse return d.fail(error.BadRequest, "remove-partition-statistics needs snapshot-id");
        try replaceBySnapshot(m, "partition-statistics", id, null);
    } else if (eq(action, "remove-partition-specs")) {
        const ids = json.arr(u, "spec-ids") orelse return d.fail(error.BadRequest, "remove-partition-specs needs spec-ids");
        try removeIds(m, "partition-specs", "spec-id", ids, json.int(m.*, "default-spec-id"), d);
    } else if (eq(action, "remove-schemas")) {
        const ids = json.arr(u, "schema-ids") orelse return d.fail(error.BadRequest, "remove-schemas needs schema-ids");
        try removeIds(m, "schemas", "schema-id", ids, json.int(m.*, "current-schema-id"), d);
    } else if (eq(action, "enable-row-lineage") or eq(action, "add-encryption-key") or eq(action, "remove-encryption-key")) {
        return d.fail(error.Unsupported, "format v3 updates are not supported");
    } else {
        return d.fail(error.BadRequest, "unknown update action");
    }
}

fn resolveLast(id: ?i64, last: ?i64, d: *Diag) Error!i64 {
    const v = id orelse return d.fail(error.BadRequest, "id missing");
    if (v != -1) return v;
    return last orelse d.fail(error.BadRequest, "no item was added in this commit for id -1");
}

fn setRef(arena: Allocator, m: *ObjectMap, u: ObjectMap, st: *Applied, now_ms: i64, d: *Diag) Error!void {
    const name = json.str(u, "ref-name") orelse return d.fail(error.BadRequest, "set-snapshot-ref needs ref-name");
    const id = json.int(u, "snapshot-id") orelse return d.fail(error.BadRequest, "set-snapshot-ref needs snapshot-id");
    const kind = json.str(u, "type") orelse return d.fail(error.BadRequest, "set-snapshot-ref needs type");
    if (!eq(kind, "branch") and !eq(kind, "tag")) return d.fail(error.BadRequest, "ref type must be branch or tag");
    if (eq(name, "main") and !eq(kind, "branch")) return d.fail(error.BadRequest, "main must be a branch");
    const snaps = json.arr(m.*, "snapshots") orelse &.{};
    const idx = findById(snaps, "snapshot-id", id) orelse return d.fail(error.BadRequest, "ref points to an unknown snapshot");
    var ref = json.newObject(arena);
    try ref.put("snapshot-id", json.i(id));
    try ref.put("type", json.s(kind));
    for ([_][]const u8{ "max-ref-age-ms", "max-snapshot-age-ms", "min-snapshots-to-keep" }) |k| {
        if (json.int(u, k)) |v| try ref.put(k, json.i(v));
    }
    const refs = try mapPtr(m, "refs");
    try refs.put(name, .{ .object = ref });
    if (eq(name, "main")) {
        try m.put("current-snapshot-id", json.i(id));
        const added = std.mem.indexOfScalar(i64, st.added_snapshots.items, id) != null;
        const ts = if (added) json.int(snaps[idx].object, "timestamp-ms").? else now_ms;
        var entry = json.newObject(arena);
        try entry.put("timestamp-ms", json.i(ts));
        try entry.put("snapshot-id", json.i(id));
        const log = try listPtr(m, "snapshot-log");
        try log.append(.{ .object = entry });
        if (log.items.len > max_list_items) _ = log.orderedRemove(0);
    }
}

fn removeSnapshot(m: *ObjectMap, id: i64) error{OutOfMemory}!void {
    if (json.arrPtr(m, "snapshots")) |list| {
        if (findById(list.items, "snapshot-id", id)) |idx| _ = list.orderedRemove(idx);
    }
    if (json.arrPtr(m, "snapshot-log")) |log| {
        var k: usize = 0;
        while (k < log.items.len) {
            const hit = switch (log.items[k]) {
                .object => |o| json.int(o, "snapshot-id") == id,
                else => false,
            };
            if (hit) _ = log.orderedRemove(k) else k += 1;
        }
    }
    var main_gone = false;
    if (json.objPtr(m, "refs")) |refs| {
        var k: usize = 0;
        while (k < refs.count()) {
            const hit = switch (refs.values()[k]) {
                .object => |o| json.int(o, "snapshot-id") == id,
                else => false,
            };
            if (hit) {
                main_gone = main_gone or eq(refs.keys()[k], "main");
                refs.orderedRemoveAt(k);
            } else k += 1;
        }
    }
    if (main_gone) try m.put("current-snapshot-id", json.i(-1));
    try replaceBySnapshot(m, "statistics", id, null);
    try replaceBySnapshot(m, "partition-statistics", id, null);
}

fn replaceBySnapshot(m: *ObjectMap, key: []const u8, id: i64, with: ?Value) error{OutOfMemory}!void {
    const list = try listPtr(m, key);
    if (findById(list.items, "snapshot-id", id)) |idx| _ = list.orderedRemove(idx);
    if (with) |w| try list.append(w);
}

fn removeIds(m: *ObjectMap, key: []const u8, id_key: []const u8, ids: []const Value, protected: ?i64, d: *Diag) Error!void {
    const list = try listPtr(m, key);
    for (ids) |iv| {
        const id = json.asInt(iv) orelse return d.fail(error.BadRequest, "ids must be integers");
        if (protected != null and protected.? == id) return d.fail(error.BadRequest, "cannot remove the current item");
        if (findById(list.items, id_key, id)) |idx| _ = list.orderedRemove(idx);
    }
}

/// Records the replaced metadata file, trimmed to write.metadata.previous-versions-max.
pub fn appendMetadataLog(arena: Allocator, m: *ObjectMap, prev_location: []const u8, prev_ts: i64) error{OutOfMemory}!void {
    var keep: i64 = 100;
    if (json.obj(m.*, "properties")) |p| if (json.str(p, "write.metadata.previous-versions-max")) |v| {
        keep = std.math.clamp(std.fmt.parseInt(i64, v, 10) catch 100, 1, 10_000);
    };
    var entry = json.newObject(arena);
    try entry.put("timestamp-ms", json.i(prev_ts));
    try entry.put("metadata-file", json.s(prev_location));
    const log = try listPtr(m, "metadata-log");
    try log.append(.{ .object = entry });
    while (log.items.len > @as(usize, @intCast(keep))) _ = log.orderedRemove(0);
}

const testing = std.testing;

fn testSchema(arena: Allocator) !Value {
    return json.parse(arena,
        \\{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"a","required":false,"type":"long"},
        \\{"id":2,"name":"s","required":false,"type":{"type":"struct","fields":[{"id":3,"name":"x","required":false,"type":"int"}]}}]}
    );
}

test "create, requirements and updates" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var d: Diag = .{};
    var m = try create(ar, .{ .location = "s3://b/t", .schema = try testSchema(ar), .uuid = "u-1", .now_ms = 1 }, &d);
    try testing.expectEqual(@as(?i64, 3), json.int(m, "last-column-id"));
    try testing.expectEqual(@as(?i64, 999), json.int(m, "last-partition-id"));

    const ok = try json.parse(ar, "[{\"type\":\"assert-current-schema-id\",\"current-schema-id\":0},{\"type\":\"assert-table-uuid\",\"uuid\":\"U-1\"},{\"type\":\"assert-ref-snapshot-id\",\"ref\":\"main\",\"snapshot-id\":null}]");
    try checkRequirements(m, ok.array.items, &d);
    const stale = try json.parse(ar, "[{\"type\":\"assert-current-schema-id\",\"current-schema-id\":5}]");
    try testing.expectError(error.CommitFailed, checkRequirements(m, stale.array.items, &d));
    const create_req = try json.parse(ar, "[{\"type\":\"assert-create\"}]");
    try testing.expectError(error.CommitFailed, checkRequirements(m, create_req.array.items, &d));
    try checkRequirements(null, create_req.array.items, &d);

    const ups = try json.parse(ar,
        \\[{"action":"add-snapshot","snapshot":{"snapshot-id":7,"sequence-number":1,"timestamp-ms":5,"manifest-list":"s3://b/t/m.avro","summary":{"operation":"append"}}},
        \\{"action":"set-snapshot-ref","ref-name":"main","type":"branch","snapshot-id":7},
        \\{"action":"add-schema","schema":{"type":"struct","fields":[{"id":1,"name":"a","required":false,"type":"long"},{"id":4,"name":"b","required":false,"type":"string"}]}},
        \\{"action":"set-current-schema","schema-id":-1},
        \\{"action":"set-properties","updates":{"k":"v"}},{"action":"remove-properties","removals":["k","nope"]}]
    );
    try applyUpdates(ar, &m, ups.array.items, 10, &d);
    try testing.expectEqual(@as(?i64, 7), json.int(m, "current-snapshot-id"));
    try testing.expectEqual(@as(?i64, 1), json.int(m, "current-schema-id"));
    try testing.expectEqual(@as(?i64, 4), json.int(m, "last-column-id"));
    try testing.expectEqual(@as(?i64, 1), json.int(m, "last-sequence-number"));
    const refreq = try json.parse(ar, "[{\"type\":\"assert-ref-snapshot-id\",\"ref\":\"main\",\"snapshot-id\":null}]");
    try testing.expectError(error.CommitFailed, checkRequirements(m, refreq.array.items, &d));

    const rm = try json.parse(ar, "[{\"action\":\"remove-snapshots\",\"snapshot-ids\":[7]}]");
    try applyUpdates(ar, &m, rm.array.items, 11, &d);
    try testing.expectEqual(@as(?i64, -1), json.int(m, "current-snapshot-id"));
    try testing.expectEqual(@as(usize, 0), json.arr(m, "snapshot-log").?.len);
    _ = try json.stringify(ar, .{ .object = m });
}

test "hostile updates are rejected, not crashed on" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var d: Diag = .{};
    const cases = [_][]const u8{
        "[1]",                                                             "[{}]",
        "[{\"action\":7}]",                                                "[{\"action\":\"nope\"}]",
        "[{\"action\":\"add-schema\",\"schema\":{\"type\":\"list\"}}]",    "[{\"action\":\"add-schema\",\"schema\":{\"type\":\"struct\",\"fields\":[1]}}]",
        "[{\"action\":\"set-current-schema\",\"schema-id\":-1}]",          "[{\"action\":\"set-current-schema\",\"schema-id\":42}]",
        "[{\"action\":\"set-snapshot-ref\",\"ref-name\":\"main\",\"type\":\"branch\",\"snapshot-id\":1}]",
        "[{\"action\":\"set-properties\",\"updates\":{\"a\":1}}]",
        "[{\"action\":\"remove-snapshots\",\"snapshot-ids\":[\"x\"]}]",     "[{\"action\":\"add-snapshot\",\"snapshot\":{\"snapshot-id\":1}}]",
        "[{\"action\":\"remove-schemas\",\"schema-ids\":[0]}]",            "[{\"action\":\"add-spec\",\"spec\":{\"fields\":[{\"source-id\":1}]}}]",
        "[{\"action\":\"set-default-sort-order\",\"sort-order-id\":99}]",
    };
    for (cases) |c| {
        var m = try create(ar, .{ .location = "s3://b/t", .schema = try testSchema(ar), .uuid = "u", .now_ms = 1 }, &d);
        const v = try json.parse(ar, c);
        try testing.expectError(error.BadRequest, applyUpdates(ar, &m, v.array.items, 2, &d));
    }
    const reqs = [_][]const u8{ "[1]", "[{\"type\":\"nope\"}]", "[{\"type\":\"assert-current-schema-id\"}]", "[{\"type\":\"assert-table-uuid\"}]" };
    const m = try create(ar, .{ .location = "s3://b/t", .schema = try testSchema(ar), .uuid = "u", .now_ms = 1 }, &d);
    for (reqs) |c| {
        const v = try json.parse(ar, c);
        try testing.expectError(error.BadRequest, checkRequirements(m, v.array.items, &d));
    }
}

test "staged create fills defaults" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var d: Diag = .{};
    var m = try skeleton(ar, "u", 1);
    try testing.expectError(error.BadRequest, completeStaged(ar, &m, "s3://b/x", &d));
    const ups = try json.parse(ar,
        \\[{"action":"assign-uuid","uuid":"u"},{"action":"upgrade-format-version","format-version":2},
        \\{"action":"add-schema","schema":{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"a","required":false,"type":"long"}]}},
        \\{"action":"set-current-schema","schema-id":-1},{"action":"add-sort-order","sort-order":{"order-id":0,"fields":[]}},
        \\{"action":"set-default-sort-order","sort-order-id":-1}]
    );
    try applyUpdates(ar, &m, ups.array.items, 2, &d);
    try completeStaged(ar, &m, "s3://b/x", &d);
    try testing.expectEqualStrings("s3://b/x", json.str(m, "location").?);
    try testing.expectEqual(@as(?i64, 0), json.int(m, "default-spec-id"));
}

test "max field id over nested types" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const v = try json.parse(a.allocator(),
        \\{"type":"struct","fields":[{"id":1,"name":"m","required":true,"type":{"type":"map","key-id":5,"key":"string","value-id":9,"value":{"type":"list","element-id":11,"element":"int","element-required":true}}}]}
    );
    try testing.expectEqual(@as(i64, 11), maxFieldId(v));
}
