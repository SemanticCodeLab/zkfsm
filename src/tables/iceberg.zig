//! Iceberg REST catalog: /v1/config and /v1/{prefix}/namespaces|tables routes.
//! The prefix (warehouse) names a table bucket; commits CAS the table pointer.
const std = @import("std");
const json = @import("json.zig");
const http = @import("http.zig");
const catalog = @import("catalog.zig");
const meta = @import("metadata.zig");
const route = @import("route.zig");

const Req = http.Req;
const RawError = http.RawError;
const Tables = route.Tables;
const Catalog = catalog.Catalog;
const Allocator = std.mem.Allocator;

const endpoints = [_][]const u8{
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}",
    "HEAD /v1/{prefix}/namespaces/{namespace}",
    "DELETE /v1/{prefix}/namespaces/{namespace}",
    "POST /v1/{prefix}/namespaces/{namespace}/properties",
    "GET /v1/{prefix}/namespaces/{namespace}/tables",
    "POST /v1/{prefix}/namespaces/{namespace}/tables",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
    "POST /v1/{prefix}/namespaces/{namespace}/register",
    "POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/metrics",
    "POST /v1/{prefix}/tables/rename",
};

/// Default data location for a new table: one prefix per table UUID.
pub fn defaultLocation(arena: Allocator, bucket: []const u8, uuid: []const u8) error{OutOfMemory}![]const u8 {
    return std.fmt.allocPrint(arena, "s3://{s}/tables/{s}", .{ bucket, uuid });
}

/// A location the catalog may write under: this bucket, outside the reserved prefix.
pub fn ownLocation(bucket: []const u8, loc: []const u8) bool {
    const l = catalog.parseLocation(loc) orelse return false;
    if (!std.mem.eql(u8, l.bucket, bucket) or l.key.len == 0) return false;
    if (std.mem.startsWith(u8, l.key, catalog.reserved_prefix[0 .. catalog.reserved_prefix.len - 1])) return false;
    return std.mem.indexOf(u8, l.key, "..") == null;
}

/// Warehouse given as a bucket name, a table bucket ARN, or s3://bucket.
pub fn warehouseBucket(w: []const u8) []const u8 {
    var v = w;
    if (std.mem.startsWith(u8, v, "arn:")) {
        const i = std.mem.indexOf(u8, v, ":bucket/") orelse return "";
        v = v[i + ":bucket/".len ..];
    } else if (catalog.parseLocation(v)) |l| v = l.bucket;
    return v[0 .. std.mem.indexOfScalar(u8, v, '/') orelse v.len];
}

pub fn handle(t: *Tables, r: *Req, rest: []const u8) RawError!void {
    const segs = try http.segments(r.arena, rest);
    if (segs.len == 1 and std.mem.eql(u8, segs[0], "config")) {
        if (r.method != .GET) return r.iceberg(.method_not_allowed, "BadRequestException", "method not allowed");
        return config(t, r);
    }
    if (segs.len < 2) return r.iceberg(.not_found, "NotFoundException", "unknown catalog route");
    const wh = http.decode(r.arena, segs[0]) catch return r.iceberg(.bad_request, "BadRequestException", "malformed prefix");
    const bucket = warehouseBucket(wh);
    const cat = t.catalogOf();
    _ = (cat.getBucket(r.arena, bucket) catch |e| return storeFail(r, e)) orelse
        return r.iceberg(.not_found, "NoSuchWarehouseException", "warehouse is not a table bucket");
    const s = segs[1..];
    var c: Call = .{ .t = t, .r = r, .cat = cat, .bucket = bucket };
    if (std.mem.eql(u8, s[0], "tables") and s.len == 2 and std.mem.eql(u8, s[1], "rename")) {
        if (r.method != .POST) return methodNotAllowed(r);
        return c.rename();
    }
    if (std.mem.eql(u8, s[0], "transactions")) return r.iceberg(.not_acceptable, "UnsupportedOperationException", "multi-table transactions are not supported");
    if (!std.mem.eql(u8, s[0], "namespaces")) return r.iceberg(.not_found, "NotFoundException", "unknown catalog route");
    if (s.len == 1) return switch (r.method) {
        .GET => c.listNamespaces(),
        .POST => c.createNamespace(),
        else => methodNotAllowed(r),
    };
    const levels = parseNamespace(r.arena, s[1]) catch return r.iceberg(.bad_request, "BadRequestException", "malformed namespace");
    if (!catalog.validLevels(levels)) return r.iceberg(.bad_request, "BadRequestException", "invalid namespace name");
    if (s.len == 2) return switch (r.method) {
        .GET, .HEAD => c.loadNamespace(levels),
        .DELETE => c.dropNamespace(levels),
        else => methodNotAllowed(r),
    };
    const sub = s[2];
    if (s.len == 3) {
        if (std.mem.eql(u8, sub, "properties")) return if (r.method == .POST) c.updateProperties(levels) else methodNotAllowed(r);
        if (std.mem.eql(u8, sub, "register")) return if (r.method == .POST) c.register(levels) else methodNotAllowed(r);
        if (std.mem.eql(u8, sub, "views")) return if (r.method == .GET) r.sendJson(.ok, try emptyIdentifiers(r.arena)) else viewsUnsupported(r);
        if (std.mem.eql(u8, sub, "tables")) return switch (r.method) {
            .GET => c.listTables(levels),
            .POST => c.createTable(levels),
            else => methodNotAllowed(r),
        };
        return r.iceberg(.not_found, "NotFoundException", "unknown catalog route");
    }
    if (std.mem.eql(u8, sub, "views")) return viewsUnsupported(r);
    if (!std.mem.eql(u8, sub, "tables")) return r.iceberg(.not_found, "NotFoundException", "unknown catalog route");
    const name = http.decode(r.arena, s[3]) catch return r.iceberg(.bad_request, "BadRequestException", "malformed table name");
    if (!catalog.validName(name)) return r.iceberg(.bad_request, "BadRequestException", "invalid table name");
    if (s.len == 4) return switch (r.method) {
        .GET => c.loadTable(levels, name),
        .HEAD => c.tableExists(levels, name),
        .POST => c.commit(levels, name),
        .DELETE => c.dropTable(levels, name),
        else => methodNotAllowed(r),
    };
    if (s.len == 5 and std.mem.eql(u8, s[4], "metrics")) {
        if (r.method != .POST) return methodNotAllowed(r);
        if (!try c.allow("s3tables:GetTable", null)) return c.denied();
        return r.noContent();
    }
    return r.iceberg(.not_found, "NotFoundException", "unknown catalog route");
}

fn methodNotAllowed(r: *Req) RawError!void {
    return r.iceberg(.method_not_allowed, "BadRequestException", "method not allowed");
}

fn viewsUnsupported(r: *Req) RawError!void {
    return r.iceberg(.not_found, "NoSuchViewException", "views are not supported");
}

fn emptyIdentifiers(arena: Allocator) error{OutOfMemory}!json.Value {
    var o = json.newObject(arena);
    try o.put("identifiers", .{ .array = json.newArray(arena) });
    return .{ .object = o };
}

/// Namespace path segment: percent-decoded, levels split on 0x1F.
pub fn parseNamespace(arena: Allocator, seg: []const u8) error{ OutOfMemory, InvalidUri }![]const []const u8 {
    const raw = try http.decode(arena, seg);
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, raw, 0x1f);
    while (it.next()) |l| {
        if (out.items.len > catalog.max_levels) return error.InvalidUri;
        try out.append(arena, l);
    }
    return out.items;
}

fn storeFail(r: *Req, e: catalog.Error) RawError!void {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidName, error.KeyTooLong => r.iceberg(.bad_request, "BadRequestException", "identifier is invalid or too long"),
        error.NoSuchBucket, error.NotTableBucket => r.iceberg(.not_found, "NoSuchWarehouseException", "warehouse is not a table bucket"),
        error.TooLarge => r.iceberg(.internal_server_error, "ServiceFailureException", "catalog document too large"),
        error.Corrupt => r.iceberg(.internal_server_error, "ServiceFailureException", "catalog document is corrupt"),
        else => r.iceberg(.service_unavailable, "ServiceUnavailableException", "catalog storage failed"),
    };
}

fn config(t: *Tables, r: *Req) RawError!void {
    const wh = try r.param("warehouse") orelse return r.iceberg(.bad_request, "BadRequestException", "warehouse parameter is required");
    const bucket = warehouseBucket(wh);
    if (!try t.allowed(r, "s3tables:GetTableBucket", bucket, null)) return r.iceberg(.forbidden, "ForbiddenException", "access denied");
    _ = (t.catalogOf().getBucket(r.arena, bucket) catch |e| return storeFail(r, e)) orelse
        return r.iceberg(.not_found, "NoSuchWarehouseException", "warehouse is not a table bucket");
    var defaults = json.newObject(r.arena);
    try defaults.put("rest-page-size", json.s("1000"));
    var overrides = json.newObject(r.arena);
    try overrides.put("prefix", json.s(bucket));
    var o = json.newObject(r.arena);
    try o.put("defaults", .{ .object = defaults });
    try o.put("overrides", .{ .object = overrides });
    try o.put("endpoints", try json.stringArray(r.arena, &endpoints));
    return r.sendObject(.ok, o);
}

const Call = struct {
    t: *Tables,
    r: *Req,
    cat: Catalog,
    bucket: []const u8,

    fn allow(c: *Call, action: []const u8, uuid: ?[]const u8) RawError!bool {
        return c.t.allowed(c.r, action, c.bucket, uuid);
    }

    fn denied(c: *Call) RawError!void {
        return c.r.iceberg(.forbidden, "ForbiddenException", "access denied");
    }

    fn bad(c: *Call, msg: []const u8) RawError!void {
        return c.r.iceberg(.bad_request, "BadRequestException", msg);
    }

    fn noNamespace(c: *Call) RawError!void {
        return c.r.iceberg(.not_found, "NoSuchNamespaceException", "namespace does not exist");
    }

    fn noTable(c: *Call) RawError!void {
        return c.r.iceberg(.not_found, "NoSuchTableException", "table does not exist");
    }

    fn body(c: *Call) RawError!?json.ObjectMap {
        return json.parseObject(c.r.arena, c.r.body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try c.bad("request body must be a JSON object");
                return null;
            },
        };
    }

    fn pageSize(c: *Call) RawError!?usize {
        const v = try c.r.param("pageSize") orelse return catalog.max_page;
        const n = std.fmt.parseInt(usize, v, 10) catch 0;
        if (n == 0) {
            try c.bad("invalid pageSize");
            return null;
        }
        return @min(n, catalog.max_page);
    }

    fn nsValue(c: *Call, levels: []const []const u8) RawError!json.Value {
        return json.stringArray(c.r.arena, levels);
    }

    fn listNamespaces(c: *Call) RawError!void {
        if (!try c.allow("s3tables:ListNamespaces", null)) return c.denied();
        var parent: []const []const u8 = &.{};
        if (try c.r.param("parent")) |p| if (p.len > 0) {
            parent = parseNamespace(c.r.arena, p) catch return c.bad("malformed parent");
            if (!catalog.validLevels(parent)) return c.bad("invalid parent namespace");
            _ = (c.cat.getNamespace(c.r.arena, c.bucket, parent) catch |e| return storeFail(c.r, e)) orelse return c.noNamespace();
        };
        const max = try c.pageSize() orelse return;
        const token = try c.r.param("pageToken") orelse "";
        const page = c.cat.listNamespaces(c.r.arena, c.bucket, parent, "", token, max) catch |e| return storeFail(c.r, e);
        var list = json.newArray(c.r.arena);
        for (page.items) |l| try list.append(try c.nsValue(l));
        var o = json.newObject(c.r.arena);
        try o.put("namespaces", .{ .array = list });
        if (page.next) |n| try o.put("next-page-token", json.s(n));
        return c.r.sendObject(.ok, o);
    }

    fn createNamespace(c: *Call) RawError!void {
        if (!try c.allow("s3tables:CreateNamespace", null)) return c.denied();
        const b = try c.body() orelse return;
        const nv = json.get(b, "namespace") orelse return c.bad("namespace is required");
        const levels = try json.strings(c.r.arena, nv) orelse return c.bad("namespace must be an array of strings");
        if (!catalog.validLevels(levels)) return c.bad("invalid namespace name");
        var props = json.newObject(c.r.arena);
        if (json.get(b, "properties")) |pv| {
            const po = switch (pv) {
                .object => |o| o,
                else => return c.bad("properties must be an object"),
            };
            var it = po.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* != .string) return c.bad("property values must be strings");
                try props.put(e.key_ptr.*, e.value_ptr.*);
            }
        }
        var ub: [36]u8 = undefined;
        c.cat.createNamespace(c.r.arena, c.bucket, .{
            .levels = levels,
            .id = meta.uuid4(&ub),
            .created_ms = catalog.nowMs(),
            .created_by = c.r.who(),
            .properties = props,
        }) catch |e| return switch (e) {
            error.AlreadyExists => c.r.iceberg(.conflict, "AlreadyExistsException", "namespace already exists"),
            else => storeFail(c.r, e),
        };
        var o = json.newObject(c.r.arena);
        try o.put("namespace", try c.nsValue(levels));
        try o.put("properties", .{ .object = props });
        return c.r.sendObject(.ok, o);
    }

    fn loadNamespace(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:GetNamespace", null)) return c.denied();
        const ns = (c.cat.getNamespace(c.r.arena, c.bucket, levels) catch |e| return storeFail(c.r, e)) orelse return c.noNamespace();
        if (c.r.method == .HEAD) return c.r.noContent();
        var o = json.newObject(c.r.arena);
        try o.put("namespace", try c.nsValue(levels));
        try o.put("properties", .{ .object = ns.properties });
        return c.r.sendObject(.ok, o);
    }

    fn dropNamespace(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:DeleteNamespace", null)) return c.denied();
        c.cat.dropNamespace(c.r.arena, c.bucket, levels) catch |e| return switch (e) {
            error.NotFound => c.noNamespace(),
            error.NotEmpty => c.r.iceberg(.conflict, "NamespaceNotEmptyException", "namespace is not empty"),
            else => storeFail(c.r, e),
        };
        return c.r.noContent();
    }

    fn updateProperties(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:CreateNamespace", null)) return c.denied();
        const b = try c.body() orelse return;
        const a = c.r.arena;
        const removals = if (json.get(b, "removals")) |v| try json.strings(a, v) orelse return c.bad("removals must be strings") else &[_][]const u8{};
        const updates = json.obj(b, "updates") orelse json.newObject(a);
        for (removals) |k| if (updates.contains(k)) return c.r.iceberg(.unprocessable_entity, "UnprocessableEntityException", "a key is both updated and removed");
        var it = updates.iterator();
        while (it.next()) |e| if (e.value_ptr.* != .string) return c.bad("property values must be strings");
        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            var ns = (c.cat.getNamespace(a, c.bucket, levels) catch |e| return storeFail(c.r, e)) orelse return c.noNamespace();
            var props = try ns.properties.clone();
            var removed = json.newArray(a);
            var missing = json.newArray(a);
            for (removals) |k| {
                if (props.orderedRemove(k)) try removed.append(json.s(k)) else try missing.append(json.s(k));
            }
            var updated = json.newArray(a);
            var ui = updates.iterator();
            while (ui.next()) |e| {
                try props.put(e.key_ptr.*, e.value_ptr.*);
                try updated.append(json.s(e.key_ptr.*));
            }
            ns.properties = props;
            c.cat.updateNamespace(a, c.bucket, ns) catch |e| switch (e) {
                error.PreconditionFailed => if (attempt < 8) continue else return c.r.iceberg(.conflict, "CommitFailedException", "namespace changed concurrently"),
                else => return storeFail(c.r, e),
            };
            var o = json.newObject(a);
            try o.put("updated", .{ .array = updated });
            try o.put("removed", .{ .array = removed });
            try o.put("missing", .{ .array = missing });
            return c.r.sendObject(.ok, o);
        }
    }

    fn listTables(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:ListTables", null)) return c.denied();
        _ = (c.cat.getNamespace(c.r.arena, c.bucket, levels) catch |e| return storeFail(c.r, e)) orelse return c.noNamespace();
        const max = try c.pageSize() orelse return;
        const token = try c.r.param("pageToken") orelse "";
        const page = c.cat.listTables(c.r.arena, c.bucket, levels, "", token, max) catch |e| return storeFail(c.r, e);
        var list = json.newArray(c.r.arena);
        for (page.items) |tb| {
            var id = json.newObject(c.r.arena);
            try id.put("namespace", try c.nsValue(tb.levels));
            try id.put("name", json.s(tb.name));
            try list.append(.{ .object = id });
        }
        var o = json.newObject(c.r.arena);
        try o.put("identifiers", .{ .array = list });
        if (page.next) |n| try o.put("next-page-token", json.s(n));
        return c.r.sendObject(.ok, o);
    }

    /// Loads the table's current metadata bytes; answers and returns null on failure.
    fn readMetadata(c: *Call, tb: catalog.Table) RawError!?[]const u8 {
        const loc = tb.metadata_location orelse {
            try c.r.iceberg(.not_found, "NoSuchTableException", "table has no metadata yet");
            return null;
        };
        const l = catalog.parseLocation(loc) orelse {
            try c.r.iceberg(.internal_server_error, "ServiceFailureException", "metadata location is not an s3 URL");
            return null;
        };
        if (!std.mem.eql(u8, l.bucket, c.bucket)) {
            try c.r.iceberg(.internal_server_error, "ServiceFailureException", "metadata location is outside the table bucket");
            return null;
        }
        const doc = c.t.store.read(c.r.arena, c.bucket, l.key, catalog.max_metadata) catch |e| {
            try storeFail(c.r, e);
            return null;
        } orelse {
            try c.r.iceberg(.internal_server_error, "ServiceFailureException", "metadata file is missing");
            return null;
        };
        return doc.body;
    }

    fn loadResult(c: *Call, location: ?[]const u8, metadata_json: []const u8) RawError!void {
        var w: std.Io.Writer.Allocating = .init(c.r.arena);
        const out = &w.writer;
        out.writeByte('{') catch return error.OutOfMemory;
        if (location) |l| {
            out.writeAll("\"metadata-location\":") catch return error.OutOfMemory;
            out.writeAll(try json.stringify(c.r.arena, json.s(l))) catch return error.OutOfMemory;
            out.writeByte(',') catch return error.OutOfMemory;
        }
        out.print("\"metadata\":{s},\"config\":{{}}}}", .{metadata_json}) catch return error.OutOfMemory;
        return c.r.send(.ok, w.written(), &.{});
    }

    fn loadTable(c: *Call, levels: []const []const u8, name: []const u8) RawError!void {
        const tb = (c.cat.getTable(c.r.arena, c.bucket, levels, name) catch |e| return storeFail(c.r, e)) orelse return c.noTable();
        if (!try c.allow("s3tables:GetTableMetadataLocation", tb.uuid)) return c.denied();
        const bytes = try c.readMetadata(tb) orelse return;
        if (!json.depthOk(bytes) or !(std.json.validate(c.r.arena, bytes) catch false))
            return c.r.iceberg(.internal_server_error, "ServiceFailureException", "metadata file is not valid JSON");
        return c.loadResult(tb.metadata_location, bytes);
    }

    fn tableExists(c: *Call, levels: []const []const u8, name: []const u8) RawError!void {
        const tb = (c.cat.getTable(c.r.arena, c.bucket, levels, name) catch |e| return storeFail(c.r, e)) orelse return c.noTable();
        if (!try c.allow("s3tables:GetTable", tb.uuid)) return c.denied();
        return c.r.noContent();
    }

    /// Writes metadata file number `gen` under the table location; returns its URL.
    fn writeMetadata(c: *Call, m: json.ObjectMap, gen: i64) RawError!?[]const u8 {
        const a = c.r.arena;
        const location = json.str(m, "location") orelse "";
        if (!ownLocation(c.bucket, location)) {
            try c.bad("table location must be inside the warehouse bucket");
            return null;
        }
        var ub: [36]u8 = undefined;
        const url = try std.fmt.allocPrint(a, "{s}/metadata/{d:0>5}-{s}.metadata.json", .{ std.mem.trimRight(u8, location, "/"), @as(u64, @intCast(@max(gen, 0))), meta.uuid4(&ub) });
        const key = catalog.parseLocation(url).?.key;
        const bytes = try json.stringify(a, .{ .object = m });
        _ = c.t.store.write(c.bucket, key, bytes, .create) catch |e| {
            try storeFail(c.r, e);
            return null;
        };
        return url;
    }

    fn dropFile(c: *Call, url: []const u8) void {
        const l = catalog.parseLocation(url) orelse return;
        c.t.store.remove(c.bucket, l.key) catch {};
    }

    fn metaFail(c: *Call, e: meta.Error, d: meta.Diag) RawError!void {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.BadRequest => c.bad(d.msg),
            error.CommitFailed => c.r.iceberg(.conflict, "CommitFailedException", d.msg),
            error.Unsupported => c.r.iceberg(.not_acceptable, "UnsupportedOperationException", d.msg),
        };
    }

    fn createTable(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:CreateTable", null)) return c.denied();
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const name = json.str(b, "name") orelse return c.bad("name is required");
        if (!catalog.validName(name)) return c.bad("invalid table name");
        const schema = json.get(b, "schema") orelse return c.bad("schema is required");
        _ = (c.cat.getNamespace(a, c.bucket, levels) catch |e| return storeFail(c.r, e)) orelse return c.noNamespace();
        if ((c.cat.getTable(a, c.bucket, levels, name) catch |e| return storeFail(c.r, e)) != null)
            return c.r.iceberg(.conflict, "AlreadyExistsException", "table already exists");
        var ub: [36]u8 = undefined;
        const uuid = try a.dupe(u8, meta.uuid4(&ub));
        const location = if (json.str(b, "location")) |l| std.mem.trimRight(u8, l, "/") else try defaultLocation(a, c.bucket, uuid);
        if (!ownLocation(c.bucket, location)) return c.bad("table location must be inside the warehouse bucket");
        var d: meta.Diag = .{};
        const m = meta.create(a, .{
            .location = location,
            .schema = schema,
            .spec = json.obj(b, "partition-spec"),
            .order = json.obj(b, "write-order"),
            .properties = json.obj(b, "properties"),
            .uuid = uuid,
            .now_ms = catalog.nowMs(),
        }, &d) catch |e| return c.metaFail(e, d);
        if (json.boolean(b, "stage-create") orelse false) return c.loadResult(null, try json.stringify(a, .{ .object = m }));
        const url = try c.writeMetadata(m, 0) orelse return;
        const now = catalog.nowMs();
        _ = c.cat.createTable(a, c.bucket, .{
            .levels = levels,
            .name = name,
            .uuid = uuid,
            .metadata_location = url,
            .warehouse = location,
            .created_ms = now,
            .modified_ms = now,
            .created_by = c.r.who(),
            .modified_by = c.r.who(),
        }) catch |e| {
            c.dropFile(url);
            return switch (e) {
                error.AlreadyExists => c.r.iceberg(.conflict, "AlreadyExistsException", "table already exists"),
                error.NotFound => c.noNamespace(),
                else => storeFail(c.r, e),
            };
        };
        return c.loadResult(url, try json.stringify(a, .{ .object = m }));
    }

    fn register(c: *Call, levels: []const []const u8) RawError!void {
        if (!try c.allow("s3tables:CreateTable", null)) return c.denied();
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const name = json.str(b, "name") orelse return c.bad("name is required");
        if (!catalog.validName(name)) return c.bad("invalid table name");
        const loc = json.str(b, "metadata-location") orelse return c.bad("metadata-location is required");
        if (json.boolean(b, "overwrite") orelse false) return c.r.iceberg(.not_acceptable, "UnsupportedOperationException", "register with overwrite is not supported");
        const l = catalog.parseLocation(loc) orelse return c.bad("metadata-location must be an s3 URL");
        if (!std.mem.eql(u8, l.bucket, c.bucket)) return c.bad("metadata-location must be inside the warehouse bucket");
        const doc = (c.t.store.read(a, c.bucket, l.key, catalog.max_metadata) catch |e| return storeFail(c.r, e)) orelse return c.bad("metadata file does not exist");
        const m = json.parseObject(a, doc.body) catch return c.bad("metadata file is not a JSON object");
        const uuid = json.str(m, "table-uuid") orelse return c.bad("metadata has no table-uuid");
        const location = json.str(m, "location") orelse return c.bad("metadata has no location");
        if (!ownLocation(c.bucket, location)) return c.bad("table location must be inside the warehouse bucket");
        const now = catalog.nowMs();
        _ = c.cat.createTable(a, c.bucket, .{
            .levels = levels,
            .name = name,
            .uuid = uuid,
            .metadata_location = loc,
            .warehouse = location,
            .created_ms = now,
            .modified_ms = now,
            .created_by = c.r.who(),
            .modified_by = c.r.who(),
            .gen = metadataGen(loc),
        }) catch |e| return switch (e) {
            error.AlreadyExists => c.r.iceberg(.conflict, "AlreadyExistsException", "table already exists"),
            error.NotFound => c.noNamespace(),
            else => storeFail(c.r, e),
        };
        return c.loadResult(loc, doc.body);
    }

    fn commit(c: *Call, levels: []const []const u8, name: []const u8) RawError!void {
        const a = c.r.arena;
        const b = try c.body() orelse return;
        if (json.obj(b, "identifier")) |id| {
            const n = json.str(id, "name") orelse return c.bad("identifier needs name");
            const nsv = json.get(id, "namespace") orelse return c.bad("identifier needs namespace");
            const lv = try json.strings(a, nsv) orelse return c.bad("identifier namespace must be strings");
            if (!std.mem.eql(u8, n, name) or !sameLevels(lv, levels)) return c.bad("identifier does not match the URL");
        }
        const reqs = if (json.get(b, "requirements")) |v| switch (v) {
            .array => |x| x.items,
            else => return c.bad("requirements must be an array"),
        } else &[_]json.Value{};
        const updates = if (json.get(b, "updates")) |v| switch (v) {
            .array => |x| x.items,
            else => return c.bad("updates must be an array"),
        } else &[_]json.Value{};
        const existing = c.cat.getTable(a, c.bucket, levels, name) catch |e| return storeFail(c.r, e);
        var d: meta.Diag = .{};
        const now = catalog.nowMs();
        const tb = existing orelse {
            if (!isCreate(reqs)) return c.noTable();
            return c.commitCreate(levels, name, reqs, updates);
        };
        if (!try c.allow("s3tables:UpdateTableMetadataLocation", tb.uuid)) return c.denied();
        const bytes = try c.readMetadata(tb) orelse return;
        var m = json.parseObject(a, bytes) catch return c.r.iceberg(.internal_server_error, "ServiceFailureException", "current metadata is not valid JSON");
        meta.checkRequirements(m, reqs, &d) catch |e| return c.metaFail(e, d);
        const prev_ts = json.int(m, "last-updated-ms") orelse now;
        meta.applyUpdates(a, &m, updates, now, &d) catch |e| return c.metaFail(e, d);
        try meta.appendMetadataLog(a, &m, tb.metadata_location.?, prev_ts);
        const gen = @max(tb.gen, metadataGen(tb.metadata_location.?)) + 1;
        const url = try c.writeMetadata(m, gen) orelse return;
        var next = tb;
        next.metadata_location = url;
        next.warehouse = json.str(m, "location") orelse tb.warehouse;
        next.modified_ms = now;
        next.modified_by = c.r.who();
        next.gen = gen;
        _ = c.cat.swapTable(a, c.bucket, next) catch |e| {
            c.dropFile(url);
            return switch (e) {
                error.PreconditionFailed, error.NotFound => c.r.iceberg(.conflict, "CommitFailedException", "table was updated concurrently; refresh and retry"),
                else => storeFail(c.r, e),
            };
        };
        return c.loadResult(url, try json.stringify(a, .{ .object = m }));
    }

    /// Staged create: an assert-create commit publishes the first metadata file.
    fn commitCreate(c: *Call, levels: []const []const u8, name: []const u8, reqs: []const json.Value, updates: []const json.Value) RawError!void {
        if (!try c.allow("s3tables:CreateTable", null)) return c.denied();
        const a = c.r.arena;
        var d: meta.Diag = .{};
        meta.checkRequirements(null, reqs, &d) catch |e| return c.metaFail(e, d);
        var ub: [36]u8 = undefined;
        const now = catalog.nowMs();
        var m = try meta.skeleton(a, try a.dupe(u8, meta.uuid4(&ub)), now);
        meta.applyUpdates(a, &m, updates, now, &d) catch |e| return c.metaFail(e, d);
        const uuid = json.str(m, "table-uuid").?;
        meta.completeStaged(a, &m, try defaultLocation(a, c.bucket, uuid), &d) catch |e| return c.metaFail(e, d);
        const url = try c.writeMetadata(m, 0) orelse return;
        _ = c.cat.createTable(a, c.bucket, .{
            .levels = levels,
            .name = name,
            .uuid = uuid,
            .metadata_location = url,
            .warehouse = json.str(m, "location").?,
            .created_ms = now,
            .modified_ms = now,
            .created_by = c.r.who(),
            .modified_by = c.r.who(),
        }) catch |e| {
            c.dropFile(url);
            return switch (e) {
                error.AlreadyExists => c.r.iceberg(.conflict, "CommitFailedException", "table was created concurrently"),
                error.NotFound => c.noNamespace(),
                else => storeFail(c.r, e),
            };
        };
        return c.loadResult(url, try json.stringify(a, .{ .object = m }));
    }

    fn dropTable(c: *Call, levels: []const []const u8, name: []const u8) RawError!void {
        const a = c.r.arena;
        const cur = (c.cat.getTable(a, c.bucket, levels, name) catch |e| return storeFail(c.r, e)) orelse return c.noTable();
        if (!try c.allow("s3tables:DeleteTable", cur.uuid)) return c.denied();
        const want_purge = if (try c.r.param("purgeRequested")) |p| std.ascii.eqlIgnoreCase(p, "true") else false;
        const tb = c.cat.dropTable(a, c.bucket, levels, name, null) catch |e| return switch (e) {
            error.NotFound => c.noTable(),
            else => storeFail(c.r, e),
        };
        if (want_purge and ownLocation(c.bucket, tb.warehouse)) c.purge(tb.warehouse);
        return c.r.noContent();
    }

    /// Best-effort delete of every object under the table location (bounded).
    fn purge(c: *Call, location: []const u8) void {
        const l = catalog.parseLocation(location) orelse return;
        var pb: [1100]u8 = undefined;
        const prefix = std.fmt.bufPrint(&pb, "{s}/", .{std.mem.trimRight(u8, l.key, "/")}) catch return;
        var rounds: usize = 0;
        while (rounds < 1000) : (rounds += 1) {
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const page = c.t.store.list(arena.allocator(), c.bucket, prefix, "", catalog.max_page) catch return;
            if (page.keys.len == 0) return;
            for (page.keys) |k| c.t.store.remove(c.bucket, k) catch return;
        }
    }

    fn rename(c: *Call) RawError!void {
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const src = json.obj(b, "source") orelse return c.bad("source is required");
        const dst = json.obj(b, "destination") orelse return c.bad("destination is required");
        const sl = try json.strings(a, json.get(src, "namespace") orelse .null) orelse return c.bad("source namespace must be strings");
        const dl = try json.strings(a, json.get(dst, "namespace") orelse .null) orelse return c.bad("destination namespace must be strings");
        const sn = json.str(src, "name") orelse return c.bad("source name is required");
        const dn = json.str(dst, "name") orelse return c.bad("destination name is required");
        if (!catalog.validLevels(sl) or !catalog.validLevels(dl) or !catalog.validName(sn) or !catalog.validName(dn)) return c.bad("invalid identifier");
        const cur = (c.cat.getTable(a, c.bucket, sl, sn) catch |e| return storeFail(c.r, e)) orelse return c.noTable();
        if (!try c.allow("s3tables:RenameTable", cur.uuid)) return c.denied();
        c.cat.renameTable(a, c.bucket, sl, sn, dl, dn, null) catch |e| return switch (e) {
            error.AlreadyExists => c.r.iceberg(.conflict, "AlreadyExistsException", "destination table already exists"),
            error.NotFound => if ((c.cat.getTable(a, c.bucket, sl, sn) catch null) == null) c.noTable() else c.noNamespace(),
            else => storeFail(c.r, e),
        };
        return c.r.noContent();
    }
};

fn sameLevels(x: []const []const u8, y: []const []const u8) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!std.mem.eql(u8, p, q)) return false;
    return true;
}

fn isCreate(reqs: []const json.Value) bool {
    for (reqs) |r| switch (r) {
        .object => |o| if (std.mem.eql(u8, json.str(o, "type") orelse "", "assert-create")) return true,
        else => {},
    };
    return false;
}

/// Sequence number from a `NNNNN-<uuid>.metadata.json` file name, else 0.
pub fn metadataGen(url: []const u8) i64 {
    const base = url[(std.mem.lastIndexOfScalar(u8, url, '/') orelse return 0) + 1 ..];
    const dash = std.mem.indexOfScalar(u8, base, '-') orelse return 0;
    if (dash == 0 or dash > 12) return 0;
    return std.fmt.parseInt(i64, base[0..dash], 10) catch 0;
}

test "warehouse forms and locations" {
    try std.testing.expectEqualStrings("wh", warehouseBucket("wh"));
    try std.testing.expectEqualStrings("wh", warehouseBucket("arn:aws:s3tables:us-east-1:000000000000:bucket/wh"));
    try std.testing.expectEqualStrings("wh", warehouseBucket("s3://wh/x"));
    try std.testing.expectEqualStrings("", warehouseBucket("arn:nope"));
    try std.testing.expect(ownLocation("wh", "s3://wh/tables/x"));
    try std.testing.expect(!ownLocation("wh", "s3://other/x"));
    try std.testing.expect(!ownLocation("wh", "s3://wh/.zkfsm-tables/x"));
    try std.testing.expect(!ownLocation("wh", "s3://wh/a/../b"));
    try std.testing.expect(!ownLocation("wh", "s3://wh"));
    try std.testing.expectEqual(@as(i64, 7), metadataGen("s3://b/t/metadata/00007-abc.metadata.json"));
    try std.testing.expectEqual(@as(i64, 0), metadataGen("s3://b/t/metadata/v1.metadata.json"));
}

test "namespace path parsing" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const l = try parseNamespace(a.allocator(), "a%1Fb%2Fc");
    try std.testing.expectEqual(@as(usize, 2), l.len);
    try std.testing.expectEqualStrings("b/c", l[1]);
    try std.testing.expectError(error.InvalidUri, parseNamespace(a.allocator(), "%1F" ** 20));
}
