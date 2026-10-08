//! S3 Tables control plane (rest-json, signing name s3tables): table buckets,
//! namespaces, tables, metadata-location CAS with version tokens, bucket policy.
const std = @import("std");
const json = @import("json.zig");
const http = @import("http.zig");
const catalog = @import("catalog.zig");
const meta = @import("metadata.zig");
const route = @import("route.zig");
const iceberg = @import("iceberg.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");

const Req = http.Req;
const RawError = http.RawError;
const Tables = route.Tables;
const Catalog = catalog.Catalog;
const Allocator = std.mem.Allocator;

const max_policy = 20 * 1024;

/// S3 Tables naming: 1..255 of [a-z0-9_], starting with a letter or digit.
pub fn validTablesName(n: []const u8) bool {
    if (n.len == 0 or n.len > catalog.max_name) return false;
    if (!std.ascii.isLower(n[0]) and !std.ascii.isDigit(n[0])) return false;
    for (n) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '_')) return false;
    return true;
}

/// Bucket name from a table bucket ARN (or a bare name).
pub fn arnBucket(arn: []const u8) ?[]const u8 {
    const b = iceberg.warehouseBucket(arn);
    return if (object.service.validBucketName(b)) b else null;
}

pub fn handle(t: *Tables, r: *Req) RawError!void {
    const segs = try http.segments(r.arena, r.path);
    var c: Ctl = .{ .t = t, .r = r, .cat = t.catalogOf() };
    if (segs.len == 0) return c.notFound("unknown operation");
    const head = segs[0];
    if (std.mem.eql(u8, head, "buckets")) {
        if (segs.len == 1) return switch (r.method) {
            .PUT => c.createBucket(),
            .GET => c.listBuckets(),
            else => c.methodNotAllowed(),
        };
        const bucket = try c.bucketArg(segs[1]) orelse return;
        if (segs.len == 2) return switch (r.method) {
            .GET => c.getBucket(bucket),
            .DELETE => c.deleteBucket(bucket),
            else => c.methodNotAllowed(),
        };
        if (segs.len == 3 and std.mem.eql(u8, segs[2], "policy")) return switch (r.method) {
            .PUT => c.putPolicy(bucket),
            .GET => c.getPolicy(bucket),
            .DELETE => c.deletePolicy(bucket),
            else => c.methodNotAllowed(),
        };
        return c.unsupported();
    }
    if (std.mem.eql(u8, head, "namespaces")) {
        if (segs.len < 2) return c.notFound("unknown operation");
        const bucket = try c.bucketArg(segs[1]) orelse return;
        if (segs.len == 2) return switch (r.method) {
            .PUT => c.createNamespace(bucket),
            .GET => c.listNamespaces(bucket),
            else => c.methodNotAllowed(),
        };
        if (segs.len != 3) return c.notFound("unknown operation");
        const ns = try c.nameArg(segs[2]) orelse return;
        return switch (r.method) {
            .GET => c.getNamespace(bucket, ns),
            .DELETE => c.deleteNamespace(bucket, ns),
            else => c.methodNotAllowed(),
        };
    }
    if (std.mem.eql(u8, head, "get-table") and segs.len == 1) {
        if (r.method != .GET) return c.methodNotAllowed();
        return c.getTableQuery();
    }
    if (std.mem.eql(u8, head, "tables")) {
        if (segs.len < 2) return c.notFound("unknown operation");
        const bucket = try c.bucketArg(segs[1]) orelse return;
        if (segs.len == 2) return if (r.method == .GET) c.listTables(bucket) else c.methodNotAllowed();
        const ns = try c.nameArg(segs[2]) orelse return;
        if (segs.len == 3) return if (r.method == .PUT) c.createTable(bucket, ns) else c.methodNotAllowed();
        const name = try c.nameArg(segs[3]) orelse return;
        if (segs.len == 4) return switch (r.method) {
            .GET => c.getTable(bucket, ns, name),
            .DELETE => c.deleteTable(bucket, ns, name),
            else => c.methodNotAllowed(),
        };
        if (segs.len == 5 and std.mem.eql(u8, segs[4], "metadata-location")) return switch (r.method) {
            .GET => c.getMetadataLocation(bucket, ns, name),
            .PUT => c.updateMetadataLocation(bucket, ns, name),
            else => c.methodNotAllowed(),
        };
        if (segs.len == 5 and std.mem.eql(u8, segs[4], "rename")) return if (r.method == .PUT) c.renameTable(bucket, ns, name) else c.methodNotAllowed();
        return c.unsupported();
    }
    return c.unsupported();
}

const Ctl = struct {
    t: *Tables,
    r: *Req,
    cat: Catalog,

    fn notFound(c: *Ctl, msg: []const u8) RawError!void {
        return c.r.tables(.not_found, "NotFoundException", msg);
    }

    fn bad(c: *Ctl, msg: []const u8) RawError!void {
        return c.r.tables(.bad_request, "BadRequestException", msg);
    }

    fn conflict(c: *Ctl, msg: []const u8) RawError!void {
        return c.r.tables(.conflict, "ConflictException", msg);
    }

    fn denied(c: *Ctl) RawError!void {
        return c.r.tables(.forbidden, "AccessDeniedException", "access denied");
    }

    fn methodNotAllowed(c: *Ctl) RawError!void {
        return c.r.tables(.method_not_allowed, "MethodNotAllowedException", "method not allowed");
    }

    fn unsupported(c: *Ctl) RawError!void {
        return c.r.tables(.bad_request, "BadRequestException", "operation is not supported");
    }

    fn fail(c: *Ctl, e: catalog.Error) RawError!void {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidName, error.KeyTooLong => c.bad("name is invalid or too long"),
            error.NoSuchBucket, error.NotTableBucket => c.notFound("table bucket does not exist"),
            error.NotFound => c.notFound("resource does not exist"),
            error.AlreadyExists => c.conflict("resource already exists"),
            error.NotEmpty => c.conflict("resource is not empty"),
            error.PreconditionFailed => c.conflict("version token does not match"),
            error.TooLarge, error.Corrupt => c.r.tables(.internal_server_error, "InternalServerErrorException", "catalog document is invalid"),
            error.Storage => c.r.tables(.internal_server_error, "InternalServerErrorException", "catalog storage failed"),
        };
    }

    fn bucketArg(c: *Ctl, seg: []const u8) RawError!?[]const u8 {
        const raw = http.decode(c.r.arena, seg) catch {
            try c.bad("malformed table bucket ARN");
            return null;
        };
        return arnBucket(raw) orelse {
            try c.bad("invalid table bucket ARN");
            return null;
        };
    }

    fn nameArg(c: *Ctl, seg: []const u8) RawError!?[]const u8 {
        const raw = http.decode(c.r.arena, seg) catch {
            try c.bad("malformed name");
            return null;
        };
        if (!catalog.validName(raw)) {
            try c.bad("invalid name");
            return null;
        }
        return raw;
    }

    fn body(c: *Ctl) RawError!?json.ObjectMap {
        const src = if (c.r.body.len == 0) "{}" else c.r.body;
        return json.parseObject(c.r.arena, src) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                try c.bad("request body must be a JSON object");
                return null;
            },
        };
    }

    fn maxParam(c: *Ctl, name: []const u8) RawError!?usize {
        const v = try c.r.param(name) orelse return catalog.max_page;
        const n = std.fmt.parseInt(usize, v, 10) catch 0;
        if (n == 0 or n > catalog.max_page) {
            try c.bad("invalid page size");
            return null;
        }
        return n;
    }

    fn requireBucket(c: *Ctl, bucket: []const u8) RawError!?catalog.Bucket {
        return (c.cat.getBucket(c.r.arena, bucket) catch |e| {
            try c.fail(e);
            return null;
        }) orelse {
            try c.notFound("table bucket does not exist");
            return null;
        };
    }

    // ---- table buckets ----

    fn bucketValue(c: *Ctl, b: catalog.Bucket) RawError!json.ObjectMap {
        const a = c.r.arena;
        var o = json.newObject(a);
        try o.put("arn", json.s(try c.t.bucketArn(a, b.name)));
        try o.put("name", json.s(b.name));
        try o.put("ownerAccountId", json.s(c.t.account));
        try o.put("createdAt", json.s(try http.isoMs(a, b.created_ms)));
        try o.put("tableBucketId", json.s(b.id));
        try o.put("type", json.s("customer"));
        return o;
    }

    fn createBucket(c: *Ctl) RawError!void {
        const b = try c.body() orelse return;
        const name = json.str(b, "name") orelse return c.bad("name is required");
        if (!object.service.validBucketName(name)) return c.bad("invalid table bucket name");
        if (!try c.t.allowed(c.r, "s3tables:CreateTableBucket", name, null)) return c.denied();
        const h = c.t.store.lock(name) catch |e| return c.fail(e);
        defer h.release();
        if ((c.cat.getBucket(c.r.arena, name) catch |e| return c.fail(e)) != null) return c.conflict("table bucket already exists");
        object.tenancy.createOwned(c.t.svc, name, "") catch |e| return switch (e) {
            error.BucketAlreadyExists => c.conflict("a bucket with this name already exists"),
            error.OutOfMemory => error.OutOfMemory,
            else => c.r.tables(.internal_server_error, "InternalServerErrorException", "cannot create bucket"),
        };
        c.cat.markBucket(c.r.arena, name, c.r.who()) catch |e| return c.fail(e);
        var o = json.newObject(c.r.arena);
        try o.put("arn", json.s(try c.t.bucketArn(c.r.arena, name)));
        return c.r.sendObject(.ok, o);
    }

    fn listBuckets(c: *Ctl) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:ListTableBuckets", null, null)) return c.denied();
        const a = c.r.arena;
        const prefix = try c.r.param("prefix") orelse "";
        const after = try c.r.param("continuationToken") orelse "";
        const max = try c.maxParam("maxBuckets") orelse return;
        const all = c.t.svc.listBuckets(a) catch return c.r.tables(.internal_server_error, "InternalServerErrorException", "cannot list buckets");
        std.mem.sort(object.BucketInfo, all, {}, struct {
            fn lt(_: void, x: object.BucketInfo, y: object.BucketInfo) bool {
                return std.mem.order(u8, x.name, y.name) == .lt;
            }
        }.lt);
        var list = json.newArray(a);
        var next: ?[]const u8 = null;
        for (all) |bi| {
            if (!std.mem.startsWith(u8, bi.name, prefix)) continue;
            if (after.len > 0 and std.mem.order(u8, bi.name, after) != .gt) continue;
            const b = (c.cat.getBucket(a, bi.name) catch null) orelse continue;
            if (list.items.len == max) {
                next = list.items[list.items.len - 1].object.get("name").?.string;
                break;
            }
            try list.append(.{ .object = try c.bucketValue(b) });
        }
        var o = json.newObject(a);
        try o.put("tableBuckets", .{ .array = list });
        if (next) |n| try o.put("continuationToken", json.s(n));
        return c.r.sendObject(.ok, o);
    }

    fn getBucket(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:GetTableBucket", bucket, null)) return c.denied();
        const b = try c.requireBucket(bucket) orelse return;
        return c.r.sendObject(.ok, try c.bucketValue(b));
    }

    fn deleteBucket(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:DeleteTableBucket", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        {
            const h = c.t.store.lock(bucket) catch |e| return c.fail(e);
            defer h.release();
            c.cat.unmarkBucket(c.r.arena, bucket) catch |e| return switch (e) {
                error.NotEmpty => c.conflict("table bucket still has namespaces or tables"),
                else => c.fail(e),
            };
        }
        // Leftover table data keeps the bucket as an ordinary S3 bucket.
        if (c.t.svc.bucketId(bucket)) |bid| {
            if (c.t.svc.deleteBucket(bucket)) |_| object.bucket_meta.dropAll(c.t.svc, bid) else |_| {}
        } else |_| {}
        return c.r.noContent();
    }

    fn putPolicy(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:PutTableBucketPolicy", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        const b = try c.body() orelse return;
        const doc = json.str(b, "resourcePolicy") orelse return c.bad("resourcePolicy is required");
        if (doc.len > max_policy) return c.bad("policy is too large");
        _ = iam.policy.parse(c.r.arena, doc) catch return c.bad("policy is not a valid policy document");
        _ = c.t.store.write(bucket, catalog.policy_key, doc, .none) catch |e| return c.fail(e);
        return c.r.send(.ok, "{}", &.{});
    }

    fn getPolicy(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:GetTableBucketPolicy", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        const doc = (c.t.store.read(c.r.arena, bucket, catalog.policy_key, max_policy) catch |e| return c.fail(e)) orelse
            return c.notFound("table bucket has no policy");
        var o = json.newObject(c.r.arena);
        try o.put("resourcePolicy", json.s(doc.body));
        return c.r.sendObject(.ok, o);
    }

    fn deletePolicy(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:DeleteTableBucketPolicy", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        c.t.store.remove(bucket, catalog.policy_key) catch |e| return c.fail(e);
        return c.r.noContent();
    }

    // ---- namespaces ----

    fn nsValue(c: *Ctl, bucket: []const u8, b: catalog.Bucket, ns: catalog.Namespace) RawError!json.ObjectMap {
        _ = bucket;
        const a = c.r.arena;
        var o = json.newObject(a);
        try o.put("namespace", try json.stringArray(a, ns.levels));
        try o.put("createdAt", json.s(try http.isoMs(a, ns.created_ms)));
        try o.put("createdBy", json.s(ns.created_by));
        try o.put("ownerAccountId", json.s(c.t.account));
        try o.put("namespaceId", json.s(ns.id));
        try o.put("tableBucketId", json.s(b.id));
        return o;
    }

    fn createNamespace(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:CreateNamespace", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        const b = try c.body() orelse return;
        const levels = try json.strings(c.r.arena, json.get(b, "namespace") orelse .null) orelse return c.bad("namespace must be a list of one name");
        if (levels.len != 1 or !validTablesName(levels[0])) return c.bad("namespace must be one name of [a-z0-9_]");
        var ub: [36]u8 = undefined;
        c.cat.createNamespace(c.r.arena, bucket, .{
            .levels = levels,
            .id = meta.uuid4(&ub),
            .created_ms = catalog.nowMs(),
            .created_by = c.r.who(),
            .properties = json.newObject(c.r.arena),
        }) catch |e| return c.fail(e);
        var o = json.newObject(c.r.arena);
        try o.put("tableBucketARN", json.s(try c.t.bucketArn(c.r.arena, bucket)));
        try o.put("namespace", try json.stringArray(c.r.arena, levels));
        return c.r.sendObject(.ok, o);
    }

    fn listNamespaces(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:ListNamespaces", bucket, null)) return c.denied();
        const tb = try c.requireBucket(bucket) orelse return;
        const prefix = try c.r.param("prefix") orelse "";
        const token = try c.r.param("continuationToken") orelse "";
        const max = try c.maxParam("maxNamespaces") orelse return;
        const page = c.cat.listNamespaces(c.r.arena, bucket, &.{}, prefix, token, max) catch |e| return c.fail(e);
        var list = json.newArray(c.r.arena);
        for (page.items) |levels| {
            const ns = (c.cat.getNamespace(c.r.arena, bucket, levels) catch null) orelse continue;
            try list.append(.{ .object = try c.nsValue(bucket, tb, ns) });
        }
        var o = json.newObject(c.r.arena);
        try o.put("namespaces", .{ .array = list });
        if (page.next) |n| try o.put("continuationToken", json.s(n));
        return c.r.sendObject(.ok, o);
    }

    fn getNamespace(c: *Ctl, bucket: []const u8, ns_name: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:GetNamespace", bucket, null)) return c.denied();
        const tb = try c.requireBucket(bucket) orelse return;
        const levels = try c.r.arena.dupe([]const u8, &.{ns_name});
        const ns = (c.cat.getNamespace(c.r.arena, bucket, levels) catch |e| return c.fail(e)) orelse return c.notFound("namespace does not exist");
        return c.r.sendObject(.ok, try c.nsValue(bucket, tb, ns));
    }

    fn deleteNamespace(c: *Ctl, bucket: []const u8, ns_name: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:DeleteNamespace", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        const levels = try c.r.arena.dupe([]const u8, &.{ns_name});
        c.cat.dropNamespace(c.r.arena, bucket, levels) catch |e| return switch (e) {
            error.NotEmpty => c.conflict("namespace is not empty"),
            error.NotFound => c.notFound("namespace does not exist"),
            else => c.fail(e),
        };
        return c.r.noContent();
    }

    // ---- tables ----

    fn lookup(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!?catalog.Table {
        const levels = try c.r.arena.dupe([]const u8, &.{ns_name});
        return (c.cat.getTable(c.r.arena, bucket, levels, name) catch |e| {
            try c.fail(e);
            return null;
        }) orelse {
            try c.notFound("table does not exist");
            return null;
        };
    }

    fn createTable(c: *Ctl, bucket: []const u8, ns_name: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:CreateTable", bucket, null)) return c.denied();
        _ = try c.requireBucket(bucket) orelse return;
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const name = json.str(b, "name") orelse return c.bad("name is required");
        if (!validTablesName(name)) return c.bad("table name must be [a-z0-9_]");
        const format = json.str(b, "format") orelse "ICEBERG";
        if (!std.mem.eql(u8, format, "ICEBERG")) return c.bad("only ICEBERG tables are supported");
        const levels = try a.dupe([]const u8, &.{ns_name});
        var ub: [36]u8 = undefined;
        const uuid = try a.dupe(u8, meta.uuid4(&ub));
        const location = try iceberg.defaultLocation(a, bucket, uuid);
        var metadata_location: ?[]const u8 = null;
        var gen: i64 = 0;
        if (json.obj(b, "metadata")) |md| {
            const ice = json.obj(md, "iceberg") orelse return c.bad("metadata.iceberg is required");
            const sch = json.obj(ice, "schema") orelse return c.bad("metadata.iceberg.schema is required");
            const schema = try schemaFromFields(a, json.arr(sch, "fields") orelse return c.bad("schema fields are required")) orelse return c.bad("schema fields need name and primitive type");
            var d: meta.Diag = .{};
            const m = meta.create(a, .{ .location = location, .schema = schema, .uuid = uuid, .now_ms = catalog.nowMs() }, &d) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => c.bad(d.msg),
            };
            const url = try std.fmt.allocPrint(a, "{s}/metadata/00000-{s}.metadata.json", .{ location, meta.uuid4(&ub) });
            _ = c.t.store.write(bucket, catalog.parseLocation(url).?.key, try json.stringify(a, .{ .object = m }), .create) catch |e| return c.fail(e);
            metadata_location = url;
            gen = 0;
        }
        const now = catalog.nowMs();
        const tag = c.cat.createTable(a, bucket, .{
            .levels = levels,
            .name = name,
            .uuid = uuid,
            .metadata_location = metadata_location,
            .warehouse = location,
            .created_ms = now,
            .modified_ms = now,
            .created_by = c.r.who(),
            .modified_by = c.r.who(),
            .gen = gen,
        }) catch |e| {
            if (metadata_location) |u| c.t.store.remove(bucket, catalog.parseLocation(u).?.key) catch {};
            return switch (e) {
                error.NotFound => c.notFound("namespace does not exist"),
                else => c.fail(e),
            };
        };
        var o = json.newObject(a);
        try o.put("tableARN", json.s(try c.t.tableArn(a, bucket, uuid)));
        try o.put("versionToken", json.s(try a.dupe(u8, &tag)));
        return c.r.sendObject(.ok, o);
    }

    fn tableSummary(c: *Ctl, bucket: []const u8, tb_bucket: catalog.Bucket, t: catalog.Table) RawError!json.ObjectMap {
        const a = c.r.arena;
        var o = json.newObject(a);
        try o.put("namespace", try json.stringArray(a, t.levels));
        try o.put("name", json.s(t.name));
        try o.put("type", json.s("customer"));
        try o.put("tableARN", json.s(try c.t.tableArn(a, bucket, t.uuid)));
        try o.put("createdAt", json.s(try http.isoMs(a, t.created_ms)));
        try o.put("modifiedAt", json.s(try http.isoMs(a, t.modified_ms)));
        try o.put("tableBucketId", json.s(tb_bucket.id));
        return o;
    }

    fn listTables(c: *Ctl, bucket: []const u8) RawError!void {
        if (!try c.t.allowed(c.r, "s3tables:ListTables", bucket, null)) return c.denied();
        const tb = try c.requireBucket(bucket) orelse return;
        const a = c.r.arena;
        const prefix = try c.r.param("prefix") orelse "";
        const token = try c.r.param("continuationToken") orelse "";
        const max = try c.maxParam("maxTables") orelse return;
        var levels: ?[]const []const u8 = null;
        if (try c.r.param("namespace")) |n| if (n.len > 0) {
            if (!catalog.validName(n)) return c.bad("invalid namespace");
            levels = try a.dupe([]const u8, &.{n});
        };
        const page = c.cat.listTables(a, bucket, levels, prefix, token, max) catch |e| return c.fail(e);
        var list = json.newArray(a);
        for (page.items) |t| try list.append(.{ .object = try c.tableSummary(bucket, tb, t) });
        var o = json.newObject(a);
        try o.put("tables", .{ .array = list });
        if (page.next) |n| try o.put("continuationToken", json.s(n));
        return c.r.sendObject(.ok, o);
    }

    fn getTableQuery(c: *Ctl) RawError!void {
        const a = c.r.arena;
        if (try c.r.param("tableArn")) |arn| {
            const bucket = arnBucket(arn) orelse return c.bad("invalid table ARN");
            const i = std.mem.indexOf(u8, arn, "/table/") orelse return c.bad("invalid table ARN");
            const uuid = arn[i + "/table/".len ..];
            _ = try c.requireBucket(bucket) orelse return;
            var token: []const u8 = "";
            var rounds: usize = 0;
            while (rounds < 100) : (rounds += 1) {
                const page = c.cat.listTables(a, bucket, null, "", token, catalog.max_page) catch |e| return c.fail(e);
                for (page.items) |t| if (std.mem.eql(u8, t.uuid, uuid)) return c.getTable(bucket, t.levels[0], t.name);
                token = page.next orelse break;
            }
            return c.notFound("table does not exist");
        }
        const arn = try c.r.param("tableBucketARN") orelse return c.bad("tableBucketARN or tableArn is required");
        const bucket = arnBucket(arn) orelse return c.bad("invalid table bucket ARN");
        const ns = try c.r.param("namespace") orelse return c.bad("namespace is required");
        const name = try c.r.param("name") orelse return c.bad("name is required");
        if (!catalog.validName(ns) or !catalog.validName(name)) return c.bad("invalid name");
        return c.getTable(bucket, ns, name);
    }

    fn getTable(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!void {
        const tb = try c.requireBucket(bucket) orelse return;
        const t = try c.lookup(bucket, ns_name, name) orelse return;
        if (!try c.t.allowed(c.r, "s3tables:GetTable", bucket, t.uuid)) return c.denied();
        const a = c.r.arena;
        var o = json.newObject(a);
        try o.put("name", json.s(t.name));
        try o.put("type", json.s("customer"));
        try o.put("tableARN", json.s(try c.t.tableArn(a, bucket, t.uuid)));
        try o.put("namespace", try json.stringArray(a, t.levels));
        const ns = c.cat.getNamespace(a, bucket, t.levels) catch null;
        if (ns) |n| try o.put("namespaceId", json.s(n.id));
        try o.put("versionToken", json.s(try a.dupe(u8, &t.tag)));
        if (t.metadata_location) |l| try o.put("metadataLocation", json.s(l));
        try o.put("warehouseLocation", json.s(t.warehouse));
        try o.put("createdAt", json.s(try http.isoMs(a, t.created_ms)));
        try o.put("createdBy", json.s(t.created_by));
        try o.put("modifiedAt", json.s(try http.isoMs(a, t.modified_ms)));
        try o.put("modifiedBy", json.s(t.modified_by));
        try o.put("ownerAccountId", json.s(c.t.account));
        try o.put("format", json.s("ICEBERG"));
        try o.put("tableBucketId", json.s(tb.id));
        return c.r.sendObject(.ok, o);
    }

    fn deleteTable(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!void {
        _ = try c.requireBucket(bucket) orelse return;
        const t = try c.lookup(bucket, ns_name, name) orelse return;
        if (!try c.t.allowed(c.r, "s3tables:DeleteTable", bucket, t.uuid)) return c.denied();
        const want = try c.r.param("versionToken");
        _ = c.cat.dropTable(c.r.arena, bucket, t.levels, name, want) catch |e| return c.fail(e);
        return c.r.noContent();
    }

    fn getMetadataLocation(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!void {
        _ = try c.requireBucket(bucket) orelse return;
        const t = try c.lookup(bucket, ns_name, name) orelse return;
        if (!try c.t.allowed(c.r, "s3tables:GetTableMetadataLocation", bucket, t.uuid)) return c.denied();
        const a = c.r.arena;
        var o = json.newObject(a);
        try o.put("versionToken", json.s(try a.dupe(u8, &t.tag)));
        if (t.metadata_location) |l| try o.put("metadataLocation", json.s(l));
        try o.put("warehouseLocation", json.s(t.warehouse));
        return c.r.sendObject(.ok, o);
    }

    fn updateMetadataLocation(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!void {
        _ = try c.requireBucket(bucket) orelse return;
        var t = try c.lookup(bucket, ns_name, name) orelse return;
        if (!try c.t.allowed(c.r, "s3tables:UpdateTableMetadataLocation", bucket, t.uuid)) return c.denied();
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const token = json.str(b, "versionToken") orelse return c.bad("versionToken is required");
        const loc = json.str(b, "metadataLocation") orelse return c.bad("metadataLocation is required");
        if (loc.len > 2048) return c.bad("metadataLocation is too long");
        const l = catalog.parseLocation(loc) orelse return c.bad("metadataLocation must be an s3 URL");
        if (!std.mem.eql(u8, l.bucket, bucket) or !iceberg.ownLocation(bucket, loc)) return c.bad("metadataLocation must be inside the table bucket");
        _ = c.t.svc.head(a, bucket, l.key) catch return c.bad("metadataLocation does not exist");
        if (!std.mem.eql(u8, token, &t.tag)) return c.conflict("version token does not match");
        t.metadata_location = loc;
        t.modified_ms = catalog.nowMs();
        t.modified_by = c.r.who();
        t.gen = @max(t.gen, iceberg.metadataGen(loc));
        const tag = c.cat.swapTable(a, bucket, t) catch |e| return switch (e) {
            error.PreconditionFailed, error.NotFound => c.conflict("version token does not match"),
            else => c.fail(e),
        };
        var o = json.newObject(a);
        try o.put("name", json.s(t.name));
        try o.put("tableARN", json.s(try c.t.tableArn(a, bucket, t.uuid)));
        try o.put("namespace", try json.stringArray(a, t.levels));
        try o.put("versionToken", json.s(try a.dupe(u8, &tag)));
        try o.put("metadataLocation", json.s(loc));
        return c.r.sendObject(.ok, o);
    }

    fn renameTable(c: *Ctl, bucket: []const u8, ns_name: []const u8, name: []const u8) RawError!void {
        _ = try c.requireBucket(bucket) orelse return;
        const t = try c.lookup(bucket, ns_name, name) orelse return;
        if (!try c.t.allowed(c.r, "s3tables:RenameTable", bucket, t.uuid)) return c.denied();
        const a = c.r.arena;
        const b = try c.body() orelse return;
        const new_ns = json.str(b, "newNamespaceName") orelse ns_name;
        const new_name = json.str(b, "newName") orelse name;
        if (!validTablesName(new_ns) or !validTablesName(new_name)) return c.bad("names must be [a-z0-9_]");
        const to = try a.dupe([]const u8, &.{new_ns});
        c.cat.renameTable(a, bucket, t.levels, name, to, new_name, json.str(b, "versionToken")) catch |e| return switch (e) {
            error.NotFound => c.notFound("table or destination namespace does not exist"),
            else => c.fail(e),
        };
        return c.r.noContent();
    }
};

/// Iceberg schema from S3 Tables `{name, type, required}` fields, ids from 1.
fn schemaFromFields(arena: Allocator, fields: []const json.Value) error{OutOfMemory}!?json.Value {
    if (fields.len == 0 or fields.len > 10_000) return null;
    var list = json.newArray(arena);
    for (fields, 1..) |f, id| {
        const fo = switch (f) {
            .object => |o| o,
            else => return null,
        };
        const name = json.str(fo, "name") orelse return null;
        const ty = json.str(fo, "type") orelse return null;
        if (name.len == 0 or name.len > catalog.max_name or ty.len == 0 or ty.len > 64) return null;
        var out = json.newObject(arena);
        try out.put("id", json.i(@intCast(id)));
        try out.put("name", json.s(name));
        try out.put("required", .{ .bool = json.boolean(fo, "required") orelse false });
        try out.put("type", json.s(ty));
        try list.append(.{ .object = out });
    }
    var s = json.newObject(arena);
    try s.put("type", json.s("struct"));
    try s.put("schema-id", json.i(0));
    try s.put("fields", .{ .array = list });
    return .{ .object = s };
}

test "s3 tables names and ARNs" {
    try std.testing.expect(validTablesName("sales_2024"));
    try std.testing.expect(!validTablesName("_x"));
    try std.testing.expect(!validTablesName("Upper"));
    try std.testing.expect(!validTablesName(""));
    try std.testing.expectEqualStrings("tb1", arnBucket("arn:aws:s3tables:us-east-1:000000000000:bucket/tb1").?);
    try std.testing.expectEqualStrings("tb1", arnBucket("arn:aws:s3tables:r:a:bucket/tb1/table/x").?);
    try std.testing.expect(arnBucket("arn:aws:s3tables:r:a:bucket/") == null);
    try std.testing.expect(arnBucket("NOPE") == null);
}

test "schema from S3 Tables fields rejects hostile shapes" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const ok = try json.parse(a.allocator(), "[{\"name\":\"id\",\"type\":\"long\",\"required\":true},{\"name\":\"v\",\"type\":\"string\"}]");
    const s = (try schemaFromFields(a.allocator(), ok.array.items)).?;
    try std.testing.expectEqual(@as(i64, 2), meta.maxFieldId(s));
    const bad = [_][]const u8{ "[]", "[1]", "[{\"name\":\"x\"}]", "[{\"type\":\"int\"}]", "[{\"name\":\"x\",\"type\":{}}]" };
    for (bad) |b| {
        const v = try json.parse(a.allocator(), b);
        try std.testing.expect((try schemaFromFields(a.allocator(), v.array.items)) == null);
    }
}
