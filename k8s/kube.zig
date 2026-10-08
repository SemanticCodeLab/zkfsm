//! Minimal Kubernetes API client: HTTPS with the service-account token and CA,
//! or a plain base URL (kubectl proxy) for development. JSON in, JSON out.
const std = @import("std");

pub const sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount";

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn ok(r: Response) bool {
        return r.status >= 200 and r.status < 300;
    }
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    http: std.http.Client,
    base: []const u8,
    token_path: ?[]const u8 = null,
    field_manager: []const u8 = "zkfsm-operator",
    mutex: std.Thread.Mutex = .{},

    /// In-cluster config. The API server's certificate names kubernetes.default.svc,
    /// so that host is used instead of the service IP.
    pub fn inCluster(gpa: std.mem.Allocator) !*Client {
        const c = try gpa.create(Client);
        errdefer gpa.destroy(c);
        c.* = .{ .gpa = gpa, .http = .{ .allocator = gpa }, .base = "https://kubernetes.default.svc", .token_path = sa_dir ++ "/token" };
        if (std.posix.getenv("KUBERNETES_SERVICE_PORT")) |p| {
            if (!std.mem.eql(u8, p, "443")) c.base = try std.fmt.allocPrint(gpa, "https://kubernetes.default.svc:{s}", .{p});
        }
        try c.http.ca_bundle.addCertsFromFilePathAbsolute(gpa, sa_dir ++ "/ca.crt");
        c.http.next_https_rescan_certs = false;
        return c;
    }

    /// Plain URL, e.g. http://127.0.0.1:8001 from `kubectl proxy`.
    pub fn fromUrl(gpa: std.mem.Allocator, base: []const u8) !*Client {
        const c = try gpa.create(Client);
        c.* = .{ .gpa = gpa, .http = .{ .allocator = gpa }, .base = base };
        return c;
    }

    /// $KUBE_API selects a proxy URL; otherwise in-cluster.
    pub fn fromEnv(gpa: std.mem.Allocator) !*Client {
        if (std.posix.getenv("KUBE_API")) |u| return fromUrl(gpa, u);
        return inCluster(gpa);
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
        c.gpa.destroy(c);
    }

    pub fn request(c: *Client, arena: std.mem.Allocator, method: std.http.Method, path: []const u8, body: ?[]const u8, content_type: []const u8) !Response {
        c.mutex.lock();
        defer c.mutex.unlock();
        const url = try std.mem.concat(arena, u8, &.{ c.base, path });
        var headers: [3]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "accept", .value = "application/json" };
        n += 1;
        if (body != null) {
            headers[n] = .{ .name = "content-type", .value = content_type };
            n += 1;
        }
        if (c.token_path) |tp| {
            // Re-read every call: projected tokens rotate.
            const tok = std.fs.cwd().readFileAlloc(arena, tp, 64 * 1024) catch return error.NoToken;
            headers[n] = .{ .name = "authorization", .value = try std.fmt.allocPrint(arena, "Bearer {s}", .{std.mem.trim(u8, tok, " \r\n")}) };
            n += 1;
        }
        var out: std.Io.Writer.Allocating = .init(arena);
        const res = try c.http.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = body,
            .extra_headers = headers[0..n],
            .response_writer = &out.writer,
        });
        return .{ .status = @intFromEnum(res.status), .body = out.written() };
    }

    pub fn get(c: *Client, arena: std.mem.Allocator, path: []const u8) !Response {
        return c.request(arena, .GET, path, null, "");
    }

    pub fn delete(c: *Client, arena: std.mem.Allocator, path: []const u8) !Response {
        return c.request(arena, .DELETE, path, "{\"propagationPolicy\":\"Background\"}", "application/json");
    }

    /// Server-side apply of a full object; JSON is valid apply-patch YAML.
    pub fn apply(c: *Client, arena: std.mem.Allocator, path: []const u8, json: []const u8) !Response {
        const p = try std.fmt.allocPrint(arena, "{s}?fieldManager={s}&force=true", .{ path, c.field_manager });
        return c.request(arena, .PATCH, p, json, "application/apply-patch+yaml");
    }

    pub fn mergePatch(c: *Client, arena: std.mem.Allocator, path: []const u8, json: []const u8) !Response {
        return c.request(arena, .PATCH, path, json, "application/merge-patch+json");
    }

    /// GET and parse; null on 404.
    pub fn getJson(c: *Client, arena: std.mem.Allocator, path: []const u8) !?std.json.Value {
        const r = try c.get(arena, path);
        if (r.status == 404) return null;
        if (!r.ok()) {
            std.log.warn("GET {s}: {d} {s}", .{ path, r.status, r.body[0..@min(r.body.len, 300)] });
            return error.ApiError;
        }
        return try std.json.parseFromSliceLeaky(std.json.Value, arena, r.body, .{});
    }
};

/// Collection path for a resource: core group when `group` is empty.
pub fn resPath(arena: std.mem.Allocator, group_version: []const u8, ns: ?[]const u8, plural: []const u8, name: ?[]const u8) ![]u8 {
    const prefix = if (std.mem.indexOfScalar(u8, group_version, '/') == null) "/api/" else "/apis/";
    var b: std.ArrayList(u8) = .empty;
    try b.appendSlice(arena, prefix);
    try b.appendSlice(arena, group_version);
    if (ns) |n| {
        try b.appendSlice(arena, "/namespaces/");
        try b.appendSlice(arena, n);
    }
    try b.append(arena, '/');
    try b.appendSlice(arena, plural);
    if (name) |n| {
        try b.append(arena, '/');
        try b.appendSlice(arena, n);
    }
    return b.items;
}

/// Walks object keys: lookup(v, &.{"status", "readyReplicas"}).
pub fn lookup(v: std.json.Value, keys: []const []const u8) ?std.json.Value {
    var cur = v;
    for (keys) |k| {
        if (cur != .object) return null;
        cur = cur.object.get(k) orelse return null;
    }
    return cur;
}

pub fn str(v: std.json.Value, keys: []const []const u8) ?[]const u8 {
    const x = lookup(v, keys) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn int(v: std.json.Value, keys: []const []const u8) ?i64 {
    const x = lookup(v, keys) orelse return null;
    return if (x == .integer) x.integer else null;
}

pub fn items(v: std.json.Value) []std.json.Value {
    const x = lookup(v, &.{"items"}) orelse return &.{};
    return if (x == .array) x.array.items else &.{};
}

test "paths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("/api/v1/namespaces/x/pods/p", try resPath(a, "v1", "x", "pods", "p"));
    try std.testing.expectEqualStrings("/apis/apps/v1/namespaces/x/statefulsets", try resPath(a, "apps/v1", "x", "statefulsets", null));
    try std.testing.expectEqualStrings("/apis/zkfsm.io/v1/clusters", try resPath(a, "zkfsm.io/v1", null, "clusters", null));
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"a\":{\"b\":3,\"s\":\"x\"},\"items\":[1,2]}", .{});
    try std.testing.expectEqual(@as(?i64, 3), int(v, &.{ "a", "b" }));
    try std.testing.expectEqualStrings("x", str(v, &.{ "a", "s" }).?);
    try std.testing.expectEqual(@as(usize, 2), items(v).len);
}
