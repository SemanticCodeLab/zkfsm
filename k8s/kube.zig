//! Minimal Kubernetes API client: HTTPS with the service-account token and CA,
//! or a plain base URL (kubectl proxy) for development. JSON in, JSON out.
const std = @import("std");
const TlsClient = @import("tls_client.zig");

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
    /// Set for https: the API server's CA. Requests then go through `tls_client`,
    /// which tolerates the server's request for an (optional) client certificate.
    ca: ?std.crypto.Certificate.Bundle = null,
    token_path: ?[]const u8 = null,
    field_manager: []const u8 = "zkfsm-operator",
    mutex: std.Thread.Mutex = .{},

    /// In-cluster config. The API server's certificate names kubernetes.default.svc,
    /// so that host is used instead of the service IP.
    pub fn inCluster(gpa: std.mem.Allocator) !*Client {
        const port = std.posix.getenv("KUBERNETES_SERVICE_PORT") orelse "443";
        const base = try std.fmt.allocPrint(gpa, "https://kubernetes.default.svc:{s}", .{port});
        return withCa(gpa, base, sa_dir ++ "/ca.crt", sa_dir ++ "/token");
    }

    /// https base URL with a CA file and a bearer-token file.
    pub fn withCa(gpa: std.mem.Allocator, base: []const u8, ca_file: []const u8, token_file: ?[]const u8) !*Client {
        const c = try gpa.create(Client);
        errdefer gpa.destroy(c);
        c.* = .{ .gpa = gpa, .http = .{ .allocator = gpa }, .base = base, .ca = .{}, .token_path = token_file };
        try c.ca.?.addCertsFromFilePathAbsolute(gpa, ca_file);
        return c;
    }

    /// Plain URL, e.g. http://127.0.0.1:8001 from `kubectl proxy`.
    pub fn fromUrl(gpa: std.mem.Allocator, base: []const u8) !*Client {
        const c = try gpa.create(Client);
        c.* = .{ .gpa = gpa, .http = .{ .allocator = gpa }, .base = base };
        return c;
    }

    /// $KUBE_API (+ $KUBE_CA, $KUBE_TOKEN_FILE for https) or in-cluster.
    pub fn fromEnv(gpa: std.mem.Allocator) !*Client {
        if (std.posix.getenv("KUBE_API")) |u| {
            if (std.posix.getenv("KUBE_CA")) |ca| return withCa(gpa, u, ca, std.posix.getenv("KUBE_TOKEN_FILE"));
            return fromUrl(gpa, u);
        }
        return inCluster(gpa);
    }

    pub fn deinit(c: *Client) void {
        if (c.ca) |*b| b.deinit(c.gpa);
        c.http.deinit();
        c.gpa.destroy(c);
    }

    pub fn request(c: *Client, arena: std.mem.Allocator, method: std.http.Method, p: []const u8, body: ?[]const u8, content_type: []const u8) !Response {
        c.mutex.lock();
        defer c.mutex.unlock();
        const url = try std.mem.concat(arena, u8, &.{ c.base, p });
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
        if (c.ca) |ca| return httpsRequest(arena, ca, url, method, headers[0..n], body);
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

/// One HTTP/1.1 request per TLS connection (Connection: close).
fn httpsRequest(arena: std.mem.Allocator, ca: std.crypto.Certificate.Bundle, url: []const u8, method: std.http.Method, headers: []const std.http.Header, body: ?[]const u8) !Response {
    const uri = try std.Uri.parse(url);
    const host = uri.host.?.percent_encoded;
    const port = uri.port orelse 443;
    const stream = try std.net.tcpConnectToHost(arena, host, port);
    defer stream.close();
    const bufs = try arena.alloc(u8, 4 * TlsClient.min_buffer_len);
    var sr = stream.reader(bufs[0..TlsClient.min_buffer_len]);
    var sw = stream.writer(bufs[TlsClient.min_buffer_len .. 2 * TlsClient.min_buffer_len]);
    var tls = try TlsClient.init(sr.interface(), &sw.interface, .{
        .host = .{ .explicit = host },
        .ca = .{ .bundle = ca },
        .read_buffer = bufs[2 * TlsClient.min_buffer_len .. 3 * TlsClient.min_buffer_len],
        .write_buffer = bufs[3 * TlsClient.min_buffer_len ..],
        // Message framing is checked below (Content-Length / chunked).
        .allow_truncation_attacks = true,
    });
    const w = &tls.writer;
    try w.print("{s} {s}{s}{s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\nUser-Agent: zkfsm-operator\r\n", .{
        @tagName(method), uri.path.percent_encoded, if (uri.query != null) "?" else "", if (uri.query) |q| q.percent_encoded else "", host,
    });
    for (headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    if (body) |b| try w.print("Content-Length: {d}\r\n\r\n{s}", .{ b.len, b }) else try w.writeAll("\r\n");
    try w.flush();
    try sw.interface.flush();
    const raw = try tls.reader.allocRemaining(arena, .limited(256 << 20));
    return parseResponse(arena, raw);
}

fn parseResponse(arena: std.mem.Allocator, raw: []const u8) !Response {
    const head_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadResponse;
    var lines = std.mem.splitSequence(u8, raw[0..head_end], "\r\n");
    const status_line = lines.next().?;
    if (status_line.len < 12) return error.BadResponse;
    const status = std.fmt.parseInt(u16, status_line[9..12], 10) catch return error.BadResponse;
    var chunked = false;
    var length: ?usize = null;
    while (lines.next()) |l| {
        const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
        const name = std.mem.trim(u8, l[0..colon], " ");
        const value = std.mem.trim(u8, l[colon + 1 ..], " ");
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding") and std.ascii.indexOfIgnoreCase(value, "chunked") != null) chunked = true;
        if (std.ascii.eqlIgnoreCase(name, "content-length")) length = std.fmt.parseInt(usize, value, 10) catch return error.BadResponse;
    }
    const rest = raw[head_end + 4 ..];
    if (chunked) {
        var out: std.ArrayList(u8) = .empty;
        var i: usize = 0;
        while (true) {
            const eol = std.mem.indexOfPos(u8, rest, i, "\r\n") orelse return error.Truncated;
            const size_txt = std.mem.trim(u8, rest[i..eol], " ");
            const semi = std.mem.indexOfScalar(u8, size_txt, ';') orelse size_txt.len;
            const size = std.fmt.parseInt(usize, size_txt[0..semi], 16) catch return error.BadResponse;
            i = eol + 2;
            if (size == 0) break;
            if (i + size + 2 > rest.len) return error.Truncated;
            try out.appendSlice(arena, rest[i .. i + size]);
            i += size + 2;
        }
        return .{ .status = status, .body = out.items };
    }
    if (length) |n| {
        if (rest.len < n) return error.Truncated;
        return .{ .status = status, .body = @constCast(rest[0..n]) };
    }
    return .{ .status = status, .body = @constCast(rest) };
}

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

test "response parsing" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try parseResponse(a, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n");
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("Wikipedia", r.body);
    const l = try parseResponse(a, "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}");
    try std.testing.expectEqualStrings("{}", l.body);
    try std.testing.expectError(error.Truncated, parseResponse(a, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}"));
    try std.testing.expectError(error.Truncated, parseResponse(a, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi"));
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
