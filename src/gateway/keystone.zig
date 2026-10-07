//! Keystone v3 token validation for the Swift gateway: a service token (password
//! auth or a fixed admin token) validates user tokens via GET /v3/auth/tokens;
//! results sit in a bounded LRU cache until the token expires.
const std = @import("std");
const util = @import("swift_util.zig");
const listener = @import("listener.zig");

pub const max_map = 64;
pub const max_id = 64;
pub const max_token = 8 * 1024;
pub const max_response = 1024 * 1024;
pub const cache_capacity = 1024;
pub const io_timeout_s = 10;

pub const MapEntry = struct { project: []const u8, access_key: []const u8 };

pub const Config = struct {
    url: ?[]const u8 = null,
    user: ?[]const u8 = null,
    password: ?[]const u8 = null,
    project: ?[]const u8 = null,
    domain: []const u8 = "Default",
    admin_token: ?[]const u8 = null,
    map: [max_map]MapEntry = undefined,
    map_len: u8 = 0,

    /// IAM access key for a project, matched by id first, then by name.
    pub fn mapped(c: *const Config, project_id: []const u8, project_name: []const u8) ?[]const u8 {
        for (c.map[0..c.map_len]) |m| if (std.mem.eql(u8, m.project, project_id)) return m.access_key;
        for (c.map[0..c.map_len]) |m| if (project_name.len > 0 and std.mem.eql(u8, m.project, project_name)) return m.access_key;
        return null;
    }

    pub fn addMap(c: *Config, spec: []const u8) error{BadArgs}!void {
        const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.BadArgs;
        if (eq == 0 or eq + 1 == spec.len or c.map_len == max_map) return error.BadArgs;
        c.map[c.map_len] = .{ .project = spec[0..eq], .access_key = spec[eq + 1 ..] };
        c.map_len += 1;
    }

    pub fn valid(c: *const Config) bool {
        if (c.url == null) return true;
        return c.admin_token != null or (c.user != null and c.password != null and c.project != null);
    }
};

/// A validated token's scope.
pub const Info = struct {
    project_id_buf: [max_id]u8 = undefined,
    project_id_len: u8 = 0,
    project_name_buf: [max_id]u8 = undefined,
    project_name_len: u8 = 0,
    expires_s: i64 = 0,

    pub fn projectId(i: *const Info) []const u8 {
        return i.project_id_buf[0..i.project_id_len];
    }
    pub fn projectName(i: *const Info) []const u8 {
        return i.project_name_buf[0..i.project_name_len];
    }
};

pub const ParseError = error{ BadResponse, OutOfMemory };

fn field(v: std.json.Value, name: []const u8) ?std.json.Value {
    return switch (v) {
        .object => |o| o.get(name),
        else => null,
    };
}

fn strField(v: std.json.Value, name: []const u8) ?[]const u8 {
    const f = field(v, name) orelse return null;
    return switch (f) {
        .string => |s| s,
        else => null,
    };
}

/// Parses a token body: {"token": {"expires_at", "project": {"id","name"}}}.
/// Unscoped tokens (no project) are rejected.
pub fn parseToken(arena: std.mem.Allocator, body: []const u8) ParseError!Info {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadResponse,
    };
    const tok = field(root, "token") orelse return error.BadResponse;
    const proj = field(tok, "project") orelse return error.BadResponse;
    const id = strField(proj, "id") orelse return error.BadResponse;
    const name = strField(proj, "name") orelse "";
    const exp = util.parseIso8601(strField(tok, "expires_at") orelse return error.BadResponse) orelse return error.BadResponse;
    if (id.len == 0 or id.len > max_id or name.len > max_id) return error.BadResponse;
    for (id) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return error.BadResponse;
    var info: Info = .{ .expires_s = exp };
    @memcpy(info.project_id_buf[0..id.len], id);
    info.project_id_len = @intCast(id.len);
    @memcpy(info.project_name_buf[0..name.len], name);
    info.project_name_len = @intCast(name.len);
    return info;
}

/// LRU of validated tokens keyed by SHA-256 of the token.
pub const Cache = struct {
    const Entry = struct { key: [32]u8, info: Info, used: u64 };
    entries: [cache_capacity]Entry = undefined,
    len: usize = 0,
    tick: u64 = 0,
    mutex: std.Thread.Mutex = .{},

    fn keyOf(token: []const u8) [32]u8 {
        var k: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &k, .{});
        return k;
    }

    pub fn get(c: *Cache, token: []const u8, now_s: i64) ?Info {
        const k = keyOf(token);
        c.mutex.lock();
        defer c.mutex.unlock();
        for (c.entries[0..c.len], 0..) |*e, i| if (std.mem.eql(u8, &e.key, &k)) {
            if (e.info.expires_s <= now_s) {
                c.entries[i] = c.entries[c.len - 1];
                c.len -= 1;
                return null;
            }
            c.tick += 1;
            e.used = c.tick;
            return e.info;
        };
        return null;
    }

    pub fn put(c: *Cache, token: []const u8, info: Info) void {
        const k = keyOf(token);
        c.mutex.lock();
        defer c.mutex.unlock();
        c.tick += 1;
        for (c.entries[0..c.len]) |*e| if (std.mem.eql(u8, &e.key, &k)) {
            e.* = .{ .key = k, .info = info, .used = c.tick };
            return;
        };
        var slot = c.len;
        if (c.len == cache_capacity) {
            slot = 0;
            for (c.entries[0..c.len], 0..) |e, i| if (e.used < c.entries[slot].used) {
                slot = i;
            };
        } else c.len += 1;
        c.entries[slot] = .{ .key = k, .info = info, .used = c.tick };
    }
};

pub const ValidateError = error{ Unavailable, OutOfMemory };

/// Talks to Keystone; one per gateway, shared by connection threads.
pub const Keystone = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    base: []const u8,
    http: std.http.Client,
    cache: Cache = .{},
    svc_mutex: std.Thread.Mutex = .{},
    svc_token: [max_token]u8 = undefined,
    svc_len: usize = 0,
    svc_expires_s: i64 = 0,

    pub fn create(gpa: std.mem.Allocator, cfg: Config) error{ OutOfMemory, BadConfig }!*Keystone {
        const url = cfg.url orelse return error.BadConfig;
        if (!cfg.valid()) return error.BadConfig;
        var base = std.mem.trimRight(u8, url, "/");
        if (std.mem.endsWith(u8, base, "/v3")) base = base[0 .. base.len - 3];
        _ = std.Uri.parse(base) catch return error.BadConfig;
        const k = try gpa.create(Keystone);
        k.* = .{ .gpa = gpa, .cfg = cfg, .base = base, .http = .{ .allocator = gpa } };
        return k;
    }

    pub fn destroy(k: *Keystone) void {
        k.http.deinit();
        k.gpa.destroy(k);
    }

    /// Info for a valid token, null for an invalid one.
    pub fn validate(k: *Keystone, token: []const u8, now_s: i64) ValidateError!?Info {
        if (token.len == 0 or token.len > max_token or !util.safeValue(token)) return null;
        if (k.cache.get(token, now_s)) |i| return i;
        var attempt: u8 = 0;
        while (attempt < 2) : (attempt += 1) {
            var svc_buf: [max_token]u8 = undefined;
            const svc = try k.serviceToken(&svc_buf, now_s, attempt > 0);
            var r = try k.call(.GET, "/v3/auth/tokens?nocatalog", &.{
                .{ .name = "X-Auth-Token", .value = svc },
                .{ .name = "X-Subject-Token", .value = token },
            }, null, null);
            defer r.deinit(k.gpa);
            switch (r.status) {
                200 => {
                    var arena = std.heap.ArenaAllocator.init(k.gpa);
                    defer arena.deinit();
                    const info = parseToken(arena.allocator(), r.body) catch |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.BadResponse => return null,
                    };
                    if (info.expires_s <= now_s) return null;
                    k.cache.put(token, info);
                    return info;
                },
                // The service token itself was rejected: refresh it once.
                401, 403 => if (attempt == 0 and k.cfg.admin_token == null) continue else return error.Unavailable,
                404 => return null,
                else => return error.Unavailable,
            }
        }
        return error.Unavailable;
    }

    fn serviceToken(k: *Keystone, out: *[max_token]u8, now_s: i64, force: bool) ValidateError![]const u8 {
        if (k.cfg.admin_token) |t| {
            if (t.len > max_token) return error.Unavailable;
            @memcpy(out[0..t.len], t);
            return out[0..t.len];
        }
        k.svc_mutex.lock();
        defer k.svc_mutex.unlock();
        if (force or k.svc_len == 0 or k.svc_expires_s - 60 <= now_s) {
            var body: std.Io.Writer.Allocating = .init(k.gpa);
            defer body.deinit();
            passwordBody(&body.writer, k.cfg) catch return error.OutOfMemory;
            var subject: [max_token]u8 = undefined;
            var subject_len: usize = 0;
            var r = try k.call(.POST, "/v3/auth/tokens?nocatalog", &.{
                .{ .name = "Content-Type", .value = "application/json" },
            }, body.written(), .{ .buf = &subject, .len = &subject_len });
            defer r.deinit(k.gpa);
            if ((r.status != 201 and r.status != 200) or subject_len == 0) return error.Unavailable;
            var arena = std.heap.ArenaAllocator.init(k.gpa);
            defer arena.deinit();
            const info = parseToken(arena.allocator(), r.body) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.BadResponse => return error.Unavailable,
            };
            @memcpy(k.svc_token[0..subject_len], subject[0..subject_len]);
            k.svc_len = subject_len;
            k.svc_expires_s = info.expires_s;
        }
        @memcpy(out[0..k.svc_len], k.svc_token[0..k.svc_len]);
        return out[0..k.svc_len];
    }

    const Resp = struct {
        status: u16,
        body: []u8,
        fn deinit(r: *Resp, gpa: std.mem.Allocator) void {
            gpa.free(r.body);
        }
    };
    const Subject = struct { buf: *[max_token]u8, len: *usize };

    fn call(k: *Keystone, method: std.http.Method, path: []const u8, headers: []const std.http.Header, body: ?[]const u8, subject: ?Subject) ValidateError!Resp {
        var ubuf: [2048]u8 = undefined;
        const url = std.fmt.bufPrint(&ubuf, "{s}{s}", .{ k.base, path }) catch return error.Unavailable;
        const uri = std.Uri.parse(url) catch return error.Unavailable;
        var req = k.http.request(method, uri, .{
            .keep_alive = false,
            .redirect_behavior = .not_allowed,
            .extra_headers = headers,
            .headers = .{ .accept_encoding = .omit, .user_agent = .{ .override = "zkfsm-swift" } },
        }) catch return error.Unavailable;
        defer req.deinit();
        if (req.connection) |c| listener.setTimeouts(c.stream_reader.getStream().handle, io_timeout_s);
        if (body) |b| {
            const copy = try k.gpa.dupe(u8, b);
            defer k.gpa.free(copy);
            req.sendBodyComplete(copy) catch return error.Unavailable;
        } else req.sendBodiless() catch return error.Unavailable;
        var response = req.receiveHead(&.{}) catch return error.Unavailable;
        if (subject) |s| {
            var it = response.head.iterateHeaders();
            while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-subject-token")) {
                if (h.value.len > max_token or !util.safeValue(h.value)) return error.Unavailable;
                @memcpy(s.buf[0..h.value.len], h.value);
                s.len.* = h.value.len;
            };
        }
        const status: u16 = @intFromEnum(response.head.status);
        var tbuf: [4096]u8 = undefined;
        const rd = response.reader(&tbuf);
        const out = rd.allocRemaining(k.gpa, .limited(max_response)) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unavailable,
        };
        return .{ .status = status, .body = out };
    }
};

fn passwordBody(w: *std.Io.Writer, c: Config) std.Io.Writer.Error!void {
    try w.writeAll("{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":");
    try util.jsonString(w, c.user orelse "");
    try w.writeAll(",\"domain\":{\"name\":");
    try util.jsonString(w, c.domain);
    try w.writeAll("},\"password\":");
    try util.jsonString(w, c.password orelse "");
    try w.writeAll("}}},\"scope\":{\"project\":{\"name\":");
    try util.jsonString(w, c.project orelse "");
    try w.writeAll(",\"domain\":{\"name\":");
    try util.jsonString(w, c.domain);
    try w.writeAll("}}}}}");
}

test "parse keystone token" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const i = try parseToken(a,
        \\{"token": {"methods": ["password"], "expires_at": "2026-10-06T12:30:05.000000Z",
        \\ "project": {"id": "8538a3f13f9541b28c2620eb19065e45", "name": "demo", "domain": {"id": "default"}},
        \\ "roles": [{"id": "r1", "name": "member"}], "user": {"id": "u1", "name": "alice"}}}
    );
    try std.testing.expectEqualStrings("8538a3f13f9541b28c2620eb19065e45", i.projectId());
    try std.testing.expectEqualStrings("demo", i.projectName());
    try std.testing.expectEqual(@as(i64, 1791289805), i.expires_s);
    try std.testing.expectError(error.BadResponse, parseToken(a, "{\"token\":{\"expires_at\":\"2026-10-06T12:30:05Z\"}}"));
    try std.testing.expectError(error.BadResponse, parseToken(a, "{\"token\":{\"expires_at\":\"x\",\"project\":{\"id\":\"p\"}}}"));
    try std.testing.expectError(error.BadResponse, parseToken(a, "{\"token\":{\"expires_at\":\"2026-10-06T12:30:05Z\",\"project\":{\"id\":\"../x\"}}}"));
    try std.testing.expectError(error.BadResponse, parseToken(a, "[]"));
    try std.testing.expectError(error.BadResponse, parseToken(a, "garbage"));
}

test "project map and config" {
    var c: Config = .{};
    try c.addMap("8538a3=alice");
    try c.addMap("demo=bob");
    try std.testing.expectError(error.BadArgs, c.addMap("nomap"));
    try std.testing.expectError(error.BadArgs, c.addMap("=x"));
    try std.testing.expectEqualStrings("alice", c.mapped("8538a3", "demo").?);
    try std.testing.expectEqualStrings("bob", c.mapped("other", "demo").?);
    try std.testing.expect(c.mapped("other", "") == null);
    c.url = "http://k";
    try std.testing.expect(!c.valid());
    c.admin_token = "t";
    try std.testing.expect(c.valid());
}

test "token cache is bounded LRU with expiry" {
    const cache = try std.testing.allocator.create(Cache);
    defer std.testing.allocator.destroy(cache);
    cache.* = .{};
    var info: Info = .{ .expires_s = 100 };
    info.project_id_len = 1;
    info.project_id_buf[0] = 'p';
    var name: [16]u8 = undefined;
    for (0..cache_capacity) |i| cache.put(try std.fmt.bufPrint(&name, "t{d}", .{i}), info);
    try std.testing.expect(cache.get("t0", 50) != null);
    cache.put("new", info);
    try std.testing.expectEqual(@as(usize, cache_capacity), cache.len);
    try std.testing.expect(cache.get("t1", 50) == null);
    try std.testing.expect(cache.get("t0", 50) != null);
    try std.testing.expect(cache.get("new", 100) == null);
}
