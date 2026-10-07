//! Bucket CORS configuration: parse, serialize, rule matching and response headers.
const std = @import("std");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");

pub const Error = error{ MalformedXML, InvalidRequest, OutOfMemory };

pub const max_rules = 100;
pub const methods = [_][]const u8{ "GET", "PUT", "HEAD", "POST", "DELETE" };

pub const Rule = struct {
    id: ?[]const u8 = null,
    allowed_origins: [][]const u8,
    allowed_methods: [][]const u8,
    allowed_headers: [][]const u8 = &.{},
    expose_headers: [][]const u8 = &.{},
    max_age_s: ?u32 = null,
};

pub const Config = struct {
    rules: []Rule,
};

fn collect(arena: std.mem.Allocator, body: []const u8, name: []const u8) Error![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var sc: xml_read.Scanner = .{ .s = body };
    while (try sc.next(name)) |raw| {
        const v = try xml_read.unescape(arena, std.mem.trim(u8, raw, " \t\r\n"));
        try out.append(arena, v);
    }
    return out.items;
}

fn starCount(s: []const u8) usize {
    return std.mem.count(u8, s, "*");
}

pub fn parse(arena: std.mem.Allocator, xml_body: []const u8) Error!Config {
    var root: xml_read.Scanner = .{ .s = xml_body };
    const inner = (try root.next("CORSConfiguration")) orelse return error.MalformedXML;
    var rules: std.ArrayList(Rule) = .empty;
    var sc: xml_read.Scanner = .{ .s = inner };
    while (try sc.next("CORSRule")) |rb| {
        if (rules.items.len >= max_rules) return error.InvalidRequest;
        var r: Rule = .{
            .allowed_origins = try collect(arena, rb, "AllowedOrigin"),
            .allowed_methods = try collect(arena, rb, "AllowedMethod"),
            .allowed_headers = try collect(arena, rb, "AllowedHeader"),
            .expose_headers = try collect(arena, rb, "ExposeHeader"),
        };
        var idsc: xml_read.Scanner = .{ .s = rb };
        if (try idsc.next("ID")) |id| r.id = try xml_read.unescape(arena, id);
        var masc: xml_read.Scanner = .{ .s = rb };
        if (try masc.next("MaxAgeSeconds")) |ma|
            r.max_age_s = std.fmt.parseInt(u32, std.mem.trim(u8, ma, " \t\r\n"), 10) catch return error.MalformedXML;
        if (r.allowed_origins.len == 0 or r.allowed_methods.len == 0) return error.MalformedXML;
        for (r.allowed_methods) |m| {
            if (!isMethod(m)) return error.InvalidRequest;
        }
        for (r.allowed_origins) |o| if (starCount(o) > 1) return error.InvalidRequest;
        for (r.allowed_headers) |h| if (starCount(h) > 1) return error.InvalidRequest;
        try rules.append(arena, r);
    }
    if (rules.items.len == 0) return error.MalformedXML;
    return .{ .rules = rules.items };
}

fn isMethod(m: []const u8) bool {
    for (methods) |k| if (std.mem.eql(u8, k, m)) return true;
    return false;
}

pub fn write(w: *std.Io.Writer, cfg: Config) std.Io.Writer.Error!void {
    try xml.openRoot(w, "CORSConfiguration");
    for (cfg.rules) |r| {
        try xml.open(w, "CORSRule");
        if (r.id) |id| try xml.elem(w, "ID", id);
        for (r.allowed_headers) |v| try xml.elem(w, "AllowedHeader", v);
        for (r.allowed_methods) |v| try xml.elem(w, "AllowedMethod", v);
        for (r.allowed_origins) |v| try xml.elem(w, "AllowedOrigin", v);
        for (r.expose_headers) |v| try xml.elem(w, "ExposeHeader", v);
        if (r.max_age_s) |ma| try xml.elemInt(w, "MaxAgeSeconds", ma);
        try xml.close(w, "CORSRule");
    }
    try xml.close(w, "CORSConfiguration");
}

/// Glob match where `*` matches any (possibly empty) substring.
fn glob(pattern: []const u8, s: []const u8, ci: bool) bool {
    var p: usize = 0;
    var i: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (i < s.len) {
        if (p < pattern.len and pattern[p] != '*' and eqc(pattern[p], s[i], ci)) {
            p += 1;
            i += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            mark = i;
        } else if (star) |sp| {
            p = sp + 1;
            mark += 1;
            i = mark;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqc(a: u8, b: u8, ci: bool) bool {
    return if (ci) std.ascii.toLower(a) == std.ascii.toLower(b) else a == b;
}

fn originPattern(rule: *const Rule, origin: []const u8) ?[]const u8 {
    for (rule.allowed_origins) |o| if (glob(o, origin, false)) return o;
    return null;
}

fn headerAllowed(rule: *const Rule, h: []const u8) bool {
    for (rule.allowed_headers) |p| if (glob(p, h, true)) return true;
    return false;
}

/// First rule matching origin, method and every requested header.
pub fn match(cfg: Config, origin: []const u8, method: []const u8, request_headers: []const []const u8) ?*const Rule {
    for (cfg.rules) |*r| {
        if (originPattern(r, origin) == null) continue;
        if (!isIn(r.allowed_methods, method)) continue;
        const ok = for (request_headers) |h| {
            if (!headerAllowed(r, h)) break false;
        } else true;
        if (ok) return r;
    }
    return null;
}

fn isIn(list: []const []const u8, v: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, v)) return true;
    return false;
}

/// Splits an Access-Control-Request-Headers value; trims and drops empties.
pub fn splitHeaders(arena: std.mem.Allocator, csv: ?[]const u8) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, csv orelse return out.items, ',');
    while (it.next()) |part| {
        const tr = std.mem.trim(u8, part, " \t");
        if (tr.len > 0) try out.append(arena, tr);
    }
    return out.items;
}

/// Headers for a matched rule. A pattern of exactly `*` echoes `*` without credentials;
/// otherwise the origin is echoed with credentials and `vary: Origin`.
pub fn responseHeaders(
    arena: std.mem.Allocator,
    rule: *const Rule,
    origin: []const u8,
    request_headers: []const []const u8,
    preflight_req: bool,
) Error![]std.http.Header {
    var out: std.ArrayList(std.http.Header) = .empty;
    const pat = originPattern(rule, origin) orelse origin;
    const any = std.mem.eql(u8, pat, "*");
    try out.append(arena, .{ .name = "access-control-allow-origin", .value = if (any) "*" else origin });
    try out.append(arena, .{ .name = "access-control-allow-methods", .value = try std.mem.join(arena, ", ", rule.allowed_methods) });
    if (!any) try out.append(arena, .{ .name = "access-control-allow-credentials", .value = "true" });
    if (preflight_req) {
        if (request_headers.len > 0)
            try out.append(arena, .{ .name = "access-control-allow-headers", .value = try std.mem.join(arena, ", ", request_headers) });
        if (rule.max_age_s) |ma|
            try out.append(arena, .{ .name = "access-control-max-age", .value = try std.fmt.allocPrint(arena, "{d}", .{ma}) });
    } else if (rule.expose_headers.len > 0) {
        try out.append(arena, .{ .name = "access-control-expose-headers", .value = try std.mem.join(arena, ", ", rule.expose_headers) });
    }
    try out.append(arena, .{ .name = "vary", .value = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method" });
    return out.items;
}

/// CORS headers for a non-OPTIONS request (any status). The rule method is the
/// Access-Control-Request-Method header when present, else the request method.
pub fn simpleHeaders(
    arena: std.mem.Allocator,
    cfg: ?Config,
    origin: ?[]const u8,
    method: []const u8,
    req_method: ?[]const u8,
) Error![]std.http.Header {
    const c = cfg orelse return &.{};
    const o = origin orelse return &.{};
    const rule = match(c, o, req_method orelse method, &.{}) orelse return &.{};
    return responseHeaders(arena, rule, o, &.{}, false);
}

pub const Failure = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

pub const PreflightResult = union(enum) {
    ok: []std.http.Header,
    fail: Failure,
};

/// OPTIONS evaluation; runs before authentication.
pub fn preflight(
    cfg: ?Config,
    origin: ?[]const u8,
    req_method: ?[]const u8,
    req_headers_csv: ?[]const u8,
    arena: std.mem.Allocator,
) Error!PreflightResult {
    const o = origin orelse return .{ .fail = .{ .status = 400, .code = "BadRequest", .message = "Insufficient information. Origin request header needed." } };
    const m = req_method orelse return .{ .fail = .{ .status = 400, .code = "BadRequest", .message = "Invalid Access-Control-Request-Method: null" } };
    if (!isMethod(m)) return .{ .fail = .{ .status = 400, .code = "BadRequest", .message = "Invalid Access-Control-Request-Method" } };
    const forbidden: PreflightResult = .{ .fail = .{ .status = 403, .code = "AccessForbidden", .message = "CORSResponse: This CORS request is not allowed." } };
    const c = cfg orelse return forbidden;
    const hs = try splitHeaders(arena, req_headers_csv);
    const rule = match(c, o, m, hs) orelse return forbidden;
    return .{ .ok = try responseHeaders(arena, rule, o, hs, true) };
}

// ---- tests ----

const t = std.testing;

fn hdr(hs: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

const origin_cfg =
    \\<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    \\<CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*suffix</AllowedOrigin></CORSRule>
    \\<CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>start*end</AllowedOrigin></CORSRule>
    \\<CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>prefix*</AllowedOrigin></CORSRule>
    \\<CORSRule><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>*.put</AllowedOrigin></CORSRule>
    \\</CORSConfiguration>
;

test "parse and round trip" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const body =
        \\<?xml version="1.0"?><CORSConfiguration><CORSRule><ID>r&amp;1</ID>
        \\<AllowedOrigin>*.get</AllowedOrigin><AllowedOrigin>*.put</AllowedOrigin>
        \\<AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>
        \\<AllowedHeader>x-amz-*</AllowedHeader><ExposeHeader>ETag</ExposeHeader>
        \\<MaxAgeSeconds>3000</MaxAgeSeconds></CORSRule></CORSConfiguration>
    ;
    const cfg = try parse(a, body);
    try t.expectEqual(@as(usize, 1), cfg.rules.len);
    const r = cfg.rules[0];
    try t.expectEqualStrings("r&1", r.id.?);
    try t.expectEqualStrings("*.put", r.allowed_origins[1]);
    try t.expectEqualStrings("PUT", r.allowed_methods[1]);
    try t.expectEqual(@as(?u32, 3000), r.max_age_s);

    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, cfg);
    try t.expect(std.mem.indexOf(u8, w.buffered(), "<ID>r&amp;1</ID>") != null);
    const again = try parse(a, w.buffered());
    try t.expectEqualStrings("x-amz-*", again.rules[0].allowed_headers[0]);
    try t.expectEqualStrings("ETag", again.rules[0].expose_headers[0]);
    try t.expectEqual(@as(?u32, 3000), again.rules[0].max_age_s);
}

test "parse validation" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    try t.expectError(error.MalformedXML, parse(a, "<CORSConfiguration></CORSConfiguration>"));
    try t.expectError(error.MalformedXML, parse(a, "<Nope/>"));
    try t.expectError(error.MalformedXML, parse(a, "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"));
    try t.expectError(error.MalformedXML, parse(a, "<CORSConfiguration><CORSRule><AllowedOrigin>a</AllowedOrigin></CORSRule></CORSConfiguration>"));
    try t.expectError(error.InvalidRequest, parse(a, "<CORSConfiguration><CORSRule><AllowedOrigin>a</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod></CORSRule></CORSConfiguration>"));
    try t.expectError(error.InvalidRequest, parse(a, "<CORSConfiguration><CORSRule><AllowedOrigin>*a*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"));
    try t.expectError(error.InvalidRequest, parse(a, "<CORSConfiguration><CORSRule><AllowedOrigin>a</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>**</AllowedHeader></CORSRule></CORSConfiguration>"));
    try t.expectError(error.MalformedXML, parse(a, "<CORSConfiguration><CORSRule><AllowedOrigin>a</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>x</MaxAgeSeconds></CORSRule></CORSConfiguration>"));

    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(a, "<CORSConfiguration>");
    for (0..101) |_| try many.appendSlice(a, "<CORSRule><AllowedOrigin>a</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule>");
    try many.appendSlice(a, "</CORSConfiguration>");
    try t.expectError(error.InvalidRequest, parse(a, many.items));
}

test "glob" {
    try t.expect(glob("*", "", false));
    try t.expect(glob("*suffix", "foo.suffix", false));
    try t.expect(!glob("*suffix", "foo.suffix.get", false));
    try t.expect(glob("start*end", "startend", false));
    try t.expect(!glob("start*end", "0start12end", false));
    try t.expect(!glob("Prefix*", "prefix", false));
    try t.expect(glob("X-Amz-*", "x-amz-date", true));
    try t.expect(glob("a*b*c", "aXbYbc", false));
}

test "simple request headers follow s3-tests" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cfg = try parse(a, origin_cfg);
    const Case = struct { o: []const u8, m: []const u8, rm: ?[]const u8, want: ?[]const u8, meth: ?[]const u8 };
    const cases = [_]Case{
        .{ .o = "foo.suffix", .m = "GET", .rm = null, .want = "foo.suffix", .meth = "GET" },
        .{ .o = "foo.bar", .m = "GET", .rm = null, .want = null, .meth = null },
        .{ .o = "foo.suffix.get", .m = "GET", .rm = null, .want = null, .meth = null },
        .{ .o = "start12end", .m = "GET", .rm = null, .want = "start12end", .meth = "GET" },
        .{ .o = "0start12end", .m = "GET", .rm = null, .want = null, .meth = null },
        .{ .o = "bla.prefix", .m = "GET", .rm = null, .want = null, .meth = null },
        .{ .o = "foo.suffix", .m = "PUT", .rm = "GET", .want = "foo.suffix", .meth = "GET" },
        .{ .o = "foo.suffix", .m = "PUT", .rm = "PUT", .want = null, .meth = null },
        .{ .o = "foo.suffix", .m = "PUT", .rm = null, .want = null, .meth = null },
        .{ .o = "foo.put", .m = "PUT", .rm = null, .want = "foo.put", .meth = "PUT" },
    };
    for (cases) |c| {
        const hs = try simpleHeaders(a, cfg, c.o, c.m, c.rm);
        try t.expectEqualDeep(c.want, hdr(hs, "access-control-allow-origin"));
        try t.expectEqualDeep(c.meth, hdr(hs, "access-control-allow-methods"));
    }
    try t.expectEqual(@as(usize, 0), (try simpleHeaders(a, cfg, null, "GET", null)).len);
    try t.expectEqual(@as(usize, 0), (try simpleHeaders(a, null, "x", "GET", null)).len);
}

test "wildcard origin echoes star" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cfg = try parse(a, "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin><ExposeHeader>x-amz-meta-header1</ExposeHeader></CORSRule></CORSConfiguration>");
    const hs = try simpleHeaders(a, cfg, "example.origin", "GET", null);
    try t.expectEqualStrings("*", hdr(hs, "access-control-allow-origin").?);
    try t.expect(hdr(hs, "access-control-allow-credentials") == null);
    try t.expectEqualStrings("x-amz-meta-header1", hdr(hs, "access-control-expose-headers").?);
    const pf = try preflight(cfg, "example.origin", "GET", "x-amz-meta-header2", a);
    try t.expectEqual(@as(u16, 403), pf.fail.status);
}

test "preflight outcomes" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cfg = try parse(a, origin_cfg);
    try t.expectEqual(@as(u16, 400), (try preflight(cfg, null, null, null, a)).fail.status);
    try t.expectEqual(@as(u16, 400), (try preflight(cfg, "foo.suffix", null, null, a)).fail.status);
    try t.expectEqual(@as(u16, 400), (try preflight(null, null, null, null, a)).fail.status);
    try t.expectEqual(@as(u16, 403), (try preflight(null, "x", "GET", null, a)).fail.status);
    try t.expectEqual(@as(u16, 403), (try preflight(cfg, "foo.bar", "GET", null, a)).fail.status);
    try t.expectEqual(@as(u16, 403), (try preflight(cfg, "foo.put", "GET", null, a)).fail.status);
    const ok = (try preflight(cfg, "foo.put", "PUT", null, a)).ok;
    try t.expectEqualStrings("foo.put", hdr(ok, "access-control-allow-origin").?);
    try t.expectEqualStrings("PUT", hdr(ok, "access-control-allow-methods").?);
    try t.expectEqualStrings("true", hdr(ok, "access-control-allow-credentials").?);

    const hcfg = try parse(a, "<CORSConfiguration><CORSRule><AllowedMethod>PUT</AllowedMethod><AllowedMethod>GET</AllowedMethod><AllowedOrigin>https://*.ex.com</AllowedOrigin><AllowedHeader>X-Amz-*</AllowedHeader><AllowedHeader>content-type</AllowedHeader><MaxAgeSeconds>60</MaxAgeSeconds></CORSRule></CORSConfiguration>");
    const h = (try preflight(hcfg, "https://a.ex.com", "PUT", "x-amz-date, Content-Type", a)).ok;
    try t.expectEqualStrings("x-amz-date, Content-Type", hdr(h, "access-control-allow-headers").?);
    try t.expectEqualStrings("PUT, GET", hdr(h, "access-control-allow-methods").?);
    try t.expectEqualStrings("60", hdr(h, "access-control-max-age").?);
    try t.expectEqual(@as(u16, 403), (try preflight(hcfg, "https://a.ex.com", "PUT", "authorization", a)).fail.status);
    try t.expectEqual(@as(u16, 403), (try preflight(hcfg, "http://a.ex.com", "PUT", null, a)).fail.status);
}
