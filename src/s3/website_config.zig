//! Bucket static website configuration: parse, serialize and pure request routing.
const std = @import("std");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");

pub const Error = error{ MalformedXML, InvalidRequest, OutOfMemory };

pub const max_rules = 50;

pub const RedirectAll = struct {
    host_name: []const u8,
    protocol: ?[]const u8 = null,
};

pub const Condition = struct {
    key_prefix_equals: ?[]const u8 = null,
    http_error_code_returned_equals: ?u16 = null,
};

pub const RuleRedirect = struct {
    protocol: ?[]const u8 = null,
    host_name: ?[]const u8 = null,
    replace_key_prefix_with: ?[]const u8 = null,
    replace_key_with: ?[]const u8 = null,
    http_redirect_code: ?u16 = null,
};

pub const RoutingRule = struct {
    condition: ?Condition = null,
    redirect: RuleRedirect,
};

pub const Config = union(enum) {
    redirect_all: RedirectAll,
    site: Site,
};

pub const Site = struct {
    index_suffix: []const u8,
    error_key: ?[]const u8 = null,
    routing_rules: []RoutingRule = &.{},
};

/// A computed redirect response.
pub const Redirect = struct {
    location: []const u8,
    code: u16,
};

pub const Action = union(enum) {
    redirect: Redirect,
    /// Object key to serve.
    serve: []const u8,
};

fn text(arena: std.mem.Allocator, body: []const u8, name: []const u8) Error!?[]const u8 {
    var sc: xml_read.Scanner = .{ .s = body };
    const raw = (try sc.next(name)) orelse return null;
    return try xml_read.unescape(arena, std.mem.trim(u8, raw, " \t\r\n"));
}

fn code(arena: std.mem.Allocator, body: []const u8, name: []const u8, lo: u16, hi: u16) Error!?u16 {
    const s = (try text(arena, body, name)) orelse return null;
    const v = std.fmt.parseInt(u16, s, 10) catch return error.MalformedXML;
    if (v < lo or v > hi) return error.InvalidRequest;
    return v;
}

fn protocol(arena: std.mem.Allocator, body: []const u8) Error!?[]const u8 {
    const p = (try text(arena, body, "Protocol")) orelse return null;
    if (!std.mem.eql(u8, p, "http") and !std.mem.eql(u8, p, "https")) return error.InvalidRequest;
    return p;
}

pub fn parse(arena: std.mem.Allocator, body: []const u8) Error!Config {
    var root: xml_read.Scanner = .{ .s = body };
    const inner = (try root.next("WebsiteConfiguration")) orelse return error.MalformedXML;
    var ra_sc: xml_read.Scanner = .{ .s = inner };
    const index_raw = blk: {
        var s: xml_read.Scanner = .{ .s = inner };
        break :blk try s.next("IndexDocument");
    };
    const err_raw = blk: {
        var s: xml_read.Scanner = .{ .s = inner };
        break :blk try s.next("ErrorDocument");
    };
    const rules_raw = blk: {
        var s: xml_read.Scanner = .{ .s = inner };
        break :blk try s.next("RoutingRules");
    };
    if (try ra_sc.next("RedirectAllRequestsTo")) |ra| {
        if (index_raw != null or err_raw != null or rules_raw != null) return error.InvalidRequest;
        const host = (try text(arena, ra, "HostName")) orelse return error.MalformedXML;
        if (host.len == 0) return error.InvalidRequest;
        return .{ .redirect_all = .{ .host_name = host, .protocol = try protocol(arena, ra) } };
    }
    const idx = index_raw orelse return error.InvalidRequest;
    const suffix = (try text(arena, idx, "Suffix")) orelse return error.MalformedXML;
    if (suffix.len == 0 or std.mem.indexOfScalar(u8, suffix, '/') != null) return error.InvalidRequest;
    var site: Site = .{ .index_suffix = suffix };
    if (err_raw) |e| {
        const k = (try text(arena, e, "Key")) orelse return error.MalformedXML;
        if (k.len == 0) return error.InvalidRequest;
        site.error_key = k;
    }
    if (rules_raw) |rr| {
        var rules: std.ArrayList(RoutingRule) = .empty;
        var sc: xml_read.Scanner = .{ .s = rr };
        while (try sc.next("RoutingRule")) |rb| {
            if (rules.items.len >= max_rules) return error.InvalidRequest;
            try rules.append(arena, try parseRule(arena, rb));
        }
        if (rules.items.len == 0) return error.MalformedXML;
        site.routing_rules = rules.items;
    }
    return .{ .site = site };
}

fn parseRule(arena: std.mem.Allocator, rb: []const u8) Error!RoutingRule {
    var rule: RoutingRule = .{ .redirect = .{} };
    var csc: xml_read.Scanner = .{ .s = rb };
    if (try csc.next("Condition")) |c| {
        rule.condition = .{
            .key_prefix_equals = try text(arena, c, "KeyPrefixEquals"),
            .http_error_code_returned_equals = try code(arena, c, "HttpErrorCodeReturnedEquals", 400, 599),
        };
        if (rule.condition.?.key_prefix_equals == null and rule.condition.?.http_error_code_returned_equals == null)
            return error.InvalidRequest;
    }
    var rsc: xml_read.Scanner = .{ .s = rb };
    const r = (try rsc.next("Redirect")) orelse return error.MalformedXML;
    rule.redirect = .{
        .protocol = try protocol(arena, r),
        .host_name = try text(arena, r, "HostName"),
        .replace_key_prefix_with = try text(arena, r, "ReplaceKeyPrefixWith"),
        .replace_key_with = try text(arena, r, "ReplaceKeyWith"),
        .http_redirect_code = try code(arena, r, "HttpRedirectCode", 300, 399),
    };
    if (rule.redirect.replace_key_prefix_with != null and rule.redirect.replace_key_with != null)
        return error.InvalidRequest;
    return rule;
}

pub fn write(w: *std.Io.Writer, cfg: Config) std.Io.Writer.Error!void {
    try xml.openRoot(w, "WebsiteConfiguration");
    switch (cfg) {
        .redirect_all => |ra| {
            try xml.open(w, "RedirectAllRequestsTo");
            try xml.elem(w, "HostName", ra.host_name);
            if (ra.protocol) |p| try xml.elem(w, "Protocol", p);
            try xml.close(w, "RedirectAllRequestsTo");
        },
        .site => |s| {
            try xml.open(w, "IndexDocument");
            try xml.elem(w, "Suffix", s.index_suffix);
            try xml.close(w, "IndexDocument");
            if (s.error_key) |k| {
                try xml.open(w, "ErrorDocument");
                try xml.elem(w, "Key", k);
                try xml.close(w, "ErrorDocument");
            }
            if (s.routing_rules.len > 0) {
                try xml.open(w, "RoutingRules");
                for (s.routing_rules) |r| try writeRule(w, r);
                try xml.close(w, "RoutingRules");
            }
        },
    }
    try xml.close(w, "WebsiteConfiguration");
}

fn writeRule(w: *std.Io.Writer, r: RoutingRule) std.Io.Writer.Error!void {
    try xml.open(w, "RoutingRule");
    if (r.condition) |c| {
        try xml.open(w, "Condition");
        if (c.http_error_code_returned_equals) |e| try xml.elemInt(w, "HttpErrorCodeReturnedEquals", e);
        if (c.key_prefix_equals) |k| try xml.elem(w, "KeyPrefixEquals", k);
        try xml.close(w, "Condition");
    }
    try xml.open(w, "Redirect");
    if (r.redirect.host_name) |v| try xml.elem(w, "HostName", v);
    if (r.redirect.http_redirect_code) |v| try xml.elemInt(w, "HttpRedirectCode", v);
    if (r.redirect.protocol) |v| try xml.elem(w, "Protocol", v);
    if (r.redirect.replace_key_prefix_with) |v| try xml.elem(w, "ReplaceKeyPrefixWith", v);
    if (r.redirect.replace_key_with) |v| try xml.elem(w, "ReplaceKeyWith", v);
    try xml.close(w, "Redirect");
    try xml.close(w, "RoutingRule");
}

fn prefixOk(c: Condition, key: []const u8) bool {
    const p = c.key_prefix_equals orelse return true;
    return std.mem.startsWith(u8, key, p);
}

fn build(arena: std.mem.Allocator, r: RoutingRule, host: []const u8, key: []const u8) Error!Redirect {
    const rd = r.redirect;
    const new_key = if (rd.replace_key_with) |k|
        k
    else if (rd.replace_key_prefix_with) |p| blk: {
        const plen = if (r.condition) |c| (if (c.key_prefix_equals) |kp| kp.len else 0) else 0;
        break :blk try std.mem.concat(arena, u8, &.{ p, key[plen..] });
    } else key;
    return .{
        .location = try std.fmt.allocPrint(arena, "{s}://{s}/{s}", .{ rd.protocol orelse "http", rd.host_name orelse host, new_key }),
        .code = rd.http_redirect_code orelse 301,
    };
}

/// Initial lookup for `key` (no leading slash); `host` is the request Host.
pub fn resolve(arena: std.mem.Allocator, cfg: Config, host: []const u8, key: []const u8) Error!Action {
    switch (cfg) {
        .redirect_all => |ra| return .{ .redirect = .{
            .location = try std.fmt.allocPrint(arena, "{s}://{s}/{s}", .{ ra.protocol orelse "http", ra.host_name, key }),
            .code = 301,
        } },
        .site => |s| {
            for (s.routing_rules) |r| {
                const c = r.condition orelse return .{ .redirect = try build(arena, r, host, key) };
                if (c.http_error_code_returned_equals != null) continue;
                if (prefixOk(c, key)) return .{ .redirect = try build(arena, r, host, key) };
            }
            if (key.len == 0 or key[key.len - 1] == '/')
                return .{ .serve = try std.mem.concat(arena, u8, &.{ key, s.index_suffix }) };
            return .{ .serve = key };
        },
    }
}

/// Redirect for a lookup that failed with `status`, from error-code rules.
pub fn onError(arena: std.mem.Allocator, cfg: Config, host: []const u8, key: []const u8, status: u16) Error!?Redirect {
    const s = switch (cfg) {
        .site => |s| s,
        .redirect_all => return null,
    };
    for (s.routing_rules) |r| {
        const c = r.condition orelse continue;
        const e = c.http_error_code_returned_equals orelse continue;
        if (e == status and prefixOk(c, key)) return try build(arena, r, host, key);
    }
    return null;
}

pub fn errorDocument(cfg: Config) ?[]const u8 {
    return switch (cfg) {
        .site => |s| s.error_key,
        .redirect_all => null,
    };
}

/// `key` has no trailing slash but `key/` + suffix exists (caller checks): 302 to `/key/`.
pub fn directoryRedirect(arena: std.mem.Allocator, key: []const u8) Error!Redirect {
    return .{ .location = try std.fmt.allocPrint(arena, "/{s}/", .{key}), .code = 302 };
}

// ---- tests ----

const t = std.testing;

const full =
    \\<?xml version="1.0"?><WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    \\<IndexDocument><Suffix>index.html</Suffix></IndexDocument>
    \\<ErrorDocument><Key>err&amp;.html</Key></ErrorDocument>
    \\<RoutingRules>
    \\<RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals></Condition>
    \\<Redirect><ReplaceKeyPrefixWith>documents/</ReplaceKeyPrefixWith></Redirect></RoutingRule>
    \\<RoutingRule><Condition><KeyPrefixEquals>old.html</KeyPrefixEquals></Condition>
    \\<Redirect><HostName>ex.com</HostName><Protocol>https</Protocol><ReplaceKeyWith>new.html</ReplaceKeyWith><HttpRedirectCode>302</HttpRedirectCode></Redirect></RoutingRule>
    \\<RoutingRule><Condition><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition>
    \\<Redirect><HostName>fallback.com</HostName><ReplaceKeyPrefixWith>report-404/</ReplaceKeyPrefixWith></Redirect></RoutingRule>
    \\</RoutingRules></WebsiteConfiguration>
;

test "parse and round trip" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cfg = try parse(a, full);
    try t.expectEqualStrings("index.html", cfg.site.index_suffix);
    try t.expectEqualStrings("err&.html", errorDocument(cfg).?);
    try t.expectEqual(@as(usize, 3), cfg.site.routing_rules.len);
    try t.expectEqual(@as(?u16, 302), cfg.site.routing_rules[1].redirect.http_redirect_code);

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try write(&w, cfg);
    const again = try parse(a, w.buffered());
    try t.expectEqualDeep(cfg, again);

    const ra = try parse(a, "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>x.org</HostName><Protocol>https</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>");
    var w2: std.Io.Writer = .fixed(&buf);
    try write(&w2, ra);
    try t.expectEqualDeep(ra, try parse(a, w2.buffered()));
    try t.expect(errorDocument(ra) == null);
}

test "parse validation" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const bad = [_]struct { []const u8, Error }{
        .{ "<Nope/>", error.MalformedXML },
        .{ "<WebsiteConfiguration></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix></Suffix></IndexDocument></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix>a/b</Suffix></IndexDocument></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>h</HostName></RedirectAllRequestsTo><IndexDocument><Suffix>i</Suffix></IndexDocument></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>h</HostName><Protocol>ftp</Protocol></RedirectAllRequestsTo></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules><RoutingRule><Redirect><ReplaceKeyWith>a</ReplaceKeyWith><ReplaceKeyPrefixWith>b</ReplaceKeyPrefixWith></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules><RoutingRule><Redirect><HttpRedirectCode>200</HttpRedirectCode></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", error.InvalidRequest },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules><RoutingRule><Redirect><HttpRedirectCode>x</HttpRedirectCode></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>", error.MalformedXML },
        .{ "<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules><RoutingRule></RoutingRule></RoutingRules></WebsiteConfiguration>", error.MalformedXML },
    };
    for (bad) |b| try t.expectError(b[1], parse(a, b[0]));

    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(a, "<WebsiteConfiguration><IndexDocument><Suffix>i</Suffix></IndexDocument><RoutingRules>");
    for (0..51) |_| try many.appendSlice(a, "<RoutingRule><Redirect><HostName>h</HostName></Redirect></RoutingRule>");
    try many.appendSlice(a, "</RoutingRules></WebsiteConfiguration>");
    try t.expectError(error.InvalidRequest, parse(a, many.items));
}

test "routing" {
    var ar = std.heap.ArenaAllocator.init(t.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    const cfg = try parse(a, full);
    try t.expectEqualStrings("index.html", (try resolve(a, cfg, "b.web", "")).serve);
    try t.expectEqualStrings("sub/index.html", (try resolve(a, cfg, "b.web", "sub/")).serve);
    try t.expectEqualStrings("a.txt", (try resolve(a, cfg, "b.web", "a.txt")).serve);

    const r1 = (try resolve(a, cfg, "b.web", "docs/x/y.html")).redirect;
    try t.expectEqualStrings("http://b.web/documents/x/y.html", r1.location);
    try t.expectEqual(@as(u16, 301), r1.code);
    const r2 = (try resolve(a, cfg, "b.web", "old.html")).redirect;
    try t.expectEqualStrings("https://ex.com/new.html", r2.location);
    try t.expectEqual(@as(u16, 302), r2.code);

    const e = (try onError(a, cfg, "b.web", "missing", 404)).?;
    try t.expectEqualStrings("http://fallback.com/report-404/missing", e.location);
    try t.expect((try onError(a, cfg, "b.web", "missing", 403)) == null);

    const ra = try parse(a, "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>x.org</HostName></RedirectAllRequestsTo></WebsiteConfiguration>");
    const r3 = (try resolve(a, ra, "b.web", "p/q")).redirect;
    try t.expectEqualStrings("http://x.org/p/q", r3.location);
    try t.expect((try onError(a, ra, "b.web", "p", 404)) == null);

    const dr = try directoryRedirect(a, "photos");
    try t.expectEqualStrings("/photos/", dr.location);
    try t.expectEqual(@as(u16, 302), dr.code);
}
