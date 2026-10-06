//! WebDAV wire pieces: header parsing (Depth, Destination, If, Overwrite), request
//! bodies (propfind, propertyupdate, lockinfo), hrefs and multistatus rendering.
const std = @import("std");
const core = @import("../core/root.zig");
const xml = @import("webdav_xml.zig");
const lock = @import("webdav_lock.zig");

const Writer = std.Io.Writer;
pub const max_props = 256;
pub const max_if_lists = 16;
pub const max_if_conds = 16;

pub const Depth = enum { zero, one, infinity };

/// Null when the header is present but not 0, 1 or infinity.
pub fn parseDepth(h: ?[]const u8, default: Depth) ?Depth {
    const v = std.mem.trim(u8, h orelse return default, " \t");
    if (std.mem.eql(u8, v, "0")) return .zero;
    if (std.mem.eql(u8, v, "1")) return .one;
    if (std.ascii.eqlIgnoreCase(v, "infinity")) return .infinity;
    return null;
}

/// Overwrite: T (default) or F; null when malformed.
pub fn parseOverwrite(h: ?[]const u8) ?bool {
    const v = std.mem.trim(u8, h orelse return true, " \t");
    if (std.ascii.eqlIgnoreCase(v, "T")) return true;
    if (std.ascii.eqlIgnoreCase(v, "F")) return false;
    return null;
}

/// The path part of a request target or absolute URI, without query or fragment.
pub fn uriPath(uri: []const u8) []const u8 {
    var p = uri;
    if (std.mem.indexOf(u8, p, "://")) |i| {
        const rest = p[i + 3 ..];
        p = if (std.mem.indexOfScalar(u8, rest, '/')) |s| rest[s..] else "/";
    }
    const end = std.mem.indexOfAny(u8, p, "?#") orelse p.len;
    return p[0..end];
}

/// Strips `prefix` ("" or "/x") from an encoded path; null when outside it.
pub fn stripPrefix(prefix: []const u8, p: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, p, prefix)) return null;
    const rest = p[prefix.len..];
    if (rest.len == 0) return "/";
    if (rest[0] != '/') return null;
    return rest;
}

/// Percent-decodes into `out`; NUL bytes and bad escapes are rejected.
pub fn percentDecode(out: []u8, s: []const u8) error{InvalidPath}![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (n += 1) {
        if (n == out.len) return error.InvalidPath;
        var c = s[i];
        if (c == '%') {
            if (i + 2 >= s.len) return error.InvalidPath;
            c = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.InvalidPath;
            i += 3;
        } else i += 1;
        if (c == 0) return error.InvalidPath;
        out[n] = c;
    }
    return out[0..n];
}

fn unreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~' or c == '/';
}

/// Writes prefix + percent-encoded `path` (+ `/` for collections), XML-safe.
pub fn writeHref(w: *Writer, prefix: []const u8, path: []const u8, collection: bool) Writer.Error!void {
    try w.writeAll(prefix);
    for (path) |c| {
        if (unreserved(c)) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
    if (collection and (path.len == 0 or path[path.len - 1] != '/')) try w.writeByte('/');
}

// ---- If header (RFC 4918 10.4) ----

pub const Cond = struct {
    not: bool = false,
    etag: bool = false,
    value: []const u8,
};

pub const List = struct {
    /// Resource tag URI, or null for the request URI.
    tag: ?[]const u8 = null,
    conds: []const Cond,
};

pub fn parseIf(arena: std.mem.Allocator, h: []const u8) error{ BadIf, OutOfMemory }![]const List {
    var lists: std.ArrayList(List) = .empty;
    var tag: ?[]const u8 = null;
    var i: usize = 0;
    while (true) {
        while (i < h.len and (h[i] == ' ' or h[i] == '\t')) i += 1;
        if (i >= h.len) break;
        if (h[i] == '<') {
            const e = std.mem.indexOfScalarPos(u8, h, i, '>') orelse return error.BadIf;
            tag = h[i + 1 .. e];
            i = e + 1;
            continue;
        }
        if (h[i] != '(') return error.BadIf;
        i += 1;
        var conds: std.ArrayList(Cond) = .empty;
        while (true) {
            while (i < h.len and (h[i] == ' ' or h[i] == '\t')) i += 1;
            if (i >= h.len) return error.BadIf;
            if (h[i] == ')') {
                i += 1;
                break;
            }
            var c: Cond = .{ .value = "" };
            if (h.len - i >= 3 and std.ascii.eqlIgnoreCase(h[i .. i + 3], "Not")) {
                c.not = true;
                i += 3;
                while (i < h.len and (h[i] == ' ' or h[i] == '\t')) i += 1;
                if (i >= h.len) return error.BadIf;
            }
            const close: u8 = switch (h[i]) {
                '<' => '>',
                '[' => ']',
                else => return error.BadIf,
            };
            c.etag = close == ']';
            const e = std.mem.indexOfScalarPos(u8, h, i, close) orelse return error.BadIf;
            c.value = h[i + 1 .. e];
            i = e + 1;
            if (conds.items.len == max_if_conds) return error.BadIf;
            try conds.append(arena, c);
        }
        if (conds.items.len == 0 or lists.items.len == max_if_lists) return error.BadIf;
        try lists.append(arena, .{ .tag = tag, .conds = conds.items });
    }
    if (lists.items.len == 0) return error.BadIf;
    return lists.items;
}

/// State tokens submitted positively (these count as lock tokens held).
pub fn ifTokens(arena: std.mem.Allocator, lists: []const List) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (lists) |l| for (l.conds) |c| if (!c.not and !c.etag) try out.append(arena, c.value);
    return out.items;
}

/// The token in a Lock-Token header (`<...>`), or null.
pub fn parseLockToken(h: ?[]const u8) ?[]const u8 {
    const v = std.mem.trim(u8, h orelse return null, " \t");
    if (v.len < 3 or v[0] != '<' or v[v.len - 1] != '>') return null;
    return v[1 .. v.len - 1];
}

// ---- request bodies ----

pub const PropName = struct { ns: []const u8, name: []const u8 };
pub const Propfind = union(enum) { allprop, propname, prop: []const PropName };
pub const BodyError = error{ BadBody, OutOfMemory };

fn doc(arena: std.mem.Allocator, body: []const u8) BodyError!xml.Doc {
    return xml.parse(arena, body) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadBody,
    };
}

fn validName(n: []const u8) bool {
    if (n.len == 0) return false;
    for (n) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.' or c >= 0x80)) return false;
    return true;
}

fn propNames(arena: std.mem.Allocator, d: xml.Doc, prop: u16, out: *std.ArrayList(PropName)) BodyError!void {
    var it = d.children(prop);
    while (it.next()) |c| {
        if (!validName(d.nodes[c].name)) continue;
        if (out.items.len == max_props) return error.BadBody;
        try out.append(arena, .{ .ns = d.nodes[c].ns, .name = d.nodes[c].name });
    }
}

/// An empty body means allprop (RFC 4918 9.1).
pub fn parsePropfind(arena: std.mem.Allocator, body: []const u8) BodyError!Propfind {
    if (std.mem.trim(u8, body, " \t\r\n").len == 0) return .allprop;
    const d = try doc(arena, body);
    const r = d.root().?;
    if (!d.is(r, xml.dav_ns, "propfind")) return error.BadBody;
    if (d.child(r, "allprop") != null) return .allprop;
    if (d.child(r, "propname") != null) return .propname;
    const p = d.child(r, "prop") orelse return error.BadBody;
    var out: std.ArrayList(PropName) = .empty;
    try propNames(arena, d, p, &out);
    return .{ .prop = out.items };
}

/// Property names named by a propertyupdate's set/remove instructions.
pub fn parseProppatch(arena: std.mem.Allocator, body: []const u8) BodyError![]const PropName {
    const d = try doc(arena, body);
    const r = d.root().?;
    if (!d.is(r, xml.dav_ns, "propertyupdate")) return error.BadBody;
    var out: std.ArrayList(PropName) = .empty;
    var it = d.children(r);
    while (it.next()) |c| {
        if (!d.is(c, xml.dav_ns, "set") and !d.is(c, xml.dav_ns, "remove")) continue;
        const p = d.child(c, "prop") orelse return error.BadBody;
        try propNames(arena, d, p, &out);
    }
    return out.items;
}

pub const LockInfo = struct {
    scope: lock.Scope,
    owner: []const u8 = "",
    owner_href: bool = false,
};

pub fn parseLockinfo(arena: std.mem.Allocator, body: []const u8) BodyError!LockInfo {
    const d = try doc(arena, body);
    const r = d.root().?;
    if (!d.is(r, xml.dav_ns, "lockinfo")) return error.BadBody;
    const sc = d.child(r, "lockscope") orelse return error.BadBody;
    const ty = d.child(r, "locktype") orelse return error.BadBody;
    if (d.child(ty, "write") == null) return error.BadBody;
    var info: LockInfo = .{ .scope = if (d.child(sc, "exclusive") != null)
        .exclusive
    else if (d.child(sc, "shared") != null)
        .shared
    else
        return error.BadBody };
    if (d.child(r, "owner")) |o| {
        const src = if (d.child(o, "href")) |h| blk: {
            info.owner_href = true;
            break :blk d.nodes[h].inner;
        } else d.nodes[o].inner;
        info.owner = xml.text(arena, src, lock.max_owner) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadBody,
        };
        info.owner = std.mem.trim(u8, info.owner, " \t\r\n");
    }
    return info;
}

// ---- rendering ----

pub const Resource = struct {
    /// Normalized absolute path ("/" for the root).
    path: []const u8,
    collection: bool,
    size: u64 = 0,
    mtime_ns: i128 = 0,
    etag: ?core.ETag = null,
    content_type: []const u8 = "",
    locks: []const lock.Lock = &.{},
    now_s: i64 = 0,
};

const live = [_][]const u8{ "resourcetype", "displayname", "getlastmodified", "creationdate", "getcontentlength", "getcontenttype", "getetag", "supportedlock", "lockdiscovery" };

fn available(r: Resource, name: []const u8) bool {
    for (live) |l| if (std.mem.eql(u8, l, name)) {
        if (!r.collection) return true;
        return !std.mem.eql(u8, name, "getcontentlength") and !std.mem.eql(u8, name, "getcontenttype") and !std.mem.eql(u8, name, "getetag");
    };
    return false;
}

pub const supported_lock =
    "<D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>" ++
    "<D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>";

pub fn writeActiveLock(w: *Writer, prefix: []const u8, l: *const lock.Lock, now_s: i64) Writer.Error!void {
    try w.print("<D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:{t}/></D:lockscope><D:depth>{s}</D:depth>", .{
        l.scope, if (l.infinite) "infinity" else "0",
    });
    if (l.owner_len > 0) {
        try w.writeAll(if (l.owner_href) "<D:owner><D:href>" else "<D:owner>");
        try xml.escape(w, l.owner());
        try w.writeAll(if (l.owner_href) "</D:href></D:owner>" else "</D:owner>");
    }
    const left = @max(0, l.expires_s - now_s);
    try w.print("<D:timeout>Second-{d}</D:timeout><D:locktoken><D:href>{s}</D:href></D:locktoken><D:lockroot><D:href>", .{ left, &l.token });
    try writeHref(w, prefix, l.path(), false);
    try w.writeAll("</D:href></D:lockroot></D:activelock>");
}

fn writeValue(w: *Writer, prefix: []const u8, r: Resource, name: []const u8) Writer.Error!void {
    try w.print("<D:{s}>", .{name});
    if (std.mem.eql(u8, name, "resourcetype")) {
        if (r.collection) try w.writeAll("<D:collection/>");
    } else if (std.mem.eql(u8, name, "displayname")) {
        try xml.escape(w, baseName(r.path));
    } else if (std.mem.eql(u8, name, "getlastmodified")) {
        var b: [29]u8 = undefined;
        try w.writeAll(core.time.httpDate(r.mtime_ns, &b));
    } else if (std.mem.eql(u8, name, "creationdate")) {
        var b: [24]u8 = undefined;
        try w.writeAll(core.time.iso8601(r.mtime_ns, &b));
    } else if (std.mem.eql(u8, name, "getcontentlength")) {
        try w.print("{d}", .{r.size});
    } else if (std.mem.eql(u8, name, "getcontenttype")) {
        try xml.escape(w, r.content_type);
    } else if (std.mem.eql(u8, name, "getetag")) {
        if (r.etag) |e| {
            var b: [core.ETag.quoted_max]u8 = undefined;
            try xml.escape(w, e.quoted(&b));
        }
    } else if (std.mem.eql(u8, name, "supportedlock")) {
        try w.writeAll(supported_lock);
    } else if (std.mem.eql(u8, name, "lockdiscovery")) {
        for (r.locks) |*l| try writeActiveLock(w, prefix, l, r.now_s);
    }
    try w.print("</D:{s}>", .{name});
}

fn writeEmpty(w: *Writer, p: PropName) Writer.Error!void {
    if (std.mem.eql(u8, p.ns, xml.dav_ns)) return w.print("<D:{s}/>", .{p.name});
    try w.print("<X:{s} xmlns:X=\"", .{p.name});
    try xml.escape(w, p.ns);
    try w.writeAll("\"/>");
}

fn statusLine(code: u16) []const u8 {
    return switch (code) {
        200 => "HTTP/1.1 200 OK",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        424 => "HTTP/1.1 424 Failed Dependency",
        else => "HTTP/1.1 500 Internal Server Error",
    };
}

pub const multistatus_open = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">";
pub const multistatus_close = "</D:multistatus>\n";

/// One `<D:response>` for a PROPFIND.
pub fn writeResponse(w: *Writer, prefix: []const u8, r: Resource, pf: Propfind) Writer.Error!void {
    try w.writeAll("<D:response><D:href>");
    try writeHref(w, prefix, r.path, r.collection);
    try w.writeAll("</D:href><D:propstat><D:prop>");
    switch (pf) {
        .allprop => for (live) |n| if (available(r, n)) try writeValue(w, prefix, r, n),
        .propname => for (live) |n| if (available(r, n)) try w.print("<D:{s}/>", .{n}),
        .prop => |ps| for (ps) |p| if (std.mem.eql(u8, p.ns, xml.dav_ns) and available(r, p.name)) try writeValue(w, prefix, r, p.name),
    }
    try w.print("</D:prop><D:status>{s}</D:status></D:propstat>", .{statusLine(200)});
    if (pf == .prop) {
        var missing = false;
        for (pf.prop) |p| if (!std.mem.eql(u8, p.ns, xml.dav_ns) or !available(r, p.name)) {
            if (!missing) try w.writeAll("<D:propstat><D:prop>");
            missing = true;
            try writeEmpty(w, p);
        };
        if (missing) try w.print("</D:prop><D:status>{s}</D:status></D:propstat>", .{statusLine(404)});
    }
    try w.writeAll("</D:response>");
}

/// PROPPATCH answer: every named property refused with `code`.
pub fn writePatchResponse(w: *Writer, prefix: []const u8, path: []const u8, collection: bool, props: []const PropName, code: u16) Writer.Error!void {
    try w.writeAll("<D:response><D:href>");
    try writeHref(w, prefix, path, collection);
    try w.writeAll("</D:href><D:propstat><D:prop>");
    for (props) |p| try writeEmpty(w, p);
    try w.print("</D:prop><D:status>{s}</D:status></D:propstat></D:response>", .{statusLine(code)});
}

pub fn baseName(path: []const u8) []const u8 {
    const p = std.mem.trimRight(u8, path, "/");
    const i = std.mem.lastIndexOfScalar(u8, p, '/') orelse return p;
    return p[i + 1 ..];
}

/// Content type from the file extension; the stored type wins when known.
pub fn guessType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    const map = [_][2][]const u8{
        .{ ".txt", "text/plain" },        .{ ".html", "text/html" },          .{ ".htm", "text/html" },
        .{ ".css", "text/css" },          .{ ".js", "text/javascript" },      .{ ".json", "application/json" },
        .{ ".xml", "application/xml" },   .{ ".pdf", "application/pdf" },     .{ ".zip", "application/zip" },
        .{ ".gz", "application/gzip" },   .{ ".tar", "application/x-tar" },   .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },        .{ ".jpeg", "image/jpeg" },         .{ ".gif", "image/gif" },
        .{ ".svg", "image/svg+xml" },     .{ ".webp", "image/webp" },         .{ ".mp4", "video/mp4" },
        .{ ".mp3", "audio/mpeg" },        .{ ".md", "text/markdown" },        .{ ".csv", "text/csv" },
    };
    for (map) |m| if (std.ascii.eqlIgnoreCase(ext, m[0])) return m[1];
    return "application/octet-stream";
}

test "depth and overwrite" {
    try std.testing.expectEqual(Depth.infinity, parseDepth(null, .infinity).?);
    try std.testing.expectEqual(Depth.zero, parseDepth("0", .infinity).?);
    try std.testing.expectEqual(Depth.one, parseDepth(" 1 ", .zero).?);
    try std.testing.expectEqual(Depth.infinity, parseDepth("Infinity", .zero).?);
    try std.testing.expect(parseDepth("2", .zero) == null);
    try std.testing.expect(parseOverwrite(null).?);
    try std.testing.expect(!parseOverwrite("F").?);
    try std.testing.expect(parseOverwrite("x") == null);
}

test "destination and paths" {
    try std.testing.expectEqualStrings("/dav/b/a%20b", uriPath("https://h:8443/dav/b/a%20b?x=1"));
    try std.testing.expectEqualStrings("/", uriPath("http://h"));
    try std.testing.expectEqualStrings("/b/c", uriPath("/b/c#frag"));
    try std.testing.expectEqualStrings("/b", stripPrefix("/dav", "/dav/b").?);
    try std.testing.expectEqualStrings("/", stripPrefix("/dav", "/dav").?);
    try std.testing.expect(stripPrefix("/dav", "/davx/b") == null);
    try std.testing.expectEqualStrings("/x", stripPrefix("", "/x").?);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/b/a b+ü", try percentDecode(&buf, "/b/a%20b+%C3%BC"));
    try std.testing.expectError(error.InvalidPath, percentDecode(&buf, "/b/%00"));
    try std.testing.expectError(error.InvalidPath, percentDecode(&buf, "/b/%4"));
    try std.testing.expectError(error.InvalidPath, percentDecode(&buf, "/b/%zz"));
    var ob: [128]u8 = undefined;
    var w: Writer = .fixed(&ob);
    try writeHref(&w, "/dav", "/b/a b&<ü>", true);
    try std.testing.expectEqualStrings("/dav/b/a%20b%26%3C%C3%BC%3E/", w.buffered());
}

test "if header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try parseIf(a, "<http://h/b/x> (<opaquelocktoken:1> [\"e1\"]) (Not <urn:x>)");
    try std.testing.expectEqual(@as(usize, 2), l.len);
    try std.testing.expectEqualStrings("http://h/b/x", l[0].tag.?);
    try std.testing.expect(l[0].conds[1].etag);
    try std.testing.expect(l[1].conds[0].not);
    const t = try ifTokens(a, l);
    try std.testing.expectEqual(@as(usize, 1), t.len);
    try std.testing.expectEqualStrings("opaquelocktoken:1", t[0]);
    try std.testing.expectError(error.BadIf, parseIf(a, "garbage"));
    try std.testing.expectError(error.BadIf, parseIf(a, "(<a>"));
    try std.testing.expectError(error.BadIf, parseIf(a, "()"));
    try std.testing.expectError(error.BadIf, parseIf(a, ""));
    try std.testing.expectEqualStrings("opaquelocktoken:z", parseLockToken(" <opaquelocktoken:z>").?);
    try std.testing.expect(parseLockToken("opaquelocktoken:z") == null);
}

test "propfind bodies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expect(try parsePropfind(a, "") == .allprop);
    try std.testing.expect(try parsePropfind(a, "<propfind xmlns=\"DAV:\"><propname/></propfind>") == .propname);
    const p = try parsePropfind(a, "<a:propfind xmlns:a=\"DAV:\"><a:prop><a:getetag/><z:q xmlns:z=\"urn:z\"/></a:prop></a:propfind>");
    try std.testing.expectEqual(@as(usize, 2), p.prop.len);
    try std.testing.expectEqualStrings("urn:z", p.prop[1].ns);
    try std.testing.expectError(error.BadBody, parsePropfind(a, "<propfind/>"));
    try std.testing.expectError(error.BadBody, parsePropfind(a, "<x"));
    const pp = try parseProppatch(a, "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:x>1</D:x></D:prop></D:set><D:remove><D:prop><D:y/></D:prop></D:remove></D:propertyupdate>");
    try std.testing.expectEqual(@as(usize, 2), pp.len);
}

test "lockinfo bodies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const li = try parseLockinfo(a,
        \\<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope>
        \\<D:locktype><D:write/></D:locktype><D:owner><D:href> me&amp;you </D:href></D:owner></D:lockinfo>
    );
    try std.testing.expectEqual(lock.Scope.shared, li.scope);
    try std.testing.expectEqualStrings("me&you", li.owner);
    try std.testing.expect(li.owner_href);
    try std.testing.expectError(error.BadBody, parseLockinfo(a, "<lockinfo xmlns='DAV:'><lockscope><exclusive/></lockscope></lockinfo>"));
}

test "multistatus rendering and escaping" {
    var buf: [4096]u8 = undefined;
    var w: Writer = .fixed(&buf);
    const props = [_]PropName{ .{ .ns = "DAV:", .name = "getcontentlength" }, .{ .ns = "urn:\"x\"", .name = "color" } };
    try writeResponse(&w, "", .{ .path = "/b/a&b", .collection = false, .size = 7 }, .{ .prop = &props });
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "<D:href>/b/a%26b</D:href>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<D:getcontentlength>7</D:getcontentlength>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "<X:color xmlns:X=\"urn:&quot;x&quot;\"/>") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "404 Not Found") != null);
    w = .fixed(&buf);
    try writeResponse(&w, "/p", .{ .path = "/b/d<ir", .collection = true }, .allprop);
    const o2 = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, o2, "<D:href>/p/b/d%3Cir/</D:href>") != null);
    try std.testing.expect(std.mem.indexOf(u8, o2, "<D:resourcetype><D:collection/></D:resourcetype>") != null);
    try std.testing.expect(std.mem.indexOf(u8, o2, "<D:displayname>d&lt;ir</D:displayname>") != null);
    try std.testing.expect(std.mem.indexOf(u8, o2, "getcontentlength") == null);
}
