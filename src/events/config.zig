//! Bucket notification configuration: the NotificationConfiguration XML document,
//! validation, canonical rendering, and rule matching.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const names = @import("names.zig");

const xml = s3.xml;
const xml_read = s3.xml_read;
const Allocator = std.mem.Allocator;

pub const Kind = enum {
    queue,
    topic,
    cloud_function,

    fn element(k: Kind) []const u8 {
        return switch (k) {
            .queue => "QueueConfiguration",
            .topic => "TopicConfiguration",
            .cloud_function => "CloudFunctionConfiguration",
        };
    }

    fn arnElement(k: Kind) []const u8 {
        return switch (k) {
            .queue => "Queue",
            .topic => "Topic",
            .cloud_function => "CloudFunction",
        };
    }
};

pub const Rule = struct {
    kind: Kind = .queue,
    id: []const u8 = "",
    arn: []const u8,
    /// Event strings as configured (wildcards kept for rendering).
    events: []const []const u8,
    mask: names.Mask,
    prefix: []const u8 = "",
    suffix: []const u8 = "",

    pub fn matches(r: Rule, n: names.Name, key: []const u8) bool {
        return names.has(r.mask, n) and std.mem.startsWith(u8, key, r.prefix) and std.mem.endsWith(u8, key, r.suffix);
    }
};

pub const Config = struct {
    rules: []const Rule = &.{},
};

pub const ParseError = error{ MalformedXML, InvalidArgument, OutOfMemory };

pub const max_rules = 100;
const max_events = 64;
const max_filter_len = 1024;

/// Parses a document; ARNs are checked separately against the configured targets.
pub fn parse(a: Allocator, doc: []const u8) ParseError!Config {
    const body = s3.versioning.elemText(doc, "NotificationConfiguration") orelse {
        // An empty element is a valid "remove everything".
        if (std.mem.indexOf(u8, doc, "<NotificationConfiguration") != null) return .{};
        return error.MalformedXML;
    };
    var rules: std.ArrayList(Rule) = .empty;
    inline for (.{ Kind.queue, Kind.topic, Kind.cloud_function }) |k| {
        var sc: xml_read.Scanner = .{ .s = body };
        while (try sc.next(k.element())) |raw| {
            if (rules.items.len == max_rules) return error.InvalidArgument;
            try rules.append(a, try parseRule(a, k, raw));
        }
    }
    for (rules.items, 0..) |*r, i| {
        if (r.id.len == 0) r.id = try std.fmt.allocPrint(a, "rule-{d}", .{i + 1});
        for (rules.items[0..i]) |o| {
            if (std.mem.eql(u8, o.id, r.id)) return error.InvalidArgument;
            if (overlaps(o, r.*)) return error.InvalidArgument;
        }
    }
    return .{ .rules = rules.items };
}

/// Same target, a shared event, and key filters that can both match one key.
fn overlaps(a: Rule, b: Rule) bool {
    if (!std.mem.eql(u8, a.arn, b.arn)) return false;
    var m = a.mask;
    m.setIntersection(b.mask);
    if (m.count() == 0) return false;
    const pre = std.mem.startsWith(u8, a.prefix, b.prefix) or std.mem.startsWith(u8, b.prefix, a.prefix);
    const suf = std.mem.endsWith(u8, a.suffix, b.suffix) or std.mem.endsWith(u8, b.suffix, a.suffix);
    return pre and suf;
}

fn unesc(a: Allocator, s: []const u8) ParseError![]const u8 {
    return xml_read.unescape(a, std.mem.trim(u8, s, " \t\r\n")) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedXML => error.MalformedXML,
    };
}

fn parseRule(a: Allocator, comptime k: Kind, raw: []const u8) ParseError!Rule {
    const arn_text = s3.versioning.elemText(raw, k.arnElement()) orelse return error.InvalidArgument;
    var r: Rule = .{ .kind = k, .arn = try unesc(a, arn_text), .events = &.{}, .mask = names.Mask.initEmpty() };
    if (s3.versioning.elemText(raw, "Id")) |id| r.id = try unesc(a, id);
    var evs: std.ArrayList([]const u8) = .empty;
    var sc: xml_read.Scanner = .{ .s = raw };
    while (try sc.next("Event")) |e| {
        if (evs.items.len == max_events) return error.InvalidArgument;
        const name = try unesc(a, e);
        const m = names.parse(name) orelse return error.InvalidArgument;
        r.mask.setUnion(m);
        try evs.append(a, name);
    }
    if (evs.items.len == 0) return error.InvalidArgument;
    r.events = evs.items;
    if (s3.versioning.elemText(raw, "Filter")) |f| {
        var fr: xml_read.Scanner = .{ .s = f };
        var seen_prefix = false;
        var seen_suffix = false;
        while (try fr.next("FilterRule")) |rule| {
            const n = try unesc(a, s3.versioning.elemText(rule, "Name") orelse return error.InvalidArgument);
            const v = try unesc(a, s3.versioning.elemText(rule, "Value") orelse "");
            if (v.len > max_filter_len) return error.InvalidArgument;
            if (std.ascii.eqlIgnoreCase(n, "prefix") and !seen_prefix) {
                seen_prefix = true;
                r.prefix = v;
            } else if (std.ascii.eqlIgnoreCase(n, "suffix") and !seen_suffix) {
                seen_suffix = true;
                r.suffix = v;
            } else return error.InvalidArgument;
        }
    }
    return r;
}

/// Canonical XML rendering of `cfg`.
pub fn render(a: Allocator, cfg: Config) error{OutOfMemory}![]const u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    renderTo(&out.writer, cfg) catch return error.OutOfMemory;
    return out.written();
}

fn renderTo(w: *std.Io.Writer, cfg: Config) std.Io.Writer.Error!void {
    try xml.openRoot(w, "NotificationConfiguration");
    inline for (.{ Kind.queue, Kind.topic, Kind.cloud_function }) |k| {
        for (cfg.rules) |r| if (r.kind == k) {
            try xml.open(w, k.element());
            try xml.elem(w, "Id", r.id);
            try xml.elem(w, k.arnElement(), r.arn);
            for (r.events) |e| try xml.elem(w, "Event", e);
            if (r.prefix.len > 0 or r.suffix.len > 0) {
                try w.writeAll("<Filter><S3Key>");
                if (r.prefix.len > 0) try filterRule(w, "prefix", r.prefix);
                if (r.suffix.len > 0) try filterRule(w, "suffix", r.suffix);
                try w.writeAll("</S3Key></Filter>");
            }
            try xml.close(w, k.element());
        };
    }
    try xml.close(w, "NotificationConfiguration");
}

fn filterRule(w: *std.Io.Writer, name: []const u8, value: []const u8) std.Io.Writer.Error!void {
    try w.writeAll("<FilterRule>");
    try xml.elem(w, "Name", name);
    try xml.elem(w, "Value", value);
    try w.writeAll("</FilterRule>");
}

/// Parts of `arn:<partition>:sqs:<region>:<id>:<type>`.
pub const Arn = struct { region: []const u8, id: []const u8, kind: []const u8 };

pub fn parseArn(s: []const u8) ?Arn {
    var it = std.mem.splitScalar(u8, s, ':');
    if (!std.mem.eql(u8, it.next() orelse return null, "arn")) return null;
    const part = it.next() orelse return null;
    if (!std.mem.eql(u8, part, "minio") and !std.mem.eql(u8, part, "aws") and !std.mem.eql(u8, part, "zkfsm")) return null;
    if (!std.mem.eql(u8, it.next() orelse return null, "sqs")) return null;
    const region = it.next() orelse return null;
    const id = it.next() orelse return null;
    const kind = it.next() orelse return null;
    if (it.next() != null or id.len == 0 or kind.len == 0) return null;
    return .{ .region = region, .id = id, .kind = kind };
}

const t = std.testing;

test "parse, render, match" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<QueueConfiguration><Id>1</Id><Queue>arn:minio:sqs::1:webhook</Queue>
        \\<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:Delete</Event>
        \\<Filter><S3Key><FilterRule><Name>prefix</Name><Value>img/</Value></FilterRule>
        \\<FilterRule><Name>suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter>
        \\</QueueConfiguration>
        \\<TopicConfiguration><Topic>arn:minio:sqs::k:kafka</Topic><Event>s3:ObjectAccessed:*</Event></TopicConfiguration>
        \\</NotificationConfiguration>
    ;
    const c = try parse(a, doc);
    try t.expectEqual(@as(usize, 2), c.rules.len);
    try t.expect(c.rules[0].matches(.object_created_put, "img/a.jpg"));
    try t.expect(!c.rules[0].matches(.object_created_put, "img/a.png"));
    try t.expect(!c.rules[0].matches(.object_created_put, "doc/a.jpg"));
    try t.expect(c.rules[0].matches(.object_removed_delete, "img/x.jpg"));
    try t.expect(!c.rules[0].matches(.object_removed_delete_marker_created, "img/x.jpg"));
    try t.expectEqualStrings("rule-2", c.rules[1].id);
    const again = try parse(a, try render(a, c));
    try t.expectEqual(@as(usize, 2), again.rules.len);
    try t.expectEqualStrings("img/", again.rules[0].prefix);
    try t.expectEqual(@as(usize, 0), (try parse(a, "<NotificationConfiguration/>")).rules.len);
    const arn = parseArn("arn:minio:sqs::1:webhook").?;
    try t.expectEqualStrings("webhook", arn.kind);
    try t.expect(parseArn("arn:minio:s3:::b") == null);
}

test "invalid documents" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try t.expectError(error.InvalidArgument, parse(a, "<NotificationConfiguration><QueueConfiguration><Queue>x</Queue><Event>s3:Nope</Event></QueueConfiguration></NotificationConfiguration>"));
    try t.expectError(error.InvalidArgument, parse(a, "<NotificationConfiguration><QueueConfiguration><Queue>x</Queue></QueueConfiguration></NotificationConfiguration>"));
    const dup = "<QueueConfiguration><Id>a</Id><Queue>x</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration>";
    try t.expectError(error.InvalidArgument, parse(a, "<NotificationConfiguration>" ++ dup ++ dup ++ "</NotificationConfiguration>"));
    const o1 = "<QueueConfiguration><Queue>x</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration>";
    const o2 = "<QueueConfiguration><Queue>x</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration>";
    try t.expectError(error.InvalidArgument, parse(a, "<NotificationConfiguration>" ++ o1 ++ o2 ++ "</NotificationConfiguration>"));
    try t.expectError(error.MalformedXML, parse(a, "junk"));
}
