//! Bucket replication configuration: the ReplicationConfiguration XML document,
//! validation, canonical rendering, and rule matching for one object.
const std = @import("std");
const s3 = @import("../s3/root.zig");

const xml = s3.xml;
const xml_read = s3.xml_read;
const Allocator = std.mem.Allocator;

pub const Tag = struct { key: []const u8, value: []const u8 };

pub const Rule = struct {
    id: []const u8,
    priority: i32 = 0,
    enabled: bool = true,
    prefix: []const u8 = "",
    /// All must be present on the object.
    tags: []const Tag = &.{},
    /// Destination bucket ARN (`arn:minio:replication:<region>:<id>:<bucket>`).
    dest: []const u8,
    storage_class: []const u8 = "",
    delete_marker: bool = false,
    /// MinIO extension: replicate permanent version deletes.
    delete: bool = false,
    existing: bool = false,
    replica_modifications: bool = false,
};

pub const Config = struct {
    role: []const u8 = "",
    rules: []const Rule = &.{},
};

pub const ParseError = error{ MalformedXML, InvalidRequest, OutOfMemory };

pub const max_rules = 1000;

/// Parses and validates a document; unnamed rules get a random ID.
pub fn parse(a: Allocator, doc: []const u8) ParseError!Config {
    const body = s3.versioning.elemText(doc, "ReplicationConfiguration") orelse return error.MalformedXML;
    var cfg: Config = .{};
    if (s3.versioning.elemText(body, "Role")) |r| cfg.role = try unesc(a, r);
    var rules: std.ArrayList(Rule) = .empty;
    var sc: xml_read.Scanner = .{ .s = body };
    while (try sc.next("Rule")) |raw| {
        if (rules.items.len == max_rules) return error.InvalidRequest;
        try rules.append(a, try parseRule(a, raw));
    }
    if (rules.items.len == 0) return error.MalformedXML;
    cfg.rules = rules.items;
    try validate(cfg);
    return cfg;
}

fn unesc(a: Allocator, s: []const u8) ParseError![]const u8 {
    return xml_read.unescape(a, s) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.MalformedXML => error.MalformedXML,
    };
}

fn statusOf(parent: []const u8, name: []const u8) ParseError!?bool {
    const sect = s3.versioning.elemText(parent, name) orelse return null;
    const st = s3.versioning.elemText(sect, "Status") orelse return error.MalformedXML;
    if (std.mem.eql(u8, st, "Enabled")) return true;
    if (std.mem.eql(u8, st, "Disabled")) return false;
    return error.MalformedXML;
}

fn parseTags(a: Allocator, scope: []const u8, out: *std.ArrayList(Tag)) ParseError!void {
    var sc: xml_read.Scanner = .{ .s = scope };
    while (try sc.next("Tag")) |t| {
        // Some clients send an empty <Tag></Tag> for "no tag".
        const k = s3.versioning.elemText(t, "Key") orelse continue;
        const v = s3.versioning.elemText(t, "Value") orelse "";
        try out.append(a, .{ .key = try unesc(a, k), .value = try unesc(a, v) });
    }
}

/// `raw` without the nested sections that carry their own Status.
fn directPart(a: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    const nested = [_][]const u8{ "DeleteMarkerReplication", "DeleteReplication", "ExistingObjectReplication", "SourceSelectionCriteria" };
    var cur: []const u8 = raw;
    for (nested) |n| {
        const open_tag = try std.fmt.allocPrint(a, "<{s}>", .{n});
        const close_tag = try std.fmt.allocPrint(a, "</{s}>", .{n});
        const i = std.mem.indexOf(u8, cur, open_tag) orelse continue;
        const j = std.mem.indexOfPos(u8, cur, i, close_tag) orelse continue;
        cur = try std.mem.concat(a, u8, &.{ cur[0..i], cur[j + close_tag.len ..] });
    }
    return cur;
}

fn parseRule(a: Allocator, raw: []const u8) ParseError!Rule {
    const status = s3.versioning.elemText(try directPart(a, raw), "Status") orelse return error.MalformedXML;
    const dest = s3.versioning.elemText(raw, "Destination") orelse return error.MalformedXML;
    var r: Rule = .{
        .id = if (s3.versioning.elemText(raw, "ID")) |id| try unesc(a, id) else "",
        .dest = try unesc(a, s3.versioning.elemText(dest, "Bucket") orelse return error.MalformedXML),
        .storage_class = if (s3.versioning.elemText(dest, "StorageClass")) |x| try unesc(a, x) else "",
    };
    r.enabled = if (std.mem.eql(u8, status, "Enabled")) true else if (std.mem.eql(u8, status, "Disabled")) false else return error.MalformedXML;
    if (s3.versioning.elemText(raw, "Priority")) |p| r.priority = std.fmt.parseInt(i32, p, 10) catch return error.MalformedXML;
    var tags: std.ArrayList(Tag) = .empty;
    if (s3.versioning.elemText(raw, "Filter")) |f| {
        const and_ = s3.versioning.elemText(f, "And") orelse "";
        if (and_.len > 0) {
            if (s3.versioning.elemText(and_, "Prefix")) |p| r.prefix = try unesc(a, p);
            try parseTags(a, and_, &tags);
        } else {
            if (s3.versioning.elemText(f, "Prefix")) |p| r.prefix = try unesc(a, p);
            try parseTags(a, f, &tags);
            if (tags.items.len > 1) return error.MalformedXML;
        }
    } else if (s3.versioning.elemText(raw, "Prefix")) |p| r.prefix = try unesc(a, p);
    r.tags = tags.items;
    r.delete_marker = try statusOf(raw, "DeleteMarkerReplication") orelse false;
    r.delete = try statusOf(raw, "DeleteReplication") orelse false;
    r.existing = try statusOf(raw, "ExistingObjectReplication") orelse false;
    if (s3.versioning.elemText(raw, "SourceSelectionCriteria")) |ssc|
        r.replica_modifications = try statusOf(ssc, "ReplicaModifications") orelse false;
    if (r.id.len == 0) {
        var b: [16]u8 = undefined;
        std.crypto.random.bytes(&b);
        r.id = try a.dupe(u8, &std.fmt.bytesToHex(b, .lower));
    }
    return r;
}

/// Rule-level checks shared by parse and the engine.
pub fn validate(cfg: Config) ParseError!void {
    for (cfg.rules, 0..) |r, i| {
        if (r.id.len > 255) return error.InvalidRequest;
        if (parseArn(r.dest) == null) return error.InvalidRequest;
        // Delete markers carry no tags, so tag-filtered rules cannot replicate them.
        if (r.delete_marker and r.tags.len > 0) return error.InvalidRequest;
        for (cfg.rules[0..i]) |p| {
            if (std.mem.eql(u8, p.id, r.id)) return error.InvalidRequest;
            if (cfg.rules.len > 1 and p.priority == r.priority and std.mem.eql(u8, p.dest, r.dest)) return error.InvalidRequest;
        }
    }
}

pub const Arn = struct { region: []const u8, id: []const u8, bucket: []const u8 };

/// `arn:minio:replication:<region>:<id>:<bucket>`, or `arn:aws:s3:::<bucket>`.
pub fn parseArn(s: []const u8) ?Arn {
    if (std.mem.startsWith(u8, s, "arn:aws:s3:::")) {
        const b = s["arn:aws:s3:::".len..];
        return if (b.len == 0) null else .{ .region = "", .id = "", .bucket = b };
    }
    const p = "arn:minio:replication:";
    if (!std.mem.startsWith(u8, s, p)) return null;
    var it = std.mem.splitScalar(u8, s[p.len..], ':');
    const region = it.next() orelse return null;
    const id = it.next() orelse return null;
    const bucket = it.next() orelse return null;
    if (it.next() != null or id.len == 0 or bucket.len == 0) return null;
    return .{ .region = region, .id = id, .bucket = bucket };
}

pub fn render(w: *std.Io.Writer, cfg: Config) std.Io.Writer.Error!void {
    try xml.openRoot(w, "ReplicationConfiguration");
    if (cfg.role.len > 0) try xml.elem(w, "Role", cfg.role);
    for (cfg.rules) |r| {
        try w.writeAll("<Rule>");
        try xml.elem(w, "ID", r.id);
        try xml.elemInt(w, "Priority", r.priority);
        try xml.elem(w, "Status", if (r.enabled) "Enabled" else "Disabled");
        try w.writeAll("<Filter>");
        const and_ = r.tags.len > 1 or (r.tags.len == 1 and r.prefix.len > 0);
        if (and_) try w.writeAll("<And>");
        if (r.prefix.len > 0 or r.tags.len == 0) try xml.elem(w, "Prefix", r.prefix);
        for (r.tags) |t| {
            try w.writeAll("<Tag>");
            try xml.elem(w, "Key", t.key);
            try xml.elem(w, "Value", t.value);
            try w.writeAll("</Tag>");
        }
        if (and_) try w.writeAll("</And>");
        try w.writeAll("</Filter>");
        try w.writeAll("<Destination>");
        try xml.elem(w, "Bucket", r.dest);
        if (r.storage_class.len > 0) try xml.elem(w, "StorageClass", r.storage_class);
        try w.writeAll("</Destination>");
        try statusElem(w, "DeleteMarkerReplication", r.delete_marker);
        try statusElem(w, "DeleteReplication", r.delete);
        try statusElem(w, "ExistingObjectReplication", r.existing);
        try w.writeAll("<SourceSelectionCriteria>");
        try statusElem(w, "ReplicaModifications", r.replica_modifications);
        try w.writeAll("</SourceSelectionCriteria>");
        try w.writeAll("</Rule>");
    }
    try xml.close(w, "ReplicationConfiguration");
}

fn statusElem(w: *std.Io.Writer, name: []const u8, on: bool) std.Io.Writer.Error!void {
    try w.print("<{s}><Status>{s}</Status></{s}>", .{ name, if (on) "Enabled" else "Disabled", name });
}

pub const Op = enum { put, delete_marker, delete_version, metadata, existing };

/// Whether `r` covers an object with `key` and `tags` for operation `op`.
pub fn ruleApplies(r: Rule, key: []const u8, tags: []const Tag, op: Op, replica: bool) bool {
    if (!r.enabled or !std.mem.startsWith(u8, key, r.prefix)) return false;
    switch (op) {
        .delete_marker => return r.delete_marker,
        .delete_version => return r.delete,
        .existing => if (!r.existing) return false,
        .metadata => if (replica and !r.replica_modifications) return false,
        .put => {},
    }
    for (r.tags) |want| {
        const hit = for (tags) |t| {
            if (std.mem.eql(u8, t.key, want.key) and std.mem.eql(u8, t.value, want.value)) break true;
        } else false;
        if (!hit) return false;
    }
    return true;
}

/// Destinations for an object: per destination ARN, the highest-priority matching rule.
pub fn match(a: Allocator, cfg: Config, key: []const u8, tags: []const Tag, op: Op, replica: bool) Allocator.Error![]const Rule {
    var out: std.ArrayList(Rule) = .empty;
    for (cfg.rules) |r| {
        if (!ruleApplies(r, key, tags, op, replica)) continue;
        const dup = for (out.items) |*o| {
            if (std.mem.eql(u8, o.dest, r.dest)) {
                if (r.priority > o.priority) o.* = r;
                break true;
            }
        } else false;
        if (!dup) try out.append(a, r);
    }
    return out.items;
}

test "parse, render, and match" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Role></Role>
        \\<Rule><ID>r1</ID><Status>Enabled</Status><Priority>1</Priority>
        \\<DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>
        \\<DeleteReplication><Status>Disabled</Status></DeleteReplication>
        \\<Destination><Bucket>arn:minio:replication::abc:dst</Bucket><StorageClass>STANDARD</StorageClass></Destination>
        \\<Filter><Prefix>logs/</Prefix><And></And><Tag></Tag></Filter></Rule>
        \\<Rule><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication><Status>Enabled</Status><Priority>2</Priority><Destination><Bucket>arn:minio:replication::abc:dst</Bucket></Destination>
        \\<Filter><And><Prefix>logs/a</Prefix><Tag><Key>k</Key><Value>v</Value></Tag><Tag><Key>x</Key><Value>&amp;</Value></Tag></And></Filter>
        \\<SourceSelectionCriteria><ReplicaModifications><Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria></Rule>
        \\</ReplicationConfiguration>
    ;
    const cfg = try parse(a, doc);
    try std.testing.expectEqual(@as(usize, 2), cfg.rules.len);
    try std.testing.expect(cfg.rules[0].delete_marker and !cfg.rules[0].delete);
    try std.testing.expectEqualStrings("logs/", cfg.rules[0].prefix);
    try std.testing.expectEqualStrings("&", cfg.rules[1].tags[1].value);
    try std.testing.expect(cfg.rules[1].replica_modifications);
    try std.testing.expectEqual(@as(usize, 32), cfg.rules[1].id.len);

    const m = try match(a, cfg, "logs/a1", &.{ .{ .key = "k", .value = "v" }, .{ .key = "x", .value = "&" } }, .put, false);
    try std.testing.expectEqual(@as(usize, 1), m.len);
    try std.testing.expectEqual(@as(i32, 2), m[0].priority);
    try std.testing.expectEqual(@as(usize, 1), (try match(a, cfg, "logs/b", &.{}, .put, false)).len);
    try std.testing.expectEqual(@as(usize, 0), (try match(a, cfg, "other", &.{}, .put, false)).len);
    try std.testing.expectEqual(@as(usize, 1), (try match(a, cfg, "logs/z", &.{}, .delete_marker, false)).len);
    try std.testing.expectEqual(@as(usize, 0), (try match(a, cfg, "logs/z", &.{}, .delete_version, false)).len);

    var out: std.Io.Writer.Allocating = .init(a);
    try render(&out.writer, cfg);
    const again = try parse(a, out.written());
    try std.testing.expectEqual(@as(usize, 2), again.rules.len);
    try std.testing.expectEqualStrings(cfg.rules[1].id, again.rules[1].id);
    try std.testing.expectEqual(@as(usize, 2), again.rules[1].tags.len);
}

test "validation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bad_arn = "<ReplicationConfiguration><Rule><Status>Enabled</Status><Destination><Bucket>dst</Bucket></Destination></Rule></ReplicationConfiguration>";
    try std.testing.expectError(error.InvalidRequest, parse(a, bad_arn));
    const dm_tags = "<ReplicationConfiguration><Rule><Status>Enabled</Status><DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication><Filter><Tag><Key>a</Key><Value>b</Value></Tag></Filter><Destination><Bucket>arn:minio:replication::x:d</Bucket></Destination></Rule></ReplicationConfiguration>";
    try std.testing.expectError(error.InvalidRequest, parse(a, dm_tags));
    try std.testing.expectError(error.MalformedXML, parse(a, "<ReplicationConfiguration></ReplicationConfiguration>"));
    try std.testing.expect(parseArn("arn:minio:replication:us-east-1:id1:b").?.bucket.len == 1);
    try std.testing.expect(parseArn("arn:minio:replication::id1") == null);
}
