//! Get/Put/DeleteBucketLifecycleConfiguration: expiration, abort, and transition
//! actions (StorageClass names a configured remote tier).
const std = @import("std");
const core = @import("../core/root.zig");
const object = @import("../object/root.zig");
const handler = @import("handler.zig");
const xml = @import("xml.zig");
const xml_read = @import("xml_read.zig");
const s3v = @import("versioning.zig");

const Ctx = handler.Ctx;
const DispatchError = handler.DispatchError;
const Rule = object.lifecycle.Rule;
const Tag = object.Tag;
const max_body = 1024 * 1024;

/// Handles `?lifecycle` on a bucket; false means "not mine".
pub fn route(c: *Ctx) DispatchError!bool {
    if (c.route.key.len != 0 or (try handler.param(c, "lifecycle")) == null) return false;
    switch (c.method) {
        .GET => {
            const rules = try object.lifecycle.get(c.svc, c.arena, c.route.bucket) orelse {
                try handler.fail(c, .NoSuchLifecycleConfiguration);
                return true;
            };
            var a: std.Io.Writer.Allocating = .init(c.arena);
            try write(&a.writer, rules);
            try handler.respondXml(c, .ok, a.written());
        },
        .PUT => {
            const body = try s3v.readBodyMax(c, max_body) orelse return true;
            const rules = parse(c.arena, body) catch |e| {
                try handler.fail(c, switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.MalformedXML => .MalformedXML,
                    error.InvalidArgument => .InvalidArgument,
                    error.NotImplemented => .NotImplemented,
                });
                return true;
            };
            try object.lifecycle.set(c.svc, c.route.bucket, rules);
            try handler.respondEmpty(c, .ok, &.{});
        },
        .DELETE => {
            try object.lifecycle.set(c.svc, c.route.bucket, null);
            try handler.respondEmpty(c, .no_content, &.{});
        },
        else => try handler.fail(c, .MethodNotAllowed),
    }
    return true;
}

pub const ParseError = error{ OutOfMemory, MalformedXML, InvalidArgument, NotImplemented };

/// Parses a LifecycleConfiguration document; strings live in `arena`.
pub fn parse(arena: std.mem.Allocator, doc: []const u8) ParseError![]Rule {
    var top: xml_read.Scanner = .{ .s = doc };
    const root = try top.next("LifecycleConfiguration") orelse return error.MalformedXML;
    var rules: std.ArrayList(Rule) = .empty;
    var sc: xml_read.Scanner = .{ .s = root };
    while (try sc.next("Rule")) |body| {
        if (rules.items.len >= object.lifecycle.max_rules) return error.InvalidArgument;
        try rules.append(arena, try parseRule(arena, body));
    }
    if (rules.items.len == 0) return error.MalformedXML;
    return rules.items;
}

fn child(s: []const u8, name: []const u8) ParseError!?[]const u8 {
    var sc: xml_read.Scanner = .{ .s = s };
    return sc.next(name);
}

fn text(arena: std.mem.Allocator, s: []const u8, name: []const u8) ParseError!?[]const u8 {
    const raw = try child(s, name) orelse return null;
    return try xml_read.unescape(arena, std.mem.trim(u8, raw, " \t\r\n"));
}

fn int(comptime T: type, s: []const u8, name: []const u8) ParseError!?T {
    const raw = try child(s, name) orelse return null;
    return std.fmt.parseInt(T, std.mem.trim(u8, raw, " \t\r\n"), 10) catch error.InvalidArgument;
}

fn parseRule(arena: std.mem.Allocator, body: []const u8) ParseError!Rule {
    var r: Rule = .{};
    r.id = try text(arena, body, "ID") orelse "";
    const status = try text(arena, body, "Status") orelse return error.MalformedXML;
    r.enabled = if (std.mem.eql(u8, status, "Enabled")) true else if (std.mem.eql(u8, status, "Disabled")) false else return error.MalformedXML;
    if (try child(body, "Filter")) |f| {
        r.filter = try parseFilter(arena, f);
    } else if (try text(arena, body, "Prefix")) |p| {
        r.filter.prefix = p; // legacy rule-level prefix
    }
    if (try child(body, "Expiration")) |e| {
        r.expiration_days = try int(u32, e, "Days");
        if (try text(arena, e, "Date")) |d| r.expiration_date_ns = core.time.parseIso8601(d) catch return error.InvalidArgument;
        if (try text(arena, e, "ExpiredObjectDeleteMarker")) |m| r.expired_object_delete_marker = try boolean(m);
    }
    if (try child(body, "NoncurrentVersionExpiration")) |e| {
        r.noncurrent_days = try int(u32, e, "NoncurrentDays") orelse return error.MalformedXML;
        r.newer_noncurrent_versions = try int(u32, e, "NewerNoncurrentVersions");
    }
    if (try child(body, "AbortIncompleteMultipartUpload")) |e| {
        r.abort_upload_days = try int(u32, e, "DaysAfterInitiation") orelse return error.MalformedXML;
    }
    if (try single(body, "Transition")) |e| {
        r.transition_days = try int(u32, e, "Days");
        if (try text(arena, e, "Date")) |d| r.transition_date_ns = core.time.parseIso8601(d) catch return error.InvalidArgument;
        r.transition_tier = try storageClass(arena, e);
    }
    if (try single(body, "NoncurrentVersionTransition")) |e| {
        r.noncurrent_transition_days = try int(u32, e, "NoncurrentDays") orelse return error.MalformedXML;
        r.noncurrent_transition_newer = try int(u32, e, "NewerNoncurrentVersions");
        r.noncurrent_transition_tier = try storageClass(arena, e);
    }
    object.lifecycle.validate(&.{r}) catch return error.InvalidArgument;
    return r;
}

/// One transition per kind and rule; more than one is not supported.
fn single(body: []const u8, name: []const u8) ParseError!?[]const u8 {
    var sc: xml_read.Scanner = .{ .s = body };
    const first = try sc.next(name) orelse return null;
    if (try sc.next(name) != null) return error.NotImplemented;
    return first;
}

fn storageClass(arena: std.mem.Allocator, e: []const u8) ParseError![]const u8 {
    const sc = try text(arena, e, "StorageClass") orelse return error.MalformedXML;
    if (sc.len == 0 or sc.len > 64) return error.InvalidArgument;
    return sc;
}

fn boolean(s: []const u8) ParseError!bool {
    if (std.mem.eql(u8, s, "true")) return true;
    if (std.mem.eql(u8, s, "false")) return false;
    return error.MalformedXML;
}

/// `<Filter>` holds at most one of Prefix, Tag, size bounds, or an `<And>` combining them.
fn parseFilter(arena: std.mem.Allocator, f: []const u8) ParseError!object.lifecycle.Filter {
    const scope = try child(f, "And") orelse f;
    var out: object.lifecycle.Filter = .{};
    var singles: usize = 0;
    if (try text(arena, scope, "Prefix")) |p| {
        out.prefix = p;
        singles += 1;
    }
    out.size_gt = try int(u64, scope, "ObjectSizeGreaterThan");
    out.size_lt = try int(u64, scope, "ObjectSizeLessThan");
    singles += @intFromBool(out.size_gt != null) + @intFromBool(out.size_lt != null);
    var tags: std.ArrayList(Tag) = .empty;
    var sc: xml_read.Scanner = .{ .s = scope };
    while (try sc.next("Tag")) |t| {
        const k = try text(arena, t, "Key") orelse return error.MalformedXML;
        try tags.append(arena, .{ .key = k, .value = try text(arena, t, "Value") orelse "" });
    }
    singles += tags.items.len;
    if (scope.ptr == f.ptr and singles > 1) return error.MalformedXML;
    _ = object.versioning.encodeObjectTags(arena, tags.items) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidArgument,
    };
    out.tags = tags.items;
    return out;
}

pub fn write(w: *std.Io.Writer, rules: []const Rule) std.Io.Writer.Error!void {
    try xml.openRoot(w, "LifecycleConfiguration");
    for (rules) |r| {
        try w.writeAll("<Rule>");
        if (r.id.len > 0) try xml.elem(w, "ID", r.id);
        try writeFilter(w, r.filter);
        try xml.elem(w, "Status", if (r.enabled) "Enabled" else "Disabled");
        if (r.expiration_days != null or r.expiration_date_ns != null or r.expired_object_delete_marker) {
            try w.writeAll("<Expiration>");
            if (r.expiration_days) |d| try xml.elemInt(w, "Days", d);
            if (r.expiration_date_ns) |d| {
                var tb: [24]u8 = undefined;
                try xml.elem(w, "Date", core.time.iso8601(d, &tb));
            }
            if (r.expired_object_delete_marker) try xml.elem(w, "ExpiredObjectDeleteMarker", "true");
            try w.writeAll("</Expiration>");
        }
        if (r.noncurrent_days) |d| {
            try w.writeAll("<NoncurrentVersionExpiration>");
            try xml.elemInt(w, "NoncurrentDays", d);
            if (r.newer_noncurrent_versions) |n| try xml.elemInt(w, "NewerNoncurrentVersions", n);
            try w.writeAll("</NoncurrentVersionExpiration>");
        }
        if (r.abort_upload_days) |d| {
            try w.writeAll("<AbortIncompleteMultipartUpload>");
            try xml.elemInt(w, "DaysAfterInitiation", d);
            try w.writeAll("</AbortIncompleteMultipartUpload>");
        }
        if (r.transition_tier.len > 0) {
            try w.writeAll("<Transition>");
            if (r.transition_days) |d| try xml.elemInt(w, "Days", d);
            if (r.transition_date_ns) |d| {
                var tb: [24]u8 = undefined;
                try xml.elem(w, "Date", core.time.iso8601(d, &tb));
            }
            try xml.elem(w, "StorageClass", r.transition_tier);
            try w.writeAll("</Transition>");
        }
        if (r.noncurrent_transition_days) |d| {
            try w.writeAll("<NoncurrentVersionTransition>");
            try xml.elemInt(w, "NoncurrentDays", d);
            if (r.noncurrent_transition_newer) |n| try xml.elemInt(w, "NewerNoncurrentVersions", n);
            try xml.elem(w, "StorageClass", r.noncurrent_transition_tier);
            try w.writeAll("</NoncurrentVersionTransition>");
        }
        try w.writeAll("</Rule>");
    }
    try xml.close(w, "LifecycleConfiguration");
}

fn writeFilter(w: *std.Io.Writer, f: object.lifecycle.Filter) std.Io.Writer.Error!void {
    const n = @intFromBool(f.prefix.len > 0) + f.tags.len + @intFromBool(f.size_gt != null) + @intFromBool(f.size_lt != null);
    try w.writeAll("<Filter>");
    if (n > 1) try w.writeAll("<And>");
    if (f.prefix.len > 0 or n == 0) try xml.elem(w, "Prefix", f.prefix);
    for (f.tags) |t| {
        try w.writeAll("<Tag>");
        try xml.elem(w, "Key", t.key);
        try xml.elem(w, "Value", t.value);
        try w.writeAll("</Tag>");
    }
    if (f.size_gt) |v| try xml.elemInt(w, "ObjectSizeGreaterThan", v);
    if (f.size_lt) |v| try xml.elemInt(w, "ObjectSizeLessThan", v);
    if (n > 1) try w.writeAll("</And>");
    try w.writeAll("</Filter>");
}

test "lifecycle xml parse and write" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<Rule><ID>logs</ID><Filter><And><Prefix>logs/</Prefix><Tag><Key>a&amp;b</Key><Value>1</Value></Tag>
        \\<ObjectSizeGreaterThan>10</ObjectSizeGreaterThan></And></Filter><Status>Enabled</Status>
        \\<Expiration><Days>30</Days></Expiration>
        \\<NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>
        \\<AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>
        \\<Rule><Prefix>old/</Prefix><Status>Disabled</Status><Expiration><Date>2030-01-01T00:00:00.000Z</Date></Expiration></Rule>
        \\<Rule><Filter><ObjectSizeLessThan>5</ObjectSizeLessThan></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>
        \\<Rule><ID>dm</ID><Filter/><Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>
        \\</LifecycleConfiguration>
    ;
    // A tag filter with AbortIncompleteMultipartUpload is invalid; drop that action for this case.
    try std.testing.expectError(error.InvalidArgument, parse(a, doc));
    const ok = try std.mem.replaceOwned(u8, a, doc, "<AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload>", "");
    const rules = try parse(a, ok);
    try std.testing.expectEqual(@as(usize, 4), rules.len);
    try std.testing.expectEqualStrings("logs/", rules[0].filter.prefix);
    try std.testing.expectEqualStrings("a&b", rules[0].filter.tags[0].key);
    try std.testing.expectEqual(@as(?u64, 10), rules[0].filter.size_gt);
    try std.testing.expectEqual(@as(?u32, 2), rules[0].newer_noncurrent_versions);
    try std.testing.expectEqualStrings("old/", rules[1].filter.prefix);
    try std.testing.expect(!rules[1].enabled and rules[1].expiration_date_ns != null);
    try std.testing.expectEqual(@as(?u64, 5), rules[2].filter.size_lt);
    try std.testing.expect(rules[3].expired_object_delete_marker);

    var out: std.Io.Writer.Allocating = .init(a);
    try write(&out.writer, rules);
    const again = try parse(a, out.written());
    try std.testing.expectEqual(@as(usize, 4), again.len);
    try std.testing.expectEqualStrings("a&b", again[0].filter.tags[0].key);
    try std.testing.expectEqual(rules[1].expiration_date_ns, again[1].expiration_date_ns);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "<Filter><And><Prefix>logs/</Prefix>") != null);

    const tr = "<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Days>0</Days><StorageClass>WARM</StorageClass></Transition>" ++
        "<NoncurrentVersionTransition><NoncurrentDays>2</NoncurrentDays><StorageClass>COLD</StorageClass></NoncurrentVersionTransition></Rule></LifecycleConfiguration>";
    const tr_rules = try parse(a, tr);
    try std.testing.expectEqualStrings("WARM", tr_rules[0].transition_tier);
    try std.testing.expectEqual(@as(?u32, 0), tr_rules[0].transition_days);
    try std.testing.expectEqual(@as(?u32, 2), tr_rules[0].noncurrent_transition_days);
    var tw: std.Io.Writer.Allocating = .init(a);
    try write(&tw.writer, tr_rules);
    try std.testing.expectEqualStrings("COLD", (try parse(a, tw.written()))[0].noncurrent_transition_tier);
    const two = "<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Days>1</Days><StorageClass>A</StorageClass></Transition>" ++
        "<Transition><Days>2</Days><StorageClass>B</StorageClass></Transition></Rule></LifecycleConfiguration>";
    try std.testing.expectError(error.NotImplemented, parse(a, two));
    try std.testing.expectError(error.MalformedXML, parse(a, "<LifecycleConfiguration><Rule><Status>Enabled</Status><Transition><Days>1</Days></Transition></Rule></LifecycleConfiguration>"));
    try std.testing.expectError(error.MalformedXML, parse(a, "<LifecycleConfiguration></LifecycleConfiguration>"));
    try std.testing.expectError(error.MalformedXML, parse(a, "<LifecycleConfiguration><Rule><Status>On</Status></Rule></LifecycleConfiguration>"));
    try std.testing.expectError(error.InvalidArgument, parse(a, "<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>"));
    try std.testing.expectError(error.InvalidArgument, parse(a, "<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Date>2030-01-01T05:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>"));
    try std.testing.expectError(error.MalformedXML, parse(a, "<LifecycleConfiguration><Rule><Filter><Prefix>a</Prefix><ObjectSizeLessThan>5</ObjectSizeLessThan></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"));
}
