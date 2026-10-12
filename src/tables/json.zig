//! Bounded JSON helpers over std.json.Value: depth-checked parsing (stringify
//! recurses), typed getters that never trust shapes, and value builders.
const std = @import("std");

pub const Value = std.json.Value;
pub const ObjectMap = std.json.ObjectMap;
pub const Array = std.json.Array;

/// Deepest nesting accepted; Iceberg metadata needs well under this.
pub const max_depth = 64;

pub const ParseError = error{ OutOfMemory, InvalidJson, TooDeep };

/// Parses with numbers kept as text so re-serialization is lossless.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8) ParseError!Value {
    if (!depthOk(bytes)) return error.TooDeep;
    return std.json.parseFromSliceLeaky(Value, arena, bytes, .{
        .parse_numbers = false,
        .duplicate_field_behavior = .use_last,
    }) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidJson,
    };
}

/// Parses and requires a top-level object.
pub fn parseObject(arena: std.mem.Allocator, bytes: []const u8) ParseError!ObjectMap {
    const v = try parse(arena, bytes);
    return switch (v) {
        .object => |o| o,
        else => error.InvalidJson,
    };
}

/// Nesting of brackets outside strings stays within `max_depth`.
pub fn depthOk(bytes: []const u8) bool {
    var depth: usize = 0;
    var in_str = false;
    var esc = false;
    for (bytes) |c| {
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        switch (c) {
            '"' => in_str = true,
            '[', '{' => {
                depth += 1;
                if (depth > max_depth) return false;
            },
            ']', '}' => depth -|= 1,
            else => {},
        }
    }
    return true;
}

pub fn get(o: ObjectMap, key: []const u8) ?Value {
    const v = o.get(key) orelse return null;
    return if (v == .null) null else v;
}

pub fn str(o: ObjectMap, key: []const u8) ?[]const u8 {
    return switch (get(o, key) orelse return null) {
        .string => |x| x,
        else => null,
    };
}

pub fn asInt(v: Value) ?i64 {
    return switch (v) {
        .integer => |x| x,
        .number_string => |x| std.fmt.parseInt(i64, x, 10) catch null,
        .float => |f| if (@floor(f) == f and @abs(f) < 9.0e15) @intFromFloat(f) else null,
        else => null,
    };
}

pub fn int(o: ObjectMap, key: []const u8) ?i64 {
    return asInt(get(o, key) orelse return null);
}

pub fn boolean(o: ObjectMap, key: []const u8) ?bool {
    return switch (get(o, key) orelse return null) {
        .bool => |b| b,
        else => null,
    };
}

pub fn obj(o: ObjectMap, key: []const u8) ?ObjectMap {
    return switch (get(o, key) orelse return null) {
        .object => |m| m,
        else => null,
    };
}

pub fn arr(o: ObjectMap, key: []const u8) ?[]Value {
    return switch (get(o, key) orelse return null) {
        .array => |a| a.items,
        else => null,
    };
}

/// Mutable view of an array member; null when absent or not an array.
pub fn arrPtr(o: *ObjectMap, key: []const u8) ?*Array {
    const p = o.getPtr(key) orelse return null;
    return switch (p.*) {
        .array => |*a| a,
        else => null,
    };
}

pub fn objPtr(o: *ObjectMap, key: []const u8) ?*ObjectMap {
    const p = o.getPtr(key) orelse return null;
    return switch (p.*) {
        .object => |*m| m,
        else => null,
    };
}

/// Array of strings; null when any element is not a string.
pub fn strings(arena: std.mem.Allocator, v: Value) error{OutOfMemory}!?[]const []const u8 {
    const items = switch (v) {
        .array => |a| a.items,
        else => return null,
    };
    const out = try arena.alloc([]const u8, items.len);
    for (items, out) |it, *o| o.* = switch (it) {
        .string => |x| x,
        else => return null,
    };
    return out;
}

pub fn s(v: []const u8) Value {
    return .{ .string = v };
}

pub fn i(v: i64) Value {
    return .{ .integer = v };
}

pub fn newObject(arena: std.mem.Allocator) ObjectMap {
    return ObjectMap.init(arena);
}

pub fn newArray(arena: std.mem.Allocator) Array {
    return Array.init(arena);
}

pub fn stringArray(arena: std.mem.Allocator, items: []const []const u8) error{OutOfMemory}!Value {
    var a = newArray(arena);
    for (items) |x| try a.append(s(x));
    return .{ .array = a };
}

pub fn stringify(arena: std.mem.Allocator, v: Value) error{OutOfMemory}![]const u8 {
    return std.json.Stringify.valueAlloc(arena, v, .{});
}

test "depth guard rejects deep nesting, ignores brackets in strings" {
    var buf: [200]u8 = undefined;
    @memset(buf[0..100], '[');
    @memset(buf[100..200], ']');
    try std.testing.expect(!depthOk(&buf));
    try std.testing.expect(depthOk("{\"a\":\"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\"}"));
    try std.testing.expect(depthOk("{\"a\":\"\\\"[\"}"));
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    try std.testing.expectError(error.TooDeep, parse(a.allocator(), &buf));
}

test "hostile JSON inputs fail with typed errors" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const bad = [_][]const u8{ "", "{", "}", "[1,]", "{\"a\":}", "nul", "\"\\u12\"", "{\"a\" 1}", "1e99999x", "\x00", "{\"a\":1}}" };
    for (bad) |b| try std.testing.expectError(error.InvalidJson, parse(a.allocator(), b));
    try std.testing.expectError(error.InvalidJson, parseObject(a.allocator(), "[1,2]"));
    const o = try parseObject(a.allocator(), "{\"n\":99999999999999999999999,\"x\":1.5,\"k\":\"v\",\"z\":null}");
    try std.testing.expect(int(o, "n") == null);
    try std.testing.expect(int(o, "x") == null);
    try std.testing.expect(int(o, "k") == null);
    try std.testing.expect(str(o, "z") == null);
    try std.testing.expectEqualStrings("v", str(o, "k").?);
}

test "numbers round-trip losslessly" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const src = "{\"a\":1.0,\"b\":9223372036854775807,\"c\":[1e3]}";
    const v = try parse(a.allocator(), src);
    try std.testing.expectEqualStrings(src, try stringify(a.allocator(), v));
}
