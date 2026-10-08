//! Builds std.json.Value trees from Zig literals: structs become objects (null
//! fields dropped), tuples and slices become arrays, Values pass through.
const std = @import("std");
const Value = std.json.Value;

pub fn v(a: std.mem.Allocator, x: anytype) error{OutOfMemory}!Value {
    const T = @TypeOf(x);
    if (T == Value) return x;
    switch (@typeInfo(T)) {
        .bool => return .{ .bool = x },
        .int, .comptime_int => return .{ .integer = @intCast(x) },
        .float, .comptime_float => return .{ .float = @floatCast(x) },
        .null => return .null,
        .optional => return if (x) |y| v(a, y) else .null,
        .@"enum", .enum_literal => return .{ .string = @tagName(x) },
        .pointer => |p| {
            if (p.size == .one) {
                const C = @typeInfo(p.child);
                if (C == .array and C.array.child == u8) return .{ .string = x };
                return v(a, x.*);
            }
            if (p.child == u8) return .{ .string = x };
            var arr = Value{ .array = .init(a) };
            for (x) |e| try arr.array.append(try v(a, e));
            return arr;
        },
        .array => |ar| {
            if (ar.child == u8) return .{ .string = &x };
            var arr = Value{ .array = .init(a) };
            for (x) |e| try arr.array.append(try v(a, e));
            return arr;
        },
        .@"struct" => |s| {
            // `.{}` is an empty object (emptyDir: {}), not an empty array.
            if (s.is_tuple and s.fields.len > 0) {
                var arr = Value{ .array = .init(a) };
                inline for (x) |e| {
                    const ev = try v(a, e);
                    if (ev != .null) try arr.array.append(ev);
                }
                return arr;
            }
            var obj = Value{ .object = .init(a) };
            inline for (s.fields) |f| {
                const fv = try v(a, @field(x, f.name));
                if (fv != .null) try obj.object.put(f.name, fv);
            }
            return obj;
        },
        else => @compileError("jv: unsupported type " ++ @typeName(T)),
    }
}

pub fn stringify(a: std.mem.Allocator, x: Value) ![]u8 {
    return std.json.Stringify.valueAlloc(a, x, .{});
}

/// Array value from a runtime list of Values.
pub fn list(a: std.mem.Allocator, items: []const Value) !Value {
    var arr = Value{ .array = .init(a) };
    try arr.array.appendSlice(items);
    return arr;
}

test "jv" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const name: []const u8 = "x";
    const none: ?u32 = null;
    const val = try v(a, .{ .@"app.kubernetes.io/name" = name, .n = 3, .skip = none, .l = .{ "a", .{ .b = true } }, .s = &[_][]const u8{ "p", "q" } });
    try std.testing.expectEqualStrings(
        \\{"app.kubernetes.io/name":"x","n":3,"l":["a",{"b":true}],"s":["p","q"]}
    , try stringify(a, val));
}
