//! The prebuilt console bundle (console/dist), embedded so `zig build` needs no node.
//! Vite emits fixed names (see vite.config.ts); add new files here.
const std = @import("std");

pub const File = struct { path: []const u8, mime: []const u8, data: []const u8 };

pub const files = [_]File{
    .{ .path = "/index.html", .mime = "text/html; charset=utf-8", .data = @embedFile("dist/index.html") },
    .{ .path = "/app.js", .mime = "text/javascript; charset=utf-8", .data = @embedFile("dist/app.js") },
    .{ .path = "/app.css", .mime = "text/css; charset=utf-8", .data = @embedFile("dist/app.css") },
};

pub fn find(path: []const u8) ?File {
    const p = if (std.mem.eql(u8, path, "/")) "/index.html" else path;
    for (files) |f| if (std.mem.eql(u8, f.path, p)) return f;
    return null;
}
