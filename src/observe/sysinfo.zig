//! Host and process facts for the v3 `system` groups, read from statfs and /proc.
const std = @import("std");
const linux = std.os.linux;

const Writer = std.Io.Writer;

pub const FsStat = struct { total: u64 = 0, free: u64 = 0, files: u64 = 0, ffree: u64 = 0 };

/// Capacity of the filesystem holding `path`; null when it cannot be read.
pub fn statfs(path: []const u8) ?FsStat {
    var pb: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= pb.len) return null;
    @memcpy(pb[0..path.len], path);
    pb[path.len] = 0;
    // struct statfs on 64-bit Linux: type, bsize, blocks, bfree, bavail, files, ffree, fsid, namelen, frsize.
    var st: [16]u64 = @splat(0);
    if (linux.E.init(linux.syscall2(.statfs, @intFromPtr(&pb), @intFromPtr(&st))) != .SUCCESS) return null;
    const unit = if (st[9] != 0) st[9] else st[1];
    return .{ .total = st[2] *| unit, .free = st[4] *| unit, .files = st[5], .ffree = st[6] };
}

fn readSmall(path: []const u8, buf: []u8) ?[]const u8 {
    const f = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer f.close();
    const n = f.readAll(buf) catch return null;
    return buf[0..n];
}

fn field(text: []const u8, key: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        var t = std.mem.tokenizeAny(u8, line[key.len..], " \t:");
        return std.fmt.parseInt(u64, t.next() orelse return null, 10) catch null;
    }
    return null;
}

pub fn memory(server: []const u8, w: *Writer) Writer.Error!void {
    var buf: [8192]u8 = undefined;
    const t = readSmall("/proc/meminfo", &buf) orelse return;
    const total = (field(t, "MemTotal") orelse 0) * 1024;
    const free = (field(t, "MemFree") orelse 0) * 1024;
    const avail = (field(t, "MemAvailable") orelse 0) * 1024;
    const buffers = (field(t, "Buffers") orelse 0) * 1024;
    const cache = (field(t, "Cached") orelse 0) * 1024;
    const shared = (field(t, "Shmem") orelse 0) * 1024;
    const used = total -| avail;
    const g = .{
        .{ "minio_system_memory_total", total },
        .{ "minio_system_memory_used", used },
        .{ "minio_system_memory_free", free },
        .{ "minio_system_memory_available", avail },
        .{ "minio_system_memory_buffers", buffers },
        .{ "minio_system_memory_cache", cache },
        .{ "minio_system_memory_shared", shared },
    };
    inline for (g) |m| try w.print("# TYPE {s} gauge\n{s}{{server=\"{s}\"}} {d}\n", .{ m[0], m[0], server, m[1] });
    const perc: f64 = if (total == 0) 0 else @as(f64, @floatFromInt(used)) * 100 / @as(f64, @floatFromInt(total));
    try w.print("# TYPE minio_system_memory_used_perc gauge\nminio_system_memory_used_perc{{server=\"{s}\"}} {d:.2}\n", .{ server, perc });
}

pub fn cpu(server: []const u8, w: *Writer) Writer.Error!void {
    var buf: [4096]u8 = undefined;
    const ncpu: f64 = @floatFromInt(std.Thread.getCpuCount() catch 1);
    if (readSmall("/proc/loadavg", &buf)) |t| {
        var it = std.mem.tokenizeScalar(u8, t, ' ');
        const l1 = std.fmt.parseFloat(f64, it.next() orelse "0") catch 0;
        try w.print("# TYPE minio_system_cpu_load gauge\nminio_system_cpu_load{{server=\"{s}\"}} {d:.2}\n", .{ server, l1 });
        try w.print("# TYPE minio_system_cpu_load_perc gauge\nminio_system_cpu_load_perc{{server=\"{s}\"}} {d:.2}\n", .{ server, l1 * 100 / ncpu });
    }
    const t = readSmall("/proc/stat", &buf) orelse return;
    const line = t[0 .. std.mem.indexOfScalar(u8, t, '\n') orelse t.len];
    if (!std.mem.startsWith(u8, line, "cpu ")) return;
    var v: [8]f64 = @splat(0);
    var it = std.mem.tokenizeScalar(u8, line[4..], ' ');
    for (&v) |*x| x.* = std.fmt.parseFloat(f64, it.next() orelse "0") catch 0;
    var sum: f64 = 0;
    for (v) |x| sum += x;
    if (sum == 0) sum = 1;
    // user nice system idle iowait irq softirq steal
    const g = .{
        .{ "minio_system_cpu_user", v[0] },     .{ "minio_system_cpu_nice", v[1] },       .{ "minio_system_cpu_system", v[2] },
        .{ "minio_system_cpu_avg_idle", v[3] }, .{ "minio_system_cpu_avg_iowait", v[4] }, .{ "minio_system_cpu_steal", v[7] },
    };
    inline for (g) |m| try w.print("# TYPE {s} gauge\n{s}{{server=\"{s}\"}} {d:.2}\n", .{ m[0], m[0], server, m[1] * 100 / sum });
}

pub fn threadCount() u64 {
    var buf: [4096]u8 = undefined;
    const t = readSmall("/proc/self/status", &buf) orelse return 0;
    return field(t, "Threads") orelse 0;
}

pub fn process(server: []const u8, w: *Writer) Writer.Error!void {
    var buf: [4096]u8 = undefined;
    if (readSmall("/proc/self/status", &buf)) |t| {
        try w.print("# TYPE minio_system_process_resident_memory_bytes gauge\nminio_system_process_resident_memory_bytes{{server=\"{s}\"}} {d}\n", .{ server, (field(t, "VmRSS") orelse 0) * 1024 });
        try w.print("# TYPE minio_system_process_virtual_memory_bytes gauge\nminio_system_process_virtual_memory_bytes{{server=\"{s}\"}} {d}\n", .{ server, (field(t, "VmSize") orelse 0) * 1024 });
        try w.print("# TYPE minio_system_process_go_routine_total gauge\nminio_system_process_go_routine_total{{server=\"{s}\"}} {d}\n", .{ server, field(t, "Threads") orelse 0 });
    }
    if (readSmall("/proc/self/io", &buf)) |t| {
        const g = .{
            .{ "minio_system_process_io_rchar_bytes", "rchar" },     .{ "minio_system_process_io_wchar_bytes", "wchar" },
            .{ "minio_system_process_io_read_bytes", "read_bytes" }, .{ "minio_system_process_io_write_bytes", "write_bytes" },
            .{ "minio_system_process_syscall_read_total", "syscr" }, .{ "minio_system_process_syscall_write_total", "syscw" },
        };
        inline for (g) |m| try w.print("# TYPE {s} counter\n{s}{{server=\"{s}\"}} {d}\n", .{ m[0], m[0], server, field(t, m[1]) orelse 0 });
    }
    if (readSmall("/proc/self/stat", &buf)) |t| {
        // Fields after the parenthesised command: utime is 14th, stime 15th overall.
        const rp = std.mem.lastIndexOfScalar(u8, t, ')') orelse return;
        var it = std.mem.tokenizeScalar(u8, t[rp + 1 ..], ' ');
        var i: usize = 3;
        var ut: u64 = 0;
        var st: u64 = 0;
        while (it.next()) |f| : (i += 1) {
            if (i == 14) ut = std.fmt.parseInt(u64, f, 10) catch 0;
            if (i == 15) {
                st = std.fmt.parseInt(u64, f, 10) catch 0;
                break;
            }
        }
        const secs = @as(f64, @floatFromInt(ut + st)) / 100.0;
        try w.print("# TYPE minio_system_process_cpu_total_seconds counter\nminio_system_process_cpu_total_seconds{{server=\"{s}\"}} {d:.2}\n", .{ server, secs });
    }
    var fds: u64 = 0;
    if (std.fs.openDirAbsolute("/proc/self/fd", .{ .iterate = true })) |d0| {
        var d = d0;
        defer d.close();
        var it = d.iterate();
        while (it.next() catch null) |_| fds += 1;
    } else |_| {}
    try w.print("# TYPE minio_system_process_file_descriptor_open_total gauge\nminio_system_process_file_descriptor_open_total{{server=\"{s}\"}} {d}\n", .{ server, fds });
    const lim = std.posix.getrlimit(.NOFILE) catch std.posix.rlimit{ .cur = 0, .max = 0 };
    try w.print("# TYPE minio_system_process_file_descriptor_limit_total gauge\nminio_system_process_file_descriptor_limit_total{{server=\"{s}\"}} {d}\n", .{ server, lim.cur });
}

test "statfs and proc readers" {
    const s = statfs("/").?;
    try std.testing.expect(s.total > 0);
    try std.testing.expect(statfs("/definitely/not/here") == null);
    var buf: [16 * 1024]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try memory("n", &w);
    try cpu("n", &w);
    try process("n", &w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "minio_system_memory_total{server=\"n\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "minio_system_process_resident_memory_bytes") != null);
}
