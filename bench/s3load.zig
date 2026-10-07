//! Minimal keep-alive HTTP load generator for anonymous zkfsm endpoints.
//! usage: s3load put|get HOST PORT[,PORT...] BUCKET CONC N SIZE
//!        s3load list HOST PORT BUCKET REPS QUERY
//! With several ports, connection i goes to port i mod count.
const std = @import("std");
const posix = std.posix;

const Conn = struct {
    fd: posix.socket_t,
    buf: [64 * 1024]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn open(addr: std.net.Address) !Conn {
        const s = try std.net.tcpConnectToAddress(addr);
        const one: c_int = 1;
        try posix.setsockopt(s.handle, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one));
        return .{ .fd = s.handle };
    }

    fn writeAll(c: *Conn, bytes: []const u8) !void {
        var off: usize = 0;
        while (off < bytes.len) off += try posix.write(c.fd, bytes[off..]);
    }

    fn fill(c: *Conn) !void {
        if (c.start > 0) {
            std.mem.copyForwards(u8, c.buf[0 .. c.end - c.start], c.buf[c.start..c.end]);
            c.end -= c.start;
            c.start = 0;
        }
        if (c.end == c.buf.len) return error.HeadTooLong;
        const n = try posix.read(c.fd, c.buf[c.end..]);
        if (n == 0) return error.EndOfStream;
        c.end += n;
    }

    fn line(c: *Conn) ![]const u8 {
        while (true) {
            if (std.mem.indexOf(u8, c.buf[c.start..c.end], "\r\n")) |i| {
                const l = c.buf[c.start .. c.start + i];
                c.start += i + 2;
                return l;
            }
            try c.fill();
        }
    }

    fn skip(c: *Conn, n0: u64) !void {
        var n = n0;
        while (n > 0) {
            if (c.start == c.end) try c.fill();
            const k: usize = @intCast(@min(n, c.end - c.start));
            c.start += k;
            n -= k;
        }
    }

    /// Reads one response; returns the status code.
    fn response(c: *Conn) !u16 {
        const status_line = try c.line();
        if (status_line.len < 12) return error.BadResponse;
        const status = try std.fmt.parseInt(u16, status_line[9..12], 10);
        var len: ?u64 = null;
        var chunked = false;
        while (true) {
            const l = try c.line();
            if (l.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
            const v = std.mem.trim(u8, l[colon + 1 ..], " ");
            if (std.ascii.eqlIgnoreCase(l[0..colon], "content-length")) len = try std.fmt.parseInt(u64, v, 10);
            if (std.ascii.eqlIgnoreCase(l[0..colon], "transfer-encoding") and std.ascii.eqlIgnoreCase(v, "chunked")) chunked = true;
        }
        if (chunked) {
            while (true) {
                const n = try std.fmt.parseInt(u64, try c.line(), 16);
                try c.skip(n);
                _ = try c.line();
                if (n == 0) break;
            }
        } else try c.skip(len orelse 0);
        return status;
    }
};

const Job = struct {
    addr: std.net.Address,
    bucket: []const u8,
    mode: enum { put, get },
    first: usize,
    count: usize,
    body: []const u8,
    /// Per-request latency in ns, one slot per request of this job.
    lat: []u64,
    errors: usize = 0,

    fn run(j: *Job) void {
        var c = Conn.open(j.addr) catch {
            j.errors = j.count;
            return;
        };
        var req: [512]u8 = undefined;
        for (j.first..j.first + j.count) |i| {
            const head = switch (j.mode) {
                .put => std.fmt.bufPrint(&req, "PUT /{s}/k{d:0>8} HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{ j.bucket, i, j.body.len }),
                .get => std.fmt.bufPrint(&req, "GET /{s}/k{d:0>8} HTTP/1.1\r\nHost: x\r\n\r\n", .{ j.bucket, i }),
            } catch unreachable;
            // A server that closes after a response costs a reconnect, not an error.
            var t = std.time.Timer.start() catch unreachable;
            defer j.lat[i - j.first] = t.read();
            const st = j.once(&c, head) catch retry: {
                posix.close(c.fd);
                c = Conn.open(j.addr) catch return j.fail(i);
                break :retry j.once(&c, head) catch return j.fail(i);
            };
            if (st != 200) j.errors += 1;
        }
        posix.close(c.fd);
    }

    fn once(j: *Job, c: *Conn, head: []const u8) !u16 {
        try c.writeAll(head);
        if (j.mode == .put) try c.writeAll(j.body);
        return c.response();
    }

    fn fail(j: *Job, i: usize) void {
        j.errors += j.first + j.count - i;
    }
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_state.allocator();
    const args = try std.process.argsAlloc(arena);
    if (args.len < 7) return error.Usage;
    var ports: std.ArrayList(u16) = .empty;
    var pit = std.mem.splitScalar(u8, args[3], ',');
    while (pit.next()) |p| try ports.append(arena, try std.fmt.parseInt(u16, p, 10));
    const addr = try std.net.Address.parseIp(args[2], ports.items[0]);
    const bucket = args[4];
    var out_buf: [256]u8 = undefined;
    var out = std.fs.File.stdout().writer(&out_buf);
    const w = &out.interface;

    if (std.mem.eql(u8, args[1], "list")) {
        const reps = try std.fmt.parseInt(usize, args[5], 10);
        var c = try Conn.open(addr);
        const lat = try arena.alloc(u64, reps);
        var req: [1024]u8 = undefined;
        const head = try std.fmt.bufPrint(&req, "GET /{s}?{s} HTTP/1.1\r\nHost: x\r\n\r\n", .{ bucket, args[6] });
        for (lat) |*l| {
            var t = try std.time.Timer.start();
            try c.writeAll(head);
            if (try c.response() != 200) return error.ListFailed;
            l.* = t.read();
        }
        std.mem.sort(u64, lat, {}, std.sort.asc(u64));
        try w.print("p50_ms={d:.2} p99_ms={d:.2}\n", .{ ms(lat[lat.len / 2]), ms(lat[(lat.len * 99) / 100]) });
        try w.flush();
        return;
    }
    const conc = try std.fmt.parseInt(usize, args[5], 10);
    const n = try std.fmt.parseInt(usize, args[6], 10);
    const size = if (args.len > 7) try std.fmt.parseInt(usize, args[7], 10) else 0;
    const body = try arena.alloc(u8, size);
    @memset(body, 'x');
    const lat = try arena.alloc(u64, n);
    @memset(lat, 0);
    const jobs = try arena.alloc(Job, conc);
    const threads = try arena.alloc(std.Thread, conc);
    var t = try std.time.Timer.start();
    for (jobs, threads, 0..) |*j, *th, i| {
        const lo = n * i / conc;
        const cnt = n * (i + 1) / conc - lo;
        const a = try std.net.Address.parseIp(args[2], ports.items[i % ports.items.len]);
        j.* = .{ .addr = a, .bucket = bucket, .mode = if (std.mem.eql(u8, args[1], "put")) .put else .get, .first = lo, .count = cnt, .body = body, .lat = lat[lo..][0..cnt] };
        th.* = try std.Thread.spawn(.{}, Job.run, .{j});
    }
    var errs: usize = 0;
    for (jobs, threads) |*j, th| {
        th.join();
        errs += j.errors;
    }
    const secs = @as(f64, @floatFromInt(t.read())) / std.time.ns_per_s;
    std.mem.sort(u64, lat, {}, std.sort.asc(u64));
    const p50 = if (n > 0) ms(lat[n / 2]) else 0;
    const p99 = if (n > 0) ms(lat[(n * 99) / 100]) else 0;
    try w.print("ops_s={d:.0} p50_ms={d:.2} p99_ms={d:.2} errors={d}\n", .{ @as(f64, @floatFromInt(n)) / secs, p50, p99, errs });
    try w.flush();
}

fn ms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_ms;
}
