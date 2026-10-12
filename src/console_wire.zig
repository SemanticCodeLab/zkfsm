//! Wires the web console into the server: admin payload sealing, the dashboard
//! probe over drives/pools/heal state, and the console listener itself.
const std = @import("std");
const console = @import("console/root.zig");
const admin = @import("admin/root.zig");
const placement = @import("placement/root.zig");
const heal = @import("heal/root.zig");
const object = @import("object/root.zig");
const cluster = @import("cluster/root.zig");
const s3 = @import("s3/root.zig");

const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const usage =
    \\console (web UI):
    \\  --console-address H:P  web console listener (default: :9001, or $ZKFSM_CONSOLE_ADDRESS); "off" disables
    \\  --console-s3-url URL   public S3 URL used in share links (default: console host, S3 port)
    \\  --console-session S    console session lifetime in seconds, 900-43200 (default: 43200)
    \\
;

pub const Flags = struct {
    address: ?[]const u8 = null,
    s3_url: ?[]const u8 = null,
    session_s: u32 = console.limits.max_session_s,

    /// Consumes a console flag; false when `flag` is not one.
    pub fn set(f: *Flags, flag: []const u8, value: []const u8) error{BadArgs}!bool {
        if (std.mem.eql(u8, flag, "--console-address")) {
            f.address = value;
        } else if (std.mem.eql(u8, flag, "--console-s3-url")) {
            if (!std.mem.startsWith(u8, value, "http://") and !std.mem.startsWith(u8, value, "https://")) return error.BadArgs;
            f.s3_url = value;
        } else if (std.mem.eql(u8, flag, "--console-session")) {
            const v = std.fmt.parseInt(u32, value, 10) catch return error.BadArgs;
            if (v < console.limits.min_session_s or v > console.limits.max_session_s) return error.BadArgs;
            f.session_s = v;
        } else return false;
        return true;
    }

    /// The listen address, or null when the console is off.
    pub fn listenAddress(f: Flags, arena: Allocator) error{BadArgs}!?std.net.Address {
        const raw = f.address orelse (std.process.getEnvVarOwned(arena, "ZKFSM_CONSOLE_ADDRESS") catch null) orelse ":9001";
        if (std.mem.eql(u8, raw, "off") or raw.len == 0) return null;
        const colon = std.mem.lastIndexOfScalar(u8, raw, ':') orelse return error.BadArgs;
        const host = if (colon == 0) "0.0.0.0" else std.mem.trim(u8, raw[0..colon], "[]");
        const port = std.fmt.parseInt(u16, raw[colon + 1 ..], 10) catch return error.BadArgs;
        return std.net.Address.parseIp(host, port) catch error.BadArgs;
    }
};

fn seal(a: Allocator, secret: []const u8, plain: []const u8) console.SealError![]u8 {
    return admin.sio.encryptAlg(a, .pbkdf2_aes_gcm, secret, plain) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Failed,
    };
}

fn open(a: Allocator, secret: []const u8, data: []const u8) console.SealError![]u8 {
    return admin.sio.decrypt(a, secret, data) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Failed,
    };
}

/// Everything the dashboard reports; pools hold their drive sets.
pub const Probe = struct {
    svc: *object.ObjectService,
    started_s: i64,
    region: []const u8,
    /// Single-node drives (null in cluster mode).
    drives: ?*placement.DriveSet = null,
    healer: ?*heal.Healer = null,
    node: ?*cluster.Node = null,

    pub fn hooks(p: *Probe) console.Hooks {
        return .{ .ctx = p, .seal = seal, .open = open, .is_sealed = admin.sio.isEncrypted, .cluster = write, .heal = wake };
    }

    fn wake(ctx: *anyopaque) bool {
        const p: *Probe = @ptrCast(@alignCast(ctx));
        if (p.healer) |h| {
            if (h.thread == null) return false;
            h.wake();
            return true;
        }
        const n = p.node orelse return false;
        var any = false;
        for (n.pools) |*pool| for (pool.sets) |*set| if (set.healer.thread != null) {
            set.healer.wake();
            any = true;
        };
        return any;
    }

    const Drive = struct { path: []const u8, pool: usize, set: usize, state: []const u8, totalBytes: u64, freeBytes: u64 };
    const Pool = struct { index: usize, drives: usize, online: usize, setSize: usize };
    const NodeInfo = struct { address: []const u8, state: []const u8 };
    const HealInfo = struct { running: bool, lastScan: ?[]const u8, passes: u64, scanned: u64, healed: u64, failed: u64, lost: u64 };

    fn write(ctx: *anyopaque, a: Allocator, w: *Writer) Writer.Error!void {
        const p: *Probe = @ptrCast(@alignCast(ctx));
        p.writeJson(a, w) catch |e| switch (e) {
            error.OutOfMemory => return error.WriteFailed,
            error.WriteFailed => return error.WriteFailed,
        };
    }

    fn writeJson(p: *Probe, a: Allocator, w: *Writer) (Writer.Error || error{OutOfMemory})!void {
        var drives: std.ArrayList(Drive) = .empty;
        var pools: std.ArrayList(Pool) = .empty;
        var nodes: std.ArrayList(NodeInfo) = .empty;
        var heals: std.ArrayList(heal.Healer.Status) = .empty;
        var profile: []const u8 = "single";
        if (p.drives) |ds| {
            profile = ds.profile.name();
            try addSet(a, &drives, ds, 0, 0);
            try pools.append(a, .{ .index = 0, .drives = ds.count(), .online = ds.onlineCount(), .setSize = ds.count() });
        }
        if (p.healer) |h| try heals.append(a, h.status());
        if (p.node) |n| {
            profile = n.profile.name();
            for (n.topo.nodes, 0..) |nd, i| {
                const up = i == n.topo.local or n.rpc.isOnline(@intCast(i));
                try nodes.append(a, .{ .address = nd.name, .state = if (up) "online" else "offline" });
            }
            for (n.pools, 0..) |*pool, pi| {
                var total: usize = 0;
                var online: usize = 0;
                for (pool.sets, 0..) |*set, si| {
                    try addSet(a, &drives, &set.drives, pi, si);
                    total += set.drives.count();
                    online += set.drives.onlineCount();
                    try heals.append(a, set.healer.status());
                }
                try pools.append(a, .{ .index = pi, .drives = total, .online = online, .setSize = pool.set_size });
            }
            // Drives statfs could not size fall back to the node's own measurements.
            for (n.local_eps) |eps| for (eps) |maybe| if (maybe) |le| for (drives.items) |*d| if (d.totalBytes == 0 and std.mem.eql(u8, d.path, le.path)) {
                const t = le.total.load(.monotonic);
                if (t > 0) {
                    d.totalBytes = t;
                    d.freeBytes = t -| le.used.load(.monotonic);
                }
            };
        }
        var cap_total: u64 = 0;
        var cap_free: u64 = 0;
        for (drives.items) |d| {
            cap_total += d.totalBytes;
            cap_free += d.freeBytes;
        }
        var bytes: u64 = 0;
        var objects: u64 = 0;
        const buckets = p.svc.listBuckets(a) catch &.{};
        for (buckets) |b| {
            const u = object.quota.usage(p.svc, b.name) catch continue;
            bytes += u.bytes;
            objects += u.objects;
        }
        var hinfo: ?HealInfo = null;
        if (heals.items.len > 0) {
            var h: HealInfo = .{ .running = false, .lastScan = null, .passes = 0, .scanned = 0, .healed = 0, .failed = 0, .lost = 0 };
            var last: i64 = 0;
            for (heals.items) |s| {
                h.running = h.running or s.running;
                h.passes += s.passes;
                h.scanned += s.last.entries_scanned;
                h.healed += s.last.replicas_repaired + s.last.drives_restored + s.last.drives_reinit;
                h.failed += s.last.replicas_unrepaired;
                h.lost += s.last.keys_lost;
                last = @max(last, s.last_end_s);
            }
            if (last > 0) {
                const tb = try a.create([32]u8);
                h.lastScan = console.isoTime(last, tb);
            }
            hinfo = h;
        }
        const now = std.time.timestamp();
        var js: std.json.Stringify = .{ .writer = w };
        try js.write(.{
            .mode = if (p.node != null) "cluster" else "single",
            .protection = profile,
            .uptimeSeconds = now - p.started_s,
            .version = "zkfsm 0.1.0",
            .region = if (p.region.len > 0) p.region else "us-east-1",
            .nodes = nodes.items,
            .pools = pools.items,
            .drives = drives.items,
            .capacity = .{ .totalBytes = cap_total, .freeBytes = cap_free, .usedBytes = cap_total -| cap_free },
            .usage = .{ .buckets = buckets.len, .objects = objects, .bytes = bytes },
            .heal = hinfo,
            .features = .{ .cluster = p.node != null, .heal = p.healer != null or p.node != null },
        });
    }

    fn addSet(a: Allocator, out: *std.ArrayList(Drive), ds: *placement.DriveSet, pool: usize, set: usize) error{OutOfMemory}!void {
        for (ds.drives) |*d| {
            var online = d.online.load(.acquire);
            if (d.kind == .remote and !d.kind.remote.vtable.online(d.kind.remote.ctx)) online = false;
            var total: u64 = 0;
            var free: u64 = 0;
            if (d.kind == .local) space(d.path, &total, &free);
            try out.append(a, .{ .path = try a.dupe(u8, d.path), .pool = pool, .set = set, .state = if (online) "ok" else "offline", .totalBytes = total, .freeBytes = free });
        }
    }
};

/// Filesystem size and free space under `path` (Linux statfs).
fn space(path: []const u8, total: *u64, free: *u64) void {
    var dir = std.fs.cwd().openDir(path, .{}) catch return;
    defer dir.close();
    // struct statfs on 64-bit Linux: type, bsize, blocks, bfree, bavail, ..., frsize at word 9.
    var st: [16]u64 = @splat(0);
    if (std.os.linux.E.init(std.os.linux.syscall2(.fstatfs, @intCast(dir.fd), @intFromPtr(&st))) != .SUCCESS) return;
    const unit = if (st[9] != 0) st[9] else st[1];
    total.* = st[2] *| unit;
    free.* = st[4] *| unit;
}

/// The console listener: its own HTTP server whose single raw route is the console.
pub const Running = struct {
    con: console.Console,
    probe: Probe,
    routes: [1]s3.server.RawRoute = undefined,
    server: s3.Server = undefined,
    thread: ?std.Thread = null,

    pub fn start(r: *Running, gpa: Allocator, addr: std.net.Address, cfg: console.Config, svc: *object.ObjectService, tls_ctx: anytype) void {
        r.con = console.Console.init(gpa, cfg, r.probe.hooks());
        r.routes = .{.{ .prefix = "/", .ctx = &r.con, .serve = console.Console.serve }};
        r.server = .{
            .gpa = gpa,
            .svc = svc,
            .auth = .{},
            .raw_routes = &r.routes,
            .tls = tls_ctx,
            .limits = .{ .max_conns = 256, .workers = 32, .idle_timeout_s = 120, .header_timeout_s = 10, .shutdown_timeout_s = 5 },
        };
        r.thread = std.Thread.spawn(.{}, serveLoop, .{ &r.server, addr }) catch |e| {
            std.log.warn("console not started: {t}", .{e});
            return;
        };
        std.log.info("console on {f}", .{addr});
    }

    fn serveLoop(server: *s3.Server, addr: std.net.Address) void {
        server.run(addr) catch |e| std.log.warn("console listener failed ({t}); the S3 API is unaffected", .{e});
    }

    pub fn stop(r: *Running) void {
        const t = r.thread orelse return;
        _ = r.server.requestStop();
        t.join();
        r.thread = null;
        r.con.deinit();
    }
};

/// A free loopback port for the plain-HTTP internal listener (TLS deployments).
pub fn freeLoopbackPort() ?u16 {
    const addr = std.net.Address.parseIp("127.0.0.1", 0) catch return null;
    var l = addr.listen(.{}) catch return null;
    defer l.deinit();
    return l.listen_address.getPort();
}
