//! Request-rate and bandwidth limits for buckets and tenants. Limits persist in the
//! IAM store (shared by every node); each node meters with its own token buckets,
//! holding one second of burst. Bytes may go into debt; requests then wait.
const std = @import("std");
const store_mod = @import("store.zig");

const Allocator = std.mem.Allocator;
const Store = store_mod.Store;
const Snapshot = store_mod.Snapshot;
const RateLimit = store_mod.RateLimit;

pub const Kind = enum { bucket, tenant };
pub const max_limits = 8192;

pub const Limits = struct {
    /// Requests per second; 0 = unlimited.
    requests: u64 = 0,
    /// Bytes per second (in and out); 0 = unlimited.
    rate: u64 = 0,

    pub fn none(l: Limits) bool {
        return l.requests == 0 and l.rate == 0;
    }
};

const SetCtx = struct { kind: Kind, name: []const u8, l: Limits };

/// Sets (or with all-zero limits, clears) the limits of a bucket or tenant.
pub fn set(st: *Store, kind: Kind, name: []const u8, l: Limits) store_mod.StoreError!void {
    try st.mutate(SetCtx{ .kind = kind, .name = name, .l = l }, struct {
        fn f(c: SetCtx, a: Allocator, next: *Snapshot) store_mod.StoreError!void {
            var out: std.ArrayList(RateLimit) = .empty;
            for (next.rate_limits) |r| if (!matches(r, c.kind, c.name)) try out.append(a, r);
            if (!c.l.none()) {
                if (out.items.len >= max_limits) return error.LimitExceeded;
                try out.append(a, .{ .kind = @tagName(c.kind), .name = c.name, .requests = c.l.requests, .rate = c.l.rate });
            }
            next.rate_limits = out.items;
        }
    }.f);
}

pub fn get(st: *Store, kind: Kind, name: []const u8) Limits {
    const v = st.view();
    defer v.release();
    for (v.snap.rate_limits) |r| if (matches(r, kind, name)) return .{ .requests = r.requests, .rate = r.rate };
    return .{};
}

fn matches(r: RateLimit, kind: Kind, name: []const u8) bool {
    return std.mem.eql(u8, r.kind, @tagName(kind)) and std.mem.eql(u8, r.name, name);
}

const Bucket = struct { reqs: f64, bytes: f64, last_ns: i128, limits: Limits };

/// Per-node token buckets keyed by kind and name.
pub const Meter = struct {
    mutex: std.Thread.Mutex = .{},
    map: std.StringHashMapUnmanaged(Bucket) = .empty,
    gpa: Allocator = std.heap.page_allocator,

    pub fn deinit(m: *Meter) void {
        var it = m.map.keyIterator();
        while (it.next()) |k| m.gpa.free(k.*);
        m.map.deinit(m.gpa);
    }

    /// Takes one request and `bytes`; false when the caller should slow down.
    pub fn admit(m: *Meter, kind: Kind, name: []const u8, l: Limits, bytes: u64, now_ns: i128) bool {
        if (l.none()) return true;
        m.mutex.lock();
        defer m.mutex.unlock();
        const b = m.refill(kind, name, l, now_ns) orelse return true;
        if (l.requests > 0 and b.reqs < 1) return false;
        if (l.rate > 0 and b.bytes <= 0) return false;
        if (l.requests > 0) b.reqs -= 1;
        if (l.rate > 0) b.bytes -= @floatFromInt(bytes);
        return true;
    }

    /// Charges bytes known only after the response (downloads).
    pub fn charge(m: *Meter, kind: Kind, name: []const u8, l: Limits, bytes: u64, now_ns: i128) void {
        if (l.rate == 0 or bytes == 0) return;
        m.mutex.lock();
        defer m.mutex.unlock();
        const b = m.refill(kind, name, l, now_ns) orelse return;
        b.bytes -= @floatFromInt(bytes);
    }

    /// Caller holds the mutex. Null only when out of memory (fails open).
    fn refill(m: *Meter, kind: Kind, name: []const u8, l: Limits, now_ns: i128) ?*Bucket {
        var kb: [store_mod.limits.max_name + 8]u8 = undefined;
        const key = std.fmt.bufPrint(&kb, "{s}:{s}", .{ @tagName(kind), name }) catch return null;
        const reqs: f64 = @floatFromInt(l.requests);
        const rate: f64 = @floatFromInt(l.rate);
        const gop = m.map.getOrPut(m.gpa, key) catch return null;
        if (!gop.found_existing) gop.key_ptr.* = m.gpa.dupe(u8, key) catch {
            m.map.removeByPtr(gop.key_ptr);
            return null;
        };
        const b = gop.value_ptr;
        // New or changed limits start with a full burst.
        if (!gop.found_existing or !std.meta.eql(b.limits, l)) {
            b.* = .{ .reqs = reqs, .bytes = rate, .last_ns = now_ns, .limits = l };
            return b;
        }
        const dt: f64 = @as(f64, @floatFromInt(@max(now_ns - b.last_ns, 0))) / std.time.ns_per_s;
        b.last_ns = now_ns;
        b.reqs = @min(reqs, b.reqs + dt * reqs);
        b.bytes = @min(rate, b.bytes + dt * rate);
        return b;
    }
};

/// Process-wide meter used by the protocol front ends.
pub var global: Meter = .{};

test "limits persist and meter enforces requests and bytes" {
    const a = std.testing.allocator;
    var mem: store_mod.MemoryPersistence = .{ .gpa = a };
    defer mem.deinit();
    var st: Store = undefined;
    try st.open(a, mem.persistence(), .{ .root_access_key = "root" });
    defer st.deinit();
    try set(&st, .bucket, "b1", .{ .requests = 2 });
    try set(&st, .tenant, "acme", .{ .rate = 100 });
    try std.testing.expectEqual(@as(u64, 2), get(&st, .bucket, "b1").requests);
    try std.testing.expect(get(&st, .bucket, "b2").none());
    var m: Meter = .{ .gpa = a };
    defer m.deinit();
    const l = get(&st, .bucket, "b1");
    try std.testing.expect(m.admit(.bucket, "b1", l, 0, 0));
    try std.testing.expect(m.admit(.bucket, "b1", l, 0, 0));
    try std.testing.expect(!m.admit(.bucket, "b1", l, 0, 0));
    try std.testing.expect(m.admit(.bucket, "b1", l, 0, std.time.ns_per_s / 2 + 1));
    const t = get(&st, .tenant, "acme");
    try std.testing.expect(m.admit(.tenant, "acme", t, 500, 0));
    try std.testing.expect(!m.admit(.tenant, "acme", t, 1, std.time.ns_per_s));
    try std.testing.expect(m.admit(.tenant, "acme", t, 1, 5 * std.time.ns_per_s));
    try set(&st, .bucket, "b1", .{});
    try std.testing.expect(get(&st, .bucket, "b1").none());
}
