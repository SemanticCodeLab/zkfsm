//! Admin-triggered heal sequences (`mc admin heal -r alias/bucket[/prefix]`): a
//! background walk over the named objects that verifies and rebuilds every shard or
//! replica, recording each object's per-drive state before and after. Clients start
//! a sequence, then poll it by token; items are handed out once.
const std = @import("std");
const core = @import("../core/root.zig");
const placement = @import("../placement/root.zig");
const object = @import("../object/root.zig");
const admin = @import("../admin/root.zig");
const root = @import("root.zig");
const report = @import("report.zig");
const fmt = @import("fmt.zig");

const Allocator = std.mem.Allocator;
const Ops = root.Ops;
const Ctx = admin.api.Ctx;
const Response = admin.api.Response;
const Error = admin.api.Error;

/// madmin HealOpts as sent by clients.
pub const Opts = struct {
    recursive: bool = false,
    dryRun: bool = false,
    remove: bool = false,
    recreate: bool = false,
    scanMode: i32 = 0,
    updateParity: bool = false,
    nolock: bool = false,
    pool: ?usize = null,
    set: ?usize = null,
};

const State = enum { running, finished, stopped };

/// Finished sequences nobody polled are dropped after this long.
const keep_done_ms: i64 = 10 * std.time.ms_per_min;
const page_size = 500;

pub const Seq = struct {
    token: [32]u8,
    started_ms: i64,
    opts: Opts,
    bucket: []u8,
    prefix: []u8,
    mutex: std.Thread.Mutex = .{},
    /// Encoded HealResultItem JSON not yet handed to the client.
    items: std.ArrayList([]u8) = .empty,
    next_id: i64 = 1,
    state: State = .running,
    detail: []const u8 = "",
    ended_ms: i64 = 0,
    stop: std.atomic.Value(bool) = .init(false),

    fn destroy(s: *Seq, gpa: Allocator) void {
        for (s.items.items) |it| gpa.free(it);
        s.items.deinit(gpa);
        gpa.free(s.bucket);
        gpa.free(s.prefix);
        gpa.destroy(s);
    }
};

pub const Registry = struct {
    mutex: std.Thread.Mutex = .{},
    seqs: std.ArrayList(*Seq) = .empty,
};

pub const DriveInfo = struct { uuid: []const u8 = "", endpoint: []const u8, state: []const u8 };
const Drives = struct { drives: []const DriveInfo };

pub const Item = struct {
    resultId: i64 = 0,
    type: []const u8,
    bucket: []const u8,
    object: []const u8 = "",
    versionId: []const u8 = "",
    detail: []const u8 = "",
    parityBlocks: u8 = 0,
    dataBlocks: u8 = 0,
    diskCount: usize,
    setCount: usize,
    before: Drives,
    after: Drives,
    objectSize: u64 = 0,
};

/// Splits `/heal/<bucket>[/<prefix>]` (percent-decoded into `a`).
pub fn parsePath(a: Allocator, op: []const u8) Error!struct { bucket: []const u8, prefix: []const u8 } {
    var rest = if (std.mem.startsWith(u8, op, "/heal")) op[5..] else op;
    if (rest.len > 0 and rest[0] == '/') rest = rest[1..];
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const b = rest[0 .. slash orelse rest.len];
    const p = if (slash) |i| rest[i + 1 ..] else "";
    return .{ .bucket = try percentDecode(a, b), .prefix = try percentDecode(a, p) };
}

fn percentDecode(a: Allocator, s: []const u8) Error![]const u8 {
    const out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |v| {
                out[n] = v;
                n += 1;
                i += 2;
                continue;
            } else |_| {}
        }
        out[n] = s[i];
        n += 1;
    }
    return out[0..n];
}

pub fn handle(o: *Ops, c: *const Ctx) Error!Response {
    const path = try parsePath(c.a, c.req.target.op);
    if (try c.param("clientToken")) |tok| return status(o, c, tok);
    const force_stop = std.mem.eql(u8, try c.param("forceStop") orelse "", "true");
    if (force_stop) return stopMatching(o, c, path.bucket, path.prefix);
    var opts: Opts = .{};
    if (c.req.body.len > 0) opts = std.json.parseFromSliceLeaky(Opts, c.a, c.req.body, .{ .ignore_unknown_fields = true }) catch
        return admin.api.badRequest(c.a, "Malformed heal options.");
    if (path.bucket.len > 0) o.svc.headBucket(path.bucket) catch
        return admin.api.fail(c.a, .not_found, "NoSuchBucket", "The specified bucket does not exist.");
    const seq = try start(o, opts, path.bucket, path.prefix);
    var tb: [32]u8 = undefined;
    return c.json(.{ .clientToken = &seq.token, .clientAddress = "", .startTime = fmt.time(&tb, seq.started_ms) });
}

fn start(o: *Ops, opts: Opts, bucket: []const u8, prefix: []const u8) error{OutOfMemory}!*Seq {
    const gpa = o.gpa;
    const s = try gpa.create(Seq);
    errdefer gpa.destroy(s);
    var rnd: [16]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    s.* = .{ .token = std.fmt.bytesToHex(rnd, .lower), .started_ms = std.time.milliTimestamp(), .opts = opts, .bucket = try gpa.dupe(u8, bucket), .prefix = try gpa.dupe(u8, prefix) };
    {
        o.heals.mutex.lock();
        defer o.heals.mutex.unlock();
        prune(o);
        try o.heals.seqs.append(gpa, s);
    }
    const t = std.Thread.spawn(.{}, run, .{ o, s }) catch {
        s.mutex.lock();
        s.state = .stopped;
        s.detail = "cannot start the heal worker";
        s.ended_ms = std.time.milliTimestamp();
        s.mutex.unlock();
        return s;
    };
    t.detach();
    return s;
}

/// Drops long-finished sequences. Caller holds the registry mutex.
fn prune(o: *Ops) void {
    const now = std.time.milliTimestamp();
    var i: usize = 0;
    while (i < o.heals.seqs.items.len) {
        const s = o.heals.seqs.items[i];
        s.mutex.lock();
        const old = s.state != .running and now - s.ended_ms > keep_done_ms;
        s.mutex.unlock();
        if (old) {
            _ = o.heals.seqs.swapRemove(i);
            s.destroy(o.gpa);
        } else i += 1;
    }
}

fn status(o: *Ops, c: *const Ctx, token: []const u8) Error!Response {
    o.heals.mutex.lock();
    defer o.heals.mutex.unlock();
    const idx = for (o.heals.seqs.items, 0..) |s, i| {
        if (std.mem.eql(u8, &s.token, token)) break i;
    } else return admin.api.fail(c.a, .bad_request, "XMinioHealNoSuchProcess", "No such heal process is running on the server.");
    const s = o.heals.seqs.items[idx];
    s.mutex.lock();
    var out: std.Io.Writer.Allocating = .init(c.a);
    const w = &out.writer;
    const done = s.state != .running;
    var tb: [32]u8 = undefined;
    const settings = try std.json.Stringify.valueAlloc(c.a, s.opts, .{ .emit_null_optional_fields = false });
    const head = try std.json.Stringify.valueAlloc(c.a, .{ .summary = @tagName(s.state), .detail = s.detail, .startTime = fmt.time(&tb, s.started_ms) }, .{});
    w.writeAll(head[0 .. head.len - 1]) catch return error.OutOfMemory;
    w.print(",\"settings\":{s},\"items\":[", .{settings}) catch return error.OutOfMemory;
    for (s.items.items, 0..) |it, i| {
        if (i > 0) w.writeByte(',') catch return error.OutOfMemory;
        w.writeAll(it) catch return error.OutOfMemory;
        o.gpa.free(it);
    }
    s.items.clearRetainingCapacity();
    w.writeAll("]}") catch return error.OutOfMemory;
    s.mutex.unlock();
    if (done) {
        _ = o.heals.seqs.swapRemove(idx);
        s.destroy(o.gpa);
    }
    return .{ .body = out.written() };
}

fn stopMatching(o: *Ops, c: *const Ctx, bucket: []const u8, prefix: []const u8) Error!Response {
    o.heals.mutex.lock();
    defer o.heals.mutex.unlock();
    for (o.heals.seqs.items) |s| {
        if (!std.mem.eql(u8, s.bucket, bucket) or !std.mem.eql(u8, s.prefix, prefix)) continue;
        s.stop.store(true, .release);
        var tb: [32]u8 = undefined;
        return c.json(.{ .clientToken = &s.token, .clientAddress = "", .startTime = fmt.time(&tb, s.started_ms) });
    }
    return admin.api.fail(c.a, .bad_request, "XMinioHealNoSuchProcess", "No such heal process is running on the server.");
}

fn push(o: *Ops, s: *Seq, item: Item) void {
    s.mutex.lock();
    defer s.mutex.unlock();
    var it = item;
    it.resultId = s.next_id;
    const bytes = std.json.Stringify.valueAlloc(o.gpa, it, .{}) catch return;
    s.items.append(o.gpa, bytes) catch {
        o.gpa.free(bytes);
        return;
    };
    s.next_id += 1;
}

fn end(s: *Seq, state: State, detail: []const u8) void {
    s.mutex.lock();
    defer s.mutex.unlock();
    s.state = state;
    s.detail = detail;
    s.ended_ms = std.time.milliTimestamp();
}

fn run(o: *Ops, s: *Seq) void {
    var arena_state = std.heap.ArenaAllocator.init(o.gpa);
    defer arena_state.deinit();
    walk(o, s, &arena_state) catch |e| return end(s, .stopped, @errorName(e));
    end(s, if (s.stop.load(.acquire)) .stopped else .finished, if (s.stop.load(.acquire)) "stopped by request" else "");
}

fn walk(o: *Ops, s: *Seq, arena_state: *std.heap.ArenaAllocator) !void {
    const a = arena_state.allocator();
    var names: std.ArrayList([]const u8) = .empty;
    if (s.bucket.len > 0) {
        try names.append(a, s.bucket);
    } else for (try o.svc.listBuckets(a)) |b| try names.append(a, b.name);
    const set_count = (try o.sets(a)).len;
    for (names.items) |bucket| {
        if (s.stop.load(.acquire)) return;
        try healBucket(o, s, a, bucket, set_count);
        if (!s.opts.recursive) {
            if (s.prefix.len > 0) try healObject(o, s, a, bucket, s.prefix, set_count);
            continue;
        }
        // Every version: noncurrent ones keep their own record and blob.
        var km: []const u8 = "";
        var vm: ?core.VersionId = null;
        while (true) {
            if (s.stop.load(.acquire)) return;
            var page_arena = std.heap.ArenaAllocator.init(o.gpa);
            defer page_arena.deinit();
            const pa = page_arena.allocator();
            const res = object.versioning.listVersions(o.svc, pa, bucket, .{ .prefix = s.prefix, .key_marker = km, .version_id_marker = vm, .max_keys = page_size }) catch |e| {
                if (e == error.NoSuchBucket) break;
                return e;
            };
            for (res.entries) |v| {
                if (s.stop.load(.acquire)) return;
                if (v.is_latest) try healObject(o, s, pa, bucket, v.key, set_count) else try healVersion(o, s, pa, bucket, v, set_count);
            }
            if (!res.is_truncated) break;
            km = try a.dupe(u8, res.next_key_marker orelse break);
            vm = res.next_version_id_marker;
        }
    }
}

/// Per-drive state of `key` over the drives it is placed on.
fn states(o: *Ops, a: Allocator, set: root.SetRef, key: placement.PhysicalKey) error{OutOfMemory}![]DriveInfo {
    var pbuf: [placement.max_drives]u8 = undefined;
    const placed = set.drives.placed(key, &pbuf);
    const out = try a.alloc(DriveInfo, placed.len);
    for (placed, out) |d, *di| di.* = .{ .endpoint = o.driveEndpoint(set, d), .state = report.keyState(set.drives, d, key) };
    return out;
}

fn wanted(s: *Seq, set: root.SetRef) bool {
    if (s.opts.pool) |p| if (p != set.pool) return false;
    if (s.opts.set) |x| if (x != set.set) return false;
    return true;
}

/// The bucket item covers the catalog record that defines every bucket.
fn healBucket(o: *Ops, s: *Seq, a: Allocator, bucket: []const u8, set_count: usize) !void {
    const key = placement.catalog_key;
    const set = try o.locate(a, key);
    const before = try states(o, a, set, key);
    if (!s.opts.dryRun) _ = set.strategy.healKey(key);
    push(o, s, .{ .type = "bucket", .bucket = bucket, .diskCount = set.drives.count(), .setCount = set_count, .before = .{ .drives = before }, .after = .{ .drives = if (s.opts.dryRun) before else try states(o, a, set, key) } });
}

fn healObject(o: *Ops, s: *Seq, a: Allocator, bucket: []const u8, key: []const u8, set_count: usize) !void {
    const info = o.svc.head(a, bucket, key) catch |e| switch (e) {
        error.NoSuchKey, error.NoSuchBucket => return,
        else => return e,
    };
    const bid = try o.svc.bucketId(bucket);
    try healOne(o, s, a, bucket, key, "", info, placement.recordKey(core.ids.nameId(bid, key)), set_count);
}

/// A noncurrent version (or delete marker): its version record and its blob.
fn healVersion(o: *Ops, s: *Seq, a: Allocator, bucket: []const u8, v: object.versioning.VersionEntry, set_count: usize) !void {
    const info = object.versioning.headVersion(o.svc, a, bucket, v.key, v.version) catch |e| switch (e) {
        error.NoSuchKey, error.NoSuchVersion, error.NoSuchBucket => return,
        else => return e,
    };
    const bid = try o.svc.bucketId(bucket);
    const rkey = placement.versionRecordKey(core.ids.versionNameId(bid, v.key, v.version));
    var vb: [32]u8 = undefined;
    const vid = try a.dupe(u8, object.versioning.formatVersionId(v.version, &vb));
    try healOne(o, s, a, bucket, v.key, vid, info, rkey, set_count);
}

fn healOne(o: *Ops, s: *Seq, a: Allocator, bucket: []const u8, key: []const u8, vid: []const u8, info: object.service.ObjectInfo, rkey: placement.PhysicalKey, set_count: usize) !void {
    // Tiered objects and delete markers keep no local data; their record is what heal covers.
    const dkey = if (info.delete_marker or info.remote(core.time.nowNs())) rkey else placement.dataKey(info.object_id);
    const set = try o.locate(a, dkey);
    if (!wanted(s, set)) return;
    const before = try states(o, a, set, dkey);
    if (!s.opts.dryRun) {
        _ = set.strategy.healKey(dkey);
        if (dkey.space == .data) {
            const rset = try o.locate(a, rkey);
            _ = rset.strategy.healKey(rkey);
        }
    }
    const b = fmt.blocks(o.profile());
    push(o, s, .{
        .type = "object",
        .bucket = bucket,
        .object = key,
        .versionId = vid,
        .parityBlocks = b.parity,
        .dataBlocks = b.data,
        .diskCount = set.drives.count(),
        .setCount = set_count,
        .before = .{ .drives = before },
        .after = .{ .drives = if (s.opts.dryRun) before else try states(o, a, set, dkey) },
        .objectSize = info.size,
    });
}

test "heal paths and options" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try parsePath(a, "/heal/bkt/dir%20a/x");
    try std.testing.expectEqualStrings("bkt", p.bucket);
    try std.testing.expectEqualStrings("dir a/x", p.prefix);
    const e = try parsePath(a, "/heal/");
    try std.testing.expectEqualStrings("", e.bucket);
    const o = try std.json.parseFromSliceLeaky(Opts, a, "{\"recursive\":true,\"dryRun\":false,\"scanMode\":1,\"pool\":1,\"extra\":2}", .{ .ignore_unknown_fields = true });
    try std.testing.expect(o.recursive);
    try std.testing.expectEqual(@as(?usize, 1), o.pool);
    const item: Item = .{ .type = "object", .bucket = "b", .object = "k", .parityBlocks = 2, .dataBlocks = 4, .diskCount = 6, .setCount = 2, .before = .{ .drives = &.{.{ .endpoint = "e", .state = "missing" }} }, .after = .{ .drives = &.{.{ .endpoint = "e", .state = "ok" }} } };
    const js = try std.json.Stringify.valueAlloc(a, item, .{});
    try std.testing.expect(std.mem.indexOf(u8, js, "\"before\":{\"drives\":[{\"uuid\":\"\",\"endpoint\":\"e\",\"state\":\"missing\"}]}") != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "\"parityBlocks\":2") != null);
}
