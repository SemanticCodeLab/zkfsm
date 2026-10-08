//! One batch job: identity, live counters, cancellation, and its persisted
//! record in the system key space (so a restart resumes from the checkpoint).
const std = @import("std");
const backend = @import("../backend/root.zig");
const spec = @import("spec.zig");

const Allocator = std.mem.Allocator;

pub const State = enum {
    pending,
    running,
    complete,
    failed,
    canceled,

    pub fn active(s: State) bool {
        return s == .pending or s == .running;
    }
};

pub const id_len = 22;
pub const max_name = 1024;

pub const Counters = struct {
    objects: i64 = 0,
    objects_failed: i64 = 0,
    delete_markers: i64 = 0,
    delete_markers_failed: i64 = 0,
    bytes: i64 = 0,
    bytes_failed: i64 = 0,
};

/// Persisted form (JSON); names are this store's own.
pub const Record = struct {
    id: []const u8,
    kind: []const u8,
    user: []const u8 = "",
    started_ns: i64,
    updated_ns: i64 = 0,
    state: []const u8,
    spec: []const u8,
    checkpoint: []const u8 = "",
    retry_attempts: u32 = 0,
    counters: Counters = .{},
    last_bucket: []const u8 = "",
    last_object: []const u8 = "",
    message: []const u8 = "",
};

pub const Job = struct {
    gpa: Allocator,
    id: [id_len]u8,
    kind: spec.Kind,
    user: []const u8,
    started_ns: i128,
    /// The submitted YAML, returned by describe-job.
    yaml: []const u8,
    cancel: std.atomic.Value(bool) = .init(false),
    /// Set last by the worker thread; only then may the job be freed.
    done: std.atomic.Value(bool) = .init(false),
    mutex: std.Thread.Mutex = .{},
    state: State = .pending,
    counters: Counters = .{},
    updated_ns: i128 = 0,
    retry_attempts: u32 = 0,
    /// Last fully processed key; a resumed run lists after it.
    checkpoint: std.ArrayList(u8) = .empty,
    last_bucket: std.ArrayList(u8) = .empty,
    last_object: std.ArrayList(u8) = .empty,
    message: std.ArrayList(u8) = .empty,

    pub fn create(gpa: Allocator, id: [id_len]u8, kind: spec.Kind, user: []const u8, started_ns: i128, yaml_text: []const u8) error{OutOfMemory}!*Job {
        const j = try gpa.create(Job);
        errdefer gpa.destroy(j);
        const u = try gpa.dupe(u8, user);
        errdefer gpa.free(u);
        j.* = .{ .gpa = gpa, .id = id, .kind = kind, .user = u, .started_ns = started_ns, .yaml = try gpa.dupe(u8, yaml_text), .updated_ns = started_ns };
        return j;
    }

    pub fn destroy(j: *Job) void {
        const gpa = j.gpa;
        gpa.free(j.user);
        gpa.free(j.yaml);
        j.checkpoint.deinit(gpa);
        j.last_bucket.deinit(gpa);
        j.last_object.deinit(gpa);
        j.message.deinit(gpa);
        gpa.destroy(j);
    }

    fn setText(j: *Job, list: *std.ArrayList(u8), s: []const u8) void {
        list.clearRetainingCapacity();
        list.appendSlice(j.gpa, s[0..@min(s.len, max_name)]) catch {};
    }

    /// Records the object being worked on.
    pub fn touch(j: *Job, bucket: []const u8, key: []const u8) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        j.setText(&j.last_bucket, bucket);
        j.setText(&j.last_object, key);
        j.updated_ns = std.time.nanoTimestamp();
    }

    pub fn add(j: *Job, d: Counters) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        inline for (@typeInfo(Counters).@"struct".fields) |f| @field(j.counters, f.name) += @field(d, f.name);
        j.updated_ns = std.time.nanoTimestamp();
    }

    pub fn setCheckpoint(j: *Job, key: []const u8) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        j.checkpoint.clearRetainingCapacity();
        j.checkpoint.appendSlice(j.gpa, key) catch {};
    }

    pub fn setState(j: *Job, s: State, msg: []const u8) void {
        j.mutex.lock();
        defer j.mutex.unlock();
        j.state = s;
        if (msg.len > 0) j.setText(&j.message, msg);
        j.updated_ns = std.time.nanoTimestamp();
    }

    pub fn getState(j: *Job) State {
        j.mutex.lock();
        defer j.mutex.unlock();
        return j.state;
    }

    pub fn canceled(j: *Job) bool {
        return j.cancel.load(.acquire);
    }

    /// Consistent copy of the mutable fields; strings live in `a`.
    pub fn snapshot(j: *Job, a: Allocator) error{OutOfMemory}!Record {
        j.mutex.lock();
        defer j.mutex.unlock();
        return .{
            .id = try a.dupe(u8, &j.id),
            .kind = j.kind.text(),
            .user = try a.dupe(u8, j.user),
            .started_ns = @intCast(j.started_ns),
            .updated_ns = @intCast(j.updated_ns),
            .state = @tagName(j.state),
            .spec = j.yaml,
            .checkpoint = try a.dupe(u8, j.checkpoint.items),
            .retry_attempts = j.retry_attempts,
            .counters = j.counters,
            .last_bucket = try a.dupe(u8, j.last_bucket.items),
            .last_object = try a.dupe(u8, j.last_object.items),
            .message = try a.dupe(u8, j.message.items),
        };
    }

    /// Rebuilds a job from its record.
    pub fn fromRecord(gpa: Allocator, r: Record) error{ OutOfMemory, Corrupt }!*Job {
        if (r.id.len != id_len) return error.Corrupt;
        const kind = spec.Kind.parse(r.kind) orelse return error.Corrupt;
        const j = try create(gpa, r.id[0..id_len].*, kind, r.user, r.started_ns, r.spec);
        errdefer j.destroy();
        j.state = std.meta.stringToEnum(State, r.state) orelse return error.Corrupt;
        j.counters = r.counters;
        j.updated_ns = r.updated_ns;
        j.retry_attempts = r.retry_attempts;
        try j.checkpoint.appendSlice(gpa, r.checkpoint);
        j.setText(&j.last_bucket, r.last_bucket);
        j.setText(&j.last_object, r.last_object);
        j.setText(&j.message, r.message);
        return j;
    }
};

/// Random job id over [0-9A-Za-z].
pub fn newId() [id_len]u8 {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    var out: [id_len]u8 = undefined;
    for (&out) |*ch| ch.* = alphabet[std.crypto.random.uintLessThan(usize, alphabet.len)];
    return out;
}

pub fn validId(s: []const u8) bool {
    if (s.len != id_len) return false;
    for (s) |ch| if (!std.ascii.isAlphanumeric(ch)) return false;
    return true;
}

// ---- persistence ----

const magic_hex = "5a4a4a";

/// `5a4a4a<26 hex of sha256(id)>`.
pub fn recordKey(id: []const u8) backend.PhysicalKey {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(id, &d, .{});
    const hex = std.fmt.bytesToHex(d, .lower);
    var k: backend.PhysicalKey = .{ .space = .system, .hex = undefined };
    @memcpy(k.hex[0..6], magic_hex);
    @memcpy(k.hex[6..], hex[0..26]);
    return k;
}

pub const StoreError = error{ StorageFailed, OutOfMemory };

pub fn save(store: backend.StorageBackend, gpa: Allocator, r: Record) StoreError!void {
    const bytes = try std.json.Stringify.valueAlloc(gpa, r, .{});
    defer gpa.free(bytes);
    store.putRecord(recordKey(r.id), bytes) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.StorageFailed;
}

/// Saves the job's current record; failures are logged (the next save retries).
pub fn persist(j: *Job, store: backend.StorageBackend) void {
    var arena = std.heap.ArenaAllocator.init(j.gpa);
    defer arena.deinit();
    const r = j.snapshot(arena.allocator()) catch return;
    save(store, j.gpa, r) catch |e| std.log.warn("batch: job {s} not saved: {t}", .{ &j.id, e });
}

pub fn remove(store: backend.StorageBackend, id: []const u8) StoreError!void {
    store.deleteRecord(recordKey(id)) catch |e| switch (e) {
        error.NotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.StorageFailed,
    };
}

/// All stored records; unreadable ones are skipped.
pub fn loadAll(store: backend.StorageBackend, a: Allocator) StoreError![]Record {
    const C = struct {
        a: Allocator,
        keys: std.ArrayList(backend.PhysicalKey) = .empty,
        fn f(ctx: *anyopaque, k: backend.PhysicalKey) backend.Error!void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            if (k.space != .system or !std.mem.eql(u8, k.hex[0..6], magic_hex)) return;
            for (c.keys.items) |o| if (std.mem.eql(u8, &o.hex, &k.hex)) return;
            try c.keys.append(c.a, k);
        }
    };
    var c: C = .{ .a = a };
    store.list(.system, .{ .ctx = &c, .func = C.f }) catch |e| switch (e) {
        error.NotFound => {},
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.StorageFailed,
    };
    var out: std.ArrayList(Record) = .empty;
    for (c.keys.items) |k| {
        const bytes = store.getRecord(k, a) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        const r = std.json.parseFromSliceLeaky(Record, a, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        try out.append(a, r);
    }
    return out.items;
}

test "record round trip and ids" {
    const gpa = std.testing.allocator;
    const id = newId();
    try std.testing.expect(validId(&id));
    try std.testing.expect(!validId("short"));
    try std.testing.expect(!validId("../../../../../../etc/x"));
    const j = try Job.create(gpa, id, .expire, "admin", 5, "expire:\n  bucket: b");
    defer j.destroy();
    j.add(.{ .objects = 3, .bytes = 10 });
    j.setCheckpoint("k/1");
    j.touch("b", "k/1");
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const r = try j.snapshot(arena.allocator());
    const text = try std.json.Stringify.valueAlloc(arena.allocator(), r, .{});
    const back = try std.json.parseFromSliceLeaky(Record, arena.allocator(), text, .{ .allocate = .alloc_always });
    const j2 = try Job.fromRecord(gpa, back);
    defer j2.destroy();
    try std.testing.expectEqual(@as(i64, 3), j2.counters.objects);
    try std.testing.expectEqualStrings("k/1", j2.checkpoint.items);
    try std.testing.expectEqual(spec.Kind.expire, j2.kind);
    try std.testing.expect(std.mem.eql(u8, recordKey(&id).hex[0..6], magic_hex));
}
