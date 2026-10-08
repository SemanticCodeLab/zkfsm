//! Batch job registry: submission, background threads with retries, cancel,
//! completion webhooks, and resume of unfinished jobs after a restart.
const std = @import("std");
const object = @import("../object/root.zig");
const sse_mod = @import("../sse/root.zig");
const spec = @import("spec.zig");
const job_mod = @import("job.zig");
const run = @import("run.zig");
const report = @import("report.zig");

const Allocator = std.mem.Allocator;
const Job = job_mod.Job;
const Record = job_mod.Record;

/// Running or queued jobs at once.
pub const max_active = 32;
/// Finished job records kept for status queries; older ones are dropped.
pub const max_finished = 256;

pub const SubmitError = error{ OutOfMemory, InvalidJob, NoSuchBucket, KmsNotConfigured, TooManyJobs, StorageFailed };

pub const Manager = struct {
    gpa: Allocator,
    env: run.Env,
    mutex: std.Thread.Mutex = .{},
    jobs: std.ArrayList(*Job) = .empty,

    pub fn init(gpa: Allocator, env: run.Env) Manager {
        return .{ .gpa = gpa, .env = env };
    }

    /// Loads stored jobs and resumes the unfinished ones.
    pub fn start(m: *Manager) void {
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        const recs = job_mod.loadAll(m.env.svc.store, arena.allocator()) catch |e| {
            std.log.warn("batch: stored jobs not loaded: {t}", .{e});
            return;
        };
        std.mem.sort(Record, recs, {}, struct {
            fn lt(_: void, x: Record, y: Record) bool {
                return x.started_ns < y.started_ns;
            }
        }.lt);
        m.mutex.lock();
        defer m.mutex.unlock();
        for (recs) |r| {
            const j = Job.fromRecord(m.gpa, r) catch continue;
            m.jobs.append(m.gpa, j) catch {
                j.destroy();
                continue;
            };
            if (j.state.active()) {
                std.log.info("batch: resuming {s} job {s} after {s}", .{ j.kind.text(), &j.id, if (j.checkpoint.items.len > 0) j.checkpoint.items else "(start)" });
                m.spawn(j);
            } else j.done.store(true, .release);
        }
    }

    /// Validates and starts a job; returns its id.
    pub fn submit(m: *Manager, user: []const u8, doc: []const u8) SubmitError![job_mod.id_len]u8 {
        const now = std.time.nanoTimestamp();
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        const s = try spec.parse(arena.allocator(), doc, now);
        try m.check(s);
        m.mutex.lock();
        defer m.mutex.unlock();
        var active: usize = 0;
        for (m.jobs.items) |j| if (!j.done.load(.acquire)) {
            active += 1;
        };
        if (active >= max_active) return error.TooManyJobs;
        m.prune();
        const j = try Job.create(m.gpa, job_mod.newId(), s.kind, user, now, doc);
        errdefer j.destroy();
        var rarena = std.heap.ArenaAllocator.init(m.gpa);
        defer rarena.deinit();
        job_mod.save(m.env.svc.store, m.gpa, try j.snapshot(rarena.allocator())) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.StorageFailed;
        try m.jobs.append(m.gpa, j);
        m.spawn(j);
        return j.id;
    }

    fn check(m: *Manager, s: spec.Job) SubmitError!void {
        const svc = m.env.svc;
        switch (s.body) {
            .replicate => |r| {
                if (r.source.isLocal()) _ = svc.bucketId(r.source.bucket) catch return error.NoSuchBucket;
                if (r.target.isLocal()) _ = svc.bucketId(r.target.bucket) catch return error.NoSuchBucket;
            },
            .keyrotate => |k| {
                const ext = m.env.sse orelse return error.KmsNotConfigured;
                if (ext.kms == null) return error.KmsNotConfigured;
                _ = svc.bucketId(k.bucket) catch return error.NoSuchBucket;
            },
            .expire => |e| _ = svc.bucketId(e.bucket) catch return error.NoSuchBucket,
        }
    }

    /// Drops the oldest finished jobs beyond the retention bound. Caller holds the mutex.
    fn prune(m: *Manager) void {
        var finished: usize = 0;
        for (m.jobs.items) |j| if (j.done.load(.acquire)) {
            finished += 1;
        };
        var i: usize = 0;
        while (finished > max_finished and i < m.jobs.items.len) {
            const j = m.jobs.items[i];
            if (!j.done.load(.acquire)) {
                i += 1;
                continue;
            }
            job_mod.remove(m.env.svc.store, &j.id) catch {};
            _ = m.jobs.orderedRemove(i);
            j.destroy();
            finished -= 1;
        }
    }

    fn spawn(m: *Manager, j: *Job) void {
        const t = std.Thread.spawn(.{}, worker, .{ m, j }) catch |e| {
            std.log.warn("batch: job {s} not started: {t}", .{ &j.id, e });
            j.setState(.failed, "could not start a worker thread");
            job_mod.persist(j, m.env.svc.store);
            j.done.store(true, .release);
            return;
        };
        t.detach();
    }

    fn worker(m: *Manager, j: *Job) void {
        defer j.done.store(true, .release);
        var arena = std.heap.ArenaAllocator.init(m.gpa);
        defer arena.deinit();
        // Relative filters resolve against the submission time, so a resumed run agrees.
        const s = spec.parse(arena.allocator(), j.yaml, j.started_ns) catch {
            j.setState(.failed, "job definition no longer parses");
            job_mod.persist(j, m.env.svc.store);
            return;
        };
        j.setState(.running, "");
        job_mod.persist(j, m.env.svc.store);
        var attempt = j.retry_attempts;
        const final: job_mod.State = while (true) {
            var r = run.Run.init(m.env, j, s, attempt);
            r.pass();
            r.deinit();
            if (j.canceled()) break .canceled;
            if (!r.failures) break .complete;
            if (attempt + 1 >= @max(s.retry.attempts, 1)) break .failed;
            std.Thread.sleep(s.retry.delay_ns);
            if (j.canceled()) break .canceled;
            attempt += 1;
            j.mutex.lock();
            j.retry_attempts = attempt;
            j.pass_failed = false;
            j.counters.objects_failed = 0;
            j.counters.bytes_failed = 0;
            j.counters.delete_markers_failed = 0;
            j.mutex.unlock();
            j.setCheckpoint("");
            job_mod.persist(j, m.env.svc.store);
        };
        j.setState(final, if (final == .canceled) "canceled" else "");
        job_mod.persist(j, m.env.svc.store);
        std.log.info("batch: {s} job {s} {t}", .{ j.kind.text(), &j.id, final });
        if (s.notify.endpoint.len > 0) notify(m.gpa, j, s.notify);
    }

    /// Snapshot of one job; null when unknown.
    pub fn get(m: *Manager, a: Allocator, id: []const u8) error{OutOfMemory}!?Record {
        m.mutex.lock();
        defer m.mutex.unlock();
        for (m.jobs.items) |j| if (std.mem.eql(u8, &j.id, id)) return try j.snapshot(a);
        return null;
    }

    /// Snapshots of all jobs, oldest first, optionally of one kind.
    pub fn list(m: *Manager, a: Allocator, kind: ?spec.Kind) error{OutOfMemory}![]Record {
        m.mutex.lock();
        defer m.mutex.unlock();
        var out: std.ArrayList(Record) = .empty;
        for (m.jobs.items) |j| if (kind == null or kind.? == j.kind) try out.append(a, try j.snapshot(a));
        return out.items;
    }

    pub const CancelResult = enum { canceled, not_found, finished };

    pub fn cancel(m: *Manager, id: []const u8) CancelResult {
        m.mutex.lock();
        defer m.mutex.unlock();
        for (m.jobs.items) |j| if (std.mem.eql(u8, &j.id, id)) {
            if (j.done.load(.acquire)) return .finished;
            j.cancel.store(true, .release);
            return .canceled;
        };
        return .not_found;
    }
};

/// POSTs the final job metric to the job's notification endpoint (best effort).
fn notify(gpa: Allocator, j: *Job, n: spec.Notify) void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const r = j.snapshot(a) catch return;
    var out: std.Io.Writer.Allocating = .init(a);
    var w: std.json.Stringify = .{ .writer = &out.writer };
    report.metric(&w, r) catch return;
    var hc: std.http.Client = .{ .allocator = gpa };
    defer hc.deinit();
    var hs: [1]std.http.Header = undefined;
    if (n.token.len > 0) hs[0] = .{ .name = "authorization", .value = n.token };
    const res = hc.fetch(.{
        .location = .{ .url = n.endpoint },
        .method = .POST,
        .payload = out.written(),
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = hs[0..@intFromBool(n.token.len > 0)],
    }) catch |e| {
        std.log.warn("batch: job {s} notification to {s} failed: {t}", .{ &j.id, n.endpoint, e });
        return;
    };
    if (@intFromEnum(res.status) >= 300) std.log.warn("batch: job {s} notification answered {d}", .{ &j.id, @intFromEnum(res.status) });
}

test "submit, run expire to completion, list and cancel" {
    const backend = @import("../backend/root.zig");
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    var lb = try backend.local.LocalBackend.open(try tmp.dir.realpath(".", &pbuf));
    defer lb.close();
    var svc = try object.ObjectService.init(gpa, lb.backend());
    defer svc.deinit();
    try svc.createBucket("exb");
    for ([_][]const u8{ "a.log", "b.log", "c.txt" }) |k| {
        var body: std.Io.Reader = .fixed("data");
        _ = try svc.put("exb", k, &body, .{});
    }
    var m = Manager.init(gpa, .{ .svc = &svc });
    defer {
        for (m.jobs.items) |j| {
            while (!j.done.load(.acquire)) std.Thread.sleep(std.time.ns_per_ms);
            j.destroy();
        }
        m.jobs.deinit(gpa);
    }
    try std.testing.expectError(error.NoSuchBucket, m.submit("u", "expire:\n  bucket: nope\n  rules:\n    - type: object"));
    try std.testing.expectError(error.InvalidJob, m.submit("u", "expire: ["));
    try std.testing.expectError(error.KmsNotConfigured, m.submit("u", "keyrotate:\n  bucket: exb\n  encryption:\n    type: sse-s3"));
    const id = try m.submit("u", "expire:\n  bucket: exb\n  rules:\n    - type: object\n      name: \"*.log\"");
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var rec: Record = undefined;
    for (0..2000) |_| {
        rec = (try m.get(a, &id)).?;
        if (std.mem.eql(u8, rec.state, "complete")) break;
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expectEqualStrings("complete", rec.state);
    try std.testing.expectEqual(@as(i64, 2), rec.counters.objects);
    try std.testing.expectError(error.NoSuchKey, svc.head(a, "exb", "a.log"));
    _ = try svc.head(a, "exb", "c.txt");
    try std.testing.expectEqual(Manager.CancelResult.finished, m.cancel(&id));
    try std.testing.expectEqual(Manager.CancelResult.not_found, m.cancel("nope"));
    try std.testing.expectEqual(@as(usize, 1), (try m.list(a, .expire)).len);
    try std.testing.expectEqual(@as(usize, 0), (try m.list(a, .replicate)).len);
    // A second manager over the same store sees the finished job.
    var m2 = Manager.init(gpa, .{ .svc = &svc });
    m2.start();
    defer {
        for (m2.jobs.items) |j| j.destroy();
        m2.jobs.deinit(gpa);
    }
    try std.testing.expectEqualStrings("complete", (try m2.get(a, &id)).?.state);
}
