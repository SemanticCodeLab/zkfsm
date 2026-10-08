//! migrate: imports a source deployment into zkfsm drives, either offline from the
//! source's stopped drives or online over its S3 API. Resumable via a checkpoint in
//! the destination; `--verify` compares every imported version with the source.
const std = @import("std");
const placement = @import("../placement/root.zig");
const protection = @import("../protection/root.zig");
const object = @import("../object/root.zig");
const iam = @import("../iam/root.zig");
pub const msgpack = @import("msgpack.zig");
pub const highway = @import("highway.zig");
pub const rs = @import("rs.zig");
pub const xlmeta = @import("xlmeta.zig");
pub const bucketmeta = @import("bucketmeta.zig");
pub const model = @import("model.zig");
pub const minio_disk = @import("minio_disk.zig");
pub const s3_source = @import("s3_source.zig");
pub const sink = @import("sink.zig");
pub const checkpoint = @import("checkpoint.zig");

pub const usage =
    \\usage: zkfsm migrate (--from-minio DIR... | --from-s3 URL) --to DIR... [options]
    \\  --from-minio DIR...  drives of a stopped source deployment (/d{1...4} expands)
    \\  --from-s3 URL        live S3 endpoint, e.g. http://host:9000
    \\  --to DIR...          zkfsm drives to import into
    \\  --protection P       protection for fresh destination drives (as for the server)
    \\  --access-key K       source credentials for --from-s3 (or $ZKFSM_MIGRATE_ACCESS_KEY)
    \\  --secret-key S       (or $ZKFSM_MIGRATE_SECRET_KEY)
    \\  --region R           source signing region (default: us-east-1)
    \\  --bucket B           only this bucket; repeatable
    \\  --verify             after copying, compare every version with the source
    \\  --verify-only        only compare, copy nothing
    \\  --no-iam             skip users, groups, and policies
    \\  --restart            ignore the checkpoint and copy everything again
    \\IAM is imported into the destination's IAM store when ZKFSM_ACCESS_KEY /
    \\ZKFSM_SECRET_KEY (or MINIO_ROOT_USER / MINIO_ROOT_PASSWORD) are set.
    \\
;

const Mode = enum { disk, s3 };

pub const Options = struct {
    mode: Mode = .disk,
    from: []const []const u8 = &.{},
    url: []const u8 = "",
    to: []const []const u8 = &.{},
    protection: ?placement.Profile = null,
    access_key: ?[]const u8 = null,
    secret_key: ?[]const u8 = null,
    region: []const u8 = "us-east-1",
    buckets: []const []const u8 = &.{},
    verify: bool = false,
    verify_only: bool = false,
    iam: bool = true,
    restart: bool = false,
};

pub const ArgError = error{ BadArgs, HelpRequested, OutOfMemory };

/// `args[0]` is the subcommand name.
pub fn parseArgs(arena: std.mem.Allocator, args: []const []const u8) ArgError!Options {
    var o: Options = .{};
    var from: std.ArrayList([]const u8) = .empty;
    var to: std.ArrayList([]const u8) = .empty;
    var buckets: std.ArrayList([]const u8) = .empty;
    var have_source = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) return error.HelpRequested;
        if (std.mem.eql(u8, a, "--verify")) {
            o.verify = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--verify-only")) {
            o.verify_only = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--no-iam")) {
            o.iam = false;
            continue;
        }
        if (std.mem.eql(u8, a, "--restart")) {
            o.restart = true;
            continue;
        }
        if (i + 1 >= args.len) return error.BadArgs;
        i += 1;
        if (std.mem.eql(u8, a, "--from-minio") or std.mem.eql(u8, a, "--to")) {
            const list = if (a[2] == 'f') &from else &to;
            if (a[2] == 'f') {
                if (have_source) return error.BadArgs;
                have_source = true;
            }
            try expandInto(arena, args[i], list);
            while (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "-")) : (i += 1) try expandInto(arena, args[i + 1], list);
        } else if (std.mem.eql(u8, a, "--from-s3")) {
            if (have_source) return error.BadArgs;
            have_source = true;
            o.mode = .s3;
            o.url = args[i];
        } else if (std.mem.eql(u8, a, "--protection")) {
            o.protection = placement.Profile.parse(args[i]) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--access-key")) {
            o.access_key = args[i];
        } else if (std.mem.eql(u8, a, "--secret-key")) {
            o.secret_key = args[i];
        } else if (std.mem.eql(u8, a, "--region")) {
            o.region = args[i];
        } else if (std.mem.eql(u8, a, "--bucket")) {
            try buckets.append(arena, args[i]);
        } else return error.BadArgs;
    }
    if (!have_source or to.items.len == 0) return error.BadArgs;
    o.from = from.items;
    o.to = to.items;
    o.buckets = buckets.items;
    return o;
}

fn expandInto(arena: std.mem.Allocator, arg: []const u8, list: *std.ArrayList([]const u8)) ArgError!void {
    placement.ellipsis.expand(arena, arg, list) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadArgs,
    };
}

/// Entry point for `zkfsm migrate ...`; returns the process exit code.
pub fn main(gpa: std.mem.Allocator, args: []const []const u8) u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const opts = parseArgs(arena, args) catch |e| {
        std.debug.print("{s}", .{usage});
        return if (e == error.HelpRequested) 0 else 2;
    };
    var drives = placement.DriveSet.open(gpa, opts.to, opts.protection) catch |e| {
        std.log.err("cannot open destination drives: {t}", .{e});
        return 1;
    };
    defer drives.deinit();
    var stores: protection.Stores = .{};
    const strategy = protection.Strategy.init(gpa, &drives, &stores) catch {
        std.log.err("protection {s} is not supported", .{drives.profile.name()});
        return 1;
    };
    var svc = object.ObjectService.init(gpa, strategy.backend()) catch |e| {
        std.log.err("cannot load destination catalog: {t}", .{e});
        return 1;
    };
    defer svc.deinit();
    std.log.info("destination: {d} drive(s), protection {s}", .{ drives.count(), drives.profile.name() });

    var out: sink.Sink = .{ .svc = &svc };
    var iam_dir: ?std.fs.Dir = null;
    defer if (iam_dir) |*d| d.close();
    var iam_file: iam.store.FilePersistence = undefined;
    var iam_store: iam.Store = undefined;
    if (opts.iam and !opts.verify_only) if (rootCredentials(arena)) |c| {
        if (openZkfsmDir(opts.to[0])) |d| {
            iam_dir = d;
            iam_file = .{ .dir = d };
            if (iam_store.open(gpa, iam_file.persistence(), .{ .root_access_key = c[0], .root_secret = c[1] })) {
                out.iam_store = &iam_store;
            } else |e| std.log.warn("IAM store not opened ({t}); IAM is not imported", .{e});
        } else |_| std.log.warn("cannot open {s}/.zkfsm; IAM is not imported", .{opts.to[0]});
    } else std.log.warn("no root credentials in the environment; IAM is not imported", .{});
    defer if (out.iam_store) |st| st.deinit();

    const ckpt_dir = openZkfsmDir(opts.to[0]) catch {
        std.log.err("cannot open {s}/.zkfsm for the checkpoint", .{opts.to[0]});
        return 1;
    };
    var ckpt = checkpoint.Checkpoint.open(gpa, ckpt_dir, if (opts.mode == .disk) opts.from else &.{opts.url}, opts.restart) catch |e| {
        std.log.err("cannot open checkpoint: {t}", .{e});
        return 1;
    };
    defer ckpt.deinit();

    var run: Run = .{ .gpa = gpa, .opts = opts, .sink = &out, .ckpt = &ckpt };
    const ok = switch (opts.mode) {
        .disk => run.fromDisk(),
        .s3 => run.fromS3(),
    } catch |e| {
        std.log.err("migration stopped: {t}", .{e});
        svc.flush() catch {};
        return 1;
    };
    svc.flush() catch |e| std.log.warn("index flush failed: {t}", .{e});
    const st = out.stats;
    std.log.info("buckets created {d}, versions {d} ({d} bytes), delete markers {d}, skipped {d}, failed {d}, config warnings {d}, iam entities {d}", .{
        st.buckets, st.versions, st.bytes, st.markers, st.skipped, st.failed, st.config_warnings, st.iam_entities,
    });
    if (opts.verify or opts.verify_only) std.log.info("verified {d} version(s), {d} mismatch(es)", .{ st.verified, st.mismatches });
    return if (ok and st.failed == 0 and st.mismatches == 0) 0 else 1;
}

fn rootCredentials(arena: std.mem.Allocator) ?[2][]const u8 {
    const pairs = [_][2][]const u8{ .{ "ZKFSM_ACCESS_KEY", "ZKFSM_SECRET_KEY" }, .{ "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD" } };
    for (pairs) |p| {
        const ak = std.process.getEnvVarOwned(arena, p[0]) catch continue;
        const sk = std.process.getEnvVarOwned(arena, p[1]) catch continue;
        return .{ ak, sk };
    }
    return null;
}

fn openZkfsmDir(data: []const u8) error{CannotOpen}!std.fs.Dir {
    var root = std.fs.cwd().openDir(data, .{}) catch return error.CannotOpen;
    defer root.close();
    return root.makeOpenPath(".zkfsm", .{}) catch error.CannotOpen;
}

pub const RunError = error{ OutOfMemory, SourceFailed, CheckpointFailed };

const Run = struct {
    gpa: std.mem.Allocator,
    opts: Options,
    sink: *sink.Sink,
    ckpt: *checkpoint.Checkpoint,
    disk: ?*minio_disk.Source = null,
    s3: ?*s3_source.Source = null,
    bucket: []const u8 = "",

    fn wanted(r: *Run, bucket: []const u8) bool {
        if (r.opts.buckets.len == 0) return true;
        for (r.opts.buckets) |b| if (std.mem.eql(u8, b, bucket)) return true;
        return false;
    }

    fn copying(r: *Run) bool {
        return !r.opts.verify_only;
    }

    fn verifying(r: *Run) bool {
        return r.opts.verify or r.opts.verify_only;
    }

    // ---- offline ----

    fn fromDisk(r: *Run) RunError!bool {
        var arena_state = std.heap.ArenaAllocator.init(r.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var src = minio_disk.Source.open(r.gpa, arena, r.opts.from) catch |e| {
            std.log.err("source drives: {t}", .{e});
            return error.SourceFailed;
        };
        defer src.deinit();
        r.disk = &src;
        if (src.stats.missing_drives > 0) std.log.warn("{d} source drive(s) missing; reading through parity", .{src.stats.missing_drives});
        const buckets = src.listBuckets(arena) catch return error.OutOfMemory;
        for (buckets) |b| {
            if (!r.wanted(b)) continue;
            var ba = std.heap.ArenaAllocator.init(r.gpa);
            defer ba.deinit();
            const cfg = r.diskConfigs(ba.allocator(), b);
            try r.bucketPass(b, cfg, .disk);
        }
        if (r.copying() and r.opts.iam and r.sink.iam_store != null) try r.diskIam();
        if (src.stats.bitrot_failures > 0 or src.stats.shards_rebuilt > 0)
            std.log.info("source: {d} bitrot failure(s), {d} block(s) rebuilt from parity", .{ src.stats.bitrot_failures, src.stats.shards_rebuilt });
        return true;
    }

    fn diskConfigs(r: *Run, arena: std.mem.Allocator, bucket: []const u8) model.BucketConfigs {
        const key = std.fmt.allocPrint(arena, "buckets/{s}/.metadata.bin", .{bucket}) catch return .{};
        const bytes = r.disk.?.readSmall(arena, minio_disk.meta_bucket, key, 16 << 20) catch |e| {
            std.log.warn("bucket {s}: metadata unreadable ({t}); configurations skipped", .{ bucket, e });
            return .{};
        } orelse return .{};
        const p = bucketmeta.parse(bytes) catch |e| {
            std.log.warn("bucket {s}: metadata malformed ({t}); configurations skipped", .{ bucket, e });
            return .{};
        };
        return p.configs;
    }

    fn bucketPass(r: *Run, bucket: []const u8, cfg: model.BucketConfigs, comptime mode: Mode) RunError!void {
        r.bucket = bucket;
        if (r.copying() and !r.ckpt.bucketDone(bucket)) {
            r.sink.ensureBucket(bucket, cfg) catch |e| {
                std.log.err("bucket {s}: cannot create: {t}", .{ bucket, e });
                r.sink.stats.failed += 1;
                return;
            };
            const before = r.sink.stats.failed;
            try r.objects(bucket, mode, false);
            var a = std.heap.ArenaAllocator.init(r.gpa);
            defer a.deinit();
            r.sink.finishBucket(a.allocator(), bucket, cfg) catch |e| {
                std.log.err("bucket {s}: configurations: {t}", .{ bucket, e });
                r.sink.stats.failed += 1;
            };
            if (r.sink.stats.failed == before) r.ckpt.markBucket(bucket) catch return error.CheckpointFailed;
            std.log.info("bucket {s}: done", .{bucket});
        }
        if (r.verifying()) try r.objects(bucket, mode, true);
    }

    fn objects(r: *Run, bucket: []const u8, comptime mode: Mode, verify: bool) RunError!void {
        const Ctx = struct { r: *Run, verify: bool };
        var ctx: Ctx = .{ .r = r, .verify = verify };
        switch (mode) {
            .disk => r.disk.?.walk(bucket, "", RunError, &ctx, struct {
                fn f(c: *Ctx, si: usize, key: []const u8) RunError!void {
                    try c.r.diskObject(si, key, c.verify);
                }
            }.f) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.CheckpointFailed => error.CheckpointFailed,
                else => error.SourceFailed,
            },
            .s3 => r.s3.?.eachKey(bucket, RunError, &ctx, struct {
                fn f(c: *Ctx, key: []const u8, versions: []model.VersionInfo) RunError!void {
                    try c.r.s3Object(key, versions, c.verify);
                }
            }.f) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.CheckpointFailed => error.CheckpointFailed,
                else => error.SourceFailed,
            },
        }
    }

    fn diskObject(r: *Run, si: usize, key: []const u8, verify: bool) RunError!void {
        const bucket = r.bucket;
        if (!verify and r.ckpt.objectDone(bucket, key)) return;
        var arena_state = std.heap.ArenaAllocator.init(r.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const src = r.disk.?;
        const obj = src.loadObject(arena, si, bucket, key) catch |e| {
            std.log.err("{s}/{s}: cannot read metadata: {t}", .{ bucket, key, e });
            r.sink.stats.failed += 1;
            return;
        };
        const order = try arena.alloc(usize, obj.versions.len);
        for (order, 0..) |*o, i| o.* = i;
        std.mem.sort(usize, order, obj.versions, struct {
            fn lt(vs: []minio_disk.Merged, a: usize, b: usize) bool {
                return vs[a].v.mod_time_ns < vs[b].v.mod_time_ns;
            }
        }.lt);
        var failed = false;
        for (order) |i| {
            const m = &obj.versions[i];
            const vi = minio_disk.Source.info(arena, m) catch return error.OutOfMemory;
            const Opener = struct {
                src: *minio_disk.Source,
                obj: *const minio_disk.Object,
                m: *const minio_disk.Merged,
                rd: ?minio_disk.ObjectReader = null,
                buf: [64 * 1024]u8 = undefined,
                fn open(o: *@This(), a: std.mem.Allocator) ?*std.Io.Reader {
                    o.rd = minio_disk.ObjectReader.init(o.src, a, o.obj, o.m, &o.buf) catch return null;
                    return &o.rd.?.interface;
                }
                fn close(o: *@This()) void {
                    if (o.rd) |*x| x.deinit();
                    o.rd = null;
                }
            };
            var op: Opener = .{ .src = src, .obj = &obj, .m = m };
            if (!try r.oneVersion(arena, key, vi, &op, verify)) failed = true;
        }
        if (!verify and !failed) r.ckpt.markObject(bucket, key) catch return error.CheckpointFailed;
    }

    /// Copies or verifies one version; false when it failed.
    fn oneVersion(r: *Run, arena: std.mem.Allocator, key: []const u8, vi: model.VersionInfo, op: anytype, verify: bool) RunError!bool {
        const bucket = r.bucket;
        var idb: [36]u8 = undefined;
        const id = if (vi.isNull()) "null" else xlmeta.formatUuid(vi.id, &idb);
        if (vi.skip_reason) |why| {
            if (!verify) {
                std.log.warn("{s}/{s} version {s}: skipped: {s}", .{ bucket, key, id, why });
                r.sink.stats.skipped += 1;
            }
            return true;
        }
        if (verify) {
            var body: ?*std.Io.Reader = null;
            if (!vi.delete_marker) body = op.open(arena) orelse {
                std.log.err("{s}/{s} version {s}: source unreadable", .{ bucket, key, id });
                r.sink.stats.mismatches += 1;
                return false;
            };
            defer if (!vi.delete_marker) op.close();
            const why = r.sink.verifyVersion(arena, bucket, key, vi, body) catch |e| {
                std.log.err("{s}/{s} version {s}: verify failed: {t}", .{ bucket, key, id, e });
                r.sink.stats.mismatches += 1;
                return false;
            };
            r.sink.stats.verified += 1;
            if (why) |w| {
                std.log.err("{s}/{s} version {s}: MISMATCH: {s}", .{ bucket, key, id, w });
                r.sink.stats.mismatches += 1;
                return false;
            }
            return true;
        }
        if (vi.delete_marker) {
            r.sink.putMarker(bucket, key, vi) catch |e| {
                std.log.err("{s}/{s} delete marker {s}: {t}", .{ bucket, key, id, e });
                r.sink.stats.failed += 1;
                return false;
            };
            return true;
        }
        const body = op.open(arena) orelse {
            std.log.err("{s}/{s} version {s}: source unreadable", .{ bucket, key, id });
            r.sink.stats.failed += 1;
            return false;
        };
        defer op.close();
        r.sink.putVersion(arena, bucket, key, vi, body) catch |e| {
            std.log.err("{s}/{s} version {s}: {t}", .{ bucket, key, id, e });
            r.sink.stats.failed += 1;
            return false;
        };
        return true;
    }

    fn diskIam(r: *Run) RunError!void {
        const Ctx = struct { r: *Run };
        var ctx: Ctx = .{ .r = r };
        // Policies first so users and groups can attach them.
        for ([_][]const u8{ "config/iam/policies", "config/iam/users", "config/iam/groups", "config/iam/service-accounts", "config/iam/policydb/users", "config/iam/policydb/groups" }) |dir| {
            r.disk.?.walk(minio_disk.meta_bucket, dir, RunError, &ctx, struct {
                fn f(c: *Ctx, _: usize, key: []const u8) RunError!void {
                    var a = std.heap.ArenaAllocator.init(c.r.gpa);
                    defer a.deinit();
                    const body = c.r.disk.?.readSmall(a.allocator(), minio_disk.meta_bucket, key, 1 << 20) catch |e| {
                        std.log.warn("iam {s}: unreadable: {t}", .{ key, e });
                        return;
                    } orelse return;
                    sink.importIam(c.r.sink, a.allocator(), key["config/iam/".len..], body) catch return error.OutOfMemory;
                }
            }.f) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.SourceFailed,
            };
        }
    }

    // ---- online ----

    fn fromS3(r: *Run) RunError!bool {
        var arena_state = std.heap.ArenaAllocator.init(r.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const ak = r.opts.access_key orelse std.process.getEnvVarOwned(arena, "ZKFSM_MIGRATE_ACCESS_KEY") catch {
            std.log.err("--from-s3 needs --access-key or $ZKFSM_MIGRATE_ACCESS_KEY", .{});
            return error.SourceFailed;
        };
        const sk = r.opts.secret_key orelse std.process.getEnvVarOwned(arena, "ZKFSM_MIGRATE_SECRET_KEY") catch {
            std.log.err("--from-s3 needs --secret-key or $ZKFSM_MIGRATE_SECRET_KEY", .{});
            return error.SourceFailed;
        };
        var src = s3_source.Source.init(r.gpa, r.opts.url, ak, sk, r.opts.region) catch |e| {
            std.log.err("source {s}: {t}", .{ r.opts.url, e });
            return error.SourceFailed;
        };
        defer src.deinit();
        r.s3 = &src;
        const buckets = src.listBuckets(arena) catch |e| {
            std.log.err("source {s}: cannot list buckets: {t}", .{ r.opts.url, e });
            return error.SourceFailed;
        };
        for (buckets) |b| {
            if (!r.wanted(b)) continue;
            var ba = std.heap.ArenaAllocator.init(r.gpa);
            defer ba.deinit();
            const cfg = src.bucketConfigs(ba.allocator(), b) catch |e| {
                std.log.err("bucket {s}: cannot read configuration: {t}", .{ b, e });
                r.sink.stats.failed += 1;
                continue;
            };
            try r.bucketPass(b, cfg, .s3);
        }
        return true;
    }

    fn s3Object(r: *Run, key: []const u8, versions: []model.VersionInfo, verify: bool) RunError!void {
        const bucket = r.bucket;
        if (!verify and r.ckpt.objectDone(bucket, key)) return;
        var arena_state = std.heap.ArenaAllocator.init(r.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        model.sortOldestFirst(versions);
        var failed = false;
        for (versions) |listed| {
            var vi = listed;
            const Opener = struct {
                src: *s3_source.Source,
                bucket: []const u8,
                key: []const u8,
                id: []const u8,
                get: ?s3_source.Get = null,
                fn open(o: *@This(), _: std.mem.Allocator) ?*std.Io.Reader {
                    o.get = o.src.openVersion(o.bucket, o.key, o.id) catch return null;
                    return o.get.?.reader();
                }
                fn close(o: *@This()) void {
                    if (o.get) |*g| g.deinit();
                    o.get = null;
                }
            };
            if (!vi.delete_marker) {
                r.s3.?.fillVersion(arena, bucket, key, &vi) catch |e| {
                    std.log.err("{s}/{s}: cannot read version metadata: {t}", .{ bucket, key, e });
                    r.sink.stats.failed += 1;
                    failed = true;
                    continue;
                };
            }
            var op: Opener = .{ .src = r.s3.?, .bucket = bucket, .key = key, .id = vi.src_id };
            if (!try r.oneVersion(arena, key, vi, &op, verify)) failed = true;
        }
        if (!verify and !failed) r.ckpt.markObject(bucket, key) catch return error.CheckpointFailed;
    }
};

test "argument parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const o = try parseArgs(a, &.{ "migrate", "--from-minio", "/m/d{1...4}", "--to", "/z/a", "/z/b", "--verify", "--bucket", "x" });
    try std.testing.expectEqual(@as(usize, 4), o.from.len);
    try std.testing.expectEqualStrings("/m/d3", o.from[2]);
    try std.testing.expectEqual(@as(usize, 2), o.to.len);
    try std.testing.expect(o.verify);
    try std.testing.expectEqualStrings("x", o.buckets[0]);
    const s = try parseArgs(a, &.{ "migrate", "--from-s3", "http://h:9000", "--to", "/z" });
    try std.testing.expectEqual(Mode.s3, s.mode);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "migrate", "--to", "/z" }));
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "migrate", "--from-s3", "u", "--from-minio", "/d", "--to", "/z" }));
}

test {
    _ = msgpack;
    _ = highway;
    _ = rs;
    _ = xlmeta;
    _ = bucketmeta;
    _ = model;
    _ = minio_disk;
    _ = s3_source;
    _ = sink;
    _ = checkpoint;
}
