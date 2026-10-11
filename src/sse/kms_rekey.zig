//! KMS key usage scans and rekey. Rekey re-seals each object's DEK under
//! another master key and rewrites only the version's internal metadata; the
//! data is never read. Work is done one bounded, resumable page per call.
const std = @import("std");
const core = @import("../core/root.zig");
const metadata = @import("../metadata/root.zig");
const object = @import("../object/root.zig");
const kms = @import("../kms/root.zig");
const handler = @import("handler.zig");

const sse = kms.sse;
const Allocator = std.mem.Allocator;

pub const max_page = 10_000;
/// Records examined by a reference scan before it gives up as incomplete.
pub const max_scan = 1_000_000;

pub const Error = object.Error || error{KmsNotConfigured};

pub const Params = struct {
    bucket: []const u8,
    prefix: []const u8 = "",
    target_key: []const u8,
    /// Only objects sealed under this key; null for every SSE-KMS/SSE-S3 object.
    from_key: ?[]const u8 = null,
    key_marker: []const u8 = "",
    version_marker: ?core.VersionId = null,
    max: usize = 1000,
};

pub const Report = struct {
    scanned: u64 = 0,
    rekeyed: u64 = 0,
    skipped: u64 = 0,
    /// Versions overwritten or deleted while being rekeyed; left untouched.
    changed: u64 = 0,
    failed: u64 = 0,
    first_error: ?[]const u8 = null,
    truncated: bool = false,
    next_key_marker: ?[]const u8 = null,
    next_version_marker: ?[]const u8 = null,
};

pub fn rekeyPage(ext: *handler.SseExt, svc: *object.ObjectService, arena: Allocator, p: Params) Error!Report {
    const page = try object.versioning.listVersions(svc, arena, p.bucket, .{
        .prefix = p.prefix,
        .key_marker = p.key_marker,
        .version_id_marker = p.version_marker,
        .max_keys = @min(@max(p.max, 1), max_page),
    });
    var r: Report = .{ .truncated = page.is_truncated, .next_key_marker = page.next_key_marker };
    if (page.next_version_id_marker) |v| {
        const buf = try arena.create([32]u8);
        r.next_version_marker = object.versioning.formatVersionId(v, buf);
    }
    for (page.entries) |e| {
        r.scanned += 1;
        if (e.delete_marker) {
            r.skipped += 1;
            continue;
        }
        const outcome = try rekeyOne(ext, svc, arena, p, e.key, e.version);
        switch (outcome) {
            .rekeyed => {
                r.rekeyed += 1;
                _ = ext.stats.rekeyed_objects.fetchAdd(1, .monotonic);
            },
            .skipped => r.skipped += 1,
            .changed => r.changed += 1,
            .failed => |name| {
                r.failed += 1;
                if (r.first_error == null) r.first_error = name;
            },
        }
    }
    return r;
}

const Outcome = union(enum) { rekeyed, skipped, changed, failed: []const u8 };

fn rekeyOne(ext: *handler.SseExt, svc: *object.ObjectService, arena: Allocator, p: Params, key: []const u8, version: core.VersionId) Error!Outcome {
    const info = object.versioning.headVersion(svc, arena, p.bucket, key, version) catch |e| switch (e) {
        error.NoSuchKey, error.NoSuchVersion => return .changed,
        else => return e,
    };
    if (info.delete_marker or !handler.isEncrypted(info) or std.mem.startsWith(u8, info.content_type, handler.marker)) return .skipped;
    const hs = try arena.alloc(sse.Header, info.internal.len);
    for (info.internal, hs) |h, *o| o.* = .{ .name = h.name, .value = h.value };
    var scratch: [4096]u8 = undefined;
    const meta = sse.SealedMeta.decode(hs, &scratch) catch return .{ .failed = "InvalidMetadata" };
    if (meta.scheme == .c) return .skipped;
    if (p.from_key) |f| if (!std.mem.eql(u8, f, meta.key_id)) return .skipped;
    const old_sealed = findHeader(info.internal, sse.hdr_sealed) orelse return .{ .failed = "InvalidMetadata" };
    const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ p.bucket, key });

    const fresh = blk: {
        const a = ext.lockKms() orelse return error.KmsNotConfigured;
        defer ext.unlockKms();
        break :blk sse.rewrapKmsObjectKey(ext.gpa, a.kms, meta, path, p.target_key) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .{ .failed = @errorName(e) },
        };
    };
    defer {
        sse.freeHeaders(ext.gpa, fresh);
        ext.gpa.free(fresh);
    }
    const Swap = struct { a: Allocator, old_sealed: []const u8, fresh: []const sse.Header };
    _ = object.versioning.mutate(svc, p.bucket, key, version, Swap{ .a = arena, .old_sealed = old_sealed, .fresh = fresh }, struct {
        fn f(s: Swap, _: object.versioning.BucketConfig, rec: *metadata.ObjectRecord) object.Error!void {
            // Another writer replaced this version since it was read.
            const cur = metadata.headers.decode(s.a, rec.internal_meta) catch return error.Corrupt;
            const now = findHeader(cur, sse.hdr_sealed) orelse return error.PreconditionFailed;
            if (!std.mem.eql(u8, now, s.old_sealed)) return error.PreconditionFailed;
            var enc = rec.internal_meta;
            for (s.fresh) |h| enc = try object.objmeta.withHeader(s.a, enc, h.name, h.value);
            rec.internal_meta = enc;
        }
    }.f) catch |e| switch (e) {
        error.PreconditionFailed, error.NoSuchKey, error.NoSuchVersion, error.MethodNotAllowed => return .changed,
        else => return e,
    };
    return .rekeyed;
}

fn findHeader(hs: []const metadata.headers.Header, name: []const u8) ?[]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

pub const Usage = struct {
    objects: u64 = 0,
    buckets: std.ArrayList([]const u8) = .empty,
    /// The scan hit `max_scan` before covering every record.
    incomplete: bool = false,
};

/// Bucket defaults and object versions sealed under `key_id`.
pub fn keyUsage(svc: *object.ObjectService, arena: Allocator, key_id: []const u8) object.Error!Usage {
    var u: Usage = .{};
    for (try svc.listBuckets(arena)) |b| {
        const cfg = handler.bucketConfig(svc, arena, b.name) catch |e| switch (e) {
            error.NoSuchBucket => continue,
            else => return e,
        };
        if (cfg) |c| if (std.mem.eql(u8, c.key_id, key_id)) try u.buckets.append(arena, b.name);
    }
    const it = try svc.scanRecords(arena);
    var tmp = std.heap.ArenaAllocator.init(svc.gpa);
    defer tmp.deinit();
    for (it.keys, 0..) |k, i| {
        if (i >= max_scan) {
            u.incomplete = true;
            break;
        }
        _ = tmp.reset(.retain_capacity);
        const bytes = svc.store.getRecord(k, tmp.allocator()) catch continue;
        const rec = metadata.record.decode(bytes) catch continue;
        const hs = metadata.headers.decode(tmp.allocator(), rec.internal_meta) catch continue;
        const id = findHeader(hs, sse.hdr_key_id) orelse continue;
        if (std.mem.eql(u8, id, key_id)) u.objects += 1;
    }
    return u;
}
