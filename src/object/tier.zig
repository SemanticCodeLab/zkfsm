//! Remote tiers: definitions sealed into cluster-wide system state, one provider
//! client per tier, and the remote blob operations used by transition, read-through,
//! restore and cleanup. Clients are reference counted so edits never free one in use.
const std = @import("std");
const core = @import("../core/root.zig");
const backend = @import("../backend/root.zig");
const metadata = @import("../metadata/root.zig");
const service = @import("service.zig");
const blob = @import("blob.zig");

pub const Config = metadata.tier_config.Config;
pub const Kind = metadata.tier_config.Kind;
pub const validName = metadata.tier_config.validName;

const Svc = service.ObjectService;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const log = std.log.scoped(.tier);

/// System record holding the sealed tier list ("zkfsm-tiers-cfg").
pub const config_key: backend.PhysicalKey = .{ .space = .system, .hex = "7a6b66736d2d74696572732d636667ff".* };
const seal_magic = "ZKTS";
/// Peers' edits become visible within this long.
const refresh_ns: i128 = 2 * std.time.ns_per_s;
/// Short retries so a tier outage fails reads promptly; background work retries later.
const retry: backend.s3.RetryPolicy = .{ .max_attempts = 3, .base_ms = 100, .cap_ms = 1000 };
pub const chunk_len = 8 * 1024 * 1024;

pub const AdminError = service.Error || error{
    NoSuchTier,
    TierExists,
    InvalidTierConfig,
    InvalidTierName,
    /// The remote prefix already holds objects (add) or still does (remove).
    BackendInUse,
    /// The remote endpoint rejected the probe or could not be reached.
    BackendUnreachable,
    /// No sealing key: tiers need root credentials.
    TiersDisabled,
};

/// Derives the sealing key from the root secret.
pub fn sealKey(root_access_key: []const u8, root_secret: []const u8) [32]u8 {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    var ikm: std.crypto.hash.sha2.Sha256 = .init(.{});
    ikm.update(root_access_key);
    ikm.update(&.{0});
    ikm.update(root_secret);
    const prk = Hkdf.extract("zkfsm tier config v1", &ikm.finalResult());
    var key: [32]u8 = undefined;
    Hkdf.expand(&key, "seal", prk);
    return key;
}

pub fn seal(gpa: std.mem.Allocator, key: [32]u8, plain: []const u8) error{OutOfMemory}![]u8 {
    const out = try gpa.alloc(u8, seal_magic.len + Aead.nonce_length + plain.len + Aead.tag_length);
    @memcpy(out[0..4], seal_magic);
    const nonce = out[4..][0..Aead.nonce_length];
    std.crypto.random.bytes(nonce);
    const ct = out[4 + Aead.nonce_length ..][0..plain.len];
    const tag = out[out.len - Aead.tag_length ..][0..Aead.tag_length];
    Aead.encrypt(ct, tag, plain, seal_magic, nonce.*, key);
    return out;
}

pub fn unseal(gpa: std.mem.Allocator, key: [32]u8, sealed: []const u8) error{ OutOfMemory, Corrupt }![]u8 {
    const overhead = seal_magic.len + Aead.nonce_length + Aead.tag_length;
    if (sealed.len < overhead or !std.mem.eql(u8, sealed[0..4], seal_magic)) return error.Corrupt;
    const nonce = sealed[4..][0..Aead.nonce_length].*;
    const ct = sealed[4 + Aead.nonce_length .. sealed.len - Aead.tag_length];
    const tag = sealed[sealed.len - Aead.tag_length ..][0..Aead.tag_length].*;
    const out = try gpa.alloc(u8, ct.len);
    Aead.decrypt(out, ct, tag, seal_magic, nonce, key) catch {
        gpa.free(out);
        return error.Corrupt;
    };
    return out;
}

pub const Tier = struct {
    reg: *Registry,
    refs: std.atomic.Value(u32) = .init(1),
    arena: std.heap.ArenaAllocator,
    cfg: Config,
    /// Normalized: empty or ending in '/'.
    prefix: []const u8,
    client: union(enum) { s3: backend.s3.S3Client, azure: backend.azure.AzureClient, custom: backend.remote.Provider },

    pub const name_max = 4096 + 48;

    /// Builds a client for `cfg` (copied); caller owns one reference.
    pub fn create(reg: *Registry, cfg: Config) AdminError!*Tier {
        const gpa = reg.gpa;
        const t = try gpa.create(Tier);
        errdefer gpa.destroy(t);
        t.* = .{ .reg = reg, .arena = .init(gpa), .cfg = undefined, .prefix = "", .client = undefined };
        errdefer t.arena.deinit();
        const a = t.arena.allocator();
        var c = cfg;
        inline for (.{ "name", "endpoint", "access_key", "secret_key", "bucket", "prefix", "region", "storage_class" }) |f|
            @field(c, f) = try a.dupe(u8, @field(cfg, f));
        t.cfg = c;
        const p = std.mem.trimLeft(u8, c.prefix, "/");
        t.prefix = if (p.len == 0 or p[p.len - 1] == '/') p else try std.fmt.allocPrint(a, "{s}/", .{p});
        if (c.bucket.len == 0) return error.InvalidTierConfig;
        const creds: backend.s3.Credentials = .{ .access_key = c.access_key, .secret_key = c.secret_key };
        switch (c.kind) {
            .s3, .minio => {
                const ep = if (c.endpoint.len > 0) c.endpoint else "https://s3.amazonaws.com";
                if (c.access_key.len == 0 or c.secret_key.len == 0) return error.InvalidTierConfig;
                t.client = .{ .s3 = backend.s3.S3Client.init(gpa, .{
                    .endpoint = ep,
                    .region = if (c.region.len > 0) c.region else "us-east-1",
                    .bucket = c.bucket,
                    .credentials = creds,
                    .retry = retry,
                }) catch |e| return mapInit(e) };
            },
            .gcs => {
                if (c.access_key.len == 0 or c.secret_key.len == 0) return error.InvalidTierConfig;
                var sc = backend.gcs.s3Config(.{ .bucket = c.bucket, .credentials = creds, .retry = retry });
                if (c.endpoint.len > 0) sc.endpoint = c.endpoint;
                t.client = .{ .s3 = backend.s3.S3Client.init(gpa, sc) catch |e| return mapInit(e) };
            },
            .azure => {
                t.client = .{ .azure = undefined };
                t.client.azure.init(gpa, .{
                    .account = c.access_key,
                    .key = c.secret_key,
                    .container = c.bucket,
                    .endpoint = if (c.endpoint.len > 0) c.endpoint else null,
                    .retry = retry,
                }) catch |e| return mapInit(e);
            },
        }
        return t;
    }

    fn mapInit(e: error{ InvalidConfig, OutOfMemory }) AdminError {
        return switch (e) {
            error.InvalidConfig => error.InvalidTierConfig,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// A tier over a caller-provided provider (embedders, tests); never persisted.
    pub fn createCustom(reg: *Registry, name: []const u8, p: backend.remote.Provider) error{OutOfMemory}!*Tier {
        const t = try reg.gpa.create(Tier);
        t.* = .{ .reg = reg, .arena = .init(reg.gpa), .cfg = undefined, .prefix = "", .client = .{ .custom = p } };
        t.cfg = .{ .name = t.arena.allocator().dupe(u8, name) catch |e| {
            t.arena.deinit();
            reg.gpa.destroy(t);
            return e;
        }, .kind = .s3, .bucket = "" };
        return t;
    }

    fn destroy(t: *Tier) void {
        switch (t.client) {
            .s3 => |*c| c.deinit(),
            .azure => |*c| c.deinit(),
            .custom => {},
        }
        t.arena.deinit();
        t.reg.gpa.destroy(t);
    }

    pub fn retain(t: *Tier) void {
        _ = t.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(t: *Tier) void {
        if (t.refs.fetchSub(1, .acq_rel) == 1) t.destroy();
    }

    fn provider(t: *Tier) backend.remote.Provider {
        return switch (t.client) {
            .s3 => |*c| c.provider(),
            .azure => |*c| c.provider(),
            .custom => |p| p,
        };
    }

    /// `<prefix><h0h1>/<h2h3>/<hex>`; ids are random, so names never collide.
    pub fn objectName(t: *const Tier, id: [16]u8, buf: *[name_max]u8) []const u8 {
        const h = std.fmt.bytesToHex(id, .lower);
        return std.fmt.bufPrint(buf, "{s}{s}/{s}/{s}", .{ t.prefix, h[0..2], h[2..4], h }) catch unreachable; // prefix <= max_field
    }

    pub fn put(t: *Tier, id: [16]u8, src: *std.Io.Reader, size: u64) backend.Error!void {
        var nb: [name_max]u8 = undefined;
        const p = t.provider();
        _ = p.vtable.put(p.ctx, t.objectName(id, &nb), src, .{ .size_hint = size }) catch |e| return switch (e) {
            error.PreconditionFailed => error.IoFailed,
            else => |x| x,
        };
    }

    pub fn get(t: *Tier, id: [16]u8, range: ?core.Range, sink: *std.Io.Writer) backend.Error!void {
        var nb: [name_max]u8 = undefined;
        const p = t.provider();
        _ = try p.vtable.get(p.ctx, t.objectName(id, &nb), range, sink);
    }

    /// Missing objects count as deleted.
    pub fn delete(t: *Tier, id: [16]u8) backend.Error!void {
        var nb: [name_max]u8 = undefined;
        const p = t.provider();
        p.vtable.delete(p.ctx, t.objectName(id, &nb)) catch |e| if (e != error.NotFound) return e;
    }

    /// Writes, reads back, and deletes a probe object.
    pub fn verify(t: *Tier) backend.Error!void {
        var id: [16]u8 = undefined;
        std.crypto.random.bytes(&id);
        const data = "zkfsm tier probe";
        var src: std.Io.Reader = .fixed(data);
        try t.put(id, &src, data.len);
        defer t.delete(id) catch {};
        var buf: [data.len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try t.get(id, null, &w);
        if (!std.mem.eql(u8, w.buffered(), data)) return error.IoFailed;
    }

    /// True when nothing lives under the tier's prefix.
    pub fn isEmpty(t: *Tier) backend.Error!bool {
        const Stop = struct {
            fn f(_: *anyopaque, _: []const u8) backend.Error!void {
                return error.TooLarge; // any name ends the listing
            }
        };
        const p = t.provider();
        var dummy: u8 = 0;
        p.vtable.list(p.ctx, t.prefix, .{ .ctx = &dummy, .func = Stop.f }) catch |e| switch (e) {
            error.TooLarge => return false,
            else => return e,
        };
        return true;
    }
};

/// Maps a remote failure on the read/restore path to an object error.
pub fn mapRemote(e: backend.Error) service.Error {
    return switch (e) {
        error.WriteFailed => error.WriteFailed,
        error.ReadFailed => error.ReadFailed,
        error.OutOfMemory => error.OutOfMemory,
        error.NotFound => error.StorageFailed,
        else => error.TierUnavailable,
    };
}

pub const Counters = struct {
    transitions: std.atomic.Value(u64) = .init(0),
    transitioned_bytes: std.atomic.Value(u64) = .init(0),
    transition_failures: std.atomic.Value(u64) = .init(0),
    restores: std.atomic.Value(u64) = .init(0),
    restore_failures: std.atomic.Value(u64) = .init(0),
    restores_expired: std.atomic.Value(u64) = .init(0),
    remote_reads: std.atomic.Value(u64) = .init(0),
    remote_read_bytes: std.atomic.Value(u64) = .init(0),
    remote_read_failures: std.atomic.Value(u64) = .init(0),
    cleanup_deleted: std.atomic.Value(u64) = .init(0),
    cleanup_failures: std.atomic.Value(u64) = .init(0),
    cleanup_pending: std.atomic.Value(u64) = .init(0),

    pub fn inc(c: *std.atomic.Value(u64), n: u64) void {
        _ = c.fetchAdd(n, .monotonic);
    }
};

pub const Usage = struct { objects: u64 = 0, versions: u64 = 0, bytes: u64 = 0 };

pub const TierStat = struct {
    name: []const u8,
    kind: []const u8,
    usage: Usage = .{},
    /// Transitions completed by this node, per UTC hour of the last day.
    daily: Daily = .{},
};

/// 24 hourly bins indexed by UTC hour; bins older than a day are cleared on update.
pub const Daily = struct {
    bins: [24]Usage = @splat(.{}),
    updated_ns: i128 = 0,

    fn hour(ns: i128) i128 {
        return @divFloor(ns, std.time.ns_per_hour);
    }

    pub fn forwardTo(d: *Daily, now_ns: i128) void {
        const from = hour(d.updated_ns);
        const to = hour(now_ns);
        if (to <= from) return;
        if (to - from >= 24) {
            d.bins = @splat(.{});
        } else {
            var h = from + 1;
            while (h <= to) : (h += 1) d.bins[@intCast(@mod(h, 24))] = .{};
        }
        d.updated_ns = now_ns;
    }

    pub fn add(d: *Daily, now_ns: i128, bytes: u64) void {
        d.forwardTo(now_ns);
        if (d.updated_ns == 0) d.updated_ns = now_ns;
        const b = &d.bins[@intCast(@mod(hour(now_ns), 24))];
        b.objects += 1;
        b.versions += 1;
        b.bytes += bytes;
    }
};

pub const Registry = struct {
    gpa: std.mem.Allocator,
    svc: *Svc,
    /// Null without root credentials: tiers cannot be configured.
    key: ?[32]u8,
    mutex: std.Thread.Mutex = .{},
    tiers: std.ArrayList(*Tier) = .empty,
    /// In-process tiers from `pin`; looked up after the configured ones.
    pinned: std.ArrayList(*Tier) = .empty,
    /// Hash of the sealed bytes last applied; null before the first load.
    loaded: ?[32]u8 = null,
    checked_ns: i128 = 0,
    counters: Counters = .{},
    /// Usage from the last housekeeping scan; owned by `stats_arena`.
    stats_arena: std.heap.ArenaAllocator,
    hot: Usage = .{},
    stats: []TierStat = &.{},
    stats_ns: i128 = 0,
    /// Object ids with a restore in flight.
    restoring: std.AutoHashMapUnmanaged([16]u8, void) = .empty,
    /// Per-tier transition activity; keys owned by gpa.
    daily: std.StringHashMapUnmanaged(Daily) = .empty,

    pub fn init(gpa: std.mem.Allocator, svc: *Svc, key: ?[32]u8) Registry {
        return .{ .gpa = gpa, .svc = svc, .key = key, .stats_arena = .init(gpa) };
    }

    pub fn deinit(r: *Registry) void {
        for (r.tiers.items) |t| t.release();
        r.tiers.deinit(r.gpa);
        for (r.pinned.items) |t| t.release();
        r.pinned.deinit(r.gpa);
        r.stats_arena.deinit();
        r.restoring.deinit(r.gpa);
        var it = r.daily.keyIterator();
        while (it.next()) |k| r.gpa.free(k.*);
        r.daily.deinit(r.gpa);
    }

    /// Counts one completed transition of `bytes` into `name`.
    pub fn recordTransition(r: *Registry, name: []const u8, bytes: u64) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        const gop = r.daily.getOrPut(r.gpa, name) catch return;
        if (!gop.found_existing) {
            gop.key_ptr.* = r.gpa.dupe(u8, name) catch {
                _ = r.daily.remove(name);
                return;
            };
            gop.value_ptr.* = .{};
        }
        gop.value_ptr.add(core.time.nowNs(), bytes);
    }

    /// Returns a referenced tier; pair with `Tier.release`.
    pub fn acquire(r: *Registry, name: []const u8) ?*Tier {
        r.mutex.lock();
        defer r.mutex.unlock();
        r.refreshLocked(false);
        for ([_][]*Tier{ r.tiers.items, r.pinned.items }) |l| for (l) |t| if (std.mem.eql(u8, t.cfg.name, name)) {
            t.retain();
            return t;
        };
        return null;
    }

    /// Registers an in-process tier under `name` (not persisted, not listed).
    pub fn pin(r: *Registry, name: []const u8, p: backend.remote.Provider) error{OutOfMemory}!void {
        const t = try Tier.createCustom(r, name, p);
        r.mutex.lock();
        defer r.mutex.unlock();
        r.pinned.append(r.gpa, t) catch |e| {
            t.release();
            return e;
        };
    }

    /// Configured plus pinned tiers.
    pub fn count(r: *Registry) usize {
        r.mutex.lock();
        defer r.mutex.unlock();
        r.refreshLocked(false);
        return r.tiers.items.len + r.pinned.items.len;
    }

    pub fn exists(r: *Registry, name: []const u8) bool {
        const t = r.acquire(name) orelse return false;
        t.release();
        return true;
    }

    /// Current definitions with strings in `arena`.
    pub fn list(r: *Registry, arena: std.mem.Allocator) error{OutOfMemory}![]Config {
        r.mutex.lock();
        defer r.mutex.unlock();
        r.refreshLocked(false);
        const out = try arena.alloc(Config, r.tiers.items.len);
        for (r.tiers.items, out) |t, *o| {
            o.* = t.cfg;
            inline for (.{ "name", "endpoint", "access_key", "secret_key", "bucket", "prefix", "region", "storage_class" }) |f|
                @field(o, f) = try arena.dupe(u8, @field(t.cfg, f));
        }
        return out;
    }

    /// Re-reads the sealed list when stale (or `force`); keeps the old one on errors.
    fn refreshLocked(r: *Registry, force: bool) void {
        const now = core.time.nowNs();
        if (!force and r.loaded != null and now - r.checked_ns < refresh_ns) return;
        r.checked_ns = now;
        const bytes = r.svc.store.getRecord(config_key, r.gpa) catch |e| switch (e) {
            error.NotFound => {
                r.applyLocked(&.{}, @splat(0));
                return;
            },
            else => return log.warn("cannot read tier config: {t}", .{e}),
        };
        defer r.gpa.free(bytes);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &h, .{});
        if (r.loaded) |l| if (std.mem.eql(u8, &l, &h)) return;
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const cfgs = r.openSealed(arena.allocator(), bytes) catch |e| {
            r.loaded = h; // do not retry (and log) every call
            return log.err("tier config unreadable ({t}); were the root credentials changed?", .{e});
        };
        r.applyLocked(cfgs, h);
    }

    fn openSealed(r: *Registry, arena: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, Corrupt }![]Config {
        const key = r.key orelse return error.Corrupt;
        const plain = try unseal(arena, key, bytes);
        return metadata.tier_config.decode(arena, plain);
    }

    fn applyLocked(r: *Registry, cfgs: []const Config, h: [32]u8) void {
        var next: std.ArrayList(*Tier) = .empty;
        for (cfgs) |c| {
            const reuse = for (r.tiers.items) |t| {
                if (t.cfg.eql(c)) break t;
            } else null;
            if (reuse) |t| {
                t.retain();
                next.append(r.gpa, t) catch t.release();
                continue;
            }
            const t = Tier.create(r, c) catch |e| {
                log.warn("tier {s}: client not created: {t}", .{ c.name, e });
                continue;
            };
            next.append(r.gpa, t) catch t.release();
        }
        for (r.tiers.items) |t| t.release();
        r.tiers.deinit(r.gpa);
        r.tiers = next;
        r.loaded = h;
    }

    /// Loads, edits under the cluster lock, seals, persists, and applies.
    fn update(r: *Registry, ctx: anytype, comptime f: fn (@TypeOf(ctx), std.mem.Allocator, *std.ArrayList(Config)) AdminError!void) AdminError!void {
        const key = r.key orelse return error.TiersDisabled;
        const held = try r.svc.clusterLock("tiers", "", "");
        defer r.svc.clusterUnlock(held);
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var cur: std.ArrayList(Config) = .empty;
        if (r.svc.store.getRecord(config_key, a)) |bytes| {
            try cur.appendSlice(a, r.openSealed(a, bytes) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.Corrupt => error.Corrupt,
            });
        } else |e| if (e != error.NotFound) return service.mapBackend(e);
        try f(ctx, a, &cur);
        const plain = metadata.tier_config.encode(a, cur.items) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidConfig => error.InvalidTierConfig,
        };
        const sealed = try seal(a, key, plain);
        r.svc.store.putRecord(config_key, sealed) catch |e| return service.mapBackend(e);
        r.mutex.lock();
        defer r.mutex.unlock();
        r.refreshLocked(true);
    }

    pub const AddOptions = struct { force: bool = false };

    /// Probes the backend (and that its prefix is empty unless `force`) before saving.
    pub fn add(r: *Registry, cfg: Config, opts: AddOptions) AdminError!void {
        if (!validName(cfg.name)) return error.InvalidTierName;
        if (r.key == null) return error.TiersDisabled;
        if (r.exists(cfg.name)) return error.TierExists;
        var c = cfg;
        c.created_ns = core.time.nowNs();
        try probe(r, c, !opts.force);
        try r.update(c, struct {
            fn f(x: Config, a: std.mem.Allocator, l: *std.ArrayList(Config)) AdminError!void {
                for (l.items) |e| if (std.mem.eql(u8, e.name, x.name)) return error.TierExists;
                if (l.items.len >= metadata.tier_config.max_tiers) return error.InvalidTierConfig;
                try l.append(a, x);
            }
        }.f);
    }

    pub const Creds = struct {
        access_key: ?[]const u8 = null,
        secret_key: ?[]const u8 = null,
    };

    /// Replaces credentials after probing them.
    pub fn edit(r: *Registry, name: []const u8, creds: Creds) AdminError!void {
        if (r.key == null) return error.TiersDisabled;
        var arena = std.heap.ArenaAllocator.init(r.gpa);
        defer arena.deinit();
        const cur = for (try r.list(arena.allocator())) |c| {
            if (std.mem.eql(u8, c.name, name)) break c;
        } else return error.NoSuchTier;
        var next = cur;
        if (creds.access_key) |v| next.access_key = v;
        if (creds.secret_key) |v| next.secret_key = v;
        try probe(r, next, false);
        try r.update(next, struct {
            fn f(x: Config, _: std.mem.Allocator, l: *std.ArrayList(Config)) AdminError!void {
                for (l.items) |*e| if (std.mem.eql(u8, e.name, x.name)) {
                    e.access_key = x.access_key;
                    e.secret_key = x.secret_key;
                    return;
                };
                return error.NoSuchTier;
            }
        }.f);
    }

    /// Without `force` the tier must be reachable and hold no transitioned data.
    pub fn remove(r: *Registry, name: []const u8, force: bool) AdminError!void {
        if (!force) {
            const t = r.acquire(name) orelse return error.NoSuchTier;
            defer t.release();
            const empty = t.isEmpty() catch return error.BackendUnreachable;
            if (!empty) return error.BackendInUse;
        }
        try r.update(name, struct {
            fn f(x: []const u8, _: std.mem.Allocator, l: *std.ArrayList(Config)) AdminError!void {
                for (l.items, 0..) |e, i| if (std.mem.eql(u8, e.name, x)) {
                    _ = l.orderedRemove(i);
                    return;
                };
                return error.NoSuchTier;
            }
        }.f);
    }

    pub fn verify(r: *Registry, name: []const u8) AdminError!void {
        const t = r.acquire(name) orelse return error.NoSuchTier;
        defer t.release();
        t.verify() catch return error.BackendUnreachable;
    }

    // ---- stats ----

    /// Replaces the usage snapshot; `per_tier` names are copied.
    pub fn setStats(r: *Registry, hot: Usage, per_tier: []const TierStat) void {
        var fresh = std.heap.ArenaAllocator.init(r.gpa);
        const a = fresh.allocator();
        const copy = a.alloc(TierStat, per_tier.len) catch return fresh.deinit();
        for (per_tier, copy) |s, *d| d.* = .{
            .name = a.dupe(u8, s.name) catch return fresh.deinit(),
            .kind = a.dupe(u8, s.kind) catch return fresh.deinit(),
            .usage = s.usage,
        };
        r.mutex.lock();
        defer r.mutex.unlock();
        r.stats_arena.deinit();
        r.stats_arena = fresh;
        r.stats = copy;
        r.hot = hot;
        r.stats_ns = core.time.nowNs();
    }

    pub const StatsView = struct { hot: Usage, tiers: []TierStat, updated_ns: i128 };

    /// Every configured tier, with usage from the last scan (zero if not seen yet).
    pub fn statsCopy(r: *Registry, arena: std.mem.Allocator) error{OutOfMemory}!StatsView {
        const cfgs = try r.list(arena);
        r.mutex.lock();
        defer r.mutex.unlock();
        const out = try arena.alloc(TierStat, cfgs.len);
        for (cfgs, out) |c, *o| {
            o.* = .{ .name = c.name, .kind = @tagName(c.kind) };
            for (r.stats) |s| if (std.mem.eql(u8, s.name, c.name)) {
                o.usage = s.usage;
            };
            if (r.daily.getPtr(c.name)) |d| {
                d.forwardTo(core.time.nowNs());
                o.daily = d.*;
            }
        }
        return .{ .hot = r.hot, .tiers = out, .updated_ns = r.stats_ns };
    }

    // ---- restores in flight ----

    pub fn beginRestore(r: *Registry, id: [16]u8) error{ OutOfMemory, RestoreInProgress }!void {
        r.mutex.lock();
        defer r.mutex.unlock();
        const gop = try r.restoring.getOrPut(r.gpa, id);
        if (gop.found_existing) return error.RestoreInProgress;
    }

    pub fn endRestore(r: *Registry, id: [16]u8) void {
        r.mutex.lock();
        defer r.mutex.unlock();
        _ = r.restoring.remove(id);
    }

    pub fn isRestoring(r: *Registry, id: [16]u8) bool {
        r.mutex.lock();
        defer r.mutex.unlock();
        return r.restoring.contains(id);
    }
};

/// Builds a throwaway client for `cfg` and checks it end to end.
fn probe(r: *Registry, cfg: Config, need_empty: bool) AdminError!void {
    const t = try Tier.create(r, cfg);
    defer t.release();
    t.verify() catch |e| {
        log.warn("tier {s}: probe failed: {t}", .{ cfg.name, e });
        return error.BackendUnreachable;
    };
    if (need_empty and !(t.isEmpty() catch return error.BackendUnreachable)) return error.BackendInUse;
}

/// Pulls a tiered blob in large ranged reads (copy, multipart copy, restore).
pub const Reader = struct {
    tier: *Tier,
    id: [16]u8,
    pos: u64,
    end: u64,
    chunk: []u8,
    have: usize = 0,
    used: usize = 0,
    err: ?backend.Error = null,
    interface: std.Io.Reader,

    /// `chunk` should be large (see `chunk_len`); `buffer` may be small.
    pub fn init(t: *Tier, id: [16]u8, offset: u64, len: u64, chunk: []u8, buffer: []u8) Reader {
        return .{
            .tier = t,
            .id = id,
            .pos = offset,
            .end = offset + len,
            .chunk = chunk,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Reader = @alignCast(@fieldParentPtr("interface", r));
        if (self.err != null) return error.ReadFailed;
        if (self.used == self.have) {
            if (self.pos == self.end) return error.EndOfStream;
            const n: usize = @intCast(@min(self.chunk.len, self.end - self.pos));
            var fw: std.Io.Writer = .fixed(self.chunk[0..n]);
            self.tier.get(self.id, .{ .offset = self.pos, .length = n }, &fw) catch |e| {
                self.err = e;
                return error.ReadFailed;
            };
            if (fw.end != n) {
                self.err = error.IoFailed;
                return error.ReadFailed;
            }
            self.pos += n;
            self.have = n;
            self.used = 0;
        }
        const n = try w.write(limit.slice(self.chunk[self.used..self.have]));
        self.used += n;
        return n;
    }
};

test "daily bins roll forward by hour" {
    const h = std.time.ns_per_hour;
    var d: Daily = .{};
    d.add(10 * h + 5, 100);
    d.add(10 * h + 9, 50);
    try std.testing.expectEqual(@as(u64, 150), d.bins[10].bytes);
    d.add(12 * h, 7);
    try std.testing.expectEqual(@as(u64, 2), d.bins[10].objects);
    try std.testing.expectEqual(@as(u64, 7), d.bins[12].bytes);
    d.forwardTo(34 * h); // 10:00 the next day clears hour 10 only
    try std.testing.expectEqual(@as(u64, 0), d.bins[10].bytes);
    try std.testing.expectEqual(@as(u64, 7), d.bins[12].bytes);
    d.forwardTo(80 * h);
    try std.testing.expectEqual(@as(u64, 0), d.bins[12].bytes);
}

test "seal roundtrip and tamper detection" {
    const gpa = std.testing.allocator;
    const key = sealKey("root", "rootsecret");
    try std.testing.expect(!std.mem.eql(u8, &key, &sealKey("root", "other-secret")));
    const s = try seal(gpa, key, "tier list");
    defer gpa.free(s);
    const p = try unseal(gpa, key, s);
    defer gpa.free(p);
    try std.testing.expectEqualStrings("tier list", p);
    s[s.len - 1] ^= 1;
    try std.testing.expectError(error.Corrupt, unseal(gpa, key, s));
    try std.testing.expectError(error.Corrupt, unseal(gpa, key, "ZK"));
}

/// Streams tiered data for `info`; counts reads for metrics.
pub fn readRemote(svc: *Svc, info: service.ObjectInfo, range: ?core.Range, sink: *std.Io.Writer) service.Error!void {
    const reg = svc.tiers orelse return error.TierUnavailable;
    const t = reg.acquire(info.tier) orelse {
        log.warn("object {s}: tier {s} is not configured", .{ info.key, info.tier });
        return error.TierUnavailable;
    };
    defer t.release();
    Counters.inc(&reg.counters.remote_reads, 1);
    // Provider streams need buffer space in their sink; response writers may have none.
    var buf: [64 * 1024]u8 = undefined;
    var fw: Forward = .init(sink, &buf);
    t.get(info.tier_object, range, &fw.writer) catch |e| {
        if (e != error.WriteFailed) Counters.inc(&reg.counters.remote_read_failures, 1);
        if (e != error.WriteFailed) log.warn("tier {s}: read of {s} failed: {t}", .{ info.tier, info.key, e });
        return mapRemote(e);
    };
    fw.writer.flush() catch return error.WriteFailed;
    Counters.inc(&reg.counters.remote_read_bytes, if (range) |r| r.length else info.blob_size);
}

/// A buffered writer that forwards everything to `out`.
const Forward = struct {
    out: *std.Io.Writer,
    writer: std.Io.Writer,

    fn init(out: *std.Io.Writer, buf: []u8) Forward {
        return .{ .out = out, .writer = .{ .buffer = buf, .vtable = &.{ .drain = drain } } };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Forward = @alignCast(@fieldParentPtr("writer", w));
        try self.out.writeAll(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try self.out.writeAll(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try self.out.writeAll(last);
        return n + last.len * splat;
    }
};

/// Reads a byte range of a version's data whether it is local or tiered. Initialize
/// in place; the readers point into the struct.
pub const Source = struct {
    gpa: std.mem.Allocator,
    held: ?*Tier = null,
    chunk: []u8 = &.{},
    seg: [1]blob.Segment,
    br: blob.BlobReader = undefined,
    tr: Reader = undefined,

    pub fn init(s: *Source, svc: *Svc, info: service.ObjectInfo, offset: u64, len: u64, buf: []u8) service.Error!void {
        s.* = .{ .gpa = svc.gpa, .seg = .{.{ .blob = info.object_id, .offset = offset, .length = len }} };
        if (!info.remote(core.time.nowNs())) {
            s.br = blob.BlobReader.init(svc.store, &s.seg, buf);
            return;
        }
        const reg = svc.tiers orelse return error.TierUnavailable;
        const t = reg.acquire(info.tier) orelse return error.TierUnavailable;
        errdefer t.release();
        s.chunk = try svc.gpa.alloc(u8, @intCast(@max(1, @min(chunk_len, len))));
        s.held = t;
        s.tr = Reader.init(t, info.tier_object, offset, len, s.chunk, buf);
    }

    pub fn deinit(s: *Source) void {
        if (s.held) |t| {
            t.release();
            s.gpa.free(s.chunk);
        }
    }

    pub fn reader(s: *Source) *std.Io.Reader {
        return if (s.held != null) &s.tr.interface else &s.br.reader;
    }

    /// Why the reader reported ReadFailed, if the source (not the consumer) failed.
    pub fn failure(s: *const Source) ?service.Error {
        if (s.held != null) return if (s.tr.err) |e| mapRemote(e) else null;
        const e = s.br.err orelse return null;
        return if (e == error.NotFound) error.NoSuchKey else service.mapBackend(e);
    }
};
