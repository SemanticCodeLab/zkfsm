//! Server certificate chain + key, reference counted so SIGHUP reloads can swap them live.
const std = @import("std");
const pem = @import("pem.zig");
const keys = @import("keys.zig");

pub const LoadError = error{ CannotRead, NoCertificate, BadCertificate, KeyMismatch, BadKey, UnsupportedKey, EncryptedKey, NoKey, OutOfMemory };

const max_file = 1 << 20;
const max_chain_bytes = 1 << 16;

pub const Credentials = struct {
    gpa: std.mem.Allocator,
    refs: std.atomic.Value(u32) = .init(1),
    chain: [][]u8,
    key: keys.PrivateKey,

    pub fn fromPem(gpa: std.mem.Allocator, cert_pem: []const u8, key_pem: []const u8) LoadError!*Credentials {
        var list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (list.items) |c| gpa.free(c);
            list.deinit(gpa);
        }
        var total: usize = 0;
        var it: pem.Iterator = .{ .text = cert_pem };
        while (it.next() catch return error.BadCertificate) |blk| {
            if (!std.mem.eql(u8, blk.label, "CERTIFICATE")) continue;
            const d = pem.decode(gpa, blk.body) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.BadPem => error.BadCertificate,
            };
            list.append(gpa, d) catch {
                gpa.free(d);
                return error.OutOfMemory;
            };
            total += d.len;
            if (total > max_chain_bytes or d.len > 0xffffff) return error.BadCertificate;
        }
        if (list.items.len == 0) return error.NoCertificate;
        var key = try keys.parsePem(gpa, key_pem);
        errdefer key.deinit(gpa);
        const leaf = (std.crypto.Certificate{ .buffer = list.items[0], .index = 0 }).parse() catch return error.BadCertificate;
        if (!key.matchesPublic(leaf.pub_key_algo, leaf.pubKey())) return error.KeyMismatch;
        const self = try gpa.create(Credentials);
        self.* = .{ .gpa = gpa, .chain = try list.toOwnedSlice(gpa), .key = key };
        return self;
    }

    pub fn fromFiles(gpa: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) LoadError!*Credentials {
        const cert = std.fs.cwd().readFileAlloc(gpa, cert_path, max_file) catch |e| return mapRead(e);
        defer gpa.free(cert);
        const key = std.fs.cwd().readFileAlloc(gpa, key_path, max_file) catch |e| return mapRead(e);
        defer {
            std.crypto.secureZero(u8, key);
            gpa.free(key);
        }
        return fromPem(gpa, cert, key);
    }

    pub fn retain(c: *Credentials) void {
        _ = c.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(c: *Credentials) void {
        if (c.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = c.gpa;
        for (c.chain) |d| gpa.free(d);
        gpa.free(c.chain);
        c.key.deinit(gpa);
        gpa.destroy(c);
    }
};

fn mapRead(e: anytype) LoadError {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.CannotRead;
}

/// Where credentials come from and the live set; `acquire` is safe from any thread.
pub const Context = struct {
    gpa: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    mutex: std.Thread.Mutex = .{},
    current: *Credentials,

    pub fn init(gpa: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) LoadError!Context {
        return .{ .gpa = gpa, .cert_path = cert_path, .key_path = key_path, .current = try Credentials.fromFiles(gpa, cert_path, key_path) };
    }

    pub fn deinit(ctx: *Context) void {
        ctx.current.release();
    }

    /// Caller must `release` the result.
    pub fn acquire(ctx: *Context) *Credentials {
        ctx.mutex.lock();
        defer ctx.mutex.unlock();
        ctx.current.retain();
        return ctx.current;
    }

    /// Loads fresh files; on failure the old credentials stay active.
    pub fn reload(ctx: *Context) LoadError!void {
        const fresh = try Credentials.fromFiles(ctx.gpa, ctx.cert_path, ctx.key_path);
        ctx.mutex.lock();
        const old = ctx.current;
        ctx.current = fresh;
        ctx.mutex.unlock();
        old.release();
    }

    /// Reloads on SIGHUP from a background thread.
    pub fn watchSighup(ctx: *Context) error{SpawnFailed}!void {
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = onHup },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        std.posix.sigaction(std.posix.SIG.HUP, &act, null);
        const t = std.Thread.spawn(.{}, hupLoop, .{ctx}) catch return error.SpawnFailed;
        t.detach();
    }
};

var hup_pending: std.atomic.Value(bool) = .init(false);

fn onHup(_: c_int) callconv(.c) void {
    hup_pending.store(true, .release);
}

fn hupLoop(ctx: *Context) void {
    while (true) {
        std.Thread.sleep(200 * std.time.ns_per_ms);
        if (!hup_pending.swap(false, .acq_rel)) continue;
        if (ctx.reload()) |_| {
            std.log.info("tls: reloaded certificate {s}", .{ctx.cert_path});
        } else |e| std.log.err("tls: reload failed, keeping previous certificate: {t}", .{e});
    }
}
