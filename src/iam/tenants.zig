//! Tenants: named isolation boundaries. A user (with its service accounts and STS
//! sessions) belongs to at most one tenant; buckets record their owning tenant.
const std = @import("std");
const store_mod = @import("store.zig");

const Allocator = std.mem.Allocator;
const Store = store_mod.Store;
const Snapshot = store_mod.Snapshot;
const Tenant = store_mod.Tenant;

pub const max_tenants = 4096;

pub const Error = store_mod.StoreError || error{ TenantExists, NoSuchTenant, TenantNotEmpty, InvalidTenantName, TooManyTenants };

/// Lowercase letters, digits, and `-`, 1..63 chars, so names are safe in paths and logs.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 63) return false;
    for (name) |c| if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '-')) return false;
    return true;
}

const Op = union(enum) {
    add: []const u8,
    remove: []const u8,
    enable: struct { name: []const u8, on: bool },
    assign: struct { user: []const u8, tenant: ?[]const u8 },
};

const Ctx = struct { op: Op, err: ?Error = null };

fn apply(c: *Ctx, a: Allocator, next: *Snapshot) store_mod.StoreError!void {
    switch (c.op) {
        .add => |name| {
            if (index(next.tenants, name) != null) return fail(c, error.TenantExists);
            if (next.tenants.len >= max_tenants) return fail(c, error.TooManyTenants);
            next.tenants = try std.mem.concat(a, Tenant, &.{ next.tenants, &.{.{ .name = name }} });
        },
        .remove => |name| {
            const i = index(next.tenants, name) orelse return fail(c, error.NoSuchTenant);
            for (next.users) |u| if (u.tenant) |t| if (std.mem.eql(u8, t, name)) return fail(c, error.TenantNotEmpty);
            var keep: std.ArrayList(Tenant) = .empty;
            for (next.tenants, 0..) |t, j| if (j != i) try keep.append(a, t);
            next.tenants = keep.items;
        },
        .enable => |e| {
            const i = index(next.tenants, e.name) orelse return fail(c, error.NoSuchTenant);
            const ts = try a.dupe(Tenant, next.tenants);
            ts[i].enabled = e.on;
            next.tenants = ts;
        },
        .assign => |as| {
            if (as.tenant) |t| if (index(next.tenants, t) == null) return fail(c, error.NoSuchTenant);
            const users = try a.dupe(store_mod.User, next.users);
            for (users) |*u| if (std.mem.eql(u8, u.name, as.user)) {
                u.tenant = as.tenant;
                next.users = users;
                return;
            };
            return error.NotFound;
        },
    }
}

fn fail(c: *Ctx, e: Error) store_mod.StoreError!void {
    c.err = e;
    return error.NotFound;
}

fn run(st: *Store, op: Op) Error!void {
    var c: Ctx = .{ .op = op };
    st.mutate(&c, apply) catch |e| return c.err orelse e;
}

pub fn add(st: *Store, name: []const u8) Error!void {
    if (!validName(name)) return error.InvalidTenantName;
    return run(st, .{ .add = name });
}

/// Fails while users still belong to the tenant; buckets are checked by the caller.
pub fn remove(st: *Store, name: []const u8) Error!void {
    return run(st, .{ .remove = name });
}

pub fn setEnabled(st: *Store, name: []const u8, on: bool) Error!void {
    return run(st, .{ .enable = .{ .name = name, .on = on } });
}

/// Moves a user into `tenant`, or out of any tenant when null.
pub fn assignUser(st: *Store, user: []const u8, tenant: ?[]const u8) Error!void {
    return run(st, .{ .assign = .{ .user = user, .tenant = tenant } });
}

fn index(ts: []const Tenant, name: []const u8) ?usize {
    for (ts, 0..) |t, i| if (std.mem.eql(u8, t.name, name)) return i;
    return null;
}

pub const Info = struct { name: []const u8, enabled: bool, users: []const []const u8 };

/// All tenants with their users, copied into `a`.
pub fn list(a: Allocator, st: *Store) error{OutOfMemory}![]const Info {
    const v = st.view();
    defer v.release();
    const out = try a.alloc(Info, v.snap.tenants.len);
    for (v.snap.tenants, out) |t, *o| {
        var users: std.ArrayList([]const u8) = .empty;
        for (v.snap.users) |u| if (u.tenant) |ut| if (std.mem.eql(u8, ut, t.name)) try users.append(a, try a.dupe(u8, u.name));
        o.* = .{ .name = try a.dupe(u8, t.name), .enabled = t.enabled, .users = users.items };
    }
    return out;
}

test "tenant lifecycle" {
    var mem: store_mod.MemoryPersistence = .{ .gpa = std.testing.allocator };
    defer mem.deinit();
    var st: Store = undefined;
    try st.open(std.testing.allocator, mem.persistence(), .{ .root_access_key = "root" });
    defer st.deinit();
    try st.createUser("alice", "alicesecret");
    try st.createServiceAccount(.{ .access_key = "alicesvc", .secret = "svcsecret1", .parent = "alice" });
    try add(&st, "acme");
    try std.testing.expectError(error.TenantExists, add(&st, "acme"));
    try std.testing.expectError(error.InvalidTenantName, add(&st, "Acme"));
    try std.testing.expectError(error.NoSuchTenant, assignUser(&st, "alice", "globex"));
    try std.testing.expectError(error.NotFound, assignUser(&st, "nobody", "acme"));
    try assignUser(&st, "alice", "acme");
    var buf: [store_mod.limits.max_name]u8 = undefined;
    try std.testing.expectEqualStrings("acme", st.tenantOf("alice", &buf).?);
    try std.testing.expectEqualStrings("acme", st.tenantOf("alicesvc", &buf).?);
    try std.testing.expectError(error.TenantNotEmpty, remove(&st, "acme"));
    try setEnabled(&st, "acme", false);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const l = try list(arena.allocator(), &st);
    try std.testing.expect(!l[0].enabled);
    try std.testing.expectEqualStrings("alice", l[0].users[0]);
    try assignUser(&st, "alice", null);
    try std.testing.expect(st.tenantOf("alice", &buf) == null);
    try remove(&st, "acme");
    try std.testing.expectError(error.NoSuchTenant, remove(&st, "acme"));
}
