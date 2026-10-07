//! IAM store: users, groups, service accounts, policies, and attachments.
//! Every mutation builds a new snapshot, persists it, then swaps it in, so a failed
//! write leaves memory unchanged. Persistence is a vtable so it can move to the cluster store.
const std = @import("std");
const policy = @import("policy.zig");
const eval = @import("eval.zig");
const context = @import("context.zig");

const Policy = policy.Policy;
const Allocator = std.mem.Allocator;

pub const format_version: u32 = 1;

pub const limits = struct {
    pub const max_name = 128;
    pub const min_secret = 8;
    pub const max_secret = 40;
    pub const max_attached = 32;
    pub const max_file_bytes = 64 * 1024 * 1024;
};

// ---------------------------------------------------------------- persisted model

pub const User = struct {
    name: []const u8,
    secret: []const u8,
    enabled: bool = true,
    policies: []const []const u8 = &.{},
    /// Owning tenant; null for global users.
    tenant: ?[]const u8 = null,
};

pub const Group = struct {
    name: []const u8,
    enabled: bool = true,
    members: []const []const u8 = &.{},
    policies: []const []const u8 = &.{},
};

pub const ServiceAccount = struct {
    access_key: []const u8,
    secret: []const u8,
    /// User name, or the root access key.
    parent: []const u8,
    enabled: bool = true,
    /// Optional session policy JSON narrowing the parent's rights.
    policy: ?[]const u8 = null,
    expires_s: ?i64 = null,
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
};

pub const PolicyDoc = struct { name: []const u8, document: []const u8 };

/// External identity provider settings as key/value pairs (see idp.zig).
pub const IdpConfig = struct {
    kind: []const u8,
    name: []const u8,
    settings: []const Setting = &.{},
};
pub const Setting = struct { key: []const u8, value: []const u8 };

/// Policies attached to an LDAP user or group DN.
pub const LdapMapping = struct {
    dn: []const u8,
    group: bool = false,
    policies: []const []const u8 = &.{},
};

/// An isolation boundary for users and buckets (see tenant.zig).
pub const Tenant = struct {
    name: []const u8,
    enabled: bool = true,
};

pub const Snapshot = struct {
    format: u32 = format_version,
    users: []const User = &.{},
    groups: []const Group = &.{},
    service_accounts: []const ServiceAccount = &.{},
    policies: []const PolicyDoc = &.{},
    idp: []const IdpConfig = &.{},
    ldap_mappings: []const LdapMapping = &.{},
    tenants: []const Tenant = &.{},
};

// ---------------------------------------------------------------- persistence

pub const PersistError = error{ OutOfMemory, PersistFailed, StoreTooLarge };

pub const Persistence = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Returns the last saved bytes (caller frees), or null when nothing was saved yet.
        load: *const fn (ptr: *anyopaque, gpa: Allocator) PersistError!?[]u8,
        /// Must be atomic: after a crash, load returns either the old or the new bytes.
        save: *const fn (ptr: *anyopaque, bytes: []const u8) PersistError!void,
        /// Shared stores (a cluster): serialize mutations across processes. A mutation
        /// takes `lock`, reloads, saves, then `unlock` (which may notify peers).
        lock: ?*const fn (ptr: *anyopaque) PersistError!void = null,
        unlock: ?*const fn (ptr: *anyopaque) void = null,
    };

    pub fn shared(p: Persistence) bool {
        return p.vtable.lock != null;
    }

    pub fn load(p: Persistence, gpa: Allocator) PersistError!?[]u8 {
        return p.vtable.load(p.ptr, gpa);
    }
    pub fn save(p: Persistence, bytes: []const u8) PersistError!void {
        return p.vtable.save(p.ptr, bytes);
    }
};

/// JSON file replaced atomically (temp file, fsync, rename, fsync dir).
pub const FilePersistence = struct {
    dir: std.fs.Dir,
    name: []const u8 = "iam.json",

    pub fn persistence(self: *FilePersistence) Persistence {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save } };
    }

    fn load(ptr: *anyopaque, gpa: Allocator) PersistError!?[]u8 {
        const self: *FilePersistence = @ptrCast(@alignCast(ptr));
        return self.dir.readFileAlloc(gpa, self.name, limits.max_file_bytes) catch |e| switch (e) {
            error.FileNotFound => null,
            error.OutOfMemory => error.OutOfMemory,
            error.FileTooBig => error.StoreTooLarge,
            else => error.PersistFailed,
        };
    }

    fn save(ptr: *anyopaque, bytes: []const u8) PersistError!void {
        const self: *FilePersistence = @ptrCast(@alignCast(ptr));
        var buf: [4096]u8 = undefined;
        var af = self.dir.atomicFile(self.name, .{ .write_buffer = &buf, .mode = 0o600 }) catch return error.PersistFailed;
        defer af.deinit();
        af.file_writer.interface.writeAll(bytes) catch return error.PersistFailed;
        af.flush() catch return error.PersistFailed;
        af.file_writer.file.sync() catch return error.PersistFailed;
        af.renameIntoPlace() catch return error.PersistFailed;
        // A fresh readable handle: fsync on an O_PATH descriptor is EBADF.
        var d = self.dir.openDir(".", .{ .iterate = true }) catch return error.PersistFailed;
        defer d.close();
        std.posix.fsync(d.fd) catch return error.PersistFailed;
    }
};

/// In-memory persistence for tests and ephemeral deployments.
pub const MemoryPersistence = struct {
    gpa: Allocator,
    data: ?[]u8 = null,
    fail_saves: bool = false,

    pub fn deinit(self: *MemoryPersistence) void {
        if (self.data) |d| self.gpa.free(d);
    }

    pub fn persistence(self: *MemoryPersistence) Persistence {
        return .{ .ptr = self, .vtable = &.{ .load = load, .save = save } };
    }

    fn load(ptr: *anyopaque, gpa: Allocator) PersistError!?[]u8 {
        const self: *MemoryPersistence = @ptrCast(@alignCast(ptr));
        const d = self.data orelse return null;
        return try gpa.dupe(u8, d);
    }

    fn save(ptr: *anyopaque, bytes: []const u8) PersistError!void {
        const self: *MemoryPersistence = @ptrCast(@alignCast(ptr));
        if (self.fail_saves) return error.PersistFailed;
        const copy = try self.gpa.dupe(u8, bytes);
        if (self.data) |d| self.gpa.free(d);
        self.data = copy;
    }
};

// ---------------------------------------------------------------- canned policies

pub const Canned = struct { name: []const u8, document: []const u8 };

/// MinIO-compatible built-in policies; they cannot be replaced or deleted.
pub const canned = [_]Canned{
    .{ .name = "readonly", .document = 
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}
    },
    .{ .name = "readwrite", .document = 
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}
    },
    .{ .name = "writeonly", .document = 
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}
    },
    .{ .name = "consoleAdmin", .document = 
    \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]},{"Effect":"Allow","Action":["kms:*"]},{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}
    },
};

fn cannedIndex(name: []const u8) ?usize {
    for (canned, 0..) |c, i| if (std.mem.eql(u8, c.name, name)) return i;
    return null;
}

// ---------------------------------------------------------------- store

pub const StoreError = error{
    OutOfMemory,
    PersistFailed,
    StoreTooLarge,
    CorruptStore,
    UnsupportedFormat,
    NotFound,
    AlreadyExists,
    InvalidName,
    InvalidSecret,
    InvalidPolicy,
    PolicyNotFound,
    PolicyInUse,
    BuiltinPolicy,
    LimitExceeded,
    GroupNotEmpty,
};

pub const Options = struct {
    /// Account id used in principal ARNs (`arn:aws:iam::<account>:user/<name>`).
    account: []const u8 = "000000000000",
    root_access_key: []const u8 = "",
    root_secret: []const u8 = "",
};

pub const AttachTarget = enum { user, group };
pub const ListKind = enum { users, groups, service_accounts, policies };

/// The caller's credential: a user, service account, root, or an STS session on one of them.
pub const Identity = struct {
    access_key: []const u8,
    /// STS session policy (already parsed by the caller from the token claims).
    session_policy: ?*const Policy = null,
    /// Federated session: comma-separated policy names; `access_key` is then the
    /// external identity's name and is not looked up.
    federated_policies: ?[]const u8 = null,
};

/// Loaded snapshot plus lookup indexes; everything lives in `arena`.
const State = struct {
    arena: std.heap.ArenaAllocator,
    snap: Snapshot,
    users: std.StringHashMapUnmanaged(usize) = .empty,
    service_accounts: std.StringHashMapUnmanaged(usize) = .empty,
    policies: std.StringHashMapUnmanaged(Policy) = .empty,
    /// Parsed service-account session policies, keyed by access key.
    sa_policies: std.StringHashMapUnmanaged(Policy) = .empty,

    fn load(gpa: Allocator, bytes: ?[]const u8) StoreError!*State {
        const st = try gpa.create(State);
        errdefer gpa.destroy(st);
        st.* = .{ .arena = .init(gpa), .snap = .{} };
        errdefer st.arena.deinit();
        const a = st.arena.allocator();
        if (bytes) |b| {
            st.snap = std.json.parseFromSliceLeaky(Snapshot, a, b, .{ .allocate = .alloc_always }) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.CorruptStore,
            };
        }
        if (st.snap.format != format_version) return error.UnsupportedFormat;
        for (st.snap.users, 0..) |u, i| {
            const gop = try st.users.getOrPut(a, u.name);
            if (gop.found_existing) return error.CorruptStore;
            gop.value_ptr.* = i;
        }
        for (st.snap.service_accounts, 0..) |s, i| {
            const gop = try st.service_accounts.getOrPut(a, s.access_key);
            if (gop.found_existing or st.users.contains(s.access_key)) return error.CorruptStore;
            gop.value_ptr.* = i;
            if (s.policy) |doc| try st.sa_policies.put(a, s.access_key, try parsePolicy(a, doc));
        }
        for (st.snap.policies) |p| {
            const gop = try st.policies.getOrPut(a, p.name);
            if (gop.found_existing) return error.CorruptStore;
            gop.value_ptr.* = try parsePolicy(a, p.document);
        }
        return st;
    }

    fn destroy(st: *State, gpa: Allocator) void {
        st.arena.deinit();
        gpa.destroy(st);
    }

    fn user(st: *const State, name: []const u8) ?*const User {
        const i = st.users.get(name) orelse return null;
        return &st.snap.users[i];
    }

    fn serviceAccount(st: *const State, key: []const u8) ?*const ServiceAccount {
        const i = st.service_accounts.get(key) orelse return null;
        return &st.snap.service_accounts[i];
    }

    fn groupIndex(st: *const State, name: []const u8) ?usize {
        for (st.snap.groups, 0..) |g, i| if (std.mem.eql(u8, g.name, name)) return i;
        return null;
    }
};

fn parsePolicy(a: Allocator, doc: []const u8) StoreError!Policy {
    return policy.parse(a, doc) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidPolicy,
    };
}

pub const Store = struct {
    gpa: Allocator,
    persist: Persistence,
    opts: Options,
    lock: std.Thread.RwLock = .{},
    state: *State,
    builtins: [canned.len]Policy,
    /// Digest of the persisted bytes behind `state`; lets `reload` skip unchanged data.
    digest: [32]u8 = @splat(0),

    /// Store must not move after `open` returns (it holds a lock); allocate it in place.
    pub fn open(self: *Store, gpa: Allocator, persist: Persistence, opts: Options) StoreError!void {
        var builtins: [canned.len]Policy = undefined;
        var n: usize = 0;
        errdefer for (builtins[0..n]) |*p| p.deinit();
        for (canned) |c| {
            builtins[n] = try parsePolicy(gpa, c.document);
            n += 1;
        }
        const bytes = try persist.load(gpa);
        defer if (bytes) |b| gpa.free(b);
        const st = try State.load(gpa, bytes);
        self.* = .{ .gpa = gpa, .persist = persist, .opts = opts, .state = st, .builtins = builtins, .digest = digestOf(bytes) };
    }

    fn digestOf(bytes: ?[]const u8) [32]u8 {
        var d: [32]u8 = @splat(0);
        if (bytes) |b| std.crypto.hash.sha2.Sha256.hash(b, &d, .{});
        return d;
    }

    /// Picks up changes another process saved. Cheap when nothing changed.
    pub fn reload(self: *Store) StoreError!void {
        const bytes = try self.persist.load(self.gpa);
        defer if (bytes) |b| self.gpa.free(b);
        self.lock.lock();
        defer self.lock.unlock();
        try self.swapIn(bytes);
    }

    /// Caller holds the write lock.
    fn swapIn(self: *Store, bytes: ?[]const u8) StoreError!void {
        const d = digestOf(bytes);
        if (std.mem.eql(u8, &d, &self.digest)) return;
        const st = try State.load(self.gpa, bytes);
        self.state.destroy(self.gpa);
        self.state = st;
        self.digest = d;
    }

    pub fn deinit(self: *Store) void {
        self.state.destroy(self.gpa);
        for (&self.builtins) |*p| p.deinit();
    }

    // ------------------------------------------------------------ credentials and authorization

    pub const SecretBuf = [limits.max_secret]u8;

    /// Secret for a usable (enabled, unexpired) access key, copied into `out`.
    pub fn secretFor(self: *Store, access_key: []const u8, now_s: i64, out: *SecretBuf) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const secret = self.usableSecret(access_key, now_s) orelse return null;
        if (secret.len > out.len) return null;
        @memcpy(out[0..secret.len], secret);
        return out[0..secret.len];
    }

    fn usableSecret(self: *Store, key: []const u8, now_s: i64) ?[]const u8 {
        if (self.isRoot(key)) return self.opts.root_secret;
        const st = self.state;
        if (st.user(key)) |u| return if (u.enabled) u.secret else null;
        const sa = st.serviceAccount(key) orelse return null;
        if (!self.serviceAccountUsable(sa, now_s)) return null;
        return sa.secret;
    }

    fn serviceAccountUsable(self: *Store, sa: *const ServiceAccount, now_s: i64) bool {
        if (!sa.enabled) return false;
        if (sa.expires_s) |e| if (now_s >= e) return false;
        if (self.isRoot(sa.parent)) return true;
        const parent = self.state.user(sa.parent) orelse return false;
        return parent.enabled;
    }

    fn isRoot(self: *const Store, key: []const u8) bool {
        return self.opts.root_access_key.len > 0 and std.mem.eql(u8, key, self.opts.root_access_key);
    }

    /// Resolves the identity's policies and evaluates. Unknown or disabled identities are denied.
    pub fn authorize(self: *Store, who: Identity, action: []const u8, resource: []const u8, ctx: *const context.Context) eval.Decision {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const st = self.state;
        const now_s = ctx.now_s orelse std.time.timestamp();
        var sfa = std.heap.stackFallback(2048, self.gpa);
        const a = sfa.get();
        var ids: std.ArrayList(*const Policy) = .empty;
        defer ids.deinit(a);
        var sessions: [2]*const Policy = undefined;
        var n_sess: usize = 0;
        var username: []const u8 = who.access_key;
        var root = false;

        if (who.federated_policies) |names| {
            var it = std.mem.tokenizeScalar(u8, names, ',');
            while (it.next()) |n| if (self.policyByName(n)) |p| ids.append(a, p) catch return .implicit_deny;
        } else if (self.isRoot(who.access_key)) {
            root = true;
        } else if (st.user(who.access_key)) |u| {
            if (!u.enabled) return .implicit_deny;
            self.collectUserPolicies(a, u, &ids) catch return .implicit_deny;
        } else if (st.serviceAccount(who.access_key)) |sa| {
            if (!self.serviceAccountUsable(sa, now_s)) return .implicit_deny;
            username = sa.parent;
            if (self.isRoot(sa.parent)) {
                ids.append(a, &self.builtins[cannedIndex("consoleAdmin").?]) catch return .implicit_deny;
            } else {
                const parent = st.user(sa.parent) orelse return .implicit_deny;
                self.collectUserPolicies(a, parent, &ids) catch return .implicit_deny;
            }
            if (st.sa_policies.getPtr(sa.access_key)) |p| {
                sessions[n_sess] = p;
                n_sess += 1;
            }
        } else return .implicit_deny;

        if (who.session_policy) |p| {
            sessions[n_sess] = p;
            n_sess += 1;
        }
        // A root session with a session policy is narrowed like any other session.
        if (root and n_sess == 0) return .allow;
        if (root) ids.append(a, &self.builtins[cannedIndex("consoleAdmin").?]) catch return .implicit_deny;

        var arn_buf: [256]u8 = undefined;
        const arn = std.fmt.bufPrint(&arn_buf, "arn:aws:iam::{s}:user/{s}", .{ self.opts.account, username }) catch "";
        const principal: eval.Principal = .{
            .account = self.opts.account,
            .arn = arn,
            .username = username,
            .userid = who.access_key,
            .identity_policies = ids.items,
            .session_policies = sessions[0..n_sess],
        };
        return eval.authorize(&principal, action, resource, ctx);
    }

    fn collectUserPolicies(self: *Store, a: Allocator, u: *const User, out: *std.ArrayList(*const Policy)) Allocator.Error!void {
        for (u.policies) |name| if (self.policyByName(name)) |p| try out.append(a, p);
        for (self.state.snap.groups) |g| {
            if (!g.enabled or !containsName(g.members, u.name)) continue;
            for (g.policies) |name| if (self.policyByName(name)) |p| try out.append(a, p);
        }
    }

    fn policyByName(self: *Store, name: []const u8) ?*const Policy {
        if (cannedIndex(name)) |i| return &self.builtins[i];
        return self.state.policies.getPtr(name);
    }

    // ------------------------------------------------------------ queries

    /// Names of all entities of `kind`; caller frees with `freeNames`.
    pub fn list(self: *Store, gpa: Allocator, kind: ListKind) Allocator.Error![][]u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const s = self.state.snap;
        var out: std.ArrayList([]u8) = .empty;
        errdefer freeNames(gpa, out.items);
        errdefer out.deinit(gpa);
        switch (kind) {
            .users => for (s.users) |x| try out.append(gpa, try gpa.dupe(u8, x.name)),
            .groups => for (s.groups) |x| try out.append(gpa, try gpa.dupe(u8, x.name)),
            .service_accounts => for (s.service_accounts) |x| try out.append(gpa, try gpa.dupe(u8, x.access_key)),
            .policies => {
                for (canned) |c| try out.append(gpa, try gpa.dupe(u8, c.name));
                for (s.policies) |x| try out.append(gpa, try gpa.dupe(u8, x.name));
            },
        }
        return out.toOwnedSlice(gpa);
    }

    pub fn freeNames(gpa: Allocator, names: []const []u8) void {
        for (names) |n| gpa.free(n);
        gpa.free(names);
    }

    // ------------------------------------------------------------ mutations

    pub fn createUser(self: *Store, name: []const u8, secret: []const u8) StoreError!void {
        try validName(name);
        try validSecret(secret);
        var m = try self.begin();
        defer m.end();
        if (self.keyTaken(name)) return error.AlreadyExists;
        var next = self.state.snap;
        next.users = try appendOne(m.a(), User, next.users, .{ .name = name, .secret = secret });
        try self.commit(next);
    }

    /// Also removes the user's group memberships and service accounts.
    pub fn deleteUser(self: *Store, name: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const a = m.a();
        const i = self.state.users.get(name) orelse return error.NotFound;
        var next = self.state.snap;
        next.users = try removeAt(a, User, next.users, i);
        const groups = try a.dupe(Group, next.groups);
        for (groups) |*g| g.members = try removeName(a, g.members, name);
        next.groups = groups;
        var sas: std.ArrayList(ServiceAccount) = .empty;
        for (next.service_accounts) |sa| if (!std.mem.eql(u8, sa.parent, name)) try sas.append(a, sa);
        next.service_accounts = sas.items;
        try self.commit(next);
    }

    pub fn setUserEnabled(self: *Store, name: []const u8, enabled: bool) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.users.get(name) orelse return error.NotFound;
        var next = self.state.snap;
        const users = try m.a().dupe(User, next.users);
        users[i].enabled = enabled;
        next.users = users;
        try self.commit(next);
    }

    pub fn setUserSecret(self: *Store, name: []const u8, secret: []const u8) StoreError!void {
        try validSecret(secret);
        var m = try self.begin();
        defer m.end();
        const i = self.state.users.get(name) orelse return error.NotFound;
        var next = self.state.snap;
        const users = try m.a().dupe(User, next.users);
        users[i].secret = secret;
        next.users = users;
        try self.commit(next);
    }

    pub fn createGroup(self: *Store, name: []const u8) StoreError!void {
        try validName(name);
        var m = try self.begin();
        defer m.end();
        if (self.state.groupIndex(name) != null) return error.AlreadyExists;
        var next = self.state.snap;
        next.groups = try appendOne(m.a(), Group, next.groups, .{ .name = name });
        try self.commit(next);
    }

    pub fn deleteGroup(self: *Store, name: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.groupIndex(name) orelse return error.NotFound;
        var next = self.state.snap;
        next.groups = try removeAt(m.a(), Group, next.groups, i);
        try self.commit(next);
    }

    pub fn setGroupEnabled(self: *Store, name: []const u8, enabled: bool) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.groupIndex(name) orelse return error.NotFound;
        var next = self.state.snap;
        const groups = try m.a().dupe(Group, next.groups);
        groups[i].enabled = enabled;
        next.groups = groups;
        try self.commit(next);
    }

    pub fn addGroupMember(self: *Store, group: []const u8, user: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.groupIndex(group) orelse return error.NotFound;
        if (self.state.user(user) == null) return error.NotFound;
        if (containsName(self.state.snap.groups[i].members, user)) return;
        var next = self.state.snap;
        const groups = try m.a().dupe(Group, next.groups);
        groups[i].members = try appendOne(m.a(), []const u8, groups[i].members, user);
        next.groups = groups;
        try self.commit(next);
    }

    pub fn removeGroupMember(self: *Store, group: []const u8, user: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.groupIndex(group) orelse return error.NotFound;
        if (!containsName(self.state.snap.groups[i].members, user)) return error.NotFound;
        var next = self.state.snap;
        const groups = try m.a().dupe(Group, next.groups);
        groups[i].members = try removeName(m.a(), groups[i].members, user);
        next.groups = groups;
        try self.commit(next);
    }

    /// Creates or replaces a named policy after validating it.
    pub fn putPolicy(self: *Store, name: []const u8, document: []const u8) StoreError!void {
        try validName(name);
        if (cannedIndex(name) != null) return error.BuiltinPolicy;
        var check = try parsePolicy(self.gpa, document);
        check.deinit();
        var m = try self.begin();
        defer m.end();
        var next = self.state.snap;
        const doc: PolicyDoc = .{ .name = name, .document = document };
        for (next.policies, 0..) |p, i| {
            if (!std.mem.eql(u8, p.name, name)) continue;
            const ps = try m.a().dupe(PolicyDoc, next.policies);
            ps[i] = doc;
            next.policies = ps;
            return self.commit(next);
        }
        next.policies = try appendOne(m.a(), PolicyDoc, next.policies, doc);
        try self.commit(next);
    }

    pub fn deletePolicy(self: *Store, name: []const u8) StoreError!void {
        if (cannedIndex(name) != null) return error.BuiltinPolicy;
        var m = try self.begin();
        defer m.end();
        const s = self.state.snap;
        const idx = for (s.policies, 0..) |p, i| {
            if (std.mem.eql(u8, p.name, name)) break i;
        } else return error.PolicyNotFound;
        for (s.users) |u| if (containsName(u.policies, name)) return error.PolicyInUse;
        for (s.groups) |g| if (containsName(g.policies, name)) return error.PolicyInUse;
        for (s.ldap_mappings) |l| if (containsName(l.policies, name)) return error.PolicyInUse;
        var next = s;
        next.policies = try removeAt(m.a(), PolicyDoc, s.policies, idx);
        try self.commit(next);
    }

    pub fn attachPolicy(self: *Store, target: AttachTarget, name: []const u8, policy_name: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        if (self.policyByName(policy_name) == null) return error.PolicyNotFound;
        const a = m.a();
        var next = self.state.snap;
        switch (target) {
            .user => {
                const i = self.state.users.get(name) orelse return error.NotFound;
                const cur = next.users[i].policies;
                if (containsName(cur, policy_name)) return;
                if (cur.len >= limits.max_attached) return error.LimitExceeded;
                const users = try a.dupe(User, next.users);
                users[i].policies = try appendOne(a, []const u8, cur, policy_name);
                next.users = users;
            },
            .group => {
                const i = self.state.groupIndex(name) orelse return error.NotFound;
                const cur = next.groups[i].policies;
                if (containsName(cur, policy_name)) return;
                if (cur.len >= limits.max_attached) return error.LimitExceeded;
                const groups = try a.dupe(Group, next.groups);
                groups[i].policies = try appendOne(a, []const u8, cur, policy_name);
                next.groups = groups;
            },
        }
        try self.commit(next);
    }

    pub fn detachPolicy(self: *Store, target: AttachTarget, name: []const u8, policy_name: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const a = m.a();
        var next = self.state.snap;
        switch (target) {
            .user => {
                const i = self.state.users.get(name) orelse return error.NotFound;
                if (!containsName(next.users[i].policies, policy_name)) return error.PolicyNotFound;
                const users = try a.dupe(User, next.users);
                users[i].policies = try removeName(a, users[i].policies, policy_name);
                next.users = users;
            },
            .group => {
                const i = self.state.groupIndex(name) orelse return error.NotFound;
                if (!containsName(next.groups[i].policies, policy_name)) return error.PolicyNotFound;
                const groups = try a.dupe(Group, next.groups);
                groups[i].policies = try removeName(a, groups[i].policies, policy_name);
                next.groups = groups;
            },
        }
        try self.commit(next);
    }

    pub fn createServiceAccount(self: *Store, sa: ServiceAccount) StoreError!void {
        try validName(sa.access_key);
        try validSecret(sa.secret);
        if (sa.policy) |doc| {
            var check = try parsePolicy(self.gpa, doc);
            check.deinit();
        }
        var m = try self.begin();
        defer m.end();
        if (self.keyTaken(sa.access_key)) return error.AlreadyExists;
        if (!self.isRoot(sa.parent) and self.state.user(sa.parent) == null) return error.NotFound;
        var next = self.state.snap;
        next.service_accounts = try appendOne(m.a(), ServiceAccount, next.service_accounts, sa);
        try self.commit(next);
    }

    pub fn deleteServiceAccount(self: *Store, access_key: []const u8) StoreError!void {
        var m = try self.begin();
        defer m.end();
        const i = self.state.service_accounts.get(access_key) orelse return error.NotFound;
        var next = self.state.snap;
        next.service_accounts = try removeAt(m.a(), ServiceAccount, next.service_accounts, i);
        try self.commit(next);
    }

    pub const ServiceAccountUpdate = struct {
        secret: ?[]const u8 = null,
        enabled: ?bool = null,
        /// Outer null keeps the policy; `.{ .set = null }` clears it.
        policy: ?struct { set: ?[]const u8 } = null,
        expires_s: ?i64 = null,
        name: ?[]const u8 = null,
        description: ?[]const u8 = null,
    };

    pub fn updateServiceAccount(self: *Store, access_key: []const u8, u: ServiceAccountUpdate) StoreError!void {
        if (u.secret) |s| try validSecret(s);
        if (u.policy) |p| if (p.set) |doc| {
            var check = try parsePolicy(self.gpa, doc);
            check.deinit();
        };
        var m = try self.begin();
        defer m.end();
        const i = self.state.service_accounts.get(access_key) orelse return error.NotFound;
        var next = self.state.snap;
        const sas = try m.a().dupe(ServiceAccount, next.service_accounts);
        const sa = &sas[i];
        if (u.secret) |s| sa.secret = s;
        if (u.enabled) |e| sa.enabled = e;
        if (u.policy) |p| sa.policy = p.set;
        if (u.expires_s) |e| sa.expires_s = e;
        if (u.name) |n| sa.name = n;
        if (u.description) |d| sa.description = d;
        next.service_accounts = sas;
        try self.commit(next);
    }

    /// Replaces the full policy list of a user or group in one commit.
    pub fn setPolicies(self: *Store, target: AttachTarget, name: []const u8, names: []const []const u8) StoreError!void {
        if (names.len > limits.max_attached) return error.LimitExceeded;
        var m = try self.begin();
        defer m.end();
        const a = m.a();
        var uniq: std.ArrayList([]const u8) = .empty;
        for (names) |p| {
            if (self.policyByName(p) == null) return error.PolicyNotFound;
            if (!containsName(uniq.items, p)) try uniq.append(a, p);
        }
        var next = self.state.snap;
        switch (target) {
            .user => {
                const i = self.state.users.get(name) orelse return error.NotFound;
                const users = try a.dupe(User, next.users);
                users[i].policies = uniq.items;
                next.users = users;
            },
            .group => {
                const i = self.state.groupIndex(name) orelse return error.NotFound;
                const groups = try a.dupe(Group, next.groups);
                groups[i].policies = uniq.items;
                next.groups = groups;
            },
        }
        try self.commit(next);
    }

    /// Creates the user, or replaces the secret and status of an existing one.
    pub fn upsertUser(self: *Store, name: []const u8, secret: []const u8, enabled: bool) StoreError!void {
        try validName(name);
        try validSecret(secret);
        var m = try self.begin();
        defer m.end();
        var next = self.state.snap;
        if (self.state.users.get(name)) |i| {
            const users = try m.a().dupe(User, next.users);
            users[i].secret = secret;
            users[i].enabled = enabled;
            next.users = users;
        } else {
            if (self.keyTaken(name)) return error.AlreadyExists;
            next.users = try appendOne(m.a(), User, next.users, .{ .name = name, .secret = secret, .enabled = enabled });
        }
        try self.commit(next);
    }

    /// Adds members (creating the group), or removes them. Removing no members
    /// deletes the group, which must then be empty. One commit either way.
    pub fn updateGroupMembers(self: *Store, group: []const u8, members: []const []const u8, remove: bool) StoreError!void {
        try validName(group);
        var m = try self.begin();
        defer m.end();
        const a = m.a();
        var next = self.state.snap;
        const idx = self.state.groupIndex(group);
        if (remove) {
            const i = idx orelse return error.NotFound;
            if (members.len == 0) {
                if (next.groups[i].members.len != 0) return error.GroupNotEmpty;
                next.groups = try removeAt(a, Group, next.groups, i);
                return self.commit(next);
            }
            const groups = try a.dupe(Group, next.groups);
            for (members) |u| {
                if (!containsName(groups[i].members, u)) return error.NotFound;
                groups[i].members = try removeName(a, groups[i].members, u);
            }
            next.groups = groups;
            return self.commit(next);
        }
        for (members) |u| if (self.state.user(u) == null) return error.NotFound;
        var groups = next.groups;
        const i = idx orelse blk: {
            groups = try appendOne(a, Group, groups, .{ .name = group });
            break :blk groups.len - 1;
        };
        const out = try a.dupe(Group, groups);
        for (members) |u| if (!containsName(out[i].members, u)) {
            out[i].members = try appendOne(a, []const u8, out[i].members, u);
        };
        next.groups = out;
        try self.commit(next);
    }

    /// Applies `f` to a copy of the latest snapshot and commits it. `f` allocates
    /// from the given arena; lets feature modules add mutations without new store code.
    pub fn mutate(self: *Store, ctx: anytype, comptime f: fn (@TypeOf(ctx), Allocator, *Snapshot) StoreError!void) StoreError!void {
        var m = try self.begin();
        defer m.end();
        var next = self.state.snap;
        try f(ctx, m.a(), &next);
        try self.commit(next);
    }

    /// True when `name` is a canned or stored policy.
    pub fn policyExists(self: *Store, name: []const u8) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.policyByName(name) != null;
    }

    /// Tenant of a user, or of a service account's parent; null for global identities.
    pub fn tenantOf(self: *Store, access_key: []const u8, out: *[limits.max_name]u8) ?[]const u8 {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const st = self.state;
        const name = if (st.serviceAccount(access_key)) |sa| sa.parent else access_key;
        const u = st.user(name) orelse return null;
        const t = u.tenant orelse return null;
        if (t.len > out.len) return null;
        @memcpy(out[0..t.len], t);
        return out[0..t.len];
    }

    /// Read-locked access to the current snapshot; call `release` when done.
    pub const View = struct {
        store: *Store,
        snap: *const Snapshot,

        pub fn release(v: View) void {
            v.store.lock.unlockShared();
        }
        pub fn user(v: View, name: []const u8) ?*const User {
            return v.store.state.user(name);
        }
        pub fn serviceAccount(v: View, key: []const u8) ?*const ServiceAccount {
            return v.store.state.serviceAccount(key);
        }
        pub fn group(v: View, name: []const u8) ?*const Group {
            const i = v.store.state.groupIndex(name) orelse return null;
            return &v.snap.groups[i];
        }
        /// Document of a canned or stored policy.
        pub fn policyDocument(v: View, name: []const u8) ?[]const u8 {
            if (cannedIndex(name)) |i| return canned[i].document;
            for (v.snap.policies) |p| if (std.mem.eql(u8, p.name, name)) return p.document;
            return null;
        }
        pub fn isRoot(v: View, key: []const u8) bool {
            return v.store.isRoot(key);
        }
    };

    pub fn view(self: *Store) View {
        self.lock.lockShared();
        return .{ .store = self, .snap = &self.state.snap };
    }

    fn keyTaken(self: *Store, key: []const u8) bool {
        return self.isRoot(key) or self.state.users.contains(key) or self.state.service_accounts.contains(key);
    }

    const Mutation = struct {
        store: *Store,
        arena: std.heap.ArenaAllocator,
        fn a(m: *Mutation) Allocator {
            return m.arena.allocator();
        }
        fn end(m: *Mutation) void {
            m.arena.deinit();
            m.store.lock.unlock();
            if (m.store.persist.vtable.unlock) |f| f(m.store.persist.ptr);
        }
    };

    /// Shared stores: lock across processes and start from the latest saved state.
    fn begin(self: *Store) StoreError!Mutation {
        if (self.persist.vtable.lock) |f| try f(self.persist.ptr);
        errdefer if (self.persist.vtable.unlock) |f| f(self.persist.ptr);
        var fresh: ?[]u8 = null;
        if (self.persist.shared()) fresh = try self.persist.load(self.gpa);
        defer if (fresh) |b| self.gpa.free(b);
        self.lock.lock();
        if (self.persist.shared()) self.swapIn(fresh) catch |e| {
            self.lock.unlock();
            return e;
        };
        return .{ .store = self, .arena = .init(self.gpa) };
    }

    /// Serializes, reloads (validating), persists, then swaps. Caller holds the write lock.
    fn commit(self: *Store, next: Snapshot) StoreError!void {
        const bytes = try std.json.Stringify.valueAlloc(self.gpa, next, .{ .emit_null_optional_fields = false });
        defer self.gpa.free(bytes);
        const st = try State.load(self.gpa, bytes);
        errdefer st.destroy(self.gpa);
        try self.persist.save(bytes);
        self.state.destroy(self.gpa);
        self.state = st;
        self.digest = digestOf(bytes);
    }
};

fn validName(name: []const u8) StoreError!void {
    if (name.len < 1 or name.len > limits.max_name) return error.InvalidName;
    for (name) |c| {
        const ok = std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "+=,.@_-", c) != null;
        if (!ok) return error.InvalidName;
    }
}

fn validSecret(secret: []const u8) StoreError!void {
    if (secret.len < limits.min_secret or secret.len > limits.max_secret) return error.InvalidSecret;
    for (secret) |c| if (c < 0x21 or c > 0x7e) return error.InvalidSecret;
}

fn containsName(list: []const []const u8, name: []const u8) bool {
    for (list) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

fn appendOne(a: Allocator, comptime T: type, items: []const T, item: T) Allocator.Error![]const T {
    const out = try a.alloc(T, items.len + 1);
    @memcpy(out[0..items.len], items);
    out[items.len] = item;
    return out;
}

fn removeAt(a: Allocator, comptime T: type, items: []const T, i: usize) Allocator.Error![]const T {
    const out = try a.alloc(T, items.len - 1);
    @memcpy(out[0..i], items[0..i]);
    @memcpy(out[i..], items[i + 1 ..]);
    return out;
}

fn removeName(a: Allocator, items: []const []const u8, name: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (items) |n| if (!std.mem.eql(u8, n, name)) try out.append(a, n);
    return out.items;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const root_opts: Options = .{ .account = "123456789012", .root_access_key = "rootkey", .root_secret = "rootsecret" };

fn decide(s: *Store, who: Identity, action: []const u8, resource: []const u8) eval.Decision {
    const ctx: context.Context = .{ .now_s = 1000 };
    return s.authorize(who, action, resource, &ctx);
}

test "users, groups, attachments, and persistence round trip" {
    var mem: MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(testing.allocator, mem.persistence(), root_opts);
    {
        defer s.deinit();
        try s.createUser("alice", "alicesecret");
        try testing.expectError(error.AlreadyExists, s.createUser("alice", "alicesecret"));
        try testing.expectError(error.AlreadyExists, s.createUser("rootkey", "whatever1"));
        try testing.expectError(error.InvalidName, s.createUser("bad/name", "whatever1"));
        try testing.expectError(error.InvalidSecret, s.createUser("bob", "short"));
        try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "alice" }, "s3:GetObject", "arn:aws:s3:::b/k"));

        try s.attachPolicy(.user, "alice", "readonly");
        try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "alice" }, "s3:GetObject", "arn:aws:s3:::b/k"));
        try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "alice" }, "s3:PutObject", "arn:aws:s3:::b/k"));

        try s.createGroup("writers");
        try s.attachPolicy(.group, "writers", "writeonly");
        try s.addGroupMember("writers", "alice");
        try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "alice" }, "s3:PutObject", "arn:aws:s3:::b/k"));
        try s.setGroupEnabled("writers", false);
        try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "alice" }, "s3:PutObject", "arn:aws:s3:::b/k"));
        try s.setGroupEnabled("writers", true);

        try s.putPolicy("no-delete",
            \\{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:Delete*","Resource":"*"}]}
        );
        try testing.expectError(error.InvalidPolicy, s.putPolicy("broken", "{"));
        try testing.expectError(error.BuiltinPolicy, s.putPolicy("readonly", "{}"));
        try testing.expectError(error.PolicyNotFound, s.attachPolicy(.user, "alice", "nope"));
        try s.attachPolicy(.user, "alice", "readwrite");
        try s.attachPolicy(.user, "alice", "no-delete");
        try testing.expectEqual(eval.Decision.explicit_deny, decide(&s, .{ .access_key = "alice" }, "s3:DeleteObject", "arn:aws:s3:::b/k"));
        try testing.expectError(error.PolicyInUse, s.deletePolicy("no-delete"));
        try testing.expectError(error.BuiltinPolicy, s.deletePolicy("readwrite"));
    }
    // Reopen from persisted bytes: state survives.
    var s2: Store = undefined;
    try s2.open(testing.allocator, mem.persistence(), root_opts);
    defer s2.deinit();
    try testing.expectEqual(eval.Decision.explicit_deny, decide(&s2, .{ .access_key = "alice" }, "s3:DeleteObject", "arn:aws:s3:::b/k"));
    try testing.expectEqual(eval.Decision.allow, decide(&s2, .{ .access_key = "alice" }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try s2.detachPolicy(.user, "alice", "no-delete");
    try s2.deletePolicy("no-delete");
    try testing.expectEqual(eval.Decision.allow, decide(&s2, .{ .access_key = "alice" }, "s3:DeleteObject", "arn:aws:s3:::b/k"));

    const users = try s2.list(testing.allocator, .users);
    defer Store.freeNames(testing.allocator, users);
    try testing.expectEqual(@as(usize, 1), users.len);
    const pols = try s2.list(testing.allocator, .policies);
    defer Store.freeNames(testing.allocator, pols);
    try testing.expectEqual(canned.len, pols.len);

    try s2.setUserEnabled("alice", false);
    var sb: Store.SecretBuf = undefined;
    try testing.expect(s2.secretFor("alice", 0, &sb) == null);
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s2, .{ .access_key = "alice" }, "s3:GetObject", "arn:aws:s3:::b/k"));
    try s2.deleteUser("alice");
    try testing.expectError(error.NotFound, s2.deleteUser("alice"));
}

test "service accounts inherit and narrow parent rights" {
    var mem: MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(testing.allocator, mem.persistence(), root_opts);
    defer s.deinit();
    try s.createUser("alice", "alicesecret");
    try s.attachPolicy(.user, "alice", "readwrite");
    try s.createServiceAccount(.{ .access_key = "svc1", .secret = "svc1secret", .parent = "alice" });
    try s.createServiceAccount(.{ .access_key = "svc2", .secret = "svc2secret", .parent = "alice", .expires_s = 500, .policy = 
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}
    });
    try s.createServiceAccount(.{ .access_key = "svc3", .secret = "svc3secret", .parent = "alice", .policy = 
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}
    });
    try testing.expectError(error.NotFound, s.createServiceAccount(.{ .access_key = "svc4", .secret = "svc4secret", .parent = "ghost" }));
    try testing.expectError(error.AlreadyExists, s.createServiceAccount(.{ .access_key = "alice", .secret = "svc4secret", .parent = "alice" }));

    var sb: Store.SecretBuf = undefined;
    try testing.expectEqualStrings("svc1secret", s.secretFor("svc1", 1000, &sb).?);
    try testing.expect(s.secretFor("svc2", 1000, &sb) == null);
    try testing.expectEqualStrings("rootsecret", s.secretFor("rootkey", 1000, &sb).?);
    try testing.expect(s.secretFor("nobody", 1000, &sb) == null);

    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "svc1" }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "svc2" }, "s3:GetObject", "arn:aws:s3:::pub/k"));
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "svc3" }, "s3:GetObject", "arn:aws:s3:::pub/k"));
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "svc3" }, "s3:PutObject", "arn:aws:s3:::pub/k"));

    try s.setUserEnabled("alice", false);
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "svc1" }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try s.setUserEnabled("alice", true);

    try s.deleteUser("alice");
    const sas = try s.list(testing.allocator, .service_accounts);
    defer Store.freeNames(testing.allocator, sas);
    try testing.expectEqual(@as(usize, 0), sas.len);
}

test "root bypass and root sessions" {
    var mem: MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(testing.allocator, mem.persistence(), root_opts);
    defer s.deinit();
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "rootkey" }, "admin:ServerInfo", "*"));
    var p = try policy.parse(testing.allocator,
        \\{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
    );
    defer p.deinit();
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "rootkey", .session_policy = &p }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "rootkey", .session_policy = &p }, "s3:GetObject", "arn:aws:s3:::b/k"));
    try s.createServiceAccount(.{ .access_key = "rootsvc", .secret = "rootsvcsecret", .parent = "rootkey" });
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "rootsvc" }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try testing.expectEqual(eval.Decision.implicit_deny, decide(&s, .{ .access_key = "unknown" }, "s3:GetObject", "arn:aws:s3:::b/k"));
}

test "failed persist leaves state unchanged" {
    var mem: MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(testing.allocator, mem.persistence(), root_opts);
    defer s.deinit();
    mem.fail_saves = true;
    try testing.expectError(error.PersistFailed, s.createUser("alice", "alicesecret"));
    mem.fail_saves = false;
    var sb: Store.SecretBuf = undefined;
    try testing.expect(s.secretFor("alice", 0, &sb) == null);
    try s.createUser("alice", "alicesecret");
    try testing.expect(s.secretFor("alice", 0, &sb) != null);
}

test "corrupt and future-format stores are rejected" {
    const Case = struct { bytes: []const u8, err: StoreError };
    const cases = [_]Case{
        .{ .bytes = "garbage", .err = error.CorruptStore },
        .{ .bytes = "{\"format\":99}", .err = error.UnsupportedFormat },
        .{ .bytes = "{\"users\":[{\"name\":\"a\",\"secret\":\"12345678\"},{\"name\":\"a\",\"secret\":\"12345678\"}]}", .err = error.CorruptStore },
        .{ .bytes = "{\"policies\":[{\"name\":\"p\",\"document\":\"{}\"}]}", .err = error.InvalidPolicy },
    };
    for (cases) |c| {
        var mem: MemoryPersistence = .{ .gpa = testing.allocator, .data = try testing.allocator.dupe(u8, c.bytes) };
        defer mem.deinit();
        var s: Store = undefined;
        try testing.expectError(c.err, s.open(testing.allocator, mem.persistence(), .{}));
    }
}

test "file persistence is atomic and reloadable" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var fp: FilePersistence = .{ .dir = tmp.dir };
    {
        var s: Store = undefined;
        try s.open(testing.allocator, fp.persistence(), .{});
        defer s.deinit();
        try s.createUser("alice", "alicesecret");
        try s.attachPolicy(.user, "alice", "readonly");
    }
    var s: Store = undefined;
    try s.open(testing.allocator, fp.persistence(), .{});
    defer s.deinit();
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "alice" }, "s3:GetObject", "arn:aws:s3:::b/k"));
    var it = tmp.dir.iterate();
    var files: usize = 0;
    while (try it.next()) |_| files += 1;
    try testing.expectEqual(@as(usize, 1), files);
}

test "admin mutations: upsert, group membership, policy sets, service account updates" {
    var mem: MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var s: Store = undefined;
    try s.open(testing.allocator, mem.persistence(), root_opts);
    defer s.deinit();
    try s.upsertUser("bob", "bobsecret1", true);
    try s.upsertUser("bob", "bobsecret2", false);
    try testing.expectError(error.AlreadyExists, s.upsertUser("rootkey", "whatever1", true));
    var sb: Store.SecretBuf = undefined;
    try testing.expect(s.secretFor("bob", 0, &sb) == null);
    try s.setUserEnabled("bob", true);
    try testing.expectEqualStrings("bobsecret2", s.secretFor("bob", 0, &sb).?);

    try s.updateGroupMembers("ops", &.{"bob"}, false);
    try testing.expectError(error.NotFound, s.updateGroupMembers("ops", &.{"ghost"}, false));
    try testing.expectError(error.GroupNotEmpty, s.updateGroupMembers("ops", &.{}, true));
    try s.setPolicies(.group, "ops", &.{ "readonly", "readonly", "writeonly" });
    {
        const v = s.view();
        defer v.release();
        try testing.expectEqual(@as(usize, 2), v.group("ops").?.policies.len);
    }
    try testing.expectEqual(eval.Decision.allow, decide(&s, .{ .access_key = "bob" }, "s3:PutObject", "arn:aws:s3:::b/k"));
    try s.updateGroupMembers("ops", &.{"bob"}, true);
    try s.updateGroupMembers("ops", &.{}, true);
    try testing.expectError(error.PolicyNotFound, s.setPolicies(.user, "bob", &.{"nope"}));

    try s.createServiceAccount(.{ .access_key = "svcbob", .secret = "svcsecret1", .parent = "bob" });
    try s.updateServiceAccount("svcbob", .{ .enabled = false, .name = "ci" });
    try testing.expect(s.secretFor("svcbob", 0, &sb) == null);
    try s.updateServiceAccount("svcbob", .{ .enabled = true, .secret = "svcsecret2", .policy = .{ .set = 
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
    } });
    try testing.expectEqualStrings("svcsecret2", s.secretFor("svcbob", 0, &sb).?);
    try testing.expectError(error.InvalidPolicy, s.updateServiceAccount("svcbob", .{ .policy = .{ .set = "{}" } }));
    try s.updateServiceAccount("svcbob", .{ .policy = .{ .set = null } });
    try testing.expectError(error.NotFound, s.updateServiceAccount("ghost", .{}));
    const v = s.view();
    defer v.release();
    try testing.expectEqualStrings("ci", v.serviceAccount("svcbob").?.name.?);
    try testing.expect(v.serviceAccount("svcbob").?.policy == null);
}
