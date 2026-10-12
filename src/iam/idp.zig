//! External identity provider configuration: OpenID Connect providers and one LDAP
//! directory, stored as key/value settings in the IAM snapshot (so cluster nodes
//! share them) and optionally supplied through the environment.
const std = @import("std");
const store_mod = @import("store.zig");

const Allocator = std.mem.Allocator;
const Setting = store_mod.Setting;
const IdpConfig = store_mod.IdpConfig;
const Store = store_mod.Store;
const Snapshot = store_mod.Snapshot;
const StoreError = store_mod.StoreError;

pub const Kind = enum { openid, ldap };

/// Name used when a client gives none (`_` in the admin API).
pub const default_name = "_";

pub const limits = struct {
    pub const max_value = 2048;
    pub const max_providers = 16;
    pub const max_config_name = 64;
};

pub const openid_keys = [_][]const u8{
    "enable",      "config_url",     "client_id",            "client_secret", "claim_name",   "claim_prefix",
    "role_policy", "redirect_uri",   "redirect_uri_dynamic", "scopes",        "display_name", "comment",
    "vendor",      "claim_userinfo", "tenant",               "tenant_claim",  "user_claim",
};

pub const ldap_keys = [_][]const u8{
    "enable",                 "server_addr",           "lookup_bind_dn",       "lookup_bind_password",
    "user_dn_search_base_dn", "user_dn_search_filter", "group_search_base_dn", "group_search_filter",
    "tls_skip_verify",        "server_insecure",       "server_starttls",      "tls_ca_file",
    "comment",                "tenant",                "srv_record_name",      "tls_client_cert",
    "tls_client_key",
};

const secret_keys = [_][]const u8{ "client_secret", "lookup_bind_password" };

pub fn keysOf(kind: Kind) []const []const u8 {
    return switch (kind) {
        .openid => &openid_keys,
        .ldap => &ldap_keys,
    };
}

pub fn isSecret(key: []const u8) bool {
    for (secret_keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

pub const ParseError = error{ OutOfMemory, InvalidSyntax, UnknownKey, InvalidValue };

/// Parses `key=value key2="quoted value"` into settings; later duplicates win.
pub fn parseSettings(a: Allocator, kind: Kind, text: []const u8) ParseError![]const Setting {
    var out: std.ArrayList(Setting) = .empty;
    var i: usize = 0;
    while (true) {
        while (i < text.len and std.ascii.isWhitespace(text[i])) i += 1;
        if (i >= text.len) break;
        const ks = i;
        while (i < text.len and text[i] != '=' and !std.ascii.isWhitespace(text[i])) i += 1;
        if (i >= text.len or text[i] != '=') return error.InvalidSyntax;
        const key = text[ks..i];
        i += 1;
        var value: []const u8 = undefined;
        if (i < text.len and text[i] == '"') {
            const end = std.mem.indexOfScalarPos(u8, text, i + 1, '"') orelse return error.InvalidSyntax;
            value = text[i + 1 .. end];
            i = end + 1;
        } else {
            const vs = i;
            while (i < text.len and !std.ascii.isWhitespace(text[i])) i += 1;
            value = text[vs..i];
        }
        if (!known(kind, key)) return error.UnknownKey;
        if (value.len > limits.max_value) return error.InvalidValue;
        for (value) |c| if (c < 0x20 or c == 0x7f) return error.InvalidValue;
        try put(a, &out, key, value);
    }
    return out.items;
}

fn known(kind: Kind, key: []const u8) bool {
    for (keysOf(kind)) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

fn put(a: Allocator, list: *std.ArrayList(Setting), key: []const u8, value: []const u8) error{OutOfMemory}!void {
    for (list.items) |*s| if (std.mem.eql(u8, s.key, key)) {
        s.value = value;
        return;
    };
    try list.append(a, .{ .key = key, .value = value });
}

pub fn get(settings: []const Setting, key: []const u8) ?[]const u8 {
    for (settings) |s| if (std.mem.eql(u8, s.key, key)) return s.value;
    return null;
}

fn flag(settings: []const Setting, key: []const u8, default: bool) bool {
    const v = get(settings, key) orelse return default;
    return std.ascii.eqlIgnoreCase(v, "on") or std.ascii.eqlIgnoreCase(v, "true") or std.mem.eql(u8, v, "1");
}

/// Settings from `<prefix><KEY>` environment variables (e.g. ZKFSM_IDENTITY_OPENID_CLIENT_ID).
pub fn fromEnv(a: Allocator, kind: Kind, env: *const std.process.EnvMap) error{OutOfMemory}![]const Setting {
    const prefix = switch (kind) {
        .openid => "ZKFSM_IDENTITY_OPENID_",
        .ldap => "ZKFSM_IDENTITY_LDAP_",
    };
    var out: std.ArrayList(Setting) = .empty;
    for (keysOf(kind)) |k| {
        var buf: [96]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "{s}{s}", .{ prefix, k }) catch continue;
        for (name[prefix.len..]) |*c| c.* = std.ascii.toUpper(c.*);
        if (env.get(name)) |v| try out.append(a, .{ .key = k, .value = try a.dupe(u8, v) });
    }
    return out.items;
}

pub const ValidateError = error{ MissingKey, InvalidValue };

/// Checks that the settings describe a usable provider.
pub fn validate(kind: Kind, settings: []const Setting) ValidateError!void {
    switch (kind) {
        .openid => {
            const url = get(settings, "config_url") orelse return error.MissingKey;
            if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) return error.InvalidValue;
            if ((get(settings, "client_id") orelse "").len == 0) return error.MissingKey;
        },
        .ldap => {
            const addr = get(settings, "server_addr") orelse return error.MissingKey;
            if (std.mem.lastIndexOfScalar(u8, addr, ':') == null) return error.InvalidValue;
            if ((get(settings, "user_dn_search_base_dn") orelse "").len == 0) return error.MissingKey;
            const filter = get(settings, "user_dn_search_filter") orelse return error.MissingKey;
            if (std.mem.indexOf(u8, filter, "%s") == null) return error.InvalidValue;
            if ((get(settings, "lookup_bind_dn") orelse "").len == 0) return error.MissingKey;
        },
    }
}

// ---------------------------------------------------------------- typed views

pub const OpenId = struct {
    name: []const u8,
    enabled: bool,
    config_url: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    claim_name: []const u8,
    claim_prefix: []const u8,
    /// When set, every identity of this provider gets these policies (RoleArn mode).
    role_policy: []const u8,
    scopes: []const u8,
    redirect_uri: []const u8,
    user_claim: []const u8,
    tenant: []const u8,
    tenant_claim: []const u8,

    pub fn from(name: []const u8, s: []const Setting) OpenId {
        return .{
            .name = name,
            .enabled = flag(s, "enable", true),
            .config_url = get(s, "config_url") orelse "",
            .client_id = get(s, "client_id") orelse "",
            .client_secret = get(s, "client_secret") orelse "",
            .claim_name = get(s, "claim_name") orelse "policy",
            .claim_prefix = get(s, "claim_prefix") orelse "",
            .role_policy = get(s, "role_policy") orelse "",
            .scopes = get(s, "scopes") orelse "",
            .redirect_uri = get(s, "redirect_uri") orelse "",
            .user_claim = get(s, "user_claim") orelse "sub",
            .tenant = get(s, "tenant") orelse "",
            .tenant_claim = get(s, "tenant_claim") orelse "",
        };
    }

    /// Role ARN clients pass to pick a role-policy provider.
    pub fn roleArn(self: OpenId, buf: []u8) []const u8 {
        if (self.role_policy.len == 0) return "";
        return std.fmt.bufPrint(buf, "arn:zkfsm:iam:::role/{s}", .{self.name}) catch "";
    }
};

pub const Ldap = struct {
    enabled: bool,
    server_addr: []const u8,
    lookup_bind_dn: []const u8,
    lookup_bind_password: []const u8,
    user_dn_search_base_dn: []const u8,
    user_dn_search_filter: []const u8,
    group_search_base_dn: []const u8,
    group_search_filter: []const u8,
    tls_skip_verify: bool,
    /// Plain TCP without TLS.
    server_insecure: bool,
    server_starttls: bool,
    tls_ca_file: []const u8,
    tls_client_cert: []const u8,
    tls_client_key: []const u8,
    tenant: []const u8,

    pub fn from(s: []const Setting) Ldap {
        return .{
            .enabled = flag(s, "enable", true),
            .server_addr = get(s, "server_addr") orelse "",
            .lookup_bind_dn = get(s, "lookup_bind_dn") orelse "",
            .lookup_bind_password = get(s, "lookup_bind_password") orelse "",
            .user_dn_search_base_dn = get(s, "user_dn_search_base_dn") orelse "",
            .user_dn_search_filter = get(s, "user_dn_search_filter") orelse "",
            .group_search_base_dn = get(s, "group_search_base_dn") orelse "",
            .group_search_filter = get(s, "group_search_filter") orelse "",
            .tls_skip_verify = flag(s, "tls_skip_verify", false),
            .server_insecure = flag(s, "server_insecure", false),
            .server_starttls = flag(s, "server_starttls", false),
            .tls_ca_file = get(s, "tls_ca_file") orelse "",
            .tls_client_cert = get(s, "tls_client_cert") orelse "",
            .tls_client_key = get(s, "tls_client_key") orelse "",
            .tenant = get(s, "tenant") orelse "",
        };
    }
};

// ---------------------------------------------------------------- effective configuration

/// Environment-supplied providers; they appear as the default (`_`) config.
pub const EnvConfig = struct {
    openid: []const Setting = &.{},
    ldap: []const Setting = &.{},

    fn of(self: EnvConfig, kind: Kind) []const Setting {
        return switch (kind) {
            .openid => self.openid,
            .ldap => self.ldap,
        };
    }
};

pub const Entry = struct {
    name: []const u8,
    settings: []const Setting,
    /// Keys whose value came from the environment.
    env_keys: []const []const u8 = &.{},
};

/// Stored configs of `kind` merged with the environment (env values win), copied into `a`.
pub fn effective(a: Allocator, st: *Store, env: EnvConfig, kind: Kind) error{OutOfMemory}![]const Entry {
    var out: std.ArrayList(Entry) = .empty;
    {
        const v = st.view();
        defer v.release();
        for (v.snap.idp) |c| {
            if (!std.mem.eql(u8, c.kind, @tagName(kind))) continue;
            const ss = try a.alloc(Setting, c.settings.len);
            for (c.settings, ss) |s, *d| d.* = .{ .key = try a.dupe(u8, s.key), .value = try a.dupe(u8, s.value) };
            try out.append(a, .{ .name = try a.dupe(u8, c.name), .settings = ss });
        }
    }
    const es = env.of(kind);
    if (es.len == 0) return out.items;
    const idx = for (out.items, 0..) |e, i| {
        if (std.mem.eql(u8, e.name, default_name)) break i;
    } else blk: {
        try out.append(a, .{ .name = default_name, .settings = &.{} });
        break :blk out.items.len - 1;
    };
    var merged: std.ArrayList(Setting) = .empty;
    try merged.appendSlice(a, out.items[idx].settings);
    var keys: std.ArrayList([]const u8) = .empty;
    for (es) |s| {
        try put(a, &merged, s.key, s.value);
        try keys.append(a, s.key);
    }
    out.items[idx] = .{ .name = default_name, .settings = merged.items, .env_keys = keys.items };
    return out.items;
}

// ---------------------------------------------------------------- store mutations

pub const UpdateError = StoreError || error{ ConfigExists, ConfigNotFound, TooManyConfigs, InvalidConfigName, MissingKey, InvalidValue };

pub fn validConfigName(name: []const u8) bool {
    if (name.len == 0 or name.len > limits.max_config_name) return false;
    if (std.mem.eql(u8, name, default_name)) return true;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.') return false;
    return true;
}

/// Adds a config (`update` false: it must not exist) or merges settings into an existing
/// one (`update` true: it must exist). The merged result must validate.
pub fn upsert(st: *Store, kind: Kind, name: []const u8, settings: []const Setting, update: bool) UpdateError!void {
    if (!validConfigName(name)) return error.InvalidConfigName;
    if (kind == .ldap and !std.mem.eql(u8, name, default_name)) return error.InvalidConfigName;
    const Ctx = struct { kind: Kind, name: []const u8, settings: []const Setting, update: bool, err: ?UpdateError = null };
    var ctx: Ctx = .{ .kind = kind, .name = name, .settings = settings, .update = update };
    st.mutate(&ctx, struct {
        fn f(c: *Ctx, a: Allocator, next: *Snapshot) StoreError!void {
            const i = find(next.idp, c.kind, c.name);
            if (i != null and !c.update) return fail(c, error.ConfigExists);
            if (i == null and c.update) return fail(c, error.ConfigNotFound);
            var merged: std.ArrayList(Setting) = .empty;
            if (i) |x| try merged.appendSlice(a, next.idp[x].settings);
            for (c.settings) |s| try put(a, &merged, s.key, s.value);
            validate(c.kind, merged.items) catch |e| return fail(c, e);
            const list = try a.dupe(IdpConfig, next.idp);
            const cfg: IdpConfig = .{ .kind = @tagName(c.kind), .name = c.name, .settings = merged.items };
            if (i) |x| {
                list[x] = cfg;
                next.idp = list;
            } else {
                if (list.len >= limits.max_providers) return fail(c, error.TooManyConfigs);
                next.idp = try std.mem.concat(a, IdpConfig, &.{ list, &.{cfg} });
            }
        }
        fn fail(c: *Ctx, e: UpdateError) StoreError!void {
            c.err = e;
            return error.NotFound;
        }
    }.f) catch |e| return ctx.err orelse e;
}

pub fn remove(st: *Store, kind: Kind, name: []const u8) UpdateError!void {
    const Ctx = struct { kind: Kind, name: []const u8, missing: bool = false };
    var ctx: Ctx = .{ .kind = kind, .name = name };
    st.mutate(&ctx, struct {
        fn f(c: *Ctx, a: Allocator, next: *Snapshot) StoreError!void {
            const i = find(next.idp, c.kind, c.name) orelse {
                c.missing = true;
                return error.NotFound;
            };
            var list: std.ArrayList(IdpConfig) = .empty;
            for (next.idp, 0..) |x, j| if (j != i) try list.append(a, x);
            next.idp = list.items;
        }
    }.f) catch |e| return if (ctx.missing) error.ConfigNotFound else e;
}

fn find(list: []const IdpConfig, kind: Kind, name: []const u8) ?usize {
    for (list, 0..) |c, i| if (std.mem.eql(u8, c.kind, @tagName(kind)) and std.mem.eql(u8, c.name, name)) return i;
    return null;
}

// ---------------------------------------------------------------- LDAP policy mappings

/// Canonical DN form for comparisons: lowercase, no spaces around `,` `=` `+`.
pub fn normalizeDn(a: Allocator, dn: []const u8) error{OutOfMemory}![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    const trimmed = std.mem.trim(u8, dn, " ");
    while (i < trimmed.len) : (i += 1) {
        const c = trimmed[i];
        if (c == '\\' and i + 1 < trimmed.len) {
            try out.append(a, c);
            i += 1;
            try out.append(a, std.ascii.toLower(trimmed[i]));
            continue;
        }
        if (c == ' ') {
            var j = i;
            while (j < trimmed.len and trimmed[j] == ' ') j += 1;
            const next_sep = j < trimmed.len and std.mem.indexOfScalar(u8, ",=+", trimmed[j]) != null;
            const prev_sep = out.items.len > 0 and std.mem.indexOfScalar(u8, ",=+", out.items[out.items.len - 1]) != null;
            if (next_sep or prev_sep) {
                i = j - 1;
                continue;
            }
        }
        try out.append(a, std.ascii.toLower(c));
    }
    return out.items;
}

pub const MappingError = StoreError || error{ InvalidDn, NoChange };

pub const Change = struct { attached: []const []const u8, detached: []const []const u8 };

/// Attaches (or detaches) policies to a user or group DN in one commit.
pub fn associate(st: *Store, a: Allocator, dn: []const u8, group: bool, policies: []const []const u8, attach: bool) MappingError!Change {
    const norm = try normalizeDn(a, dn);
    if (norm.len == 0 or norm.len > 1024 or std.mem.indexOfScalar(u8, norm, '=') == null) return error.InvalidDn;
    for (policies) |p| if (attach and !st.policyExists(p)) return error.PolicyNotFound;
    const Ctx = struct { dn: []const u8, group: bool, policies: []const []const u8, attach: bool, changed: std.ArrayList([]const u8) = .empty, out: Allocator, none: bool = false };
    var ctx: Ctx = .{ .dn = norm, .group = group, .policies = policies, .attach = attach, .out = a };
    st.mutate(&ctx, struct {
        fn f(c: *Ctx, ma: Allocator, next: *Snapshot) StoreError!void {
            const list = try ma.dupe(store_mod.LdapMapping, next.ldap_mappings);
            const idx = for (list, 0..) |m, i| {
                if (m.group == c.group and std.mem.eql(u8, m.dn, c.dn)) break i;
            } else null;
            var cur: std.ArrayList([]const u8) = .empty;
            if (idx) |i| try cur.appendSlice(ma, list[i].policies);
            for (c.policies) |p| {
                const at = for (cur.items, 0..) |x, i| {
                    if (std.mem.eql(u8, x, p)) break i;
                } else null;
                if (c.attach and at == null) {
                    if (cur.items.len >= store_mod.limits.max_attached) return error.LimitExceeded;
                    try cur.append(ma, p);
                    try c.changed.append(c.out, try c.out.dupe(u8, p));
                } else if (!c.attach and at != null) {
                    _ = cur.orderedRemove(at.?);
                    try c.changed.append(c.out, try c.out.dupe(u8, p));
                }
            }
            if (c.changed.items.len == 0) {
                c.none = true;
                return error.NotFound;
            }
            const m: store_mod.LdapMapping = .{ .dn = c.dn, .group = c.group, .policies = cur.items };
            if (idx) |i| {
                if (cur.items.len == 0) {
                    var keep: std.ArrayList(store_mod.LdapMapping) = .empty;
                    for (list, 0..) |x, j| if (j != i) try keep.append(ma, x);
                    next.ldap_mappings = keep.items;
                } else {
                    list[i] = m;
                    next.ldap_mappings = list;
                }
            } else next.ldap_mappings = try std.mem.concat(ma, store_mod.LdapMapping, &.{ list, &.{m} });
        }
    }.f) catch |e| return if (ctx.none) error.NoChange else e;
    return if (attach) .{ .attached = ctx.changed.items, .detached = &.{} } else .{ .attached = &.{}, .detached = ctx.changed.items };
}

/// Policy names mapped to the user DN and any of its group DNs, de-duplicated, comma-joined.
pub fn ldapPolicies(a: Allocator, st: *Store, user_dn: []const u8, groups: []const []const u8) error{OutOfMemory}![]const u8 {
    const udn = try normalizeDn(a, user_dn);
    const gdns = try a.alloc([]const u8, groups.len);
    for (groups, gdns) |g, *d| d.* = try normalizeDn(a, g);
    var names: std.ArrayList([]const u8) = .empty;
    const v = st.view();
    defer v.release();
    for (v.snap.ldap_mappings) |m| {
        const hit = if (m.group) blk: {
            for (gdns) |g| if (std.mem.eql(u8, g, m.dn)) break :blk true;
            break :blk false;
        } else std.mem.eql(u8, m.dn, udn);
        if (!hit) continue;
        for (m.policies) |p| {
            for (names.items) |x| {
                if (std.mem.eql(u8, x, p)) break;
            } else try names.append(a, try a.dupe(u8, p));
        }
    }
    return std.mem.join(a, ",", names.items);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "settings grammar" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try parseSettings(a, .openid, "config_url=http://idp/.well-known/openid-configuration client_id=zk display_name=\"My IdP\" client_id=zk2");
    try testing.expectEqual(@as(usize, 3), s.len);
    try testing.expectEqualStrings("zk2", get(s, "client_id").?);
    try testing.expectEqualStrings("My IdP", get(s, "display_name").?);
    try testing.expectError(error.UnknownKey, parseSettings(a, .openid, "bogus=1"));
    try testing.expectError(error.InvalidSyntax, parseSettings(a, .openid, "client_id"));
    try testing.expectError(error.InvalidSyntax, parseSettings(a, .openid, "client_id=\"open"));
    try testing.expectError(error.UnknownKey, parseSettings(a, .ldap, "client_id=x"));
    try validate(.openid, s);
    try testing.expectError(error.MissingKey, validate(.openid, &.{}));
    const o = OpenId.from("_", s);
    try testing.expectEqualStrings("policy", o.claim_name);
    try testing.expect(o.enabled);
}

test "dn normalization" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("uid=alice,ou=people,dc=example,dc=org", try normalizeDn(a, " UID=Alice, ou = People,DC=example,dc=org "));
    try testing.expectEqualStrings("cn=a b,dc=x", try normalizeDn(a, "cn=A B,dc=x"));
}

test "idp configs and ldap mappings in the store" {
    var mem: store_mod.MemoryPersistence = .{ .gpa = testing.allocator };
    defer mem.deinit();
    var st: Store = undefined;
    try st.open(testing.allocator, mem.persistence(), .{ .root_access_key = "root" });
    defer st.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const s = try parseSettings(a, .openid, "config_url=https://idp.example/.well-known/openid-configuration client_id=zk");
    try upsert(&st, .openid, "corp", s, false);
    try testing.expectError(error.ConfigExists, upsert(&st, .openid, "corp", s, false));
    try testing.expectError(error.ConfigNotFound, upsert(&st, .openid, "other", s, true));
    try upsert(&st, .openid, "corp", try parseSettings(a, .openid, "claim_name=groups"), true);
    try testing.expectError(error.MissingKey, upsert(&st, .openid, "x", try parseSettings(a, .openid, "client_id=1"), false));
    try testing.expectError(error.InvalidConfigName, upsert(&st, .ldap, "named", &.{}, false));

    const env_s = try parseSettings(a, .openid, "client_id=fromenv config_url=http://e/x");
    const eff = try effective(a, &st, .{ .openid = env_s }, .openid);
    try testing.expectEqual(@as(usize, 2), eff.len);
    try testing.expectEqualStrings("groups", get(eff[0].settings, "claim_name").?);
    try testing.expectEqualStrings("fromenv", get(eff[1].settings, "client_id").?);
    try remove(&st, .openid, "corp");
    try testing.expectError(error.ConfigNotFound, remove(&st, .openid, "corp"));

    const ch = try associate(&st, a, "cn=devs,ou=groups,dc=example,dc=org", true, &.{ "readwrite", "readonly" }, true);
    try testing.expectEqual(@as(usize, 2), ch.attached.len);
    try testing.expectError(error.NoChange, associate(&st, a, "CN=devs, ou=groups,dc=example,dc=org", true, &.{"readwrite"}, true));
    try testing.expectError(error.PolicyNotFound, associate(&st, a, "uid=bob,dc=x", false, &.{"nope"}, true));
    _ = try associate(&st, a, "uid=bob,dc=x", false, &.{"writeonly"}, true);
    try testing.expectEqualStrings("readwrite,readonly,writeonly", try ldapPolicies(a, &st, "UID=bob,dc=x", &.{"cn=devs,ou=groups,dc=example,dc=org"}));
    try testing.expectEqualStrings("", try ldapPolicies(a, &st, "uid=eve,dc=x", &.{}));
    _ = try associate(&st, a, "uid=bob,dc=x", false, &.{"writeonly"}, false);
    try testing.expectEqualStrings("", try ldapPolicies(a, &st, "uid=bob,dc=x", &.{}));
}
