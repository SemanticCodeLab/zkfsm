//! zkfsm entry point: config parsing and wiring. The only file that sees every layer.
const std = @import("std");
const backend = @import("backend/root.zig");
const placement = @import("placement/root.zig");
const protection = @import("protection/root.zig");
const heal = @import("heal/root.zig");
const object = @import("object/root.zig");
const s3 = @import("s3/root.zig");
const metrics = @import("metrics/root.zig");
const iam = @import("iam/root.zig");
const admin = @import("admin/root.zig");
const admin_http = @import("admin_http.zig");
const tls = @import("tls/root.zig");
const cluster = @import("cluster/root.zig");
const gateway = @import("gateway/root.zig");
const replication = @import("replication/root.zig");
const events = @import("events/root.zig");
const sse = @import("sse/root.zig");
const batch = @import("batch/root.zig");

pub const std_options: std.Options = .{ .log_level = .info };

const usage =
    \\usage: zkfsm [heal] [--data DIR...] [--listen HOST:PORT] [--protection P] [--scan-interval S] [--anonymous]
    \\             [--domain D]... [--path-prefix P] [--health-prefix P] [--metrics-path P] [--no-minio-compat]
    \\             [--lifecycle-interval S]
    \\  heal             run one scan/heal pass over the drives and exit
    \\  --data           one or more drives; /data{1...4} expands (default: $ZKFSM_DATA, else ./data)
    \\  --listen         listen address (default: 0.0.0.0:9000)
    \\  --protection     single | replica:2 | replica:3 | EC:4+2 | EC:8+4 | EC:12+4
    \\                   default: stored in the drive format, else replica:2 with 2+ drives
    \\  --scan-interval  seconds between background heal passes, 0 disables (default: 600)
    \\  --anonymous      serve without authentication when no credentials are set
    \\  --domain         virtual-host domain: Host {bucket}.D addresses the bucket; repeatable
    \\                   (default: $ZKFSM_DOMAIN, comma-separated)
    \\  --website-domain static-website endpoint: Host {bucket}.D serves the bucket's website
    \\                   configuration; repeatable (default: $ZKFSM_WEBSITE_DOMAIN)
    \\  --path-prefix    base path of the S3 API, e.g. /s3 (default: $ZKFSM_PATH_PREFIX, else /)
    \\  --health-prefix  health endpoints at P/live and P/ready (default: /health)
    \\  --metrics-path   Prometheus metrics path (default: /metrics)
    \\  --no-minio-compat  do not serve /minio/health/* and /minio/v2/metrics/cluster
    \\  --lifecycle-interval  seconds between lifecycle passes, 0 disables (default: 3600)
    \\  --admin-prefix   admin API path prefix (default: $ZKFSM_ADMIN_PREFIX, else /minio/admin);
    \\                   /zkfsm/admin is always accepted too. Path-style keys under
    \\                   <prefix>/v3/ (bucket = first segment) are shadowed by the admin API
    \\  --tls-cert FILE  PEM certificate chain, leaf first (or $ZKFSM_TLS_CERT); enables HTTPS
    \\  --tls-key FILE   PEM private key: EC P-256 or RSA 2048-4096 (or $ZKFSM_TLS_KEY)
    \\  --tls-client-ca FILE  PEM CAs for optional client certificates (AssumeRoleWithCertificate)
    \\  --certs-dir DIR  directory holding public.crt and private.key (or $ZKFSM_CERTS_DIR)
    \\                   SIGHUP reloads the certificate and key
    \\  --max-conns      open connections before new ones get 503 (default: 1024)
    \\  --workers        connections served concurrently (default: 256)
    \\  --idle-timeout   seconds a connection may idle or a socket op may stall (default: 30)
    \\  --header-timeout seconds to receive a request head once it starts (default: 10)
    \\  --shutdown-timeout seconds SIGINT/SIGTERM waits for in-flight requests (default: 30)
    \\cluster (every node gets the same endpoint list; see README "Cluster"):
    \\  --data URL...    http(s)://host:port/path endpoints with {a...b} patterns; each
    \\                   --data flag is one pool, pools may only be appended
    \\  --node-address H:P  this node's host:port in the endpoint list (default: from --listen)
    \\  --cluster-secret S  node-to-node RPC secret (or $ZKFSM_CLUSTER_SECRET);
    \\                   default: derived from the root credentials
    \\  --set-size N     drives per erasure set (default: largest fitting divisor <= 16)
    \\  --cluster-refresh S  seconds between catalog/IAM reloads from the store (default: 10)
    \\  --cluster-ca FILE  extra PEM certificates trusted for peer TLS; repeatable
    \\identity providers (also settable at runtime with mc admin idp openid|ldap add):
    \\  --identity-openid "k=v ..."  default OpenID provider, e.g. config_url=... client_id=...
    \\                   (or $ZKFSM_IDENTITY_OPENID_<KEY>)
    \\  --identity-ldap "k=v ..."    LDAP directory, e.g. server_addr=host:636 lookup_bind_dn=...
    \\                   (or $ZKFSM_IDENTITY_LDAP_<KEY>)
    \\events: targets from mc admin config set notify_<type>[:id] ..., or MINIO_NOTIFY_<TYPE>_<KEY>[_ID]
    \\             / ZKFSM_NOTIFY_... env (ENABLE=on); audit via audit_webhook / audit_kafka, or
    \\             ZKFSM_AUDIT_CONSOLE=on and ZKFSM_AUDIT_FILE=path; region from ZKFSM_REGION / MINIO_REGION;
    \\             queues under ZKFSM_EVENTS_DIR (default: <first drive>/.zkfsm/events)
    \\credentials: ZKFSM_ACCESS_KEY / ZKFSM_SECRET_KEY (or MINIO_ROOT_USER / MINIO_ROOT_PASSWORD)
    \\
;

const Config = struct {
    heal_only: bool = false,
    data: []const []const u8,
    host: []const u8 = "0.0.0.0",
    port: u16 = 9000,
    protection: ?placement.Profile = null,
    scan_interval_s: u64 = 600,
    anonymous: bool = false,
    domains: []const []const u8 = &.{},
    website_domains: []const []const u8 = &.{},
    path_prefix: ?[]const u8 = null,
    health_prefix: []const u8 = "/health",
    metrics_path: []const u8 = "/metrics",
    minio_compat: bool = true,
    lifecycle_interval_s: u64 = 3600,
    admin_prefix: ?[]const u8 = null,
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    certs_dir: ?[]const u8 = null,
    limits: s3.server.Limits = .{},
    /// Cluster mode: per pool, its endpoint arguments (empty for local drives).
    pools: []const []const []const u8 = &.{},
    node_address: ?[]const u8 = null,
    cluster_secret: ?[]const u8 = null,
    set_size: ?usize = null,
    cluster_refresh_s: u64 = 10,
    cluster_ca: []const []const u8 = &.{},
    gateways: gateway.Config = .{},
    identity_openid: ?[]const u8 = null,
    identity_ldap: ?[]const u8 = null,
    tls_client_ca: ?[]const u8 = null,
    kms: sse.setup.Flags = .{},
};

/// Hooks for builds that embed zkfsm (see lib.zig `app`).
pub const Options = struct {
    extensions: []const s3.Extension = &.{},
    /// Consumes an unknown `--flag value` pair; return false to reject it.
    extra_flag: ?*const fn (ctx: ?*anyopaque, flag: []const u8, value: []const u8) bool = null,
    extra_ctx: ?*anyopaque = null,
    extra_usage: []const u8 = "",
};

const ConfigError = error{ BadArgs, HelpRequested, OutOfMemory };

fn isFlag(a: []const u8) bool {
    return std.mem.startsWith(u8, a, "-");
}

const limit_flags = [_][2][]const u8{
    .{ "--max-conns", "max_conns" },
    .{ "--workers", "workers" },
    .{ "--idle-timeout", "idle_timeout_s" },
    .{ "--header-timeout", "header_timeout_s" },
    .{ "--shutdown-timeout", "shutdown_timeout_s" },
};

fn limitField(flag: []const u8) ?[]const u8 {
    for (limit_flags) |lf| if (std.mem.eql(u8, flag, lf[0])) return lf[1];
    return null;
}

/// Strings in the result point into `args`, `env_data`, or `arena`.
fn parseArgs(arena: std.mem.Allocator, args: []const []const u8, env_data: ?[]const u8, opts: Options) ConfigError!Config {
    var cfg: Config = .{ .data = &.{} };
    var specs: std.ArrayList([]const u8) = .empty;
    var domains: std.ArrayList([]const u8) = .empty;
    var website_domains: std.ArrayList([]const u8) = .empty;
    var groups: std.ArrayList([]const []const u8) = .empty;
    var cas: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    if (args.len > 1 and std.mem.eql(u8, args[1], "heal")) {
        cfg.heal_only = true;
        i = 2;
    }
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) return error.HelpRequested;
        if (std.mem.eql(u8, a, "--anonymous")) {
            cfg.anonymous = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--no-minio-compat")) {
            cfg.minio_compat = false;
            continue;
        }
        if (i + 1 >= args.len) return error.BadArgs;
        i += 1;
        if (std.mem.eql(u8, a, "--data")) {
            const first = specs.items.len;
            try specs.append(arena, args[i]);
            while (i + 1 < args.len and !isFlag(args[i + 1])) : (i += 1) try specs.append(arena, args[i + 1]);
            try groups.append(arena, try arena.dupe([]const u8, specs.items[first..]));
        } else if (std.mem.eql(u8, a, "--node-address")) {
            cfg.node_address = args[i];
        } else if (std.mem.eql(u8, a, "--cluster-secret")) {
            cfg.cluster_secret = args[i];
        } else if (std.mem.eql(u8, a, "--cluster-ca")) {
            try cas.append(arena, args[i]);
        } else if (std.mem.eql(u8, a, "--identity-openid")) {
            cfg.identity_openid = args[i];
        } else if (std.mem.eql(u8, a, "--tls-client-ca")) {
            cfg.tls_client_ca = args[i];
        } else if (std.mem.eql(u8, a, "--identity-ldap")) {
            cfg.identity_ldap = args[i];
        } else if (std.mem.eql(u8, a, "--set-size")) {
            cfg.set_size = std.fmt.parseInt(usize, args[i], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--cluster-refresh")) {
            cfg.cluster_refresh_s = std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--listen")) {
            const colon = std.mem.lastIndexOfScalar(u8, args[i], ':') orelse return error.BadArgs;
            cfg.host = args[i][0..colon];
            cfg.port = std.fmt.parseInt(u16, args[i][colon + 1 ..], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--protection")) {
            cfg.protection = placement.Profile.parse(args[i]) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--admin-prefix")) {
            admin.api.validatePrefix(args[i]) catch return error.BadArgs;
            cfg.admin_prefix = args[i];
        } else if (std.mem.eql(u8, a, "--tls-cert")) {
            cfg.tls_cert = args[i];
        } else if (std.mem.eql(u8, a, "--tls-key")) {
            cfg.tls_key = args[i];
        } else if (std.mem.eql(u8, a, "--certs-dir")) {
            cfg.certs_dir = args[i];
        } else if (limitField(a)) |field| {
            const v = std.fmt.parseInt(u32, args[i], 10) catch return error.BadArgs;
            if (v == 0) return error.BadArgs;
            inline for (limit_flags) |lf| if (std.mem.eql(u8, field, lf[1])) {
                @field(cfg.limits, lf[1]) = v;
            };
        } else if (std.mem.eql(u8, a, "--scan-interval")) {
            cfg.scan_interval_s = std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--lifecycle-interval")) {
            cfg.lifecycle_interval_s = std.fmt.parseInt(u64, args[i], 10) catch return error.BadArgs;
        } else if (std.mem.eql(u8, a, "--domain")) {
            try domains.append(arena, args[i]);
        } else if (std.mem.eql(u8, a, "--website-domain")) {
            if (!validDomain(args[i])) return error.BadArgs;
            try website_domains.append(arena, args[i]);
        } else if (std.mem.eql(u8, a, "--path-prefix")) {
            cfg.path_prefix = args[i];
        } else if (std.mem.eql(u8, a, "--health-prefix")) {
            cfg.health_prefix = args[i];
        } else if (std.mem.eql(u8, a, "--metrics-path")) {
            cfg.metrics_path = args[i];
        } else if (sse.setup.Flags.isFlag(a)) {
            if (!cfg.kms.set(a, args[i])) return error.BadArgs;
        } else if (try gateway.parseFlag(&cfg.gateways, a, args[i])) {
            continue;
        } else if (opts.extra_flag) |f| {
            if (!f(opts.extra_ctx, a, args[i])) return error.BadArgs;
        } else return error.BadArgs;
    }
    if (specs.items.len == 0) {
        var it = std.mem.tokenizeScalar(u8, env_data orelse "./data", ' ');
        while (it.next()) |d| try specs.append(arena, d);
        try groups.append(arena, specs.items);
    }
    cfg.cluster_ca = cas.items;
    cfg.website_domains = website_domains.items;
    var urls: usize = 0;
    for (specs.items) |sp| urls += @intFromBool(cluster.isUrl(sp));
    if (urls > 0) {
        // Cluster endpoints: each --data flag is one pool.
        if (urls != specs.items.len) return error.BadArgs;
        cfg.pools = groups.items;
        return finish(&cfg, domains.items);
    }
    var paths: std.ArrayList([]const u8) = .empty;
    for (specs.items) |sp| placement.ellipsis.expand(arena, sp, &paths) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadArgs,
    };
    cfg.data = paths.items;
    return finish(&cfg, domains.items);
}

fn finish(cfg: *Config, domains: []const []const u8) ConfigError!Config {
    cfg.domains = domains;
    for (cfg.domains) |d| if (!validDomain(d)) return error.BadArgs;
    if (cfg.path_prefix) |p| if (p.len > 0 and !s3.router.validBasePath(p)) return error.BadArgs;
    if (!s3.router.validBasePath(cfg.health_prefix) or !s3.router.validBasePath(cfg.metrics_path)) return error.BadArgs;
    return cfg.*;
}

fn validDomain(d: []const u8) bool {
    if (d.len == 0 or d[0] == '.' or d[d.len - 1] == '.') return false;
    for (d) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-')) return false;
    return true;
}

pub fn main() u8 {
    return run(.{});
}

pub fn run(opts: Options) u8 {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const args = std.process.argsAlloc(arena) catch return 1;
    const env_data = std.process.getEnvVarOwned(arena, "ZKFSM_DATA") catch null;

    var cfg = parseArgs(arena, args, env_data, opts) catch |e| {
        std.debug.print("{s}{s}{s}{s}", .{ usage, gateway.usage, sse.setup.usage, opts.extra_usage });
        return if (e == error.HelpRequested) 0 else 2;
    };
    applyEnv(arena, &cfg) catch {
        std.log.err("invalid ZKFSM_PATH_PREFIX or ZKFSM_DOMAIN", .{});
        return 2;
    };
    const creds = loadCredentials(gpa) catch |e| {
        std.log.err("{s}", .{switch (e) {
            error.Incomplete => "access key and secret key must be set together",
            error.OutOfMemory => "out of memory",
        }});
        return 2;
    };
    if (creds == null and !cfg.anonymous and !cfg.heal_only) {
        std.log.err("no credentials: set ZKFSM_ACCESS_KEY and ZKFSM_SECRET_KEY, or pass --anonymous", .{});
        return 2;
    }
    if (creds) |c| if (c.access_key.len < 3 or c.secret_key.len < iam.store.limits.min_secret or c.secret_key.len > iam.store.limits.max_secret) {
        std.log.err("access key needs at least 3 characters and secret key 8 to 40", .{});
        return 2;
    };
    if (creds == null and !cfg.heal_only) std.log.warn("anonymous mode: requests are not authenticated", .{});
    const addr = std.net.Address.parseIp(cfg.host, cfg.port) catch {
        std.log.err("invalid listen address {s}", .{cfg.host});
        return 2;
    };
    var kms_holder: sse.setup.Holder = .{};
    if (!cfg.heal_only) {
        if (!cfg.kms.applyEnv(arena)) {
            std.log.err("invalid ZKFSM_KMS_BACKEND or ZKFSM_KMS_DEFAULT_KEY", .{});
            return 2;
        }
        kms_holder.init(gpa, cfg.kms) catch |e| {
            std.log.err("kms backend {s} failed to start: {t}", .{ cfg.kms.backend.text(), e });
            return 2;
        };
        if (kms_holder.handle != null) std.log.info("kms backend {s}, default key {s}", .{ cfg.kms.backend.text(), kms_holder.default_key });
    }
    if (cfg.pools.len > 0) return runCluster(gpa, arena, cfg, creds, addr, opts, &kms_holder);
    var drives = placement.DriveSet.open(gpa, cfg.data, cfg.protection) catch |e| {
        std.log.err("cannot open drives: {t}", .{e});
        return 1;
    };
    defer drives.deinit();
    var stores: protection.Stores = .{};
    const strategy = protection.Strategy.init(gpa, &drives, &stores) catch {
        std.log.err("protection {s} is not supported", .{drives.profile.name()});
        return 1;
    };
    const be = strategy.backend();
    var healer = heal.Healer.init(gpa, &drives, strategy, .{});
    std.log.info("{d} drive(s), protection {s}", .{ drives.count(), drives.profile.name() });

    if (cfg.heal_only) {
        const r = healer.runOnce() catch |e| {
            std.log.err("heal failed: {t}", .{e});
            return 1;
        };
        heal.logReport(r);
        return if (r.fullyRedundant()) 0 else 3;
    }

    var svc = object.ObjectService.init(gpa, be) catch |e| {
        std.log.err("cannot load catalog: {t}", .{e});
        return 1;
    };
    defer svc.deinit();
    var tiers = object.tier.Registry.init(gpa, &svc, tierKey(creds));
    defer tiers.deinit();
    svc.tiers = &tiers;
    startTierLoop(&svc, cfg.lifecycle_interval_s, null);
    if (cfg.scan_interval_s > 0) {
        healer.start(cfg.scan_interval_s * std.time.ns_per_s) catch {
            std.log.err("cannot start healer", .{});
            return 1;
        };
    }
    defer if (cfg.scan_interval_s > 0) healer.stop();
    if (std.Thread.spawn(.{}, sweepLoop, .{ &svc, @as(?*cluster.Node, null) })) |t| t.detach() else |e| std.log.warn("upload sweeper not started: {t}", .{e});
    if (cfg.lifecycle_interval_s > 0) {
        if (std.Thread.spawn(.{}, lifecycleLoop, .{ &svc, cfg.lifecycle_interval_s, @as(?*cluster.Node, null) })) |t| t.detach() else |e| std.log.warn("lifecycle worker not started: {t}", .{e});
    }
    var auth: s3.sigv4.Config = .{};
    var iam_dir: ?std.fs.Dir = null;
    defer if (iam_dir) |*d| d.close();
    var iam_file: iam.store.FilePersistence = undefined;
    var iam_store: iam.Store = undefined;
    if (creds) |c| {
        iam_dir = openIamDir(cfg.data[0]) catch |e| {
            std.log.err("cannot open {s}/.zkfsm: {t}", .{ cfg.data[0], e });
            return 1;
        };
        iam_file = .{ .dir = iam_dir.? };
        iam_store.open(gpa, iam_file.persistence(), .{ .root_access_key = c.access_key, .root_secret = c.secret_key }) catch |e| {
            std.log.err("cannot load IAM store: {t}", .{e});
            return 1;
        };
        auth = .{ .iam = &iam_store, .sts = .{ .key = s3.sigv4.stsIssuerKey(c.secret_key) } };
    }
    defer if (auth.iam) |st| st.deinit();
    var federation: iam.federation.Federation = .{ .gpa = gpa, .store = &iam_store };
    defer federation.deinit();
    if (creds != null) {
        federation.env = identityEnv(arena, cfg) catch return 2;
        auth.federation = &federation;
    }
    const admin_prefix = cfg.admin_prefix orelse std.process.getEnvVarOwned(arena, "ZKFSM_ADMIN_PREFIX") catch admin.api.default_prefix;
    admin.api.validatePrefix(admin_prefix) catch {
        std.log.err("invalid admin prefix {s}: need /seg[/seg...], no trailing slash, '?', '..' or '//'", .{admin_prefix});
        return 2;
    };
    warnShadowedBucket(&svc, arena, admin_prefix);
    var repl = replication.Replicator.init(gpa, &svc, .{});
    defer repl.deinit();
    startReplication(&repl, &svc, auth.iam);
    var repl_ext: replication.s3ext.Ext = .{ .r = &repl };
    const ev_opts = eventOptions(arena, cfg, cfg.data[0], addr) catch return 2;
    var notif = events.Notifier.init(gpa, &svc, ev_opts);
    defer notif.deinit();
    startEvents(&notif, &svc, false);
    var ev_ext: events.s3ext.Ext = .{ .n = &notif };
    svc.events = ev_ext.sink();
    const observers = [_]s3.Observer{ev_ext.observer()};
    var bridge: admin_http.Bridge = .{ .prefix = admin_prefix, .auth = auth, .svc = &svc, .started_s = std.time.timestamp(), .repl = &repl, .events = &notif };
    var sse_route: sse.Sse = .{ .gpa = gpa, .kms = kms_holder.handle, .default_key = kms_holder.default_key };
    var select_route: sse.SelectApi = .{ .gpa = gpa, .sse = &sse_route };
    var kms_admin: sse.KmsAdmin = .{ .sse = &sse_route, .store = auth.iam, .backend_name = cfg.kms.backend.text(), .key_store = kms_holder.key_store };
    var batch_mgr = batch.Manager.init(gpa, .{ .svc = &svc, .sse = &sse_route });
    batch_mgr.start();
    var batch_api: batch.Api = .{ .m = &batch_mgr, .prefix = admin_prefix, .store = auth.iam };
    const builtin_ext = [_]s3.Extension{ batch_api.extension(), bridge.extension(), kms_admin.extension(), ev_ext.extension(), repl_ext.extension(), select_route.extension(), sse_route.extension() };
    const extensions = std.mem.concat(arena, s3.Extension, &.{ &builtin_ext, opts.extensions }) catch return 1;
    var tls_ctx: tls.Context = undefined;
    const tls_paths = tlsPaths(arena, cfg) catch {
        std.log.err("--tls-cert and --tls-key must be set together", .{});
        return 2;
    };
    if (tls_paths) |tp| {
        tls_ctx = tls.Context.init(gpa, tp[0], tp[1]) catch |e| {
            std.log.err("cannot load TLS certificate {s} / key {s}: {t}", .{ tp[0], tp[1], e });
            return 2;
        };
        tls_ctx.watchSighup() catch std.log.warn("tls: SIGHUP reload unavailable", .{});
        if (cfg.tls_client_ca) |ca| tls_ctx.setClientCa(ca) catch |e| {
            std.log.err("cannot load client CA {s}: {t}", .{ ca, e });
            return 2;
        };
        std.log.info("tls enabled ({s})", .{tp[0]});
    }
    defer if (tls_paths != null) tls_ctx.deinit();
    var server: s3.Server = .{
        .gpa = gpa,
        .svc = &svc,
        .auth = auth,
        .extensions = extensions,
        .observers = &observers,
        .tls = if (tls_paths != null) &tls_ctx else null,
        .limits = cfg.limits,
        .routing = .{ .path_prefix = cfg.path_prefix orelse "", .domains = cfg.domains, .website_domains = cfg.website_domains },
        .ops = .{ .health_prefix = cfg.health_prefix, .metrics_path = cfg.metrics_path, .minio_compat = cfg.minio_compat },
    };
    var gateways = gateway.Running.start(.{
        .gpa = gpa,
        .access = .{ .svc = &svc, .iam = auth.iam },
        .tls = if (tls_paths != null) &tls_ctx else null,
        .state_dir = if (creds != null) std.fs.path.join(arena, &.{ cfg.data[0], ".zkfsm" }) catch return 1 else null,
    }, cfg.gateways) catch |e| {
        std.log.err("cannot start protocol gateways: {t}", .{e});
        return 1;
    };
    defer gateways.stop();
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    active_server = &server;
    installStopSignals();
    server.run(addr) catch |e| {
        std.log.err("server failed: {t}", .{e});
        return 1;
    };
    svc.flush() catch |e| std.log.warn("key index not saved ({t}); it is rebuilt on next start", .{e});
    be.sync() catch |e| std.log.warn("final sync failed: {t}", .{e});
    std.log.info("stopped", .{});
    return 0;
}

/// Cluster mode: the RPC route is served before bootstrap so peers can negotiate
/// the layout; S3 requests wait behind the gate until storage and IAM are up.
fn runCluster(gpa: std.mem.Allocator, arena: std.mem.Allocator, cfg: Config, creds: ?s3.sigv4.Credentials, addr: std.net.Address, opts: Options, kms_holder: *const sse.setup.Holder) u8 {
    if (cfg.heal_only) {
        std.log.err("heal runs continuously on cluster nodes; the one-shot heal command is for local drives", .{});
        return 2;
    }
    const secret_str = cfg.cluster_secret orelse (envVar(arena, "ZKFSM_CLUSTER_SECRET") catch return 1);
    const secret = if (secret_str) |sct| cluster.auth.fromString(sct) else if (creds) |c| cluster.auth.fromRoot(c.access_key, c.secret_key) else {
        std.log.err("an anonymous cluster needs --cluster-secret", .{});
        return 2;
    };
    const tls_paths = tlsPaths(arena, cfg) catch {
        std.log.err("--tls-cert and --tls-key must be set together", .{});
        return 2;
    };
    var cas: std.ArrayList([]const u8) = .empty;
    for (cfg.cluster_ca) |c| cas.append(arena, std.fs.cwd().realpathAlloc(arena, c) catch c) catch return 1;
    if (tls_paths) |tp| cas.append(arena, std.fs.cwd().realpathAlloc(arena, tp[0]) catch tp[0]) catch return 1;
    const node = cluster.Node.create(gpa, .{
        .pools = cfg.pools,
        .node_address = cfg.node_address,
        .listen_host = cfg.host,
        .listen_port = cfg.port,
        .profile = cfg.protection,
        .set_size = cfg.set_size,
        .secret = secret,
        .root_fp = if (creds) |c| cluster.auth.rootFingerprint(secret, c.access_key, c.secret_key) else @splat(0),
        .ca_files = cas.items,
        .scan_interval_s = if (cfg.scan_interval_s == 0) 600 else cfg.scan_interval_s,
        .refresh_s = cfg.cluster_refresh_s,
    }) catch return 2;
    defer node.destroy();

    var svc: object.ObjectService = undefined;
    var svc_ready = false;
    defer if (svc_ready) svc.deinit();
    var tiers: object.tier.Registry = undefined;
    defer if (svc_ready) tiers.deinit();
    var iam_store: iam.Store = undefined;
    var iam_ready = false;
    defer if (iam_ready) iam_store.deinit();
    var auth: s3.sigv4.Config = .{};
    if (creds) |c| auth = .{ .iam = &iam_store, .sts = .{ .key = s3.sigv4.stsIssuerKey(c.secret_key) } };
    var federation: iam.federation.Federation = .{ .gpa = gpa, .store = &iam_store };
    defer federation.deinit();
    if (creds != null) {
        federation.env = identityEnv(arena, cfg) catch return 2;
        auth.federation = &federation;
    }
    const admin_prefix = cfg.admin_prefix orelse std.process.getEnvVarOwned(arena, "ZKFSM_ADMIN_PREFIX") catch admin.api.default_prefix;
    admin.api.validatePrefix(admin_prefix) catch {
        std.log.err("invalid admin prefix {s}", .{admin_prefix});
        return 2;
    };
    // Set up once the object service exists; requests wait behind the gate until then.
    var repl: replication.Replicator = undefined;
    var repl_ready = false;
    defer if (repl_ready) repl.deinit();
    var repl_ext: replication.s3ext.Ext = .{ .r = &repl };
    var notif: events.Notifier = undefined;
    var notif_ready = false;
    defer if (notif_ready) notif.deinit();
    var ev_ext: events.s3ext.Ext = .{ .n = &notif };
    const observers = [_]s3.Observer{ev_ext.observer()};
    var bridge: admin_http.Bridge = .{ .prefix = admin_prefix, .auth = auth, .svc = &svc, .started_s = std.time.timestamp(), .repl = &repl, .events = &notif };
    var sse_route: sse.Sse = .{ .gpa = gpa, .kms = kms_holder.handle, .default_key = kms_holder.default_key };
    var select_route: sse.SelectApi = .{ .gpa = gpa, .sse = &sse_route };
    var kms_admin: sse.KmsAdmin = .{ .sse = &sse_route, .store = auth.iam, .backend_name = cfg.kms.backend.text(), .key_store = kms_holder.key_store };
    const builtin_ext = [_]s3.Extension{ bridge.extension(), kms_admin.extension(), ev_ext.extension(), repl_ext.extension(), select_route.extension(), sse_route.extension() };
    const extensions = std.mem.concat(arena, s3.Extension, &.{ &builtin_ext, opts.extensions }) catch return 1;
    var tls_ctx: tls.Context = undefined;
    if (tls_paths) |tp| {
        tls_ctx = tls.Context.init(gpa, tp[0], tp[1]) catch |e| {
            std.log.err("cannot load TLS certificate {s} / key {s}: {t}", .{ tp[0], tp[1], e });
            return 2;
        };
        tls_ctx.watchSighup() catch std.log.warn("tls: SIGHUP reload unavailable", .{});
        if (cfg.tls_client_ca) |ca| tls_ctx.setClientCa(ca) catch |e| {
            std.log.err("cannot load client CA {s}: {t}", .{ ca, e });
            return 2;
        };
    }
    defer if (tls_paths != null) tls_ctx.deinit();
    const routes = [_]s3.server.RawRoute{cluster.server.route(node)};
    var server: s3.Server = .{
        .gpa = gpa,
        .svc = &svc,
        .auth = auth,
        .extensions = extensions,
        .observers = &observers,
        .tls = if (tls_paths != null) &tls_ctx else null,
        .limits = cfg.limits,
        .routing = .{ .path_prefix = cfg.path_prefix orelse "", .domains = cfg.domains, .website_domains = cfg.website_domains },
        .ops = .{ .health_prefix = cfg.health_prefix, .metrics_path = cfg.metrics_path, .minio_compat = cfg.minio_compat },
        .raw_routes = &routes,
        .ready = .{ .ctx = node, .func = clusterReady },
        .open_gate = &node.open,
    };
    metrics.global.counters.started_ns = std.time.nanoTimestamp();
    active_server = &server;
    installStopSignals();
    var gateways: gateway.Running = .{};
    const serving = std.Thread.spawn(.{}, serveThread, .{ &server, addr, node }) catch {
        std.log.err("cannot start the listener", .{});
        return 1;
    };
    const code: u8 = blk: {
        node.bootstrap() catch |e| {
            if (e != error.Stopped) std.log.err("cluster bootstrap failed: {t}", .{e});
            break :blk if (e == error.Stopped) 0 else 1;
        };
        node.initService(&svc) catch |e| {
            if (e != error.Stopped) std.log.err("cannot open the object service: {t}", .{e});
            break :blk if (e == error.Stopped) 0 else 1;
        };
        tiers = object.tier.Registry.init(gpa, &svc, tierKey(creds));
        svc.tiers = &tiers;
        svc_ready = true;
        if (creds) |c| {
            while (true) {
                iam_store.open(gpa, node.iamPersistence(), .{ .root_access_key = c.access_key, .root_secret = c.secret_key }) catch |e| {
                    if (e != error.PersistFailed) {
                        std.log.err("cannot load IAM store: {t}", .{e});
                        break :blk 1;
                    }
                    if (node.stop_ev.isSet()) break :blk 0;
                    std.log.info("cluster: waiting for IAM read quorum", .{});
                    std.Thread.sleep(std.time.ns_per_s);
                    continue;
                };
                iam_ready = true;
                break;
            }
        }
        repl = replication.Replicator.init(gpa, &svc, .{ .leader = .{ .ctx = node, .func = clusterLeader } });
        repl_ready = true;
        startReplication(&repl, &svc, if (iam_ready) &iam_store else null);
        const ev_opts = eventOptions(arena, cfg, node.localPath() orelse ".", addr) catch break :blk 2;
        notif = events.Notifier.init(gpa, &svc, ev_opts);
        notif_ready = true;
        events_ext = .{ .ctx = &notif, .handle = eventsPeerHandle };
        startEvents(&notif, &svc, true);
        svc.events = ev_ext.sink();
        notif.peers = .{ .ctx = node, .count = node.nodeCount(), .call = eventsPeerCall };
        node.ext.store(&events_ext, .release);
        node.start(if (iam_ready) &iam_store else null);
        gateways = gateway.Running.start(.{
            .gpa = gpa,
            .access = .{ .svc = &svc, .iam = if (iam_ready) &iam_store else null },
            .tls = if (tls_paths != null) &tls_ctx else null,
        }, cfg.gateways) catch |e| {
            std.log.err("cannot start protocol gateways: {t}", .{e});
            break :blk 1;
        };
        if (std.Thread.spawn(.{}, sweepLoop, .{ &svc, @as(?*cluster.Node, node) })) |t| t.detach() else |_| {}
        startTierLoop(&svc, cfg.lifecycle_interval_s, node);
        if (cfg.lifecycle_interval_s > 0) {
            if (std.Thread.spawn(.{}, lifecycleLoop, .{ &svc, cfg.lifecycle_interval_s, @as(?*cluster.Node, node) })) |t| t.detach() else |_| {}
        }
        std.log.info("cluster: serving S3 on {f}", .{addr});
        break :blk 0;
    };
    if (code != 0) _ = server.requestStop();
    serving.join();
    gateways.stop();
    node.stop();
    if (svc_ready) node.storage().sync() catch {};
    std.log.info("stopped", .{});
    return code;
}

fn serveThread(server: *s3.Server, addr: std.net.Address, node: *cluster.Node) void {
    server.run(addr) catch |e| std.log.err("server failed: {t}", .{e});
    // Unblocks a bootstrap that is still waiting for peers.
    node.stop_ev.set();
}

fn clusterLeader(ctx: *anyopaque) bool {
    const node: *cluster.Node = @ptrCast(@alignCast(ctx));
    return node.isLeader();
}

/// Hooks the replication engine into the object service, metrics, and IAM.
fn startReplication(repl: *replication.Replicator, svc: *object.ObjectService, iam_store: ?*iam.Store) void {
    repl.site_ctx = .{ .iam = iam_store };
    svc.replication = repl.sink();
    metrics.global.extra[0] = .{ .ctx = &repl.stats, .func = replication.stats.Stats.render };
    repl.start() catch |e| std.log.warn("replication worker not started: {t}", .{e});
}

/// Event options from the environment; queues default under `<drive>/.zkfsm/events`.
fn eventOptions(arena: std.mem.Allocator, cfg: Config, drive: []const u8, addr: std.net.Address) error{ BadArgs, OutOfMemory }!events.notifier.Options {
    var env = std.process.getEnvMap(arena) catch return error.OutOfMemory;
    const region = env.get("ZKFSM_REGION") orelse env.get("MINIO_REGION") orelse env.get("MINIO_SITE_REGION") orelse "";
    const root = env.get("ZKFSM_EVENTS_DIR") orelse try std.fs.path.join(arena, &.{ drive, ".zkfsm", "events" });
    const host = cfg.node_address orelse try std.fmt.allocPrint(arena, "{f}", .{addr});
    const scheme = if ((tlsPaths(arena, cfg) catch null) != null) "https" else "http";
    const targets = try events.settings.fromEnv(arena, &env);
    for (targets) |t| {
        const k = events.kinds.bySubsys(t.subsys).?;
        const c = k.create(arena, t.settings()) catch {
            std.log.err("{s}:{s} from the environment: invalid settings", .{ t.subsys, t.id });
            return error.BadArgs;
        };
        c.deinit();
    }
    return .{
        .region = region,
        .queue_root = root,
        .endpoint = try std.fmt.allocPrint(arena, "{s}://{s}", .{ scheme, host }),
        .env_targets = targets,
    };
}

var events_ext: cluster.node.Ext = undefined;

fn eventsPeerCall(ctx: *anyopaque, peer: usize, a: std.mem.Allocator, body: []const u8) ?[]const u8 {
    const node: *cluster.Node = @ptrCast(@alignCast(ctx));
    return node.extCall(peer, a, body, 8 * 1024 * 1024);
}

fn eventsPeerHandle(ctx: *anyopaque, a: std.mem.Allocator, body: []const u8) error{OutOfMemory}![]const u8 {
    const n: *events.Notifier = @ptrCast(@alignCast(ctx));
    return n.handlePeer(a, body);
}

/// Loads targets, opens the audit console/file loggers, and hooks up metrics.
fn startEvents(n: *events.Notifier, svc: *object.ObjectService, cluster_mode: bool) void {
    _ = svc;
    const a = n.gpa;
    if (envVar(a, "ZKFSM_AUDIT_CONSOLE") catch null) |v| {
        n.audit_console = std.mem.eql(u8, v, "on") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1");
    }
    if (envVar(a, "ZKFSM_AUDIT_FILE") catch null) |p| {
        if (std.fs.cwd().createFile(p, .{ .truncate = false })) |f| {
            f.seekFromEnd(0) catch {};
            n.audit_file = f;
        } else |e| std.log.err("audit file {s}: {t}", .{ p, e });
    }
    n.reload() catch |e| {
        std.log.warn("events: stored target configuration not loaded ({t}); using the environment only", .{e});
        n.apply("") catch {};
    };
    metrics.global.extra[1] = .{ .ctx = n, .func = events.Notifier.render };
    n.startWatcher(if (cluster_mode) 10 else 60) catch |e| std.log.warn("events: config watcher not started: {t}", .{e});
}

fn clusterReady(ctx: *anyopaque) bool {
    const node: *cluster.Node = @ptrCast(@alignCast(ctx));
    return node.ready();
}

/// The admin prefix takes precedence over path-style S3 keys that share it.
fn warnShadowedBucket(svc: *object.ObjectService, arena: std.mem.Allocator, prefix: []const u8) void {
    const buckets = svc.listBuckets(arena) catch return;
    for ([_][]const u8{ prefix, admin.api.native_prefix }) |p| {
        const name = admin.api.shadowedBucket(p);
        for (buckets) |b| if (std.mem.eql(u8, b.name, name))
            std.log.warn("bucket {s}: path-style keys under {s}/v3/ are served by the admin API", .{ name, p });
    }
}

/// Certificate and key paths from flags, else environment; null when TLS is off.
fn tlsPaths(arena: std.mem.Allocator, cfg: Config) error{ Incomplete, OutOfMemory }!?[2][]const u8 {
    const env = struct {
        fn get(a: std.mem.Allocator, name: []const u8) ?[]const u8 {
            const v = std.process.getEnvVarOwned(a, name) catch return null;
            return if (v.len == 0) null else v;
        }
    };
    var cert = cfg.tls_cert orelse env.get(arena, "ZKFSM_TLS_CERT");
    var key = cfg.tls_key orelse env.get(arena, "ZKFSM_TLS_KEY");
    if (cert == null and key == null) {
        const dir = cfg.certs_dir orelse env.get(arena, "ZKFSM_CERTS_DIR") orelse return null;
        cert = try std.fs.path.join(arena, &.{ dir, "public.crt" });
        key = try std.fs.path.join(arena, &.{ dir, "private.key" });
    }
    return .{ cert orelse return error.Incomplete, key orelse return error.Incomplete };
}

var active_server: ?*s3.Server = null;

fn onStopSignal(_: i32) callconv(.c) void {
    const s = active_server orelse return;
    // A second signal skips the drain.
    if (!s.requestStop()) std.posix.exit(1);
}

fn installStopSignals() void {
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onStopSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Aborts multipart uploads older than a week; runs at start, then hourly.
/// In a cluster only the leader node sweeps.
fn sweepLoop(svc: *object.ObjectService, leader: ?*cluster.Node) void {
    const max_age: i128 = 7 * std.time.ns_per_day;
    while (true) {
        if (leader) |l| if (!l.isLeader()) {
            std.Thread.sleep(std.time.ns_per_hour);
            continue;
        };
        const n = object.multipart.sweepStale(svc, std.time.nanoTimestamp(), max_age) catch |e| blk: {
            std.log.warn("upload sweep failed: {t}", .{e});
            break :blk 0;
        };
        if (n > 0) std.log.info("aborted {d} stale multipart uploads", .{n});
        std.Thread.sleep(std.time.ns_per_hour);
    }
}

/// Applies bucket lifecycle rules: first pass after one interval, then every interval.
fn lifecycleLoop(svc: *object.ObjectService, interval_s: u64, leader: ?*cluster.Node) void {
    while (true) {
        std.Thread.sleep(interval_s * std.time.ns_per_s);
        if (leader) |l| if (!l.isLeader()) continue;
        const st = object.lifecycle.runOnce(svc, std.time.nanoTimestamp()) catch |e| {
            std.log.warn("lifecycle pass failed: {t}", .{e});
            continue;
        };
        const n = st.expired + st.noncurrent_expired + st.markers_removed + st.uploads_aborted;
        if (n > 0 or st.locked > 0) std.log.info("lifecycle: {d} expired, {d} noncurrent, {d} markers, {d} uploads, {d} locked", .{
            st.expired, st.noncurrent_expired, st.markers_removed, st.uploads_aborted, st.locked,
        });
        const t = st.transitioned + st.noncurrent_transitioned;
        if (t > 0 or st.transition_failed > 0) std.log.info("lifecycle: {d} transitioned, {d} noncurrent transitioned, {d} failed", .{
            st.transitioned, st.noncurrent_transitioned, st.transition_failed,
        });
    }
}

/// Tier config is sealed with a key derived from the root credentials.
fn tierKey(creds: ?s3.sigv4.Credentials) ?[32]u8 {
    const c = creds orelse return null;
    return object.tier.sealKey(c.access_key, c.secret_key);
}

/// The remote cleanup journal every minute (or lifecycle interval, if shorter); restore
/// expiry and tier usage (a full record scan) every 10 minutes, or as often with a short
/// lifecycle interval. ZKFSM_ILM_DAY_SECONDS shortens lifecycle/restore days (tests).
fn startTierLoop(svc: *object.ObjectService, lifecycle_interval_s: u64, leader: ?*cluster.Node) void {
    if (std.process.getEnvVarOwned(svc.gpa, "ZKFSM_ILM_DAY_SECONDS")) |v| {
        defer svc.gpa.free(v);
        const n = std.fmt.parseInt(u32, v, 10) catch 0;
        if (n > 0) {
            object.transition.day_len_ns = @as(i128, n) * std.time.ns_per_s;
            std.log.warn("lifecycle days last {d}s (ZKFSM_ILM_DAY_SECONDS)", .{n});
        }
    } else |_| {}
    const interval = if (lifecycle_interval_s == 0) 60 else @min(lifecycle_interval_s, 60);
    if (std.Thread.spawn(.{}, tierLoop, .{ svc, interval, leader })) |t| t.detach() else |e| std.log.warn("tier worker not started: {t}", .{e});
}

fn tierLoop(svc: *object.ObjectService, interval_s: u64, leader: ?*cluster.Node) void {
    const scan_every: u64 = if (interval_s < 60) 1 else 10;
    var pass: u64 = 0;
    while (true) : (pass += 1) {
        std.Thread.sleep(interval_s * std.time.ns_per_s);
        if (leader) |l| if (!l.isLeader()) continue;
        const st = object.transition.housekeeping(svc, std.time.nanoTimestamp(), pass % scan_every == 0) catch |e| {
            std.log.warn("tier housekeeping failed: {t}", .{e});
            continue;
        };
        if (st.restores_expired > 0 or st.cleaned > 0) std.log.info("tiers: {d} restored copies expired, {d} remote blobs deleted, {d} deletes pending", .{
            st.restores_expired, st.cleaned, st.cleanup_pending,
        });
    }
}

/// Environment defaults for flags not given on the command line.
fn applyEnv(arena: std.mem.Allocator, cfg: *Config) error{ BadArgs, OutOfMemory }!void {
    if (cfg.path_prefix == null) {
        if (envVar(arena, "ZKFSM_PATH_PREFIX") catch return error.OutOfMemory) |p| {
            if (!s3.router.validBasePath(p)) return error.BadArgs;
            cfg.path_prefix = p;
        }
    }
    if (cfg.domains.len == 0) {
        const v = envVar(arena, "ZKFSM_DOMAIN") catch return error.OutOfMemory;
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeAny(u8, v orelse "", ", ");
        while (it.next()) |d| {
            if (!validDomain(d)) return error.BadArgs;
            try list.append(arena, d);
        }
        cfg.domains = list.items;
    }
    if (cfg.website_domains.len == 0) {
        const v = envVar(arena, "ZKFSM_WEBSITE_DOMAIN") catch return error.OutOfMemory;
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeAny(u8, v orelse "", ", ");
        while (it.next()) |d| {
            if (!validDomain(d)) return error.BadArgs;
            try list.append(arena, d);
        }
        cfg.website_domains = list.items;
    }
}

fn openIamDir(data: []const u8) error{CannotOpen}!std.fs.Dir {
    var root = std.fs.cwd().openDir(data, .{}) catch return error.CannotOpen;
    defer root.close();
    return root.makeOpenPath(".zkfsm", .{}) catch error.CannotOpen;
}

/// Root credentials from the environment; process-lifetime, never freed.
fn loadCredentials(gpa: std.mem.Allocator) error{ Incomplete, OutOfMemory }!?s3.sigv4.Credentials {
    const pairs = [_][2][]const u8{
        .{ "ZKFSM_ACCESS_KEY", "ZKFSM_SECRET_KEY" },
        .{ "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD" },
    };
    for (pairs) |p| {
        const ak = envVar(gpa, p[0]) catch return error.OutOfMemory;
        const sk = envVar(gpa, p[1]) catch return error.OutOfMemory;
        if (ak == null and sk == null) continue;
        return .{ .access_key = ak orelse return error.Incomplete, .secret_key = sk orelse return error.Incomplete };
    }
    return null;
}

/// Identity provider settings from the environment, overridden key by key by the flags.
fn identityEnv(arena: std.mem.Allocator, cfg: Config) error{ BadArgs, OutOfMemory }!iam.idp.EnvConfig {
    var env = std.process.getEnvMap(arena) catch return error.OutOfMemory;
    var out: iam.idp.EnvConfig = .{};
    inline for (.{ .{ iam.idp.Kind.openid, "openid" }, .{ iam.idp.Kind.ldap, "ldap" } }) |k| {
        var list: std.ArrayList(iam.store.Setting) = .empty;
        try list.appendSlice(arena, try iam.idp.fromEnv(arena, k[0], &env));
        if (@field(cfg, "identity_" ++ k[1])) |text| {
            const flag_settings = iam.idp.parseSettings(arena, k[0], text) catch |e| {
                std.log.err("--identity-{s}: {t}", .{ k[1], e });
                return error.BadArgs;
            };
            for (flag_settings) |fs| {
                for (list.items) |*x| {
                    if (std.mem.eql(u8, x.key, fs.key)) {
                        x.value = fs.value;
                        break;
                    }
                } else try list.append(arena, fs);
            }
        }
        if (list.items.len > 0) {
            iam.idp.validate(k[0], list.items) catch |e| {
                std.log.err("identity {s} settings: {t}", .{ k[1], e });
                return error.BadArgs;
            };
            std.log.info("identity: {s} provider from flags/environment", .{k[1]});
        }
        @field(out, k[1]) = list.items;
    }
    return out;
}

fn envVar(gpa: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]const u8 {
    const v = std.process.getEnvVarOwned(gpa, name) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
    if (v.len == 0) return null;
    return v;
}

test "arg parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const c = try parseArgs(a, &.{ "zkfsm", "--data", "/tmp/x", "--listen", "127.0.0.1:9100" }, null, .{});
    try std.testing.expectEqualStrings("/tmp/x", c.data[0]);
    try std.testing.expectEqual(@as(u16, 9100), c.port);
    try std.testing.expectEqualStrings("env", (try parseArgs(a, &.{"zkfsm"}, "env", .{})).data[0]);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--listen", "nope" }, null, .{}));

    const m = try parseArgs(a, &.{ "zkfsm", "heal", "--data", "/d{1...3}", "/e", "--protection", "replica:3", "--scan-interval", "5" }, null, .{});
    try std.testing.expect(m.heal_only);
    try std.testing.expectEqual(@as(usize, 4), m.data.len);
    try std.testing.expectEqualStrings("/d3", m.data[2]);
    try std.testing.expectEqualStrings("/e", m.data[3]);
    try std.testing.expect(m.protection.?.eql(.{ .replica = 3 }));
    try std.testing.expectEqual(@as(u64, 5), m.scan_interval_s);
    try std.testing.expectEqual(@as(usize, 2), (try parseArgs(a, &.{"zkfsm"}, "/a /b", .{})).data.len);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--protection", "replica:5" }, null, .{}));
    try std.testing.expect((try parseArgs(a, &.{ "zkfsm", "--anonymous", "--data", "d" }, null, .{})).anonymous);
    try std.testing.expectEqualStrings("/ops/admin", (try parseArgs(a, &.{ "zkfsm", "--admin-prefix", "/ops/admin" }, null, .{})).admin_prefix.?);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--admin-prefix", "/ops/" }, null, .{}));
    const l = try parseArgs(a, &.{ "zkfsm", "--max-conns", "8", "--idle-timeout", "3", "--workers", "2" }, null, .{});
    try std.testing.expectEqual(@as(u32, 8), l.limits.max_conns);
    try std.testing.expectEqual(@as(u32, 3), l.limits.idle_timeout_s);
    try std.testing.expectEqual(@as(u32, 2), l.limits.workers);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--workers", "0" }, null, .{}));

    const r = try parseArgs(a, &.{ "zkfsm", "--domain", "s3.local", "--domain", "example.com", "--path-prefix", "/s3", "--health-prefix", "/ops/health", "--metrics-path", "/ops/metrics", "--no-minio-compat", "--lifecycle-interval", "60" }, null, .{});
    try std.testing.expectEqual(@as(usize, 2), r.domains.len);
    try std.testing.expectEqualStrings("/s3", r.path_prefix.?);
    try std.testing.expectEqualStrings("/ops/metrics", r.metrics_path);
    try std.testing.expect(!r.minio_compat);
    try std.testing.expectEqual(@as(u64, 60), r.lifecycle_interval_s);
    for ([_][]const u8{ "s3/", "/s3/", "/s3?x", "/a/../b" }) |bad| {
        try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--path-prefix", bad }, null, .{}));
        try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--health-prefix", bad }, null, .{}));
        try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--metrics-path", bad }, null, .{}));
    }
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--domain", ".bad" }, null, .{}));

    // Cluster endpoints: each --data flag is a pool; local paths cannot be mixed in.
    const k = try parseArgs(a, &.{ "zkfsm", "--data", "http://h{1...4}:9000/d{1...4}", "--data", "http://g1:9000/e{1...8}", "http://g2:9000/e{1...8}", "--node-address", "h1:9000", "--set-size", "8", "--cluster-secret", "s3cr3t" }, null, .{});
    try std.testing.expectEqual(@as(usize, 2), k.pools.len);
    try std.testing.expectEqual(@as(usize, 2), k.pools[1].len);
    try std.testing.expectEqualStrings("h1:9000", k.node_address.?);
    try std.testing.expectEqual(@as(?usize, 8), k.set_size);
    try std.testing.expectError(error.BadArgs, parseArgs(a, &.{ "zkfsm", "--data", "http://h:9000/d", "/local" }, null, .{}));
}

test {
    _ = @import("core/root.zig");
    _ = @import("io/root.zig");
    _ = @import("device/root.zig");
    _ = @import("metadata/root.zig");
    _ = backend;
    _ = placement;
    _ = protection;
    _ = heal;
    _ = object;
    _ = @import("metrics/root.zig");
    _ = s3;
    _ = iam;
    _ = admin;
    _ = tls;
    _ = cluster;
    _ = gateway;
    _ = replication;
    _ = events;
    _ = sse;
    _ = batch;
    _ = @import("kms/root.zig");
    _ = @import("select/root.zig");
}
