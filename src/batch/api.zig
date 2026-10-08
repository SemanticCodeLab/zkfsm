//! Batch job admin API on the S3 listener, as `mc batch` calls it:
//! generate-job, list-supported-job-types, start-job, list-jobs, describe-job,
//! status-job, cancel-job, and the batch-jobs realtime metrics stream.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const iam = @import("../iam/root.zig");
const admin = @import("../admin/root.zig");
const sse_mod = @import("../sse/root.zig");
const spec = @import("spec.zig");
const job_mod = @import("job.zig");
const report = @import("report.zig");
const templates = @import("templates.zig");
const manager = @import("manager.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const Status = std.http.Status;
const Stringify = std.json.Stringify;

/// madmin MetricsBatchJobs bit.
const metrics_batch_jobs: u32 = 1 << 3;
/// Upper bound on one metrics stream.
const max_stream_ns: i128 = 6 * 3600 * std.time.ns_per_s;

pub const Api = struct {
    m: *manager.Manager,
    prefix: []const u8 = admin.api.default_prefix,
    /// Null in anonymous mode, where the API is unavailable.
    store: ?*iam.Store,

    pub fn extension(self: *Api) s3.Extension {
        return .{ .name = "batch", .ctx = self, .route = route, .before_authz = true };
    }

    fn route(ptr: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *Api = @ptrCast(@alignCast(ptr));
        const t = admin.api.match(self.prefix, c.target) orelse return false;
        const Op = struct { []const u8, std.http.Method, []const u8, *const fn (*Api, *Ctx, []const u8) ConnError!bool };
        const ops = [_]Op{
            .{ "/list-supported-job-types", .GET, "admin:ListBatchJobs", supported },
            .{ "/generate-job", .GET, "admin:ListBatchJobs", generate },
            .{ "/start-job", .POST, "admin:StartBatchJob", startJob },
            .{ "/list-jobs", .GET, "admin:ListBatchJobs", listJobs },
            .{ "/describe-job", .GET, "admin:DescribeBatchJob", describe },
            .{ "/status-job", .GET, "admin:ListBatchJobs", status },
            .{ "/cancel-job", .DELETE, "admin:CancelBatchJob", cancel },
            .{ "/metrics", .GET, "admin:ServerInfo", metrics },
        };
        for (ops) |o| if (std.mem.eql(u8, t.op, o[0])) {
            // Other metric types stay with the general admin API.
            if (std.mem.eql(u8, o[0], "/metrics") and !try isBatchMetrics(c, t.query)) return false;
            const store = self.store orelse return fail(c, .not_implemented, "NotImplemented", "The admin API requires authenticated mode.");
            if (c.method != o[1]) return fail(c, .method_not_allowed, "MethodNotAllowed", "The specified method is not allowed against this resource.");
            if (!try allowed(c, store, o[2])) return fail(c, .forbidden, "AccessDenied", "Access Denied.");
            return o[3](self, c, t.query);
        };
        return false;
    }

    fn supported(_: *Api, c: *Ctx, _: []const u8) ConnError!bool {
        return json(c, [_][]const u8{ "replicate", "keyrotate", "expire" });
    }

    fn generate(_: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const t = try param(c, q, "jobType") orelse "";
        const k = spec.Kind.parse(t) orelse return fail(c, .bad_request, "XMinioAdminInvalidArgument", "Unknown batch job type.");
        try send(c, .ok, "application/yaml", templates.get(k));
        return true;
    }

    fn startJob(self: *Api, c: *Ctx, _: []const u8) ConnError!bool {
        var rejected: ?s3.errors.Code = null;
        const body = sse_mod.common.readBody(c, admin.api.max_body, &rejected) catch |e| switch (e) {
            error.TooLarge => return fail(c, .payload_too_large, "EntityTooLarge", "Job definition is too large."),
            error.Rejected => return fail(c, .forbidden, @tagName(rejected.?), "Request body rejected."),
            else => |ce| return ce,
        };
        const id = self.m.submit(c.auth.principal, body) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidJob => fail(c, .bad_request, "XMinioAdminInvalidArgument", "The job definition is not valid."),
            error.NoSuchBucket => fail(c, .not_found, "NoSuchBucket", "The specified bucket does not exist."),
            error.KmsNotConfigured => fail(c, .not_implemented, "XMinioKMSNotConfigured", "KMS is not configured."),
            error.TooManyJobs => fail(c, .service_unavailable, "XMinioAdminBatchJobLimit", "Too many batch jobs are running."),
            error.StorageFailed => fail(c, .internal_server_error, "InternalError", "The job could not be stored."),
        };
        const r = try self.m.get(c.arena, &id) orelse return fail(c, .internal_server_error, "InternalError", "The job vanished.");
        return render(c, r, struct {
            fn f(w: *Stringify, x: job_mod.Record) std.Io.Writer.Error!void {
                try report.result(w, x, false);
            }
        }.f);
    }

    fn listJobs(self: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const t = try param(c, q, "jobType") orelse "";
        const kind: ?spec.Kind = if (t.len == 0) null else spec.Kind.parse(t) orelse return fail(c, .bad_request, "XMinioAdminInvalidArgument", "Unknown batch job type.");
        const recs = try self.m.list(c.arena, kind);
        var out: std.Io.Writer.Allocating = .init(c.arena);
        var w: Stringify = .{ .writer = &out.writer };
        writeList(&w, recs) catch return error.OutOfMemory;
        try send(c, .ok, "application/json", out.written());
        return true;
    }

    fn writeList(w: *Stringify, recs: []const job_mod.Record) std.Io.Writer.Error!void {
        try w.beginObject();
        try w.objectField("jobs");
        try w.beginArray();
        for (recs) |r| try report.result(w, r, true);
        try w.endArray();
        try w.endObject();
    }

    /// Only active jobs are described; clients fall back to status-job otherwise.
    fn describe(self: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const r = try self.lookup(c, q, "jobId") orelse return noSuchJob(c);
        const st = std.meta.stringToEnum(job_mod.State, r.state) orelse .failed;
        if (!st.active()) return noSuchJob(c);
        try send(c, .ok, "application/yaml", r.spec);
        return true;
    }

    fn status(self: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const r = try self.lookup(c, q, "jobId") orelse return noSuchJob(c);
        return render(c, r, struct {
            fn f(w: *Stringify, x: job_mod.Record) std.Io.Writer.Error!void {
                try w.beginObject();
                try w.objectField("LastMetric");
                try report.metric(w, x);
                try w.endObject();
            }
        }.f);
    }

    fn cancel(self: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const id = try param(c, q, "id") orelse "";
        if (!job_mod.validId(id)) return noSuchJob(c);
        return switch (self.m.cancel(id)) {
            .not_found => noSuchJob(c),
            .finished => fail(c, .bad_request, "XMinioAdminBatchJobNotActive", "The job is not running."),
            .canceled => blk: {
                try send(c, .no_content, "application/json", "");
                break :blk true;
            },
        };
    }

    /// Streams one realtime-metrics packet per interval until the job ends.
    fn metrics(self: *Api, c: *Ctx, q: []const u8) ConnError!bool {
        const id = try param(c, q, "by-jobID") orelse "";
        const interval = intervalNs(try param(c, q, "interval") orelse "");
        const hs = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
        };
        var buf: [s3.handler.io_buf_len]u8 = undefined;
        var bw = try c.req.respondStreaming(&buf, .{ .respond_options = .{ .status = .ok, .extra_headers = &hs } });
        const host = c.host orelse "";
        const t0 = std.time.nanoTimestamp();
        while (true) {
            var arena = std.heap.ArenaAllocator.init(self.m.gpa);
            defer arena.deinit();
            const now = std.time.nanoTimestamp();
            const rec = if (job_mod.validId(id)) try self.m.get(arena.allocator(), id) else null;
            var w: Stringify = .{ .writer = &bw.writer };
            const r = rec orelse {
                // Unknown job: an empty final packet ends the client's wait.
                bw.writer.writeAll("{\"hosts\":[],\"aggregated\":{},\"final\":true}\n") catch return error.WriteFailed;
                break;
            };
            const st = std.meta.stringToEnum(job_mod.State, r.state) orelse .failed;
            const final = !st.active() or now - t0 > max_stream_ns;
            report.realtime(&w, r, host, now, final) catch return error.WriteFailed;
            bw.writer.writeByte('\n') catch return error.WriteFailed;
            bw.flush() catch return error.WriteFailed;
            if (final) break;
            std.Thread.sleep(interval);
        }
        bw.end() catch return error.WriteFailed;
        return true;
    }

    fn lookup(self: *Api, c: *Ctx, q: []const u8, name: []const u8) ConnError!?job_mod.Record {
        const id = try param(c, q, name) orelse return null;
        if (!job_mod.validId(id)) return null;
        return self.m.get(c.arena, id);
    }
};

fn isBatchMetrics(c: *Ctx, q: []const u8) error{OutOfMemory}!bool {
    if (try param(c, q, "by-jobID")) |id| if (id.len > 0) return true;
    const types = std.fmt.parseInt(u32, try param(c, q, "types") orelse "", 10) catch return false;
    return types == metrics_batch_jobs;
}

/// Go duration text from the client (`1s`), clamped to 100 ms .. 60 s.
fn intervalNs(s: []const u8) u64 {
    const d = spec.duration(s) catch return std.time.ns_per_s;
    return std.math.clamp(d, 100 * std.time.ns_per_ms, 60 * std.time.ns_per_s);
}

fn param(c: *Ctx, q: []const u8, name: []const u8) error{OutOfMemory}!?[]const u8 {
    return s3.router.queryParam(c.arena, q, name) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

fn allowed(c: *Ctx, store: *iam.Store, action: []const u8) ConnError!bool {
    if (c.auth.principal.len == 0 or c.tenant.len > 0) return false;
    var sp: ?iam.Policy = null;
    if (c.auth.session_policy) |doc| sp = iam.policy.parse(c.arena, doc) catch return false;
    const id: iam.Identity = .{ .access_key = c.auth.principal, .session_policy = if (sp) |*p| p else null, .federated_policies = c.auth.federated_policies };
    const ctx: iam.Context = .{ .now_s = std.time.timestamp() };
    return store.authorize(id, action, iam.actions.admin_resource, &ctx).allowed();
}

fn render(c: *Ctx, r: job_mod.Record, comptime f: fn (*Stringify, job_mod.Record) std.Io.Writer.Error!void) ConnError!bool {
    var out: std.Io.Writer.Allocating = .init(c.arena);
    var w: Stringify = .{ .writer = &out.writer };
    f(&w, r) catch return error.OutOfMemory;
    try send(c, .ok, "application/json", out.written());
    return true;
}

fn json(c: *Ctx, v: anytype) ConnError!bool {
    try send(c, .ok, "application/json", try std.json.Stringify.valueAlloc(c.arena, v, .{}));
    return true;
}

fn noSuchJob(c: *Ctx) ConnError!bool {
    return fail(c, .not_found, "XMinioAdminNoSuchJob", "The specified job does not exist.");
}

fn fail(c: *Ctx, st: Status, code: []const u8, message: []const u8) ConnError!bool {
    const body = try std.json.Stringify.valueAlloc(c.arena, .{ .Code = code, .Message = message, .Resource = std.mem.sliceTo(c.target, '?'), .RequestId = &c.request_id }, .{});
    try send(c, st, "application/json", body);
    return true;
}

fn send(c: *Ctx, st: Status, ct: []const u8, body: []const u8) ConnError!void {
    const hs = [_]std.http.Header{
        .{ .name = "content-type", .value = ct },
        .{ .name = "x-amz-request-id", .value = &c.request_id },
    };
    try c.req.respond(body, .{ .status = st, .extra_headers = &hs });
}
