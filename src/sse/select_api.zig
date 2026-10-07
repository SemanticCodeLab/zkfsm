//! SelectObjectContent: POST /bucket/key?select&select-type=2 streams
//! event-stream frames; encrypted objects are decrypted on the fly.
const std = @import("std");
const s3 = @import("../s3/root.zig");
const select = @import("../select/root.zig");
const common = @import("common.zig");
const sse_ext = @import("handler.zig");

const Ctx = s3.handler.Ctx;
const ConnError = s3.handler.ConnError;
const DispatchError = s3.handler.DispatchError;

const max_request_body = 256 * 1024;

pub const SelectExt = struct {
    gpa: std.mem.Allocator,
    /// Decrypts SSE objects.
    sse: *sse_ext.SseExt,
    opts: select.Options = .{},

    pub fn extension(self: *SelectExt) s3.Extension {
        return .{ .name = "select", .ctx = self, .route = route };
    }

    fn route(ctx: *anyopaque, c: *Ctx) ConnError!bool {
        const self: *SelectExt = @ptrCast(@alignCast(ctx));
        if (c.route.bucket.len == 0 or c.route.key.len == 0 or c.method != .POST) return false;
        if (!try common.hasParam(c, "select")) return false;
        self.run(c) catch |e| try common.failObject(c, e);
        return true;
    }

    fn run(self: *SelectExt, c: *Ctx) DispatchError!void {
        const st = try s3.handler.param(c, "select-type") orelse "";
        if (!std.mem.eql(u8, st, "2")) return s3.handler.fail(c, .InvalidArgument);
        const h = try sse_ext.SseHeaders.capture(c);

        var rejected: ?s3.errors.Code = null;
        const body = common.readBody(c, max_request_body, &rejected) catch |e| switch (e) {
            error.TooLarge => return common.failCustom(c, .bad_request, "MaxMessageLengthExceeded", "Your request was too big."),
            error.Rejected => return s3.handler.fail(c, rejected.?),
            else => |ce| return ce,
        };
        const info = try c.svc.head(c.arena, c.route.bucket, c.route.key);
        var sel = select.Select.initXml(self.gpa, body, self.opts) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidXml, error.XmlTooDeep, error.XmlTooLarge => return s3.handler.fail(c, .MalformedXML),
            else => |pe| return common.failCustom(c, .bad_request, @errorName(pe), "The SQL expression or request parameters are invalid."),
        };
        defer sel.deinit();

        var plain: ?*sse_ext.Plain = null;
        defer if (plain) |p| p.deinit();
        var obj: common.ObjectReader = undefined;
        const input: *std.Io.Reader = if (sse_ext.isEncrypted(info)) blk: {
            const path = try std.fmt.allocPrint(c.arena, "{s}/{s}", .{ c.route.bucket, c.route.key });
            var opened = (try self.sse.openObject(c, info, h.customer, path)) orelse return;
            defer std.crypto.secureZero(u8, &opened.dek);
            plain = sse_ext.openPlain(c.arena, c.svc, info, &opened.dek, opened.stored.segs, path, 0, opened.stored.size) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Corrupt,
            };
            break :blk plain.?.reader();
        } else blk: {
            obj.init(c.svc, info, 0, info.size, try c.arena.alloc(u8, 256 * 1024));
            break :blk &obj.interface;
        };

        const hdrs = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "x-amz-request-id", .value = &c.request_id },
        };
        var out_buf: [s3.handler.io_buf_len]u8 = undefined;
        var bw = try c.req.respondStreaming(&out_buf, .{ .respond_options = .{ .extra_headers = &hdrs } });
        // Failures after this point are reported in-band as an error event.
        _ = sel.run(input, &bw.writer) catch |e| {
            std.log.debug("select failed: {t}", .{e});
            if (e == error.WriteFailed) return error.WriteFailed;
        };
        try bw.end();
    }
};
