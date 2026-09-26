//! SigV4 request verification: header and presigned-query auth, clock skew,
//! and payload checks (sha256, aws-chunked with per-chunk signatures).
const std = @import("std");
const core = @import("../core/root.zig");
const router = @import("router.zig");
const errors = @import("errors.zig");
const iam = @import("../iam/root.zig");

const sv = core.sigv4;
const Code = errors.Code;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Header = std.http.Header;

pub const Credentials = struct { access_key: []const u8, secret_key: []const u8 };

/// Where secrets come from. A null store means anonymous mode: nothing is checked.
pub const Config = struct {
    iam: ?*iam.Store = null,
    /// Validates STS session tokens and derives their secrets.
    sts: ?iam.sts.Issuer = null,
};

/// STS issuer key derived from the root secret, so tokens survive restarts.
pub fn stsIssuerKey(root_secret: []const u8) [32]u8 {
    return sv.hmac(root_secret, "zkfsm-sts-issuer");
}

pub const max_skew_s = 15 * 60;
pub const max_presign_expires_s = 7 * 24 * 3600;
const max_trailer_lines = 16;

/// The parts of a request that signing covers, copied out of the HTTP head.
pub const Input = struct {
    method: []const u8,
    target: []const u8,
    headers: []const Header,

    pub fn header(in: Input, name: []const u8) ?[]const u8 {
        for (in.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }

    pub fn fromRequest(arena: std.mem.Allocator, req: *std.http.Server.Request) error{OutOfMemory}!Input {
        var list: std.ArrayList(Header) = .empty;
        var it = req.iterateHeaders();
        while (it.next()) |h| try list.append(arena, .{ .name = try arena.dupe(u8, h.name), .value = try arena.dupe(u8, h.value) });
        return .{ .method = @tagName(req.head.method), .target = try arena.dupe(u8, req.head.target), .headers = list.items };
    }
};

pub const PayloadMode = enum { unchecked, sha256, chunked_signed, chunked_unsigned };

/// Verified request state needed to check the body as it streams.
pub const Auth = struct {
    mode: PayloadMode = .unchecked,
    sha256: [32]u8 = undefined,
    decoded_length: ?u64 = null,
    /// Chunk-signing chain; key is null when signatures are not checked.
    key: ?[32]u8 = null,
    seed: sv.Hex = undefined,
    amz_date: []const u8 = "",
    scope: sv.Scope = .{ .date = "", .region = "", .service = "" },
    /// Identity to authorize: the access key, or an STS session's parent.
    principal: []const u8 = "",
    /// No credentials were presented; only bucket policies can grant access.
    anonymous: bool = false,
    session_policy: ?[]const u8 = null,
};

pub const Outcome = union(enum) { ok: Auth, denied: Code };

fn deny(c: Code) Outcome {
    return .{ .denied = c };
}

/// Authenticates a request at `now_s` (Unix seconds).
pub fn verify(arena: std.mem.Allocator, cfg: Config, in: Input, now_s: i64) error{OutOfMemory}!Outcome {
    var auth: Auth = .{};
    const payload = in.header("x-amz-content-sha256");
    if (payload) |p| {
        if (std.mem.eql(u8, p, sv.streaming_payload)) {
            auth.mode = .chunked_signed;
        } else if (std.mem.eql(u8, p, sv.streaming_unsigned_trailer)) {
            auth.mode = .chunked_unsigned;
        } else if (std.mem.startsWith(u8, p, "STREAMING-")) {
            return deny(.NotImplemented);
        } else if (std.mem.eql(u8, p, sv.unsigned_payload)) {
            auth.mode = .unchecked;
        } else {
            if (p.len != 64) return deny(.InvalidArgument);
            _ = std.fmt.hexToBytes(&auth.sha256, p) catch return deny(.InvalidArgument);
            auth.mode = .sha256;
        }
    }
    if (auth.mode == .chunked_signed or auth.mode == .chunked_unsigned) {
        if (in.header("x-amz-decoded-content-length")) |d|
            auth.decoded_length = std.fmt.parseInt(u64, d, 10) catch return deny(.InvalidArgument);
    }

    const store = cfg.iam orelse return .{ .ok = auth };
    const src: Source = .{ .cfg = cfg, .store = store, .now_s = now_s };
    const query = if (std.mem.indexOfScalar(u8, in.target, '?')) |i| in.target[i + 1 ..] else "";
    if (in.header("authorization")) |h| {
        const p = parseAuthorization(h) orelse return deny(.AuthorizationHeaderMalformed);
        const amz_date = in.header("x-amz-date") orelse return deny(.AccessDenied);
        const t = sv.parseAmzDate(amz_date) catch return deny(.AccessDenied);
        if (@abs(now_s - t) > max_skew_s) return deny(.RequestTimeTooSkewed);
        if (payload == null) {
            auth.mode = .sha256;
            sv.Sha256.hash("", &auth.sha256, .{});
        }
        return check(arena, src, in.header("x-amz-security-token"), in, p, amz_date, payload orelse sv.empty_sha256_hex, false, &auth);
    }
    const qp = struct {
        fn get(a: std.mem.Allocator, q: []const u8, name: []const u8) error{OutOfMemory}!?[]const u8 {
            return router.queryParam(a, q, name) catch |e| switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.InvalidUri => null,
            };
        }
    }.get;
    const sig = try qp(arena, query, "X-Amz-Signature") orelse {
        if (try qp(arena, query, "X-Amz-Credential") != null or try qp(arena, query, "X-Amz-Algorithm") != null) return deny(.AccessDenied);
        auth.anonymous = true;
        return .{ .ok = auth };
    };
    const alg = try qp(arena, query, "X-Amz-Algorithm") orelse return deny(.AuthorizationHeaderMalformed);
    const cred = try qp(arena, query, "X-Amz-Credential") orelse return deny(.AuthorizationHeaderMalformed);
    const amz_date = try qp(arena, query, "X-Amz-Date") orelse return deny(.AuthorizationHeaderMalformed);
    const exp_s = try qp(arena, query, "X-Amz-Expires") orelse return deny(.AuthorizationHeaderMalformed);
    const signed = try qp(arena, query, "X-Amz-SignedHeaders") orelse return deny(.AuthorizationHeaderMalformed);
    if (!std.mem.eql(u8, alg, sv.algorithm)) return deny(.AuthorizationHeaderMalformed);
    const expires = std.fmt.parseInt(i64, exp_s, 10) catch return deny(.AuthorizationHeaderMalformed);
    if (expires < 1 or expires > max_presign_expires_s) return deny(.AuthorizationHeaderMalformed);
    const t = sv.parseAmzDate(amz_date) catch return deny(.AuthorizationHeaderMalformed);
    if (now_s + max_skew_s < t or now_s > t + expires) return deny(.AccessDenied);
    const p: Parsed = .{
        .cred = parseCredential(cred) orelse return deny(.AuthorizationHeaderMalformed),
        .signed_headers = signed,
        .signature = sig,
    };
    const ph = try qp(arena, query, "X-Amz-Content-Sha256") orelse sv.unsigned_payload;
    const token = try qp(arena, query, "X-Amz-Security-Token");
    return check(arena, src, token, in, p, amz_date, ph, true, &auth);
}

const Credential = struct { access_key: []const u8, scope: sv.Scope };

const Parsed = struct { cred: Credential, signed_headers: []const u8, signature: []const u8 };

fn parseCredential(s: []const u8) ?Credential {
    var it = std.mem.splitScalar(u8, s, '/');
    const ak = it.next() orelse return null;
    const date = it.next() orelse return null;
    const region = it.next() orelse return null;
    const service = it.next() orelse return null;
    const term = it.next() orelse return null;
    if (it.next() != null or !std.mem.eql(u8, term, sv.terminator)) return null;
    return .{ .access_key = ak, .scope = .{ .date = date, .region = region, .service = service } };
}

fn parseAuthorization(h: []const u8) ?Parsed {
    const prefix = sv.algorithm ++ " ";
    if (!std.mem.startsWith(u8, h, prefix)) return null;
    var cred: ?Credential = null;
    var signed: ?[]const u8 = null;
    var sig: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, h[prefix.len..], ',');
    while (it.next()) |raw| {
        const kv = std.mem.trim(u8, raw, " ");
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return null;
        const k = kv[0..eq];
        const v = kv[eq + 1 ..];
        if (std.mem.eql(u8, k, "Credential")) {
            cred = parseCredential(v) orelse return null;
        } else if (std.mem.eql(u8, k, "SignedHeaders")) {
            signed = v;
        } else if (std.mem.eql(u8, k, "Signature")) {
            sig = v;
        }
    }
    return .{ .cred = cred orelse return null, .signed_headers = signed orelse return null, .signature = sig orelse return null };
}

const Source = struct { cfg: Config, store: *iam.Store, now_s: i64 };

fn check(
    arena: std.mem.Allocator,
    src: Source,
    token: ?[]const u8,
    in: Input,
    p: Parsed,
    amz_date: []const u8,
    payload_hash: []const u8,
    presigned: bool,
    auth: *Auth,
) error{OutOfMemory}!Outcome {
    var sbuf: iam.Store.SecretBuf = undefined;
    var sts_secret: [iam.sts.secret_key_len]u8 = undefined;
    var dbuf: iam.sts.DecodeBuffer = undefined;
    const ak = p.cred.access_key;
    auth.principal = ak;
    const secret: []const u8 = if (token) |t| blk: {
        const issuer = src.cfg.sts orelse return deny(.InvalidToken);
        const claims = issuer.verify(ak, t, src.now_s, &dbuf) catch |e| return deny(switch (e) {
            error.Expired => .ExpiredToken,
            else => .InvalidToken,
        });
        auth.principal = try arena.dupe(u8, claims.parent);
        auth.session_policy = if (claims.session_policy) |sp| try arena.dupe(u8, sp) else null;
        sts_secret = issuer.secretFor(ak);
        break :blk &sts_secret;
    } else src.store.secretFor(ak, src.now_s, &sbuf) orelse return deny(.InvalidAccessKeyId);
    const scope = p.cred.scope;
    if (!std.mem.eql(u8, scope.date, amz_date[0..8]) or !std.mem.eql(u8, scope.service, "s3"))
        return deny(.AuthorizationHeaderMalformed);
    var has_host = false;
    var hit = std.mem.splitScalar(u8, p.signed_headers, ';');
    while (hit.next()) |n| has_host = has_host or std.mem.eql(u8, n, "host");
    if (!has_host) return deny(.AuthorizationHeaderMalformed);

    const creq = canonicalRequest(arena, in, p.signed_headers, payload_hash, presigned) catch |e| switch (e) {
        error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
        error.InvalidUri => return deny(.InvalidURI),
    };
    var sts: Writer.Allocating = .init(arena);
    sv.writeStringToSign(&sts.writer, amz_date, scope, creq) catch return error.OutOfMemory;
    const key = sv.signingKey(secret, scope.date, scope.region, scope.service);
    const want = sv.sign(key, sts.written());
    if (p.signature.len != want.len or !std.crypto.timing_safe.eql(sv.Hex, want, p.signature[0..64].*))
        return deny(.SignatureDoesNotMatch);
    auth.key = key;
    auth.seed = want;
    auth.amz_date = amz_date;
    auth.scope = scope;
    return .{ .ok = auth.* };
}

fn canonicalRequest(
    arena: std.mem.Allocator,
    in: Input,
    signed_headers: []const u8,
    payload_hash: []const u8,
    presigned: bool,
) (Writer.Error || router.Error)![]const u8 {
    var a: Writer.Allocating = .init(arena);
    const w = &a.writer;
    const q = std.mem.indexOfScalar(u8, in.target, '?');
    const path = try router.percentDecode(arena, in.target[0 .. q orelse in.target.len], false);
    try w.print("{s}\n", .{in.method});
    try sv.uriEncode(w, path, true);
    try w.writeByte('\n');

    var params: std.ArrayList(sv.Param) = .empty;
    if (q) |i| {
        var it = std.mem.splitScalar(u8, in.target[i + 1 ..], '&');
        while (it.next()) |pair| {
            if (pair.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, pair, '=');
            const name = try router.percentDecode(arena, pair[0 .. eq orelse pair.len], false);
            if (presigned and std.mem.eql(u8, name, "X-Amz-Signature")) continue;
            const value = if (eq) |e| try router.percentDecode(arena, pair[e + 1 ..], false) else "";
            try params.append(arena, .{ .name = name, .value = value });
        }
    }
    try sv.writeCanonicalQuery(arena, w, params.items);
    try w.writeByte('\n');

    var names = std.mem.splitScalar(u8, signed_headers, ';');
    while (names.next()) |name| {
        try w.print("{s}:", .{name});
        var first = true;
        for (in.headers) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, name)) continue;
            if (!first) try w.writeByte(',');
            first = false;
            try sv.writeHeaderValue(w, h.value);
        }
        try w.writeByte('\n');
    }
    try w.print("\n{s}\n{s}", .{ signed_headers, payload_hash });
    return a.written();
}

/// Parses an HTTP head, tolerating `Content-Encoding: aws-chunked`, which
/// std.http rejects. The raw head (and so the signed header) is left intact.
/// An absolute-form target (RFC 9112 3.2.2) is reduced to its path and query.
pub fn parseHead(arena: std.mem.Allocator, head: []const u8) std.http.Server.Request.Head.ParseError!std.http.Server.Request.Head {
    const Head = std.http.Server.Request.Head;
    var h = Head.parse(head) catch |e| blk: {
        if (e != error.HttpTransferEncodingUnsupported) return e;
        var a: Writer.Allocating = .init(arena);
        stripAwsChunked(&a.writer, head) catch return e;
        break :blk try Head.parse(a.written());
    };
    h.target = originForm(h.target);
    return h;
}

fn originForm(target: []const u8) []const u8 {
    inline for (.{ "http://", "https://" }) |scheme| if (std.ascii.startsWithIgnoreCase(target, scheme)) {
        const rest = target[scheme.len..];
        const i = std.mem.indexOfAny(u8, rest, "/?") orelse return "/";
        return rest[i..];
    };
    return target;
}

fn stripAwsChunked(w: *Writer, head: []const u8) Writer.Error!void {
    const name = "content-encoding:";
    var lines = std.mem.splitScalar(u8, head, '\n');
    while (lines.next()) |l| {
        if (lines.peek() == null) return w.writeAll(l);
        if (l.len < name.len or !std.ascii.eqlIgnoreCase(l[0..name.len], name)) {
            try w.print("{s}\n", .{l});
            continue;
        }
        var kept: usize = 0;
        try w.writeAll(name);
        var toks = std.mem.tokenizeAny(u8, l[name.len..], ", \r");
        while (toks.next()) |t| {
            if (std.ascii.eqlIgnoreCase(t, "aws-chunked")) continue;
            try w.print("{s}{s}", .{ if (kept > 0) "," else " ", t });
            kept += 1;
        }
        try w.writeAll(if (kept == 0) " identity\r\n" else "\r\n");
    }
}

test "head with aws-chunked content encoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const raw = "PUT /b/k HTTP/1.1\r\nHost: h\r\nContent-Encoding: aws-chunked\r\nContent-Length: 5\r\n\r\n";
    const h = try parseHead(arena.allocator(), raw);
    try std.testing.expectEqual(@as(?u64, 5), h.content_length);
    try std.testing.expectEqual(std.http.ContentEncoding.identity, h.transfer_compression);
    const g = try parseHead(arena.allocator(), "PUT / HTTP/1.1\r\ncontent-encoding: aws-chunked,gzip\r\n\r\n");
    try std.testing.expectEqual(std.http.ContentEncoding.gzip, g.transfer_compression);
    const p = try parseHead(arena.allocator(), "GET http://b.s3.local:9000/k?acl HTTP/1.1\r\nHost: b.s3.local:9000\r\n\r\n");
    try std.testing.expectEqualStrings("/k?acl", p.target);
    try std.testing.expectEqualStrings("/", originForm("http://host"));
}

/// Wraps a request body per `Auth`: verifies a declared sha256 at EOF, or
/// decodes aws-chunked framing and checks each chunk signature.
pub const BodyReader = struct {
    in: *Reader,
    auth: Auth,
    hasher: sv.Sha256 = .init(.{}),
    prev: sv.Hex,
    chunk_sig: sv.Hex = undefined,
    remaining: u64 = 0,
    state: enum { header, data, done } = .header,
    /// Set when the body was rejected; the handler reports it as the S3 error.
    failure: ?Code = null,
    reader: Reader,

    pub fn init(auth: Auth, in: *Reader, buffer: []u8) BodyReader {
        return .{
            .in = in,
            .auth = auth,
            .prev = auth.seed,
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
    }

    /// The reader to consume; the raw body when nothing needs checking.
    pub fn body(self: *BodyReader) *Reader {
        return if (self.auth.mode == .unchecked) self.in else &self.reader;
    }

    /// Decoded payload length for chunked bodies, else the HTTP length.
    pub fn contentLength(self: *const BodyReader, http_length: ?u64) ?u64 {
        return switch (self.auth.mode) {
            .chunked_signed, .chunked_unsigned => self.auth.decoded_length,
            else => http_length,
        };
    }

    fn fail(self: *BodyReader, c: Code) Reader.StreamError {
        self.failure = c;
        self.state = .done;
        return error.ReadFailed;
    }

    fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const self: *BodyReader = @alignCast(@fieldParentPtr("reader", r));
        if (self.state == .done) return if (self.failure != null) error.ReadFailed else error.EndOfStream;
        return switch (self.auth.mode) {
            .sha256 => self.streamPlain(w, limit),
            else => self.streamChunked(w, limit),
        };
    }

    fn streamPlain(self: *BodyReader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const dest = limit.slice(try w.writableSliceGreedy(1));
        if (dest.len == 0) return 0;
        const n = try self.in.readSliceShort(dest);
        self.hasher.update(dest[0..n]);
        w.advance(n);
        if (n < dest.len) {
            // Short read means the body ended; never read it again.
            if (!std.mem.eql(u8, &self.hasher.finalResult(), &self.auth.sha256)) return self.fail(.XAmzContentSHA256Mismatch);
            self.state = .done;
            if (n == 0) return error.EndOfStream;
        }
        return n;
    }

    fn streamChunked(self: *BodyReader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        if (self.state == .header) {
            try self.readChunkHeader();
            if (self.state == .done) return error.EndOfStream;
        }
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const want: usize = @intCast(@min(dest.len, self.remaining));
        if (want == 0) return 0;
        const n = try self.in.readSliceShort(dest[0..want]);
        if (n < want) return self.fail(.IncompleteBody);
        self.hasher.update(dest[0..n]);
        self.remaining -= n;
        if (self.remaining == 0) {
            const crlf = self.in.takeArray(2) catch |e| return self.readError(e);
            if (!std.mem.eql(u8, crlf, "\r\n")) return self.fail(.InvalidArgument);
            if (!self.chunkSignatureOk()) return self.fail(.SignatureDoesNotMatch);
            self.state = .header;
        }
        w.advance(n);
        return n;
    }

    fn readError(self: *BodyReader, e: Reader.DelimiterError) Reader.StreamError {
        return switch (e) {
            error.ReadFailed => error.ReadFailed,
            error.EndOfStream => self.fail(.IncompleteBody),
            error.StreamTooLong => self.fail(.InvalidArgument),
        };
    }

    fn line(self: *BodyReader) Reader.StreamError![]const u8 {
        const l = self.in.takeDelimiterInclusive('\n') catch |e| return self.readError(e);
        if (l.len < 2 or l[l.len - 2] != '\r') return self.fail(.InvalidArgument);
        return l[0 .. l.len - 2];
    }

    fn readChunkHeader(self: *BodyReader) Reader.StreamError!void {
        const l = try self.line();
        const semi = std.mem.indexOfScalar(u8, l, ';');
        const size = std.fmt.parseInt(u64, l[0 .. semi orelse l.len], 16) catch return self.fail(.InvalidArgument);
        if (self.auth.mode == .chunked_signed) {
            const ext = if (semi) |i| l[i + 1 ..] else return self.fail(.InvalidArgument);
            const prefix = "chunk-signature=";
            if (!std.mem.startsWith(u8, ext, prefix) or ext.len != prefix.len + 64) return self.fail(.InvalidArgument);
            self.chunk_sig = ext[prefix.len..][0..64].*;
        }
        self.hasher = .init(.{});
        self.remaining = size;
        self.state = .data;
        if (size > 0) return;
        if (!self.chunkSignatureOk()) return self.fail(.SignatureDoesNotMatch);
        // Trailer section (checksum trailers are not verified yet), then the blank line.
        var i: usize = 0;
        while (i < max_trailer_lines) : (i += 1) {
            if ((try self.line()).len == 0) {
                // Drain to the HTTP end of body so the connection stays reusable.
                const extra = self.in.discardRemaining() catch return self.fail(.IncompleteBody);
                if (extra != 0) return self.fail(.InvalidArgument);
                self.state = .done;
                return;
            }
            if (self.auth.mode == .chunked_signed) return self.fail(.InvalidArgument);
        }
        return self.fail(.InvalidArgument);
    }

    fn chunkSignatureOk(self: *BodyReader) bool {
        if (self.auth.mode != .chunked_signed) return true;
        const key = self.auth.key orelse return true;
        const digest = self.hasher.finalResult();
        var buf: [1024]u8 = undefined;
        var w: Writer = .fixed(&buf);
        sv.writeChunkStringToSign(&w, self.auth.amz_date, self.auth.scope, &self.prev, &std.fmt.bytesToHex(digest, .lower)) catch return false;
        const sig = sv.sign(key, w.buffered());
        if (!std.crypto.timing_safe.eql(sv.Hex, sig, self.chunk_sig)) return false;
        self.prev = sig;
        return true;
    }
};

// Examples from the AWS S3 SigV4 documentation.
const ex_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const ex_ak = "AKIAIOSFODNN7EXAMPLE";

/// verify() against an IAM store whose root is `ak`/`sk`; null `ak` is anonymous mode.
fn tverify(a: std.mem.Allocator, ak: ?[]const u8, sk: []const u8, in: Input, now_s: i64) !Outcome {
    var mem: iam.store.MemoryPersistence = .{ .gpa = std.testing.allocator };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(std.testing.allocator, mem.persistence(), .{ .root_access_key = ak orelse "", .root_secret = sk });
    defer st.deinit();
    return verify(a, .{ .iam = if (ak != null) &st else null }, in, now_s);
}
const ex_now: i64 = 1369353600; // 20130524T000000Z

fn expectDenied(want: Code, got: Outcome) !void {
    try std.testing.expectEqual(Outcome{ .denied = want }, got);
}

test "header auth: GET object example" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const auth_hdr = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request," ++
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date," ++
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
    var hdrs = [_]Header{
        .{ .name = "Host", .value = "examplebucket.s3.amazonaws.com" },
        .{ .name = "Authorization", .value = auth_hdr },
        .{ .name = "Range", .value = "bytes=0-9" },
        .{ .name = "x-amz-content-sha256", .value = sv.empty_sha256_hex },
        .{ .name = "x-amz-date", .value = "20130524T000000Z" },
    };
    const in: Input = .{ .method = "GET", .target = "/test.txt", .headers = &hdrs };
    const out = try tverify(arena.allocator(), ex_ak, ex_secret, in, ex_now + 60);
    try std.testing.expect(out == .ok);
    try std.testing.expectEqual(PayloadMode.sha256, out.ok.mode);

    try expectDenied(.RequestTimeTooSkewed, try tverify(arena.allocator(), ex_ak, ex_secret, in, ex_now + 16 * 60));
    try expectDenied(.InvalidAccessKeyId, try tverify(arena.allocator(), "OTHER", ex_secret, in, ex_now));
    try expectDenied(.SignatureDoesNotMatch, try tverify(arena.allocator(), ex_ak, "wrongwrong", in, ex_now));
    hdrs[2].value = "bytes=0-10";
    try expectDenied(.SignatureDoesNotMatch, try tverify(arena.allocator(), ex_ak, ex_secret, in, ex_now));
    hdrs[1].value = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3";
    try expectDenied(.AuthorizationHeaderMalformed, try tverify(arena.allocator(), ex_ak, ex_secret, in, ex_now));
}

test "anonymous and unauthenticated requests" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const in: Input = .{ .method = "GET", .target = "/b/k", .headers = &.{.{ .name = "host", .value = "h" }} };
    try std.testing.expect((try tverify(arena.allocator(), null, "", in, 0)) == .ok);
    // Unsigned requests pass authentication as anonymous; authorization decides.
    const anon = try tverify(arena.allocator(), ex_ak, ex_secret, in, ex_now);
    try std.testing.expect(anon == .ok and anon.ok.anonymous and anon.ok.principal.len == 0);
    const partial: Input = .{ .method = "GET", .target = "/b/k?X-Amz-Credential=x", .headers = in.headers };
    try expectDenied(.AccessDenied, try tverify(arena.allocator(), ex_ak, ex_secret, partial, ex_now));
}

test "presigned GET example" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const target = "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" ++
        "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" ++
        "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" ++
        "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
    const in: Input = .{ .method = "GET", .target = target, .headers = &.{.{ .name = "Host", .value = "examplebucket.s3.amazonaws.com" }} };
    const a = arena.allocator();
    try std.testing.expect((try tverify(a, ex_ak, ex_secret, in, ex_now + 3600)) == .ok);
    try expectDenied(.AccessDenied, try tverify(a, ex_ak, ex_secret, in, ex_now + 86401));
    const bad: Input = .{ .method = "PUT", .target = target, .headers = in.headers };
    try expectDenied(.SignatureDoesNotMatch, try tverify(a, ex_ak, ex_secret, bad, ex_now));
}

fn chunkedExample(a: std.mem.Allocator, final_sig: []const u8) ![]u8 {
    var body: Writer.Allocating = .init(a);
    const w = &body.writer;
    try w.writeAll("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n");
    try w.splatByteAll('a', 65536);
    try w.writeAll("\r\n400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n");
    try w.splatByteAll('a', 1024);
    try w.print("\r\n0;chunk-signature={s}\r\n\r\n", .{final_sig});
    return body.written();
}

fn decode(a: std.mem.Allocator, auth: Auth, raw: []const u8) !struct { data: []const u8, failure: ?Code } {
    var src: Reader = .fixed(raw);
    var buf: [4096]u8 = undefined;
    var br: BodyReader = .init(auth, &src, &buf);
    var out: Writer.Allocating = .init(a);
    _ = br.body().streamRemaining(&out.writer) catch |e| switch (e) {
        error.ReadFailed => return .{ .data = out.written(), .failure = br.failure },
        else => return e,
    };
    return .{ .data = out.written(), .failure = null };
}

test "aws-chunked PUT example with per-chunk signatures" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const auth_hdr = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request," ++
        "SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class," ++
        "Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
    const in: Input = .{ .method = "PUT", .target = "/examplebucket/chunkObject.txt", .headers = &.{
        .{ .name = "Host", .value = "s3.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20130524T000000Z" },
        .{ .name = "x-amz-storage-class", .value = "REDUCED_REDUNDANCY" },
        .{ .name = "Authorization", .value = auth_hdr },
        .{ .name = "x-amz-content-sha256", .value = sv.streaming_payload },
        .{ .name = "Content-Encoding", .value = "aws-chunked" },
        .{ .name = "x-amz-decoded-content-length", .value = "66560" },
        .{ .name = "Content-Length", .value = "66824" },
    } };
    const out = try tverify(a, ex_ak, ex_secret, in, ex_now);
    try std.testing.expect(out == .ok);
    const auth = out.ok;
    try std.testing.expectEqual(@as(?u64, 66560), auth.decoded_length);

    const good = try chunkedExample(a, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");
    try std.testing.expectEqual(@as(usize, 66824), good.len);
    const ok = try decode(a, auth, good);
    try std.testing.expectEqual(@as(?Code, null), ok.failure);
    try std.testing.expectEqual(@as(usize, 66560), ok.data.len);
    try std.testing.expect(std.mem.allEqual(u8, ok.data, 'a'));

    const bad_final = try decode(a, auth, try chunkedExample(a, "0" ** 64));
    try std.testing.expectEqual(@as(?Code, .SignatureDoesNotMatch), bad_final.failure);
    const tampered = try chunkedExample(a, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");
    tampered[200] = 'b';
    try std.testing.expectEqual(@as(?Code, .SignatureDoesNotMatch), (try decode(a, auth, tampered)).failure);
    try std.testing.expectEqual(@as(?Code, .IncompleteBody), (try decode(a, auth, good[0..66000])).failure);

    // Anonymous mode still strips the framing.
    const anon = try tverify(a, null, "", in, 0);
    const plain = try decode(a, anon.ok, good);
    try std.testing.expectEqual(@as(usize, 66560), plain.data.len);
}

test "unsigned trailer chunked body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const auth: Auth = .{ .mode = .chunked_unsigned };
    const r = try decode(a, auth, "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n");
    try std.testing.expectEqual(@as(?Code, null), r.failure);
    try std.testing.expectEqualStrings("hello", r.data);
}

test "x-amz-content-sha256 verified at end of body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var auth: Auth = .{ .mode = .sha256 };
    sv.Sha256.hash("hello world", &auth.sha256, .{});
    const ok = try decode(a, auth, "hello world");
    try std.testing.expectEqual(@as(?Code, null), ok.failure);
    try std.testing.expectEqualStrings("hello world", ok.data);
    try std.testing.expectEqual(@as(?Code, .XAmzContentSHA256Mismatch), (try decode(a, auth, "hello worle")).failure);
}

/// Header-signs a GET /b/k at 20130524T000000Z, for round-trip tests.
fn signedGet(a: std.mem.Allocator, ak: []const u8, sk: []const u8, token: []const u8) !Input {
    var hdrs: std.ArrayList(Header) = .empty;
    try hdrs.appendSlice(a, &.{
        .{ .name = "Host", .value = "localhost" },
        .{ .name = "x-amz-content-sha256", .value = sv.empty_sha256_hex },
        .{ .name = "x-amz-date", .value = "20130524T000000Z" },
        .{ .name = "x-amz-security-token", .value = token },
    });
    const signed = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    const in: Input = .{ .method = "GET", .target = "/b/k", .headers = hdrs.items };
    const creq = try canonicalRequest(a, in, signed, sv.empty_sha256_hex, false);
    const scope: sv.Scope = .{ .date = "20130524", .region = "us-east-1", .service = "s3" };
    var sts: Writer.Allocating = .init(a);
    try sv.writeStringToSign(&sts.writer, "20130524T000000Z", scope, creq);
    const sig = sv.sign(sv.signingKey(sk, scope.date, scope.region, scope.service), sts.written());
    try hdrs.append(a, .{ .name = "Authorization", .value = try std.fmt.allocPrint(
        a,
        "AWS4-HMAC-SHA256 Credential={s}/{f}, SignedHeaders={s}, Signature={s}",
        .{ ak, scope, signed, &sig },
    ) });
    return .{ .method = in.method, .target = in.target, .headers = hdrs.items };
}

test "STS session credentials" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var mem: iam.store.MemoryPersistence = .{ .gpa = gpa };
    defer mem.deinit();
    var st: iam.Store = undefined;
    try st.open(gpa, mem.persistence(), .{ .root_access_key = "rootkey", .root_secret = "rootsecret" });
    defer st.deinit();
    try st.createUser("alice", "alicesecret");
    const issuer: iam.sts.Issuer = .{ .key = stsIssuerKey("rootsecret") };
    var prng = std.Random.DefaultPrng.init(1);
    var live = try issuer.issue(gpa, .{ .parent = "alice", .session_policy = 
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}
    }, ex_now - 60, prng.random());
    defer live.deinit(gpa);
    const in = try signedGet(a, &live.access_key, &live.secret_key, live.session_token);
    const cfg: Config = .{ .iam = &st, .sts = issuer };

    const out = try verify(a, cfg, in, ex_now);
    try std.testing.expect(out == .ok);
    try std.testing.expectEqualStrings("alice", out.ok.principal);
    try std.testing.expect(out.ok.session_policy != null);
    try expectDenied(.InvalidToken, try verify(a, .{ .iam = &st }, in, ex_now));
    const forged = try signedGet(a, &live.access_key, &live.secret_key, "Zm9v");
    try expectDenied(.InvalidToken, try verify(a, cfg, forged, ex_now));

    var old = try issuer.issue(gpa, .{ .parent = "alice", .duration_s = 900 }, ex_now - 900, prng.random());
    defer old.deinit(gpa);
    try expectDenied(.ExpiredToken, try verify(a, cfg, try signedGet(a, &old.access_key, &old.secret_key, old.session_token), ex_now));
}
