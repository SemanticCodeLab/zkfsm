//! S3 error codes, HTTP statuses, and the XML error body.
const std = @import("std");
const object = @import("../object/root.zig");
const xml = @import("xml.zig");

pub const Code = enum {
    NoSuchBucket,
    NoSuchKey,
    BucketAlreadyExists,
    BucketNotEmpty,
    InvalidBucketName,
    KeyTooLongError,
    InvalidRange,
    InvalidArgument,
    InvalidURI,
    IncompleteBody,
    MethodNotAllowed,
    NotImplemented,
    InternalError,
    ServiceUnavailable,
    AccessDenied,
    SignatureDoesNotMatch,
    InvalidAccessKeyId,
    RequestTimeTooSkewed,
    AuthorizationHeaderMalformed,
    XAmzContentSHA256Mismatch,

    pub fn status(c: Code) std.http.Status {
        return switch (c) {
            .NoSuchBucket, .NoSuchKey => .not_found,
            .BucketAlreadyExists, .BucketNotEmpty => .conflict,
            .InvalidBucketName, .KeyTooLongError, .InvalidArgument, .InvalidURI, .IncompleteBody => .bad_request,
            .InvalidRange => .range_not_satisfiable,
            .MethodNotAllowed => .method_not_allowed,
            .NotImplemented => .not_implemented,
            .InternalError => .internal_server_error,
            .ServiceUnavailable => .service_unavailable,
            .AccessDenied, .SignatureDoesNotMatch, .InvalidAccessKeyId, .RequestTimeTooSkewed => .forbidden,
            .AuthorizationHeaderMalformed, .XAmzContentSHA256Mismatch => .bad_request,
        };
    }

    pub fn message(c: Code) []const u8 {
        return switch (c) {
            .NoSuchBucket => "The specified bucket does not exist",
            .NoSuchKey => "The specified key does not exist.",
            .BucketAlreadyExists => "The requested bucket name is not available.",
            .BucketNotEmpty => "The bucket you tried to delete is not empty",
            .InvalidBucketName => "The specified bucket is not valid.",
            .KeyTooLongError => "Your key is too long",
            .InvalidRange => "The requested range is not satisfiable",
            .InvalidArgument => "Invalid Argument",
            .InvalidURI => "Couldn't parse the specified URI.",
            .IncompleteBody => "You did not provide the number of bytes specified by the Content-Length HTTP header",
            .MethodNotAllowed => "The specified method is not allowed against this resource.",
            .NotImplemented => "A header or query you provided implies functionality that is not implemented",
            .InternalError => "We encountered an internal error. Please try again.",
            .ServiceUnavailable => "Reduce your request rate or retry later.",
            .AccessDenied => "Access Denied",
            .SignatureDoesNotMatch => "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
            .InvalidAccessKeyId => "The AWS Access Key Id you provided does not exist in our records.",
            .RequestTimeTooSkewed => "The difference between the request time and the server's time is too large.",
            .AuthorizationHeaderMalformed => "The authorization header or query parameters are malformed.",
            .XAmzContentSHA256Mismatch => "The provided 'x-amz-content-sha256' header does not match what was computed.",
        };
    }
};

pub fn fromObject(e: object.Error) Code {
    return switch (e) {
        error.NoSuchBucket => .NoSuchBucket,
        error.NoSuchKey => .NoSuchKey,
        error.BucketAlreadyExists => .BucketAlreadyExists,
        error.BucketNotEmpty => .BucketNotEmpty,
        error.InvalidBucketName => .InvalidBucketName,
        error.KeyTooLong => .KeyTooLongError,
        error.InvalidKey => .InvalidArgument,
        error.IncompleteBody, error.ReadFailed => .IncompleteBody,
        error.NoSpace, error.OutOfMemory => .ServiceUnavailable,
        error.StorageFailed, error.Corrupt, error.WriteFailed => .InternalError,
    };
}

pub fn writeBody(w: *std.Io.Writer, code: Code, resource: []const u8, request_id: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(xml.declaration);
    try xml.open(w, "Error");
    try xml.elem(w, "Code", @tagName(code));
    try xml.elem(w, "Message", code.message());
    try xml.elem(w, "Resource", resource);
    try xml.elem(w, "RequestId", request_id);
    try xml.close(w, "Error");
}

test "error body and status" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeBody(&w, .NoSuchKey, "/b/k", "RID");
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<Code>NoSuchKey</Code>") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "<Resource>/b/k</Resource>") != null);
    try std.testing.expectEqual(std.http.Status.not_found, fromObject(error.NoSuchKey).status());
    try std.testing.expectEqual(std.http.Status.conflict, Code.BucketNotEmpty.status());
}
