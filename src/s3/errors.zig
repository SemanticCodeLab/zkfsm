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
    InvalidToken,
    ExpiredToken,
    PreconditionFailed,
    NoSuchVersion,
    InvalidRequest,
    InvalidBucketState,
    ObjectLockConfigurationNotFoundError,
    NoSuchObjectLockConfiguration,
    NoSuchTagSet,
    InvalidTag,
    MalformedXML,
    NoSuchUpload,
    InvalidPart,
    InvalidPartOrder,
    EntityTooSmall,
    EntityTooLarge,
    MetadataTooLarge,
    BadDigest,
    InvalidDigest,
    NoSuchLifecycleConfiguration,
    NoSuchBucketPolicy,
    MalformedPolicy,
    InvalidPartNumber,

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
            .AuthorizationHeaderMalformed, .XAmzContentSHA256Mismatch, .InvalidToken, .ExpiredToken => .bad_request,
            .PreconditionFailed => .precondition_failed,
            .NoSuchVersion, .ObjectLockConfigurationNotFoundError, .NoSuchObjectLockConfiguration, .NoSuchTagSet => .not_found,
            .InvalidRequest, .InvalidTag, .MalformedXML => .bad_request,
            .InvalidBucketState => .conflict,
            .NoSuchUpload => .not_found,
            .InvalidPart, .InvalidPartOrder, .EntityTooSmall, .EntityTooLarge, .MetadataTooLarge, .BadDigest, .InvalidDigest => .bad_request,
            .NoSuchLifecycleConfiguration, .NoSuchBucketPolicy => .not_found,
            .MalformedPolicy => .bad_request,
            .InvalidPartNumber => .range_not_satisfiable,
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
            .InvalidAccessKeyId => "The access key ID you provided does not exist in our records.",
            .RequestTimeTooSkewed => "The difference between the request time and the server's time is too large.",
            .AuthorizationHeaderMalformed => "The authorization header or query parameters are malformed.",
            .XAmzContentSHA256Mismatch => "The provided 'x-amz-content-sha256' header does not match what was computed.",
            .InvalidToken => "The provided token is malformed or otherwise invalid.",
            .ExpiredToken => "The provided token has expired.",
            .PreconditionFailed => "At least one of the pre-conditions you specified did not hold",
            .NoSuchVersion => "The specified version does not exist.",
            .InvalidRequest => "Invalid Request",
            .InvalidBucketState => "The request is not valid with the current state of the bucket.",
            .ObjectLockConfigurationNotFoundError => "Object Lock configuration does not exist for this bucket",
            .NoSuchObjectLockConfiguration => "The specified object does not have a ObjectLock configuration",
            .NoSuchTagSet => "The TagSet does not exist",
            .InvalidTag => "The tag provided was not a valid tag.",
            .MalformedXML => "The XML you provided was not well-formed or did not validate against our published schema.",
            .NoSuchUpload => "The specified multipart upload does not exist.",
            .InvalidPart => "One or more of the specified parts could not be found or its entity tag did not match.",
            .InvalidPartOrder => "The list of parts was not in ascending order.",
            .EntityTooSmall => "Your proposed upload is smaller than the minimum allowed object size.",
            .EntityTooLarge => "Your proposed upload exceeds the maximum allowed size.",
            .MetadataTooLarge => "Your metadata headers exceed the maximum allowed metadata size.",
            .BadDigest => "The Content-MD5 you specified did not match what we received.",
            .InvalidDigest => "The Content-MD5 you specified is not valid.",
            .NoSuchLifecycleConfiguration => "The lifecycle configuration does not exist",
            .NoSuchBucketPolicy => "The bucket policy does not exist",
            .MalformedPolicy => "Policies must be valid JSON and the first byte must be '{'",
            .InvalidPartNumber => "The requested partnumber is not satisfiable",
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
        error.PreconditionFailed => .PreconditionFailed,
        error.ObjectLocked => .AccessDenied,
        error.NoSuchVersion => .NoSuchVersion,
        error.InvalidVersionId => .InvalidArgument,
        error.InvalidRequest => .InvalidRequest,
        error.InvalidBucketState => .InvalidBucketState,
        error.MethodNotAllowed => .MethodNotAllowed,
        error.NoSuchTagSet => .NoSuchTagSet,
        error.InvalidTag => .InvalidTag,
        error.MetadataTooLarge => .MetadataTooLarge,
        error.BadDigest => .BadDigest,
        error.InvalidMetadata => .InvalidArgument,
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
