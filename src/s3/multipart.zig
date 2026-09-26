//! Multipart upload. Not implemented; requests get NotImplemented.
const std = @import("std");

/// True when the query names a multipart subresource (`uploads` or `uploadId`).
pub fn isMultipartRequest(query: []const u8) bool {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const k = pair[0 .. std.mem.indexOfScalar(u8, pair, '=') orelse pair.len];
        if (std.mem.eql(u8, k, "uploads") or std.mem.eql(u8, k, "uploadId")) return true;
    }
    return false;
}

test "multipart detection" {
    try std.testing.expect(isMultipartRequest("uploads"));
    try std.testing.expect(isMultipartRequest("partNumber=1&uploadId=x"));
    try std.testing.expect(!isMultipartRequest("list-type=2"));
}
