//! Job templates served by generate-job; fill in the placeholders and pass
//! the file to `mc batch start`.
const spec = @import("spec.zig");

pub const replicate =
    \\replicate:
    \\  apiVersion: v1
    \\  # Objects to copy. Leave out endpoint/credentials when the source is this server.
    \\  source:
    \\    type: minio # s3 or minio
    \\    bucket: BUCKET
    \\    prefix: PREFIX # optional
    \\    # endpoint: "http[s]://HOST:PORT"
    \\    # credentials:
    \\    #   accessKey: ACCESS-KEY
    \\    #   secretKey: SECRET-KEY
    \\
    \\  # Where the objects go. Source or target (not both) may be remote.
    \\  target:
    \\    type: minio # s3 or minio
    \\    bucket: BUCKET
    \\    prefix: PREFIX # optional, prepended to every key
    \\    endpoint: "http[s]://HOST:PORT"
    \\    credentials:
    \\      accessKey: ACCESS-KEY
    \\      secretKey: SECRET-KEY
    \\
    \\  # Everything below is optional.
    \\  flags:
    \\    filter:
    \\      newerThan: "7d" # modified within this duration (e.g. 7d10h31s)
    \\      olderThan: "7d" # modified before this duration
    \\      createdAfter: "2024-01-01T00:00:00Z"
    \\      createdBefore: "2025-01-01T00:00:00Z"
    \\      # tags (local source only):
    \\      # tags:
    \\      #   - key: "name"
    \\      #     value: "pick*" # wildcard value
    \\      # metadata:
    \\      #   - key: "content-type"
    \\      #     value: "image/*"
    \\    notify:
    \\      endpoint: "https://notify.example" # receives the final job status
    \\      token: "Bearer xxxxx" # optional Authorization header
    \\    retry:
    \\      attempts: 10 # passes before the job is marked failed
    \\      delay: "500ms" # pause between passes
    \\
;

pub const keyrotate =
    \\keyrotate:
    \\  apiVersion: v1
    \\  bucket: BUCKET
    \\  prefix: PREFIX # optional
    \\  encryption:
    \\    type: sse-kms # sse-s3 or sse-kms
    \\    key: KMS-KEY # sse-kms only: the new key
    \\    context: "key1=value1,key2=value2" # sse-kms only, optional
    \\
    \\  # Everything below is optional.
    \\  flags:
    \\    filter:
    \\      newerThan: "7d"
    \\      olderThan: "7d"
    \\      createdAfter: "2024-01-01T00:00:00Z"
    \\      createdBefore: "2025-01-01T00:00:00Z"
    \\      tags:
    \\        - key: "name"
    \\          value: "pick*"
    \\      metadata:
    \\        - key: "content-type"
    \\          value: "image/*"
    \\      kmskey: "OLD-KEY" # only objects sealed under this key
    \\    notify:
    \\      endpoint: "https://notify.example"
    \\      token: "Bearer xxxxx"
    \\    retry:
    \\      attempts: 10
    \\      delay: "500ms"
    \\
;

pub const expire =
    \\expire:
    \\  apiVersion: v1
    \\  bucket: BUCKET
    \\  prefix: PREFIX # optional
    \\  # The first matching rule decides; versions beyond retainVersions are deleted.
    \\  rules:
    \\    - type: object # latest version is an object
    \\      name: "NAME*" # wildcard on the key
    \\      olderThan: 70h
    \\      createdBefore: "2006-01-02T15:04:05Z"
    \\      tags:
    \\        - key: name
    \\          value: pick*
    \\      metadata:
    \\        - key: content-type
    \\          value: image/*
    \\      size:
    \\        lessThan: 10MiB
    \\        greaterThan: 1MiB
    \\      purge:
    \\        # retainVersions: 0 # 0 (default) deletes every version
    \\
    \\    - type: deleted # latest version is a delete marker
    \\      name: "NAME*"
    \\      olderThan: 10h
    \\      purge:
    \\        # retainVersions: 0
    \\
    \\  notify:
    \\    endpoint: https://notify.example
    \\    token: Bearer xxxxx
    \\
    \\  retry:
    \\    attempts: 10
    \\    delay: 500ms
    \\
;

pub fn get(k: spec.Kind) []const u8 {
    return switch (k) {
        .replicate => replicate,
        .keyrotate => keyrotate,
        .expire => expire,
    };
}

test "templates parse once placeholders are filled" {
    const std = @import("std");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]spec.Kind{ .replicate, .keyrotate, .expire }) |k| {
        var t = try std.mem.replaceOwned(u8, a, get(k), "http[s]://HOST:PORT", "http://127.0.0.1:9000");
        t = try std.mem.replaceOwned(u8, a, t, "https://notify.example", "http://127.0.0.1:1");
        const j = try spec.parse(a, t, 0);
        try std.testing.expectEqual(k, j.kind);
    }
}
