//! Rendezvous (highest random weight) hashing: stable per-key drive ranking.
const std = @import("std");
const core = @import("../core/root.zig");

pub const max_drives = 32;

fn score(drive: core.DriveId, key: []const u8) u64 {
    var h = std.hash.Wyhash.init(0x7a6b_6673_6d00);
    h.update(&drive.bytes);
    h.update(key);
    return h.final();
}

/// Writes drive indexes into `out`, highest score first. Deterministic for a given drive set.
pub fn rank(drives: []const core.DriveId, key: []const u8, out: *[max_drives]u8) []u8 {
    const n = @min(drives.len, max_drives);
    var scores: [max_drives]u64 = undefined;
    for (0..n) |i| {
        scores[i] = score(drives[i], key);
        out[i] = @intCast(i);
    }
    // Insertion sort; n is small.
    var i: usize = 1;
    while (i < n) : (i += 1) {
        var j = i;
        while (j > 0 and scores[out[j]] > scores[out[j - 1]]) : (j -= 1) {
            std.mem.swap(u8, &out[j], &out[j - 1]);
        }
    }
    return out[0..n];
}

test "rank is deterministic, a permutation, and spreads load" {
    var ids: [4]core.DriveId = undefined;
    for (&ids, 0..) |*d, i| d.* = .{ .bytes = [_]u8{@intCast(i + 1)} ** 16 };
    var a: [max_drives]u8 = undefined;
    var b: [max_drives]u8 = undefined;
    const ra = rank(&ids, "key-1", &a);
    const rb = rank(&ids, "key-1", &b);
    try std.testing.expectEqualSlices(u8, ra, rb);
    var seen = [_]bool{false} ** 4;
    for (ra) |x| seen[x] = true;
    for (seen) |s| try std.testing.expect(s);

    var first = [_]u32{0} ** 4;
    var kb: [16]u8 = undefined;
    for (0..4000) |k| {
        const key = try std.fmt.bufPrint(&kb, "k{d}", .{k});
        first[rank(&ids, key, &a)[0]] += 1;
    }
    for (first) |c| try std.testing.expect(c > 700 and c < 1300);
}

test "removing a drive only moves keys that ranked it first" {
    var ids: [4]core.DriveId = undefined;
    for (&ids, 0..) |*d, i| d.* = .{ .bytes = [_]u8{@intCast(i + 1)} ** 16 };
    var a: [max_drives]u8 = undefined;
    var b: [max_drives]u8 = undefined;
    var kb: [16]u8 = undefined;
    for (0..500) |k| {
        const key = try std.fmt.bufPrint(&kb, "k{d}", .{k});
        const full = rank(&ids, key, &a)[0];
        const part = rank(ids[0..3], key, &b)[0];
        if (full != 3) try std.testing.expectEqual(full, part);
    }
}
