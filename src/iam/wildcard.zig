//! Glob matching for IAM patterns: `*` matches any run, `?` exactly one byte.
//! Iterative single-backtrack algorithm: O(len(pattern) * len(text)) worst case, no recursion.
const std = @import("std");

pub const Options = struct {
    ignore_case: bool = false,
    /// When set, `\` makes the next pattern byte literal (used for expanded policy variables).
    escaped: bool = false,
};

pub fn match(pattern: []const u8, text: []const u8, opts: Options) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;
    while (t < text.len) {
        if (p < pattern.len) {
            const c = pattern[p];
            if (c == '*') {
                star = p;
                mark = t;
                p += 1;
                continue;
            }
            if (c == '?') {
                p += 1;
                t += 1;
                continue;
            }
            const lit_len: usize = if (opts.escaped and c == '\\' and p + 1 < pattern.len) 2 else 1;
            const lit = pattern[p + lit_len - 1];
            if (eq(lit, text[t], opts.ignore_case)) {
                p += lit_len;
                t += 1;
                continue;
            }
        }
        const s = star orelse return false;
        p = s + 1;
        mark += 1;
        t = mark;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// True if `pattern` contains no wildcard metacharacters.
pub fn isLiteral(pattern: []const u8) bool {
    return std.mem.indexOfAny(u8, pattern, "*?") == null;
}

fn eq(a: u8, b: u8, ignore_case: bool) bool {
    if (!ignore_case) return a == b;
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

test "glob table" {
    const Case = struct { p: []const u8, t: []const u8, want: bool, ic: bool = false, esc: bool = false };
    const cases = [_]Case{
        .{ .p = "*", .t = "", .want = true },
        .{ .p = "*", .t = "anything", .want = true },
        .{ .p = "", .t = "", .want = true },
        .{ .p = "", .t = "a", .want = false },
        .{ .p = "s3:Get*", .t = "s3:GetObject", .want = true },
        .{ .p = "s3:get*", .t = "s3:GetObject", .want = false },
        .{ .p = "s3:get*", .t = "s3:GetObject", .want = true, .ic = true },
        .{ .p = "s3:*Object", .t = "s3:PutObject", .want = true },
        .{ .p = "s3:*Object", .t = "s3:PutObjectTagging", .want = false },
        .{ .p = "a?c", .t = "abc", .want = true },
        .{ .p = "a?c", .t = "ac", .want = false },
        .{ .p = "arn:aws:s3:::b/*", .t = "arn:aws:s3:::b/x/y/z", .want = true },
        .{ .p = "arn:aws:s3:::b/*", .t = "arn:aws:s3:::b", .want = false },
        .{ .p = "*a*b*c*", .t = "xxaxxbxxcxx", .want = true },
        .{ .p = "*a*b*c*", .t = "xxaxxcxxbxx", .want = false },
        .{ .p = "a\\*b", .t = "a*b", .want = true, .esc = true },
        .{ .p = "a\\*b", .t = "axb", .want = false, .esc = true },
        .{ .p = "a\\*b", .t = "a\\xb", .want = true },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.want, match(c.p, c.t, .{ .ignore_case = c.ic, .escaped = c.esc }));
    }
}

test "pathological pattern stays polynomial" {
    var pat: [200]u8 = undefined;
    for (&pat, 0..) |*b, i| b.* = if (i % 2 == 0) '*' else 'a';
    var txt: [1000]u8 = undefined;
    @memset(&txt, 'a');
    txt[txt.len - 1] = 'b';
    try std.testing.expect(!match(&pat, &txt, .{}));
}
