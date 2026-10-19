#!/usr/bin/env bash
# Builds zkfsm as a pinned dependency from a local tarball: catches files the
# package needs but build.zig.zon `.paths` leaves out.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0
fail=0
check() { # name expected actual
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"
  else fail=$((fail + 1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

# The checkout as a release tarball would hold it (tracked and new files).
(cd "$ROOT" && git ls-files -co --exclude-standard -z | xargs -0 tar --transform 's,^,zkfsm/,' -czf "$WORK/zkfsm.tar.gz")
mkdir -p "$WORK/app"
cd "$WORK/app"
cat >build.zig.zon <<'ZON'
.{
    .name = .app,
    .version = "0.0.0",
    .fingerprint = 0xc96e70cf73666706,
    .minimum_zig_version = "0.15.2",
    .dependencies = .{},
    .paths = .{""},
}
ZON
cat >build.zig <<'ZIG'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const dep = b.dependency("zkfsm", .{ .target = target });
    const mod = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target });
    mod.addImport("zkfsm", dep.module("zkfsm"));
    b.installArtifact(b.addExecutable(.{ .name = "app", .root_module = mod }));
}
ZIG
cat >main.zig <<'ZIG'
const std = @import("std");
const zkfsm = @import("zkfsm");
const cluster = zkfsm.cluster;

fn layout(_: ?*anyopaque, _: std.mem.Allocator, argv: []const []const []const u8) ?cluster.StartLayout {
    return .{ .pools = argv, .retired = &.{} };
}
fn attach(_: ?*anyopaque, node: *cluster.Node) void {
    _ = node.applyMembership(.{ .epoch = 1, .pools = node.cfg.pools }) catch {};
}
fn pools(_: ?*anyopaque, m: *cluster.Pools) void {
    _ = m.decommissionStatus(0) catch {};
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const t = try cluster.parseTopology(arena.allocator(), &.{&.{"http://h{1...2}:9000/d{1...2}"}}, "h1:9000", "0.0.0.0", 9000);
    const s: cluster.Secret = cluster.fromString("x");
    _ = cluster.fromRoot("a", "b");
    if (t.nodes.len != 2 or s.len != 32) return error.Unexpected;
    if (std.os.argv.len > 1) std.process.exit(zkfsm.app.run(.{ .cluster = .{ .layout = layout, .attach = attach, .pools = pools } }));
}
ZIG
export ZIG_GLOBAL_CACHE_DIR="$WORK/gcache" ZIG_LOCAL_CACHE_DIR="$WORK/lcache"
check "fetch pins the tarball" 0 "$(zig fetch --save=zkfsm "file://$WORK/zkfsm.tar.gz" >"$WORK/fetch.log" 2>&1; echo $?)"
check "fetched package holds the console bundle" 1 "$(find "$WORK/gcache/p" -path '*/console/dist/index.html' | wc -l)"
check "app builds against the package" 0 "$(zig build >"$WORK/build.log" 2>&1; echo $?)"
[[ $fail -eq 0 ]] || { tail -n 30 "$WORK/fetch.log" "$WORK/build.log"; }
check "app runs" 0 "$(./zig-out/bin/app >/dev/null 2>&1; echo $?)"

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
