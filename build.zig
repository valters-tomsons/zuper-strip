const std = @import("std");

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const target = b.standardTargetOptions(.{
        .default_target = .{ .os_tag = .linux, .abi = .musl },
    });

    const sstrip_bin = b.addExecutable(.{ .name = "zstrip", .root_source_file = b.path("zstrip.zig"), .target = target, .optimize = optimize });
    sstrip_bin.linkLibC();

    b.installArtifact(sstrip_bin);
}
