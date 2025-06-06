const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 🖥️ Zen Server
    const zen_server = b.addExecutable(.{
        .name = "zen_server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize,
    });
    zen_server.linkLibC();
    b.installArtifact(zen_server);

    // ZeiCoin CLI - Zen command line interface
    const zeicoin_cli = b.addExecutable(.{
        .name = "zeicoin",
        .root_source_file = b.path("cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeicoin_cli.linkLibC();
    b.installArtifact(zeicoin_cli);
}
