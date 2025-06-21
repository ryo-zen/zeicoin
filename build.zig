const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    
    // Add pg.zig dependency
    const pg_dep = b.dependency("pg", .{
        .target = target,
        .optimize = optimize,
    });

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
    
    // 📊 PostgreSQL Indexer
    const zeicoin_indexer = b.addExecutable(.{
        .name = "zeicoin_indexer",
        .root_source_file = b.path("indexer.zig"),
        .target = target,
        .optimize = optimize,
    });
    zeicoin_indexer.linkLibC();
    zeicoin_indexer.root_module.addImport("pg", pg_dep.module("pg"));
    b.installArtifact(zeicoin_indexer);

    // Tests
    const main_tests = b.addTest(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_tests.linkLibC();

    const types_tests = b.addTest(.{
        .root_source_file = b.path("types.zig"),
        .target = target,
        .optimize = optimize,
    });

    const db_tests = b.addTest(.{
        .root_source_file = b.path("db.zig"),
        .target = target,
        .optimize = optimize,
    });

    const net_tests = b.addTest(.{
        .root_source_file = b.path("net.zig"),
        .target = target,
        .optimize = optimize,
    });

    const serialize_tests = b.addTest(.{
        .root_source_file = b.path("serialize.zig"),
        .target = target,
        .optimize = optimize,
    });

    const key_tests = b.addTest(.{
        .root_source_file = b.path("key.zig"),
        .target = target,
        .optimize = optimize,
    });

    const genesis_tests = b.addTest(.{
        .root_source_file = b.path("genesis.zig"),
        .target = target,
        .optimize = optimize,
    });

    const forkmanager_tests = b.addTest(.{
        .root_source_file = b.path("forkmanager.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Block security tests
    const security_tests = b.addTest(.{
        .root_source_file = b.path("block_security_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Indexer tests
    const indexer_tests = b.addTest(.{
        .root_source_file = b.path("indexer.zig"),
        .target = target,
        .optimize = optimize,
    });
    indexer_tests.root_module.addImport("pg", pg_dep.module("pg"));

    // Test step that runs all tests
    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&main_tests.step);
    test_step.dependOn(&types_tests.step);
    test_step.dependOn(&db_tests.step);
    test_step.dependOn(&net_tests.step);
    test_step.dependOn(&serialize_tests.step);
    test_step.dependOn(&key_tests.step);
    test_step.dependOn(&genesis_tests.step);
    test_step.dependOn(&forkmanager_tests.step);
    test_step.dependOn(&security_tests.step);
    test_step.dependOn(&indexer_tests.step);

    // Individual test steps
    const test_security_step = b.step("test-security", "Run block security tests");
    test_security_step.dependOn(&security_tests.step);
}
