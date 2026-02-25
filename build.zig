const std = @import("std");
const build_helpers = @import("build_helpers.zig");
const package_name = "zeicoin";
const package_path = "src/lib.zig";

// NOTE: External Zig dependencies removed - using libpq C library for PostgreSQL.
// Core blockchain (zen_server, CLI) has ZERO external dependencies.
// System libraries: RocksDB (blockchain storage), libpq (optional PostgreSQL analytics)
//
// List of external dependencies that this package requires.
const external_dependencies = [_]build_helpers.Dependency{
    // All external dependencies removed - using C libraries instead
};

pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // **************************************************************
    // *            HANDLE DEPENDENCY MODULES                       *
    // **************************************************************
    // No external Zig module dependencies - using C libraries (libpq, rocksdb)
    // const deps = build_helpers.generateModuleDependencies(
    //     b,
    //     &external_dependencies,
    //     .{
    //         .optimize = optimize,
    //         .target = target,
    //     },
    // ) catch unreachable;

    // **************************************************************
    // *               ZEICOIN AS A MODULE                          *
    // **************************************************************
    // Create the root module for zeicoin library
    const zeicoin_module = b.createModule(.{
        .root_source_file = b.path(package_path),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Link RocksDB to the module (system dependency for core blockchain)
    zeicoin_module.linkSystemLibrary("rocksdb", .{});

    // Link libpq to the module (PostgreSQL for optional analytics/indexer)
    zeicoin_module.linkSystemLibrary("pq", .{});

    // Expose zeicoin as a public module
    try b.modules.put(b.dupe(package_name), zeicoin_module);

    // **************************************************************
    // *              ZEICOIN AS A LIBRARY                          *
    // **************************************************************
    const lib = b.addLibrary(.{
        .name = "zeicoin",
        .root_module = zeicoin_module,
        .linkage = .static,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // **************************************************************
    // *              ZEN_SERVER AS AN EXECUTABLE                   *
    // **************************************************************
    {
        const server_module = b.createModule(.{
            .root_source_file = b.path("src/apps/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        // Import zeicoin library
        server_module.addImport("zeicoin", zeicoin_module);

        const exe = b.addExecutable(.{
            .name = "zen_server",
            .root_module = server_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-server", "Run the zen server");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              ZEICOIN CLI AS AN EXECUTABLE                  *
    // **************************************************************
    {
        const cli_module = b.createModule(.{
            .root_source_file = b.path("src/apps/cli.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        // Import zeicoin library
        cli_module.addImport("zeicoin", zeicoin_module);

        const exe = b.addExecutable(.{
            .name = "zeicoin",
            .root_module = cli_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-cli", "Run the zeicoin CLI");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              ANALYTICS EXECUTABLES                         *
    // *              (Require pg dependency - now compatible)      *
    // **************************************************************

    // NOTE: pg.zig has been updated for Zig 0.16.0 compatibility (ryo-zen fork).
    // The following executables are now enabled:
    //
    // - zeicoin_indexer (requires pg) - ENABLED
    // - transaction_api (requires pg + zap) - DISABLED (zap not yet compatible)
    // - error_monitor (requires pg) - DISABLED (not needed)
    //
    // Core blockchain functionality (zen_server + CLI) works without these.

    // **************************************************************
    // *              ZEICOIN INDEXER AS AN EXECUTABLE              *
    // **************************************************************
    // Indexer uses libpq wrapper (migrated from pg.zig for Zig 0.16)
    {
        const indexer_module = b.createModule(.{
            .root_source_file = b.path("src/apps/indexer.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        indexer_module.addImport("zeicoin", zeicoin_module);
        indexer_module.linkSystemLibrary("rocksdb", .{});
        indexer_module.linkSystemLibrary("pq", .{});
        const exe = b.addExecutable(.{
            .name = "zeicoin_indexer",
            .root_module = indexer_module,
        });
        b.installArtifact(exe);
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        const run_step = b.step("run-indexer", "Run the zeicoin indexer");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *           TRANSACTION API AS AN EXECUTABLE                 *
    // **************************************************************
    {
        const api_module = b.createModule(.{
            .root_source_file = b.path("src/apps/transaction_api.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        api_module.addImport("zeicoin", zeicoin_module);
        api_module.linkSystemLibrary("pq", .{});

        const exe = b.addExecutable(.{
            .name = "transaction_api",
            .root_module = api_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-transaction-api", "Run the transaction API server (port 8080)");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *           L2 SERVICE AS AN EXECUTABLE                      *
    // **************************************************************
    {
        const l2_module = b.createModule(.{
            .root_source_file = b.path("src/apps/l2_service.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        l2_module.addImport("zeicoin", zeicoin_module);
        l2_module.linkSystemLibrary("pq", .{});

        const exe = b.addExecutable(.{
            .name = "l2_service",
            .root_module = l2_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-l2", "Run the L2 messaging service (port 8081)");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              RECOVERY TOOL                                 *
    // **************************************************************
    {
        const recovery_module = b.createModule(.{
            .root_source_file = b.path("src/tools/recover_db.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        // Import zeicoin library
        recovery_module.addImport("zeicoin", zeicoin_module);

        const exe = b.addExecutable(.{
            .name = "recover_db",
            .root_module = recovery_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        const run_step = b.step("run-recovery", "Run the DB recovery tool");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              ERROR MONITOR                                 *
    // **************************************************************
    {
        const monitor_module = b.createModule(.{
            .root_source_file = b.path("src/apps/error_monitor.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        monitor_module.addImport("zeicoin", zeicoin_module);
        monitor_module.linkSystemLibrary("pq", .{});

        const exe = b.addExecutable(.{
            .name = "zeicoin_error_monitor",
            .root_module = monitor_module,
        });

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        const run_step = b.step("run-error-monitor", "Run the error monitor");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              CHECK FOR FAST FEEDBACK LOOP                  *
    // **************************************************************
    // Tip taken from: `https://kristoff.it/blog/improving-your-zls-experience/`
    {
        const check_module = b.createModule(.{
            .root_source_file = b.path("src/apps/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        check_module.addImport("zeicoin", zeicoin_module);

        const exe_check = b.addExecutable(.{
            .name = "zen_server",
            .root_module = check_module,
        });

        const check_test_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .link_libc = true,
        });

        const check_test = b.addTest(.{
            .root_module = check_test_module,
        });

        // This step is used to check if zeicoin compiles, it helps to provide a faster feedback loop when developing.
        const check = b.step("check", "Check if zeicoin compiles");
        check.dependOn(&exe_check.step);
        check.dependOn(&check_test.step);
    }

    // **************************************************************
    // *              UNIT TESTS                                    *
    // **************************************************************

    // Create test module
    const test_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Test the library which includes all modules
    const lib_unit_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Integration tests
    {
        const tests_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        tests_module.addImport("zeicoin", zeicoin_module);

        const integration_tests = b.addTest(.{
            .root_module = tests_module,
        });
        integration_tests.root_module.linkSystemLibrary("rocksdb", .{});

        const run_integration_tests = b.addRunArtifact(integration_tests);
        const integration_test_step = b.step("test-integration", "Run all integration tests");
        integration_test_step.dependOn(&run_integration_tests.step);
        
        // Also add to main test step
        test_step.dependOn(&run_integration_tests.step);
    }

    // **************************************************************
    // *              DOCUMENTATION                                 *
    // **************************************************************
    // Only enable documentation generation if explicitly requested
    // This avoids cache issues on GitHub runners
    const docs_step = b.step("docs", "Generate documentation");

    // Check if we're in CI environment or if docs are explicitly requested
    const enable_docs = b.option(bool, "enable-docs", "Enable documentation generation") orelse false;

    if (enable_docs) {
        // Add documentation generation step
        const install_docs = b.addInstallDirectory(.{
            .source_dir = lib.getEmittedDocs(),
            .install_dir = .prefix,
            .install_subdir = "docs",
        });
        docs_step.dependOn(&install_docs.step);
    }

    // **************************************************************
    // *              FUZZ TESTS                                    *
    // **************************************************************

    // Bech32 fuzz tests
    {
        const fuzz_module = b.createModule(.{
            .root_source_file = b.path("fuzz/bech32_simple_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        fuzz_module.addImport("zeicoin", zeicoin_module);

        const bech32_fuzz_tests = b.addTest(.{
            .name = "bech32_fuzz_tests",
            .root_module = fuzz_module,
        });

        const run_bech32_fuzz = b.addRunArtifact(bech32_fuzz_tests);
        const bech32_fuzz_step = b.step("fuzz-bech32", "Run Bech32 fuzz tests");
        bech32_fuzz_step.dependOn(&run_bech32_fuzz.step);
    }

    // Network message fuzz tests
    {
        const fuzz_module = b.createModule(.{
            .root_source_file = b.path("fuzz/network_message_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        fuzz_module.addImport("zeicoin", zeicoin_module);

        const network_fuzz_tests = b.addTest(.{
            .name = "network_message_fuzz_tests",
            .root_module = fuzz_module,
        });

        const run_network_fuzz = b.addRunArtifact(network_fuzz_tests);
        const network_fuzz_step = b.step("fuzz-network", "Run network protocol fuzz tests");
        network_fuzz_step.dependOn(&run_network_fuzz.step);
    }

    // Transaction validator fuzz tests (randomized, 10k+ iterations)
    {
        const fuzz_module = b.createModule(.{
            .root_source_file = b.path("fuzz/validator_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        fuzz_module.addImport("zeicoin", zeicoin_module);

        const validator_fuzz_tests = b.addTest(.{
            .name = "validator_fuzz_tests",
            .root_module = fuzz_module,
        });

        const run_validator_fuzz = b.addRunArtifact(validator_fuzz_tests);
        const validator_fuzz_step = b.step("fuzz-validator", "Run transaction validator fuzz tests (10k iterations)");
        validator_fuzz_step.dependOn(&run_validator_fuzz.step);
    }

    // **************************************************************
    // *              CLEAN                                         *
    // **************************************************************
    const clean_step = b.step("clean", "Clean build artifacts and cache");

    // Use system command to clean directories
    const clean_cmd = b.addSystemCommand(&[_][]const u8{
        "rm",
        "-rf",
        "zig-cache",
        "zig-out",
        ".zig-cache",
    });
    clean_step.dependOn(&clean_cmd.step);
}
