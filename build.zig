const std = @import("std");
const build_helpers = @import("build_helpers.zig");
const package_name = "zeicoin";
const package_path = "src/lib.zig";

// List of external dependencies that this package requires.
const external_dependencies = [_]build_helpers.Dependency{
    .{
        .name = "pg",
        .module_name = "pg",
    },
    .{
        .name = "zap",
        .module_name = "zap",
    },
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
    const deps = build_helpers.generateModuleDependencies(
        b,
        &external_dependencies,
        .{
            .optimize = optimize,
            .target = target,
        },
    ) catch unreachable;

    // **************************************************************
    // *               ZEICOIN AS A MODULE                          *
    // **************************************************************
    // expose zeicoin as a module
    _ = b.addModule(package_name, .{
        .root_source_file = b.path(package_path),
        .imports = deps,
    });

    // **************************************************************
    // *              ZEICOIN AS A LIBRARY                          *
    // **************************************************************
    const lib = b.addStaticLibrary(.{
        .name = "zeicoin",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Add dependency modules to the library.
    for (deps) |mod| lib.root_module.addImport(
        mod.name,
        mod.module,
    );
    lib.linkLibC();
    // Link RocksDB
    lib.linkSystemLibrary("rocksdb");
    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // **************************************************************
    // *              ZEN_SERVER AS AN EXECUTABLE                   *
    // **************************************************************
    {
        const exe = b.addExecutable(.{
            .name = "zen_server",
            .root_source_file = b.path("src/apps/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules to the executable.
        for (deps) |mod| exe.root_module.addImport(
            mod.name,
            mod.module,
        );
        exe.root_module.addImport("zeicoin", lib.root_module);
        exe.linkLibC();
        // Link RocksDB
        exe.linkSystemLibrary("rocksdb");

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
        const exe = b.addExecutable(.{
            .name = "zeicoin",
            .root_source_file = b.path("src/apps/cli.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules to the executable.
        for (deps) |mod| exe.root_module.addImport(
            mod.name,
            mod.module,
        );
        exe.root_module.addImport("zeicoin", lib.root_module);
        exe.linkLibC();
        // Link RocksDB
        exe.linkSystemLibrary("rocksdb");

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
    // *              ZEICOIN INDEXER AS AN EXECUTABLE              *
    // **************************************************************
    {
        const exe = b.addExecutable(.{
            .name = "zeicoin_indexer",
            .root_source_file = b.path("src/apps/indexer.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules to the executable.
        for (deps) |mod| exe.root_module.addImport(
            mod.name,
            mod.module,
        );
        exe.root_module.addImport("zeicoin", lib.root_module);
        exe.linkLibC();
        // Link RocksDB
        exe.linkSystemLibrary("rocksdb");

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
        const exe = b.addExecutable(.{
            .name = "transaction_api",
            .root_source_file = b.path("src/apps/transaction_api.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules
        for (deps) |mod| exe.root_module.addImport(
            mod.name,
            mod.module,
        );
        exe.root_module.addImport("zeicoin", lib.root_module);
        exe.linkLibC();

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        const run_step = b.step("run-transaction-api", "Run the transaction API server (port 8080)");
        run_step.dependOn(&run_cmd.step);
    }

    // **************************************************************
    // *              CHECK FOR FAST FEEDBACK LOOP                  *
    // **************************************************************
    // Tip taken from: `https://kristoff.it/blog/improving-your-zls-experience/`
    {
        const exe_check = b.addExecutable(.{
            .name = "zen_server",
            .root_source_file = b.path("src/apps/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules to the executable.
        for (deps) |mod| exe_check.root_module.addImport(
            mod.name,
            mod.module,
        );
        exe_check.root_module.addImport("zeicoin", lib.root_module);
        exe_check.linkLibC();

        const check_test = b.addTest(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
        });

        // This step is used to check if zeicoin compiles, it helps to provide a faster feedback loop when developing.
        const check = b.step("check", "Check if zeicoin compiles");
        check.dependOn(&exe_check.step);
        check.dependOn(&check_test.step);
    }

    // **************************************************************
    // *              UNIT TESTS                                    *
    // **************************************************************

    // Test the library which includes all modules
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add dependency modules to the test.
    for (deps) |mod| lib_unit_tests.root_module.addImport(
        mod.name,
        mod.module,
    );
    lib_unit_tests.linkLibC();

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

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
    // *              ADDITIONAL TESTS                              *
    // **************************************************************

    // Add tests here if neeed to test new test

    // **************************************************************
    // *              FUZZ TESTS                                    *
    // **************************************************************

    // Bech32 fuzz tests
    {
        const bech32_fuzz_tests = b.addTest(.{
            .name = "bech32_fuzz_tests",
            .root_source_file = b.path("fuzz/bech32_simple_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        bech32_fuzz_tests.root_module.addImport("zeicoin", lib.root_module);

        const run_bech32_fuzz = b.addRunArtifact(bech32_fuzz_tests);
        const bech32_fuzz_step = b.step("fuzz-bech32", "Run Bech32 fuzz tests");
        bech32_fuzz_step.dependOn(&run_bech32_fuzz.step);
    }

    // Network message fuzz tests
    {
        const network_fuzz_tests = b.addTest(.{
            .name = "network_message_fuzz_tests",
            .root_source_file = b.path("fuzz/network_message_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        network_fuzz_tests.root_module.addImport("zeicoin", lib.root_module);

        const run_network_fuzz = b.addRunArtifact(network_fuzz_tests);
        const network_fuzz_step = b.step("fuzz-network", "Run network protocol fuzz tests");
        network_fuzz_step.dependOn(&run_network_fuzz.step);
    }

    // Transaction validator fuzz tests (randomized, 10k+ iterations)
    {
        const validator_fuzz_tests = b.addTest(.{
            .name = "validator_fuzz_tests",
            .root_source_file = b.path("fuzz/validator_fuzz.zig"),
            .target = target,
            .optimize = optimize,
        });
        validator_fuzz_tests.root_module.addImport("zeicoin", lib.root_module);

        const run_validator_fuzz = b.addRunArtifact(validator_fuzz_tests);
        const validator_fuzz_step = b.step("fuzz-validator", "Run transaction validator fuzz tests (10k iterations)");
        validator_fuzz_step.dependOn(&run_validator_fuzz.step);
    }

    // **************************************************************
    // *              CLEAN                                         *
    // **************************************************************
    const clean_step = b.step("clean", "Clean build artifacts and cache");

    // Define directories to clean
    const dirs_to_clean = [_][]const u8{
        "zig-cache",
        "zig-out",
        ".zig-cache",
    };

    // Add remove directory commands for each directory
    for (dirs_to_clean) |dir| {
        const remove_dir = b.addRemoveDirTree(b.path(dir));
        clean_step.dependOn(&remove_dir.step);
    }
}
