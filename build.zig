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
    // *              ANALYTICS REST API AS AN EXECUTABLE          *
    // **************************************************************
    {
        const exe = b.addExecutable(.{
            .name = "analytics_api",
            .root_source_file = b.path("src/apps/analytics_rest_api.zig"),
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

        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("run-analytics", "Run the analytics REST API");
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
    // Add documentation generation step
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);

    // **************************************************************
    // *              MEMORY CORRUPTION TEST                        *
    // **************************************************************
    {
        const test_exe = b.addExecutable(.{
            .name = "test_memory_corruption",
            .root_source_file = b.path("tests/test_memory_corruption.zig"),
            .target = target,
            .optimize = optimize,
        });
        // Add dependency modules to the executable.
        for (deps) |mod| test_exe.root_module.addImport(
            mod.name,
            mod.module,
        );
        test_exe.root_module.addImport("zeicoin", lib.root_module);
        test_exe.linkLibC();

        b.installArtifact(test_exe);

        const run_test_cmd = b.addRunArtifact(test_exe);
        run_test_cmd.step.dependOn(b.getInstallStep());

        const run_test_step = b.step("test-memory", "Run memory corruption test");
        run_test_step.dependOn(&run_test_cmd.step);
    }

    // **************************************************************
    // *              ADDITIONAL TESTS                              *
    // **************************************************************
    
    // Block security tests
    {
        const security_tests = b.addTest(.{
            .name = "security_tests",
            .root_source_file = b.path("tests/block_security_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        security_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_security_tests = b.addRunArtifact(security_tests);
        const security_test_step = b.step("test-security", "Run security tests");
        security_test_step.dependOn(&run_security_tests.step);
    }
    
    // Bech32 address tests
    {
        const bech32_tests = b.addTest(.{
            .name = "bech32_tests", 
            .root_source_file = b.path("tests/test_bech32_addresses.zig"),
            .target = target,
            .optimize = optimize,
        });
        bech32_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_bech32_tests = b.addRunArtifact(bech32_tests);
        const bech32_test_step = b.step("test-bech32", "Run Bech32 address tests");
        bech32_test_step.dependOn(&run_bech32_tests.step);
    }
    
    // Address versioning tests
    {
        const versioning_tests = b.addTest(.{
            .name = "versioning_tests",
            .root_source_file = b.path("tests/test_address_versioning.zig"), 
            .target = target,
            .optimize = optimize,
        });
        versioning_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_versioning_tests = b.addRunArtifact(versioning_tests);
        const versioning_test_step = b.step("test-versioning", "Run address versioning tests");
        versioning_test_step.dependOn(&run_versioning_tests.step);
    }
    
    // Transaction signing tests
    {
        const tx_tests = b.addExecutable(.{
            .name = "tx_signing_test",
            .root_source_file = b.path("tests/test_tx_signing.zig"),
            .target = target,
            .optimize = optimize,
        });
        tx_tests.root_module.addImport("zeicoin", lib.root_module);
        tx_tests.linkLibC();
        
        const run_tx_tests = b.addRunArtifact(tx_tests);
        const tx_test_step = b.step("test-tx-signing", "Run transaction signing tests");
        tx_test_step.dependOn(&run_tx_tests.step);
    }
    
    // CLI spinner tests
    {
        const spinner_tests = b.addExecutable(.{
            .name = "spinner_test",
            .root_source_file = b.path("tests/testcli.zig"),
            .target = target, 
            .optimize = optimize,
        });
        spinner_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_spinner_tests = b.addRunArtifact(spinner_tests);
        const spinner_test_step = b.step("test-spinners", "Run CLI spinner tests");
        spinner_test_step.dependOn(&run_spinner_tests.step);
    }
    
    // Creative spinner tests
    {
        const creative_tests = b.addExecutable(.{
            .name = "creative_test",
            .root_source_file = b.path("tests/testcreative.zig"),
            .target = target,
            .optimize = optimize,
        });
        creative_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_creative_tests = b.addRunArtifact(creative_tests);
        const creative_test_step = b.step("test-creative", "Run creative spinner tests");
        creative_test_step.dependOn(&run_creative_tests.step);
    }
    
    // Network protocol tests
    {
        const protocol_tests = b.addTest(.{
            .name = "protocol_tests",
            .root_source_file = b.path("tests/protocol_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        protocol_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_protocol_tests = b.addRunArtifact(protocol_tests);
        const protocol_test_step = b.step("test-protocol", "Run network protocol tests");
        protocol_test_step.dependOn(&run_protocol_tests.step);
    }
    
    // Server component tests
    {
        const server_tests = b.addTest(.{
            .name = "server_tests",
            .root_source_file = b.path("tests/server_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        server_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_server_tests = b.addRunArtifact(server_tests);
        const server_test_step = b.step("test-server", "Run server component tests");
        server_test_step.dependOn(&run_server_tests.step);
    }
    
    // Parallel download tests
    {
        const download_tests = b.addTest(.{
            .name = "download_tests",
            .root_source_file = b.path("tests/parrallel_download_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        download_tests.root_module.addImport("zeicoin", lib.root_module);
        
        const run_download_tests = b.addRunArtifact(download_tests);
        const download_test_step = b.step("test-download", "Run parallel download tests");
        download_test_step.dependOn(&run_download_tests.step);
    }
    
    // Address validation test (executable)
    {
        const addr_validation_test = b.addExecutable(.{
            .name = "test_address_validation",
            .root_source_file = b.path("tests/test_address_validation.zig"),
            .target = target,
            .optimize = optimize,
        });
        addr_validation_test.root_module.addImport("zeicoin", lib.root_module);
        addr_validation_test.linkLibC();
        
        const run_addr_test = b.addRunArtifact(addr_validation_test);
        const addr_test_step = b.step("test-address-validation", "Run address validation test");
        addr_test_step.dependOn(&run_addr_test.step);
    }
    
    // Mempool flood test (executable)
    {
        const mempool_flood_test = b.addExecutable(.{
            .name = "test_mempool_flood",
            .root_source_file = b.path("tests/test_mempool_flood.zig"),
            .target = target,
            .optimize = optimize,
        });
        mempool_flood_test.root_module.addImport("zeicoin", lib.root_module);
        mempool_flood_test.linkLibC();
        
        const run_mempool_test = b.addRunArtifact(mempool_flood_test);
        const mempool_test_step = b.step("test-mempool-flood", "Run mempool flood test");
        mempool_test_step.dependOn(&run_mempool_test.step);
    }

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
