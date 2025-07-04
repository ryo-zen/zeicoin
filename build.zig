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
