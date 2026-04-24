// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// main.zig - ZeiCoin Node Entry Point
// This is the main entry point for the zeicoin node executable

const std = @import("std");
const builtin = @import("builtin");

// Configure logging for the entire application
pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
    },
};

// Import the server module which contains the actual node implementation
const zeicoin = @import("zeicoin");
const server = zeicoin.server;

pub fn main(init: std.process.Init) !void {
    // Forward to the server's main function
    try server.main(init);
}