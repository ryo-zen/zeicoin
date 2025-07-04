// main.zig - ZeiCoin Node Entry Point
// This is the main entry point for the zeicoin node executable

const std = @import("std");
const print = std.debug.print;

// Import the server module which contains the actual node implementation
const zeicoin = @import("zeicoin");
const server = zeicoin.server;

pub fn main() !void {
    // Forward to the server's main function
    try server.main();
}