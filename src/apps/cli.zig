// cli_new.zig - Modular ZeiCoin Command Line Interface
// Clean main entry point that delegates to specialized modules

const std = @import("std");
const print = std.debug.print;

const zeicoin = @import("zeicoin");

// Import our modular CLI components
const wallet_commands = @import("cli/commands/wallet.zig");
const transaction_commands = @import("cli/commands/transaction.zig");
const network_commands = @import("cli/commands/network.zig");
const display = @import("cli/utils/display.zig");

const CLIError = error{
    InvalidCommand,
    InvalidArguments,
};

const Command = enum {
    wallet,
    balance,
    send,
    status,
    address,
    sync,
    block,
    history,
    seed,
    mnemonic,
    help,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Load .env file if present (before processing arguments)
    zeicoin.dotenv.loadForNetwork(allocator) catch |err| {
        // Don't fail if .env loading fails, just warn
        if (err != error.FileNotFound) {
            print("⚠️  Warning: Failed to load .env file: {}\n", .{err});
        }
    };
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        display.printHelp();
        return;
    }
    
    const command_str = args[1];
    const command = std.meta.stringToEnum(Command, command_str) orelse {
        print("❌ Unknown command: {s}\n", .{command_str});
        print("💡 Use 'zeicoin help' to see available commands\n", .{});
        display.printHelp();
        return;
    };
    
    // Delegate to appropriate command handler
    switch (command) {
        .wallet => try wallet_commands.handleWallet(allocator, args[2..]),
        .balance => try transaction_commands.handleBalance(allocator, args[2..]),
        .send => try transaction_commands.handleSend(allocator, args[2..]),
        .status => try network_commands.handleStatus(allocator, args[2..]),
        .address => try wallet_commands.handleAddress(allocator, args[2..]),
        .sync => try network_commands.handleSync(allocator, args[2..]),
        .block => try network_commands.handleBlock(allocator, args[2..]),
        .history => try transaction_commands.handleHistory(allocator, args[2..]),
        .seed, .mnemonic => try wallet_commands.handleSeed(allocator, args[2..]),
        .help => display.printHelp(),
    }
}