// cli_new.zig - Modular ZeiCoin Command Line Interface
// Clean main entry point that delegates to specialized modules

const std = @import("std");
const log = std.log.scoped(.cli);
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

// Import CLIError from transaction commands for error handling
const TransactionCLIError = transaction_commands.CLIError;

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
            log.info("⚠️  Warning: Failed to load .env file: {}", .{err});
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
    
    // Ensure cleanup happens even on early returns
    defer transaction_commands.cleanupGlobalNonceManager();

    // Delegate to appropriate command handler
    switch (command) {
        .wallet => try wallet_commands.handleWallet(allocator, args[2..]),
        .balance => transaction_commands.handleBalance(allocator, args[2..]) catch |err| {
            switch (err) {
                TransactionCLIError.TransactionFailed => std.process.exit(1),
                TransactionCLIError.NetworkError => std.process.exit(1),
                else => return err,
            }
        },
        .send => transaction_commands.handleSend(allocator, args[2..]) catch |err| {
            switch (err) {
                TransactionCLIError.TransactionFailed => std.process.exit(1),
                TransactionCLIError.NetworkError => std.process.exit(1),
                else => return err,
            }
        },
        .status => try network_commands.handleStatus(allocator, args[2..]),
        .address => try wallet_commands.handleAddress(allocator, args[2..]),
        .sync => try network_commands.handleSync(allocator, args[2..]),
        .block => try network_commands.handleBlock(allocator, args[2..]),
        .history => transaction_commands.handleHistory(allocator, args[2..]) catch |err| {
            switch (err) {
                TransactionCLIError.TransactionFailed => std.process.exit(1),
                TransactionCLIError.NetworkError => std.process.exit(1),
                else => return err,
            }
        },
        .seed, .mnemonic => try wallet_commands.handleSeed(allocator, args[2..]),
        .help => display.printHelp(),
    }
}