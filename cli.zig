// cli.zig - ZeiCoin Command Line Interface
// Simple CLI tool for everyday Zeicoin operations

const std = @import("std");
const print = std.debug.print;
const net = std.net;
const Thread = std.Thread;

const types = @import("types.zig");
const wallet = @import("wallet.zig");
const db = @import("db.zig");
const util = @import("util.zig");

const CLIError = error{
    InvalidCommand,
    InvalidArguments,
    WalletNotFound,
    NetworkError,
    InsufficientArguments,
    ConnectionTimeout,
    ConnectionFailed,
    ThreadSpawnFailed,
    ReadTimeout,
    ReadFailed,
};

// Auto-detect server IP by checking common interfaces
fn autoDetectServerIP(allocator: std.mem.Allocator) ?[]const u8 {
    // Try to get local IP from hostname command
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "hostname", "-I" },
    }) catch return null;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited == 0 and result.stdout.len > 0) {
        // Parse first IP from output
        var it = std.mem.splitScalar(u8, result.stdout, ' ');
        if (it.next()) |first_ip| {
            const trimmed = std.mem.trim(u8, first_ip, " \t\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
        }
    }

    return null;
}

fn getServerIP(allocator: std.mem.Allocator) ![]const u8 {
    // 1. Try environment variable first
    if (std.process.getEnvVarOwned(allocator, "ZEICOIN_SERVER")) |server_ip| {
        return server_ip;
    } else |_| {}

    // 2. Try auto-detection with connection test
    if (autoDetectServerIP(allocator)) |detected_ip| {
        defer allocator.free(detected_ip);

        // Test if detected IP actually has a ZeiCoin server
        if (testServerConnection(detected_ip)) {
            print("🔍 Auto-detected server IP: {s}\n", .{detected_ip});
            return allocator.dupe(u8, detected_ip);
        } else {
            print("🔍 Auto-detected {s} but no ZeiCoin server found\n", .{detected_ip});
        }
    }

    // 3. Try bootstrap servers from types.zig
    for (types.BOOTSTRAP_NODES) |bootstrap_addr| {
        // Parse IP from "ip:port" format
        var it = std.mem.splitScalar(u8, bootstrap_addr, ':');
        if (it.next()) |ip_str| {
            if (testServerConnection(ip_str)) {
                print("🌐 Found ZeiCoin server at bootstrap node: {s}\n", .{ip_str});
                return allocator.dupe(u8, ip_str);
            }
        }
    }

    // 4. Final fallback to localhost
    print("💡 Using localhost fallback (set ZEICOIN_SERVER to override)\n", .{});
    return allocator.dupe(u8, "127.0.0.1");
}

// Connect with 5 second timeout using thread-based approach
fn connectWithTimeout(address: net.Address) !net.Stream {
    const ConnectResult = struct {
        result: ?net.Stream = null,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var connect_result = ConnectResult{};

    // Spawn thread for connection attempt
    const connect_thread = std.Thread.spawn(.{}, struct {
        fn connectWorker(addr: net.Address, result: *ConnectResult) void {
            result.result = net.tcpConnectToAddress(addr) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.connectWorker, .{ address, &connect_result }) catch {
        return error.ThreadSpawnFailed;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!connect_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return error.ConnectionTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    connect_thread.join();

    if (connect_result.error_occurred) {
        return error.ConnectionFailed;
    }

    return connect_result.result orelse error.ConnectionFailed;
}

// Read with 5 second timeout using thread-based approach
fn readWithTimeout(stream: net.Stream, buffer: []u8) !usize {
    const ReadResult = struct {
        bytes_read: usize = 0,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var read_result = ReadResult{};

    // Spawn thread for read attempt
    const read_thread = std.Thread.spawn(.{}, struct {
        fn readWorker(s: net.Stream, buf: []u8, result: *ReadResult) void {
            result.bytes_read = s.read(buf) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.readWorker, .{ stream, buffer, &read_result }) catch {
        return error.ThreadSpawnFailed;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!read_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return error.ReadTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    read_thread.join();

    if (read_result.error_occurred) {
        return error.ReadFailed;
    }

    return read_result.bytes_read;
}

// Test if a server IP actually has ZeiCoin running on port 10802
fn testServerConnection(ip: []const u8) bool {
    const address = net.Address.parseIp4(ip, 10802) catch return false;

    // Quick connection test
    var stream = connectWithTimeout(address) catch return false;
    defer stream.close();

    return true;
}

const Command = enum {
    wallet,
    balance,
    send,
    status,
    address,
    fund,
    sync,
    help,
};

const WalletSubcommand = enum {
    create,
    load,
    list,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printHelp();
        return;
    }

    const command_str = args[1];
    const command = std.meta.stringToEnum(Command, command_str) orelse {
        print("❌ Unknown command: {s}\n", .{command_str});
        print("💡 Use 'zeicoin help' to see available commands\n", .{});
        printHelp();
        return;
    };

    switch (command) {
        .wallet => try handleWalletCommand(allocator, args[2..]),
        .balance => try handleBalanceCommand(allocator, args[2..]),
        .send => try handleSendCommand(allocator, args[2..]),
        .status => try handleStatusCommand(allocator, args[2..]),
        .address => try handleAddressCommand(allocator, args[2..]),
        .fund => try handleFundCommand(allocator, args[2..]),
        .sync => try handleSyncCommand(allocator, args[2..]),
        .help => printHelp(),
    }
}

fn handleWalletCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Wallet subcommand required\n", .{});
        print("Usage: zeicoin wallet <create|load|list> [name]\n", .{});
        return;
    }

    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(WalletSubcommand, subcommand_str) orelse {
        print("❌ Unknown wallet subcommand: {s}\n", .{subcommand_str});
        return;
    };

    switch (subcommand) {
        .create => try createWallet(allocator, args[1..]),
        .load => try loadWallet(allocator, args[1..]),
        .list => try listWallets(allocator),
    }
}

fn createWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    print("💳 Creating new ZeiCoin wallet: {s}\n", .{wallet_name});

    // Initialize database with network-specific directory
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    var database = try db.Database.init(allocator, data_dir);
    defer database.deinit();

    // Check if wallet already exists
    if (database.walletExists(wallet_name)) {
        print("❌ Wallet '{s}' already exists\n", .{wallet_name});
        return;
    }

    // Create new wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    try zen_wallet.createNew();

    // Get wallet path and save
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    const password = "zen"; // Simple password for demo - could be made configurable
    try zen_wallet.saveToFile(wallet_path, password);

    const address = zen_wallet.getAddress() orelse return error.WalletCreationFailed;
    print("✅ Wallet '{s}' created successfully!\n", .{wallet_name});
    print("🆔 Address: {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
    print("💡 Use 'zeicoin fund' to get test ZEI for this wallet\n", .{});
}

fn loadWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    print("🔓 Loading ZeiCoin wallet: {s}\n", .{wallet_name});

    // Initialize database with network-specific directory
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    var database = try db.Database.init(allocator, data_dir);
    defer database.deinit();

    if (!database.walletExists(wallet_name)) {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        print("💡 Use 'zeicoin wallet create {s}' to create it\n", .{wallet_name});
        return;
    }

    // Load wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    const password = "zen";
    try zen_wallet.loadFromFile(wallet_path, password);

    const address = zen_wallet.getAddress() orelse return error.WalletLoadFailed;
    print("✅ Wallet '{s}' loaded successfully!\n", .{wallet_name});
    print("🆔 Address: {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
}

fn listWallets(allocator: std.mem.Allocator) !void {
    _ = allocator;
    print("📁 Available ZeiCoin wallets:\n", .{});

    // Use network-specific wallet directory
    const wallets_path = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet/wallets",
        .mainnet => "zeicoin_data_mainnet/wallets",
    };

    var wallets_dir = std.fs.cwd().openDir(wallets_path, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            print("   No wallets found. Use 'zeicoin wallet create' to create one.\n", .{});
            return;
        }
        return err;
    };
    defer wallets_dir.close();

    var iterator = wallets_dir.iterate();
    var wallet_count: u32 = 0;

    while (try iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wallet")) {
            const wallet_name = entry.name[0 .. entry.name.len - 7]; // Remove .wallet extension
            print("   • {s}\n", .{wallet_name});
            wallet_count += 1;
        }
    }

    if (wallet_count == 0) {
        print("   No wallets found. Use 'zeicoin wallet create' to create one.\n", .{});
    } else {
        print("💡 Use 'zeicoin wallet load <name>' to load a wallet\n", .{});
    }
}

fn handleBalanceCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;

    // Connect to server and check balance
    const balance = getBalanceFromServer(allocator, address) catch |err| {
        switch (err) {
            error.NetworkError => {
                print("❌ Cannot connect to ZeiCoin server\n", .{});
                print("💡 Make sure the server is running\n", .{});
                return;
            },
            else => return err,
        }
    };

    // Format balance properly for display
    const balance_display = util.formatZEI(allocator, balance) catch "? ZEI";
    defer if (!std.mem.eql(u8, balance_display, "? ZEI")) allocator.free(balance_display);

    print("💰 Wallet '{s}' balance: {s}\n", .{ wallet_name, balance_display });
    print("🆔 Address: {s}\n", .{std.fmt.fmtSliceHexLower(address[0..16])});
}

fn handleSendCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) {
        print("❌ Usage: zeicoin send <amount> <recipient_address> [wallet_name]\n", .{});
        print("💡 Example: zeicoin send 10 a1b2c3d4e5f6... alice\n", .{});
        return;
    }

    const amount_str = args[0];
    const recipient_hex = args[1];
    const wallet_name = if (args.len > 2) args[2] else "default";

    // Parse amount
    const amount_zei = std.fmt.parseInt(u64, amount_str, 10) catch {
        print("❌ Invalid amount: {s}\n", .{amount_str});
        print("💡 Amount must be a positive number (in ZEI)\n", .{});
        return;
    };
    // Check for overflow when converting to zei units
    const amount = std.math.mul(u64, amount_zei, types.ZEI_COIN) catch {
        print("❌ Amount too large: {s} ZEI\n", .{amount_str});
        print("💡 Maximum amount is {} ZEI\n", .{std.math.maxInt(u64) / types.ZEI_COIN});
        return;
    };

    // Parse recipient address
    var recipient_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&recipient_address, recipient_hex) catch {
        print("❌ Invalid recipient address format\n", .{});
        print("💡 Address must be 64 hex characters (32 bytes)\n", .{});
        return;
    };

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const sender_address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;
    const sender_public_key = zen_wallet.getPublicKey() orelse return error.WalletNotLoaded;

    print("💸 Sending {} ZEI from wallet '{s}'...\n", .{ amount_zei, wallet_name });
    print("🆔 From: {s}\n", .{std.fmt.fmtSliceHexLower(sender_address[0..16])});
    print("🎯 To: {s}\n", .{std.fmt.fmtSliceHexLower(recipient_address[0..16])});

    // Create and send transaction
    sendTransaction(allocator, zen_wallet, sender_address, sender_public_key, recipient_address, amount) catch |err| {
        switch (err) {
            error.TransactionFailed => {
                // Error message already printed in sendTransaction
                return;
            },
            error.NetworkError => {
                print("❌ Cannot connect to ZeiCoin server\n", .{});
                print("💡 Make sure the server is running\n", .{});
                return;
            },
            else => return err,
        }
    };

    print("✅ Transaction sent successfully!\n", .{});
    print("💡 Use 'zeicoin balance' to check updated balance\n", .{});
}

fn handleStatusCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    _ = args;

    print("📊 ZeiCoin Network Status:\n", .{});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const address = net.Address.parseIp4(server_ip, 10802) catch {
        print("❌ Invalid server address\n", .{});
        return;
    };

    const connection = connectWithTimeout(address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802 (5s)\n", .{server_ip});
                return;
            },
            else => {
                print("❌ Cannot connect to ZeiCoin server at {s}:10802\n", .{server_ip});
                print("💡 Make sure the server is running\n", .{});
                return;
            },
        }
    };
    defer connection.close();

    // Send status request
    try connection.writeAll("BLOCKCHAIN_STATUS");

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Server response timeout (5s)\n", .{});
                return;
            },
            else => {
                print("❌ Failed to read server response\n", .{});
                return;
            },
        }
    };
    const response = buffer[0..bytes_read];

    print("🌐 Server: {s}:10802\n", .{server_ip});
    print("📨 Status: {s}\n", .{response});
}

fn handleAddressCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;

    print("🆔 Wallet '{s}' address:\n", .{wallet_name});
    print("   {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
    print("📋 Short address: {s}\n", .{std.fmt.fmtSliceHexLower(address[0..16])});
}

fn handleSyncCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    _ = args;

    print("🔄 Triggering manual blockchain sync...\n", .{});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const address = net.Address.parseIp4(server_ip, 10802) catch {
        print("❌ Invalid server address\n", .{});
        return;
    };

    const connection = connectWithTimeout(address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802 (5s)\n", .{server_ip});
                return;
            },
            else => {
                print("❌ Cannot connect to ZeiCoin server at {s}:10802\n", .{server_ip});
                print("💡 Make sure the server is running\n", .{});
                return;
            },
        }
    };
    defer connection.close();

    // Send sync trigger request
    try connection.writeAll("TRIGGER_SYNC");

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Server response timeout (5s)\n", .{});
                return;
            },
            else => {
                print("❌ Failed to read server response\n", .{});
                return;
            },
        }
    };
    const response = buffer[0..bytes_read];

    print("🌐 Server: {s}:10802\n", .{server_ip});
    print("📨 Sync response: {s}\n", .{response});
}

fn handleFundCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;

    print("💰 Requesting test funds for wallet '{s}'...\n", .{wallet_name});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        print("❌ Invalid server address\n", .{});
        return;
    };

    const connection = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802\n", .{server_ip});
                print("💡 Server did not respond within 5 seconds\n", .{});
                return;
            },
            error.ConnectionFailed => {
                print("❌ Connection failed to ZeiCoin server at {s}:10802\n", .{server_ip});
                print("💡 Make sure the server is running and accessible\n", .{});
                return;
            },
            error.ThreadSpawnFailed => {
                print("❌ System error: Could not create connection thread\n", .{});
                return;
            },
        }
    };
    defer connection.close();

    // Send funding request
    const fund_request = try std.fmt.allocPrint(allocator, "FUND_WALLET:{s}", .{std.fmt.fmtSliceHexLower(&address)});
    defer allocator.free(fund_request);

    try connection.writeAll(fund_request);

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Server response timeout (5s) - server may be busy\n", .{});
                return;
            },
            error.ReadFailed => {
                print("❌ Failed to read server response\n", .{});
                return;
            },
            error.ThreadSpawnFailed => {
                print("❌ System error: Could not create read thread\n", .{});
                return;
            },
        }
    };
    const response = buffer[0..bytes_read];

    if (std.mem.startsWith(u8, response, "WALLET_FUNDED")) {
        print("✅ Wallet funded successfully!\n", .{});
        print("💰 Received test ZEI for development\n", .{});
        print("💡 Use 'zeicoin balance' to check your balance\n", .{});
    } else {
        print("❌ Funding failed: {s}\n", .{response});
    }
}

// Helper functions

fn loadWalletForOperation(allocator: std.mem.Allocator, wallet_name: []const u8) !*wallet.Wallet {
    // Initialize database with network-specific directory
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    var database = try db.Database.init(allocator, data_dir);
    defer database.deinit();

    if (!database.walletExists(wallet_name)) {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        print("💡 Use 'zeicoin wallet create {s}' to create it\n", .{wallet_name});
        return error.WalletNotFound;
    }

    // Create wallet
    const zen_wallet = try allocator.create(wallet.Wallet);
    zen_wallet.* = wallet.Wallet.init(allocator);
    errdefer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    // Load wallet
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    // Use appropriate password based on wallet name
    const password = if (std.mem.eql(u8, wallet_name, "server_miner")) "zen_miner" else "zen";
    zen_wallet.loadFromFile(wallet_path, password) catch {
        print("❌ Failed to load wallet '{s}'\n", .{wallet_name});
        return error.WalletNotFound;
    };

    return zen_wallet;
}

fn getBalanceFromServer(allocator: std.mem.Allocator, address: types.Address) !u64 {
    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        return error.NetworkError;
    };

    const connection = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802 (5s)\n", .{server_ip});
                return error.NetworkError;
            },
            else => {
                print("❌ Cannot connect to ZeiCoin server at {s}:10802\n", .{server_ip});
                return error.NetworkError;
            },
        }
    };
    defer connection.close();

    // Send balance request
    const balance_request = try std.fmt.allocPrint(allocator, "CHECK_BALANCE:{s}", .{std.fmt.fmtSliceHexLower(&address)});
    defer allocator.free(balance_request);

    try connection.writeAll(balance_request);

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Balance query timeout (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                print("❌ Failed to read balance response\n", .{});
                return error.NetworkError;
            },
        }
    };
    const response = buffer[0..bytes_read];

    // Parse BALANCE:amount response
    if (std.mem.startsWith(u8, response, "BALANCE:")) {
        const balance_str = response[8..];
        return std.fmt.parseInt(u64, balance_str, 10) catch 0;
    }

    return 0;
}

fn getNonceFromServer(allocator: std.mem.Allocator, address: types.Address) !u64 {
    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        return error.NetworkError;
    };

    const connection = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802 (5s)\n", .{server_ip});
                return error.NetworkError;
            },
            else => {
                print("❌ Cannot connect to ZeiCoin server at {s}:10802\n", .{server_ip});
                return error.NetworkError;
            },
        }
    };
    defer connection.close();

    // Send nonce request
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{std.fmt.fmtSliceHexLower(&address)});
    defer allocator.free(nonce_request);

    try connection.writeAll(nonce_request);

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Nonce query timeout (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                print("❌ Failed to read nonce response\n", .{});
                return error.NetworkError;
            },
        }
    };
    const response = buffer[0..bytes_read];

    // Parse NONCE:value response
    if (std.mem.startsWith(u8, response, "NONCE:")) {
        const nonce_str = response[6..];
        return std.fmt.parseInt(u64, nonce_str, 10) catch 0;
    }

    return 0;
}

fn sendTransaction(allocator: std.mem.Allocator, zen_wallet: *wallet.Wallet, sender_address: types.Address, sender_public_key: [32]u8, recipient_address: types.Address, amount: u64) !void {
    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        return error.NetworkError;
    };

    const connection = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                return error.NetworkError;
            },
        }
    };
    defer connection.close();

    // Get current nonce from server using the same connection
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{std.fmt.fmtSliceHexLower(&sender_address)});
    defer allocator.free(nonce_request);

    try connection.writeAll(nonce_request);

    // Read nonce response with timeout
    var nonce_buffer: [1024]u8 = undefined;
    const nonce_bytes_read = readWithTimeout(connection, &nonce_buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Nonce request timeout (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                print("❌ Failed to read nonce for transaction\n", .{});
                return error.NetworkError;
            },
        }
    };
    const nonce_response = nonce_buffer[0..nonce_bytes_read];

    // Parse NONCE:value response
    const current_nonce = if (std.mem.startsWith(u8, nonce_response, "NONCE:"))
        std.fmt.parseInt(u64, nonce_response[6..], 10) catch 0
    else
        0;

    // Create transaction
    const fee = types.ZenFees.STANDARD_FEE;
    var transaction = types.Transaction{
        .sender = sender_address,
        .sender_public_key = sender_public_key,
        .recipient = recipient_address,
        .amount = amount,
        .fee = fee,
        .nonce = current_nonce,
        .timestamp = @intCast(util.getTime()),
        .signature = std.mem.zeroes(types.Signature),
    };

    // Sign transaction
    const tx_hash = transaction.hash();
    transaction.signature = zen_wallet.signTransaction(&tx_hash) catch {
        print("❌ Failed to sign transaction\n", .{});
        return error.NetworkError;
    };

    // Send transaction to server
    const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{s}:{s}:{}:{}:{}:{s}:{s}", .{
        std.fmt.fmtSliceHexLower(&sender_address),
        std.fmt.fmtSliceHexLower(&recipient_address),
        amount,
        fee,
        transaction.nonce,
        std.fmt.fmtSliceHexLower(&transaction.signature),
        std.fmt.fmtSliceHexLower(&sender_public_key),
    });
    defer allocator.free(tx_message);

    try connection.writeAll(tx_message);

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Transaction response timeout (5s)\n", .{});
                return error.TransactionFailed;
            },
            else => {
                print("❌ Failed to read transaction response\n", .{});
                return error.TransactionFailed;
            },
        }
    };
    const response = buffer[0..bytes_read];

    if (!std.mem.startsWith(u8, response, "CLIENT_TRANSACTION_ACCEPTED")) {
        // Provide helpful error messages based on server response
        if (std.mem.startsWith(u8, response, "ERROR: Insufficient balance")) {
            print("❌ Insufficient balance! You don't have enough ZEI for this transaction.\n", .{});
            print("💡 Check your balance with: zeicoin balance\n", .{});
            print("💡 Get test funds with: zeicoin fund\n", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Invalid nonce")) {
            print("❌ Invalid transaction nonce. This usually means another transaction is pending.\n", .{});
            print("💡 Wait a moment and try again after the current transaction is processed.\n", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Sender account not found")) {
            print("❌ Wallet account not found on the network.\n", .{});
            print("💡 Get initial funds with: zeicoin fund\n", .{});
        } else {
            print("❌ Transaction failed: {s}\n", .{response});
        }
        return error.TransactionFailed;
    }
}

fn printZeiBanner() void {
    print("\n", .{});
    print("╔══════════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                                                                      ║\n", .{});
    print("║            ███████╗███████╗██╗ ██████╗ ██████╗ ██╗███╗   ██╗         ║\n", .{});
    print("║            ╚══███╔╝██╔════╝██║██╔════╝██╔═══██╗██║████╗  ██║         ║\n", .{});
    print("║              ███╔╝ █████╗  ██║██║     ██║   ██║██║██╔██╗ ██║         ║\n", .{});
    print("║             ███╔╝  ██╔══╝  ██║██║     ██║   ██║██║██║╚██╗██║         ║\n", .{});
    print("║            ███████╗███████╗██║╚██████╗╚██████╔╝██║██║ ╚████║         ║\n", .{});
    print("║            ╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝         ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("║                    Zen Digital Currency CLI Tool                     ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("║                   Pure minimalism meets blockchain                   ║\n", .{});
    print("║                    The simplest thing that works                     ║\n", .{});
    print("║                    ⚡ Fast • Secure • Minimal ⚡                     ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("╚══════════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

fn printHelp() void {
    printZeiBanner();

    print("WALLET COMMANDS:\n", .{});
    print("  zeicoin wallet create [name]     Create new wallet\n", .{});
    print("  zeicoin wallet load [name]       Load existing wallet\n", .{});
    print("  zeicoin wallet list              List all wallets\n\n", .{});
    print("TRANSACTION COMMANDS:\n", .{});
    print("  zeicoin balance [wallet]         Check wallet balance\n", .{});
    print("  zeicoin send <amount> <address>  Send ZEI to address\n", .{});
    print("  zeicoin fund [wallet]            Request test funds\n\n", .{});
    print("NETWORK COMMANDS:\n", .{});
    print("  zeicoin status                   Show network status\n", .{});
    print("  zeicoin sync                     Trigger manual blockchain sync\n", .{});
    print("  zeicoin address [wallet]         Show wallet address\n\n", .{});
    print("EXAMPLES:\n", .{});
    print("  zeicoin wallet create alice      # Create wallet named 'alice'\n", .{});
    print("  zeicoin fund alice               # Get test funds for alice\n", .{});
    print("  zeicoin balance alice            # Check alice's balance\n", .{});
    print("  zeicoin send 50 a1b2c3d4...      # Send 50 ZEI to address\n", .{});
    print("  zeicoin status                   # Check network status\n\n", .{});
    print("ENVIRONMENT:\n", .{});
    print("  ZEICOIN_SERVER=ip               Set server IP (default: 127.0.0.1)\n\n", .{});
    print("💡 Default wallet is 'default' if no name specified\n", .{});
}
