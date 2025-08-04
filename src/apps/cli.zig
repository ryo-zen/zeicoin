// cli.zig - ZeiCoin Command Line Interface
// Simple CLI tool for everyday Zeicoin operations

const std = @import("std");
const print = std.debug.print;
const net = std.net;
const Thread = std.Thread;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const wallet = zeicoin.wallet;
const db = zeicoin.db;
const util = zeicoin.util;
const clispinners = @import("../core/util/clispinners.zig");
// HD wallet is not exposed through zeicoin module yet, so we need direct imports
const bip39 = zeicoin.bip39;
const hd_wallet = zeicoin.hd_wallet;

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
            return allocator.dupe(u8, detected_ip);
        }
    }

    // 3. Try bootstrap servers from JSON config
    const bootstrap_nodes = types.loadBootstrapNodes(allocator) catch |err| {
        print("⚠️  Failed to load bootstrap nodes: {}\n", .{err});
        return error.NoServerFound;
    };
    defer types.freeBootstrapNodes(allocator, bootstrap_nodes);
    
    print("🔍 Testing bootstrap nodes for health...\n", .{});
    for (bootstrap_nodes) |bootstrap_addr| {
        // Parse IP from "ip:port" format
        var it = std.mem.splitScalar(u8, bootstrap_addr, ':');
        if (it.next()) |ip_str| {
            print("  Testing {s}... ", .{ip_str});
            if (testServerConnection(ip_str)) {
                print("✅ Healthy!\n", .{});
                print("🌐 Using healthy bootstrap node: {s}\n", .{ip_str});
                return allocator.dupe(u8, ip_str);
            } else {
                print("❌ Unhealthy or offline\n", .{});
            }
        }
    }
    
    print("⚠️  No healthy bootstrap nodes found\n", .{});

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

    // Connect and test actual API response
    var stream = connectWithTimeout(address) catch return false;
    defer stream.close();

    // Send status request to verify it's actually a ZeiCoin server
    stream.writeAll("BLOCKCHAIN_STATUS\n") catch return false;

    // Try to read response - if we get any data, server is healthy
    var buffer: [64]u8 = undefined;
    const bytes_read = readWithTimeout(stream, &buffer) catch return false;

    // Server is healthy if it responds with any data
    return bytes_read > 0;
}

const Command = enum {
    wallet,
    balance,
    send,
    status,
    address,
    sync,
    block,
    help,
};

const WalletSubcommand = enum {
    create,
    load,
    list,
    restore,
    derive,
    import, // For genesis accounts
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
        .sync => try handleSyncCommand(allocator, args[2..]),
        .block => try handleBlockCommand(allocator, args[2..]),
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
        .restore => try restoreWallet(allocator, args[1..]),
        .derive => try deriveAddress(allocator, args[1..]),
        .import => try importGenesisWallet(allocator, args[1..]),
    }
}

fn createWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";
    const use_hd = args.len > 1 and std.mem.eql(u8, args[1], "--hd");

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
        std.process.exit(1);
    }

    // Get wallet path
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);
    const password = "zen"; // Simple password for demo - could be made configurable

    // Check if this is a genesis account name (TestNet only)
    const genesis_names = [_][]const u8{ "alice", "bob", "charlie", "david", "eve" };
    var is_genesis = false;
    for (genesis_names) |name| {
        if (std.mem.eql(u8, wallet_name, name)) {
            is_genesis = true;
            break;
        }
    }
    
    if (is_genesis and types.CURRENT_NETWORK == .testnet) {
        // Import genesis account instead of creating new
        var zen_wallet = wallet.Wallet.init(allocator);
        defer zen_wallet.deinit();
        
        zen_wallet.importGenesisAccount(wallet_name) catch |err| {
            print("❌ Failed to import genesis account '{s}': {}\n", .{ wallet_name, err });
            std.process.exit(1);
        };
        print("🔑 Importing pre-funded genesis account '{s}'...\n", .{wallet_name});
        
        try zen_wallet.saveToFile(wallet_path, password);
        const address = zen_wallet.getAddress() orelse return error.WalletCreationFailed;
        print("✅ Wallet '{s}' created successfully!\n", .{wallet_name});
        
        // Show bech32 address
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            // Show error if bech32 encoding fails
            print("🆔 Address: <encoding error>\n", .{});
            print("💡 Genesis accounts (alice, bob, charlie, david, eve) have pre-funded balances\n", .{});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address: {s}\n", .{bech32_addr});
        print("💡 Genesis accounts (alice, bob, charlie, david, eve) have pre-funded balances\n", .{});
    } else if (use_hd) {
        // Create HD wallet
        var hd_zen_wallet = hd_wallet.HDWallet.init(allocator);
        defer hd_zen_wallet.deinit();
        
        // Generate 24-word mnemonic
        const mnemonic = try hd_zen_wallet.generateNew(.twentyfour);
        defer allocator.free(mnemonic);
        
        // Save HD wallet
        try hd_zen_wallet.saveToFile(wallet_path, password);
        
        // Get first address
        const address = try hd_zen_wallet.getAddress(0);
        
        print("✅ HD Wallet '{s}' created successfully!\n", .{wallet_name});
        print("\n", .{});
        print("🔐 MNEMONIC PHRASE (Write this down!):\n", .{});
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
        
        // Display mnemonic in 4 rows of 6 words each
        var words = std.mem.tokenizeScalar(u8, mnemonic, ' ');
        var word_count: u32 = 0;
        while (words.next()) |word| {
            print("{d:>2}. {s:<12}", .{ word_count + 1, word });
            word_count += 1;
            if (word_count % 6 == 0) {
                print("\n", .{});
            }
        }
        
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
        print("\n", .{});
        print("⚠️  IMPORTANT: Save this mnemonic phrase securely!\n", .{});
        print("    This is the ONLY way to recover your wallet.\n", .{});
        print("\n", .{});
        
        // Show first address
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address: <encoding error>\n", .{});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address #0: {s}\n", .{bech32_addr});
        print("💡 Use 'zeicoin wallet derive {s}' to generate more addresses\n", .{wallet_name});
    } else {
        // Create standard wallet
        var zen_wallet = wallet.Wallet.init(allocator);
        defer zen_wallet.deinit();
        
        try zen_wallet.createNew();
        try zen_wallet.saveToFile(wallet_path, password);
        
        const address = zen_wallet.getAddress() orelse return error.WalletCreationFailed;
        print("✅ Wallet '{s}' created successfully!\n", .{wallet_name});
        
        // Show bech32 address
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            // Show error if bech32 encoding fails
            print("🆔 Address: <encoding error>\n", .{});
            print("💡 Genesis accounts (alice, bob, charlie, david, eve) have pre-funded balances\n", .{});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address: {s}\n", .{bech32_addr});
        print("💡 Genesis accounts (alice, bob, charlie, david, eve) have pre-funded balances\n", .{});
        print("💡 Use 'zeicoin wallet create {s} --hd' to create an HD wallet\n", .{wallet_name});
    }
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
        std.process.exit(1);
    }

    // Load wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    const password = if (std.mem.eql(u8, wallet_name, "default_miner")) "zen_miner" else "zen";
    try zen_wallet.loadFromFile(wallet_path, password);

    const address = zen_wallet.getAddress() orelse return error.WalletLoadFailed;
    print("✅ Wallet '{s}' loaded successfully!\n", .{wallet_name});
    
    // Show bech32 address
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch |err| blk: {
        print("⚠️  Could not encode bech32 address: {}\n", .{err});
        break :blk null;
    };
    defer if (bech32_addr) |addr| allocator.free(addr);
    
    if (bech32_addr) |addr| {
        print("🆔 Address: {s}\n", .{addr});
    }
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

fn restoreWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) {
        print("❌ Wallet name and mnemonic phrase required\n", .{});
        print("Usage: zeicoin wallet restore <name> <mnemonic phrase...>\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    
    // Join the remaining args as the mnemonic
    var mnemonic_parts = std.ArrayList(u8).init(allocator);
    defer mnemonic_parts.deinit();
    
    for (args[1..], 0..) |word, i| {
        if (i > 0) try mnemonic_parts.append(' ');
        try mnemonic_parts.appendSlice(word);
    }
    
    const mnemonic = mnemonic_parts.items;
    
    print("🔐 Restoring HD wallet '{s}' from mnemonic...\n", .{wallet_name});
    
    // Initialize database
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    var database = try db.Database.init(allocator, data_dir);
    defer database.deinit();
    
    // Check if wallet already exists
    if (database.walletExists(wallet_name)) {
        print("❌ Wallet '{s}' already exists\n", .{wallet_name});
        std.process.exit(1);
    }
    
    // Create HD wallet from mnemonic
    var hd_zen_wallet = hd_wallet.HDWallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    hd_zen_wallet.fromMnemonic(mnemonic, null) catch |err| {
        print("❌ Invalid mnemonic phrase: {}\n", .{err});
        std.process.exit(1);
    };
    
    // Save wallet
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);
    const password = "zen";
    
    try hd_zen_wallet.saveToFile(wallet_path, password);
    
    // Get first address
    const address = try hd_zen_wallet.getAddress(0);
    
    print("✅ HD Wallet '{s}' restored successfully!\n", .{wallet_name});
    
    // Show first address
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("🆔 Address: <encoding error>\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    print("🆔 Address #0: {s}\n", .{bech32_addr});
    print("💡 Use 'zeicoin wallet derive {s}' to generate more addresses\n", .{wallet_name});
}

fn deriveAddress(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Wallet name required\n", .{});
        print("Usage: zeicoin wallet derive <wallet_name> [index]\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    const index = if (args.len > 1) 
        std.fmt.parseInt(u32, args[1], 10) catch {
            print("❌ Invalid index: {s}\n", .{args[1]});
            return;
        }
    else null;
    
    // Initialize database
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    var database = try db.Database.init(allocator, data_dir);
    defer database.deinit();
    
    if (!database.walletExists(wallet_name)) {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        std.process.exit(1);
    }
    
    // Check if it's an HD wallet
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);
    
    if (!hd_wallet.HDWallet.isHDWallet(wallet_path)) {
        print("❌ Wallet '{s}' is not an HD wallet\n", .{wallet_name});
        print("💡 Only HD wallets support address derivation\n", .{});
        std.process.exit(1);
    }
    
    // Load HD wallet
    var hd_zen_wallet = hd_wallet.HDWallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    const password = "zen";
    try hd_zen_wallet.loadFromFile(wallet_path, password);
    
    if (index) |idx| {
        // Derive specific address
        const address = try hd_zen_wallet.getAddress(idx);
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address #{}: <encoding error>\n", .{idx});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address #{}: {s}\n", .{ idx, bech32_addr });
    } else {
        // Get next address
        const address = try hd_zen_wallet.getNextAddress();
        const new_index = hd_zen_wallet.highest_index;
        
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address #{}: <encoding error>\n", .{new_index});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("✅ New address derived!\n", .{});
        print("🆔 Address #{}: {s}\n", .{ new_index, bech32_addr });
        
        // Save updated wallet with new highest index
        try hd_zen_wallet.saveToFile(wallet_path, password);
    }
}

fn importGenesisWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Genesis account name required\n", .{});
        print("Usage: zeicoin wallet import <alice|bob|charlie|david|eve>\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    
    // Check if it's a valid genesis account
    const genesis_names = [_][]const u8{ "alice", "bob", "charlie", "david", "eve" };
    var is_genesis = false;
    for (genesis_names) |name| {
        if (std.mem.eql(u8, wallet_name, name)) {
            is_genesis = true;
            break;
        }
    }
    
    if (!is_genesis) {
        print("❌ '{s}' is not a valid genesis account name\n", .{wallet_name});
        print("💡 Valid genesis accounts: alice, bob, charlie, david, eve\n", .{});
        std.process.exit(1);
    }
    
    if (types.CURRENT_NETWORK != .testnet) {
        print("❌ Genesis accounts are only available on TestNet\n", .{});
        std.process.exit(1);
    }
    
    // Create wallet with genesis name
    try createWallet(allocator, args);
}

fn handleBalanceCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                std.process.exit(1);
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
    const balance_info = getBalanceFromServer(allocator, address) catch |err| {
        switch (err) {
            error.NetworkError => {
                print("❌ Cannot connect to ZeiCoin server\n", .{});
                print("💡 Make sure the server is running\n", .{});
                return;
            },
            else => return err,
        }
    };

    // Format balances properly for display
    const mature_display = util.formatZEI(allocator, balance_info.mature) catch "? ZEI";
    defer if (!std.mem.eql(u8, mature_display, "? ZEI")) allocator.free(mature_display);
    
    const immature_display = util.formatZEI(allocator, balance_info.immature) catch "? ZEI";
    defer if (!std.mem.eql(u8, immature_display, "? ZEI")) allocator.free(immature_display);
    
    const total_display = util.formatZEI(allocator, balance_info.mature + balance_info.immature) catch "? ZEI";
    defer if (!std.mem.eql(u8, total_display, "? ZEI")) allocator.free(total_display);

    print("💰 Wallet '{s}' balance:\n", .{wallet_name});
    print("   ✅ Mature (spendable): {s}\n", .{mature_display});
    if (balance_info.immature > 0) {
        print("   ⏳ Immature (not spendable): {s}\n", .{immature_display});
        print("   📊 Total balance: {s}\n", .{total_display});
    }
    
    // Show bech32 address (truncated for display)
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        // Show error if bech32 encoding fails
        print("🆔 Address: <encoding error>\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    // Show first and last parts of bech32 address
    if (bech32_addr.len > 20) {
        print("🆔 Address: {s}...{s}\n", .{bech32_addr[0..16], bech32_addr[bech32_addr.len-4..]});
    } else {
        print("🆔 Address: {s}\n", .{bech32_addr});
    }
}

fn handleSendCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) {
        print("❌ Usage: zeicoin send <amount> <recipient> [wallet_name]\n", .{});
        print("💡 Recipient can be a bech32 address or wallet name\n", .{});
        print("💡 Example: zeicoin send 10 tzei1qr2qge3sdeq... alice\n", .{});
        print("💡 Example: zeicoin send 10 bob alice\n", .{});
        return;
    }

    const amount_str = args[0];
    const recipient_hex = args[1];
    const wallet_name = if (args.len > 2) args[2] else "default";

    // Parse amount (supports decimals)
    const amount = parseZeiAmount(amount_str) catch {
        print("❌ Invalid amount: {s}\n", .{amount_str});
        print("💡 Amount must be a positive number (supports up to 8 decimal places)\n", .{});
        std.process.exit(1);
    };

    // Validate amount is not zero
    if (amount == 0) {
        print("❌ Invalid amount: cannot send zero ZEI\n", .{});
        std.process.exit(1);
    }

    // Try to parse recipient as bech32 address first, then as wallet name
    const recipient_address = types.Address.fromString(allocator, recipient_hex) catch blk: {
        // Check if this looks like a bech32 address but is invalid
        if (std.mem.startsWith(u8, recipient_hex, "tzei1") or std.mem.startsWith(u8, recipient_hex, "mzei1")) {
            print("❌ Invalid bech32 address: '{s}'\n", .{recipient_hex});
            print("💡 Address format is invalid or has wrong checksum\n", .{});
            std.process.exit(1);
        }
        
        // If not a bech32 format, try to resolve as wallet name
        const recipient_wallet = loadWalletForOperation(allocator, recipient_hex) catch {
            print("❌ Invalid recipient: '{s}'\n", .{recipient_hex});
            print("💡 Recipient must be a valid bech32 address or wallet name\n", .{});
            print("💡 Example: zeicoin send 10 tzei1qr2q... alice\n", .{});
            print("💡 Example: zeicoin send 10 bob alice\n", .{});
            std.process.exit(1);
        };
        defer {
            recipient_wallet.deinit();
            allocator.destroy(recipient_wallet);
        }
        
        const addr = recipient_wallet.getAddress() orelse {
            print("❌ Could not get address from wallet '{s}'\n", .{recipient_hex});
            return;
        };
        
        print("💡 Resolved wallet '{s}' to address\n", .{recipient_hex});
        break :blk addr;
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

    // Format amount for display
    const amount_display = util.formatZEI(allocator, amount) catch "? ZEI";
    defer if (!std.mem.eql(u8, amount_display, "? ZEI")) allocator.free(amount_display);
    
    print("💸 Sending {s} from wallet '{s}'...\n", .{ amount_display, wallet_name });
    
    // Format addresses for display
    const sender_bech32 = sender_address.toBech32(allocator, types.CURRENT_NETWORK) catch null;
    defer if (sender_bech32) |addr| allocator.free(addr);
    
    const recipient_bech32 = recipient_address.toBech32(allocator, types.CURRENT_NETWORK) catch null;
    defer if (recipient_bech32) |addr| allocator.free(addr);
    
    // Display addresses (prefer bech32, fallback to hex)
    if (sender_bech32) |addr| {
        // Show shortened bech32 (first 16 + last 4 chars)
        const short_addr = if (addr.len > 20) 
            try std.fmt.allocPrint(allocator, "{s}...{s}", .{addr[0..16], addr[addr.len-4..]})
        else addr;
        defer if (addr.len > 20) allocator.free(short_addr);
        print("🆔 From: {s}\n", .{short_addr});
    } else {
        const sender_bytes = sender_address.toBytes();
        print("🆔 From: {s}\n", .{std.fmt.fmtSliceHexLower(sender_bytes[0..16])});
    }
    
    if (recipient_bech32) |addr| {
        // Show shortened bech32 (first 16 + last 4 chars)
        const short_addr = if (addr.len > 20) 
            try std.fmt.allocPrint(allocator, "{s}...{s}", .{addr[0..16], addr[addr.len-4..]})
        else addr;
        defer if (addr.len > 20) allocator.free(short_addr);
        print("🎯 To: {s}\n", .{short_addr});
    } else {
        const recipient_bytes = recipient_address.toBytes();
        print("🎯 To: {s}\n", .{std.fmt.fmtSliceHexLower(recipient_bytes[0..16])});
    }

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
    // Check for --watch flag
    var watch_mode = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--watch") or std.mem.eql(u8, arg, "-w")) {
            watch_mode = true;
            break;
        }
    }

    if (watch_mode) {
        try handleWatchStatus(allocator);
        return;
    }

    print("📊 ZeiCoin Network Status:\n", .{});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);
    
    print("🌐 Server: {s}:10802\n", .{server_ip});

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
    try connection.writeAll("BLOCKCHAIN_STATUS\n");

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
    
    // Show bech32 address as primary format
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch |err| blk: {
        print("⚠️  Could not encode bech32 address: {}\n", .{err});
        break :blk null;
    };
    defer if (bech32_addr) |addr| allocator.free(addr);
    
    if (bech32_addr) |addr| {
        print("   📬 {s}\n", .{addr});
    }
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
    try connection.writeAll("TRIGGER_SYNC\n");

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

fn handleBlockCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Block height required\n", .{});
        print("Usage: zeicoin block <height>\n", .{});
        return;
    }

    const height_str = args[0];
    const height = std.fmt.parseUnsigned(u32, height_str, 10) catch {
        print("❌ Invalid height format: {s}\n", .{height_str});
        print("Usage: zeicoin block <height>\n", .{});
        return;
    };

    print("🔗 Getting block at height {}...\n", .{height});

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

    // Send get block request
    const request = try std.fmt.allocPrint(allocator, "GET_BLOCK:{}\n", .{height});
    defer allocator.free(request);
    try connection.writeAll(request);

    // Read response with timeout
    var buffer: [2048]u8 = undefined;
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

    if (std.mem.startsWith(u8, response, "ERROR:")) {
        print("❌ {s}\n", .{response[7..]});
        return;
    }

    if (std.mem.startsWith(u8, response, "BLOCK:")) {
        print("📦 Block Information:\n", .{});
        print("{s}\n", .{response[6..]});
    } else {
        print("📨 Response: {s}\n", .{response});
    }
}


// Helper functions

// Parse ZEI amount supporting decimals up to 8 places
fn parseZeiAmount(amount_str: []const u8) !u64 {
    if (amount_str.len == 0) return error.InvalidAmount;
    
    // Check for decimal point
    if (std.mem.indexOfScalar(u8, amount_str, '.')) |decimal_pos| {
        // Has decimal point
        const integer_part = amount_str[0..decimal_pos];
        const fractional_part = amount_str[decimal_pos + 1..];
        
        // Check decimal places limit (8 max)
        if (fractional_part.len > 8) return error.InvalidAmount;
        
        // Parse integer part
        const integer_zei = if (integer_part.len == 0) 0 else std.fmt.parseInt(u64, integer_part, 10) catch return error.InvalidAmount;
        
        // Parse fractional part and pad to 8 decimal places
        var fractional_str: [8]u8 = "00000000".*;
        if (fractional_part.len > 0) {
            @memcpy(fractional_str[0..fractional_part.len], fractional_part);
        }
        
        const fractional_units = std.fmt.parseInt(u64, &fractional_str, 10) catch return error.InvalidAmount;
        
        // Convert to base units
        const integer_units = std.math.mul(u64, integer_zei, types.ZEI_COIN) catch return error.InvalidAmount;
        const total_units = std.math.add(u64, integer_units, fractional_units) catch return error.InvalidAmount;
        
        return total_units;
    } else {
        // No decimal point - integer ZEI
        const zei_amount = std.fmt.parseInt(u64, amount_str, 10) catch return error.InvalidAmount;
        return std.math.mul(u64, zei_amount, types.ZEI_COIN) catch return error.InvalidAmount;
    }
}

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
    const password = if (std.mem.eql(u8, wallet_name, "server_miner") or std.mem.eql(u8, wallet_name, "default_miner")) "zen_miner" else "zen";
    zen_wallet.loadFromFile(wallet_path, password) catch |err| {
        print("❌ Failed to load wallet '{s}': {}\n", .{wallet_name, err});
        return error.WalletNotFound;
    };

    return zen_wallet;
}

const BalanceInfo = struct {
    mature: u64,
    immature: u64,
};

fn getBalanceFromServer(allocator: std.mem.Allocator, address: types.Address) !BalanceInfo {
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

    // Send balance request with bech32 address
    const bech32_addr = try address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(bech32_addr);
    
    const balance_request = try std.fmt.allocPrint(allocator, "CHECK_BALANCE:{s}", .{bech32_addr});
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

    // Parse BALANCE:mature,immature response
    if (std.mem.startsWith(u8, response, "BALANCE:")) {
        const balance_str = response[8..];
        
        // Split by comma to get mature and immature
        var parts = std.mem.splitScalar(u8, balance_str, ',');
        const mature_str = std.mem.trim(u8, parts.next() orelse "0", " \n\r\t");
        const immature_str = std.mem.trim(u8, parts.next() orelse "0", " \n\r\t");
        
        return BalanceInfo{
            .mature = std.fmt.parseInt(u64, mature_str, 10) catch 0,
            .immature = std.fmt.parseInt(u64, immature_str, 10) catch 0,
        };
    }

    return BalanceInfo{ .mature = 0, .immature = 0 };
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

    // Send nonce request using bech32 format
    const bech32_addr = try address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(bech32_addr);
    
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{bech32_addr});
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
    const sender_bech32_for_nonce = try sender_address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(sender_bech32_for_nonce);
    
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{sender_bech32_for_nonce});
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

    // Get current blockchain height from server for expiry calculation
    try connection.writeAll("GET_HEIGHT\n");
    
    // Read height response with timeout
    var height_buffer: [1024]u8 = undefined;
    const height_bytes_read = readWithTimeout(connection, &height_buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("❌ Height request timeout (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                print("❌ Failed to read blockchain height\n", .{});
                return error.NetworkError;
            },
        }
    };
    const height_response = height_buffer[0..height_bytes_read];
    
    // Parse HEIGHT:value response
    const current_height = if (std.mem.startsWith(u8, height_response, "HEIGHT:"))
        std.fmt.parseInt(u64, height_response[7..], 10) catch 0
    else
        0;
    
    // Create transaction with expiry height (24 hours from now)
    const fee = types.ZenFees.STANDARD_FEE;
    const expiry_window = types.TransactionExpiry.getExpiryWindow();
    var transaction = types.Transaction{
        .version = 0, // Version 0 for initial protocol
        .flags = .{}, // Default flags
        .sender = sender_address,
        .sender_public_key = sender_public_key,
        .recipient = recipient_address,
        .amount = amount,
        .fee = fee,
        .nonce = current_nonce,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = current_height + expiry_window,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Sign transaction
    const tx_hash = transaction.hashForSigning();
    transaction.signature = zen_wallet.signTransaction(&tx_hash) catch {
        print("❌ Failed to sign transaction\n", .{});
        return error.NetworkError;
    };

    // Convert addresses to bech32 for sending
    const sender_bech32 = try sender_address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(sender_bech32);
    
    const recipient_bech32 = try recipient_address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(recipient_bech32);
    
    // Send transaction to server with bech32 addresses
    const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{s}:{s}:{}:{}:{}:{}:{}:{s}:{s}", .{
        sender_bech32,
        recipient_bech32,
        amount,
        fee,
        transaction.nonce,
        transaction.timestamp,
        transaction.expiry_height,
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

    if (!std.mem.startsWith(u8, response, "OK:")) {
        // Provide helpful error messages based on server response
        if (std.mem.startsWith(u8, response, "ERROR: Insufficient balance")) {
            print("❌ Insufficient balance! You don't have enough ZEI for this transaction.\n", .{});
            print("💡 Check your balance with: zeicoin balance\n", .{});
            print("💡 Use genesis accounts (alice, bob, charlie, david, eve) which have pre-funded balances\n", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Invalid nonce")) {
            print("❌ Invalid transaction nonce. This usually means another transaction is pending.\n", .{});
            print("💡 Wait a moment and try again after the current transaction is processed.\n", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Sender account not found")) {
            print("❌ Wallet account not found on the network.\n", .{});
            print("💡 Use genesis accounts (alice, bob, charlie, david, eve) which have pre-funded balances\n", .{});
        } else {
            print("❌ Transaction failed: {s}\n", .{response});
        }
        std.process.exit(1);
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
    print("  zeicoin wallet create [name]           Create new wallet\n", .{});
    print("  zeicoin wallet create [name] --hd      Create HD wallet with mnemonic\n", .{});
    print("  zeicoin wallet load [name]             Load existing wallet\n", .{});
    print("  zeicoin wallet list                    List all wallets\n", .{});
    print("  zeicoin wallet restore <name> <words>  Restore HD wallet from mnemonic\n", .{});
    print("  zeicoin wallet derive <name> [index]   Derive new HD wallet address\n", .{});
    print("  zeicoin wallet import <genesis>        Import genesis account (testnet)\n\n", .{});
    print("TRANSACTION COMMANDS:\n", .{});
    print("  zeicoin balance [wallet]         Check wallet balance\n", .{});
    print("  zeicoin send <amount> <recipient> Send ZEI to address or wallet\n", .{});
    print("NETWORK COMMANDS:\n", .{});
    print("  zeicoin status                   Show network status\n", .{});
    print("  zeicoin status --watch           Monitor mining status with live spinner\n", .{});
    print("  zeicoin sync                     Trigger manual blockchain sync\n", .{});
    print("  zeicoin block <height>           Inspect block at specific height\n", .{});
    print("  zeicoin address [wallet]         Show wallet address\n\n", .{});
    print("EXAMPLES:\n", .{});
    print("  zeicoin wallet create alice            # Create wallet named 'alice'\n", .{});
    print("  zeicoin wallet create myhd --hd        # Create HD wallet with mnemonic\n", .{});
    print("  zeicoin wallet restore myhd word1...   # Restore from 24-word mnemonic\n", .{});
    print("  zeicoin wallet derive myhd             # Get next HD address\n", .{});
    print("  zeicoin balance alice                  # Check alice's balance (pre-funded)\n", .{});
    print("  zeicoin send 50 tzei1qr2q...          # Send 50 ZEI to address\n", .{});
    print("  zeicoin send 50 bob                    # Send 50 ZEI to wallet 'bob'\n", .{});
    print("  zeicoin status                         # Check network status\n", .{});
    print("  zeicoin block 6                        # Inspect block at height 6\n\n", .{});
    print("ENVIRONMENT:\n", .{});
    print("  ZEICOIN_SERVER=ip                      Set server IP (default: 127.0.0.1)\n\n", .{});
    print("💡 Default wallet is 'default' if no name specified\n", .{});
    print("💡 Genesis accounts (alice, bob, charlie, david, eve) have pre-funded balances on testnet\n", .{});
}

// Shared state for watch mode
const WatchState = struct {
    running: std.atomic.Value(bool),
    server_ip: []const u8,
    status_text: [1024]u8,
    status_len: std.atomic.Value(usize),
    is_mining: std.atomic.Value(bool),
    block_height: std.atomic.Value(u64),
    hash_rate: std.atomic.Value(f64),
    
    fn init(server_ip: []const u8) WatchState {
        return WatchState{
            .running = std.atomic.Value(bool).init(true),
            .server_ip = server_ip,
            .status_text = std.mem.zeroes([1024]u8),
            .status_len = std.atomic.Value(usize).init(0),
            .is_mining = std.atomic.Value(bool).init(false),
            .block_height = std.atomic.Value(u64).init(0),
            .hash_rate = std.atomic.Value(f64).init(0.0),
        };
    }
};

fn handleWatchStatus(allocator: std.mem.Allocator) !void {
    // Get server IP
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);
    
    var watch_state = WatchState.init(server_ip);
    
    // Signal handling will be done through the polling loop
    // Simplified approach without signal handlers for now
    
    print("📊 ZeiCoin Network Status (Watch Mode)\n", .{});
    print("🌐 Server: {s}:10802\n", .{server_ip});
    print("💡 Press Ctrl+C to exit\n\n", .{});
    
    // Start status polling thread
    const status_thread = try Thread.spawn(.{}, statusPollingWorker, .{ allocator, &watch_state });
    defer status_thread.join();
    
    // Start spinner thread
    const spinner_thread = try Thread.spawn(.{}, spinnerWorker, .{&watch_state});
    defer spinner_thread.join();
    
    // Main thread waits for interrupt - simplified approach
    // User can press Ctrl+C to exit (handled by terminal)
    var counter: u32 = 0;
    while (watch_state.running.load(.acquire)) {
        std.time.sleep(500 * std.time.ns_per_ms); // Check every 500ms
        counter += 1;
        
        // For demo purposes, run for a reasonable time or until stopped
        if (counter > 600) { // Stop after 5 minutes automatically
            break;
        }
    }
    
    // Clean shutdown
    watch_state.running.store(false, .release);
    clispinners.Terminal.clearLine();
    clispinners.Terminal.showCursor();
    print("\n✅ Stopped monitoring\n", .{});
}

fn statusPollingWorker(allocator: std.mem.Allocator, state: *WatchState) !void {
    while (state.running.load(.acquire)) {
        // Poll server status
        pollServerStatus(allocator, state) catch |err| {
            // Continue on error, just log it
            std.log.warn("Failed to poll server status: {}", .{err});
        };
        
        // Adaptive polling: faster when mining, slower when idle
        const is_mining = state.is_mining.load(.acquire);
        const poll_interval: u32 = if (is_mining) 500 else 2000; // 0.5s when mining, 2s when idle
        const sleep_iterations: u32 = poll_interval / 100;
        
        for (0..sleep_iterations) |_| {
            if (!state.running.load(.acquire)) break;
            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
}

fn spinnerWorker(state: *WatchState) !void {
    const stdout = std.io.getStdOut().writer();
    var current_frame: usize = 0;
    var last_mining_state: bool = false;
    
    while (state.running.load(.acquire)) {
        const is_mining = state.is_mining.load(.acquire);
        const block_height = state.block_height.load(.acquire);
        const hash_rate = state.hash_rate.load(.acquire);
        
        // Reset animation when mining state changes
        if (is_mining != last_mining_state) {
            current_frame = 0; // Reset animation
            last_mining_state = is_mining;
        }
        
        // Clear both lines
        clispinners.Terminal.clearLine();
        try stdout.print("\x1b[1B", .{}); // Move down 1 line
        clispinners.Terminal.clearLine();
        try stdout.print("\x1b[1A", .{}); // Move back up
        
        if (is_mining) {
            // Show blockchain animation
            const frame = clispinners.blockchain.frames[current_frame];
            try stdout.print("{s}\nMining... Block: {} | Hash Rate: {d:.1} H/s", 
                .{ frame, block_height, hash_rate });
            
            // Update frame for next iteration
            current_frame = (current_frame + 1) % clispinners.blockchain.frames.len;
        } else {
            // Show inactive status with reset animation
            try stdout.print("⏸️ Mining inactive\nWaiting for transactions... Block: {} | Hash Rate: {d:.1} H/s", 
                .{ block_height, hash_rate });
            current_frame = 0; // Keep at start when inactive
        }
        
        // Move cursor back to start of first line
        try stdout.print("\x1b[1A\r", .{});
        
        std.time.sleep(120 * std.time.ns_per_ms); // Update every 120ms (blockchain spinner interval)
    }
    
    // Clean up display
    clispinners.Terminal.clearLine();
    try stdout.print("\x1b[1B", .{}); // Move down 1 line  
    clispinners.Terminal.clearLine();
    clispinners.Terminal.showCursor();
}

fn pollServerStatus(allocator: std.mem.Allocator, state: *WatchState) !void {
    _ = allocator;
    const address = net.Address.parseIp4(state.server_ip, 10802) catch return;
    
    const connection = connectWithTimeout(address) catch return;
    defer connection.close();
    
    // Send enhanced status request
    try connection.writeAll("BLOCKCHAIN_STATUS_ENHANCED\n");
    
    // Read response
    var buffer: [2048]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch return;
    const response = buffer[0..bytes_read];
    
    // Parse enhanced response format: 
    // "STATUS:height:peers:mempool:mining:hashrate"
    if (std.mem.startsWith(u8, response, "STATUS:")) {
        var parts = std.mem.splitScalar(u8, response[7..], ':');
        
        if (parts.next()) |height_str| {
            const height = std.fmt.parseInt(u64, std.mem.trim(u8, height_str, " \n\r\t"), 10) catch 0;
            state.block_height.store(height, .release);
        }
        
        // Skip peers and mempool for now
        _ = parts.next(); // peers
        _ = parts.next(); // mempool
        
        if (parts.next()) |mining_str| {
            const is_mining = std.mem.eql(u8, std.mem.trim(u8, mining_str, " \n\r\t"), "true");
            state.is_mining.store(is_mining, .release);
        }
        
        if (parts.next()) |hashrate_str| {
            const hash_rate = std.fmt.parseFloat(f64, std.mem.trim(u8, hashrate_str, " \n\r\t")) catch 0.0;
            state.hash_rate.store(hash_rate, .release);
        }
    }
    
    // Store full response for debugging
    const response_len = @min(response.len, state.status_text.len - 1);
    @memcpy(state.status_text[0..response_len], response[0..response_len]);
    state.status_text[response_len] = 0;
    state.status_len.store(response_len, .release);
}
