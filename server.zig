// server.zig - ZeiCoin Multi-Peer Network Server
// Minimalist blockchain node: P2P networking + client API server
// Ports:10800 (UDP Discovery) 10801 (P2P), 10802 (Client API)
// Features: Auto-mining, peer discovery, transaction broadcasting

const std = @import("std");
const net = std.net;
const print = std.debug.print;

const zeicoin_main = @import("main.zig");
const zen_net = @import("net.zig");
const types = @import("types.zig");
const key = @import("key.zig");
const util = @import("util.zig");
const db = @import("db.zig");
const wallet = @import("wallet.zig");

// Global log file
var log_file: ?std.fs.File = null;

fn logMessage(comptime fmt: []const u8, args: anytype) void {
    const timestamp = std.time.timestamp();
    if (log_file) |file| {
        file.writer().print("[{}] ", .{timestamp}) catch {};
        file.writer().print(fmt, args) catch {};
        file.writer().print("\n", .{}) catch {};
    }
    print(fmt, args);
}

// Compact banner for server startup
fn printCompactBanner() void {
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

// Helper function to format ZEI amounts with proper decimal places
fn formatZEI(allocator: std.mem.Allocator, amount_zei: u64) ![]u8 {
    const zei_coins = amount_zei / types.ZEI_COIN;
    const zei_fraction = amount_zei % types.ZEI_COIN;

    if (zei_fraction == 0) {
        return std.fmt.allocPrint(allocator, "{} ZEI", .{zei_coins});
    } else {
        // Format with 5 decimal places for precision
        const decimal = @as(f64, @floatFromInt(zei_fraction)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        return std.fmt.allocPrint(allocator, "{}.{d:0>5} ZEI", .{ zei_coins, @as(u64, @intFromFloat(decimal * 100000)) });
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize logging
    log_file = std.fs.cwd().createFile("logs/server.log", .{}) catch null;
    defer if (log_file) |file| file.close();

    // Show compact banner
    printCompactBanner();

    // Initialize ZeiCoin blockchain with networking
    print("🫡  Initializing Zei Blockchain...\n", .{});
    var zeicoin = try zeicoin_main.ZeiCoin.init(allocator);
    defer zeicoin.deinit();

    // Initialize network manager (zen flow)
    print("🌊 Creating network flow...\n", .{});
    var network = zen_net.NetworkManager.init(allocator);
    defer network.deinit();

    // Connect blockchain to network (zen unity - bidirectional flow)
    zeicoin.network = &network;
    network.blockchain = &zeicoin;

    print("✅ ZeiCoin zen blockchain loaded!\n", .{});
    print("\n📋 Network Configuration:\n", .{});
    types.NetworkConfig.displayInfo();
    zeicoin.printStatus();

    // 🖥️ Create/load persistent server miner wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    const wallet_path = try zeicoin.database.getWalletPath("server_miner");
    defer allocator.free(wallet_path);

    if (zeicoin.database.walletExists("server_miner")) {
        // Load existing miner wallet
        const password = "zen_miner"; // Simple password for demo
        try zen_wallet.loadFromFile(wallet_path, password);
        print("🔓 Loaded existing zen miner wallet\n", .{});
    } else {
        // Create new persistent miner wallet
        try zen_wallet.createNew();
        const password = "zen_miner"; // Simple password for demo
        try zen_wallet.saveToFile(wallet_path, password);
        print("💾 Created new persistent zen miner wallet\n", .{});
    }

    const miner_address = zen_wallet.getAddress() orelse return error.WalletLoadFailed;
    print("⛏️  Zen miner: {s}\n", .{std.fmt.fmtSliceHexLower(miner_address[0..8])});

    // Get our ports (zen port separation)
    const p2p_port: u16 = 10801; // P2P network port
    const client_port: u16 = 10802; // Client API port

    // Create TCP server for client connections (separate from P2P)
    const address = net.Address.parseIp4("0.0.0.0", client_port) catch |err| {
        print("❌ Failed to parse client address: {}\n", .{err});
        return;
    };

    print("🕸️  Starting zen multi-peer network on port {}...\n", .{p2p_port});

    // Start P2P networking for peer connections
    try network.start(p2p_port);

    print("🔍 Discovering zen peers in the network (async)...\n", .{});
    // Start peer discovery in background to avoid blocking client server setup
    // try network.discoverPeers(p2p_port);

    // Create TCP server for client API connections (separate port)
    var server = address.listen(.{ .reuse_address = true }) catch |err| {
        print("❌ Failed to create client TCP server: {}\n", .{err});
        return;
    };
    defer server.deinit();

    print("✅ ZeiCoin Stage 3 server ready!\n", .{});
    print("🌐 P2P Network: Port {} ACTIVE\n", .{p2p_port});
    print("🔗 Client API: Port {} ACCEPTING\n", .{client_port});
    print("⚡ Auto-discovery: ENABLED\n", .{});
    network.printStatus();
    print("\n💎 The network flows like water...\n", .{});
    print("⏹️  Press Ctrl+C to achieve digital nirvana\n\n", .{});

    // Statistics for the zen journey
    var connection_count: u32 = 0;
    var transaction_count: u32 = 0;
    var block_count: u32 = 0;

    // Main zen loop - network handles P2P, we handle clients and auto-mining
    while (true) {
        // Check for auto-mining opportunities (zen mining happens naturally)
        if (zeicoin.mempool.items.len > 0) {
            print("⛏️  Zen mining triggered by natural transaction flow...\n", .{});

            // Get ZeiCoin KeyPair from zen wallet for mining
            const miner_keypair = zen_wallet.getZeiCoinKeyPair() orelse return error.WalletLoadFailed;

            // Mine block with current transactions
            const new_block = try zeicoin.zenMineBlock(miner_keypair);
            block_count += 1;

            const block_height = try zeicoin.getHeight() - 1; // Just mined, so current height - 1
            print("💎 Block #{} mined with zen energy! ({} transactions)\n", .{ block_height, new_block.transactions.len });

            // Broadcast block to all peers (network propagation)
            if (zeicoin.network) |net_mgr| {
                net_mgr.broadcastBlock(new_block);
                print("📡 Block flows to {} peers naturally\n", .{net_mgr.getPeerCount()});
            }
        }

        // Handle client connections (non-blocking)
        if (server.accept()) |connection| {
            defer connection.stream.close();
            connection_count += 1;
            print("🎉 ZeiCoin client #{} connected!\n", .{connection_count});

            // Handle ZeiCoin protocol
            handleZeiCoinClient(allocator, connection, &zeicoin, &zen_wallet, &transaction_count, &block_count) catch |err| {
                print("❌ Client handling error: {}\n", .{err});
            };

            print("👋 ZeiCoin client #{} disconnected\n", .{connection_count});
        } else |err| switch (err) {
            error.WouldBlock => {
                // No client connection, continue with zen flow
            },
            else => {
                print("⚠️  Accept error: {}\n", .{err});
            },
        }

        // Brief meditation pause for zen flow (reduced for better responsiveness)
        std.time.sleep(10 * std.time.ns_per_ms);

        // Occasional network status (pure information)
        if (block_count % 10 == 0 and block_count > 0) {
            print("\n🌐 Zen Network Status:\n", .{});
            network.printStatus();
            zeicoin.printStatus();
        }
    }
}

fn handleZeiCoinClient(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, miner_wallet: *wallet.Wallet, transaction_count: *u32, block_count: *u32) !void {
    var buffer: [4096]u8 = undefined;

    while (true) {
        // Read message from client
        const bytes_read = connection.stream.read(&buffer) catch |err| {
            if (err == error.EndOfStream) {
                print("🔚 Client disconnected gracefully\n", .{});
                break;
            }
            print("❌ Read error: {}\n", .{err});
            break;
        };

        if (bytes_read == 0) {
            print("🔚 Client closed connection\n", .{});
            break;
        }

        const message = buffer[0..bytes_read];
        print("📨 Received: '{s}' ({} bytes)\n", .{ message, bytes_read });

        // Parse ZeiCoin protocol messages
        if (std.mem.eql(u8, message, "BLOCKCHAIN_STATUS")) {
            print("🔍 Processing BLOCKCHAIN_STATUS command\n", .{});
            try sendBlockchainStatus(connection, zeicoin);
        } else if (std.mem.startsWith(u8, message, "FUND_WALLET:")) {
            try handleWalletFunding(allocator, connection, zeicoin, message);
        } else if (std.mem.startsWith(u8, message, "CHECK_BALANCE:")) {
            try handleBalanceCheck(allocator, connection, zeicoin, message);
        } else if (std.mem.startsWith(u8, message, "GET_NONCE:")) {
            try handleNonceCheck(allocator, connection, zeicoin, message);
        } else if (std.mem.startsWith(u8, message, "CLIENT_TRANSACTION:")) {
            try handleClientTransaction(allocator, connection, zeicoin, message, transaction_count);
        } else if (std.mem.startsWith(u8, message, "SEND_TRANSACTION:")) {
            try handleTransaction(allocator, connection, zeicoin, message, transaction_count);
        } else if (std.mem.eql(u8, message, "PING")) {
            const response = "PONG from ZeiCoin Bootstrap";
            try connection.stream.writeAll(response);
            print("🏓 Responded to PING\n", .{});
        } else {
            // Default response for unknown messages
            const response = "ZeiCoin Bootstrap Server Ready";
            try connection.stream.writeAll(response);
            print("📤 Sent default response for unknown command: {s}\n", .{message});
        }

        // Check for pending transactions and auto-mine
        if (zeicoin.mempool.items.len > 0) {
            print("⛏️  Found {} pending transactions - auto-mining...\n", .{zeicoin.mempool.items.len});

            // Get ZeiCoin KeyPair from zen wallet for mining
            const miner_keypair = miner_wallet.getZeiCoinKeyPair() orelse {
                print("❌ Miner wallet not loaded\n", .{});
                continue;
            };

            _ = zeicoin.zenMineBlock(miner_keypair) catch |err| {
                print("❌ Mining failed: {}\n", .{err});
                continue;
            };

            block_count.* += 1;
            const current_height = zeicoin.getHeight() catch 0;
            print("⛏️  Block #{} mined! Broadcasting to client...\n", .{current_height});

            // Send new block notification to client
            try sendNewBlockNotification(connection, zeicoin);
        }
    }
}

fn sendBlockchainStatus(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin) !void {
    const height = zeicoin.getHeight() catch 0;
    const pending = zeicoin.mempool.items.len;

    // Create status message
    var status_buffer: [256]u8 = undefined;
    const status_msg = try std.fmt.bufPrint(&status_buffer, "STATUS:HEIGHT={},PENDING={},READY=true", .{ height, pending });

    print("🔄 Preparing to send blockchain status: {s}\n", .{status_msg});
    try connection.stream.writeAll(status_msg);
    print("📊 Sent blockchain status successfully: {s}\n", .{status_msg});
}

fn handleTransaction(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8, transaction_count: *u32) !void {
    _ = allocator; // For future JSON parsing
    _ = message; // For future transaction parsing

    print("💰 Creating valid test transaction with funded wallet...\n", .{});

    // Create a funded sender wallet (server test wallet)
    var test_sender_wallet = try key.KeyPair.generateNew();
    const sender_address = test_sender_wallet.getAddress();

    // Create a recipient wallet (for testing)
    var test_recipient_wallet = try key.KeyPair.generateNew();
    const recipient_address = test_recipient_wallet.getAddress();

    print("📝 Sender: {s}\n", .{std.fmt.fmtSliceHexLower(sender_address[0..8])});
    print("📝 Recipient: {s}\n", .{std.fmt.fmtSliceHexLower(recipient_address[0..8])});

    // Fund the sender account (create account with balance)
    const sender_balance = 100 * types.ZEI_COIN; // Give sender 100 ZEI
    const sender_account = types.Account{
        .address = sender_address,
        .balance = sender_balance,
        .nonce = 0,
    };

    // Save funded sender account to database
    try zeicoin.database.saveAccount(sender_address, sender_account);
    print("💰 Funded sender with {} ZEI\n", .{sender_balance / types.ZEI_COIN});

    // Create valid transaction with zen fee
    const send_amount = 10 * types.ZEI_COIN; // Send 10 ZEI
    const zen_fee = types.ZenFees.STANDARD_FEE; // 💰 Pay standard fee
    var test_tx = types.Transaction{
        .sender = sender_address,
        .sender_public_key = test_sender_wallet.public_key,
        .recipient = recipient_address,
        .amount = send_amount,
        .fee = zen_fee, // 💰 Include fee for complete crypto
        .nonce = sender_account.nonce, // Use current account nonce
        .timestamp = @intCast(util.getTime()),
        .signature = std.mem.zeroes(types.Signature), // Will be filled below
    };

    // Sign the transaction properly
    const tx_hash = test_tx.hash();
    test_tx.signature = try test_sender_wallet.signTransaction(tx_hash);

    print("✍️  Transaction signed with valid Ed25519 signature\n", .{});
    print("📊 Transaction details: {} ZEI from {s} to {s}\n", .{ send_amount / types.ZEI_COIN, std.fmt.fmtSliceHexLower(sender_address[0..8]), std.fmt.fmtSliceHexLower(recipient_address[0..8]) });

    // Add to mempool
    zeicoin.addTransaction(test_tx) catch |err| {
        print("❌ Failed to add transaction: {}\n", .{err});
        const error_msg = "ERROR: Transaction validation failed";
        try connection.stream.writeAll(error_msg);
        return;
    };

    transaction_count.* += 1;
    print("✅ Valid transaction #{} added to mempool successfully!\n", .{transaction_count.*});
    print("🎯 Transaction ready for mining\n", .{});

    const success_msg = "TRANSACTION_ACCEPTED_AND_VALID";
    try connection.stream.writeAll(success_msg);
    print("📤 Confirmed valid transaction acceptance to client\n", .{});
}

fn handleWalletFunding(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    _ = allocator;

    // Parse FUND_WALLET:address message
    const prefix = "FUND_WALLET:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const address_hex = message[prefix.len..];
    print("💰 Funding request for client address: {s}\n", .{address_hex});

    // Parse hex address
    var client_address: types.Address = undefined;
    const parsed_len = std.fmt.hexToBytes(&client_address, address_hex) catch |err| {
        print("❌ Failed to parse hex address: {}\n", .{err});
        const error_msg = "ERROR: Invalid address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    print("✅ Parsed address length: {}, expected: {}\n", .{ parsed_len.len, @sizeOf(types.Address) });

    if (parsed_len.len != @sizeOf(types.Address)) {
        print("❌ Address length mismatch\n", .{});
        const error_msg = "ERROR: Invalid address length";
        try connection.stream.writeAll(error_msg);
        return;
    }

    // Create funded account for client
    const client_balance = 100 * types.ZEI_COIN; // Give client 100 ZEI
    const client_account = types.Account{
        .address = client_address,
        .balance = client_balance,
        .nonce = 0,
    };

    // Save client account to database
    try zeicoin.database.saveAccount(client_address, client_account);

    print("✅ Funded client {s} with {} ZEI\n", .{ address_hex[0..16], client_balance / types.ZEI_COIN });

    const success_msg = "WALLET_FUNDED_100ZEI";
    try connection.stream.writeAll(success_msg);
    print("📤 Confirmed wallet funding to client\n", .{});
}

fn handleBalanceCheck(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    // Parse CHECK_BALANCE:address message
    const prefix = "CHECK_BALANCE:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const address_hex = message[prefix.len..];
    print("💰 Balance check for address: {s}\n", .{address_hex});

    // Parse hex address
    var client_address: types.Address = undefined;
    const parsed_len = std.fmt.hexToBytes(&client_address, address_hex) catch |err| {
        print("❌ Failed to parse hex address: {}\n", .{err});
        const error_msg = "ERROR: Invalid address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    if (parsed_len.len != @sizeOf(types.Address)) {
        print("❌ Address length mismatch\n", .{});
        const error_msg = "ERROR: Invalid address length";
        try connection.stream.writeAll(error_msg);
        return;
    }

    // Get account balance
    const account = zeicoin.database.getAccount(client_address) catch |err| {
        print("⚠️  Account not found: {}\n", .{err});
        const error_msg = "BALANCE:0";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Send raw balance in zei units (no division to preserve decimals)
    const response = try std.fmt.allocPrint(allocator, "BALANCE:{}", .{account.balance});
    defer allocator.free(response);

    try connection.stream.writeAll(response);

    // Format display for server logs
    const balance_display = formatZEI(allocator, account.balance) catch "? ZEI";
    defer if (!std.mem.eql(u8, balance_display, "? ZEI")) allocator.free(balance_display);
    print("📤 Sent balance: {s} for {s}\n", .{ balance_display, address_hex[0..16] });
}

fn handleNonceCheck(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    // Parse GET_NONCE:address message
    const prefix = "GET_NONCE:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const address_hex = message[prefix.len..];
    print("🔢 Nonce check for address: {s}\n", .{address_hex});

    // Parse hex address
    var client_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&client_address, address_hex) catch |err| {
        print("❌ Failed to parse hex address: {}\n", .{err});
        const error_msg = "ERROR: Invalid address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Get account nonce
    const account = zeicoin.database.getAccount(client_address) catch |err| {
        print("⚠️  Account not found: {}, returning nonce 0\n", .{err});
        const error_msg = "NONCE:0";
        try connection.stream.writeAll(error_msg);
        return;
    };

    const current_nonce = account.nextNonce();
    const response = try std.fmt.allocPrint(allocator, "NONCE:{}", .{current_nonce});
    defer allocator.free(response);

    try connection.stream.writeAll(response);
    print("📤 Sent nonce: {} for {s}\n", .{ current_nonce, address_hex[0..16] });
}

fn handleClientTransaction(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8, transaction_count: *u32) !void {

    // Parse CLIENT_TRANSACTION:sender:recipient:amount:fee:nonce:signature:public_key
    const prefix = "CLIENT_TRANSACTION:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const data = message[prefix.len..];
    logMessage("💸 Processing client transaction: {s}", .{data});

    // Parse CLIENT_TRANSACTION:sender_hex:recipient_hex:amount:fee:nonce:signature_hex:public_key_hex
    var parts = std.mem.splitScalar(u8, data, ':');
    const sender_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing sender address";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const recipient_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing recipient address";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const amount_str = parts.next() orelse {
        const error_msg = "ERROR: Missing amount";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const fee_str = parts.next() orelse {
        const error_msg = "ERROR: Missing fee";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const nonce_str = parts.next() orelse {
        const error_msg = "ERROR: Missing nonce";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const signature_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing signature";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const public_key_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing public key";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse sender address
    var sender_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&sender_address, sender_hex) catch {
        const error_msg = "ERROR: Invalid sender address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse recipient address
    var recipient_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&recipient_address, recipient_hex) catch {
        const error_msg = "ERROR: Invalid recipient address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse amount, fee, and nonce
    const amount = std.fmt.parseInt(u64, amount_str, 10) catch {
        const error_msg = "ERROR: Invalid amount format";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const fee = std.fmt.parseInt(u64, fee_str, 10) catch {
        const error_msg = "ERROR: Invalid fee format";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const nonce = std.fmt.parseInt(u32, nonce_str, 10) catch {
        const error_msg = "ERROR: Invalid nonce format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse signature
    var signature: types.Signature = undefined;
    _ = std.fmt.hexToBytes(&signature, signature_hex) catch {
        const error_msg = "ERROR: Invalid signature format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse public key
    var public_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&public_key, public_key_hex) catch {
        const error_msg = "ERROR: Invalid public key format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Get sender account from database
    const sender_account = zeicoin.database.getAccount(sender_address) catch |err| {
        print("❌ Sender account not found: {}\n", .{err});
        const error_msg = "ERROR: Sender account not found";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 💰 Validate transaction (amount + fee)
    const total_cost = amount + fee;
    if (sender_account.balance < total_cost) {
        print("❌ Insufficient balance: {} < {} (amount: {} + fee: {})\n", .{ sender_account.balance, total_cost, amount, fee });
        const error_msg = "ERROR: Insufficient balance for amount + fee";
        try connection.stream.writeAll(error_msg);
        return;
    }

    if (sender_account.nonce != nonce) {
        print("❌ Invalid nonce: expected {}, got {}\n", .{ sender_account.nonce, nonce });
        const error_msg = "ERROR: Invalid nonce";
        try connection.stream.writeAll(error_msg);
        return;
    }

    // Create transaction from client data with real signature and public key
    const client_tx = types.Transaction{
        .sender = sender_address,
        .sender_public_key = public_key,
        .recipient = recipient_address,
        .amount = amount,
        .fee = fee, // 💰 Include zen fee
        .nonce = nonce,
        .timestamp = @intCast(util.getTime()),
        .signature = signature,
    };

    // Format amounts properly for display
    const amount_display = formatZEI(allocator, amount) catch "? ZEI";
    defer if (!std.mem.eql(u8, amount_display, "? ZEI")) allocator.free(amount_display);
    const fee_display = formatZEI(allocator, fee) catch "? ZEI";
    defer if (!std.mem.eql(u8, fee_display, "? ZEI")) allocator.free(fee_display);

    logMessage("📝 Client transaction: {s} + {s} fee from {s} to {s}", .{ amount_display, fee_display, std.fmt.fmtSliceHexLower(sender_address[0..8]), std.fmt.fmtSliceHexLower(recipient_address[0..8]) });

    logMessage("🔄 About to call zeicoin.addTransaction...", .{});
    // Add to mempool (ZeiCoin will handle balance updates after validation)
    zeicoin.addTransaction(client_tx) catch |err| {
        logMessage("❌ Failed to add client transaction: {}", .{err});
        const error_msg = "ERROR: Client transaction rejected";
        try connection.stream.writeAll(error_msg);
        return;
    };
    logMessage("✅ zeicoin.addTransaction completed successfully", .{});

    transaction_count.* += 1;
    print("✅ Client transaction #{} added to mempool\n", .{transaction_count.*});

    // Zen broadcasting: transaction flows to all connected peers like ripples
    if (zeicoin.network) |network| {
        network.*.broadcastTransaction(client_tx);
        const peer_count = network.*.peers.items.len;
        print("🌊 Transaction flows to {} zen peers naturally\n", .{peer_count});
    }

    logMessage("📤 About to send success response to client", .{});
    const success_msg = "CLIENT_TRANSACTION_ACCEPTED";
    try connection.stream.writeAll(success_msg);
    logMessage("✅ Sent CLIENT_TRANSACTION_ACCEPTED to client", .{});
}

fn sendNewBlockNotification(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin) !void {
    const height = zeicoin.getHeight() catch 0;

    var block_buffer: [256]u8 = undefined;
    const block_msg = try std.fmt.bufPrint(&block_buffer, "NEW_BLOCK:HEIGHT={},MINED=true", .{height});

    try connection.stream.writeAll(block_msg);
    print("📡 Broadcasted new block notification: {s}\n", .{block_msg});
}
