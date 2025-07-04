// server.zig - Blockchain node server with headers-first sync
// Production implementation with headers-first protocol

const std = @import("std");
const zen = @import("../node.zig");
const types = @import("../types/types.zig");
const net = @import("peer.zig");
const util = @import("../util/util.zig");
const genesis = @import("../chain/genesis.zig");
const headerchain = @import("headerchain.zig");
const key = @import("../crypto/key.zig");
const sync = @import("sync.zig");
const wallet = @import("../wallet/wallet.zig");
const serialize = @import("../storage/serialize.zig");

const print = std.debug.print;

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
    print("\n", .{});
}

pub fn main() !void {
    print("\n", .{});
    print("╔═══════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                  ⚡ ZeiCoin Node Server ⚡                     ║\n", .{});
    print("║                    Headers-First Protocol                         ║\n", .{});
    print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize logging
    std.fs.cwd().makeDir("logs") catch {}; // Create logs directory if it doesn't exist
    log_file = std.fs.cwd().createFile("logs/server.log", .{}) catch null;
    defer if (log_file) |file| file.close();

    // Initialize blockchain with heap allocation for stable memory addresses
    var blockchain = try zen.ZeiCoin.init(allocator);
    defer {
        blockchain.deinit();
        allocator.destroy(blockchain);
    }

    // Initialize blockchain (will create genesis if needed)
    try blockchain.initializeBlockchain();
    print("✅ Blockchain initialized\n", .{});

    // Initialize network
    var network = net.NetworkManager.init(allocator);
    defer network.deinit();

    // Connect blockchain to network
    network.setBlockchain(blockchain);
    blockchain.network = &network;
    
    // Connect mempool to network for broadcasting
    blockchain.mempool_manager.setNetworkManager(&network);

    // Initialize SyncManager
    blockchain.sync_manager = try allocator.create(sync.SyncManager);
    blockchain.sync_manager.?.* = sync.SyncManager.init(allocator, blockchain);

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var port: u16 = net.DEFAULT_PORT;
    var bootstrap_nodes = std.ArrayList(net.NetworkAddress).init(allocator);
    defer bootstrap_nodes.deinit();

    // Parse arguments
    var enable_mining = false;
    var miner_wallet_name: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--bootstrap") and i + 1 < args.len) {
            // Parse bootstrap nodes
            var iter = std.mem.tokenizeScalar(u8, args[i + 1], ',');
            while (iter.next()) |node| {
                var parts = std.mem.tokenizeScalar(u8, node, ':');
                const ip = parts.next() orelse continue;
                const node_port = if (parts.next()) |p| try std.fmt.parseInt(u16, p, 10) else net.DEFAULT_PORT;

                try bootstrap_nodes.append(.{
                    .ip = try allocator.dupe(u8, ip),
                    .port = node_port,
                });
            }
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--mine")) {
            enable_mining = true;
            // Check if next argument is a wallet name
            if (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "--")) {
                miner_wallet_name = args[i + 1];
                i += 1;
            }
        }
    }

    // Start network
    try network.start(port);
    print("✅ Network.start() completed\n", .{});

    // Connect to bootstrap nodes
    if (bootstrap_nodes.items.len == 0) {
        // Default bootstrap nodes
        // TODO: Re-enable when bootstrap nodes are available
        // try bootstrap_nodes.append(.{ .ip = "134.199.168.129", .port = 10801 });
        // try bootstrap_nodes.append(.{ .ip = "161.189.98.149", .port = 10801 });
        print("📝 Running in standalone mode (no bootstrap nodes)\n", .{});
    }

    for (bootstrap_nodes.items) |node| {
        network.connectToPeer(node) catch |err| {
            print("⚠️ Failed to connect to bootstrap node {}: {}\n", .{ node, err });
        };
    }
    print("✅ Bootstrap connection attempts completed\n", .{});

    // Start sync process
    print("🔄 Starting sync process...\n", .{});
    try blockchain.sync_manager.?.startSync();
    print("✅ Sync process started\n", .{});

    // Main loop
    print("\n🌐 Node running on port {}. Press Ctrl+C to stop.\n", .{port});
    print("📊 Current height: {}\n", .{try blockchain.getHeight()});

    // Start mining thread if enabled
    print("🔍 DEBUG: enable_mining = {}\n", .{enable_mining});
    if (enable_mining) {
        // TODO: Integrate mining with MempoolManager
        if (miner_wallet_name) |wallet_name| {
            print("⛏️ Mining with wallet '{s}' - integration with MempoolManager needed\n", .{wallet_name});
        } else {
            print("⛏️ Mining with default address - integration with MempoolManager needed\n", .{});
        }
    }

    // Start client API listener thread
    print("🚀 Spawning client API thread...\n", .{});
    const client_thread = try std.Thread.spawn(.{}, clientApiListener, .{ allocator, blockchain });
    defer client_thread.join();
    print("✅ Client API thread spawned\n", .{});

    // Status loop
    while (true) {
        std.time.sleep(10 * std.time.ns_per_s); // Every 10 seconds

        const height = try blockchain.getHeight();
        const peers = network.getConnectedPeerCount();
        const mempool_count = 0; // TODO: Get from MempoolManager

        print("\n📊 Status: Height={} | Peers={} | Mempool={}\n", .{ height, peers, mempool_count });
    }
}

fn clientApiListener(allocator: std.mem.Allocator, blockchain: *zen.ZeiCoin) !void {
    const client_port: u16 = 10802;
    print("🔧 Starting client API listener on port {}\n", .{client_port});

    // Create TCP server for client API connections
    const address = std.net.Address.parseIp4("0.0.0.0", client_port) catch |err| {
        print("❌ Failed to parse client address: {}\n", .{err});
        return;
    };

    var server = address.listen(.{ .reuse_address = true }) catch |err| {
        print("❌ Failed to create client TCP server: {}\n", .{err});
        return;
    };
    defer server.deinit();

    print("🔗 Client API: Port {} ACCEPTING\n", .{client_port});

    var connection_count: u32 = 0;
    var transaction_count: u32 = 0;

    while (true) {
        // Handle client connections
        if (server.accept()) |connection| {
            defer connection.stream.close();
            connection_count += 1;
            print("🎉 Client #{} connected!\n", .{connection_count});

            // Handle client request
            handleClientConnection(allocator, connection, blockchain, &transaction_count) catch |err| {
                print("❌ Error handling client: {}\n", .{err});
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
            };
        } else |err| {
            if (err != error.WouldBlock) {
                print("❌ Accept error: {}\n", .{err});
            }
            std.time.sleep(100 * std.time.ns_per_ms); // 100ms
        }
    }
}

fn handleClientConnection(allocator: std.mem.Allocator, connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin, transaction_count: *u32) !void {
    var buffer: [4096]u8 = undefined;

    while (true) {
        const bytes_read = try connection.stream.read(&buffer);

        if (bytes_read == 0) {
            print("🔚 Client closed connection\n", .{});
            break;
        }

        const message = buffer[0..bytes_read];
        print("📨 Received: '{s}' ({} bytes)\n", .{ message, bytes_read });

        // Debug: print first few chars
        if (message.len >= 12) {
            print("🔍 First 12 chars: '{s}'\n", .{message[0..12]});
        }

        // Parse messages
        if (std.mem.eql(u8, message, "BLOCKCHAIN_STATUS")) {
            try sendBlockchainStatus(connection, blockchain);
        } else if (std.mem.startsWith(u8, message, "CHECK_BALANCE:")) {
            print("🔍 Handling CHECK_BALANCE request\n", .{});
            try handleBalanceCheck(allocator, connection, blockchain, message);
        } else if (std.mem.startsWith(u8, message, "GET_NONCE:")) {
            try handleNonceCheck(allocator, connection, blockchain, message);
        } else if (std.mem.startsWith(u8, message, "CLIENT_TRANSACTION:")) {
            try handleClientTransaction(allocator, connection, blockchain, message, transaction_count);
        } else if (std.mem.startsWith(u8, message, "FUND_WALLET:")) {
            print("🔍 Handling FUND_WALLET request\n", .{});
            try handleWalletFunding(allocator, connection, blockchain, message);
        } else if (std.mem.eql(u8, message, "GET_HEIGHT")) {
            try handleGetHeight(connection, blockchain);
        } else if (std.mem.eql(u8, message, "PING")) {
            try connection.stream.writeAll("PONG");
            print("🏓 Responded to PING\n", .{});
        } else {
            try connection.stream.writeAll("ZeiCoin Server Ready");
        }
    }
}

fn sendBlockchainStatus(connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin) !void {
    const height = blockchain.getHeight() catch 0;
    const pending = 0; // TODO: Get from MempoolManager

    var status_buffer: [256]u8 = undefined;
    const status_msg = try std.fmt.bufPrint(&status_buffer, "STATUS:HEIGHT={},PENDING={},READY=true", .{ height, pending });

    try connection.stream.writeAll(status_msg);
    print("📊 Sent blockchain status\n", .{});
}

fn handleBalanceCheck(allocator: std.mem.Allocator, connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin, message: []const u8) !void {
    print("🔎 In handleBalanceCheck, message len: {}\n", .{message.len});
    if (message.len < 15) {
        try connection.stream.writeAll("ERROR:Invalid format");
        return;
    }

    const address_str = message[14..];
    print("🔍 Looking up balance for address: {s}\n", .{address_str});

    // Parse address (supports both bech32 and hex)
    const address = types.Address.fromString(allocator, address_str) catch {
        try connection.stream.writeAll("ERROR:Invalid address format");
        return;
    };

    // Get balance
    const account = blockchain.getAccount(address) catch |err| {
        if (err == error.AccountNotFound) {
            print("❌ Account not found for address {s}\n", .{address_str});
            try connection.stream.writeAll("BALANCE:0,0");
            return;
        }
        print("❌ Error getting account: {}\n", .{err});
        return err;
    };

    print("📊 Account found - Balance: {} zei ({} ZEI), Immature: {} zei ({} ZEI)\n", .{ account.balance, account.balance / types.ZEI_COIN, account.immature_balance, account.immature_balance / types.ZEI_COIN });
    print("🔍 Account address version: {}\n", .{account.address.version});

    var response_buffer: [256]u8 = undefined;
    const response = try std.fmt.bufPrint(&response_buffer, "BALANCE:{},{}", .{ account.balance, account.immature_balance });
    try connection.stream.writeAll(response);
}

fn handleGetHeight(connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin) !void {
    const height = blockchain.getHeight() catch 0;

    var response_buffer: [64]u8 = undefined;
    const response = try std.fmt.bufPrint(&response_buffer, "HEIGHT:{}", .{height});
    try connection.stream.writeAll(response);
}

fn handleNonceCheck(allocator: std.mem.Allocator, connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin, message: []const u8) !void {
    if (message.len < 11) {
        try connection.stream.writeAll("ERROR:Invalid format");
        return;
    }

    const address_str = message[10..];

    // Parse address (supports both bech32 and hex)
    const address = types.Address.fromString(allocator, address_str) catch {
        try connection.stream.writeAll("ERROR:Invalid address format");
        return;
    };

    // Get nonce
    const account = blockchain.getAccount(address) catch |err| {
        if (err == error.AccountNotFound) {
            try connection.stream.writeAll("NONCE:0");
            return;
        }
        return err;
    };

    var response_buffer: [64]u8 = undefined;
    const response = try std.fmt.bufPrint(&response_buffer, "NONCE:{}", .{account.nonce});
    try connection.stream.writeAll(response);
}

fn handleClientTransaction(allocator: std.mem.Allocator, connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin, message: []const u8, transaction_count: *u32) !void {

    // Parse CLIENT_TRANSACTION:sender:recipient:amount:fee:nonce:signature:public_key
    const prefix = "CLIENT_TRANSACTION:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const data = message[prefix.len..];
    logMessage("💸 Processing client transaction: {s}", .{data});

    // Parse CLIENT_TRANSACTION:sender_hex:recipient_hex:amount:fee:nonce:timestamp:expiry_height:signature_hex:public_key_hex
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
    const timestamp_str = parts.next() orelse {
        const error_msg = "ERROR: Missing timestamp";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const expiry_height_str = parts.next() orelse {
        const error_msg = "ERROR: Missing expiry_height";
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

    // Parse sender address (supports both bech32 and hex)
    const sender_address = types.Address.fromString(allocator, sender_hex) catch {
        const error_msg = "ERROR: Invalid sender address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse recipient address (supports both bech32 and hex)
    const recipient_address = types.Address.fromString(allocator, recipient_hex) catch {
        const error_msg = "ERROR: Invalid recipient address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse amount, fee, nonce, timestamp, and expiry_height
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
    const timestamp = std.fmt.parseInt(u64, timestamp_str, 10) catch {
        const error_msg = "ERROR: Invalid timestamp format";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const expiry_height = std.fmt.parseInt(u64, expiry_height_str, 10) catch {
        const error_msg = "ERROR: Invalid expiry_height format";
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

    // Debug: Print sender address details
    print("🔍 Sender address: {s}\n", .{sender_hex});

    // Get sender account from blockchain
    const sender_account = blockchain.getAccount(sender_address) catch |err| {
        print("❌ Sender account not found: {}\n", .{err});
        const error_msg = "ERROR: Sender account not found";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Debug: Print account details
    print("📊 Found sender account - Balance: {} zei ({} ZEI), Nonce: {}\n", .{ sender_account.balance, sender_account.balance / types.ZEI_COIN, sender_account.nonce });

    // 💰 Validate transaction (amount + fee)
    const total_cost = amount + fee;
    if (sender_account.balance < total_cost) {
        print("❌ Insufficient balance: {} < {} (amount: {} + fee: {})", .{ sender_account.balance, total_cost, amount, fee });
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
        .version = 0, // Version 0 for initial protocol
        .flags = .{}, // Default flags
        .sender = sender_address,
        .sender_public_key = public_key,
        .recipient = recipient_address,
        .amount = amount,
        .fee = fee, // 💰 Include zen fee
        .nonce = nonce,
        .timestamp = timestamp, // Use client's timestamp
        .expiry_height = expiry_height, // Use client's expiry_height
        .signature = signature,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Format amounts properly for display
    const amount_display = util.formatZEI(allocator, amount) catch "? ZEI";
    defer if (!std.mem.eql(u8, amount_display, "? ZEI")) allocator.free(amount_display);
    const fee_display = util.formatZEI(allocator, fee) catch "? ZEI";
    defer if (!std.mem.eql(u8, fee_display, "? ZEI")) allocator.free(fee_display);

    // Use the bech32 addresses we already have for logging
    logMessage("📝 Client transaction: {s} + {s} fee from {s} to {s}", .{ amount_display, fee_display, sender_hex, recipient_hex });

    logMessage("🔄 About to call zeicoin.addTransaction...", .{});
    // Add to mempool (ZeiCoin will handle balance updates after validation)
    blockchain.addTransaction(client_tx) catch |err| {
        logMessage("❌ Failed to add client transaction: {}", .{err});
        const error_msg = "ERROR: Client transaction rejected";
        try connection.stream.writeAll(error_msg);
        return;
    };
    logMessage("✅ zeicoin.addTransaction completed successfully", .{});

    transaction_count.* += 1;
    print("✅ Client transaction #{} added to mempool\n", .{transaction_count.*});

    // Broadcast transaction to network peers
    if (blockchain.network) |network| {
        network.*.broadcastTransaction(client_tx);
        const peer_count = network.*.peers.items.len;
        print("📡 Transaction broadcast to {} peers\n", .{peer_count});
    }

    logMessage("📤 About to send success response to client", .{});
    const success_msg = "OK:Transaction accepted";
    try connection.stream.writeAll(success_msg);
    logMessage("✅ Sent OK:Transaction accepted to client", .{});
}

fn handleWalletFunding(allocator: std.mem.Allocator, connection: std.net.Server.Connection, blockchain: *zen.ZeiCoin, message: []const u8) !void {
    if (message.len < 13) {
        try connection.stream.writeAll("ERROR:Invalid format");
        return;
    }

    const address_str = message[12..];

    // Only allow funding on TestNet
    if (types.CURRENT_NETWORK != .testnet) {
        try connection.stream.writeAll("ERROR:Funding only available on TestNet");
        return;
    }

    // Parse address (supports both bech32 and hex)
    const recipient = types.Address.fromString(allocator, address_str) catch {
        try connection.stream.writeAll("ERROR:Invalid address format");
        return;
    };

    // Create a special funding transaction
    const funding_amount = 100 * types.ZEI_COIN; // 100 ZEI

    // For simplicity, we'll just update the account balance directly
    // In a real implementation, this would create a proper transaction
    var account = blockchain.getAccount(recipient) catch |err| {
        if (err == error.AccountNotFound) {
            // Create new account
            const new_account = types.Account{
                .address = recipient,
                .balance = funding_amount,
                .immature_balance = 0,
                .nonce = 0,
            };
            try blockchain.database.saveAccount(recipient, new_account);
            try connection.stream.writeAll("WALLET_FUNDED_100ZEI");
            print("💰 Funded new account with 100 ZEI\n", .{});
            return;
        }
        return err;
    };

    // Add to existing balance
    account.balance += funding_amount;
    try blockchain.database.saveAccount(recipient, account);

    try connection.stream.writeAll("WALLET_FUNDED_100ZEI");
    print("💰 Funded existing account with 100 ZEI (new balance: {} ZEI)\n", .{account.balance / types.ZEI_COIN});
}
