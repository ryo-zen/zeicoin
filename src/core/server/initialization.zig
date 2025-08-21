// initialization.zig - Node initialization and setup
// Handles blockchain, network, and miner initialization

const std = @import("std");
const zen = @import("../node.zig");
const network = @import("../network/peer.zig");
const sync = @import("../sync/manager.zig");
const miner_mod = @import("../miner/main.zig");
const wallet = @import("../wallet/wallet.zig");
const password_util = @import("../util/password.zig");
const key = @import("../crypto/key.zig");
const command_line = @import("command_line.zig");
const types = @import("../types/types.zig");
const bech32 = @import("../crypto/bech32.zig");

/// Thread function to accept incoming connections
fn acceptConnectionsThread(network_manager: *network.NetworkManager) void {
    network_manager.acceptConnections() catch |err| {
        std.log.err("Accept connections thread error: {}", .{err});
    };
}

/// Load bootstrap nodes from JSON config, with command line fallback
fn loadBootstrapNodes(allocator: std.mem.Allocator, cmd_line_nodes: []const command_line.BootstrapNode) ![]const command_line.BootstrapNode {
    // If command line nodes are provided, use them (they override JSON)
    if (cmd_line_nodes.len > 0) {
        std.log.info("Using {} command line bootstrap nodes", .{cmd_line_nodes.len});
        // Duplicate the slice to ensure consistent memory management
        var result = try allocator.alloc(command_line.BootstrapNode, cmd_line_nodes.len);
        for (cmd_line_nodes, 0..) |node, i| {
            result[i] = command_line.BootstrapNode{
                .ip = try allocator.dupe(u8, node.ip),
                .port = node.port,
            };
        }
        return result;
    }
    
    // Try to load from JSON config
    const json_nodes = types.loadBootstrapNodes(allocator) catch |err| {
        std.log.warn("Failed to load bootstrap nodes from JSON: {}", .{err});
        // Return empty slice if both JSON and command line fail
        return try allocator.alloc(command_line.BootstrapNode, 0);
    };
    defer types.freeBootstrapNodes(allocator, json_nodes);
    
    std.log.info("Loaded {} bootstrap nodes from JSON config", .{json_nodes.len});
    
    // Convert JSON format (ip:port strings) to BootstrapNode format
    var result = try allocator.alloc(command_line.BootstrapNode, json_nodes.len);
    for (json_nodes, 0..) |node_str, i| {
        // Parse "ip:port" format
        var it = std.mem.splitScalar(u8, node_str, ':');
        const ip_str = it.next() orelse {
            std.log.warn("Invalid bootstrap node format: {s}", .{node_str});
            continue;
        };
        const port_str = it.next() orelse "10801"; // Default port
        const port = std.fmt.parseInt(u16, port_str, 10) catch 10801;
        
        result[i] = command_line.BootstrapNode{
            .ip = try allocator.dupe(u8, ip_str),
            .port = port,
        };
    }
    
    return result;
}

/// Free bootstrap nodes memory
fn freeBootstrapNodes(allocator: std.mem.Allocator, nodes: []const command_line.BootstrapNode) void {
    for (nodes) |node| {
        allocator.free(node.ip);
    }
    allocator.free(nodes);
}

/// Load consensus configuration from environment variables
fn loadConsensusConfig() void {
    // Load consensus mode
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_MODE")) |mode_str| {
        defer std.heap.page_allocator.free(mode_str);
        
        if (std.mem.eql(u8, mode_str, "disabled")) {
            types.CONSENSUS.mode = .disabled;
        } else if (std.mem.eql(u8, mode_str, "optional")) {
            types.CONSENSUS.mode = .optional;
        } else if (std.mem.eql(u8, mode_str, "enforced")) {
            types.CONSENSUS.mode = .enforced;
        } else {
            std.log.warn("Invalid consensus mode: {s}, using default 'optional'", .{mode_str});
        }
    } else |_| {}
    
    // Load consensus threshold
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_THRESHOLD")) |threshold_str| {
        defer std.heap.page_allocator.free(threshold_str);
        
        if (std.fmt.parseFloat(f32, threshold_str)) |threshold| {
            if (threshold >= 0.0 and threshold <= 1.0) {
                types.CONSENSUS.threshold = threshold;
            } else {
                std.log.warn("Consensus threshold must be between 0.0 and 1.0, using default 0.5", .{});
            }
        } else |_| {
            std.log.warn("Invalid consensus threshold: {s}, using default 0.5", .{threshold_str});
        }
    } else |_| {}
    
    // Load minimum peer responses
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_MIN_PEERS")) |min_str| {
        defer std.heap.page_allocator.free(min_str);
        
        if (std.fmt.parseInt(u32, min_str, 10)) |min_peers| {
            types.CONSENSUS.min_peer_responses = min_peers;
        } else |_| {
            std.log.warn("Invalid minimum peers: {s}, using default 0", .{min_str});
        }
    } else |_| {}
    
    // Load check during normal operation flag
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_CHECK_NORMAL")) |check_str| {
        defer std.heap.page_allocator.free(check_str);
        
        types.CONSENSUS.check_during_normal_operation = std.mem.eql(u8, check_str, "true");
    } else |_| {}
    
    std.log.info("📊 Consensus Configuration:", .{});
    std.log.info("  Mode: {s}", .{@tagName(types.CONSENSUS.mode)});
    std.log.info("  Threshold: {d:.0}%", .{types.CONSENSUS.threshold * 100});
    std.log.info("  Min peer responses: {}", .{types.CONSENSUS.min_peer_responses});
    std.log.info("  Check during normal: {}", .{types.CONSENSUS.check_during_normal_operation});
}


pub const NodeComponents = struct {
    blockchain: *zen.ZeiCoin,
    network_manager: *network.NetworkManager,
    sync_manager: *sync.SyncManager,
    server_handlers: *ServerHandlers,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *NodeComponents) void {
        // CRITICAL: Order matters for thread safety!
        // 1. Stop network first (this waits for threads)
        self.network_manager.stop();
        
        // 2. Then clean up sync manager (no threads accessing it now)
        self.sync_manager.deinit();
        self.allocator.destroy(self.sync_manager);
        // Clear the pointer in blockchain to prevent double-free
        self.blockchain.sync_manager = null;
        
        // 3. Now fully deinit network
        self.network_manager.deinit();
        self.allocator.destroy(self.network_manager);
        
        // 4. Clear network reference in blockchain to prevent double-free
        self.blockchain.network_coordinator.network = null;
        
        // 5. Clean up message handler
        @import("server_handlers.zig").clearGlobalHandler();
        self.allocator.destroy(self.server_handlers);
        
        // 6. Finally blockchain (network_coordinator.deinit won't double-free now)
        self.blockchain.deinit();
        self.allocator.destroy(self.blockchain);
    }
};

pub fn initializeNode(allocator: std.mem.Allocator, config: command_line.Config) !NodeComponents {
    std.log.info("Initializing ZeiCoin node", .{});
    
    // Load consensus configuration from environment
    loadConsensusConfig();
    
    // Initialize blockchain
    const blockchain = try zen.ZeiCoin.init(allocator);
    errdefer {
        blockchain.deinit();
        allocator.destroy(blockchain);
    }
    
    try blockchain.initializeBlockchain();
    std.log.info("Blockchain initialized", .{});
    
    // Create message handler
    const handler_result = try createMessageHandler(allocator, blockchain);
    errdefer allocator.destroy(handler_result.impl);
    
    // Initialize network
    var network_manager = try allocator.create(network.NetworkManager);
    network_manager.* = network.NetworkManager.init(allocator, handler_result.handler);
    // Note: network_manager ownership is transferred to blockchain.network_coordinator
    // No errdefer needed - NodeComponents.deinit() handles cleanup
    
    // Connect components
    blockchain.mempool_manager.setNetworkManager(network_manager);
    
    // Set the network manager on blockchain's network coordinator
    blockchain.network_coordinator.network = network_manager;
    std.log.info("✅ Network manager set on blockchain coordinator", .{});
    
    // Initialize sync manager following ZeiCoin ownership principles
    const sync_manager = try allocator.create(sync.SyncManager);
    sync_manager.* = try sync.SyncManager.init(allocator, blockchain);
    blockchain.sync_manager = sync_manager;
    
    // Start network listening
    try network_manager.listen(config.port);
    std.log.info("Network listening on port {}", .{config.port});
    
    // Start accepting connections in a separate thread
    const accept_thread = try std.Thread.spawn(.{}, acceptConnectionsThread, .{network_manager});
    accept_thread.detach();
    std.log.info("Connection accept thread started", .{});
    
    
    // Load bootstrap nodes - JSON first, then command line fallback
    const bootstrap_nodes = try loadBootstrapNodes(allocator, config.bootstrap_nodes);
    defer freeBootstrapNodes(allocator, bootstrap_nodes);
    
    // Set bootstrap nodes for auto-reconnect (NetworkManager will copy them)
    try network_manager.setBootstrapNodes(bootstrap_nodes);
    
    // Connect to bootstrap nodes
    std.log.info("Connecting to {} bootstrap nodes", .{bootstrap_nodes.len});
    for (bootstrap_nodes) |node| {
        std.log.info("Attempting to connect to bootstrap node {s}:{}", .{ node.ip, node.port });
        const address = std.net.Address.parseIp(node.ip, node.port) catch |err| {
            std.log.warn("Failed to parse bootstrap node {s}:{} - {}", .{ node.ip, node.port, err });
            continue;
        };
        
        network_manager.connectToPeer(address) catch |err| {
            std.log.warn("Failed to connect to bootstrap node {any} - {}", .{ address, err });
        };
    }
    
    // Initialize mining if enabled - but delay actual mining start until after sync
    if (config.enable_mining) {
        // miner_wallet is guaranteed to be non-null when enable_mining is true
        if (initializeMiningSystem(blockchain, config.miner_wallet.?)) {
            std.log.info("⛏️  Mining system initialized - will start mining after initial sync", .{});
        } else |err| {
            // Handle mining initialization errors gracefully without exposing internals
            switch (err) {
                error.WalletFileNotFound => {
                    std.log.err("❌ Mining wallet '{s}' not found", .{config.miner_wallet.?});
                    std.log.err("💡 Create wallet: ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin wallet create {s}", .{config.miner_wallet.?});
                },
                error.PasswordRequired => {
                    std.log.err("❌ Password required for mining wallet '{s}'", .{config.miner_wallet.?});
                    std.log.err("💡 Set ZEICOIN_WALLET_PASSWORD or enable ZEICOIN_TEST_MODE=1", .{});
                },
                error.WalletHasNoAddress => {
                    std.log.err("❌ Mining wallet '{s}' has no address", .{config.miner_wallet.?});
                },
                else => {
                    std.log.err("❌ Mining initialization failed: {}", .{err});
                },
            }
            std.log.err("🔄 Starting server without mining - you can enable mining later", .{});
            // Continue without mining instead of crashing
        }
    }
    
    return NodeComponents{
        .blockchain = blockchain,
        .network_manager = network_manager,
        .sync_manager = sync_manager,
        .server_handlers = handler_result.impl,
        .allocator = allocator,
    };
}

const ServerHandlers = @import("server_handlers.zig").ServerHandlers;

const HandlerResult = struct {
    impl: *ServerHandlers,
    handler: network.MessageHandler,
};

fn createMessageHandler(allocator: std.mem.Allocator, blockchain: *zen.ZeiCoin) !HandlerResult {
    // Create message handler implementation
    const handler_impl = try allocator.create(ServerHandlers);
    handler_impl.* = ServerHandlers.init(blockchain);
    
    return HandlerResult{
        .impl = handler_impl,
        .handler = handler_impl.createHandler(),
    };
}

fn initializeMiningSystem(blockchain: *zen.ZeiCoin, miner_wallet_name: []const u8) !void {
    const allocator = blockchain.allocator;
    
    // Load specified mining wallet
    const wallet_name = miner_wallet_name;
    var mining_address: types.Address = undefined;
    var wallet_instance: ?wallet.Wallet = null;
    
    // Load specified wallet
    var wallet_obj = wallet.Wallet.init(allocator);
    
    // Build proper wallet path (wallet_name is already safely owned by Config)
    const data_dir = types.CURRENT_NETWORK.getDataDir();
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    std.log.info("Loading mining wallet from: {s}", .{wallet_path});
    
    // Get password for mining wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch |pwd_err| {
        wallet_obj.deinit(); // Clean up wallet on password error
        std.log.err("❌ Failed to get password for mining wallet '{s}'", .{wallet_name});
        std.log.err("❌ Error: {}", .{pwd_err});
        std.log.err("", .{});
        std.log.err("💡 To fix this issue:", .{});
        std.log.err("   - Set ZEICOIN_WALLET_PASSWORD in your .env file", .{});
        std.log.err("   - Or set ZEICOIN_TEST_MODE=1 for development", .{});
        std.log.err("   - Or enter the password interactively (if running in terminal)", .{});
        return error.PasswordRequired;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    wallet_obj.loadFromFile(wallet_path, password) catch |err| {
        wallet_obj.deinit(); // Clean up wallet on load error
        std.log.err("❌ Failed to load mining wallet '{s}' from path: {s}", .{wallet_name, wallet_path});
        std.log.err("❌ Error: {}", .{err});
        std.log.err("", .{});
        std.log.err("💡 To fix this issue:", .{});
        std.log.err("   1. Create the wallet first: ZEICOIN_SERVER=127.0.0.1 ./zig-out/bin/zeicoin wallet create {s}", .{wallet_name});
        std.log.err("   2. Then restart the server with mining: --mine {s}", .{wallet_name});
        std.log.err("", .{});
        std.log.err("🔄 Or start the server without mining and create the wallet later", .{});
        return err;
    };
    
    wallet_instance = wallet_obj;
    
    const addr = wallet_instance.?.getAddress(0) catch {
        wallet_obj.deinit(); // Clean up wallet on address error
        std.log.err("❌ Wallet '{s}' has no address!", .{wallet_name});
        return error.WalletHasNoAddress;
    };
    
    mining_address = addr;
    std.log.info("✅ Mining enabled for wallet: {s}", .{wallet_name});
    const addr_str = bech32.encodeAddress(allocator, addr, types.CURRENT_NETWORK) catch "<invalid>";
    defer if (!std.mem.eql(u8, addr_str, "<invalid>")) allocator.free(addr_str);
    std.log.info("⛏️  Mining address: {s}", .{addr_str});
    
    if (wallet_instance) |*w| {
        defer w.deinit();
    }
    
    // Start mining
    if (wallet_instance) |*w| {
        // Get keypair from wallet for mining
        const keypair = w.getKeyPair(0) catch {
            std.log.err("❌ Failed to get keypair from wallet for mining", .{});
            return error.WalletKeyPairError;
        };
        
        // Initialize mining manager if needed
        if (blockchain.mining_manager == null) {
            const mining_context = miner_mod.MiningContext{
                .allocator = allocator,
                .database = blockchain.database,
                .mempool_manager = blockchain.mempool_manager,
                .mining_state = &blockchain.mining_state,
                .network = blockchain.network_coordinator.getNetworkManager(),
                .blockchain = blockchain,
            };
            blockchain.mining_manager = try allocator.create(miner_mod.MiningManager);
            blockchain.mining_manager.?.* = miner_mod.MiningManager.init(mining_context, mining_address);
        }
        
        // Store keypair for deferred mining start
        blockchain.mining_keypair = keypair;
        std.log.info("⛏️  Mining keypair stored for deferred start", .{});
    } else {
        return error.WalletNotFound;
    }
    
    const address_str = bech32.encodeAddress(allocator, mining_address, types.CURRENT_NETWORK) catch "<invalid>";
    defer if (!std.mem.eql(u8, address_str, "<invalid>")) allocator.free(address_str);
    
    std.log.info("⛏️  Mining enabled to address: {s}", .{address_str});
}