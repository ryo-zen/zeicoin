// initialization.zig - Node initialization and setup
// Handles blockchain, network, and miner initialization

const std = @import("std");
const zen = @import("../node.zig");
const network = @import("../network/peer.zig");
const sync = @import("../sync/manager.zig");
const miner_mod = @import("../miner/main.zig");
const wallet = @import("../wallet/wallet.zig");
const key = @import("../crypto/key.zig");
const command_line = @import("command_line.zig");
const types = @import("../types/types.zig");

/// Thread function to accept incoming connections
fn acceptConnectionsThread(network_manager: *network.NetworkManager) void {
    network_manager.acceptConnections() catch |err| {
        std.log.err("Accept connections thread error: {}", .{err});
    };
}


pub const NodeComponents = struct {
    blockchain: *zen.ZeiCoin,
    network_manager: *network.NetworkManager,
    sync_manager: *sync.SyncManager,
    message_handler_impl: *MessageHandlerImpl,
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
        @import("message_handlers.zig").clearGlobalHandler();
        self.allocator.destroy(self.message_handler_impl);
        
        // 6. Finally blockchain (network_coordinator.deinit won't double-free now)
        self.blockchain.deinit();
        self.allocator.destroy(self.blockchain);
    }
};

pub fn initializeNode(allocator: std.mem.Allocator, config: command_line.Config) !NodeComponents {
    std.log.info("Initializing ZeiCoin node", .{});
    
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
    
    
    // Set bootstrap nodes for auto-reconnect
    network_manager.setBootstrapNodes(config.bootstrap_nodes);
    
    // Connect to bootstrap nodes
    std.log.info("Connecting to {} bootstrap nodes", .{config.bootstrap_nodes.len});
    for (config.bootstrap_nodes) |node| {
        std.log.info("Attempting to connect to bootstrap node {s}:{}", .{ node.ip, node.port });
        const address = std.net.Address.parseIp(node.ip, node.port) catch |err| {
            std.log.warn("Failed to parse bootstrap node {s}:{} - {}", .{ node.ip, node.port, err });
            continue;
        };
        
        network_manager.connectToPeer(address) catch |err| {
            std.log.warn("Failed to connect to bootstrap node {any} - {}", .{ address, err });
        };
    }
    
    // Initialize mining if enabled
    if (config.enable_mining) {
        // miner_wallet is guaranteed to be non-null when enable_mining is true
        try initializeMining(blockchain, config.miner_wallet.?);
    }
    
    return NodeComponents{
        .blockchain = blockchain,
        .network_manager = network_manager,
        .sync_manager = sync_manager,
        .message_handler_impl = handler_result.impl,
        .allocator = allocator,
    };
}

const MessageHandlerImpl = @import("message_handlers.zig").MessageHandlerImpl;

const HandlerResult = struct {
    impl: *MessageHandlerImpl,
    handler: network.MessageHandler,
};

fn createMessageHandler(allocator: std.mem.Allocator, blockchain: *zen.ZeiCoin) !HandlerResult {
    // Create message handler implementation
    const handler_impl = try allocator.create(MessageHandlerImpl);
    handler_impl.* = MessageHandlerImpl.init(blockchain);
    
    return HandlerResult{
        .impl = handler_impl,
        .handler = handler_impl.createHandler(),
    };
}

fn initializeMining(blockchain: *zen.ZeiCoin, miner_wallet_name: []const u8) !void {
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
    
    wallet_obj.loadFromFile(wallet_path, "zen") catch |err| {
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
    
    if (wallet_instance.?.address) |addr| {
        mining_address = addr;
        std.log.info("✅ Mining enabled for wallet: {s}", .{wallet_name});
        std.log.info("⛏️  Mining address: {s}", .{std.fmt.fmtSliceHexLower(std.mem.asBytes(&addr))});
    } else {
        std.log.err("❌ Wallet '{s}' has no address!", .{wallet_name});
        return error.WalletHasNoAddress;
    }
    
    if (wallet_instance) |*w| {
        defer w.deinit();
    }
    
    // Start mining
    if (wallet_instance) |*w| {
        // Get keypair from wallet for mining
        if (w.private_key) |private_key| {
            const keypair = key.KeyPair.fromPrivateKey(private_key);
            
            // Initialize mining manager if needed
            if (blockchain.mining_manager == null) {
                const mining_context = miner_mod.MiningContext{
                    .allocator = allocator,
                    .database = blockchain.database,
                    .mempool_manager = blockchain.mempool_manager,
                    .mining_state = &blockchain.mining_state,
                    .network = blockchain.network_coordinator.getNetworkManager(),
                    .fork_manager = &blockchain.fork_manager,
                    .blockchain = blockchain,
                };
                blockchain.mining_manager = try allocator.create(miner_mod.MiningManager);
                blockchain.mining_manager.?.* = miner_mod.MiningManager.init(mining_context, mining_address);
            }
            
            // Start mining
            try blockchain.mining_manager.?.startMining(keypair);
        } else {
            return error.WalletKeyPairNotFound;
        }
    } else {
        return error.WalletNotFound;
    }
    
    const address_str = try std.fmt.allocPrint(allocator, "{}", .{mining_address});
    defer allocator.free(address_str);
    
    std.log.info("⛏️  Mining enabled to address: {s}", .{address_str});
}