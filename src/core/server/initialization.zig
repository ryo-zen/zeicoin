// initialization.zig - Node initialization and setup
// Handles blockchain, network, and miner initialization

const std = @import("std");
const zen = @import("../node.zig");
const network = @import("../network/peer.zig");
const sync = @import("../network/sync.zig");
const miner_mod = @import("../miner/main.zig");
const wallet = @import("../wallet/wallet.zig");
const key = @import("../crypto/key.zig");
const command_line = @import("command_line.zig");
const types = @import("../types/types.zig");

pub const NodeComponents = struct {
    blockchain: *zen.ZeiCoin,
    network_manager: *network.NetworkManager,
    sync_manager: *sync.SyncManager,
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *NodeComponents) void {
        self.sync_manager.deinit();
        self.allocator.destroy(self.sync_manager);
        
        self.network_manager.deinit();
        self.allocator.destroy(self.network_manager);
        
        self.blockchain.deinit();
    }
};

pub fn initializeNode(allocator: std.mem.Allocator, config: command_line.Config) !NodeComponents {
    std.log.info("Initializing ZeiCoin node", .{});
    
    // Initialize blockchain
    const blockchain = try zen.ZeiCoin.init(allocator);
    errdefer blockchain.deinit();
    
    try blockchain.initializeBlockchain();
    std.log.info("Blockchain initialized", .{});
    
    // Create message handler
    const handler = createMessageHandler(blockchain);
    
    // Initialize network
    var network_manager = try allocator.create(network.NetworkManager);
    network_manager.* = network.NetworkManager.init(allocator, handler);
    errdefer {
        network_manager.deinit();
        allocator.destroy(network_manager);
    }
    
    // Connect components
    blockchain.network = network_manager;
    blockchain.mempool_manager.setNetworkManager(network_manager);
    
    // Initialize sync manager
    const sync_manager = try allocator.create(sync.SyncManager);
    sync_manager.* = sync.SyncManager.init(allocator, blockchain);
    blockchain.sync_manager = sync_manager;
    
    // Start network listening
    try network_manager.listen(config.port);
    std.log.info("Network listening on port {}", .{config.port});
    
    // Connect to bootstrap nodes
    for (config.bootstrap_nodes) |node| {
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
        try initializeMining(blockchain, config.miner_wallet);
    }
    
    return NodeComponents{
        .blockchain = blockchain,
        .network_manager = network_manager,
        .sync_manager = sync_manager,
        .allocator = allocator,
    };
}

const MessageHandlerImpl = @import("message_handlers.zig").MessageHandlerImpl;

fn createMessageHandler(blockchain: *zen.ZeiCoin) network.MessageHandler {
    // Create message handler implementation
    var handler_impl = blockchain.allocator.create(MessageHandlerImpl) catch {
        std.log.err("Failed to allocate message handler", .{});
        std.process.exit(1);
    };
    handler_impl.* = MessageHandlerImpl.init(blockchain);
    
    return handler_impl.createHandler();
}

fn initializeMining(blockchain: *zen.ZeiCoin, miner_wallet_name: ?[]const u8) !void {
    const allocator = blockchain.allocator;
    
    // Determine mining address
    var mining_address: types.Address = undefined;
    var wallet_instance: ?wallet.Wallet = null;
    
    if (miner_wallet_name) |wallet_name| {
        // Load specified wallet
        var wallet_obj = wallet.Wallet.init(allocator);
        const wallet_path = try std.fmt.allocPrint(allocator, "{s}.wallet", .{wallet_name});
        defer allocator.free(wallet_path);
        
        wallet_obj.loadFromFile(wallet_path, "") catch |err| {
            std.log.err("Failed to load mining wallet", .{});
            return err;
        };
        wallet_instance = wallet_obj;
        mining_address = wallet_instance.?.address.?;
        std.log.info("Mining to wallet: {s}", .{wallet_name});
    } else {
        // Create default mining wallet
        var wallet_obj = wallet.Wallet.init(allocator);
        try wallet_obj.createNew();
        const wallet_path = try std.fmt.allocPrint(allocator, "default_miner.wallet", .{});
        defer allocator.free(wallet_path);
        try wallet_obj.saveToFile(wallet_path, "");
        wallet_instance = wallet_obj;
        mining_address = wallet_instance.?.address.?;
        std.log.info("Created default mining wallet", .{});
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
                    .network = blockchain.network,
                    .fork_manager = &blockchain.fork_manager,
                    .blockchain = blockchain,
                };
                blockchain.mining_manager = try allocator.create(miner_mod.MiningManager);
                blockchain.mining_manager.?.* = miner_mod.MiningManager.init(mining_context);
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