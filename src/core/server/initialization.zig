// initialization.zig - Node initialization and setup
// Handles blockchain, network, and miner initialization

const std = @import("std");
const libp2p = @import("libp2p");
const zen = @import("../node.zig");
const network = @import("../network/peer.zig");
const sync = @import("../sync/manager.zig");
const miner_mod = @import("../miner/main.zig");
const wallet = @import("../wallet/wallet.zig");
const password_util = @import("../util/password.zig");
const key = @import("../crypto/key.zig");
const command_line = @import("command_line.zig");
const bootstrap = @import("../network/bootstrap.zig");
const types = @import("../types/types.zig");
const bech32 = @import("../crypto/bech32.zig");
const util = @import("../util/util.zig");

/// Thread function to accept incoming connections
fn acceptConnectionsThread(network_manager: *network.NetworkManager) void {
    network_manager.acceptConnections() catch |err| {
        std.log.err("Accept connections thread error: {}", .{err});
    };
}


/// Load consensus configuration from environment variables
fn loadConsensusConfig() void {
    // Load consensus mode
    if (util.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_MODE")) |mode_str| {
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
    if (util.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_THRESHOLD")) |threshold_str| {
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
    if (util.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_MIN_PEERS")) |min_str| {
        defer std.heap.page_allocator.free(min_str);
        
        if (std.fmt.parseInt(u32, min_str, 10)) |min_peers| {
            types.CONSENSUS.min_peer_responses = min_peers;
        } else |_| {
            std.log.warn("Invalid minimum peers: {s}, using default 0", .{min_str});
        }
    } else |_| {}
    
    // Load check during normal operation flag
    if (util.getEnvVarOwned(std.heap.page_allocator, "ZEICOIN_CONSENSUS_CHECK_NORMAL")) |check_str| {
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

pub fn initializeNode(allocator: std.mem.Allocator, io: std.Io, config: command_line.Config) !NodeComponents {
    std.log.info("Initializing ZeiCoin node", .{});
    
    // Load consensus configuration from environment
    loadConsensusConfig();

    // Check for ZEICOIN_DATA_DIR override
    var data_dir_override: ?[]u8 = null;
    if (util.getEnvVarOwned(allocator, "ZEICOIN_DATA_DIR")) |dir| {
        data_dir_override = dir;
        std.log.info("📂 Using data directory override: {s}", .{dir});
    } else |_| {}
    defer if (data_dir_override) |dir| allocator.free(dir);
    
    // Initialize blockchain
    const blockchain = try zen.ZeiCoin.init(allocator, io, data_dir_override);
    errdefer {
        blockchain.deinit();
        allocator.destroy(blockchain);
    }
    
    try blockchain.initializeBlockchain();
    std.log.info("Blockchain initialized", .{});
    
    // Create message handler
    const handler_result = try createMessageHandler(allocator, blockchain);
    errdefer allocator.destroy(handler_result.impl);
    
    // Load or create persistent node identity key (Ed25519, stored at data_dir/node_key).
    const data_dir_for_key = if (data_dir_override) |dir| dir else types.CURRENT_NETWORK.getDataDir();
    const node_key_path = try std.fmt.allocPrint(allocator, "{s}/node_key", .{data_dir_for_key});
    defer allocator.free(node_key_path);
    const identity = try libp2p.IdentityKey.loadOrCreate(allocator, io, node_key_path);
    // Ownership transferred to NetworkManager.init() below — do not call identity.deinit().
    std.log.info("🔑 Node identity: {s}", .{identity.peer_id.toString()});

    // Initialize network
    var network_manager = try allocator.create(network.NetworkManager);
    network_manager.* = network.NetworkManager.init(allocator, io, handler_result.handler, identity);
    // Note: network_manager ownership is transferred to blockchain.network_coordinator
    // No errdefer needed - NodeComponents.deinit() handles cleanup
    
    // Connect components
    blockchain.mempool_manager.setNetworkManager(network_manager);
    
    // Set the network manager on blockchain's network coordinator
    blockchain.network_coordinator.network = network_manager;
    std.log.info("✅ Network manager set on blockchain coordinator", .{});
    
    // Initialize sync manager following ZeiCoin ownership principles
    const sync_manager = try allocator.create(sync.SyncManager);
    errdefer allocator.destroy(sync_manager);
    sync_manager.* = try sync.SyncManager.init(allocator, blockchain);
    blockchain.sync_manager = sync_manager;
    
    // Start network listening
    try network_manager.listen(config.bind_address, config.port);
    std.log.info("Network listening on {s}:{}", .{ config.bind_address, config.port });
    
    // Start accepting connections in a separate thread
    const accept_thread = try std.Thread.spawn(.{}, acceptConnectionsThread, .{network_manager});
    accept_thread.detach();
    std.log.info("Connection accept thread started", .{});
    
    
    // Resolve bootstrap nodes: CLI > env var > hardcoded fallback
    const bootstrap_nodes = try bootstrap.resolveBootstrapNodes(
        allocator,
        config.bootstrap_nodes,
        config.bootstrap_nodes_configured,
    );
    defer bootstrap.freeList(allocator, bootstrap_nodes);

    // Set bootstrap nodes for auto-reconnect (NetworkManager will copy them)
    try network_manager.setBootstrapNodes(bootstrap_nodes);

    // Connect to bootstrap nodes
    std.log.info("Connecting to {} bootstrap nodes", .{bootstrap_nodes.len});
    for (bootstrap_nodes) |*node| {
        const address = node.tcpAddress() orelse {
            std.log.warn("Bootstrap node '{s}' has no TCP address, skipping",
                .{node.multiaddr.getStringAddress()});
            continue;
        };
        std.log.info("Attempting to connect to bootstrap node {any}", .{address});
        network_manager.connectToPeer(address) catch |err| {
            std.log.warn("Failed to connect to bootstrap node {any}: {}", .{ address, err });
        };
    }
    
    // Initialize mining if enabled - but delay actual mining start until after sync
    if (config.enable_mining) {
        // miner_wallet is guaranteed to be non-null when enable_mining is true
        if (initializeMiningSystem(blockchain, io, config.miner_wallet.?, data_dir_override)) {
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

fn initializeMiningSystem(blockchain: *zen.ZeiCoin, io: std.Io, miner_wallet_name: []const u8, data_dir_override: ?[]const u8) !void {
    const allocator = blockchain.allocator;
    
    // Load specified mining wallet
    const wallet_name = miner_wallet_name;
    var mining_address: types.Address = undefined;
    
    // Load specified wallet
    var wallet_obj = wallet.Wallet.init(allocator);
    defer wallet_obj.deinit();
    
    // Build proper wallet path (wallet_name is already safely owned by Config)
    const data_dir = if (data_dir_override) |dir| dir else types.CURRENT_NETWORK.getDataDir();
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    std.log.info("Loading mining wallet from: {s}", .{wallet_path});
    
    // Get password for mining wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch |pwd_err| {
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
    
    wallet_obj.loadFromFile(io, wallet_path, password) catch |err| {
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

    const addr = wallet_obj.getAddress(0) catch {
        std.log.err("❌ Wallet '{s}' has no address!", .{wallet_name});
        return error.WalletHasNoAddress;
    };
    
    mining_address = addr;
    std.log.info("✅ Mining enabled for wallet: {s}", .{wallet_name});
    const addr_str = bech32.encodeAddress(allocator, addr, types.CURRENT_NETWORK) catch "<invalid>";
    defer if (!std.mem.eql(u8, addr_str, "<invalid>")) allocator.free(addr_str);
    std.log.info("⛏️  Mining address: {s}", .{addr_str});

    // Get keypair from wallet for mining
    const keypair = wallet_obj.getKeyPair(0) catch {
        std.log.err("❌ Failed to get keypair from wallet for mining", .{});
        return error.WalletKeyPairError;
    };
    
    // Initialize mining manager if needed
    if (blockchain.mining_manager == null) {
        const mining_context = miner_mod.MiningContext{
            .allocator = allocator,
            .io = blockchain.io,
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
    
    const address_str = bech32.encodeAddress(allocator, mining_address, types.CURRENT_NETWORK) catch "<invalid>";
    defer if (!std.mem.eql(u8, address_str, "<invalid>")) allocator.free(address_str);
    
    std.log.info("⛏️  Mining enabled to address: {s}", .{address_str});
}
