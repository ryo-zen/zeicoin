const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const net = @import("peer.zig");
const ZeiCoin = @import("../node.zig").ZeiCoin;

// Import modular components
const BlockProcessor = @import("processors/block_processor.zig").BlockProcessor;
const NetworkCoordinator = @import("coordinators/network_coordinator.zig").NetworkCoordinator;

const Transaction = types.Transaction;
const Block = types.Block;

pub const NetworkMessageHandler = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    // Modular components
    block_processor: BlockProcessor,
    network_coordinator: NetworkCoordinator,
    
    const Self = @This();
    
    /// Initialize message handler with modular components
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .block_processor = BlockProcessor.init(allocator, blockchain),
            .network_coordinator = NetworkCoordinator.init(allocator, blockchain),
        };
    }
    
    /// Cleanup message handler resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to cleanup currently
    }
    
    /// Handle incoming block from network peer (delegates to block processor)
    pub fn handleIncomingBlock(self: *Self, block: Block, peer: ?*net.Peer) !void {
        const result = try self.block_processor.processIncomingBlock(block, peer);
        
        // Handle post-processing actions based on result
        switch (result) {
            .accepted, .reorganized => {
                // Block was successfully processed - network coordinator will handle broadcasting
                print("✅ Block processing completed with result: {}\n", .{result});
            },
            .stored_as_orphan => {
                // Orphan handling is managed by block processor
                print("🔀 Block stored as orphan for future processing\n", .{});
            },
            .stored_as_sidechain => {
                // Side chain handling is managed by block processor
                print("📦 Block stored in side chain\n", .{});
            },
            .ignored => {
                // Already seen blocks are gracefully ignored
                print("🌊 Block already known - gracefully ignored\n", .{});
            },
            .rejected => {
                // Invalid blocks are rejected
                print("❌ Block rejected due to validation failure\n", .{});
            },
        }
    }
    
    /// Handle incoming transaction from network peer (delegates to network coordinator)
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction, peer: ?*net.Peer) !void {
        try self.network_coordinator.handleIncomingTransaction(transaction, peer);
    }
    
    /// Broadcast new block to network peers (delegates to network coordinator)
    pub fn broadcastNewBlock(self: *Self, block: Block) !void {
        try self.network_coordinator.broadcastBlock(block);
    }
    
    /// Check connected peers for new blocks (delegates to network coordinator)
    pub fn checkForNewBlocks(self: *Self) !void {
        try self.network_coordinator.checkForNewBlocks();
    }
    
    // Network operations (delegate to network coordinator)
    pub fn processDownloadedBlock(self: *Self, block: Block, expected_height: u32) !void {
        try self.network_coordinator.processDownloadedBlock(block, expected_height);
    }
    
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.network_coordinator.validateSyncBlock(block, expected_height);
    }
    
    pub fn startNetwork(self: *Self, port: u16) !void {
        try self.network_coordinator.startNetwork(port);
    }
    
    pub fn stopNetwork(self: *Self) void {
        self.network_coordinator.stopNetwork();
    }
    
    pub fn connectToPeer(self: *Self, address: []const u8) !void {
        try self.network_coordinator.connectToPeer(address);
    }
    
    pub fn shouldSync(self: *Self, peer_height: u32) !bool {
        return try self.network_coordinator.shouldSync(peer_height);
    }
    
    /// Get current sync state (delegates to network coordinator)
    pub fn getSyncState(self: *Self) @import("../sync/sync.zig").SyncState {
        return self.network_coordinator.getSyncState();
    }
    
    /// Handle chain reorganization when better chain is found (legacy compatibility)
    pub fn handleChainReorganization(self: *Self, new_block: Block, new_chain_state: types.ChainState) !void {
        const current_height = try self.blockchain.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.blockchain.fork_manager.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
            print("❌ Reorganization too deep ({} -> {}) - rejected for safety\n", .{ current_height, new_chain_state.tip_height });
            return;
        }

        const reorg_depth = if (current_height > new_chain_state.tip_height) 
            current_height - new_chain_state.tip_height 
        else 
            new_chain_state.tip_height - current_height;
            
        print("🔄 Starting reorganization: {} -> {} (depth: {})\n", .{ current_height, new_chain_state.tip_height, reorg_depth });

        // Find common ancestor and perform reorganization
        const common_ancestor_height = try self.findCommonAncestor(new_chain_state.tip_hash);
        
        if (common_ancestor_height == 0) {
            print("⚠️ Deep reorganization required - rebuilding from genesis\n", .{});
        }

        try self.blockchain.rollbackToHeight(common_ancestor_height);
        try self.blockchain.acceptBlock(new_block);
        
        // Update fork manager
        self.blockchain.fork_manager.updateChain(0, new_chain_state);

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
    }
    
    /// Find common ancestor between current chain and new chain (private helper)
    fn findCommonAncestor(self: *Self, new_tip_hash: types.BlockHash) !u32 {
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        _ = self;
        _ = new_tip_hash;
        return 0;
    }
};