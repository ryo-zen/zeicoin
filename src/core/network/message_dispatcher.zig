const std = @import("std");
const log = std.log.scoped(.message_handler);

const types = @import("../types/types.zig");
const net = @import("peer.zig");
const ZeiCoin = @import("../node.zig").ZeiCoin;

// Import modular components
const BlockProcessor = @import("processors/block_processor.zig").BlockProcessor;

const Transaction = types.Transaction;
const Block = types.Block;

pub const MessageDispatcher = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    // Modular components
    block_processor: BlockProcessor,
    
    const Self = @This();
    
    /// Initialize message dispatcher with modular components
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .block_processor = BlockProcessor.init(allocator, blockchain),
        };
    }
    
    /// Cleanup message dispatcher resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to cleanup currently
    }
    
    /// Handle incoming block from network peer (delegates to block processor)
    pub fn handleIncomingBlock(self: *Self, block: Block, peer: ?*net.Peer) !void {
        log.debug("handleIncomingBlock() ENTRY - calling block processor", .{});
        const result = try self.block_processor.processIncomingBlock(block, peer);
        log.debug("Block processor returned result: {}", .{result});
        
        // Handle post-processing actions based on result
        switch (result) {
            .accepted, .reorganized => {
                // Block was successfully processed - network coordinator will handle broadcasting
                log.info("Block processing completed with result: {}", .{result});
            },
            .stored_as_orphan => {
                // Orphan handling is managed by block processor
                log.info("Block stored as orphan for future processing", .{});
            },
            .stored_as_sidechain => {
                // Side chain handling is managed by block processor
                log.info("Block stored in side chain", .{});
            },
            .ignored => {
                // Already seen blocks are gracefully ignored
                log.debug("Block already known - gracefully ignored", .{});
            },
            .rejected => {
                // Invalid blocks are rejected
                log.warn("Block rejected due to validation failure", .{});
            },
        }
    }
    
    /// Handle incoming transaction from network peer (delegates to blockchain)
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction, peer: ?*net.Peer) !void {
        // Log peer info if available
        if (peer) |p| {
            log.info("Transaction received from peer {}", .{p.id});
        } else {
            log.info("Transaction received from network peer", .{});
        }
        
        // Forward to blockchain's transaction handler
        try self.blockchain.handleIncomingTransaction(transaction);
        log.info("Transaction processed successfully", .{});
    }
    
    /// Handle request for block hash at specific height
    pub fn handleGetBlockHash(self: *Self, height: u32) !?types.Hash {
        // Query blockchain for block at height
        const chain = &self.blockchain.chain_query;

        // Check if we have the block at this height
        const chain_height = chain.getHeight() catch |err| {
            log.warn("Error getting chain height: {}", .{err});
            return null;
        };

        if (height > chain_height) {
            // We don't have this block yet
            return null;
        }

        // Get the block at this height and return its hash
        var block = chain.getBlock(height) catch |err| {
            log.warn("Error getting block at height {}: {}", .{ height, err });
            return null;
        };
        defer block.deinit(self.allocator);

        return block.hash();
    }

    /// Handle request for cumulative chain work for a range of blocks
    pub fn handleGetChainWork(self: *Self, start_height: u32, end_height: u32) !types.ChainWork {
        log.debug("📤 [CHAIN WORK] Request for work from height {} to {}", .{ start_height, end_height });

        // Validate request
        if (start_height > end_height) {
            log.warn("❌ [CHAIN WORK] Invalid request: start > end", .{});
            return error.InvalidRequest;
        }

        const chain = &self.blockchain.chain_query;
        const chain_height = try chain.getHeight();

        if (end_height > chain_height) {
            log.warn("❌ [CHAIN WORK] Request exceeds chain height: {} > {}", .{ end_height, chain_height });
            return error.HeightTooHigh;
        }

        // Calculate cumulative work for the range
        var total_work: types.ChainWork = 0;
        var height = start_height;

        while (height <= end_height) : (height += 1) {
            var block = try chain.getBlock(height);
            defer block.deinit(self.allocator);
            const block_work = block.header.getWork();
            total_work += block_work;
        }

        log.debug("✅ [CHAIN WORK] Calculated work: {} for range {}-{}", .{ total_work, start_height, end_height });
        return total_work;
    }
    
    /// Broadcast new block to network peers (delegates to blockchain's network coordinator)
    pub fn broadcastNewBlock(self: *Self, block: Block) !void {
        // print("🔧 [BROADCAST] Attempting to broadcast block...\n", .{});
        // print("🔧 [BROADCAST] Network coordinator ptr: {*}\n", .{&self.blockchain.network_coordinator});
        if (self.blockchain.network_coordinator.getNetworkManager()) |network| {
            // print("📡 Broadcasting new block to {} peers\n", .{network.peer_manager.getConnectedCount()});
            try network.broadcastBlock(block);
        } else {
            // print("⚠️  No network manager - block not broadcasted\n", .{});
        }
    }
    
    /// Check connected peers for new blocks (delegates to blockchain)
    pub fn checkForNewBlocks(self: *Self) !void {
        // This functionality should be handled by the blockchain's sync system
        _ = self;
    }
    
    // Network operations (delegate to network coordinator)
    pub fn processDownloadedBlock(self: *Self, block: Block, expected_height: u32) !void {
        // During sync, validation is already done by sync manager
        // Use dedicated sync path that bypasses block processor entirely
        try self.blockchain.addSyncBlockToChain(block, expected_height);
    }
    
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.blockchain.validateSyncBlock(block, expected_height);
    }
    
    pub fn startNetwork(self: *Self, port: u16) !void {
        try self.blockchain.network_coordinator.startNetwork(port);
    }
    
    pub fn stopNetwork(self: *Self) void {
        self.blockchain.network_coordinator.stopNetwork();
    }
    
    pub fn connectToPeer(self: *Self, address: []const u8) !void {
        try self.blockchain.network_coordinator.connectToPeer(address);
    }
    
    pub fn shouldSync(self: *Self, peer_height: u32) !bool {
        const our_height = try self.blockchain.getHeight();
        return peer_height > our_height;
    }
    
    /// Get current sync state (delegates to blockchain sync manager)
    pub fn getSyncState(self: *Self) @import("../sync/sync.zig").SyncState {
        if (self.blockchain.sync_manager) |sync_manager| {
            return sync_manager.getSyncState();
        }
        return .synced;
    }
    
    /// Handle chain reorganization when better chain is found (legacy compatibility)
    pub fn handleChainReorganization(self: *Self, new_block: Block, new_chain_state: types.ChainState) !void {
        const current_height = try self.blockchain.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.blockchain.fork_manager.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
            log.err("Reorganization too deep ({} -> {}) - rejected for safety", .{ current_height, new_chain_state.tip_height });
            return;
        }

        const reorg_depth = if (current_height > new_chain_state.tip_height) 
            current_height - new_chain_state.tip_height 
        else 
            new_chain_state.tip_height - current_height;
            
        log.info("Starting reorganization: {} -> {} (depth: {})", .{ current_height, new_chain_state.tip_height, reorg_depth });

        // Find common ancestor and perform reorganization
        const common_ancestor_height = try self.findCommonAncestor(new_chain_state.tip_hash);
        
        if (common_ancestor_height == 0) {
            log.warn("Deep reorganization required - rebuilding from genesis", .{});
        }

        try self.blockchain.rollbackToHeight(common_ancestor_height);
        try self.blockchain.acceptBlock(new_block);
        
        // Update fork manager
        self.blockchain.fork_manager.updateChain(0, new_chain_state);

        log.info("Reorganization complete! New chain tip: {s}", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
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