// manager.zig - Fork Manager Coordinator
// Main coordinator for all fork management components

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const fork_types = @import("types.zig");
const chains = @import("chains.zig");
const orphans = @import("orphans.zig");
const decisions = @import("decisions.zig");

const Block = types.Block;
const BlockHash = types.BlockHash;
const ChainWork = types.ChainWork;
const ForkDecision = fork_types.ForkDecision;
const ForkStats = fork_types.ForkStats;

/// Main Fork Manager - coordinates all fork management operations
pub const ForkManager = struct {
    allocator: std.mem.Allocator,
    
    // Specialized components
    chain_tracker: chains.ChainTracker,
    orphan_manager: orphans.OrphanManager,
    decision_engine: decisions.DecisionEngine,
    
    pub fn init(allocator: std.mem.Allocator) ForkManager {
        return ForkManager{
            .allocator = allocator,
            .chain_tracker = chains.ChainTracker.init(),
            .orphan_manager = orphans.OrphanManager.init(allocator),
            .decision_engine = decisions.DecisionEngine{},
        };
    }
    
    pub fn deinit(self: *ForkManager) void {
        self.orphan_manager.deinit();
    }
    
    /// Initialize with genesis chain
    pub fn initWithGenesis(self: *ForkManager, genesis_hash: BlockHash, genesis_work: ChainWork) void {
        self.chain_tracker.initWithGenesis(genesis_hash, genesis_work);
    }
    
    /// Get the currently active chain
    pub fn getActiveChain(self: *const ForkManager) ?types.ChainState {
        return self.chain_tracker.getActiveChain();
    }
    
    /// Check if a block hash was recently seen
    pub fn wasRecentlySeen(self: *ForkManager, block_hash: BlockHash) bool {
        return self.orphan_manager.wasRecentlySeen(block_hash);
    }
    
    /// Mark a block as recently seen
    pub fn markAsSeen(self: *ForkManager, block_hash: BlockHash) !void {
        try self.orphan_manager.markAsSeen(block_hash);
    }
    
    /// Evaluate a new block and decide how to handle it
    pub fn evaluateBlock(self: *ForkManager, block: Block, block_height: u32, cumulative_work: ChainWork) !ForkDecision {
        const decision = decisions.DecisionEngine.evaluateBlock(
            &self.chain_tracker,
            &self.orphan_manager,
            block,
            block_height,
            cumulative_work,
        );
        
        // Handle the decision
        switch (decision) {
            .ignore => {
                // Already processed, mark as seen
                try self.markAsSeen(block.hash());
            },
            .store_orphan => {
                // Store as orphan block
                const received_time = util.getTime();
                try self.orphan_manager.storeOrphan(block, received_time);
                try self.markAsSeen(block.hash());
            },
            .extends_chain => |chain_info| {
                // Block extends a known chain
                try self.markAsSeen(block.hash());
                print("🔗 Block extends chain {} (reorg: {})\n", .{ chain_info.chain_index, chain_info.requires_reorg });
            },
            .new_best_chain => |chain_index| {
                // New best chain detected
                try self.markAsSeen(block.hash());
                print("🏆 New best chain detected: chain {}\n", .{chain_index});
            },
        }
        
        return decision;
    }
    
    /// Update a specific chain's state
    pub fn updateChain(self: *ForkManager, chain_index: u8, new_chain_state: types.ChainState) void {
        self.chain_tracker.updateChain(chain_index, new_chain_state);
    }
    
    /// Update the best chain with a new block
    pub fn updateBestChain(self: *ForkManager, new_block: *const Block, new_height: u32, new_cumulative_work: ChainWork) void {
        const new_block_hash = new_block.hash();
        self.chain_tracker.updateBestChain(new_block_hash, new_height, new_cumulative_work);
    }
    
    /// Check if a reorganization depth exceeds safety limits
    pub fn isReorgTooDeep(self: *const ForkManager, from_height: u32, to_height: u32) bool {
        _ = self; // unused parameter
        const reorg_depth = if (to_height > from_height) 
            to_height - from_height 
        else 
            from_height - to_height;
        return decisions.DecisionEngine.isReorgTooDeep(reorg_depth);
    }
    
    /// Get fork management statistics
    pub fn getStats(self: *const ForkManager) ForkStats {
        return ForkStats{
            .active_chain_index = self.chain_tracker.active_chain_index,
            .total_chains = self.chain_tracker.getActiveChainCount(),
            .orphan_count = self.orphan_manager.getOrphanCount(),
            .recent_blocks_count = self.orphan_manager.getRecentBlocksCount(),
        };
    }
    
    /// Perform maintenance (cleanup old orphans and recent blocks)
    pub fn performMaintenance(self: *ForkManager) void {
        self.orphan_manager.cleanupOrphanBlocks();
        self.orphan_manager.cleanupRecentBlocks();
    }

    /// Handle chain reorganization when a better chain is found
    pub fn handleChainReorganization(self: *ForkManager, blockchain: anytype, new_block: types.Block, new_chain_state: types.ChainState) !void {
        const current_height = try blockchain.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
            print("❌ Reorganization too deep ({} -> {}) - rejected for safety\n", .{ current_height, new_chain_state.tip_height });
            return;
        }

        print("🔄 Starting reorganization: {} -> {} (depth: {})\n", .{ current_height, new_chain_state.tip_height, if (current_height > new_chain_state.tip_height) current_height - new_chain_state.tip_height else new_chain_state.tip_height - current_height });

        // Find common ancestor (simplified - assume we need to rebuild from genesis for now)
        const common_ancestor_height = try self.findCommonAncestor(blockchain, new_chain_state.tip_hash);

        if (common_ancestor_height == 0) {
            print("⚠️ Deep reorganization required - rebuilding from genesis\n", .{});
        }

        // Rollback to common ancestor
        try self.rollbackToHeight(blockchain, common_ancestor_height);

        // Accept the new block (this will become the new tip)
        try self.acceptBlock(blockchain, new_block);

        // Update fork manager
        self.updateChain(0, new_chain_state); // Update main chain

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
    }

    /// Find common ancestor between current chain and new chain
    fn findCommonAncestor(self: *ForkManager, blockchain: anytype, new_tip_hash: types.BlockHash) !u32 {
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        _ = self;
        _ = blockchain;
        _ = new_tip_hash;
        return 0;
    }

    /// Rollback blockchain to a specific height
    fn rollbackToHeight(self: *ForkManager, blockchain: anytype, target_height: u32) !void {
        const current_height = try blockchain.getHeight();
        
        if (target_height >= current_height) {
            return; // Nothing to rollback
        }

        // Backup transactions from orphaned blocks
        try self.backupOrphanedTransactions(blockchain, target_height + 1, current_height);

        // TODO: Implement actual rollback logic
        // This would involve:
        // 1. Reversing transactions from orphaned blocks
        // 2. Updating chain state
        // 3. Removing orphaned blocks from database
        print("🔄 Rollback to height {} not yet fully implemented\n", .{target_height});
    }

    /// Backup transactions from orphaned blocks
    fn backupOrphanedTransactions(self: *ForkManager, blockchain: anytype, from_height: u32, to_height: u32) !void {
        print("💾 Backing up transactions from orphaned blocks ({} to {})\n", .{ from_height, to_height });

        var transactions = std.ArrayList(types.Transaction).init(self.allocator);
        defer transactions.deinit();

        // Collect all transactions from orphaned blocks
        for (from_height..to_height) |height| {
            const block = blockchain.database.getBlock(@intCast(height)) catch continue;
            defer block.deinit(self.allocator);

            // Add non-coinbase transactions to backup list
            for (block.transactions) |tx| {
                if (!tx.isCoinbase()) {
                    try transactions.append(tx);
                }
            }
        }

        // Restore transactions to mempool
        if (transactions.items.len > 0) {
            blockchain.mempool_manager.restoreOrphanedTransactions(transactions.items);
        }
    }

    /// Accept a block after validation (used in reorganization)
    fn acceptBlock(self: *ForkManager, blockchain: anytype, block: types.Block) !void {
        _ = self;
        return try blockchain.chain_processor.acceptBlock(block);
    }

    /// Check if a block is a valid fork block
    pub fn isValidForkBlock(self: *ForkManager, block: types.Block, blockchain: anytype) !bool {
        _ = self;
        const current_height = try blockchain.getHeight();
        for (0..current_height) |height| {
            var existing_block = blockchain.database.getBlock(@intCast(height)) catch continue;
            defer existing_block.deinit(blockchain.allocator);
            const existing_hash = existing_block.hash();
            if (std.mem.eql(u8, &block.header.previous_hash, &existing_hash)) {
                print("🔗 Fork block builds on height {} (current tip: {})\n", .{ height, current_height - 1 });
                return true;
            }
        }
        return false;
    }

    /// Store a fork block for potential chain reorganization
    pub fn storeForkBlock(self: *ForkManager, block: types.Block, fork_height: u32) !void {
        _ = self;
        _ = block;
        _ = fork_height;
        print("⚠️ Fork storage not yet implemented - longest chain rule needed\n", .{});
    }
};