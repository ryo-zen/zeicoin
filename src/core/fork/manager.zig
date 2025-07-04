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
        const decision = self.decision_engine.evaluateBlock(
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
};