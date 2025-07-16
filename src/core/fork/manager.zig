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
const sidechains = @import("sidechains.zig");

const Block = types.Block;
const BlockHash = types.BlockHash;
const ChainWork = types.ChainWork;
const ForkDecision = fork_types.ForkDecision;
const ForkStats = fork_types.ForkStats;

/// Account snapshot for rollback operations
pub const AccountSnapshot = struct {
    address: types.Address,
    balance: u64,
    nonce: u64,
    immature_balance: u64,
};

/// Block effect tracking for rollback
pub const BlockEffect = struct {
    block_height: u32,
    block_hash: BlockHash,
    account_changes: std.ArrayList(AccountSnapshot),
    transactions: std.ArrayList(types.Transaction),
    
    pub fn init(allocator: std.mem.Allocator, height: u32, hash: BlockHash) BlockEffect {
        return .{
            .block_height = height,
            .block_hash = hash,
            .account_changes = std.ArrayList(AccountSnapshot).init(allocator),
            .transactions = std.ArrayList(types.Transaction).init(allocator),
        };
    }
    
    pub fn deinit(self: *BlockEffect) void {
        self.account_changes.deinit();
        self.transactions.deinit();
    }
};

/// Main Fork Manager - coordinates all fork management operations
pub const ForkManager = struct {
    allocator: std.mem.Allocator,
    
    // Specialized components
    chain_tracker: chains.ChainTracker,
    orphan_manager: orphans.OrphanManager,
    decision_engine: decisions.DecisionEngine,
    side_chain_manager: sidechains.SideChainManager,
    
    // Rollback state tracking
    block_effects: std.ArrayList(BlockEffect),
    
    pub fn init(allocator: std.mem.Allocator) ForkManager {
        return ForkManager{
            .allocator = allocator,
            .chain_tracker = chains.ChainTracker.init(),
            .orphan_manager = orphans.OrphanManager.init(allocator),
            .decision_engine = decisions.DecisionEngine{},
            .side_chain_manager = sidechains.SideChainManager.init(allocator),
            .block_effects = std.ArrayList(BlockEffect).init(allocator),
        };
    }
    
    pub fn deinit(self: *ForkManager) void {
        self.orphan_manager.deinit();
        self.side_chain_manager.deinit();
        // Clean up block effects
        for (self.block_effects.items) |*effect| {
            effect.deinit();
        }
        self.block_effects.deinit();
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
        
        // Clear block effects after successful reorganization
        self.clearBlockEffects();

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

        print("🔄 Starting rollback from height {} to {}\n", .{ current_height, target_height });

        // Collect orphaned transactions for potential replay
        var orphaned_transactions = std.ArrayList(types.Transaction).init(self.allocator);
        defer orphaned_transactions.deinit();

        // Process blocks in reverse order (newest to oldest)
        var height = current_height;
        while (height > target_height) : (height -= 1) {
            print("⏪ Rolling back block at height {}\n", .{height});
            
            // Get the block to rollback
            var block = try blockchain.database.getBlock(height);
            defer block.deinit(self.allocator);
            
            // Create block effect to track changes
            var effect = BlockEffect.init(self.allocator, height, block.hash());
            errdefer effect.deinit();
            
            // Reverse all transactions in the block (process in reverse order)
            var i = block.transactions.len;
            while (i > 0) {
                i -= 1;
                const tx = block.transactions[i];
                
                if (blockchain.chain_state.isCoinbaseTransaction(tx)) {
                    // Reverse coinbase transaction
                    try self.reverseCoinbaseTransaction(blockchain, tx, &effect);
                } else {
                    // Reverse regular transaction
                    try self.reverseRegularTransaction(blockchain, tx, &effect);
                    // Save for potential replay
                    try orphaned_transactions.append(tx);
                }
            }
            
            // Store the effect for potential redo
            try self.block_effects.append(effect);
            
            // Remove the block from database
            try blockchain.database.removeBlock(height);
        }
        
        // Update chain height
        try blockchain.database.saveHeight(target_height);
        
        // Restore valid orphaned transactions to mempool
        print("💾 Restoring {} orphaned transactions to mempool\n", .{orphaned_transactions.items.len});
        for (orphaned_transactions.items) |tx| {
            // Validate transaction against new state
            if (blockchain.chain_validator.validateTransaction(tx) catch false) {
                blockchain.mempool_manager.addTransaction(tx) catch {
                    print("⚠️ Failed to restore transaction to mempool\n", .{});
                };
            }
        }
        
        print("✅ Rollback complete! New height: {}\n", .{target_height});
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

    /// Reverse a coinbase transaction
    fn reverseCoinbaseTransaction(self: *ForkManager, blockchain: anytype, tx: types.Transaction, effect: *BlockEffect) !void {
        _ = self; // We use blockchain directly
        
        // Snapshot current miner account state
        var miner_account = try blockchain.database.getAccount(tx.recipient);
        try effect.account_changes.append(AccountSnapshot{
            .address = tx.recipient,
            .balance = miner_account.balance,
            .nonce = miner_account.nonce,
            .immature_balance = miner_account.immature_balance,
        });
        
        // Remove the coinbase reward from immature balance
        if (miner_account.immature_balance >= tx.amount) {
            miner_account.immature_balance -= tx.amount;
        } else {
            // This shouldn't happen, but handle gracefully
            print("⚠️ Warning: Immature balance mismatch during rollback\n", .{});
            miner_account.immature_balance = 0;
        }
        
        // Save updated account
        try blockchain.database.saveAccount(tx.recipient, miner_account);
        
        print("⏪ Reversed coinbase: {} ZEI from miner\n", .{tx.amount});
    }

    /// Reverse a regular transaction
    fn reverseRegularTransaction(self: *ForkManager, blockchain: anytype, tx: types.Transaction, effect: *BlockEffect) !void {
        _ = self; // We use blockchain directly
        
        // Get current account states
        var sender_account = try blockchain.database.getAccount(tx.sender);
        var recipient_account = try blockchain.database.getAccount(tx.recipient);
        
        // Snapshot both accounts before reversal
        try effect.account_changes.append(AccountSnapshot{
            .address = tx.sender,
            .balance = sender_account.balance,
            .nonce = sender_account.nonce,
            .immature_balance = sender_account.immature_balance,
        });
        try effect.account_changes.append(AccountSnapshot{
            .address = tx.recipient,
            .balance = recipient_account.balance,
            .nonce = recipient_account.nonce,
            .immature_balance = recipient_account.immature_balance,
        });
        
        // Reverse the transaction
        // Return funds to sender (amount + fee)
        sender_account.balance += tx.amount + tx.fee;
        // Decrement sender nonce
        if (sender_account.nonce > 0) {
            sender_account.nonce -= 1;
        }
        
        // Remove funds from recipient
        if (recipient_account.balance >= tx.amount) {
            recipient_account.balance -= tx.amount;
        } else {
            // This shouldn't happen in a valid blockchain
            print("⚠️ Warning: Insufficient recipient balance during rollback\n", .{});
            recipient_account.balance = 0;
        }
        
        // Save updated accounts
        try blockchain.database.saveAccount(tx.sender, sender_account);
        try blockchain.database.saveAccount(tx.recipient, recipient_account);
        
        // Store transaction for potential replay
        try effect.transactions.append(tx);
        
        print("⏪ Reversed transaction: {} ZEI from {} to {}\n", .{
            tx.amount,
            std.fmt.fmtSliceHexLower(tx.recipient.hash[0..8]),
            std.fmt.fmtSliceHexLower(tx.sender.hash[0..8]),
        });
    }

    /// Clear stored block effects (after successful reorganization)
    pub fn clearBlockEffects(self: *ForkManager) void {
        for (self.block_effects.items) |*effect| {
            effect.deinit();
        }
        self.block_effects.clearRetainingCapacity();
    }
    
    /// Handle a side chain block
    pub fn handleSideChainBlock(self: *ForkManager, block: Block, parent_hash: BlockHash, parent_height: u32, block_work: ChainWork) !sidechains.ChainAction {
        // Add to side chain manager
        const action = try self.side_chain_manager.addSideChainBlock(block, parent_hash, parent_height, block_work);
        
        // Perform maintenance periodically
        if (self.side_chain_manager.total_blocks_stored % 10 == 0) {
            self.side_chain_manager.pruneOldChains();
        }
        
        return action;
    }
    
    /// Check if any side chain should trigger reorganization
    pub fn evaluateSideChains(self: *ForkManager, main_chain_work: ChainWork) ?*sidechains.SideChainInfo {
        return self.side_chain_manager.evaluateSideChains(main_chain_work);
    }
    
    /// Get side chain blocks for reorganization
    pub fn getSideChainBlocks(self: *ForkManager, chain_tip: BlockHash) !std.ArrayList(Block) {
        return try self.side_chain_manager.extractChainBlocks(chain_tip);
    }
    
    /// Get side chain statistics
    pub fn getSideChainStats(self: *const ForkManager) struct {
        chain_count: usize,
        total_blocks: usize,
        memory_usage: usize,
        total_stored: u64,
        total_chains: u64,
        total_reorgs: u64,
    } {
        return self.side_chain_manager.getStats();
    }
};

// Tests
test "AccountSnapshot creation" {
    const test_addr = std.mem.zeroes(types.Address);
    const snapshot = AccountSnapshot{
        .address = test_addr,
        .balance = 1000,
        .nonce = 5,
        .immature_balance = 500,
    };
    
    try std.testing.expectEqual(@as(u64, 1000), snapshot.balance);
    try std.testing.expectEqual(@as(u64, 5), snapshot.nonce);
    try std.testing.expectEqual(@as(u64, 500), snapshot.immature_balance);
}

test "BlockEffect init and deinit" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_hash = std.mem.zeroes(BlockHash);
    var effect = BlockEffect.init(allocator, 100, test_hash);
    defer effect.deinit();
    
    try std.testing.expectEqual(@as(u32, 100), effect.block_height);
    try std.testing.expectEqual(test_hash, effect.block_hash);
    try std.testing.expectEqual(@as(usize, 0), effect.account_changes.items.len);
    try std.testing.expectEqual(@as(usize, 0), effect.transactions.items.len);
}