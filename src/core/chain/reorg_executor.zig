const std = @import("std");
const types = @import("../types/types.zig");
const ChainState = @import("./state.zig").ChainState;
const Database = @import("../storage/db.zig").Database;
const state_root = @import("./state_root.zig");

const Block = types.Block;
const Hash = types.Hash;

/// Result of a reorganization operation
pub const ReorgResult = struct {
    success: bool,
    blocks_reverted: u32,
    blocks_applied: u32,
    fork_height: u32,
    error_message: ?[]const u8 = null,
};

/// Simple State-Based Reorganization Executor
/// Uses state roots for verification (Ethereum-style) with Bitcoin's simplicity
pub const ReorgExecutor = struct {
    allocator: std.mem.Allocator,
    chain_state: *ChainState,
    db: *Database,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState, db: *Database) Self {
        return .{
            .allocator = allocator,
            .chain_state = chain_state,
            .db = db,
        };
    }

    /// Execute a reorganization from old_tip to new_tip
    /// This is the main entry point for reorganization
    ///
    /// NOTE: Orphaned transactions are handled by MempoolManager:
    /// - Before calling this, call mempool.handleReorganization(orphaned_blocks)
    /// - This backs up transactions from reverted blocks
    /// - After reorg succeeds, transactions are restored to mempool
    /// - Invalid transactions are automatically discarded
    pub fn executeReorg(
        self: *Self,
        io: std.Io,
        old_tip_height: u32,
        new_tip_height: u32,
        new_blocks: []const Block,
    ) !ReorgResult {
        std.log.warn("🔄 [REORG] Starting reorganization: old height {} → new height {}", .{old_tip_height, new_tip_height});

        // Validation: new chain must be longer or equal (with higher hash)
        if (new_tip_height < old_tip_height) {
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .fork_height = 0,
                .error_message = "New chain is shorter than current chain",
            };
        }

        // Find the fork point (common ancestor)
        const fork_height = try self.findForkPoint(old_tip_height, new_blocks);
        std.log.info("🔍 [REORG] Fork point found at height {}", .{fork_height});

        const blocks_to_revert = old_tip_height - fork_height;
        const blocks_to_apply = new_tip_height - fork_height;
        var original_blocks = try self.backupExistingChainSegment(io, fork_height + 1, old_tip_height);
        defer {
            for (original_blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            original_blocks.deinit();
        }

        // Save state snapshot before making changes
        try state_root.saveStateSnapshot(self.allocator, self.db, fork_height);

        // Phase 1: Revert STATE only (not blocks yet - safer to keep blocks until we verify new chain)
        if (blocks_to_revert > 0) {
            std.log.warn("⏪ [REORG] Reverting state (accounts) from height {} to {}", .{old_tip_height, fork_height});
            self.revertStateToHeight(io, fork_height) catch |err| {
                std.log.err("❌ [REORG] Failed to revert state: {}", .{err});

                self.restoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height) catch |restore_err| {
                    std.log.err("💥 [REORG] CRITICAL: Failed to restore original chain after revert failure: {}", .{restore_err});
                };

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = 0,
                    .blocks_applied = 0,
                    .fork_height = fork_height,
                    .error_message = "Failed to revert state",
                };
            };
        }

        // Phase 2: Apply new blocks from fork point forward
        std.log.warn("⏩ [REORG] Applying {} new blocks from height {} to {}", .{blocks_to_apply, fork_height + 1, new_tip_height});

        var applied: u32 = 0;
        for (new_blocks) |new_block| {
            const expected_height = fork_height + 1 + applied;

            // State roots commit to the account state before this block executes.
            if (!std.mem.eql(u8, &new_block.header.state_root, &[_]u8{0} ** 32)) {
                const current_state_root = try self.chain_state.calculateStateRoot();
                if (!std.mem.eql(u8, &new_block.header.state_root, &current_state_root)) {
                    std.log.err("❌ [REORG] Pre-state root mismatch at height {}", .{expected_height});
                    std.log.err("   Expected: {x}", .{&new_block.header.state_root});
                    std.log.err("   Actual:   {x}", .{&current_state_root});

                    try self.restoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height);

                    return ReorgResult{
                        .success = false,
                        .blocks_reverted = blocks_to_revert,
                        .blocks_applied = applied,
                        .fork_height = fork_height,
                        .error_message = "State root verification failed before applying block",
                    };
                }
            }

            // Apply the block after verifying its parent state commitment.
            self.applyBlock(io, &new_block, expected_height) catch |err| {
                std.log.err("❌ [REORG] Failed to apply block at height {}: {}", .{expected_height, err});

                self.restoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height) catch |restore_err| {
                    std.log.err("💥 [REORG] CRITICAL: Failed to restore original chain after apply failure: {}", .{restore_err});
                };

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = blocks_to_revert,
                    .blocks_applied = applied,
                    .fork_height = fork_height,
                    .error_message = "Failed to apply new blocks",
                };
            };

            applied += 1;
        }

        // Phase 3: SUCCESS - Now it's safe to delete old blocks that were replaced
        if (blocks_to_revert > 0) {
            // Replacement blocks were already written in-place at their target heights.
            // Deleting the old height range here would remove the newly applied chain.
            try self.db.saveHeight(new_tip_height);
            std.log.warn("📊 [REORG] Database height updated from {} to {}", .{old_tip_height, new_tip_height});
        }

        // Clean up old snapshot
        try state_root.deleteStateSnapshot(self.allocator, self.db, fork_height);

        std.log.warn("✅ [REORG] Reorganization complete: reverted {}, applied {}", .{blocks_to_revert, blocks_to_apply});

        return ReorgResult{
            .success = true,
            .blocks_reverted = blocks_to_revert,
            .blocks_applied = blocks_to_apply,
            .fork_height = fork_height,
        };
    }

    /// Find the fork point (common ancestor) between current chain and new chain
    fn findForkPoint(self: *Self, current_height: u32, new_blocks: []const Block) !u32 {
        // Start from the beginning of the new chain
        // Find where our chain and their chain first match

        if (new_blocks.len == 0) return current_height;

        // Get the first block's previous hash
        const first_new_block = new_blocks[0];

        // Find where this previous hash exists in our chain
        var check_height: u32 = 0;
        while (check_height <= current_height) : (check_height += 1) {
            if (self.chain_state.getBlockHash(check_height)) |our_hash| {
                if (std.mem.eql(u8, &our_hash, &first_new_block.header.previous_hash)) {
                    return check_height;
                }
            }
        }

        // If not found, fork is at genesis
        return 0;
    }

    /// Revert state (accounts) back to a specific height WITHOUT deleting blocks
    /// This is safer because if the reorg fails, the old blocks are still available
    fn revertStateToHeight(self: *Self, io: std.Io, target_height: u32) !void {
        const current_height = try self.chain_state.getHeight();

        // Use ChainState's rollback functionality but WITHOUT deleting blocks
        try self.chain_state.rollbackStateWithoutDeletingBlocks(io, target_height, current_height);

        std.log.debug("⏪ Reverted state from height {} to {}", .{current_height, target_height});
    }

    /// Apply a single block to the chain
    fn applyBlock(self: *Self, io: std.Io, block: *const Block, height: u32) !void {
        // Process all transactions in the block using ChainState
        // Force processing = true because we might be reapplying blocks that exist in DB
        try self.chain_state.processBlockTransactions(io, block.transactions, height, true);

        // Save block to database
        try self.db.saveBlock(io, height, block.*);

        // Update block index
        try self.chain_state.indexBlock(height, block.header.hash());

        // Mirror normal block application so post-block state matches the block's state root.
        const coinbase_maturity = types.getCoinbaseMaturity();
        if (height >= coinbase_maturity) {
            try self.chain_state.matureCoinbaseRewards(io, height - coinbase_maturity);
        }

        std.log.debug("⏩ Applied block at height {}", .{height});
    }

    fn backupExistingChainSegment(self: *Self, io: std.Io, start_height: u32, end_height: u32) !std.array_list.Managed(Block) {
        var blocks = std.array_list.Managed(Block).init(self.allocator);
        errdefer {
            for (blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            blocks.deinit();
        }

        if (start_height > end_height) return blocks;

        var height = start_height;
        while (height <= end_height) : (height += 1) {
            const block = try self.db.getBlock(io, height);
            try blocks.append(block);
        }

        return blocks;
    }

    fn restoreOriginalChain(self: *Self, io: std.Io, old_tip_height: u32, original_blocks: []const Block, fork_height: u32) !void {
        std.log.warn("⏪ [REORG] Restoring original canonical chain to height {}", .{old_tip_height});

        for (original_blocks, 0..) |block, i| {
            const height = fork_height + 1 + @as(u32, @intCast(i));
            try self.db.saveBlock(io, height, block);
        }

        const current_db_height = try self.db.getHeight();
        if (current_db_height > old_tip_height) {
            try self.db.deleteBlocksFromHeight(old_tip_height + 1, current_db_height);
        }
        try self.db.saveHeight(old_tip_height);

        try self.chain_state.rebuildStateToHeight(io, old_tip_height);
        std.log.warn("✅ [REORG] Original chain restored after failed reorganization", .{});
    }
};
