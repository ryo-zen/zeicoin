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

        // Save state snapshot before making changes
        try state_root.saveStateSnapshot(self.allocator, self.db, fork_height);

        // Phase 1: Revert STATE only (not blocks yet - safer to keep blocks until we verify new chain)
        if (blocks_to_revert > 0) {
            std.log.warn("⏪ [REORG] Reverting state (accounts) from height {} to {}", .{old_tip_height, fork_height});
            self.revertStateToHeight(fork_height) catch |err| {
                std.log.err("❌ [REORG] Failed to revert state: {}", .{err});

                // Attempt rollback
                state_root.loadStateSnapshot(self.allocator, self.db, fork_height) catch |rollback_err| {
                    std.log.err("💥 [REORG] CRITICAL: Rollback failed: {}", .{rollback_err});
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

            // Apply the block first - this executes all transactions and updates account states
            self.applyBlock(&new_block, expected_height) catch |err| {
                std.log.err("❌ [REORG] Failed to apply block at height {}: {}", .{expected_height, err});

                // Rollback to fork point - state will be restored, old blocks still exist
                state_root.loadStateSnapshot(self.allocator, self.db, fork_height) catch |rollback_err| {
                    std.log.err("💥 [REORG] CRITICAL: Rollback failed: {}", .{rollback_err});
                };

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = blocks_to_revert,
                    .blocks_applied = applied,
                    .fork_height = fork_height,
                    .error_message = "Failed to apply new blocks",
                };
            };

            // CRITICAL FIX: Verify state root AFTER applying block transactions
            // The block's state root represents the state AFTER executing its transactions
            // So we must apply the block first, then verify the resulting state matches
            if (!std.mem.eql(u8, &new_block.header.state_root, &[_]u8{0} ** 32)) {
                const actual_state_root = try state_root.calculateStateRoot(self.allocator, self.db);
                if (!std.mem.eql(u8, &new_block.header.state_root, &actual_state_root)) {
                    std.log.err("❌ [REORG] State root mismatch at height {}", .{expected_height});
                    std.log.err("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&new_block.header.state_root)});
                    std.log.err("   Actual:   {s}", .{std.fmt.fmtSliceHexLower(&actual_state_root)});

                    // Rollback to fork point - state will be restored, old blocks still exist
                    try state_root.loadStateSnapshot(self.allocator, self.db, fork_height);

                    return ReorgResult{
                        .success = false,
                        .blocks_reverted = blocks_to_revert,
                        .blocks_applied = applied + 1, // We did apply this block before detecting mismatch
                        .fork_height = fork_height,
                        .error_message = "State root verification failed after applying block",
                    };
                }
            }

            applied += 1;
        }

        // Phase 3: SUCCESS - Now it's safe to delete old blocks that were replaced
        if (blocks_to_revert > 0) {
            std.log.warn("🗑️  [REORG] Deleting {} replaced blocks from height {} to {}", .{blocks_to_revert, fork_height + 1, old_tip_height});
            try self.db.deleteBlocksFromHeight(fork_height + 1, old_tip_height);
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
    fn revertStateToHeight(self: *Self, target_height: u32) !void {
        const current_height = try self.chain_state.getHeight();

        // Use ChainState's rollback functionality but WITHOUT deleting blocks
        try self.chain_state.rollbackStateWithoutDeletingBlocks(target_height, current_height);

        std.log.debug("⏪ Reverted state from height {} to {}", .{current_height, target_height});
    }

    /// Apply a single block to the chain
    fn applyBlock(self: *Self, block: *const Block, height: u32) !void {
        // Process all transactions in the block using ChainState
        // Force processing = true because we might be reapplying blocks that exist in DB
        try self.chain_state.processBlockTransactions(block.transactions, height, true);

        // Save block to database
        try self.db.saveBlock(height, block.*);

        // Update block index
        try self.chain_state.indexBlock(height, block.header.hash());

        std.log.debug("⏩ Applied block at height {}", .{height});
    }
};
