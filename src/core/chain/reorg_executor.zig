// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const types = @import("../types/types.zig");
const ChainState = @import("./state.zig").ChainState;
const ChainValidator = @import("./validator.zig").ChainValidator;
const Database = @import("../storage/db.zig").Database;
const MempoolManager = @import("../mempool/manager.zig").MempoolManager;
const state_root = @import("./state_root.zig");

const Block = types.Block;
const Hash = types.Hash;

pub const ReorgFailureReason = enum {
    invalid_competing_branch,
    block_validation_failed,
    revert_state_failed,
    pre_state_root_mismatch,
    apply_block_failed,

    pub fn description(self: ReorgFailureReason) []const u8 {
        return switch (self) {
            .invalid_competing_branch => "Competing branch failed local continuity/height validation",
            .block_validation_failed => "Competing block failed consensus validation (PoW, signatures, or difficulty)",
            .revert_state_failed => "Failed to revert state",
            .pre_state_root_mismatch => "State root verification failed before applying block",
            .apply_block_failed => "Failed to apply new blocks",
        };
    }
};

/// Result of a reorganization operation
pub const ReorgResult = struct {
    success: bool,
    blocks_reverted: u32,
    blocks_applied: u32,
    fork_height: u32,
    failure_reason: ?ReorgFailureReason = null,
    chain_corrupted: bool = false,
};

/// Simple State-Based Reorganization Executor
/// Uses state roots for verification (Ethereum-style) with Bitcoin's simplicity
pub const ReorgExecutor = struct {
    allocator: std.mem.Allocator,
    chain_state: *ChainState,
    validator: ?*ChainValidator,
    db: *Database,
    mempool_manager: ?*MempoolManager,
    force_restore_failure_for_testing: bool,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        chain_state: *ChainState,
        validator: ?*ChainValidator,
        db: *Database,
        mempool_manager: ?*MempoolManager,
    ) Self {
        return .{
            .allocator = allocator,
            .chain_state = chain_state,
            .validator = validator,
            .db = db,
            .mempool_manager = mempool_manager,
            .force_restore_failure_for_testing = false,
        };
    }

    pub fn setMempoolManager(self: *Self, mempool_manager: ?*MempoolManager) void {
        self.mempool_manager = mempool_manager;
    }

    pub fn forceRestoreFailureForTesting(self: *Self, enabled: bool) void {
        self.force_restore_failure_for_testing = enabled;
    }

    /// Execute a reorganization from old_tip to new_tip
    /// This is the main entry point for reorganization
    ///
    pub fn executeReorg(
        self: *Self,
        io: std.Io,
        old_tip_height: u32,
        fork_height: u32,
        new_tip_height: u32,
        new_blocks: []const Block,
    ) !ReorgResult {
        std.log.warn("🔄 [REORG] Starting reorganization: old height {} → new height {}", .{ old_tip_height, new_tip_height });

        if (fork_height > old_tip_height or fork_height > new_tip_height) {
            std.log.warn("❌ [REORG] Invalid fork height {} for old tip {} and new tip {}", .{
                fork_height,
                old_tip_height,
                new_tip_height,
            });
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .fork_height = fork_height,
                .failure_reason = .invalid_competing_branch,
            };
        }

        std.log.info("🔍 [REORG] Using known fork point at height {}", .{fork_height});

        const blocks_to_revert = old_tip_height - fork_height;
        const blocks_to_apply = new_tip_height - fork_height;

        if (!self.validateCompetingBranch(fork_height, new_tip_height, new_blocks)) {
            std.log.warn("❌ [REORG] Competing branch failed local continuity validation", .{});
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .fork_height = fork_height,
                .failure_reason = .invalid_competing_branch,
            };
        }

        self.validateCompetingBlocks(fork_height + 1, new_blocks) catch |err| {
            std.log.warn("❌ [REORG] Competing branch failed consensus validation before state mutation: {}", .{err});
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .fork_height = fork_height,
                .failure_reason = .block_validation_failed,
            };
        };

        var original_blocks = try self.backupExistingChainSegment(io, fork_height + 1, old_tip_height);
        defer {
            for (original_blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            original_blocks.deinit();
        }

        var clear_staged_orphans_on_exit = false;
        defer {
            if (clear_staged_orphans_on_exit) {
                if (self.mempool_manager) |mempool| {
                    mempool.clearStagedOrphanedTransactions();
                }
            }
        }

        if (self.mempool_manager) |mempool| {
            try mempool.stageOrphanedTransactions(original_blocks.items);
            clear_staged_orphans_on_exit = true;
        }

        // Save the exact canonical tip before mutating state so failure recovery can
        // restore the original chain directly instead of reconstructing it indirectly.
        try self.chain_state.saveExactStateSnapshotAtHeight(io, old_tip_height);

        // Phase 1: Revert STATE only (not blocks yet - safer to keep blocks until we verify new chain)
        if (blocks_to_revert > 0) {
            std.log.warn("⏪ [REORG] Reverting state (accounts) from height {} to {}", .{ old_tip_height, fork_height });
            self.revertStateToHeight(io, fork_height) catch |err| {
                std.log.err("❌ [REORG] Failed to revert state: {}", .{err});
                const restored = self.attemptRestoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height, "revert failure");

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = 0,
                    .blocks_applied = 0,
                    .fork_height = fork_height,
                    .failure_reason = .revert_state_failed,
                    .chain_corrupted = !restored,
                };
            };
        }

        // Persist the exact ancestor state after rollback so recovery can restore it
        // without replaying from genesis if applying the replacement branch fails.
        try self.chain_state.saveExactStateSnapshotAtHeight(io, fork_height);

        // Phase 2: Apply new blocks from fork point forward
        std.log.warn("⏩ [REORG] Applying {} new blocks from height {} to {}", .{ blocks_to_apply, fork_height + 1, new_tip_height });

        var applied: u32 = 0;
        for (new_blocks) |new_block| {
            const expected_height = fork_height + 1 + applied;

            // State roots commit to the account state before this block executes.
            const current_state_root = try self.chain_state.calculateStateRoot();
            if (!std.mem.eql(u8, &new_block.header.state_root, &current_state_root)) {
                std.log.warn("❌ [REORG] Pre-state root mismatch at height {}", .{expected_height});
                std.log.warn("   Expected: {x}", .{&new_block.header.state_root});
                std.log.warn("   Actual:   {x}", .{&current_state_root});
                self.logPreStateDiagnostics(expected_height, &new_block, current_state_root);
                const restored = self.attemptRestoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height, "pre-state root mismatch");

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = blocks_to_revert,
                    .blocks_applied = applied,
                    .fork_height = fork_height,
                    .failure_reason = .pre_state_root_mismatch,
                    .chain_corrupted = !restored,
                };
            }

            // Apply the block after verifying its parent state commitment.
            self.applyBlock(io, &new_block, expected_height) catch |err| {
                std.log.warn("❌ [REORG] Failed to apply block at height {}: {}", .{ expected_height, err });
                const restored = self.attemptRestoreOriginalChain(io, old_tip_height, original_blocks.items, fork_height, "replacement block apply failure");

                return ReorgResult{
                    .success = false,
                    .blocks_reverted = blocks_to_revert,
                    .blocks_applied = applied,
                    .fork_height = fork_height,
                    .failure_reason = .apply_block_failed,
                    .chain_corrupted = !restored,
                };
            };

            applied += 1;
        }

        // Phase 3: SUCCESS - Now it's safe to finalize the new canonical height
        if (blocks_to_revert > 0) {
            // Replacement blocks were already written in-place at their target heights.
            // Deleting the old height range here would remove the newly applied chain.
            try self.db.saveHeight(new_tip_height);
            std.log.warn("📊 [REORG] Database height updated from {} to {}", .{ old_tip_height, new_tip_height });
        }

        if (self.mempool_manager) |mempool| {
            const winning_branch_hashes = try collectTransactionHashes(self.allocator, new_blocks);
            defer self.allocator.free(winning_branch_hashes);

            mempool.restoreStagedOrphanedTransactions(winning_branch_hashes);
            clear_staged_orphans_on_exit = false;
        }

        // Once the new branch wins, the old tip snapshot no longer anchors the canonical chain.
        if (old_tip_height > fork_height) {
            try state_root.deleteStateSnapshot(self.allocator, self.db, old_tip_height);
        }

        std.log.warn("✅ [REORG] Reorganization complete: reverted {}, applied {}", .{ blocks_to_revert, blocks_to_apply });

        return ReorgResult{
            .success = true,
            .blocks_reverted = blocks_to_revert,
            .blocks_applied = blocks_to_apply,
            .fork_height = fork_height,
        };
    }

    fn validateCompetingBranch(self: *Self, fork_height: u32, new_tip_height: u32, new_blocks: []const Block) bool {
        if (new_tip_height < fork_height) {
            return false;
        }

        const expected_blocks = new_tip_height - fork_height;
        if (new_blocks.len != expected_blocks) {
            return false;
        }

        if (new_blocks.len == 0) {
            return true;
        }

        const fork_hash = self.chain_state.getBlockHash(fork_height) orelse return false;
        var expected_previous_hash = fork_hash;

        for (new_blocks, 0..) |new_block, i| {
            const expected_height = fork_height + 1 + @as(u32, @intCast(i));
            if (new_block.height != expected_height) {
                return false;
            }

            if (!std.mem.eql(u8, &new_block.header.previous_hash, &expected_previous_hash)) {
                return false;
            }

            expected_previous_hash = new_block.hash();
        }

        return true;
    }

    fn validateCompetingBlocks(self: *Self, start_height: u32, new_blocks: []const Block) !void {
        if (self.validator) |validator| {
            try validator.validateReorgBranch(new_blocks, start_height);
        }
    }

    /// Revert state (accounts) back to a specific height WITHOUT deleting blocks
    /// This is safer because if the reorg fails, the old blocks are still available
    fn revertStateToHeight(self: *Self, io: std.Io, target_height: u32) !void {
        const current_height = try self.chain_state.getHeight();

        // Use ChainState's rollback functionality but WITHOUT deleting blocks
        if (target_height >= current_height) {
            return;
        }
        try self.chain_state.rollbackStateWithoutDeletingBlocks(io, target_height);

        std.log.debug("⏪ Reverted state from height {} to {}", .{ current_height, target_height });
    }

    /// Apply a single block to the chain
    fn applyBlock(self: *Self, io: std.Io, block: *const Block, height: u32) !void {
        // Process all transactions in the block using ChainState
        // Force processing = true because we might be reapplying blocks that exist in DB
        try self.chain_state.processBlockTransactions(io, block.transactions, height, true);

        const canonical_block = try self.recomputeCanonicalBlockMetadata(io, block, height);

        // Save block to database
        try self.db.saveBlock(io, height, canonical_block);

        // Update block index
        try self.chain_state.indexBlock(height, block.header.hash());
        try self.chain_state.maybeSavePeriodicStateSnapshot(io, height, block.hash());

        std.log.debug("⏩ Applied block at height {}", .{height});
    }

    fn recomputeCanonicalBlockMetadata(self: *Self, io: std.Io, block: *const Block, height: u32) !Block {
        var canonical_block = block.*;
        canonical_block.height = height;

        const block_work = canonical_block.header.getWork();
        const prev_chain_work = if (height > 0) blk: {
            var prev_block = try self.db.getBlock(io, height - 1);
            defer prev_block.deinit(self.allocator);
            break :blk prev_block.chain_work;
        } else 0;

        canonical_block.chain_work = prev_chain_work + block_work;
        return canonical_block;
    }

    fn logPreStateDiagnostics(self: *Self, expected_height: u32, block: *const Block, current_state_root: Hash) void {
        std.log.warn("🧪 [REORG DEBUG] Inspecting pre-state mismatch for height {}", .{expected_height});
        std.log.warn("🧪 [REORG DEBUG] Candidate block hash: {x}", .{block.hash()});
        std.log.warn("🧪 [REORG DEBUG] Candidate previous hash: {x}", .{&block.header.previous_hash});
        std.log.warn("🧪 [REORG DEBUG] Candidate header state_root: {x}", .{&block.header.state_root});
        std.log.warn("🧪 [REORG DEBUG] Local ChainState root:     {x}", .{&current_state_root});

        self.chain_state.debugLogAccounts("reorg-pre-state", 16) catch |err| {
            std.log.err("🧪 [REORG DEBUG] Failed to log account snapshot: {}", .{err});
        };
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

    fn collectTransactionHashes(allocator: std.mem.Allocator, blocks: []const Block) ![]Hash {
        var tx_count: usize = 0;
        for (blocks) |block| {
            tx_count += block.transactions.len;
        }

        const hashes = try allocator.alloc(Hash, tx_count);
        errdefer allocator.free(hashes);

        var index: usize = 0;
        for (blocks) |block| {
            for (block.transactions) |tx| {
                hashes[index] = tx.hash();
                index += 1;
            }
        }

        return hashes;
    }

    fn attemptRestoreOriginalChain(
        self: *Self,
        io: std.Io,
        old_tip_height: u32,
        original_blocks: []const Block,
        fork_height: u32,
        context: []const u8,
    ) bool {
        self.restoreOriginalChain(io, old_tip_height, original_blocks, fork_height) catch |restore_err| {
            if (self.force_restore_failure_for_testing) {
                std.log.warn("💥 [REORG] CRITICAL: Failed to restore original chain after {s}: {}", .{ context, restore_err });
            } else {
                std.log.err("💥 [REORG] CRITICAL: Failed to restore original chain after {s}: {}", .{ context, restore_err });
            }
            return false;
        };

        return true;
    }

    fn restoreOriginalChain(self: *Self, io: std.Io, old_tip_height: u32, original_blocks: []const Block, fork_height: u32) !void {
        if (self.force_restore_failure_for_testing) {
            return error.InjectedRestoreFailure;
        }

        std.log.warn("⏪ [REORG] Restoring original canonical chain to height {}", .{old_tip_height});

        const recovery_tip_hash = if (original_blocks.len > 0)
            original_blocks[original_blocks.len - 1].hash()
        else
            self.chain_state.getBlockHash(old_tip_height) orelse blk: {
                var block = try self.db.getBlock(io, old_tip_height);
                defer block.deinit(self.allocator);
                break :blk block.hash();
            };

        var batch = self.db.createWriteBatch();
        defer batch.deinit();

        for (original_blocks, 0..) |block, i| {
            const height = fork_height + 1 + @as(u32, @intCast(i));
            try batch.saveBlock(height, block);
        }

        const current_db_height = try self.db.getHeight();
        if (current_db_height > old_tip_height) {
            var height = old_tip_height + 1;
            while (height <= current_db_height) : (height += 1) {
                try batch.deleteBlock(height);
            }
        }

        const restored_anchor = state_root.appendStateSnapshotRestoreToBatch(
            self.allocator,
            self.db,
            &batch,
            old_tip_height,
            recovery_tip_hash,
        ) catch |err| {
            std.log.err("❌ [REORG] Failed to prepare atomic snapshot restore for old tip {}: {}", .{ old_tip_height, err });
            try self.rebuildOriginalChainFallback(io, old_tip_height, original_blocks, fork_height);
            return;
        };

        if (restored_anchor == null) {
            std.log.err("❌ [REORG] Missing old-tip snapshot at height {}; replaying canonical chain", .{old_tip_height});
            try self.rebuildOriginalChainFallback(io, old_tip_height, original_blocks, fork_height);
            return;
        }

        batch.saveHeight(old_tip_height);
        try batch.commit();

        try self.chain_state.refreshBlockIndexRange(fork_height + 1, original_blocks);
        try self.chain_state.verifyCurrentStateRoot(restored_anchor.?.state_root);
        std.log.warn("✅ [REORG] Original chain restored atomically from old-tip snapshot", .{});
    }

    fn rebuildOriginalChainFallback(self: *Self, io: std.Io, old_tip_height: u32, original_blocks: []const Block, fork_height: u32) !void {
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
        std.log.warn("✅ [REORG] Original chain restored via replay fallback", .{});
    }
};
