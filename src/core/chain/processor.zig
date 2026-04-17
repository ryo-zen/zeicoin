// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: MIT

// processor.zig - Blockchain Processing Module
// Handles block processing, application, and chain updates

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.chain);
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const util = @import("../util/util.zig");
const genesis = @import("genesis.zig");
const ChainState = @import("state.zig").ChainState;
const ChainValidator = @import("../validation/validator.zig").ChainValidator;
const bech32 = @import("../crypto/bech32.zig");
const OrphanPool = @import("orphan_pool.zig").OrphanPool;
const ReorgExecutor = @import("reorg_executor.zig").ReorgExecutor;

pub const ChainProcessor = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    chain_state: *ChainState,
    chain_validator: *ChainValidator,
    mempool_manager: ?*@import("../mempool/manager.zig").MempoolManager,
    reorg_executor: ReorgExecutor,
    reorg_in_progress: std.atomic.Value(bool),
    chain_quarantined: std.atomic.Value(bool),
    orphan_pool: OrphanPool,
    network_callback: ?*const fn (block: types.Block) void = null,

    pub fn init(
        allocator: std.mem.Allocator,
        database: *db.Database,
        chain_state: *ChainState,
        chain_validator: *ChainValidator,
        mempool_manager: ?*@import("../mempool/manager.zig").MempoolManager,
    ) ChainProcessor {
        return .{
            .allocator = allocator,
            .database = database,
            .chain_state = chain_state,
            .chain_validator = chain_validator,
            .mempool_manager = mempool_manager,
            .reorg_executor = ReorgExecutor.init(allocator, chain_state, &chain_validator.real_validator, database, mempool_manager),
            .reorg_in_progress = std.atomic.Value(bool).init(false),
            .chain_quarantined = std.atomic.Value(bool).init(false),
            .orphan_pool = OrphanPool.init(allocator, OrphanPool.MAX_ORPHANS_DEFAULT),
        };
    }

    pub fn deinit(self: *ChainProcessor) void {
        self.orphan_pool.deinit();
    }

    pub fn setNetworkCallback(self: *ChainProcessor, callback: *const fn (block: types.Block) void) void {
        self.network_callback = callback;
    }

    pub fn setMempoolManager(self: *ChainProcessor, mempool_manager: *@import("../mempool/manager.zig").MempoolManager) void {
        self.mempool_manager = mempool_manager;
        self.reorg_executor.setMempoolManager(mempool_manager);
    }

    pub fn isReorgInProgress(self: *const ChainProcessor) bool {
        return self.reorg_in_progress.load(.acquire);
    }

    pub fn isChainQuarantined(self: *const ChainProcessor) bool {
        return self.chain_quarantined.load(.acquire);
    }

    fn quarantineChain(self: *ChainProcessor) void {
        self.chain_quarantined.store(true, .release);
    }

    fn rejectIfChainQuarantined(self: *const ChainProcessor, operation: []const u8) !void {
        if (!self.isChainQuarantined()) return;

        if (builtin.is_test and self.reorg_executor.force_restore_failure_for_testing) {
            log.warn("🛑 [CHAIN QUARANTINE] Rejecting {s} because canonical recovery could not be proven", .{operation});
        } else {
            log.err("🛑 [CHAIN QUARANTINE] Rejecting {s} because canonical recovery could not be proven", .{operation});
        }
        return error.ChainQuarantined;
    }

    fn rejectIfReorgInProgress(self: *const ChainProcessor, operation: []const u8, block_height: ?u32) !void {
        if (!self.isReorgInProgress()) return;

        if (block_height) |height| {
            log.info("🔒 [REORG GUARD] Deferring {s} for block {} while reorganization is active", .{ operation, height });
        } else {
            log.info("🔒 [REORG GUARD] Deferring {s} while reorganization is active", .{operation});
        }

        return error.ReorgInProgress;
    }

    /// Apply a valid block to the blockchain during sync
    pub fn addBlockToChain(self: *ChainProcessor, io: std.Io, block: types.Block, height: u32) !void {
        try self.rejectIfChainQuarantined("sync block application");

        if (self.database.blockExistsByHeight(height)) {
            log.info("🔄 [SYNC DEDUP] Block #{} already exists, skipping", .{height});
            return;
        }

        try self.rejectIfReorgInProgress("sync block application", height);

        if (block.transactions.len > 10000) {
            return error.TooManyTransactions;
        }

        try self.commitBlock(io, block, height);
        log.info("✅ Block #{} added to chain ({} txs)", .{ height, block.txCount() });
    }

    /// Apply a valid block to the blockchain (internal, used during reorg)
    pub fn applyBlock(self: *ChainProcessor, io: std.Io, block: types.Block) !void {
        const block_height = try self.database.getHeight();
        try self.rejectIfChainQuarantined("block application");
        try self.rejectIfReorgInProgress("block application", block_height);

        try self.commitBlock(io, block, block_height);
        log.info("📊 [BLOCK APPLY] Block applied at height {}", .{block_height});
    }

    /// Accept a block after validation (used in reorganization and sync)
    pub fn acceptBlock(self: *ChainProcessor, io: std.Io, block: types.Block) !void {
        const block_hash = block.hash();
        try self.rejectIfChainQuarantined("block acceptance");

        // CRITICAL FIX: Check if block hash already exists anywhere in the chain
        if (self.chain_state.getBlockHeight(block_hash)) |existing_height| {
            log.info("🔄 [SYNC DEDUP] Block with hash {x} already exists at height {}, skipping processing to prevent double-spend", .{ block_hash[0..8], existing_height });
            return; // Skip processing but don't error - this is expected during sync replay
        }

        try self.rejectIfReorgInProgress("block acceptance", block.height);

        const current_height = try self.database.getHeight();

        // CRITICAL: Verify this block builds on our current chain tip
        // The block's previous_hash must match our current tip's hash
        if (current_height > 0) {
            var current_tip = try self.database.getBlock(io, current_height);
            defer current_tip.deinit(self.allocator);
            const current_tip_hash = current_tip.hash();

            if (!std.mem.eql(u8, &block.header.previous_hash, &current_tip_hash)) {
                log.warn("⚠️ [FORK DETECTED] Block doesn't connect to our chain tip", .{});
                log.warn("   📊 Our tip at height {}: {x}", .{ current_height, current_tip_hash });
                log.warn("   📦 Block's previous_hash: {x}", .{&block.header.previous_hash});
                log.warn("   🔀 Block hash: {x}", .{&block_hash});
                log.warn("   📏 Block height: {}", .{block.height});

                // Block doesn't connect to our chain - store as orphan
                // The sync manager will handle detecting competing chains and triggering reorganization
                log.info("💾 [ORPHAN] Storing block as orphan - sync manager will handle chain resolution", .{});

                var block_copy = try block.clone(self.allocator);
                self.orphan_pool.addOrphan(block_copy) catch |err| {
                    log.warn("⚠️ Failed to add orphan: {}", .{err});
                    block_copy.deinit(self.allocator);
                    return error.InvalidPreviousHash;
                };

                return; // Stored as orphan
            }
        } else if (current_height == 0) {
            // At height 0, we're waiting for block 1 which must reference genesis
            // Block at height 1 must reference genesis
            const genesis_hash = genesis.getCanonicalGenesisHash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &genesis_hash)) {
                log.warn("❌ [BLOCK REJECT] Block at height 1 must reference genesis", .{});
                log.warn("   📊 Genesis hash: {x}", .{&genesis_hash});
                log.warn("   📦 Block's previous_hash: {x}", .{&block.header.previous_hash});
                return error.InvalidPreviousHash;
            }
        }

        const target_height = current_height + 1;

        if (self.database.blockExistsByHeight(target_height)) {
            log.info("🔄 [SYNC DEDUP] Block #{} already exists by height, skipping", .{target_height});
            return;
        }

        if (!try self.chain_validator.validateSyncBlock(&block, target_height)) {
            return error.BlockValidationFailed;
        }

        try self.commitBlock(io, block, target_height);
        log.info("📦 [BLOCK PROCESS] Block #{} accepted", .{target_height});

        // FIX: Check if any orphan blocks can now be processed after adding this block
        self.processOrphanBlocks(io) catch |err| {
            log.warn("⚠️ [ORPHAN PROCESS] Error processing orphans: {}", .{err});
            // Continue - orphan processing failures shouldn't stop block acceptance
        };

        // Broadcast to network if callback is set
        if (self.network_callback) |callback| {
            util.logSuccess("🚀 Broadcasting newly mined block #{} to P2P network", .{target_height});
            callback(block);
        } else {
            util.logInfo("💭 No network connected, block not broadcast", .{});
        }
    }

    /// Shared commit path: process transactions, save block with chain work, index, and clean mempool.
    fn commitBlock(self: *ChainProcessor, io: std.Io, block: types.Block, height: u32) !void {
        try self.chain_state.processBlockTransactions(io, block.transactions, height, false);

        // Calculate cumulative chain work
        var block_with_work = block;
        const block_work = block.header.getWork();
        const prev_chain_work = if (height > 0) blk: {
            var prev_block = try self.database.getBlock(io, height - 1);
            defer prev_block.deinit(self.allocator);
            break :blk prev_block.chain_work;
        } else 0;
        block_with_work.chain_work = prev_chain_work + block_work;

        log.debug("⚡ [CHAIN WORK] Block #{} work: {}, cumulative: {}", .{ height, block_work, block_with_work.chain_work });

        try self.database.saveBlock(io, height, block_with_work);

        const block_hash = block.hash();
        try self.chain_state.indexBlock(height, block_hash);
        try self.chain_state.maybeSavePeriodicStateSnapshot(io, height, block_hash);

        if (self.mempool_manager) |mempool| {
            mempool.cleanAfterBlock(block) catch |err| {
                log.warn("⚠️ Mempool cleanup failed: {}", .{err});
            };
        }
    }

    /// Execute bulk chain reorganization
    /// Called by sync manager when a competing longer chain is detected
    pub fn executeBulkReorg(self: *ChainProcessor, io: std.Io, fork_height: u32, new_blocks: []const types.Block) !void {
        try self.rejectIfChainQuarantined("reorganization");

        if (self.reorg_in_progress.swap(true, .acq_rel)) {
            log.warn("🔒 [REORG GUARD] Reorganization already in progress, rejecting overlapping request", .{});
            return error.ReorgInProgress;
        }
        defer self.reorg_in_progress.store(false, .release);

        const current_height = try self.database.getHeight();
        const new_tip_height = if (new_blocks.len > 0) new_blocks[new_blocks.len - 1].height else fork_height;

        log.warn("🔄 [BULK REORG] Starting reorganization: height {} → {}", .{ current_height, new_tip_height });
        log.warn("   📦 Blocks to process: {}", .{new_blocks.len});

        // Execute the reorganization
        const result = try self.reorg_executor.executeReorg(io, current_height, fork_height, new_tip_height, new_blocks);

        if (result.success) {
            log.warn("✅ [BULK REORG] Chain reorganization successful!", .{});
            log.warn("   ⏪ Blocks reverted: {}", .{result.blocks_reverted});
            log.warn("   ⏩ Blocks applied: {}", .{result.blocks_applied});
            log.warn("   🔀 Fork height: {}", .{result.fork_height});

            // Clear orphan pool after successful reorg
            self.orphan_pool.clear();
        } else {
            if (builtin.is_test and self.reorg_executor.force_restore_failure_for_testing) {
                log.warn("❌ [BULK REORG] Chain reorganization failed!", .{});
            } else {
                log.err("❌ [BULK REORG] Chain reorganization failed!", .{});
            }
            if (result.failure_reason) |reason| {
                if (builtin.is_test and self.reorg_executor.force_restore_failure_for_testing) {
                    log.warn("   💬 Error: {s}", .{reason.description()});
                } else {
                    log.err("   💬 Error: {s}", .{reason.description()});
                }
            }
            if (result.chain_corrupted) {
                self.quarantineChain();
                if (builtin.is_test and self.reorg_executor.force_restore_failure_for_testing) {
                    log.warn("💥 [BULK REORG] Canonical chain recovery could not be proven; quarantining node until manual recovery/resync", .{});
                } else {
                    log.err("💥 [BULK REORG] Canonical chain recovery could not be proven; quarantining node until manual recovery/resync", .{});
                }
                return error.ChainQuarantined;
            }

            return error.ReorgFailed;
        }
    }

    /// Process orphan blocks after a new block is added to the chain
    /// Checks if any orphans are now ready to be connected
    fn processOrphanBlocks(self: *ChainProcessor, io: std.Io) anyerror!void {
        if (self.isReorgInProgress()) {
            log.info("🔒 [REORG GUARD] Skipping orphan processing while reorganization is active", .{});
            return;
        }

        log.info("🔍 [ORPHAN PROCESS] Checking orphan pool for processable blocks", .{});
        log.info("   📊 Current orphan count: {}", .{self.orphan_pool.size()});

        // Get the current chain tip
        const current_height = try self.database.getHeight();
        var current_tip = try self.database.getBlock(io, current_height);
        defer current_tip.deinit(self.allocator);
        const current_tip_hash = current_tip.hash();

        // Check if any orphans are waiting for this block as their parent
        if (self.orphan_pool.getOrphansByParent(current_tip_hash)) |orphan_blocks| {
            var owned_orphans = orphan_blocks;
            defer {
                for (owned_orphans.items) |*block| {
                    block.deinit(self.allocator);
                }
                owned_orphans.deinit();
            }

            log.info("✅ [ORPHAN PROCESS] Found {} orphan(s) that can now be processed", .{owned_orphans.items.len});

            // Process each orphan block
            for (owned_orphans.items) |orphan_block| {
                const orphan_hash = orphan_block.hash();
                log.info("   📦 Processing orphan block at height {} (hash: {x})", .{
                    orphan_block.height,
                    orphan_hash[0..8],
                });

                // Try to accept the orphan block
                // Note: We don't catch errors here - let them propagate up
                try self.acceptBlock(io, orphan_block);

                log.info("   ✅ Orphan block processed successfully", .{});
            }

            // Note: Don't recurse here to avoid inferred error set issues
            // The caller (addBlockToChain) will call processOrphanBlocks again if needed
        } else {
            log.info("   ℹ️  No orphans ready for processing", .{});
        }
    }
};
