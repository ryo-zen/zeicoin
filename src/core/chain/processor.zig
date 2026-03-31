// processor.zig - Blockchain Processing Module
// Handles block processing, application, and chain updates

const std = @import("std");
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
            .reorg_executor = ReorgExecutor.init(allocator, chain_state, &chain_validator.real_validator, database),
            .reorg_in_progress = std.atomic.Value(bool).init(false),
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
    }

    pub fn isReorgInProgress(self: *const ChainProcessor) bool {
        return self.reorg_in_progress.load(.acquire);
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

    /// Apply a valid block to the blockchain
    pub fn addBlockToChain(self: *ChainProcessor, io: std.Io, block: types.Block, height: u32) !void {
        // SAFETY: Basic validation - these should not be null in normal operation

        // Check if block already exists to prevent double-processing during sync replay
        if (self.database.blockExistsByHeight(height)) {
            log.info("🔄 [SYNC DEDUP] Block #{} already exists, skipping processing to prevent double-spend", .{height});
            return; // Skip processing but don't error - this is expected during crash recovery
        }

        try self.rejectIfReorgInProgress("sync block application", height);

        const block_hash = block.hash();
        log.info("📦 [BLOCK PROCESS] Block #{} received with {} transactions (hash: {x})", .{ height, block.txCount(), block_hash[0..8] });

        // SAFETY: Check transaction array bounds
        if (block.transactions.len > 10000) { // Reasonable upper limit
            log.info("❌ [SAFETY] Block has too many transactions: {}", .{block.transactions.len});
            return error.TooManyTransactions;
        }

        // Process all transactions in the block
        try self.processBlockTransactions(io, block.transactions, height);

        // Calculate cumulative chain work (critical for reorganization)
        var block_with_work = block;
        const block_work = block.header.getWork();
        const prev_chain_work = if (height > 0) blk: {
            var prev_block = try self.database.getBlock(io, height - 1);
            defer prev_block.deinit(self.allocator);
            break :blk prev_block.chain_work;
        } else 0;

        block_with_work.chain_work = prev_chain_work + block_work;

        log.debug("⚡ [CHAIN WORK] Block #{} work: {}, cumulative: {}", .{ height, block_work, block_with_work.chain_work });

        // Save block to database with chain work
        try self.database.saveBlock(io, height, block_with_work);

        // Update block index for O(1) lookups in reorganizations
        const index_block_hash = block.hash();
        try self.chain_state.indexBlock(height, index_block_hash);
        try self.chain_state.maybeSavePeriodicStateSnapshot(io, height, index_block_hash);

        // Remove processed transactions from mempool
        self.cleanMempool(block);

        // Chain state tracking moved to modern reorganization system
        // Fork manager updateBestChain call removed - handled by ChainState

        log.info("✅ Block #{} added to chain ({} txs)", .{ height, block.txCount() });
    }

    /// Apply a valid block to the blockchain (internal)
    pub fn applyBlock(self: *ChainProcessor, io: std.Io, block: types.Block) !void {
        // Get the current height - this is the height for the new block
        const block_height = try self.database.getHeight();

        try self.rejectIfReorgInProgress("block application", block_height);

        // Process all transactions in the block
        try self.processBlockTransactions(io, block.transactions, block_height);

        // Save block to database at the current height
        try self.database.saveBlock(io, block_height, block);

        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(block_height, block_hash);
        try self.chain_state.maybeSavePeriodicStateSnapshot(io, block_height, block_hash);

        // Remove processed transactions from mempool
        self.cleanMempool(block);

        log.info("📊 [BLOCK APPLY] Block applied at height {}, database now has {} blocks", .{ block_height, try self.database.getHeight() });
    }

    /// Accept a block after validation (used in reorganization and sync)
    pub fn acceptBlock(self: *ChainProcessor, io: std.Io, block: types.Block) !void {
        const block_hash = block.hash();

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

        // Secondary check: verify height is available (defensive programming)
        if (self.database.blockExistsByHeight(target_height)) {
            log.info("🔄 [SYNC DEDUP] Block #{} already exists by height, skipping processing to prevent double-spend", .{target_height});
            return; // Skip processing but don't error - this is expected during sync replay
        }

        // Use sync validation for blocks received during normal operation
        // (validateSyncBlock is more appropriate for network-received blocks)
        if (!try self.chain_validator.validateSyncBlock(&block, target_height)) {
            return error.BlockValidationFailed;
        }

        // Process transactions
        try self.processBlockTransactions(io, block.transactions, target_height);

        // Calculate cumulative chain work (critical for reorganization)
        var block_with_work = block;
        const block_work = block.header.getWork();
        const prev_chain_work = if (target_height > 0) blk: {
            var prev_block = try self.database.getBlock(io, target_height - 1);
            defer prev_block.deinit(self.allocator);
            break :blk prev_block.chain_work;
        } else 0;

        block_with_work.chain_work = prev_chain_work + block_work;

        log.debug("⚡ [CHAIN WORK] Block #{} work: {}, cumulative: {}", .{ target_height, block_work, block_with_work.chain_work });

        // Save to database with chain work
        try self.database.saveBlock(io, target_height, block_with_work);

        // Update block index for O(1) lookups in reorganizations
        const index_block_hash = block.hash();
        try self.chain_state.indexBlock(target_height, index_block_hash);
        try self.chain_state.maybeSavePeriodicStateSnapshot(io, target_height, index_block_hash);

        const old_height = self.chain_state.getHeight() catch 0;
        log.info("📦 [BLOCK PROCESS] Block #{} accepted - chain height: {} → {}", .{ target_height, old_height, target_height });

        // Clean mempool of transactions that are now confirmed in this block
        self.cleanMempool(block);

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

    fn processBlockTransactions(self: *ChainProcessor, io: std.Io, transactions: []const types.Transaction, height: u32) !void {
        try self.chain_state.processBlockTransactions(io, transactions, height, false);
    }

    fn cleanMempool(self: *ChainProcessor, block: types.Block) void {
        if (self.mempool_manager) |mempool| {
            mempool.cleanAfterBlock(block) catch |err| {
                log.info("⚠️  Mempool cleanup failed: {}", .{err});
                // Continue processing - mempool cleanup failure shouldn't stop block processing
            };
            log.info("🧹 Mempool cleaned after block processing", .{});
        } else {
            log.info("🧹 No mempool manager - cleanup skipped", .{});
        }
    }

    fn estimateCumulativeWork(self: *ChainProcessor, io: std.Io, height: u32) !types.ChainWork {
        // SAFETY: Check for reasonable height bounds
        if (height > 1000000) { // Sanity check - 1M blocks
            log.info("❌ [SAFETY] Height {} too large for cumulative work calculation", .{height});
            return 0;
        }

        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(io, @intCast(h)) catch {
                // Skip missing blocks instead of crashing
                log.info("⚠️ [SAFETY] Missing block at height {} during work calculation", .{h});
                continue;
            };

            // SAFETY: Ensure block is valid before accessing header
            if (!block.isValid()) {
                log.info("⚠️ [SAFETY] Invalid block at height {} during work calculation", .{h});
                block.deinit(self.allocator);
                continue;
            }

            total_work += block.header.getWork();
            block.deinit(self.allocator);
        }
        return total_work;
    }

    /// Request a range of missing blocks from the sync system
    /// This is called when we detect a gap in the blockchain
    fn requestMissingBlocks(self: *ChainProcessor, start_height: u32, end_height: u32) !void {
        _ = self; // Currently unused but needed for future implementation
        log.info("📥 [MISSING BLOCKS] Requesting blocks {} to {} ({} blocks)", .{
            start_height,
            end_height,
            end_height - start_height + 1,
        });

        // Access global blockchain instance via sync manager
        const sync_manager_module = @import("../sync/manager.zig");
        if (sync_manager_module.g_blockchain) |blockchain| {
            if (blockchain.sync_manager) |sync_mgr| {
                // Get the network manager to find a peer
                const network_mgr = blockchain.network_coordinator.getNetworkManager() orelse {
                    log.warn("❌ [MISSING BLOCKS] Network manager not available", .{});
                    return error.NoNetworkManager;
                };

                // Get the best peer for sync
                const peer = network_mgr.peer_manager.getBestPeerForSync() orelse {
                    log.warn("❌ [MISSING BLOCKS] No peers available for sync", .{});
                    return error.NoPeersAvailable;
                };
                defer peer.release();

                log.info("✅ [MISSING BLOCKS] Using peer at height {} for sync", .{peer.height});

                // Trigger sync for the missing block range
                // Note: startSync will handle the actual block fetching
                sync_mgr.startSync(peer, end_height, false) catch |err| {
                    log.warn("❌ [MISSING BLOCKS] Failed to start sync: {}", .{err});
                    return err;
                };

                log.info("✅ [MISSING BLOCKS] Sync request initiated successfully", .{});
            } else {
                log.warn("❌ [MISSING BLOCKS] Sync manager not available", .{});
                return error.NoSyncManager;
            }
        } else {
            log.warn("❌ [MISSING BLOCKS] Global blockchain instance not available", .{});
            return error.NoBlockchain;
        }
    }

    /// Execute bulk chain reorganization
    /// Called by sync manager when a competing longer chain is detected
    pub fn executeBulkReorg(self: *ChainProcessor, io: std.Io, fork_height: u32, new_blocks: []const types.Block) !void {
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
            log.err("❌ [BULK REORG] Chain reorganization failed!", .{});
            if (result.failure_reason) |reason| {
                log.err("   💬 Error: {s}", .{reason.description()});
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
