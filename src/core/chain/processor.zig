// processor.zig - Blockchain Processing Module
// Handles block processing, application, and chain updates

const std = @import("std");
const log = std.log.scoped(.chain);
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const util = @import("../util/util.zig");
const genesis = @import("genesis.zig");
const ChainState = @import("state.zig").ChainState;
// ForkManager removed - using modern reorganization system
const ChainValidator = @import("../validation/validator.zig").ChainValidator;
const bech32 = @import("../crypto/bech32.zig");

pub const ChainProcessor = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    chain_state: *ChainState,
    // fork_manager removed - using modern reorganization system
    chain_validator: *ChainValidator,
    mempool_manager: ?*@import("../mempool/manager.zig").MempoolManager,
    reorg_manager: ?*@import("reorganization/manager.zig").ReorgManager = null,
    // Reference to parent for network broadcasting
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
        };
    }

    pub fn deinit(self: *ChainProcessor) void {
        _ = self;
    }

    pub fn setNetworkCallback(self: *ChainProcessor, callback: *const fn (block: types.Block) void) void {
        self.network_callback = callback;
    }

    pub fn setMempoolManager(self: *ChainProcessor, mempool_manager: *@import("../mempool/manager.zig").MempoolManager) void {
        self.mempool_manager = mempool_manager;
    }

    /// Apply a valid block to the blockchain
    pub fn addBlockToChain(self: *ChainProcessor, block: types.Block, height: u32) !void {
        // SAFETY: Basic validation - these should not be null in normal operation

        // Check if block already exists to prevent double-processing during sync replay
        if (self.database.blockExistsByHeight(height)) {
            log.info("🔄 [SYNC DEDUP] Block #{} already exists, skipping processing to prevent double-spend", .{height});
            return; // Skip processing but don't error - this is expected during crash recovery
        }

        const block_hash = block.hash();
        log.info("📦 [BLOCK PROCESS] Block #{} received with {} transactions (hash: {s})", .{ height, block.txCount(), std.fmt.fmtSliceHexLower(block_hash[0..8]) });

        // SAFETY: Check transaction array bounds
        if (block.transactions.len > 10000) { // Reasonable upper limit
            log.info("❌ [SAFETY] Block has too many transactions: {}", .{block.transactions.len});
            return error.TooManyTransactions;
        }

        // Process all transactions in the block
        try self.processBlockTransactions(block.transactions, height);

        // Save block to database
        try self.database.saveBlock(height, block);

        // Update block index for O(1) lookups in reorganizations
        const index_block_hash = block.hash();
        try self.chain_state.indexBlock(height, index_block_hash);

        // Mature any coinbase rewards that have reached 100 confirmations
        try self.matureCoinbaseRewards(height);

        // Remove processed transactions from mempool
        self.cleanMempool(block);

        // Chain state tracking moved to modern reorganization system
        // Fork manager updateBestChain call removed - handled by ChainState

        log.info("✅ Block #{} added to chain ({} txs)", .{ height, block.txCount() });
    }

    /// Apply a valid block to the blockchain (internal)
    pub fn applyBlock(self: *ChainProcessor, block: types.Block) !void {
        // Get the current height - this is the height for the new block
        const block_height = try self.database.getHeight();

        // Process all transactions in the block
        try self.processBlockTransactions(block.transactions, block_height);

        // Save block to database at the current height
        try self.database.saveBlock(block_height, block);

        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(block_height, block_hash);

        // Mature any coinbase rewards that have reached 100 confirmations
        try self.matureCoinbaseRewards(block_height);

        // Remove processed transactions from mempool
        self.cleanMempool(block);

        log.info("📊 [BLOCK APPLY] Block applied at height {}, database now has {} blocks", .{ block_height, try self.database.getHeight() });
    }

    /// Accept a block after validation (used in reorganization and sync)
    pub fn acceptBlock(self: *ChainProcessor, block: types.Block) !void {
        const block_hash = block.hash();
        
        // CRITICAL FIX: Check if block hash already exists anywhere in the chain
        if (self.chain_state.getBlockHeight(block_hash)) |existing_height| {
            log.info("🔄 [SYNC DEDUP] Block with hash {s} already exists at height {}, skipping processing to prevent double-spend", .{ std.fmt.fmtSliceHexLower(block_hash[0..8]), existing_height });
            return; // Skip processing but don't error - this is expected during sync replay
        }

        const current_height = try self.database.getHeight();
        
        // CRITICAL: Verify this block builds on our current chain tip
        // The block's previous_hash must match our current tip's hash
        if (current_height > 0) {
            var current_tip = try self.database.getBlock(current_height);
            defer current_tip.deinit(self.allocator);
            const current_tip_hash = current_tip.hash();
            
            if (!std.mem.eql(u8, &block.header.previous_hash, &current_tip_hash)) {
                log.warn("⚠️ [FORK DETECTED] Block doesn't connect to our chain tip", .{});
                log.warn("   📊 Our tip at height {}: {s}", .{ current_height, std.fmt.fmtSliceHexLower(&current_tip_hash) });
                log.warn("   📦 Block's previous_hash: {s}", .{ std.fmt.fmtSliceHexLower(&block.header.previous_hash) });
                log.warn("   🔀 Block hash: {s}", .{ std.fmt.fmtSliceHexLower(&block_hash) });
                
                // Check if we have a reorg manager to handle chain forks
                if (self.reorg_manager) |reorg| {
                    log.info("🔄 [REORG] Attempting chain reorganization...", .{});
                    log.info("   📍 Current height: {}", .{current_height});
                    log.info("   📦 New block attempting to fork chain", .{});
                    
                    // Attempt reorganization
                    const result = reorg.executeReorganization(block, block_hash) catch |err| {
                        log.err("❌ [REORG FAILED] Error during reorganization: {}", .{err});
                        return error.InvalidPreviousHash;
                    };
                    
                    if (result.success) {
                        log.info("✅ [REORG SUCCESS] Chain reorganized!", .{});
                        log.info("   ⬆️ Blocks reverted: {}", .{result.blocks_reverted});
                        log.info("   ⬇️ Blocks applied: {}", .{result.blocks_applied});
                        log.info("   🔄 Transactions replayed: {}", .{result.transactions_replayed});
                        log.info("   ❌ Transactions orphaned: {}", .{result.transactions_orphaned});
                        log.info("   ⏱️ Duration: {}ms", .{result.duration_ms});
                        return; // Reorg successful, block accepted
                    } else {
                        log.warn("❌ [REORG FAILED] Could not reorganize to new chain", .{});
                        if (result.error_message) |msg| {
                            log.warn("   💬 Reason: {s}", .{msg});
                        }
                        
                        // If reorganization failed but we found a fork point, 
                        // we need to sync from that point to get the missing blocks
                        if (result.fork_height) |fork_height| {
                            log.info("🔄 [FORK SYNC] Need to sync from fork point at height {}", .{fork_height});
                            log.info("   📥 Missing blocks: {}-{}", .{ fork_height + 1, current_height + 2 });
                            
                            // Store fork height for sync system to use
                            // TODO: Implement custom sync start height
                            // For now, the error will trigger normal sync retry
                        }
                        
                        return error.InvalidPreviousHash;
                    }
                } else {
                    log.warn("   ⚠️ No reorg manager available, rejecting block", .{});
                    return error.InvalidPreviousHash;
                }
            }
        } else if (current_height == 0) {
            // At height 0, we're waiting for block 1 which must reference genesis
            // Block at height 1 must reference genesis
            const genesis_hash = genesis.getCanonicalGenesisHash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &genesis_hash)) {
                log.warn("❌ [BLOCK REJECT] Block at height 1 must reference genesis", .{});
                log.warn("   📊 Genesis hash: {s}", .{ std.fmt.fmtSliceHexLower(&genesis_hash) });
                log.warn("   📦 Block's previous_hash: {s}", .{ std.fmt.fmtSliceHexLower(&block.header.previous_hash) });
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
        try self.processBlockTransactions(block.transactions, target_height);

        // Save to database
        try self.database.saveBlock(target_height, block);

        // Update block index for O(1) lookups in reorganizations
        const index_block_hash = block.hash();
        try self.chain_state.indexBlock(target_height, index_block_hash);

        const old_height = self.chain_state.getHeight() catch 0;
        log.info("📦 [BLOCK PROCESS] Block #{} accepted - chain height: {} → {}", .{ target_height, old_height, target_height });

        // Clean mempool of transactions that are now confirmed in this block
        self.cleanMempool(block);

        // Broadcast to network if callback is set
        if (self.network_callback) |callback| {
            util.logSuccess("🚀 Broadcasting newly mined block #{} to P2P network", .{target_height});
            callback(block);
        } else {
            util.logInfo("💭 No network connected, block not broadcast", .{});
        }
    }

    fn processBlockTransactions(self: *ChainProcessor, transactions: []const types.Transaction, height: u32) !void {
        // SAFETY: Check for valid transactions array
        if (transactions.len == 0) {
            log.info("⚠️ [SAFETY] Block has no transactions at height {}", .{height});
            return; // Empty block is valid
        }

        for (transactions, 0..) |tx, i| {
            // SAFETY: Check transaction bounds and validity
            if (i >= transactions.len) {
                log.info("❌ [SAFETY] Transaction index {} >= array length {}", .{ i, transactions.len });
                return error.TransactionIndexOutOfBounds;
            }

            // Log transaction processing
            const tx_hash = tx.hash();
            const amount_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const sender_addr = bech32.encodeAddress(self.allocator, tx.sender, types.CURRENT_NETWORK) catch "<invalid>";
            defer if (!std.mem.eql(u8, sender_addr, "<invalid>")) self.allocator.free(sender_addr);
            const recipient_addr = bech32.encodeAddress(self.allocator, tx.recipient, types.CURRENT_NETWORK) catch "<invalid>";
            defer if (!std.mem.eql(u8, recipient_addr, "<invalid>")) self.allocator.free(recipient_addr);
            log.info("📦 [BLOCK PROCESS] Processing transaction {}/{}: {s} ({d:.8} ZEI from {s} to {s})", .{ i + 1, transactions.len, std.fmt.fmtSliceHexLower(tx_hash[0..8]), amount_zei, sender_addr, recipient_addr });

            // SAFETY: Validate transaction structure before processing
            if (!tx.isValid()) {
                log.info("❌ [SAFETY] Invalid transaction {} in block at height {}", .{ i, height });
                return error.InvalidTransaction;
            }

            if (tx.isCoinbase()) {
                try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, height);
            } else {
                try self.chain_state.processTransaction(tx);
            }
        }
    }

    fn matureCoinbaseRewards(self: *ChainProcessor, current_height: u32) !void {
        // Check if we have mature coinbase rewards (100 block maturity)
        if (current_height >= types.COINBASE_MATURITY) {
            const maturity_height = current_height - types.COINBASE_MATURITY;
            try self.chain_state.matureCoinbaseRewards(maturity_height);
        }
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

    fn estimateCumulativeWork(self: *ChainProcessor, height: u32) !types.ChainWork {
        // SAFETY: Check for reasonable height bounds
        if (height > 1000000) { // Sanity check - 1M blocks
            log.info("❌ [SAFETY] Height {} too large for cumulative work calculation", .{height});
            return 0;
        }

        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(@intCast(h)) catch {
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
};
