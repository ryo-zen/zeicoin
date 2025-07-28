// processor.zig - Blockchain Processing Module
// Handles block processing, application, and chain updates

const std = @import("std");
const print = std.debug.print;
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const util = @import("../util/util.zig");
const genesis = @import("genesis.zig");
const ChainState = @import("state.zig").ChainState;
const ForkManager = @import("../fork/main.zig").ForkManager;
const ChainValidator = @import("../validation/validator.zig").ChainValidator;

pub const ChainProcessor = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    chain_state: *ChainState,
    fork_manager: *ForkManager,
    chain_validator: *ChainValidator,
    mempool_manager: ?*@import("../mempool/manager.zig").MempoolManager,
    // Reference to parent for network broadcasting
    network_callback: ?*const fn (block: types.Block) void = null,

    pub fn init(
        allocator: std.mem.Allocator,
        database: *db.Database,
        chain_state: *ChainState,
        fork_manager: *ForkManager,
        chain_validator: *ChainValidator,
        mempool_manager: ?*@import("../mempool/manager.zig").MempoolManager,
    ) ChainProcessor {
        return .{
            .allocator = allocator,
            .database = database,
            .chain_state = chain_state,
            .fork_manager = fork_manager,
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
            print("🔄 [SYNC DEDUP] Block #{} already exists, skipping processing to prevent double-spend\n", .{height});
            return; // Skip processing but don't error - this is expected during crash recovery
        }

        const block_hash = block.hash();
        print("📦 [BLOCK PROCESS] Block #{} received with {} transactions (hash: {s})\n", .{ height, block.txCount(), std.fmt.fmtSliceHexLower(block_hash[0..8]) });

        // SAFETY: Check transaction array bounds
        if (block.transactions.len > 10000) { // Reasonable upper limit
            print("❌ [SAFETY] Block has too many transactions: {}\n", .{block.transactions.len});
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

        // Update fork manager with the new best chain
        const new_cumulative_work = self.estimateCumulativeWork(height) catch 0;
        self.fork_manager.updateBestChain(&block, height, new_cumulative_work);

        print("✅ Block #{} added to chain ({} txs)\n", .{ height, block.txCount() });
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

        print("📊 [BLOCK APPLY] Block applied at height {}, database now has {} blocks\n", .{ block_height, try self.database.getHeight() });
    }

    /// Accept a block after validation (used in reorganization)
    pub fn acceptBlock(self: *ChainProcessor, block: types.Block) !void {
        const current_height = try self.database.getHeight();

        // Special case: if we're at height 0 (after rollback to genesis) and the incoming block
        // is not a genesis block, we need to save it at height 1, not height 0
        const target_height = if (current_height == 0 and !genesis.validateGenesis(block)) blk: {
            print("🔄 Accepting non-genesis block after rollback - placing at height 1\n", .{});
            break :blk @as(u32, 1);
        } else current_height;

        // During reorganization, use reorganization-specific validation (skips hash chain checks)
        if (!try self.chain_validator.validateReorgBlock(block, target_height)) {
            return error.BlockValidationFailed;
        }

        // Process transactions
        try self.processBlockTransactions(block.transactions, target_height);

        // Save to database
        try self.database.saveBlock(target_height, block);

        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(target_height, block_hash);

        const old_height = self.chain_state.getHeight() catch 0;
        print("📦 [BLOCK PROCESS] Block #{} accepted - chain height: {} → {}\n", .{ target_height, old_height, target_height });

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
            print("⚠️ [SAFETY] Block has no transactions at height {}\n", .{height});
            return; // Empty block is valid
        }

        for (transactions, 0..) |tx, i| {
            // SAFETY: Check transaction bounds and validity
            if (i >= transactions.len) {
                print("❌ [SAFETY] Transaction index {} >= array length {}\n", .{ i, transactions.len });
                return error.TransactionIndexOutOfBounds;
            }

            // Log transaction processing
            const tx_hash = tx.hash();
            const amount_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            print("📦 [BLOCK PROCESS] Processing transaction {}/{}: {s} ({d:.8} ZEI from {x} to {x})\n", .{ i + 1, transactions.len, std.fmt.fmtSliceHexLower(tx_hash[0..8]), amount_zei, tx.sender.hash, tx.recipient.hash });

            // SAFETY: Validate transaction structure before processing
            if (!tx.isValid()) {
                print("❌ [SAFETY] Invalid transaction {} in block at height {}\n", .{ i, height });
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
                print("⚠️  Mempool cleanup failed: {}\n", .{err});
                // Continue processing - mempool cleanup failure shouldn't stop block processing
            };
            print("🧹 Mempool cleaned after block processing\n", .{});
        } else {
            print("🧹 No mempool manager - cleanup skipped\n", .{});
        }
    }

    fn estimateCumulativeWork(self: *ChainProcessor, height: u32) !types.ChainWork {
        // SAFETY: Check for reasonable height bounds
        if (height > 1000000) { // Sanity check - 1M blocks
            print("❌ [SAFETY] Height {} too large for cumulative work calculation\n", .{height});
            return 0;
        }

        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(@intCast(h)) catch {
                // Skip missing blocks instead of crashing
                print("⚠️ [SAFETY] Missing block at height {} during work calculation\n", .{h});
                continue;
            };

            // SAFETY: Ensure block is valid before accessing header
            if (!block.isValid()) {
                print("⚠️ [SAFETY] Invalid block at height {} during work calculation\n", .{h});
                block.deinit(self.allocator);
                continue;
            }

            total_work += block.header.getWork();
            block.deinit(self.allocator);
        }
        return total_work;
    }
};
