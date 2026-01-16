// operations.zig - Chain Operations Manager
// Handles chain mechanics, difficulty adjustment, and block operations
// Manages chain height, block storage, and chain progression

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const genesis = @import("genesis.zig");
const ChainState = @import("state.zig").ChainState;
const ChainValidator = @import("validator.zig").ChainValidator;

const log = std.log.scoped(.chain);

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// ChainOperations manages chain mechanics and block operations
/// - Chain height and block queries
/// - Difficulty adjustment calculations
/// - Block addition and acceptance
/// - Chain progression and fork detection
pub const ChainOperations = struct {
    chain_state: *ChainState,
    chain_validator: *ChainValidator,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ChainOperations with references to ChainState and ChainValidator
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState, chain_validator: *ChainValidator) Self {
        return .{
            .chain_state = chain_state,
            .chain_validator = chain_validator,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No cleanup needed currently
    }

    // Chain Operations Methods (to be extracted from node.zig)
    // - getHeight()
    // - getBlockByHeight()
    // - getMedianTimePast()
    // - calculateNextDifficulty()
    // - estimateCumulativeWork()
    // - addBlockToChain()
    // - acceptBlock()
    // - applyBlock()
    // - isValidForkBlock()
    // - storeForkBlock()

    // Chain Operations Methods extracted from node.zig

    /// Get current blockchain height
    pub fn getHeight(self: *Self) !u32 {
        return self.chain_state.getHeight();
    }

    /// Calculate total work for the current chain
    pub fn calculateTotalWork(self: *Self) !u64 {
        const current_height = try self.getHeight();
        var total_work: u64 = 0;

        // Sum work from all blocks in the chain
        for (0..current_height + 1) |height| {
            var block = self.chain_state.database.getBlock(@intCast(height)) catch {
                // Skip missing blocks
                continue;
            };
            defer block.deinit(self.allocator);

            total_work += block.header.getWork();
        }

        return total_work;
    }

    /// Get block at specific height
    pub fn getBlockByHeight(self: *Self, height: u32) !Block {
        return self.chain_state.database.getBlock(height);
    }

    /// Calculate median time past for timestamp validation
    pub fn getMedianTimePast(self: *Self, height: u32) !u64 {
        // Need at least MTP_BLOCK_COUNT blocks for meaningful median
        if (height < types.TimestampValidation.MTP_BLOCK_COUNT) {
            // For early blocks, use genesis timestamp as baseline
            return types.Genesis.timestamp();
        }

        var timestamps = std.ArrayList(u64).init(self.allocator);
        defer timestamps.deinit();

        // Collect timestamps from last MTP_BLOCK_COUNT blocks
        const start_height = height - types.TimestampValidation.MTP_BLOCK_COUNT + 1;
        for (start_height..height + 1) |h| {
            var block = try self.chain_state.database.getBlock(@intCast(h));
            defer block.deinit(self.allocator);
            try timestamps.append(block.header.timestamp);
        }

        // Sort timestamps
        std.sort.heap(u64, timestamps.items, {}, comptime std.sort.asc(u64));

        // Return median (middle value for odd count)
        const median_index = timestamps.items.len / 2;
        return timestamps.items[median_index];
    }

    /// Calculate next difficulty target
    pub fn calculateNextDifficulty(self: *Self) !types.DifficultyTarget {
        const current_height = try self.getHeight();

        // For first adjustment period blocks, use initial difficulty
        if (current_height < types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD) {
            return types.ZenMining.initialDifficultyTarget();
        }

        // Only adjust every DIFFICULTY_ADJUSTMENT_PERIOD blocks
        if (current_height % types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD != 0) {
            // Not an adjustment block, use previous difficulty
            const prev_block_height: u32 = @intCast(current_height - 1);
            var prev_block = try self.chain_state.database.getBlock(prev_block_height);
            defer prev_block.deinit(self.allocator);
            return prev_block.header.getDifficultyTarget();
        }

        // This is an adjustment block! Calculate new difficulty
        log.info("📊 Difficulty adjustment at block {}", .{current_height});

        // Get timestamps from last adjustment period blocks for time calculation
        const lookback_blocks = types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD;
        var oldest_timestamp: u64 = 0;
        var newest_timestamp: u64 = 0;

        // Get timestamp from adjustment period blocks ago
        {
            const old_block_height: u32 = @intCast(current_height - lookback_blocks);
            var old_block = try self.chain_state.database.getBlock(old_block_height);
            defer old_block.deinit(self.allocator);
            oldest_timestamp = old_block.header.timestamp;
        }

        // Get timestamp from most recent block
        {
            const new_block_height: u32 = @intCast(current_height - 1);
            var new_block = try self.chain_state.database.getBlock(new_block_height);
            defer new_block.deinit(self.allocator);
            newest_timestamp = new_block.header.timestamp;
        }

        // Get current difficulty from previous block
        var prev_block = try self.chain_state.database.getBlock(current_height - 1);
        defer prev_block.deinit(self.allocator);
        const current_difficulty = prev_block.header.getDifficultyTarget();

        // Calculate actual time for last adjustment period blocks
        const actual_time = newest_timestamp - oldest_timestamp;
        const target_time = lookback_blocks * types.ZenMining.TARGET_BLOCK_TIME;

        // Calculate adjustment factor
        const adjustment_factor = if (actual_time > 0)
            @as(f64, @floatFromInt(target_time)) / @as(f64, @floatFromInt(actual_time))
        else
            1.0; // Fallback if time calculation fails

        // Apply adjustment with constraints
        const new_difficulty = current_difficulty.adjust(adjustment_factor, types.CURRENT_NETWORK);

        // Log the adjustment
        log.info("📈 Difficulty adjusted: factor={d:.3}, time={}s->{}s", .{ adjustment_factor, actual_time, target_time });

        return new_difficulty;
    }

    /// Estimate cumulative work for the chain up to given height
    pub fn estimateCumulativeWork(self: *Self, height: u32) !types.ChainWork {
        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.chain_state.database.getBlock(@intCast(h)) catch continue;
            defer block.deinit(self.allocator);
            total_work += block.header.getWork();
        }
        return total_work;
    }

    /// Add a validated block to the chain
    pub fn addBlockToChain(self: *Self, block: Block, height: u32) !void {
        // Process all transactions in the block
        try self.chain_state.processBlockTransactions(block.transactions, height, false);

        // Save block to database
        try self.chain_state.database.saveBlock(height, block);

        // Mature coinbase rewards if enough blocks have passed
        if (height >= types.COINBASE_MATURITY) {
            const maturity_height = height - types.COINBASE_MATURITY;
            try self.chain_state.matureCoinbaseRewards(maturity_height);
        }

        log.info("✅ Block #{} added to chain ({} txs)", .{ height, block.txCount() });
    }

    /// Accept a block during reorganization
    pub fn acceptBlock(self: *Self, block: Block) !void {
        const current_height = try self.getHeight();

        // Special case: if we're at height 0 and incoming block is not genesis
        const target_height = if (current_height == 0 and !self.isGenesisBlock(block)) blk: {
            log.info("🔄 Accepting non-genesis block after rollback - placing at height 1", .{});
            break :blk @as(u32, 1);
        } else current_height;

        // Validate using reorganization-specific validation
        if (!try self.chain_validator.validateReorgBlock(block, target_height)) {
            return error.BlockValidationFailed;
        }

        // Process transactions
        try self.chain_state.processBlockTransactions(block.transactions, target_height, false);

        // Save to database
        try self.chain_state.database.saveBlock(target_height, block);

        log.info("✅ Block accepted at height {}", .{target_height});
    }

    /// Apply a block (simpler version without validation)
    pub fn applyBlock(self: *Self, block: Block) !void {
        const block_height = try self.getHeight();

        // Process all transactions in the block
        try self.chain_state.processBlockTransactions(block.transactions, block_height, false);

        // Save block to database
        try self.chain_state.database.saveBlock(block_height, block);
    }

    /// Check if a block is a valid fork block
    pub fn isValidForkBlock(self: *Self, block: Block) !bool {
        const current_height = try self.getHeight();

        // Check if block's previous_hash matches any block in our chain
        for (0..current_height) |height| {
            var existing_block = self.chain_state.database.getBlock(@intCast(height)) catch continue;
            defer existing_block.deinit(self.allocator);

            const existing_hash = existing_block.hash();
            if (std.mem.eql(u8, &block.header.previous_hash, &existing_hash)) {
                log.info("🔗 Fork block builds on height {} (current tip: {})", .{ height, current_height - 1 });
                return true;
            }
        }

        return false;
    }

    /// Store a fork block and check for reorganization
    pub fn storeForkBlock(self: *Self, block: Block, fork_height: u32) !void {
        log.info("🔀 Storing fork block at height {}", .{fork_height});

        // Calculate cumulative work of the fork
        const fork_work = block.header.getWork();

        // Get current chain work at the same height
        const current_block = self.chain_state.database.getBlock(fork_height) catch |err| {
            log.info("❌ Cannot compare fork - missing block at height {}: {}", .{ fork_height, err });
            return;
        };
        defer current_block.deinit(self.allocator);

        const current_work = current_block.header.getWork();

        // Highest cumulative work rule: if fork has more work, reorganize
        if (fork_work > current_work) {
            log.info("🏆 Fork block has more work ({} vs {}) - triggering reorganization", .{ fork_work, current_work });
            log.warn("⚠️ storeForkBlock() called - reorganization should use ChainProcessor.executeBulkReorg()", .{});
        } else {
            log.info("📊 Fork block has less work ({} vs {}) - keeping current chain", .{ fork_work, current_work });
        }
    }

    /// Check if block is the genesis block
    fn isGenesisBlock(self: *Self, block: Block) bool {
        _ = self;
        return genesis.GenesisBlocks.TESTNET.getBlock().equals(&block);
    }
};
