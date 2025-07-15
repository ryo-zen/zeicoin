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
    // Reference to parent for network broadcasting
    network_callback: ?*const fn(block: types.Block) void = null,
    
    pub fn init(
        allocator: std.mem.Allocator, 
        database: *db.Database,
        chain_state: *ChainState,
        fork_manager: *ForkManager,
        chain_validator: *ChainValidator,
    ) ChainProcessor {
        return .{
            .allocator = allocator,
            .database = database,
            .chain_state = chain_state,
            .fork_manager = fork_manager,
            .chain_validator = chain_validator,
        };
    }
    
    pub fn deinit(self: *ChainProcessor) void {
        _ = self;
    }
    
    pub fn setNetworkCallback(self: *ChainProcessor, callback: *const fn(block: types.Block) void) void {
        self.network_callback = callback;
    }
    
    /// Apply a valid block to the blockchain
    pub fn addBlockToChain(self: *ChainProcessor, block: types.Block, height: u32) !void {
        // Process all transactions in the block
        try self.processBlockTransactions(block.transactions);

        // Save block to database
        try self.database.saveBlock(height, block);
        
        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(height, block_hash);
        
        // Mature any coinbase rewards that have reached 100 confirmations
        try self.matureCoinbaseRewards(height);

        // Remove processed transactions from mempool
        self.cleanMempool(block);

        // Update fork manager with the new best chain
        const new_cumulative_work = self.estimateCumulativeWork(height) catch 0;
        self.fork_manager.updateBestChain(&block, height, new_cumulative_work);

        print("✅ Block #{} added to chain ({} txs)\n", .{height, block.txCount()});
    }
    
    /// Apply a valid block to the blockchain (internal)
    pub fn applyBlock(self: *ChainProcessor, block: types.Block) !void {
        // Process all transactions in the block
        try self.processBlockTransactions(block.transactions);

        // Save block to database
        const block_height = try self.database.getHeight();
        try self.database.saveBlock(block_height, block);
        
        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(block_height, block_hash);
        
        // Mature any coinbase rewards that have reached 100 confirmations
        try self.matureCoinbaseRewards(block_height);

        // Remove processed transactions from mempool
        self.cleanMempool(block);
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
        try self.processBlockTransactions(block.transactions);

        // Save to database
        try self.database.saveBlock(target_height, block);
        
        // Update block index for O(1) lookups in reorganizations
        const block_hash = block.hash();
        try self.chain_state.indexBlock(target_height, block_hash);

        print("✅ Block accepted at height {}\n", .{target_height});

        // Broadcast to network if callback is set
        if (self.network_callback) |callback| {
            util.logSuccess("🚀 Broadcasting newly mined block #{} to P2P network", .{target_height});
            callback(block);
        } else {
            util.logInfo("💭 No network connected, block not broadcast", .{});
        }
    }
    
    fn processBlockTransactions(self: *ChainProcessor, transactions: []const types.Transaction) !void {
        for (transactions) |tx| {
            if (tx.isCoinbase()) {
                try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, 0);
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
        // TODO: Clean mempool of transactions that were included in this block
        // This should be handled by the node coordinator that has access to mempool
        _ = self;
        _ = block;
        print("🧹 Block processed, mempool cleanup delegated to coordinator\n", .{});
    }
    
    fn estimateCumulativeWork(self: *ChainProcessor, height: u32) !types.ChainWork {
        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(@intCast(h)) catch continue;
            defer block.deinit(self.allocator);
            total_work += block.header.getWork();
        }
        return total_work;
    }
};