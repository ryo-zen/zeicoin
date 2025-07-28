// chain_manager.zig - Next-Generation ZeiCoin Chain Manager
// Zero backward compatibility constraints - optimized for correctness and performance

const std = @import("std");
const print = std.debug.print;

// ZeiCoin core imports
const types = @import("../types/types.zig");
const work_mod = @import("work.zig");
const BlockIndexManager = @import("block_index.zig").BlockIndexManager;
const BlockIndex = @import("block_index.zig").BlockIndex;
const BlockStatus = @import("block_index.zig").BlockStatus;
const AtomicReorgManager = @import("atomic_reorg.zig").AtomicReorgManager;
const ReorgResult = @import("atomic_reorg.zig").ReorgResult;

// External dependencies
const db = @import("../storage/db.zig");
const genesis = @import("../chain/genesis.zig");

/// Chain validation errors
pub const ChainError = error{
    InvalidBlock,
    InvalidTransaction,
    OrphanBlock,
    DuplicateBlock,
    ChainWorkOverflow,
    ReorganizationFailed,
    GenesisValidationFailed,
    InsufficientWork,
    ConsensusFailure,
};

/// Chain manager statistics for monitoring
pub const ChainStats = struct {
    height: u32,
    total_work: work_mod.ChainWork,
    active_tips: u32,
    total_blocks: u32,
    orphan_blocks: u32,
    reorg_count: u32,
    last_reorg_depth: u32,
};

/// Next-generation chain manager with consensus
pub const ChainManager = struct {
    // Core consensus engine
    block_index: BlockIndexManager,
    atomic_reorg: AtomicReorgManager,

    // Block storage and validation
    database: *db.Database,
    validator: ?*@import("../chain/validator.zig").ChainValidator, // Optional for testing

    // State management
    account_state: std.HashMap(types.Address, types.Account, std.hash_map.DefaultContext(types.Address), std.hash_map.default_max_load_percentage),
    genesis_block: ?types.Block,

    // Statistics tracking
    stats: ChainStats,
    reorg_count: u32,

    // Memory management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize next-generation chain manager
    pub fn init(allocator: std.mem.Allocator, database: *db.Database) Self {
        var result = Self{
            .block_index = BlockIndexManager.init(allocator),
            .atomic_reorg = undefined, // Will be initialized below
            .database = database,
            .validator = null, // Will be set separately to avoid circular deps
            .account_state = std.HashMap(types.Address, types.Account, std.hash_map.DefaultContext(types.Address), std.hash_map.default_max_load_percentage).init(allocator),
            .genesis_block = null,
            .stats = ChainStats{
                .height = 0,
                .total_work = 0,
                .active_tips = 0,
                .total_blocks = 0,
                .orphan_blocks = 0,
                .reorg_count = 0,
                .last_reorg_depth = 0,
            },
            .reorg_count = 0,
            .allocator = allocator,
        };

        // Initialize atomic reorg manager with pointer to block index
        result.atomic_reorg = AtomicReorgManager.init(allocator, &result.block_index);

        return result;
    }

    /// Cleanup chain manager resources
    pub fn deinit(self: *Self) void {
        self.block_index.deinit();
        self.account_state.deinit();
        if (self.genesis_block) |*genesis_blk| {
            _ = genesis_blk; // Block doesn't need explicit deinit for now
        }
    }

    /// Set validator (called after initialization to avoid circular dependencies)
    pub fn setValidator(self: *Self, validator: *@import("../chain/validator.zig").ChainValidator) void {
        self.validator = validator;
    }

    /// Initialize blockchain with genesis block
    pub fn initializeGenesis(self: *Self, network: types.Network) !void {
        print("🚀 Initializing ZeiCoin genesis for network: {}\n", .{network});

        // Create genesis block
        const genesis_block = try genesis.createGenesis(self.allocator);
        self.genesis_block = genesis_block;

        // Calculate genesis hash
        const genesis_hash = genesis_block.hash();

        // Add genesis to block index (height 0, no parent)
        const genesis_index = try self.block_index.addBlock(genesis_hash, genesis_block.header, 0);

        // Mark genesis as fully validated
        genesis_index.markFullyValid();

        // Process genesis transactions to initialize accounts
        try self.processGenesisTransactions(genesis_block);

        // Update statistics
        self.updateStats();

        print("✅ Genesis initialized: height=0, work={}, accounts={}\n", .{ genesis_index.chain_work, self.account_state.count() });
    }

    /// Process a new block from the network
    /// This is the main entry point for consensus decisions
    pub fn processBlock(self: *Self, block: types.Block) !BlockAcceptanceResult {
        const block_hash = block.hash();

        print("🔍 Processing block: height={}, hash={s}\n", .{ self.getHeightForBlock(block), std.fmt.fmtSliceHexLower(block_hash[0..8]) });

        // Step 1: Check if we already have this block
        if (self.block_index.getBlockByHash(block_hash) != null) {
            return BlockAcceptanceResult{ .duplicate = {} };
        }

        // Step 2: Determine block height and find parent
        const height = self.getHeightForBlock(block);
        const parent_index = self.block_index.getBlockByHash(block.header.previous_hash);

        // Step 3: Check for orphan blocks
        if (height > 0 and parent_index == null) {
            print("⚠️ Orphan block detected (parent not found)\n", .{});
            return BlockAcceptanceResult{ .orphan = {} };
        }

        // Step 4: Validate block structure and proof-of-work
        if (self.validator) |validator| {
            if (!try validator.validateBlock(block, height)) {
                print("❌ Block validation failed\n", .{});
                return BlockAcceptanceResult{ .invalid = ChainError.InvalidBlock };
            }
        }

        // Step 5: Add to block index and check for chain reorganization
        const block_index = try self.block_index.addBlock(block_hash, block.header, height);

        // Step 6: Determine consensus action
        const active_tip = self.block_index.getActiveTip() orelse {
            return BlockAcceptanceResult{ .invalid = ChainError.ConsensusFailure };
        };

        if (block_index == active_tip) {
            // This block extends or creates the new best chain
            const old_tip = self.getPreviousActiveTip();

            if (parent_index != null and parent_index.? == old_tip) {
                // Simple chain extension - no reorganization needed
                try self.activateNewChain(block_index, block);
                print("✅ Block extends active chain\n", .{});
                return BlockAcceptanceResult{ .accepted = .chain_extension };
            } else {
                // Chain reorganization required - use atomic reorganization
                print("🔄 Chain reorganization triggered - using atomic reorg\n", .{});

                if (old_tip) |old_tip_index| {
                    const reorg_result = try self.atomic_reorg.performReorganization(old_tip_index, block_index);

                    switch (reorg_result) {
                        .success => |stats| {
                            print("✅ Atomic reorganization completed: {} blocks disconnected, {} connected\n", .{ stats.blocks_disconnected, stats.blocks_connected });
                            self.reorg_count += 1;
                            self.stats.last_reorg_depth = stats.reorg_depth;

                            // Apply the new chain state
                            try self.activateNewChain(block_index, block);
                            return BlockAcceptanceResult{ .accepted = .reorganization };
                        },
                        .failed => |err| {
                            print("❌ Atomic reorganization failed: {}\n", .{err});
                            return BlockAcceptanceResult{ .invalid = ChainError.ReorganizationFailed };
                        },
                        .no_action => {
                            print("ℹ️ No reorganization needed\n", .{});
                            try self.activateNewChain(block_index, block);
                            return BlockAcceptanceResult{ .accepted = .chain_extension };
                        },
                    }
                } else {
                    // No previous tip - this is likely genesis or first block
                    try self.activateNewChain(block_index, block);
                    return BlockAcceptanceResult{ .accepted = .chain_extension };
                }
            }
        } else {
            // Block added to side chain
            print("🔗 Block added to alternative chain\n", .{});
            return BlockAcceptanceResult{ .accepted = .side_chain };
        }
    }

    /// Get current chain height
    pub fn getHeight(self: *const Self) u32 {
        if (self.block_index.getActiveTip()) |tip| {
            return tip.height;
        }
        return 0;
    }

    /// Get current chain work
    pub fn getTotalWork(self: *const Self) work_mod.ChainWork {
        if (self.block_index.getActiveTip()) |tip| {
            return tip.chain_work;
        }
        return 0;
    }

    /// Get block by height (O(1) for active chain)
    pub fn getBlockByHeight(self: *Self, height: u32) ?*BlockIndex {
        return self.block_index.getBlockByHeight(height);
    }

    /// Get block by hash (O(1))
    pub fn getBlockByHash(self: *Self, hash: types.Hash) ?*BlockIndex {
        return self.block_index.getBlockByHash(hash);
    }

    /// Get account balance (O(1))
    pub fn getAccountBalance(self: *const Self, address: types.Address) u64 {
        if (self.account_state.get(address)) |account| {
            return account.balance;
        }
        return 0;
    }

    /// Get chain statistics
    pub fn getStats(self: *const Self) ChainStats {
        return self.stats;
    }

    /// Validate chain consistency (for debugging)
    pub fn validateChainConsistency(self: *const Self) bool {
        return self.block_index.validateIndex();
    }

    // Private helper methods

    /// Process genesis transactions to initialize account state
    fn processGenesisTransactions(self: *Self, genesis_block: types.Block) !void {
        for (genesis_block.transactions) |tx| {
            // Genesis transactions are special - they create initial balances
            if (!tx.recipient.isZero()) {
                const account = types.Account{
                    .balance = tx.amount,
                    .nonce = 0,
                };
                try self.account_state.put(tx.recipient, account);
            }
        }
    }

    /// Get height for a block based on its parent
    fn getHeightForBlock(self: *const Self, block: types.Block) u32 {
        if (std.mem.eql(u8, &block.header.previous_hash, &std.mem.zeroes(types.Hash))) {
            return 0; // Genesis block
        }

        if (self.block_index.getBlockByHash(block.header.previous_hash)) |parent| {
            return parent.height + 1;
        }

        // Parent not found - this will be handled as orphan
        return 0;
    }

    /// Activate new chain (apply state changes)
    fn activateNewChain(self: *Self, new_tip: *BlockIndex, block: types.Block) !void {
        // Mark block as fully validated and applied
        new_tip.markFullyValid();
        new_tip.status.applied = true;

        // Process block transactions (simplified for now)
        // In a full implementation, this would apply all state changes
        for (block.transactions, 0..) |tx, i| {
            if (i == 0) continue; // Skip coinbase

            // Apply transaction (simplified)
            try self.applyTransaction(tx);
        }

        // Update statistics
        self.updateStats();
    }

    /// Apply a transaction to account state
    fn applyTransaction(self: *Self, tx: types.Transaction) !void {
        // Get sender account
        var sender = self.account_state.get(tx.sender) orelse types.Account{ .balance = 0, .nonce = 0 };

        // Get recipient account
        var recipient = self.account_state.get(tx.recipient) orelse types.Account{ .balance = 0, .nonce = 0 };

        // Apply transaction
        sender.balance -= (tx.amount + tx.fee);
        sender.nonce += 1;
        recipient.balance += tx.amount;

        // Update accounts
        try self.account_state.put(tx.sender, sender);
        try self.account_state.put(tx.recipient, recipient);
    }

    /// Update chain statistics
    fn updateStats(self: *Self) void {
        const active_tip = self.block_index.getActiveTip();

        self.stats = ChainStats{
            .height = if (active_tip) |tip| tip.height else 0,
            .total_work = if (active_tip) |tip| tip.chain_work else 0,
            .active_tips = @intCast(self.block_index.getTips().len),
            .total_blocks = @intCast(self.block_index.height_index.items.len),
            .orphan_blocks = 0, // TODO: implement orphan tracking
            .reorg_count = self.reorg_count,
            .last_reorg_depth = 0, // TODO: track last reorg depth
        };
    }

    /// Get previous active tip (for reorg detection)
    fn getPreviousActiveTip(_: *const Self) ?*BlockIndex {
        // This would be stored from previous state
        // For now, simplified implementation
        return null;
    }
};

/// Result of processing a block
pub const BlockAcceptanceResult = union(enum) {
    /// Block was accepted and applied
    accepted: AcceptanceType,
    /// Block is invalid and rejected
    invalid: ChainError,
    /// Block is an orphan (parent not found)
    orphan: void,
    /// Block is a duplicate (already processed)
    duplicate: void,
};

/// Type of block acceptance
pub const AcceptanceType = enum {
    /// Block extends the current active chain
    chain_extension,
    /// Block triggered a chain reorganization
    reorganization,
    /// Block added to a side chain (not active)
    side_chain,
};

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

const testing = std.testing;

test "chain manager initialization" {
    var database = db.Database.init(testing.allocator, ":memory:");
    defer database.deinit();

    var chain_manager = ChainManager.init(testing.allocator, &database);
    defer chain_manager.deinit();

    // Test initial state
    try testing.expect(chain_manager.getHeight() == 0);
    try testing.expect(chain_manager.getTotalWork() == 0);

    const stats = chain_manager.getStats();
    try testing.expect(stats.height == 0);
    try testing.expect(stats.total_blocks == 0);
}

test "genesis initialization" {
    var database = db.Database.init(testing.allocator, ":memory:");
    defer database.deinit();

    var chain_manager = ChainManager.init(testing.allocator, &database);
    defer chain_manager.deinit();

    // Initialize genesis
    try chain_manager.initializeGenesis(types.Network.TestNet);

    // Verify genesis state
    try testing.expect(chain_manager.getHeight() == 0);
    try testing.expect(chain_manager.getTotalWork() > 0);

    const stats = chain_manager.getStats();
    try testing.expect(stats.height == 0);
    try testing.expect(stats.total_blocks == 1);
}

test "block processing basic flow" {
    var database = db.Database.init(testing.allocator, ":memory:");
    defer database.deinit();

    var chain_manager = ChainManager.init(testing.allocator, &database);
    defer chain_manager.deinit();

    // Initialize genesis
    try chain_manager.initializeGenesis(types.Network.TestNet);

    // Create a simple block
    const genesis_hash = chain_manager.genesis_block.?.hash();
    const block1_header = types.BlockHeader{
        .version = 1,
        .previous_hash = genesis_hash,
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 2000,
        .difficulty = 0x1d00ffff,
        .nonce = 123,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };

    const block1 = types.Block{
        .header = block1_header,
        .transactions = &[_]types.Transaction{},
    };

    // Process block (will be orphan without validator)
    const result = try chain_manager.processBlock(block1);

    // Should be orphan or invalid without proper validation
    try testing.expect(result == .orphan or result == .invalid);
}

test "chain statistics tracking" {
    var database = db.Database.init(testing.allocator, ":memory:");
    defer database.deinit();

    var chain_manager = ChainManager.init(testing.allocator, &database);
    defer chain_manager.deinit();

    // Test initial stats
    var stats = chain_manager.getStats();
    try testing.expect(stats.height == 0);
    try testing.expect(stats.total_work == 0);
    try testing.expect(stats.active_tips == 0);

    // Initialize genesis and check stats
    try chain_manager.initializeGenesis(types.Network.TestNet);

    stats = chain_manager.getStats();
    try testing.expect(stats.height == 0); // Genesis is height 0
    try testing.expect(stats.total_work > 0);
    try testing.expect(stats.active_tips == 1); // Genesis is the only tip
}

test "chain consistency validation" {
    var database = db.Database.init(testing.allocator, ":memory:");
    defer database.deinit();

    var chain_manager = ChainManager.init(testing.allocator, &database);
    defer chain_manager.deinit();

    // Should be consistent initially
    try testing.expect(chain_manager.validateChainConsistency());

    // Should still be consistent after genesis
    try chain_manager.initializeGenesis(types.Network.TestNet);
    try testing.expect(chain_manager.validateChainConsistency());
}
