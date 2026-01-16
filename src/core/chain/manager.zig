// manager.zig - Chain Manager Coordinator
// Main coordinator for all chain operations and components
// Provides high-level API for blockchain operations

const std = @import("std");
const log = std.log.scoped(.chain);
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const db = @import("../storage/db.zig");

// Import chain components
const ChainState = @import("state.zig").ChainState;
const ChainValidator = @import("validator.zig").ChainValidator;
const ChainOperations = @import("operations.zig").ChainOperations;
const Genesis = @import("genesis.zig");

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Address = types.Address;
const Hash = types.Hash;

/// Chain state information for external queries
pub const ChainStateInfo = struct {
    height: u32,
    total_work: u64,
    current_difficulty: u64,
    mempool_size: u32,
};

/// ChainManager coordinates all chain operations and components
/// - Owns and manages all chain-related components
/// - Provides high-level API for blockchain operations
/// - Handles component orchestration and dependency injection
/// - Abstracts complex chain operations behind simple interface
pub const ChainManager = struct {
    // Core components
    state: ChainState,
    validator: ChainValidator,
    operations: ChainOperations,

    // Resource management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ChainManager with database and allocator
    pub fn init(allocator: std.mem.Allocator, database: db.Database) !Self {
        // Initialize components in dependency order
        const state = ChainState.init(allocator, database);
        
        return .{
            .state = state,
            .validator = undefined, // Will be initialized below
            .operations = undefined, // Will be initialized below
            .allocator = allocator,
        };
    }

    /// Complete initialization after struct is created (to handle circular references)
    pub fn completeInit(self: *Self) !void {
        self.validator = ChainValidator.init(self.allocator, &self.state);
        self.operations = ChainOperations.init(self.allocator, &self.state, &self.validator);

        // Initialize block index from existing blockchain data
        self.state.initializeBlockIndex() catch |err| {
            log.info("⚠️ Failed to initialize block index: {} - O(1) lookups disabled", .{err});
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.operations.deinit();
        self.validator.deinit();
        self.state.deinit();
    }

    // High-Level Chain Operations API
    
    /// Apply a transaction to the blockchain state
    pub fn applyTransaction(self: *Self, transaction: Transaction) !void {
        // Validate transaction first
        if (!try self.validator.validateTransaction(transaction)) {
            return error.InvalidTransaction;
        }
        
        // Process transaction through state manager
        try self.state.processTransaction(transaction);
    }

    /// Validate and accept a block if valid
    pub fn validateAndAcceptBlock(self: *Self, block: Block) !bool {
        // Validate block structure and proof-of-work
        if (!try self.validator.validateBlock(block)) {
            return false;
        }
        
        // Accept block through operations manager
        try self.operations.acceptBlock(block);
        return true;
    }

    /// Apply a block to the blockchain (without validation)
    pub fn applyBlock(self: *Self, block: Block) !void {
        try self.operations.applyBlock(block);
    }

    /// Get current chain state information
    pub fn getChainState(self: *Self) !ChainStateInfo {
        return ChainStateInfo{
            .height = try self.operations.getHeight(),
            .total_work = try self.operations.calculateTotalWork(),
            .current_difficulty = try self.operations.calculateNextDifficulty(),
            .mempool_size = try self.getMempoolSize(),
        };
    }

    /// Get account balance
    pub fn getAccountBalance(self: *Self, address: Address) !u64 {
        return self.state.getBalance(address);
    }

    /// Get current chain height
    pub fn getChainHeight(self: *Self) !u32 {
        return self.operations.getHeight();
    }

    /// Get block at specific height
    pub fn getBlockAtHeight(self: *Self, height: u32) !Block {
        return self.operations.getBlockByHeight(height);
    }


    /// Get current mempool size
    fn getMempoolSize(self: *Self) !usize {
        // ChainManager doesn't have direct access to mempool
        // This would need to be provided through dependency injection
        _ = self;
        return 0;
    }

    /// Initialize blockchain with genesis block
    pub fn initializeWithGenesis(self: *Self, network: types.Network) !void {
        // Use the Genesis component to create and save genesis block
        const genesis = @import("genesis.zig");
        const genesis_block = try genesis.createGenesis(self.allocator);
        defer genesis_block.deinit(self.allocator);
        
        // Save genesis block at height 0  
        try self.state.database.saveBlock(0, genesis_block);
        
        // Process genesis transactions - force processing as this is initialization
        try self.state.processBlockTransactions(genesis_block.transactions, 0, true);
        
        log.info("✅ Genesis block initialized for network {}", .{network});
    }
};