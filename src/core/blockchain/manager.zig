// BlockchainManager - Coordinates core blockchain operations
// Handles the high-level blockchain coordination between components

const std = @import("std");
const types = @import("../types/types.zig");
const ChainQuery = @import("../chain/query.zig").ChainQuery;
const ChainProcessor = @import("../chain/processor.zig").ChainProcessor;
const DifficultyCalculator = @import("../chain/difficulty.zig").DifficultyCalculator;
const ChainState = @import("../chain/state.zig").ChainState;
const Database = @import("../storage/db.zig").Database;

const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Address = types.Address;
const Account = types.Account;

pub const BlockchainManager = struct {
    allocator: std.mem.Allocator,
    chain_query: *ChainQuery,
    chain_processor: *ChainProcessor,
    difficulty_calculator: *DifficultyCalculator,
    chain_state: *ChainState,
    database: *Database,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        database: *Database,
        chain_state: *ChainState,
        chain_query: *ChainQuery,
        chain_processor: *ChainProcessor,
        difficulty_calculator: *DifficultyCalculator,
    ) Self {
        return .{
            .allocator = allocator,
            .chain_query = chain_query,
            .chain_processor = chain_processor,
            .difficulty_calculator = difficulty_calculator,
            .chain_state = chain_state,
            .database = database,
        };
    }
    
    pub fn deinit(self: *Self) void {
        _ = self;
        // Components are owned by Node, just cleanup any local state
    }
    
    /// Get current blockchain height
    pub fn getHeight(self: *Self) !u32 {
        return try self.chain_query.getHeight();
    }
    
    /// Get block by height
    pub fn getBlock(self: *Self, height: u32) !Block {
        return try self.chain_query.getBlock(height);
    }
    
    /// Get block by height (alias for compatibility)
    pub fn getBlockByHeight(self: *Self, height: u32) !Block {
        return try self.getBlock(height);
    }
    
    /// Get account information
    pub fn getAccount(self: *Self, address: Address) !Account {
        return try self.chain_query.getAccount(address);
    }
    
    /// Add a block to the blockchain
    pub fn addBlockToChain(self: *Self, block: Block, height: u32) !void {
        return try self.chain_processor.addBlockToChain(block, height);
    }
    
    /// Apply a block to the blockchain
    pub fn applyBlock(self: *Self, block: Block) !void {
        return try self.chain_processor.applyBlock(block);
    }
    
    /// Calculate next difficulty for mining
    pub fn calculateNextDifficulty(self: *Self) !types.DifficultyTarget {
        return try self.difficulty_calculator.calculateNextDifficulty();
    }
    
    /// Get block headers for a range
    pub fn getHeadersRange(self: *Self, start_height: u32, count: u32) ![]BlockHeader {
        return try self.chain_query.getHeadersRange(start_height, count);
    }
    
    /// Get median time past for a height
    pub fn getMedianTimePast(self: *Self, height: u32) !u64 {
        return try self.chain_query.getMedianTimePast(height);
    }
    
    /// Check if blockchain has a specific transaction
    pub fn hasTransaction(self: *Self, hash: [32]u8) bool {
        return self.chain_query.hasTransaction(hash);
    }
    
    /// Get cumulative work for the current chain
    pub fn getTotalWork(self: *Self) !types.ChainWork {
        const current_height = try self.database.getHeight();
        
        // For now, return a basic work calculation
        // In production, this would sum up all the block difficulties
        return @as(types.ChainWork, current_height);
    }
    
    /// Validate database integrity
    pub fn validateDatabase(self: *Self) bool {
        return self.database.validate();
    }
};