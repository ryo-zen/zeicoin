const std = @import("std");
const types = @import("../types/types.zig");

// Forward declaration for blockchain dependency
const ZeiCoin = @import("../node.zig").ZeiCoin;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// Chain Validator - Handles all validation logic for blocks and transactions
/// Provides different validation modes for different contexts (sync, reorg, normal)
pub const ChainValidator = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
        };
    }
    
    pub fn deinit(self: *Self) void {
        _ = self;
    }
    
    pub fn validateBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.blockchain.chain_validator.validateBlock(block, expected_height);
    }
    
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.blockchain.chain_validator.validateSyncBlock(block, expected_height);
    }
    
    pub fn validateReorgBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.validateSyncBlock(block, expected_height);
    }
    
    pub fn validateTransaction(self: *Self, transaction: Transaction) !bool {
        return try self.blockchain.chain_validator.validateTransaction(transaction);
    }
    
    pub fn validateBlockStructure(self: *Self, block: Block) !bool {
        _ = self;
        if (!block.isValid()) return false;
        
        const calculated_merkle = block.calculateMerkleRoot();
        return std.mem.eql(u8, &block.header.merkle_root, &calculated_merkle);
    }
    
    pub fn validateProofOfWork(self: *Self, header: BlockHeader, expected_difficulty: u64) !bool {
        _ = self;
        const miner_validation = @import("../miner/validation.zig");
        
        if (@import("builtin").mode == .Debug) {
            return miner_validation.validateBlockHashSHA256(header, expected_difficulty);
        } else {
            return miner_validation.validateBlockHashRandomX(header, expected_difficulty);
        }
    }
};