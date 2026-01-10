const std = @import("std");
const types = @import("../types/types.zig");

// Forward declaration for blockchain dependency
const ZeiCoin = @import("../node.zig").ZeiCoin;
// Import the real chain validator
const RealChainValidator = @import("../chain/validator.zig").ChainValidator;

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
    real_validator: RealChainValidator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .real_validator = RealChainValidator.init(allocator, &blockchain.chain_state),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.real_validator.deinit();
    }
    
    pub fn validateBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.real_validator.validateBlock(block, expected_height);
    }
    
    pub fn validateSyncBlock(self: *Self, block: *const Block, expected_height: u32) !bool {
        return try self.real_validator.validateSyncBlock(block, expected_height);
    }
    
    pub fn validateReorgBlock(self: *Self, block: *const Block, expected_height: u32) !bool {
        return try self.real_validator.validateReorgBlock(block.*, expected_height);
    }
    
    pub fn validateTransaction(self: *Self, transaction: Transaction) !bool {
        return try self.real_validator.validateTransaction(transaction);
    }
    
    pub fn validateBlockStructure(self: *Self, block: Block) !bool {
        if (!block.isValid()) return false;

        const calculated_merkle = try block.calculateMerkleRoot(self.allocator);
        return std.mem.eql(u8, &block.header.merkle_root, &calculated_merkle);
    }
    
    // validateProofOfWork removed - use chain validator's validateBlockPoW instead
    // This ensures consistent RandomX validation across all code paths
};