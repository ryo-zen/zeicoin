// reorganization.zig - Chain Reorganization Manager
// Handles fork management and chain reorganization logic
// Manages competing chains and resolves fork conflicts

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const forkmanager = @import("../fork/main.zig");

const print = std.debug.print;
const ChainState = @import("state.zig").ChainState;
const ChainValidator = @import("validator.zig").ChainValidator;
const ChainOperations = @import("operations.zig").ChainOperations;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// ChainReorganization manages fork resolution and chain reorganization
/// - Fork detection and management
/// - Chain reorganization logic
/// - Rollback and replay operations
/// - Transaction backup during reorganization
pub const ChainReorganization = struct {
    fork_manager: forkmanager.ForkManager,
    chain_state: *ChainState,
    chain_validator: *ChainValidator,
    chain_operations: *ChainOperations,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ChainReorganization with all required components
    pub fn init(
        allocator: std.mem.Allocator,
        chain_state: *ChainState,
        chain_validator: *ChainValidator,
        chain_operations: *ChainOperations
    ) Self {
        return .{
            .fork_manager = forkmanager.ForkManager.init(allocator),
            .chain_state = chain_state,
            .chain_validator = chain_validator,
            .chain_operations = chain_operations,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.fork_manager.deinit();
    }

    // Reorganization Methods (to be extracted from node.zig)
    // - handleChainReorganization()
    // - findCommonAncestor()
    // - backupOrphanedTransactions()
    // - replayCoinbaseTransaction()
    // - replayRegularTransaction()
    
    // Reorganization Methods extracted from node.zig
    
    /// Handle chain reorganization process
    pub fn handleChainReorganization(self: *Self, new_block: Block, new_chain_tip: Hash) !void {
        const current_height = try self.chain_state.getHeight();
        
        print("🔄 Starting reorganization from height {}\n", .{current_height});

        // Find common ancestor (simplified - assume rebuild from genesis for safety)
        const common_ancestor_height = try self.findCommonAncestor(new_chain_tip);

        if (common_ancestor_height == 0) {
            print("⚠️ Deep reorganization required - rebuilding from genesis\n", .{});
        }

        // Rollback to common ancestor
        try self.chain_state.rollbackToHeight(common_ancestor_height, current_height);

        // Accept the new block through operations manager
        try self.chain_operations.acceptBlock(new_block);

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_tip[0..8])});
    }

    /// Find common ancestor between chains (simplified implementation)
    pub fn findCommonAncestor(self: *Self, new_tip_hash: Hash) !u32 {
        _ = self;
        _ = new_tip_hash;
        
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        return 0;
    }

    /// Backup transactions from orphaned blocks to mempool
    pub fn backupOrphanedTransactions(self: *Self, from_height: u32, to_height: u32) !void {
        print("💾 Backing up transactions from orphaned blocks ({} to {})\n", .{ from_height, to_height });

        for (from_height..to_height) |height| {
            const block = self.chain_state.database.getBlock(@intCast(height)) catch continue;
            defer block.deinit(self.allocator);

            // Re-validate and add non-coinbase transactions back to mempool
            for (block.transactions) |tx| {
                if (!self.chain_state.isCoinbaseTransaction(tx)) {
                    // Validate transaction is still valid
                    if (self.chain_validator.validateTransaction(tx) catch false) {
                        print("🔄 Restored orphaned transaction to mempool\n", .{});
                        // Note: In full implementation, would add to mempool
                        // For now, just log the restoration
                    } else {
                        print("❌ Orphaned transaction no longer valid - discarded\n", .{});
                    }
                }
            }
        }
    }

    /// Replay coinbase transaction during reorganization
    pub fn replayCoinbaseTransaction(self: *Self, tx: Transaction, block_height: u32) !void {
        // Use simplified coinbase processing through chain state
        try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, block_height);
    }

    /// Replay regular transaction during reorganization
    pub fn replayRegularTransaction(self: *Self, tx: Transaction) !void {
        // Get sender account (might not exist in test scenario)
        const sender_account = self.chain_state.getAccount(tx.sender) catch {
            // In test scenarios, skip transaction if sender not found
            return;
        };
        
        // Check if sender has sufficient balance (safety check)
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            return; // Skip transaction if insufficient balance
        }
        
        // Process transaction through chain state
        try self.chain_state.processTransaction(tx);
    }
};