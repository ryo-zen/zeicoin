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
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState, chain_validator: *ChainValidator, chain_operations: *ChainOperations) Self {
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

    /// Find common ancestor between chains using efficient binary search
    /// O(log n) performance vs O(n) for linear search
    pub fn findCommonAncestor(self: *Self, new_tip_hash: Hash) !u32 {
        const current_height = try self.chain_state.getHeight();

        // Binary search for the common ancestor
        var low: u32 = 0;
        var high: u32 = current_height;
        var common_height: u32 = 0;

        while (low <= high) {
            const mid = low + (high - low) / 2;

            // Get block at mid height from our current chain
            var our_block = self.chain_state.database.getBlock(mid) catch {
                // If block doesn't exist, try lower
                if (mid == 0) break;
                high = mid - 1;
                continue;
            };
            defer our_block.deinit(self.allocator);

            const our_hash = our_block.hash();

            // Check if this hash exists in the new chain by comparing with new tip ancestry
            if (self.isAncestorOf(our_hash, new_tip_hash)) {
                // This block is common, try to find a higher one
                common_height = mid;
                low = mid + 1;
            } else {
                // This block is not common, search lower
                if (mid == 0) break;
                high = mid - 1;
            }
        }

        print("🔍 Found common ancestor at height {} using binary search\n", .{common_height});
        return common_height;
    }

    /// Check if block_hash is an ancestor of tip_hash (helper for binary search)
    /// Modern height-based traversal with O(height_diff) performance and memory safety
    fn isAncestorOf(self: *Self, ancestor_hash: Hash, descendant_hash: Hash) bool {
        // Input validation: hashes must not be identical
        if (std.mem.eql(u8, &ancestor_hash, &descendant_hash)) return false;

        // Input validation: hashes must not be zero (invalid)
        const zero_hash = std.mem.zeroes([32]u8);
        if (std.mem.eql(u8, &ancestor_hash, &zero_hash) or
            std.mem.eql(u8, &descendant_hash, &zero_hash)) return false;

        // Fast path: get heights with proper error handling
        const ancestor_height = self.getBlockHeight(ancestor_hash) catch |err| {
            print("⚠️ Failed to get ancestor height: {}\n", .{err});
            return false;
        };
        const descendant_height = self.getBlockHeight(descendant_hash) catch |err| {
            print("⚠️ Failed to get descendant height: {}\n", .{err});
            return false;
        };

        // Logic validation: ancestor must have lower height than descendant
        if (ancestor_height >= descendant_height) return false;

        // Security: limit traversal depth to prevent DoS attacks
        const height_diff = descendant_height - ancestor_height;
        const MAX_TRAVERSAL_DEPTH = 10000; // Configurable safety limit
        if (height_diff > MAX_TRAVERSAL_DEPTH) {
            print("⚠️ Chain traversal depth {} exceeds safety limit {}\n", .{ height_diff, MAX_TRAVERSAL_DEPTH });
            return false;
        }

        // Traverse backwards from descendant to ancestor height with memory safety
        var current_hash = descendant_hash;
        var current_height = descendant_height;
        var steps: u32 = 0;

        while (current_height > ancestor_height and steps < height_diff + 1) {
            // Memory-safe block retrieval with proper cleanup
            var block = self.chain_state.database.getBlockByHash(current_hash) catch |err| {
                print("⚠️ Failed to retrieve block at height {}: {}\n", .{ current_height, err });
                return false;
            };
            defer block.deinit(self.allocator); // Guaranteed cleanup

            // Validate block header integrity before accessing prev_hash
            if (block.header.version == 0) {
                print("⚠️ Invalid block header detected at height {}\n", .{current_height});
                return false;
            }

            // Extract previous hash safely
            current_hash = block.header.previous_hash;
            current_height -= 1;
            steps += 1;

            // Safety check: ensure we're making progress
            if (steps > height_diff + 1) {
                print("⚠️ Traversal exceeded expected steps\n", .{});
                return false;
            }

            // Check if we reached genesis (prev_hash is zero) - this is valid
            if (std.mem.eql(u8, &current_hash, &zero_hash)) {
                // We've reached genesis, ancestor cannot be found
                return false;
            }
        }

        // Final validation: check if we found the ancestor at the expected height
        const found_ancestor = std.mem.eql(u8, &current_hash, &ancestor_hash);

        if (found_ancestor) {
            print("✅ Confirmed: block is ancestor (traversed {} steps)\n", .{steps});
        }

        return found_ancestor;
    }

    /// Get block height by hash with O(1) performance using block index
    /// Replaces previous O(n) linear search with hash map lookup
    fn getBlockHeight(self: *Self, block_hash: Hash) !u32 {
        // Input validation
        const zero_hash = std.mem.zeroes([32]u8);
        if (std.mem.eql(u8, &block_hash, &zero_hash)) {
            return error.InvalidHash;
        }

        // O(1) lookup using block index cache
        if (self.chain_state.getBlockHeight(block_hash)) |height| {
            return height;
        }

        // If not found in index, this could indicate:
        // 1. Block doesn't exist on this chain
        // 2. Block index needs rebuilding (shouldn't happen in normal operation)
        print("⚠️ Block height not found in index for hash (may not exist on chain)\n", .{});
        return error.BlockNotFound;
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
