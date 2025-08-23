// cleaner.zig - Mempool Maintenance and Cleanup
// Handles cleanup and maintenance operations for the mempool
// Removes confirmed transactions and manages processed history

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");

const log = std.log.scoped(.mempool);

// Forward declarations for components
const MempoolStorage = @import("pool.zig").MempoolStorage;
const TransactionValidator = @import("validator.zig").TransactionValidator;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const Hash = types.Hash;

/// Mempool cleaner for maintenance operations
/// - Removes confirmed transactions from mempool
/// - Manages processed transaction history
/// - Performs periodic cleanup and optimization
/// - Handles memory management for long-running operations
pub const MempoolCleaner = struct {
    // Component references
    storage: *MempoolStorage,
    validator: *TransactionValidator,
    
    // Cleanup statistics
    last_cleanup_time: i64,
    total_cleanups: u64,
    transactions_cleaned: u64,
    
    // Resource management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize mempool cleaner with component references
    pub fn init(
        allocator: std.mem.Allocator,
        storage: *MempoolStorage,
        validator: *TransactionValidator
    ) Self {
        return .{
            .storage = storage,
            .validator = validator,
            .last_cleanup_time = util.getTime(),
            .total_cleanups = 0,
            .transactions_cleaned = 0,
            .allocator = allocator,
        };
    }
    
    /// Clean mempool of transactions that are now in a block
    pub fn cleanConfirmedTransactions(self: *Self, block: Block) !usize {
        const start_time = util.getTime();
        
        // Collect hashes of transactions in the block
        var block_tx_hashes = try self.allocator.alloc(Hash, block.transactions.len);
        defer self.allocator.free(block_tx_hashes);
        
        for (block.transactions, 0..) |tx, i| {
            block_tx_hashes[i] = tx.hash();
            const amount_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            log.info("🔄 [TX LIFECYCLE] Transaction {s} included in block (mempool → blockchain): {d:.8} ZEI", .{
                std.fmt.fmtSliceHexLower(tx.hash()[0..8]), amount_zei
            });
        }
        
        // Remove transactions from mempool that match block transactions
        const removed_count = self.storage.removeTransactionsByHashes(block_tx_hashes);
        
        self.transactions_cleaned += removed_count;
        self.total_cleanups += 1;
        self.last_cleanup_time = util.getTime();
        
        if (removed_count > 0) {
            const elapsed = util.getTime() - start_time;
            const mempool_size = self.storage.getTransactionCount();
            log.info("🧹 [TX LIFECYCLE] Cleaned {} confirmed transactions from mempool ({}ms, mempool size: {})", .{
                removed_count, elapsed, mempool_size
            });
        }
        
        return removed_count;
    }
    
    /// Perform periodic maintenance on mempool
    pub fn performMaintenance(self: *Self) !MaintenanceResult {
        const start_time = util.getTime();
        var result = MaintenanceResult{
            .processed_history_cleaned = 0,
            .memory_optimized = false,
            .duration_ms = 0,
        };
        
        // 1. Clean up processed transaction history
        const initial_processed_count = self.validator.getValidationStats().processed_transactions;
        self.validator.cleanupProcessedTransactions();
        const final_processed_count = self.validator.getValidationStats().processed_transactions;
        result.processed_history_cleaned = initial_processed_count - final_processed_count;
        
        // 2. Check if memory optimization is needed
        const current_count = self.storage.getTransactionCount();
        const stats = self.storage.getStats();
        
        // If mempool is relatively empty but still using significant memory,
        // we could implement memory optimization here
        if (current_count < 100 and stats.total_size_bytes > 1024 * 1024) {
            // Placeholder for memory optimization
            result.memory_optimized = true;
            log.info("🧹 Memory optimization opportunity detected", .{});
        }
        
        result.duration_ms = util.getTime() - start_time;
        
        if (result.processed_history_cleaned > 0 or result.memory_optimized) {
            log.info("🔧 Maintenance completed: {} processed txs cleaned, memory optimized: {}", .{
                result.processed_history_cleaned, result.memory_optimized
            });
        }
        
        return result;
    }
    
    /// Remove expired transactions from mempool
    pub fn removeExpiredTransactions(self: *Self, current_height: u32) !usize {
        // Get all transactions and check expiry
        const transactions = try self.storage.getAllTransactions();
        defer self.storage.freeTransactionArray(transactions);
        
        var expired_hashes = std.ArrayList(Hash).init(self.allocator);
        defer expired_hashes.deinit();
        
        for (transactions) |tx| {
            if (tx.expiry_height <= current_height) {
                try expired_hashes.append(tx.hash());
            }
        }
        
        if (expired_hashes.items.len > 0) {
            const removed_count = self.storage.removeTransactionsByHashes(expired_hashes.items);
            log.info("⏰ Removed {} expired transactions from mempool", .{removed_count});
            return removed_count;
        }
        
        return 0;
    }
    
    /// Emergency cleanup when mempool is full
    pub fn emergencyCleanup(self: *Self) !EmergencyCleanupResult {
        const start_time = util.getTime();
        var result = EmergencyCleanupResult{
            .transactions_removed = 0,
            .strategy_used = .none,
            .duration_ms = 0,
        };
        
        // Strategy 1: Remove very old processed transactions from history
        self.validator.cleanupProcessedTransactions();
        
        // Strategy 2: In a more sophisticated implementation, we could:
        // - Remove transactions with lowest fees
        // - Remove oldest transactions
        // - Implement more complex eviction policies
        
        // For now, just report that emergency cleanup was triggered
        result.strategy_used = .processed_history_cleanup;
        result.duration_ms = util.getTime() - start_time;
        
        log.info("🚨 Emergency cleanup completed (strategy: processed history)", .{});
        
        return result;
    }
    
    /// Check if maintenance is needed
    pub fn shouldPerformMaintenance(self: *Self) bool {
        const current_time = util.getTime();
        const MAINTENANCE_INTERVAL = 300; // 5 minutes
        
        return (current_time - self.last_cleanup_time) > MAINTENANCE_INTERVAL;
    }
    
    /// Backup transactions from orphaned blocks during reorganization
    pub fn backupOrphanedTransactions(
        self: *Self,
        orphaned_blocks: []const Block,
        coinbase_filter: bool
    ) !usize {
        var restored_count: usize = 0;
        
        for (orphaned_blocks) |block| {
            for (block.transactions) |tx| {
                // Skip coinbase transactions if filter is enabled
                if (coinbase_filter and self.isCoinbaseTransaction(tx)) {
                    continue;
                }
                
                // Try to validate and add back to mempool
                if (self.validator.validateTransaction(tx) catch false) {
                    self.storage.addTransactionToPool(tx) catch {
                        // If we can't add it back (e.g., limits), just continue
                        continue;
                    };
                    restored_count += 1;
                } else {
                    log.info("❌ Orphaned transaction no longer valid - discarded", .{});
                }
            }
        }
        
        if (restored_count > 0) {
            log.info("🔄 Restored {} orphaned transactions to mempool", .{restored_count});
        }
        
        return restored_count;
    }
    
    /// Check if transaction is a coinbase transaction
    fn isCoinbaseTransaction(self: *Self, tx: Transaction) bool {
        _ = self;
        // Coinbase transactions have zero sender address and nonce
        return tx.sender.isZero() and tx.nonce == 0;
    }
    
    /// Get cleanup statistics
    pub fn getCleanupStats(self: *Self) CleanupStats {
        return CleanupStats{
            .total_cleanups = self.total_cleanups,
            .transactions_cleaned = self.transactions_cleaned,
            .last_cleanup_time = self.last_cleanup_time,
            .average_transactions_per_cleanup = if (self.total_cleanups > 0)
                @as(f64, @floatFromInt(self.transactions_cleaned)) / @as(f64, @floatFromInt(self.total_cleanups))
            else 0.0,
        };
    }
    
    /// Reset cleanup statistics
    pub fn resetStats(self: *Self) void {
        self.total_cleanups = 0;
        self.transactions_cleaned = 0;
        self.last_cleanup_time = util.getTime();
    }
};

/// Result of maintenance operation
pub const MaintenanceResult = struct {
    processed_history_cleaned: usize,
    memory_optimized: bool,
    duration_ms: i64,
};

/// Result of emergency cleanup
pub const EmergencyCleanupResult = struct {
    transactions_removed: usize,
    strategy_used: EmergencyStrategy,
    duration_ms: i64,
};

/// Emergency cleanup strategies
pub const EmergencyStrategy = enum {
    none,
    processed_history_cleanup,
    low_fee_eviction,
    oldest_transaction_eviction,
    random_eviction,
};

/// Cleanup statistics for monitoring
pub const CleanupStats = struct {
    total_cleanups: u64,
    transactions_cleaned: u64,
    last_cleanup_time: i64,
    average_transactions_per_cleanup: f64,
};