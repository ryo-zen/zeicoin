// manager.zig - Mempool Manager Coordinator
// Main coordinator for all mempool operations and components
// Provides high-level API for mempool operations

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const net = @import("../network/peer.zig");
const ChainState = @import("../chain/state.zig").ChainState;

const print = std.debug.print;

// Import mempool components
const MempoolStorage = @import("pool.zig").MempoolStorage;
const TransactionValidator = @import("validator.zig").TransactionValidator;
const MempoolLimits = @import("limits.zig").MempoolLimits;
const NetworkHandler = @import("network.zig").NetworkHandler;
const MempoolCleaner = @import("cleaner.zig").MempoolCleaner;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const Hash = types.Hash;

/// Mempool state information for external queries
pub const MempoolStateInfo = struct {
    transaction_count: usize,
    total_size_bytes: usize,
    utilization_percent: f64,
    pending_transactions: usize,
};

/// MempoolManager coordinates all mempool operations and components
/// - Owns and manages all mempool-related components
/// - Provides high-level API for blockchain operations
/// - Handles component orchestration and dependency injection
/// - Abstracts complex mempool operations behind simple interface
pub const MempoolManager = struct {
    // Core components
    storage: MempoolStorage,
    validator: TransactionValidator,
    limits: MempoolLimits,
    network_handler: NetworkHandler,
    cleaner: MempoolCleaner,
    
    // Mining integration
    mining_state: ?*types.MiningState,
    
    // Resource management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize MempoolManager with chain state and allocator
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState) !Self {
        // Initialize components in dependency order
        var storage = MempoolStorage.init(allocator);
        var validator = TransactionValidator.init(allocator, chain_state);
        var limits = MempoolLimits.init();
        const network_handler = NetworkHandler.init(allocator, &storage, &validator, &limits);
        const cleaner = MempoolCleaner.init(allocator, &storage, &validator);
        
        return .{
            .storage = storage,
            .validator = validator,
            .limits = limits,
            .network_handler = network_handler,
            .cleaner = cleaner,
            .mining_state = null,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.storage.deinit();
        self.validator.deinit();
        // Other components don't need cleanup
    }

    /// Set network manager for broadcasting
    pub fn setNetworkManager(self: *Self, network: *net.NetworkManager) void {
        self.network_handler.setNetworkManager(network);
    }
    
    /// Set mining state for mining integration
    pub fn setMiningState(self: *Self, mining_state: *types.MiningState) void {
        self.mining_state = mining_state;
    }

    // High-Level Mempool Operations API
    
    /// Add transaction from local source (CLI, RPC, etc.)
    pub fn addTransaction(self: *Self, transaction: Transaction) !void {
        const result = try self.network_handler.processLocalTransaction(transaction);
        
        if (!result.accepted) {
            switch (result.reason) {
                .accepted => {}, // This shouldn't happen when !result.accepted, but required for completeness
                .duplicate_in_mempool => return error.DuplicateTransaction,
                .validation_failed => return error.InvalidTransaction,
                .mempool_limits_exceeded => return error.MempoolFull,
            }
        }
        
        // Signal mining thread if available
        if (self.mining_state) |mining_state| {
            print("🔔 Broadcasting to mining thread\\n", .{});
            mining_state.condition.broadcast();
        }
        
        // Broadcast to network if needed
        if (result.should_broadcast) {
            self.network_handler.broadcastTransaction(transaction);
        }
    }

    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction) !void {
        const result = try self.network_handler.handleIncomingTransaction(transaction);
        
        if (result.accepted) {
            // Signal mining thread if available
            if (self.mining_state) |mining_state| {
                mining_state.condition.broadcast();
            }
            
            // Broadcast to other peers if needed
            if (result.should_broadcast) {
                self.network_handler.broadcastTransaction(transaction);
            }
        } else {
            // Handle rejection reasons
            switch (result.reason) {
                .validation_failed => {
                    // Might trigger auto-sync if we're behind
                    try self.network_handler.checkAutoSyncTrigger(transaction);
                },
                else => {
                    // Other rejections don't require special handling
                },
            }
        }
    }

    /// Clean mempool after a block is added to the chain
    pub fn cleanAfterBlock(self: *Self, block: Block) !void {
        _ = try self.cleaner.cleanConfirmedTransactions(block);
    }

    /// Get all transactions for mining
    pub fn getTransactionsForMining(self: *Self) ![]Transaction {
        return try self.storage.getAllTransactions();
    }
    
    /// Free transaction array returned by getTransactionsForMining
    pub fn freeTransactionArray(self: *Self, transactions: []Transaction) void {
        self.storage.freeTransactionArray(transactions);
    }

    /// Check if transaction exists in mempool
    pub fn isTransactionInMempool(self: *Self, tx_hash: Hash) bool {
        return self.storage.containsTransaction(tx_hash);
    }

    /// Get current mempool state information
    pub fn getMempoolState(self: *Self) !MempoolStateInfo {
        const stats = self.storage.getStats();
        const utilization = self.limits.getUtilization(stats.transaction_count, stats.total_size_bytes);
        
        return MempoolStateInfo{
            .transaction_count = stats.transaction_count,
            .total_size_bytes = stats.total_size_bytes,
            .utilization_percent = utilization.overall_utilization,
            .pending_transactions = stats.transaction_count,
        };
    }

    /// Get transaction count
    pub fn getTransactionCount(self: *Self) usize {
        return self.storage.getTransactionCount();
    }

    /// Get total mempool size in bytes
    pub fn getTotalSize(self: *Self) usize {
        return self.storage.getTotalSize();
    }

    /// Perform periodic maintenance
    pub fn performMaintenance(self: *Self) !void {
        if (self.cleaner.shouldPerformMaintenance()) {
            _ = try self.cleaner.performMaintenance();
        }
    }
    
    /// Remove expired transactions
    pub fn removeExpiredTransactions(self: *Self, current_height: u32) !usize {
        return try self.cleaner.removeExpiredTransactions(current_height);
    }

    /// Emergency cleanup when mempool is full
    pub fn emergencyCleanup(self: *Self) !void {
        _ = try self.cleaner.emergencyCleanup();
    }

    /// Handle chain reorganization - backup orphaned transactions
    pub fn handleReorganization(self: *Self, orphaned_blocks: []const Block) !void {
        _ = try self.cleaner.backupOrphanedTransactions(orphaned_blocks, true);
    }

    /// Clear all transactions from mempool
    pub fn clearMempool(self: *Self) void {
        self.storage.clearPool();
        print("🧹 Mempool cleared\\n", .{});
    }

    /// Get comprehensive mempool statistics
    pub fn getStats(self: *Self) MempoolStats {
        const storage_stats = self.storage.getStats();
        const network_stats = self.network_handler.getNetworkStats();
        const cleanup_stats = self.cleaner.getCleanupStats();
        const validation_stats = self.validator.getValidationStats();
        const utilization = self.limits.getUtilization(storage_stats.transaction_count, storage_stats.total_size_bytes);
        
        return MempoolStats{
            .transaction_count = storage_stats.transaction_count,
            .total_size_bytes = storage_stats.total_size_bytes,
            .average_tx_size = storage_stats.average_tx_size,
            .utilization_percent = utilization.overall_utilization,
            .network_received = network_stats.received_count,
            .network_broadcast = network_stats.broadcast_count,
            .network_duplicates = network_stats.duplicate_count,
            .network_rejected = network_stats.rejected_count,
            .total_cleanups = cleanup_stats.total_cleanups,
            .transactions_cleaned = cleanup_stats.transactions_cleaned,
            .processed_transactions = validation_stats.processed_transactions,
        };
    }
    
    /// Print mempool status
    pub fn printStatus(self: *Self) void {
        const stats = self.getStats();
        const limits_config = self.limits.getLimits();
        
        print("\\n📊 Mempool Status:\\n", .{});
        print("   Transactions: {}/{} ({:.1}% full)\\n", .{
            stats.transaction_count,
            limits_config.max_transactions,
            stats.utilization_percent
        });
        print("   Size: {} bytes / {} bytes\\n", .{
            stats.total_size_bytes,
            limits_config.max_size_bytes
        });
        print("   Average TX size: {} bytes\\n", .{stats.average_tx_size});
        print("   Network: {} received, {} broadcast, {} rejected\\n", .{
            stats.network_received,
            stats.network_broadcast,
            stats.network_rejected
        });
        print("   Maintenance: {} cleanups, {} transactions cleaned\\n", .{
            stats.total_cleanups,
            stats.transactions_cleaned
        });
        print("\\n", .{});
    }
};

/// Comprehensive mempool statistics
pub const MempoolStats = struct {
    // Storage statistics
    transaction_count: usize,
    total_size_bytes: usize,
    average_tx_size: usize,
    utilization_percent: f64,
    
    // Network statistics
    network_received: u64,
    network_broadcast: u64,
    network_duplicates: u64,
    network_rejected: u64,
    
    // Cleanup statistics
    total_cleanups: u64,
    transactions_cleaned: u64,
    
    // Validation statistics
    processed_transactions: usize,
};