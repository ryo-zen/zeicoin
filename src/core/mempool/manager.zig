// manager.zig - Mempool Manager Coordinator
// Main coordinator for all mempool operations and components
// Provides high-level API for mempool operations

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const net = @import("../network/peer.zig");
const ChainState = @import("../chain/state.zig").ChainState;

const log = std.log.scoped(.mempool);

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
    /// Returns a heap-allocated MempoolManager to ensure stable addresses
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState) !*Self {
        
        // Allocate on heap to ensure stable addresses
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        
        // Initialize components in dependency order
        self.* = Self{
            .storage = MempoolStorage.init(allocator),
            .validator = TransactionValidator.init(allocator, chain_state),
            .limits = MempoolLimits.init(),
            .network_handler = undefined,
            .cleaner = undefined,
            .mining_state = null,
            .allocator = allocator,
        };
        
        
        // Initialize components that need pointers to other components
        self.network_handler = NetworkHandler.init(allocator, &self.storage, &self.validator, &self.limits, chain_state);
        self.cleaner = MempoolCleaner.init(allocator, &self.storage, &self.validator);
        
        
        return self;
    }

    /// Cleanup resources and free self
    pub fn deinit(self: *Self) void {
        self.storage.deinit();
        self.validator.deinit();
        // Other components don't need cleanup
        
        // Free self (allocated in init)
        self.allocator.destroy(self);
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
        const tx_hash = transaction.hash();
        const amount_zei = @as(f64, @floatFromInt(transaction.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const fee_zei = @as(f64, @floatFromInt(transaction.fee)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        
        // Convert addresses to bech32 for display
        const sender_bech32 = transaction.sender.toBech32(self.allocator, types.CURRENT_NETWORK) catch "invalid";
        defer if (!std.mem.eql(u8, sender_bech32, "invalid")) self.allocator.free(sender_bech32);
        
        const recipient_bech32 = transaction.recipient.toBech32(self.allocator, types.CURRENT_NETWORK) catch "invalid";
        defer if (!std.mem.eql(u8, recipient_bech32, "invalid")) self.allocator.free(recipient_bech32);
        
        log.info("🔄 [TX LIFECYCLE] Received transaction {s} from {s} → {s}: {d:.8} ZEI (fee: {d:.8}, nonce: {})", .{
            std.fmt.fmtSliceHexLower(tx_hash[0..8]), sender_bech32, recipient_bech32, amount_zei, fee_zei, transaction.nonce
        });
        
        const result = try self.network_handler.processLocalTransaction(transaction);
        
        if (!result.accepted) {
            const reject_tx_hash = transaction.hash();
            switch (result.reason) {
                .accepted => {}, // This shouldn't happen when !result.accepted, but required for completeness
                .duplicate_in_mempool => {
                    log.info("❌ [TX LIFECYCLE] Transaction {s} REJECTED: duplicate in mempool", .{std.fmt.fmtSliceHexLower(reject_tx_hash[0..8])});
                    return error.DuplicateTransaction;
                },
                .validation_failed => {
                    // Check if we have a specific validation error
                    if (result.validation_error) |validation_error| {
                        log.info("❌ [TX LIFECYCLE] Transaction {s} REJECTED: validation failed ({})", .{std.fmt.fmtSliceHexLower(reject_tx_hash[0..8]), validation_error});
                        switch (validation_error) {
                            error.InsufficientBalance => return error.InsufficientBalance,
                            error.FeeTooLow => return error.FeeTooLow,
                            error.InvalidNonce => return error.InvalidNonce,
                            error.TransactionExpired => return error.TransactionExpired,
                            else => return error.InvalidTransaction,
                        }
                    }
                    log.info("❌ [TX LIFECYCLE] Transaction {s} REJECTED: validation failed (unknown)", .{std.fmt.fmtSliceHexLower(reject_tx_hash[0..8])});
                    return error.InvalidTransaction;
                },
                .mempool_limits_exceeded => {
                    log.info("❌ [TX LIFECYCLE] Transaction {s} REJECTED: mempool full", .{std.fmt.fmtSliceHexLower(reject_tx_hash[0..8])});
                    return error.MempoolFull;
                },
            }
        }
        
        const accept_tx_hash = transaction.hash();
        const mempool_size = self.getTransactionCount();
        log.info("✅ [TX LIFECYCLE] Transaction {s} ACCEPTED and added to mempool (size: {})", .{std.fmt.fmtSliceHexLower(accept_tx_hash[0..8]), mempool_size});
        
        // Signal mining thread if available
        if (self.mining_state) |mining_state| {
            log.info("🔔 Broadcasting to mining thread", .{});
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
    
    /// Check if transaction exists in mempool (alias for initialization.zig)
    pub fn hasTransaction(self: *Self, tx_hash: Hash) bool {
        return self.storage.containsTransaction(tx_hash);
    }
    
    /// Get transaction from mempool by hash
    pub fn getTransaction(self: *Self, tx_hash: Hash) ?Transaction {
        return self.storage.getTransaction(tx_hash);
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

    /// Restore orphaned transactions back to mempool after reorganization
    pub fn restoreOrphanedTransactions(self: *Self, transactions: []const Transaction) void {
        for (transactions) |tx| {
            if (!tx.isCoinbase()) {
                // Validate transaction is still valid
                if (self.validator.validateTransaction(tx) catch false) {
                    // Deep copy transaction to transfer ownership to mempool
                    const tx_copy = tx.dupe(self.allocator) catch |err| switch (err) {
                        error.OutOfMemory => {
                            log.info("⚠️  Out of memory restoring orphaned transaction - skipping", .{});
                            continue;
                        },
                    };
                    
                    // Add to mempool with proper error handling
                    if (self.addTransaction(tx_copy)) {
                        log.info("🔄 Orphaned transaction restored to mempool", .{});
                    } else |err| switch (err) {
                        error.DuplicateTransaction => {
                            // Transaction already in mempool, clean up our copy
                            tx_copy.deinit(self.allocator);
                            log.info("🔄 Orphaned transaction already in mempool - skipping", .{});
                        },
                        error.InsufficientBalance, error.FeeTooLow, error.InvalidNonce, error.TransactionExpired, error.InvalidTransaction => {
                            // Transaction no longer valid, clean up our copy
                            tx_copy.deinit(self.allocator);
                            log.info("❌ Orphaned transaction validation failed - discarded", .{});
                        },
                        error.MempoolFull => {
                            // Mempool is full, clean up our copy
                            tx_copy.deinit(self.allocator);
                            log.info("⚠️  Mempool full - cannot restore orphaned transaction", .{});
                        },
                        else => {
                            // Unexpected error, clean up our copy and continue
                            tx_copy.deinit(self.allocator);
                            log.info("⚠️  Error restoring orphaned transaction - skipping", .{});
                        },
                    }
                } else {
                    log.info("❌ Orphaned transaction no longer valid - discarded", .{});
                }
            }
        }
    }

    /// Clear all transactions from mempool
    pub fn clearMempool(self: *Self) void {
        self.storage.clearPool();
        log.info("🧹 Mempool cleared", .{});
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
    
    /// Get the highest nonce for pending transactions from a specific address
    pub fn getHighestPendingNonce(self: *Self, address: types.Address) u64 {
        return self.storage.getHighestNonceForAddress(address);
    }

    /// Print mempool status
    pub fn printStatus(self: *Self) void {
        const stats = self.getStats();
        const limits_config = self.limits.getLimits();
        
        log.info("📊 Mempool Status:", .{});
        log.info("   Transactions: {}/{} ({:.1}% full)", .{
            stats.transaction_count,
            limits_config.max_transactions,
            stats.utilization_percent
        });
        log.info("   Size: {} bytes / {} bytes", .{
            stats.total_size_bytes,
            limits_config.max_size_bytes
        });
        log.info("   Average TX size: {} bytes", .{stats.average_tx_size});
        log.info("   Network: {} received, {} broadcast, {} rejected", .{
            stats.network_received,
            stats.network_broadcast,
            stats.network_rejected
        });
        log.info("   Maintenance: {} cleanups, {} transactions cleaned", .{
            stats.total_cleanups,
            stats.transactions_cleaned
        });
        log.info("", .{});
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