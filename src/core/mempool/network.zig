// network.zig - Network Integration for Mempool
// Handles network-related mempool operations
// Manages incoming transactions and broadcasting

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const net = @import("../network/peer.zig");
const NetworkCoordinator = @import("../network/coordinator.zig").NetworkCoordinator;
const ChainState = @import("../chain/state.zig").ChainState;

const log = std.log.scoped(.mempool);

// Forward declarations for components
const MempoolStorage = @import("pool.zig").MempoolStorage;
const TransactionValidator = @import("validator.zig").TransactionValidator;
const MempoolLimits = @import("limits.zig").MempoolLimits;

// Type aliases for clarity
const Transaction = types.Transaction;
const Hash = types.Hash;

/// Network handler for mempool operations
/// - Processes incoming transactions from network peers
/// - Handles transaction broadcasting
/// - Manages network-specific validation
/// - Provides duplicate detection for network transactions
pub const NetworkHandler = struct {
    // Component references (owned by parent MempoolManager)
    storage: *MempoolStorage,
    validator: *TransactionValidator,
    limits: *MempoolLimits,
    
    // Chain state reference for height queries
    chain_state: *ChainState,
    
    // Network manager reference (optional)
    network: ?*net.NetworkManager,
    
    // Network coordinator reference (for sync triggers)
    network_coordinator: ?*NetworkCoordinator,
    
    // Statistics
    received_count: u64,
    broadcast_count: u64,
    duplicate_count: u64,
    rejected_count: u64,
    
    // Resource management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize network handler with component references
    pub fn init(
        allocator: std.mem.Allocator,
        storage: *MempoolStorage,
        validator: *TransactionValidator,
        limits: *MempoolLimits,
        chain_state: *ChainState
    ) Self {
        return .{
            .storage = storage,
            .validator = validator,
            .limits = limits,
            .chain_state = chain_state,
            .network = null,
            .network_coordinator = null,
            .received_count = 0,
            .broadcast_count = 0,
            .duplicate_count = 0,
            .rejected_count = 0,
            .allocator = allocator,
        };
    }
    
    /// Set network manager reference
    pub fn setNetworkManager(self: *Self, network: *net.NetworkManager) void {
        self.network = network;
    }
    
    /// Set network coordinator reference
    pub fn setNetworkCoordinator(self: *Self, coordinator: *NetworkCoordinator) void {
        self.network_coordinator = coordinator;
    }
    
    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction) !NetworkTransactionResult {
        self.received_count += 1;
        
        const tx_hash = transaction.hash();
        
        // 1. Check if already in mempool (duplicate detection)
        if (self.storage.containsTransaction(tx_hash)) {
            self.duplicate_count += 1;
            log.info("🌊 Transaction already flows in our zen mempool - gracefully ignored", .{});
            return NetworkTransactionResult{
                .accepted = false,
                .reason = .duplicate_in_mempool,
                .should_broadcast = false,
            };
        }
        
        // 2. Check if already processed (replay protection handled by validator)
        if (self.validator.isReplayTransaction(transaction)) {
            self.rejected_count += 1;
            return NetworkTransactionResult{
                .accepted = false,
                .reason = .already_processed,
                .should_broadcast = false,
            };
        }
        
        // 3. Validate transaction using network-specific validation
        if (!try self.validator.validateNetworkTransaction(transaction)) {
            self.rejected_count += 1;
            log.info("⚠️ Rejected network transaction: validation failed", .{});
            
            // Check auto-sync trigger in case account state is out of sync
            try self.checkAutoSyncTrigger(transaction);
            
            return NetworkTransactionResult{
                .accepted = false,
                .reason = .validation_failed,
                .should_broadcast = false,
            };
        }
        
        // 4. Check mempool limits
        const current_count = self.storage.getTransactionCount();
        const current_size = self.storage.getTotalSize();
        const limit_result = try self.limits.canAcceptTransaction(transaction, current_count, current_size);
        
        if (!limit_result.can_accept) {
            self.rejected_count += 1;
            self.limits.printLimitCheckResult(limit_result);
            return NetworkTransactionResult{
                .accepted = false,
                .reason = .mempool_limits_exceeded,
                .should_broadcast = false,
            };
        }
        
        // 5. Add to mempool storage
        try self.storage.addTransactionToPool(transaction);
        
        // 6. Mark as processed for replay protection
        try self.validator.markAsProcessed(transaction);
        
        log.info("✅ Network transaction flows into zen mempool", .{});
        
        return NetworkTransactionResult{
            .accepted = true,
            .reason = .accepted,
            .should_broadcast = true,
        };
    }
    
    /// Broadcast transaction to network peers
    pub fn broadcastTransaction(self: *Self, transaction: Transaction) void {
        if (self.network) |network| {
            network.broadcastTransaction(transaction);
            self.broadcast_count += 1;
            log.info("📡 Transaction broadcasted to network peers", .{});
        } else {
            log.info("⚠️  No network manager available for transaction broadcast", .{});
        }
    }
    
    /// Check if we should trigger auto-sync based on transaction failures
    pub fn checkAutoSyncTrigger(self: *Self, transaction: Transaction) !void {
        if (self.network) |network| {
            // If transaction failed due to insufficient balance or invalid nonce,
            // we might be behind. Check peer heights and trigger sync if needed.
            const highest_peer_height = network.getHighestPeerHeight();
            
            // Auto-sync trigger: if peers are significantly ahead, start sync
            const current_height = self.chain_state.getHeight() catch 0;
            
            // If peers are more than 2 blocks ahead, trigger sync
            if (highest_peer_height > current_height + 2) {
                log.info("🔄 Peers are {} blocks ahead, triggering auto-sync", .{highest_peer_height - current_height});
                
                // Trigger sync through network coordinator
                if (self.network_coordinator) |coordinator| {
                    coordinator.triggerSync(highest_peer_height) catch |err| {
                        log.info("⚠️ Failed to trigger sync: {}", .{err});
                    };
                } else {
                    log.info("⚠️ No network coordinator available for sync trigger", .{});
                }
            } else {
                log.info("ℹ️ Chain up to date, no auto-sync needed", .{});
            }
            
            _ = transaction; // Transaction already processed
        }
    }
    
    /// Process transaction from local source (CLI, RPC, etc.)
    pub fn processLocalTransaction(self: *Self, transaction: Transaction) !LocalTransactionResult {
        const tx_hash = transaction.hash();
        
        // 1. Check if already in mempool
        if (self.storage.containsTransaction(tx_hash)) {
            return LocalTransactionResult{
                .accepted = false,
                .reason = .duplicate_in_mempool,
                .should_broadcast = false,
                .validation_error = null,
            };
        }
        
        // 2. Validate transaction
        if (!try self.validator.validateTransaction(transaction)) {
            // Try to get specific validation error
            const validation_error: ?anyerror = blk: {
                self.validator.validateTransactionWithError(transaction) catch |err| {
                    break :blk err;
                };
                break :blk null;
            };
            return LocalTransactionResult{
                .accepted = false,
                .reason = .validation_failed,
                .should_broadcast = false,
                .validation_error = validation_error,
            };
        }
        
        // 3. Check mempool limits
        const current_count = self.storage.getTransactionCount();
        const current_size = self.storage.getTotalSize();
        const limit_result = try self.limits.canAcceptTransaction(transaction, current_count, current_size);
        
        if (!limit_result.can_accept) {
            self.limits.printLimitCheckResult(limit_result);
            return LocalTransactionResult{
                .accepted = false,
                .reason = .mempool_limits_exceeded,
                .should_broadcast = false,
                .validation_error = null,
            };
        }
        
        // 4. Add to mempool storage
        try self.storage.addTransactionToPool(transaction);
        
        // 5. Mark as processed for replay protection
        try self.validator.markAsProcessed(transaction);
        
        log.info("✅ Local transaction added to mempool", .{});
        
        return LocalTransactionResult{
            .accepted = true,
            .reason = .accepted,
            .should_broadcast = true,
            .validation_error = null,
        };
    }
    
    /// Get network statistics
    pub fn getNetworkStats(self: *Self) NetworkStats {
        return NetworkStats{
            .received_count = self.received_count,
            .broadcast_count = self.broadcast_count,
            .duplicate_count = self.duplicate_count,
            .rejected_count = self.rejected_count,
            .acceptance_rate = if (self.received_count > 0)
                (@as(f64, @floatFromInt(self.received_count - self.rejected_count)) / @as(f64, @floatFromInt(self.received_count))) * 100.0
            else 0.0,
        };
    }
    
    /// Reset network statistics
    pub fn resetStats(self: *Self) void {
        self.received_count = 0;
        self.broadcast_count = 0;
        self.duplicate_count = 0;
        self.rejected_count = 0;
    }
};

/// Result of processing a network transaction
pub const NetworkTransactionResult = struct {
    accepted: bool,
    reason: NetworkTransactionReason,
    should_broadcast: bool,
};

/// Reason for network transaction result
pub const NetworkTransactionReason = enum {
    accepted,
    duplicate_in_mempool,
    already_processed,
    validation_failed,
    mempool_limits_exceeded,
};

/// Result of processing a local transaction
pub const LocalTransactionResult = struct {
    accepted: bool,
    reason: LocalTransactionReason,
    should_broadcast: bool,
    validation_error: ?anyerror = null,
};

/// Reason for local transaction result
pub const LocalTransactionReason = enum {
    accepted,
    duplicate_in_mempool,
    validation_failed,
    mempool_limits_exceeded,
};

/// Network statistics for monitoring
pub const NetworkStats = struct {
    received_count: u64,
    broadcast_count: u64,
    duplicate_count: u64,
    rejected_count: u64,
    acceptance_rate: f64,
};