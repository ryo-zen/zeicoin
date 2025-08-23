// limits.zig - Mempool Limits Enforcer
// Enforces mempool size and count constraints
// Manages capacity limits and prevents spam

const std = @import("std");
const types = @import("../types/types.zig");

const log = std.log.scoped(.mempool);

// Type aliases for clarity
const Transaction = types.Transaction;

/// Mempool limits enforcer
/// - Enforces transaction count limits
/// - Enforces total size limits (bytes)
/// - Enforces individual transaction size limits
/// - Provides capacity management
pub const MempoolLimits = struct {
    // Configuration (could be made configurable in the future)
    max_transactions: usize,
    max_size_bytes: usize,
    max_individual_tx_size: usize,
    
    const Self = @This();
    
    /// Initialize with default limits from types.zig
    pub fn init() Self {
        return .{
            .max_transactions = types.MempoolLimits.MAX_TRANSACTIONS,
            .max_size_bytes = types.MempoolLimits.MAX_SIZE_BYTES,
            .max_individual_tx_size = types.TransactionLimits.MAX_TX_SIZE,
        };
    }
    
    /// Initialize with custom limits
    pub fn initWithLimits(max_transactions: usize, max_size_bytes: usize, max_individual_tx_size: usize) Self {
        return .{
            .max_transactions = max_transactions,
            .max_size_bytes = max_size_bytes,
            .max_individual_tx_size = max_individual_tx_size,
        };
    }
    
    /// Check if transaction can be accepted given current mempool state
    pub fn canAcceptTransaction(
        self: *Self,
        tx: Transaction,
        current_count: usize,
        current_size: usize
    ) !LimitCheckResult {
        // Check individual transaction size first
        const tx_size = tx.getSerializedSize();
        if (!self.checkIndividualSize(tx_size)) {
            return LimitCheckResult{
                .can_accept = false,
                .reason = .transaction_too_large,
                .current_count = current_count,
                .current_size = current_size,
                .transaction_size = tx_size,
            };
        }
        
        // Check transaction count limit
        if (!self.checkTransactionCount(current_count)) {
            return LimitCheckResult{
                .can_accept = false,
                .reason = .count_limit_exceeded,
                .current_count = current_count,
                .current_size = current_size,
                .transaction_size = tx_size,
            };
        }
        
        // Check total size limit
        if (!self.checkTotalSize(current_size, tx_size)) {
            return LimitCheckResult{
                .can_accept = false,
                .reason = .size_limit_exceeded,
                .current_count = current_count,
                .current_size = current_size,
                .transaction_size = tx_size,
            };
        }
        
        return LimitCheckResult{
            .can_accept = true,
            .reason = .accepted,
            .current_count = current_count,
            .current_size = current_size,
            .transaction_size = tx_size,
        };
    }
    
    /// Check if transaction count is within limits
    pub fn checkTransactionCount(self: *Self, current_count: usize) bool {
        return current_count < self.max_transactions;
    }
    
    /// Check if total size is within limits (including new transaction)
    pub fn checkTotalSize(self: *Self, current_size: usize, new_tx_size: usize) bool {
        return (current_size + new_tx_size) <= self.max_size_bytes;
    }
    
    /// Check if individual transaction size is within limits
    pub fn checkIndividualSize(self: *Self, tx_size: usize) bool {
        return tx_size <= self.max_individual_tx_size;
    }
    
    /// Get current utilization as percentage
    pub fn getUtilization(self: *Self, current_count: usize, current_size: usize) UtilizationInfo {
        const count_percent = (@as(f64, @floatFromInt(current_count)) / @as(f64, @floatFromInt(self.max_transactions))) * 100.0;
        const size_percent = (@as(f64, @floatFromInt(current_size)) / @as(f64, @floatFromInt(self.max_size_bytes))) * 100.0;
        
        return UtilizationInfo{
            .count_utilization = count_percent,
            .size_utilization = size_percent,
            .overall_utilization = @max(count_percent, size_percent),
        };
    }
    
    /// Check if mempool is approaching capacity
    pub fn isApproachingCapacity(self: *Self, current_count: usize, current_size: usize) bool {
        const utilization = self.getUtilization(current_count, current_size);
        return utilization.overall_utilization > 80.0; // 80% threshold
    }
    
    /// Get remaining capacity
    pub fn getRemainingCapacity(self: *Self, current_count: usize, current_size: usize) RemainingCapacity {
        return RemainingCapacity{
            .transactions = if (self.max_transactions > current_count) 
                self.max_transactions - current_count 
            else 0,
            .bytes = if (self.max_size_bytes > current_size) 
                self.max_size_bytes - current_size 
            else 0,
        };
    }
    
    /// Print limit check result with detailed information
    pub fn printLimitCheckResult(self: *Self, result: LimitCheckResult) void {
        _ = self;
        
        switch (result.reason) {
            .accepted => {
                log.info("✅ Transaction accepted (count: {}, size: {} bytes)", .{
                    result.current_count + 1,
                    result.current_size + result.transaction_size
                });
            },
            .transaction_too_large => {
                log.info("❌ Transaction too large: {} bytes (max: {} bytes)", .{
                    result.transaction_size,
                    types.TransactionLimits.MAX_TX_SIZE
                });
            },
            .count_limit_exceeded => {
                log.info("❌ Mempool full: {} transactions (limit: {})", .{
                    result.current_count,
                    types.MempoolLimits.MAX_TRANSACTIONS
                });
            },
            .size_limit_exceeded => {
                log.info("❌ Mempool size limit exceeded: {} + {} bytes > {} bytes", .{
                    result.current_size,
                    result.transaction_size,
                    types.MempoolLimits.MAX_SIZE_BYTES
                });
            },
        }
    }
    
    /// Get limit configuration
    pub fn getLimits(self: *Self) LimitConfiguration {
        return LimitConfiguration{
            .max_transactions = self.max_transactions,
            .max_size_bytes = self.max_size_bytes,
            .max_individual_tx_size = self.max_individual_tx_size,
        };
    }
};

/// Result of limit checking
pub const LimitCheckResult = struct {
    can_accept: bool,
    reason: LimitCheckReason,
    current_count: usize,
    current_size: usize,
    transaction_size: usize,
};

/// Reason for limit check result
pub const LimitCheckReason = enum {
    accepted,
    transaction_too_large,
    count_limit_exceeded,
    size_limit_exceeded,
};

/// Utilization information
pub const UtilizationInfo = struct {
    count_utilization: f64,    // Percentage of transaction count used
    size_utilization: f64,     // Percentage of size limit used
    overall_utilization: f64,  // Maximum of count and size utilization
};

/// Remaining capacity information
pub const RemainingCapacity = struct {
    transactions: usize,
    bytes: usize,
};

/// Limit configuration
pub const LimitConfiguration = struct {
    max_transactions: usize,
    max_size_bytes: usize,
    max_individual_tx_size: usize,
};