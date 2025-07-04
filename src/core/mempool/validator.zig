// validator.zig - Transaction Validator
// Handles all transaction validation logic for the mempool
// Validates transactions before they are added to the pool

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const key = @import("../crypto/key.zig");
const ChainState = @import("../chain/state.zig").ChainState;

const print = std.debug.print;

// Type aliases for clarity
const Transaction = types.Transaction;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Transaction validator for mempool operations
/// - Validates transaction structure and cryptographic signatures
/// - Checks nonce sequences and account balances
/// - Provides replay protection and expiry validation
/// - Integrates with chain state for account queries
pub const TransactionValidator = struct {
    // Chain state reference for account queries
    chain_state: *ChainState,
    
    // Processed transaction history for replay protection
    processed_transactions: std.ArrayList(Hash),
    
    // Resource management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize transaction validator
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState) Self {
        return .{
            .chain_state = chain_state,
            .processed_transactions = std.ArrayList(Hash).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.processed_transactions.deinit();
    }
    
    /// Validate transaction completely
    pub fn validateTransaction(self: *Self, tx: Transaction) !bool {
        // 1. Basic structure validation
        if (!tx.isValid()) {
            return false;
        }
        
        // 2. Check replay protection
        if (self.isReplayTransaction(tx)) {
            print("❌ Transaction already processed - replay attempt blocked\\n", .{});
            return false;
        }
        
        // 3. Check expiry
        if (!try self.validateExpiry(tx)) {
            return false;
        }
        
        // 4. Check amount sanity
        if (!self.validateAmount(tx)) {
            return false;
        }
        
        // 5. Check self-transfer (warn but allow)
        if (tx.sender.equals(tx.recipient)) {
            print("⚠️ Self-transfer detected (wasteful but allowed)\\n", .{});
        }
        
        // 6. Validate nonce
        if (!try self.validateNonce(tx)) {
            return false;
        }
        
        // 7. Validate balance and fees
        if (!try self.validateBalance(tx)) {
            return false;
        }
        
        // 8. Validate signature
        if (!self.validateSignature(tx)) {
            return false;
        }
        
        return true;
    }
    
    /// Check if transaction is a replay attempt
    pub fn isReplayTransaction(self: *Self, tx: Transaction) bool {
        const tx_hash = tx.hash();
        
        for (self.processed_transactions.items) |processed_hash| {
            if (std.mem.eql(u8, &processed_hash, &tx_hash)) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Validate transaction expiry
    pub fn validateExpiry(self: *Self, tx: Transaction) !bool {
        const current_height = try self.chain_state.getHeight();
        
        if (tx.expiry_height <= current_height) {
            print("❌ Transaction expired: expiry height {} <= current height {}\\n", .{
                tx.expiry_height, current_height
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate transaction amount
    pub fn validateAmount(self: *Self, tx: Transaction) bool {
        _ = self;
        
        // Allow zero-amount transactions (fee-only payments)
        if (tx.amount == 0) {
            print("💸 Zero amount transaction (fee-only payment)\\n", .{});
        }
        
        // Check for extremely high amounts (overflow protection)
        if (tx.amount > 1000000 * types.ZEI_COIN) {
            print("❌ Transaction amount too high: {} ZEI (max: 1,000,000 ZEI)\\n", .{
                tx.amount / types.ZEI_COIN
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate transaction nonce
    pub fn validateNonce(self: *Self, tx: Transaction) !bool {
        const sender_account = try self.chain_state.getAccount(tx.sender);
        
        if (tx.nonce != sender_account.nextNonce()) {
            print("❌ Invalid nonce: expected {}, got {}\\n", .{
                sender_account.nextNonce(), tx.nonce
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate sender balance and fees
    pub fn validateBalance(self: *Self, tx: Transaction) !bool {
        const sender_account = try self.chain_state.getAccount(tx.sender);
        
        // Check minimum fee
        if (tx.fee < types.ZenFees.MIN_FEE) {
            print("❌ Fee too low: {} (minimum: {})\\n", .{
                tx.fee, types.ZenFees.MIN_FEE
            });
            return false;
        }
        
        // Check if sender has sufficient balance
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            print("❌ Insufficient balance: {} needed, {} available\\n", .{
                total_cost, sender_account.balance
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate transaction signature
    pub fn validateSignature(self: *Self, tx: Transaction) bool {
        _ = self;
        
        // Use the transaction's built-in signature validation
        return tx.isValid();
    }
    
    /// Mark transaction as processed (for replay protection)
    pub fn markAsProcessed(self: *Self, tx: Transaction) !void {
        const tx_hash = tx.hash();
        try self.processed_transactions.append(tx_hash);
    }
    
    /// Clean up old processed transactions to prevent memory growth
    pub fn cleanupProcessedTransactions(self: *Self) void {
        const MAX_PROCESSED_TXS = 1000;
        const KEEP_RECENT_TXS = 500;
        
        if (self.processed_transactions.items.len > MAX_PROCESSED_TXS) {
            const items_to_remove = self.processed_transactions.items.len - KEEP_RECENT_TXS;
            
            // Remove oldest transactions (first items in the list)
            for (0..items_to_remove) |_| {
                _ = self.processed_transactions.orderedRemove(0);
            }
            
            print("🧹 Cleaned {} old processed transactions (kept {} recent)\\n", .{
                items_to_remove, KEEP_RECENT_TXS
            });
        }
    }
    
    /// Validate transaction for network acceptance (stricter validation)
    pub fn validateNetworkTransaction(self: *Self, tx: Transaction) !bool {
        // Apply all standard validations
        if (!try self.validateTransaction(tx)) {
            return false;
        }
        
        // Additional network-specific validations can be added here
        // For example: rate limiting, peer reputation, etc.
        
        return true;
    }
    
    /// Get validation statistics
    pub fn getValidationStats(self: *Self) ValidationStats {
        return ValidationStats{
            .processed_transactions = self.processed_transactions.items.len,
        };
    }
};

/// Validation statistics for monitoring
pub const ValidationStats = struct {
    processed_transactions: usize,
};