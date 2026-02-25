// validator.zig - Transaction Validator
// Handles all transaction validation logic for the mempool
// Validates transactions before they are added to the pool

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const key = @import("../crypto/key.zig");
const ChainState = @import("../chain/state.zig").ChainState;

const log = std.log.scoped(.mempool);

// Type aliases for clarity
const Transaction = types.Transaction;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Specific validation error types for detailed error reporting
pub const ValidationError = error{
    InvalidStructure,
    TransactionExpired,
    InvalidAmount,
    InvalidNonce,
    InsufficientBalance,
    FeeTooLow,
    InvalidSignature,
};

/// Transaction validator for mempool operations
/// - Validates transaction structure and cryptographic signatures
/// - Checks nonce sequences and account balances
/// - Provides expiry validation
/// - Integrates with chain state for account queries
pub const TransactionValidator = struct {
    // Chain state reference for account queries
    chain_state: *ChainState,
    io: std.Io,

    // Resource management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize transaction validator
    pub fn init(allocator: std.mem.Allocator, io: std.Io, chain_state: *ChainState) Self {
        return .{
            .chain_state = chain_state,
            .io = io,
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to clean up
    }
    
    /// Validate transaction completely
    pub fn validateTransaction(self: *Self, tx: Transaction) !bool {
        // 1. Basic structure validation
        if (!tx.isValid()) {
            return false;
        }

        // 2. Check expiry
        if (!try self.validateExpiry(tx)) {
            return false;
        }

        // 3. Check amount sanity
        if (!self.validateAmount(tx)) {
            return false;
        }

        // 4. Check self-transfer (warn but allow)
        if (tx.sender.equals(tx.recipient)) {
            log.info("⚠️ Self-transfer detected (wasteful but allowed)", .{});
        }

        // 5. Validate nonce
        if (!try self.validateNonce(tx)) {
            return false;
        }

        // 6. Validate balance and fees
        if (!try self.validateBalance(tx)) {
            return false;
        }

        // 7. Validate signature
        if (!self.validateSignature(tx)) {
            return false;
        }
        
        return true;
    }
    
    /// Validate transaction with specific error reporting
    pub fn validateTransactionWithError(self: *Self, tx: Transaction) !void {
        // 1. Basic structure validation
        if (!tx.isValid()) {
            return ValidationError.InvalidStructure;
        }

        // 2. Check expiry
        if (!(self.validateExpiry(tx) catch false)) {
            return ValidationError.TransactionExpired;
        }

        // 3. Check amount sanity
        if (!self.validateAmount(tx)) {
            return ValidationError.InvalidAmount;
        }

        // 4. Check self-transfer (warn but allow)
        if (tx.sender.equals(tx.recipient)) {
            log.info("⚠️ Self-transfer detected (wasteful but allowed)", .{});
        }

        // 5. Validate nonce
        if (!(self.validateNonce(tx) catch false)) {
            return ValidationError.InvalidNonce;
        }

        // 6. Validate balance and fees
        self.validateBalanceWithError(tx) catch |err| {
            return err;
        };

        // 7. Validate signature
        if (!self.validateSignature(tx)) {
            return ValidationError.InvalidSignature;
        }
    }

    /// Validate transaction expiry
    pub fn validateExpiry(self: *Self, tx: Transaction) !bool {
        const current_height = try self.chain_state.getHeight();
        
        if (tx.expiry_height <= current_height) {
            log.info("❌ Transaction expired: expiry height {} <= current height {}", .{
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
            log.info("💸 Zero amount transaction (fee-only payment)", .{});
        }
        
        // Check for extremely high amounts (overflow protection)
        if (tx.amount > 1000000 * types.ZEI_COIN) {
            log.info("❌ Transaction amount too high: {} ZEI (max: 1,000,000 ZEI)", .{
                tx.amount / types.ZEI_COIN
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate transaction nonce
    pub fn validateNonce(self: *Self, tx: Transaction) !bool {
        const sender_account = try self.chain_state.getAccount(self.io, tx.sender);
        const expected_nonce = sender_account.nextNonce();
        
        // Allow nonce to be equal or higher than expected (for queuing future transactions)
        // But don't allow nonces that are too far in the future (prevent spam)
        const max_future_nonce = expected_nonce + 100; // Allow up to 100 transactions ahead
        
        if (tx.nonce < expected_nonce) {
            log.info("❌ Invalid nonce: too low, expected >= {}, got {}", .{
                expected_nonce, tx.nonce
            });
            return false;
        }
        
        if (tx.nonce > max_future_nonce) {
            log.info("❌ Invalid nonce: too high, expected <= {}, got {}", .{
                max_future_nonce, tx.nonce
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate sender balance and fees
    pub fn validateBalance(self: *Self, tx: Transaction) !bool {
        const sender_account = try self.chain_state.getAccount(self.io, tx.sender);
        
        // Check minimum fee
        if (tx.fee < types.ZenFees.MIN_FEE) {
            log.info("❌ Fee too low: {} (minimum: {})", .{
                tx.fee, types.ZenFees.MIN_FEE
            });
            return false;
        }
        
        // Check if sender has sufficient balance
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            log.info("❌ Insufficient balance: {} needed, {} available", .{
                total_cost, sender_account.balance
            });
            return false;
        }
        
        return true;
    }
    
    /// Validate sender balance and fees with specific error reporting
    pub fn validateBalanceWithError(self: *Self, tx: Transaction) !void {
        const sender_account = self.chain_state.getAccount(self.io, tx.sender) catch {
            return ValidationError.InvalidNonce; // Account not found, treat as invalid nonce
        };
        
        // Check minimum fee
        if (tx.fee < types.ZenFees.MIN_FEE) {
            log.info("❌ Fee too low: {} (minimum: {})", .{
                tx.fee, types.ZenFees.MIN_FEE
            });
            return ValidationError.FeeTooLow;
        }
        
        // Check if sender has sufficient balance
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            log.info("❌ Insufficient balance: {} needed, {} available", .{
                total_cost, sender_account.balance
            });
            return ValidationError.InsufficientBalance;
        }
    }
    
    /// Validate transaction signature
    pub fn validateSignature(self: *Self, tx: Transaction) bool {
        _ = self;

        // Verify Ed25519 signature
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            log.warn("❌ Invalid signature: transaction not signed by sender", .{});
            return false;
        }
        return true;
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
        _ = self;
        return ValidationStats{};
    }
};

/// Validation statistics for monitoring
pub const ValidationStats = struct {
    // Stats can be added here as needed
};
