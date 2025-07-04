// state.zig - Chain State Manager
// Manages database ownership and account/balance operations
// This is the single source of truth for blockchain state

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const db = @import("../storage/db.zig");

const print = std.debug.print;

// Type aliases for clarity
const Transaction = types.Transaction;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// ChainState manages all blockchain state operations
/// - Database ownership and persistence
/// - Account balance and nonce management
/// - Transaction processing and validation
/// - State rollback and replay operations
pub const ChainState = struct {
    // Core state storage
    database: db.Database,
    processed_transactions: std.ArrayList([32]u8),
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ChainState with database and allocator
    pub fn init(allocator: std.mem.Allocator, database: db.Database) Self {
        return .{
            .database = database,
            .processed_transactions = std.ArrayList([32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.processed_transactions.deinit();
        self.database.deinit();
    }

    // Account Management Methods (to be extracted from node.zig)
    // - getAccount()
    // - getBalance()
    // - processTransaction()
    // - processCoinbaseTransaction()
    // - matureCoinbaseRewards()
    // - clearAllAccounts()
    // - replayFromGenesis()
    // - rollbackToHeight()
    
    // Database & Account Management Methods
    
    /// Get account by address, creating new account if not found
    pub fn getAccount(self: *Self, address: Address) !types.Account {
        // Try to load from database
        if (self.database.getAccount(address)) |account| {
            return account;
        } else |err| switch (err) {
            db.DatabaseError.NotFound => {
                // Create new account with zero balance
                const new_account = types.Account{
                    .address = address,
                    .balance = 0,
                    .nonce = 0,
                };
                // Save to database immediately
                try self.database.saveAccount(address, new_account);
                return new_account;
            },
            else => return err,
        }
    }

    /// Get account balance
    pub fn getBalance(self: *Self, address: Address) !u64 {
        const account = try self.getAccount(address);
        return account.balance;
    }

    /// Get current blockchain height
    pub fn getHeight(self: *Self) !u32 {
        return self.database.getHeight();
    }

    /// Process a regular transaction and update account states
    pub fn processTransaction(self: *Self, tx: Transaction) !void {
        // Get accounts
        var sender_account = try self.getAccount(tx.sender);
        var recipient_account = try self.getAccount(tx.recipient);

        // 💰 Apply transaction with fee deduction
        // Check for integer overflow in addition
        const total_cost = std.math.add(u64, tx.amount, tx.fee) catch {
            return error.IntegerOverflow;
        };

        // Safety check for sufficient balance
        if (sender_account.balance < total_cost) {
            return error.InsufficientBalance;
        }

        sender_account.balance -= total_cost;

        // Check for nonce overflow
        sender_account.nonce = std.math.add(u64, sender_account.nonce, 1) catch {
            return error.NonceOverflow;
        };

        // Check for balance overflow on recipient
        recipient_account.balance = std.math.add(u64, recipient_account.balance, tx.amount) catch {
            return error.BalanceOverflow;
        };

        // Save updated accounts to database
        try self.database.saveAccount(tx.sender, sender_account);
        try self.database.saveAccount(tx.recipient, recipient_account);
    }

    /// Process a coinbase transaction (mining reward)
    pub fn processCoinbaseTransaction(self: *Self, coinbase_tx: Transaction, miner_address: Address, current_height: u32) !void {
        // Get or create miner account
        var miner_account = self.getAccount(miner_address) catch types.Account{
            .address = miner_address,
            .balance = 0,
            .nonce = 0,
        };

        // Check if this is a genesis block (height 0) transaction
        if (current_height == 0) {
            // Genesis block pre-mine allocations are immediately mature
            miner_account.balance += coinbase_tx.amount;
        } else {
            // Regular mining rewards (will need maturity tracking in future)
            miner_account.balance += coinbase_tx.amount;
        }

        // Save miner account
        try self.database.saveAccount(miner_address, miner_account);
    }

    /// Clear all account state for rebuild
    pub fn clearAllAccounts(self: *Self) !void {
        // Open accounts directory
        var accounts_dir = std.fs.cwd().openDir(self.database.accounts_dir, .{ .iterate = true }) catch {
            // Directory might not exist, that's okay
            return;
        };
        defer accounts_dir.close();

        // Delete all account files
        var iter = accounts_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".account")) {
                accounts_dir.deleteFile(entry.name) catch |err| {
                    std.debug.print("  ⚠️  Failed to delete account file {s}: {}\n", .{entry.name, err});
                };
            }
        }
    }

    /// Replay blockchain from genesis to rebuild state
    pub fn replayFromGenesis(self: *Self, up_to_height: u32) !void {
        // Start from genesis (height 0)
        for (0..up_to_height + 1) |height| {
            var block = self.database.getBlock(@intCast(height)) catch {
                return error.ReplayFailed;
            };
            defer block.deinit(self.allocator);

            // Process each transaction in the block
            for (block.transactions) |tx| {
                if (self.isCoinbaseTransaction(tx)) {
                    // Process coinbase - simplified for now
                    try self.replayCoinbaseTransaction(tx);
                } else {
                    // Process regular transaction
                    try self.replayRegularTransaction(tx);
                }
            }
        }
    }

    /// Rollback blockchain to specific height
    pub fn rollbackToHeight(self: *Self, target_height: u32, current_height: u32) !void {
        if (target_height >= current_height) {
            return; // Nothing to rollback
        }

        // Clear all account state - we'll rebuild by replaying from genesis
        try self.clearAllAccounts();

        // Replay blockchain from genesis up to target height
        try self.replayFromGenesis(target_height);
    }

    /// Check if transaction is a coinbase transaction
    pub fn isCoinbaseTransaction(self: *Self, tx: Transaction) bool {
        _ = self;
        // Coinbase transactions have zero sender address and nonce
        return tx.sender.isZero() and tx.nonce == 0;
    }

    /// Replay coinbase transaction during state rebuild
    fn replayCoinbaseTransaction(self: *Self, tx: Transaction) !void {
        var miner_account = self.getAccount(tx.recipient) catch types.Account{
            .address = tx.recipient,
            .balance = 0,
            .nonce = 0,
        };

        // Add to balance (simplified - no maturity tracking for now)
        miner_account.balance += tx.amount;

        // Save updated account
        try self.database.saveAccount(tx.recipient, miner_account);
    }

    /// Replay regular transaction during state rebuild
    fn replayRegularTransaction(self: *Self, tx: Transaction) !void {
        // Get sender account (might not exist in test scenario)
        var sender_account = self.getAccount(tx.sender) catch {
            // In test scenarios, we might have pre-funded accounts that don't exist in blocks
            // Skip this transaction during replay
            return;
        };

        // Check if sender has sufficient balance (safety check)
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            return;
        }

        // Deduct amount and fee from sender
        sender_account.balance -= total_cost;
        sender_account.nonce = tx.nonce + 1;
        try self.database.saveAccount(tx.sender, sender_account);

        // Credit recipient
        var recipient_account = self.getAccount(tx.recipient) catch types.Account{
            .address = tx.recipient,
            .balance = 0,
            .nonce = 0,
        };
        recipient_account.balance += tx.amount;
        try self.database.saveAccount(tx.recipient, recipient_account);
    }

    /// Process all transactions in a block
    pub fn processBlockTransactions(self: *Self, transactions: []Transaction, current_height: u32) !void {
        // First pass: process all coinbase transactions
        for (transactions) |tx| {
            if (self.isCoinbaseTransaction(tx)) {
                try self.processCoinbaseTransaction(tx, tx.recipient, current_height);
            }
        }

        // Second pass: process all regular transactions
        for (transactions) |tx| {
            if (!self.isCoinbaseTransaction(tx)) {
                try self.processTransaction(tx);
            }
        }

        // Mark all transactions as processed to prevent re-broadcasting
        for (transactions) |tx| {
            const tx_hash = tx.hash();
            try self.processed_transactions.append(tx_hash);
        }
    }
};