// state.zig - Chain State Manager
// Manages database ownership and account/balance operations
// This is the single source of truth for blockchain state

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const db = @import("../storage/db.zig");
const block_index = @import("block_index.zig");

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
    database: *db.Database,
    processed_transactions: std.ArrayList([32]u8),
    
    // O(1) block lookups - replaces O(n) searches
    block_index: block_index.BlockIndex,
    
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize ChainState with database and allocator
    pub fn init(allocator: std.mem.Allocator, database: *db.Database) Self {
        return .{
            .database = database,
            .processed_transactions = std.ArrayList([32]u8).init(allocator),
            .block_index = block_index.BlockIndex.init(allocator),
            .allocator = allocator,
        };
    }

    /// Cleanup resources
    /// Note: Database is owned by ZeiCoin, we only clean up our own resources
    pub fn deinit(self: *Self) void {
        self.processed_transactions.deinit();
        self.block_index.deinit();
    }

    /// Initialize block index from existing blockchain data
    /// Should be called after ChainState creation to populate O(1) lookups
    pub fn initializeBlockIndex(self: *Self) !void {
        try self.block_index.rebuild(self.database);
        print("✅ ChainState: Block index initialized\n", .{});
    }

    /// Add block to index when new block is processed
    /// Maintains O(1) lookup performance for reorganizations
    pub fn indexBlock(self: *Self, height: u32, block_hash: Hash) !void {
        try self.block_index.addBlock(height, block_hash);
    }

    /// Remove blocks from index during reorganization
    /// Used when rolling back to a previous chain state
    pub fn removeBlocksFromIndex(self: *Self, from_height: u32) void {
        self.block_index.removeFromHeight(from_height);
    }

    /// Get block height by hash - O(1) operation
    /// Replaces the O(n) search in reorganization.zig
    pub fn getBlockHeight(self: *const Self, block_hash: Hash) ?u32 {
        return self.block_index.getHeight(block_hash);
    }

    /// Get block hash by height - O(1) operation
    /// Useful for chain validation and reorganization
    pub fn getBlockHash(self: *const Self, height: u32) ?Hash {
        return self.block_index.getHash(height);
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
            // Regular mining rewards go to immature balance (100 block maturity)
            miner_account.immature_balance += coinbase_tx.amount;
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

            // Rebuild block index during replay
            const block_hash = block.hash();
            self.indexBlock(@intCast(height), block_hash) catch |err| {
                print("⚠️ Failed to rebuild block index at height {}: {}\n", .{height, err});
            };

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

        // Remove blocks from index that will be rolled back
        self.removeBlocksFromIndex(target_height + 1);
        
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

    /// Mature coinbase rewards after 100 block confirmation period
    pub fn matureCoinbaseRewards(self: *Self, maturity_height: u32) !void {
        // Get the block at maturity height to find coinbase transactions
        var mature_block = self.database.getBlock(maturity_height) catch {
            // Block might not exist (genesis or test scenario)
            return;
        };
        defer mature_block.deinit(self.allocator);
        
        // Process coinbase transactions in the mature block
        for (mature_block.transactions) |tx| {
            if (self.isCoinbaseTransaction(tx)) {
                // Move rewards from immature to mature balance
                var miner_account = self.getAccount(tx.recipient) catch {
                    // Miner account should exist, but handle gracefully
                    continue;
                };
                
                // Only mature if there's actually immature balance to move
                if (miner_account.immature_balance >= tx.amount) {
                    miner_account.immature_balance -= tx.amount;
                    miner_account.balance += tx.amount;
                    try self.database.saveAccount(tx.recipient, miner_account);
                    print("💰 Coinbase reward matured: {} ZEI for block {} (recipient: {})\n", .{
                        tx.amount,
                        maturity_height,
                        std.fmt.fmtSliceHexLower(tx.recipient.hash[0..8])
                    });
                }
            }
        }
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