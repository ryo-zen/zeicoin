// state.zig - Chain State Manager
// Manages database ownership and account/balance operations
// This is the single source of truth for blockchain state

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const db = @import("../storage/db.zig");
const block_index = @import("block_index.zig");
const bech32 = @import("../crypto/bech32.zig");

const log = std.log.scoped(.chain);

// Helper function to format address as bech32 string for logging
fn formatAddress(allocator: std.mem.Allocator, address: Address) []const u8 {
    return bech32.encodeAddress(allocator, address, types.CURRENT_NETWORK) catch "<invalid>";
}


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

    /// Helper method to format address for logging in ChainState context
    fn formatAddressForLogging(self: *const Self, address: Address) []const u8 {
        return formatAddress(self.allocator, address);
    }

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
        log.info("✅ ChainState: Block index initialized", .{});
    }

    /// Check if a block hash already exists in the chain
    /// Important for preventing duplicate blocks
    pub fn hasBlock(self: *const Self, block_hash: Hash) bool {
        return self.block_index.hasBlock(block_hash);
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
            const balance_zei = @as(f64, @floatFromInt(account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const addr_str = self.formatAddressForLogging(address);
            defer self.allocator.free(addr_str);
            log.info("🔍 [ACCOUNT LOAD] Found existing account {s}: balance={d:.8} ZEI, nonce={}", .{ addr_str, balance_zei, account.nonce });
            return account;
        } else |err| switch (err) {
            db.DatabaseError.NotFound => {
                // Create new account with zero balance
                const new_account = types.Account{
                    .address = address,
                    .balance = 0,
                    .nonce = 0,
                };
                const balance_zei = @as(f64, @floatFromInt(new_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
                const addr_str = self.formatAddressForLogging(address);
                defer self.allocator.free(addr_str);
                log.info("🔍 [ACCOUNT LOAD] Created new account {s}: balance={d:.8} ZEI, nonce={}", .{ addr_str, balance_zei, new_account.nonce });
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
        // CRITICAL: Check for duplicate transaction before processing
        const tx_hash = tx.hash();
        if (self.database.hasTransaction(tx_hash)) {
            const tx_hash_hex = std.fmt.fmtSliceHexLower(tx_hash[0..8]);
            log.info("🚫 [DUPLICATE TX] Transaction {s} already exists in blockchain - SKIPPING to prevent double-spend", .{tx_hash_hex});
            return; // Skip processing duplicate transaction
        }

        log.info("🔍 [TX VALIDATION] =============================================", .{});
        log.info("🔍 [TX VALIDATION] Processing transaction:", .{});
        const sender_addr = self.formatAddressForLogging(tx.sender);
        defer self.allocator.free(sender_addr);
        const recipient_addr = self.formatAddressForLogging(tx.recipient);
        defer self.allocator.free(recipient_addr);
        log.info("🔍 [TX VALIDATION]   Sender: {s}", .{sender_addr});
        log.info("🔍 [TX VALIDATION]   Recipient: {s}", .{recipient_addr});
        log.info("🔍 [TX VALIDATION]   Amount: {} ZEI", .{tx.amount});
        log.info("🔍 [TX VALIDATION]   Fee: {} ZEI", .{tx.fee});
        log.info("🔍 [TX VALIDATION]   Nonce: {}", .{tx.nonce});

        // Get accounts
        log.info("🔍 [TX VALIDATION] Loading sender account...", .{});
        var sender_account = try self.getAccount(tx.sender);
        log.info("🔍 [TX VALIDATION] Loading recipient account...", .{});
        var recipient_account = try self.getAccount(tx.recipient);

        const sender_addr_2 = self.formatAddressForLogging(tx.sender);
        defer self.allocator.free(sender_addr_2);
        log.info("🔍 [TX VALIDATION] Processing transaction from sender: {s}", .{sender_addr_2});
        const sender_balance_zei = @as(f64, @floatFromInt(sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const recipient_balance_zei = @as(f64, @floatFromInt(recipient_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const amount_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const fee_zei = @as(f64, @floatFromInt(tx.fee)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        log.info("🔍 [TX VALIDATION] Sender balance: {d:.8} ZEI, nonce: {}", .{ sender_balance_zei, sender_account.nonce });
        log.info("🔍 [TX VALIDATION] Recipient balance: {d:.8} ZEI, nonce: {}", .{ recipient_balance_zei, recipient_account.nonce });
        log.info("🔍 [TX VALIDATION] Transaction amount: {d:.8} ZEI, fee: {d:.8} ZEI", .{ amount_zei, fee_zei });

        // 💰 Apply transaction with fee deduction
        // Check for integer overflow in addition
        const total_cost = std.math.add(u64, tx.amount, tx.fee) catch {
            log.info("❌ [TX VALIDATION] Integer overflow in cost calculation", .{});
            return error.IntegerOverflow;
        };

        const total_cost_zei = @as(f64, @floatFromInt(total_cost)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        log.info("🔍 [TX VALIDATION] Total cost: {d:.8} ZEI", .{total_cost_zei});

        // Safety check for sufficient balance
        if (sender_account.balance < total_cost) {
            const sender_balance_zei_err = @as(f64, @floatFromInt(sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const needed_zei = @as(f64, @floatFromInt(total_cost)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const shortfall_zei = @as(f64, @floatFromInt(total_cost - sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            log.info("❌ [TX VALIDATION] INSUFFICIENT BALANCE! Sender has {d:.8} ZEI, needs {d:.8} ZEI", .{ sender_balance_zei_err, needed_zei });
            log.info("❌ [TX VALIDATION] Shortfall: {d:.8} ZEI", .{shortfall_zei});
            return error.InsufficientBalance;
        }

        log.info("✅ [TX VALIDATION] Balance check passed", .{});

        // Log account state changes
        const sender_old_balance = sender_account.balance;
        const sender_old_nonce = sender_account.nonce;
        const recipient_old_balance = recipient_account.balance;

        sender_account.balance -= total_cost;

        // Check for nonce overflow
        sender_account.nonce = std.math.add(u64, sender_account.nonce, 1) catch {
            return error.NonceOverflow;
        };

        // Check for balance overflow on recipient
        recipient_account.balance = std.math.add(u64, recipient_account.balance, tx.amount) catch {
            return error.BalanceOverflow;
        };

        // Log detailed account changes

        const sender_old_zei = @as(f64, @floatFromInt(sender_old_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const sender_new_zei = @as(f64, @floatFromInt(sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const recipient_old_zei = @as(f64, @floatFromInt(recipient_old_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const recipient_new_zei = @as(f64, @floatFromInt(recipient_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const change_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const update_fee_zei = @as(f64, @floatFromInt(tx.fee)) / @as(f64, @floatFromInt(types.ZEI_COIN));

        const sender_addr_update = self.formatAddressForLogging(tx.sender);
        defer self.allocator.free(sender_addr_update);
        const recipient_addr_update = self.formatAddressForLogging(tx.recipient);
        defer self.allocator.free(recipient_addr_update);
        log.info("💰 [ACCOUNT UPDATE] SENDER {s}: {d:.8} → {d:.8} ZEI (−{d:.8}, nonce: {}→{})", .{ sender_addr_update, sender_old_zei, sender_new_zei, change_zei + update_fee_zei, sender_old_nonce, sender_account.nonce });
        log.info("💰 [ACCOUNT UPDATE] RECIPIENT {s}: {d:.8} → {d:.8} ZEI (+{d:.8})", .{ recipient_addr_update, recipient_old_zei, recipient_new_zei, change_zei });

        // Save updated accounts to database
        try self.database.saveAccount(tx.sender, sender_account);
        try self.database.saveAccount(tx.recipient, recipient_account);
    }

    /// Process a coinbase transaction (mining reward)
    pub fn processCoinbaseTransaction(self: *Self, coinbase_tx: Transaction, miner_address: Address, current_height: u32) !void {
        // CRITICAL: Check for duplicate coinbase transaction before processing
        const tx_hash = coinbase_tx.hash();
        if (self.database.hasTransaction(tx_hash)) {
            const tx_hash_hex = std.fmt.fmtSliceHexLower(tx_hash[0..8]);
            log.info("🚫 [DUPLICATE COINBASE] Coinbase transaction {s} already exists in blockchain - SKIPPING to prevent double-spend", .{tx_hash_hex});
            return; // Skip processing duplicate coinbase transaction
        }

        log.info("🔍 [COINBASE TX] =============================================", .{});
        const miner_addr = self.formatAddressForLogging(miner_address);
        defer self.allocator.free(miner_addr);
        log.info("🔍 [COINBASE TX] Processing coinbase transaction to miner: {s}", .{miner_addr});
        log.info("🔍 [COINBASE TX] Coinbase amount: {} ZEI, height: {}", .{ coinbase_tx.amount, current_height });

        // Get or create miner account
        var miner_account = self.getAccount(miner_address) catch types.Account{
            .address = miner_address,
            .balance = 0,
            .nonce = 0,
        };

        const balance_before = @as(f64, @floatFromInt(miner_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const immature_before = @as(f64, @floatFromInt(miner_account.immature_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        log.info("🔍 [COINBASE TX] Miner account BEFORE: balance={d:.8} ZEI, immature={d:.8} ZEI, nonce={}", .{ balance_before, immature_before, miner_account.nonce });

        // Check if this is a genesis block (height 0) transaction
        if (current_height == 0) {
            log.info("🔍 [COINBASE TX] Genesis block - adding {} ZEI to mature balance", .{coinbase_tx.amount});
            // Genesis block pre-mine allocations are immediately mature
            miner_account.balance += coinbase_tx.amount;
        } else {
            log.info("🔍 [COINBASE TX] Regular block - adding {} ZEI to immature balance", .{coinbase_tx.amount});
            // Regular mining rewards go to immature balance (100 block maturity)
            miner_account.immature_balance += coinbase_tx.amount;
        }

        const balance_after = @as(f64, @floatFromInt(miner_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const immature_after = @as(f64, @floatFromInt(miner_account.immature_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        log.info("🔍 [COINBASE TX] Miner account AFTER: balance={d:.8} ZEI, immature={d:.8} ZEI, nonce={}", .{ balance_after, immature_after, miner_account.nonce });

        // Log coinbase reward account change
        const reward_zei = @as(f64, @floatFromInt(coinbase_tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const miner_addr_update = self.formatAddressForLogging(miner_address);
        defer self.allocator.free(miner_addr_update);
        if (current_height == 0) {
            log.info("💰 [COINBASE UPDATE] MINER {s}: {d:.8} → {d:.8} ZEI (+{d:.8} mature reward)", .{ miner_addr_update, balance_before, balance_after, reward_zei });
        } else {
            log.info("💰 [COINBASE UPDATE] MINER {s}: immature {d:.8} → {d:.8} ZEI (+{d:.8} immature reward)", .{ miner_addr_update, immature_before, immature_after, reward_zei });
        }

        // Save miner account
        try self.database.saveAccount(miner_address, miner_account);
        log.info("🔍 [COINBASE TX] Miner account saved to database", .{});
    }

    /// Clear all account state for rebuild
    pub fn clearAllAccounts(self: *Self) !void {
        // With RocksDB, we would need to iterate and delete all account keys
        // For now, this is a no-op since we don't have a batch delete API
        // Accounts will be overwritten as needed during rebuild
        _ = self;
        log.info("  ⚠️  Account clearing not implemented for RocksDB backend", .{});
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
                log.info("⚠️ Failed to rebuild block index at height {}: {}", .{ height, err });
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
                    log.info("💰 Coinbase reward matured: {} ZEI for block {} (recipient: {})", .{ tx.amount, maturity_height, std.fmt.fmtSliceHexLower(tx.recipient.hash[0..8]) });
                }
            }
        }
    }

    /// Process all transactions in a block
    pub fn processBlockTransactions(self: *Self, transactions: []Transaction, current_height: u32) !void {
        log.info("🔍 [BLOCK TX] Processing {} transactions at height {}", .{ transactions.len, current_height });

        // First pass: process all coinbase transactions
        for (transactions, 0..) |tx, i| {
            if (self.isCoinbaseTransaction(tx)) {
                const tx_hash = tx.hash();

                // Check for duplicate processing to prevent double-spend during sync replay
                if (self.isTransactionProcessed(tx_hash)) {
                    log.info("🔄 [TX DEDUP] Coinbase transaction {} already processed, skipping", .{i});
                    continue;
                }

                log.info("🔍 [BLOCK TX] Processing coinbase transaction {} at height {}", .{ i, current_height });
                try self.processCoinbaseTransaction(tx, tx.recipient, current_height);
            }
        }

        // Second pass: process all regular transactions
        for (transactions, 0..) |tx, i| {
            if (!self.isCoinbaseTransaction(tx)) {
                const tx_hash = tx.hash();

                // Check for duplicate processing to prevent double-spend during sync replay
                if (self.isTransactionProcessed(tx_hash)) {
                    log.info("🔄 [TX DEDUP] Regular transaction {} already processed, skipping", .{i});
                    continue;
                }

                log.info("🔍 [BLOCK TX] Processing regular transaction {} at height {}", .{ i, current_height });
                try self.processTransaction(tx);
            }
        }

        // Mark all transactions as processed to prevent re-broadcasting
        for (transactions) |tx| {
            const tx_hash = tx.hash();
            try self.processed_transactions.append(tx_hash);
        }
    }

    /// Check if a transaction has already been processed (for sync deduplication)
    pub fn isTransactionProcessed(self: *const Self, tx_hash: [32]u8) bool {
        for (self.processed_transactions.items) |processed_hash| {
            if (std.mem.eql(u8, &processed_hash, &tx_hash)) {
                return true;
            }
        }
        return false;
    }
};
