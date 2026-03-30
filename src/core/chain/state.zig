// state.zig - Chain State Manager
// Manages database ownership and account/balance operations
// This is the single source of truth for blockchain state

const std = @import("std");
const builtin = @import("builtin");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const db = @import("../storage/db.zig");
const block_index = @import("block_index.zig");
const state_root = @import("state_root.zig");
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
    pub const SNAPSHOT_INTERVAL: u32 = 1000;

    // Core state storage
    database: *db.Database,
    processed_transactions: std.array_list.Managed([32]u8),

    // O(1) block lookups - replaces O(n) searches
    block_index: block_index.BlockIndex,

    mutex: std.Thread.Mutex,

    allocator: std.mem.Allocator,

    // State root cache (optimization for mining loop)
    cached_state_root: [32]u8,
    state_dirty: bool, // true = needs recalculation

    const Self = @This();

    /// Helper method to format address for logging in ChainState context
    fn formatAddressForLogging(self: *const Self, address: Address) []const u8 {
        // Safe to access allocator without lock as it's thread-safe or immutable in this context
        return formatAddress(self.allocator, address);
    }

    fn defaultAccount(address: Address) Account {
        return .{
            .address = address,
            .balance = 0,
            .nonce = 0,
            .immature_balance = 0,
        };
    }

    fn invalidateStateRootCache(self: *Self) void {
        self.cached_state_root = std.mem.zeroes([32]u8);
        self.state_dirty = true;
    }

    fn readPersistedAccount(self: *Self, address: Address) !?Account {
        if (self.database.getAccount(address)) |account| {
            return account;
        } else |err| switch (err) {
            db.DatabaseError.NotFound => return null,
            else => return err,
        }
    }

    fn getOrLoadStagedAccount(
        self: *Self,
        io: std.Io,
        staged_accounts: *std.AutoHashMap(Address, Account),
        address: Address,
    ) !*Account {
        const account_entry = try staged_accounts.getOrPut(address);
        if (!account_entry.found_existing) {
            account_entry.value_ptr.* = try self.getAccount(io, address);
        }
        return account_entry.value_ptr;
    }

    /// Initialize ChainState with database and allocator
    pub fn init(allocator: std.mem.Allocator, database: *db.Database) Self {
        return .{
            .database = database,
            .processed_transactions = std.array_list.Managed([32]u8).init(allocator),
            .block_index = block_index.BlockIndex.init(allocator),
            .mutex = .{},
            .allocator = allocator,
            .cached_state_root = std.mem.zeroes([32]u8), // Placeholder
            .state_dirty = true, // Force calculation on first access
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
    pub fn initializeBlockIndex(self: *Self, io: std.Io) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.block_index.rebuild(io, self.database);
        log.info("✅ ChainState: Block index initialized", .{});
    }

    /// Check if a block hash already exists in the chain
    /// Important for preventing duplicate blocks
    pub fn hasBlock(self: *Self, block_hash: Hash) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.block_index.hasBlock(block_hash);
    }

    /// Add block to index when new block is processed
    /// Maintains O(1) lookup performance for reorganizations
    pub fn indexBlock(self: *Self, height: u32, block_hash: Hash) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.block_index.addBlock(height, block_hash);
    }

    /// Remove blocks from index during reorganization
    /// Used when rolling back to a previous chain state
    pub fn removeBlocksFromIndex(self: *Self, from_height: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.block_index.removeFromHeight(from_height);
    }

    fn clearProcessedTransactions(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.processed_transactions.clearRetainingCapacity();
    }

    /// Get block height by hash - O(1) operation
    /// Replaces the O(n) search in reorganization.zig
    pub fn getBlockHeight(self: *Self, block_hash: Hash) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.block_index.getHeight(block_hash);
    }

    /// Get block hash by height - O(1) operation
    /// Useful for chain validation and reorganization
    pub fn getBlockHash(self: *Self, height: u32) ?Hash {
        self.mutex.lock();
        defer self.mutex.unlock();
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

    /// Get account by address without mutating persistent state on misses.
    pub fn getAccount(self: *Self, io: std.Io, address: Address) !types.Account {
        _ = io;
        return (try self.readPersistedAccount(address)) orelse defaultAccount(address);
    }

    /// Get account balance
    pub fn getBalance(self: *Self, io: std.Io, address: Address) !u64 {
        const account = try self.getAccount(io, address);
        return account.balance;
    }

    /// Get current blockchain height
    pub fn getHeight(self: *Self) !u32 {
        return self.database.getHeight();
    }

    /// Process a regular transaction and update account states
    pub fn processTransaction(self: *Self, io: std.Io, tx: Transaction, batch: ?*db.Database.WriteBatch, force_processing: bool) !void {
        // CRITICAL: Check for duplicate transaction before processing
        const tx_hash = tx.hash();
        if (!force_processing and self.database.hasTransaction(io, tx_hash)) {
            log.info("🚫 [DUPLICATE TX] Transaction {x} already exists in blockchain - SKIPPING to prevent double-spend", .{tx_hash[0..8]});
            return; // Skip processing duplicate transaction
        }

        // CACHE INVALIDATION: Account state will change
        self.invalidateStateRootCache();

        var debug_sender_addr: ?[]const u8 = null;
        defer if (debug_sender_addr) |addr| self.allocator.free(addr);

        var debug_recipient_addr: ?[]const u8 = null;
        defer if (debug_recipient_addr) |addr| self.allocator.free(addr);

        if (builtin.mode == .Debug) {
            debug_sender_addr = self.formatAddressForLogging(tx.sender);
            debug_recipient_addr = self.formatAddressForLogging(tx.recipient);

            log.debug("🔍 [TX VALIDATION] tx={x} sender={s} recipient={s} amount={} fee={} nonce={}", .{
                tx_hash[0..8],
                debug_sender_addr.?,
                debug_recipient_addr.?,
                tx.amount,
                tx.fee,
                tx.nonce,
            });
        }

        // Get accounts
        var sender_account = try self.getAccount(io, tx.sender);
        var recipient_account = try self.getAccount(io, tx.recipient);

        if (builtin.mode == .Debug) {
            const sender_balance_zei = @as(f64, @floatFromInt(sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const recipient_balance_zei = @as(f64, @floatFromInt(recipient_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const amount_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const fee_zei = @as(f64, @floatFromInt(tx.fee)) / @as(f64, @floatFromInt(types.ZEI_COIN));

            log.debug("🔍 [TX VALIDATION] sender_balance={d:.8} nonce={} recipient_balance={d:.8} nonce={} amount={d:.8} fee={d:.8}", .{
                sender_balance_zei,
                sender_account.nonce,
                recipient_balance_zei,
                recipient_account.nonce,
                amount_zei,
                fee_zei,
            });
        }

        // 💰 Apply transaction with fee deduction
        // Check for integer overflow in addition
        const total_cost = std.math.add(u64, tx.amount, tx.fee) catch {
            log.info("❌ [TX VALIDATION] Integer overflow in cost calculation", .{});
            return error.IntegerOverflow;
        };

        if (builtin.mode == .Debug) {
            const total_cost_zei = @as(f64, @floatFromInt(total_cost)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            log.debug("🔍 [TX VALIDATION] total cost: {d:.8} ZEI", .{total_cost_zei});
        }

        // Safety check for sufficient balance
        if (sender_account.balance < total_cost) {
            log.info("❌ [TX VALIDATION] Insufficient balance for tx {x}: has {}, needs {}", .{
                tx_hash[0..8],
                sender_account.balance,
                total_cost,
            });
            return error.InsufficientBalance;
        }

        // Log account state changes
        const sender_old_balance = sender_account.balance;
        const sender_old_nonce = sender_account.nonce;
        const recipient_old_balance = recipient_account.balance;

        sender_account.balance -= total_cost;

        // Advance nonce to tx.nonce + 1 to stay consistent with the actual nonce used.
        // Transactions may have future nonces (>= expected), so we set nonce = tx.nonce + 1
        // rather than blindly incrementing, ensuring the next expected nonce is correct.
        sender_account.nonce = std.math.add(u64, tx.nonce, 1) catch {
            return error.NonceOverflow;
        };

        // Check for balance overflow on recipient
        recipient_account.balance = std.math.add(u64, recipient_account.balance, tx.amount) catch {
            return error.BalanceOverflow;
        };

        // Log detailed account changes

        if (builtin.mode == .Debug) {
            const sender_old_zei = @as(f64, @floatFromInt(sender_old_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const sender_new_zei = @as(f64, @floatFromInt(sender_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const recipient_old_zei = @as(f64, @floatFromInt(recipient_old_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const recipient_new_zei = @as(f64, @floatFromInt(recipient_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const change_zei = @as(f64, @floatFromInt(tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
            const update_fee_zei = @as(f64, @floatFromInt(tx.fee)) / @as(f64, @floatFromInt(types.ZEI_COIN));

            log.debug("💰 [ACCOUNT UPDATE] SENDER {s}: {d:.8} → {d:.8} ZEI (−{d:.8}, nonce: {}→{})", .{
                debug_sender_addr.?,
                sender_old_zei,
                sender_new_zei,
                change_zei + update_fee_zei,
                sender_old_nonce,
                sender_account.nonce,
            });
            log.debug("💰 [ACCOUNT UPDATE] RECIPIENT {s}: {d:.8} → {d:.8} ZEI (+{d:.8})", .{
                debug_recipient_addr.?,
                recipient_old_zei,
                recipient_new_zei,
                change_zei,
            });
        }

        // Save updated accounts to database
        if (batch) |b| {
            try b.saveAccount(tx.sender, sender_account);
            try b.saveAccount(tx.recipient, recipient_account);
        } else {
            try self.database.saveAccount(tx.sender, sender_account);
            try self.database.saveAccount(tx.recipient, recipient_account);
        }
    }

    /// Process a coinbase transaction (mining reward)
    pub fn processCoinbaseTransaction(self: *Self, io: std.Io, coinbase_tx: Transaction, miner_address: Address, current_height: u32, batch: ?*db.Database.WriteBatch, force_processing: bool) !void {
        _ = force_processing;

        // Coinbase transaction hashes are not unique across heights, so block-level
        // deduplication must guard replay instead of tx-hash checks here.

        // CACHE INVALIDATION: Miner account state will change
        self.invalidateStateRootCache();

        // SECURITY: Validate supply cap before processing coinbase
        const current_supply = self.database.getTotalSupply();
        if (current_supply + coinbase_tx.amount > types.MAX_SUPPLY) {
            log.err("❌ [SUPPLY CAP] Coinbase would exceed MAX_SUPPLY: {} + {} > {}", .{
                current_supply,
                coinbase_tx.amount,
                types.MAX_SUPPLY,
            });
            return error.SupplyCapExceeded;
        }

        log.info("🔍 [COINBASE TX] =============================================", .{});
        const miner_addr = self.formatAddressForLogging(miner_address);
        defer self.allocator.free(miner_addr);
        log.info("🔍 [COINBASE TX] Processing coinbase transaction to prefunded account: {s}", .{miner_addr});
        log.info("🔍 [COINBASE TX] Coinbase amount: {} ZEI, height: {}", .{ coinbase_tx.amount, current_height });

        // Get or create miner account
        var miner_account = try self.getAccount(io, miner_address);

        const balance_before = @as(f64, @floatFromInt(miner_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const immature_before = @as(f64, @floatFromInt(miner_account.immature_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));

        // Check if this is a genesis block (height 0) transaction
        if (current_height == 0) {
            log.info("🔍 [COINBASE TX] Genesis block - adding {} ZEI to mature balance", .{coinbase_tx.amount});
            // Genesis block pre-mine allocations are immediately mature
            miner_account.balance += coinbase_tx.amount;
            // Genesis pre-mine is immediately circulating
            if (batch == null) {
                try self.database.addToCirculatingSupply(coinbase_tx.amount);
            }
        } else {
            log.info("🔍 [COINBASE TX] Regular block - adding {} ZEI to immature balance", .{coinbase_tx.amount});
            // Regular mining rewards go to immature balance (100 block maturity)
            miner_account.immature_balance += coinbase_tx.amount;
        }

        // Update total supply (includes both mature and immature coins)
        if (batch == null) {
            try self.database.addToTotalSupply(coinbase_tx.amount);
        }

        const balance_after = @as(f64, @floatFromInt(miner_account.balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const immature_after = @as(f64, @floatFromInt(miner_account.immature_balance)) / @as(f64, @floatFromInt(types.ZEI_COIN));

        // Log coinbase reward account change
        const reward_zei = @as(f64, @floatFromInt(coinbase_tx.amount)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        const miner_addr_update = self.formatAddressForLogging(miner_address);
        defer self.allocator.free(miner_addr_update);
        if (current_height == 0) {
            log.info("💰 [COINBASE UPDATE] MINER {s}: {d:.8} → {d:.8} ZEI (+{d:.8} mature reward)", .{ miner_addr_update, balance_before, balance_after, reward_zei });
        } else {
            log.info("💰 [COINBASE UPDATE] MINER {s}: immature {d:.8} → {d:.8} ZEI (+{d:.8} immature reward)", .{ miner_addr_update, immature_before, immature_after, reward_zei });
        }

        // Log supply tracking
        if (batch == null) {
            const new_total_supply = self.database.getTotalSupply();
            const supply_pct = @as(f64, @floatFromInt(new_total_supply)) / @as(f64, @floatFromInt(types.MAX_SUPPLY)) * 100.0;
            log.info("📊 [SUPPLY] Total: {} / {} ({d:.4}% of max)", .{
                new_total_supply / types.ZEI_COIN,
                types.MAX_SUPPLY / types.ZEI_COIN,
                supply_pct,
            });
        }

        // Save miner account
        if (batch) |b| {
            try b.saveAccount(miner_address, miner_account);
        } else {
            try self.database.saveAccount(miner_address, miner_account);
        }
    }

    /// Clear all account state for rebuild
    pub fn clearAllAccounts(self: *Self) !void {
        // CACHE INVALIDATION: All accounts being deleted
        self.invalidateStateRootCache();

        // Use the new batch deletion capability in Database
        // This ensures no "dirty state" remains from reverted blocks
        try self.database.deleteAllAccounts();
        log.info("🧹 All accounts cleared for state rebuild", .{});
    }

    /// Replay blockchain from genesis to rebuild state
    pub fn replayFromGenesis(self: *Self, io: std.Io, up_to_height: u32) !void {
        // Start from genesis (height 0)
        for (0..up_to_height + 1) |height| {
            const block_height: u32 = @intCast(height);
            var block = self.database.getBlock(io, block_height) catch |err| {
                log.err("❌ [REPLAY] Failed to load block {}: {}", .{ block_height, err });
                return err;
            };
            defer block.deinit(self.allocator);

            // Rebuild block index during replay
            const block_hash = block.hash();
            self.indexBlock(block_height, block_hash) catch |err| {
                log.err("❌ [REPLAY] Failed to index block {}: {}", .{ block_height, err });
                return err;
            };

            try self.processBlockTransactions(io, block.transactions, block_height, true);
        }
    }

    /// Rebuild canonical account state and block index from genesis up to a height.
    /// This is the safe recovery path after rollback/reorg failures.
    pub fn rebuildStateToHeight(self: *Self, io: std.Io, target_height: u32) !void {
        // CACHE INVALIDATION: State is rebuilt from canonical blocks.
        self.invalidateStateRootCache();

        self.removeBlocksFromIndex(0);
        self.clearProcessedTransactions();

        try self.clearAllAccounts();
        try self.database.resetTotalSupply();
        try self.database.updateCirculatingSupply(0);

        try self.replayFromGenesis(io, target_height);
    }

    fn replayRange(self: *Self, io: std.Io, start_height: u32, end_height: u32) !void {
        if (start_height > end_height) return;

        var height = start_height;
        while (height <= end_height) : (height += 1) {
            var block = self.database.getBlock(io, height) catch |err| {
                log.err("❌ [REPLAY] Failed to load block {}: {}", .{ height, err });
                return err;
            };
            defer block.deinit(self.allocator);

            const block_hash = block.hash();
            self.indexBlock(height, block_hash) catch |err| {
                log.err("❌ [REPLAY] Failed to index block {}: {}", .{ height, err });
                return err;
            };

            try self.processBlockTransactions(io, block.transactions, height, true);
        }
    }

    fn resetVolatileStateFromHeight(self: *Self, from_height: u32) void {
        self.invalidateStateRootCache();
        self.clearProcessedTransactions();
        self.removeBlocksFromIndex(from_height);
    }

    fn loadCanonicalBlockHash(self: *Self, io: std.Io, height: u32) !Hash {
        if (self.getBlockHash(height)) |block_hash| {
            return block_hash;
        }

        var block = try self.database.getBlock(io, height);
        defer block.deinit(self.allocator);
        return block.hash();
    }

    pub fn verifyCurrentStateRoot(self: *Self, expected_state_root: Hash) !void {
        const restored_root = try self.calculateStateRoot();
        if (!std.mem.eql(u8, &restored_root, &expected_state_root)) {
            log.err("❌ [SNAPSHOT] Restored state root mismatch", .{});
            log.err("   Expected: {x}", .{&expected_state_root});
            log.err("   Actual:   {x}", .{&restored_root});
            return error.SnapshotStateRootMismatch;
        }
    }

    fn shouldSavePeriodicSnapshot(height: u32) bool {
        return height == 0 or (height % SNAPSHOT_INTERVAL) == 0;
    }

    pub fn maybeSavePeriodicStateSnapshot(self: *Self, io: std.Io, height: u32, block_hash: Hash) !void {
        _ = io;
        if (!shouldSavePeriodicSnapshot(height)) {
            return;
        }

        const current_state_root = try self.calculateStateRoot();
        try state_root.saveStateSnapshot(self.allocator, self.database, height, block_hash, current_state_root);
    }

    pub fn saveExactStateSnapshotAtHeight(self: *Self, io: std.Io, height: u32) !void {
        const block_hash = try self.loadCanonicalBlockHash(io, height);
        const current_state_root = try self.calculateStateRoot();
        try state_root.saveStateSnapshot(self.allocator, self.database, height, block_hash, current_state_root);
    }

    pub fn restoreStateSnapshot(self: *Self, io: std.Io, target_height: u32) !bool {
        const expected_block_hash = try self.loadCanonicalBlockHash(io, target_height);
        const restored = try state_root.loadStateSnapshot(
            self.allocator,
            self.database,
            target_height,
            expected_block_hash,
        );
        const anchor = restored orelse return false;

        self.resetVolatileStateFromHeight(target_height + 1);
        try self.verifyCurrentStateRoot(anchor.state_root);
        return true;
    }

    pub fn restoreNearestStateSnapshotAtOrBelow(self: *Self, io: std.Io, target_height: u32) !?state_root.SnapshotAnchor {
        const snapshot_heights = try state_root.collectSnapshotHeightsAtOrBelow(self.allocator, self.database, target_height);
        defer self.allocator.free(snapshot_heights);

        var index = snapshot_heights.len;
        while (index > 0) {
            index -= 1;
            const snapshot_height = snapshot_heights[index];
            const expected_block_hash = self.loadCanonicalBlockHash(io, snapshot_height) catch |err| {
                log.warn("⚠️ [SNAPSHOT] Skipping snapshot at height {}: failed to load canonical block hash: {}", .{ snapshot_height, err });
                continue;
            };

            const restored = state_root.loadStateSnapshot(
                self.allocator,
                self.database,
                snapshot_height,
                expected_block_hash,
            ) catch |err| switch (err) {
                error.SnapshotBlockHashMismatch => {
                    log.warn("⚠️ [SNAPSHOT] Skipping stale snapshot at height {} due to block-hash mismatch", .{snapshot_height});
                    continue;
                },
                error.SnapshotStateRootMismatch => {
                    log.err("❌ [SNAPSHOT] Skipping corrupted snapshot at height {} due to state-root mismatch", .{snapshot_height});
                    continue;
                },
                error.SnapshotHeightMismatch => {
                    log.err("❌ [SNAPSHOT] Skipping malformed snapshot at height {}", .{snapshot_height});
                    continue;
                },
                else => return err,
            };

            const anchor = restored orelse continue;
            self.resetVolatileStateFromHeight(snapshot_height + 1);
            try self.verifyCurrentStateRoot(anchor.state_root);
            return anchor;
        }

        return null;
    }

    pub fn refreshBlockIndexRange(self: *Self, from_height: u32, blocks: []const types.Block) !void {
        self.resetVolatileStateFromHeight(from_height);
        for (blocks, 0..) |block, i| {
            const height = from_height + @as(u32, @intCast(i));
            try self.indexBlock(height, block.hash());
        }
    }

    /// Rollback blockchain to specific height
    pub fn rollbackToHeight(self: *Self, io: std.Io, target_height: u32, current_height: u32) !void {
        if (target_height >= current_height) {
            return; // Nothing to rollback
        }

        // Delete rolled-back blocks from database to prevent duplicate TX detection
        try self.database.deleteBlocksFromHeight(target_height + 1, current_height);
        try self.database.saveHeight(target_height);
        try self.rebuildStateToHeight(io, target_height);
    }

    /// Rollback state (accounts) to specific height WITHOUT deleting blocks
    /// This is used during reorganization to safely revert state before applying new blocks
    /// If the reorg fails, the old blocks are still in the database for recovery
    pub fn rollbackStateWithoutDeletingBlocks(self: *Self, io: std.Io, target_height: u32) !void {
        const current_height = try self.getHeight();
        if (target_height >= current_height) {
            return; // Nothing to rollback
        }

        if (try self.restoreStateSnapshot(io, target_height)) {
            try self.saveExactStateSnapshotAtHeight(io, target_height);
            std.log.info("🔄 [STATE ROLLBACK] State reverted to height {} from exact snapshot (blocks preserved)", .{target_height});
            return;
        }

        if (try self.restoreNearestStateSnapshotAtOrBelow(io, target_height)) |snapshot_anchor| {
            if (snapshot_anchor.height < target_height) {
                try self.replayRange(io, snapshot_anchor.height + 1, target_height);
            }
            try self.saveExactStateSnapshotAtHeight(io, target_height);
            std.log.info("🔄 [STATE ROLLBACK] State reverted to height {} from nearest snapshot at {}", .{ target_height, snapshot_anchor.height });
            return;
        }

        try self.rebuildStateToHeight(io, target_height);
        try self.saveExactStateSnapshotAtHeight(io, target_height);

        std.log.info("🔄 [STATE ROLLBACK] State reverted to height {} via replay fallback (blocks preserved)", .{target_height});
    }

    /// Mature coinbase rewards after 100 block confirmation period
    pub fn matureCoinbaseRewards(self: *Self, io: std.Io, maturity_height: u32) !void {
        var circulating_supply_delta: u64 = 0;
        try self.applyCoinbaseMaturityTransitions(io, maturity_height, null, &circulating_supply_delta);
    }

    fn applyCoinbaseMaturityTransitions(
        self: *Self,
        io: std.Io,
        maturity_height: u32,
        batch: ?*db.Database.WriteBatch,
        circulating_supply_delta: *u64,
    ) !void {
        // Get the block at maturity height to find coinbase transactions
        var mature_block = self.database.getBlock(io, maturity_height) catch {
            // Block might not exist (genesis or test scenario)
            return;
        };
        defer mature_block.deinit(self.allocator);

        // Process coinbase transactions in the mature block
        for (mature_block.transactions) |tx| {
            if (tx.isCoinbase()) {
                // Move rewards from immature to mature balance
                var miner_account = try self.getAccount(io, tx.recipient);

                if (miner_account.immature_balance < tx.amount) {
                    continue;
                }

                self.invalidateStateRootCache();

                miner_account.immature_balance -= tx.amount;
                miner_account.balance = try std.math.add(u64, miner_account.balance, tx.amount);

                if (batch) |b| {
                    try b.saveAccount(tx.recipient, miner_account);
                } else {
                    try self.database.saveAccount(tx.recipient, miner_account);
                }

                circulating_supply_delta.* = try std.math.add(u64, circulating_supply_delta.*, tx.amount);

                if (batch == null) {
                    try self.database.addToCirculatingSupply(tx.amount);
                }

                log.info("💰 Coinbase reward matured: {} ZEI for block {} (recipient: {x})", .{ tx.amount, maturity_height, tx.recipient.hash[0..8] });
            }
        }
    }

    /// Process all transactions in a block
    pub fn processBlockTransactions(self: *Self, io: std.Io, transactions: []const Transaction, current_height: u32, force_processing: bool) !void {
        log.info("🔍 [BLOCK TX] Processing {} transactions at height {}", .{ transactions.len, current_height });

        var staged_accounts = std.AutoHashMap(Address, Account).init(self.allocator);
        defer staged_accounts.deinit();

        const current_total_supply = self.database.getTotalSupply();
        var total_supply_delta: u64 = 0;
        var circulating_supply_delta: u64 = 0;

        for (transactions, 0..) |tx, i| {
            if (!tx.isValid()) {
                return error.InvalidTransaction;
            }

            if (tx.isCoinbase()) {
                log.info("🔍 [BLOCK TX] Processing coinbase transaction {} at height {}", .{ i, current_height });
                total_supply_delta = try std.math.add(u64, total_supply_delta, tx.amount);

                const staged_miner = try self.getOrLoadStagedAccount(io, &staged_accounts, tx.recipient);
                if (current_height == 0) {
                    staged_miner.balance = try std.math.add(u64, staged_miner.balance, tx.amount);
                    circulating_supply_delta = try std.math.add(u64, circulating_supply_delta, tx.amount);
                } else {
                    staged_miner.immature_balance = try std.math.add(u64, staged_miner.immature_balance, tx.amount);
                }

                continue;
            }

            if (!force_processing and self.database.hasTransaction(io, tx.hash())) {
                log.info("🚫 [DUPLICATE TX] Transaction {x} already exists in blockchain - SKIPPING to prevent double-spend", .{tx.hash()[0..8]});
                continue;
            }

            log.info("🔍 [BLOCK TX] Processing regular transaction {} at height {}", .{ i, current_height });

            _ = try self.getOrLoadStagedAccount(io, &staged_accounts, tx.sender);
            _ = try self.getOrLoadStagedAccount(io, &staged_accounts, tx.recipient);

            const staged_sender = staged_accounts.getPtr(tx.sender).?;
            const staged_recipient = staged_accounts.getPtr(tx.recipient).?;
            const total_cost = try std.math.add(u64, tx.amount, tx.fee);

            if (staged_sender.balance < total_cost) {
                return error.InsufficientBalance;
            }

            if (tx.nonce < staged_sender.nonce) {
                return error.InvalidNonce;
            }

            staged_sender.balance -= total_cost;
            staged_sender.nonce = try std.math.add(u64, tx.nonce, 1);
            staged_recipient.balance = try std.math.add(u64, staged_recipient.balance, tx.amount);
        }

        const new_total_supply = try std.math.add(u64, current_total_supply, total_supply_delta);
        if (new_total_supply > types.MAX_SUPPLY) {
            return error.SupplyCapExceeded;
        }

        const coinbase_maturity = types.getCoinbaseMaturity();
        if (current_height >= coinbase_maturity) {
            const maturity_height = current_height - coinbase_maturity;
            var mature_block = self.database.getBlock(io, maturity_height) catch null;
            if (mature_block) |*block| {
                defer block.deinit(self.allocator);

                for (block.transactions) |mature_tx| {
                    if (!mature_tx.isCoinbase()) continue;

                    const staged_miner = try self.getOrLoadStagedAccount(io, &staged_accounts, mature_tx.recipient);
                    if (staged_miner.immature_balance < mature_tx.amount) continue;

                    staged_miner.immature_balance -= mature_tx.amount;
                    staged_miner.balance = try std.math.add(u64, staged_miner.balance, mature_tx.amount);
                    circulating_supply_delta = try std.math.add(u64, circulating_supply_delta, mature_tx.amount);

                    log.info("💰 Coinbase reward matured: {} ZEI for block {} (recipient: {x})", .{ mature_tx.amount, maturity_height, mature_tx.recipient.hash[0..8] });
                }
            }
        }

        var batch = self.database.createWriteBatch();
        defer batch.deinit();

        if (staged_accounts.count() > 0) {
            self.invalidateStateRootCache();

            var account_iterator = staged_accounts.iterator();
            while (account_iterator.next()) |entry| {
                try batch.saveAccount(entry.key_ptr.*, entry.value_ptr.*);
            }
        }

        if (total_supply_delta > 0) {
            try batch.updateTotalSupply(new_total_supply);
        }

        if (circulating_supply_delta > 0) {
            const current_circulating_supply = self.database.getCirculatingSupply();
            const new_circulating_supply = try std.math.add(u64, current_circulating_supply, circulating_supply_delta);
            try batch.updateCirculatingSupply(new_circulating_supply);
        }

        try batch.commit();

        self.mutex.lock();
        defer self.mutex.unlock();
        for (transactions) |tx| {
            const tx_hash = tx.hash();
            try self.processed_transactions.append(tx_hash);
        }
    }

    /// Check if a transaction has already been processed (for sync deduplication)
    pub fn isTransactionProcessed(self: *Self, tx_hash: [32]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.processed_transactions.items) |processed_hash| {
            if (std.mem.eql(u8, &processed_hash, &tx_hash)) {
                return true;
            }
        }
        return false;
    }

    /// Calculate the Merkle root of all account states in the database
    /// This creates a cryptographic commitment to the entire account state
    /// Any change to any account balance or nonce will change the root
    pub fn calculateStateRoot(self: *Self) ![32]u8 {
        // OPTIMIZATION: Return cached value if state hasn't changed
        if (!self.state_dirty) {
            log.debug("🌳 [STATE ROOT CACHE HIT] Returning cached value: {x}", .{self.cached_state_root});
            return self.cached_state_root;
        }

        log.debug("🌳 [STATE ROOT CACHE MISS] Recalculating (state was modified)", .{});

        // Structure to collect account hashes
        const AccountHashCollector = struct {
            hashes: *std.array_list.Managed([32]u8),

            pub fn callback(account: types.Account, user_data: ?*anyopaque) bool {
                const collector = @as(*@This(), @ptrCast(@alignCast(user_data.?)));

                // Hash the account state using our Merkle tree utility
                const account_hash = util.MerkleTree.hashAccountState(account);
                collector.hashes.append(account_hash) catch {
                    return false; // Stop iteration on allocation error
                };

                return true; // Continue iteration
            }
        };

        // Collect all account hashes in deterministic order
        var account_hashes = std.array_list.Managed([32]u8).init(self.allocator);
        defer account_hashes.deinit();

        var collector = AccountHashCollector{ .hashes = &account_hashes };

        try self.database.iterateAccounts(AccountHashCollector.callback, &collector);

        // Calculate Merkle root from all account hashes
        const root = try util.MerkleTree.calculateRoot(self.allocator, account_hashes.items);

        // CACHE UPDATE: Store result and mark clean
        self.cached_state_root = root;
        self.state_dirty = false;

        const account_count = account_hashes.items.len;
        log.info("🌳 [STATE ROOT] Calculated from {} accounts: {x}", .{ account_count, root });

        return root;
    }

    /// Debug helper for reorg investigations: log a deterministic slice of account state.
    pub fn debugLogAccounts(self: *Self, label: []const u8, max_accounts: usize) !void {
        const AccountLogger = struct {
            allocator: std.mem.Allocator,
            label: []const u8,
            seen: usize = 0,
            max_accounts: usize,

            fn callback(account: types.Account, user_data: ?*anyopaque) bool {
                const logger = @as(*@This(), @ptrCast(@alignCast(user_data.?)));
                if (logger.seen >= logger.max_accounts) {
                    return false;
                }

                const addr = formatAddress(logger.allocator, account.address);
                defer if (!std.mem.eql(u8, addr, "<invalid>")) logger.allocator.free(addr);

                const account_hash = util.MerkleTree.hashAccountState(account);
                log.warn("🧪 [STATE DEBUG] {s} account[{d}] addr={s} balance={} immature={} nonce={} hash={x}", .{
                    logger.label,
                    logger.seen,
                    addr,
                    account.balance,
                    account.immature_balance,
                    account.nonce,
                    account_hash,
                });

                logger.seen += 1;
                return true;
            }
        };

        var logger = AccountLogger{
            .allocator = self.allocator,
            .label = label,
            .max_accounts = max_accounts,
        };

        try self.database.iterateAccounts(AccountLogger.callback, &logger);
        log.warn("🧪 [STATE DEBUG] {s} logged {} account(s){s}", .{
            label,
            logger.seen,
            if (logger.seen == max_accounts) " (truncated)" else "",
        });
    }
};
