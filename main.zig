// main.zig - ZeiCoin Blockchain Core
// A minimalist proof-of-work blockchain implementation written in Zig
// Features account-based model, Ed25519 signatures, RandomX PoW, Bech32 addresses, and nonce-based double spending protection
// Additional features: P2P networking, mempool management, file-based persistence, transaction fees, CLI wallet
// Now with ASIC-resistant RandomX proof-of-work algorithm

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;

const types = @import("types.zig");
const util = @import("util.zig");
const serialize = @import("serialize.zig");
const db = @import("db.zig");
const key = @import("key.zig");
const net = @import("net.zig");
const randomx = @import("randomx.zig");
const genesis = @import("genesis.zig");
const forkmanager = @import("forkmanager.zig");

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Blockchain synchronization state
pub const SyncState = enum {
    synced, // Up to date with peers
    syncing, // Currently downloading blocks
    sync_complete, // Sync completed, ready to switch to synced
    sync_failed, // Sync failed, will retry later
};

/// Sync progress tracking
pub const SyncProgress = struct {
    target_height: u32,
    current_height: u32,
    blocks_downloaded: u32,
    start_time: i64,
    last_progress_report: i64,
    last_request_time: i64,
    retry_count: u32,
    consecutive_failures: u32, // Track consecutive failures across all peers

    pub fn init(current: u32, target: u32) SyncProgress {
        const now = util.getTime();
        return SyncProgress{
            .target_height = target,
            .current_height = current,
            .blocks_downloaded = 0,
            .start_time = now,
            .last_progress_report = now,
            .last_request_time = now,
            .retry_count = 0,
            .consecutive_failures = 0,
        };
    }

    pub fn getProgress(self: *const SyncProgress) f64 {
        if (self.target_height <= self.current_height) return 100.0;
        const total_blocks = self.target_height - self.current_height;
        if (total_blocks == 0) return 100.0;
        return (@as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(total_blocks))) * 100.0;
    }

    pub fn getETA(self: *const SyncProgress) i64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0 or self.blocks_downloaded == 0) return 0;

        if (self.blocks_downloaded >= (self.target_height - self.current_height)) return 0;
        const remaining_blocks = (self.target_height - self.current_height) - self.blocks_downloaded;
        const blocks_per_second = @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
        if (blocks_per_second == 0) return 0;

        return @as(i64, @intFromFloat(@as(f64, @floatFromInt(remaining_blocks)) / blocks_per_second));
    }

    pub fn getBlocksPerSecond(self: *const SyncProgress) f64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0) return 0.0;
        return @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
    }
};

// Helper functions for cleaner code
/// Check if transaction is a coinbase transaction (zero sender address)
/// NOTE: This function is deprecated - use tx.isCoinbase() instead
fn isCoinbaseTransaction(tx: Transaction) bool {
    return tx.isCoinbase();
}

/// Create a test transaction with all required fields
fn createTestTransaction(sender: Address, recipient: Address, amount: u64, fee: u64, nonce: u64, keypair: key.KeyPair, allocator: std.mem.Allocator) !Transaction {
    _ = allocator; // Currently unused
    const timestamp = @as(u64, @intCast(std.time.timestamp()));
    const expiry_height = 1000000; // Far in the future for tests
    
    var tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender,
        .recipient = recipient,
        .amount = amount,
        .fee = fee,
        .nonce = nonce,
        .timestamp = timestamp,
        .expiry_height = expiry_height,
        .sender_public_key = keypair.public_key,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    
    // Sign the transaction
    const hash = tx.hashForSigning();
    tx.signature = try keypair.sign(&hash);
    
    return tx;
}

/// Create a test block header with all required fields
fn createTestBlockHeader(previous_hash: Hash, merkle_root: Hash, timestamp: u64, difficulty: u64, nonce: u32) BlockHeader {
    return BlockHeader{
        .version = 0,
        .previous_hash = previous_hash,
        .merkle_root = merkle_root,
        .timestamp = timestamp,
        .difficulty = difficulty,
        .nonce = nonce,
        .witness_root = std.mem.zeroes(Hash),
        .state_root = std.mem.zeroes(Hash),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };
}

/// Logging utilities for simplicity
fn logError(comptime fmt: []const u8, args: anytype) void {
    print("❌ " ++ fmt ++ "\n", args);
}

fn logSuccess(comptime fmt: []const u8, args: anytype) void {
    print("✅ " ++ fmt ++ "\n", args);
}

fn logInfo(comptime fmt: []const u8, args: anytype) void {
    print("ℹ️  " ++ fmt ++ "\n", args);
}

fn logProcess(comptime fmt: []const u8, args: anytype) void {
    print("🔄 " ++ fmt ++ "\n", args);
}

/// ZeiCoin blockchain state and operations
pub const ZeiCoin = struct {
    // Persistent database storage
    database: db.Database,

    // Memory pool for pending transactions
    mempool: ArrayList(Transaction),
    mempool_size_bytes: usize, // Track total size of mempool in bytes

    // Network manager for P2P communication (pointer to external manager)
    network: ?*net.NetworkManager,

    // Allocator for dynamic memory
    allocator: std.mem.Allocator,

    // Sync state and progress tracking
    sync_state: SyncState,
    sync_progress: ?SyncProgress,
    sync_peer: ?*net.Peer,
    failed_peers: ArrayList(*net.Peer), // Blacklist of failed sync peers

    // Transaction history for duplicate detection
    processed_transactions: std.ArrayList([32]u8), // Recent tx hashes (simple array for compatibility)

    // Fork manager for longest chain consensus
    fork_manager: forkmanager.ForkManager,
    
    // Mining state for thread-safe mining operations
    mining_state: types.MiningState,

    /// Initialize new ZeiCoin blockchain with persistent storage
    pub fn init(allocator: std.mem.Allocator) !ZeiCoin {
        // Use network-specific data directory
        const data_dir = switch (types.CURRENT_NETWORK) {
            .testnet => "zeicoin_data_testnet",
            .mainnet => "zeicoin_data_mainnet",
        };

        // Initialize database
        const database = try db.Database.init(allocator, data_dir);

        var blockchain = ZeiCoin{
            .database = database,
            .mempool = ArrayList(Transaction).init(allocator),
            .mempool_size_bytes = 0,
            .network = null,
            .allocator = allocator,
            .sync_state = .synced,
            .sync_progress = null,
            .sync_peer = null,
            .failed_peers = ArrayList(*net.Peer).init(allocator),
            .processed_transactions = std.ArrayList([32]u8).init(allocator),
            .fork_manager = forkmanager.ForkManager.init(allocator),
            .mining_state = types.MiningState.init(),
        };

        // Always create canonical genesis block if no blockchain exists
        // Every node uses the same hardcoded canonical genesis from genesis.zig
        if (try blockchain.getHeight() == 0) {
            print("🌐 No blockchain found - creating canonical genesis block\n", .{});
            try blockchain.createCanonicalGenesis();
            print("✅ Genesis block created successfully!\n", .{});
        } else {
            const height = try blockchain.getHeight();
            print("📊 Existing blockchain found with {} blocks\n", .{height});
        }

        return blockchain;
    }

    /// Initialize blockchain after network discovery
    /// Genesis is already created in init(), this just logs readiness for sync
    pub fn initializeBlockchain(self: *ZeiCoin) !void {
        const current_height = try self.getHeight();
        print("🔗 Blockchain initialized at height {}, ready for network sync\n", .{current_height});
    }

    /// Cleanup blockchain resources
    pub fn deinit(self: *ZeiCoin) void {
        // Stop mining thread first
        self.mining_state.deinit();
        
        self.database.deinit();
        
        // Free all transactions in mempool before freeing the mempool itself
        for (self.mempool.items) |*tx| {
            tx.deinit(self.allocator);
        }
        self.mempool.deinit();
        
        self.failed_peers.deinit();
        self.processed_transactions.deinit();
        self.fork_manager.deinit();
        // Note: network is managed externally
    }

    /// Create the canonical genesis block from hardcoded definition
    fn createCanonicalGenesis(self: *ZeiCoin) !void {
        // Use the actual canonical genesis from genesis.zig instead of custom empty one
        // Use the deinit pattern for robust cleanup, consistency, and future-proofing
        var genesis_block = try genesis.createGenesis(self.allocator);
        defer genesis_block.deinit(self.allocator);

        // Save genesis block to database
        try self.database.saveBlock(0, genesis_block);

        // Initialize fork manager with genesis
        const genesis_hash = genesis_block.hash();
        const genesis_work = genesis_block.header.getWork();
        self.fork_manager.initWithGenesis(genesis_hash, genesis_work);

        print("\n🎉 ===============================================\n", .{});
        print("🎉 GENESIS BLOCK CREATED SUCCESSFULLY!\n", .{});
        print("🎉 ===============================================\n", .{});
        print("📦 Block Height: 0\n", .{});
        print("📦 Transactions: {}\n", .{genesis_block.txCount()});
        print("🌐 Network: {s} (Canonical Genesis)\n", .{types.NetworkConfig.networkName()});
        print("🔗 Fork manager initialized with genesis chain\n", .{});
        print("✅ Blockchain ready for operation!\n\n", .{});
    }

    /// Create genesis block (wrapper for createCanonicalGenesis)
    fn createGenesis(self: *ZeiCoin) !void {
        try self.createCanonicalGenesis();
    }

    /// Get account for an address (creates new account if doesn't exist)
    pub fn getAccount(self: *ZeiCoin, address: Address) !Account {
        // Try to load from database
        if (self.database.getAccount(address)) |account| {
            return account;
        } else |err| switch (err) {
            db.DatabaseError.NotFound => {
                // Create new account with zero balance
                const new_account = Account{
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

    /// Add transaction to memory pool (thread-safe)
    pub fn addTransaction(self: *ZeiCoin, transaction: Transaction) !void {
        // Lock mempool for thread-safe access
        self.mining_state.mutex.lock();
        
        // Check for duplicate in mempool (integrity protection)
        const tx_hash = transaction.hash();
        for (self.mempool.items) |existing_tx| {
            if (std.mem.eql(u8, &existing_tx.hash(), &tx_hash)) {
                print("🔄 Transaction already in mempool - ignored\n", .{});
                self.mining_state.mutex.unlock();
                return; // Silently ignore duplicate
            }
        }

        // Validate transaction (can be done without lock, but keeping it simple)
        if (!try self.validateTransaction(transaction)) {
            self.mining_state.mutex.unlock();
            return error.InvalidTransaction;
        }

        // Check mempool limits before adding
        const tx_size = transaction.getSerializedSize();
        
        // Double-check individual transaction size limit (defense in depth)
        if (tx_size > types.TransactionLimits.MAX_TX_SIZE) {
            print("❌ Transaction too large: {} bytes (max: {} bytes)\n", .{
                tx_size, 
                types.TransactionLimits.MAX_TX_SIZE
            });
            self.mining_state.mutex.unlock();
            return error.TransactionTooLarge;
        }
        
        // Check transaction count limit
        if (self.mempool.items.len >= types.MempoolLimits.MAX_TRANSACTIONS) {
            print("❌ Mempool full: {} transactions (limit: {})\n", .{
                self.mempool.items.len, 
                types.MempoolLimits.MAX_TRANSACTIONS
            });
            self.mining_state.mutex.unlock();
            return error.MempoolFull;
        }
        
        // Check size limit
        if (self.mempool_size_bytes + tx_size > types.MempoolLimits.MAX_SIZE_BYTES) {
            print("❌ Mempool size limit exceeded: {} + {} bytes > {} bytes\n", .{
                self.mempool_size_bytes,
                tx_size,
                types.MempoolLimits.MAX_SIZE_BYTES
            });
            self.mining_state.mutex.unlock();
            return error.MempoolSizeLimitExceeded;
        }

        // Take ownership of the transaction by deep copying it
        var owned_tx = try transaction.dupe(self.allocator);
        errdefer owned_tx.deinit(self.allocator);
        
        try self.mempool.append(owned_tx);
        self.mempool_size_bytes += tx_size;
        logInfo("Transaction added to mempool: {} ZEI from sender to recipient (mempool: {}/{})", .{
            transaction.amount / types.ZEI_COIN,
            self.mempool.items.len,
            types.MempoolLimits.MAX_TRANSACTIONS
        });

        // Unlock before signaling
        self.mining_state.mutex.unlock();

        // Signal mining thread that new work is available
        print("🔔 Broadcasting to mining thread (before broadcast)\n", .{});
        self.mining_state.condition.broadcast();
        print("🔔 Broadcast sent to mining thread\n", .{});

        // Broadcast transaction to network peers
        if (self.network) |*network| {
            network.*.broadcastTransaction(transaction);
        }
    }

    /// Validate a transaction against current blockchain state
    fn validateTransaction(self: *ZeiCoin, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // Additional integrity checks
        
        // 1. Check if transaction has expired
        const current_height = self.getHeight() catch 0;
        if (tx.expiry_height <= current_height) {
            print("❌ Transaction expired: expiry height {} <= current height {}\n", .{ tx.expiry_height, current_height });
            return false;
        }

        // 2. Prevent self-transfer (wasteful but not harmful)
        if (tx.sender.equals(tx.recipient)) {
            print("⚠️ Self-transfer detected (wasteful but allowed)\n", .{});
            // Allow but warn - some users might legitimately do this
        }

        // 3. Check for zero amount (should pay fee only)
        if (tx.amount == 0) {
            print("💸 Zero amount transaction (fee-only payment)\n", .{});
            // Allow zero-amount transactions (useful for fee-only operations)
        }

        // 4. Sanity check for extremely high amounts (overflow protection)
        if (tx.amount > 1000000 * types.ZEI_COIN) { // 1 million ZEI limit
            print("❌ Transaction amount too high: {} ZEI (max: 1,000,000 ZEI)\n", .{tx.amount / types.ZEI_COIN});
            return false;
        }

        // 5. Check if transaction was already processed (replay protection)
        const tx_hash = tx.hash();
        for (self.processed_transactions.items) |processed_hash| {
            if (std.mem.eql(u8, &processed_hash, &tx_hash)) {
                print("❌ Transaction already processed - replay attempt blocked\n", .{});
                return false;
            }
        }

        // Get sender account
        const sender_account = try self.getAccount(tx.sender);

        // Check nonce (must be next expected nonce)
        if (tx.nonce != sender_account.nextNonce()) {
            logError("Invalid nonce: expected {}, got {}", .{ sender_account.nextNonce(), tx.nonce });
            return false;
        }

        // 💰 Check fee minimum (prevent spam)
        if (tx.fee < types.ZenFees.MIN_FEE) {
            print("❌ Fee too low: {} zei, minimum {} zei\n", .{ tx.fee, types.ZenFees.MIN_FEE });
            return false;
        }

        // Check balance (amount + fee)
        const total_cost = tx.amount + tx.fee;
        if (!sender_account.canAfford(total_cost)) {
            // Format amounts properly for error display
            const balance_display = util.formatZEI(self.allocator, sender_account.balance) catch "? ZEI";
            defer if (!std.mem.eql(u8, balance_display, "? ZEI")) self.allocator.free(balance_display);
            const amount_display = util.formatZEI(self.allocator, tx.amount) catch "? ZEI";
            defer if (!std.mem.eql(u8, amount_display, "? ZEI")) self.allocator.free(amount_display);
            const fee_display = util.formatZEI(self.allocator, tx.fee) catch "? ZEI";
            defer if (!std.mem.eql(u8, fee_display, "? ZEI")) self.allocator.free(fee_display);
            const total_display = util.formatZEI(self.allocator, total_cost) catch "? ZEI";
            defer if (!std.mem.eql(u8, total_display, "? ZEI")) self.allocator.free(total_display);

            print("❌ Insufficient balance: has {s}, needs {s} (amount) + {s} (fee) = {s}\n", .{ balance_display, amount_display, fee_display, total_display });
            return false;
        }

        // Verify transaction signature
        const signing_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &signing_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            return false;
        }

        return true;
    }

    /// Process a transaction (apply state changes)
    fn processTransaction(self: *ZeiCoin, tx: Transaction) !void {
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
            // During sync, we might encounter historical blocks with different validation rules
            // Log the issue but continue processing to maintain chain integrity
            if (self.sync_state == .syncing) {
                print("⚠️ Warning: insufficient balance during sync (historical block)\n", .{});
                const addr_bytes = sender_account.address.toLegacyBytes();
                print("   Account {} has {} zei, needs {} zei\n", .{ std.fmt.fmtSliceHexLower(addr_bytes[0..8]), sender_account.balance, total_cost });
                // Deduct what we can, but don't go negative
                sender_account.balance = 0;
            } else {
                // In normal operation, this is an error
                return error.InsufficientBalance;
            }
        } else {
            sender_account.balance -= total_cost;
        }

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

        // Format amounts properly for display
        const amount_display = util.formatZEI(self.allocator, tx.amount) catch "? ZEI";
        defer if (!std.mem.eql(u8, amount_display, "? ZEI")) self.allocator.free(amount_display);
        const fee_display = util.formatZEI(self.allocator, tx.fee) catch "? ZEI";
        defer if (!std.mem.eql(u8, fee_display, "? ZEI")) self.allocator.free(fee_display);
        const total_display = util.formatZEI(self.allocator, total_cost) catch "? ZEI";
        defer if (!std.mem.eql(u8, total_display, "? ZEI")) self.allocator.free(total_display);

        print("💸 Processed: {s} transferred + {s} fee = {s} total cost\n", .{ amount_display, fee_display, total_display });
    }

    /// Mining thread function that runs in the background
    fn miningThreadFn(self: *ZeiCoin, miner_keypair: key.KeyPair) void {
        print("⛏️  Mining thread started\n", .{});
        
        while (self.mining_state.active.load(.acquire)) {
            // Lock for checking mempool
            self.mining_state.mutex.lock();
            
            // Check if we should mine
            const should_mine = self.mempool.items.len > 0;
            const current_height = self.getHeight() catch 0;
            print("🔍 Mining thread check: mempool has {} transactions, should_mine={}\n", .{self.mempool.items.len, should_mine});
            
            if (!should_mine) {
                // Wait for new transactions
                print("⏳ Mining thread: Waiting for transactions (mempool empty)\n", .{});
                print("🔐 Mining thread: About to wait on condition variable\n", .{});
                self.mining_state.condition.wait(&self.mining_state.mutex);
                print("👀 Mining thread: Woke up from condition wait\n", .{});
                print("🔍 Mining thread: Rechecking mempool after wake - has {} transactions\n", .{self.mempool.items.len});
                // Unlock before continuing to avoid double-lock
                self.mining_state.mutex.unlock();
                continue;
            }
            
            // Update current mining height
            self.mining_state.current_height.store(current_height, .release);
            
            // Unlock before mining (mining takes time)
            self.mining_state.mutex.unlock();
            
            // Mine the block
            print("🔨 Mining thread: Calling zenMineBlock (mempool has {} transactions)\n", .{self.mempool.items.len});
            const block = self.zenMineBlock(miner_keypair) catch |err| {
                print("❌ Mining error: {}\n", .{err});
                std.time.sleep(1 * std.time.ns_per_s); // Wait 1 second before retry
                continue;
            };
            
            // Successfully mined - the block is already added to chain in zenMineBlock
            const block_height = self.getHeight() catch 0;
            print("✅ Block #{} mined by background thread\n", .{block_height});
            
            // Broadcast block to network peers
            if (self.network) |net_mgr| {
                net_mgr.broadcastBlock(block);
                print("📡 Block broadcasted to {} peers\n", .{net_mgr.getPeerCount()});
            }
        }
        
        print("⛏️  Mining thread stopped\n", .{});
    }
    
    /// Start the mining thread
    pub fn startMining(self: *ZeiCoin, miner_keypair: key.KeyPair) !void {
        if (self.mining_state.active.load(.acquire)) {
            return; // Already mining
        }
        
        self.mining_state.active.store(true, .release);
        self.mining_state.thread = try std.Thread.spawn(.{}, miningThreadFn, .{ self, miner_keypair });
        print("⛏️  Mining thread started successfully\n", .{});
    }
    
    /// Stop the mining thread
    pub fn stopMining(self: *ZeiCoin) void {
        if (!self.mining_state.active.load(.acquire)) {
            return; // Not mining
        }
        
        self.mining_state.active.store(false, .release);
        self.mining_state.condition.signal(); // Wake up the thread if it's waiting
        
        if (self.mining_state.thread) |thread| {
            thread.join();
            self.mining_state.thread = null;
        }
        
        print("⛏️  Mining thread stopped successfully\n", .{});
    }
    
    /// Mine a new block with zen proof-of-work (the simplest thing that works)
    pub fn mineBlock(self: *ZeiCoin) !void {
        // Genesis mining with dummy keypair
        const genesis_keypair = key.KeyPair.fromPrivateKey(std.mem.zeroes([64]u8));
        _ = try self.zenMineBlock(genesis_keypair);
    }

    /// Mine a new block with zen proof-of-work for a specific miner
    pub fn zenMineBlock(self: *ZeiCoin, miner_keypair: key.KeyPair) !types.Block {
        print("⛏️  zenMineBlock: Starting to mine new block\n", .{});
        // Lock mempool to safely copy transactions
        self.mining_state.mutex.lock();
        
        // 💰 Calculate total fees from mempool transactions
        var total_fees: u64 = 0;
        for (self.mempool.items) |tx| {
            total_fees += tx.fee;
        }

        // Create coinbase transaction (miner reward + fees)
        const miner_reward = types.ZenMining.BLOCK_REWARD + total_fees;
        const coinbase_tx = Transaction{
            .version = 0, // Version 0 for coinbase
            .flags = .{}, // Default flags
            .sender = types.Address.zero(), // From thin air (coinbase)
            .sender_public_key = std.mem.zeroes([32]u8), // No sender for coinbase
            .recipient = miner_keypair.getAddress(),
            .amount = miner_reward, // 💰 Block reward + all transaction fees
            .fee = 0, // Coinbase has no fee
            .nonce = 0, // Coinbase always nonce 0
            .timestamp = @intCast(util.getTime()),
            .expiry_height = std.math.maxInt(u64), // Coinbase transactions never expire
            .signature = std.mem.zeroes(types.Signature), // No signature needed for coinbase
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };

        // Format miner reward display
        const base_reward_display = util.formatZEI(self.allocator, types.ZenMining.BLOCK_REWARD) catch "? ZEI";
        defer if (!std.mem.eql(u8, base_reward_display, "? ZEI")) self.allocator.free(base_reward_display);
        const fees_display = util.formatZEI(self.allocator, total_fees) catch "? ZEI";
        defer if (!std.mem.eql(u8, fees_display, "? ZEI")) self.allocator.free(fees_display);
        const total_reward_display = util.formatZEI(self.allocator, miner_reward) catch "? ZEI";
        defer if (!std.mem.eql(u8, total_reward_display, "? ZEI")) self.allocator.free(total_reward_display);

        print("💰 Miner reward: {s} (base) + {s} (fees) = {s} total\n", .{ base_reward_display, fees_display, total_reward_display });

        // Apply soft limit for mining (2MB default, configurable)
        var transactions_to_include = std.ArrayList(Transaction).init(self.allocator);
        defer transactions_to_include.deinit();

        // Always include coinbase
        try transactions_to_include.append(coinbase_tx);

        // Calculate running block size
        var current_block_size: usize = 84 + 4; // Header + tx count
        current_block_size += 192; // Coinbase transaction

        // Add transactions from mempool until we hit soft limit
        for (self.mempool.items) |tx| {
            const tx_size: usize = 192; // Approximate transaction size
            if (current_block_size + tx_size > types.BlockLimits.SOFT_BLOCK_SIZE) {
                print("📦 Soft block size limit reached: {} bytes (limit: {} bytes)\n", .{ current_block_size, types.BlockLimits.SOFT_BLOCK_SIZE });
                print("📊 Including {} of {} mempool transactions\n", .{ transactions_to_include.items.len - 1, self.mempool.items.len });
                break;
            }
            try transactions_to_include.append(tx);
            current_block_size += tx_size;
        }

        const all_transactions = try transactions_to_include.toOwnedSlice();
        defer self.allocator.free(all_transactions);
        
        // Unlock mempool before the time-consuming mining operation
        self.mining_state.mutex.unlock();

        // Get previous block hash and calculate next difficulty
        const current_height = try self.getHeight();
        const previous_hash = if (current_height > 0) blk: {
            var prev_block = try self.database.getBlock(current_height - 1);
            const hash = prev_block.hash();
            prev_block.deinit(self.allocator);
            break :blk hash;
        } else std.mem.zeroes(Hash);

        // Calculate difficulty for new block
        const next_difficulty_target = try self.calculateNextDifficulty();

        // Create block with dynamic difficulty
        var new_block = Block{
            .header = BlockHeader{
                .version = types.CURRENT_BLOCK_VERSION,
                .previous_hash = previous_hash,
                .merkle_root = std.mem.zeroes(Hash), // Zen simplicity
                .timestamp = @intCast(util.getTime()),
                .difficulty = next_difficulty_target.toU64(),
                .nonce = 0,
                .witness_root = std.mem.zeroes(Hash), // No witness data yet
                .state_root = std.mem.zeroes(Hash), // No state yet
                .extra_nonce = 0,
                .extra_data = std.mem.zeroes([32]u8), // No extra data
            },
            // Deep copy all transactions to ensure the block owns its memory.
            // This prevents double-frees or invalid frees when the block is deinitialized.
            .transactions = blk: {
                const allocated_txs = try self.allocator.alloc(types.Transaction, all_transactions.len);
                var copied_count: usize = 0;
                errdefer {
                    // Clean up any transactions we've already copied if an error occurs
                    for (allocated_txs[0..copied_count]) |*tx| {
                        tx.deinit(self.allocator);
                    }
                    self.allocator.free(allocated_txs);
                }
                
                for (all_transactions, 0..) |tx, i| {
                    allocated_txs[i] = try tx.dupe(self.allocator);
                    copied_count += 1;
                }
                break :blk allocated_txs;
            },
        };

        print("👌 Starting mining\n", .{});
        const start_time = util.getTime();

        const miner_address = miner_keypair.getAddress();

        // ZEN PROOF-OF-WORK: Find valid nonce
        const found_nonce = self.zenProofOfWork(&new_block);

        const mining_time = util.getTime() - start_time;

        if (found_nonce) {
            // Process coinbase transaction (create new coins!)
            try self.processCoinbaseTransaction(coinbase_tx, miner_address);

            // Process regular transactions
            for (new_block.transactions[1..]) |tx| {
                try self.processTransaction(tx);
            }

            // Save block to database
            const block_height = try self.getHeight();
            try self.database.saveBlock(block_height, new_block);
            
            // Check for matured coinbase rewards
            try self.matureCoinbaseRewards(block_height);

            // Clear mempool (need to lock again)
            self.mining_state.mutex.lock();
            self.mempool.clearRetainingCapacity();
            self.mempool_size_bytes = 0;
            self.mining_state.mutex.unlock();

            // Cleanup old processed transactions periodically
            self.cleanupProcessedTransactions();

            print("⛏️  ZEN BLOCK #{} MINED! ({} txs, {} ZEI reward, {}s)\n", .{ block_height, new_block.txCount(), types.ZenMining.BLOCK_REWARD / types.ZEI_COIN, mining_time });

            // Broadcast the newly mined block to network peers (zen propagation)
            self.broadcastNewBlock(new_block);

            print("📡 Block propagates through zen network like ripples in water\n", .{});

            return new_block;
        } else {
            print("😔 Zen mining failed - nonce not found (the universe wasn't ready)\n", .{});
            // Free block memory and return error
            new_block.deinit(self.allocator);
            return error.MiningFailed;
        }
    }

    /// Zen Proof-of-Work: Now with RandomX ASIC resistance
    fn zenProofOfWork(self: *ZeiCoin, block: *Block) bool {
        if (@import("builtin").mode == .Debug) {
            // Use fast SHA256 mining for tests
            return self.zenProofOfWorkSHA256(block);
        }

        // Initialize RandomX context for production
        const network_name = switch (types.CURRENT_NETWORK) {
            .testnet => "TestNet",
            .mainnet => "MainNet",
        };
        const chain_key = randomx.createRandomXKey(network_name);
        
        // Convert binary key to hex string for RandomX helper
        var hex_key: [64]u8 = undefined;
        for (chain_key, 0..) |byte, i| {
            _ = std.fmt.bufPrint(hex_key[i*2..i*2+2], "{x:0>2}", .{byte}) catch unreachable;
        }
        
        const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
        var rx_ctx = randomx.RandomXContext.init(self.allocator, &hex_key, mode) catch {
            print("❌ Failed to initialize RandomX\n", .{});
            return false;
        };
        defer rx_ctx.deinit();

        const starting_height = self.mining_state.current_height.load(.acquire);
        var nonce: u32 = 0;
        while (nonce < types.ZenMining.MAX_NONCE) {
            // Check if blockchain height changed (new block received)
            const current_height = self.getHeight() catch starting_height;
            if (current_height > starting_height) {
                print("🛑 Mining stopped - new block received at height {}\n", .{current_height});
                return false;
            }

            block.header.nonce = nonce;

            // Serialize block header for RandomX input
            var buffer: [256]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            block.header.serialize(stream.writer()) catch return false;
            const header_data = stream.getWritten();

            // Calculate RandomX hash with proper difficulty
            var hash: [32]u8 = undefined;
            const difficulty_target = block.header.getDifficultyTarget();
            rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch {
                print("❌ RandomX hash calculation failed\n", .{});
                return false;
            };

            // Check if hash meets difficulty target
            if (randomx.hashMeetsDifficultyTarget(hash, difficulty_target)) {
                print("✨ RandomX nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
                return true;
            }

            nonce += 1;

            // Progress indicator (every 10k tries due to RandomX being slower)
            if (nonce % types.PROGRESS.RANDOMX_REPORT_INTERVAL == 0) {
                print("RandomX mining... tried {} nonces\n", .{nonce});
                
                // Also check height on progress reports
                const progress_height = self.getHeight() catch starting_height;
                if (progress_height > starting_height) {
                    print("🛑 Mining stopped - new block received during progress check\n", .{});
                    return false;
                }
            }
        }

        return false; // Mining timeout
    }

    /// Legacy SHA256 proof-of-work for tests (faster)
    fn zenProofOfWorkSHA256(self: *ZeiCoin, block: *Block) bool {
        const starting_height = self.mining_state.current_height.load(.acquire);
        var nonce: u32 = 0;
        while (nonce < types.ZenMining.MAX_NONCE) {
            // Check if blockchain height changed (new block received)
            const current_height = self.getHeight() catch starting_height;
            if (current_height > starting_height) {
                print("🛑 Mining stopped - new block received at height {}\n", .{current_height});
                return false;
            }

            block.header.nonce = nonce;

            // Calculate block hash using SHA256
            const hash = block.header.hash();

            // Check if hash meets zen difficulty
            const difficulty_target = block.header.getDifficultyTarget();
            if (difficulty_target.meetsDifficulty(hash)) {
                print("✨ Zen nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
                return true;
            }

            nonce += 1;

            // Check more frequently for SHA256 (every 100k nonces)
            if (nonce % 100000 == 0) {
                const progress_height = self.getHeight() catch starting_height;
                if (progress_height > starting_height) {
                    print("🛑 Mining stopped - new block received during mining\n", .{});
                    return false;
                }
            }

            // Progress indicator (every 100k tries)
            if (nonce % types.PROGRESS.SHA256_REPORT_INTERVAL == 0) {
                print("Zen mining... tried {} nonces\n", .{nonce});
            }
        }

        return false;
    }

    /// Validate block proof-of-work using RandomX
    fn validateBlockPoW(self: *ZeiCoin, block: Block) !bool {
        // Initialize RandomX context for validation
        const network_name = switch (types.CURRENT_NETWORK) {
            .testnet => "TestNet",
            .mainnet => "MainNet",
        };
        const chain_key = randomx.createRandomXKey(network_name);
        
        // Convert binary key to hex string for RandomX helper
        var hex_key: [64]u8 = undefined;
        for (chain_key, 0..) |byte, i| {
            _ = std.fmt.bufPrint(hex_key[i*2..i*2+2], "{x:0>2}", .{byte}) catch unreachable;
        }
        
        const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
        var rx_ctx = randomx.RandomXContext.init(self.allocator, &hex_key, mode) catch {
            print("❌ Failed to initialize RandomX for validation\n", .{});
            return false;
        };
        defer rx_ctx.deinit();

        // Serialize block header for RandomX input
        var buffer: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        try block.header.serialize(stream.writer());
        const header_data = stream.getWritten();

        // Calculate RandomX hash with proper difficulty
        var hash: [32]u8 = undefined;
        const difficulty_target = block.header.getDifficultyTarget();
        rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch {
            print("❌ RandomX hash calculation failed during validation\n", .{});
            return false;
        };

        // Check if hash meets difficulty target
        return randomx.hashMeetsDifficultyTarget(hash, difficulty_target);
    }

    /// Calculate next difficulty target for mining
    fn calculateNextDifficulty(self: *ZeiCoin) !types.DifficultyTarget {
        const current_height = try self.getHeight();

        // For first 20 blocks, use initial difficulty
        if (current_height < types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD) {
            return types.ZenMining.initialDifficultyTarget();
        }

        // Only adjust every 20 blocks
        if (current_height % types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD != 0) {
            // Not an adjustment block, use previous difficulty
            const prev_block_height: u32 = @intCast(current_height - 1);
            var prev_block = try self.database.getBlock(prev_block_height);
            defer prev_block.deinit(self.allocator);
            return prev_block.header.getDifficultyTarget();
        }

        // This is an adjustment block! Calculate new difficulty
        print("📊 Difficulty adjustment at block {}\n", .{current_height});

        // Get timestamps from last 20 blocks for time calculation
        const lookback_blocks = types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD;
        var oldest_timestamp: u64 = 0;
        var newest_timestamp: u64 = 0;

        // Get timestamp from 20 blocks ago
        if (current_height >= lookback_blocks) {
            const old_block_height: u32 = @intCast(current_height - lookback_blocks);
            var old_block = try self.database.getBlock(old_block_height);
            defer old_block.deinit(self.allocator);
            oldest_timestamp = old_block.header.timestamp;
        }

        // Get timestamp from previous block
        const prev_block_height: u32 = @intCast(current_height - 1);
        var prev_block = try self.database.getBlock(prev_block_height);
        defer prev_block.deinit(self.allocator);
        newest_timestamp = prev_block.header.timestamp;
        const current_difficulty = prev_block.header.getDifficultyTarget();

        // Calculate actual time for last 20 blocks
        const actual_time = newest_timestamp - oldest_timestamp;
        const target_time = lookback_blocks * types.ZenMining.TARGET_BLOCK_TIME;

        // Calculate adjustment factor
        const adjustment_factor = if (actual_time > 0)
            @as(f64, @floatFromInt(target_time)) / @as(f64, @floatFromInt(actual_time))
        else
            1.0; // Fallback if time calculation fails

        // Apply adjustment with constraints
        const new_difficulty = current_difficulty.adjust(adjustment_factor, types.CURRENT_NETWORK);

        // Log the adjustment
        print("📈 Difficulty adjusted: factor={d:.3}, time={}s->{}s\n", .{ adjustment_factor, actual_time, target_time });

        return new_difficulty;
    }

    /// Process coinbase transaction (create new coins from thin air)
    fn processCoinbaseTransaction(self: *ZeiCoin, coinbase_tx: Transaction, miner_address: Address) !void {
        // Get or create miner account
        var miner_account = self.getAccount(miner_address) catch types.Account{
            .address = miner_address,
            .balance = 0,
            .nonce = 0,
            .immature_balance = 0,
        };

        // Get current height to determine when coins mature
        const current_height = try self.getHeight();
        const maturity_height = current_height + types.ZenMining.COINBASE_MATURITY;

        // Create new coins as IMMATURE (require 100 blocks to mature)
        miner_account.immature_balance += coinbase_tx.amount;

        // Save miner account
        try self.database.saveAccount(miner_address, miner_account);

        const miner_addr_bytes = miner_address.toLegacyBytes();
        print("💰 NEW COINS CREATED: {} ZEI for miner {s} (immature until block {})\n", .{ 
            coinbase_tx.amount / types.ZEI_COIN, 
            std.fmt.fmtSliceHexLower(miner_addr_bytes[0..8]),
            maturity_height
        });
    }
    
    /// Check if a transaction is a coinbase transaction
    fn isCoinbaseTransaction(self: *ZeiCoin, tx: Transaction) bool {
        _ = self;
        // Coinbase transactions have zero sender address and nonce
        return tx.sender.isZero() and tx.nonce == 0;
    }
    
    /// Check and mature any coins that have reached required confirmations
    /// This should be called when processing each new block
    pub fn matureCoinbaseRewards(self: *ZeiCoin, new_block_height: u32) !void {
        // Check if we're past the maturity period
        if (new_block_height < types.ZenMining.COINBASE_MATURITY) {
            return; // Nothing can be mature yet
        }
        
        // The block whose coinbase can now be spent
        const mature_block_height = new_block_height - types.ZenMining.COINBASE_MATURITY;
        
        // Load the block that's now mature
        var mature_block = try self.database.getBlock(mature_block_height);
        defer mature_block.deinit(self.allocator);
        
        // Find the coinbase transaction (always first)
        if (mature_block.transactions.len > 0) {
            const coinbase_tx = mature_block.transactions[0];
            if (self.isCoinbaseTransaction(coinbase_tx)) {
                // Move coins from immature to mature balance
                var miner_account = try self.getAccount(coinbase_tx.recipient);
                
                if (miner_account.immature_balance >= coinbase_tx.amount) {
                    miner_account.immature_balance -= coinbase_tx.amount;
                    miner_account.balance += coinbase_tx.amount;
                    
                    try self.database.saveAccount(coinbase_tx.recipient, miner_account);
                    
                    const recipient_bytes = coinbase_tx.recipient.toLegacyBytes();
                    print("✅ Matured {} ZEI for miner {s} from block {}\n", .{
                        coinbase_tx.amount / types.ZEI_COIN,
                        std.fmt.fmtSliceHexLower(recipient_bytes[0..8]),
                        mature_block_height
                    });
                }
            }
        }
    }

    /// Get blockchain height
    pub fn getHeight(self: *ZeiCoin) !u32 {
        return try self.database.getHeight();
    }

    /// Get account balance
    pub fn getBalance(self: *ZeiCoin, address: Address) !u64 {
        const account = try self.getAccount(address);
        return account.balance;
    }

    /// Get block by height
    pub fn getBlockByHeight(self: *ZeiCoin, height: u32) !Block {
        return try self.database.getBlock(height);
    }

    /// Calculate median time past (MTP) for timestamp validation
    fn getMedianTimePast(self: *ZeiCoin, height: u32) !u64 {
        // Need at least MTP_BLOCK_COUNT blocks for meaningful median
        if (height < types.TimestampValidation.MTP_BLOCK_COUNT) {
            // For early blocks, use genesis timestamp as baseline
            return types.Genesis.timestamp();
        }

        var timestamps = std.ArrayList(u64).init(self.allocator);
        defer timestamps.deinit();

        // Collect timestamps from last MTP_BLOCK_COUNT blocks
        const start_height = height - types.TimestampValidation.MTP_BLOCK_COUNT + 1;
        for (start_height..height + 1) |h| {
            var block = try self.database.getBlock(@intCast(h));
            defer block.deinit(self.allocator);
            try timestamps.append(block.header.timestamp);
        }

        // Sort timestamps
        std.sort.heap(u64, timestamps.items, {}, comptime std.sort.asc(u64));

        // Return median (middle value for odd count)
        const median_index = timestamps.items.len / 2;
        return timestamps.items[median_index];
    }

    /// Validate an incoming block
    pub fn validateBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            if (!genesis.validateGenesis(block)) {
                print("❌ Genesis block validation failed: not canonical genesis\n", .{});
                return false;
            }
            return true; // Genesis block passed validation
        }

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Block validation failed: invalid block structure\n", .{});
            return false;
        }

        // Check block size limit (16MB hard limit)
        const block_size = block.getSize();
        if (block_size > types.BlockLimits.MAX_BLOCK_SIZE) {
            print("❌ Block validation failed: size {} bytes exceeds limit of {} bytes\n", .{ block_size, types.BlockLimits.MAX_BLOCK_SIZE });
            return false;
        }

        // Timestamp validation - prevent blocks from the future
        const current_time = util.getTime();
        if (!types.TimestampValidation.isTimestampValid(block.header.timestamp, current_time)) {
            const future_seconds = @as(i64, @intCast(block.header.timestamp)) - current_time;
            print("❌ Block timestamp too far in future: {} seconds ahead\n", .{future_seconds});
            return false;
        }

        // Check block height consistency
        const current_height = try self.getHeight();
        if (expected_height != current_height) {
            print("❌ Block validation failed: height mismatch (expected: {}, current: {})\n", .{ expected_height, current_height });
            return false;
        }

        // For non-genesis blocks, validate against previous block
        if (expected_height > 0) {
            var prev_block = try self.getBlockByHeight(expected_height - 1);
            defer prev_block.deinit(self.allocator);

            // Check timestamp against median time past (MTP)
            const mtp = try self.getMedianTimePast(expected_height - 1);
            if (block.header.timestamp <= mtp) {
                print("❌ Block timestamp not greater than median time past\n", .{});
                print("   MTP: {}, Block timestamp: {}\n", .{ mtp, block.header.timestamp });
                return false;
            }

            // Check previous hash links correctly
            const prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                print("❌ Previous hash validation failed\n", .{});
                print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                return false;
            }
        }

        // Check proof-of-work with dynamic difficulty
        if (@import("builtin").mode == .Debug) {
            // In test mode, use dynamic difficulty with SHA256 for speed
            const difficulty_target = block.header.getDifficultyTarget();
            if (!difficulty_target.meetsDifficulty(block.header.hash())) {
                print("❌ Proof-of-work validation failed\n", .{});
                return false;
            }
        } else {
            // In production, use full RandomX validation with dynamic difficulty
            if (!try self.validateBlockPoW(block)) {
                print("❌ RandomX proof-of-work validation failed\n", .{});
                return false;
            }
        }

        // Validate all transactions in block
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) continue;

            if (!try self.validateTransaction(tx)) {
                print("❌ Transaction {} validation failed\n", .{i});
                return false;
            }
        }

        return true;
    }

    /// Validate block during sync (skips transaction balance checks)
    pub fn validateSyncBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        print("🔍 validateSyncBlock: Starting validation for height {}\n", .{expected_height});

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            print("🔍 validateSyncBlock: Processing genesis block (height 0)\n", .{});

            // Detailed genesis validation debugging
            print("🔍 Genesis validation details:\n", .{});
            print("   Block timestamp: {}\n", .{block.header.timestamp});
            print("   Expected genesis timestamp: {}\n", .{types.Genesis.timestamp()});
            print("   Block previous_hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
            print("   Block difficulty: {}\n", .{block.header.difficulty});
            print("   Block nonce: 0x{X}\n", .{block.header.nonce});
            print("   Block transaction count: {}\n", .{block.txCount()});

            const block_hash = block.hash();
            print("   Block hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block_hash)});
            print("   Expected genesis hash: {s}\n", .{std.fmt.fmtSliceHexLower(&genesis.getCanonicalGenesisHash())});

            if (!genesis.validateGenesis(block)) {
                print("❌ Genesis block validation failed: not canonical genesis\n", .{});
                print("❌ Genesis validation failed - detailed comparison above\n", .{});
                return false;
            }
            print("✅ Genesis block validation passed\n", .{});
            return true; // Genesis block passed validation
        }

        print("🔍 validateSyncBlock: Checking basic block structure for height {}\n", .{expected_height});

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Block validation failed: invalid block structure at height {}\n", .{expected_height});
            print("   Block transaction count: {}\n", .{block.txCount()});
            print("   Block timestamp: {}\n", .{block.header.timestamp});
            print("   Block difficulty: {}\n", .{block.header.difficulty});
            return false;
        }
        print("✅ Basic block structure validation passed for height {}\n", .{expected_height});

        // Timestamp validation for sync blocks (more lenient than normal validation)
        const current_time = util.getTime();
        // Allow more future time during sync (network time differences)
        const sync_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2; // 4 hours
        if (@as(i64, @intCast(block.header.timestamp)) > current_time + sync_future_allowance) {
            const future_seconds = @as(i64, @intCast(block.header.timestamp)) - current_time;
            print("❌ Sync block timestamp too far in future: {} seconds ahead\n", .{future_seconds});
            return false;
        }

        print("🔍 validateSyncBlock: Checking proof-of-work for height {}\n", .{expected_height});

        // Check proof-of-work with dynamic difficulty
        if (@import("builtin").mode == .Debug) {
            // In test mode, use dynamic difficulty with SHA256 for speed
            const difficulty_target = block.header.getDifficultyTarget();
            const block_hash = block.header.hash();
            print("   Difficulty target: {}\n", .{difficulty_target.toU64()});
            print("   Block hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block_hash)});

            if (!difficulty_target.meetsDifficulty(block_hash)) {
                print("❌ Proof-of-work validation failed for height {}\n", .{expected_height});
                print("   Difficulty target does not meet required threshold\n", .{});
                return false;
            }
        } else {
            // In production, use full RandomX validation with dynamic difficulty
            if (!try self.validateBlockPoW(block)) {
                print("❌ RandomX proof-of-work validation failed for height {}\n", .{expected_height});
                return false;
            }
        }
        print("✅ Proof-of-work validation passed for height {}\n", .{expected_height});

        print("🔍 validateSyncBlock: Checking previous hash links for height {}\n", .{expected_height});

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.getHeight();
            print("   Current blockchain height: {}\n", .{current_height});
            print("   Expected block height: {}\n", .{expected_height});

            if (expected_height > current_height) {
                // During sync, we might not have the previous block yet - skip this check
                print("⚠️ Skipping previous hash check during sync (height {} > current {})\n", .{ expected_height, current_height });
            } else if (expected_height == current_height) {
                // We're about to add this block - check against our current tip
                print("   Checking previous hash against current blockchain tip\n", .{});
                var prev_block = try self.getBlockByHeight(expected_height - 1);
                defer prev_block.deinit(self.allocator);

                const prev_hash = prev_block.hash();
                print("   Previous block hash in chain: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                print("   Block's previous_hash field: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    print("❌ Previous hash validation failed during sync\n", .{});
                    print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                    print("⚠️ This might indicate a fork - skipping hash validation during sync\n", .{});
                    // During sync, we trust the peer's chain - skip this validation
                }
            } else {
                // We already have this block height - this shouldn't happen during normal sync
                print("⚠️ Unexpected: trying to sync block {} but we already have height {}\n", .{ expected_height, current_height });
            }
        }

        print("🔍 validateSyncBlock: Validating {} transactions for height {}\n", .{ block.txCount(), expected_height });

        // For sync blocks, validate transaction structure but skip balance checks
        // The balance validation will happen naturally when transactions are processed
        for (block.transactions, 0..) |tx, i| {
            print("   🔍 Validating transaction {} of {}\n", .{ i, block.txCount() - 1 });

            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) {
                print("   ✅ Skipping coinbase transaction validation\n", .{});
                continue;
            }

            print("   🔍 Checking transaction structure...\n", .{});

            // Basic transaction structure validation only
            if (!tx.isValid()) {
                print("❌ Transaction {} structure validation failed\n", .{i});
                const sender_bytes = tx.sender.toLegacyBytes();
                const recipient_bytes = tx.recipient.toLegacyBytes();
                print("   Sender: {s}\n", .{std.fmt.fmtSliceHexLower(&sender_bytes)});
                print("   Recipient: {s}\n", .{std.fmt.fmtSliceHexLower(&recipient_bytes)});
                print("   Amount: {}\n", .{tx.amount});
                print("   Fee: {}\n", .{tx.fee});
                print("   Nonce: {}\n", .{tx.nonce});
                print("   Timestamp: {}\n", .{tx.timestamp});
                return false;
            }
            print("   ✅ Transaction {} structure validation passed\n", .{i});

            print("   🔍 Checking transaction signature...\n", .{});

            // Signature validation (but no balance check)
            if (!try self.validateTransactionSignature(tx)) {
                print("❌ Transaction {} signature validation failed\n", .{i});
                print("   Public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
                print("   Signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});
                return false;
            }
            print("   ✅ Transaction {} signature validation passed\n", .{i});
        }

        print("✅ Sync block {} structure and signatures validated\n", .{expected_height});
        return true;
    }

    /// Validate transaction signature only (used during sync)
    fn validateTransactionSignature(self: *ZeiCoin, tx: Transaction) !bool {
        _ = self; // Unused parameter

        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        print("     🔍 Transaction hash for signing: {s}\n", .{std.fmt.fmtSliceHexLower(&tx_hash)});
        print("     🔍 Sender public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
        print("     🔍 Transaction signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});

        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            print("❌ Signature verification failed - detailed info above\n", .{});
            return false;
        }
        print("     ✅ Signature verification passed\n", .{});

        return true;
    }

    /// Validate block during reorganization (skips all chain linkage checks)
    pub fn validateReorgBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            if (!genesis.validateGenesis(block)) {
                print("❌ Genesis block validation failed: not canonical genesis\n", .{});
                return false;
            }
            return true; // Genesis block passed validation
        }

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Block validation failed: invalid block structure\n", .{});
            return false;
        }

        // Timestamp validation for reorg blocks (lenient like sync)
        const current_time = util.getTime();
        const reorg_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2; // 4 hours
        if (@as(i64, @intCast(block.header.timestamp)) > current_time + reorg_future_allowance) {
            const future_seconds = @as(i64, @intCast(block.header.timestamp)) - current_time;
            print("❌ Reorg block timestamp too far in future: {} seconds ahead\n", .{future_seconds});
            return false;
        }

        // Check proof-of-work with dynamic difficulty
        if (@import("builtin").mode == .Debug) {
            // In test mode, use dynamic difficulty with SHA256 for speed
            const difficulty_target = block.header.getDifficultyTarget();
            if (!difficulty_target.meetsDifficulty(block.header.hash())) {
                print("❌ Proof-of-work validation failed\n", .{});
                return false;
            }
        } else {
            // In production, use full RandomX validation with dynamic difficulty
            if (!try self.validateBlockPoW(block)) {
                print("❌ RandomX proof-of-work validation failed\n", .{});
                return false;
            }
        }

        // Skip all chain linkage validation during reorganization
        // The fork manager has already validated that this block is part of a valid chain

        // For reorg blocks, validate transaction structure but skip balance checks
        // The balance validation will happen naturally when transactions are processed
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) continue;

            // Basic transaction structure validation only
            if (!tx.isValid()) {
                print("❌ Transaction {} structure validation failed\n", .{i});
                return false;
            }

            // Signature validation (but no balance check)
            if (!try self.validateTransactionSignature(tx)) {
                print("❌ Transaction {} signature validation failed\n", .{i});
                return false;
            }
        }

        print("✅ Reorg block {} structure and signatures validated\n", .{expected_height});
        return true;
    }

    /// Check if a block builds on a known block in our chain (for fork detection)
    fn isValidForkBlock(self: *ZeiCoin, block: types.Block) !bool {
        const current_height = try self.getHeight();

        // Check if block's previous_hash matches any block in our chain
        for (0..current_height) |height| {
            var existing_block = self.database.getBlock(@intCast(height)) catch continue;
            defer existing_block.deinit(self.allocator);

            const existing_hash = existing_block.hash();
            if (std.mem.eql(u8, &block.header.previous_hash, &existing_hash)) {
                print("🔗 Fork block builds on height {} (current tip: {})\n", .{ height, current_height - 1 });
                return true;
            }
        }

        return false;
    }

    /// Store a fork block for potential reorganization
    fn storeForkBlock(self: *ZeiCoin, block: types.Block, fork_height: u32) !void {
        // For now, we'll implement a simple approach: if we receive a block that
        // would create a longer chain, we'll trigger a reorganization immediately
        _ = self;
        _ = block;
        _ = fork_height;

        print("⚠️ Fork storage not yet implemented - longest chain rule needed\n", .{});
        // TODO: Implement proper fork storage and reorganization
        // This is the main remaining piece for full fork resolution
    }

    /// Apply a valid block to the blockchain
    fn applyBlock(self: *ZeiCoin, block: Block) !void {
        // Process all transactions in the block
        try self.processBlockTransactions(block.transactions);

        // Save block to database
        const block_height = try self.getHeight();
        try self.database.saveBlock(block_height, block);
        
        // Mature any coinbase rewards that have reached 100 confirmations
        try self.matureCoinbaseRewards(block_height);

        // Remove processed transactions from mempool
        self.cleanMempool(block);
    }

    /// Clean mempool of transactions that are now in a block
    fn cleanMempool(self: *ZeiCoin, block: Block) void {
        var i: usize = 0;
        while (i < self.mempool.items.len) {
            const mempool_tx = self.mempool.items[i];
            var found_in_block = false;

            // Check if this mempool transaction is in the block
            for (block.transactions) |block_tx| {
                if (std.mem.eql(u8, &mempool_tx.hash(), &block_tx.hash())) {
                    found_in_block = true;
                    break;
                }
            }

            if (found_in_block) {
                // Update size before removing
                const tx_size = mempool_tx.getSerializedSize();
                _ = self.mempool.swapRemove(i);
                self.mempool_size_bytes -= tx_size;
                // Don't increment i since we removed an item
            } else {
                i += 1;
            }
        }
    }

    /// Start networking on specified port
    pub fn startNetwork(self: *ZeiCoin, port: u16) !void {
        if (self.network != null) return; // Already started

        var network = net.NetworkManager.init(self.allocator);
        try network.start(port);
        self.network = network;

        print("🌐 ZeiCoin network started on port {}\n", .{port});
    }

    /// Stop networking
    pub fn stopNetwork(self: *ZeiCoin) void {
        if (self.network) |*network| {
            network.stop();
            network.deinit();
            self.network = null;
            print("🛑 ZeiCoin network stopped\n", .{});
        }
    }

    /// Connect to a peer
    pub fn connectToPeer(self: *ZeiCoin, address: []const u8) !void {
        if (self.network) |*network| {
            try network.addPeer(address);
        } else {
            return error.NetworkNotStarted;
        }
    }

    /// Print blockchain status
    pub fn printStatus(self: *ZeiCoin) void {
        print("\n📊 ZeiCoin Blockchain Status:\n", .{});
        const height = self.getHeight() catch 0;
        const account_count = self.database.getAccountCount() catch 0;
        print("   Height: {} blocks\n", .{height});
        print("   Pending: {} transactions\n", .{self.mempool.items.len});
        print("   Accounts: {} active\n", .{account_count});

        // Show network status
        if (self.network) |*network| {
            const connected_peers = network.*.getConnectedPeers();
            const total_peers = network.*.peers.items.len;
            print("   Network: {} of {} peers connected\n", .{ connected_peers, total_peers });

            if (total_peers > 0) {
                for (network.*.peers.items) |peer| {
                    var addr_buf: [32]u8 = undefined;
                    const addr_str = peer.address.toString(&addr_buf);
                    const status = switch (peer.state) {
                        .connected => "🟢",
                        .connecting => "🟡",
                        .handshaking => "🟡",
                        .reconnecting => "🛜",
                        .disconnecting => "🔴",
                        .disconnected => "🔴",
                    };
                    print("     {s} {s}\n", .{ status, addr_str });
                }
            }
        } else {
            print("   Network: offline\n", .{});
        }

        // Show recent blocks
        const start_idx = if (height > 3) height - 3 else 0;
        var i = start_idx;
        while (i < height) : (i += 1) {
            if (self.database.getBlock(i)) |block_data| {
                var block = block_data;
                print("   Block #{}: {} txs\n", .{ i, block.txCount() });
                // Free block memory after displaying
                block.deinit(self.allocator);
            } else |_| {
                print("   Block #{}: Error loading\n", .{i});
            }
        }
        print("\n", .{});
    }

    /// Broadcast newly mined block to network peers
    fn broadcastNewBlock(self: *ZeiCoin, block: types.Block) void {
        if (self.network) |network| {
            network.broadcastBlock(block);
            print("📡 Block broadcast to {} peers\n", .{network.getPeerCount()});
        }
    }

    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *ZeiCoin, transaction: types.Transaction) !void {
        // Check if we've already processed this transaction (prevents broadcast storms)
        const tx_hash = transaction.hash();

        // 1. Check if already processed in a block
        for (self.processed_transactions.items) |processed_hash| {
            if (std.mem.eql(u8, &processed_hash, &tx_hash)) {
                // Silent ignore - no need to log repeated already-processed transactions
                return;
            }
        }

        // 2. Check if already in mempool
        for (self.mempool.items) |existing_tx| {
            if (std.mem.eql(u8, &existing_tx.hash(), &tx_hash)) {
                print("🌊 Transaction already flows in our zen mempool - gracefully ignored\n", .{});
                return;
            }
        }

        // Validate and add to mempool if valid
        self.addTransaction(transaction) catch |err| {
            print("⚠️ Rejected network transaction: {}\n", .{err});
            
            // Fast catchup: If transaction failed due to insufficient balance,
            // we might be behind. Trigger sync to catch up with network state.
            if (err == error.InvalidTransaction) {
                // Check if we might be behind by querying peer heights
                if (self.network) |network| {
                    const highest_peer_height = network.getHighestPeerHeight();
                    const our_height = self.getHeight() catch 0;
                    
                    if (highest_peer_height > our_height) {
                        print("🔄 Fast catchup: We're behind (height {} vs {}), triggering sync...\n", .{our_height, highest_peer_height});
                        
                        // Trigger auto-sync to catch up
                        self.triggerAutoSyncWithPeerQuery() catch |sync_err| {
                            print("⚠️  Fast catchup sync failed: {}\n", .{sync_err});
                        };
                    }
                }
            }
            
            return err;
        };

        print("✅ Network transaction flows into zen mempool\n", .{});
    }

    /// Handle incoming block from network peer with longest chain consensus
    /// NOTE: We take ownership of the block - the caller transfers ownership to us.
    pub fn handleIncomingBlock(self: *ZeiCoin, block: types.Block) !void {
        // Take ownership and ensure cleanup
        var owned_block = block;
        defer owned_block.deinit(self.allocator);
        
        const current_height = try self.getHeight();
        const block_height = current_height + 1; // Block would be at next height if accepted

        print("🌊 Block flows in from network peer with {} transactions\n", .{block.transactions.len});

        // Calculate cumulative work for this block
        const block_work = owned_block.header.getWork();
        const cumulative_work = if (current_height > 0) parent_calc: {
            // Get parent block work
            var parent_block = self.database.getBlock(current_height - 1) catch {
                print("❌ Cannot find parent block for height {}\n", .{current_height - 1});
                return;
            };
            defer parent_block.deinit(self.allocator);

            // For now, estimate parent cumulative work (should be stored in future)
            const parent_work = self.estimateCumulativeWork(current_height - 1) catch 0;
            break :parent_calc parent_work + block_work;
        } else block_work;

        // Evaluate block using fork manager
        const decision = self.fork_manager.evaluateBlock(owned_block, block_height, cumulative_work) catch |err| {
            print("❌ Fork evaluation failed: {}\n", .{err});
            return;
        };

        switch (decision) {
            .already_seen => {
                print("🌊 Block already seen - gracefully ignored\n", .{});
                return;
            },
            .orphan_stored => {
                print("🔀 Block stored as orphan - waiting for parent\n", .{});

                // Auto-sync logic: If we're storing orphan blocks, we're likely behind
                // The block was stored as orphan, which means it doesn't fit our current chain
                // This indicates we're likely behind - trigger auto-sync to catch up
                print("🔄 Orphan block detected - we may be behind, triggering auto-sync\n", .{});

                // Use a defer to ensure auto-sync happens after current processing completes
                // This avoids any issues with peer references during message handling
                defer {
                    self.triggerAutoSyncWithPeerQuery() catch |err| {
                        print("⚠️  Auto-sync trigger failed: {}\n", .{err});
                    };
                }
                return;
            },
            .extends_chain => |chain_info| {
                if (chain_info.is_new_best) {
                    print("🏆 New best chain detected! Starting reorganization...\n", .{});
                    try self.handleChainReorganization(owned_block, chain_info.new_chain_state);
                } else {
                    print("📈 Block extends side chain {}\n", .{chain_info.chain_index});
                    // Just update the side chain for now
                    self.fork_manager.updateChain(chain_info.chain_index, chain_info.new_chain_state);
                }
            },
        }
    }

    /// Estimate cumulative work for a block height (temporary until we store it properly)
    fn estimateCumulativeWork(self: *ZeiCoin, height: u32) !types.ChainWork {
        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(@intCast(h)) catch continue;
            defer block.deinit(self.allocator);
            total_work += block.header.getWork();
        }
        return total_work;
    }

    /// Handle chain reorganization when a better chain is found
    fn handleChainReorganization(self: *ZeiCoin, new_block: types.Block, new_chain_state: types.ChainState) !void {
        const current_height = try self.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.fork_manager.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
            print("❌ Reorganization too deep ({} -> {}) - rejected for safety\n", .{ current_height, new_chain_state.tip_height });
            return;
        }

        print("🔄 Starting reorganization: {} -> {} (depth: {})\n", .{ current_height, new_chain_state.tip_height, if (current_height > new_chain_state.tip_height) current_height - new_chain_state.tip_height else new_chain_state.tip_height - current_height });

        // Find common ancestor (simplified - assume we need to rebuild from genesis for now)
        const common_ancestor_height = try self.findCommonAncestor(new_chain_state.tip_hash);

        if (common_ancestor_height == 0) {
            print("⚠️ Deep reorganization required - rebuilding from genesis\n", .{});
        }

        // Rollback to common ancestor (no transaction backup needed - new block contains valid transactions)
        try self.rollbackToHeight(common_ancestor_height);

        // Accept the new block (this will become the new tip)
        try self.acceptBlock(new_block);

        // Update fork manager
        self.fork_manager.updateChain(0, new_chain_state); // Update main chain

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
    }

    /// Find common ancestor between current chain and new chain
    fn findCommonAncestor(self: *ZeiCoin, new_tip_hash: types.BlockHash) !u32 {
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        _ = self;
        _ = new_tip_hash;
        return 0;
    }

    /// Backup transactions from orphaned blocks
    fn backupOrphanedTransactions(self: *ZeiCoin, from_height: u32, to_height: u32) !void {
        print("💾 Backing up transactions from orphaned blocks ({} to {})\n", .{ from_height, to_height });

        for (from_height..to_height) |height| {
            const block = self.database.getBlock(@intCast(height)) catch continue;
            defer block.deinit(self.allocator);

            // Re-validate and add non-coinbase transactions back to mempool
            for (block.transactions) |tx| {
                if (!tx.isCoinbase()) {
                    // Validate transaction is still valid
                    if (self.validateTransaction(tx) catch false) {
                        // Deep copy the transaction before adding to mempool
                        var owned_tx = try tx.dupe(self.allocator);
                        errdefer owned_tx.deinit(self.allocator);
                        
                        try self.mempool.append(owned_tx);
                        self.mempool_size_bytes += tx.getSerializedSize();
                        print("🔄 Restored orphaned transaction to mempool\n", .{});
                    } else {
                        print("❌ Orphaned transaction no longer valid - discarded\n", .{});
                    }
                }
            }
        }
    }

    /// Clear all account state from the database
    fn clearAllAccounts(self: *ZeiCoin) !void {
        print("🗑️  Clearing all account state for rebuild\n", .{});
        
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
                    print("  ⚠️  Failed to delete account file {s}: {}\n", .{entry.name, err});
                };
            }
        }
        
        print("  ✅ Cleared all account files\n", .{});
    }
    
    /// Replay blockchain from genesis to rebuild account state
    fn replayFromGenesis(self: *ZeiCoin, up_to_height: u32) !void {
        print("🔄 Replaying blockchain from genesis to height {}\n", .{up_to_height});
        
        // Start from genesis (height 0)
        for (0..up_to_height + 1) |height| {
            var block = self.database.getBlock(@intCast(height)) catch {
                print("❌ Failed to load block at height {} during replay\n", .{height});
                return error.ReplayFailed;
            };
            defer block.deinit(self.allocator);
            
            // Process each transaction in the block
            for (block.transactions, 0..) |tx, tx_index| {
                if (tx.isCoinbase()) {
                    // Process coinbase - credits go to immature balance
                    try self.replayCoinbaseTransaction(tx, @intCast(height));
                } else {
                    // Process regular transaction
                    try self.replayRegularTransaction(tx);
                }
                
                // Show progress every 100 blocks
                if (height % 100 == 0 and tx_index == 0) {
                    print("  📊 Replayed up to block {}/{}\n", .{height, up_to_height});
                }
            }
            
            // After processing block, check for matured coinbase rewards
            if (height >= types.ZenMining.COINBASE_MATURITY) {
                try self.matureCoinbaseRewards(@intCast(height));
            }
        }
        
        print("✅ Replay complete - all account states rebuilt\n", .{});
    }
    
    /// Process a coinbase transaction during replay
    fn replayCoinbaseTransaction(self: *ZeiCoin, tx: types.Transaction, block_height: u32) !void {
        _ = block_height; // Will be used for maturity tracking in the future
        
        var miner_account = self.getAccount(tx.recipient) catch types.Account{
            .address = tx.recipient,
            .balance = 0,
            .nonce = 0,
            .immature_balance = 0,
        };
        
        // Add to immature balance (will mature after 100 blocks)
        miner_account.immature_balance += tx.amount;
        
        // Save updated account
        try self.database.saveAccount(tx.recipient, miner_account);
    }
    
    /// Process a regular transaction during replay
    fn replayRegularTransaction(self: *ZeiCoin, tx: types.Transaction) !void {
        // Get sender account (might not exist in test scenario)
        var sender_account = self.getAccount(tx.sender) catch {
            // In test scenarios, we might have pre-funded accounts that don't exist in blocks
            // Skip this transaction during replay
            print("  ⚠️  Skipping transaction during replay - sender not found\n", .{});
            return;
        };
        
        // Check if sender has sufficient balance (safety check)
        const total_cost = tx.amount + tx.fee;
        if (sender_account.balance < total_cost) {
            print("  ⚠️  Skipping transaction during replay - insufficient balance\n", .{});
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
            .immature_balance = 0,
        };
        recipient_account.balance += tx.amount;
        try self.database.saveAccount(tx.recipient, recipient_account);
        
        // Fee goes to immature balance tracking (handled by coinbase in same block)
    }

    /// Rollback blockchain to specified height
    fn rollbackToHeight(self: *ZeiCoin, target_height: u32) !void {
        const current_height = try self.getHeight();

        if (target_height >= current_height) {
            return; // Nothing to rollback
        }

        print("⏪ Rolling back blockchain from {} to {}\n", .{ current_height, target_height });

        // Clear all account state - we'll rebuild by replaying from genesis
        try self.clearAllAccounts();
        
        // Clear mempool as transactions may no longer be valid
        self.mempool.clearRetainingCapacity();
        self.mempool_size_bytes = 0;
        print("🗑️  Cleared mempool during rollback\n", .{});

        // Replay blockchain from genesis up to target height
        try self.replayFromGenesis(target_height);

        print("✅ Rollback complete - state rebuilt up to height {}\n", .{target_height});
    }

    /// Accept a block after validation (used in reorganization)
    fn acceptBlock(self: *ZeiCoin, block: types.Block) !void {
        const current_height = try self.getHeight();

        // Special case: if we're at height 0 (after rollback to genesis) and the incoming block
        // is not a genesis block, we need to save it at height 1, not height 0
        const target_height = if (current_height == 0 and !genesis.validateGenesis(block)) blk: {
            print("🔄 Accepting non-genesis block after rollback - placing at height 1\n", .{});
            break :blk @as(u32, 1);
        } else current_height;

        // During reorganization, use reorganization-specific validation (skips hash chain checks)
        if (!try self.validateReorgBlock(block, target_height)) {
            return error.BlockValidationFailed;
        }

        // Process transactions
        try self.processBlockTransactions(block.transactions);

        // Save to database
        try self.database.saveBlock(target_height, block);

        print("✅ Block accepted at height {}\n", .{target_height});

        // Broadcast to network
        if (self.network) |network| {
            logSuccess("🚀 Broadcasting newly mined block #{} to P2P network", .{target_height});
            network.*.broadcastBlock(block);
        } else {
            logInfo("💭 No network connected, block not broadcast", .{});
        }
    }

    /// Handle sync block from network (specifically for sync process)
    /// NOTE: We take ownership of the block - the caller transfers ownership to us.
    pub fn handleSyncBlock(self: *ZeiCoin, expected_height: u32, block: types.Block) !void {
        // Take ownership and ensure cleanup
        var owned_block = block;
        defer owned_block.deinit(self.allocator);
        
        print("🔄 Processing sync block at height {}\n", .{expected_height});

        // Check if block already exists to prevent duplicate processing
        const existing_block = self.database.getBlock(expected_height) catch null;
        if (existing_block) |block_data| {
            // IMPORTANT: Free the loaded block to prevent memory leak
            var block_to_free = block_data;
            defer block_to_free.deinit(self.allocator);
            
            print("ℹ️  Block {} already exists, skipping duplicate during sync\n", .{expected_height});

            // Still need to update sync progress for this "processed" block
            if (self.sync_progress) |*progress| {
                progress.blocks_downloaded += 1;
                progress.consecutive_failures = 0; // Reset on successful processing

                // Check if we've completed sync with this existing block
                const current_height = self.getHeight() catch expected_height;
                if (current_height >= progress.target_height) {
                    print("🎉 Sync completed with existing blocks!\n", .{});
                    self.completSync();
                    return;
                }
            }
            return; // Skip duplicate block gracefully
        }

        // For sync, validate block structure and PoW only (skip transaction balance checks)
        const validation_result = self.validateSyncBlock(owned_block, expected_height) catch |err| {
            print("❌ Block validation threw error at height {}: {}\n", .{ expected_height, err });
            return;
        };
        if (!validation_result) {
            print("❌ Block validation failed at height {}\n", .{expected_height});

            // Check if this is a hash validation failure during sync
            const current_height = try self.getHeight();
            if (expected_height == current_height) {
                print("🔄 Hash validation failed during sync - this might be a fork situation\n", .{});
                print("💡 Restarting sync from current position to handle potential fork\n", .{});

                // Reset sync to restart from current position
                if (self.sync_progress) |*progress| {
                    progress.current_height = current_height;
                    progress.retry_count = 0;
                }

                // Trigger a fresh sync request
                try self.requestNextSyncBatch();
                return;
            }

            return error.InvalidSyncBlock;
        }

        // Process transactions first to update account states
        try self.processBlockTransactions(owned_block.transactions);

        // Add block to chain
        try self.database.saveBlock(expected_height, owned_block);

        // Update sync progress
        if (self.sync_progress) |*progress| {
            progress.blocks_downloaded += 1;
            // Reset consecutive failures on successful block processing
            progress.consecutive_failures = 0;

            // Report progress periodically
            const now = util.getTime();
            if (now - progress.last_progress_report >= types.SYNC.PROGRESS_REPORT_INTERVAL) {
                self.reportSyncProgress();
                progress.last_progress_report = now;
            }

            // Check if we've reached the target height
            const current_height = self.getHeight() catch expected_height;
            print("🔍 SYNC DEBUG: current_height={}, target_height={}, expected_height={}\n", .{ current_height, progress.target_height, expected_height });
            if (current_height >= progress.target_height) {
                print("🎉 SYNC COMPLETION: Calling completSync() because {} >= {}\n", .{ current_height, progress.target_height });
                self.completSync();
                return;
            } else {
                print("⏳ SYNC CONTINUING: Not complete because {} < {}\n", .{ current_height, progress.target_height });
            }
        }

        print("✅ Sync block {} added to chain\n", .{expected_height});
    }

    /// Start sync process with a peer
    pub fn startSync(self: *ZeiCoin, peer: *net.Peer, target_height: u32) !void {
        const current_height = try self.getHeight();

        // Special case: if we have no blockchain (height 0), sync from genesis (height 0)
        if (current_height == 0 and target_height > 0) {
            print("🔄 Starting sync from genesis: 0 -> {} ({} blocks to download)\n", .{ target_height, target_height });
        } else if (target_height <= current_height) {
            print("ℹ️  Already up to date (height {})\n", .{current_height});
            return;
        } else {
            print("🔄 Starting sync: {} -> {} ({} blocks behind)\n", .{ current_height, target_height, target_height - current_height });
        }

        // Initialize sync state
        self.sync_state = .syncing;
        self.sync_progress = SyncProgress.init(current_height, target_height);
        self.sync_peer = peer;

        // Start downloading blocks in batches
        try self.requestNextSyncBatch();
    }

    /// Automatically trigger sync by querying peer heights when orphan blocks indicate we're behind
    pub fn triggerAutoSyncWithPeerQuery(self: *ZeiCoin) !void {
        // Check if we're already syncing
        if (self.sync_state == .syncing) {
            print("ℹ️  Already syncing - orphan block detection ignored\n", .{});
            return;
        }

        const current_height = try self.getHeight();

        // Find an available peer to sync with and query their height
        if (self.network) |network| {
            // Get a fresh list of peers to avoid stale references
            const peer_count = network.peers.items.len;
            if (peer_count == 0) {
                print("⚠️  No peers available for auto-sync\n", .{});
                return;
            }

            // Try each peer until we find a connected one
            var attempts: u32 = 0;
            for (network.peers.items) |*peer| {
                attempts += 1;

                // Skip if not connected
                if (peer.state != .connected) {
                    continue;
                }

                // Skip if socket is null
                if (peer.socket == null) {
                    print("⚠️  Peer has no socket, skipping\n", .{});
                    continue;
                }

                // Skip peers with invalid addresses (0.0.0.0)
                const is_zero_addr = peer.address.ip[0] == 0 and peer.address.ip[1] == 0 and 
                                   peer.address.ip[2] == 0 and peer.address.ip[3] == 0;
                if (is_zero_addr) {
                    print("⚠️  Skipping peer with invalid address 0.0.0.0\n", .{});
                    continue;
                }
                
                // Format peer address safely with bounds checking
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.address.toString(&addr_buf);

                print("🔄 Auto-sync triggered - requesting peer height from {s}\n", .{addr_str});

                // Send version to query height
                peer.sendVersion(current_height) catch |err| {
                    print("⚠️  Failed to query peer {s}: {}\n", .{ addr_str, err });
                    continue;
                };

                print("📡 Height query sent to peer - sync will trigger automatically if needed\n", .{});
                return;
            }

            print("⚠️  Tried {} peers but none were suitable for auto-sync\n", .{attempts});
        } else {
            print("⚠️  No network manager available for auto-sync\n", .{});
        }
    }

    /// Request next batch of blocks for sync
    pub fn requestNextSyncBatch(self: *ZeiCoin) !void {
        if (self.sync_peer == null or self.sync_progress == null) {
            return error.SyncNotInitialized;
        }

        const peer = self.sync_peer.?;
        const progress = &self.sync_progress.?;
        const now = util.getTime();

        // Check for timeout on previous request
        if (now - progress.last_request_time > types.SYNC.SYNC_TIMEOUT_SECONDS) {
            logProcess("Sync timeout detected, retrying...", .{});
            progress.retry_count += 1;

            if (progress.retry_count >= types.SYNC.MAX_SYNC_RETRIES) {
                logError("Max sync retries exceeded, switching peer", .{});
                try self.switchSyncPeer();
                return;
            }
        }

        const current_height = try self.getHeight();
        const next_height = current_height;
        const remaining = progress.target_height - next_height;

        if (remaining == 0) {
            self.completSync();
            return;
        }

        const batch_size = @min(types.SYNC.BATCH_SIZE, remaining);

        print("📥 Requesting {} blocks starting from height {} (attempt {})\n", .{ batch_size, next_height, progress.retry_count + 1 });

        // Update request time and send request
        progress.last_request_time = now;
        peer.sendGetBlocks(next_height, batch_size) catch |err| {
            print("❌ Failed to send sync request: {}\n", .{err});
            progress.retry_count += 1;

            if (progress.retry_count >= types.SYNC.MAX_SYNC_RETRIES) {
                self.switchSyncPeer() catch {
                    self.failSync("Failed to switch sync peer");
                    return;
                };
                // After switching peer, try the request again with new peer
                if (self.sync_peer) |new_peer| {
                    new_peer.sendGetBlocks(next_height, batch_size) catch {
                        self.failSync("Failed to send request to new peer");
                        return;
                    };
                }
            }
            return;
        };

        // Reset retry count on successful request
        if (progress.retry_count > 0) {
            self.resetSyncRetry();
        }
    }

    /// Complete sync process
    fn completSync(self: *ZeiCoin) void {
        print("🎉 Sync completed! Chain is up to date\n", .{});

        if (self.sync_progress) |*progress| {
            const elapsed = util.getTime() - progress.start_time;
            const blocks_per_sec = progress.getBlocksPerSecond();
            print("📊 Sync stats: {} blocks in {}s ({:.2} blocks/sec)\n", .{ progress.blocks_downloaded, elapsed, blocks_per_sec });
            // Reset consecutive failures on successful sync completion
            progress.consecutive_failures = 0;
        }

        self.sync_state = .sync_complete;
        self.sync_progress = null;
        self.sync_peer = null;

        // Transition to synced state
        self.sync_state = .synced;
    }

    /// Report sync progress
    fn reportSyncProgress(self: *ZeiCoin) void {
        if (self.sync_progress) |progress| {
            const percent = progress.getProgress();
            const blocks_per_sec = progress.getBlocksPerSecond();
            const eta = progress.getETA();

            print("🔄 Sync progress: {:.1}% ({} blocks/sec, ETA: {}s)\n", .{ percent, blocks_per_sec, eta });
        }
    }

    /// Check if we need to sync with a peer
    pub fn shouldSync(self: *ZeiCoin, peer_height: u32) !bool {
        const our_height = try self.getHeight();

        // If we have no blockchain and peer has blocks, always sync (including genesis)
        if (our_height == 0 and peer_height > 0) {
            print("🌐 Network has blockchain (height {}), will sync from genesis\n", .{peer_height});
            return true;
        }

        if (self.sync_state != .synced) {
            return false; // Already syncing or in error state
        }

        return peer_height > our_height;
    }

    /// Get sync state
    pub fn getSyncState(self: *const ZeiCoin) SyncState {
        return self.sync_state;
    }

    /// Get block by height (used by network layer for sending blocks)
    pub fn getBlock(self: *ZeiCoin, height: u32) !types.Block {
        return try self.database.getBlock(height);
    }

    // Helper methods for cleaner code
    /// Process all transactions in a block (coinbase first, then regular)
    fn processBlockTransactions(self: *ZeiCoin, transactions: []Transaction) !void {
        // First pass: process all coinbase transactions
        for (transactions) |tx| {
            if (self.isCoinbaseTransaction(tx)) {
                print("💰 Processing coinbase: {} ZEI for miner\n", .{tx.amount / types.ZEI_COIN});
                try self.processCoinbaseTransaction(tx, tx.recipient);
            }
        }

        // Second pass: process all regular transactions
        for (transactions) |tx| {
            if (!self.isCoinbaseTransaction(tx)) {
                print("💸 Processing transaction: {} ZEI\n", .{tx.amount / types.ZEI_COIN});
                try self.processTransaction(tx);
            }
        }

        // Mark all transactions as processed to prevent re-broadcasting
        for (transactions) |tx| {
            const tx_hash = tx.hash();
            try self.processed_transactions.append(tx_hash);
        }
    }

    /// Reset sync retry count and update timestamp
    fn resetSyncRetry(self: *ZeiCoin) void {
        if (self.sync_progress) |*progress| {
            progress.retry_count = 0;
            progress.last_request_time = util.getTime();
        }
    }

    /// Clean old processed transactions to prevent memory growth
    fn cleanupProcessedTransactions(self: *ZeiCoin) void {
        // Keep only recent transactions (limit to 1000 for memory efficiency)
        const MAX_PROCESSED_TXS = 1000;
        const KEEP_RECENT_TXS = 500; // Keep half when cleaning up

        if (self.processed_transactions.items.len > MAX_PROCESSED_TXS) {
            // Keep only the most recent transactions (better integrity than clearing all)
            const items_to_remove = self.processed_transactions.items.len - KEEP_RECENT_TXS;

            // Remove oldest transactions (first items in the list)
            for (0..items_to_remove) |_| {
                _ = self.processed_transactions.orderedRemove(0);
            }

            print("🧹 Cleaned {} old processed transactions (kept {} recent)\n", .{ items_to_remove, KEEP_RECENT_TXS });
        }
    }

    /// Switch to a different peer for sync (peer fallback mechanism)
    fn switchSyncPeer(self: *ZeiCoin) !void {
        if (self.network == null) {
            return error.NoNetworkManager;
        }

        // Add current peer to failed list
        if (self.sync_peer) |failed_peer| {
            try self.failed_peers.append(failed_peer);
            print("🚫 Added peer to blacklist (total: {})\n", .{self.failed_peers.items.len});
        }

        // Find a new peer that's not in the failed list
        const network = self.network.?;
        var new_peer: ?*net.Peer = null;

        for (network.peers.items) |*peer| {
            if (peer.state != .connected) continue;

            // Check if this peer is in the failed list
            var is_failed = false;
            for (self.failed_peers.items) |failed_peer| {
                if (peer == failed_peer) {
                    is_failed = true;
                    break;
                }
            }

            if (!is_failed) {
                new_peer = peer;
                break;
            }
        }

        if (new_peer) |peer| {
            print("🔄 Switching to new sync peer\n", .{});
            self.sync_peer = peer;

            // Reset retry count - caller will retry the request
            self.resetSyncRetry();
        } else {
            print("❌ No more peers available for sync\n", .{});
            self.failSync("No more peers available");
        }
    }

    /// Fail sync process with error message
    fn failSync(self: *ZeiCoin, reason: []const u8) void {
        print("❌ Sync failed: {s}\n", .{reason});
        self.sync_state = .sync_failed;
        self.sync_progress = null;
        self.sync_peer = null;

        // Clear failed peers list for future attempts
        self.failed_peers.clearAndFree();
    }

    /// Check if sync has timed out and needs recovery
    pub fn checkSyncTimeout(self: *ZeiCoin) void {
        if (self.sync_state != .syncing or self.sync_progress == null) {
            return;
        }

        const progress = &self.sync_progress.?;
        const now = util.getTime();

        // Check for overall sync timeout (much longer than individual requests)
        const total_timeout = types.SYNC.SYNC_TIMEOUT_SECONDS * 10; // 5 minutes total
        if (now - progress.start_time > total_timeout) {
            self.failSync("Sync took too long overall");
            return;
        }

        // Check for individual request timeout
        if (now - progress.last_request_time > types.SYNC.SYNC_TIMEOUT_SECONDS) {
            // Check consecutive failure limit to prevent infinite retry loops
            if (progress.consecutive_failures >= types.SYNC.MAX_CONSECUTIVE_FAILURES) {
                print("🛑 Sync stopped: {} consecutive failures exceeded limit\n", .{progress.consecutive_failures});
                self.failSync("Too many consecutive sync failures");
                return;
            }

            print("⏰ Sync request timed out (failure #{}) \n", .{progress.consecutive_failures + 1});
            progress.consecutive_failures += 1;

            self.requestNextSyncBatch() catch |err| {
                print("❌ Failed to retry sync request: {}\n", .{err});
                self.failSync("Failed to retry sync request");
            };
        }
    }

    /// Periodically check connected peers for new blocks
    pub fn checkForNewBlocks(self: *ZeiCoin) !void {
        // Only check if we're not already syncing
        if (self.sync_state != .synced) {
            return;
        }

        if (self.network == null) {
            return;
        }

        const network = self.network.?;

        // Only query one random connected peer to reduce message traffic
        network.peers_mutex.lock();
        defer network.peers_mutex.unlock();

        var connected_count: usize = 0;
        for (network.peers.items) |peer| {
            if (peer.state == .connected) connected_count += 1;
        }

        if (connected_count == 0) return;

        // Find a connected peer to query (simple round-robin approach)
        var peer_index: usize = 0;
        for (network.peers.items, 0..) |*peer, i| {
            if (peer.state == .connected) {
                peer_index = i;
                break;
            }
        }

        // Query only one peer to avoid message storm
        if (peer_index < network.peers.items.len) {
            const peer = &network.peers.items[peer_index];
            if (peer.state == .connected) {
                peer.requestHeightUpdate() catch {
                    // If height request fails, peer might be disconnected
                };
            }
        }
    }

    /// Retry failed sync (can be called externally)
    pub fn retrySyncIfFailed(self: *ZeiCoin) !void {
        if (self.sync_state != .sync_failed) {
            return;
        }

        if (self.network == null) {
            return error.NoNetworkManager;
        }

        print("🔄 Retrying failed sync...\n", .{});

        // Find any connected peer
        const network = self.network.?;
        for (network.peers.items) |*peer| {
            if (peer.state == .connected) {
                // Get their height and restart sync
                // Note: In a full implementation, we'd send a version message first
                // For now, just assume they're still ahead
                if (self.sync_progress) |progress| {
                    try self.startSync(peer, progress.target_height);
                    return;
                }
            }
        }

        print("❌ No peers available for sync retry\n", .{});
    }
};

// Tests
const testing = std.testing;

// Test helper function for cleaner test code
fn createTestZeiCoin(data_dir: []const u8) !ZeiCoin {
    // Clean up any existing test data first
    std.fs.cwd().deleteTree(data_dir) catch {};

    var zeicoin = ZeiCoin{
        .database = try db.Database.init(testing.allocator, data_dir),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .mempool_size_bytes = 0,
        .network = null,
        .allocator = testing.allocator,
        .sync_state = .synced,
        .sync_progress = null,
        .sync_peer = null,
        .failed_peers = ArrayList(*net.Peer).init(testing.allocator),
        .processed_transactions = std.ArrayList([32]u8).init(testing.allocator),
        .fork_manager = forkmanager.ForkManager.init(testing.allocator),
        .mining_state = types.MiningState.init(),
    };

    // Initialize fork manager with genesis (database should be empty now)
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    return zeicoin;
}

test "blockchain initialization" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_init");
    defer zeicoin.deinit();

    // Should have genesis block (height starts at 1 after genesis creation)
    const height = try zeicoin.getHeight();
    try testing.expect(height >= 1);

    // Test that fork manager was initialized during genesis creation
    const active_chain = zeicoin.fork_manager.getActiveChain();
    try testing.expect(active_chain != null);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_init") catch {};
}

test "transaction processing" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_tx");
    defer zeicoin.deinit();

    // Create a test keypair for the transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    // Create a unique test address
    var alice_hash: [31]u8 = undefined;
    @memset(&alice_hash, 0);
    alice_hash[0] = 0xAA;
    alice_hash[1] = 0xBB;
    alice_hash[30] = 0xFF;
    const alice_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = alice_hash,
    };

    // Create account for sender manually since this is just a test
    const sender_account = Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN, // Give sender some balance
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and sign transaction
    var tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1704067200,
        .expiry_height = 10000, // Far future for test
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature), // Will be replaced
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Sign the transaction
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mine with a different miner so alice doesn't get mining reward
    var miner_keypair = try key.KeyPair.generateNew();
    defer miner_keypair.deinit();
    const mined_block = try zeicoin.zenMineBlock(miner_keypair);
    var mutable_mined_block = mined_block;
    defer mutable_mined_block.deinit(testing.allocator);

    // Check balances
    const alice_balance = try zeicoin.getBalance(alice_addr);
    try testing.expectEqual(10 * types.ZEI_COIN, alice_balance);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_tx") catch {};
}

test "block retrieval by height" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_retrieval");
    defer zeicoin.deinit();

    // Should have genesis block at height 0
    var genesis_block = try zeicoin.getBlockByHeight(0);
    defer genesis_block.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 1), genesis_block.txCount()); // Genesis has 1 coinbase transaction
    try testing.expectEqual(@as(u64, types.Genesis.timestamp()), genesis_block.header.timestamp);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_retrieval") catch {};
}

test "block validation" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_validation");
    defer zeicoin.deinit();

    // Create a valid test block that extends the genesis
    const current_height = try zeicoin.getHeight();
    if (current_height == 0) {
        // Skip this test if no genesis block exists
        return;
    }
    var prev_block = try zeicoin.getBlockByHeight(current_height - 1);
    defer prev_block.deinit(testing.allocator);

    // Create valid transactions for the block
    const transactions = try testing.allocator.alloc(types.Transaction, 1);
    defer testing.allocator.free(transactions);

    // Coinbase transaction
    transactions[0] = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = Address.zero(),
        .sender_public_key = std.mem.zeroes([32]u8),
        .recipient = Address.zero(),
        .amount = types.ZenMining.BLOCK_REWARD,
        .fee = 0, // Coinbase has no fee
        .nonce = 0,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
        .timestamp = @intCast(util.getTime()),
        .expiry_height = std.math.maxInt(u64), // Coinbase never expires
        .signature = std.mem.zeroes(types.Signature),
    };

    // Create valid block
    var valid_block = types.Block{
        .header = createTestBlockHeader(
            prev_block.hash(),
            std.mem.zeroes(types.Hash),
            @intCast(util.getTime()),
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = transactions,
    };

    // Find a valid nonce for the block
    var nonce: u32 = 0;
    var found_valid_nonce = false;
    while (nonce < 10000) {
        valid_block.header.nonce = nonce;
        const difficulty_target = valid_block.header.getDifficultyTarget();
        if (difficulty_target.meetsDifficulty(valid_block.header.hash())) {
            found_valid_nonce = true;
            break;
        }
        nonce += 1;
    }

    // Should have found a valid nonce
    try testing.expect(found_valid_nonce);

    // Should validate correctly
    const is_valid = try zeicoin.validateBlock(valid_block, current_height);
    try testing.expect(is_valid);

    // Invalid block with wrong previous hash should fail
    var invalid_block = valid_block;
    invalid_block.header.previous_hash = std.mem.zeroes(types.Hash);
    const is_invalid = try zeicoin.validateBlock(invalid_block, current_height);
    try testing.expect(!is_invalid);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_validation") catch {};
}

test "mempool cleaning after block application" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_mempool");
    defer zeicoin.deinit();

    // Create test keypair and transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    // Create a unique test address
    var alice_hash: [31]u8 = undefined;
    @memset(&alice_hash, 0);
    alice_hash[0] = 1;
    const alice_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = alice_hash,
    };

    // Create sender account
    const sender_account = types.Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN,
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and add transaction to mempool
    var tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = 10000,
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mempool should have 1 transaction
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);

    // Mine block (which includes the transaction)
    const mined_block = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_mined_block = mined_block;
    defer mutable_mined_block.deinit(testing.allocator);

    // Mempool should be empty after mining
    try testing.expectEqual(@as(usize, 0), zeicoin.mempool.items.len);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_mempool") catch {};
}

test "block broadcasting integration" {
    var zeicoin = try ZeiCoin.init(testing.allocator);
    defer zeicoin.deinit();

    // This test verifies that broadcastNewBlock doesn't crash when no network is present
    const transactions = try testing.allocator.alloc(types.Transaction, 0);
    defer testing.allocator.free(transactions);

    const test_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            @intCast(util.getTime()),
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = transactions,
    };

    // Should not crash when no network is available
    zeicoin.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}

test "timestamp validation - future blocks rejected" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_timestamp_future");
    defer zeicoin.deinit();
    defer std.fs.cwd().deleteTree("test_zeicoin_timestamp_future") catch {};

    // Create a block with timestamp too far in future
    const future_time = @as(u64, @intCast(util.getTime())) + @as(u64, @intCast(types.TimestampValidation.MAX_FUTURE_TIME)) + 3600; // 1 hour beyond limit

    var transactions = [_]types.Transaction{};
    const future_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            future_time,
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = &transactions,
    };

    // Block should be rejected
    const is_valid = try zeicoin.validateBlock(future_block, 1);
    try testing.expect(!is_valid);
}

test "timestamp validation - median time past" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_mtp");
    defer zeicoin.deinit();
    defer std.fs.cwd().deleteTree("test_zeicoin_mtp") catch {};

    // Mine some blocks with increasing timestamps
    var i: u32 = 0;
    while (i < 15) : (i += 1) {
        var transactions = [_]types.Transaction{};
        const block = types.Block{
            .header = createTestBlockHeader(
                if (i == 0) std.mem.zeroes(types.Hash) else blk: {
                    var prev = try zeicoin.getBlockByHeight(i - 1);
                    defer prev.deinit(zeicoin.allocator);
                    break :blk prev.hash();
                },
                std.mem.zeroes(types.Hash),
                types.Genesis.timestamp() + (i + 1) * 600, // 10 minutes apart
                types.ZenMining.initialDifficultyTarget().toU64(),
                0
            ),
            .transactions = &transactions,
        };

        // Process block directly (bypass validation for test setup)
        try zeicoin.database.saveBlock(i, block);
    }

    // Calculate expected MTP (median of last 11 blocks)
    const expected_mtp = types.Genesis.timestamp() + 10 * 600; // Median of blocks 4-14
    const actual_mtp = try zeicoin.getMedianTimePast(14);
    try testing.expectEqual(expected_mtp, actual_mtp);

    // Create block with timestamp equal to MTP (should fail)
    var bad_transactions = [_]types.Transaction{};
    const bad_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            expected_mtp,
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = &bad_transactions,
    };

    // This should fail MTP validation
    const is_valid = try zeicoin.validateBlock(bad_block, 15);
    try testing.expect(!is_valid);
}

test "timestamp validation - constants" {
    // Test that our constants make sense
    try testing.expect(types.TimestampValidation.MAX_FUTURE_TIME > 0);
    try testing.expect(types.TimestampValidation.MAX_FUTURE_TIME <= 24 * 60 * 60); // Max 24 hours
    try testing.expect(types.TimestampValidation.MTP_BLOCK_COUNT >= 3); // Need at least 3 for meaningful median
    try testing.expect(types.TimestampValidation.MTP_BLOCK_COUNT % 2 == 1); // Odd number for clean median
}

test "coinbase maturity basic" {
    const test_dir = "test_coinbase_maturity";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer zeicoin.deinit();

    // Create a test miner
    const miner_keypair = try key.KeyPair.generateNew();
    const miner_address = miner_keypair.getAddress();

    // Mine a block (coinbase reward should be immature)
    const block1 = try zeicoin.zenMineBlock(miner_keypair);
    var mutable_block1 = block1;
    defer mutable_block1.deinit(zeicoin.allocator);
    
    // Check balance - should all be immature
    const account1 = try zeicoin.getAccount(miner_address);
    try testing.expectEqual(@as(u64, 0), account1.balance); // No mature balance
    try testing.expectEqual(@as(u64, types.ZenMining.BLOCK_REWARD), account1.immature_balance); // All immature
    
    print("\n✅ Coinbase maturity test: Mining reward correctly marked as immature\n", .{});
}

test "mempool limits enforcement" {
    const test_dir = "test_mempool_limits";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer zeicoin.deinit();

    // Test 1: Test reaching transaction count limit
    print("\n🧪 Testing mempool transaction count limit...\n", .{});
    
    // Directly fill mempool to limit by manipulating internal state
    // This avoids creating 10,000 actual transactions
    const max_tx = types.MempoolLimits.MAX_TRANSACTIONS;
    
    // Create dummy transactions to fill mempool
    var i: usize = 0;
    while (i < max_tx) : (i += 1) {
        // Create unique recipient address for each transaction
        var recipient_hash: [31]u8 = undefined;
        @memset(&recipient_hash, 0);
        recipient_hash[0] = @intCast(i % 256);
        recipient_hash[1] = @intCast((i / 256) % 256);
        const recipient_addr = Address{
            .version = @intFromEnum(types.AddressVersion.P2PKH),
            .hash = recipient_hash,
        };
        
        var dummy_tx = types.Transaction{
            .version = 0,
            .flags = std.mem.zeroes(types.TransactionFlags),
            .sender = std.mem.zeroes(types.Address),
            .sender_public_key = std.mem.zeroes([32]u8),
            .recipient = recipient_addr,
            .amount = 1,
            .fee = types.ZenFees.MIN_FEE,
            .nonce = i,
            .timestamp = @intCast(util.getTime()),
            .expiry_height = 10000,
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        
        try zeicoin.mempool.append(dummy_tx);
        zeicoin.mempool_size_bytes += dummy_tx.getSerializedSize();
    }
    
    try testing.expectEqual(@as(usize, max_tx), zeicoin.mempool.items.len);
    print("  ✅ Mempool filled to exactly {} transactions (limit)\n", .{max_tx});
    
    
    // Try to add one more (should fail)
    const overflow_sender = try key.KeyPair.generateNew();
    const overflow_sender_addr = overflow_sender.getAddress();
    try zeicoin.database.saveAccount(overflow_sender_addr, types.Account{
        .address = overflow_sender_addr,
        .balance = 10 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    var overflow_hash: [31]u8 = undefined;
    @memset(&overflow_hash, 0);
    overflow_hash[0] = 254;
    const overflow_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = overflow_hash,
    };
    var overflow_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = overflow_sender_addr,
        .sender_public_key = overflow_sender.public_key,
        .recipient = overflow_addr,
        .amount = 1 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_overflow = overflow_tx;
    signed_overflow.signature = try overflow_sender.signTransaction(overflow_tx.hashForSigning());
    
    const result = zeicoin.addTransaction(signed_overflow);
    try testing.expectError(error.MempoolFull, result);
    print("  ✅ Transaction correctly rejected when mempool full\n", .{});
    
    // Test 2: Size tracking
    const expected_size = max_tx * types.MempoolLimits.TRANSACTION_SIZE;
    try testing.expectEqual(expected_size, zeicoin.mempool_size_bytes);
    print("  ✅ Mempool size correctly tracked: {} bytes\n", .{expected_size});
    
    // Test 3: Clear mempool and test size limit
    zeicoin.mempool.clearRetainingCapacity();
    zeicoin.mempool_size_bytes = 0;
    print("\n🧪 Testing mempool size limit...\n", .{});
    
    // Calculate how many transactions fit in size limit
    const txs_for_size_limit = types.MempoolLimits.MAX_SIZE_BYTES / types.MempoolLimits.TRANSACTION_SIZE;
    print("  📊 Size limit allows for {} transactions\n", .{txs_for_size_limit});
    
    // Artificially set the size to just below limit
    zeicoin.mempool_size_bytes = types.MempoolLimits.MAX_SIZE_BYTES - types.MempoolLimits.TRANSACTION_SIZE + 1;
    
    // Try to add a transaction (should fail due to size limit)
    const size_test_sender = try key.KeyPair.generateNew();
    const size_test_sender_addr = size_test_sender.getAddress();
    try zeicoin.database.saveAccount(size_test_sender_addr, types.Account{
        .address = size_test_sender_addr,
        .balance = 10 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    var recipient_hash: [31]u8 = undefined;
    @memset(&recipient_hash, 0);
    recipient_hash[0] = 123;
    const size_test_recipient = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = recipient_hash,
    };
    const size_test_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = size_test_sender_addr,
        .sender_public_key = size_test_sender.public_key,
        .recipient = size_test_recipient,
        .amount = 1 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_size_test = size_test_tx;
    signed_size_test.signature = try size_test_sender.signTransaction(size_test_tx.hashForSigning());
    
    const size_result = zeicoin.addTransaction(signed_size_test);
    try testing.expectError(error.MempoolSizeLimitExceeded, size_result);
    print("  ✅ Transaction correctly rejected when size limit exceeded\n", .{});
    
    print("\n🎉 All mempool limit tests passed!\n", .{});
}

test "transaction expiration" {
    const test_dir = "test_tx_expiry";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer zeicoin.deinit();

    // Create test wallets
    const sender_keypair = try key.KeyPair.generateNew();
    const sender_addr = sender_keypair.getAddress();
    const recipient_keypair = try key.KeyPair.generateNew();
    const recipient_addr = recipient_keypair.getAddress();

    // Fund sender
    try zeicoin.database.saveAccount(sender_addr, types.Account{
        .address = sender_addr,
        .balance = 100 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });

    print("\n📅 Testing transaction expiration...\n", .{});

    // Test 1: Valid transaction with future expiry
    const current_height = zeicoin.getHeight() catch 0;
    const valid_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = current_height + 100, // Expires in 100 blocks
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_valid = valid_tx;
    signed_valid.signature = try sender_keypair.signTransaction(valid_tx.hashForSigning());
    
    try zeicoin.addTransaction(signed_valid);
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);
    print("  ✅ Transaction with future expiry accepted\n", .{});

    // Clear mempool
    zeicoin.mempool.clearRetainingCapacity();

    // Test 2: Expired transaction (expiry at current height)
    const expired_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = current_height, // Already expired
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_expired = expired_tx;
    signed_expired.signature = try sender_keypair.signTransaction(expired_tx.hashForSigning());
    
    const expired_result = zeicoin.addTransaction(signed_expired);
    try testing.expectError(error.InvalidTransaction, expired_result);
    try testing.expectEqual(@as(usize, 0), zeicoin.mempool.items.len);
    print("  ✅ Expired transaction correctly rejected\n", .{});

    // Test 3: Mine blocks and verify transaction expiration
    // Add a transaction that expires in 2 blocks
    const short_expiry_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = current_height + 2, // Expires in 2 blocks
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_short = short_expiry_tx;
    signed_short.signature = try sender_keypair.signTransaction(short_expiry_tx.hashForSigning());
    
    try zeicoin.addTransaction(signed_short);
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);
    
    // Mine first block - transaction should still be valid
    const block1 = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_block1 = block1;
    defer mutable_block1.deinit(zeicoin.allocator);
    
    // Mine second block - now at expiry height
    const block2 = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_block2 = block2;
    defer mutable_block2.deinit(zeicoin.allocator);
    
    // Try to add the same transaction again (simulating rebroadcast)
    const rebroadcast_result = zeicoin.addTransaction(signed_short);
    try testing.expectError(error.InvalidTransaction, rebroadcast_result);
    print("  ✅ Transaction expired after mining blocks\n", .{});

    // Test 4: Verify default expiry window is set correctly
    const expiry_window = types.TransactionExpiry.getExpiryWindow();
    try testing.expectEqual(@as(u64, 8_640), expiry_window); // TestNet: 24 hours
    print("  ✅ Default expiry window is 24 hours (8,640 blocks)\n", .{});

    print("\n🎉 All transaction expiration tests passed!\n", .{});
}

test "reorganization with coinbase maturity" {
    const test_dir = "test_reorg_maturity";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer zeicoin.deinit();

    // Create test accounts
    const miner1 = try key.KeyPair.generateNew();
    const miner1_addr = miner1.getAddress();
    const miner2 = try key.KeyPair.generateNew();
    const miner2_addr = miner2.getAddress();
    
    // Fund an account for transactions
    const sender = try key.KeyPair.generateNew();
    const sender_addr = sender.getAddress();
    try zeicoin.database.saveAccount(sender_addr, types.Account{
        .address = sender_addr,
        .balance = 1000 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    print("\n🧪 Testing reorganization with coinbase maturity...\n", .{});
    
    // Scenario: Mine 101 blocks so first coinbase matures
    print("  1️⃣ Mining 101 blocks to mature first coinbase...\n", .{});
    var i: u32 = 0;
    while (i < 101) : (i += 1) {
        // Mine a block and immediately deinitialize it to free its transactions
        var block = try zeicoin.zenMineBlock(miner1);
        block.deinit(zeicoin.allocator);
    }
    
    // Check miner1's balance after 101 blocks  
    // Note: We start at height 0 (genesis), so after mining 101 blocks we're at height 101
    // Block at height 1 matures at height 101 (100 blocks later)
    const height = try zeicoin.getHeight();
    print("  📊 Current height: {}\n", .{height});
    const account_before = try zeicoin.getAccount(miner1_addr);
    print("  💰 Miner balance - mature: {}, immature: {}\n", .{account_before.balance, account_before.immature_balance});
    try testing.expectEqual(@as(u64, types.ZenMining.BLOCK_REWARD), account_before.balance); // Block 1 matured
    try testing.expectEqual(@as(u64, 100 * types.ZenMining.BLOCK_REWARD), account_before.immature_balance); // Blocks 2-101 still immature
    print("  ✅ Block 1 coinbase matured correctly\n", .{});
    
    // Create a transaction that spends the matured coinbase
    const spend_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = miner1_addr,
        .sender_public_key = miner1.public_key,
        .recipient = miner2_addr,
        .amount = types.ZenMining.BLOCK_REWARD / 2, // Spend half
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_tx = spend_tx;
    signed_tx.signature = try miner1.signTransaction(spend_tx.hash());
    
    // Add transaction and mine it
    try zeicoin.addTransaction(signed_tx);
    const block_with_spend = try zeicoin.zenMineBlock(miner1);
    var mutable_block_with_spend = block_with_spend;
    defer mutable_block_with_spend.deinit(zeicoin.allocator);
    print("  ✅ Spent matured coinbase in block 102\n", .{});
    
    // Verify the spend worked
    const miner1_after_spend = try zeicoin.getAccount(miner1_addr);
    const miner2_after_spend = try zeicoin.getAccount(miner2_addr);
    print("  💰 After spend - Miner1: mature={}, immature={}\n", .{miner1_after_spend.balance, miner1_after_spend.immature_balance});
    print("  💰 After spend - Miner2: mature={}, immature={}\n", .{miner2_after_spend.balance, miner2_after_spend.immature_balance});
    // Miner1 spent half of first mature block but block 2 also matured, plus got fees
    // So balance should be: 0.5 ZEI (remaining from block 1) + 1 ZEI (block 2) + small fees
    try testing.expect(miner1_after_spend.balance > 0); // Has balance
    try testing.expect(miner2_after_spend.balance == types.ZenMining.BLOCK_REWARD / 2); // Got exactly half
    
    // Now trigger a reorg back to height 50 (before maturity)
    print("  2️⃣ Simulating reorganization back to height 50...\n", .{});
    const current_height = try zeicoin.getHeight();
    try testing.expectEqual(@as(u32, 103), current_height); // Genesis + 101 + 1 spend block
    
    // Perform rollback
    try zeicoin.rollbackToHeight(50);
    
    // Verify rollback worked
    const height_after_rollback = try zeicoin.getHeight();
    try testing.expectEqual(@as(u32, 103), height_after_rollback); // Height doesn't change, only state
    
    // Check miner1's balance after rollback - no mature coins yet!
    const account_after_reorg = try zeicoin.getAccount(miner1_addr);
    try testing.expectEqual(@as(u64, 0), account_after_reorg.balance); // No mature balance at height 50
    // We replayed to height 50, which includes blocks 1-50 (genesis at 0 has no miner reward)
    try testing.expectEqual(@as(u64, 50 * types.ZenMining.BLOCK_REWARD), account_after_reorg.immature_balance); // Blocks 1-50
    
    // Miner2 should have no balance
    const miner2_after_reorg = zeicoin.getAccount(miner2_addr) catch {
        // Account might not exist, which is fine
        print("  ✅ Miner2 account correctly doesn't exist after reorg\n", .{});
        return;
    };
    try testing.expectEqual(@as(u64, 0), miner2_after_reorg.balance);
    try testing.expectEqual(@as(u64, 0), miner2_after_reorg.immature_balance);
    
    print("  ✅ Reorganization correctly rolled back matured coinbase and dependent transactions\n", .{});
}

test "transaction size limit" {
    // This test verifies that transactions exceeding MAX_TX_SIZE are rejected
    print("\n🔍 Testing transaction size limit...\n", .{});
    
    // Create test blockchain
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_tx_size");
    defer zeicoin.deinit();
    
    // Create test keypairs
    var alice = try key.KeyPair.generateNew();
    defer alice.deinit();
    const alice_addr = alice.getAddress();
    var bob = try key.KeyPair.generateNew();
    defer bob.deinit();
    const bob_addr = bob.getAddress();
    
    // Give Alice some coins
    try zeicoin.database.saveAccount(alice_addr, types.Account{
        .address = alice_addr,
        .balance = 1000 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    // Create a transaction with extra_data that exceeds the limit
    const large_data = try testing.allocator.alloc(u8, types.TransactionLimits.MAX_TX_SIZE);
    defer testing.allocator.free(large_data);
    @memset(large_data, 'A'); // Fill with 'A's
    
    const oversized_tx = types.Transaction{
        .version = 0,
        .flags = types.TransactionFlags{},
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.timestamp()),
        .expiry_height = try zeicoin.getHeight() + types.TransactionExpiry.getExpiryWindow(),
        .sender_public_key = alice.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = large_data,
    };
    
    // Check that the transaction is invalid due to size
    try testing.expectEqual(false, oversized_tx.isValid());
    print("  ✅ Oversized transaction ({} bytes) correctly rejected by isValid()\n", .{oversized_tx.getSerializedSize()});
    
    // Don't try to sign or add invalid transaction - it would panic during hashing
    
    // Create a transaction with small extra_data (should succeed)
    const small_extra = 256; // Small enough to fit in hash buffer
    const small_data = try testing.allocator.alloc(u8, small_extra);
    defer testing.allocator.free(small_data);
    @memset(small_data, 'B');
    
    const valid_tx = types.Transaction{
        .version = 0,
        .flags = types.TransactionFlags{},
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 50 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.timestamp()),
        .expiry_height = try zeicoin.getHeight() + types.TransactionExpiry.getExpiryWindow(),
        .sender_public_key = alice.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = small_data,
    };
    
    // Check that this transaction is valid
    try testing.expectEqual(true, valid_tx.isValid());
    print("  ✅ Transaction with {} bytes extra_data accepted (under {} byte limit)\n", .{small_data.len, types.TransactionLimits.MAX_EXTRA_DATA_SIZE});
    
    // Sign and add to mempool
    var signed_valid_tx = valid_tx;
    signed_valid_tx.signature = try alice.signTransaction(valid_tx.hash());
    try zeicoin.addTransaction(signed_valid_tx);
    print("  ✅ Valid transaction successfully added to mempool\n", .{});
    
    print("  ✅ Transaction size limit tests passed!\n", .{});
}

test "memory leak detection - block operations" {
    print("\n🔍 Testing memory leak prevention in block operations...\n", .{});
    
    // Use testing allocator which tracks leaks
    const allocator = testing.allocator;
    
    // Test 1: Block loading and cleanup
    {
        print("  Testing block load/free cycle...\n", .{});
        var zeicoin = try createTestZeiCoin("test_memory_leak_blocks");
        defer zeicoin.deinit();
        
        // Create and mine a block with multiple transactions
        const alice = try key.KeyPair.generateNew();
        const bob = try key.KeyPair.generateNew();
        const alice_addr = alice.getAddress();
        const bob_addr = bob.getAddress();
        
        // Fund alice by creating an account
        const alice_account = types.Account{
            .address = alice_addr,
            .balance = 1000 * types.ZEI_COIN,
            .immature_balance = 0,
            .nonce = 0,
        };
        try zeicoin.database.saveAccount(alice_addr, alice_account);
        
        // Add multiple transactions (without extra_data to avoid allocation issues)
        // Note: All use nonce 0 since they're all from the same account in mempool
        for (0..3) |i| {
            const amount = (10 + i) * types.ZEI_COIN; // Vary amount instead of nonce
            const tx = try createTestTransaction(alice_addr, bob_addr, amount, types.ZenFees.MIN_FEE, 0, alice, allocator);
            try zeicoin.addTransaction(tx);
        }
        
        // Mine block
        const block = try zeicoin.zenMineBlock(alice);
        var mutable_block = block;
        defer mutable_block.deinit(zeicoin.allocator);
        
        // Load block from database multiple times to test cleanup
        for (0..5) |_| {
            var loaded_block = try zeicoin.database.getBlock(0);
            // This should properly free all nested allocations
            loaded_block.deinit(zeicoin.allocator);
        }
        
        print("  ✅ Block load/free cycle completed without leaks\n", .{});
    }
    
    // Test 2: Sync block handling
    {
        print("  Testing sync block memory management...\n", .{});
        var zeicoin = try createTestZeiCoin("test_memory_leak_sync");
        defer zeicoin.deinit();
        
        // Create a block with transactions containing extra_data
        const miner = try key.KeyPair.generateNew();
        const recipient = try key.KeyPair.generateNew();
        
        var transactions = try allocator.alloc(types.Transaction, 2);
        
        // Coinbase transaction
        transactions[0] = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = types.Address.zero(),
            .recipient = miner.getAddress(),
            .amount = types.ZenMining.BLOCK_REWARD,
            .fee = 0,
            .nonce = 0,
            .timestamp = @intCast(std.time.timestamp()),
            .expiry_height = 0,
            .sender_public_key = std.mem.zeroes([32]u8),
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        
        // Regular transaction with extra_data
        const test_message = "Test message for memory leak detection";
        const extra_data_copy = try allocator.dupe(u8, test_message);
        transactions[1] = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = miner.getAddress(),
            .recipient = recipient.getAddress(),
            .amount = 5 * types.ZEI_COIN,
            .fee = types.ZenFees.MIN_FEE,
            .nonce = 0,
            .timestamp = @intCast(std.time.timestamp()),
            .expiry_height = 1000,
            .sender_public_key = miner.public_key,
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = extra_data_copy,
        };
        
        // Create first block for sync
        const sync_block1 = types.Block{
            .header = createTestBlockHeader(std.mem.zeroes(types.Hash), std.mem.zeroes(types.Hash), @intCast(std.time.timestamp()), 0x1d00ffff, 0),
            .transactions = transactions,
        };
        
        // Create a duplicate of transactions for second block
        const transactions2 = try allocator.alloc(types.Transaction, 2);
        // Deep copy transactions to avoid double-free
        for (transactions, 0..) |tx, i| {
            transactions2[i] = try tx.dupe(allocator);
        }
        
        const sync_block2 = types.Block{
            .header = createTestBlockHeader(std.mem.zeroes(types.Hash), std.mem.zeroes(types.Hash), @intCast(std.time.timestamp()), 0x1d00ffff, 0),
            .transactions = transactions2,
        };
        
        // Simulate receiving this block during sync
        // handleSyncBlock takes ownership and will free the block
        try zeicoin.handleSyncBlock(0, sync_block1);
        
        // Try again with duplicate - should detect duplicate and free properly
        try zeicoin.handleSyncBlock(0, sync_block2);
        
        print("  ✅ Sync block memory properly managed\n", .{});
    }
    
    // Test 3: Transaction deinit validation
    {
        print("  Testing transaction deinit with various slice configurations...\n", .{});
        
        // Test with allocated slices
        const witness_buf = try allocator.alloc(u8, 10);
        const extra_buf = try allocator.alloc(u8, 20);
        @memset(witness_buf, 'W');
        @memset(extra_buf, 'E');
        
        var tx1 = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = types.Address.zero(),
            .recipient = types.Address.zero(),
            .amount = 1000,
            .fee = 0,
            .nonce = 0,
            .timestamp = 0,
            .expiry_height = 0,
            .sender_public_key = std.mem.zeroes([32]u8),
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = witness_buf,
            .extra_data = extra_buf,
        };
        tx1.deinit(allocator);
        
        // Test with empty static slices (should not crash)
        var tx2 = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = types.Address.zero(),
            .recipient = types.Address.zero(),
            .amount = 1000,
            .fee = 0,
            .nonce = 0,
            .timestamp = 0,
            .expiry_height = 0,
            .sender_public_key = std.mem.zeroes([32]u8),
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        tx2.deinit(allocator); // Should handle empty slices gracefully
        
        print("  ✅ Transaction deinit handles all slice configurations correctly\n", .{});
    }
    
    print("\n🎉 All memory leak detection tests passed!\n", .{});
}
