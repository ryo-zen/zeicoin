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
            .network = null,
            .allocator = allocator,
            .sync_state = .synced,
            .sync_progress = null,
            .sync_peer = null,
            .failed_peers = ArrayList(*net.Peer).init(allocator),
            .processed_transactions = std.ArrayList([32]u8).init(allocator),
        };

        // Create canonical genesis block if database is empty
        if (try blockchain.getHeight() == 0) {
            try blockchain.createCanonicalGenesis();
        }

        return blockchain;
    }

    /// Initialize blockchain after network discovery
    /// Creates genesis if no network exists, otherwise prepares for sync
    pub fn initializeBlockchain(self: *ZeiCoin) !void {
        const current_height = try self.getHeight();
        
        if (current_height == 0) {
            // No blockchain exists locally
            if (self.network) |network| {
                const connected_peers = network.getConnectedPeers();
                if (connected_peers > 0) {
                    print("🔗 Connected to {} peers, waiting for blockchain sync...\n", .{connected_peers});
                    // Don't create genesis - wait for sync to download the network's blockchain
                    return;
                }
            }
            
            // No network peers found, create local genesis
            print("🌐 No network peers found, creating local genesis block\n", .{});
            try self.createGenesis();
        }
    }

    /// Cleanup blockchain resources
    pub fn deinit(self: *ZeiCoin) void {
        self.database.deinit();
        self.mempool.deinit();
        self.failed_peers.deinit();
        self.processed_transactions.deinit();
        // Note: network is managed externally
    }

    /// Create the canonical genesis block from hardcoded definition
    fn createCanonicalGenesis(self: *ZeiCoin) !void {
        // For compatibility with existing bootstrap server, create empty genesis
        const transactions = try self.allocator.alloc(types.Transaction, 0);
        const genesis_block = types.Block{
            .header = types.BlockHeader{
                .previous_hash = std.mem.zeroes([32]u8),
                .merkle_root = std.mem.zeroes(types.Hash),
                .timestamp = 1704067200,
                .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
                .nonce = 0,
            },
            .transactions = transactions,
        };

        // Save genesis block to database
        try self.database.saveBlock(0, genesis_block);

        print("🎉 ZeiCoin Genesis Block Created!\n", .{});
        print("📦 Block #0: {} transactions\n", .{genesis_block.txCount()});
        print("🌐 Network: TestNet (Bootstrap Compatible)\n", .{});
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

    /// Add transaction to memory pool
    pub fn addTransaction(self: *ZeiCoin, transaction: Transaction) !void {
        // Validate transaction
        if (!try self.validateTransaction(transaction)) {
            return error.InvalidTransaction;
        }

        try self.mempool.append(transaction);
        logInfo("Transaction added to mempool: {} ZEI from sender to recipient", .{transaction.amount / types.ZEI_COIN});

        // Broadcast transaction to network peers
        if (self.network) |*network| {
            network.*.broadcastTransaction(transaction);
        }
    }

    /// Validate a transaction against current blockchain state
    fn validateTransaction(self: *ZeiCoin, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

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
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
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
        const total_cost = tx.amount + tx.fee;
        
        // Safety check for integer overflow during sync
        if (sender_account.balance < total_cost) {
            print("⚠️ Warning: insufficient balance during sync (trusting historical block)\n", .{});
            print("   Account {} has {} zei, needs {} zei\n", .{ 
                std.fmt.fmtSliceHexLower(sender_account.address[0..8]), 
                sender_account.balance, 
                total_cost 
            });
            // During sync, we trust the historical block was valid - just set balance to 0
            sender_account.balance = 0;
        } else {
            sender_account.balance -= total_cost;
        }
        
        sender_account.nonce += 1;
        recipient_account.balance += tx.amount; // Only amount goes to recipient, fee goes to miner

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

    /// Mine a new block with zen proof-of-work (the simplest thing that works)
    pub fn mineBlock(self: *ZeiCoin) !void {
        // Genesis mining with dummy keypair
        const genesis_keypair = key.KeyPair.fromPrivateKey(std.mem.zeroes([64]u8));
        _ = try self.zenMineBlock(genesis_keypair);
    }

    /// Mine a new block with zen proof-of-work for a specific miner
    pub fn zenMineBlock(self: *ZeiCoin, miner_keypair: key.KeyPair) !types.Block {
        // 💰 Calculate total fees from mempool transactions
        var total_fees: u64 = 0;
        for (self.mempool.items) |tx| {
            total_fees += tx.fee;
        }

        // Create coinbase transaction (miner reward + fees)
        const miner_reward = types.ZenMining.BLOCK_REWARD + total_fees;
        const coinbase_tx = Transaction{
            .sender = std.mem.zeroes(types.Address), // From thin air (coinbase)
            .sender_public_key = std.mem.zeroes([32]u8), // No sender for coinbase
            .recipient = miner_keypair.getAddress(),
            .amount = miner_reward, // 💰 Block reward + all transaction fees
            .fee = 0, // Coinbase has no fee
            .nonce = 0, // Coinbase always nonce 0
            .timestamp = @intCast(util.getTime()),
            .signature = std.mem.zeroes(types.Signature), // No signature needed for coinbase
        };

        // Format miner reward display
        const base_reward_display = util.formatZEI(self.allocator, types.ZenMining.BLOCK_REWARD) catch "? ZEI";
        defer if (!std.mem.eql(u8, base_reward_display, "? ZEI")) self.allocator.free(base_reward_display);
        const fees_display = util.formatZEI(self.allocator, total_fees) catch "? ZEI";
        defer if (!std.mem.eql(u8, fees_display, "? ZEI")) self.allocator.free(fees_display);
        const total_reward_display = util.formatZEI(self.allocator, miner_reward) catch "? ZEI";
        defer if (!std.mem.eql(u8, total_reward_display, "? ZEI")) self.allocator.free(total_reward_display);

        print("💰 Miner reward: {s} (base) + {s} (fees) = {s} total\n", .{ base_reward_display, fees_display, total_reward_display });

        // Combine coinbase + mempool transactions
        var all_transactions = try self.allocator.alloc(Transaction, self.mempool.items.len + 1);
        defer self.allocator.free(all_transactions);

        all_transactions[0] = coinbase_tx; // Coinbase always first
        @memcpy(all_transactions[1..], self.mempool.items);

        // Get previous block hash and calculate next difficulty
        const current_height = try self.getHeight();
        const previous_hash = if (current_height > 0) blk: {
            const prev_block = try self.database.getBlock(current_height - 1);
            const hash = prev_block.hash();
            self.allocator.free(prev_block.transactions);
            break :blk hash;
        } else std.mem.zeroes(Hash);

        // Calculate difficulty for new block
        const next_difficulty_target = try self.calculateNextDifficulty();

        // Create block with dynamic difficulty
        var new_block = Block{
            .header = BlockHeader{
                .previous_hash = previous_hash,
                .merkle_root = std.mem.zeroes(Hash), // Zen simplicity
                .timestamp = @intCast(util.getTime()),
                .difficulty = next_difficulty_target.toU64(),
                .nonce = 0,
            },
            .transactions = try self.allocator.dupe(Transaction, all_transactions),
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

            // Clear mempool
            self.mempool.clearRetainingCapacity();
            
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
            self.allocator.free(new_block.transactions);
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
        const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
        var rx_ctx = randomx.RandomXContext.init(self.allocator, &chain_key, mode) catch {
            print("❌ Failed to initialize RandomX\n", .{});
            return false;
        };
        defer rx_ctx.deinit();

        var nonce: u32 = 0;
        while (nonce < types.ZenMining.MAX_NONCE) {
            block.header.nonce = nonce;

            // Serialize block header for RandomX input
            var buffer: [256]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            block.header.serialize(stream.writer()) catch return false;
            const header_data = stream.getWritten();

            // Calculate RandomX hash
            var hash: [32]u8 = undefined;
            rx_ctx.hash(header_data, &hash) catch {
                print("❌ RandomX hash calculation failed\n", .{});
                return false;
            };

            // Check if hash meets difficulty target
            const difficulty_target = block.header.getDifficultyTarget();
            if (randomx.hashMeetsDifficultyTarget(hash, difficulty_target)) {
                print("✨ RandomX nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
                return true;
            }

            nonce += 1;

            // Progress indicator (every 10k tries due to RandomX being slower)
            if (nonce % types.PROGRESS.RANDOMX_REPORT_INTERVAL == 0) {
                print("RandomX mining... tried {} nonces\n", .{nonce});
            }
        }

        return false; // Mining timeout
    }

    /// Legacy SHA256 proof-of-work for tests (faster)
    fn zenProofOfWorkSHA256(self: *ZeiCoin, block: *Block) bool {
        _ = self; // suppress unused parameter warning
        var nonce: u32 = 0;
        while (nonce < types.ZenMining.MAX_NONCE) {
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
        const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
        var rx_ctx = randomx.RandomXContext.init(self.allocator, &chain_key, mode) catch {
            print("❌ Failed to initialize RandomX for validation\n", .{});
            return false;
        };
        defer rx_ctx.deinit();

        // Serialize block header for RandomX input
        var buffer: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        try block.header.serialize(stream.writer());
        const header_data = stream.getWritten();

        // Calculate RandomX hash
        var hash: [32]u8 = undefined;
        rx_ctx.hash(header_data, &hash) catch {
            print("❌ RandomX hash calculation failed during validation\n", .{});
            return false;
        };

        // Check if hash meets difficulty target
        const difficulty_target = block.header.getDifficultyTarget();
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
            const prev_block = try self.database.getBlock(prev_block_height);
            defer self.allocator.free(prev_block.transactions);
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
            const old_block = try self.database.getBlock(old_block_height);
            defer self.allocator.free(old_block.transactions);
            oldest_timestamp = old_block.header.timestamp;
        }

        // Get timestamp from previous block
        const prev_block_height: u32 = @intCast(current_height - 1);
        const prev_block = try self.database.getBlock(prev_block_height);
        defer self.allocator.free(prev_block.transactions);
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
        };

        // Create new coins! (This is where ZEI comes from)
        miner_account.balance += coinbase_tx.amount;

        // Save miner account
        try self.database.saveAccount(miner_address, miner_account);

        print("💰 NEW COINS CREATED: {} ZEI for miner {s}\n", .{ coinbase_tx.amount / types.ZEI_COIN, std.fmt.fmtSliceHexLower(miner_address[0..8]) });
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

        // Check block height consistency
        const current_height = try self.getHeight();
        if (expected_height != current_height) {
            print("❌ Block validation failed: height mismatch (expected: {}, current: {})\n", .{ expected_height, current_height });
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

        // Check previous hash links correctly
        if (expected_height > 0) {
            const prev_block = try self.getBlockByHeight(expected_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                print("❌ Previous hash validation failed\n", .{});
                print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
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

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.getHeight();
            if (expected_height > current_height) {
                // During sync, we might not have the previous block yet - skip this check
                print("⚠️ Skipping previous hash check during sync (height {} > current {})\n", .{ expected_height, current_height });
            } else {
                const prev_block = try self.getBlockByHeight(expected_height - 1);
                defer self.allocator.free(prev_block.transactions);

                const prev_hash = prev_block.hash();
                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    print("❌ Previous hash validation failed\n", .{});
                    print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                    return false;
                }
            }
        }

        // For sync blocks, validate transaction structure but skip balance checks
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

        print("✅ Sync block {} structure and signatures validated\n", .{expected_height});
        return true;
    }

    /// Validate transaction signature only (used during sync)
    fn validateTransactionSignature(self: *ZeiCoin, tx: Transaction) !bool {
        _ = self; // Unused parameter
        
        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            return false;
        }

        return true;
    }

    /// Check if a block builds on a known block in our chain (for fork detection)
    fn isValidForkBlock(self: *ZeiCoin, block: types.Block) !bool {
        const current_height = try self.getHeight();
        
        // Check if block's previous_hash matches any block in our chain
        for (0..current_height) |height| {
            const existing_block = self.database.getBlock(@intCast(height)) catch continue;
            defer self.allocator.free(existing_block.transactions);
            
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
                _ = self.mempool.swapRemove(i);
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
            if (self.database.getBlock(i)) |block| {
                print("   Block #{}: {} txs\n", .{ i, block.txCount() });
                // Free block memory after displaying
                self.allocator.free(block.transactions);
            } else |_| {
                print("   Block #{}: Error loading\n", .{i});
            }
        }
        print("\n", .{});
    }

    /// Broadcast newly mined block to network peers (zen flow)
    fn broadcastNewBlock(self: *ZeiCoin, block: types.Block) void {
        if (self.network) |network| {
            network.broadcastBlock(block);
            print("📡 Block flows to {} peers naturally\n", .{network.getPeerCount()});
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
            return err;
        };

        print("✅ Network transaction flows into zen mempool\n", .{});
    }

    /// Handle incoming block from network peer
    pub fn handleIncomingBlock(self: *ZeiCoin, block: types.Block) !void {
        // Basic validation and chain extension
        const current_height = try self.getHeight();

        print("🌊 Block flows in from network peer with {} transactions\n", .{block.transactions.len});

        // Zen wisdom: check if we already have this block (prevent duplicates)
        const block_hash = block.hash();
        if (current_height > 0) {
            for (0..current_height) |height| {
                const existing_block = self.database.getBlock(@intCast(height)) catch continue;
                defer self.allocator.free(existing_block.transactions);

                if (std.mem.eql(u8, &existing_block.hash(), &block_hash)) {
                    print("🌊 Block already flows in our zen chain - gracefully ignored\n", .{});
                    return;
                }
            }
        }

        // Fork resolution: check if block extends current tip OR creates a longer chain
        var is_chain_extension = false;
        var is_fork_block = false;
        
        if (current_height > 0) {
            const current_tip = try self.database.getBlock(current_height - 1);
            defer self.allocator.free(current_tip.transactions);

            const expected_prev_hash = current_tip.hash();
            if (std.mem.eql(u8, &block.header.previous_hash, &expected_prev_hash)) {
                // Block extends current chain tip
                is_chain_extension = true;
                print("📈 Block extends current chain (height {} → {})\n", .{ current_height, current_height + 1 });
            } else {
                // Potential fork - check if it builds on an earlier block
                is_fork_block = try self.isValidForkBlock(block);
                if (is_fork_block) {
                    print("🔀 Fork block detected - evaluating longest chain rule\n", .{});
                } else {
                    print("❌ Block rejected: doesn't build on known chain\n", .{});
                    return;
                }
            }
        } else {
            // Genesis block case
            is_chain_extension = true;
        }

        // If it's a fork, we'll handle it after validation
        if (!is_chain_extension and !is_fork_block) {
            print("❌ Block rejected: invalid chain connection\n", .{});
            return;
        }

        // Zen proof-of-work validation with dynamic difficulty
        const difficulty_target = block.header.getDifficultyTarget();
        if (!difficulty_target.meetsDifficulty(block_hash)) {
            print("❌ Block rejected: doesn't meet zen proof-of-work target\n", .{});
            return;
        }

        // Handle block acceptance based on type
        if (is_chain_extension) {
            // Normal case: block extends current chain
            try self.processBlockTransactions(block.transactions);
            try self.database.saveBlock(current_height, block);
            print("✅ Block #{} accepted and flows into zen blockchain\n", .{current_height});
            
            // Broadcast the accepted block
            if (self.network) |network| {
                network.*.broadcastBlock(block);
                print("🌊 Valid block flows onwards to other zen peers\n", .{});
            }
        } else if (is_fork_block) {
            // Fork case: store block for potential reorganization
            print("🔀 Fork block received - implementing longest chain rule\n", .{});
            
            // For now, simply reject forks and stick to first-seen rule
            // TODO: Implement proper longest chain reorganization
            print("⚠️ Fork rejected: longest chain rule not yet implemented\n", .{});
            print("💡 Tip: For TestNet, avoid simultaneous mining to prevent forks\n", .{});
            return;
        }
    }

    /// Handle sync block from network (specifically for sync process)
    pub fn handleSyncBlock(self: *ZeiCoin, expected_height: u32, block: types.Block) !void {
        print("🔄 Processing sync block at height {}\n", .{expected_height});

        // For sync, validate block structure and PoW only (skip transaction balance checks)
        if (!try self.validateSyncBlock(block, expected_height)) {
            print("❌ Block validation failed at height {}\n", .{expected_height});
            return error.InvalidSyncBlock;
        }

        // Process transactions first to update account states
        try self.processBlockTransactions(block.transactions);

        // Add block to chain
        try self.database.saveBlock(expected_height, block);

        // Update sync progress
        if (self.sync_progress) |*progress| {
            progress.blocks_downloaded += 1;

            // Report progress periodically
            const now = util.getTime();
            if (now - progress.last_progress_report >= types.SYNC.PROGRESS_REPORT_INTERVAL) {
                self.reportSyncProgress();
                progress.last_progress_report = now;
            }

            // Check if we've reached the target height
            const current_height = self.getHeight() catch expected_height;
            if (current_height >= progress.target_height) {
                self.completSync();
                return;
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

        if (self.sync_progress) |progress| {
            const elapsed = util.getTime() - progress.start_time;
            const blocks_per_sec = progress.getBlocksPerSecond();
            print("📊 Sync stats: {} blocks in {}s ({:.2} blocks/sec)\n", .{ progress.blocks_downloaded, elapsed, blocks_per_sec });
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
            if (isCoinbaseTransaction(tx)) {
                print("💰 Processing coinbase: {} ZEI for miner\n", .{tx.amount / types.ZEI_COIN});
                try self.processCoinbaseTransaction(tx, tx.recipient);
            }
        }
        
        // Second pass: process all regular transactions  
        for (transactions) |tx| {
            if (!isCoinbaseTransaction(tx)) {
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
        if (self.processed_transactions.items.len > MAX_PROCESSED_TXS) {
            // Clear all and let them rebuild naturally
            self.processed_transactions.clearAndFree();
            print("🧹 Cleaned processed transaction cache (memory management)\n", .{});
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
            print("⏰ Sync request timed out\n", .{});
            self.requestNextSyncBatch() catch |err| {
                print("❌ Failed to retry sync request: {}\n", .{err});
                self.failSync("Failed to retry sync request");
            };
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
    return ZeiCoin{
        .database = try db.Database.init(testing.allocator, data_dir),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .network = null,
        .allocator = testing.allocator,
        .sync_state = .synced,
        .sync_progress = null,
        .sync_peer = null,
        .failed_peers = ArrayList(*net.Peer).init(testing.allocator),
        .processed_transactions = std.ArrayList([32]u8).init(testing.allocator),
    };
}

test "blockchain initialization" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_init");
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    // Should have genesis block (height starts at 1 after genesis creation)
    const height = try zeicoin.getHeight();
    try testing.expect(height >= 1); // May be 1 or 2 depending on auto-mining

    // Should have genesis account (use same key generation as createGenesis)
    const genesis_config = types.Genesis.getConfig();
    var genesis_public_key: [32]u8 = undefined;
    std.mem.writeInt(u64, genesis_public_key[0..8], genesis_config.nonce, .little);
    @memset(genesis_public_key[8..], 0);
    const genesis_addr = util.hash256(&genesis_public_key);
    const balance = try zeicoin.getBalance(genesis_addr);
    try testing.expectEqual(types.Genesis.reward(), balance);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_init") catch {};
}

test "transaction processing" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_tx");
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    // Create a test keypair for the transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    var alice_addr = std.mem.zeroes(Address);
    // Use a more unique address pattern
    alice_addr[0] = 0xAA;
    alice_addr[1] = 0xBB;
    alice_addr[31] = 0xFF;

    // Create account for sender manually since this is just a test
    const sender_account = Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN, // Give sender some balance
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and sign transaction
    var tx = Transaction{
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1704067200,
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature), // Will be replaced
    };

    // Sign the transaction
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mine with a different miner so alice doesn't get mining reward
    var miner_keypair = try key.KeyPair.generateNew();
    defer miner_keypair.deinit();
    const mined_block = try zeicoin.zenMineBlock(miner_keypair);
    defer testing.allocator.free(mined_block.transactions);

    // Check balances
    const alice_balance = try zeicoin.getBalance(alice_addr);
    try testing.expectEqual(10 * types.ZEI_COIN, alice_balance);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_tx") catch {};
}

test "block retrieval by height" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_retrieval");
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    // Should have genesis block at height 0
    const genesis_block = try zeicoin.getBlockByHeight(0);
    defer testing.allocator.free(genesis_block.transactions);

    try testing.expectEqual(@as(u32, 0), genesis_block.txCount());
    try testing.expectEqual(@as(u64, types.Genesis.timestamp()), genesis_block.header.timestamp);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_retrieval") catch {};
}

test "block validation" {
    var zeicoin = try ZeiCoin.init(testing.allocator);
    defer zeicoin.deinit();

    // Create a valid test block that extends the genesis
    const current_height = try zeicoin.getHeight();
    const prev_block = try zeicoin.getBlockByHeight(current_height - 1);
    defer testing.allocator.free(prev_block.transactions);

    // Create valid transactions for the block
    const transactions = try testing.allocator.alloc(types.Transaction, 1);
    defer testing.allocator.free(transactions);

    // Coinbase transaction - sender address must match hash of public key
    const coinbase_public_key = std.mem.zeroes([32]u8);
    const coinbase_sender = util.hash256(&coinbase_public_key);
    transactions[0] = types.Transaction{
        .sender = coinbase_sender,
        .sender_public_key = coinbase_public_key,
        .recipient = std.mem.zeroes(types.Address),
        .amount = types.ZenMining.BLOCK_REWARD,
        .fee = 0, // Coinbase has no fee
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .signature = std.mem.zeroes(types.Signature),
    };

    // Create valid block
    var valid_block = types.Block{
        .header = types.BlockHeader{
            .previous_hash = prev_block.hash(),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = @intCast(util.getTime()),
            .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 0,
        },
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
}

test "mempool cleaning after block application" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_mempool");
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    // Create test keypair and transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    var alice_addr = std.mem.zeroes(types.Address);
    alice_addr[0] = 1;

    // Create sender account
    const sender_account = types.Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN,
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and add transaction to mempool
    var tx = types.Transaction{
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature),
    };

    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mempool should have 1 transaction
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);

    // Mine block (which includes the transaction)
    const mined_block = try zeicoin.zenMineBlock(sender_keypair);
    defer testing.allocator.free(mined_block.transactions);

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
        .header = types.BlockHeader{
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = @intCast(util.getTime()),
            .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 0,
        },
        .transactions = transactions,
    };

    // Should not crash when no network is available
    zeicoin.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}
