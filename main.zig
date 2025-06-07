// main.zig - ZeiCoin Blockchain Core
// A minimalist proof-of-work blockchain implementation written in Zig
// Features account-based model, Ed25519 signatures, RandomX PoW, Bech32 addresses, and nonce-based double spending protection
// Additional features: P2P networking, mempool management, file-based persistence, transaction fees, CLI wallet
// Now with ASIC-resistant RandomX proof-of-work algorithm

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const types = @import("types.zig");
const util = @import("util.zig");
const serialize = @import("serialize.zig");
const db = @import("db.zig");
const key = @import("key.zig");
const net = @import("net.zig");
const randomx = @import("randomx.zig");

// Helper function to format ZEI amounts with proper decimal places
fn formatZEI(allocator: std.mem.Allocator, amount_zei: u64) ![]u8 {
    const zei_coins = amount_zei / types.ZEI_COIN;
    const zei_fraction = amount_zei % types.ZEI_COIN;

    if (zei_fraction == 0) {
        return std.fmt.allocPrint(allocator, "{} ZEI", .{zei_coins});
    } else {
        // Format with 5 decimal places for precision
        const decimal = @as(f64, @floatFromInt(zei_fraction)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        return std.fmt.allocPrint(allocator, "{}.{d:0>5} ZEI", .{ zei_coins, @as(u64, @intFromFloat(decimal * 100000)) });
    }
}

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

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
        };

        // Create genesis block if database is empty
        if (try blockchain.getHeight() == 0) {
            try blockchain.createGenesis();
        }

        return blockchain;
    }

    /// Cleanup blockchain resources
    pub fn deinit(self: *ZeiCoin) void {
        self.database.deinit();
        self.mempool.deinit();
        // Note: network is managed externally
    }

    /// Create the genesis block with initial distribution
    fn createGenesis(self: *ZeiCoin) !void {
        // Get network-specific genesis configuration
        const genesis_config = types.Genesis.getConfig();
        
        // Create unique genesis public key using network-specific nonce
        var genesis_public_key: [32]u8 = undefined;
        std.mem.writeInt(u64, genesis_public_key[0..8], genesis_config.nonce, .little);
        @memset(genesis_public_key[8..], 0);
        
        const genesis_addr = util.hash256(&genesis_public_key);

        // Create genesis account with initial supply
        const genesis_account = Account{
            .address = genesis_addr,
            .balance = genesis_config.reward,
            .nonce = 0,
        };

        // Save genesis account to database
        try self.database.saveAccount(genesis_addr, genesis_account);

        // Create genesis block with network-specific message
        const genesis_transactions = try self.allocator.alloc(Transaction, 0);
        defer self.allocator.free(genesis_transactions);

        // Include genesis message in merkle root calculation
        var message_hash: Hash = undefined;
        std.crypto.hash.sha2.Sha256.hash(genesis_config.message, &message_hash, .{});

        const genesis_block = Block{
            .header = BlockHeader{
                .previous_hash = std.mem.zeroes(Hash),
                .merkle_root = message_hash, // Genesis message hash as merkle root
                .timestamp = genesis_config.timestamp,
                .difficulty = 0x1d00ffff, // Easy difficulty for genesis
                .nonce = @as(u32, @truncate(genesis_config.nonce)), // Use network nonce
            },
            .transactions = genesis_transactions,
        };

        // Save genesis block to database
        try self.database.saveBlock(0, genesis_block);

        print("🎉 ZeiCoin Genesis Block Created!\n", .{});
        print("📦 Block #{}: {} transactions\n", .{ 0, genesis_block.txCount() });
        print("💰 Genesis Account: {} ZEI\n", .{genesis_config.reward / types.ZEI_COIN});
        print("📝 Genesis Message: \"{s}\"\n", .{genesis_config.message});
        print("🌐 Network: {s}\n", .{types.NetworkConfig.networkName()});
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
        print("📝 Transaction added to mempool: {} ZEI from sender to recipient\n", .{transaction.amount / types.ZEI_COIN});

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
            print("❌ Invalid nonce: expected {}, got {}\n", .{ sender_account.nextNonce(), tx.nonce });
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
            const balance_display = formatZEI(self.allocator, sender_account.balance) catch "? ZEI";
            defer if (!std.mem.eql(u8, balance_display, "? ZEI")) self.allocator.free(balance_display);
            const amount_display = formatZEI(self.allocator, tx.amount) catch "? ZEI";
            defer if (!std.mem.eql(u8, amount_display, "? ZEI")) self.allocator.free(amount_display);
            const fee_display = formatZEI(self.allocator, tx.fee) catch "? ZEI";
            defer if (!std.mem.eql(u8, fee_display, "? ZEI")) self.allocator.free(fee_display);
            const total_display = formatZEI(self.allocator, total_cost) catch "? ZEI";
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
        sender_account.balance -= total_cost;
        sender_account.nonce += 1;
        recipient_account.balance += tx.amount; // Only amount goes to recipient, fee goes to miner

        // Save updated accounts to database
        try self.database.saveAccount(tx.sender, sender_account);
        try self.database.saveAccount(tx.recipient, recipient_account);

        // Format amounts properly for display
        const amount_display = formatZEI(self.allocator, tx.amount) catch "? ZEI";
        defer if (!std.mem.eql(u8, amount_display, "? ZEI")) self.allocator.free(amount_display);
        const fee_display = formatZEI(self.allocator, tx.fee) catch "? ZEI";
        defer if (!std.mem.eql(u8, fee_display, "? ZEI")) self.allocator.free(fee_display);
        const total_display = formatZEI(self.allocator, total_cost) catch "? ZEI";
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
        const base_reward_display = formatZEI(self.allocator, types.ZenMining.BLOCK_REWARD) catch "? ZEI";
        defer if (!std.mem.eql(u8, base_reward_display, "? ZEI")) self.allocator.free(base_reward_display);
        const fees_display = formatZEI(self.allocator, total_fees) catch "? ZEI";
        defer if (!std.mem.eql(u8, fees_display, "? ZEI")) self.allocator.free(fees_display);
        const total_reward_display = formatZEI(self.allocator, miner_reward) catch "? ZEI";
        defer if (!std.mem.eql(u8, total_reward_display, "? ZEI")) self.allocator.free(total_reward_display);

        print("💰 Miner reward: {s} (base) + {s} (fees) = {s} total\n", .{ base_reward_display, fees_display, total_reward_display });

        // Combine coinbase + mempool transactions
        var all_transactions = try self.allocator.alloc(Transaction, self.mempool.items.len + 1);
        defer self.allocator.free(all_transactions);

        all_transactions[0] = coinbase_tx; // Coinbase always first
        @memcpy(all_transactions[1..], self.mempool.items);

        // Get previous block hash
        const current_height = try self.getHeight();
        const previous_hash = if (current_height > 0) blk: {
            const prev_block = try self.database.getBlock(current_height - 1);
            const hash = prev_block.hash();
            self.allocator.free(prev_block.transactions);
            break :blk hash;
        } else std.mem.zeroes(Hash);

        // Create block with zen difficulty
        var new_block = Block{
            .header = BlockHeader{
                .previous_hash = previous_hash,
                .merkle_root = std.mem.zeroes(Hash), // Zen simplicity
                .timestamp = @intCast(util.getTime()),
                .difficulty = types.ZenMining.INITIAL_DIFFICULTY,
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
            if (randomx.hashMeetsDifficulty(hash, types.ZenMining.DIFFICULTY_BYTES)) {
                print("✨ RandomX nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
                return true;
            }

            nonce += 1;

            // Progress indicator (every 10k tries due to RandomX being slower)
            if (nonce % 10_000 == 0) {
                print("RandomX mining... tried {} nonces\n", .{nonce});
            }
        }

        return false; // Mining timeout
    }

    /// Legacy SHA256 proof-of-work for tests (faster)
    fn zenProofOfWorkSHA256(self: *ZeiCoin, block: *Block) bool {
        var nonce: u32 = 0;
        while (nonce < types.ZenMining.MAX_NONCE) {
            block.header.nonce = nonce;

            // Calculate block hash using SHA256
            const hash = block.header.hash();

            // Check if hash meets zen difficulty
            if (self.zenHashMeetsTarget(hash)) {
                print("✨ Zen nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
                return true;
            }

            nonce += 1;

            // Progress indicator (every 100k tries)
            if (nonce % 100_000 == 0) {
                print("Zen mining... tried {} nonces\n", .{nonce});
            }
        }

        return false;
    }

    /// Check if hash meets zen target (now uses configurable difficulty)
    fn zenHashMeetsTarget(self: *ZeiCoin, hash: [32]u8) bool {
        _ = self; // zen simplicity

        // Use RandomX difficulty checking
        return randomx.hashMeetsDifficulty(hash, types.ZenMining.DIFFICULTY_BYTES);
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
        return randomx.hashMeetsDifficulty(hash, types.ZenMining.DIFFICULTY_BYTES);
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
        // Check basic block structure
        if (!block.isValid()) return false;

        // Check block height consistency
        const current_height = try self.getHeight();
        if (expected_height != current_height) return false;

        // Check proof-of-work with RandomX (simplified for tests)
        if (@import("builtin").mode == .Debug) {
            // In test mode, just check simple hash target for speed
            if (!self.zenHashMeetsTarget(block.header.hash())) return false;
        } else {
            // In production, use full RandomX validation
            if (!try self.validateBlockPoW(block)) return false;
        }

        // Check previous hash links correctly
        if (expected_height > 0) {
            const prev_block = try self.getBlockByHeight(expected_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) return false;
        }

        // Validate all transactions in block
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) continue;

            if (!try self.validateTransaction(tx)) return false;
        }

        return true;
    }

    /// Apply a valid block to the blockchain
    fn applyBlock(self: *ZeiCoin, block: Block) !void {
        // Process all transactions in the block
        for (block.transactions) |tx| {
            // Handle coinbase transaction
            if (std.mem.eql(u8, &tx.sender, &std.mem.zeroes(Address))) {
                try self.processCoinbaseTransaction(tx, tx.recipient);
            } else {
                try self.processTransaction(tx);
            }
        }

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
        // Zen wisdom: check if we already have this transaction (prevent duplicates)
        const tx_hash = transaction.hash();
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

        // Zen validation: check if block extends our chain properly
        if (current_height > 0) {
            const prev_block = try self.database.getBlock(current_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const expected_prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &expected_prev_hash)) {
                print("❌ Block rejected: previous hash doesn't match (zen wisdom protects chain)\n", .{});
                return;
            }
        }

        // Zen proof-of-work validation
        if (!self.zenHashMeetsTarget(block_hash)) {
            print("❌ Block rejected: doesn't meet zen proof-of-work target\n", .{});
            return;
        }

        // Process all transactions in the block (zen flow)
        for (block.transactions) |tx| {
            // Skip coinbase transaction (first one)
            if (std.mem.eql(u8, &tx.sender, &std.mem.zeroes(types.Address))) {
                try self.processCoinbaseTransaction(tx, tx.recipient);
            } else {
                try self.processTransaction(tx);
            }
        }

        // Save block to database (zen persistence)
        try self.database.saveBlock(current_height, block);

        print("✅ Block #{} accepted and flows into zen blockchain\n", .{current_height});

        // Zen propagation: relay valid block to other peers (but not back to sender)
        if (self.network) |network| {
            network.*.broadcastBlock(block);
            print("🌊 Valid block flows onwards to other zen peers\n", .{});
        }
    }
};

// Tests
const testing = std.testing;

test "blockchain initialization" {
    // Use unique data directory for this test
    var zeicoin = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_init"),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .network = null,
        .allocator = testing.allocator,
    };
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }

    // Should have genesis block (height starts at 1 after genesis creation)
    const height = try zeicoin.getHeight();
    try testing.expect(height >= 1); // May be 1 or 2 depending on auto-mining

    // Should have genesis account
    const genesis_public_key = std.mem.zeroes([32]u8);
    const genesis_addr = util.hash256(&genesis_public_key);
    const balance = try zeicoin.getBalance(genesis_addr);
    try testing.expectEqual(types.Genesis.reward, balance);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_init") catch {};
}

test "transaction processing" {
    // Use unique data directory for this test
    var zeicoin = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_tx"),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .network = null,
        .allocator = testing.allocator,
    };
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
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
    // Use unique data directory for this test
    var zeicoin = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_retrieval"),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .network = null,
        .allocator = testing.allocator,
    };
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }

    // Should have genesis block at height 0
    const genesis_block = try zeicoin.getBlockByHeight(0);
    defer testing.allocator.free(genesis_block.transactions);

    try testing.expectEqual(@as(u32, 0), genesis_block.txCount());
    try testing.expectEqual(@as(u64, types.Genesis.timestamp), genesis_block.header.timestamp);

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
            .difficulty = types.ZenMining.INITIAL_DIFFICULTY,
            .nonce = 0,
        },
        .transactions = transactions,
    };

    // Find a valid nonce for the block
    var nonce: u32 = 0;
    var found_valid_nonce = false;
    while (nonce < 10000) {
        valid_block.header.nonce = nonce;
        if (zeicoin.zenHashMeetsTarget(valid_block.header.hash())) {
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
    // Use unique data directory for this test
    var zeicoin = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_mempool"),
        .mempool = ArrayList(Transaction).init(testing.allocator),
        .network = null,
        .allocator = testing.allocator,
    };
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
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
            .difficulty = types.ZenMining.INITIAL_DIFFICULTY,
            .nonce = 0,
        },
        .transactions = transactions,
    };

    // Should not crash when no network is available
    zeicoin.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}
