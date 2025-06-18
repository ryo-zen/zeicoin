// types.zig - Zeicoin Core Types
// Minimal approach - only what we need, nothing more
// Simple account model with nonce-based double-spend protection

const std = @import("std");
const util = @import("util.zig");

// Money constants - ZeiCoin monetary units
pub const ZEI_COIN: u64 = 100000000; // 1 Zeicoin = 100,000,000 zei
pub const ZEI_CENT: u64 = 1000000; // 1 cent = 1,000,000 zei

// Timing constants - Common intervals used throughout the codebase
pub const TIMING = struct {
    pub const PEER_TIMEOUT_SECONDS: i64 = 60;
    pub const DISCOVERY_INTERVAL_SECONDS: i64 = 300; // 5 minutes
    pub const HEIGHT_CHECK_INTERVAL_SECONDS: i64 = 120; // 2 minutes - less frequent
    pub const MAINTENANCE_CYCLE_SECONDS: u64 = 10;
    pub const SERVER_SLEEP_MS: u64 = 10;
    pub const CLI_TIMEOUT_SECONDS: u64 = 5;
    pub const BACKOFF_BASE_SECONDS: i64 = 30;
};

// Progress reporting constants
pub const PROGRESS = struct {
    pub const RANDOMX_REPORT_INTERVAL: u32 = 10_000;
    pub const SHA256_REPORT_INTERVAL: u32 = 100_000;
    pub const DECIMAL_PRECISION_MULTIPLIER: u64 = 100_000;
};

// Sync protocol constants - ZeiCoin blockchain synchronization
pub const SYNC = struct {
    pub const BATCH_SIZE: u32 = 10; // Blocks per sync request (small for responsiveness)
    pub const SYNC_TIMEOUT_SECONDS: i64 = 30; // Timeout for sync requests
    pub const RETRY_DELAY_SECONDS: i64 = 5; // Delay before retrying failed sync
    pub const MAX_SYNC_RETRIES: u32 = 3; // Maximum sync retry attempts
    pub const MAX_CONSECUTIVE_FAILURES: u32 = 5; // Maximum consecutive sync failures before peer disconnect
    pub const PROGRESS_REPORT_INTERVAL: u32 = 10; // Report progress every N blocks
};

// Network constants - Bootstrap nodes for peer discovery
pub const BOOTSTRAP_NODES = [_][]const u8{
    "134.199.168.129:10801", // Public bootstrap node
    // Note: Local/private IPs should not be hardcoded as bootstrap nodes
    // They will be discovered via local network scanning if available
};

// Network ports - ZeiCoin zen networking
pub const NETWORK_PORTS = struct {
    pub const P2P: u16 = 10801; // Peer-to-peer network
    pub const CLIENT_API: u16 = 10802; // Client API
    pub const DISCOVERY: u16 = 10800; // UDP discovery
};

// Node types for asymmetric networking
pub const NodeType = enum {
    full_node,     // Can accept incoming connections (public IP)
    outbound_only, // Behind NAT, outbound connections only (private IP)
    unknown,       // Not yet determined
    
    pub fn canServeBlocks(self: NodeType) bool {
        return self == .full_node;
    }
    
    pub fn canReceiveBlocks(self: NodeType) bool {
        _ = self; // All node types can receive blocks
        return true; // All nodes can receive blocks
    }
};

// Address is a simple 32-byte hash
pub const Address = [32]u8;

// Transaction signature (Ed25519 signature)
pub const Signature = [64]u8;

// Hash types for various purposes
pub const Hash = [32]u8;
pub const TxHash = Hash;
pub const BlockHash = Hash;

/// ZeiCoin transaction - simple account model
pub const Transaction = struct {
    version: u16, // Transaction version for protocol upgrades
    sender: Address,
    recipient: Address,
    amount: u64, // Amount in zei (base unit)
    fee: u64, // 💰 Transaction fee paid to miner
    nonce: u64, // Sender's transaction counter (prevents double-spend)
    timestamp: u64, // Unix timestamp when transaction was created
    sender_public_key: [32]u8, // Public key of sender (for signature verification)
    signature: Signature, // Ed25519 signature of transaction data

    /// Calculate the hash of this transaction (used as transaction ID)
    pub fn hash(self: *const Transaction) TxHash {
        return self.hashForSigning();
    }

    /// Calculate hash of transaction data for signing (excludes signature field)
    pub fn hashForSigning(self: *const Transaction) Hash {
        // Create a copy without signature for hashing
        const tx_for_hash = struct {
            version: u16,
            sender: Address,
            recipient: Address,
            amount: u64,
            fee: u64, // 💰 Include fee in transaction hash
            nonce: u64,
            timestamp: u64,
            sender_public_key: [32]u8,
        }{
            .version = self.version,
            .sender = self.sender,
            .recipient = self.recipient,
            .amount = self.amount,
            .fee = self.fee,
            .nonce = self.nonce,
            .timestamp = self.timestamp,
            .sender_public_key = self.sender_public_key,
        };

        // Serialize and hash the transaction data
        var buffer: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        const writer = stream.writer();

        // Simple serialization for hashing (order matters!)
        writer.writeInt(u16, tx_for_hash.version, .little) catch unreachable;
        writer.writeAll(&tx_for_hash.sender) catch unreachable;
        writer.writeAll(&tx_for_hash.recipient) catch unreachable;
        writer.writeInt(u64, tx_for_hash.amount, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.fee, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.nonce, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.timestamp, .little) catch unreachable;
        writer.writeAll(&tx_for_hash.sender_public_key) catch unreachable;

        const data = stream.getWritten();
        return util.hash256(data);
    }

    /// Check if this is a coinbase transaction (created from thin air)
    pub fn isCoinbase(self: *const Transaction) bool {
        return std.mem.eql(u8, &self.sender, &std.mem.zeroes(Address));
    }

    /// Check if transaction has valid basic structure
    pub fn isValid(self: *const Transaction) bool {
        // Version validation - only version 0 is currently supported
        if (self.version != 0) {
            std.debug.print("❌ Transaction invalid: unsupported version {}\n", .{self.version});
            return false;
        }
        
        // Coinbase transactions have simpler validation rules
        if (self.isCoinbase()) {
            // Coinbase validation: amount > 0, timestamp > 0
            if (self.amount == 0) {
                std.debug.print("❌ Coinbase invalid: amount is 0\n", .{});
                return false;
            }
            if (self.timestamp == 0) {
                std.debug.print("❌ Coinbase invalid: timestamp is 0\n", .{});
                return false;
            }
            // Coinbase can send to any recipient
            return true;
        }

        // Regular transaction validation
        if (self.amount == 0) {
            std.debug.print("❌ Transaction invalid: amount is 0\n", .{});
            return false;
        }
        if (self.timestamp == 0) {
            std.debug.print("❌ Transaction invalid: timestamp is 0\n", .{});
            return false;
        }
        if (std.mem.eql(u8, &self.sender, &self.recipient)) {
            std.debug.print("❌ Transaction invalid: sender equals recipient\n", .{});
            return false;
        }

        // Verify that sender address matches the hash of provided public key
        const derived_address = util.hash256(&self.sender_public_key);
        if (!std.mem.eql(u8, &self.sender, &derived_address)) {
            std.debug.print("❌ Transaction invalid: sender address doesn't match public key\n", .{});
            return false;
        }

        return true;
    }
    
    /// Get the serialized size of this transaction in bytes
    pub fn getSerializedSize(self: *const Transaction) usize {
        _ = self;
        // All transactions have the same size due to fixed-size fields
        return MempoolLimits.TRANSACTION_SIZE;
    }
};

/// Account state in ZeiCoin network
pub const Account = struct {
    address: Address,
    balance: u64, // Current balance in zei (mature, spendable)
    nonce: u64, // Next expected transaction nonce
    immature_balance: u64 = 0, // Balance from recent coinbase transactions (not spendable)
    
    /// Check if account can afford a transaction (only considers mature balance)
    pub fn canAfford(self: *const Account, amount: u64) bool {
        return self.balance >= amount;
    }
    
    /// Get expected nonce for next transaction
    pub fn nextNonce(self: *const Account) u64 {
        return self.nonce;
    }
    
    /// Get total balance (mature + immature)
    pub fn totalBalance(self: *const Account) u64 {
        return self.balance + self.immature_balance;
    }
};

/// Track immature coinbase rewards for an account
pub const ImmatureCoins = struct {
    address: Address,
    entries: [100]ImmatureCoinEntry = std.mem.zeroes([100]ImmatureCoinEntry), // Max 100 immature entries
    count: u32 = 0, // Number of valid entries
};

/// Individual immature coin entry
pub const ImmatureCoinEntry = struct {
    height: u32, // Block height where coins were created
    amount: u64, // Amount of coins that are immature
};

/// Dynamic difficulty target for constrained adjustment
pub const DifficultyTarget = struct {
    base_bytes: u8,    // 1 for TestNet, 2 for MainNet (never changes)
    threshold: u32,    // Value within the remaining bytes (0x00000000 to 0xFFFFFFFF)
    
    /// Create initial difficulty target for network
    pub fn initial(network: NetworkType) DifficultyTarget {
        return switch (network) {
            .testnet => DifficultyTarget{
                .base_bytes = 1,
                .threshold = 0x80000000, // Middle of 1-byte range
            },
            .mainnet => DifficultyTarget{
                .base_bytes = 2,
                .threshold = 0x00008000, // Middle of 2-byte range
            },
        };
    }
    
    /// Check if hash meets this difficulty target
    pub fn meetsDifficulty(self: DifficultyTarget, hash: [32]u8) bool {
        // First check required zero bytes
        for (0..self.base_bytes) |i| {
            if (hash[i] != 0) return false;
        }
        
        // Then check threshold in next 4 bytes
        if (self.base_bytes + 4 > 32) return true; // Edge case: not enough bytes
        
        var hash_value: u32 = 0;
        for (0..4) |i| {
            if (self.base_bytes + i < 32) {
                hash_value = (hash_value << 8) | @as(u32, hash[self.base_bytes + i]);
            }
        }
        
        return hash_value < self.threshold;
    }
    
    /// Adjust difficulty by factor, constrained to network limits
    pub fn adjust(self: DifficultyTarget, factor: f64, network: NetworkType) DifficultyTarget {
        // Clamp factor to prevent extreme changes
        const clamped_factor = @max(0.5, @min(2.0, factor));
        
        // Calculate new threshold (inverse relationship: higher factor = higher threshold = easier)
        const new_threshold_f64 = @as(f64, @floatFromInt(self.threshold)) * clamped_factor;
        var new_threshold = @as(u32, @intFromFloat(@max(1.0, @min(0xFFFFFFFF, new_threshold_f64))));
        
        // Ensure we stay within network constraints
        const min_threshold: u32 = switch (network) {
            .testnet => 0x00010000,  // Hardest 1-byte difficulty
            .mainnet => 0x00000001,  // Hardest 2-byte difficulty
        };
        const max_threshold: u32 = switch (network) {
            .testnet => 0xFF000000,  // Easiest 1-byte difficulty
            .mainnet => 0x00FF0000,  // Easiest 2-byte difficulty
        };
        
        new_threshold = @max(min_threshold, @min(max_threshold, new_threshold));
        
        return DifficultyTarget{
            .base_bytes = self.base_bytes,
            .threshold = new_threshold,
        };
    }
    
    /// Serialize difficulty target to u64 for storage compatibility
    pub fn toU64(self: DifficultyTarget) u64 {
        return (@as(u64, self.base_bytes) << 32) | @as(u64, self.threshold);
    }
    
    /// Deserialize difficulty target from u64
    pub fn fromU64(value: u64) DifficultyTarget {
        return DifficultyTarget{
            .base_bytes = @intCast((value >> 32) & 0xFF),
            .threshold = @intCast(value & 0xFFFFFFFF),
        };
    }
};

/// Block header containing essential block information
pub const BlockHeader = struct {
    previous_hash: BlockHash,
    merkle_root: Hash, // Root of transaction merkle tree
    timestamp: u64, // Unix timestamp when block was created
    difficulty: u64, // Dynamic difficulty target (serialized DifficultyTarget)
    nonce: u32, // Proof-of-work nonce

    /// Serialize block header to bytes
    pub fn serialize(self: *const BlockHeader, writer: anytype) !void {
        try writer.writeAll(&self.previous_hash);
        try writer.writeAll(&self.merkle_root);
        try writer.writeInt(u64, self.timestamp, .little);
        try writer.writeInt(u64, self.difficulty, .little);
        try writer.writeInt(u32, self.nonce, .little);
    }
    
    /// Get difficulty target from header
    pub fn getDifficultyTarget(self: *const BlockHeader) DifficultyTarget {
        return DifficultyTarget.fromU64(self.difficulty);
    }

    /// Calculate hash of this block header
    pub fn hash(self: *const BlockHeader) BlockHash {
        // Serialize the block header to bytes
        var buffer: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        const writer = stream.writer();

        // Simple serialization for hashing (order matters!)
        self.serialize(writer) catch unreachable;

        const data = stream.getWritten();
        return util.hash256(data);
    }
    
    /// Calculate the work contribution of this block
    pub fn getWork(self: *const BlockHeader) ChainWork {
        const target = self.getDifficultyTarget();
        
        // Work = 2^128 / (target_value + 1)
        // For simplicity, use approximation: work = base_bytes * 256^28 + inverse(threshold)
        const base_work: ChainWork = (@as(ChainWork, target.base_bytes) << 112); // Heavy weight for zero bytes
        const threshold_work: ChainWork = if (target.threshold > 0) 
            @as(ChainWork, 0xFFFFFFFF) / @as(ChainWork, target.threshold)
        else 
            @as(ChainWork, 0xFFFFFFFF);
            
        return base_work + threshold_work;
    }
};

/// Complete block with header and transactions
pub const Block = struct {
    header: BlockHeader,
    transactions: []Transaction,

    /// Get the hash of this block
    pub fn hash(self: *const Block) BlockHash {
        return self.header.hash();
    }

    /// Get number of transactions in this block
    pub fn txCount(self: *const Block) u32 {
        return @intCast(self.transactions.len);
    }

    /// Calculate the serialized size of this block in bytes
    pub fn getSize(self: *const Block) usize {
        var size: usize = 0;
        
        // Header size (fixed): 32 + 32 + 8 + 8 + 4 = 84 bytes
        size += @sizeOf(BlockHash);    // previous_hash: 32 bytes
        size += @sizeOf(Hash);         // merkle_root: 32 bytes  
        size += @sizeOf(u64);          // timestamp: 8 bytes
        size += @sizeOf(u64);          // difficulty: 8 bytes
        size += @sizeOf(u32);          // nonce: 4 bytes
        
        // Transaction count: 4 bytes
        size += @sizeOf(u32);
        
        // Each transaction size (approximate)
        for (self.transactions) |_| {
            // Transaction structure:
            // version: 2, sender: 32, recipient: 32, amount: 8, fee: 8, nonce: 8, 
            // timestamp: 8, sender_public_key: 32, signature: 64
            size += 2 + 32 + 32 + 8 + 8 + 8 + 8 + 32 + 64; // 194 bytes per transaction
        }
        
        return size;
    }

    /// Check if block structure is valid
    pub fn isValid(self: *const Block) bool {
        // Genesis blocks can have transactions (they contain coinbase)
        // Regular blocks must have at least one transaction
        
        // Regular blocks must have transactions
        if (self.transactions.len == 0) {
            std.debug.print("❌ Block invalid: no transactions\n", .{});
            return false;
        }

        // All transactions must be valid
        for (self.transactions, 0..) |tx, i| {
            if (!tx.isValid()) {
                std.debug.print("❌ Block invalid: transaction {} failed validation\n", .{i});
                return false;
            }
        }

        return true;
    }
};

/// Genesis block configuration
pub const GenesisConfig = struct {
    timestamp: u64,
    message: []const u8,
    reward: u64,
    nonce: u64, // Unique nonce for each network
};

/// Chain work - cumulative proof of work (use u128 for now, upgrade to u256 if needed)
pub const ChainWork = u128;

/// Chain state for tracking competing blockchain forks
pub const ChainState = struct {
    tip_hash: BlockHash,
    tip_height: u32,
    cumulative_work: ChainWork,
    
    pub fn init(genesis_hash: BlockHash, genesis_work: ChainWork) ChainState {
        return .{
            .tip_hash = genesis_hash,
            .tip_height = 0,
            .cumulative_work = genesis_work,
        };
    }
    
    /// Compare two chains by cumulative work
    pub fn hasMoreWork(self: ChainState, other: ChainState) bool {
        return self.cumulative_work > other.cumulative_work;
    }
};

/// Fork block - block waiting to be connected to main chain
pub const ForkBlock = struct {
    block: Block,
    height: u32,
    cumulative_work: ChainWork,
    received_time: i64,
};

/// Network-specific genesis configurations
pub const Genesis = struct {
    pub fn getConfig() GenesisConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => GenesisConfig{
                .timestamp = 1704067200, // January 1, 2024 00:00:00 UTC
                .message = "ZeiCoin TestNet Genesis - A minimal digital currency written in ⚡Zig",
                .reward = 50 * ZEI_COIN,
                .nonce = 0x7E57DE7,
            },
            .mainnet => GenesisConfig{
                .timestamp = 1736150400, // January 6, 2025 00:00:00 UTC (PLACEHOLDER)
                .message = "ZeiCoin MainNet Launch - [Quote]",
                .reward = 50 * ZEI_COIN,
                .nonce = 0x3A1F1E7,
            },
        };
    }

    // Helper to get individual values for backward compatibility
    pub fn timestamp() u64 {
        return getConfig().timestamp;
    }

    pub fn message() []const u8 {
        return getConfig().message;
    }

    pub fn reward() u64 {
        return getConfig().reward;
    }
};

/// Network configuration - TestNet vs MainNet
pub const NetworkType = enum {
    testnet,
    mainnet,
};

/// Current network configuration
pub const CURRENT_NETWORK: NetworkType = .testnet; // Change to .mainnet for production

/// Network-specific configurations
pub const NetworkConfig = struct {
    randomx_mode: bool, // false = light (256MB), true = fast (2GB)
    target_block_time: u64, // seconds
    max_nonce: u32,
    block_reward: u64,
    min_fee: u64,

    pub fn current() NetworkConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => NetworkConfig{
                .randomx_mode = false, // Light mode (256MB RAM)
                .target_block_time = 10, // 10 seconds
                .max_nonce = 1_000_000, // Reasonable limit for testing
                .block_reward = 1 * ZEI_COIN, // 1 ZEI per block
                .min_fee = 1000, // 0.00001 ZEI minimum fee
            },
            .mainnet => NetworkConfig{
                .randomx_mode = true, // Fast mode (2GB RAM) for better performance
                .target_block_time = 120, // 2 minutes (Monero-like)
                .max_nonce = 10_000_000, // Higher limit for production
                .block_reward = 50 * ZEI_CENT, // 0.5 ZEI per block (deflationary)
                .min_fee = 5000, // 0.00005 ZEI minimum fee
            },
        };
    }

    pub fn networkName() []const u8 {
        return switch (CURRENT_NETWORK) {
            .testnet => "TestNet",
            .mainnet => "MainNet",
        };
    }

    pub fn displayInfo() void {
        const config = current();
        const initial_difficulty = ZenMining.initialDifficultyTarget();
        std.debug.print("🌐 Network: {s}\n", .{networkName()});
        std.debug.print("⚡ Difficulty: {}-byte range (dynamic)\n", .{initial_difficulty.base_bytes});
        std.debug.print("🧠 RandomX Mode: {s}\n", .{if (config.randomx_mode) "Fast (2GB)" else "Light (256MB)"});
        std.debug.print("⏰ Block Time: {}s\n", .{config.target_block_time});
        std.debug.print("💰 Block Reward: {d:.8} ZEI\n", .{@as(f64, @floatFromInt(config.block_reward)) / @as(f64, @floatFromInt(ZEI_COIN))});
        std.debug.print("💸 Min Fee: {d:.8} ZEI\n", .{@as(f64, @floatFromInt(config.min_fee)) / @as(f64, @floatFromInt(ZEI_COIN))});
    }
};

/// Zeicoin mining configuration - network-aware
pub const ZenMining = struct {
    pub const BLOCK_REWARD: u64 = NetworkConfig.current().block_reward;
    pub const TARGET_BLOCK_TIME: u64 = NetworkConfig.current().target_block_time;
    pub const MAX_NONCE: u32 = NetworkConfig.current().max_nonce;
    pub const RANDOMX_MODE: bool = NetworkConfig.current().randomx_mode;
    pub const DIFFICULTY_ADJUSTMENT_PERIOD: u64 = 20; // Adjust every 20 blocks
    pub const MAX_ADJUSTMENT_FACTOR: f64 = 2.0; // Maximum 2x change per adjustment
    pub const COINBASE_MATURITY: u32 = 100; // Coinbase rewards require 100 confirmations
    
    /// Get initial difficulty target for current network
    pub fn initialDifficultyTarget() DifficultyTarget {
        return DifficultyTarget.initial(CURRENT_NETWORK);
    }
};

/// 💰 Zeicoin transaction fee configuration - network-aware economic incentives
pub const ZenFees = struct {
    pub const MIN_FEE: u64 = NetworkConfig.current().min_fee;
    pub const STANDARD_FEE: u64 = NetworkConfig.current().min_fee * 5; // 5x minimum
    pub const PRIORITY_FEE: u64 = NetworkConfig.current().min_fee * 10; // 10x minimum
};

/// 📦 Block size limits - prevent spam while allowing growth
pub const BlockLimits = struct {
    /// Maximum block size in bytes (16MB) - hard consensus limit
    pub const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024; // 16MB
    
    /// Soft limit for miners (2MB) - can be adjusted without fork
    pub const SOFT_BLOCK_SIZE: usize = 2 * 1024 * 1024; // 2MB
    
    /// Average transaction size estimate for capacity planning
    pub const AVG_TX_SIZE: usize = 2048; // 2KB average
    
    /// Estimated transactions per block at soft limit
    pub const SOFT_TXS_PER_BLOCK: usize = SOFT_BLOCK_SIZE / AVG_TX_SIZE; // ~1000 txs
    
    /// Estimated transactions per block at hard limit  
    pub const MAX_TXS_PER_BLOCK: usize = MAX_BLOCK_SIZE / AVG_TX_SIZE; // ~8000 txs
};

/// 🏊 Mempool limits - prevent memory exhaustion attacks
pub const MempoolLimits = struct {
    /// Maximum number of transactions in mempool
    pub const MAX_TRANSACTIONS: usize = 10_000;
    
    /// Maximum total size of mempool in bytes (50MB)
    pub const MAX_SIZE_BYTES: usize = 50 * 1024 * 1024;
    
    /// Transaction size for serialization (with version field)
    pub const TRANSACTION_SIZE: usize = 194;
};

/// ⏰ Timestamp validation configuration - prevents time-based attacks
pub const TimestampValidation = struct {
    /// Maximum allowed timestamp in the future (seconds)
    pub const MAX_FUTURE_TIME: i64 = 2 * 60 * 60; // 2 hours
    
    /// Minimum blocks for median time past calculation
    pub const MTP_BLOCK_COUNT: u32 = 11; // Use last 11 blocks for median
    
    /// Maximum timestamp adjustment per block (seconds)
    pub const MAX_TIME_ADJUSTMENT: i64 = 90 * 60; // 90 minutes
    
    /// Validate a block timestamp against current time
    pub fn isTimestampValid(timestamp: u64, current_time: i64) bool {
        const block_time = @as(i64, @intCast(timestamp));
        return block_time <= current_time + MAX_FUTURE_TIME;
    }
    
    /// Check if timestamp is not too far in the past
    pub fn isNotTooOld(timestamp: u64, previous_timestamp: u64) bool {
        // Block timestamp must be greater than previous block
        return timestamp > previous_timestamp;
    }
};

// Tests
const testing = std.testing;

test "transaction validation" {
    // Create a test public key and derive address from it
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash256(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1; // Make it different from alice

    const tx = Transaction{
        .version = 0,
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
    };

    try testing.expect(tx.isValid());
}

test "account affordability" {
    const addr = std.mem.zeroes(Address);
    const account = Account{
        .address = addr,
        .balance = 50 * ZEI_COIN,
        .nonce = 0,
    };

    try testing.expect(account.canAfford(25 * ZEI_COIN));
    try testing.expect(!account.canAfford(100 * ZEI_COIN));
}

test "block validation" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash256(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1;

    const tx = Transaction{
        .version = 0,
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1704067200,
            .difficulty = ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 0,
        },
        .transactions = &transactions,
    };

    try testing.expect(block.isValid());
    try testing.expectEqual(@as(u32, 1), block.txCount());
}

test "money constants" {
    try testing.expectEqual(@as(u64, 100000000), ZEI_COIN);
    try testing.expectEqual(@as(u64, 1000000), ZEI_CENT);
    try testing.expectEqual(@as(u64, 100), ZEI_COIN / ZEI_CENT);
}

test "transaction hash" {
    // Create test public key and address
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = util.hash256(&public_key);

    // Create test transaction
    const tx1 = Transaction{
        .version = 0,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .amount = 1000000000,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
    };

    // Create identical transaction
    const tx2 = Transaction{
        .version = 0,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .amount = 1000000000,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
    };

    // Identical transactions should have same hash
    const hash1 = tx1.hash();
    const hash2 = tx2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Different transactions should have different hashes
    const tx3 = Transaction{
        .version = 0,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .amount = 2000000000, // Different amount
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
    };

    const hash3 = tx3.hash();
    try testing.expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "block header hash consistency" {
    // Create test block header
    const test_difficulty = ZenMining.initialDifficultyTarget().toU64();
    const header1 = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .difficulty = test_difficulty,
        .nonce = 42,
    };

    // Create identical header
    const header2 = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .difficulty = test_difficulty,
        .nonce = 42,
    };

    // Identical headers should have same hash
    const hash1 = header1.hash();
    const hash2 = header2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Hash should not be all zeros
    const zero_hash = std.mem.zeroes(Hash);
    try testing.expect(!std.mem.eql(u8, &hash1, &zero_hash));
}

test "block header hash uniqueness" {
    const test_difficulty = ZenMining.initialDifficultyTarget().toU64();
    const base_header = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = std.mem.zeroes(Hash),
        .timestamp = 1704067200,
        .difficulty = test_difficulty,
        .nonce = 0,
    };

    // Different nonce should produce different hash
    var header_nonce1 = base_header;
    header_nonce1.nonce = 1;
    var header_nonce2 = base_header;
    header_nonce2.nonce = 2;

    const hash_nonce1 = header_nonce1.hash();
    const hash_nonce2 = header_nonce2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_nonce1, &hash_nonce2));

    // Different timestamp should produce different hash
    var header_time1 = base_header;
    header_time1.timestamp = 1704067200;
    var header_time2 = base_header;
    header_time2.timestamp = 1704067300;

    const hash_time1 = header_time1.hash();
    const hash_time2 = header_time2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_time1, &hash_time2));

    // Different difficulty should produce different hash
    var header_diff1 = base_header;
    header_diff1.difficulty = test_difficulty;
    var header_diff2 = base_header;
    header_diff2.difficulty = test_difficulty + 1;

    const hash_diff1 = header_diff1.hash();
    const hash_diff2 = header_diff2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_diff1, &hash_diff2));
}

test "block hash delegated to header hash" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash256(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1;

    const tx = Transaction{
        .version = 0,
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1704067200,
            .difficulty = ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 12345,
        },
        .transactions = &transactions,
    };

    // Block hash should equal header hash
    const block_hash = block.hash();
    const header_hash = block.header.hash();
    try testing.expectEqualSlices(u8, &block_hash, &header_hash);
}
