// types.zig - Zeicoin Core Types
// Minimal approach - only what we need, nothing more
// Simple account model with nonce-based double-spend protection

const std = @import("std");
const util = @import("util.zig");

// Money constants - ZeiCoin monetary units
pub const ZEI_COIN: u64 = 100000000; // 1 Zeicoin = 100,000,000 zei
pub const ZEI_CENT: u64 = 1000000; // 1 cent = 1,000,000 zei

// Network constants - Bootstrap nodes for peer discovery
pub const BOOTSTRAP_NODES = [_][]const u8{
    "134.199.168.129:10801", // Primary bootstrap node
    "192.168.1.122:10801", // Secondary bootstrap node
    "127.0.0.1:10801", // Local fallback
};

// Network ports - ZeiCoin zen networking
pub const NETWORK_PORTS = struct {
    pub const P2P: u16 = 10801; // Peer-to-peer network
    pub const CLIENT_API: u16 = 10802; // Client API
    pub const DISCOVERY: u16 = 10800; // UDP discovery
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
            sender: Address,
            recipient: Address,
            amount: u64,
            fee: u64, // 💰 Include fee in transaction hash
            nonce: u64,
            timestamp: u64,
            sender_public_key: [32]u8,
        }{
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
        writer.writeAll(&tx_for_hash.sender) catch unreachable;
        writer.writeAll(&tx_for_hash.recipient) catch unreachable;
        writer.writeInt(u64, tx_for_hash.amount, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.nonce, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.timestamp, .little) catch unreachable;
        writer.writeAll(&tx_for_hash.sender_public_key) catch unreachable;

        const data = stream.getWritten();
        return util.hash256(data);
    }

    /// Check if transaction has valid basic structure
    pub fn isValid(self: *const Transaction) bool {
        // Basic validation rules
        if (self.amount == 0 or self.timestamp == 0) return false;
        if (std.mem.eql(u8, &self.sender, &self.recipient)) return false; // Can't send to self

        // Verify that sender address matches the hash of provided public key
        const derived_address = util.hash256(&self.sender_public_key);
        if (!std.mem.eql(u8, &self.sender, &derived_address)) return false;

        return true;
    }
};

/// Account state in ZeiCoin network
pub const Account = struct {
    address: Address,
    balance: u64, // Current balance in zei
    nonce: u64, // Next expected transaction nonce

    /// Check if account can afford a transaction
    pub fn canAfford(self: *const Account, amount: u64) bool {
        return self.balance >= amount;
    }

    /// Get expected nonce for next transaction
    pub fn nextNonce(self: *const Account) u64 {
        return self.nonce;
    }
};

/// Block header containing essential block information
pub const BlockHeader = struct {
    previous_hash: BlockHash,
    merkle_root: Hash, // Root of transaction merkle tree
    timestamp: u64, // Unix timestamp when block was created
    difficulty: u32, // Proof-of-work difficulty target
    nonce: u32, // Proof-of-work nonce

    /// Serialize block header to bytes
    pub fn serialize(self: *const BlockHeader, writer: anytype) !void {
        try writer.writeAll(&self.previous_hash);
        try writer.writeAll(&self.merkle_root);
        try writer.writeInt(u64, self.timestamp, .little);
        try writer.writeInt(u32, self.difficulty, .little);
        try writer.writeInt(u32, self.nonce, .little);
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

    /// Check if block structure is valid
    pub fn isValid(self: *const Block) bool {
        // Basic validation
        if (self.transactions.len == 0) return false;

        // All transactions must be valid
        for (self.transactions) |tx| {
            if (!tx.isValid()) return false;
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
    difficulty_bytes: u8,
    randomx_mode: bool, // false = light (256MB), true = fast (2GB)
    target_block_time: u64, // seconds
    max_nonce: u32,
    block_reward: u64,
    min_fee: u64,

    pub fn current() NetworkConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => NetworkConfig{
                .difficulty_bytes = 1, // 1 byte = fast mining for development
                .randomx_mode = false, // Light mode (256MB RAM)
                .target_block_time = 10, // 10 seconds
                .max_nonce = 1_000_000, // Reasonable limit for testing
                .block_reward = 1 * ZEI_COIN, // 1 ZEI per block
                .min_fee = 1000, // 0.00001 ZEI minimum fee
            },
            .mainnet => NetworkConfig{
                .difficulty_bytes = 2, // 2 bytes = secure mining for production
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
        std.debug.print("🌐 Network: {s}\n", .{networkName()});
        std.debug.print("⚡ Difficulty: {} bytes\n", .{config.difficulty_bytes});
        std.debug.print("🧠 RandomX Mode: {s}\n", .{if (config.randomx_mode) "Fast (2GB)" else "Light (256MB)"});
        std.debug.print("⏰ Block Time: {}s\n", .{config.target_block_time});
        std.debug.print("💰 Block Reward: {d:.8} ZEI\n", .{@as(f64, @floatFromInt(config.block_reward)) / @as(f64, @floatFromInt(ZEI_COIN))});
        std.debug.print("💸 Min Fee: {d:.8} ZEI\n", .{@as(f64, @floatFromInt(config.min_fee)) / @as(f64, @floatFromInt(ZEI_COIN))});
    }
};

/// Zeicoin mining configuration - network-aware
pub const ZenMining = struct {
    pub const BLOCK_REWARD: u64 = NetworkConfig.current().block_reward;
    pub const INITIAL_DIFFICULTY: u32 = 0x0FFFFFFF; // Easy difficulty (not used with RandomX)
    pub const TARGET_BLOCK_TIME: u64 = NetworkConfig.current().target_block_time;
    pub const MAX_NONCE: u32 = NetworkConfig.current().max_nonce;
    pub const DIFFICULTY_BYTES: u8 = NetworkConfig.current().difficulty_bytes;
    pub const RANDOMX_MODE: bool = NetworkConfig.current().randomx_mode;
};

/// 💰 Zeicoin transaction fee configuration - network-aware economic incentives
pub const ZenFees = struct {
    pub const MIN_FEE: u64 = NetworkConfig.current().min_fee;
    pub const STANDARD_FEE: u64 = NetworkConfig.current().min_fee * 5; // 5x minimum
    pub const PRIORITY_FEE: u64 = NetworkConfig.current().min_fee * 10; // 10x minimum
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
            .difficulty = 0x1d00ffff,
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
    const header1 = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .difficulty = 0x1d00ffff,
        .nonce = 42,
    };

    // Create identical header
    const header2 = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .difficulty = 0x1d00ffff,
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
    const base_header = BlockHeader{
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = std.mem.zeroes(Hash),
        .timestamp = 1704067200,
        .difficulty = 0x1d00ffff,
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
    header_diff1.difficulty = 0x1d00ffff;
    var header_diff2 = base_header;
    header_diff2.difficulty = 0x1e00ffff;

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
            .difficulty = 0x1d00ffff,
            .nonce = 12345,
        },
        .transactions = &transactions,
    };

    // Block hash should equal header hash
    const block_hash = block.hash();
    const header_hash = block.header.hash();
    try testing.expectEqualSlices(u8, &block_hash, &header_hash);
}
