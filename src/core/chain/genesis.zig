// genesis.zig - ZeiCoin Genesis Block Definitions
// Hardcoded genesis blocks for network security and consistency

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");

/// Network-specific genesis block configurations
/// These are the canonical genesis blocks that define each ZeiCoin network
pub const GenesisBlocks = struct {
    /// TestNet Genesis Block (for development and testing)
    /// Created: 2024-01-01 00:00:00 UTC
    /// Purpose: Development, testing, and experimentation
    pub const TESTNET = struct {
        pub const HASH: [32]u8 = [_]u8{ 0x36, 0x60, 0xde, 0x42, 0x29, 0xdc, 0xa4, 0xd5, 0xcd, 0x3c, 0xe3, 0xa2, 0x60, 0x38, 0x77, 0xf3, 0xc9, 0xe6, 0xb5, 0xea, 0xef, 0x7d, 0x7f, 0x3e, 0xe1, 0x8e, 0x35, 0x3c, 0x22, 0x8c, 0x41, 0x9e };

        pub const MESSAGE = "ZeiCoin TestNet Genesis - A minimal digital currency written in ⚡Zig";
        pub const TIMESTAMP: u64 = 1757419151; // 2025-09-09 (current date)
        pub const NONCE: u64 = 0x7E57DE7;
        pub const MINER_REWARD: u64 = 50 * types.ZEI_COIN; // 50 ZEI initial distribution

        /// Get the hardcoded TestNet genesis block
        /// Returns a block with a static empty transactions slice.
        /// The caller should use createGenesis() for a properly allocated block.
        pub fn getBlock() types.Block {
            // Create genesis block header with proper merkle root
            const header = types.BlockHeader{
                .version = types.CURRENT_BLOCK_VERSION,
                .previous_hash = std.mem.zeroes([32]u8), // No previous block
                .merkle_root = [_]u8{ 0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b, 0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a, 0xfd, 0xed, 0xa3, 0x3b }, // Pre-calculated merkle root
                .timestamp = TIMESTAMP,
                .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
                .nonce = @truncate(NONCE),
                .witness_root = std.mem.zeroes([32]u8), // No witness data yet
                .state_root = std.mem.zeroes([32]u8), // No state yet
                .extra_nonce = 0,
                .extra_data = std.mem.zeroes([32]u8), // No extra data
            };

            // Return block with empty transactions - caller must use createGenesis() for actual block
            return types.Block{
                .header = header,
                .transactions = &[_]types.Transaction{}, // Empty static slice
            };
        }
    };

    /// MainNet Genesis Block (for production use)
    /// Created: TBD (will be set when mainnet launches)
    /// Purpose: Production ZeiCoin network
    pub const MAINNET = struct {
        pub const HASH: [32]u8 = [_]u8{ 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f };

        pub const MESSAGE = "ZeiCoin MainNet Launch - [INSERT_LAUNCH_HEADLINE]";
        pub const TIMESTAMP: u64 = 0; // TBD - will be set to exact launch time
        pub const NONCE: u64 = 0x3A1F1E7;
        pub const MINER_REWARD: u64 = 21 * types.ZEI_COIN; // 21 ZEI initial distribution

        /// Get the hardcoded MainNet genesis block
        /// Returns a block with a static empty transactions slice.
        /// The caller should use createGenesis() for a properly allocated block.
        pub fn getBlock() types.Block {
            // Create genesis block header with proper merkle root
            const header = types.BlockHeader{
                .version = types.CURRENT_BLOCK_VERSION,
                .previous_hash = std.mem.zeroes([32]u8),
                .merkle_root = [_]u8{ 0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b, 0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a, 0xfd, 0xed, 0xa3, 0x3b }, // Pre-calculated merkle root
                .timestamp = TIMESTAMP,
                .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
                .nonce = @truncate(NONCE),
                .witness_root = std.mem.zeroes([32]u8),
                .state_root = std.mem.zeroes([32]u8),
                .extra_nonce = 0,
                .extra_data = std.mem.zeroes([32]u8),
            };

            // Return block with empty transactions - caller must use createGenesis() for actual block
            return types.Block{
                .header = header,
                .transactions = &[_]types.Transaction{}, // Empty static slice
            };
        }
    };
};

/// Create deterministic public key from network seed
pub fn createGenesisPublicKey(seed: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(seed);
    hasher.update("_ZEICOIN_GENESIS_KEY");
    var seed_bytes: [32]u8 = undefined;
    hasher.final(&seed_bytes);

    // Create proper Ed25519 keypair from seed
    const Ed25519 = std.crypto.sign.Ed25519;
    const keypair = Ed25519.KeyPair.generateDeterministic(seed_bytes) catch unreachable;

    return keypair.public_key.bytes;
}

/// Get the canonical genesis block for the current network
pub fn getCanonicalGenesis() types.Block {
    return switch (types.CURRENT_NETWORK) {
        .testnet => GenesisBlocks.TESTNET.getBlock(),
        .mainnet => GenesisBlocks.MAINNET.getBlock(),
    };
}

/// Get the canonical genesis hash for the current network
pub fn getCanonicalGenesisHash() [32]u8 {
    return switch (types.CURRENT_NETWORK) {
        .testnet => GenesisBlocks.TESTNET.HASH,
        .mainnet => GenesisBlocks.MAINNET.HASH,
    };
}

/// Validate that a block is the correct genesis block for this network
pub fn validateGenesis(block: types.Block) bool {
    const canonical_hash = getCanonicalGenesisHash();
    const block_hash = block.hash();

    // Must match canonical genesis hash
    if (!std.mem.eql(u8, &block_hash, &canonical_hash)) {
        const log = std.log.scoped(.chain);
        log.info("❌ Genesis validation failed: hash mismatch", .{});
        log.info("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&canonical_hash)});
        log.info("   Received: {s}", .{std.fmt.fmtSliceHexLower(&block_hash)});
        return false;
    }

    return true;
}

/// TestNet pre-funded accounts for testing (HD Wallet addresses)
pub const TESTNET_DISTRIBUTION = [_]struct {
    name: []const u8,
    address_hex: []const u8, // Bech32 address from HD wallet
    amount: u64,
}{
    .{ .name = "alice", .address_hex = "tzei1qzhrhfgcdpz4gldle6zlk0q8kcd2elhfwumf0ejs", .amount = 1000 * types.ZEI_COIN },
    .{ .name = "bob", .address_hex = "tzei1qpgmfkzc4mu9xtljtyvpnrcesjnq7wv4f5ley9hu", .amount = 1000 * types.ZEI_COIN },
    .{ .name = "charlie", .address_hex = "tzei1qz5rc4ru98ht33uu2w03rc57n32gekzmycd692tz", .amount = 1000 * types.ZEI_COIN },
    .{ .name = "david", .address_hex = "tzei1qpc7xkcg52w7txsce6ad8scnyg2v54z9ec0hhcdv", .amount = 1000 * types.ZEI_COIN },
    .{ .name = "eve", .address_hex = "tzei1qpdg0wzte5966248hcekh298sz526pzjw5r8wxlf", .amount = 1000 * types.ZEI_COIN },
};

/// Get deterministic address for a test account
pub fn getTestAccountAddress(name: []const u8) ?types.Address {
    for (TESTNET_DISTRIBUTION) |account| {
        if (std.mem.eql(u8, account.name, name)) {
            // Parse the bech32 address
            return types.Address.fromString(std.heap.page_allocator, account.address_hex) catch null;
        }
    }
    return null;
}

/// Create genesis block with proper memory management
pub fn createGenesis(allocator: std.mem.Allocator) !types.Block {
    const canonical = getCanonicalGenesis();

    // Determine which network we're on
    const network_seed = switch (types.CURRENT_NETWORK) {
        .testnet => "TESTNET_GENESIS",
        .mainnet => "MAINNET_GENESIS",
    };

    const miner_reward = switch (types.CURRENT_NETWORK) {
        .testnet => GenesisBlocks.TESTNET.MINER_REWARD,
        .mainnet => GenesisBlocks.MAINNET.MINER_REWARD,
    };

    const timestamp = switch (types.CURRENT_NETWORK) {
        .testnet => GenesisBlocks.TESTNET.TIMESTAMP,
        .mainnet => GenesisBlocks.MAINNET.TIMESTAMP,
    };

    // Create genesis public key from network identifier
    const genesis_public_key = createGenesisPublicKey(network_seed);
    const genesis_address = types.Address.fromPublicKey(genesis_public_key);

    // Calculate number of transactions
    const tx_count = switch (types.CURRENT_NETWORK) {
        .testnet => 1 + TESTNET_DISTRIBUTION.len, // Coinbase + distributions
        .mainnet => 1, // Just coinbase for now
    };

    // Allocate memory for transactions array
    const transactions = try allocator.alloc(types.Transaction, tx_count);

    // Create coinbase transaction
    transactions[0] = types.Transaction{
        .version = 0,
        .flags = .{},
        .sender = types.Address.zero(),
        .sender_public_key = std.mem.zeroes([32]u8),
        .recipient = genesis_address,
        .amount = miner_reward,
        .fee = 0,
        .nonce = 0,
        .timestamp = timestamp,
        .expiry_height = std.math.maxInt(u64),
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Add TestNet distribution transactions
    if (types.CURRENT_NETWORK == .testnet) {
        for (TESTNET_DISTRIBUTION, 0..) |account, i| {
            // Parse the bech32 address from the account
            const account_address = types.Address.fromString(std.heap.page_allocator, account.address_hex) catch unreachable;

            transactions[i + 1] = types.Transaction{
                .version = 0,
                .flags = .{},
                .sender = types.Address.zero(),
                .sender_public_key = std.mem.zeroes([32]u8),
                .recipient = account_address,
                .amount = account.amount,
                .fee = 0,
                .nonce = 0,
                .timestamp = timestamp,
                .expiry_height = std.math.maxInt(u64),
                .signature = std.mem.zeroes(types.Signature),
                .script_version = 0,
                .witness_data = &[_]u8{},
                .extra_data = &[_]u8{},
            };
        }
    }

    return types.Block{
        .header = canonical.header,
        .transactions = transactions,
    };
}

// Tests
test "Genesis block validation" {
    const testnet_genesis = GenesisBlocks.TESTNET.getBlock();
    const mainnet_genesis = GenesisBlocks.MAINNET.getBlock();

    // Test block headers are valid
    try std.testing.expect(testnet_genesis.header.version == types.CURRENT_BLOCK_VERSION);
    try std.testing.expect(mainnet_genesis.header.version == types.CURRENT_BLOCK_VERSION);

    // Test different networks have different hashes
    try std.testing.expect(!std.mem.eql(u8, &GenesisBlocks.TESTNET.HASH, &GenesisBlocks.MAINNET.HASH));

    // Test createGenesis works properly
    const allocator = std.testing.allocator;
    var created_genesis = try createGenesis(allocator);
    defer created_genesis.deinit(allocator);

    // TestNet should have 6 transactions (1 coinbase + 5 distributions)
    const expected_tx_count = if (types.CURRENT_NETWORK == .testnet) 6 else 1;
    try std.testing.expect(created_genesis.transactions.len == expected_tx_count);

    // All transactions should be coinbase (genesis funding)
    for (created_genesis.transactions) |tx| {
        try std.testing.expect(tx.isCoinbase());
    }

    const log = std.log.scoped(.chain);
    log.info("✅ Genesis block validation tests passed", .{});
}
