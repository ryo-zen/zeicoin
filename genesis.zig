// genesis.zig - ZeiCoin Genesis Block Definitions
// Hardcoded genesis blocks for network security and consistency

const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");

/// Network-specific genesis block configurations
/// These are the canonical genesis blocks that define each ZeiCoin network
pub const GenesisBlocks = struct {
    /// TestNet Genesis Block (for development and testing)
    /// Created: 2024-01-01 00:00:00 UTC
    /// Purpose: Development, testing, and experimentation
    pub const TESTNET = struct {
        pub const HASH: [32]u8 = [_]u8{ 0xaf, 0x5c, 0x07, 0x3a, 0x98, 0xaf, 0x00, 0xbf, 0x7e, 0x9a, 0xbb, 0xbb, 0x99, 0xff, 0xe5, 0x6f, 0x15, 0x52, 0xdc, 0xe1, 0x3d, 0xda, 0x3c, 0x09, 0xf5, 0x5e, 0x2a, 0xb3, 0xa5, 0x80, 0xcb, 0x08 };

        pub const MESSAGE = "ZeiCoin TestNet Genesis - A minimal digital currency written in ⚡Zig";
        pub const TIMESTAMP: u64 = 1704067200; // 2024-01-01 00:00:00 UTC
        pub const NONCE: u64 = 0x7E57DE7;
        pub const MINER_REWARD: u64 = 50 * types.ZEI_COIN; // 50 ZEI initial distribution

        /// Get the hardcoded TestNet genesis block
        pub fn getBlock() types.Block {
            // Create genesis public key from network identifier
            const genesis_public_key = createGenesisPublicKey("TESTNET_GENESIS");
            const genesis_address = util.hash256(&genesis_public_key);

            // Create coinbase transaction for initial distribution
            const coinbase_tx = types.Transaction{
                .version = 0, // Version 0 for genesis
                .sender = std.mem.zeroes(types.Address), // From thin air
                .sender_public_key = std.mem.zeroes([32]u8),
                .recipient = genesis_address,
                .amount = MINER_REWARD,
                .fee = 0,
                .nonce = 0,
                .timestamp = TIMESTAMP,
                .expiry_height = std.math.maxInt(u64), // Genesis tx never expires
                .signature = std.mem.zeroes(types.Signature),
            };

            // Create genesis block header
            const header = types.BlockHeader{
                .version = 0, // Version 0 for genesis
                .previous_hash = std.mem.zeroes([32]u8), // No previous block
                .merkle_root = coinbase_tx.hash(),
                .timestamp = TIMESTAMP,
                .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
                .nonce = @truncate(NONCE),
            };

            // Allocate transactions array (must be freed by caller)
            // Note: This is a limitation - we can't return owned memory from a pure function
            // The caller must handle memory management
            // Create a static slice for the transaction
            const static_transactions = [_]types.Transaction{coinbase_tx};
            return types.Block{
                .header = header,
                .transactions = @constCast(&static_transactions),
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
        pub fn getBlock() types.Block {
            // Create genesis public key from network identifier
            const genesis_public_key = createGenesisPublicKey("MAINNET_GENESIS");
            const genesis_address = util.hash256(&genesis_public_key);

            // Create coinbase transaction for initial distribution
            const coinbase_tx = types.Transaction{
                .version = 0, // Version 0 for genesis
                .sender = std.mem.zeroes(types.Address),
                .sender_public_key = std.mem.zeroes([32]u8),
                .recipient = genesis_address,
                .amount = MINER_REWARD,
                .fee = 0,
                .nonce = 0,
                .timestamp = TIMESTAMP,
                .expiry_height = std.math.maxInt(u64), // Genesis tx never expires
                .signature = std.mem.zeroes(types.Signature),
            };

            // Create genesis block header
            const header = types.BlockHeader{
                .version = 0, // Version 0 for genesis
                .previous_hash = std.mem.zeroes([32]u8),
                .merkle_root = coinbase_tx.hash(),
                .timestamp = TIMESTAMP,
                .difficulty = types.ZenMining.initialDifficultyTarget().toU64(),
                .nonce = @truncate(NONCE),
            };

            // Create a static slice for the transaction
            const static_transactions = [_]types.Transaction{coinbase_tx};
            return types.Block{
                .header = header,
                .transactions = @constCast(&static_transactions),
            };
        }
    };
};

/// Create deterministic public key from network seed
fn createGenesisPublicKey(seed: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(seed);
    hasher.update("_ZEICOIN_GENESIS_KEY");
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
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
        std.debug.print("❌ Genesis validation failed: hash mismatch\n", .{});
        std.debug.print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&canonical_hash)});
        std.debug.print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block_hash)});
        return false;
    }

    return true;
}

/// Create genesis block with proper memory management
pub fn createGenesis(allocator: std.mem.Allocator) !types.Block {
    const canonical = getCanonicalGenesis();

    // Allocate memory for transactions
    const transactions = try allocator.alloc(types.Transaction, canonical.transactions.len);
    @memcpy(transactions, canonical.transactions);

    return types.Block{
        .header = canonical.header,
        .transactions = transactions,
    };
}

// Tests
test "Genesis block validation" {
    const testnet_genesis = GenesisBlocks.TESTNET.getBlock();
    const mainnet_genesis = GenesisBlocks.MAINNET.getBlock();

    // Test transactions exist
    try std.testing.expect(testnet_genesis.transactions.len > 0);
    try std.testing.expect(mainnet_genesis.transactions.len > 0);

    // Test different networks have different hashes
    try std.testing.expect(!std.mem.eql(u8, &GenesisBlocks.TESTNET.HASH, &GenesisBlocks.MAINNET.HASH));

    std.debug.print("\n✅ Genesis block validation tests passed\n", .{});
}
