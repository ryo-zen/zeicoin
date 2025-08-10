// validator.zig - Chain Validator
// Handles all blockchain validation logic and consensus rules
// Validates blocks, transactions, and enforces protocol rules

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const key = @import("../crypto/key.zig");
const genesis = @import("genesis.zig");
const miner_mod = @import("../miner/miner.zig");
const ChainState = @import("state.zig").ChainState;

const print = std.debug.print;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Address = types.Address;
const Hash = types.Hash;

/// ChainValidator enforces all consensus rules and validation logic
/// - Block validation (structure, proof-of-work, timestamps)
/// - Transaction validation (signatures, amounts, nonces)
/// - Consensus rule enforcement
/// - Protocol compliance checks
pub const ChainValidator = struct {
    chain_state: *ChainState,
    allocator: std.mem.Allocator,
    // Additional dependencies for comprehensive validation
    fork_manager: ?*@import("../fork/manager.zig").ForkManager,

    const Self = @This();

    /// Initialize ChainValidator with reference to ChainState
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState) Self {
        return .{
            .chain_state = chain_state,
            .allocator = allocator,
            .fork_manager = null,
        };
    }

    /// Initialize ChainValidator with all dependencies
    pub fn initWithDependencies(
        allocator: std.mem.Allocator,
        chain_state: *ChainState,
        fork_manager: ?*@import("../fork/manager.zig").ForkManager,
    ) Self {
        return .{
            .chain_state = chain_state,
            .allocator = allocator,
            .fork_manager = fork_manager,
        };
    }

    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No cleanup needed currently
    }

    // Validation Methods (to be extracted from node.zig)
    // - validateBlock()
    // - validateSyncBlock()
    // - validateReorgBlock()
    // - validateTransaction()
    // - validateTransactionSignature()

    // Validation Methods extracted from node.zig

    /// Validate a regular transaction (balance, nonce, signature, etc.)
    pub fn validateTransaction(self: *Self, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // 1. Check if transaction has expired
        const current_height = self.chain_state.getHeight() catch 0;
        if (tx.expiry_height <= current_height) {
            print("❌ Transaction expired: expiry height {} <= current height {}\n", .{ tx.expiry_height, current_height });
            return false;
        }

        // 2. Prevent self-transfer (wasteful but not harmful)
        if (tx.sender.equals(tx.recipient)) {
            print("⚠️ Self-transfer detected (wasteful but allowed)\n", .{});
        }

        // 3. Check for zero amount (should pay fee only)
        if (tx.amount == 0) {
            print("💸 Zero amount transaction (fee-only payment)\n", .{});
        }

        // 4. Sanity check for extremely high amounts (overflow protection)
        if (tx.amount > 1000000 * types.ZEI_COIN) { // 1 million ZEI limit
            print("❌ Transaction amount too high: {} ZEI (max: 1,000,000 ZEI)\n", .{tx.amount / types.ZEI_COIN});
            return false;
        }

        // Get sender account
        const sender_account = try self.chain_state.getAccount(tx.sender);

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
            const balance_display = util.formatZEI(self.allocator, sender_account.balance) catch "? ZEI";
            defer if (!std.mem.eql(u8, balance_display, "? ZEI")) self.allocator.free(balance_display);
            const total_display = util.formatZEI(self.allocator, total_cost) catch "? ZEI";
            defer if (!std.mem.eql(u8, total_display, "? ZEI")) self.allocator.free(total_display);

            print("❌ Insufficient balance: has {s}, needs {s}\n", .{ balance_display, total_display });
            return false;
        }

        // Verify transaction signature
        return self.validateTransactionSignature(tx);
    }

    /// Validate transaction signature only
    pub fn validateTransactionSignature(self: *Self, tx: Transaction) !bool {
        _ = self;

        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            return false;
        }
        return true;
    }

    /// Validate transaction signature with detailed logging (used during sync)
    fn validateTransactionSignatureDetailed(self: *Self, tx: Transaction) !bool {
        _ = self; // Unused parameter

        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        // print("     🔍 Transaction hash for signing: {s}\n", .{std.fmt.fmtSliceHexLower(&tx_hash)});
        // print("     🔍 Sender public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
        // print("     🔍 Transaction signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});

        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            print("❌ Signature verification failed - detailed info above\n", .{});
            return false;
        }
        print("     ✅ Signature verification passed\n", .{});

        return true;
    }

    /// Validate a complete block (structure, PoW, transactions)
    /// Full validation from node.zig with all consensus rules
    pub fn validateBlock(self: *Self, block: Block, expected_height: u32) !bool {
        // CRITICAL: Check for duplicate block hash before any other validation
        const block_hash = block.hash();
        if (self.chain_state.hasBlock(block_hash)) {
            const existing_height = self.chain_state.block_index.getHeight(block_hash) orelse unreachable;
            print("❌ [CONSENSUS] Block validation failed: duplicate block hash {s} already exists at height {}\n", .{ std.fmt.fmtSliceHexLower(block_hash[0..8]), existing_height });
            return false;
        }

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
        const current_height = try self.chain_state.getHeight();
        // Allow either current height (reprocessing) or next height (normal progression)
        if (expected_height != current_height and expected_height != current_height + 1) {
            print("❌ Block validation failed: height mismatch (expected: {}, current: {})\n", .{ expected_height, current_height });
            print("💡 Block height must be current ({}) or next ({})\n", .{ current_height, current_height + 1 });
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

                // CRITICAL: Check if this is actually a duplicate of a different block
                // This catches the case where the same block is submitted at multiple heights
                const submitted_hash = block.hash();
                if (self.chain_state.hasBlock(submitted_hash)) {
                    const existing_height = self.chain_state.block_index.getHeight(submitted_hash) orelse unreachable;
                    print("❌ [CHAIN CONTINUITY] This block is a duplicate of block at height {}!\n", .{existing_height});
                    print("   Block hash: {s}\n", .{std.fmt.fmtSliceHexLower(submitted_hash[0..8])});
                }

                return false;
            }
        }

        // SECURITY: Calculate required difficulty
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            print("❌ Failed to calculate required difficulty\n", .{});
            return false;
        };

        // SECURITY: Verify block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            print("❌ SECURITY: Block difficulty mismatch! Required: {}, Claimed: {}\n", .{ required_difficulty.toU64(), claimed_difficulty.toU64() });
            return false;
        }

        // Always use RandomX validation for consistent security
        const mining_context = miner_mod.MiningContext{
            .allocator = self.allocator,
            .database = self.chain_state.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = null,
            .fork_manager = self.fork_manager orelse undefined,
            .blockchain = undefined, // Not needed for validation
        };
        if (!try miner_mod.validateBlockPoW(mining_context, block)) {
            print("❌ RandomX proof-of-work validation failed\n", .{});
            return false;
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

    /// Validate a block during synchronization (more lenient)
    /// Full sync validation from node.zig with detailed logging
    pub fn validateSyncBlock(self: *Self, block: *const Block, expected_height: u32) !bool {
        print("🔍 validateSyncBlock: Starting validation for height {}\n", .{expected_height});

        // CRITICAL: Check for duplicate block hash even during sync
        const block_hash = block.hash();
        if (self.chain_state.hasBlock(block_hash)) {
            const existing_height = self.chain_state.block_index.getHeight(block_hash) orelse unreachable;
            print("❌ [SYNC] Block validation failed: duplicate block hash {s} already exists at height {}\n", .{ std.fmt.fmtSliceHexLower(block_hash[0..8]), existing_height });
            return false;
        }

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            print("🔍 validateSyncBlock: Processing genesis block (height 0)\n", .{});

            // Detailed genesis validation debugging
            print("🔍 Genesis validation details:\n", .{});
            print("   Block timestamp: {}\n", .{block.header.timestamp});
            print("   Expected genesis timestamp: {}\n", .{types.Genesis.timestamp()});
            // print("   Block previous_hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
            print("   Block difficulty: {}\n", .{block.header.difficulty});
            print("   Block nonce: 0x{X}\n", .{block.header.nonce});
            print("   Block transaction count: {}\n", .{block.txCount()});

            _ = block.hash(); // Block hash calculated but not used in release mode
            // print("   Block hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block_hash)});
            // print("   Expected genesis hash: {s}\n", .{std.fmt.fmtSliceHexLower(&genesis.getCanonicalGenesisHash())});

            if (!genesis.validateGenesis(block.*)) {
                print("❌ Genesis block validation failed: not canonical genesis\n", .{});
                print("❌ Genesis validation failed - detailed comparison above\n", .{});
                return false;
            }
            print("✅ Genesis block validation passed\n", .{});
            return true; // Genesis block passed validation
        }

        print("🔍 validateSyncBlock: About to check basic block structure for height {}\n", .{expected_height});
        print("🔍 validateSyncBlock: Block pointer address: {*}\n", .{&block});

        // Try to access block fields safely first
        print("🔍 validateSyncBlock: Checking block field access...\n", .{});

        // Check if we can access basic fields
        const tx_count = block.txCount();
        print("🔍 validateSyncBlock: Block transaction count: {}\n", .{tx_count});

        const timestamp = block.header.timestamp;
        print("🔍 validateSyncBlock: Block timestamp: {}\n", .{timestamp});

        const difficulty = block.header.difficulty;
        print("🔍 validateSyncBlock: Block difficulty: {}\n", .{difficulty});

        print("🔍 validateSyncBlock: Basic field access successful, now calling isValid()...\n", .{});

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Block validation failed: invalid block structure at height {}\n", .{expected_height});
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

        // SECURITY: Calculate required difficulty for sync blocks
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            print("❌ Failed to calculate required difficulty for sync block\n", .{});
            return false;
        };

        // SECURITY: Verify sync block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            print("❌ SECURITY: Sync block difficulty mismatch! Required: {}, Claimed: {}\n", .{ required_difficulty.toU64(), claimed_difficulty.toU64() });
            return false;
        }

        // Always use RandomX validation for consistent security
        const mining_context = miner_mod.MiningContext{
            .allocator = self.allocator,
            .database = self.chain_state.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = null,
            .fork_manager = self.fork_manager orelse undefined,
            .blockchain = undefined, // Not needed for validation
        };
        if (!try miner_mod.validateBlockPoW(mining_context, block.*)) {
            print("❌ RandomX proof-of-work validation failed for height {}\n", .{expected_height});
            return false;
        }
        print("✅ Proof-of-work validation passed for height {}\n", .{expected_height});

        print("🔍 validateSyncBlock: Checking previous hash links for height {}\n", .{expected_height});

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.chain_state.getHeight();
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
                // print("   Previous block hash in chain: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                // print("   Block's previous_hash field: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    print("❌ Previous hash validation failed during sync\n", .{});
                    // print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    // print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
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
                _ = tx.sender.toBytes(); // Sender bytes calculated but not used in release mode
                _ = tx.recipient.toBytes(); // Recipient bytes calculated but not used in release mode
                // print("   Sender: {s}\n", .{std.fmt.fmtSliceHexLower(&sender_bytes)});
                // print("   Recipient: {s}\n", .{std.fmt.fmtSliceHexLower(&recipient_bytes)});
                print("   Amount: {}\n", .{tx.amount});
                print("   Fee: {}\n", .{tx.fee});
                print("   Nonce: {}\n", .{tx.nonce});
                print("   Timestamp: {}\n", .{tx.timestamp});
                return false;
            }
            print("   ✅ Transaction {} structure validation passed\n", .{i});

            print("   🔍 Checking transaction signature...\n", .{});

            // Signature validation (but no balance check)
            if (!try self.validateTransactionSignatureDetailed(tx)) {
                print("❌ Transaction {} signature validation failed\n", .{i});
                // print("   Public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
                // print("   Signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});
                return false;
            }
            print("   ✅ Transaction {} signature validation passed\n", .{i});
        }

        print("✅ Sync block {} structure and signatures validated\n", .{expected_height});
        return true;
    }

    /// Validate a block during reorganization (skip chain linkage)
    pub fn validateReorgBlock(self: *Self, block: Block, expected_height: u32) !bool {
        // Special validation for genesis block
        if (expected_height == 0) {
            if (!genesis.GenesisBlocks.TESTNET.getBlock().equals(&block)) {
                print("❌ Reorg genesis block validation failed\n", .{});
                return false;
            }
            return true;
        }

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Reorg block structure validation failed\n", .{});
            return false;
        }

        // Lenient timestamp validation during reorganization
        const current_time = util.getTime();
        const reorg_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2;
        if (@as(i64, @intCast(block.header.timestamp)) > current_time + reorg_future_allowance) {
            print("❌ Reorg block timestamp too far in future\n", .{});
            return false;
        }

        // SECURITY: Calculate required difficulty for reorg blocks - DO NOT trust block header!
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            print("❌ Failed to calculate required difficulty for reorg block\n", .{});
            return false;
        };

        // SECURITY: Verify reorg block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            print("❌ SECURITY: Reorg block difficulty mismatch! Required: {}, Claimed: {}\n", .{ required_difficulty.toU64(), claimed_difficulty.toU64() });
            return false;
        }

        // Always use RandomX validation for consistent security
        if (!try self.validateBlockPoW(block)) {
            print("❌ Reorg block RandomX validation failed\n", .{});
            return false;
        }

        // Validate transaction structure and signatures only
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction
            if (i == 0) continue;

            if (!tx.isValid()) {
                print("❌ Reorg transaction {} structure validation failed\n", .{i});
                return false;
            }

            if (!try self.validateTransactionSignature(tx)) {
                print("❌ Reorg transaction {} signature validation failed\n", .{i});
                return false;
            }
        }

        return true;
    }

    /// Validate block proof-of-work (delegates to miner module)
    fn validateBlockPoW(self: *Self, block: Block) !bool {
        const mining_context = miner_mod.MiningContext{
            .allocator = self.allocator,
            .database = self.chain_state.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = null, // Not needed for validation
            .fork_manager = undefined, // Not needed for validation
            .blockchain = undefined, // Not needed for validation
        };
        return miner_mod.validateBlockPoW(mining_context, block);
    }

    /// Get block by height (delegates to ChainState database)
    fn getBlockByHeight(self: *Self, height: u32) !types.Block {
        return self.chain_state.database.getBlock(height);
    }

    /// Calculate median time past for timestamp validation
    fn getMedianTimePast(self: *Self, height: u32) !u64 {
        const num_blocks = @min(height + 1, 11); // Use up to 11 blocks for median
        var timestamps = std.ArrayList(u64).init(self.allocator);
        defer timestamps.deinit();

        // Collect timestamps from recent blocks
        var i: u32 = 0;
        while (i < num_blocks) : (i += 1) {
            const block_height = height - i;
            var block = try self.getBlockByHeight(block_height);
            defer block.deinit(self.allocator);
            try timestamps.append(block.header.timestamp);
        }

        // Sort timestamps
        std.sort.heap(u64, timestamps.items, {}, comptime std.sort.asc(u64));

        // Return median (middle value for odd count)
        const median_index = timestamps.items.len / 2;
        return timestamps.items[median_index];
    }
};
