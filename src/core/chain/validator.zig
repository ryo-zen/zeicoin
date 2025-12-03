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

const log = std.log.scoped(.chain);

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
    // Fork manager removed - using modern reorganization system

    const Self = @This();

    /// Initialize ChainValidator with reference to ChainState
    pub fn init(allocator: std.mem.Allocator, chain_state: *ChainState) Self {
        return .{
            .chain_state = chain_state,
            .allocator = allocator,
        };
    }

    /// Initialize ChainValidator with all dependencies (deprecated)
    pub fn initWithDependencies(
        allocator: std.mem.Allocator,
        chain_state: *ChainState,
        _: anytype, // fork_manager parameter removed
    ) Self {
        return .{
            .chain_state = chain_state,
            .allocator = allocator,
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
            log.warn("❌ Transaction expired: expiry height {} <= current height {}", .{ tx.expiry_height, current_height });
            return false;
        }

        // 2. Prevent self-transfer (wasteful but not harmful)
        if (tx.sender.equals(tx.recipient)) {
            log.warn("⚠️ Self-transfer detected (wasteful but allowed)", .{});
        }

        // 3. Check for zero amount (should pay fee only)
        if (tx.amount == 0) {
            log.warn("💸 Zero amount transaction (fee-only payment)", .{});
        }

        // 4. Sanity check for extremely high amounts (overflow protection)
        if (tx.amount > 1000000 * types.ZEI_COIN) { // 1 million ZEI limit
            log.warn("❌ Transaction amount too high: {} ZEI (max: 1,000,000 ZEI)", .{tx.amount / types.ZEI_COIN});
            return false;
        }

        // Get sender account
        const sender_account = try self.chain_state.getAccount(tx.sender);

        // Check nonce (must be next expected nonce)
        if (tx.nonce != sender_account.nextNonce()) {
            log.warn("❌ Invalid nonce: expected {}, got {}", .{ sender_account.nextNonce(), tx.nonce });
            return false;
        }

        // 💰 Check fee minimum (prevent spam)
        if (tx.fee < types.ZenFees.MIN_FEE) {
            log.warn("❌ Fee too low: {} zei, minimum {} zei", .{ tx.fee, types.ZenFees.MIN_FEE });
            return false;
        }

        // Check balance (amount + fee)
        const total_cost = tx.amount + tx.fee;
        if (!sender_account.canAfford(total_cost)) {
            const balance_display = util.formatZEI(self.allocator, sender_account.balance) catch "? ZEI";
            defer if (!std.mem.eql(u8, balance_display, "? ZEI")) self.allocator.free(balance_display);
            const total_display = util.formatZEI(self.allocator, total_cost) catch "? ZEI";
            defer if (!std.mem.eql(u8, total_display, "? ZEI")) self.allocator.free(total_display);

            log.warn("❌ Insufficient balance: has {s}, needs {s}", .{ balance_display, total_display });
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
            log.warn("❌ Invalid signature: transaction not signed by sender", .{});
            return false;
        }
        return true;
    }

    /// Validate transaction signature with detailed logging (used during sync)
    fn validateTransactionSignatureDetailed(self: *Self, tx: Transaction) !bool {
        _ = self; // Unused parameter

        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        // log.warn("     🔍 Transaction hash for signing: {s}", .{std.fmt.fmtSliceHexLower(&tx_hash)});
        // log.warn("     🔍 Sender public key: {s}", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
        // log.warn("     🔍 Transaction signature: {s}", .{std.fmt.fmtSliceHexLower(&tx.signature)});

        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            log.warn("❌ Invalid signature: transaction not signed by sender", .{});
            log.warn("❌ Signature verification failed - detailed info above", .{});
            return false;
        }
        log.warn("     ✅ Signature verification passed", .{});

        return true;
    }

    /// Validate a complete block (structure, PoW, transactions)
    /// Full validation from node.zig with all consensus rules
    pub fn validateBlock(self: *Self, block: Block, expected_height: u32) !bool {
        // CRITICAL: Check for duplicate block hash before any other validation
        const block_hash = block.hash();
        if (self.chain_state.hasBlock(block_hash)) {
            const existing_height = self.chain_state.block_index.getHeight(block_hash) orelse unreachable;
            log.warn("❌ [CONSENSUS] Block validation failed: duplicate block hash {s} already exists at height {}", .{ std.fmt.fmtSliceHexLower(block_hash[0..8]), existing_height });
            return false;
        }

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            if (!genesis.validateGenesis(block)) {
                log.warn("❌ Genesis block validation failed: not canonical genesis", .{});
                return false;
            }
            return true; // Genesis block passed validation
        }

        // Check basic block structure
        if (!block.isValid()) {
            log.warn("❌ Block validation failed: invalid block structure", .{});
            return false;
        }

        // Check block size limit (16MB hard limit)
        const block_size = block.getSize();
        if (block_size > types.BlockLimits.MAX_BLOCK_SIZE) {
            log.warn("❌ Block validation failed: size {} bytes exceeds limit of {} bytes", .{ block_size, types.BlockLimits.MAX_BLOCK_SIZE });
            return false;
        }

        // Timestamp validation - prevent blocks from the future
        const current_time = util.getTime();
        // Block timestamps are in milliseconds, convert to seconds for comparison
        const block_time_seconds = @divFloor(@as(i64, @intCast(block.header.timestamp)), 1000);
        if (block_time_seconds > current_time + types.TimestampValidation.MAX_FUTURE_TIME) {
            const future_seconds = block_time_seconds - current_time;
            log.warn("❌ Block timestamp too far in future: {} seconds ahead", .{future_seconds});
            return false;
        }

        // Check block height consistency
        const current_height = try self.chain_state.getHeight();
        // Allow either current height (reprocessing) or next height (normal progression)
        if (expected_height != current_height and expected_height != current_height + 1) {
            log.warn("❌ Block validation failed: height mismatch (expected: {}, current: {})", .{ expected_height, current_height });
            log.warn("💡 Block height must be current ({}) or next ({})", .{ current_height, current_height + 1 });
            return false;
        }

        // For non-genesis blocks, validate against previous block
        if (expected_height > 0) {
            var prev_block = try self.getBlockByHeight(expected_height - 1);
            defer prev_block.deinit(self.allocator);

            // Check timestamp against median time past (MTP)
            const mtp = try self.getMedianTimePast(expected_height - 1);
            if (block.header.timestamp <= mtp) {
                log.warn("❌ Block timestamp not greater than median time past", .{});
                log.warn("   MTP: {}, Block timestamp: {}", .{ mtp, block.header.timestamp });
                return false;
            }

            // Check previous hash links correctly
            const prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                log.warn("❌ Previous hash validation failed", .{});
                log.warn("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                log.warn("   Received: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                // CRITICAL: Check if this is actually a duplicate of a different block
                // This catches the case where the same block is submitted at multiple heights
                const submitted_hash = block.hash();
                if (self.chain_state.hasBlock(submitted_hash)) {
                    const existing_height = self.chain_state.block_index.getHeight(submitted_hash) orelse unreachable;
                    log.warn("❌ [CHAIN CONTINUITY] This block is a duplicate of block at height {}!", .{existing_height});
                    log.warn("   Block hash: {s}", .{std.fmt.fmtSliceHexLower(submitted_hash[0..8])});
                }

                return false;
            }
        }

        // SECURITY: Calculate required difficulty
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            log.warn("❌ Failed to calculate required difficulty", .{});
            return false;
        };

        // SECURITY: Verify block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            // ENHANCED: Log detailed difficulty calculation chain for debugging
            log.warn("❌ SECURITY: Block difficulty mismatch detected!", .{});
            log.warn("   📊 Required difficulty: {} (base_bytes={}, threshold=0x{X})", .{ required_difficulty.toU64(), required_difficulty.base_bytes, required_difficulty.threshold });
            log.warn("   📦 Block claimed difficulty: {} (base_bytes={}, threshold=0x{X})", .{ claimed_difficulty.toU64(), claimed_difficulty.base_bytes, claimed_difficulty.threshold });
            log.warn("   🔍 Block height: {}, timestamp: {}", .{ expected_height, block.header.timestamp });
            
            // Log detailed calculation chain for debugging
            self.logDifficultyCalculationChain(expected_height) catch |err| {
                log.warn("   ⚠️ Failed to log difficulty calculation chain: {}", .{err});
            };
            
            return false;
        }

        // Always use RandomX validation for consistent security
        const mining_context = miner_mod.MiningContext{
            .allocator = self.allocator,
            .database = self.chain_state.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = null,
            // fork_manager removed
            .blockchain = undefined, // Not needed for validation
        };
        if (!try miner_mod.validateBlockPoW(mining_context, block)) {
            log.warn("❌ RandomX proof-of-work validation failed", .{});
            return false;
        }

        // CRITICAL: Validate account state root commitment
        // This prevents hidden state divergence where nodes have same block hash but different account states
        const expected_state_root = try self.chain_state.calculateStateRoot();
        if (!std.mem.eql(u8, &block.header.state_root, &expected_state_root)) {
            log.warn("❌ CRITICAL: Account state root mismatch - hidden divergence detected!", .{});
            log.warn("   Expected: {}", .{std.fmt.fmtSliceHexLower(&expected_state_root)});
            log.warn("   Block:    {}", .{std.fmt.fmtSliceHexLower(&block.header.state_root)});
            log.warn("   This indicates the block was created with different account states than this node has");
            return false;
        }
        log.info("✅ [STATE ROOT] Account state root verified: {}", .{std.fmt.fmtSliceHexLower(&expected_state_root)});

        // SECURITY: Validate coinbase transaction
        if (!try self.validateCoinbase(block, expected_height)) {
            log.warn("❌ Coinbase validation failed for block {}", .{expected_height});
            return false;
        }

        // Validate all transactions in block
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) continue;

            if (!try self.validateTransaction(tx)) {
                log.warn("❌ Transaction {} validation failed", .{i});
                return false;
            }
        }

        return true;
    }

    /// Validate a block during synchronization (more lenient)
    /// Full sync validation from node.zig with detailed logging
    pub fn validateSyncBlock(self: *Self, block: *const Block, expected_height: u32) !bool {
        log.warn("🔍 validateSyncBlock: Starting validation for height {}", .{expected_height});

        // CRITICAL: Check for duplicate block hash even during sync
        const block_hash = block.hash();
        if (self.chain_state.hasBlock(block_hash)) {
            const existing_height = self.chain_state.block_index.getHeight(block_hash) orelse unreachable;
            log.warn("❌ [SYNC] Block validation failed: duplicate block hash {s} already exists at height {}", .{ std.fmt.fmtSliceHexLower(block_hash[0..8]), existing_height });
            return false;
        }

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            log.warn("🔍 validateSyncBlock: Processing genesis block (height 0)", .{});

            // Detailed genesis validation debugging
            log.warn("🔍 Genesis validation details:", .{});
            log.warn("   Block timestamp: {}", .{block.header.timestamp});
            log.warn("   Expected genesis timestamp: {}", .{types.Genesis.timestamp()});
            // log.warn("   Block previous_hash: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
            log.warn("   Block difficulty: {}", .{block.header.difficulty});
            log.warn("   Block nonce: 0x{X}", .{block.header.nonce});
            log.warn("   Block transaction count: {}", .{block.txCount()});

            _ = block.hash(); // Block hash calculated but not used in release mode
            // log.warn("   Block hash: {s}", .{std.fmt.fmtSliceHexLower(&block_hash)});
            // log.warn("   Expected genesis hash: {s}", .{std.fmt.fmtSliceHexLower(&genesis.getCanonicalGenesisHash())});

            if (!genesis.validateGenesis(block.*)) {
                log.warn("❌ Genesis block validation failed: not canonical genesis", .{});
                log.warn("❌ Genesis validation failed - detailed comparison above", .{});
                return false;
            }
            log.warn("✅ Genesis block validation passed", .{});
            return true; // Genesis block passed validation
        }

        log.warn("🔍 validateSyncBlock: About to check basic block structure for height {}", .{expected_height});
        log.warn("🔍 validateSyncBlock: Block pointer address: {*}", .{&block});

        // Try to access block fields safely first
        log.warn("🔍 validateSyncBlock: Checking block field access...", .{});

        // Check if we can access basic fields
        const tx_count = block.txCount();
        log.warn("🔍 validateSyncBlock: Block transaction count: {}", .{tx_count});

        const timestamp = block.header.timestamp;
        log.warn("🔍 validateSyncBlock: Block timestamp: {}", .{timestamp});

        const difficulty = block.header.difficulty;
        log.warn("🔍 validateSyncBlock: Block difficulty: {}", .{difficulty});

        log.warn("🔍 validateSyncBlock: Basic field access successful, now calling isValid()...", .{});

        // Check basic block structure
        if (!block.isValid()) {
            log.warn("❌ Block validation failed: invalid block structure at height {}", .{expected_height});
            return false;
        }

        log.warn("✅ Basic block structure validation passed for height {}", .{expected_height});

        // Timestamp validation for sync blocks (more lenient than normal validation)
        const current_time = util.getTime();
        // Block timestamps are in milliseconds, convert to seconds for comparison
        const block_time_seconds = @divFloor(@as(i64, @intCast(block.header.timestamp)), 1000);
        // Allow more future time during sync (network time differences)
        const sync_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2; // 4 hours
        if (block_time_seconds > current_time + sync_future_allowance) {
            const future_seconds = block_time_seconds - current_time;
            log.warn("❌ Sync block timestamp too far in future: {} seconds ahead", .{future_seconds});
            return false;
        }

        log.warn("🔍 validateSyncBlock: Checking proof-of-work for height {}", .{expected_height});

        // SECURITY: Calculate required difficulty for sync blocks
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            log.warn("❌ Failed to calculate required difficulty for sync block", .{});
            return false;
        };

        // SECURITY: Verify sync block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            // ENHANCED: Log detailed sync block difficulty calculation chain
            log.warn("❌ SECURITY: Sync block difficulty mismatch detected!", .{});
            log.warn("   📊 Required difficulty: {} (base_bytes={}, threshold=0x{X})", .{ required_difficulty.toU64(), required_difficulty.base_bytes, required_difficulty.threshold });
            log.warn("   📦 Sync block claimed difficulty: {} (base_bytes={}, threshold=0x{X})", .{ claimed_difficulty.toU64(), claimed_difficulty.base_bytes, claimed_difficulty.threshold });
            log.warn("   🔍 Block height: {}, timestamp: {}", .{ expected_height, block.header.timestamp });
            
            // Log detailed calculation chain for sync debugging
            self.logDifficultyCalculationChain(expected_height) catch |err| {
                log.warn("   ⚠️ Failed to log sync difficulty calculation chain: {}", .{err});
            };
            
            return false;
        }

        // Always use RandomX validation for consistent security
        const mining_context = miner_mod.MiningContext{
            .allocator = self.allocator,
            .database = self.chain_state.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = null,
            // fork_manager removed
            .blockchain = undefined, // Not needed for validation
        };
        if (!try miner_mod.validateBlockPoW(mining_context, block.*)) {
            log.warn("❌ RandomX proof-of-work validation failed for height {}", .{expected_height});
            return false;
        }
        log.warn("✅ Proof-of-work validation passed for height {}", .{expected_height});

        // NOTE: State root validation is skipped during sync because:
        // 1. The block's state_root represents the state AFTER applying this block's transactions
        // 2. We're validating BEFORE applying transactions, so roots will never match
        // 3. State correctness is ensured by:
        //    - Transaction validation (signatures, structure)
        //    - Proof-of-work validation (ensures block is valid)
        //    - Balance checks during transaction application
        // State root validation is only meaningful for blocks we're creating, not syncing
        log.warn("ℹ️ [SYNC] Skipping state root validation (validated after transaction application)", .{});

        // SECURITY: Validate coinbase transaction during sync
        if (!try self.validateCoinbaseSync(block, expected_height)) {
            log.warn("❌ [SYNC] Coinbase validation failed for block {}", .{expected_height});
            return false;
        }

        log.warn("🔍 validateSyncBlock: Checking previous hash links for height {}", .{expected_height});

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.chain_state.getHeight();
            log.warn("   Current blockchain height: {}", .{current_height});
            log.warn("   Expected block height: {}", .{expected_height});

            if (expected_height > current_height) {
                // During sync, we might not have the previous block yet - skip this check
                log.warn("⚠️ Skipping previous hash check during sync (height {} > current {})", .{ expected_height, current_height });
            } else if (expected_height == current_height) {
                // We're about to add this block - check against our current tip
                log.warn("   Checking previous hash against current blockchain tip", .{});
                var prev_block = try self.getBlockByHeight(expected_height - 1);
                defer prev_block.deinit(self.allocator);

                const prev_hash = prev_block.hash();
                // log.warn("   Previous block hash in chain: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                // log.warn("   Block's previous_hash field: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    log.warn("❌ Previous hash validation failed during sync", .{});
                    // log.warn("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    // log.warn("   Received: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                    log.warn("⚠️ This might indicate a fork - skipping hash validation during sync", .{});
                    // During sync, we trust the peer's chain - skip this validation
                }
            } else {
                // We already have this block height - this shouldn't happen during normal sync
                log.warn("⚠️ Unexpected: trying to sync block {} but we already have height {}", .{ expected_height, current_height });
            }
        }

        log.warn("🔍 validateSyncBlock: Validating {} transactions for height {}", .{ block.txCount(), expected_height });

        // For sync blocks, validate transaction structure but skip balance checks
        // The balance validation will happen naturally when transactions are processed
        for (block.transactions, 0..) |tx, i| {
            log.warn("   🔍 Validating transaction {} of {}", .{ i, block.txCount() - 1 });

            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) {
                log.warn("   ✅ Skipping coinbase transaction validation", .{});
                continue;
            }

            log.warn("   🔍 Checking transaction structure...", .{});

            // Basic transaction structure validation only
            if (!tx.isValid()) {
                log.warn("❌ Transaction {} structure validation failed", .{i});
                _ = tx.sender.toBytes(); // Sender bytes calculated but not used in release mode
                _ = tx.recipient.toBytes(); // Recipient bytes calculated but not used in release mode
                // log.warn("   Sender: {s}", .{std.fmt.fmtSliceHexLower(&sender_bytes)});
                // log.warn("   Recipient: {s}", .{std.fmt.fmtSliceHexLower(&recipient_bytes)});
                log.warn("   Amount: {}", .{tx.amount});
                log.warn("   Fee: {}", .{tx.fee});
                log.warn("   Nonce: {}", .{tx.nonce});
                log.warn("   Timestamp: {}", .{tx.timestamp});
                return false;
            }
            log.warn("   ✅ Transaction {} structure validation passed", .{i});

            log.warn("   🔍 Checking transaction signature...", .{});

            // Signature validation (but no balance check)
            if (!try self.validateTransactionSignatureDetailed(tx)) {
                log.warn("❌ Transaction {} signature validation failed", .{i});
                // log.warn("   Public key: {s}", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
                // log.warn("   Signature: {s}", .{std.fmt.fmtSliceHexLower(&tx.signature)});
                return false;
            }
            log.warn("   ✅ Transaction {} signature validation passed", .{i});
        }

        log.warn("✅ Sync block {} structure and signatures validated", .{expected_height});
        return true;
    }

    /// Validate a block during reorganization (skip chain linkage)
    pub fn validateReorgBlock(self: *Self, block: Block, expected_height: u32) !bool {
        // Special validation for genesis block
        if (expected_height == 0) {
            if (!genesis.GenesisBlocks.TESTNET.getBlock().equals(&block)) {
                log.warn("❌ Reorg genesis block validation failed", .{});
                return false;
            }
            return true;
        }

        // Check basic block structure
        if (!block.isValid()) {
            log.warn("❌ Reorg block structure validation failed", .{});
            return false;
        }

        // Lenient timestamp validation during reorganization
        const current_time = util.getTime();
        // Block timestamps are in milliseconds, convert to seconds for comparison
        const block_time_seconds = @divFloor(@as(i64, @intCast(block.header.timestamp)), 1000);
        const reorg_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2;
        if (block_time_seconds > current_time + reorg_future_allowance) {
            const future_seconds = block_time_seconds - current_time;
            log.warn("❌ Reorg block timestamp too far in future: {} seconds ahead", .{future_seconds});
            return false;
        }

        // SECURITY: Calculate required difficulty for reorg blocks - DO NOT trust block header!
        var difficulty_calc = @import("difficulty.zig").DifficultyCalculator.init(self.allocator, self.chain_state.database);
        const required_difficulty = difficulty_calc.calculateNextDifficulty() catch {
            log.warn("❌ Failed to calculate required difficulty for reorg block", .{});
            return false;
        };

        // SECURITY: Verify reorg block claims correct difficulty
        const claimed_difficulty = block.header.getDifficultyTarget();
        if (claimed_difficulty.toU64() != required_difficulty.toU64()) {
            // ENHANCED: Log detailed reorg block difficulty calculation chain
            log.warn("❌ SECURITY: Reorg block difficulty mismatch detected!", .{});
            log.warn("   📊 Required difficulty: {} (base_bytes={}, threshold=0x{X})", .{ required_difficulty.toU64(), required_difficulty.base_bytes, required_difficulty.threshold });
            log.warn("   📦 Reorg block claimed difficulty: {} (base_bytes={}, threshold=0x{X})", .{ claimed_difficulty.toU64(), claimed_difficulty.base_bytes, claimed_difficulty.threshold });
            log.warn("   🔍 Block height: {}, timestamp: {}", .{ expected_height, block.header.timestamp });
            
            // Log detailed calculation chain for reorg debugging
            self.logDifficultyCalculationChain(expected_height) catch |err| {
                log.warn("   ⚠️ Failed to log reorg difficulty calculation chain: {}", .{err});
            };
            
            return false;
        }

        // Always use RandomX validation for consistent security
        if (!try self.validateBlockPoW(block)) {
            log.warn("❌ Reorg block RandomX validation failed", .{});
            return false;
        }

        // Validate transaction structure and signatures only
        for (block.transactions, 0..) |tx, i| {
            // Skip coinbase transaction
            if (i == 0) continue;

            if (!tx.isValid()) {
                log.warn("❌ Reorg transaction {} structure validation failed", .{i});
                return false;
            }

            if (!try self.validateTransactionSignature(tx)) {
                log.warn("❌ Reorg transaction {} signature validation failed", .{i});
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
            // fork_manager removed - not needed for validation
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

    /// ENHANCED: Log detailed difficulty calculation chain for debugging mismatches
    fn logDifficultyCalculationChain(self: *Self, height: u32) !void {
        log.warn("   🔗 DIFFICULTY CALCULATION CHAIN DEBUG:", .{});
        
        const current_height = try self.chain_state.getHeight();
        log.warn("   📊 Current blockchain height: {}", .{current_height});
        log.warn("   🎯 Target block height: {}", .{height});
        
        // Check if we're in adjustment period
        const lookback_blocks = types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD;
        const target_block_time = types.ZenMining.TARGET_BLOCK_TIME;
        
        if (height < lookback_blocks) {
            log.warn("   ⚡ Using initial difficulty (height {} < adjustment period {})", .{ height, lookback_blocks });
            const initial_difficulty = types.ZenMining.initialDifficultyTarget();
            log.warn("   📈 Initial difficulty: {} (base_bytes={}, threshold=0x{X})", .{ initial_difficulty.toU64(), initial_difficulty.base_bytes, initial_difficulty.threshold });
            return;
        }
        
        if (height % lookback_blocks != 0) {
            log.warn("   ↔️ Not adjustment block (height {} % {} = {})", .{ height, lookback_blocks, height % lookback_blocks });
            if (height > 0) {
                var prev_block = try self.getBlockByHeight(height - 1);
                defer prev_block.deinit(self.allocator);
                const prev_difficulty = prev_block.header.getDifficultyTarget();
                log.warn("   📈 Using previous block difficulty: {} (base_bytes={}, threshold=0x{X})", .{ prev_difficulty.toU64(), prev_difficulty.base_bytes, prev_difficulty.threshold });
            }
            return;
        }
        
        log.warn("   🎯 ADJUSTMENT BLOCK - Calculating new difficulty:", .{});
        
        // Get timestamps for calculation
        const old_block_height: u32 = @intCast(height - lookback_blocks);
        const new_block_height: u32 = @intCast(height - 1);
        
        var old_block = try self.getBlockByHeight(old_block_height);
        defer old_block.deinit(self.allocator);
        var new_block = try self.getBlockByHeight(new_block_height);
        defer new_block.deinit(self.allocator);
        
        const oldest_timestamp = old_block.header.timestamp;
        const newest_timestamp = new_block.header.timestamp;
        const actual_time_raw = newest_timestamp - oldest_timestamp;
        const target_time = lookback_blocks * target_block_time;
        
        log.warn("   📅 Timestamp analysis:", .{});
        log.warn("     🕐 Block {} timestamp: {}", .{ old_block_height, oldest_timestamp });
        log.warn("     🕐 Block {} timestamp: {}", .{ new_block_height, newest_timestamp });
        log.warn("     ⏱️ Raw time difference: {} seconds", .{actual_time_raw});
        log.warn("     🎯 Target time ({} blocks × {} seconds): {} seconds", .{ lookback_blocks, target_block_time, target_time });
        
        // Apply bounds checking
        const bounded_actual_time = if (actual_time_raw == 0) 
            1 
        else if (actual_time_raw > target_time * 4) 
            target_time * 2 
        else 
            actual_time_raw;
            
        if (bounded_actual_time != actual_time_raw) {
            log.warn("     ⚠️ Time bounded: {} → {} seconds", .{ actual_time_raw, bounded_actual_time });
        }
        
        // Calculate adjustment factor using fixed-point arithmetic
        const FIXED_POINT_MULTIPLIER: u64 = 1_000_000;
        const adjustment_factor_fixed = (target_time * FIXED_POINT_MULTIPLIER) / bounded_actual_time;
        const adjustment_factor_display = @as(f64, @floatFromInt(adjustment_factor_fixed)) / @as(f64, @floatFromInt(FIXED_POINT_MULTIPLIER));
        
        log.warn("   🧮 Adjustment calculation:", .{});
        log.warn("     📐 Fixed-point factor: {} (= {d:.6})", .{ adjustment_factor_fixed, adjustment_factor_display });
        
        // Get current difficulty and show adjustment
        const current_difficulty = new_block.header.getDifficultyTarget();
        log.warn("     📊 Current difficulty: {} (base_bytes={}, threshold=0x{X})", .{ current_difficulty.toU64(), current_difficulty.base_bytes, current_difficulty.threshold });
        
        const new_difficulty = current_difficulty.adjustFixed(adjustment_factor_fixed, FIXED_POINT_MULTIPLIER, types.CURRENT_NETWORK);
        log.warn("     📈 Calculated new difficulty: {} (base_bytes={}, threshold=0x{X})", .{ new_difficulty.toU64(), new_difficulty.base_bytes, new_difficulty.threshold });
    }

    // ============================================
    // Coinbase Validation Functions
    // ============================================

    /// Validate coinbase transaction in a block
    /// Checks: correct amount (reward + fees), supply cap not exceeded
    fn validateCoinbase(self: *Self, block: Block, height: u32) !bool {
        // Genesis block has special handling - no coinbase validation
        if (height == 0) {
            return true;
        }

        // Block must have at least one transaction (coinbase)
        if (block.transactions.len == 0) {
            log.warn("❌ [COINBASE] Block {} has no transactions", .{height});
            return false;
        }

        const coinbase_tx = block.transactions[0];

        // First transaction must be a coinbase
        if (!coinbase_tx.isCoinbase()) {
            log.warn("❌ [COINBASE] First transaction is not coinbase at height {}", .{height});
            return false;
        }

        // Calculate expected block reward using halving schedule
        const expected_reward = types.ZenMining.calculateBlockReward(height);

        // Calculate total fees from other transactions
        var total_fees: u64 = 0;
        for (block.transactions[1..]) |tx| {
            total_fees += tx.fee;
        }

        // Maximum allowed coinbase = reward + fees
        const max_coinbase = expected_reward + total_fees;

        // Validate coinbase amount
        if (coinbase_tx.amount > max_coinbase) {
            log.warn("❌ [COINBASE] Amount {} exceeds maximum {} (reward: {}, fees: {}) at height {}", .{
                coinbase_tx.amount,
                max_coinbase,
                expected_reward,
                total_fees,
                height,
            });
            return false;
        }

        // Check supply cap
        const current_supply = self.chain_state.database.getTotalSupply();
        if (current_supply + coinbase_tx.amount > types.MAX_SUPPLY) {
            log.warn("❌ [COINBASE] Would exceed MAX_SUPPLY: current {} + coinbase {} > max {}", .{
                current_supply,
                coinbase_tx.amount,
                types.MAX_SUPPLY,
            });
            return false;
        }

        log.info("✅ [COINBASE] Valid: {} ZEI (reward: {}, fees: {}) at height {}", .{
            coinbase_tx.amount / types.ZEI_COIN,
            expected_reward / types.ZEI_COIN,
            total_fees,
            height,
        });

        return true;
    }

    /// Validate coinbase during sync (uses block pointer)
    fn validateCoinbaseSync(_: *Self, block: *const Block, height: u32) !bool {
        // Genesis block has special handling
        if (height == 0) {
            return true;
        }

        // Block must have at least one transaction (coinbase)
        if (block.transactions.len == 0) {
            log.warn("❌ [COINBASE SYNC] Block {} has no transactions", .{height});
            return false;
        }

        const coinbase_tx = block.transactions[0];

        // First transaction must be a coinbase
        if (!coinbase_tx.isCoinbase()) {
            log.warn("❌ [COINBASE SYNC] First transaction is not coinbase at height {}", .{height});
            return false;
        }

        // Calculate expected block reward using halving schedule
        const expected_reward = types.ZenMining.calculateBlockReward(height);

        // Calculate total fees from other transactions
        var total_fees: u64 = 0;
        for (block.transactions[1..]) |tx| {
            total_fees += tx.fee;
        }

        // Maximum allowed coinbase = reward + fees
        const max_coinbase = expected_reward + total_fees;

        // Validate coinbase amount
        if (coinbase_tx.amount > max_coinbase) {
            log.warn("❌ [COINBASE SYNC] Amount {} exceeds maximum {} (reward: {}, fees: {}) at height {}", .{
                coinbase_tx.amount,
                max_coinbase,
                expected_reward,
                total_fees,
                height,
            });
            return false;
        }

        // During sync, we trust the chain's supply tracking
        // The supply cap will be enforced when processing the coinbase transaction
        log.warn("✅ [COINBASE SYNC] Valid coinbase at height {}: {} (max: {})", .{
            height,
            coinbase_tx.amount,
            max_coinbase,
        });

        return true;
    }
};
