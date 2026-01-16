// core.zig - Core Mining Logic
// Handles block creation, transaction selection, and mining orchestration

const std = @import("std");
const log = std.log.scoped(.mining);
const ArrayList = std.ArrayList;

const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const serialize = @import("../storage/serialize.zig");
const key = @import("../crypto/key.zig");
const MiningContext = @import("context.zig").MiningContext;
const randomx_algo = @import("algorithms/randomx.zig");

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;
const Address = types.Address;

/// Mine a new block with transactions from mempool
pub fn zenMineBlock(ctx: MiningContext, miner_keypair: key.KeyPair, mining_address: Address) !types.Block {
    _ = miner_keypair; // Coinbase transactions don't need signatures
    log.info("⛏️ ZenMineBlock: Starting to mine new block", .{});

    // Get current height to calculate proper block reward with halving
    const current_height = try ctx.blockchain.getHeight();
    const new_block_height = current_height + 1;

    // SECURITY: Check supply cap before mining
    const current_supply = ctx.database.getTotalSupply();
    const base_reward = types.ZenMining.calculateBlockReward(new_block_height);

    if (current_supply >= types.MAX_SUPPLY) {
        log.warn("⛔ [SUPPLY CAP] Cannot mine: MAX_SUPPLY ({} ZEI) already reached", .{types.MAX_SUPPLY / types.ZEI_COIN});
        return error.SupplyCapReached;
    }

    // Log halving info
    const halving_epoch = new_block_height / types.ZenMining.HALVING_INTERVAL;
    const blocks_until_halving = types.ZenMining.HALVING_INTERVAL - (new_block_height % types.ZenMining.HALVING_INTERVAL);
    if (blocks_until_halving <= 10 or new_block_height % types.ZenMining.HALVING_INTERVAL == 0) {
        log.info("📉 [HALVING] Epoch {}: {} blocks until next halving, current reward: {} zei", .{
            halving_epoch,
            blocks_until_halving,
            base_reward,
        });
    }

    // Get transactions from mempool manager
    const mempool_transactions = try ctx.mempool_manager.getTransactionsForMining();
    defer ctx.mempool_manager.freeTransactionArray(mempool_transactions);

    // 💰 Calculate total fees from mempool transactions
    var total_fees: u64 = 0;
    for (mempool_transactions) |tx| {
        total_fees += tx.fee;
    }

    // Create coinbase transaction (miner reward + fees) using height-based reward
    const miner_reward = base_reward + total_fees;

    // SECURITY: Final supply cap check with exact reward
    if (current_supply + miner_reward > types.MAX_SUPPLY) {
        // Cap the reward to not exceed MAX_SUPPLY
        const capped_reward = types.MAX_SUPPLY - current_supply;
        log.warn("⚠️ [SUPPLY CAP] Capping miner reward from {} to {} to respect MAX_SUPPLY", .{
            miner_reward,
            capped_reward,
        });
        // Can't reduce below fees (miners deserve their fees)
        if (capped_reward < total_fees) {
            log.warn("⛔ [SUPPLY CAP] Cannot mine: would exceed MAX_SUPPLY even with fees only", .{});
            return error.SupplyCapReached;
        }
    }

    const coinbase_tx = Transaction{
        .version = 0, // Version 0 for coinbase
        .flags = .{}, // Default flags
        .sender = types.Address.zero(), // From thin air (coinbase)
        .sender_public_key = std.mem.zeroes([32]u8), // No sender for coinbase
        .recipient = mining_address,
        .amount = miner_reward, // 💰 Block reward + all transaction fees
        .fee = 0, // Coinbase has no fee
        .nonce = 0, // Coinbase always nonce 0
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = std.math.maxInt(u64), // Coinbase transactions never expire
        .signature = std.mem.zeroes(types.Signature), // No signature needed for coinbase
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Format miner reward display
    const base_reward_display = util.formatZEI(ctx.allocator, base_reward) catch "? ZEI";
    defer if (!std.mem.eql(u8, base_reward_display, "? ZEI")) ctx.allocator.free(base_reward_display);
    const fees_display = util.formatZEI(ctx.allocator, total_fees) catch "? ZEI";
    defer if (!std.mem.eql(u8, fees_display, "? ZEI")) ctx.allocator.free(fees_display);
    const total_reward_display = util.formatZEI(ctx.allocator, miner_reward) catch "? ZEI";
    defer if (!std.mem.eql(u8, total_reward_display, "? ZEI")) ctx.allocator.free(total_reward_display);

    log.info("💰 Miner reward: {s} (base) + {s} (fees) = {s} total", .{ base_reward_display, fees_display, total_reward_display });

    // Apply soft limit for mining (2MB default, configurable)
    var transactions_to_include = std.ArrayList(Transaction).init(ctx.allocator);
    defer transactions_to_include.deinit();

    // Always include coinbase
    try transactions_to_include.append(coinbase_tx);

    // Calculate running block size
    var current_block_size: usize = 84 + 4; // Header + tx count
    current_block_size += 192; // Coinbase transaction

    // Add transactions from mempool until we hit soft limit
    for (mempool_transactions) |tx| {
        const tx_size: usize = 192; // Approximate transaction size
        if (current_block_size + tx_size > types.BlockLimits.SOFT_BLOCK_SIZE) {
            log.info("📦 Soft block size limit reached: {} bytes (limit: {} bytes)", .{ current_block_size, types.BlockLimits.SOFT_BLOCK_SIZE });
            log.info("📊 Including {} of {} mempool transactions", .{ transactions_to_include.items.len - 1, mempool_transactions.len });
            break;
        }
        try transactions_to_include.append(tx);
        current_block_size += tx_size;
    }

    const all_transactions = try transactions_to_include.toOwnedSlice();
    defer ctx.allocator.free(all_transactions);

    // Update mining state height before mining (current_height already fetched above)
    ctx.mining_state.current_height.store(current_height, .release);
    log.info("🔍 zenMineBlock: storing current_height = {} to atomic", .{current_height});

    // Get previous block hash even for block 1 (height 0 = genesis exists)
    // Check if database is completely empty (no blocks at all)
    const has_genesis = ctx.database.getBlock(0) catch null != null;

    const previous_hash = if (current_height == 0 and !has_genesis) blk: {
        // Special case: mining first block when genesis doesn't exist yet
        // This should only happen during chain initialization
        break :blk std.mem.zeroes(Hash);
    } else blk: {
        // Normal case: get the hash of the previous block (current_height is the existing tip)
        // When mining block at height N+1, we need hash of block N
        log.info("🔍 Mining block at height {}, getting previous block at height {}", .{ current_height + 1, current_height });
        var prev_block = try ctx.database.getBlock(current_height);
        const hash = prev_block.hash();
        const hash_hex = std.fmt.fmtSliceHexLower(&hash);
        log.info("🔍 Previous block hash: {}", .{hash_hex});
        prev_block.deinit(ctx.allocator);
        break :blk hash;
    };

    // Calculate difficulty for new block
    const next_difficulty_target = try ctx.blockchain.calculateNextDifficulty();

    // Calculate current account state root before creating block
    const account_state_root = try ctx.blockchain.chain_state.calculateStateRoot();
    log.info("🌳 [MINING] Calculated state root for new block: {}", .{std.fmt.fmtSliceHexLower(&account_state_root)});

    // Create block with dynamic difficulty
    var new_block = Block{
        .header = BlockHeader{
            .version = types.CURRENT_BLOCK_VERSION,
            .previous_hash = previous_hash,
            .merkle_root = std.mem.zeroes(Hash), // Will be calculated after transactions are set
            .timestamp = @intCast(std.time.milliTimestamp()),
            .difficulty = next_difficulty_target.toU64(),
            .nonce = 0,
            .witness_root = std.mem.zeroes(Hash), // No witness data yet
            .state_root = account_state_root, // Account state commitment
            .extra_nonce = 0,
            .extra_data = blk: {
                // Add randomness to prevent identical blocks between miners
                var random_data: [32]u8 = std.mem.zeroes([32]u8);
                std.crypto.random.bytes(&random_data);
                break :blk random_data;
            },
        },
        // Deep copy all transactions to ensure the block owns its memory.
        // This prevents double-frees or invalid frees when the block is deinitialized.
        .transactions = blk: {
            const allocated_txs = try ctx.allocator.alloc(types.Transaction, all_transactions.len);
            var copied_count: usize = 0;
            errdefer {
                // Clean up any transactions we've already copied if an error occurs
                for (allocated_txs[0..copied_count]) |*tx| {
                    tx.deinit(ctx.allocator);
                }
                ctx.allocator.free(allocated_txs);
            }

            for (all_transactions, 0..) |tx, i| {
                allocated_txs[i] = try tx.dupe(ctx.allocator);
                copied_count += 1;
            }
            break :blk allocated_txs;
        },
        .height = current_height + 1, // Fix 2: Set block height explicitly
    };

    // Calculate merkle root now that transactions are set
    new_block.header.merkle_root = try new_block.calculateMerkleRoot(ctx.allocator);
    log.info("🌲 [MINING] Calculated merkle root for new block: {}", .{std.fmt.fmtSliceHexLower(&new_block.header.merkle_root)});

    log.info("👌 Starting mining", .{});
    const start_time = util.getTime();

    // ZEN PROOF-OF-WORK: Find valid nonce
    // Ensure mining state height is synchronized before mining
    ctx.mining_state.current_height.store(current_height, .release);

    const found_nonce = zenProofOfWork(ctx, &new_block);

    const mining_time = util.getTime() - start_time;

    if (found_nonce) {
        // Process coinbase transaction (create new coins!)
        // Note: new_block_height was already calculated at function start
        try ctx.blockchain.chain_state.processCoinbaseTransaction(coinbase_tx, mining_address, new_block_height, false);

        // Process regular transactions
        for (new_block.transactions[1..]) |tx| {
            try ctx.blockchain.chain_state.processTransaction(tx, false);
        }

        // Calculate cumulative chain work before saving (critical for reorganization)
        const block_work = new_block.header.getWork();
        const prev_chain_work = if (new_block_height > 0) blk: {
            var prev_block = try ctx.database.getBlock(new_block_height - 1);
            defer prev_block.deinit(ctx.allocator);
            break :blk prev_block.chain_work;
        } else 0;

        new_block.chain_work = prev_chain_work + block_work;

        log.debug("⚡ [CHAIN WORK] Block #{} work: {}, cumulative: {}", .{
            new_block_height,
            block_work,
            new_block.chain_work,
        });

        // Save block to database at next height
        const block_height = new_block_height;
        const block_hash_hex = std.fmt.fmtSliceHexLower(&new_block.hash());
        const prev_hash_hex = std.fmt.fmtSliceHexLower(&new_block.header.previous_hash);
        log.info("💾 Saving block {} with hash {} and previous_hash {}", .{ block_height, block_hash_hex, prev_hash_hex });
        try ctx.database.saveBlock(block_height, new_block);

        // CRITICAL FIX: Index the new block in memory so getBlockHash/getHash works
        try ctx.blockchain.chain_state.indexBlock(block_height, new_block.hash());

        // Check for matured coinbase rewards (100 block maturity)
        if (block_height >= types.COINBASE_MATURITY) {
            const maturity_height = block_height - types.COINBASE_MATURITY;
            try ctx.blockchain.chain_state.matureCoinbaseRewards(maturity_height);
        }

        // Clean mempool of confirmed transactions
        try ctx.mempool_manager.cleanAfterBlock(new_block);

        log.info("⛏️  ZEN BLOCK #{} MINED! ({} txs, {} ZEI reward, {}s)", .{ block_height, new_block.txCount(), base_reward / types.ZEI_COIN, mining_time });

        // Chain state updates handled by modern reorganization system
        // Fork manager updateBestChain call removed - handled internally

        // Broadcast the newly mined block to network peers (zen propagation)
        try ctx.blockchain.broadcastNewBlock(new_block);

        log.info("📡 Block propagates through zen network like ripples in water", .{});

        return new_block;
    } else {
        const height = ctx.blockchain.getHeight() catch 0;
        log.info("😔 [MINING TIMEOUT] Height {} - nonce not found (the universe wasn't ready)", .{height});
        // Free block memory and return error
        new_block.deinit(ctx.allocator);
        return error.MiningFailed;
    }
}

/// Zen Proof-of-Work: Always uses RandomX for ASIC resistance and security
/// Network difficulty is controlled by target thresholds, not algorithm choice
pub fn zenProofOfWork(ctx: MiningContext, block: *Block) bool {
    // Always use RandomX for consistent security model
    // TestNet uses easier difficulty targets (not different algorithms)
    return randomx_algo.zenProofOfWorkRandomX(ctx, block);
}
