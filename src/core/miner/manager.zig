// manager.zig - Mining Manager
// Handles mining thread management and coordination

const std = @import("std");
const log = std.log.scoped(.mining);

const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");
const MiningContext = @import("context.zig").MiningContext;
const core = @import("core.zig");
const validation = @import("validation.zig");

/// Mining Manager - coordinates all mining operations
pub const MiningManager = struct {
    context: MiningContext,
    mining_address: types.Address,

    pub fn init(context: MiningContext, mining_address: types.Address) MiningManager {
        return MiningManager{
            .context = context,
            .mining_address = mining_address,
        };
    }

    /// Start the mining thread
    pub fn startMining(self: *MiningManager, miner_keypair: key.KeyPair) !void {
        if (self.context.mining_state.active.load(.acquire)) {
            return; // Already mining
        }

        self.context.mining_state.active.store(true, .release);
        self.context.mining_state.thread = try std.Thread.spawn(.{}, miningThreadFn, .{ self.context, miner_keypair, self.mining_address });
        log.info("⛏️ Mining thread started successfully", .{});
    }

    /// Start mining using keypair stored in blockchain (for deferred start after sync)
    pub fn startMiningDeferred(self: *MiningManager) !void {
        if (self.context.blockchain.mining_keypair) |keypair| {
            try self.startMining(keypair);
        } else {
            return error.NoKeypairStored;
        }
    }

    /// Stop the mining thread
    pub fn stopMining(self: *MiningManager) void {
        if (!self.context.mining_state.active.load(.acquire)) {
            return; // Not mining
        }

        self.context.mining_state.active.store(false, .release);
        self.context.mining_state.condition.signal(); // Wake up the thread if it's waiting

        if (self.context.mining_state.thread) |thread| {
            thread.join();
            self.context.mining_state.thread = null;
        }
        log.info("⛏️  Mining thread stopped", .{});
    }

    /// Mine a single block (public API)
    pub fn mineBlock(self: *MiningManager, miner_keypair: key.KeyPair) !types.Block {
        return core.zenMineBlock(self.context, miner_keypair, self.mining_address);
    }

    /// Validate a block's proof-of-work (public API)
    pub fn validateBlockPoW(self: *MiningManager, block: types.Block) !bool {
        return validation.validateBlockPoW(self.context, block);
    }
};

/// Mining thread function - runs in background
pub fn miningThreadFn(ctx: MiningContext, miner_keypair: key.KeyPair, mining_address: types.Address) void {
    log.info("⛏️ Mining thread started", .{});

    while (ctx.mining_state.active.load(.acquire)) {
        // Lock for checking mempool
        ctx.mining_state.mutex.lock();

        // Check if we should mine - wait for multiple transactions or timeout
        const tx_count = ctx.mempool_manager.getTransactionCount();
        const min_batch_size = 1; // Wait for at least 1 transaction before mining
        const should_mine = tx_count >= min_batch_size;
        const current_height = ctx.blockchain.getHeight() catch 0;
        log.info("🔍 [MINING CHECK] Height {} - mempool has {} transactions, should_mine={}", .{ current_height, tx_count, should_mine });

        if (!should_mine) {
            // Wait for new transactions
            log.info("⏳ Mining thread: Waiting for transactions (mempool empty)", .{});
            log.info("🔐 Mining thread: About to wait on condition variable", .{});
            ctx.mining_state.condition.wait(&ctx.mining_state.mutex);
            log.info("👀 Mining thread: Woke up from condition wait", .{});
            log.info("🔍 Mining thread: Rechecking mempool after wake - has {} transactions", .{ctx.mempool_manager.getTransactionCount()});
            // Unlock before continuing to avoid double-lock
            ctx.mining_state.mutex.unlock();
            continue;
        }

        // BATCHING: If we have few transactions, wait a bit for more (but not forever)
        if (tx_count == 1) {
            log.info("📦 Single transaction, waiting 2 seconds for more to batch...", .{});
            ctx.mining_state.mutex.unlock();
            std.time.sleep(2 * std.time.ns_per_s); // Wait 2 seconds for more transactions

            // Re-check mempool count after delay
            const new_tx_count = ctx.mempool_manager.getTransactionCount();
            if (new_tx_count == 1) {
                log.info("⏰ Timeout reached, mining single transaction...", .{});
                // Continue to mine the single transaction after timeout
                // Note: mutex is already unlocked, so we DON'T unlock again below
            } else {
                log.info("📦 Found {} transactions after batching delay", .{new_tx_count});
                continue; // Re-check with more transactions
            }
        } else {
            // Only unlock if we didn't already unlock in the batching logic above
            ctx.mining_state.mutex.unlock();
        }

        // Update current mining height
        ctx.mining_state.current_height.store(current_height, .release);

        // Mine the block
        log.info("🔨 Mining thread: Calling zenMineBlock (mempool has {} transactions)", .{ctx.mempool_manager.getTransactionCount()});
        const block = core.zenMineBlock(ctx, miner_keypair, mining_address) catch |err| {
            log.info("❌ [MINING ERROR] Height {} - {}", .{ current_height, err });
            std.time.sleep(1 * std.time.ns_per_s); // Wait 1 second before retry
            continue;
        };

        // Successfully mined - the block is already added to chain in zenMineBlock
        const block_height = ctx.blockchain.getHeight() catch 0;
        log.info("✅ Block #{} mined by background thread", .{block_height});

        // Broadcast block to network peers
        if (ctx.network) |net_mgr| {
            net_mgr.broadcastBlock(block) catch |err| {
                log.info("⚠️  Failed to broadcast block: {}", .{err});
            };
            log.info("📡 Block broadcasted to {} peers", .{net_mgr.getConnectedPeerCount()});
        }
    }

    log.info("⛏️  Mining thread stopped", .{});
}
