// manager.zig - Mining Manager
// Handles mining thread management and coordination

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");
const MiningContext = @import("context.zig").MiningContext;
const core = @import("core.zig");
const validation = @import("validation.zig");

/// Mining Manager - coordinates all mining operations
pub const MiningManager = struct {
    context: MiningContext,
    
    pub fn init(context: MiningContext) MiningManager {
        return MiningManager{
            .context = context,
        };
    }
    
    /// Start the mining thread
    pub fn startMining(self: *MiningManager, miner_keypair: key.KeyPair) !void {
        if (self.context.mining_state.active.load(.acquire)) {
            return; // Already mining
        }
        
        self.context.mining_state.active.store(true, .release);
        self.context.mining_state.thread = try std.Thread.spawn(.{}, miningThreadFn, .{ self.context, miner_keypair });
        print("⛏️  Mining thread started successfully\n", .{});
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
        print("⛏️  Mining thread stopped\n", .{});
    }
    
    /// Mine a single block (public API)
    pub fn mineBlock(self: *MiningManager, miner_keypair: key.KeyPair) !types.Block {
        return core.zenMineBlock(self.context, miner_keypair);
    }
    
    /// Validate a block's proof-of-work (public API)
    pub fn validateBlockPoW(self: *MiningManager, block: types.Block) !bool {
        return validation.validateBlockPoW(self.context, block);
    }
};

/// Mining thread function - runs in background
pub fn miningThreadFn(ctx: MiningContext, miner_keypair: key.KeyPair) void {
    print("⛏️  Mining thread started\n", .{});
    
    while (ctx.mining_state.active.load(.acquire)) {
        // Lock for checking mempool
        ctx.mining_state.mutex.lock();
        
        // Check if we should mine
        const tx_count = ctx.mempool_manager.getTransactionCount();
        const should_mine = tx_count > 0;
        const current_height = ctx.blockchain.getHeight() catch 0;
        print("🔍 Mining thread check: mempool has {} transactions, should_mine={}\n", .{tx_count, should_mine});
        
        if (!should_mine) {
            // Wait for new transactions
            print("⏳ Mining thread: Waiting for transactions (mempool empty)\n", .{});
            print("🔐 Mining thread: About to wait on condition variable\n", .{});
            ctx.mining_state.condition.wait(&ctx.mining_state.mutex);
            print("👀 Mining thread: Woke up from condition wait\n", .{});
            print("🔍 Mining thread: Rechecking mempool after wake - has {} transactions\n", .{ctx.mempool_manager.getTransactionCount()});
            // Unlock before continuing to avoid double-lock
            ctx.mining_state.mutex.unlock();
            continue;
        }
        
        // Update current mining height
        ctx.mining_state.current_height.store(current_height, .release);
        
        // Unlock before mining (mining takes time)
        ctx.mining_state.mutex.unlock();
        
        // Mine the block
        print("🔨 Mining thread: Calling zenMineBlock (mempool has {} transactions)\n", .{ctx.mempool_manager.getTransactionCount()});
        const block = core.zenMineBlock(ctx, miner_keypair) catch |err| {
            print("❌ Mining error: {}\n", .{err});
            std.time.sleep(1 * std.time.ns_per_s); // Wait 1 second before retry
            continue;
        };
        
        // Successfully mined - the block is already added to chain in zenMineBlock
        const block_height = ctx.blockchain.getHeight() catch 0;
        print("✅ Block #{} mined by background thread\n", .{block_height});
        
        // Broadcast block to network peers
        if (ctx.network) |net_mgr| {
            net_mgr.broadcastBlock(block);
            print("📡 Block broadcasted to {} peers\n", .{net_mgr.getConnectedPeerCount()});
        }
    }
    
    print("⛏️  Mining thread stopped\n", .{});
}