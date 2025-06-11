// forkmanager.zig - Longest Chain Consensus Manager
// Handles competing blockchain forks and chain reorganization

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const types = @import("types.zig");
const util = @import("util.zig");

const Block = types.Block;
const BlockHash = types.BlockHash;
const ChainWork = types.ChainWork;
const ChainState = types.ChainState;
const ForkBlock = types.ForkBlock;

/// Fork Manager - handles competing chains and reorganization
pub const ForkManager = struct {
    allocator: std.mem.Allocator,
    
    // Track top 3 chains by cumulative work
    chains: [3]?ChainState,
    active_chain_index: u8, // Index of currently active chain (0-2)
    
    // Orphan blocks waiting for parents
    orphan_blocks: HashMap(BlockHash, ForkBlock, HashContext, std.hash_map.default_max_load_percentage),
    
    // Recently seen blocks (prevent re-processing)
    recent_blocks: HashMap(BlockHash, void, HashContext, std.hash_map.default_max_load_percentage),
    
    // Safety and performance limits
    const MAX_REORG_DEPTH: u32 = 100;
    const MAX_ORPHANS: usize = 50;
    const MAX_RECENT_BLOCKS: usize = 1000;
    const ORPHAN_TIMEOUT_SECONDS: i64 = 3600; // 1 hour
    const RECENT_BLOCK_TIMEOUT_SECONDS: i64 = 1800; // 30 minutes
    
    // Hash context for BlockHash
    const HashContext = struct {
        pub fn hash(self: @This(), key: BlockHash) u64 {
            _ = self;
            return std.hash_map.hashString(&key);
        }
        
        pub fn eql(self: @This(), a: BlockHash, b: BlockHash) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) ForkManager {
        return ForkManager{
            .allocator = allocator,
            .chains = [_]?ChainState{null} ** 3,
            .active_chain_index = 0,
            .orphan_blocks = HashMap(BlockHash, ForkBlock, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .recent_blocks = HashMap(BlockHash, void, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *ForkManager) void {
        self.orphan_blocks.deinit();
        self.recent_blocks.deinit();
    }
    
    /// Initialize with genesis chain
    pub fn initWithGenesis(self: *ForkManager, genesis_hash: BlockHash, genesis_work: ChainWork) void {
        self.chains[0] = ChainState.init(genesis_hash, genesis_work);
        self.active_chain_index = 0;
        print("🔗 Fork manager initialized with genesis chain\n", .{});
    }
    
    /// Get the currently active chain
    pub fn getActiveChain(self: *const ForkManager) ?ChainState {
        return self.chains[self.active_chain_index];
    }
    
    /// Check if a block hash was recently seen
    pub fn wasRecentlySeen(self: *ForkManager, block_hash: BlockHash) bool {
        return self.recent_blocks.contains(block_hash);
    }
    
    /// Mark a block as recently seen
    pub fn markAsSeen(self: *ForkManager, block_hash: BlockHash) !void {
        // Clean up old entries if we're getting too large
        if (self.recent_blocks.count() > MAX_RECENT_BLOCKS) {
            self.cleanupRecentBlocks();
        }
        
        try self.recent_blocks.put(block_hash, {});
    }
    
    /// Evaluate if a new block creates a better chain
    pub fn evaluateBlock(self: *ForkManager, block: Block, block_height: u32, cumulative_work: ChainWork) !ForkDecision {
        const block_hash = block.hash();
        
        // Check if we've seen this block recently
        if (self.wasRecentlySeen(block_hash)) {
            return ForkDecision.already_seen;
        }
        
        // Mark as seen
        try self.markAsSeen(block_hash);
        
        // Find which chain this block extends (if any)
        for (self.chains, 0..) |maybe_chain, i| {
            if (maybe_chain) |chain| {
                if (std.mem.eql(u8, &block.header.previous_hash, &chain.tip_hash)) {
                    // Block extends this chain
                    const new_chain = ChainState{
                        .tip_hash = block_hash,
                        .tip_height = block_height,
                        .cumulative_work = cumulative_work,
                    };
                    
                    return ForkDecision{
                        .extends_chain = .{
                            .chain_index = @intCast(i),
                            .new_chain_state = new_chain,
                            .is_new_best = self.isNewBestChain(new_chain),
                        }
                    };
                }
            }
        }
        
        // Block doesn't extend any known chain - it's an orphan or fork
        return self.handleOrphanBlock(block, block_height, cumulative_work);
    }
    
    /// Check if a chain has more work than the current best
    fn isNewBestChain(self: *const ForkManager, candidate_chain: ChainState) bool {
        const active_chain = self.getActiveChain() orelse return true;
        return candidate_chain.hasMoreWork(active_chain);
    }
    
    /// Handle orphan block (doesn't extend any known chain)
    fn handleOrphanBlock(self: *ForkManager, block: Block, block_height: u32, cumulative_work: ChainWork) !ForkDecision {
        const block_hash = block.hash();
        
        // Check if we already have this orphan
        if (self.orphan_blocks.contains(block_hash)) {
            return ForkDecision.already_seen;
        }
        
        // Clean up old orphans if we're at the limit
        if (self.orphan_blocks.count() >= MAX_ORPHANS) {
            self.cleanupOrphans();
        }
        
        // Store as orphan
        const fork_block = ForkBlock{
            .block = block,
            .height = block_height,
            .cumulative_work = cumulative_work,
            .received_time = util.getTime(),
        };
        
        try self.orphan_blocks.put(block_hash, fork_block);
        
        print("🔀 Stored orphan block at height {} (total orphans: {})\n", .{ block_height, self.orphan_blocks.count() });
        
        return ForkDecision.orphan_stored;
    }
    
    /// Update chain state after accepting a block
    pub fn updateChain(self: *ForkManager, chain_index: u8, new_chain_state: ChainState) void {
        if (chain_index < 3) {
            self.chains[chain_index] = new_chain_state;
            
            // Check if this becomes the new best chain
            if (self.isNewBestChain(new_chain_state)) {
                print("🏆 Chain {} is now the best chain (work: {})\n", .{ chain_index, new_chain_state.cumulative_work });
                self.active_chain_index = chain_index;
            }
        }
    }
    
    /// Check if reorganization would be too deep
    pub fn isReorgTooDeep(self: *const ForkManager, from_height: u32, to_height: u32) bool {
        _ = self; // Only used for constants
        const depth = if (from_height > to_height) from_height - to_height else to_height - from_height;
        return depth > MAX_REORG_DEPTH;
    }
    
    /// Clean up old orphan blocks
    fn cleanupOrphans(self: *ForkManager) void {
        const current_time = util.getTime();
        var to_remove = ArrayList(BlockHash).init(self.allocator);
        defer to_remove.deinit();
        
        var iterator = self.orphan_blocks.iterator();
        while (iterator.next()) |entry| {
            if (current_time - entry.value_ptr.received_time > ORPHAN_TIMEOUT_SECONDS) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (to_remove.items) |hash| {
            _ = self.orphan_blocks.remove(hash);
        }
        
        if (to_remove.items.len > 0) {
            print("🧹 Cleaned up {} old orphan blocks\n", .{to_remove.items.len});
        }
    }
    
    /// Clean up old recent blocks
    fn cleanupRecentBlocks(self: *ForkManager) void {
        // Simple strategy: clear half when full
        const to_remove = self.recent_blocks.count() / 2;
        var removed: usize = 0;
        
        var iterator = self.recent_blocks.iterator();
        while (iterator.next()) |entry| {
            if (removed >= to_remove) break;
            _ = self.recent_blocks.remove(entry.key_ptr.*);
            removed += 1;
        }
        
        print("🧹 Cleaned up {} recent block entries\n", .{removed});
    }
    
    /// Get statistics for debugging
    pub fn getStats(self: *const ForkManager) ForkStats {
        var active_chains: u8 = 0;
        for (self.chains) |maybe_chain| {
            if (maybe_chain != null) active_chains += 1;
        }
        
        return ForkStats{
            .active_chains = active_chains,
            .orphan_blocks = @intCast(self.orphan_blocks.count()),
            .recent_blocks = @intCast(self.recent_blocks.count()),
            .active_chain_work = if (self.getActiveChain()) |chain| chain.cumulative_work else 0,
        };
    }
};

/// Decision about what to do with a new block
pub const ForkDecision = union(enum) {
    already_seen: void,
    orphan_stored: void,
    extends_chain: struct {
        chain_index: u8,
        new_chain_state: ChainState,
        is_new_best: bool,
    },
};

/// Fork manager statistics
pub const ForkStats = struct {
    active_chains: u8,
    orphan_blocks: u32,
    recent_blocks: u32,
    active_chain_work: ChainWork,
};

// Tests
const testing = std.testing;

test "fork manager initialization" {
    var fork_manager = ForkManager.init(testing.allocator);
    defer fork_manager.deinit();
    
    const genesis_hash = std.mem.zeroes(BlockHash);
    fork_manager.initWithGenesis(genesis_hash, 1000);
    
    const active_chain = fork_manager.getActiveChain().?;
    try testing.expectEqual(@as(u32, 0), active_chain.tip_height);
    try testing.expectEqual(@as(ChainWork, 1000), active_chain.cumulative_work);
}

test "chain comparison" {
    const chain1 = ChainState.init(std.mem.zeroes(BlockHash), 1000);
    const chain2 = ChainState.init(std.mem.zeroes(BlockHash), 2000);
    
    try testing.expect(chain2.hasMoreWork(chain1));
    try testing.expect(!chain1.hasMoreWork(chain2));
}