// sidechains.zig - Modern Side Chain Management
// Memory-safe storage and evaluation of competing blockchain branches
// Enables efficient reorganization without re-downloading blocks

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const fork_types = @import("types.zig");

// Type aliases
const Block = types.Block;
const BlockHash = types.BlockHash;
const Hash = types.Hash;
const ChainWork = types.ChainWork;
const HashContext = fork_types.HashContext;

// Configuration constants
const MAX_SIDE_CHAINS: usize = 10;              // Maximum number of side chains to track
const MAX_BLOCKS_PER_CHAIN: usize = 100;       // Maximum blocks per side chain
const MAX_MEMORY_BYTES: usize = 100 * 1024 * 1024; // 100MB memory limit
const CHAIN_TIMEOUT_SECONDS: i64 = 3600;        // 1 hour
const CHAIN_INACTIVE_SECONDS: i64 = 1800;       // 30 minutes

/// Action to take after evaluating a side chain
pub const ChainAction = enum {
    trigger_reorganization,  // Side chain is now best chain
    stored,                 // Block stored successfully
    rejected,              // Block rejected (limits/invalid)
    keep_monitoring,       // Continue tracking this chain
    mark_for_cleanup,      // Chain is stale/inactive
};

/// Information about a side chain
pub const SideChainInfo = struct {
    blocks: ArrayList(Block),      // Blocks in this side chain
    root_hash: BlockHash,          // Where it forks from main chain
    root_height: u32,              // Height where fork occurred
    tip_hash: BlockHash,           // Current tip of side chain
    tip_height: u32,               // Current height of side chain
    cumulative_work: ChainWork,    // Total proof of work
    created_time: i64,             // For pruning old chains
    last_extended: i64,            // Last time chain was extended
    estimated_memory: usize,       // Estimated memory usage
    
    /// Initialize a new side chain
    pub fn init(allocator: std.mem.Allocator, root_hash: BlockHash, root_height: u32) SideChainInfo {
        return .{
            .blocks = ArrayList(Block).init(allocator),
            .root_hash = root_hash,
            .root_height = root_height,
            .tip_hash = root_hash,
            .tip_height = root_height,
            .cumulative_work = 0,
            .created_time = util.getTime(),
            .last_extended = util.getTime(),
            .estimated_memory = 0,
        };
    }
    
    /// Clean up resources
    pub fn deinit(self: *SideChainInfo, allocator: std.mem.Allocator) void {
        // Free all blocks in the chain
        for (self.blocks.items) |*block| {
            block.deinit(allocator);
        }
        self.blocks.deinit();
    }
    
    /// Add a block to this side chain
    pub fn addBlock(self: *SideChainInfo, block: Block, block_work: ChainWork) !void {
        const block_size = @sizeOf(Block) + (block.transactions.len * @sizeOf(types.Transaction));
        
        // Check if we're at capacity
        if (self.blocks.items.len >= MAX_BLOCKS_PER_CHAIN) {
            return error.ChainCapacityExceeded;
        }
        
        // Update chain info
        self.tip_hash = block.hash();
        self.tip_height += 1;
        self.cumulative_work += block_work;
        self.last_extended = util.getTime();
        self.estimated_memory += block_size;
        
        // Store the block
        try self.blocks.append(block);
    }
};

/// Memory usage tracker
const MemoryTracker = struct {
    total_bytes: usize,
    chain_count: usize,
    block_count: usize,
    
    pub fn init() MemoryTracker {
        return .{
            .total_bytes = 0,
            .chain_count = 0,
            .block_count = 0,
        };
    }
    
    pub fn addChain(self: *MemoryTracker, chain_info: *const SideChainInfo) void {
        self.chain_count += 1;
        self.block_count += chain_info.blocks.items.len;
        self.total_bytes += chain_info.estimated_memory;
    }
    
    pub fn removeChain(self: *MemoryTracker, chain_info: *const SideChainInfo) void {
        self.chain_count -= 1;
        self.block_count -= chain_info.blocks.items.len;
        self.total_bytes -= chain_info.estimated_memory;
    }
    
    pub fn isAtLimit(self: *const MemoryTracker) bool {
        return self.total_bytes >= MAX_MEMORY_BYTES or self.chain_count >= MAX_SIDE_CHAINS;
    }
};

/// Modern side chain manager with memory-safe operations
pub const SideChainManager = struct {
    allocator: std.mem.Allocator,
    
    // Side chain storage keyed by tip hash
    side_chains: HashMap(BlockHash, SideChainInfo, HashContext, std.hash_map.default_max_load_percentage),
    
    // Index: parent hash -> child hashes for efficient lookups
    parent_index: HashMap(BlockHash, ArrayList(BlockHash), HashContext, std.hash_map.default_max_load_percentage),
    
    // Memory tracking
    memory_tracker: MemoryTracker,
    
    // Statistics
    total_blocks_stored: u64,
    total_chains_created: u64,
    total_reorgs_triggered: u64,
    
    const Self = @This();
    
    /// Initialize the side chain manager
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .side_chains = HashMap(BlockHash, SideChainInfo, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .parent_index = HashMap(BlockHash, ArrayList(BlockHash), HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .memory_tracker = MemoryTracker.init(),
            .total_blocks_stored = 0,
            .total_chains_created = 0,
            .total_reorgs_triggered = 0,
        };
    }
    
    /// Clean up all resources
    pub fn deinit(self: *Self) void {
        // Clean up all side chains
        var chain_iter = self.side_chains.iterator();
        while (chain_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.side_chains.deinit();
        
        // Clean up parent index
        var index_iter = self.parent_index.iterator();
        while (index_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.parent_index.deinit();
    }
    
    /// Add a block that doesn't extend the main chain
    pub fn addSideChainBlock(self: *Self, block: Block, parent_hash: BlockHash, parent_height: u32, block_work: ChainWork) !ChainAction {
        const block_hash = block.hash();
        
        print("📦 Processing side chain block: {s}\n", .{std.fmt.fmtSliceHexLower(block_hash[0..8])});
        
        // Check if this extends an existing side chain
        if (self.findChainByTip(parent_hash)) |chain_info| {
            // Extends existing side chain
            try chain_info.addBlock(block, block_work);
            self.total_blocks_stored += 1;
            
            print("📈 Extended side chain: height={}, work={}\n", .{ chain_info.tip_height, chain_info.cumulative_work });
            
            // Update indices
            try self.updateParentIndex(parent_hash, block_hash);
            
            return .stored;
        }
        
        // Check if we're at capacity
        if (self.memory_tracker.isAtLimit()) {
            // Try to make room by cleaning up
            self.pruneOldChains();
            
            if (self.memory_tracker.isAtLimit()) {
                print("❌ Side chain storage at capacity\n", .{});
                return .rejected;
            }
        }
        
        // Create new side chain
        var new_chain = SideChainInfo.init(self.allocator, parent_hash, parent_height);
        try new_chain.addBlock(block, block_work);
        
        try self.side_chains.put(block_hash, new_chain);
        self.memory_tracker.addChain(&new_chain);
        self.total_chains_created += 1;
        self.total_blocks_stored += 1;
        
        // Update indices
        try self.updateParentIndex(parent_hash, block_hash);
        
        print("🌿 Created new side chain: root={s}, height={}\n", .{
            std.fmt.fmtSliceHexLower(parent_hash[0..8]),
            parent_height,
        });
        
        return .stored;
    }
    
    /// Find a side chain by its tip hash
    fn findChainByTip(self: *Self, tip_hash: BlockHash) ?*SideChainInfo {
        if (self.side_chains.getPtr(tip_hash)) |chain| {
            return chain;
        }
        
        // Also check if any chain contains this block
        var iter = self.side_chains.iterator();
        while (iter.next()) |entry| {
            for (entry.value_ptr.blocks.items) |block| {
                if (std.mem.eql(u8, &block.hash(), &tip_hash)) {
                    return entry.value_ptr;
                }
            }
        }
        
        return null;
    }
    
    /// Update parent-child index
    fn updateParentIndex(self: *Self, parent_hash: BlockHash, child_hash: BlockHash) !void {
        const entry = try self.parent_index.getOrPut(parent_hash);
        if (!entry.found_existing) {
            entry.value_ptr.* = ArrayList(BlockHash).init(self.allocator);
        }
        try entry.value_ptr.append(child_hash);
    }
    
    /// Evaluate if any side chain should trigger reorganization
    pub fn evaluateSideChains(self: *Self, main_chain_work: ChainWork) ?*SideChainInfo {
        var best_chain: ?*SideChainInfo = null;
        var best_work: ChainWork = main_chain_work;
        
        var iter = self.side_chains.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.cumulative_work > best_work) {
                best_work = entry.value_ptr.cumulative_work;
                best_chain = entry.value_ptr;
            }
        }
        
        if (best_chain) |chain| {
            print("🏆 Side chain has more work: {} > {}\n", .{ chain.cumulative_work, main_chain_work });
            self.total_reorgs_triggered += 1;
        }
        
        return best_chain;
    }
    
    /// Get blocks for reorganization (ownership transferred to caller)
    pub fn extractChainBlocks(self: *Self, chain_tip: BlockHash) !ArrayList(Block) {
        if (self.side_chains.fetchRemove(chain_tip)) |kv| {
            var chain_info = kv.value;
            self.memory_tracker.removeChain(&chain_info);
            
            // Transfer ownership of blocks
            const blocks = chain_info.blocks;
            chain_info.blocks = ArrayList(Block).init(self.allocator); // Empty list
            chain_info.deinit(self.allocator);
            
            return blocks;
        }
        
        return error.ChainNotFound;
    }
    
    /// Prune old and inactive chains
    pub fn pruneOldChains(self: *Self) void {
        const current_time = util.getTime();
        var chains_to_remove = ArrayList(BlockHash).init(self.allocator);
        defer chains_to_remove.deinit();
        
        var iter = self.side_chains.iterator();
        while (iter.next()) |entry| {
            const chain = entry.value_ptr;
            const age = current_time - chain.created_time;
            const inactive = current_time - chain.last_extended;
            
            if (age > CHAIN_TIMEOUT_SECONDS or inactive > CHAIN_INACTIVE_SECONDS) {
                chains_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (chains_to_remove.items) |tip_hash| {
            if (self.side_chains.fetchRemove(tip_hash)) |kv| {
                var chain_info = kv.value;
                self.memory_tracker.removeChain(&chain_info);
                chain_info.deinit(self.allocator);
                
                print("🗑️ Pruned old side chain: {s}\n", .{std.fmt.fmtSliceHexLower(tip_hash[0..8])});
            }
        }
    }
    
    /// Get statistics
    pub fn getStats(self: *const Self) struct {
        chain_count: usize,
        total_blocks: usize,
        memory_usage: usize,
        total_stored: u64,
        total_chains: u64,
        total_reorgs: u64,
    } {
        return .{
            .chain_count = self.side_chains.count(),
            .total_blocks = self.memory_tracker.block_count,
            .memory_usage = self.memory_tracker.total_bytes,
            .total_stored = self.total_blocks_stored,
            .total_chains = self.total_chains_created,
            .total_reorgs = self.total_reorgs_triggered,
        };
    }
};

// Tests
test "SideChainInfo basic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const root_hash = std.mem.zeroes(BlockHash);
    var chain_info = SideChainInfo.init(allocator, root_hash, 100);
    defer chain_info.deinit(allocator);
    
    try std.testing.expectEqual(@as(u32, 100), chain_info.root_height);
    try std.testing.expectEqual(@as(u32, 100), chain_info.tip_height);
    try std.testing.expectEqual(@as(usize, 0), chain_info.blocks.items.len);
}

test "SideChainManager initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = SideChainManager.init(allocator);
    defer manager.deinit();
    
    const stats = manager.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.chain_count);
    try std.testing.expectEqual(@as(usize, 0), stats.total_blocks);
    try std.testing.expectEqual(@as(usize, 0), stats.memory_usage);
}

test "SideChainManager add and evaluate chains" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = SideChainManager.init(allocator);
    defer manager.deinit();
    
    // Create a test block
    const test_header = types.BlockHeader{
        .version = 0,
        .previous_hash = std.mem.zeroes(BlockHash),
        .merkle_root = std.mem.zeroes(Hash),
        .timestamp = 1234567890,
        .difficulty = 0x1d00ffff,
        .nonce = 42,
        .witness_root = std.mem.zeroes(Hash),
        .state_root = std.mem.zeroes(Hash),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };
    
    const test_block = Block{
        .header = test_header,
        .transactions = try allocator.alloc(types.Transaction, 0),
    };
    defer allocator.free(test_block.transactions);
    
    // Add as side chain block
    const parent_hash = std.mem.zeroes(BlockHash);
    const action = try manager.addSideChainBlock(test_block, parent_hash, 100, 1000);
    
    try std.testing.expectEqual(ChainAction.stored, action);
    
    // Check stats
    const stats = manager.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.chain_count);
    try std.testing.expectEqual(@as(usize, 1), stats.total_blocks);
    try std.testing.expectEqual(@as(u64, 1), stats.total_stored);
    
    // Evaluate - should not trigger reorg with lower work
    const main_chain_work: ChainWork = 2000;
    const better_chain = manager.evaluateSideChains(main_chain_work);
    try std.testing.expectEqual(@as(?*SideChainInfo, null), better_chain);
}