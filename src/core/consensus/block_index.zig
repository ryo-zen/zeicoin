// block_index.zig - ZeiCoin Block Index for Efficient Chain Operations
// Mission-critical consensus infrastructure for ZeiCoin
// Implements efficient O(1) chain operations with cumulative work tracking

const std = @import("std");
const print = std.debug.print;
const types = @import("../types/types.zig");
const work_mod = @import("work.zig");

/// Block validation status flags for tracking validation progress
pub const BlockStatus = packed struct {
    /// Block has valid proof-of-work and basic structure
    valid_header: bool = false,
    /// Block transactions are structurally valid
    valid_transactions: bool = false,
    /// Block passes all consensus rules
    valid_consensus: bool = false,
    /// Block data is stored on disk
    have_data: bool = false,
    /// Block has been applied to chain state
    applied: bool = false,
    /// Block validation failed
    failed: bool = false,
    /// Reserved for future use
    _reserved: u26 = 0,
    
    /// Check if block is fully validated
    pub fn isFullyValid(self: BlockStatus) bool {
        return self.valid_header and self.valid_transactions and self.valid_consensus and !self.failed;
    }
    
    /// Check if block failed validation
    pub fn hasFailed(self: BlockStatus) bool {
        return self.failed;
    }
};

/// ZeiCoin Block Index Entry
/// Stores metadata for O(1) chain operations without loading full blocks
pub const BlockIndex = struct {
    // Block identification
    block_hash: types.Hash,
    height: u32,
    
    // Chain relationships for efficient traversal
    parent: ?*BlockIndex,
    children: std.ArrayList(*BlockIndex),
    skip: ?*BlockIndex, // For O(log n) ancestor lookup
    
    // CRITICAL: Consensus data (must be exact)
    chain_work: work_mod.ChainWork, // Cumulative work from genesis
    status: BlockStatus,
    
    // Block header data (for validation without disk access)
    version: u32,
    previous_hash: types.Hash,
    merkle_root: types.Hash,
    timestamp: u64,
    difficulty_target: types.DifficultyTarget,
    nonce: u32,
    
    // Storage metadata
    file_pos: ?u64, // Position in block file (if stored)
    
    // Memory management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Create new block index entry
    pub fn init(
        allocator: std.mem.Allocator,
        block_hash: types.Hash,
        header: types.BlockHeader,
        height: u32,
        parent: ?*BlockIndex,
    ) !*BlockIndex {
        const self = try allocator.create(BlockIndex);
        
        // Calculate cumulative work (CRITICAL - this is where consensus happens)
        const block_work = header.getWork();
        const parent_work = if (parent) |p| p.chain_work else 0;
        
        // Check for overflow (blockchain too long)
        if (parent_work > work_mod.CONSENSUS.MAX_WORK - block_work) {
            allocator.destroy(self);
            return error.ChainWorkOverflow;
        }
        
        self.* = BlockIndex{
            .block_hash = block_hash,
            .height = height,
            .parent = parent,
            .children = std.ArrayList(*BlockIndex).init(allocator),
            .skip = null, // Will be set by buildSkipList()
            .chain_work = parent_work + block_work, // NEVER recalculate - always increment
            .status = BlockStatus{},
            .version = header.version,
            .previous_hash = header.previous_hash,
            .merkle_root = header.merkle_root,
            .timestamp = header.timestamp,
            .difficulty_target = header.getDifficultyTarget(),
            .nonce = header.nonce,
            .file_pos = null,
            .allocator = allocator,
        };
        
        // Add this block as a child of parent
        if (parent) |p| {
            try p.children.append(self);
        }
        
        return self;
    }
    
    /// Free block index and all children recursively
    pub fn deinit(self: *Self) void {
        // Free all children first
        for (self.children.items) |child| {
            child.deinit();
        }
        self.children.deinit();
        
        // Remove from parent's children list
        if (self.parent) |parent| {
            for (parent.children.items, 0..) |child, i| {
                if (child == self) {
                    _ = parent.children.swapRemove(i);
                    break;
                }
            }
        }
        
        self.allocator.destroy(self);
    }
    
    /// Build skip list pointer for O(log n) ancestor lookup
    pub fn buildSkipList(self: *Self) void {
        if (self.height < 2) {
            self.skip = null;
            return;
        }
        
        // ZeiCoin skip list algorithm (industry standard)
        var skip_height = self.height;
        
        // Find the highest power of 2 that divides height
        while (skip_height % 2 == 0) {
            skip_height /= 2;
        }
        
        // Skip back by that amount
        if (skip_height < self.height) {
            self.skip = self.getAncestor(self.height - skip_height);
        }
    }
    
    /// Get ancestor at specific height (O(log n) with skip list)
    pub fn getAncestor(self: *Self, target_height: u32) ?*BlockIndex {
        if (target_height > self.height) {
            return null;
        }
        
        if (target_height == self.height) {
            return self;
        }
        
        // Use skip list for efficient traversal
        if (self.skip) |skip| {
            if (skip.height >= target_height) {
                return skip.getAncestor(target_height);
            }
        }
        
        // Fall back to parent traversal
        if (self.parent) |parent| {
            return parent.getAncestor(target_height);
        }
        
        return null;
    }
    
    /// Find last common ancestor with another block (for reorg calculations)
    pub fn findCommonAncestor(self: *Self, other: *BlockIndex) ?*BlockIndex {
        var a: ?*BlockIndex = self;
        var b: ?*BlockIndex = other;
        
        // Move to same height
        while (a != null and b != null and a.?.height != b.?.height) {
            if (a.?.height > b.?.height) {
                a = a.?.parent;
            } else {
                b = b.?.parent;
            }
        }
        
        // Walk back until we find common ancestor
        while (a != null and b != null and a != b) {
            a = a.?.parent;
            b = b.?.parent;
        }
        
        return a;
    }
    
    /// Check if this block is an ancestor of another block
    pub fn isAncestorOf(self: *Self, descendant: *BlockIndex) bool {
        if (self.height >= descendant.height) {
            return false;
        }
        
        const ancestor = descendant.getAncestor(self.height);
        return ancestor == self;
    }
    
    /// Get best child (highest work) for chain selection
    pub fn getBestChild(self: *Self) ?*BlockIndex {
        if (self.children.items.len == 0) {
            return null;
        }
        
        var best: *BlockIndex = self.children.items[0];
        for (self.children.items[1..]) |child| {
            if (child.chain_work > best.chain_work) {
                best = child;
            }
        }
        
        return best;
    }
    
    /// Update validation status (atomic operation)
    pub fn setStatus(self: *Self, status: BlockStatus) void {
        self.status = status;
    }
    
    /// Mark block as having valid header
    pub fn markHeaderValid(self: *Self) void {
        self.status.valid_header = true;
    }
    
    /// Mark block as having valid transactions
    pub fn markTransactionsValid(self: *Self) void {
        self.status.valid_transactions = true;
    }
    
    /// Mark block as fully validated
    pub fn markFullyValid(self: *Self) void {
        self.status.valid_header = true;
        self.status.valid_transactions = true;
        self.status.valid_consensus = true;
    }
    
    /// Mark block as failed
    pub fn markFailed(self: *Self) void {
        self.status.failed = true;
    }
    
    /// Get block header for validation (without loading full block)
    pub fn getHeader(self: *Self) types.BlockHeader {
        return types.BlockHeader{
            .version = self.version,
            .previous_hash = self.previous_hash,
            .merkle_root = self.merkle_root,
            .timestamp = self.timestamp,
            .difficulty = self.difficulty_target.toU64(),
            .nonce = self.nonce,
            .witness_root = std.mem.zeroes(types.Hash),
            .state_root = std.mem.zeroes(types.Hash),
            .extra_nonce = 0,
        };
    }
    
    /// Validate chain work consistency (for debugging)
    pub fn validateChainWork(self: *Self) bool {
        if (self.parent) |parent| {
            const header = self.getHeader();
            const expected_work = parent.chain_work + header.getWork();
            if (self.chain_work != expected_work) {
                print("❌ Chain work inconsistency at height {}: expected {}, got {}\n", 
                    .{self.height, expected_work, self.chain_work});
                return false;
            }
        }
        return true;
    }
};

/// Block index manager - maintains the complete block tree
pub const BlockIndexManager = struct {
    // Block lookup (simplified approach)
    height_index: std.ArrayList(?*BlockIndex), // Index by height
    hash_to_height: std.HashMap(types.Hash, u32, std.hash_map.DefaultContext(types.Hash), std.hash_map.default_max_load_percentage), // Hash to height lookup
    
    // Chain tips (blocks with no children)
    tips: std.ArrayList(*BlockIndex),
    
    // Active chain tip (highest work)
    active_tip: ?*BlockIndex,
    
    // Memory management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize block index manager
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .height_index = std.ArrayList(?*BlockIndex).init(allocator),
            .hash_to_height = std.HashMap(types.Hash, u32, std.hash_map.DefaultContext(types.Hash), std.hash_map.default_max_load_percentage).init(allocator),
            .tips = std.ArrayList(*BlockIndex).init(allocator),
            .active_tip = null,
            .allocator = allocator,
        };
    }
    
    /// Cleanup all block index entries
    pub fn deinit(self: *Self) void {
        // Free all block index entries
        for (self.height_index.items) |maybe_block| {
            if (maybe_block) |block| {
                block.deinit();
            }
        }
        
        self.height_index.deinit();
        self.hash_to_height.deinit();
        self.tips.deinit();
    }
    
    /// Add new block to index
    pub fn addBlock(
        self: *Self,
        block_hash: types.Hash,
        header: types.BlockHeader,
        height: u32,
    ) !*BlockIndex {
        // Find parent block
        const parent = if (height > 0) self.getBlockByHash(header.previous_hash) else null;
        
        // Create block index entry
        const block_index = try BlockIndex.init(
            self.allocator,
            block_hash,
            header,
            height,
            parent,
        );
        
        // Ensure height_index is large enough
        while (self.height_index.items.len <= height) {
            try self.height_index.append(null);
        }
        
        // Add to lookup structures
        self.height_index.items[height] = block_index;
        try self.hash_to_height.put(block_hash, height);
        
        // Update tips list
        try self.updateTips(block_index);
        
        // Build skip list for efficient ancestor lookup
        block_index.buildSkipList();
        
        // Update active tip if this chain has more work
        self.updateActiveTip();
        
        return block_index;
    }
    
    /// Update tips list when new block is added
    fn updateTips(self: *Self, new_block: *BlockIndex) !void {
        // Remove parent from tips if it exists
        if (new_block.parent) |parent| {
            for (self.tips.items, 0..) |tip, i| {
                if (tip == parent) {
                    _ = self.tips.swapRemove(i);
                    break;
                }
            }
        }
        
        // Add new block as tip
        try self.tips.append(new_block);
    }
    
    /// Update active tip to highest work chain
    fn updateActiveTip(self: *Self) void {
        if (self.tips.items.len == 0) {
            self.active_tip = null;
            return;
        }
        
        var best: *BlockIndex = self.tips.items[0];
        for (self.tips.items[1..]) |tip| {
            if (tip.chain_work > best.chain_work) {
                best = tip;
            }
        }
        
        self.active_tip = best;
    }
    
    /// Get block by hash (O(1))
    pub fn getBlockByHash(self: *Self, hash: types.Hash) ?*BlockIndex {
        const height = self.hash_to_height.get(hash) orelse return null;
        if (height >= self.height_index.items.len) return null;
        return self.height_index.items[height];
    }
    
    /// Get block by height (O(1) - but only for main chain)
    pub fn getBlockByHeight(self: *Self, height: u32) ?*BlockIndex {
        if (height >= self.height_index.items.len) return null;
        return self.height_index.items[height];
    }
    
    /// Get active chain tip
    pub fn getActiveTip(self: *Self) ?*BlockIndex {
        return self.active_tip;
    }
    
    /// Get all chain tips
    pub fn getTips(self: *Self) []const *BlockIndex {
        return self.tips.items;
    }
    
    /// Validate entire index consistency
    pub fn validateIndex(self: *Self) bool {
        for (self.height_index.items) |maybe_block| {
            if (maybe_block) |block| {
                if (!block.validateChainWork()) {
                    return false;
                }
            }
        }
        return true;
    }
};

// =============================================================================
// COMPREHENSIVE TEST SUITE FOR ZEICOIN CONSENSUS
// =============================================================================

const testing = std.testing;

test "block index basic operations" {
    var manager = BlockIndexManager.init(testing.allocator);
    defer manager.deinit();
    
    // Create genesis block
    const genesis_hash = types.Hash{0} ** 32;
    const genesis_header = types.BlockHeader{
        .version = 1,
        .previous_hash = std.mem.zeroes(types.Hash),
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 1234567890,
        .difficulty = 0x1d00ffff,
        .nonce = 12345,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    const genesis_index = try manager.addBlock(genesis_hash, genesis_header, 0);
    
    // Verify genesis
    try testing.expect(genesis_index.height == 0);
    try testing.expect(genesis_index.parent == null);
    try testing.expect(genesis_index.chain_work > 0);
    
    // Verify manager state
    try testing.expect(manager.getActiveTip() == genesis_index);
    try testing.expect(manager.getBlockByHeight(0) == genesis_index);
}

test "chain work accumulation" {
    var manager = BlockIndexManager.init(testing.allocator);
    defer manager.deinit();
    
    // Create genesis
    const genesis_hash = types.Hash{1} ** 32;
    const genesis_header = types.BlockHeader{
        .version = 1,
        .previous_hash = std.mem.zeroes(types.Hash),
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 1000,
        .difficulty = 0x1d00ffff,
        .nonce = 1,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    const genesis = try manager.addBlock(genesis_hash, genesis_header, 0);
    const genesis_work = genesis.chain_work;
    
    // Add block 1
    const block1_hash = types.Hash{2} ** 32;
    const block1_header = types.BlockHeader{
        .version = 1,
        .previous_hash = genesis_hash,
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 2000,
        .difficulty = 0x1d00ffff,
        .nonce = 2,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    const block1 = try manager.addBlock(block1_hash, block1_header, 1);
    
    // Verify work accumulation
    try testing.expect(block1.chain_work > genesis_work);
    try testing.expect(block1.parent == genesis);
    try testing.expect(manager.getActiveTip() == block1);
}

test "fork detection and best chain selection" {
    var manager = BlockIndexManager.init(testing.allocator);
    defer manager.deinit();
    
    // Create genesis
    const genesis_hash = types.Hash{1} ** 32;
    const genesis_header = types.BlockHeader{
        .version = 1,
        .previous_hash = std.mem.zeroes(types.Hash),
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 1000,
        .difficulty = 0x1d00ffff,
        .nonce = 1,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    _ = try manager.addBlock(genesis_hash, genesis_header, 0);
    
    // Create fork A (lower difficulty)
    const fork_a_hash = types.Hash{2} ** 32;
    const fork_a_header = types.BlockHeader{
        .version = 1,
        .previous_hash = genesis_hash,
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 2000,
        .difficulty = 0x1d00ffff, // Same difficulty
        .nonce = 2,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    const fork_a = try manager.addBlock(fork_a_hash, fork_a_header, 1);
    
    // Create fork B (higher difficulty - should win)
    const fork_b_hash = types.Hash{3} ** 32;
    const fork_b_header = types.BlockHeader{
        .version = 1,
        .previous_hash = genesis_hash,
        .merkle_root = std.mem.zeroes(types.Hash),
        .timestamp = 2000,
        .difficulty = 0x1e00ffff, // Higher difficulty
        .nonce = 3,
        .witness_root = std.mem.zeroes(types.Hash),
        .state_root = std.mem.zeroes(types.Hash),
        .extra_nonce = 0,
    };
    
    const fork_b = try manager.addBlock(fork_b_hash, fork_b_header, 1);
    
    // Verify best chain selection
    try testing.expect(fork_b.chain_work > fork_a.chain_work);
    try testing.expect(manager.getActiveTip() == fork_b);
    try testing.expect(manager.getTips().len == 2); // Two competing tips
}