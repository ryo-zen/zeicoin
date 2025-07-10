// orphans.zig - Orphan Block Management
// Handles orphan blocks waiting for parents and cleanup

const std = @import("std");
const print = std.debug.print;
const HashMap = std.HashMap;

const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const fork_types = @import("types.zig");

const Block = types.Block;
const BlockHash = types.BlockHash;
const ForkBlock = types.ForkBlock;
const HashContext = fork_types.HashContext;

/// Orphan block manager
pub const OrphanManager = struct {
    allocator: std.mem.Allocator,
    
    // Orphan blocks waiting for parents
    orphan_blocks: HashMap(BlockHash, ForkBlock, HashContext, std.hash_map.default_max_load_percentage),
    
    // Recently seen blocks (prevent re-processing)
    recent_blocks: HashMap(BlockHash, void, HashContext, std.hash_map.default_max_load_percentage),
    
    // Safety and performance limits
    const MAX_ORPHANS: usize = 50;
    const MAX_RECENT_BLOCKS: usize = 1000;
    const ORPHAN_TIMEOUT_SECONDS: i64 = 3600; // 1 hour
    const RECENT_BLOCK_TIMEOUT_SECONDS: i64 = 1800; // 30 minutes
    
    pub fn init(allocator: std.mem.Allocator) OrphanManager {
        return OrphanManager{
            .allocator = allocator,
            .orphan_blocks = HashMap(BlockHash, ForkBlock, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .recent_blocks = HashMap(BlockHash, void, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    pub fn deinit(self: *OrphanManager) void {
        // Free all orphan blocks before deinitializing the HashMap
        var iterator = self.orphan_blocks.iterator();
        while (iterator.next()) |entry| {
            var block_to_free = entry.value_ptr.block;
            block_to_free.deinit(self.allocator);
        }
        
        self.orphan_blocks.deinit();
        self.recent_blocks.deinit();
    }
    
    /// Check if a block hash was recently seen
    pub fn wasRecentlySeen(self: *OrphanManager, block_hash: BlockHash) bool {
        return self.recent_blocks.contains(block_hash);
    }
    
    /// Mark a block as recently seen
    pub fn markAsSeen(self: *OrphanManager, block_hash: BlockHash) !void {
        // Clean up old entries if we're getting too large
        if (self.recent_blocks.count() > MAX_RECENT_BLOCKS) {
            self.cleanupRecentBlocks();
        }
        
        try self.recent_blocks.put(block_hash, {});
    }
    
    /// Store an orphan block
    pub fn storeOrphan(self: *OrphanManager, block: Block, received_time: i64) !void {
        // Don't store if we're at capacity
        if (self.orphan_blocks.count() >= MAX_ORPHANS) {
            print("⚠️  Orphan block storage at capacity, cleaning up old blocks\n", .{});
            self.cleanupOrphanBlocks();
            
            // If still at capacity after cleanup, reject the block
            if (self.orphan_blocks.count() >= MAX_ORPHANS) {
                print("❌ Cannot store orphan block - storage full\n", .{});
                return;
            }
        }
        
        const block_hash = block.hash();
        const fork_block = ForkBlock{
            .block = block,
            .height = 0, // Unknown height for orphan
            .cumulative_work = 0, // Unknown cumulative work for orphan
            .received_time = received_time,
        };
        
        try self.orphan_blocks.put(block_hash, fork_block);
        print("📦 Stored orphan block: {s}\n", .{std.fmt.fmtSliceHexLower(block_hash[0..8])});
    }
    
    /// Cleanup old orphan blocks based on timeout
    pub fn cleanupOrphanBlocks(self: *OrphanManager) void {
        const current_time = util.getTime();
        var blocks_to_remove = std.ArrayList(BlockHash).init(self.allocator);
        defer blocks_to_remove.deinit();
        
        var iterator = self.orphan_blocks.iterator();
        while (iterator.next()) |entry| {
            const age = current_time - entry.value_ptr.received_time;
            if (age > ORPHAN_TIMEOUT_SECONDS) {
                blocks_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (blocks_to_remove.items) |hash| {
            if (self.orphan_blocks.fetchRemove(hash)) |kv| {
                var block_to_free = kv.value.block;
                block_to_free.deinit(self.allocator);
                print("🗑️  Removed expired orphan block: {s}\n", .{std.fmt.fmtSliceHexLower(hash[0..8])});
            }
        }
    }
    
    /// Cleanup old recent blocks based on timeout
    pub fn cleanupRecentBlocks(self: *OrphanManager) void {
        // For simplicity, just clear half of the recent blocks when we hit the limit
        // In a production system, you'd want to track timestamps and remove based on age
        var count: usize = 0;
        const target_count = MAX_RECENT_BLOCKS / 2;
        
        var iterator = self.recent_blocks.iterator();
        var blocks_to_remove = std.ArrayList(BlockHash).init(self.allocator);
        defer blocks_to_remove.deinit();
        
        while (iterator.next()) |entry| {
            if (count >= target_count) break;
            blocks_to_remove.append(entry.key_ptr.*) catch continue;
            count += 1;
        }
        
        for (blocks_to_remove.items) |hash| {
            _ = self.recent_blocks.remove(hash);
        }
        
        print("🧹 Cleaned up {} recent blocks\n", .{blocks_to_remove.items.len});
    }
    
    /// Get orphan count
    pub fn getOrphanCount(self: *const OrphanManager) usize {
        return self.orphan_blocks.count();
    }
    
    /// Get recent blocks count
    pub fn getRecentBlocksCount(self: *const OrphanManager) usize {
        return self.recent_blocks.count();
    }
};