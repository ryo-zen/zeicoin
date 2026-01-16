// orphan_pool.zig - Storage for orphan blocks (blocks whose parent we don't have yet)

const std = @import("std");
const types = @import("../types/types.zig");
const Block = types.Block;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.orphan_pool);

/// Storage for orphan blocks (blocks whose parent we don't have yet)
pub const OrphanPool = struct {
    allocator: Allocator,

    /// Map: parent_hash -> list of orphan blocks waiting for that parent
    /// Key is the parent hash, value is list of blocks that reference it
    orphans_by_parent: std.AutoHashMap([32]u8, std.ArrayList(Block)),

    /// Map: block_hash -> block (for quick duplicate detection)
    orphans_by_hash: std.AutoHashMap([32]u8, void),

    /// Total number of orphan blocks stored
    total_orphans: usize,

    /// Maximum orphan blocks allowed (prevent memory bloat)
    max_orphans: usize,

    /// Statistics
    stats: Stats,

    pub const Stats = struct {
        orphans_added: u64 = 0,
        orphans_processed: u64 = 0,
        orphans_evicted: u64 = 0,
        orphans_expired: u64 = 0,
    };

    pub const MAX_ORPHANS_DEFAULT: usize = 100;

    pub fn init(allocator: Allocator, max_orphans: usize) OrphanPool {
        return .{
            .allocator = allocator,
            .orphans_by_parent = std.AutoHashMap([32]u8, std.ArrayList(Block)).init(allocator),
            .orphans_by_hash = std.AutoHashMap([32]u8, void).init(allocator),
            .total_orphans = 0,
            .max_orphans = max_orphans,
            .stats = .{},
        };
    }

    pub fn deinit(self: *OrphanPool) void {
        // Clean up all orphan blocks
        var it = self.orphans_by_parent.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |*block| {
                block.deinit(self.allocator);
            }
            entry.value_ptr.deinit();
        }
        self.orphans_by_parent.deinit();
        self.orphans_by_hash.deinit();
    }

    /// Add an orphan block to the pool
    pub fn addOrphan(self: *OrphanPool, block: Block) !void {
        const block_hash = block.hash();
        const parent_hash = block.header.previous_hash;

        // Check if we already have this orphan
        if (self.orphans_by_hash.contains(block_hash)) {
            log.debug("Orphan block already in pool: {s}", .{
                std.fmt.fmtSliceHexLower(&block_hash),
            });
            return error.DuplicateOrphan;
        }

        // Check capacity
        if (self.total_orphans >= self.max_orphans) {
            log.warn("Orphan pool full ({}/{}), evicting oldest", .{
                self.total_orphans,
                self.max_orphans,
            });
            try self.evictOldest();
        }

        // Get or create list for this parent hash
        const gop = try self.orphans_by_parent.getOrPut(parent_hash);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.ArrayList(Block).init(self.allocator);
        }

        // Add block to list
        try gop.value_ptr.append(block);

        // Track in hash map
        try self.orphans_by_hash.put(block_hash, {});

        self.total_orphans += 1;
        self.stats.orphans_added += 1;

        log.info("[ORPHAN] Added orphan block (height {}, total orphans: {})", .{
            block.height,
            self.total_orphans,
        });
        log.debug("   Parent needed: {s}", .{
            std.fmt.fmtSliceHexLower(&parent_hash),
        });
    }

    /// Get all orphan blocks that have this parent hash
    /// Returns ownership of the blocks (caller must deinit them)
    pub fn getOrphansByParent(self: *OrphanPool, parent_hash: [32]u8) ?[]Block {
        const entry = self.orphans_by_parent.getEntry(parent_hash) orelse return null;

        const blocks = entry.value_ptr.items;
        if (blocks.len == 0) return null;

        // Remove from tracking maps
        for (blocks) |block| {
            const block_hash = block.hash();
            _ = self.orphans_by_hash.remove(block_hash);
            self.total_orphans -= 1;
            self.stats.orphans_processed += 1;
        }

        // Remove the entry and return the blocks
        const owned_list = entry.value_ptr.*;
        _ = self.orphans_by_parent.remove(parent_hash);

        log.info("[ORPHAN] Found {} orphan(s) ready for processing", .{blocks.len});

        return owned_list.items;
    }

    /// Check if we have any orphans waiting for this parent
    pub fn hasOrphansForParent(self: *OrphanPool, parent_hash: [32]u8) bool {
        if (self.orphans_by_parent.get(parent_hash)) |list| {
            return list.items.len > 0;
        }
        return false;
    }

    /// Get list of all missing parent hashes (for requesting from peers)
    pub fn getMissingParentHashes(self: *OrphanPool, allocator: Allocator) ![]const [32]u8 {
        var hashes = std.ArrayList([32]u8).init(allocator);
        errdefer hashes.deinit();

        var it = self.orphans_by_parent.keyIterator();
        while (it.next()) |parent_hash| {
            try hashes.append(parent_hash.*);
        }

        return hashes.toOwnedSlice();
    }

    /// Evict oldest orphan block to make room
    fn evictOldest(self: *OrphanPool) !void {
        // Simple strategy: remove first entry found
        // Could be improved with timestamp tracking
        var it = self.orphans_by_parent.iterator();
        if (it.next()) |entry| {
            if (entry.value_ptr.items.len > 0) {
                var block = entry.value_ptr.orderedRemove(0);
                const block_hash = block.hash();
                block.deinit(self.allocator);

                _ = self.orphans_by_hash.remove(block_hash);

                self.total_orphans -= 1;
                self.stats.orphans_evicted += 1;

                // Remove parent entry if empty
                if (entry.value_ptr.items.len == 0) {
                    entry.value_ptr.deinit();
                    _ = self.orphans_by_parent.remove(entry.key_ptr.*);
                }
            }
        }
    }

    /// Get current statistics
    pub fn getStats(self: *OrphanPool) Stats {
        return self.stats;
    }

    /// Get current pool size
    pub fn size(self: *OrphanPool) usize {
        return self.total_orphans;
    }

    /// Clear all orphans from the pool
    pub fn clear(self: *OrphanPool) void {
        // Clean up all orphan blocks
        var it = self.orphans_by_parent.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |*block| {
                block.deinit(self.allocator);
            }
            entry.value_ptr.deinit();
        }
        self.orphans_by_parent.clearRetainingCapacity();
        self.orphans_by_hash.clearRetainingCapacity();
        self.total_orphans = 0;
        log.info("[ORPHAN] Cleared all orphans from pool", .{});
    }
};
