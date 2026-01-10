// block_index.zig - O(1) Block Hash-to-Height Index Cache
// Provides fast block lookups for chain reorganization and validation

const std = @import("std");
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");

const log = std.log.scoped(.chain);

// Type aliases
const Hash = types.Hash;

/// Block Index Cache for O(1) hash-to-height lookups
/// Follows ZeiCoin memory management principles with explicit ownership
pub const BlockIndex = struct {
    // Hash to height mapping for O(1) block height queries
    hash_to_height: std.HashMap([32]u8, u32, HashContext, std.hash_map.default_max_load_percentage),

    // Height to hash mapping for O(1) reverse lookups and reorganization
    height_to_hash: std.ArrayList([32]u8),

    allocator: std.mem.Allocator,

    const Self = @This();

    /// Hash context for [32]u8 keys - required for HashMap
    const HashContext = struct {
        pub fn hash(self: @This(), s: [32]u8) u64 {
            _ = self;
            return std.hash_map.hashString(&s);
        }
        pub fn eql(self: @This(), a: [32]u8, b: [32]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };

    /// Initialize block index with proper memory management
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .hash_to_height = std.HashMap([32]u8, u32, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .height_to_hash = std.ArrayList([32]u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Clean up all allocated memory following ZeiCoin deinit pattern
    pub fn deinit(self: *Self) void {
        self.hash_to_height.deinit();
        self.height_to_hash.deinit();
    }

    /// Check if a block hash already exists in the index - O(1) operation
    /// Important for preventing duplicate blocks in the chain
    pub fn hasBlock(self: *const Self, block_hash: [32]u8) bool {
        return self.hash_to_height.contains(block_hash);
    }

    /// Add block to index - O(1) operation
    /// Memory safety: ensures proper capacity before insertion
    /// Consensus safety: prevents duplicate blocks from being indexed
    pub fn addBlock(self: *Self, height: u32, block_hash: [32]u8) !void {
        // Input validation
        const zero_hash = std.mem.zeroes([32]u8);
        if (std.mem.eql(u8, &block_hash, &zero_hash)) {
            return error.InvalidHash;
        }

        // Prevent duplicate blocks from being indexed - Important!
        if (self.hasBlock(block_hash)) {
            // Duplicate block logging disabled - too verbose during reorganization
            return error.DuplicateBlock;
        }

        // Ensure height_to_hash array is large enough
        const old_len = self.height_to_hash.items.len;
        if (height >= old_len) {
            try self.height_to_hash.resize(height + 1);

            // Initialize new slots to zero hash
            for (self.height_to_hash.items[old_len..]) |*slot| {
                slot.* = std.mem.zeroes([32]u8);
            }
        }

        // Store bidirectional mappings
        try self.hash_to_height.put(block_hash, height);
        self.height_to_hash.items[height] = block_hash;
    }

    /// Get height by hash - O(1) operation replaces O(n) search
    pub fn getHeight(self: *const Self, block_hash: [32]u8) ?u32 {
        return self.hash_to_height.get(block_hash);
    }

    /// Get hash by height - O(1) operation for reverse lookups
    pub fn getHash(self: *const Self, height: u32) ?[32]u8 {
        if (height >= self.height_to_hash.items.len) return null;

        const hash = self.height_to_hash.items[height];
        const zero_hash = std.mem.zeroes([32]u8);
        if (std.mem.eql(u8, &hash, &zero_hash)) return null;

        return hash;
    }

    /// Remove block from index (for chain reorganizations)
    /// Memory safety: handles missing entries gracefully
    pub fn removeBlock(self: *Self, height: u32, block_hash: [32]u8) void {
        // Remove from hash mapping
        _ = self.hash_to_height.remove(block_hash);

        // Clear height mapping
        if (height < self.height_to_hash.items.len) {
            self.height_to_hash.items[height] = std.mem.zeroes([32]u8);
        }
    }

    /// Remove blocks from height onwards (for rollback during reorganization)
    pub fn removeFromHeight(self: *Self, from_height: u32) void {
        // Remove all blocks from specified height onwards
        if (from_height >= self.height_to_hash.items.len) return;

        for (from_height..self.height_to_hash.items.len) |height| {
            const hash = self.height_to_hash.items[height];
            const zero_hash = std.mem.zeroes([32]u8);
            if (!std.mem.eql(u8, &hash, &zero_hash)) {
                _ = self.hash_to_height.remove(hash);
                self.height_to_hash.items[height] = zero_hash;
            }
        }

        // Shrink array to remove trailing zeros
        self.height_to_hash.shrinkRetainingCapacity(from_height);
    }

    /// Rebuild index from database (recovery/initialization)
    /// Memory safety: proper error handling with cleanup on failure
    pub fn rebuild(self: *Self, database: *db.Database) !void {
        // Clear existing index
        self.hash_to_height.clearRetainingCapacity();
        self.height_to_hash.clearRetainingCapacity();

        const current_height = database.getHeight() catch |err| {
            log.info("⚠️ Failed to get chain height during index rebuild: {}", .{err});
            return err;
        };

        // Pre-allocate space for efficiency
        try self.height_to_hash.ensureTotalCapacity(current_height + 1);
        try self.hash_to_height.ensureTotalCapacity(current_height + 1);

        var successful_blocks: u32 = 0;
        errdefer {
            // Cleanup on failure - clear partial state
            self.hash_to_height.clearRetainingCapacity();
            self.height_to_hash.clearRetainingCapacity();
            log.info("⚠️ Index rebuild failed after {} blocks", .{successful_blocks});
        }

        // Build index from all blocks
        for (0..current_height + 1) |height| {
            var block = database.getBlock(@intCast(height)) catch |err| {
                log.info("⚠️ Failed to load block {} during rebuild: {}", .{ height, err });
                continue; // Skip missing blocks, don't fail entirely
            };
            defer block.deinit(self.allocator);

            const block_hash = block.hash();
            self.addBlock(@intCast(height), block_hash) catch |err| {
                log.info("⚠️ Failed to index block {} during rebuild: {}", .{ height, err });
                continue; // Skip failed additions
            };

            successful_blocks += 1;
        }

        log.info("✅ Block index rebuilt: {} blocks indexed", .{successful_blocks});
    }

    /// Get current index statistics for monitoring
    pub fn getStats(self: *const Self) struct { hash_entries: u32, height_entries: u32, max_height: u32 } {
        return .{
            .hash_entries = @intCast(self.hash_to_height.count()),
            .height_entries = @intCast(self.height_to_hash.items.len),
            .max_height = if (self.height_to_hash.items.len > 0) @intCast(self.height_to_hash.items.len - 1) else 0,
        };
    }

    /// Check index consistency for debugging
    pub fn validateConsistency(self: *const Self) bool {
        // Verify bidirectional mappings are consistent
        for (self.height_to_hash.items, 0..) |hash, height| {
            const zero_hash = std.mem.zeroes([32]u8);
            if (std.mem.eql(u8, &hash, &zero_hash)) continue;

            const lookup_height = self.hash_to_height.get(hash) orelse return false;
            if (lookup_height != height) return false;
        }

        return true;
    }
};

// Tests
const testing = std.testing;

test "BlockIndex basic operations" {
    var index = BlockIndex.init(testing.allocator);
    defer index.deinit();

    // Test adding blocks
    const hash1 = [_]u8{1} ++ [_]u8{0} ** 31;
    const hash2 = [_]u8{2} ++ [_]u8{0} ** 31;

    try index.addBlock(0, hash1);
    try index.addBlock(5, hash2); // Non-sequential height

    // Test lookups
    try testing.expectEqual(@as(?u32, 0), index.getHeight(hash1));
    try testing.expectEqual(@as(?u32, 5), index.getHeight(hash2));

    // Test reverse lookups
    try testing.expect(std.mem.eql(u8, &(index.getHash(0) orelse return error.TestFailed), &hash1));
    try testing.expect(std.mem.eql(u8, &(index.getHash(5) orelse return error.TestFailed), &hash2));

    // Test missing lookups
    const missing_hash = [_]u8{99} ++ [_]u8{0} ** 31;
    try testing.expectEqual(@as(?u32, null), index.getHeight(missing_hash));
    try testing.expectEqual(@as(?[32]u8, null), index.getHash(99));
}

test "BlockIndex reorganization" {
    var index = BlockIndex.init(testing.allocator);
    defer index.deinit();

    // Add some blocks
    const hash1 = [_]u8{1} ++ [_]u8{0} ** 31;
    const hash2 = [_]u8{2} ++ [_]u8{0} ** 31;
    const hash3 = [_]u8{3} ++ [_]u8{0} ** 31;

    try index.addBlock(0, hash1);
    try index.addBlock(1, hash2);
    try index.addBlock(2, hash3);

    // Remove from height 1 onwards (simulating reorganization)
    index.removeFromHeight(1);

    // Verify state
    try testing.expectEqual(@as(?u32, 0), index.getHeight(hash1));
    try testing.expectEqual(@as(?u32, null), index.getHeight(hash2));
    try testing.expectEqual(@as(?u32, null), index.getHeight(hash3));

    try testing.expect(index.validateConsistency());
}

test "BlockIndex error handling" {
    var index = BlockIndex.init(testing.allocator);
    defer index.deinit();

    // Test invalid hash
    const zero_hash = std.mem.zeroes([32]u8);
    try testing.expectError(error.InvalidHash, index.addBlock(0, zero_hash));
}

test "BlockIndex duplicate hash detection" {
    const allocator = std.testing.allocator;
    var index = BlockIndex.init(allocator);
    defer index.deinit();

    // Create a test hash (simulating a real block hash)
    var hash: [32]u8 = undefined;
    @memset(&hash, 0xAB);

    // First addition should succeed
    try index.addBlock(4, hash);
    try testing.expect(index.hasBlock(hash));
    try testing.expectEqual(@as(?u32, 4), index.getHeight(hash));

    // Attempting to add the same hash at a different height should fail - Important!
    // This is exactly the bug that allowed blocks 4, 5, and 6 to be duplicates
    try testing.expectError(error.DuplicateBlock, index.addBlock(5, hash));

    // The original block should still be at height 4
    try testing.expectEqual(@as(?u32, 4), index.getHeight(hash));

    // Even attempting to add at the same height should fail
    try testing.expectError(error.DuplicateBlock, index.addBlock(4, hash));

    // Test that hasBlock works correctly
    try testing.expect(index.hasBlock(hash));

    var nonexistent_hash: [32]u8 = undefined;
    @memset(&nonexistent_hash, 0xCD);
    try testing.expect(!index.hasBlock(nonexistent_hash));
}
