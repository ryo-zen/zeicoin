// snapshot.zig - Memory-Safe Chain Snapshots
// Atomic state capture and restoration for reorganization operations

const std = @import("std");
const types = @import("../../types/types.zig");
const ChainState = @import("../state.zig").ChainState;
const db = @import("../../storage/db.zig");

// Type aliases
const Block = types.Block;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Chain snapshot for atomic state operations
pub const ChainSnapshot = struct {
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize snapshot manager
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // Snapshot manager itself doesn't own resources
    }
    
    /// Individual snapshot containing chain state
    pub const Snapshot = struct {
        // Block data
        blocks: std.ArrayList(Block),
        block_heights: std.HashMap(Hash, u32, HashContext, std.hash_map.default_max_load_percentage),
        
        // Account state
        accounts: std.HashMap(Address, Account, AddressContext, std.hash_map.default_max_load_percentage),
        
        // Metadata
        chain_height: u32,
        chain_tip: Hash,
        snapshot_height: u32, // Height from which snapshot was taken
        state_root: Hash,
        
        allocator: std.mem.Allocator,
        
        const SnapshotSelf = @This();
        
        /// Hash context for block hash keys
        const HashContext = struct {
            pub fn hash(self: @This(), s: Hash) u64 {
                _ = self;
                return std.hash_map.hashString(&s);
            }
            pub fn eql(self: @This(), a: Hash, b: Hash) bool {
                _ = self;
                return std.mem.eql(u8, &a, &b);
            }
        };
        
        /// Address context for account keys
        const AddressContext = struct {
            pub fn hash(self: @This(), addr: Address) u64 {
                _ = self;
                const bytes = addr.toBytes();
                return std.hash_map.hashString(&bytes);
            }
            pub fn eql(self: @This(), a: Address, b: Address) bool {
                _ = self;
                return a.equals(b);
            }
        };
        
        /// Initialize empty snapshot
        pub fn init(allocator: std.mem.Allocator) SnapshotSelf {
            return .{
                .blocks = std.ArrayList(Block).init(allocator),
                .block_heights = std.HashMap(Hash, u32, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
                .accounts = std.HashMap(Address, Account, AddressContext, std.hash_map.default_max_load_percentage).init(allocator),
                .chain_height = 0,
                .chain_tip = std.mem.zeroes(Hash),
                .snapshot_height = 0,
                .state_root = std.mem.zeroes(Hash),
                .allocator = allocator,
            };
        }
        
        /// Cleanup snapshot resources
        pub fn deinit(self: *SnapshotSelf) void {
            // Free all blocks
            for (self.blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            self.blocks.deinit();
            self.block_heights.deinit();
            self.accounts.deinit();
        }
        
        /// Get snapshot statistics
        pub fn getStats(self: *const SnapshotSelf) struct {
            blocks: usize,
            accounts: usize,
            memory_usage: usize,
        } {
            var memory_usage: usize = 0;
            
            // Calculate approximate memory usage
            memory_usage += self.blocks.capacity * @sizeOf(Block);
            memory_usage += self.block_heights.capacity() * (@sizeOf(Hash) + @sizeOf(u32));
            memory_usage += self.accounts.capacity() * (@sizeOf(Address) + @sizeOf(Account));
            
            return .{
                .blocks = self.blocks.items.len,
                .accounts = self.accounts.count(),
                .memory_usage = memory_usage,
            };
        }
    };
    
    /// Capture complete chain state from specified height
    pub fn captureChainState(self: *Self, chain_state: *ChainState, from_height: u32) !Snapshot {
        var snapshot = Snapshot.init(self.allocator);
        errdefer snapshot.deinit();
        
        const current_height = try chain_state.getHeight();
        snapshot.chain_height = current_height;
        snapshot.snapshot_height = from_height;
        
        std.debug.print("📸 Capturing chain snapshot from height {} to {}\n", .{ from_height, current_height });
        
        // Capture blocks from fork point to current tip
        try self.captureBlocks(&snapshot, chain_state, from_height, current_height);
        
        // Capture account states
        try self.captureAccounts(&snapshot, chain_state);
        
        // Calculate state root (simplified)
        snapshot.state_root = try self.calculateStateRoot(&snapshot);
        
        if (current_height > 0) {
            // Get current chain tip
            var tip_block = try chain_state.database.getBlock(current_height - 1);
            defer tip_block.deinit(self.allocator);
            snapshot.chain_tip = tip_block.hash();
        }
        
        const stats = snapshot.getStats();
        std.debug.print("✅ Snapshot captured: {} blocks, {} accounts, ~{}KB\n", .{
            stats.blocks, stats.accounts, stats.memory_usage / 1024
        });
        
        return snapshot;
    }
    
    /// Restore chain state from snapshot
    pub fn restoreChainState(self: *Self, snapshot: *const Snapshot, chain_state: *ChainState) !void {
        _ = self;
        std.debug.print("🔄 Restoring chain state from snapshot\n", .{});
        
        // Rollback to snapshot height
        try chain_state.rollbackToHeight(snapshot.snapshot_height, snapshot.chain_height);
        
        // Restore blocks (in a full implementation)
        for (snapshot.blocks.items) |block| {
            // Would restore block to database
            _ = block;
        }
        
        // Restore accounts (in a full implementation)
        var account_iter = snapshot.accounts.iterator();
        while (account_iter.next()) |entry| {
            // Would restore account to database
            _ = entry;
        }
        
        std.debug.print("✅ Chain state restored to height {}\n", .{snapshot.snapshot_height});
    }
    
    /// Capture blocks from height range
    fn captureBlocks(self: *Self, snapshot: *Snapshot, chain_state: *ChainState, from_height: u32, to_height: u32) !void {
        // Pre-allocate capacity
        const block_count = if (to_height > from_height) to_height - from_height else 0;
        try snapshot.blocks.ensureTotalCapacity(block_count);
        try snapshot.block_heights.ensureTotalCapacity(block_count);
        
        // Capture each block
        for (from_height..to_height) |height| {
            var block = chain_state.database.getBlock(@intCast(height)) catch |err| {
                std.debug.print("⚠️ Failed to capture block at height {}: {}\n", .{ height, err });
                continue;
            };
            
            // Create deep copy of block
            var block_copy = try block.dupe(self.allocator);
            block.deinit(self.allocator); // Clean up original
            
            const block_hash = block_copy.hash();
            
            // Store block and its height mapping
            try snapshot.blocks.append(block_copy);
            try snapshot.block_heights.put(block_hash, @intCast(height));
        }
    }
    
    /// Capture account states (simplified version)
    fn captureAccounts(self: *Self, snapshot: *Snapshot, chain_state: *ChainState) !void {
        _ = self;
        _ = snapshot;
        _ = chain_state;
        
        // In a full implementation, this would:
        // 1. Iterate through all accounts in the database
        // 2. Create deep copies of account data
        // 3. Store in snapshot's account HashMap
        
        // For now, we'll capture a minimal set
        std.debug.print("📊 Account capture (simplified implementation)\n", .{});
    }
    
    /// Calculate state root hash (simplified)
    fn calculateStateRoot(self: *Self, snapshot: *const Snapshot) !Hash {
        _ = self;
        
        // In a full implementation, this would calculate a merkle root
        // of all accounts and their states
        
        // For now, return a hash based on basic state
        var hasher = std.crypto.hash.Blake3.init(.{});
        
        // Include chain height
        const height_bytes = std.mem.asBytes(&snapshot.chain_height);
        hasher.update(height_bytes);
        
        // Include block count
        const block_count = snapshot.blocks.items.len;
        const count_bytes = std.mem.asBytes(&block_count);
        hasher.update(count_bytes);
        
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        return hash;
    }
};

/// Snapshot comparison utilities
pub const SnapshotComparator = struct {
    /// Compare two snapshots for differences
    pub fn compare(snapshot1: *const ChainSnapshot.Snapshot, snapshot2: *const ChainSnapshot.Snapshot) SnapshotDiff {
        return SnapshotDiff{
            .height_diff = @as(i64, @intCast(snapshot1.chain_height)) - @as(i64, @intCast(snapshot2.chain_height)),
            .block_count_diff = @as(i64, @intCast(snapshot1.blocks.items.len)) - @as(i64, @intCast(snapshot2.blocks.items.len)),
            .account_count_diff = @as(i64, @intCast(snapshot1.accounts.count())) - @as(i64, @intCast(snapshot2.accounts.count())),
            .state_root_matches = std.mem.eql(u8, &snapshot1.state_root, &snapshot2.state_root),
        };
    }
};

pub const SnapshotDiff = struct {
    height_diff: i64,
    block_count_diff: i64,
    account_count_diff: i64,
    state_root_matches: bool,
};