// types.zig - Fork Management Types
// Shared types and enums for fork management system

const std = @import("std");
const types = @import("../types/types.zig");

const Block = types.Block;
const BlockHash = types.BlockHash;
const ChainWork = types.ChainWork;

/// Decision result from evaluating a new block
pub const ForkDecision = union(enum) {
    ignore: void, // Block already seen or invalid
    store_orphan: void, // Store as orphan block
    extends_chain: struct {
        chain_index: u8,
        requires_reorg: bool,
    },
    new_best_chain: u8, // Chain index of new best chain
};

/// Statistics about fork manager state
pub const ForkStats = struct {
    active_chain_index: u8,
    total_chains: u8,
    orphan_count: usize,
    recent_blocks_count: usize,
    
    pub fn format(self: ForkStats, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("ForkStats{{ active: {}, chains: {}, orphans: {}, recent: {} }}", .{
            self.active_chain_index,
            self.total_chains,
            self.orphan_count,
            self.recent_blocks_count,
        });
    }
};

/// Hash context for BlockHash hash maps
pub const HashContext = struct {
    pub fn hash(self: @This(), key: BlockHash) u64 {
        _ = self;
        return std.hash_map.hashString(&key);
    }
    
    pub fn eql(self: @This(), a: BlockHash, b: BlockHash) bool {
        _ = self;
        return std.mem.eql(u8, &a, &b);
    }
};