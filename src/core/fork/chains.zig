// chains.zig - Chain State Management
// Manages the top 3 competing chains and active chain selection

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const fork_types = @import("types.zig");

const ChainState = types.ChainState;
const ChainWork = types.ChainWork;
const BlockHash = types.BlockHash;

/// Chain manager for tracking top 3 competing chains
pub const ChainTracker = struct {
    // Track top 3 chains by cumulative work
    chains: [3]?ChainState,
    active_chain_index: u8, // Index of currently active chain (0-2)
    
    pub fn init() ChainTracker {
        return ChainTracker{
            .chains = [_]?ChainState{null} ** 3,
            .active_chain_index = 0,
        };
    }
    
    /// Initialize with genesis chain
    pub fn initWithGenesis(self: *ChainTracker, genesis_hash: BlockHash, genesis_work: ChainWork) void {
        self.chains[0] = ChainState.init(genesis_hash, genesis_work);
        self.active_chain_index = 0;
        print("🔗 Chain tracker initialized with genesis chain\n", .{});
    }
    
    /// Get the currently active chain
    pub fn getActiveChain(self: *const ChainTracker) ?ChainState {
        return self.chains[self.active_chain_index];
    }
    
    /// Update a specific chain's state
    pub fn updateChain(self: *ChainTracker, chain_index: u8, new_chain_state: ChainState) void {
        if (chain_index >= 3) {
            print("❌ Invalid chain index: {}\n", .{chain_index});
            return;
        }
        
        self.chains[chain_index] = new_chain_state;
        print("🔄 Updated chain {} with height {} and work {}\n", .{ 
            chain_index, 
            new_chain_state.tip_height, 
            new_chain_state.cumulative_work 
        });
    }
    
    /// Update the best chain with a new block
    pub fn updateBestChain(self: *ChainTracker, new_block_hash: BlockHash, new_height: u32, new_cumulative_work: ChainWork) void {
        const new_chain_state = ChainState{
            .tip_hash = new_block_hash,
            .tip_height = new_height,
            .cumulative_work = new_cumulative_work,
        };
        
        // Update the active chain
        self.chains[self.active_chain_index] = new_chain_state;
        
        print("📈 Best chain updated: height={}, work={}\n", .{ new_height, new_cumulative_work });
    }
    
    /// Find the chain with the most work
    pub fn findBestChain(self: *const ChainTracker) ?struct { index: u8, chain: ChainState } {
        var best_chain: ?ChainState = null;
        var best_index: u8 = 0;
        
        for (self.chains, 0..) |maybe_chain, index| {
            if (maybe_chain) |chain| {
                if (best_chain == null or chain.cumulative_work > best_chain.?.cumulative_work) {
                    best_chain = chain;
                    best_index = @intCast(index);
                }
            }
        }
        
        if (best_chain) |chain| {
            return .{ .index = best_index, .chain = chain };
        }
        return null;
    }
    
    /// Get total number of active chains
    pub fn getActiveChainCount(self: *const ChainTracker) u8 {
        var count: u8 = 0;
        for (self.chains) |maybe_chain| {
            if (maybe_chain != null) count += 1;
        }
        return count;
    }
};