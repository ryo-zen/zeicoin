// decisions.zig - Fork Decision Logic
// Evaluates blocks and makes fork decisions

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const fork_types = @import("types.zig");
const chains = @import("chains.zig");
const orphans = @import("orphans.zig");

const Block = types.Block;
const ChainWork = types.ChainWork;
const ForkDecision = fork_types.ForkDecision;

/// Fork decision engine
pub const DecisionEngine = struct {
    // Safety limits
    const MAX_REORG_DEPTH: u32 = 100;
    
    /// Evaluate a new block and decide what to do with it
    pub fn evaluateBlock(
        chain_tracker: *const chains.ChainTracker,
        orphan_manager: *const orphans.OrphanManager,
        block: Block,
        block_height: u32,
        cumulative_work: ChainWork,
    ) ForkDecision {
        const block_hash = block.hash();
        
        // Check if we've already seen this block
        if (orphan_manager.wasRecentlySeen(block_hash)) {
            print("🔄 Block already seen recently: {s}\n", .{std.fmt.fmtSliceHexLower(block_hash[0..8])});
            return ForkDecision.ignore;
        }
        
        // Get current best chain
        const active_chain = chain_tracker.getActiveChain() orelse {
            print("❌ No active chain found\n", .{});
            return ForkDecision.ignore;
        };
        
        // Check if this block extends the current best chain
        if (std.mem.eql(u8, &block.header.previous_hash, &active_chain.tip_hash)) {
            print("✅ Block extends active chain at height {}\n", .{block_height});
            return ForkDecision{ .extends_chain = .{
                .chain_index = chain_tracker.active_chain_index,
                .requires_reorg = false,
            } };
        }
        
        // Check if this creates a better competing chain
        if (cumulative_work > active_chain.cumulative_work) {
            // This could be a new best chain, but we need to validate the reorganization
            const reorg_depth = if (block_height > active_chain.tip_height) 
                block_height - active_chain.tip_height 
            else 
                active_chain.tip_height - block_height;
                
            if (isReorgTooDeep(reorg_depth)) {
                print("⚠️  Reorganization too deep ({} blocks), storing as orphan\n", .{reorg_depth});
                return ForkDecision.store_orphan;
            }
            
            print("🔄 Potential reorganization: new chain has more work\n", .{});
            return ForkDecision{ .extends_chain = .{
                .chain_index = chain_tracker.active_chain_index,
                .requires_reorg = true,
            } };
        }
        
        // Check if it extends any of the other tracked chains
        for (chain_tracker.chains, 0..) |maybe_chain, index| {
            if (maybe_chain) |chain| {
                if (index != chain_tracker.active_chain_index and 
                   std.mem.eql(u8, &block.header.previous_hash, &chain.tip_hash)) {
                    print("🔗 Block extends alternative chain {}\n", .{index});
                    return ForkDecision{ .extends_chain = .{
                        .chain_index = @intCast(index),
                        .requires_reorg = false,
                    } };
                }
            }
        }
        
        // Block doesn't extend any known chain - store as orphan
        print("🔍 Block doesn't extend known chains, storing as orphan\n", .{});
        return ForkDecision.store_orphan;
    }
    
    /// Check if a reorganization depth exceeds safety limits
    pub fn isReorgTooDeep(reorg_depth: u32) bool {
        return reorg_depth > MAX_REORG_DEPTH;
    }
    
    /// Determine if we should switch to a new best chain
    pub fn shouldSwitchChains(current_work: ChainWork, new_work: ChainWork) bool {
        return new_work > current_work;
    }
};