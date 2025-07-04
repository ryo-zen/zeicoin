// difficulty.zig - Blockchain Difficulty Calculation Module
// Handles all difficulty adjustment calculations for the blockchain

const std = @import("std");
const print = std.debug.print;
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");

pub const DifficultyCalculator = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    
    pub fn init(allocator: std.mem.Allocator, database: *db.Database) DifficultyCalculator {
        return .{
            .allocator = allocator,
            .database = database,
        };
    }
    
    pub fn deinit(self: *DifficultyCalculator) void {
        _ = self;
    }
    
    pub fn calculateNextDifficulty(self: *DifficultyCalculator) !types.DifficultyTarget {
        const current_height = try self.database.getHeight();

        // For first 20 blocks, use initial difficulty
        if (current_height < types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD) {
            return types.ZenMining.initialDifficultyTarget();
        }

        // Only adjust every 20 blocks
        if (current_height % types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD != 0) {
            // Not an adjustment block, use previous difficulty
            const prev_block_height: u32 = @intCast(current_height - 1);
            var prev_block = try self.database.getBlock(prev_block_height);
            defer prev_block.deinit(self.allocator);
            return prev_block.header.getDifficultyTarget();
        }

        // This is an adjustment block! Calculate new difficulty
        print("📊 Difficulty adjustment at block {}\n", .{current_height});

        // Get timestamps from last 20 blocks for time calculation
        const lookback_blocks = types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD;
        var oldest_timestamp: u64 = 0;
        var newest_timestamp: u64 = 0;

        // Get timestamp from 20 blocks ago
        {
            const old_block_height: u32 = @intCast(current_height - lookback_blocks);
            var old_block = try self.database.getBlock(old_block_height);
            defer old_block.deinit(self.allocator);
            oldest_timestamp = old_block.header.timestamp;
        }

        // Get timestamp from most recent block
        {
            const new_block_height: u32 = @intCast(current_height - 1);
            var new_block = try self.database.getBlock(new_block_height);
            defer new_block.deinit(self.allocator);
            newest_timestamp = new_block.header.timestamp;
        }

        // Get current difficulty from previous block
        var prev_block = try self.database.getBlock(current_height - 1);
        defer prev_block.deinit(self.allocator);
        const current_difficulty = prev_block.header.getDifficultyTarget();

        // Calculate actual time for last 20 blocks
        const actual_time = newest_timestamp - oldest_timestamp;
        const target_time = lookback_blocks * types.ZenMining.TARGET_BLOCK_TIME;

        // Calculate adjustment factor
        const adjustment_factor = if (actual_time > 0)
            @as(f64, @floatFromInt(target_time)) / @as(f64, @floatFromInt(actual_time))
        else
            1.0; // Fallback if time calculation fails

        // Apply adjustment with constraints
        const new_difficulty = current_difficulty.adjust(adjustment_factor, types.CURRENT_NETWORK);

        // Log the adjustment
        print("📈 Difficulty adjusted: factor={d:.3}, time={}s->{}s\n", .{ adjustment_factor, actual_time, target_time });

        return new_difficulty;
    }
};