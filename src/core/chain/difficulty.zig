// difficulty.zig - Blockchain Difficulty Calculation Module
// Handles all difficulty adjustment calculations for the blockchain

const std = @import("std");
const log = std.log.scoped(.chain);
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
        // FOR TESTING: Disable adjustment on TestNet to keep mining speed predictable
        if (types.CURRENT_NETWORK == .testnet) {
            return types.ZenMining.initialDifficultyTarget();
        }

        const current_height = try self.database.getHeight();
        // The next block height is current_height + 1
        const next_height = current_height + 1;

        // For first adjustment period blocks, use initial difficulty
        if (next_height < types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD) {
            return types.ZenMining.initialDifficultyTarget();
        }

        // Only adjust every DIFFICULTY_ADJUSTMENT_PERIOD blocks
        if (next_height % types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD != 0) {
            // Not an adjustment block, use previous difficulty (which is current block)
            var prev_block = try self.database.getBlock(current_height);
            defer prev_block.deinit(self.allocator);
            return prev_block.header.getDifficultyTarget();
        }

        // This is an adjustment block! Calculate new difficulty
        log.info("📊 Difficulty adjustment at block {}", .{next_height});

        // Get timestamps from last adjustment period blocks for time calculation
        const lookback_blocks = types.ZenMining.DIFFICULTY_ADJUSTMENT_PERIOD;
        var oldest_timestamp: u64 = 0;
        var newest_timestamp: u64 = 0;

        // Get timestamp from adjustment period blocks ago
        {
            const old_block_height: u32 = @intCast(next_height - lookback_blocks);
            var old_block = try self.database.getBlock(old_block_height);
            defer old_block.deinit(self.allocator);
            oldest_timestamp = old_block.header.timestamp;
        }

        // Get timestamp from most recent block (current_height)
        {
            var new_block = try self.database.getBlock(current_height);
            defer new_block.deinit(self.allocator);
            newest_timestamp = new_block.header.timestamp;
        }

        // Get current difficulty from most recent block
        var prev_block = try self.database.getBlock(current_height);
        defer prev_block.deinit(self.allocator);
        const current_difficulty = prev_block.header.getDifficultyTarget();

        // Calculate actual time for last adjustment period blocks (Convert ms to seconds)
        const actual_time_ms = if (newest_timestamp >= oldest_timestamp)
            newest_timestamp - oldest_timestamp
        else
            types.ZenMining.TARGET_BLOCK_TIME * lookback_blocks * 1000;
        
        // Ensure actual_time is at least 1 second to avoid division by zero
        const actual_time = @max(1, actual_time_ms / 1000);
            
        const target_time = lookback_blocks * types.ZenMining.TARGET_BLOCK_TIME;

        // DETERMINISTIC: Simplified bounds checking with clear, deterministic rules
        const bounded_actual_time = if (actual_time == 0) 
            1 // Prevent division by zero (minimum 1 second)
        else if (actual_time > target_time * 4) 
            target_time * 2 // Cap extreme increases to 2x target  
        else 
            actual_time;

        // DETERMINISTIC: Replace floating-point with fixed-point integer arithmetic
        // Use 1,000,000 as fixed-point multiplier for 6 decimal places of precision
        const FIXED_POINT_MULTIPLIER: u64 = 1_000_000;
        const adjustment_factor_fixed = (target_time * FIXED_POINT_MULTIPLIER) / bounded_actual_time;

        // DEBUG: Log detailed calculation steps
        log.info("🔍 [DIFFICULTY DEBUG] Calculation details:", .{});
        log.info("   📊 Next block height: {}, Lookback: {} blocks", .{ next_height, lookback_blocks });
        log.info("   ⏰ Oldest timestamp: {} (block {})", .{ oldest_timestamp, next_height - lookback_blocks });
        log.info("   ⏰ Newest timestamp: {} (block {})", .{ newest_timestamp, current_height });
        log.info("   📈 Raw time difference: {}s", .{actual_time});
        log.info("   📈 Bounded time: {}s (target: {}s)", .{ bounded_actual_time, target_time });
        log.info("   🔢 Current difficulty: {} (0x{X})", .{ current_difficulty.toU64(), current_difficulty.threshold });
        log.info("   🔢 Adjustment factor (fixed): {}", .{ adjustment_factor_fixed });

        // Apply adjustment with constraints using fixed-point arithmetic
        const new_difficulty = current_difficulty.adjustFixed(adjustment_factor_fixed, FIXED_POINT_MULTIPLIER, types.CURRENT_NETWORK);
        
        // DEBUG: Log final result
        log.info("   ✅ Final difficulty: {} (0x{X}) -> {} (0x{X})", .{ current_difficulty.toU64(), current_difficulty.threshold, new_difficulty.toU64(), new_difficulty.threshold });

        // Log the adjustment with debug info (using integer values for deterministic logging)
        log.info("📈 Difficulty adjusted: factor_fixed={} (={d:.6}), actual={}s, bounded={}s, target={}s", .{ 
            adjustment_factor_fixed, 
            @as(f64, @floatFromInt(adjustment_factor_fixed)) / @as(f64, @floatFromInt(FIXED_POINT_MULTIPLIER)),
            actual_time, 
            bounded_actual_time, 
            target_time 
        });

        return new_difficulty;
    }
};