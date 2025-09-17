// Utilities for Zeicoin

const std = @import("std");

const log = std.log.scoped(.util);

// Global debug flag
pub var debug_mode: bool = false;

/// Simple logging utilities for blockchain
pub fn logSuccess(comptime fmt: []const u8, args: anytype) void {
    log.info("✅ " ++ fmt, args);
}

pub fn logInfo(comptime fmt: []const u8, args: anytype) void {
    log.info("ℹ️  " ++ fmt, args);
}

pub fn logProcess(comptime fmt: []const u8, args: anytype) void {
    log.info("🔄 " ++ fmt, args);
}

/// Get current Unix timestamp
pub fn getTime() i64 {
    return std.time.timestamp();
}

/// Format Unix timestamp to human-readable string
pub fn formatTime(timestamp: u64) [23]u8 {
    // Convert millisecond timestamp to seconds
    const seconds = timestamp / 1_000;
    
    var buf: [23]u8 = undefined;
    const fmt = "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC";
    
    // Convert to epoch seconds struct
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
    const day_seconds = epoch.getDaySeconds();
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    
    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const seconds_in_minute = day_seconds.getSecondsIntoMinute();
    
    _ = std.fmt.bufPrint(&buf, fmt, .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        hours,
        minutes,
        seconds_in_minute,
    }) catch return "0000-00-00 00:00:00 UTC".*;
    
    return buf;
}

/// Double SHA256 hash (legacy - used for Bitcoin compatibility)
pub fn hash256(data: []const u8) [32]u8 {
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data);
    const hash1 = hasher1.finalResult();

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    return hasher2.finalResult();
}

/// BLAKE3 hash (modern - preferred for ZeiCoin)
/// BLAKE3 is faster, more secure, and simpler than SHA256
pub fn blake3Hash(data: []const u8) [32]u8 {
    var output: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(data, &output, .{});
    return output;
}

/// Simple Merkle Tree implementation for account state commitments
pub const MerkleTree = struct {
    /// Calculate Merkle root from a list of hashes using binary tree structure
    /// If list is empty, returns zero hash
    /// If list has one item, returns that hash
    /// Otherwise builds a binary tree bottom-up
    pub fn calculateRoot(allocator: std.mem.Allocator, hashes: []const [32]u8) ![32]u8 {
        if (hashes.len == 0) {
            return std.mem.zeroes([32]u8); // Empty state root
        }

        if (hashes.len == 1) {
            return hashes[0]; // Single account state
        }

        // Create working list that we can modify
        var current_level = try allocator.dupe([32]u8, hashes);

        // Build tree bottom-up until we have one root hash
        while (current_level.len > 1) {
            const next_level_size = (current_level.len + 1) / 2; // Round up for odd counts
            var next_level = try allocator.alloc([32]u8, next_level_size);

            var i: usize = 0;
            var next_idx: usize = 0;
            
            while (i < current_level.len) {
                if (i + 1 < current_level.len) {
                    // Hash pair of nodes
                    var combined: [64]u8 = undefined;
                    @memcpy(combined[0..32], &current_level[i]);
                    @memcpy(combined[32..64], &current_level[i + 1]);
                    next_level[next_idx] = blake3Hash(&combined);
                    i += 2;
                } else {
                    // Odd number of nodes: duplicate the last one
                    var combined: [64]u8 = undefined;
                    @memcpy(combined[0..32], &current_level[i]);
                    @memcpy(combined[32..64], &current_level[i]); // Duplicate
                    next_level[next_idx] = blake3Hash(&combined);
                    i += 1;
                }
                next_idx += 1;
            }

            // Clean up current level and move to next
            allocator.free(current_level);
            current_level = next_level;
        }

        // We now have exactly one element - the root
        const result = current_level[0];
        allocator.free(current_level);
        return result;
    }

    /// Hash an individual account state for Merkle tree inclusion
    /// Format: address_bytes + balance_bytes + nonce_bytes (deterministic serialization)
    pub fn hashAccountState(account: anytype) [32]u8 {
        // Create deterministic serialization buffer
        // Address (21 bytes) + balance (8 bytes) + nonce (8 bytes) = 37 bytes
        var buffer: [37]u8 = undefined;
        
        // Serialize address (21 bytes: version + hash)
        const address_bytes = account.address.toBytes();
        @memcpy(buffer[0..21], &address_bytes);
        
        // Serialize balance (8 bytes, little endian)
        std.mem.writeInt(u64, buffer[21..29], account.balance, .little);
        
        // Serialize nonce (8 bytes, little endian) 
        std.mem.writeInt(u64, buffer[29..37], account.nonce, .little);

        return blake3Hash(&buffer);
    }
};

/// Helper function to format ZEI amounts with proper decimal places
pub fn formatZEI(allocator: std.mem.Allocator, amount_zei: u64) ![]u8 {
    const types = @import("../types/types.zig");
    const zei_coins = amount_zei / types.ZEI_COIN;
    const zei_fraction = amount_zei % types.ZEI_COIN;

    if (zei_fraction == 0) {
        return std.fmt.allocPrint(allocator, "{} ZEI", .{zei_coins});
    } else {
        // Format with 5 decimal places for precision
        const decimal = @as(f64, @floatFromInt(zei_fraction)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        return std.fmt.allocPrint(allocator, "{}.{d:0>5} ZEI", .{ zei_coins, @as(u64, @intFromFloat(decimal * types.PROGRESS.DECIMAL_PRECISION_MULTIPLIER)) });
    }
}