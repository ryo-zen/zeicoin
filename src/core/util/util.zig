// Utilities for Zeicoin

const std = @import("std");
const print = std.debug.print;

// Global debug flag
pub var debug_mode: bool = false;

/// Simple logging utilities for blockchain
pub fn logSuccess(comptime fmt: []const u8, args: anytype) void {
    print("✅ " ++ fmt ++ "\n", args);
}

pub fn logInfo(comptime fmt: []const u8, args: anytype) void {
    print("ℹ️  " ++ fmt ++ "\n", args);
}

pub fn logProcess(comptime fmt: []const u8, args: anytype) void {
    print("🔄 " ++ fmt ++ "\n", args);
}

/// Get current Unix timestamp
pub fn getTime() i64 {
    return std.time.timestamp();
}

/// Format Unix timestamp to human-readable string
pub fn formatTime(timestamp: u64) [19]u8 {
    const seconds = timestamp;
    
    var buf: [19]u8 = undefined;
    const fmt = "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}";
    
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
    }) catch return "0000-00-00 00:00:00".*;
    
    return buf;
}

/// Double SHA256 hash
pub fn hash256(data: []const u8) [32]u8 {
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data);
    const hash1 = hasher1.finalResult();

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    return hasher2.finalResult();
}

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