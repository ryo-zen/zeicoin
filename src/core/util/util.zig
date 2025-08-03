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