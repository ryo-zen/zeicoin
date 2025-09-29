const std = @import("std");
const zeicoin = @import("zeicoin");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Create genesis with current settings
    var gen = try zeicoin.genesis.createGenesis(allocator);
    defer gen.deinit(allocator);

    // Calculate hash
    const hash = gen.hash();

    // Print in format for copying to genesis.zig
    std.debug.print("New genesis hash with updated timestamp (Sep 9, 2025 09:09:09.090):\n", .{});
    std.debug.print("Hex: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});

    std.debug.print("\nFormatted for genesis.zig HASH field:\n", .{});
    std.debug.print("pub const HASH: [32]u8 = [_]u8{{ ", .{});
    for (hash, 0..) |byte, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("0x{x:0>2}", .{byte});
    }
    std.debug.print(" }};\n", .{});
}