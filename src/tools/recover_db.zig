const std = @import("std");
const zeicoin = @import("zeicoin");
const db = zeicoin.db;
const types = zeicoin.types;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const data_dir = "zeicoin_data_testnet";
    std.debug.print("Opening database at {s}...\n", .{data_dir});

    var database = try db.Database.init(allocator, io, data_dir);
    defer database.deinit();

    const current_height = try database.getHeight();
    std.debug.print("Current height: {}\n", .{current_height});

    if (current_height == 32) {
        std.debug.print("Detected corrupt height 32. Rolling back...\n", .{});
        
        // Remove block 32
        try database.removeBlock(32);
        std.debug.print("Removed block 32\n", .{});

        // Set height to 31
        try database.saveHeight(31);
        std.debug.print("Reset height to 31\n", .{});
        
        std.debug.print("✅ Rollback successful\n", .{});
    } else {
        std.debug.print("Height is not 32. No action taken.\n", .{});
    }
}
