// Network commands for ZeiCoin CLI
// Handles status, sync, and block inspection commands

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;

const connection = @import("../client/connection.zig");

const CLIError = error{
    NetworkError,
    InvalidArguments,
};

/// Handle status command
pub fn handleStatus(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    // Check for --watch or -w flag
    var watch_mode = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--watch") or std.mem.eql(u8, arg, "-w")) {
            watch_mode = true;
            break;
        }
    }

    if (watch_mode) {
        try handleWatchStatus(allocator);
        return;
    }

    print("📊 ZeiCoin Network Status:\n", .{});

    // Show server information (try to get it, fallback to localhost)
    if (connection.getServerIP(allocator)) |server_ip| {
        defer allocator.free(server_ip);
        print("🌐 Server: {s}:10802\n", .{server_ip});
    } else |_| {
        print("🌐 Server: 127.0.0.1:10802\n", .{});
    }

    var buffer: [1024]u8 = undefined;
    const response = connection.sendRequest(allocator, "BLOCKCHAIN_STATUS_ENHANCED", &buffer) catch |err| {
        switch (err) {
            connection.ConnectionError.NetworkError, connection.ConnectionError.ConnectionFailed, connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };

    // Parse and display status: "STATUS:height:peers:mempool:mining:hashrate"
    if (std.mem.startsWith(u8, response, "STATUS:")) {
        var parts = std.mem.splitScalar(u8, response[7..], ':'); // Skip "STATUS:"
        if (parts.next()) |height_str| {
            print("📊 Network Height: {s}\n", .{std.mem.trim(u8, height_str, " \n\r\t")});
        }
        if (parts.next()) |peers_str| {
            print("👥 Connected Peers: {s}\n", .{std.mem.trim(u8, peers_str, " \n\r\t")});
        }
        if (parts.next()) |mempool_str| {
            print("⏳ Pending Transactions: {s}\n", .{std.mem.trim(u8, mempool_str, " \n\r\t")});
        }
        if (parts.next()) |mining_str| {
            const is_mining = std.mem.eql(u8, std.mem.trim(u8, mining_str, " \n\r\t"), "true");
            print("⛏️ Mining: {s}\n", .{if (is_mining) "Active" else "Inactive"});
        }
        if (parts.next()) |hashrate_str| {
            print("🔥 Hash Rate: {s} H/s\n", .{std.mem.trim(u8, hashrate_str, " \n\r\t")});
        }
    } else {
        print("📨 Server Response: {s}\n", .{response});
    }
}

/// Handle watch status with enhanced blockchain animation
fn handleWatchStatus(allocator: std.mem.Allocator) !void {
    print("🔍 Monitoring ZeiCoin network status... (Press Ctrl+C to stop)\n", .{});

    // Blockchain animation frames
    const blockchain_frames = [_][]const u8{
        "░░░░░░░░░▓",
        "░░░░░░░░▓░",
        "░░░░░░░▓░░",
        "░░░░░░▓░░░",
        "░░░░░▓░░░░",
        "░░░░▓░░░░░",
        "░░░▓░░░░░░",
        "░░▓░░░░░░░",
        "░▓░░░░░░░░",
        "▓░░░░░░░░░",
        "▓░░░░░░░░░",
        "░▓░░░░░░░░",
        "░░▓░░░░░░░",
        "░░░▓░░░░░░",
        "░░░░▓░░░░░",
        "░░░░░▓░░░░",
        "░░░░░░▓░░░",
        "░░░░░░░▓░░",
        "░░░░░░░░▓░",
        "░░░░░░░░░▓",
    };

    var frame_counter: u32 = 0;
    var last_mining_state: ?bool = null;
    var first_iteration: bool = true;

    while (true) {
        // Get status from server
        var buffer: [1024]u8 = undefined;
        const response = connection.sendRequest(allocator, "BLOCKCHAIN_STATUS_ENHANCED", &buffer) catch |err| {
            switch (err) {
                connection.ConnectionError.NetworkError, connection.ConnectionError.ConnectionFailed, connection.ConnectionError.ConnectionTimeout => {
                    return;
                },
                else => return err,
            }
        };

        // Parse response: "STATUS:height:peers:mempool:mining:hashrate"
        var height: ?[]const u8 = null;
        var peers: ?[]const u8 = null;
        var pending: ?[]const u8 = null;
        var mining: ?[]const u8 = null;
        var hashrate: ?[]const u8 = null;

        if (std.mem.startsWith(u8, response, "STATUS:")) {
            var parts = std.mem.splitScalar(u8, response[7..], ':'); // Skip "STATUS:"
            if (parts.next()) |height_str| height = std.mem.trim(u8, height_str, " \n\r\t");
            if (parts.next()) |peers_str| peers = std.mem.trim(u8, peers_str, " \n\r\t");
            if (parts.next()) |mempool_str| pending = std.mem.trim(u8, mempool_str, " \n\r\t");
            if (parts.next()) |mining_str| mining = std.mem.trim(u8, mining_str, " \n\r\t");
            if (parts.next()) |hashrate_str| hashrate = std.mem.trim(u8, hashrate_str, " \n\r\t");
        }

        const is_mining = if (mining) |m| std.mem.eql(u8, m, "true") else false;

        // Reset animation when mining state changes
        if (last_mining_state) |last| {
            if (is_mining != last) frame_counter = 0;
        }
        last_mining_state = is_mining;

        // Clear previous display (2 lines) - but not on first iteration
        if (!first_iteration) {
            print("\r\x1b[K", .{}); // Clear current line
            print("\x1b[1A\x1b[K", .{}); // Move up and clear line
        }
        first_iteration = false;

        if (is_mining) {
            // Show blockchain animation when mining
            const frame = blockchain_frames[frame_counter % blockchain_frames.len];
            print("{s}\n", .{frame});
            print("Mining Block: {s} | Peers: {s} | Mempool: {s} | {s} H/s", .{ height orelse "?", peers orelse "?", pending orelse "?", hashrate orelse "0" });
            frame_counter += 1;
        } else {
            // Show static status when not mining
            print("⏸️ Mining Inactive ⏸️\n", .{});
            print("Current blockchain height: {s} | Peers: {s} | Mempool: {s} | Ready for transactions", .{ height orelse "?", peers orelse "?", pending orelse "?" });
            frame_counter = 0; // Keep at start when inactive
        }

        // Wait 200ms for smooth animation
        std.time.sleep(200 * std.time.ns_per_ms);
    }
}

/// Handle sync command
pub fn handleSync(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    _ = args; // Unused parameter

    var buffer: [1024]u8 = undefined;
    const response = connection.sendRequest(allocator, "TRIGGER_SYNC", &buffer) catch |err| {
        switch (err) {
            connection.ConnectionError.NetworkError, connection.ConnectionError.ConnectionFailed, connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };

    print("📨 Sync response: {s}\n", .{response});
}

/// Handle block inspection command
pub fn handleBlock(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Block height required\n", .{});
        print("Usage: zeicoin block <height>\n", .{});
        return;
    }

    const height_str = args[0];

    // Validate height is a number
    _ = std.fmt.parseInt(u64, height_str, 10) catch {
        print("❌ Invalid block height: {s}\n", .{height_str});
        return;
    };

    // Format block request
    const block_request = try std.fmt.allocPrint(allocator, "GET_BLOCK:{s}", .{height_str});
    defer allocator.free(block_request);

    var buffer: [4096]u8 = undefined;
    const response = connection.sendRequest(allocator, block_request, &buffer) catch |err| {
        switch (err) {
            connection.ConnectionError.NetworkError, connection.ConnectionError.ConnectionFailed, connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };

    if (std.mem.startsWith(u8, response, "ERROR:")) {
        print("❌ {s}\n", .{response[7..]});
        return;
    }

    if (std.mem.startsWith(u8, response, "BLOCK:")) {
        print("📦 Block Information:\n", .{});
        print("{s}\n", .{response[6..]});
    } else {
        print("📨 Response: {s}\n", .{response});
    }
}
