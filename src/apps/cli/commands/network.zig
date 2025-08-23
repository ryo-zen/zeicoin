// Network commands for ZeiCoin CLI
// Handles status, sync, and block inspection commands

const std = @import("std");
const log = std.log.scoped(.cli);

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
    
    log.info("📊 ZeiCoin Network Status:", .{});
    
    // Show server information (try to get it, fallback to localhost)
    if (connection.getServerIP(allocator)) |server_ip| {
        defer allocator.free(server_ip);
        log.info("🌐 Server: {s}:10802", .{server_ip});
    } else |_| {
        log.info("🌐 Server: 127.0.0.1:10802", .{});
    }
    
    var buffer: [1024]u8 = undefined;
    const response = connection.sendRequest(allocator, "BLOCKCHAIN_STATUS_ENHANCED", &buffer) catch |err| {
        switch (err) {
            connection.ConnectionError.NetworkError,
            connection.ConnectionError.ConnectionFailed,
            connection.ConnectionError.ConnectionTimeout => {
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
            log.info("📊 Network Height: {s}", .{std.mem.trim(u8, height_str, " \n\r\t")});
        }
        if (parts.next()) |peers_str| {
            log.info("👥 Connected Peers: {s}", .{std.mem.trim(u8, peers_str, " \n\r\t")});
        }
        if (parts.next()) |mempool_str| {
            log.info("⏳ Pending Transactions: {s}", .{std.mem.trim(u8, mempool_str, " \n\r\t")});
        }
        if (parts.next()) |mining_str| {
            const is_mining = std.mem.eql(u8, std.mem.trim(u8, mining_str, " \n\r\t"), "true");
            log.info("⛏️  Mining: {s}", .{if (is_mining) "Active" else "Inactive"});
        }
        if (parts.next()) |hashrate_str| {
            log.info("🔥 Hash Rate: {s} H/s", .{std.mem.trim(u8, hashrate_str, " \n\r\t")});
        }
    } else {
        log.info("📨 Server Response: {s}", .{response});
    }
}

/// Handle watch status with enhanced blockchain animation
fn handleWatchStatus(allocator: std.mem.Allocator) !void {
    log.info("🔍 Monitoring ZeiCoin network status... (Press Ctrl+C to stop)\n", .{});
    
    // Blockchain animation frames
    const blockchain_frames = [_][]const u8{
        "⛓️ ▓▓▓▓▓▓▓▓▓▓ ⛓️",
        "⛓️ ▓▓▓▓▓▓▓▓▓░ ⛓️", 
        "⛓️ ▓▓▓▓▓▓▓▓░░ ⛓️",
        "⛓️ ▓▓▓▓▓▓▓░░░ ⛓️",
        "⛓️ ▓▓▓▓▓▓░░░░ ⛓️",
        "⛓️ ▓▓▓▓▓░░░░░ ⛓️",
        "⛓️ ▓▓▓▓░░░░░░ ⛓️",
        "⛓️ ▓▓▓░░░░░░░ ⛓️",
        "⛓️ ▓▓░░░░░░░░ ⛓️",
        "⛓️ ▓░░░░░░░░░ ⛓️",
        "⛓️ ░░░░░░░░░░ ⛓️",
        "⛓️ ░▓░░░░░░░░ ⛓️",
        "⛓️ ░░▓░░░░░░░ ⛓️",
        "⛓️ ░░░▓░░░░░░ ⛓️",
        "⛓️ ░░░░▓░░░░░ ⛓️",
        "⛓️ ░░░░░▓░░░░ ⛓️",
        "⛓️ ░░░░░░▓░░░ ⛓️",
        "⛓️ ░░░░░░░▓░░ ⛓️",
        "⛓️ ░░░░░░░░▓░ ⛓️",
        "⛓️ ░░░░░░░░░▓ ⛓️",
    };
    
    var frame_counter: u32 = 0;
    var last_mining_state: ?bool = null;
    
    while (true) {
        // Get status from server
        var buffer: [1024]u8 = undefined;
        const response = connection.sendRequest(allocator, "BLOCKCHAIN_STATUS_ENHANCED", &buffer) catch |err| {
            switch (err) {
                connection.ConnectionError.NetworkError,
                connection.ConnectionError.ConnectionFailed,
                connection.ConnectionError.ConnectionTimeout => {
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
        
        // Clear previous display (2 lines)
        log.info("\r\x1b[K", .{}); // Clear current line
        log.info("\x1b[1A\x1b[K", .{}); // Move up and clear line
        
        if (is_mining) {
            // Show blockchain animation when mining
            const frame = blockchain_frames[frame_counter % blockchain_frames.len];
            log.info("{s}", .{frame});
            log.info("⛏️  Mining Block {s} | Peers: {s} | Mempool: {s} | {s} H/s", .{
                height orelse "?", peers orelse "?", pending orelse "?", hashrate orelse "0"
            });
            frame_counter += 1;
        } else {
            // Show static status when not mining
            log.info("⏸️  Mining Inactive", .{});
            log.info("📊 Height: {s} | Peers: {s} | Mempool: {s} | Ready for transactions", .{
                height orelse "?", peers orelse "?", pending orelse "?"
            });
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
            connection.ConnectionError.NetworkError,
            connection.ConnectionError.ConnectionFailed,
            connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };
    
    log.info("📨 Sync response: {s}", .{response});
}

/// Handle block inspection command
pub fn handleBlock(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        log.info("❌ Block height required", .{});
        log.info("Usage: zeicoin block <height>", .{});
        return;
    }
    
    const height_str = args[0];
    
    // Validate height is a number
    _ = std.fmt.parseInt(u64, height_str, 10) catch {
        log.info("❌ Invalid block height: {s}", .{height_str});
        return CLIError.InvalidArguments;
    };
    
    // Format block request
    const block_request = try std.fmt.allocPrint(allocator, "GET_BLOCK:{s}", .{height_str});
    defer allocator.free(block_request);
    
    var buffer: [4096]u8 = undefined;
    const response = connection.sendRequest(allocator, block_request, &buffer) catch |err| {
        switch (err) {
            connection.ConnectionError.NetworkError,
            connection.ConnectionError.ConnectionFailed,
            connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };
    
    if (std.mem.startsWith(u8, response, "ERROR:")) {
        log.info("❌ {s}", .{response[7..]});
        return;
    }
    
    if (std.mem.startsWith(u8, response, "BLOCK:")) {
        log.info("📦 Block Information:", .{});
        log.info("{s}", .{response[6..]});
    } else {
        log.info("📨 Response: {s}", .{response});
    }
}