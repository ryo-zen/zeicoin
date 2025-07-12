// server.zig - ZeiCoin node server (modular version)
// Thin coordinator that delegates to specialized modules

const std = @import("std");
const command_line = @import("command_line.zig");
const initialization = @import("initialization.zig");
const client_api = @import("client_api.zig");

// Signal handling for graceful shutdown
var running = true;

fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    running = false;
}

pub fn main() !void {
    // Print banner
    printBanner();
    
    // Setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    
    // Parse command line
    var config = command_line.parseArgs(allocator) catch |err| switch (err) {
        error.HelpRequested => return,
        error.MissingMinerWallet => return, // Error already printed in parseArgs
        error.UnknownArgument => return,   // Error already printed in parseArgs
        else => return err,
    };
    defer config.deinit();
    
    // Initialize node components
    var components = try initialization.initializeNode(allocator, config);
    defer components.deinit();
    
    // Start client API if not disabled
    var api_server: ?client_api.ClientApiServer = null;
    if (!config.client_api_disabled) {
        api_server = client_api.ClientApiServer.init(allocator, components.blockchain, config.bind_address);
        
        const api_thread = try std.Thread.spawn(.{}, client_api.ClientApiServer.start, .{&api_server.?});
        api_thread.detach();
        
        std.log.info("✅ Client API started on {s}:{}", .{config.bind_address, client_api.CLIENT_API_PORT});
    }
    defer if (api_server) |*server| server.deinit();
    
    // Setup signal handlers
    _ = std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);
    
    std.log.info("✅ ZeiCoin node started successfully", .{});
    std.log.info("Press Ctrl+C to shutdown", .{});
    
    // Main loop - wait for shutdown signal
    var last_status_time = std.time.timestamp();
    while (running) {
        // Check if still running before maintenance
        if (!running) break;
        
        // Periodic maintenance
        components.network_manager.maintenance();
        
        // Print status every 30 seconds
        const now = std.time.timestamp();
        if (now - last_status_time >= 30) {
            printStatus(&components);
            last_status_time = now;
        }
        
        std.time.sleep(1 * std.time.ns_per_s);
    }
    
    std.log.info("Shutting down...", .{});
    
    // Stop mining if active
    if (components.blockchain.mining_manager) |mining_manager| {
        mining_manager.stopMining();
    }
    
    // Stop client API
    if (api_server) |*server| {
        server.stop();
    }
    
    // Note: Network stop is handled in components.deinit()
    // to ensure proper ordering with sync manager cleanup
}

fn printBanner() void {
    std.debug.print("\n", .{});
    std.debug.print("╔═══════════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║                  ⚡ ZeiCoin Node Server ⚡                        ║\n", .{});
    std.debug.print("║                    Modular Architecture                           ║\n", .{});
    std.debug.print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});
}

fn printStatus(components: *const initialization.NodeComponents) void {
    const height = components.blockchain.getHeight() catch 0;
    const peer_stats = components.network_manager.getPeerStats();
    const is_mining = components.blockchain.mining_manager != null;
    const mempool_size = components.blockchain.mempool_manager.getTransactionCount();
    
    std.log.info(
        \\📊 Status: Height={} | Peers={}/{} | Mempool={} | Mining={}
    , .{
        height,
        peer_stats.connected,
        peer_stats.total,
        mempool_size,
        is_mining,
    });
}