// server.zig - ZeiCoin node server (modular version)
// Thin coordinator that delegates to specialized modules

const std = @import("std");
const log = std.log.scoped(.server);
const print = std.debug.print;
const command_line = @import("command_line.zig");
const initialization = @import("initialization.zig");
const client_api = @import("client_api.zig");

// Signal handling for graceful shutdown
var running = std.atomic.Value(bool).init(true);

fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    running.store(false, .release);
    log.info("\nReceived Ctrl+C, shutting down gracefully...", .{});
    
    // Give a moment for cleanup, then force exit if needed
    std.time.sleep(2 * std.time.ns_per_s);
    log.info("Force exit after 2 seconds...", .{});
    std.process.exit(0);
}

pub fn main() !void {
    // Print banner
    printBanner();
    
    // Setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Load .env file if present (before processing arguments)
    // Use page allocator for dotenv since putenv requires persistent memory
    @import("../util/dotenv.zig").loadForNetwork(std.heap.page_allocator) catch |err| {
        // Don't fail if .env loading fails, just warn
        if (err != error.FileNotFound) {
            log.info("⚠️  Warning: Failed to load .env file: {}", .{err});
        }
    };
    
    // Parse command line
    var config = command_line.parseArgs(allocator) catch |err| switch (err) {
        error.HelpRequested => return,
        error.MissingMinerWallet => return, // Error already printed in parseArgs
        error.UnknownArgument => return,   // Error already printed in parseArgs
        else => return err,
    };
    defer config.deinit();
    
    // Initialize node components
    var components = initialization.initializeNode(allocator, config) catch |err| switch (err) {
        error.OpenFailed => {
            std.debug.print("❌ Database is locked or in use by another process\n", .{});
            std.debug.print("💡 Stop any running ZeiCoin servers and try again\n", .{});
            std.debug.print("💡 Or remove the lock file: rm zeicoin_data_*/rocksdb/LOCK\n", .{});
            return;
        },
        else => return err,
    };
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
    var mining_started = false;
    var initial_sync_done = false;
    
    while (running.load(.acquire)) {
        // Periodic maintenance (only if still running)
        if (running.load(.acquire)) {
            components.network_manager.maintenance();
        }
        
        // Check if we should start mining after initial sync
        if (!mining_started and components.blockchain.mining_manager != null) {
            const should_start_mining = blk: {
                // If no peers connected yet, wait a bit for network to settle
                const peer_stats = components.network_manager.getPeerStats();
                if (peer_stats.connected == 0) {
                    if (!initial_sync_done) {
                        // Give network 5 seconds to connect before starting mining on empty network
                        const startup_time = 5;
                        std.time.sleep(startup_time * std.time.ns_per_s);
                        initial_sync_done = true;
                        std.log.info("⛏️  No peers found after startup delay - starting mining on local chain", .{});
                        break :blk true;
                    } else {
                        break :blk false;
                    }
                }
                
                // If we have peers, check if sync is complete
                if (components.sync_manager.isActive()) {
                    break :blk false; // Still syncing
                }
                
                // Sync is complete or we're up to date
                break :blk true;
            };
            
            if (should_start_mining) {
                if (startMiningAfterSync(&components)) {
                    mining_started = true;
                } else {
                    std.log.warn("⚠️ Failed to start mining after sync", .{});
                }
            }
        }
        
        // Print status every 30 seconds
        const now = std.time.timestamp();
        if (now - last_status_time >= 30 and running.load(.acquire)) {
            printStatus(&components);
            last_status_time = now;
        }
        
        std.time.sleep(100 * std.time.ns_per_ms); // Check more frequently
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
    print("\n", .{});
    print("╔═══════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                  ⚡ ZeiCoin Node Server ⚡                        ║\n", .{});
    print("║                    Modular Architecture                           ║\n", .{});
    print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

fn startMiningAfterSync(components: *const initialization.NodeComponents) bool {
    if (components.blockchain.mining_manager) |mining_manager| {
        // Get the wallet information that was stored during initialization
        // For now, we'll need to get the keypair from the mining manager
        log.info("⛏️  Starting mining after initial sync completion", .{});
        
        // The mining manager should already have the keypair from initialization
        // We just need to start the mining process
        mining_manager.startMiningDeferred() catch |err| {
            std.log.err("❌ Failed to start mining after sync: {}", .{err});
            return false;
        };
        
        std.log.info("✅ Mining started successfully after sync", .{});
        return true;
    }
    return false;
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