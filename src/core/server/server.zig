// server.zig - ZeiCoin node server (modular version)
// Thin coordinator that delegates to specialized modules

const std = @import("std");
const log = std.log.scoped(.server);
const print = std.debug.print;
const command_line = @import("command_line.zig");
const initialization = @import("initialization.zig");
const client_api = @import("client_api.zig");
const sync = @import("../sync/manager.zig");
const RPCServer = @import("../rpc/server.zig").RPCServer;

// Signal handling for graceful shutdown
var running = std.atomic.Value(bool).init(true);

fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    running.store(false, .release);
    // Signal received - main loop will exit and trigger defer cleanup
    // systemd's TimeoutStopSec=10 acts as emergency timeout if cleanup hangs
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

    // Start RPC server with secondary database support
    const RPC_PORT = 10803;
    const types = @import("../types/types.zig");
    const data_dir = types.CURRENT_NETWORK.getDataDir();
    var rpc_server = try RPCServer.init(allocator, components.blockchain, data_dir, RPC_PORT);
    defer rpc_server.deinit();

    const rpc_thread = try std.Thread.spawn(.{}, RPCServer.start, .{rpc_server});
    rpc_thread.detach();
    
    // Setup signal handlers for graceful shutdown
    // Handle SIGINT (Ctrl+C)
    _ = std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);

    // Handle SIGTERM (systemd stop, kill command)
    _ = std.posix.sigaction(std.posix.SIG.TERM, &.{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    }, null);

    std.log.info("✅ ZeiCoin node started successfully", .{});
    std.log.info("Press Ctrl+C to shutdown", .{});
    
    // Main loop - wait for shutdown signal
    var last_status_time = std.time.timestamp();
    var last_reconnection_check = std.time.timestamp();
    var last_sync_retry_check = std.time.timestamp();
    var mining_started = false;
    var initial_sync_done = false;

    while (running.load(.acquire)) {
        const now = std.time.timestamp();

        // Periodic maintenance (only if still running)
        if (running.load(.acquire)) {
            components.network_manager.maintenance();
        }

        // Periodic reconnection check (every 10 seconds)
        if (now - last_reconnection_check >= 10) {
            last_reconnection_check = now;

            const peer_stats = components.network_manager.getPeerStats();
            if (peer_stats.connected == 0 and components.network_manager.bootstrap_nodes.len > 0) {
                std.log.debug("🔄 [AUTO RECONNECT] No peers connected, triggering maintenance", .{});
                // Trigger reconnection attempt via maintenance
                components.network_manager.maintenance();
            }
        }

        // Periodic sync retry check (every 5 seconds)
        if (now - last_sync_retry_check >= 5) {
            last_sync_retry_check = now;

            // CRITICAL FIX: Check for sync timeout before attempting retry
            // This ensures stuck syncs are detected and reset automatically
            components.sync_manager.checkTimeout();

            const sync_state = components.sync_manager.getSyncState();
            std.log.debug("🔄 [PERIODIC SYNC] Check triggered (state: {})", .{sync_state});

            // CRITICAL: Also retry when in failed state (after cooldown expires, recovery can proceed)
            if (sync_state == .idle or sync_state == .failed) {
                const our_height = components.blockchain.getHeight() catch 0;
                const highest_peer_height = components.network_manager.getHighestPeerHeight();

                std.log.debug("🔄 [PERIODIC SYNC] Heights - us: {}, highest peer: {}", .{our_height, highest_peer_height});

                // Only retry if peer has more blocks
                if (highest_peer_height > our_height) {
                    const blocks_behind = highest_peer_height - our_height;
                    std.log.info("🔄 [AUTO SYNC RETRY] {} blocks behind (state: {}), attempting recovery", .{blocks_behind, sync_state});

                    // Wrap in thread to avoid blocking main loop (detectCompetingChain blocks!)
                    _ = std.Thread.spawn(.{}, triggerSyncRecovery, .{ components.sync_manager }) catch |err| {
                        std.log.err("⚠️ [AUTO SYNC RETRY] Failed to spawn recovery thread: {}", .{err});
                    };
                } else if (highest_peer_height == 0) {
                    std.log.debug("🔄 [PERIODIC SYNC] No peers with valid height, skipping retry", .{});
                }
            } else {
                std.log.debug("🔄 [PERIODIC SYNC] State {} not eligible for retry (needs .idle or .failed)", .{sync_state});
            }
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

fn triggerSyncRecovery(sync_manager: *sync.SyncManager) void {
    sync_manager.attemptSyncRecovery() catch |err| {
        std.log.err("Asynchronous sync recovery failed: {}", .{err});
    };
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