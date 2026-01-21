// server.zig - ZeiCoin node server (modular version)
// Thin coordinator that delegates to specialized modules

const std = @import("std");
const log = std.log.scoped(.server);
const print = std.debug.print;
const command_line = @import("command_line.zig");
const initialization = @import("initialization.zig");
const client_api = @import("client_api.zig");
const sync = @import("../sync/manager.zig");
const util = @import("../util/util.zig");
const RPCServer = @import("../rpc/server.zig").RPCServer;

// Signal handling for graceful shutdown
var running = std.atomic.Value(bool).init(true);

fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    running.store(false, .release);
    // Signal received - main loop will exit and trigger defer cleanup
}

pub fn main(init: std.process.Init) !void {
    // Print banner
    printBanner();

    // Setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get args
    const args = try std.process.Args.toSlice(init.minimal.args, allocator);
    defer allocator.free(args);

    // Load .env file if present
    @import("../util/dotenv.zig").loadForNetwork(std.heap.page_allocator) catch |err| {
        if (err != error.FileNotFound) {
            log.info("⚠️  Warning: Failed to load .env file: {}", .{err});
        }
    };

    // Parse command line
    var config = command_line.parseArgs(allocator, args) catch |err| switch (err) {
        error.HelpRequested => return,
        error.MissingMinerWallet => return,
        error.UnknownArgument => return,
        else => return err,
    };
    defer config.deinit();

    // Initialize node components
    var components = initialization.initializeNode(allocator, init.io, config) catch |err| switch (err) {
        error.OpenFailed => {
            std.debug.print("❌ Database is locked or in use by another process\n", .{});
            std.debug.print("💡 Stop any running ZeiCoin servers and try again\n", .{});
            return;
        },
        else => return err,
    };
    defer components.deinit();

    // Start Client API if not disabled
    var api_server_ptr: ?*client_api.ClientApiServer = null;
    if (!config.client_api_disabled) {
        api_server_ptr = try allocator.create(client_api.ClientApiServer);
        api_server_ptr.?.* = client_api.ClientApiServer.init(allocator, components.blockchain, config.bind_address);

        // Initialize listener before spawning thread to catch early errors
        try api_server_ptr.?.setup();

        const api_thread = std.Thread.spawn(.{}, client_api.ClientApiServer.start, .{api_server_ptr.?}) catch |err| blk: {
            log.err("❌ Failed to spawn Client API thread: {}", .{err});
            break :blk null;
        };
        if (api_thread) |thread| {
            thread.detach();
            std.log.info("✅ Client API thread detached", .{});
        }
    }
    defer if (api_server_ptr) |server| {
        server.deinit();
        allocator.destroy(server);
    };

    // Start RPC server
    const RPC_PORT = 10803;
    const types = @import("../types/types.zig");
    const data_dir = types.CURRENT_NETWORK.getDataDir();
    var rpc_server = try RPCServer.init(allocator, components.blockchain, data_dir, RPC_PORT);
    defer rpc_server.deinit();

    const rpc_thread = try std.Thread.spawn(.{}, RPCServer.start, .{rpc_server});
    rpc_thread.detach();

    // Setup signal handlers for graceful shutdown
    _ = std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    _ = std.posix.sigaction(std.posix.SIG.TERM, &.{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    std.log.info("✅ ZeiCoin node started successfully", .{});
    std.log.info("Press Ctrl+C to shutdown", .{});

    // Main loop
    var last_status_time = util.getTime();
    var last_reconnection_check = util.getTime();
    var last_sync_retry_check = util.getTime();
    var mining_started = false;
    var initial_sync_done = false;
    const io = components.blockchain.io;

    while (running.load(.acquire)) {
        const now = util.getTime();

        if (running.load(.acquire)) {
            components.network_manager.maintenance();
        }

        // Periodic reconnection check (10s)
        if (now - last_reconnection_check >= 10) {
            last_reconnection_check = now;
            const peer_stats = components.network_manager.getPeerStats();
            if (peer_stats.connected == 0 and components.network_manager.bootstrap_nodes.len > 0) {
                components.network_manager.maintenance();
            }
        }

        // Periodic sync retry check (5s)
        if (now - last_sync_retry_check >= 5) {
            last_sync_retry_check = now;
            components.sync_manager.checkTimeout();
            const sync_state = components.sync_manager.getSyncState();

            if (sync_state == .idle or sync_state == .failed) {
                const our_height = components.blockchain.getHeight() catch 0;
                const highest_peer_height = components.network_manager.getHighestPeerHeight();

                if (highest_peer_height > our_height) {
                    _ = std.Thread.spawn(.{}, triggerSyncRecovery, .{components.sync_manager}) catch {};
                }
            }
        }

        // Mining start logic
        if (!mining_started and components.blockchain.mining_manager != null) {
            const should_start_mining = blk: {
                const peer_stats = components.network_manager.getPeerStats();
                if (peer_stats.connected == 0) {
                    if (!initial_sync_done) {
                        io.sleep(std.Io.Duration.fromSeconds(5), std.Io.Clock.awake) catch {};
                        initial_sync_done = true;
                        break :blk true;
                    } else break :blk false;
                }
                if (components.sync_manager.isActive()) break :blk false;
                break :blk true;
            };

            if (should_start_mining) {
                if (startMiningAfterSync(&components)) mining_started = true;
            }
        }

        // Print status (30s)
        if (now - last_status_time >= 30 and running.load(.acquire)) {
            printStatus(&components);
            last_status_time = now;
        }

        io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
    }

    std.log.info("Shutting down...", .{});
    if (components.blockchain.mining_manager) |mining_manager| mining_manager.stopMining();
    if (api_server_ptr) |server| server.stop();
}

fn triggerSyncRecovery(sync_manager: *sync.SyncManager) void {
    sync_manager.attemptSyncRecovery() catch {};
}

fn printBanner() void {
    print("\n", .{});
    print("╔═══════════════════════════════════════════════════════════════╗\n", .{});
    print("║                  ⚡ ZeiCoin Node Server ⚡                    ║\n", .{});
    print("║                    Modular Architecture                       ║\n", .{});
    print("╚═══════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

fn startMiningAfterSync(components: *const initialization.NodeComponents) bool {
    if (components.blockchain.mining_manager) |mining_manager| {
        log.info("⛏️  Starting mining after initial sync completion", .{});
        mining_manager.startMiningDeferred() catch |err| {
            log.err("❌ Failed to start mining after sync: {}", .{err});
            return false;
        };
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
