// server_v2.zig - Blockchain node server with headers-first sync
// Clean implementation using net_v2.zig

const std = @import("std");
const zen = @import("main.zig");
const types = @import("types.zig");
const net_v2 = @import("net_v2.zig");
const util = @import("util.zig");
const genesis = @import("genesis.zig");
const headerchain = @import("headerchain.zig");

const print = std.debug.print;

pub fn main() !void {
    print("\n", .{});
    print("╔═══════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                  ⚡ ZeiCoin Node Server v2 ⚡                     ║\n", .{});
    print("║                    Headers-First Protocol                         ║\n", .{});
    print("╚═══════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
    
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize blockchain
    var blockchain = try zen.ZeiCoin.init(allocator);
    defer blockchain.deinit();
    
    // Initialize blockchain (will create genesis if needed)
    try blockchain.initializeBlockchain();
    print("✅ Blockchain initialized\n", .{});
    
    // Initialize network
    var network = net_v2.NetworkManager.init(allocator);
    defer network.deinit();
    
    // Connect blockchain to network
    network.setBlockchain(&blockchain);
    // TODO: Update main.zig to use net_v2
    // blockchain.network = &network;
    
    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    var port: u16 = net_v2.DEFAULT_PORT;
    var bootstrap_nodes = std.ArrayList(net_v2.NetworkAddress).init(allocator);
    defer bootstrap_nodes.deinit();
    
    // Parse arguments
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--bootstrap") and i + 1 < args.len) {
            // Parse bootstrap nodes
            var iter = std.mem.tokenizeScalar(u8, args[i + 1], ',');
            while (iter.next()) |node| {
                var parts = std.mem.tokenizeScalar(u8, node, ':');
                const ip = parts.next() orelse continue;
                const node_port = if (parts.next()) |p| try std.fmt.parseInt(u16, p, 10) else net_v2.DEFAULT_PORT;
                
                try bootstrap_nodes.append(.{
                    .ip = try allocator.dupe(u8, ip),
                    .port = node_port,
                });
            }
            i += 1;
        }
    }
    
    // Start network
    try network.start(port);
    
    // Connect to bootstrap nodes
    if (bootstrap_nodes.items.len == 0) {
        // Default bootstrap nodes
        try bootstrap_nodes.append(.{ .ip = "134.199.168.129", .port = 10801 });
        try bootstrap_nodes.append(.{ .ip = "161.189.98.149", .port = 10801 });
    }
    
    for (bootstrap_nodes.items) |node| {
        network.connectToPeer(node) catch |err| {
            print("⚠️ Failed to connect to bootstrap node {}: {}\n", .{ node, err });
        };
    }
    
    // Start auto-mining thread
    const mining_thread = try std.Thread.spawn(.{}, autoMineLoop, .{ &blockchain, &network });
    defer mining_thread.join();
    
    // Main loop
    print("\n🌐 Node running on port {}. Press Ctrl+C to stop.\n", .{port});
    print("📊 Current height: {}\n", .{try blockchain.getHeight()});
    
    // Status loop
    while (true) {
        std.time.sleep(10 * std.time.ns_per_s); // Every 10 seconds
        
        const height = try blockchain.getHeight();
        const peers = network.getConnectedPeerCount();
        const mempool_count = blockchain.mempool.items.len;
        
        print("\n📊 Status: Height={} | Peers={} | Mempool={}\n", .{ height, peers, mempool_count });
    }
}

fn autoMineLoop(blockchain: *zen.ZeiCoin, network: *net_v2.NetworkManager) void {
    print("⛏️ Auto-mining thread started\n", .{});
    
    while (true) {
        // Check if there are transactions to mine
        if (blockchain.mempool.items.len > 0) {
            print("⛏️ Mining block with {} transactions...\n", .{blockchain.mempool.items.len});
            
            const block = blockchain.mineBlock() catch |err| {
                print("❌ Mining failed: {}\n", .{err});
                std.time.sleep(5 * std.time.ns_per_s);
                continue;
            };
            defer block.deinit(blockchain.allocator);
            
            // Process our own block
            blockchain.addBlock(block) catch |err| {
                print("❌ Failed to process mined block: {}\n", .{err});
                continue;
            };
            
            print("✅ Mined block {} with hash {s}\n", .{ block.header.height, std.fmt.fmtSliceHexLower(&block.hash()) });
            
            // Broadcast to network
            network.broadcastBlock(block);
        }
        
        std.time.sleep(1 * std.time.ns_per_s); // Check every second
    }
}