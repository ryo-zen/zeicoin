// status.zig - Blockchain Status Reporting Module
// Handles status display and monitoring output

const std = @import("std");
const print = std.debug.print;
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const net = @import("../network/peer.zig");

pub const StatusReporter = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    network: *?*net.NetworkManager,
    
    pub fn init(allocator: std.mem.Allocator, database: *db.Database, network: *?*net.NetworkManager) StatusReporter {
        return .{
            .allocator = allocator,
            .database = database,
            .network = network,
        };
    }
    
    pub fn deinit(self: *StatusReporter) void {
        _ = self;
    }
    
    /// Print blockchain status
    pub fn printStatus(self: *StatusReporter) void {
        print("\n📊 ZeiCoin Blockchain Status:\n", .{});
        const height = self.database.getHeight() catch 0;
        const account_count = self.database.getAccountCount() catch 0;
        print("   Height: {} blocks\n", .{height});
        print("   Pending: {} transactions (moved to MempoolManager)\n", .{0});
        print("   Accounts: {} active\n", .{account_count});

        // Show network status
        if (self.network.*) |network| {
            const connected_peers = network.getConnectedPeers();
            const total_peers = network.peers.items.len;
            print("   Network: {} of {} peers connected\n", .{ connected_peers, total_peers });

            if (total_peers > 0) {
                for (network.peers.items) |peer| {
                    var addr_buf: [32]u8 = undefined;
                    const addr_str = peer.address.toString(&addr_buf);
                    const status = switch (peer.state) {
                        .connected => "🟢",
                        .connecting => "🟡",
                        .handshaking => "🟡",
                        .reconnecting => "🛜",
                        .disconnecting => "🔴",
                        .disconnected => "🔴",
                    };
                    print("     {s} {s}\n", .{ status, addr_str });
                }
            }
        } else {
            print("   Network: offline\n", .{});
        }

        // Show recent blocks
        const start_idx = if (height > 3) height - 3 else 0;
        var i = start_idx;
        while (i < height) : (i += 1) {
            if (self.database.getBlock(i)) |block_data| {
                var block = block_data;
                print("   Block #{}: {} txs\n", .{ i, block.txCount() });
                // Free block memory after displaying
                block.deinit(self.allocator);
            } else |_| {
                print("   Block #{}: Error loading\n", .{i});
            }
        }
        print("\n", .{});
    }
    
    pub fn getStatus(self: *StatusReporter) !types.BlockchainStatus {
        // Get mempool count from blockchain's mempool manager
        const mempool_count = if (self.blockchain.mempool_manager) |mempool| 
            mempool.getTransactionCount() 
        else 
            0;
            
        return types.BlockchainStatus{
            .height = try self.database.getHeight(),
            .account_count = try self.database.getAccountCount(),
            .mempool_count = mempool_count,
            .network_peers = if (self.network.*) |n| n.peers.items.len else 0,
            .connected_peers = if (self.network.*) |n| n.getConnectedPeers() else 0,
        };
    }
};