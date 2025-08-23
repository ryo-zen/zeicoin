// status.zig - Blockchain Status Reporting Module
// Handles status display and monitoring output

const std = @import("std");
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const net = @import("../network/peer.zig");
const NetworkCoordinator = @import("../network/coordinator.zig").NetworkCoordinator;

const log = std.log.scoped(.monitoring);

pub const StatusReporter = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    network_coordinator: *NetworkCoordinator,
    
    pub fn init(allocator: std.mem.Allocator, database: *db.Database, network_coordinator: *NetworkCoordinator) StatusReporter {
        return .{
            .allocator = allocator,
            .database = database,
            .network_coordinator = network_coordinator,
        };
    }
    
    pub fn deinit(self: *StatusReporter) void {
        _ = self;
    }
    
    /// Print blockchain status
    pub fn printStatus(self: *StatusReporter) void {
        log.info("📊 ZeiCoin Blockchain Status:", .{});
        const height = self.database.getHeight() catch 0;
        const account_count = self.database.getAccountCount() catch 0;
        log.info("   Height: {} blocks", .{height});
        log.info("   Pending: {} transactions (moved to MempoolManager)", .{0});
        log.info("   Accounts: {} active", .{account_count});

        // Show network status
        if (self.network_coordinator.getNetworkManager()) |network| {
            const connected_peers = network.getConnectedPeers();
            const total_peers = network.peers.items.len;
            log.info("   Network: {} of {} peers connected", .{ connected_peers, total_peers });

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
                    log.info("     {s} {s}", .{ status, addr_str });
                }
            }
        } else {
            log.info("   Network: offline", .{});
        }

        // Show recent blocks
        const start_idx = if (height > 3) height - 3 else 0;
        var i = start_idx;
        while (i < height) : (i += 1) {
            if (self.database.getBlock(i)) |block_data| {
                var block = block_data;
                log.info("   Block #{}: {} txs", .{ i, block.txCount() });
                // Free block memory after displaying
                block.deinit(self.allocator);
            } else |_| {
                log.info("   Block #{}: Error loading", .{i});
            }
        }
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
            .network_peers = if (self.network_coordinator.getNetworkManager()) |n| n.peer_manager.peers.items.len else 0,
            .connected_peers = if (self.network_coordinator.getNetworkManager()) |n| n.peer_manager.getConnectedPeers() else 0,
        };
    }
};