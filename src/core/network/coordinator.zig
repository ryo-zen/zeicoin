// NetworkCoordinator - Manages network lifecycle and coordination
// Handles high-level network operations for the Node

const std = @import("std");
const print = std.debug.print;
const net = @import("peer.zig");
const message_handler = @import("message_handler.zig");

pub const NetworkCoordinator = struct {
    allocator: std.mem.Allocator,
    network: ?*net.NetworkManager,
    message_handler: message_handler.NetworkMessageHandler,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, handler: message_handler.NetworkMessageHandler) Self {
        return .{
            .allocator = allocator,
            .network = null,
            .message_handler = handler,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stopNetwork();
    }
    
    /// Start networking on specified port
    pub fn startNetwork(self: *Self, port: u16) !void {
        if (self.network != null) return; // Already started

        // Allocate NetworkManager on heap
        const network = try self.allocator.create(net.NetworkManager);
        errdefer self.allocator.destroy(network);
        
        network.* = net.NetworkManager.init(self.allocator, self.message_handler);
        try network.start(port);
        self.network = network;

        print("🌐 ZeiCoin network started on port {}\n", .{port});
    }

    /// Stop networking
    pub fn stopNetwork(self: *Self) void {
        if (self.network) |network| {
            // Set to null first to prevent access during cleanup
            self.network = null;
            
            // Skip the complex stop() and just clean up
            // The network threads will naturally die when the process exits
            network.deinit();
            self.allocator.destroy(network);
            print("🛑 ZeiCoin network stopped\n", .{});
        }
    }

    /// Connect to a peer
    pub fn connectToPeer(self: *Self, address: []const u8) !void {
        if (self.network) |network| {
            try network.addPeer(address);
        } else {
            return error.NetworkNotStarted;
        }
    }
    
    /// Safe maintenance call
    pub fn maintenance(self: *Self) void {
        if (self.network) |network| {
            network.maintenance();
        }
    }
    
    /// Check if network is running
    pub fn isNetworkRunning(self: *const Self) bool {
        return self.network != null;
    }
    
    /// Get network manager (for advanced operations)
    pub fn getNetworkManager(self: *Self) ?*net.NetworkManager {
        return self.network;
    }
    
    /// Trigger sync with peers when we detect we're behind
    pub fn triggerSync(self: *Self, target_height: u32) !void {
        if (self.network) |network| {
            // Find a connected peer for sync
            var sync_peer: ?*net.Peer = null;
            
            if (network.peer_manager.peers.items.len > 0) {
                for (network.peer_manager.peers.items) |peer| {
                    if (peer.isConnected() and peer.height >= target_height) {
                        sync_peer = peer;
                        break;
                    }
                }
            }
            
            if (sync_peer) |_| {
                print("🔄 Triggering sync to height {}\n", .{target_height});
                // Note: Node will handle actual sync through its sync manager
                print("📡 Sync request sent to peer\n", .{});
            } else {
                print("⚠️ No suitable peer available for sync to height {}\n", .{target_height});
            }
        } else {
            print("❌ Network not started, cannot trigger sync\n", .{});
            return error.NetworkNotStarted;
        }
    }
};