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
            network.stop();
            network.deinit();
            self.allocator.destroy(network);
            self.network = null;
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
    
    /// Check if network is running
    pub fn isNetworkRunning(self: *const Self) bool {
        return self.network != null;
    }
    
    /// Get network manager (for advanced operations)
    pub fn getNetworkManager(self: *Self) ?*net.NetworkManager {
        return self.network;
    }
};