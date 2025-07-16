// network_coordinator.zig - Network Coordination Module
// Handles peer management, broadcasting, and network-related operations

const std = @import("std");
const print = std.debug.print;

const types = @import("../../types/types.zig");
const net = @import("../peer.zig");
const sync_mod = @import("../../sync/sync.zig");
const ZeiCoin = @import("../../node.zig").ZeiCoin;

const Block = types.Block;
const Transaction = types.Transaction;

/// Network coordinator handles all network-related operations
pub const NetworkCoordinator = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    const Self = @This();
    
    /// Initialize network coordinator
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
        };
    }
    
    /// Broadcast new block to network peers
    pub fn broadcastBlock(self: *Self, block: Block) !void {
        if (self.blockchain.network_coordinator.getNetworkManager()) |network| {
            print("📡 Broadcasting new block to {} peers\n", .{network.peer_manager.getConnectedCount()});
            try network.broadcastBlock(block);
        } else {
            print("⚠️  No network manager - block not broadcasted\n", .{});
        }
    }
    
    /// Broadcast block after processing (with cleanup)
    pub fn broadcastBlockAfterProcessing(self: *Self, owned_block: *Block) !void {
        // Create copy for broadcast
        const block_copy = owned_block.dupe(self.allocator) catch |err| {
            print("⚠️  Failed to duplicate block for broadcast: {}\n", .{err});
            owned_block.deinit(self.allocator);
            return;
        };
        
        self.broadcastBlock(block_copy) catch |err| {
            print("⚠️  Failed to broadcast block: {}\n", .{err});
        };
        // Cleanup handled by broadcastBlock
        
        // Clean up original block
        owned_block.deinit(self.allocator);
    }
    
    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction, peer: ?*net.Peer) !void {
        // Log peer info if available
        if (peer) |p| {
            print("💰 Transaction received from peer {}\n", .{p.id});
        } else {
            print("💰 Transaction received from network peer\n", .{});
        }
        
        // Forward to blockchain's transaction handler
        // The mempool manager will handle validation and broadcasting
        try self.blockchain.handleIncomingTransaction(transaction);
        
        print("✅ Transaction processed successfully\n", .{});
    }
    
    /// Check connected peers for new blocks (periodic operation)
    pub fn checkForNewBlocks(self: *Self) !void {
        // Only check if we're not already syncing
        if (self.getSyncState() != .synced) return;
        
        const network = self.blockchain.network orelse return;
        
        // Find and query one connected peer
        if (try self.findConnectedPeer(network)) |peer| {
            self.requestHeightUpdate(peer) catch {
                print("⚠️  Height request failed for peer {}\n", .{peer.address});
            };
        }
    }
    
    /// Get current sync state for network coordination
    pub fn getSyncState(self: *Self) sync_mod.SyncState {
        // Check if sync manager is available
        if (self.blockchain.sync_manager) |sync_manager| {
            return sync_manager.getSyncState();
        }
        
        // Default to synced if no sync manager
        return .synced;
    }
    
    /// Start network with specified port
    pub fn startNetwork(self: *Self, port: u16) !void {
        try self.blockchain.startNetwork(port);
    }
    
    /// Stop network operations
    pub fn stopNetwork(self: *Self) void {
        self.blockchain.stopNetwork();
    }
    
    /// Connect to a specific peer
    pub fn connectToPeer(self: *Self, address: []const u8) !void {
        try self.blockchain.connectToPeer(address);
    }
    
    /// Check if we should sync with a peer
    pub fn shouldSync(self: *Self, peer_height: u32) !bool {
        return try self.blockchain.shouldSync(peer_height);
    }
    
    /// Process downloaded block during sync
    pub fn processDownloadedBlock(self: *Self, block: Block, expected_height: u32) !void {
        if (!try self.blockchain.validateSyncBlock(block, expected_height)) {
            return error.InvalidBlock;
        }
        try self.blockchain.addBlockToChain(block, expected_height);
    }
    
    /// Validate block during sync
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.blockchain.validateSyncBlock(block, expected_height);
    }
    
    // Private helper functions
    
    /// Find a connected peer for querying
    fn findConnectedPeer(self: *Self, network: anytype) !?*net.Peer {
        _ = self;
        
        network.peers_mutex.lock();
        defer network.peers_mutex.unlock();

        // Count connected peers
        var connected_count: usize = 0;
        for (network.peers.items) |peer| {
            if (peer.state == .connected) connected_count += 1;
        }

        if (connected_count == 0) return null;

        // Find first connected peer (simple approach)
        for (network.peers.items) |*peer| {
            if (peer.state == .connected) {
                return peer;
            }
        }
        
        return null;
    }
    
    /// Request height update from a specific peer
    fn requestHeightUpdate(self: *Self, peer: *net.Peer) !void {
        const our_height = try self.blockchain.getHeight();
        try peer.sendGetHeaders(our_height, 1);
        print("📤 Requested height update from peer {} (starting from height {})\n", .{ peer.address, our_height });
    }
};

// Tests
test "NetworkCoordinator initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Mock blockchain
    var mock_blockchain: ZeiCoin = undefined;
    
    const coordinator = NetworkCoordinator.init(allocator, &mock_blockchain);
    try testing.expectEqual(allocator, coordinator.allocator);
}