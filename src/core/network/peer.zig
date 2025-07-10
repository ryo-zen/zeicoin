// peer.zig - Network peer management
// Clean modular implementation using the new protocol

const std = @import("std");
const net = std.net;
const types = @import("../types/types.zig");

// Re-export the modular components
pub const protocol = @import("protocol/protocol.zig");
pub const messages = @import("protocol/messages/messages.zig");
pub const wire = @import("wire/wire.zig");
pub const PeerManager = @import("peer_manager.zig").PeerManager;
pub const Peer = @import("peer_manager.zig").Peer;
pub const PeerConnection = @import("peer_connection.zig").PeerConnection;
pub const MessageHandler = @import("peer_connection.zig").MessageHandler;

// Re-export commonly used types
pub const MessageType = protocol.MessageType;
pub const DEFAULT_PORT = protocol.DEFAULT_PORT;
pub const MAX_PEERS = protocol.MAX_PEERS;

// Network manager coordinates all networking
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    peer_manager: PeerManager,
    listen_address: ?net.Address,
    server: ?net.Server,
    message_handler: MessageHandler,
    running: bool,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        handler: MessageHandler,
    ) Self {
        return .{
            .allocator = allocator,
            .peer_manager = PeerManager.init(allocator, MAX_PEERS),
            .listen_address = null,
            .server = null,
            .message_handler = handler,
            .running = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stop();
        if (self.server) |*server| {
            server.deinit();
        }
        self.peer_manager.deinit();
    }
    
    /// Start listening for connections
    pub fn listen(self: *Self, port: u16) !void {
        const address = try net.Address.parseIp("0.0.0.0", port);
        self.listen_address = address;
        
        self.server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });
        
        std.log.info("Listening on {}", .{address});
    }
    
    /// Connect to a peer
    pub fn connectToPeer(self: *Self, address: net.Address) !void {
        const peer = try self.peer_manager.addPeer(address);
        
        // Spawn connection thread
        const thread = try std.Thread.spawn(.{}, runPeerConnection, .{
            self, peer
        });
        thread.detach();
    }
    
    /// Run peer connection in thread
    fn runPeerConnection(self: *Self, peer: *Peer) void {
        const stream = net.tcpConnectToAddress(peer.address) catch |err| {
            std.log.err("Failed to connect to {}: {}", .{ peer.address, err });
            self.peer_manager.removePeer(peer.id);
            return;
        };
        
        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit();
        
        conn.run() catch |err| {
            std.log.err("Peer {} connection error: {}", .{ peer, err });
        };
        
        self.peer_manager.removePeer(peer.id);
    }
    
    /// Accept incoming connections
    pub fn acceptConnections(self: *Self) !void {
        const server = self.server orelse return error.NotListening;
        
        self.running = true;
        while (self.running) {
            const connection = server.accept() catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(100 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };
            
            // Add peer
            const peer = self.peer_manager.addPeer(connection.address) catch |err| {
                std.log.warn("Failed to add peer {}: {}", .{ connection.address, err });
                connection.stream.close();
                continue;
            };
            
            // Handle in thread
            const thread = try std.Thread.spawn(.{}, handleIncomingConnection, .{
                self, peer, connection.stream
            });
            thread.detach();
        }
    }
    
    fn handleIncomingConnection(self: *Self, peer: *Peer, stream: net.Stream) void {
        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit();
        
        conn.run() catch |err| {
            std.log.err("Incoming peer {} error: {}", .{ peer, err });
        };
        
        self.peer_manager.removePeer(peer.id);
    }
    
    /// Stop network manager
    pub fn stop(self: *Self) void {
        self.running = false;
    }
    
    /// Broadcast to all peers
    pub fn broadcast(self: *Self, msg_type: MessageType, msg: anytype) !void {
        try self.peer_manager.broadcast(msg_type, msg);
    }
    
    /// Broadcast a new block to all connected peers
    pub fn broadcastBlock(self: *Self, block: types.Block) !void {
        // Create inventory item for the block
        const block_hash = block.hash();
        const item = messages.InventoryItem{
            .item_type = .block,
            .hash = block_hash,
        };
        
        // Create announce message
        var items = [_]messages.InventoryItem{item};
        const announce = try messages.AnnounceMessage.init(self.allocator, &items);
        
        // Broadcast to all peers
        self.broadcast(.announce, announce) catch |err| {
            std.log.warn("Failed to broadcast block: {}", .{err});
        };
        
        std.log.info("Broadcasted block {} to peers", .{
            std.fmt.fmtSliceHexLower(&block_hash)
        });
    }
    
    /// Broadcast a new transaction to all connected peers
    pub fn broadcastTransaction(self: *Self, tx: types.Transaction) void {
        // Create inventory item for the transaction
        const tx_hash = tx.hash();
        const item = messages.InventoryItem{
            .item_type = .transaction,
            .hash = tx_hash,
        };
        
        // Create announce message
        var items = [_]messages.InventoryItem{item};
        const announce = messages.AnnounceMessage.init(self.allocator, &items) catch |err| {
            std.log.warn("Failed to create announce message: {}", .{err});
            return;
        };
        
        // Broadcast to all peers
        self.broadcast(.announce, announce) catch |err| {
            std.log.warn("Failed to broadcast transaction: {}", .{err});
        };
        
        std.log.debug("Broadcasted transaction {} to peers", .{
            std.fmt.fmtSliceHexLower(&tx_hash)
        });
    }
    
    /// Get connected peer count
    pub fn getConnectedPeerCount(self: *Self) usize {
        return self.peer_manager.getConnectedCount();
    }
    
    /// Get highest peer height
    pub fn getHighestPeerHeight(self: *Self) u32 {
        return self.peer_manager.getHighestPeerHeight();
    }
    
    /// Get peer statistics
    pub fn getPeerStats(self: *Self) struct { total: usize, connected: usize, syncing: usize } {
        const stats = self.peer_manager.getPeerCount();
        return .{ .total = stats.total, .connected = stats.connected, .syncing = stats.syncing };
    }
    
    /// Clean up timed out connections
    pub fn maintenance(self: *Self) void {
        self.peer_manager.cleanupTimedOut();
    }
};