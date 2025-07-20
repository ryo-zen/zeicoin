// peer.zig - Network peer management
// Clean modular implementation using the new protocol

const std = @import("std");
const net = std.net;
const types = @import("../types/types.zig");
const command_line = @import("../server/command_line.zig");

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
    stopped: bool,
    bootstrap_nodes: []const command_line.BootstrapNode,
    last_reconnect_attempt: i64,
    
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
            .stopped = false,
            .bootstrap_nodes = &[_]command_line.BootstrapNode{},
            .last_reconnect_attempt = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        // Fast shutdown: just clean up resources without complex thread synchronization
        // Set flags atomically
        @atomicStore(bool, &self.stopped, true, .release);
        @atomicStore(bool, &self.running, false, .release);
        
        // Clean up server immediately
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
        
        // Clean up peer manager
        self.peer_manager.deinit();
        
        // Note: bootstrap_nodes is a slice, not owned by us, so no cleanup needed
        
        // Process will exit soon anyway, so threads will be cleaned up by OS
    }
    
    /// Start listening for connections
    pub fn listen(self: *Self, port: u16) !void {
        const address = try net.Address.parseIp("0.0.0.0", port);
        self.listen_address = address;
        
        self.server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });
        
        // Set running to true so connection threads can proceed
        self.running = true;
        std.log.info("Network manager started, running={}", .{self.running});
        
        std.log.info("Listening on {}", .{address});
    }
    
    /// Connect to a peer
    pub fn connectToPeer(self: *Self, address: net.Address) !void {
        std.log.info("Attempting to connect to peer at {}", .{address});
        const peer = try self.peer_manager.addPeer(address);
        std.log.info("Added peer {} to peer manager", .{peer.id});
        
        // Spawn connection thread
        const thread = try std.Thread.spawn(.{}, runPeerConnection, .{
            self, peer
        });
        thread.detach();
        std.log.info("Spawned connection thread for peer {}", .{peer.id});
    }
    
    /// Run peer connection in thread
    fn runPeerConnection(self: *Self, peer: *Peer) void {
        std.log.info("Connection thread started for peer {} at {}", .{ peer.id, peer.address });
        
        // Give the network time to fully initialize
        std.time.sleep(100 * std.time.ns_per_ms);
        
        // Check if we're shutting down at the very start
        std.log.info("Checking if network is running: {}", .{self.running});
        if (!self.running) {
            std.log.warn("Peer connection aborted - network shutting down (self.running=false)", .{});
            return;
        }
        
        // Attempt connection
        std.log.info("Starting TCP connection attempt to peer {} at {}", .{ peer.id, peer.address });
        const stream = net.tcpConnectToAddress(peer.address) catch |err| {
            // Check running state before ANY access to self
            if (!self.running) {
                std.log.debug("Connection failed during shutdown, skipping cleanup", .{});
                return;
            }
            
            // Only log and remove if still running
            std.log.err("TCP connection failed to {}: {}", .{ peer.address, err });
            self.peer_manager.removePeer(peer.id);
            return;
        };
        std.log.info("TCP connection established successfully to peer {} at {}", .{ peer.id, peer.address });
        
        // Check again before initializing connection
        if (!self.running) {
            stream.close();
            return;
        }
        
        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit();
        
        // Run connection loop
        conn.run() catch |err| {
            // Check running state before logging
            if (!self.running) {
                std.log.debug("Peer error during shutdown, skipping log", .{});
                return;
            }
            
            std.log.err("Peer {} connection error: {}", .{ peer, err });
        };
        
        // Final check before peer removal
        if (!self.running) {
            std.log.debug("Skipping peer removal during shutdown", .{});
            return;
        }
        
        self.peer_manager.removePeer(peer.id);
    }
    
    /// Accept incoming connections
    pub fn acceptConnections(self: *Self) !void {
        if (self.server == null) return error.NotListening;
        
        self.running = true;
        while (self.running) {
            const connection = self.server.?.accept() catch |err| switch (err) {
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
        // Check if shutting down
        if (!self.running) {
            stream.close();
            return;
        }
        
        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit();
        
        conn.run() catch |err| {
            // Only log if still running
            if (self.running) {
                std.log.err("Incoming peer {} error: {}", .{ peer, err });
            }
        };
        
        // Only remove peer if still running
        if (self.running) {
            self.peer_manager.removePeer(peer.id);
        }
    }
    
    /// Start network (convenience method that calls listen)
    pub fn start(self: *Self, port: u16) !void {
        try self.listen(port);
    }
    
    /// Add a peer by string address (parses and delegates to connectToPeer)
    pub fn addPeer(self: *Self, address_str: []const u8) !void {
        const address = try std.net.Address.parseIp4(address_str, 10801); // Default P2P port
        try self.connectToPeer(address);
    }
    
    /// Stop network manager
    pub fn stop(self: *Self) void {
        // Prevent multiple stop calls - use atomic operation for thread safety
        if (@atomicLoad(bool, &self.stopped, .acquire)) return;
        @atomicStore(bool, &self.stopped, true, .release);
        
        // Signal shutdown first - this must happen before ANY cleanup
        @atomicStore(bool, &self.running, false, .release);
        
        // Give threads a moment to see the running flag change
        std.time.sleep(100 * std.time.ns_per_ms);
        
        // Stop peer manager to close all peer connections
        // This will set all peers to disconnected state
        self.peer_manager.stop();
        
        // Deinit the server to unblock accept()
        // Do this AFTER peer manager stop so existing connections can finish
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
        
        // CRITICAL: Must wait for all detached threads to finish
        // Network threads check self.running before accessing peer_manager
        // 3 seconds should be enough for all threads to exit cleanly
        std.log.info("Waiting for network threads to finish...", .{});
        std.time.sleep(3000 * std.time.ns_per_ms);
        std.log.info("Network shutdown complete", .{});
    }
    
    /// Broadcast to all peers
    pub fn broadcast(self: *Self, msg_type: MessageType, msg: anytype) !void {
        try self.peer_manager.broadcast(msg_type, msg);
    }
    
    /// Broadcast a new block to all connected peers
    /// ZSP-001: Direct block broadcast instead of inventory system
    pub fn broadcastBlock(self: *Self, block: types.Block) !void {
        // ZSP-001: Broadcast block directly instead of using inventory system
        const block_msg = messages.BlockMessage{ .block = block };
        
        // Broadcast to all peers
        self.broadcast(.block, block_msg) catch |err| {
            std.log.warn("Failed to broadcast block: {}", .{err});
        };
        
        const block_hash = block.hash();
        std.log.info("Broadcasted block {} directly to peers (ZSP-001)", .{
            std.fmt.fmtSliceHexLower(&block_hash)
        });
    }
    
    /// Broadcast a new transaction to all connected peers
    /// ZSP-001: Direct transaction broadcast instead of inventory system
    pub fn broadcastTransaction(self: *Self, tx: types.Transaction) void {
        // ZSP-001: Broadcast transaction directly instead of using inventory system
        const tx_msg = messages.TransactionMessage{ .transaction = tx };
        
        // Broadcast to all peers
        self.broadcast(.transaction, tx_msg) catch |err| {
            std.log.warn("Failed to broadcast transaction: {}", .{err});
        };
        
        const tx_hash = tx.hash();
        std.log.debug("Broadcasted transaction {} directly to peers (ZSP-001)", .{
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
    
    /// Set bootstrap nodes for auto-reconnect
    pub fn setBootstrapNodes(self: *Self, nodes: []const command_line.BootstrapNode) void {
        self.bootstrap_nodes = nodes;
    }
    
    /// Clean up timed out connections and handle auto-reconnect
    pub fn maintenance(self: *Self) void {
        // Skip maintenance if we're shutting down
        if (@atomicLoad(bool, &self.stopped, .acquire)) return;
        
        // Clean up timed out peers first
        self.peer_manager.cleanupTimedOut();
        
        // Auto-reconnect logic
        const now = std.time.timestamp();
        const peer_stats = self.getPeerStats();
        const connected_peers = peer_stats.connected;
        
        // If no connected peers and we have bootstrap nodes, try to reconnect
        if (connected_peers == 0 and self.bootstrap_nodes.len > 0) {
            // Only attempt reconnect every 30 seconds to avoid spam
            if (now - self.last_reconnect_attempt >= 30) {
                std.log.info("🔄 Auto-reconnect: No peers connected, attempting to reconnect to bootstrap nodes", .{});
                self.last_reconnect_attempt = now;
                
                // Try to connect to each bootstrap node
                for (self.bootstrap_nodes) |node| {
                    const address = std.net.Address.parseIp(node.ip, node.port) catch |err| {
                        std.log.warn("Failed to parse bootstrap node {s}:{} - {}", .{ node.ip, node.port, err });
                        continue;
                    };
                    
                    self.connectToPeer(address) catch |err| {
                        std.log.warn("Auto-reconnect failed to {any} - {}", .{ address, err });
                    };
                }
            }
        }
    }
};