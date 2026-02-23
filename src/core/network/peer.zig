// peer.zig - Network peer management
// Clean modular implementation using the new protocol

const std = @import("std");
const net = std.Io.net;
const types = @import("../types/types.zig");
const command_line = @import("../server/command_line.zig");
const ip_detection = @import("ip_detection.zig");
const util = @import("../util/util.zig");

const log = std.log.scoped(.network);

// Re-export the modular components
pub const protocol = @import("protocol/protocol.zig");
pub const message_types = @import("protocol/messages/message_types.zig");
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
    io: std.Io,
    peer_manager: PeerManager,
    listen_address: ?net.IpAddress,
    server: ?net.Server,
    message_handler: MessageHandler,
    running: bool,
    stopped: bool,
    bootstrap_nodes: []command_line.BootstrapNode,
    owns_bootstrap_nodes: bool,
    last_reconnect_attempt: i64,
    active_connections: std.atomic.Value(u32),

    // Exponential backoff for reconnections
    reconnect_backoff_seconds: u32,
    reconnect_consecutive_failures: u32,
    last_successful_connection: i64,

    const Self = @This();
    const MAX_ACTIVE_CONNECTIONS = 100;

    inline fn isRunning(self: *const Self) bool {
        return @atomicLoad(bool, &self.running, .acquire);
    }

    inline fn setRunning(self: *Self, value: bool) void {
        @atomicStore(bool, &self.running, value, .release);
    }
    
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        handler: MessageHandler,
    ) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .peer_manager = PeerManager.init(allocator, io, MAX_PEERS),
            .listen_address = null,
            .server = null,
            .message_handler = handler,
            .running = false,
            .stopped = false,
            .bootstrap_nodes = &[_]command_line.BootstrapNode{},
            .owns_bootstrap_nodes = false,
            .last_reconnect_attempt = 0,
            .active_connections = std.atomic.Value(u32).init(0),
            .reconnect_backoff_seconds = 5,
            .reconnect_consecutive_failures = 0,
            .last_successful_connection = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        // stop() is idempotent - closes connections and waits for all threads to finish
        self.stop();

        // Now safe to release PM's peer refs; all connection threads have exited
        self.peer_manager.deinit();

        // Clean up bootstrap nodes if we own them
        if (self.owns_bootstrap_nodes and self.bootstrap_nodes.len > 0) {
            for (self.bootstrap_nodes) |node| {
                self.allocator.free(node.ip);
            }
            self.allocator.free(self.bootstrap_nodes);
        }
    }
    
    /// Start listening for connections
    pub fn listen(self: *Self, address_str: []const u8, port: u16) !void {
        const address = try net.IpAddress.parse(address_str, port);
        self.listen_address = address;
        
        const io = self.io;
        self.server = try address.listen(io, .{
            .reuse_address = true,
        });
        
        // Set running to true so connection threads can proceed
        self.setRunning(true);
        std.log.info("Network manager started, running={}", .{self.isRunning()});
        
        std.log.info("Listening on {}", .{address});
    }
    
    /// Connect to a peer
    pub fn connectToPeer(self: *Self, address: net.IpAddress) !void {
        // Check if we have too many active connections
        const current_connections = self.active_connections.load(.acquire);
        if (current_connections >= MAX_ACTIVE_CONNECTIONS) {
            return error.TooManyConnections;
        }

        // Prevent self-connections by checking if target IP is our public IP
        const io = self.io;
        if (ip_detection.isSelfConnection(self.allocator, io, address)) {
            std.log.warn("🚫 Self-connection prevented: skipping connection to own public IP {}", .{address});
            return;
        }
        
        std.log.info("Attempting to connect to peer at {}", .{address});
        const peer = try self.peer_manager.addPeer(address);
        std.log.info("Added peer {} to peer manager", .{peer.id});

        // Add ref for the connection thread (released in runPeerConnection)
        peer.addRef();

        // Increment active connections counter
        _ = self.active_connections.fetchAdd(1, .acq_rel);
        errdefer _ = self.active_connections.fetchSub(1, .acq_rel);

        // Spawn connection thread
        const thread = std.Thread.spawn(.{}, runPeerConnection, .{
            self, peer
        }) catch |err| {
            peer.release(); // Undo addRef since thread never started
            self.peer_manager.removePeer(peer.id);
            return err;
        };
        thread.detach();
        std.log.info("Spawned connection thread for peer {}", .{peer.id});
    }
    
    /// Run peer connection in thread
    fn runPeerConnection(self: *Self, peer: *Peer) void {
        defer _ = self.active_connections.fetchSub(1, .acq_rel);
        std.log.info("Connection thread started for peer {} at {}", .{ peer.id, peer.address });

        // Give the network time to fully initialize
        const io = self.io;
        io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
        
        // Check if we're shutting down at the very start
        std.log.info("Checking if network is running: {}", .{self.isRunning()});
        if (!self.isRunning()) {
            std.log.warn("Peer connection aborted - network shutting down (self.running=false)", .{});
            peer.release(); // Release thread's ref; PeerManager.deinit() handles the other
            return;
        }
        
        // Attempt connection
        std.log.info("Starting TCP connection attempt to peer {} at {}", .{ peer.id, peer.address });
        const io_connect = self.io;
        const stream = peer.address.connect(io_connect, .{ .mode = .stream }) catch |err| {
            // Check running state before ANY access to self
            if (!self.isRunning()) {
                std.log.debug("Connection failed during shutdown, skipping cleanup", .{});
                peer.release(); // Release thread's ref; PeerManager.deinit() handles the other
                return;
            }

            // Only log and remove if still running
            // ConnectionRefused is expected for bootstrap nodes that are down - not a critical error
            if (err == error.ConnectionRefused) {
                std.log.warn("Bootstrap node {} unavailable (ConnectionRefused) - this is normal if the node is offline", .{peer.address});
            } else {
                std.log.warn("TCP connection failed to {}: {} - continuing operation", .{ peer.address, err });
            }
            self.peer_manager.removePeer(peer.id); // Releases PeerManager's ref
            peer.release(); // Release thread's ref → ref hits 0 → peer destroyed
            return;
        };
        std.log.info("TCP connection established successfully to peer {} at {}", .{ peer.id, peer.address });

        const io_conn = self.io;

        // Check again before initializing connection
        if (!self.isRunning()) {
            stream.close(io_conn);
            peer.release(); // Release thread's ref; PeerManager.deinit() handles the other
            return;
        }

        // Register stream on peer so PeerManager can close it on timeout to wake the blocked reader
        peer.stream = stream;

        // Re-check after registering stream: stop() may have run in the window before stream was set
        if (!self.isRunning()) {
            stream.close(io_conn);
            peer.stream = null;
            peer.release();
            return;
        }

        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit(io_conn);

        // Run connection loop
        conn.run(io_conn) catch |err| {
            // Only log if still running — skip noisy errors during shutdown
            if (self.isRunning()) {
                if (self.message_handler.onPeerDisconnected) |onDisconnect| {
                    onDisconnect(peer, err) catch |handler_err| {
                        std.log.debug("Disconnect handler error: {}", .{handler_err});
                    };
                }
                const error_msg = switch (err) {
                    error.ConnectionResetByPeer => "connection reset by peer",
                    error.ConnectionRefused => "connection refused",
                    error.ConnectionTimedOut => "connection timed out",
                    error.NetworkUnreachable => "network unreachable",
                    error.HostUnreachable => "host unreachable",
                    error.BrokenPipe => "connection broken",
                    error.EndOfStream => "connection closed",
                    else => @errorName(err),
                };
                std.log.err("🔌 [NETWORK] Peer {} at {any} disconnected ({s})", .{ peer.id, peer.address, error_msg });
            }
            // No early return — fall through to the ref release below
        };
        
        // conn.deinit() (deferred) released PeerConnection's ref.
        // The thread's ref (added in connectToPeer before spawn) must be released here.
        // removePeer releases the PeerManager's ref when running normally.
        if (self.isRunning()) {
            self.peer_manager.removePeer(peer.id);
        } else {
            peer.release(); // release thread's ref; PeerManager.deinit() releases PM's ref
        }
    }
    
    /// Accept incoming connections
    pub fn acceptConnections(self: *Self) !void {
        if (self.server == null) return error.NotListening;
        
        self.setRunning(true);
        while (self.isRunning()) {
            const io = self.io;
            const connection = self.server.?.accept(io) catch |err| switch (err) {
                error.WouldBlock => {
                    io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
                    continue;
                },
                else => {
                    // Keep accept thread alive on transient accept errors.
                    if (!self.isRunning()) return;
                    std.log.warn("Accept failed: {} (continuing)", .{err});
                    io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
                    continue;
                },
            };
            
            // Check connection limit for incoming connections too
            const current_connections = self.active_connections.load(.acquire);
            if (current_connections >= MAX_ACTIVE_CONNECTIONS) {
                std.log.warn("Too many active connections ({}), rejecting incoming connection", .{current_connections});
                connection.close(io);
                continue;
            }

            // Add peer
            const peer = self.peer_manager.addPeer(connection.socket.address) catch |err| {
                std.log.warn("Failed to add peer: {}", .{err});
                connection.close(io);
                continue;
            };

            // Increment active connections counter for incoming connections
            _ = self.active_connections.fetchAdd(1, .acq_rel);
            errdefer _ = self.active_connections.fetchSub(1, .acq_rel);

            // Add ref for the connection thread (released in conn.deinit via handleIncomingConnection)
            peer.addRef();

            // Handle in thread
            const thread = std.Thread.spawn(.{}, handleIncomingConnection, .{
                self, peer, connection
            }) catch |err| {
                std.log.err("Failed to spawn incoming connection thread: {}", .{err});
                peer.release(); // Undo the addRef since thread never started
                connection.close(io);
                self.peer_manager.removePeer(peer.id);
                continue;
            };
            thread.detach();
        }
    }
    
    fn handleIncomingConnection(self: *Self, peer: *Peer, stream: net.Stream) void {
        defer _ = self.active_connections.fetchSub(1, .acq_rel);
        const io = self.io;
        // Check if shutting down
        if (!self.isRunning()) {
            stream.close(io);
            return;
        }

        // Register stream on peer so PeerManager can close it on timeout to wake the blocked reader
        peer.stream = stream;

        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit(io);
        
        conn.run(io) catch |err| {
            // Only log if still running
            if (self.isRunning()) {
                // Call disconnect handler if available
                if (self.message_handler.onPeerDisconnected) |onDisconnect| {
                    onDisconnect(peer, err) catch |handler_err| {
                        std.log.debug("Disconnect handler error: {}", .{handler_err});
                    };
                }
                std.log.err("Incoming peer {} error: {}", .{ peer.id, err });
            }
        };
        
        // Release the thread's reference to the peer.
        // removePeer calls peer.release() internally; if shutting down, release directly.
        if (self.isRunning()) {
            self.peer_manager.removePeer(peer.id);
        } else {
            peer.release();
        }
    }
    
    /// Start network (convenience method that calls listen)
    pub fn start(self: *Self, address_str: []const u8, port: u16) !void {
        try self.listen(address_str, port);
    }
    
    /// Add a peer by string address (parses and delegates to connectToPeer)
    pub fn addPeer(self: *Self, address_str: []const u8) !void {
        const address = try net.IpAddress.parse(address_str, 10801); // Default P2P port
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
        const io_shutdown = self.io;
        io_shutdown.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
        
        // Stop peer manager to close all peer connections
        // This will set all peers to disconnected state
        self.peer_manager.stop();
        
        // Deinit the server to unblock accept()
        // Do this AFTER peer manager stop so existing connections can finish
        if (self.server) |*server| {
            const io = self.io;
            server.deinit(io);
            self.server = null;
        }
        
        // CRITICAL: Must wait for all detached threads to finish
        // Network threads check self.running before accessing peer_manager
        // Poll active_connections with timeout to ensure clean shutdown
        std.log.info("Waiting for network threads to finish...", .{});

        const max_wait_ms: u32 = 5000;  // 5 second timeout
        const poll_interval_ms: u32 = 100;  // Check every 100ms
        var waited_ms: u32 = 0;

        while (waited_ms < max_wait_ms) {
            const active = self.active_connections.load(.acquire);
            if (active == 0) {
                std.log.info("All {} network threads finished cleanly after {}ms", .{0, waited_ms});
                break;
            }
            const io_wait = self.io;
            io_wait.sleep(std.Io.Duration.fromMilliseconds(poll_interval_ms), std.Io.Clock.awake) catch {};
            waited_ms += poll_interval_ms;
        }

        // Verify shutdown completed successfully
        const remaining = self.active_connections.load(.acquire);
        if (remaining > 0) {
            std.log.warn("Shutdown timeout: {} threads still active after {}ms (possible memory leak)", .{remaining, max_wait_ms});
        } else {
            std.log.info("Network shutdown complete", .{});
        }
    }
    
    /// Broadcast to all peers
    pub fn broadcast(self: *Self, msg_type: MessageType, msg: anytype) !void {
        try self.peer_manager.broadcast(msg_type, msg);
    }
    
    /// Broadcast a new block to all connected peers
    /// ZSP-001: Direct block broadcast instead of inventory system
    pub fn broadcastBlock(self: *Self, block: types.Block) !void {
        // ZSP-001: Broadcast block directly instead of using inventory system
        const block_msg = message_types.BlockMessage{ .block = block };
        
        // Broadcast to all peers
        self.broadcast(.block, block_msg) catch |err| {
            std.log.warn("Failed to broadcast block: {}", .{err});
        };
        
        const block_hash = block.hash();
        std.log.debug("Broadcasted block {x} directly to peers (ZSP-001)", .{block_hash});
    }
    
    /// Broadcast a new transaction to all connected peers
    /// ZSP-001: Direct transaction broadcast instead of inventory system
    pub fn broadcastTransaction(self: *Self, tx: types.Transaction) void {
        // ZSP-001: Broadcast transaction directly instead of using inventory system
        const tx_msg = message_types.TransactionMessage{ .transaction = tx };
        
        // Broadcast to all peers
        self.broadcast(.transaction, tx_msg) catch |err| {
            std.log.warn("Failed to broadcast transaction: {}", .{err});
        };
        
        const tx_hash = tx.hash();
        std.log.debug("Broadcasted transaction {x} directly to peers (ZSP-001)", .{tx_hash});
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
    
    /// Set bootstrap nodes for auto-reconnect (creates a copy)
    pub fn setBootstrapNodes(self: *Self, nodes: []const command_line.BootstrapNode) !void {
        // Clean up existing nodes if we own them
        if (self.owns_bootstrap_nodes and self.bootstrap_nodes.len > 0) {
            for (self.bootstrap_nodes) |node| {
                self.allocator.free(node.ip);
            }
            self.allocator.free(self.bootstrap_nodes);
        }
        
        // Create a copy of the nodes
        const nodes_copy = try self.allocator.alloc(command_line.BootstrapNode, nodes.len);
        for (nodes, 0..) |node, i| {
            nodes_copy[i] = .{
                .ip = try self.allocator.dupe(u8, node.ip),
                .port = node.port,
            };
        }
        
        self.bootstrap_nodes = nodes_copy;
        self.owns_bootstrap_nodes = true;
    }
    
    /// Calculate exponential backoff delay
    fn calculateBackoff(consecutive_failures: u32) u32 {
        const base: u32 = 5; // 5 seconds base
        const max_backoff: u32 = 300; // 5 minutes max
        // Cap exponent to prevent u32 overflow (5 * 2^6 = 320 > max_backoff)
        const capped = @min(consecutive_failures, 6);
        const backoff = base * std.math.pow(u32, 2, capped);
        return @min(backoff, max_backoff);
    }

    /// Clean up timed out connections and handle auto-reconnect
    pub fn maintenance(self: *Self) void {
        // Skip maintenance if we're shutting down
        if (@atomicLoad(bool, &self.stopped, .acquire)) return;
        
        // Clean up timed out peers first
        self.peer_manager.cleanupTimedOut();
        
        // Auto-reconnect logic with exponential backoff
        const now = util.getTime();
        const peer_stats = self.getPeerStats();
        const connected_peers = peer_stats.connected;

        // If no connected peers and we have bootstrap nodes, try to reconnect
        if (connected_peers == 0 and self.bootstrap_nodes.len > 0) {
            // Calculate exponential backoff: 5s, 10s, 20s, 40s, 80s, max 300s (5min)
            const backoff = calculateBackoff(self.reconnect_consecutive_failures);

            if (now - self.last_reconnect_attempt >= backoff) {
                self.last_reconnect_attempt = now;
                std.log.info("🔄 [RECONNECT] Attempting reconnection (backoff: {}s, failures: {})", .{ backoff, self.reconnect_consecutive_failures });

                var connection_succeeded = false;
                for (self.bootstrap_nodes) |node| {
                    const address = net.IpAddress.parse(node.ip, node.port) catch |err| {
                        std.log.warn("Failed to parse bootstrap node {s}:{} - {}", .{ node.ip, node.port, err });
                        continue;
                    };

                    self.connectToPeer(address) catch |err| {
                        if (err == error.AlreadyConnected) {
                            std.log.debug("Already connected to bootstrap node {any}", .{address});
                        } else {
                            std.log.debug("Failed to connect to {any}: {}", .{ address, err });
                        }
                        continue;
                    };

                    connection_succeeded = true;
                    break;
                }

                if (connection_succeeded) {
                    // Reset backoff on successful connection
                    self.reconnect_consecutive_failures = 0;
                    self.reconnect_backoff_seconds = 5;
                    self.last_successful_connection = now;
                    std.log.info("✅ [RECONNECT] Connection successful, backoff reset", .{});
                } else {
                    // Increment failure count
                    self.reconnect_consecutive_failures += 1;
                    self.reconnect_backoff_seconds = calculateBackoff(self.reconnect_consecutive_failures);
                    std.log.warn("❌ [RECONNECT] All connections failed, backoff increased to {}s", .{self.reconnect_backoff_seconds});
                }
            }
        }
    }
};
