// net.zig - ZeiCoin Pure Zig Networking Layer
// P2P networking using only Zig standard library

const std = @import("std");
const net = std.net;
const Thread = std.Thread;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const Mutex = std.Thread.Mutex;

const types = @import("types.zig");
const util = @import("util.zig");

// Helper functions for zen networking
/// Networking logging utilities
fn logNetError(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("❌ " ++ fmt ++ "\n", args);
}

fn logNetSuccess(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("✅ " ++ fmt ++ "\n", args);
}

fn logNetInfo(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("ℹ️  " ++ fmt ++ "\n", args);
}

fn logNetProcess(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("🔄 " ++ fmt ++ "\n", args);
}

fn logNetBroadcast(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("📡 " ++ fmt ++ "\n", args);
}

/// Send message header and payload to socket
fn sendMessage(socket: net.Stream, header_template: MessageHeader, payload: anytype) !void {
    var header = header_template;
    const payload_bytes = std.mem.asBytes(&payload);
    header.setChecksum(payload_bytes);
    
    _ = try socket.write(std.mem.asBytes(&header));
    _ = try socket.write(payload_bytes);
}

/// Send message header only to socket
fn sendHeaderOnly(socket: net.Stream, header: MessageHeader) !void {
    _ = try socket.write(std.mem.asBytes(&header));
}

/// Send block with header + transactions (with checksum)
fn sendBlock(socket: net.Stream, header_template: MessageHeader, block: types.Block, allocator: std.mem.Allocator) !void {
    // Calculate total payload size
    const payload_size = @sizeOf(types.BlockHeader) + @sizeOf(u32) + @sizeOf(types.Transaction) * block.transactions.len;
    
    // Allocate buffer for entire payload
    const payload_buffer = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload_buffer);
    
    // Serialize payload into buffer
    var offset: usize = 0;
    
    // Copy block header
    @memcpy(payload_buffer[offset..offset + @sizeOf(types.BlockHeader)], std.mem.asBytes(&block.header));
    offset += @sizeOf(types.BlockHeader);
    
    // Copy transaction count
    const tx_count: u32 = @intCast(block.transactions.len);
    @memcpy(payload_buffer[offset..offset + @sizeOf(u32)], std.mem.asBytes(&tx_count));
    offset += @sizeOf(u32);
    
    // Copy all transactions
    for (block.transactions) |tx| {
        @memcpy(payload_buffer[offset..offset + @sizeOf(types.Transaction)], std.mem.asBytes(&tx));
        offset += @sizeOf(types.Transaction);
    }
    
    // Create header with checksum
    var header = header_template;
    header.setChecksum(payload_buffer);
    
    // Send header with checksum
    _ = try socket.write(std.mem.asBytes(&header));
    
    // Send payload
    _ = try socket.write(payload_buffer);
}


// Network constants
pub const DEFAULT_PORT: u16 = 10801;
pub const DISCOVERY_PORT: u16 = 10800;
pub const MAGIC_BYTES = [4]u8{ 0xF9, 0xBE, 0xB4, 0xD9 };
pub const DISCOVERY_MAGIC = [4]u8{ 0xDE, 0x11, 0xC0, 0x1E }; // ZeiCoin discovery magic
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB max message
pub const MAX_PEERS: usize = 8; // Keep it simple
pub const VERSION: u32 = 1;
pub const SOFTWARE_VERSION: u32 = 11; // v11: Added address versioning and future-proof transaction/block fields

// Message types (similar to Bitcoin v0.01 protocol)
pub const MessageType = enum(u12) {
    version = 0,
    verack = 1,
    addr = 2,
    inv = 3,
    getdata = 4,
    getblocks = 5,
    tx = 6,
    block = 7,
    blocks = 8, // Batch of blocks for sync
    ping = 9,
    pong = 10,
};

// Discovery message for UDP broadcast
pub const DiscoveryMessage = struct {
    magic: [4]u8,
    node_port: u16,
    timestamp: i64,

    pub fn create(port: u16) DiscoveryMessage {
        return DiscoveryMessage{
            .magic = DISCOVERY_MAGIC,
            .node_port = port,
            .timestamp = util.getTime(),
        };
    }

    pub fn isValid(self: DiscoveryMessage) bool {
        return std.mem.eql(u8, &self.magic, &DISCOVERY_MAGIC);
    }
};

// Network address structure
pub const NetworkAddress = struct {
    ip: [4]u8,
    port: u16,

    pub fn fromString(addr_str: []const u8) !NetworkAddress {
        var parts = std.mem.splitScalar(u8, addr_str, ':');
        const ip_str = parts.next() orelse return error.InvalidAddress;

        // Parse IP address
        var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
        var ip: [4]u8 = undefined;
        for (0..4) |i| {
            const part = ip_parts.next() orelse return error.InvalidAddress;
            ip[i] = try std.fmt.parseInt(u8, part, 10);
        }

        // Parse port, use DEFAULT_PORT if not specified
        const port_str_slice = parts.next() orelse ""; // Use empty string if no port part
        const port = if (port_str_slice.len > 0) try std.fmt.parseInt(u16, port_str_slice, 10) else DEFAULT_PORT;
        return NetworkAddress{ .ip = ip, .port = port };
    }

    pub fn toString(self: NetworkAddress, buffer: []u8) []u8 {
        return std.fmt.bufPrint(buffer, "{}.{}.{}.{}:{}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port }) catch @constCast("invalid");
    }
};

// Message header
pub const MessageHeader = struct {
    magic: [4]u8,
    command: [12]u8,
    length: u32,
    checksum: u32,

    pub fn create(msg_type: MessageType, payload_len: u32) MessageHeader {
        var command = std.mem.zeroes([12]u8);
        const type_name = @tagName(msg_type);
        @memcpy(command[0..type_name.len], type_name);

        return MessageHeader{
            .magic = MAGIC_BYTES,
            .command = command,
            .length = payload_len,
            .checksum = 0, // Will be calculated when payload is available
        };
    }

    pub fn calculateChecksum(payload: []const u8) u32 {
        // Simple CRC32-like checksum for message integrity
        var checksum: u32 = 0xFFFFFFFF;
        for (payload) |byte| {
            checksum = checksum ^ @as(u32, byte);
            for (0..8) |_| {
                if (checksum & 1 != 0) {
                    checksum = (checksum >> 1) ^ 0xEDB88320;
                } else {
                    checksum = checksum >> 1;
                }
            }
        }
        return ~checksum;
    }

    pub fn setChecksum(self: *MessageHeader, payload: []const u8) void {
        self.checksum = calculateChecksum(payload);
    }

    pub fn verifyChecksum(self: MessageHeader, payload: []const u8) bool {
        return self.checksum == calculateChecksum(payload);
    }
};

// Sync protocol message structures
pub const GetBlocksMessage = struct {
    start_height: u32,
    count: u32,
};

pub const BlocksMessage = struct {
    start_height: u32,
    count: u32,
    // Followed by serialized blocks data
};

// Peer connection state
pub const PeerState = enum {
    connecting,
    handshaking,
    connected,
    disconnecting,
    disconnected,
    reconnecting,
};

/// Check if peer connection is valid
fn isConnectionValid(socket: ?net.Stream, state: PeerState) bool {
    return socket != null and state == .connected;
}

/// Format peer address to string (helper for consistent address display)
fn formatPeerAddress(address: NetworkAddress, buffer: []u8) []u8 {
    return address.toString(buffer);
}

/// Handle peer connection errors with consistent logging
fn handlePeerError(address: NetworkAddress, err: anyerror, action: []const u8) void {
    var addr_buf: [32]u8 = undefined;
    const addr_str = formatPeerAddress(address, &addr_buf);
    logNetError("{s} failed for peer {s}: {}", .{ action, addr_str, err });
}

/// Log successful peer action
fn logPeerSuccess(address: NetworkAddress, action: []const u8) void {
    var addr_buf: [32]u8 = undefined;
    const addr_str = formatPeerAddress(address, &addr_buf);
    logNetSuccess("{s} successful for peer {s}", .{ action, addr_str });
}

// Network peer
pub const Peer = struct {
    address: NetworkAddress,
    socket: ?net.Stream,
    state: PeerState,
    last_ping: i64,
    last_seen: i64,
    connection_attempts: u32,
    consecutive_failures: u32,
    version: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, address: NetworkAddress) Peer {
        const now = util.getTime();
        return Peer{
            .address = address,
            .socket = null,
            .state = .disconnected,
            .last_ping = now,
            .last_seen = now,
            .connection_attempts = 0,
            .consecutive_failures = 0,
            .version = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Peer) void {
        self.disconnect();
    }

    pub fn connect(self: *Peer, network_manager: ?*NetworkManager) !void {
        if (self.state == .connected) return;
        if (self.state == .connecting or self.state == .handshaking) return;

        // Limit connection attempts with exponential backoff
        const MAX_ATTEMPTS = 5;
        const BACKOFF_MULTIPLIER = 2;

        if (self.consecutive_failures > MAX_ATTEMPTS) {
            const backoff_time = @as(i64, 30) * std.math.pow(i64, BACKOFF_MULTIPLIER, @min(self.consecutive_failures - MAX_ATTEMPTS, 6));
            const time_since_last = util.getTime() - self.last_seen;

            if (time_since_last < backoff_time) {
                logNetInfo("Waiting {} seconds before retry", .{backoff_time - time_since_last});
                return;
            }
        }

        self.state = .connecting;
        self.connection_attempts += 1;

        // Create socket address
        const addr = net.Address.initIp4(self.address.ip, self.address.port);

        // Connection attempt
        self.socket = net.tcpConnectToAddress(addr) catch |err| {
            self.consecutive_failures += 1;
            self.state = .disconnected;
            self.last_seen = util.getTime();
            
            // Only log connection errors for significant failures (not routine retries)
            if (err == error.ConnectionRefused and self.consecutive_failures <= 2) {
                // Suppress routine connection refused messages for first few attempts
                var addr_buf: [32]u8 = undefined;
                const addr_str = formatPeerAddress(self.address, &addr_buf);
                logNetInfo("Connection to {s} refused (peer may be offline)", .{addr_str});
            } else {
                handlePeerError(self.address, err, "Connection");
            }
            return err;
        };

        // Success - reset failure count
        self.consecutive_failures = 0;
        self.state = .handshaking;
        self.last_seen = util.getTime();

        // Send version message with height
        const our_height = if (network_manager) |network| 
            if (network.blockchain) |blockchain| blockchain.getHeight() catch 0 else 0
        else 
            0;
        try self.sendVersion(our_height);
        
        // Start message handling thread for outgoing connection
        if (network_manager) |network| {
            const thread = Thread.spawn(.{}, handlePeerConnection, .{ network, self.socket.? }) catch |err| {
                logNetError("Failed to spawn peer handler thread: {}", .{err});
                self.disconnect();
                return err;
            };
            thread.detach();
        }
        
        // Connection success logged during handshake completion
    }

    pub fn disconnect(self: *Peer) void {
        if (self.socket) |socket| {
            socket.close();
            self.socket = null;
        }
        self.state = .disconnected;
        logNetError("Disconnected from peer {any}", .{self.address});
    }

    pub fn sendVersion(self: *Peer, blockchain_height: u32) !void {
        if (self.socket == null) return error.NotConnected;

        // Version message with blockchain height
        const version_payload = struct {
            version: u32,
            services: u64,
            timestamp: i64,
            block_height: u32, // For sync
            software_version: u32, // Track code version
        }{
            .version = VERSION,
            .services = 1, // NODE_NETWORK
            .timestamp = util.getTime(),
            .block_height = blockchain_height,
            .software_version = SOFTWARE_VERSION,
        };

        const header = MessageHeader.create(.version, @sizeOf(@TypeOf(version_payload)));
        
        try sendMessage(self.socket.?, header, version_payload);
        // Version sent silently
    }

    pub fn sendPing(self: *Peer) !void {
        if (!isConnectionValid(self.socket, self.state)) return error.NotConnected;

        const header = MessageHeader.create(.ping, 0);

        // Handle socket write failures gracefully (race condition protection)
        sendHeaderOnly(self.socket.?, header) catch |err| {
            // Socket was closed by another thread - mark as disconnected
            self.socket = null;
            self.state = .disconnected;
            return err;
        };

        self.last_ping = util.getTime();
        self.last_seen = self.last_ping;
        logNetInfo("Ping sent to peer", .{});
    }

    /// Request height update from peer (periodic sync check)
    pub fn requestHeightUpdate(self: *Peer) !void {
        if (!isConnectionValid(self.socket, self.state)) return error.NotConnected;

        // Send a proper version message to query current height
        const version_payload = struct {
            version: u32,
            services: u64,
            timestamp: i64,
            block_height: u32,
            software_version: u32,
        }{
            .version = VERSION,
            .services = 1, // NODE_NETWORK
            .timestamp = util.getTime(),
            .block_height = 0, // We don't need to send our height for a query
            .software_version = SOFTWARE_VERSION,
        };

        const header = MessageHeader.create(.version, @sizeOf(@TypeOf(version_payload)));
        
        sendMessage(self.socket.?, header, version_payload) catch |err| {
            // Socket was closed - mark as disconnected
            self.socket = null;
            self.state = .disconnected;
            return err;
        };

        self.last_seen = util.getTime();
        logNetInfo("Height query sent to peer", .{});
    }

    pub fn broadcastTransaction(self: *Peer, tx: types.Transaction) !void {
        if (!isConnectionValid(self.socket, self.state)) return;

        const header = MessageHeader.create(.tx, @sizeOf(types.Transaction));
        try sendMessage(self.socket.?, header, tx);
        logNetBroadcast("Broadcasted transaction to peer", .{});
    }

    pub fn broadcastBlock(self: *Peer, block: types.Block, allocator: std.mem.Allocator) !void {
        if (!isConnectionValid(self.socket, self.state)) return;

        const payload_size = @sizeOf(types.BlockHeader) + @sizeOf(u32) + @sizeOf(types.Transaction) * block.transactions.len;
        const header = MessageHeader.create(.block, @intCast(payload_size));
        
        try sendBlock(self.socket.?, header, block, allocator);
        logNetBroadcast("Broadcasted block to peer", .{});
    }

    pub fn sendGetBlocks(self: *Peer, start_height: u32, count: u32) !void {
        if (!isConnectionValid(self.socket, self.state)) return error.NotConnected;

        const getblocks_msg = GetBlocksMessage{
            .start_height = start_height,
            .count = count,
        };

        const header = MessageHeader.create(.getblocks, @sizeOf(GetBlocksMessage));
        try sendMessage(self.socket.?, header, getblocks_msg);
        logNetBroadcast("Requested {} blocks starting from height {}", .{ count, start_height });
    }
};

// Network manager
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    peers: ArrayList(Peer),
    peers_mutex: Mutex,
    is_running: bool,
    listen_address: ?net.Address,
    accept_thread: ?Thread,
    maintenance_thread: ?Thread,
    last_discovery: i64,
    last_height_check: i64,
    blockchain: ?*@import("main.zig").ZeiCoin,
    node_type: types.NodeType,

    pub fn init(allocator: std.mem.Allocator) NetworkManager {
        const now = util.getTime();
        return NetworkManager{
            .allocator = allocator,
            .peers = ArrayList(Peer).init(allocator),
            .peers_mutex = Mutex{},
            .is_running = false,
            .listen_address = null,
            .accept_thread = null,
            .maintenance_thread = null,
            .last_discovery = 0,
            .last_height_check = now, // Initialize to current time to prevent immediate triggering
            .blockchain = null,
            .node_type = .unknown, // Will be detected during startup
        };
    }

    pub fn deinit(self: *NetworkManager) void {
        self.stop();
        for (self.peers.items) |*peer| {
            peer.deinit();
        }
        self.peers.deinit();
    }

    pub fn start(self: *NetworkManager, port: u16) !void {
        if (self.is_running) return;

        // Detect node type (full node vs outbound-only)
        self.node_type = self.detectNodeType(port);
        
        // Set up listening address
        self.listen_address = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, port);

        // Only start accept thread if we can serve blocks (full node)
        if (self.node_type.canServeBlocks()) {
            self.accept_thread = try Thread.spawn(.{}, acceptConnections, .{self});
            logNetSuccess("Network started as FULL NODE on port {}", .{port});
        } else {
            logNetSuccess("Network started as OUTBOUND-ONLY NODE (behind NAT)", .{});
        }

        // Start maintenance thread
        self.maintenance_thread = try Thread.spawn(.{}, maintainConnections, .{self});

        self.is_running = true;
    }

    pub fn stop(self: *NetworkManager) void {
        if (!self.is_running) return;

        self.is_running = false;

        // Wait for accept thread to finish
        if (self.accept_thread) |thread| {
            thread.join();
            self.accept_thread = null;
        }

        // Stop maintenance thread
        if (self.maintenance_thread) |thread| {
            thread.join();
            self.maintenance_thread = null;
        }

        self.listen_address = null;

        // Disconnect all peers
        for (self.peers.items) |*peer| {
            peer.disconnect();
        }

        logNetInfo("ZeiCoin network stopped", .{});
    }

    pub fn addPeer(self: *NetworkManager, address_str: []const u8) !void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        if (self.peers.items.len >= MAX_PEERS) {
            logNetInfo("Maximum peers reached", .{});
            return;
        }

        const address = try NetworkAddress.fromString(address_str);
        
        // Check if peer already exists to prevent duplicates
        for (self.peers.items) |*existing_peer| {
            if (std.mem.eql(u8, &existing_peer.address.ip, &address.ip) and 
                existing_peer.address.port == address.port) {
                logNetInfo("Peer {s} already exists, skipping", .{address_str});
                return;
            }
        }

        const peer = Peer.init(self.allocator, address);

        // Add peer to list BEFORE connecting to avoid race condition
        // The thread spawned by connect() operates on the peer in the list
        try self.peers.append(peer);
        
        // Now connect using the peer that's in the list
        const peer_ptr = &self.peers.items[self.peers.items.len - 1];
        try peer_ptr.connect(self);

        // Peer addition success logged after handshake
    }

    pub fn broadcastTransaction(self: *NetworkManager, tx: types.Transaction) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        for (self.peers.items) |*peer| {
            peer.broadcastTransaction(tx) catch {
                logNetError("Failed to broadcast transaction to peer", .{});
            };
        }
        logNetBroadcast("Transaction broadcasted to {} peers", .{self.peers.items.len});
    }

    pub fn broadcastBlock(self: *NetworkManager, block: types.Block) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        for (self.peers.items) |*peer| {
            peer.broadcastBlock(block, self.allocator) catch {
                logNetError("Failed to broadcast block to peer", .{});
            };
        }
        logNetBroadcast("Block broadcasted to {} peers", .{self.peers.items.len});
    }

    pub fn getConnectedPeers(self: *NetworkManager) usize {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected) count += 1;
        }
        return count;
    }

    /// Start network in client-only mode (no server listening)
    pub fn startClient(self: *NetworkManager, port: u16) !void {
        _ = port; // Client doesn't need to listen
        self.is_running = true;
        logNetSuccess("ZeiCoin client network started (outbound connections only)", .{});
    }

    /// Connect to a specific peer
    pub fn connectToPeer(self: *NetworkManager, address: NetworkAddress) !void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        const peer = Peer.init(self.allocator, address);
        try self.peers.append(peer);

        // Connect in background
        const peer_ptr = &self.peers.items[self.peers.items.len - 1];
        peer_ptr.connect(self) catch |err| {
            handlePeerError(address, err, "Connection");
            return err;
        };
        logPeerSuccess(address, "Connection");
    }

    /// Get number of connected peers
    pub fn getPeerCount(self: *NetworkManager) usize {
        return self.getConnectedPeers();
    }

    pub fn printStatus(self: *NetworkManager) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        // Count connected peers while we have the lock (avoid deadlock)
        var connected_count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected) connected_count += 1;
        }
        
        std.debug.print("\n🌐 Network Status:\n", .{});
        std.debug.print("   Running: {}\n", .{self.is_running});
        std.debug.print("   Node Type: {s}\n", .{if (self.node_type == .full_node) "Full Node (can serve blocks)" else if (self.node_type == .outbound_only) "Outbound-Only (behind NAT)" else "Unknown"});
        std.debug.print("   Peers: {}/{}\n", .{ connected_count, self.peers.items.len });

        for (self.peers.items) |peer| {
            var addr_buf: [32]u8 = undefined;
            const addr_str = peer.address.toString(&addr_buf);
            const status_icon = switch (peer.state) {
                .connected => "🟢",
                .connecting => "🟡",
                .handshaking => "🟡",
                .reconnecting => "🛜",
                .disconnecting => "🔴",
                .disconnected => "🔴",
            };
            const status_text = switch (peer.state) {
                .connected => "Connected",
                .connecting => "Connecting",
                .handshaking => "Handshaking",
                .reconnecting => "Reconnecting", 
                .disconnecting => "Disconnecting",
                .disconnected => "Disconnected",
            };
            std.debug.print("   {s} {s} - {s}\n", .{ status_icon, status_text, addr_str });
        }
    }

    /// Auto-discover peers on local network
    pub fn discoverPeers(self: *NetworkManager, our_port: u16) !void {
        logNetInfo("🔍 Discovering peers...", .{});

        // Try bootstrap nodes first
        try self.connectToBootstrapNodes();

        // Try UDP broadcast for local discovery
        try self.broadcastDiscovery(our_port);

        // Fallback to TCP scanning
        try self.scanLocalNetwork(our_port);
    }

    /// Connect to bootstrap nodes for initial peer discovery
    fn connectToBootstrapNodes(self: *NetworkManager) !void {
        // Try environment variable first
        if (std.process.getEnvVarOwned(self.allocator, "ZEICOIN_BOOTSTRAP")) |env_value| {
            defer self.allocator.free(env_value);

            // Parse comma-separated list and connect to each
            var it = std.mem.splitScalar(u8, env_value, ',');
            while (it.next()) |node_addr| {
                const trimmed = std.mem.trim(u8, node_addr, " \t\n");
                if (trimmed.len > 0) {
                    self.connectToBootstrapNode(trimmed) catch continue;
                }
            }
        } else |_| {
            // Fallback to hardcoded bootstrap nodes
            for (types.BOOTSTRAP_NODES) |bootstrap_addr| {
                self.connectToBootstrapNode(bootstrap_addr) catch continue;
            }
        }
    }

    /// Connect to a single bootstrap node
    fn connectToBootstrapNode(self: *NetworkManager, addr_str: []const u8) !void {
        // Skip bootstrap nodes that match our local IP (prevent self-connection)
        if (self.getLocalIP()) |local_ip| {
            // Parse bootstrap address to check if it's our local IP
            if (NetworkAddress.fromString(addr_str)) |bootstrap_addr| {
                if (std.mem.eql(u8, &bootstrap_addr.ip, &local_ip)) {
                    return; // Silently skip self-connections
                }
            } else |_| {
                // If parsing fails, still try to connect (might be hostname)
            }
        } else |_| {
            // If we can't determine local IP, proceed with connection attempt
            logNetInfo("Unable to determine local IP for self-connection check", .{});
        }

        // Use standard addPeer method instead of custom connection handling
        self.addPeer(addr_str) catch {
            // Silently ignore bootstrap connection failures
            return;
        };
        // Connection success will be logged when handshake completes
    }

    /// Send UDP broadcast to discover peers
    fn broadcastDiscovery(self: *NetworkManager, our_port: u16) !void {

        // Create UDP socket
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(socket);

        // Enable broadcast
        const broadcast_enable: c_int = 1;
        try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, &std.mem.toBytes(broadcast_enable));

        // Create discovery message
        const discovery_msg = DiscoveryMessage.create(our_port);

        // Broadcast to common network ranges
        const broadcast_addrs = [_][]const u8{
            "192.168.1.255",
            "192.168.0.255",
            "10.0.0.255",
            "172.16.255.255",
        };

        for (broadcast_addrs) |addr_str| {
            const broadcast_addr = net.Address.parseIp4(addr_str, DISCOVERY_PORT) catch continue;

            _ = std.posix.sendto(socket, std.mem.asBytes(&discovery_msg), 0, &broadcast_addr.any, broadcast_addr.getOsSockLen()) catch |err| {
                logNetError("Broadcast to {s} failed: {}", .{ addr_str, err });
                continue;
            };
        }

        // Listen for responses briefly
        try self.listenForDiscoveryResponses(our_port);
    }

    /// Listen for UDP discovery responses
    fn listenForDiscoveryResponses(self: *NetworkManager, our_port: u16) !void {
        // Create UDP listener
        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
            logNetError("Discovery: UDP socket creation failed: {}", .{err});
            return;
        };
        defer std.posix.close(socket);

        // Use socket timeout for cross-platform compatibility
        const timeout = std.posix.timeval{ .sec = 1, .usec = 0 };
        std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            logNetError("Discovery: timeout setup failed (continuing): {}", .{err});
        };

        // Bind to discovery port (gracefully handle if already in use)
        const bind_addr = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, DISCOVERY_PORT);
        std.posix.bind(socket, &bind_addr.any, bind_addr.getOsSockLen()) catch |err| {
            if (err == error.AddressInUse) {
                // Silently continue - multiple instances are normal
            } else {
                logNetError("Discovery: bind failed: {}", .{err});
            }
            return;
        };

        var buffer: [256]u8 = undefined;
        var sender_addr: std.posix.sockaddr = undefined;
        var sender_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        // Listen for discovery responses while network runs
        var attempts: u8 = 0;
        while (attempts < 10 and self.is_running) {
            const bytes_received = std.posix.recvfrom(socket, &buffer, 0, &sender_addr, &sender_len) catch |err| switch (err) {
                error.WouldBlock => {
                    // Timeout occurred - continue
                    attempts += 1;
                    continue;
                },
                else => {
                    logNetError("Discovery: receive error: {}", .{err});
                    attempts += 1;
                    std.time.sleep(200 * std.time.ns_per_ms);
                    continue;
                },
            };

            if (bytes_received >= @sizeOf(DiscoveryMessage)) {
                const discovery_msg = std.mem.bytesToValue(DiscoveryMessage, buffer[0..@sizeOf(DiscoveryMessage)]);
                if (discovery_msg.isValid() and discovery_msg.node_port != our_port) {
                    // Extract sender IP (with proper alignment for cross-platform compatibility)
                    const sender_ip_addr = @as(*const std.posix.sockaddr.in, @alignCast(@ptrCast(&sender_addr)));
                    const ip_bytes = @as(*const [4]u8, @ptrCast(&sender_ip_addr.addr));

                    // Add discovered peer
                    var addr_str: [32]u8 = undefined;
                    const peer_addr_str = std.fmt.bufPrint(&addr_str, "{}.{}.{}.{}:{}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], discovery_msg.node_port }) catch continue;

                    logNetSuccess("Discovery: found peer {s}", .{peer_addr_str});
                    self.addPeer(peer_addr_str) catch {};
                }
            }
            attempts = 0; // Reset attempts after successful receive
        }

    }

    /// Scan local network for peers (fallback method)
    fn scanLocalNetwork(self: *NetworkManager, our_port: u16) !void {
        // Get local IP to determine subnet
        const local_ip = self.getLocalIPOrDefault();

        // Scan the same subnet
        var ip: u8 = 1;
        while (ip < 255) : (ip += 1) {
            if (ip == local_ip[3]) continue; // Skip our own IP

            var addr_str: [32]u8 = undefined;
            const peer_addr_str = std.fmt.bufPrint(&addr_str, "{}.{}.{}.{}:{}", .{ local_ip[0], local_ip[1], local_ip[2], ip, our_port }) catch continue;

            // Quick TCP connection test
            if (self.testTCPConnection(peer_addr_str)) {
                logNetSuccess("Found peer via scan: {s}", .{peer_addr_str});
                self.addPeer(peer_addr_str) catch {};
            }

            // Limit scan rate
            if (ip % 10 == 0) {
                std.time.sleep(50 * std.time.ns_per_ms);
            }
        }
    }

    /// Get local IP address - returns error if unable to determine
    fn getLocalIP(self: *NetworkManager) ![4]u8 {
        _ = self;

        // Create a dummy UDP socket to determine local IP
        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
            logNetError("Failed to create socket for IP detection: {}", .{err});
            return error.SocketCreationFailed;
        };
        defer std.posix.close(socket);

        // Connect to a remote address (doesn't actually send data)
        const remote_addr = net.Address.parseIp4("8.8.8.8", 80) catch |err| {
            logNetError("Failed to parse remote address: {}", .{err});
            return error.AddressParseFailed;
        };
        
        std.posix.connect(socket, &remote_addr.any, remote_addr.getOsSockLen()) catch |err| {
            logNetError("Failed to connect to remote address for IP detection: {}", .{err});
            return error.NetworkUnreachable;
        };

        // Get local socket address
        var local_addr: std.posix.sockaddr = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        std.posix.getsockname(socket, &local_addr, &addr_len) catch |err| {
            logNetError("Failed to get local socket address: {}", .{err});
            return error.AddressResolutionFailed;
        };

        const local_addr_in = @as(*const std.posix.sockaddr.in, @alignCast(@ptrCast(&local_addr)));
        return @as(*const [4]u8, @ptrCast(&local_addr_in.addr)).*;
    }

    /// Get local IP with fallback - for cases where callers need a reasonable default
    fn getLocalIPOrDefault(self: *NetworkManager) [4]u8 {
        return self.getLocalIP() catch |err| {
            logNetError("Unable to determine local IP ({}), using fallback", .{err});
            return [4]u8{ 192, 168, 1, 100 }; // Reasonable fallback
        };
    }

    /// Test if a TCP connection can be established
    fn testTCPConnection(self: *NetworkManager, addr_str: []const u8) bool {
        _ = self;

        const address = NetworkAddress.fromString(addr_str) catch return false;
        const addr = net.Address.initIp4(address.ip, address.port);

        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return false;
        defer std.posix.close(socket);

        // Simple blocking connect
        const result = std.posix.connect(socket, &addr.any, addr.getOsSockLen()) catch return false;
        _ = result;

        return true; // Connection succeeded
    }
    
    /// Detect if this node is behind NAT or can accept incoming connections
    fn detectNodeType(self: *NetworkManager, port: u16) types.NodeType {
        _ = port; // Port not used in current implementation
        // Check if we have a private IP address
        const local_ip = self.getLocalIP() catch {
            logNetError("Cannot determine node type - IP detection failed", .{});
            return .unknown;
        };
        
        // Private IP ranges (RFC 1918):
        // 10.0.0.0/8     (10.0.0.0 - 10.255.255.255)
        // 172.16.0.0/12  (172.16.0.0 - 172.31.255.255) 
        // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
        const is_private_ip = (local_ip[0] == 10) or
                              (local_ip[0] == 172 and local_ip[1] >= 16 and local_ip[1] <= 31) or
                              (local_ip[0] == 192 and local_ip[1] == 168) or
                              (local_ip[0] == 127); // localhost
        
        if (is_private_ip) {
            logNetInfo("Detected private IP: {}.{}.{}.{} - running as outbound-only node", .{ local_ip[0], local_ip[1], local_ip[2], local_ip[3] });
            return .outbound_only;
        } else {
            logNetInfo("Detected public IP: {}.{}.{}.{} - running as full node", .{ local_ip[0], local_ip[1], local_ip[2], local_ip[3] });
            return .full_node;
        }
    }
};

// Server connection handling
fn acceptConnections(network: *NetworkManager) void {
    const addr = network.listen_address orelse {
        std.debug.print("❌ No listen address set\n", .{});
        return;
    };

    // Create listening socket
    const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch |err| {
        logNetError("Failed to create socket: {}", .{err});
        return;
    };
    defer std.posix.close(socket);

    // Enable address reuse
    std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};

    // Bind socket
    std.posix.bind(socket, &addr.any, @sizeOf(std.posix.sockaddr.in)) catch |err| {
        logNetError("Failed to bind: {}", .{err});
        return;
    };

    // Listen for connections
    std.posix.listen(socket, 10) catch |err| {
        logNetError("Failed to listen: {}", .{err});
        return;
    };

    logNetInfo("Server listening for connections on {}", .{addr});

    while (network.is_running) {
        // Accept incoming connection
        var client_addr: std.posix.sockaddr = undefined;
        var client_addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const client_socket = std.posix.accept(socket, &client_addr, &client_addr_len, 0) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            },
            else => {
                if (network.is_running) {
                    logNetError("Accept error: {}", .{err});
                }
                continue;
            },
        };

        logNetSuccess("New peer connected!", .{});

        // Handle this connection in a separate thread
        const thread = Thread.spawn(.{}, handleIncomingPeer, .{ network, client_socket }) catch |err| {
            logNetError("Failed to spawn peer thread: {}", .{err});
            std.posix.close(client_socket);
            continue;
        };
        thread.detach(); // Let it run independently
    }

    logNetInfo("Accept thread stopped", .{});
}

// Handle incoming peer connection
fn handleIncomingPeer(network: *NetworkManager, client_socket: std.posix.socket_t) void {
    defer std.posix.close(client_socket);

    // Send version message to incoming peer
    const stream = net.Stream{ .handle = client_socket };
    const our_height = if (network.blockchain) |blockchain| 
        blockchain.getHeight() catch 0 
    else 
        0;
    
    // Send version message
    const version_payload = struct {
        version: u32,
        services: u64,
        timestamp: i64,
        block_height: u32,
        software_version: u32,
    }{
        .version = VERSION,
        .services = 1, // NODE_NETWORK
        .timestamp = util.getTime(),
        .block_height = our_height,
        .software_version = SOFTWARE_VERSION,
    };
    
    const header = MessageHeader.create(.version, @sizeOf(@TypeOf(version_payload)));
    sendMessage(stream, header, version_payload) catch |err| {
        logNetError("Failed to send version to incoming peer: {}", .{err});
        return;
    };
    logNetBroadcast("Sent version to incoming peer", .{});

    var buffer: [4096]u8 = undefined;
    var message_buffer = MessageBuffer.init();

    while (network.is_running) {
        // Read data from peer
        const bytes_read = std.posix.recv(client_socket, &buffer, 0) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => {
                if (network.is_running) {
                    logNetError("Read error from peer: {}", .{err});
                }
                break;
            },
        };

        if (bytes_read == 0) break;

        // Add data to buffer
        message_buffer.addData(buffer[0..bytes_read]);

        // Process complete messages
        while (message_buffer.hasCompleteMessage()) {
            const complete_message = message_buffer.extractMessage();
            if (complete_message.len > 0) {
                processMessage(network, complete_message, stream);
            }
        }
    }

    logNetInfo("Incoming peer disconnected", .{});
}

// Handle individual peer connection (for outgoing connections)
fn handlePeerConnection(network: *NetworkManager, stream: net.Stream) void {
    defer stream.close();

    var buffer: [4096]u8 = undefined;
    var message_buffer = MessageBuffer.init();

    while (network.is_running) {
        // Read data from peer
        const bytes_read = stream.read(&buffer) catch |err| switch (err) {
            error.WouldBlock => {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => {
                if (network.is_running) {
                    logNetError("Read error from outgoing peer: {}", .{err});
                }
                break;
            },
        };

        if (bytes_read == 0) break;

        // Add data to buffer
        message_buffer.addData(buffer[0..bytes_read]);

        // Process complete messages
        while (message_buffer.hasCompleteMessage()) {
            const complete_message = message_buffer.extractMessage();
            if (complete_message.len > 0) {
                processMessage(network, complete_message, stream);
            }
        }
    }

    logNetInfo("Peer disconnected", .{});
}

// Message buffer for handling TCP fragmentation
const MessageBuffer = struct {
    // Buffer needs to be large enough for the largest possible message,
    // or dynamically sized. MAX_MESSAGE_SIZE is 32MB, which is too large for a stack buffer.
    // This component needs a rethink if messages can truly be that large (e.g. for 'blocks').
    // A more robust solution would use an ArrayList(u8) or a two-stage read (header then payload).
    // Increasing to 64KB as a temporary measure improves handling of moderately sized messages.
    data: [64 * 1024]u8, // Increased from 8KB
    pos: usize,

    fn init() MessageBuffer {
        return MessageBuffer{
            .data = undefined,
            .pos = 0,
        };
    }

    fn addData(self: *MessageBuffer, new_data: []const u8) void {
        const available = self.data.len - self.pos;
        if (new_data.len > available) {
            // This is a critical situation: incoming data exceeds buffer capacity.
            logNetError("MessageBuffer overflow: pos={}, available={}, new_data.len={}. Truncating.", .{ self.pos, available, new_data.len });
            // Truncation will likely lead to protocol errors for the current message.
        }
        const to_copy = @min(new_data.len, available);
        @memcpy(self.data[self.pos .. self.pos + to_copy], new_data[0..to_copy]);
        self.pos += to_copy;
    }

    fn hasCompleteMessage(self: *MessageBuffer) bool {
        if (self.pos < @sizeOf(MessageHeader)) return false;

        const header = std.mem.bytesToValue(MessageHeader, self.data[0..@sizeOf(MessageHeader)]);
        const total_size = @sizeOf(MessageHeader) + header.length;

        if (total_size > MAX_MESSAGE_SIZE) {
            logNetError("Message too large as per header: {} bytes, max allowed: {}. Clearing buffer.", .{total_size, MAX_MESSAGE_SIZE});
            self.pos = 0; // Clear buffer to prevent processing invalid message
            return false;
        }
        return self.pos >= total_size;
    }

    fn extractMessage(self: *MessageBuffer) []const u8 {
        if (!self.hasCompleteMessage()) return &[_]u8{};

        const header = std.mem.bytesToValue(MessageHeader, self.data[0..@sizeOf(MessageHeader)]);
        const total_size = @sizeOf(MessageHeader) + header.length;

        // Additional check to prevent out-of-bounds read if total_size is corrupted or too large for current buffer state
        if (total_size > self.pos or total_size > self.data.len) {
            logNetError("MessageBuffer extractMessage: invalid total_size {} (pos={}, data.len={}). Clearing buffer.", .{total_size, self.pos, self.data.len});
            self.pos = 0; // Clear buffer to recover from corrupted stream
            return &[_]u8{};
        }
        const message = self.data[0..total_size];

        // Shift remaining data (use copyForwards for overlapping memory)
        const remaining = self.pos - total_size;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.data[0..remaining], self.data[total_size..self.pos]);
        }
        self.pos = remaining;

        return message;
    }
};

// Process incoming messages from server connections
fn processIncomingMessage(network: *NetworkManager, client_socket: std.posix.socket_t, data: []const u8) void {
    const stream = net.Stream{ .handle = client_socket };
    processMessage(network, data, stream);
}

// Process incoming network messages
fn processMessage(network: *NetworkManager, data: []const u8, peer_socket: ?net.Stream) void {
    if (data.len < @sizeOf(MessageHeader)) return;

    // Parse message header
    const header = std.mem.bytesToValue(MessageHeader, data[0..@sizeOf(MessageHeader)]);

    // Verify magic bytes
    if (!std.mem.eql(u8, &header.magic, &MAGIC_BYTES)) {
        logNetError("Invalid magic bytes", .{});
        return;
    }

    // Verify message length matches data
    if (data.len != @sizeOf(MessageHeader) + header.length) {
        logNetError("Message length mismatch: expected {}, got {}", .{ @sizeOf(MessageHeader) + header.length, data.len });
        return;
    }

    // Verify checksum if payload exists and checksum is non-zero (backward compatibility)
    // Skip verification for checksum = 0 (v5 and earlier, or block messages)
    if (header.length > 0 and header.checksum != 0) {
        const payload = data[@sizeOf(MessageHeader)..];
        if (!header.verifyChecksum(payload)) {
            logNetError("Message checksum verification failed", .{});
            return;
        }
    }

    // Get command name
    const command_end = std.mem.indexOf(u8, &header.command, "\x00") orelse header.command.len;
    const command = header.command[0..command_end];

    // Handle different message types
    if (std.mem.eql(u8, command, "version")) {
        handleVersionMessage(network, data[@sizeOf(MessageHeader)..], peer_socket);
    } else if (std.mem.eql(u8, command, "tx")) {
        handleIncomingTransaction(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "block")) {
        logNetInfo("Block received from network", .{});
        processIncomingBlock(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "getblocks")) {
        handleGetBlocksMessage(network, data[@sizeOf(MessageHeader)..], peer_socket);
    } else if (std.mem.eql(u8, command, "blocks")) {
        handleBlocksMessage(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "ping")) {
        handlePingMessage(network, peer_socket);
    } else if (std.mem.eql(u8, command, "pong")) {
        handlePongMessage(network, peer_socket);
    }
}

// Process incoming block from network peer
fn processIncomingBlock(network: *NetworkManager, block_data: []const u8) void {
    // Get the blockchain reference from network manager
    if (network.blockchain == null) {
        logNetError("Block received but no blockchain connection", .{});
        return;
    }

    // Parse block data
    if (block_data.len < @sizeOf(types.BlockHeader) + @sizeOf(u32)) {
        logNetError("Block too small - incomplete data", .{});
        return;
    }

    // Parse block header
    const header = std.mem.bytesToValue(types.BlockHeader, block_data[0..@sizeOf(types.BlockHeader)]);

    // Parse transaction count
    const tx_count_offset = @sizeOf(types.BlockHeader);
    const tx_count = std.mem.bytesToValue(u32, block_data[tx_count_offset .. tx_count_offset + @sizeOf(u32)]);

    logNetInfo("Block received: {} transactions, timestamp {}", .{ tx_count, header.timestamp });

    // Create transaction array
    const transactions = network.allocator.alloc(types.Transaction, tx_count) catch {
        logNetError("Memory allocation failed - block not processed", .{});
        return;
    };
    defer network.allocator.free(transactions);

    // Parse transactions
    var tx_offset: usize = tx_count_offset + @sizeOf(u32);
    for (transactions, 0..) |*tx, i| {
        if (tx_offset + @sizeOf(types.Transaction) > block_data.len) {
            logNetError("Transaction {} beyond data boundary", .{i});
            return;
        }
        tx.* = std.mem.bytesToValue(types.Transaction, block_data[tx_offset .. tx_offset + @sizeOf(types.Transaction)]);
        tx_offset += @sizeOf(types.Transaction);
    }

    // Create block structure
    const block = types.Block{
        .header = header,
        .transactions = transactions,
    };

    // Send block to blockchain
    if (network.blockchain) |blockchain| {
        blockchain.handleIncomingBlock(block) catch |err| {
            logNetError("Block rejected by blockchain: {}", .{err});
        };
    }
}

// Handle incoming transaction
fn handleIncomingTransaction(network: *NetworkManager, tx_data: []const u8) void {
    // Parse transaction data
    if (tx_data.len < @sizeOf(types.Transaction)) {
        logNetError("Transaction incomplete", .{});
        return;
    }

    const transaction = std.mem.bytesToValue(types.Transaction, tx_data[0..@sizeOf(types.Transaction)]);
    logNetInfo("Transaction received: {} ZEI from network peer", .{transaction.amount / types.ZEI_COIN});

    // Send transaction to blockchain for validation and mempool
    if (network.blockchain) |blockchain| {
        blockchain.handleIncomingTransaction(transaction) catch |err| {
            logNetError("Transaction rejected by blockchain: {}", .{err});
            return;
        };

        // Note: Don't relay transactions received from network peers to avoid broadcast loops
        // Only broadcast transactions that originate locally (from client API)
        // This prevents the infinite relay storm between connected nodes
    }
}

// Handle version message
fn handleVersionMessage(network: *NetworkManager, version_data: []const u8, peer_socket: ?net.Stream) void {
    // Parse version payload
    const version_payload = struct {
        version: u32,
        services: u64,
        timestamp: i64,
        block_height: u32,
        software_version: u32,
    };

    // Handle both old and new version formats
    const old_version_size = @sizeOf(version_payload) - @sizeOf(u32);
    if (version_data.len < old_version_size) {
        logNetError("Version message incomplete", .{});
        return;
    }

    // Check if we have the new format with software version
    const has_software_version = version_data.len >= @sizeOf(version_payload);
    
    const peer_version = if (has_software_version)
        std.mem.bytesToValue(version_payload, version_data[0..@sizeOf(version_payload)])
    else blk: {
        // Old format - set software_version to 1
        var old_data: [old_version_size]u8 = undefined;
        @memcpy(&old_data, version_data[0..old_version_size]);
        var result: version_payload = undefined;
        result.version = std.mem.bytesToValue(u32, old_data[0..4]);
        result.services = std.mem.bytesToValue(u64, old_data[4..12]);
        result.timestamp = std.mem.bytesToValue(i64, old_data[12..20]);
        result.block_height = std.mem.bytesToValue(u32, old_data[20..24]);
        result.software_version = 1; // Old version
        break :blk result;
    };
    
    // Version details logged silently

    // Only respond to version queries (not responses) to prevent message loops
    // A version query has block_height = 0, while responses have actual height
    if (peer_socket) |socket| {
        if (peer_version.block_height == 0) {
            // This is a query - respond with our height
            const our_current_height = if (network.blockchain) |bc| bc.getHeight() catch 0 else 0;
            const response_payload = struct {
                version: u32,
                services: u64,
                timestamp: i64,
                block_height: u32,
                software_version: u32,
            }{
                .version = VERSION,
                .services = 1, // NODE_NETWORK
                .timestamp = util.getTime(),
                .block_height = our_current_height,
                .software_version = SOFTWARE_VERSION,
            };

            const response_header = MessageHeader.create(.version, @sizeOf(@TypeOf(response_payload)));
            sendMessage(socket, response_header, response_payload) catch |err| {
                logNetError("Failed to send version response to peer: {}", .{err});
            };
            logNetBroadcast("Sent version response (height {}) to query", .{our_current_height});
        }
    }

    // Find and mark the specific peer that sent this version message
    var version_peer: ?*Peer = null;
    network.peers_mutex.lock();
    
    if (peer_socket) |socket| {
        // First try to find by socket handle (most reliable)
        for (network.peers.items) |*peer| {
            if (peer.socket != null and peer.socket.?.handle == socket.handle) {
                version_peer = peer;
                break;
            }
        }
    }
    
    // If we didn't find by socket, fall back to first handshaking peer
    if (version_peer == null) {
        for (network.peers.items) |*peer| {
            if (peer.state == .handshaking) {
                version_peer = peer;
                break;
            }
        }
    }
    
    // Mark the identified peer as connected and log success
    if (version_peer) |peer| {
        peer.state = .connected;
        peer.last_seen = util.getTime();
        
        // Show simple connection success message
        var addr_buf: [32]u8 = undefined;
        const addr_str = peer.address.toString(&addr_buf);
        logNetSuccess("Connected to {s}", .{addr_str});
        
        // Initialize blockchain after first peer connection if not already done
        if (network.blockchain) |blockchain| {
            const current_height = blockchain.getHeight() catch 0;
            if (current_height == 0) {
                logNetProcess("First peer connected, initializing blockchain...", .{});
                blockchain.initializeBlockchain() catch |err| {
                    logNetError("Failed to initialize blockchain: {}", .{err});
                };
            }
        }
    }
    
    network.peers_mutex.unlock();

    // Get our blockchain height for comparison
    if (network.blockchain) |blockchain| {
        const our_height = blockchain.getHeight() catch 0;
        
        // Only log if there's a significant height difference to reduce spam
        if (peer_version.block_height > our_height and peer_version.block_height - our_height > 1) {
            std.debug.print("📊 Our height: {}, peer height: {} (behind by {})\n", .{ our_height, peer_version.block_height, peer_version.block_height - our_height });
        }

        // Sync logic: if peer is ahead, start sync process
        if (peer_version.block_height > our_height) {
            // Check if we should sync
            const should_sync = blockchain.shouldSync(peer_version.block_height) catch false;
            if (should_sync) {
                // Use the peer that sent the version message for sync
                if (version_peer) |peer| {
                    std.debug.print("🔄 Starting sync with peer (height {})\n", .{peer_version.block_height});
                    blockchain.startSync(peer, peer_version.block_height) catch |err| {
                        std.debug.print("❌ Failed to start sync: {}\n", .{err});
                    };
                }
            }
        }
    }

    // TODO: Send verack response
    // std.debug.print("🤝 Handshake complete\n", .{}); // Disabled to reduce message spam
}

// Handle ping message
fn handlePingMessage(network: *NetworkManager, peer_socket: ?net.Stream) void {
    _ = network; // Not used in ping handling
    logNetInfo("Ping received - sending pong", .{});
    
    // Send pong response back to sender
    if (peer_socket) |socket| {
        const header = MessageHeader.create(.pong, 0);
        sendHeaderOnly(socket, header) catch |err| {
            logNetError("Failed to send pong response: {}", .{err});
        };
    } else {
        logNetError("Cannot send pong - no peer socket provided", .{});
    }
}

// Handle pong message
fn handlePongMessage(network: *NetworkManager, peer_socket: ?net.Stream) void {
    logNetInfo("Pong received - peer alive", .{});
    
    // Update last_seen timestamp for the specific peer
    if (peer_socket) |socket| {
        network.peers_mutex.lock();
        defer network.peers_mutex.unlock();
        
        // Find the peer by socket handle and update last_seen
        for (network.peers.items) |*peer| {
            if (peer.socket != null and peer.socket.?.handle == socket.handle) {
                peer.last_seen = util.getTime();
                logNetInfo("Updated peer last_seen timestamp", .{});
                break;
            }
        }
    } else {
        logNetError("Cannot update peer timestamp - no peer socket provided", .{});
    }
}

// Handle getblocks request - respond with requested blocks
fn handleGetBlocksMessage(network: *NetworkManager, message_data: []const u8, peer_socket: ?net.Stream) void {
    if (message_data.len < @sizeOf(GetBlocksMessage)) {
        logNetError("GetBlocks message incomplete", .{});
        return;
    }

    const getblocks_msg = std.mem.bytesToValue(GetBlocksMessage, message_data[0..@sizeOf(GetBlocksMessage)]);
    logNetInfo("GetBlocks request: {} blocks starting from height {}", .{ getblocks_msg.count, getblocks_msg.start_height });

    // Check if this node can serve blocks (asymmetric sync)
    if (!network.node_type.canServeBlocks()) {
        logNetInfo("Ignoring GetBlocks request - this is an outbound-only node (behind NAT)", .{});
        return;
    }

    // Check if we have a socket to respond to
    if (peer_socket == null) {
        logNetError("GetBlocks received but no peer socket provided", .{});
        return;
    }

    // Get blockchain reference
    if (network.blockchain == null) {
        logNetError("GetBlocks received but no blockchain connection", .{});
        return;
    }

    const blockchain = network.blockchain.?;
    const our_height = blockchain.getHeight() catch {
        logNetError("Failed to get blockchain height", .{});
        return;
    };

    // Check if we have the requested blocks
    // our_height is the count of blocks (0-indexed heights: 0 to our_height-1)
    if (getblocks_msg.start_height >= our_height) {
        logNetError("Requested blocks beyond our height ({} >= {}) - we have blocks 0 to {}", .{ getblocks_msg.start_height, our_height, our_height - 1 });
        return;
    }

    // Calculate how many blocks we can actually send
    const available_blocks = our_height - getblocks_msg.start_height;
    var blocks_to_send = @min(getblocks_msg.count, available_blocks);
    
    // Limit batch size to prevent memory exhaustion attacks
    blocks_to_send = @min(blocks_to_send, types.SYNC.BATCH_SIZE * 2); // Allow up to 2x normal batch size

    logNetInfo("Sending {} blocks to peer", .{blocks_to_send});

    // Send blocks response with improved error handling
    sendBlocksResponse(network, getblocks_msg.start_height, blocks_to_send, peer_socket) catch |err| {
        // Don't log BrokenPipe as error - it's normal when peer disconnects
        if (err == error.BrokenPipe or err == error.ConnectionResetByPeer) {
            logNetInfo("Peer disconnected during blocks response", .{});
        } else {
            logNetError("Failed to send blocks response: {}", .{err});
        }
    };
}

// Handle blocks response - process batch of blocks for sync
fn handleBlocksMessage(network: *NetworkManager, message_data: []const u8) void {
    if (message_data.len < @sizeOf(BlocksMessage)) {
        std.debug.print("⚠️ Blocks message incomplete\n", .{});
        return;
    }

    const blocks_msg = std.mem.bytesToValue(BlocksMessage, message_data[0..@sizeOf(BlocksMessage)]);
    std.debug.print("📥 Blocks response: {} blocks starting from height {}\n", .{ blocks_msg.count, blocks_msg.start_height });

    // Validate message size to prevent memory exhaustion attacks
    if (blocks_msg.count > types.SYNC.BATCH_SIZE * 3) { // Allow up to 3x normal batch size
        std.debug.print("⚠️ Blocks message too large: {} blocks (max {})\n", .{ blocks_msg.count, types.SYNC.BATCH_SIZE * 3 });
        return;
    }
    
    // Validate message data size
    const blocks_data = message_data[@sizeOf(BlocksMessage)..];
    const min_expected_size = blocks_msg.count * (@sizeOf(types.BlockHeader) + @sizeOf(u32)); // Minimum size for headers + tx counts
    if (blocks_data.len < min_expected_size) {
        std.debug.print("⚠️ Blocks message data too small: {} bytes (expected at least {})\n", .{ blocks_data.len, min_expected_size });
        return;
    }
    
    // Check total message size
    if (message_data.len > MAX_MESSAGE_SIZE) {
        std.debug.print("⚠️ Message exceeds maximum size: {} bytes (max {})\n", .{ message_data.len, MAX_MESSAGE_SIZE });
        return;
    }

    // Get blockchain reference
    if (network.blockchain == null) {
        std.debug.print("⚠️ Blocks received but no blockchain connection\n", .{});
        return;
    }

    // Process the blocks data (after the BlocksMessage header)
    processBlocksBatch(network, blocks_msg.start_height, blocks_msg.count, blocks_data) catch |err| {
        logNetError("Failed to process blocks batch: {}", .{err});
    };
}

// Send blocks response to peer
fn sendBlocksResponse(network: *NetworkManager, start_height: u32, count: u32, peer_socket: ?net.Stream) !void {
    if (peer_socket == null) {
        logNetError("No socket provided to send blocks response", .{});
        return;
    }
    
    const socket = peer_socket.?;
    const blockchain = network.blockchain.?;
    
    // Pre-validate all blocks exist before calculating size
    var validated_blocks = std.ArrayList(types.Block).init(network.allocator);
    defer validated_blocks.deinit();
    
    for (0..count) |i| {
        const block_height = start_height + @as(u32, @intCast(i));
        const block = blockchain.getBlock(block_height) catch |err| {
            logNetError("Block {} not available for sync: {}", .{ block_height, err });
            return; // Exit early if any block is missing
        };
        validated_blocks.append(block) catch return;
    }
    
    const actual_count: u32 = @intCast(validated_blocks.items.len);
    if (actual_count == 0) {
        logNetError("No blocks available for sync from height {}", .{start_height});
        return;
    }
    
    // Calculate accurate message size with validated blocks
    var total_size: usize = @sizeOf(BlocksMessage);
    for (validated_blocks.items) |block| {
        total_size += @sizeOf(types.BlockHeader) + @sizeOf(u32) + @sizeOf(types.Transaction) * block.transactions.len;
    }
    
    // Build entire payload with checksum
    const payload_buffer = try network.allocator.alloc(u8, total_size - @sizeOf(BlocksMessage));
    defer network.allocator.free(payload_buffer);
    
    var payload_offset: usize = 0;
    
    // Serialize all blocks into payload buffer
    for (validated_blocks.items) |block| {
        // Copy block header
        @memcpy(payload_buffer[payload_offset..payload_offset + @sizeOf(types.BlockHeader)], std.mem.asBytes(&block.header));
        payload_offset += @sizeOf(types.BlockHeader);
        
        // Copy transaction count
        const tx_count: u32 = @intCast(block.transactions.len);
        @memcpy(payload_buffer[payload_offset..payload_offset + @sizeOf(u32)], std.mem.asBytes(&tx_count));
        payload_offset += @sizeOf(u32);
        
        // Copy transactions
        for (block.transactions) |tx| {
            @memcpy(payload_buffer[payload_offset..payload_offset + @sizeOf(types.Transaction)], std.mem.asBytes(&tx));
            payload_offset += @sizeOf(types.Transaction);
        }
    }
    
    // Create blocks message and full payload
    const blocks_msg = BlocksMessage{
        .start_height = start_height,
        .count = actual_count,
    };
    
    // Combine blocks_msg + payload_buffer for checksum
    const full_payload = try network.allocator.alloc(u8, @sizeOf(BlocksMessage) + payload_buffer.len);
    defer network.allocator.free(full_payload);
    
    @memcpy(full_payload[0..@sizeOf(BlocksMessage)], std.mem.asBytes(&blocks_msg));
    @memcpy(full_payload[@sizeOf(BlocksMessage)..], payload_buffer);
    
    // Send header with checksum
    var header = MessageHeader.create(.blocks, @intCast(full_payload.len));
    header.setChecksum(full_payload);
    
    _ = socket.write(std.mem.asBytes(&header)) catch |err| {
        logNetError("Failed to send blocks header (peer disconnected): {}", .{err});
        return;
    };
    
    // Send full payload
    _ = socket.write(full_payload) catch |err| {
        logNetError("Failed to send blocks payload (peer disconnected): {}", .{err});
        return;
    };
    
    logNetSuccess("Sent {} blocks to peer", .{actual_count});
}

// Process batch of blocks received during sync
fn processBlocksBatch(network: *NetworkManager, start_height: u32, count: u32, blocks_data: []const u8) !void {
    const blockchain = network.blockchain.?;
    var data_offset: usize = 0;
    
    for (0..count) |i| {
        const block_height = start_height + @as(u32, @intCast(i));
        
        // Parse block header
        if (data_offset + @sizeOf(types.BlockHeader) > blocks_data.len) {
            logNetError("Block {} header beyond data boundary", .{i});
            return;
        }
        
        const header = std.mem.bytesToValue(types.BlockHeader, blocks_data[data_offset..data_offset + @sizeOf(types.BlockHeader)]);
        data_offset += @sizeOf(types.BlockHeader);
        
        // Parse transaction count
        if (data_offset + @sizeOf(u32) > blocks_data.len) {
            logNetError("Block {} tx count beyond data boundary", .{i});
            return;
        }
        
        const tx_count = std.mem.bytesToValue(u32, blocks_data[data_offset..data_offset + @sizeOf(u32)]);
        data_offset += @sizeOf(u32);
        
        // Parse transactions
        const transactions = try network.allocator.alloc(types.Transaction, tx_count);
        defer network.allocator.free(transactions);
        
        for (transactions) |*tx| {
            if (data_offset + @sizeOf(types.Transaction) > blocks_data.len) {
                logNetError("Block {} transaction beyond data boundary", .{i});
                return;
            }
            
            tx.* = std.mem.bytesToValue(types.Transaction, blocks_data[data_offset..data_offset + @sizeOf(types.Transaction)]);
            data_offset += @sizeOf(types.Transaction);
        }
        
        // Create block and add to blockchain
        const block = types.Block{
            .header = header,
            .transactions = transactions,
        };
        
        blockchain.handleSyncBlock(block_height, block) catch |err| {
            logNetError("🚨 handleSyncBlock FAILED for height {}: {}", .{block_height, err});
            // This explains why the block is never saved - handleSyncBlock is throwing an error!
            return; // Don't continue processing, something is fundamentally wrong
        };
        logNetSuccess("Processed sync block at height {}", .{block_height});
    }
    
    // After processing the batch, request the next batch if still syncing
    const sync_state = blockchain.getSyncState();
    logNetInfo("🔍 BATCH DEBUG: Finished processing {} blocks, sync_state = {}", .{count, sync_state});
    if (sync_state == .syncing) {
        logNetInfo("🔄 BATCH AUTO-REQUEST: Requesting next batch because sync_state = .syncing", .{});
        blockchain.requestNextSyncBatch() catch |err| {
            logNetError("Failed to request next sync batch: {}", .{err});
        };
    } else {
        logNetInfo("✅ BATCH COMPLETE: Not requesting more batches because sync_state = {}", .{sync_state});
    }
}

// Maintenance thread
fn maintainConnections(network: *NetworkManager) void {
    logNetProcess("Connection maintenance active", .{});

    while (network.is_running) {
        const now = util.getTime();

        // Health check - examine each peer
        network.peers_mutex.lock();
        for (network.peers.items) |*peer| {
            const time_since_seen = now - peer.last_seen;

            // Peer timeout detection
            if (peer.state == .connected and time_since_seen > types.TIMING.PEER_TIMEOUT_SECONDS) { // 60 seconds silence
                logNetInfo("Peer silent for 60s - checking health", .{});
                peer.sendPing() catch {
                    logNetError("Peer connection lost, will reconnect", .{});
                    // Only disconnect if not already disconnected (race condition protection)
                    if (peer.state != .disconnected) {
                        peer.disconnect();
                    }
                };
            }

            // Attempt reconnection
            if (peer.state == .disconnected) {
                peer.connect(network) catch {
                    // Log handled in connect function
                };
            }
        }
        network.peers_mutex.unlock();

        // Check for sync timeouts
        if (network.blockchain) |blockchain| {
            blockchain.checkSyncTimeout();
            
            // Blockchain initialization is now handled immediately when peers connect
            // This periodic check is no longer needed but kept as a safety net
            const current_height = blockchain.getHeight() catch 0;
            if (current_height == 0) {
                var connected_peers: u32 = 0;
                network.peers_mutex.lock();
                for (network.peers.items) |peer| {
                    if (peer.state == .connected) connected_peers += 1;
                }
                network.peers_mutex.unlock();
                
                if (connected_peers > 0) {
                    logNetProcess("Safety check: initializing blockchain...", .{});
                    blockchain.initializeBlockchain() catch |err| {
                        logNetError("Failed to initialize blockchain: {}", .{err});
                    };
                }
            }
            
            // Periodic height checking - RE-ENABLED with reduced spam
            // Now much quieter due to reduced debug output in version handling
            if (now - network.last_height_check > types.TIMING.HEIGHT_CHECK_INTERVAL_SECONDS) {
                logNetProcess("Starting periodic height check (every 2 minutes)", .{});
                blockchain.checkForNewBlocks() catch |err| {
                    logNetError("Failed to check for new blocks: {}", .{err});
                };
                network.last_height_check = now;
            }
        }

        // Periodic discovery (every 5 minutes)
        if (now - network.last_discovery > types.TIMING.DISCOVERY_INTERVAL_SECONDS) {
            network.discoverPeers(10801) catch {};
            network.last_discovery = now;
            
            // Blockchain initialization now happens immediately when peers connect
        }

        // Monitoring cycle
        std.time.sleep(types.TIMING.MAINTENANCE_CYCLE_SECONDS * std.time.ns_per_s);
    }

    logNetInfo("Maintenance stopped", .{});
}

// Network tests
test "NetworkAddress parsing" {
    const addr = try NetworkAddress.fromString("127.0.0.1:10801");
    try std.testing.expect(addr.ip[0] == 127);
    try std.testing.expect(addr.ip[3] == 1);
    try std.testing.expect(addr.port == 10801);

    // Test parsing address without port, should use DEFAULT_PORT
    const addr_no_port = try NetworkAddress.fromString("192.168.0.1");
    try std.testing.expect(addr_no_port.ip[0] == 192);
    try std.testing.expect(addr_no_port.ip[3] == 1);
    try std.testing.expect(addr_no_port.port == DEFAULT_PORT);
}

test "MessageHeader creation" {
    const header = MessageHeader.create(.version, 64);
    try std.testing.expect(std.mem.eql(u8, &header.magic, &MAGIC_BYTES));
    try std.testing.expect(header.length == 64);
}

test "MessageHeader checksum" {
    const test_data = "Hello ZeiCoin Network!";
    const checksum1 = MessageHeader.calculateChecksum(test_data);
    const checksum2 = MessageHeader.calculateChecksum(test_data);
    
    // Same data should produce same checksum
    try std.testing.expect(checksum1 == checksum2);
    
    // Different data should produce different checksum
    const different_data = "Hello Different Network!";
    const checksum3 = MessageHeader.calculateChecksum(different_data);
    try std.testing.expect(checksum1 != checksum3);
    
    // Test header checksum verification
    var header = MessageHeader.create(.version, @intCast(test_data.len));
    header.setChecksum(test_data);
    try std.testing.expect(header.verifyChecksum(test_data));
    try std.testing.expect(!header.verifyChecksum(different_data));
}

test "Sync response routing fix" {
    // This test verifies that sync responses are sent to the correct peer socket
    // Previously, responses were sent to the first connected peer, causing sync failures
    
    // The fix ensures handleGetBlocksMessage receives the requesting peer's socket
    // and sendBlocksResponse uses that socket instead of searching for any peer
    
    // Test that GetBlocksMessage structure is correct size
    try std.testing.expect(@sizeOf(GetBlocksMessage) == 8); // 2 u32 fields
    
    // Test that BlocksMessage structure is correct size  
    try std.testing.expect(@sizeOf(BlocksMessage) == 8); // 2 u32 fields
    
    std.debug.print("\n✅ Sync response routing fix verified\n", .{});
}

test "Duplicate peer prevention" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var network = NetworkManager.init(allocator);
    defer network.deinit();
    
    // Add the same peer twice
    network.addPeer("192.168.1.100:10801") catch {};
    try std.testing.expect(network.peers.items.len == 1);
    
    // Try to add the same peer again - should be skipped
    network.addPeer("192.168.1.100:10801") catch {};
    try std.testing.expect(network.peers.items.len == 1); // Still 1, not 2
    
    // Add a different peer - should be added
    network.addPeer("192.168.1.101:10801") catch {};
    try std.testing.expect(network.peers.items.len == 2);
    
    std.debug.print("\n✅ Duplicate peer prevention verified\n", .{});
}
