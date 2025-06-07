// net.zig - ZeiCoin Pure Zig Networking Layer
// P2P networking using only Zig standard library

const std = @import("std");
const net = std.net;
const Thread = std.Thread;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const types = @import("types.zig");
const util = @import("util.zig");

// Network constants
pub const DEFAULT_PORT: u16 = 10801;
pub const DISCOVERY_PORT: u16 = 10800;
pub const MAGIC_BYTES = [4]u8{ 0xF9, 0xBE, 0xB4, 0xD9 };
pub const DISCOVERY_MAGIC = [4]u8{ 0xDE, 0x11, 0xC0, 0x1E }; // ZeiCoin discovery magic
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB max message
pub const MAX_PEERS: usize = 8; // Keep it simple
pub const VERSION: u32 = 1;

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
    ping = 8,
    pong = 9,
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
        const port_str = parts.next() orelse "10801";

        // Parse IP address
        var ip_parts = std.mem.splitScalar(u8, ip_str, '.');
        var ip: [4]u8 = undefined;
        for (0..4) |i| {
            const part = ip_parts.next() orelse return error.InvalidAddress;
            ip[i] = try std.fmt.parseInt(u8, part, 10);
        }

        const port = try std.fmt.parseInt(u16, port_str, 10);
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
            .checksum = 0, // TODO: Calculate checksum
        };
    }
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

    pub fn connect(self: *Peer) !void {
        if (self.state == .connected) return;
        if (self.state == .connecting or self.state == .handshaking) return;

        // Limit connection attempts with exponential backoff
        const MAX_ATTEMPTS = 5;
        const BACKOFF_MULTIPLIER = 2;

        if (self.consecutive_failures > MAX_ATTEMPTS) {
            const backoff_time = @as(i64, 30) * std.math.pow(i64, BACKOFF_MULTIPLIER, @min(self.consecutive_failures - MAX_ATTEMPTS, 6));
            const time_since_last = util.getTime() - self.last_seen;

            if (time_since_last < backoff_time) {
                std.debug.print("Waiting {} seconds before retry\n", .{backoff_time - time_since_last});
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

            var addr_buf: [32]u8 = undefined;
            const addr_str = self.address.toString(&addr_buf);
            std.debug.print("❌ Connection failed to {s}: {}\n", .{ addr_str, err });
            return err;
        };

        // Success - reset failure count
        self.consecutive_failures = 0;
        self.state = .handshaking;
        self.last_seen = util.getTime();

        // Send version message with height
        try self.sendVersion(0); // TODO: Get height from network manager

        var addr_buf: [32]u8 = undefined;
        const addr_str = self.address.toString(&addr_buf);
        std.debug.print("strong to {s} (attempt #{})\n", .{ addr_str, self.connection_attempts });
    }

    pub fn disconnect(self: *Peer) void {
        if (self.socket) |socket| {
            socket.close();
            self.socket = null;
        }
        self.state = .disconnected;
        std.debug.print("❌ Disconnected from peer {any}\n", .{self.address});
    }

    pub fn sendVersion(self: *Peer, blockchain_height: u32) !void {
        if (self.socket == null) return error.NotConnected;

        // Version message with blockchain height
        const version_payload = struct {
            version: u32,
            services: u64,
            timestamp: i64,
            block_height: u32, // For sync
        }{
            .version = VERSION,
            .services = 1, // NODE_NETWORK
            .timestamp = util.getTime(),
            .block_height = blockchain_height,
        };

        const header = MessageHeader.create(.version, @sizeOf(@TypeOf(version_payload)));

        // Send header + payload
        const socket = self.socket.?;
        _ = try socket.write(std.mem.asBytes(&header));
        _ = try socket.write(std.mem.asBytes(&version_payload));

        std.debug.print("📡 Sent version to peer\n", .{});
    }

    pub fn sendPing(self: *Peer) !void {
        if (self.socket == null or self.state != .connected) return error.NotConnected;

        const header = MessageHeader.create(.ping, 0);
        const socket = self.socket.?;

        // Handle socket write failures gracefully (race condition protection)
        _ = socket.write(std.mem.asBytes(&header)) catch |err| {
            // Socket was closed by another thread - mark as disconnected
            self.socket = null;
            self.state = .disconnected;
            return err;
        };

        self.last_ping = util.getTime();
        self.last_seen = self.last_ping;
        std.debug.print("🏓 Ping sent to peer\n", .{});
    }

    pub fn broadcastTransaction(self: *Peer, tx: types.Transaction) !void {
        if (self.socket == null or self.state != .connected) return;

        // Serialize transaction and send
        const header = MessageHeader.create(.tx, @sizeOf(types.Transaction));
        const socket = self.socket.?;
        _ = try socket.write(std.mem.asBytes(&header));
        _ = try socket.write(std.mem.asBytes(&tx));

        std.debug.print("📤 Broadcasted transaction to peer\n", .{});
    }

    pub fn broadcastBlock(self: *Peer, block: types.Block) !void {
        if (self.socket == null or self.state != .connected) return;

        // For now, send block header + transaction count + transactions
        // In a real implementation, we'd use proper serialization
        const payload_size = @sizeOf(types.BlockHeader) + @sizeOf(u32) + @sizeOf(types.Transaction) * block.transactions.len;
        const header = MessageHeader.create(.block, @intCast(payload_size));
        const socket = self.socket.?;

        // Send message header
        _ = try socket.write(std.mem.asBytes(&header));

        // Send block header
        _ = try socket.write(std.mem.asBytes(&block.header));

        // Send transaction count
        const tx_count: u32 = @intCast(block.transactions.len);
        _ = try socket.write(std.mem.asBytes(&tx_count));

        // Send all transactions
        for (block.transactions) |tx| {
            _ = try socket.write(std.mem.asBytes(&tx));
        }

        std.debug.print("📤 Broadcasted block to peer\n", .{});
    }
};

// Network manager
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    peers: ArrayList(Peer),
    is_running: bool,
    listen_address: ?net.Address,
    accept_thread: ?Thread,
    maintenance_thread: ?Thread,
    last_discovery: i64,
    blockchain: ?*@import("main.zig").ZeiCoin,

    pub fn init(allocator: std.mem.Allocator) NetworkManager {
        return NetworkManager{
            .allocator = allocator,
            .peers = ArrayList(Peer).init(allocator),
            .is_running = false,
            .listen_address = null,
            .accept_thread = null,
            .maintenance_thread = null,
            .last_discovery = 0,
            .blockchain = null,
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

        // Set up listening address
        self.listen_address = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, port);

        // Start accept thread for incoming connections
        self.accept_thread = try Thread.spawn(.{}, acceptConnections, .{self});

        // Start maintenance thread
        self.maintenance_thread = try Thread.spawn(.{}, maintainConnections, .{self});

        self.is_running = true;
        std.debug.print("🌐 Network started on port {}\n", .{port});
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

        std.debug.print("🛑 ZeiCoin network stopped\n", .{});
    }

    pub fn addPeer(self: *NetworkManager, address_str: []const u8) !void {
        if (self.peers.items.len >= MAX_PEERS) {
            std.debug.print("⚠️  Maximum peers reached\n", .{});
            return;
        }

        const address = try NetworkAddress.fromString(address_str);
        var peer = Peer.init(self.allocator, address);

        try peer.connect();
        try self.peers.append(peer);

        std.debug.print("➕ Added peer: {s}\n", .{address_str});
    }

    pub fn broadcastTransaction(self: *NetworkManager, tx: types.Transaction) void {
        for (self.peers.items) |*peer| {
            peer.broadcastTransaction(tx) catch {
                std.debug.print("⚠️  Failed to broadcast to peer\n", .{});
            };
        }
        std.debug.print("📡 Transaction broadcasted to {} peers\n", .{self.peers.items.len});
    }

    pub fn broadcastBlock(self: *NetworkManager, block: types.Block) void {
        for (self.peers.items) |*peer| {
            peer.broadcastBlock(block) catch {
                std.debug.print("⚠️  Failed to broadcast block to peer\n", .{});
            };
        }
        std.debug.print("📡 Block broadcasted to {} peers\n", .{self.peers.items.len});
    }

    pub fn getConnectedPeers(self: *NetworkManager) usize {
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
        std.debug.print("🔗 ZeiCoin client network started (outbound connections only)\n", .{});
    }

    /// Connect to a specific peer
    pub fn connectToPeer(self: *NetworkManager, address: NetworkAddress) !void {
        const peer = Peer.init(self.allocator, address);
        try self.peers.append(peer);

        // Connect in background
        const peer_ptr = &self.peers.items[self.peers.items.len - 1];
        peer_ptr.connect() catch |err| {
            var addr_buf: [32]u8 = undefined;
            const addr_str = address.toString(&addr_buf);
            std.debug.print("❌ Failed to connect to peer {s}: {}\n", .{ addr_str, err });
            return err;
        };

        var addr_buf: [32]u8 = undefined;
        const addr_str = address.toString(&addr_buf);
        std.debug.print("✅ Connected to peer {s}\n", .{addr_str});
    }

    /// Get number of connected peers
    pub fn getPeerCount(self: *NetworkManager) usize {
        return self.getConnectedPeers();
    }

    pub fn printStatus(self: *NetworkManager) void {
        std.debug.print("\n🌐 Network Status:\n", .{});
        std.debug.print("   Running: {}\n", .{self.is_running});
        std.debug.print("   Peers: {}/{}\n", .{ self.getConnectedPeers(), self.peers.items.len });

        for (self.peers.items, 0..) |peer, i| {
            var addr_buf: [32]u8 = undefined;
            const addr_str = peer.address.toString(&addr_buf);
            std.debug.print("   [{}] {} - {s}\n", .{ i, peer.state, addr_str });
        }
    }

    /// Auto-discover peers on local network
    pub fn discoverPeers(self: *NetworkManager, our_port: u16) !void {
        std.debug.print("🔍 Starting peer discovery...\n", .{});

        // Try bootstrap nodes first
        try self.connectToBootstrapNodes();

        // Try UDP broadcast for local discovery
        try self.broadcastDiscovery(our_port);

        // Fallback to TCP scanning
        try self.scanLocalNetwork(our_port);
    }

    /// Connect to bootstrap nodes for initial peer discovery
    fn connectToBootstrapNodes(self: *NetworkManager) !void {
        std.debug.print("🌐 Connecting to bootstrap nodes...\n", .{});

        // Try environment variable first
        if (std.process.getEnvVarOwned(self.allocator, "ZEICOIN_BOOTSTRAP")) |env_value| {
            defer self.allocator.free(env_value);

            std.debug.print("💡 Using bootstrap nodes from ZEICOIN_BOOTSTRAP: {s}\n", .{env_value});

            // Parse comma-separated list and connect to each
            var it = std.mem.splitScalar(u8, env_value, ',');
            while (it.next()) |node_addr| {
                const trimmed = std.mem.trim(u8, node_addr, " \t\n");
                if (trimmed.len > 0) {
                    self.connectToBootstrapNode(trimmed) catch |err| {
                        std.debug.print("⚠️ Bootstrap node {s} failed: {}\n", .{ trimmed, err });
                        continue;
                    };
                }
            }
        } else |_| {
            // Fallback to hardcoded bootstrap nodes
            std.debug.print("💡 Using default bootstrap nodes\n", .{});
            for (types.BOOTSTRAP_NODES) |bootstrap_addr| {
                self.connectToBootstrapNode(bootstrap_addr) catch |err| {
                    std.debug.print("⚠️ Bootstrap node {s} failed: {}\n", .{ bootstrap_addr, err });
                    continue;
                };
            }
        }
    }

    /// Connect to a single bootstrap node
    fn connectToBootstrapNode(self: *NetworkManager, addr_str: []const u8) !void {
        std.debug.print("🤝 Attempting bootstrap connection to {s}...\n", .{addr_str});

        // Use standard addPeer method instead of custom connection handling
        // This ensures proper peer lifecycle management
        try self.addPeer(addr_str);
        std.debug.print("✅ Added bootstrap node {s} to peer list\n", .{addr_str});
    }

    /// Send UDP broadcast to discover peers
    fn broadcastDiscovery(self: *NetworkManager, our_port: u16) !void {
        std.debug.print("📡 Broadcasting discovery message...\n", .{});

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
                std.debug.print("⚠️ Broadcast to {s} failed: {}\n", .{ addr_str, err });
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
            std.debug.print("⚠️ Discovery: UDP socket creation failed: {}\n", .{err});
            return;
        };
        defer std.posix.close(socket);

        // Use socket timeout for cross-platform compatibility
        const timeout = std.posix.timeval{ .sec = 1, .usec = 0 };
        std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
            std.debug.print("⚠️ Discovery: timeout setup failed (continuing): {}\n", .{err});
        };

        // Bind to discovery port
        const bind_addr = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, DISCOVERY_PORT);
        std.posix.bind(socket, &bind_addr.any, bind_addr.getOsSockLen()) catch |err| {
            std.debug.print("⚠️ Discovery: bind failed: {}\n", .{err});
            return;
        };

        std.debug.print("📡 Discovery listening on UDP port {}\n", .{DISCOVERY_PORT});

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
                    std.debug.print("⚠️ Discovery: receive error: {}\n", .{err});
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

                    std.debug.print("🎯 Discovery: found peer {s}\n", .{peer_addr_str});
                    self.addPeer(peer_addr_str) catch {};
                }
            }
            attempts = 0; // Reset attempts after successful receive
        }

        std.debug.print("✅ Discovery session complete\n", .{});
    }

    /// Scan local network for peers (fallback method)
    fn scanLocalNetwork(self: *NetworkManager, our_port: u16) !void {
        std.debug.print("🔍 Scanning local network...\n", .{});

        // Get local IP to determine subnet
        const local_ip = try self.getLocalIP();
        std.debug.print("🏠 Local IP: {}.{}.{}.{}\n", .{ local_ip[0], local_ip[1], local_ip[2], local_ip[3] });

        // Scan the same subnet
        var ip: u8 = 1;
        while (ip < 255) : (ip += 1) {
            if (ip == local_ip[3]) continue; // Skip our own IP

            var addr_str: [32]u8 = undefined;
            const peer_addr_str = std.fmt.bufPrint(&addr_str, "{}.{}.{}.{}:{}", .{ local_ip[0], local_ip[1], local_ip[2], ip, our_port }) catch continue;

            // Quick TCP connection test
            if (self.testTCPConnection(peer_addr_str)) {
                std.debug.print("🎯 Found peer via scan: {s}\n", .{peer_addr_str});
                self.addPeer(peer_addr_str) catch {};
            }

            // Limit scan rate
            if (ip % 10 == 0) {
                std.time.sleep(50 * std.time.ns_per_ms);
            }
        }
    }

    /// Get local IP address
    fn getLocalIP(self: *NetworkManager) ![4]u8 {
        _ = self;

        // Create a dummy UDP socket to determine local IP
        const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(socket);

        // Connect to a remote address (doesn't actually send data)
        const remote_addr = net.Address.parseIp4("8.8.8.8", 80) catch return [4]u8{ 192, 168, 1, 100 };
        std.posix.connect(socket, &remote_addr.any, remote_addr.getOsSockLen()) catch {
            return [4]u8{ 192, 168, 1, 100 }; // Default fallback
        };

        // Get local socket address
        var local_addr: std.posix.sockaddr = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);
        std.posix.getsockname(socket, &local_addr, &addr_len) catch {
            return [4]u8{ 192, 168, 1, 100 }; // Default fallback
        };

        const local_addr_in = @as(*const std.posix.sockaddr.in, @alignCast(@ptrCast(&local_addr)));
        return @as(*const [4]u8, @ptrCast(&local_addr_in.addr)).*;
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
};

// Server connection handling
fn acceptConnections(network: *NetworkManager) void {
    const addr = network.listen_address orelse {
        std.debug.print("❌ No listen address set\n", .{});
        return;
    };

    // Create listening socket
    const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch |err| {
        std.debug.print("❌ Failed to create socket: {}\n", .{err});
        return;
    };
    defer std.posix.close(socket);

    // Enable address reuse
    std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1))) catch {};

    // Bind socket
    std.posix.bind(socket, &addr.any, @sizeOf(std.posix.sockaddr.in)) catch |err| {
        std.debug.print("❌ Failed to bind: {}\n", .{err});
        return;
    };

    // Listen for connections
    std.posix.listen(socket, 10) catch |err| {
        std.debug.print("❌ Failed to listen: {}\n", .{err});
        return;
    };

    std.debug.print("🎧 Server listening for connections on {}\n", .{addr});

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
                    std.debug.print("⚠️  Accept error: {}\n", .{err});
                }
                continue;
            },
        };

        std.debug.print("🔗 New peer connected!\n", .{});

        // Handle this connection in a separate thread
        const thread = Thread.spawn(.{}, handleIncomingPeer, .{ network, client_socket }) catch |err| {
            std.debug.print("⚠️  Failed to spawn peer thread: {}\n", .{err});
            std.posix.close(client_socket);
            continue;
        };
        thread.detach(); // Let it run independently
    }

    std.debug.print("🛑 Accept thread stopped\n", .{});
}

// Handle incoming peer connection
fn handleIncomingPeer(network: *NetworkManager, client_socket: std.posix.socket_t) void {
    defer std.posix.close(client_socket);

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
                    std.debug.print("⚠️  Read error from peer: {}\n", .{err});
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
                processMessage(network, complete_message);
            }
        }
    }

    std.debug.print("❌ Incoming peer disconnected\n", .{});
}

// Handle individual peer connection (for outgoing connections)
fn handlePeerConnection(network: *NetworkManager, stream: net.Stream) void {
    defer stream.close();

    var buffer: [4096]u8 = undefined;
    var message_buffer = MessageBuffer.init();

    while (network.is_running) {
        // Read data from peer
        const bytes_read = stream.read(&buffer) catch |err| switch (err) {
            error.EndOfStream => break,
            error.WouldBlock => {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            },
            else => {
                std.debug.print("⚠️  Read error: {}\n", .{err});
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
                processMessage(network, complete_message);
            }
        }
    }

    std.debug.print("❌ Peer disconnected\n", .{});
}

// Message buffer for handling TCP fragmentation
const MessageBuffer = struct {
    data: [8192]u8,
    pos: usize,

    fn init() MessageBuffer {
        return MessageBuffer{
            .data = undefined,
            .pos = 0,
        };
    }

    fn addData(self: *MessageBuffer, new_data: []const u8) void {
        const available = self.data.len - self.pos;
        const to_copy = @min(new_data.len, available);
        @memcpy(self.data[self.pos .. self.pos + to_copy], new_data[0..to_copy]);
        self.pos += to_copy;
    }

    fn hasCompleteMessage(self: *MessageBuffer) bool {
        if (self.pos < @sizeOf(MessageHeader)) return false;

        const header = std.mem.bytesToValue(MessageHeader, self.data[0..@sizeOf(MessageHeader)]);
        const total_size = @sizeOf(MessageHeader) + header.length;
        return self.pos >= total_size;
    }

    fn extractMessage(self: *MessageBuffer) []const u8 {
        if (!self.hasCompleteMessage()) return &[_]u8{};

        const header = std.mem.bytesToValue(MessageHeader, self.data[0..@sizeOf(MessageHeader)]);
        const total_size = @sizeOf(MessageHeader) + header.length;
        const message = self.data[0..total_size];

        // Shift remaining data
        const remaining = self.pos - total_size;
        if (remaining > 0) {
            @memcpy(self.data[0..remaining], self.data[total_size..self.pos]);
        }
        self.pos = remaining;

        return message;
    }
};

// Process incoming messages from server connections
fn processIncomingMessage(network: *NetworkManager, client_socket: std.posix.socket_t, data: []const u8) void {
    _ = client_socket; // TODO: Use for responses
    processMessage(network, data);
}

// Process incoming network messages
fn processMessage(network: *NetworkManager, data: []const u8) void {
    if (data.len < @sizeOf(MessageHeader)) return;

    // Parse message header
    const header = std.mem.bytesToValue(MessageHeader, data[0..@sizeOf(MessageHeader)]);

    // Verify magic bytes
    if (!std.mem.eql(u8, &header.magic, &MAGIC_BYTES)) {
        std.debug.print("⚠️  Invalid magic bytes\n", .{});
        return;
    }

    // Get command name
    const command_end = std.mem.indexOf(u8, &header.command, "\x00") orelse header.command.len;
    const command = header.command[0..command_end];

    std.debug.print("📨 Received message: {s} ({}bytes)\n", .{ command, header.length });

    // Handle different message types
    if (std.mem.eql(u8, command, "version")) {
        handleVersionMessage(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "tx")) {
        handleIncomingTransaction(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "block")) {
        std.debug.print("📦 Block received from network\n", .{});
        processIncomingBlock(network, data[@sizeOf(MessageHeader)..]);
    } else if (std.mem.eql(u8, command, "ping")) {
        handlePingMessage(network);
    } else if (std.mem.eql(u8, command, "pong")) {
        handlePongMessage(network);
    }
}

// Process incoming block from network peer
fn processIncomingBlock(network: *NetworkManager, block_data: []const u8) void {
    // Get the blockchain reference from network manager
    if (network.blockchain == null) {
        std.debug.print("⚠️ Block received but no blockchain connection\n", .{});
        return;
    }

    // Parse block data
    if (block_data.len < @sizeOf(types.BlockHeader) + @sizeOf(u32)) {
        std.debug.print("⚠️  Block too small - incomplete data\n", .{});
        return;
    }

    // Parse block header
    const header = std.mem.bytesToValue(types.BlockHeader, block_data[0..@sizeOf(types.BlockHeader)]);

    // Parse transaction count
    const tx_count_offset = @sizeOf(types.BlockHeader);
    const tx_count = std.mem.bytesToValue(u32, block_data[tx_count_offset .. tx_count_offset + @sizeOf(u32)]);

    std.debug.print("📦 Block received: {} transactions, timestamp {}\n", .{ tx_count, header.timestamp });

    // Create transaction array
    const transactions = network.allocator.alloc(types.Transaction, tx_count) catch {
        std.debug.print("❌ Memory allocation failed - block not processed\n", .{});
        return;
    };
    defer network.allocator.free(transactions);

    // Parse transactions
    var tx_offset: usize = tx_count_offset + @sizeOf(u32);
    for (transactions, 0..) |*tx, i| {
        if (tx_offset + @sizeOf(types.Transaction) > block_data.len) {
            std.debug.print("⚠️ Transaction {} beyond data boundary\n", .{i});
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
            std.debug.print("❌ Block rejected by blockchain: {}\n", .{err});
        };
    }
}

// Handle incoming transaction
fn handleIncomingTransaction(network: *NetworkManager, tx_data: []const u8) void {
    // Parse transaction data
    if (tx_data.len < @sizeOf(types.Transaction)) {
        std.debug.print("⚠️ Transaction incomplete\n", .{});
        return;
    }

    const transaction = std.mem.bytesToValue(types.Transaction, tx_data[0..@sizeOf(types.Transaction)]);
    std.debug.print("💸 Transaction received: {} ZEI from network peer\n", .{transaction.amount / types.ZEI_COIN});

    // Send transaction to blockchain for validation and mempool
    if (network.blockchain) |blockchain| {
        blockchain.handleIncomingTransaction(transaction) catch |err| {
            std.debug.print("❌ Transaction rejected by blockchain: {}\n", .{err});
            return;
        };

        // Relay valid transaction to other peers
        std.debug.print("📡 Relaying valid transaction to other peers\n", .{});
        for (network.peers.items) |*peer| {
            if (peer.state == .connected) {
                peer.broadcastTransaction(transaction) catch |err| {
                    std.debug.print("⚠️ Failed to relay transaction to peer: {}\n", .{err});
                };
            }
        }
    }
}

// Handle version message
fn handleVersionMessage(network: *NetworkManager, version_data: []const u8) void {
    // Parse version payload
    const version_payload = struct {
        version: u32,
        services: u64,
        timestamp: i64,
        block_height: u32,
    };

    if (version_data.len < @sizeOf(version_payload)) {
        std.debug.print("⚠️ Version message incomplete\n", .{});
        return;
    }

    const peer_version = std.mem.bytesToValue(version_payload, version_data[0..@sizeOf(version_payload)]);
    std.debug.print("🤝 Peer version: {}, height: {}\n", .{ peer_version.version, peer_version.block_height });

    // Get our blockchain height for comparison
    if (network.blockchain) |blockchain| {
        const our_height = blockchain.getHeight() catch 0;
        std.debug.print("📊 Our height: {}, peer height: {}\n", .{ our_height, peer_version.block_height });

        // Sync logic: if peer is ahead, request blocks
        if (peer_version.block_height > our_height) {
            const blocks_behind = peer_version.block_height - our_height;
            std.debug.print("📈 We are {} blocks behind, need to sync\n", .{blocks_behind});
            // TODO: Request blocks from peer
        } else if (our_height > peer_version.block_height) {
            const blocks_ahead = our_height - peer_version.block_height;
            std.debug.print("📈 We are {} blocks ahead\n", .{blocks_ahead});
        } else {
            std.debug.print("✅ Heights are equal\n", .{});
        }
    }

    // TODO: Send verack response
    std.debug.print("🤝 Handshake complete\n", .{});
}

// Handle ping message
fn handlePingMessage(network: *NetworkManager) void {
    _ = network; // TODO: Send pong back to specific peer
    std.debug.print("🏓 Ping received - sending pong\n", .{});
    // TODO: Send pong response to sender
}

// Handle pong message
fn handlePongMessage(network: *NetworkManager) void {
    _ = network; // TODO: Update last_seen for specific peer
    std.debug.print("🏓 Pong received - peer alive\n", .{});
    // TODO: Update peer last_seen timestamp
}

// Maintenance thread
fn maintainConnections(network: *NetworkManager) void {
    std.debug.print("🔧 Connection maintenance active\n", .{});

    while (network.is_running) {
        const now = util.getTime();

        // Health check - examine each peer
        for (network.peers.items) |*peer| {
            const time_since_seen = now - peer.last_seen;

            // Peer timeout detection
            if (peer.state == .connected and time_since_seen > types.TIMING.PEER_TIMEOUT_SECONDS) { // 60 seconds silence
                std.debug.print("⚠️ Peer silent for 60s - checking health\n", .{});
                peer.sendPing() catch {
                    std.debug.print("❌ Peer connection lost, will reconnect\n", .{});
                    // Only disconnect if not already disconnected (race condition protection)
                    if (peer.state != .disconnected) {
                        peer.disconnect();
                    }
                };
            }

            // Attempt reconnection
            if (peer.state == .disconnected) {
                peer.connect() catch {
                    // Log handled in connect function
                };
            }
        }

        // Periodic discovery (every 5 minutes)
        if (now - network.last_discovery > types.TIMING.DISCOVERY_INTERVAL_SECONDS) {
            std.debug.print("🔍 Starting periodic peer discovery\n", .{});
            network.discoverPeers(10801) catch |err| {
                std.debug.print("⚠️ Discovery failed: {}\n", .{err});
            };
            network.last_discovery = now;
        }

        // Monitoring cycle
        std.time.sleep(types.TIMING.MAINTENANCE_CYCLE_SECONDS * std.time.ns_per_s);
    }

    std.debug.print("🛑 Maintenance stopped\n", .{});
}

// Network tests
test "NetworkAddress parsing" {
    const addr = try NetworkAddress.fromString("127.0.0.1:10801");
    try std.testing.expect(addr.ip[0] == 127);
    try std.testing.expect(addr.ip[3] == 1);
    try std.testing.expect(addr.port == 10801);
}

test "MessageHeader creation" {
    const header = MessageHeader.create(.version, 64);
    try std.testing.expect(std.mem.eql(u8, &header.magic, &MAGIC_BYTES));
    try std.testing.expect(header.length == 64);
}
