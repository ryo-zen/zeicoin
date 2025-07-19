// peer_manager.zig - Modular peer management system
// Handles peer connections, discovery, and lifecycle

const std = @import("std");
const net = std.net;
const protocol = @import("protocol/protocol.zig");
const wire = @import("wire/wire.zig");
const messages = @import("protocol/messages/messages.zig");
const message_mod = @import("protocol/message.zig");

const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;
const print = std.debug.print;

/// Peer connection state
pub const PeerState = enum {
    connecting,
    handshaking,
    connected,
    syncing,
    disconnecting,
    disconnected,
};

/// Individual peer connection
pub const Peer = struct {
    allocator: std.mem.Allocator,
    id: u64,
    address: net.Address,
    state: PeerState,
    connection: wire.WireConnection,
    
    // Peer info from handshake
    version: u16,
    services: u64,
    height: u32,
    user_agent: []const u8,
    
    // Connection management
    last_ping: i64,
    last_recv: i64,
    ping_nonce: ?u64,
    
    // Sync state
    syncing: bool,
    headers_requested: bool,
    
    // TCP send callback
    tcp_send_fn: ?*const fn(ctx: ?*anyopaque, data: []const u8) anyerror!void,
    tcp_send_ctx: ?*anyopaque,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, id: u64, address: net.Address) Self {
        return .{
            .allocator = allocator,
            .id = id,
            .address = address,
            .state = .connecting,
            .connection = wire.WireConnection.init(allocator),
            .version = 0,
            .services = 0,
            .height = 0,
            .user_agent = &[_]u8{},
            .last_ping = std.time.timestamp(),
            .last_recv = std.time.timestamp(),
            .ping_nonce = null,
            .syncing = false,
            .headers_requested = false,
            .tcp_send_fn = null,
            .tcp_send_ctx = null,
        };
    }
    
    pub fn deinit(self: *Self) void {
        if (self.user_agent.len > 0) {
            self.allocator.free(self.user_agent);
        }
        self.connection.deinit();
    }
    
    /// Send a message to this peer
    pub fn sendMessage(self: *Self, msg_type: protocol.MessageType, msg: anytype) ![]const u8 {
        print("📤 [PEER SEND] Peer {} sending message type: {}\n", .{self.id, msg_type});
        const result = try self.connection.sendMessage(msg_type, msg);
        print("✅ [PEER SEND] Peer {} message created, size: {} bytes\n", .{self.id, result.len});
        
        // If we have a TCP send callback, use it to actually send the data
        if (self.tcp_send_fn) |send_fn| {
            print("🌐 [PEER TCP] Peer {} sending {} bytes over TCP callback\n", .{self.id, result.len});
            try send_fn(self.tcp_send_ctx, result);
            print("✅ [PEER TCP] Peer {} TCP send completed successfully\n", .{self.id});
        } else {
            print("⚠️ [PEER TCP] Peer {} has no TCP callback, message not sent!\n", .{self.id});
        }
        
        return result;
    }
    
    /// Set TCP send callback
    pub fn setTcpSendCallback(self: *Self, send_fn: *const fn(ctx: ?*anyopaque, data: []const u8) anyerror!void, ctx: ?*anyopaque) void {
        self.tcp_send_fn = send_fn;
        self.tcp_send_ctx = ctx;
        print("🔗 [PEER TCP] Peer {} TCP callback configured\n", .{self.id});
    }
    
    /// Process received data
    pub fn receiveData(self: *Self, data: []const u8) !void {
        self.last_recv = std.time.timestamp();
        try self.connection.receiveData(data);
    }
    
    /// Try to read next message
    pub fn readMessage(self: *Self) !?message_mod.MessageEnvelope {
        const result = try self.connection.readMessage();
        if (result) |envelope| {
            print("📥 [PEER RECV] Peer {} received message type: {}\n", .{self.id, envelope.header.message_type});
        }
        return result;
    }
    
    /// Check if peer needs ping
    pub fn needsPing(self: Self) bool {
        const now = std.time.timestamp();
        return (now - self.last_ping) > protocol.PING_INTERVAL_SECONDS;
    }
    
    /// Check if peer timed out
    pub fn isTimedOut(self: Self) bool {
        const now = std.time.timestamp();
        const timeout_result = (now - self.last_recv) > protocol.CONNECTION_TIMEOUT_SECONDS;
        if (timeout_result) {
            print("⏰ [PEER TIMEOUT] Peer {} timed out (last_recv: {}, now: {}, diff: {}s)\n", .{self.id, self.last_recv, now, now - self.last_recv});
        }
        return timeout_result;
    }
    
    /// Check if peer is connected and ready for requests
    pub fn isConnected(self: Self) bool {
        return self.state == .connected or self.state == .syncing;
    }
    
    /// Send request for specific block by hash
    pub fn sendGetBlockByHash(self: *Self, hash: [32]u8) !void {
        const hashes = [_][32]u8{hash};
        var msg = try messages.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);
        
        _ = try self.sendMessage(.get_blocks, msg);
    }
    
    /// Send request for specific block by height
    pub fn sendGetBlockByHeight(self: *Self, height: u32) !void {
        print("📤 [PEER REQUEST] Sending getBlock request for height {} to peer {}\n", .{height, self.id});
        print("🔍 [PEER REQUEST] Peer state: {}, connected: {}\n", .{self.state, self.isConnected()});
        
        // For height-based requests, we'll use a special encoding in the GetBlocksMessage
        // We'll encode the height as a 32-byte hash where the first 4 bytes contain the height
        // and the rest are zeros. The receiving peer can detect this pattern.
        var height_hash: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u32, height_hash[0..4], height, .little);
        
        // Set a magic marker in bytes 4-8 to indicate this is a height request
        const HEIGHT_REQUEST_MAGIC: u32 = 0xDEADBEEF;
        std.mem.writeInt(u32, height_hash[4..8], HEIGHT_REQUEST_MAGIC, .little);
        
        var hashes = [_][32]u8{height_hash};
        var msg = try messages.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);
        
        print("🔍 [PEER REQUEST] Sending height {} as encoded hash request\n", .{height});
        _ = try self.sendMessage(.get_blocks, msg);
        print("✅ [PEER REQUEST] Block request sent successfully for height {}\n", .{height});
    }
    
    /// Send request for multiple blocks by hash
    pub fn sendGetBlocks(self: *Self, hashes: []const [32]u8) !void {
        var msg = try messages.GetBlocksMessage.init(self.allocator, hashes);
        defer msg.deinit(self.allocator);
        
        _ = try self.sendMessage(.get_blocks, msg);
    }
    
    /// Send request for headers using block locator pattern
    pub fn sendGetHeaders(self: *Self, start_height: u32, count: u32) !void {
        _ = count; // For future use
        
        var locator = std.ArrayList([32]u8).init(self.allocator);
        defer locator.deinit();
        
        // Build a simple block locator
        // If we have a blockchain reference, use actual hashes; otherwise use genesis
        if (start_height > 0) {
            // For sync protocol, we want to start from our current height
            // Add a genesis hash as the locator - this tells the peer we need everything from genesis
            const genesis_hash = [_]u8{0} ** 32; // Genesis is always zero hash
            try locator.append(genesis_hash);
        } else {
            // Request from genesis
            const genesis_hash = [_]u8{0} ** 32;
            try locator.append(genesis_hash);
        }
        
        // Stop hash - zero means "send up to chain tip"
        const stop_hash = [_]u8{0} ** 32;
        
        var msg = try messages.GetHeadersMessage.init(self.allocator, locator.items, stop_hash);
        defer msg.deinit(self.allocator);
        
        _ = try self.sendMessage(.get_headers, msg);
        print("📤 Requested headers starting from height {} with {} locator hashes\n", .{ start_height, locator.items.len });
    }
    
    /// Send request for specific block (wrapper method)
    pub fn sendGetBlock(self: *Self, height: u32) !void {
        return self.sendGetBlockByHeight(height);
    }
    
    /// Format peer for logging
    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("Peer[{}:{}:{}]", .{ self.id, self.address, self.state });
    }
};

/// Peer manager handles all peer connections
pub const PeerManager = struct {
    allocator: std.mem.Allocator,
    peers: ArrayList(*Peer),
    mutex: Mutex,
    next_peer_id: u64,
    max_peers: usize,
    
    // Discovery
    known_addresses: ArrayList(net.Address),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, max_peers: usize) Self {
        return .{
            .allocator = allocator,
            .peers = ArrayList(*Peer).init(allocator),
            .mutex = .{},
            .next_peer_id = 1,
            .max_peers = max_peers,
            .known_addresses = ArrayList(net.Address).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.peers.items) |peer| {
            peer.deinit();
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
        self.known_addresses.deinit();
    }
    
    /// Stop all peer connections gracefully
    pub fn stop(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Mark all peers as disconnected
        for (self.peers.items) |peer| {
            peer.state = .disconnected;
        }
    }
    
    /// Add a new peer connection
    pub fn addPeer(self: *Self, address: net.Address) !*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check if already connected
        for (self.peers.items) |peer| {
            if (peer.address.eql(address)) {
                return error.AlreadyConnected;
            }
        }
        
        // Check peer limit
        if (self.peers.items.len >= self.max_peers) {
            return error.TooManyPeers;
        }
        
        // Create new peer
        const peer = try self.allocator.create(Peer);
        peer.* = Peer.init(self.allocator, self.next_peer_id, address);
        self.next_peer_id += 1;
        
        try self.peers.append(peer);
        return peer;
    }
    
    /// Remove a peer
    pub fn removePeer(self: *Self, peer_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.peers.items, 0..) |peer, i| {
            if (peer.id == peer_id) {
                peer.deinit();
                self.allocator.destroy(peer);
                _ = self.peers.orderedRemove(i);
                break;
            }
        }
    }
    
    /// Get peer by ID
    pub fn getPeer(self: *Self, peer_id: u64) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.peers.items) |peer| {
            if (peer.id == peer_id) {
                return peer;
            }
        }
        return null;
    }
    
    /// Get all connected peers
    pub fn getConnectedPeers(self: *Self, list: *ArrayList(*Peer)) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                try list.append(peer);
            }
        }
    }
    
    /// Get best peer for sync (highest height)
    pub fn getBestPeerForSync(self: *Self) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var best: ?*Peer = null;
        var best_height: u32 = 0;
        
        for (self.peers.items) |peer| {
            if (peer.state == .connected and peer.height > best_height) {
                best = peer;
                best_height = peer.height;
            }
        }
        
        return best;
    }
    
    /// Broadcast message to all connected peers
    pub fn broadcast(self: *Self, msg_type: protocol.MessageType, msg: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                _ = peer.sendMessage(msg_type, msg) catch |err| {
                    std.log.warn("Failed to send to {}: {}", .{ peer, err });
                };
            }
        }
    }
    
    /// Add known address for discovery
    pub fn addKnownAddress(self: *Self, address: net.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check if already known
        for (self.known_addresses.items) |known| {
            if (known.eql(address)) {
                return;
            }
        }
        
        try self.known_addresses.append(address);
    }
    
    /// Get random known address for connection
    pub fn getRandomAddress(self: *Self) ?net.Address {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.known_addresses.items.len == 0) {
            return null;
        }
        
        const index = std.crypto.random.uintLessThan(usize, self.known_addresses.items.len);
        return self.known_addresses.items[index];
    }
    
    /// Clean up timed out peers
    pub fn cleanupTimedOut(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.isTimedOut()) {
                std.log.info("Peer {} timed out, removing", .{peer});
                peer.deinit();
                self.allocator.destroy(peer);
                _ = self.peers.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
    
    /// Get connected peer count
    pub fn getConnectedCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                count += 1;
            }
        }
        return count;
    }
    
    /// Get highest peer height
    pub fn getHighestPeerHeight(self: *Self) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var highest: u32 = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected and peer.height > highest) {
                highest = peer.height;
            }
        }
        return highest;
    }
    
    /// Get peer count by state
    pub fn getPeerCount(self: *Self) struct { total: usize, connected: usize, syncing: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var connected: usize = 0;
        var syncing: usize = 0;
        
        for (self.peers.items) |peer| {
            if (peer.state == .connected) connected += 1;
            if (peer.syncing) syncing += 1;
        }
        
        return .{
            .total = self.peers.items.len,
            .connected = connected,
            .syncing = syncing,
        };
    }
};