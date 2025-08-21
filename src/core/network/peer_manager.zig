// peer_manager.zig - Modular peer management system
// Handles peer connections, discovery, and lifecycle

const std = @import("std");
const net = std.net;
const protocol = @import("protocol/protocol.zig");
const wire = @import("wire/wire.zig");
const message_types = @import("protocol/messages/message_types.zig");
const message_envelope = @import("protocol/message_envelope.zig");

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
    
    /// Format peer state for cleaner logging
    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        const state_str = switch (self) {
            .connecting => "connecting",
            .handshaking => "handshaking", 
            .connected => "connected",
            .syncing => "syncing",
            .disconnecting => "disconnecting",
            .disconnected => "disconnected",
        };
        try writer.writeAll(state_str);
    }
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
    
    // ZSP-001 Performance tracking
    ping_time_ms: u32,
    consecutive_successful_requests: u32,
    consecutive_failures: u32,
    
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
            .ping_time_ms = 0,
            .consecutive_successful_requests = 0,
            .consecutive_failures = 0,
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
        const result = try self.connection.sendMessage(msg_type, msg);
        
        // If we have a TCP send callback, use it to actually send the data
        if (self.tcp_send_fn) |send_fn| {
            try send_fn(self.tcp_send_ctx, result);
        }
        
        return result;
    }
    
    /// Set TCP send callback
    pub fn setTcpSendCallback(self: *Self, send_fn: *const fn(ctx: ?*anyopaque, data: []const u8) anyerror!void, ctx: ?*anyopaque) void {
        self.tcp_send_fn = send_fn;
        self.tcp_send_ctx = ctx;
        // print("🔗 [PEER TCP] Peer {} TCP callback configured\n", .{self.id});
    }
    
    /// Process received data
    pub fn receiveData(self: *Self, data: []const u8) !void {
        self.last_recv = std.time.timestamp();
        try self.connection.receiveData(data);
    }
    
    /// Try to read next message
    pub fn readMessage(self: *Self) !?message_envelope.MessageEnvelope {
        const result = try self.connection.readMessage();
        if (result) |_| {
            self.last_recv = std.time.timestamp();
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
            // print("⏰ [PEER TIMEOUT] Peer {} timed out (last_recv: {}, now: {}, diff: {}s)\n", .{self.id, self.last_recv, now, now - self.last_recv});
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
        var msg = try message_types.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);
        
        _ = try self.sendMessage(.get_blocks, msg);
    }
    
    /// Send ZSP-001 compliant request for specific block by height
    /// Uses height encoding with 0xDEADBEEF magic marker for backward compatibility
    pub fn sendGetBlockByHeight(self: *Self, height: u32) !void {
        // print("📤 [ZSP-001 PEER] Sending height-encoded block request for height {} to peer {}\n", .{height, self.id});
        // print("🔍 [ZSP-001 PEER] Peer state: {}, connected: {}\n", .{self.state, self.isConnected()});
        
        // ZSP-001 SPECIFICATION: Height-Encoded Block Requests
        // For height-based requests, we encode the height as a 32-byte hash using the
        // ZSP-001 specification format for backward compatibility with hash-based requests:
        // 
        // Bytes 0-3:   Height (little-endian u32)
        // Bytes 4-7:   Magic marker 0xDEADBEEF (ZSP-001 identifier)
        // Bytes 8-31:  Zero padding
        //
        // This encoding allows peers to distinguish between real block hashes and
        // height-based requests while maintaining protocol compatibility.
        
        var height_hash: [32]u8 = [_]u8{0} ** 32;
        
        // Encode height in first 4 bytes (ZSP-001 format)
        std.mem.writeInt(u32, height_hash[0..4], height, .little);
        
        // Set ZSP-001 magic marker in bytes 4-8 to indicate height-encoded request
        const ZSP_001_HEIGHT_MAGIC: u32 = 0xDEADBEEF;
        std.mem.writeInt(u32, height_hash[4..8], ZSP_001_HEIGHT_MAGIC, .little);
        
        // Remaining bytes stay zero as per ZSP-001 specification
        
        // Send as single-item GetBlocksMessage
        var hashes = [_][32]u8{height_hash};
        var msg = try message_types.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);
        
        // print("🔧 [ZSP-001 PEER] Encoded height {} with magic marker: {X:0>8}\n", .{height, ZSP_001_HEIGHT_MAGIC});
        // print("📡 [ZSP-001 PEER] Transmitting height-encoded request\n", .{});
        
        _ = try self.sendMessage(.get_blocks, msg);
        
        // print("✅ [ZSP-001 PEER] Height-encoded block request sent successfully for height {}\n", .{height});
    }
    
    /// Send ZSP-001 compliant request for multiple blocks (batch sync)
    /// Supports both hash-based and height-encoded requests in the same batch
    pub fn sendGetBlocks(self: *Self, hashes: []const [32]u8) !void {
        // print("📤 [ZSP-001 BATCH] Sending batch block request for {} items to peer {}\n", .{hashes.len, self.id});
        
        // Analyze the batch to determine if it contains height-encoded requests
        var height_encoded_count: usize = 0;
        var hash_requests_count: usize = 0;
        
        for (hashes) |hash| {
            const magic_marker = std.mem.readInt(u32, hash[4..8], .little);
            if (magic_marker == 0xDEADBEEF) {
                _ = std.mem.readInt(u32, hash[0..4], .little); // height unused when logging disabled
                // print("🔧 [ZSP-001 BATCH] Height-encoded request detected: height {}\n", .{height});
                height_encoded_count += 1;
            } else {
                // print("🔧 [ZSP-001 BATCH] Hash-based request: {s}\n", .{std.fmt.fmtSliceHexLower(hash[0..8])});
                hash_requests_count += 1;
            }
        }
        
        // print("📊 [ZSP-001 BATCH] Batch analysis: {} height-encoded, {} hash-based requests\n", .{
        //     height_encoded_count, hash_requests_count
        // });
        
        // Create and send the batch message
        var msg = try message_types.GetBlocksMessage.init(self.allocator, hashes);
        defer msg.deinit(self.allocator);
        
        // print("📡 [ZSP-001 BATCH] Transmitting batch request\n", .{});
        _ = try self.sendMessage(.get_blocks, msg);
        
        // print("✅ [ZSP-001 BATCH] Batch block request sent successfully ({} items)\n", .{hashes.len});
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
        
        var msg = try message_types.GetHeadersMessage.init(self.allocator, locator.items, stop_hash);
        defer msg.deinit(self.allocator);
        
        _ = try self.sendMessage(.get_headers, msg);
        print("📤 Requested headers starting from height {} with {} locator hashes\n", .{ start_height, locator.items.len });
    }
    
    /// Send request for specific block (wrapper method)
    pub fn sendGetBlock(self: *Self, height: u32) !void {
        return self.sendGetBlockByHeight(height);
    }
    
    // ========================================================================
    // ZSP-001 ENHANCED PEER FUNCTIONALITY
    // ========================================================================
    
    /// Check if peer supports ZSP-001 batch synchronization
    /// Based on advertised service flags during handshake
    pub fn supportsBatchSync(self: *const Self) bool {
        // Check for ZSP-001 batch sync capability flags
        const has_parallel_download = (self.services & protocol.ServiceFlags.PARALLEL_DOWNLOAD) != 0;
        const has_fast_sync = (self.services & protocol.ServiceFlags.FAST_SYNC) != 0;
        
        return has_parallel_download or has_fast_sync;
    }
    
    /// Get peer performance score for sync peer selection
    /// Used by sync manager to choose optimal peers for batch sync
    pub fn getSyncPerformanceScore(self: *const Self) f64 {
        // Base performance score
        var score: f64 = 100.0;
        
        // Penalize high ping times (prefer low-latency peers)
        if (self.ping_time_ms > 0) {
            const ping_penalty = @as(f64, @floatFromInt(self.ping_time_ms)) * 0.1;
            score -= ping_penalty;
        }
        
        // Bonus for stable connections
        if (self.consecutive_successful_requests > 10) {
            score += 20.0;
        }
        
        // Penalty for recent failures
        const failure_penalty = @as(f64, @floatFromInt(self.consecutive_failures)) * 5.0;
        score -= failure_penalty;
        
        // Bonus for batch sync capability
        if (self.supportsBatchSync()) {
            score += 50.0; // Significant bonus for ZSP-001 capability
        }
        
        return @max(1.0, score);
    }
    
    /// Update peer statistics after successful block request
    pub fn recordSuccessfulRequest(self: *Self) void {
        self.consecutive_successful_requests += 1;
        self.consecutive_failures = 0;
        
        // print("📈 [ZSP-001 PEER] Peer {} successful requests: {}\n", .{
        //     self.id, self.consecutive_successful_requests
        // });
    }
    
    /// Update peer statistics after failed block request
    pub fn recordFailedRequest(self: *Self) void {
        self.consecutive_failures += 1;
        self.consecutive_successful_requests = 0;
        
        // print("📉 [ZSP-001 PEER] Peer {} consecutive failures: {}\n", .{
        //     self.id, self.consecutive_failures
        // });
    }
    
    /// Check if peer should be considered for sync operations
    pub fn isEligibleForSync(self: *const Self) bool {
        // Must be connected
        if (!self.isConnected()) return false;
        
        // Too many recent failures
        if (self.consecutive_failures >= 5) return false;
        
        // High ping time threshold
        if (self.ping_time_ms > 2000) return false; // 2 second max
        
        return true;
    }
    
    /// Get human-readable peer status for debugging
    pub fn getStatusString(self: *const Self, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "Peer[{}] state:{} ping:{}ms batch:{} score:{d:.1}", .{
            self.id,
            self.state,
            self.ping_time_ms,
            self.supportsBatchSync(),
            self.getSyncPerformanceScore(),
        }) catch "status error";
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
        // print("\n══════════════════════════════════════════════════════════════════\n", .{});
        // print("🔗 [PEER MANAGER] ADDING NEW PEER CONNECTION\n", .{});
        // print("══════════════════════════════════════════════════════════════════\n", .{});
        // print("📊 [PEER MANAGER] Connection request for: {any}\n", .{address});
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // print("🔍 [PEER MANAGER] STEP 1: Checking for duplicate connections...\n", .{});
        // SECURITY: Check if IP already has a connection (ignore port to prevent dual connections)
        for (self.peers.items) |peer| {
            // Compare IP addresses by converting to string representation
            const peer_ip = peer.address.getPort();
            const new_ip = address.getPort();
            _ = peer_ip;
            _ = new_ip;
            
            // For now, use simpler exact address matching until proper IP comparison is implemented
            if (peer.address.eql(address)) {
                // print("❌ [PEER MANAGER] STEP 1 FAILED: IP already connected\n", .{});
                // print("🔒 [SECURITY] Existing peer ID: {} from same IP\n", .{peer.id});
                // print("🔒 [SECURITY] Only one connection per IP allowed to prevent resource exhaustion\n", .{});
                // print("💡 [PEER MANAGER] Existing connection: {any}\n", .{peer.address});
                // print("💡 [PEER MANAGER] Rejected connection: {any}\n", .{address});
                return error.AlreadyConnected;
            }
        }
        // print("✅ [PEER MANAGER] STEP 1 PASSED: No duplicate connections found\n", .{});
        
        // print("🔍 [PEER MANAGER] STEP 2: Checking peer capacity...\n", .{});
        // print("📊 [PEER MANAGER] Current peers: {}/{}\n", .{self.peers.items.len, self.max_peers});
        // Check peer limit
        if (self.peers.items.len >= self.max_peers) {
            // print("❌ [PEER MANAGER] STEP 2 FAILED: Peer limit reached\n", .{});
            // print("📊 [PEER MANAGER] Maximum peers: {} (consider increasing limit)\n", .{self.max_peers});
            return error.TooManyPeers;
        }
        // print("✅ [PEER MANAGER] STEP 2 PASSED: Capacity available\n", .{});
        
        // print("🔍 [PEER MANAGER] STEP 3: Creating new peer instance...\n", .{});
        // Create new peer
        const peer = try self.allocator.create(Peer);
        const assigned_id = self.next_peer_id;
        peer.* = Peer.init(self.allocator, assigned_id, address);
        self.next_peer_id += 1;
        
        // print("✅ [PEER MANAGER] STEP 3 COMPLETED: Peer instance created\n", .{});
        // print("📊 [PEER MANAGER] Assigned peer ID: {}\n", .{assigned_id});
        // print("📊 [PEER MANAGER] Next available ID: {}\n", .{self.next_peer_id});
        
        // print("🔍 [PEER MANAGER] STEP 4: Adding peer to peer list...\n", .{});
        try self.peers.append(peer);
        // print("✅ [PEER MANAGER] STEP 4 COMPLETED: Peer added to list\n", .{});
        
        // print("\n🎉 [PEER MANAGER] PEER SUCCESSFULLY ADDED!\n", .{});
        // print("📊 [PEER MANAGER] Final stats:\n", .{});
        // print("   └─ Total peers: {}\n", .{self.peers.items.len});
        // print("   └─ New peer ID: {}\n", .{assigned_id});
        // print("   └─ Address: {any}\n", .{address});
        // print("══════════════════════════════════════════════════════════════════\n", .{});
        
        return peer;
    }
    
    /// Remove a peer
    pub fn removePeer(self: *Self, peer_id: u64) void {
        // print("\n══════════════════════════════════════════════════════════════════\n", .{});
        // print("🔌 [PEER MANAGER] REMOVING PEER CONNECTION\n", .{});
        // print("══════════════════════════════════════════════════════════════════\n", .{});
        // print("📊 [PEER MANAGER] Removal request for peer ID: {}\n", .{peer_id});
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // print("🔍 [PEER MANAGER] Searching for peer in active connections...\n", .{});
        // print("📊 [PEER MANAGER] Current peer count: {}\n", .{self.peers.items.len});
        
        var found = false;
        for (self.peers.items, 0..) |peer, i| {
            if (peer.id == peer_id) {
                found = true;
                // print("✅ [PEER MANAGER] Peer found at index {}\n", .{i});
                // print("📊 [PEER MANAGER] Peer details:\n", .{});
                // print("   └─ ID: {}\n", .{peer.id});
                // print("   └─ Address: {any}\n", .{peer.address});
                // print("   └─ State: {}\n", .{peer.state});
                
                // print("🧹 [PEER MANAGER] Cleaning up peer resources...\n", .{});
                peer.deinit();
                self.allocator.destroy(peer);
                
                // print("🗑️ [PEER MANAGER] Removing peer from active list...\n", .{});
                _ = self.peers.orderedRemove(i);
                
                // print("✅ [PEER MANAGER] Peer removal completed successfully\n", .{});
                break;
            }
        }
        
        if (!found) {
            // print("⚠️ [PEER MANAGER] Peer ID {} not found in active connections\n", .{peer_id});
            // print("📊 [PEER MANAGER] Available peer IDs:\n", .{});
            // for (self.peers.items) |peer| {
            //     print("   └─ ID: {} ({any})\n", .{peer.id, peer.address});
            // }
        }
        
        // print("📊 [PEER MANAGER] Final peer count: {}\n", .{self.peers.items.len});
        // print("══════════════════════════════════════════════════════════════════\n", .{});
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
        // print("\n╔══════════════════════════════════════════════════════════════════╗\n", .{});
        // print("║                      PEER SELECTION PROCESS                     ║\n", .{});
        // print("╚══════════════════════════════════════════════════════════════════╝\n", .{});
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // print("🔍 [PEER SELECTION] Analyzing available peers...\n", .{});
        // print("📊 [PEER SELECTION] Total peers: {}\n", .{self.peers.items.len});
        
        var best: ?*Peer = null;
        var best_height: u32 = 0;
        var connected_count: u32 = 0;
        var sync_capable_count: u32 = 0;
        
        // First pass: count and analyze peers
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                connected_count += 1;
                
                // Check ZSP-001 capabilities
                const sync_capable = peer.supportsBatchSync();
                if (sync_capable) sync_capable_count += 1;
                
                // print("📊 [PEER SELECTION] Peer {any}:\n", .{peer.address});
                // print("   └─ State: {}\n", .{peer.state});
                // print("   └─ Height: {}\n", .{peer.height});
                // print("   └─ ZSP-001 capable: {}\n", .{sync_capable});
                // print("   └─ Performance score: {d:.1}\n", .{peer.getSyncPerformanceScore()});
                
                if (peer.height > best_height) {
                    // if (best) |old_best| {
                    //     print("🔄 [PEER SELECTION] New best peer found: {} → {any} (height {} → {})\n", .{
                    //         old_best.address, peer.address, best_height, peer.height
                    //     });
                    // } else {
                    //     print("✨ [PEER SELECTION] First candidate: {any} (height {})\n", .{peer.address, peer.height});
                    // }
                    best = peer;
                    best_height = peer.height;
                }
            } else {
                // print("⚠️ [PEER SELECTION] Peer {any}: state {} (not connected)\n", .{peer.address, peer.state});
            }
        }
        
        // print("\n📊 [PEER SELECTION] SELECTION SUMMARY:\n", .{});
        // print("   └─ Total peers: {}\n", .{self.peers.items.len});
        // print("   └─ Connected peers: {}\n", .{connected_count});
        // print("   └─ ZSP-001 capable: {}\n", .{sync_capable_count});
        
        // if (best) |selected_peer| {
        //     print("✅ [PEER SELECTION] BEST PEER SELECTED:\n", .{});
        //     print("   └─ Address: {any}\n", .{selected_peer.address});
        //     print("   └─ Height: {}\n", .{selected_peer.height});
        //     print("   └─ ZSP-001 capable: {}\n", .{selected_peer.supportsBatchSync()});
        //     print("   └─ Performance score: {d:.1}\n", .{selected_peer.getSyncPerformanceScore()});
        //     print("🚀 [PEER SELECTION] Ready for synchronization!\n", .{});
        // } else {
        //     print("❌ [PEER SELECTION] NO SUITABLE PEER FOUND\n", .{});
        //     if (connected_count == 0) {
        //         print("🔌 [PEER SELECTION] Issue: No connected peers available\n", .{});
        //         print("💡 [PEER SELECTION] Suggestion: Check network connectivity\n", .{});
        //     } else {
        //         print("⚠️ [PEER SELECTION] Issue: Connected peers have height 0 or lower\n", .{});
        //         print("💡 [PEER SELECTION] Suggestion: Wait for peer height updates\n", .{});
        //     }
        // }
        
        // print("╔══════════════════════════════════════════════════════════════════╗\n", .{});
        return best;
    }
    
    /// Broadcast message to all connected peers
    pub fn broadcast(self: *Self, msg_type: protocol.MessageType, msg: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var successful_sends: usize = 0;
        var failed_sends: usize = 0;
        
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                _ = peer.sendMessage(msg_type, msg) catch {
                    failed_sends += 1;
                    // print("❌ [PEER MANAGER] Failed to send {} to peer {}: {}\n", .{msg_type, peer.id, err});
                    continue;
                };
                successful_sends += 1;
            }
        }
        
        if (failed_sends > 0) {
            // print("📡 [PEER MANAGER] Broadcast {}: {}/{} peers successful\n", .{msg_type, successful_sends, successful_sends + failed_sends});
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
        
        var removed_count: usize = 0;
        
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.isTimedOut()) {
                // print("⏰ [PEER MANAGER] Removing timed out peer {} (last activity: {}s ago)\n", .{peer.id, std.time.timestamp() - peer.last_recv});
                peer.deinit();
                self.allocator.destroy(peer);
                _ = self.peers.orderedRemove(i);
                removed_count += 1;
                // Don't increment i since we removed an item
            } else {
                i += 1;
            }
        }
        
        if (removed_count > 0) {
            // print("🧹 [PEER MANAGER] Cleanup completed: {} timed out peers removed\n", .{removed_count});
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